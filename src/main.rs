// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! rhook anti-cheat -- defensive scanner for a target process.
//!
//! Looks for the fingerprints an in-process cheat leaves behind, using
//! only user-mode APIs, and reports what it *examined* as well as what it
//! objected to. A scanner that prints "ok" for a check it never performed
//! is worse than one that prints nothing.
//!
//! Coverage:
//!
//! 1. **Unexpected loaded modules** -- DLL injection.
//! 2. **Changed code**, against a clean reference image: first every
//!    exported function's prologue, then every executable section
//!    wholesale. The section sweep is the one that matters -- IL2CPP
//!    compiles game methods without exporting them, so an export-driven
//!    check is blind to rhook's actual targets.
//! 3. **Thread origins** outside any mapped module. Note the caveat in
//!    `threads`: `LoadLibrary` injection is invisible to this one by
//!    construction, and is check 1's job.
//! 4. **Module provenance** -- where each module's file lives, whether it
//!    is signed, whether it shadows a `System32` DLL, and (with
//!    `--manifest`) whether a game file still hashes as shipped. This is
//!    what catches a proxy DLL, which check 1 blesses because it is
//!    already loaded at attach. See `trust`.
//! 5. **Executable memory outside any listed image** -- manual mapping,
//!    shellcode, trampolines. See `exec_memory`.
//!
//! Educational companion to rhook's `hook-engine`: both are built on the
//! same primitives, aimed in opposite directions.

#![deny(unsafe_op_in_unsafe_fn)]

mod exec_memory;
mod image;
mod log;
mod remote_pe;
mod threads;
mod trust;

use std::collections::HashSet;
use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use rhook_common::{memory, module, process};
use windows::Win32::Foundation::HANDLE;

use crate::exec_memory::ExecScan;
use crate::log::Log;
use crate::trust::{Location, ManifestCheck, Signature, Trust};

/// Bytes compared at each export. Covers rhook's 14-byte absolute JMP and
/// the 5-byte relative variant with room to spare.
const PROLOGUE_LEN: usize = 16;

/// Sections the Windows loader rewrites at map time through mechanisms the
/// base-relocation table does not describe, so a disk reference cannot
/// validate them.
///
/// `fothk` is the function-override thunk section. Entries in it are not
/// functions: on disk each is a `jmp rel32` into `.text` followed by `CC`
/// padding, and at load time the loader retargets that jump at the
/// implementation picked for the host CPU. `msvcrt.dll!memset` is the
/// clearest case -- its export RVA lands in `fothk`, its on-disk bytes are
/// already a jump, and the running process legitimately holds a different
/// one.
///
/// Excluded only against a disk reference: with a self-process reference
/// the same rewriting has been applied to both sides and the comparison is
/// meaningful again. The exclusion is a real coverage gap -- a hook hidden
/// inside one of these thunks would be missed -- so it is counted and
/// reported rather than silently dropped.
const LOADER_REWRITTEN: [&str; 1] = ["fothk"];

/// Whether `rva` falls in a section this reference cannot validate.
fn in_loader_rewritten(clean: &image::CleanImage, src: RefSource, rva: u32) -> bool {
    src == RefSource::Disk
        && clean
            .section_of(rva)
            .is_some_and(|s| LOADER_REWRITTEN.iter().any(|k| k.eq_ignore_ascii_case(s)))
}

struct Args {
    target: String,
    watch: bool,
    verbose: bool,
    log_path: Option<String>,
    /// Extra modules to check beyond the target's own image.
    modules: Vec<String>,
    /// Manifest of the game's files to check against.
    manifest: Option<String>,
    /// Write a manifest of the target's directory and exit.
    write_manifest: Option<String>,
}

/// Findings already reported, so a `--watch` session logs an event once
/// instead of re-announcing the same state every pass.
#[derive(Default)]
struct Seen {
    modules: HashSet<String>,
    prologues: HashSet<String>,
    threads: HashSet<u32>,
    /// Provenance findings, keyed on finding kind and normalised path.
    trust: HashSet<String>,
    /// Foreign executable allocations, keyed on allocation base.
    exec: HashSet<usize>,
}

fn parse_args() -> Option<Args> {
    let argv: Vec<String> = env::args().collect();
    let mut target = None;
    let mut watch = false;
    let mut verbose = false;
    let mut log_path = None;
    let mut modules = Vec::new();
    let mut manifest = None;
    let mut write_manifest = None;

    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--watch" => watch = true,
            "--verbose" | "-v" => verbose = true,
            "--log" => {
                i += 1;
                log_path = argv.get(i).cloned();
            }
            "--manifest" => {
                i += 1;
                manifest = argv.get(i).cloned();
            }
            "--write-manifest" => {
                i += 1;
                write_manifest = argv.get(i).cloned();
            }
            "--module" => {
                i += 1;
                if let Some(m) = argv.get(i) {
                    modules.push(m.clone());
                }
            }
            other if !other.starts_with('-') && target.is_none() => {
                target = Some(other.to_string());
            }
            other => {
                eprintln!("unknown argument: {other}");
                return None;
            }
        }
        i += 1;
    }

    target.map(|t| Args {
        target: normalise_exe_name(&t),
        watch,
        verbose,
        log_path,
        modules,
        manifest,
        write_manifest,
    })
}

fn usage() {
    eprintln!(
        "Usage: rhook-anticheat <process-name|pid> [--watch] [--verbose] [--log FILE] [--module NAME]...\n\
                                [--manifest FILE | --write-manifest FILE]\n\
         \n\
           --watch                re-scan every 2s instead of a single pass\n\
           --verbose, -v          per-item detail on the console (always in --log)\n\
           --log FILE             write the full transcript, including debug detail\n\
           --module NAME          also check this module (repeatable)\n\
           --manifest FILE        check the game's files against a hash manifest\n\
           --write-manifest FILE  hash every .dll/.exe under the target's directory\n\
                                  into FILE and exit (run it on a clean install)"
    );
}

fn main() -> ExitCode {
    let Some(args) = parse_args() else {
        usage();
        return ExitCode::from(2);
    };

    let mut log = Log::new(args.verbose, args.log_path.as_deref());

    let pid = match args.target.parse::<u32>() {
        Ok(pid) => pid,
        Err(_) => match process::find_process_by_name(&args.target) {
            Ok(p) => p,
            Err(e) => {
                log.alert(format!("target not found: {e}"));
                return ExitCode::from(1);
            }
        },
    };
    log.info(format!("target: {} (pid {pid})", args.target));

    // ---- provenance setup -----------------------------------------
    //
    // The game directory is what separates "shipped with the game" from
    // "came from somewhere else", so it is resolved once, from the
    // target's own image path.
    let image_path = match process::open_process(pid) {
        Ok(h) => {
            let p = trust::process_image_path(h);
            unsafe { process::close_handle(h) };
            p
        }
        Err(e) => {
            log.debug(format!("cannot open process for its image path: {e}"));
            None
        }
    };
    let game_dir = image_path
        .as_deref()
        .and_then(|p| Path::new(p).parent())
        .map(|d| d.to_string_lossy().into_owned());

    if let Some(out) = &args.write_manifest {
        let Some(dir) = &game_dir else {
            log.alert("cannot write a manifest: the target's image path is unknown");
            return ExitCode::from(1);
        };
        return match trust::write_manifest(Path::new(dir), out) {
            Ok(n) => {
                log.info(format!(
                    "manifest: {n} file(s) under {dir} hashed into {out}"
                ));
                ExitCode::SUCCESS
            }
            Err(e) => {
                log.alert(format!("cannot write manifest: {e}"));
                ExitCode::from(1)
            }
        };
    }

    let manifest = match args.manifest.as_deref().map(trust::load_manifest) {
        None => None,
        Some(Ok(m)) => {
            log.info(format!("manifest: {} file(s) listed", m.len()));
            Some(m)
        }
        Some(Err(e)) => {
            log.alert(format!("cannot load manifest: {e}"));
            return ExitCode::from(1);
        }
    };
    match &game_dir {
        Some(d) => log.info(format!("game directory: {d}")),
        None => log.warn(
            "game directory unknown: every non-Windows module counts as 'other', and the manifest cannot be applied",
        ),
    }
    let mut trust = Trust::new(game_dir, manifest);
    if !trust.has_manifest() {
        log.warn(
            "no --manifest: game files are judged by signature alone, and an unsigned GameAssembly.dll is normal",
        );
    }

    // ---- baseline -------------------------------------------------
    //
    // Only the *module* check needs a baseline, and taking it after
    // attach means anything injected earlier is treated as legitimate.
    // The prologue check has no such weakness: its reference is the file
    // on disk, so it catches hooks installed long before this process
    // started.
    log.section("baseline");
    let baseline: HashSet<String> = match module::list_modules(pid) {
        Ok(m) => {
            log.info(format!("{} modules mapped at baseline", m.len()));
            for mi in &m {
                log.debug(format!(
                    "  {:<32} base 0x{:012X} size {:>9}",
                    mi.name, mi.base_address, mi.size
                ));
            }
            m.into_iter().map(|m| m.name.to_ascii_lowercase()).collect()
        }
        Err(e) => {
            log.alert(format!("cannot enumerate modules: {e}"));
            return ExitCode::from(1);
        }
    };
    log.warn(
        "module baseline captured after attach: a DLL injected before this point counts as clean",
    );

    let mut seen = Seen::default();
    let mut pass = 0u32;
    loop {
        pass += 1;
        log.section(&format!("pass {pass}"));
        scan_once(&mut log, pid, &args, &baseline, &mut trust, &mut seen);

        if !args.watch {
            break;
        }
        thread::sleep(Duration::from_secs(2));
    }

    log.section("summary");
    log.info(format!(
        "{} alert(s), {} warning(s)",
        log.alerts(),
        log.warnings()
    ));
    if log.alerts() > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn scan_once(
    log: &mut Log,
    pid: u32,
    args: &Args,
    baseline: &HashSet<String>,
    trust: &mut Trust,
    seen: &mut Seen,
) {
    let modules = match module::list_modules(pid) {
        Ok(m) => m,
        Err(e) => {
            log.warn(format!("module scan failed: {e}"));
            return;
        }
    };

    // ---- 1. new modules -------------------------------------------
    let now: HashSet<String> = modules
        .iter()
        .map(|m| m.name.to_ascii_lowercase())
        .collect();
    let mut added: Vec<&String> = now.difference(baseline).collect();
    added.sort();
    log.info(format!(
        "modules: {} mapped, {} new since baseline",
        modules.len(),
        added.len()
    ));
    for name in &added {
        let detail = modules
            .iter()
            .find(|m| &m.name.to_ascii_lowercase() == *name)
            .map(|m| format!(" @ 0x{:X} ({} bytes)", m.base_address, m.size))
            .unwrap_or_default();
        let msg = format!("new module since baseline: {name}{detail}");
        if seen.modules.insert((*name).clone()) {
            log.alert(msg);
        } else {
            log.debug(format!("(still present) {msg}"));
        }
    }

    // ---- 1b. module provenance ------------------------------------
    check_provenance(log, pid, &modules, trust, seen);

    // ---- 2. prologue integrity ------------------------------------
    let handle = match process::open_process(pid) {
        Ok(h) => Some(h),
        Err(e) => {
            log.warn(format!("cannot open process for memory reads: {e}"));
            None
        }
    };

    // Kept past the handle's lifetime so a foreign thread can be matched
    // to the allocation it starts in.
    let mut exec: Option<ExecScan> = None;

    if let Some(handle) = handle {
        // Which modules to inspect. Empty `--module` means *all of them*:
        // a defender does not know in advance where a hook will land, and
        // requiring the operator to name the module bakes knowledge of a
        // specific title into a tool that should only know about the
        // engine. `--module` narrows the sweep when you do know.
        let targets: Vec<&rhook_common::module::ModuleInfo> = if args.modules.is_empty() {
            modules.iter().collect()
        } else {
            let mut v: Vec<_> = Vec::new();
            for want in &args.modules {
                match modules.iter().find(|m| m.name.eq_ignore_ascii_case(want)) {
                    Some(m) => v.push(m),
                    None => log.warn(format!("module not mapped in target: {want}")),
                }
            }
            v
        };

        let mut total = ScanStats::default();
        for mi in targets {
            total += check_module(log, handle, pid, &mi.name, mi.base_address, seen);
        }

        log.info(format!(
            "integrity: {} module(s) compared against their on-disk image ({} skipped), {} MB of executable code, {} export prologue(s), {} modified region(s)",
            total.modules_scanned,
            total.modules_skipped,
            total.bytes_compared / (1024 * 1024),
            total.exports_checked,
            total.regions
        ));

        // ---- 2b. executable memory outside images -------------------
        let scan = exec_memory::scan(handle, &modules);
        report_exec_memory(log, &scan, seen);
        exec = Some(scan);

        unsafe { process::close_handle(handle) };
    }

    // ---- 3. thread origins ----------------------------------------
    match threads::scan(pid, &modules) {
        Ok(scan) if !scan.primitive_available => {
            log.warn(
                "threads: NtQueryInformationThread unavailable, thread origins were NOT checked",
            );
        }
        Ok(scan) => {
            let unreadable = scan.unreadable();
            log.info(format!(
                "threads: {} examined, {} unreadable",
                scan.threads.len(),
                unreadable
            ));
            for (m, n) in threads::by_module(&scan) {
                log.debug(format!("  {n:>3} thread(s) from {m}"));
            }
            for t in &scan.threads {
                if let Some(err) = &t.error {
                    log.debug(format!("  thread {} not classified: {err}", t.tid));
                }
            }
            let mut foreign = 0;
            for t in scan.foreign() {
                foreign += 1;
                let start = t.start.unwrap_or(0);
                let region = exec
                    .as_ref()
                    .and_then(|e| e.regions.iter().find(|r| r.contains(start)))
                    .map(|r| {
                        format!(
                            ", inside the {} executable allocation at 0x{:X}",
                            r.kind.label(),
                            r.allocation_base
                        )
                    })
                    .unwrap_or_default();
                let msg = format!(
                    "thread {} starts at 0x{start:X}, outside every mapped module{region}",
                    t.tid
                );
                if seen.threads.insert(t.tid) {
                    log.alert(msg);
                } else {
                    log.debug(format!("(still present) {msg}"));
                }
            }
            if foreign == 0 {
                log.info("threads: every readable thread starts inside a mapped module");
            }
            if unreadable > 0 {
                log.warn(format!(
                    "threads: {unreadable} could not be classified, coverage is incomplete"
                ));
            }
        }
        Err(e) => log.warn(format!("thread scan failed: {e}")),
    }
}

/// Classify every module's file and report the ones nobody vouches for.
///
/// Findings are deduplicated on their kind and path, so `--watch` reports
/// a proxy DLL once; the verdicts themselves are cached inside `Trust`.
fn check_provenance(
    log: &mut Log,
    pid: u32,
    modules: &[rhook_common::module::ModuleInfo],
    trust: &mut Trust,
    seen: &mut Seen,
) {
    let (mut system, mut game, mut other, mut no_path) = (0, 0, 0, 0);
    let (mut signed, mut unsigned, mut invalid) = (0, 0, 0);
    let (mut matched, mut mismatched, mut unknown, mut unhashed) = (0, 0, 0, 0);

    for mi in modules {
        let Some(path) = image::module_path(pid, mi.base_address) else {
            no_path += 1;
            log.debug(format!("  provenance: skip {}: no on-disk path", mi.name));
            continue;
        };
        let v = trust.verdict(&path).clone();

        match v.location {
            Location::System => system += 1,
            Location::Game => game += 1,
            Location::Other => other += 1,
        }
        match &v.signature {
            Some(Signature::Valid) => signed += 1,
            Some(Signature::Unsigned) => unsigned += 1,
            Some(Signature::Invalid(_)) => invalid += 1,
            None => {}
        }
        match &v.manifest {
            ManifestCheck::NotChecked => {}
            ManifestCheck::Match => matched += 1,
            ManifestCheck::Mismatch => mismatched += 1,
            ManifestCheck::Unknown => unknown += 1,
            ManifestCheck::Unreadable(_) => unhashed += 1,
        }
        log.debug(format!(
            "  provenance: {:<32} {:?}, signature {}, manifest {:?}{} -- {path}",
            mi.name,
            v.location,
            match &v.signature {
                None => "not checked".to_string(),
                Some(Signature::Valid) => "valid".to_string(),
                Some(Signature::Unsigned) => "none".to_string(),
                Some(Signature::Invalid(hr)) => format!("INVALID 0x{:08X}", *hr as u32),
            },
            v.manifest,
            if v.shadows_system {
                ", shadows System32"
            } else {
                ""
            }
        ));

        // (dedup kind, alert rather than warning, message)
        let mut findings: Vec<(&str, bool, String)> = Vec::new();
        if let Some(Signature::Invalid(hr)) = v.signature {
            findings.push((
                "sig",
                true,
                format!(
                    "signature does not verify: {} (0x{:08X}) -- {path}",
                    mi.name, hr as u32
                ),
            ));
        }
        if v.shadows_system && !v.signed() {
            findings.push((
                "shadow",
                true,
                format!(
                    "unsigned {} shadows a System32 DLL of the same name (proxy-DLL pattern) -- {path}",
                    mi.name
                ),
            ));
        }
        match &v.manifest {
            ManifestCheck::Mismatch => findings.push((
                "manifest",
                true,
                format!("game file differs from the manifest: {} -- {path}", mi.name),
            )),
            ManifestCheck::Unknown => findings.push((
                "manifest",
                true,
                format!(
                    "game-directory module not in the manifest: {} -- {path}",
                    mi.name
                ),
            )),
            ManifestCheck::Unreadable(e) => findings.push((
                "manifest",
                false,
                format!(
                    "cannot hash {} for the manifest check: {e} -- {path}",
                    mi.name
                ),
            )),
            _ => {}
        }
        if v.location == Location::Other
            && v.signature == Some(Signature::Unsigned)
            && !v.shadows_system
        {
            findings.push((
                "other",
                false,
                format!(
                    "unsigned module from outside the game and Windows directories: {} -- {path}",
                    mi.name
                ),
            ));
        }

        for (kind, alert, msg) in findings {
            if seen
                .trust
                .insert(format!("{kind}:{}", path.to_ascii_lowercase()))
            {
                if alert {
                    log.alert(msg);
                } else {
                    log.warn(msg);
                }
            } else {
                log.debug(format!("(still present) {msg}"));
            }
        }
    }

    let manifest = if trust.has_manifest() {
        format!(
            "; manifest: {matched} match, {mismatched} differ, {unknown} unlisted, {unhashed} unreadable"
        )
    } else {
        String::new()
    };
    log.info(format!(
        "provenance: {system} system, {game} game, {other} other ({no_path} without a path); non-system: {signed} signed, {unsigned} unsigned, {invalid} invalid signature{manifest}"
    ));
}

/// Report executable memory that no listed module accounts for.
fn report_exec_memory(log: &mut Log, scan: &ExecScan, seen: &mut Seen) {
    log.info(format!(
        "exec memory: {} region(s) walked, {} MB executable inside modules, {} executable allocation(s) outside them",
        scan.regions_walked,
        scan.image_exec_bytes / (1024 * 1024),
        scan.regions.len()
    ));
    if let Some(at) = scan.stopped_at {
        log.warn(format!(
            "exec memory: address-space walk stopped at 0x{at:X}, coverage is partial"
        ));
    }
    for r in &scan.regions {
        let msg = format!(
            "executable {} memory at 0x{:X} (allocation 0x{:X}), {} KB{}\n              head: {}",
            r.kind.label(),
            r.first_exec,
            r.allocation_base,
            r.exec_bytes / 1024,
            if r.writable { ", writable" } else { "" },
            if r.head.is_empty() {
                "<unreadable>".to_string()
            } else {
                hex(&r.head)
            }
        );
        if seen.exec.insert(r.allocation_base) {
            log.alert(msg);
        } else {
            log.debug(format!("(still present) {msg}"));
        }
    }
}

/// Per-pass totals. With a hundred-odd modules the per-module lines
/// belong in the transcript, not on the console; these counts are what
/// stays visible.
#[derive(Default, Clone, Copy)]
struct ScanStats {
    modules_scanned: usize,
    modules_skipped: usize,
    bytes_compared: usize,
    exports_checked: usize,
    regions: usize,
}

impl std::ops::AddAssign for ScanStats {
    fn add_assign(&mut self, o: Self) {
        self.modules_scanned += o.modules_scanned;
        self.modules_skipped += o.modules_skipped;
        self.bytes_compared += o.bytes_compared;
        self.exports_checked += o.exports_checked;
        self.regions += o.regions;
    }
}

/// Where the "what these bytes should be" reference comes from.
#[derive(Clone, Copy, PartialEq)]
enum RefSource {
    /// The module's file. Correct for images the loader only relocates --
    /// in practice, an application's own DLLs.
    Disk,
    /// The same module mapped in the scanner's own process, at the same
    /// base. Preferred whenever available: it has received identical
    /// loader treatment, so load-time rewriting cancels out instead of
    /// being reported as tampering.
    SelfProcess(usize),
}

/// Everything needed to answer "what should be at this RVA".
struct Reference<'a> {
    clean: &'a image::CleanImage,
    src: RefSource,
    self_handle: HANDLE,
}

impl Reference<'_> {
    fn bytes(&self, rva: u32, len: usize) -> Option<Vec<u8>> {
        match self.src {
            RefSource::Disk => self.clean.slice_at_rva(rva, len).map(<[u8]>::to_vec),
            RefSource::SelfProcess(base) => {
                memory::read_bytes(self.self_handle, base + rva as usize, len).ok()
            }
        }
    }

    fn label(&self) -> &'static str {
        match self.src {
            RefSource::Disk => "on disk",
            RefSource::SelfProcess(_) => "reference",
        }
    }
}

/// Compare one module against a clean reference: export prologues first
/// (cheap and well-labelled), then every executable section.
fn check_module(
    log: &mut Log,
    handle: HANDLE,
    pid: u32,
    module_name: &str,
    module_base: usize,
    seen: &mut Seen,
) -> ScanStats {
    let mut stats = ScanStats::default();

    // Per-module failures are logged at debug and counted, not warned:
    // across a hundred modules a handful will legitimately have no
    // readable image, and a warning each would bury the real findings.
    // The skipped total stays visible in the pass summary.
    let Some(path) = image::module_path(pid, module_base) else {
        log.debug(format!("  skip {module_name}: no on-disk path"));
        stats.modules_skipped = 1;
        return stats;
    };
    let clean = match image::CleanImage::load(&path) {
        Ok(c) => c,
        Err(e) => {
            log.debug(format!("  skip {module_name}: clean image {path}: {e}"));
            stats.modules_skipped = 1;
            return stats;
        }
    };

    let scan = match remote_pe::read_exports_remote(handle, module_base) {
        Ok(s) => s,
        Err(e) => {
            log.debug(format!("  skip {module_name}: export walk failed: {e}"));
            stats.modules_skipped = 1;
            return stats;
        }
    };
    for s in &scan.skipped {
        log.debug(format!("  {module_name}: export walk skipped {s}"));
    }
    stats.modules_scanned = 1;

    // Prefer the scanner's own copy when the image is mapped here at the
    // same base; fall back to disk otherwise. The base equality check is
    // not optional: at a different base the relocations differ and every
    // relocated pointer would read as modified. It also settles the
    // same-name-different-file case for free -- two distinct files cannot
    // both be mapped at one address.
    let self_handle = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let ref_src = match image::own_module_base(module_name) {
        Some(b) if b == module_base => RefSource::SelfProcess(b),
        _ => RefSource::Disk,
    };
    log.debug(format!(
        "  {module_name}: reference = {}",
        match ref_src {
            RefSource::Disk => "on-disk image".to_string(),
            RefSource::SelfProcess(b) => format!("own process @ 0x{b:X}"),
        }
    ));
    let reference = Reference {
        clean: &clean,
        src: ref_src,
        self_handle,
    };

    log.debug(format!(
        "  {module_name}: export table declares {} functions / {} names, directory rva 0x{:X} ({} bytes); clean image has {} sections and {} relocation sites",
        scan.num_functions,
        scan.num_names,
        scan.export_dir_rva,
        scan.export_dir_size,
        clean.section_count(),
        clean.reloc_count
    ));

    // No early return when a module exports nothing: most DLLs a game
    // loads export little or nothing, and their code still has to be
    // compared. Exports are a labelling convenience, not the scope.
    let (mut checked, mut data, mut relocated, mut unreadable, mut tampered) = (0, 0, 0, 0, 0);
    let mut loader_rewritten = 0;

    for e in &scan.exports {
        if e.forwarded {
            continue;
        }
        if !clean.is_executable(e.rva) {
            data += 1;
            log.debug(format!(
                "  skip {} -- not in an executable section ({})",
                e.name,
                clean.section_of(e.rva).unwrap_or("?")
            ));
            continue;
        }
        // The section scan already excludes these wholesale; the export
        // loop has to do it too, or a thunk the loader retargeted gets
        // reported by name as a tampered prologue.
        if in_loader_rewritten(&clean, reference.src, e.rva) {
            loader_rewritten += 1;
            log.debug(format!(
                "  skip {} -- in {}, a loader-rewritten section (disk reference unusable)",
                e.name,
                clean.section_of(e.rva).unwrap_or("?")
            ));
            continue;
        }
        if clean.overlaps_reloc(e.rva, PROLOGUE_LEN) {
            relocated += 1;
            log.debug(format!(
                "  skip {} -- prologue overlaps a relocation",
                e.name
            ));
            continue;
        }
        let Some(want) = reference.bytes(e.rva, PROLOGUE_LEN) else {
            unreadable += 1;
            log.debug(format!(
                "  skip {} -- no reference bytes at that RVA",
                e.name
            ));
            continue;
        };
        let Ok(got) = memory::read_bytes(handle, e.address, PROLOGUE_LEN) else {
            unreadable += 1;
            log.debug(format!("  skip {} -- target memory unreadable", e.name));
            continue;
        };

        checked += 1;
        if got == want {
            continue;
        }

        tampered += 1;
        let key = format!("{module_name}!{}", e.name);
        // Label the reference for what it actually is: "on disk" against a
        // self-process reference would be a lie in the one place accuracy
        // matters most.
        let want_label = match reference.src {
            RefSource::Disk => "on disk",
            RefSource::SelfProcess(_) => "reference",
        };
        let msg = format!(
            "prologue tampered: {module_name}!{} (ordinal {}, rva 0x{:X}) @ 0x{:X}\n              {want_label}: {}\n              in memory: {}",
            e.name,
            e.ordinal,
            e.rva,
            e.address,
            hex(&want),
            hex(&got)
        );
        if seen.prologues.insert(key) {
            log.alert(msg);
        } else {
            log.debug(format!("(still tampered) {msg}"));
        }
    }

    log.debug(format!(
        "  prologues: {module_name} -- {checked} checked, {tampered} tampered ({data} data exports, {relocated} relocation-adjacent, {loader_rewritten} loader-rewritten, {unreadable} unreadable skipped; ref {})",
        clean.path
    ));
    stats.exports_checked = checked;

    // Exports are the cheap, well-labelled subset. The section sweep is
    // what actually covers a game's own code.
    let (regions, bytes) = check_text_integrity(
        log,
        handle,
        module_name,
        module_base,
        &reference,
        &scan.exports,
        seen,
    );
    stats.regions = regions;
    stats.bytes_compared = bytes;
    stats
}

/// Compare every executable section against the clean on-disk image.
///
/// The export-driven check above only reaches functions that appear in
/// the export table. On an IL2CPP build that is a few hundred runtime
/// helpers out of tens of thousands of compiled game methods, and rhook's
/// normal target is one of the latter -- reached through the runtime
/// catalog, not through exports. Comparing whole sections is the only way
/// to see those hooks.
fn check_text_integrity(
    log: &mut Log,
    handle: HANDLE,
    module_name: &str,
    module_base: usize,
    reference: &Reference<'_>,
    exports: &[remote_pe::RemoteExport],
    seen: &mut Seen,
) -> (usize, usize) {
    let clean = reference.clean;
    let mut total_regions = 0usize;
    let mut total_bytes = 0usize;

    // Read in slices so a 40 MB section does not become one 40 MB
    // allocation plus one enormous cross-process read.
    const CHUNK: usize = 1 << 20;
    /// Differing bytes closer together than this are reported as one
    /// region -- a 14-byte JMP plus its operand is a single event, not
    /// fourteen.
    const COALESCE_GAP: u32 = 32;

    let mut excluded_sections = 0usize;

    for (sec_name, sec_rva, sec_len) in clean.executable_ranges() {
        if in_loader_rewritten(clean, reference.src, sec_rva) {
            excluded_sections += 1;
            log.debug(format!(
                "  text scan: {module_name}!{sec_name} -- {} KB not validated (loader-rewritten section, disk reference unusable)",
                sec_len / 1024
            ));
            continue;
        }
        let mut diffs: Vec<(u32, u32)> = Vec::new(); // (start_rva, end_rva)
        let mut compared = 0usize;
        let mut skipped_reloc = 0usize;
        let mut unreadable = 0usize;

        let mut off = 0usize;
        while off < sec_len {
            let len = CHUNK.min(sec_len - off);
            let rva = sec_rva + off as u32;

            let Some(want) = reference.bytes(rva, len) else {
                unreadable += len;
                off += len;
                continue;
            };
            let Ok(got) = memory::read_bytes(handle, module_base + rva as usize, len) else {
                unreadable += len;
                off += len;
                continue;
            };

            compared += len;
            for i in 0..len {
                if got[i] == want[i] {
                    continue;
                }
                let byte_rva = rva + i as u32;
                if clean.byte_is_relocated(byte_rva) {
                    skipped_reloc += 1;
                    continue;
                }
                match diffs.last_mut() {
                    Some((_, end)) if byte_rva <= *end + COALESCE_GAP => *end = byte_rva,
                    _ => diffs.push((byte_rva, byte_rva)),
                }
            }
            off += len;
        }

        log.debug(format!(
            "  text scan: {module_name}!{sec_name} -- {} KB compared, {} differing region(s), {skipped_reloc} relocation bytes ignored, {} KB unreadable",
            compared / 1024,
            diffs.len(),
            unreadable / 1024
        ));
        total_regions += diffs.len();
        total_bytes += compared;

        for (start, end) in &diffs {
            let len = (end - start + 1) as usize;
            let addr = module_base + *start as usize;
            // Name the nearest preceding export, but only when it is close
            // enough to plausibly own the address. On an IL2CPP build the
            // real owner is almost always a non-exported method, and
            // "after WriteZStream+0x1A2650" names a symbol 1.7 MB away
            // that has nothing to do with the patch -- a hint that
            // actively misleads is worse than no hint.
            const NEAREST_MAX: u32 = 0x1000;
            let nearest = exports
                .iter()
                .filter(|e| e.rva <= *start && !e.forwarded && start - e.rva <= NEAREST_MAX)
                .max_by_key(|e| e.rva)
                .map(|e| format!(" (in {}+0x{:X})", e.name, start - e.rva))
                .unwrap_or_default();

            let want = reference.bytes(*start, len.min(24)).unwrap_or_default();
            let got = memory::read_bytes(handle, addr, len.min(24)).unwrap_or_default();
            let ref_label = reference.label();

            let key = format!("{module_name}!{sec_name}@0x{start:X}");
            let msg = format!(
                "code modified: {module_name}!{sec_name} rva 0x{start:X} @ 0x{addr:X}, {len} byte(s){nearest}\n              {ref_label}: {}\n              in memory: {}",
                hex(&want),
                hex(&got)
            );
            if seen.prologues.insert(key) {
                log.alert(msg);
            } else {
                log.debug(format!("(still modified) {msg}"));
            }
        }
    }

    if excluded_sections > 0 {
        log.debug(format!(
            "  {module_name}: {excluded_sections} loader-rewritten section(s) left unvalidated"
        ));
    }

    (total_regions, total_bytes)
}

fn hex(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalise_exe_name(s: &str) -> String {
    if s.parse::<u32>().is_ok() || s.to_ascii_lowercase().ends_with(".exe") {
        s.to_string()
    } else {
        format!("{s}.exe")
    }
}
