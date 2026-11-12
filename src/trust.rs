// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Where a module came from, and whether anyone vouches for it.
//!
//! The module check in `main` compares names against a baseline taken at
//! attach, which blesses anything loaded before the scanner started --
//! including the most common way mods and cheats get into a Unity game: a
//! *proxy DLL*. Drop `version.dll` or `winhttp.dll` next to the game's
//! executable and the loader's search order picks it up before the real
//! one in `System32`, on every launch, before any scanner can attach.
//!
//! A name cannot catch that; the file can. Each module is classified by
//! where its file lives and checked in up to three ways:
//!
//! - **Shadowing** -- a module outside the Windows directory whose file
//!   name also exists in `System32`. Games do legitimately ship app-local
//!   copies of system-provided libraries (the VC++ runtime, `d3dcompiler`),
//!   but those are signed by their vendor. An *unsigned* file shadowing a
//!   system DLL is the proxy-DLL pattern.
//! - **Authenticode** -- `WinVerifyTrust` on the file's embedded
//!   signature. A valid signature says who built the file, not that it is
//!   harmless: anyone can buy a code-signing certificate.
//! - **Manifest** -- the game's own files, hashed from a clean install
//!   (`--write-manifest`) and checked on every scan (`--manifest`). This
//!   is what a game ships: an unsigned `GameAssembly.dll` is normal, a
//!   `GameAssembly.dll` whose hash moved is not. The manifest file itself
//!   is only as trustworthy as where it is kept -- a real deployment signs
//!   it, or keeps it on the server.
//!
//! Files under the Windows directory are trusted by location: they are
//! owned by TrustedInstaller and are, for the most part, catalog-signed
//! rather than carrying an embedded signature `WinVerifyTrust` could see.
//! That is a stated gap, not an oversight.

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
};
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows::Win32::System::Threading::{PROCESS_NAME_WIN32, QueryFullProcessImageNameW};
use windows::core::{PCWSTR, PWSTR};

/// Where a module's file lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// Under the Windows directory (System32, SysWOW64, WinSxS...).
    System,
    /// Under the directory of the target's executable.
    Game,
    /// Anywhere else: another program's install, a user folder, a temp dir.
    Other,
}

/// Outcome of `WinVerifyTrust`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    Valid,
    /// No embedded signature (`TRUST_E_NOSIGNATURE` and relatives).
    Unsigned,
    /// A signature is present but does not verify: tampered file,
    /// untrusted root, expired without a timestamp. Carries the HRESULT.
    Invalid(i32),
}

/// Outcome of the manifest lookup for a game-directory file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestCheck {
    /// No manifest was supplied.
    NotChecked,
    Match,
    /// The file is in the game directory but not in the manifest.
    Unknown,
    /// Listed, but the hash on disk differs.
    Mismatch,
    /// The file could not be read for hashing.
    Unreadable(String),
}

/// Everything known about one module file.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub location: Location,
    /// `None` for system files, which are not checked.
    pub signature: Option<Signature>,
    /// The file name also exists in `System32`.
    pub shadows_system: bool,
    pub manifest: ManifestCheck,
}

impl Verdict {
    pub fn signed(&self) -> bool {
        self.signature == Some(Signature::Valid)
    }
}

/// Classifies module files, caching verdicts per path: verifying a
/// signature and hashing a 100 MB `GameAssembly.dll` every two seconds in
/// `--watch` would dominate the scan for no new information -- a mapped
/// image cannot change underneath the process that maps it.
pub struct Trust {
    windows_dir: String,
    system_dir: PathBuf,
    game_dir: Option<String>,
    manifest: Option<HashMap<String, String>>,
    cache: HashMap<String, Verdict>,
}

/// Lower-cased, backslash-separated, so prefix tests are reliable.
fn norm(p: &str) -> String {
    p.replace('/', "\\").to_ascii_lowercase()
}

fn with_trailing_sep(mut s: String) -> String {
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

fn wide_buf_to_string(buf: &[u16], len: usize) -> String {
    String::from_utf16_lossy(&buf[..len.min(buf.len())])
}

fn windows_dir() -> String {
    let mut buf = [0u16; 512];
    let n = unsafe { GetWindowsDirectoryW(Some(&mut buf)) } as usize;
    wide_buf_to_string(&buf, n)
}

fn system_dir() -> String {
    let mut buf = [0u16; 512];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    wide_buf_to_string(&buf, n)
}

/// Full path of the target's executable.
pub fn process_image_path(handle: HANDLE) -> Option<String> {
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    }
    .ok()?;
    Some(wide_buf_to_string(&buf, len as usize))
}

/// `WinVerifyTrust` on the embedded signature, without UI and without
/// network access: revocation is not checked, and URL retrieval is
/// limited to the local cache so a scan never stalls on a CRL download.
pub fn verify_signature(path: &str) -> Signature {
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `data` and `file` outlive both calls, `wide` is
    // NUL-terminated, and the state opened by VERIFY is released by CLOSE
    // on the same structure.
    let status = unsafe {
        let s = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(HWND::default(), &mut action, &mut data as *mut _ as *mut _);
        s
    };

    // TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN,
    // TRUST_E_PROVIDER_UNKNOWN: "nothing to verify", not "verification
    // failed".
    const NO_SIGNATURE: [u32; 3] = [0x800B_0100, 0x800B_0003, 0x800B_0001];
    match status {
        0 => Signature::Valid,
        s if NO_SIGNATURE.contains(&(s as u32)) => Signature::Unsigned,
        s => Signature::Invalid(s),
    }
}

/// SHA-256 of a file, lower-case hex.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Read a manifest: one `<sha256>  <path relative to the game directory>`
/// per line, `#` comments allowed. Paths are normalised on load.
pub fn load_manifest(path: &str) -> Result<HashMap<String, String>, String> {
    let f = fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut map = HashMap::new();
    for (n, line) in io::BufReader::new(f).lines().enumerate() {
        let line = line.map_err(|e| format!("{path}:{}: {e}", n + 1))?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((hash, rel)) = line.split_once(char::is_whitespace) else {
            return Err(format!("{path}:{}: expected '<sha256> <path>'", n + 1));
        };
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("{path}:{}: not a SHA-256: {hash}", n + 1));
        }
        map.insert(norm(rel.trim()), hash.to_ascii_lowercase());
    }
    Ok(map)
}

/// Hash every `.dll` and `.exe` under `game_dir` into a manifest file.
/// Returns how many files were written.
pub fn write_manifest(game_dir: &Path, out: &str) -> Result<usize, String> {
    let mut files = Vec::new();
    let mut stack = vec![game_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("dll") || e.eq_ignore_ascii_case("exe"))
            {
                files.push(p);
            }
        }
    }
    files.sort();

    let mut f = fs::File::create(out).map_err(|e| format!("create {out}: {e}"))?;
    writeln!(
        f,
        "# rhook-anticheat manifest: sha256 and path relative to {}",
        game_dir.display()
    )
    .map_err(|e| e.to_string())?;
    for p in &files {
        let hash = sha256_file(p).map_err(|e| format!("hash {}: {e}", p.display()))?;
        let rel = p.strip_prefix(game_dir).unwrap_or(p);
        writeln!(f, "{hash}  {}", rel.display()).map_err(|e| e.to_string())?;
    }
    Ok(files.len())
}

impl Trust {
    /// `game_dir` is the directory of the target's executable, when it
    /// could be determined.
    pub fn new(game_dir: Option<String>, manifest: Option<HashMap<String, String>>) -> Self {
        Trust {
            windows_dir: with_trailing_sep(norm(&windows_dir())),
            system_dir: PathBuf::from(system_dir()),
            game_dir: game_dir.map(|d| with_trailing_sep(norm(&d))),
            manifest,
            cache: HashMap::new(),
        }
    }

    pub fn has_manifest(&self) -> bool {
        self.manifest.is_some()
    }

    fn locate(&self, path: &str) -> Location {
        let p = norm(path);
        if p.starts_with(&self.windows_dir) {
            Location::System
        } else if self.game_dir.as_ref().is_some_and(|g| p.starts_with(g)) {
            Location::Game
        } else {
            Location::Other
        }
    }

    fn check_manifest(&self, path: &str) -> ManifestCheck {
        let (Some(manifest), Some(game_dir)) = (&self.manifest, &self.game_dir) else {
            return ManifestCheck::NotChecked;
        };
        let rel = norm(path)[game_dir.len()..].to_string();
        let Some(want) = manifest.get(&rel) else {
            return ManifestCheck::Unknown;
        };
        match sha256_file(Path::new(path)) {
            Ok(got) if &got == want => ManifestCheck::Match,
            Ok(_) => ManifestCheck::Mismatch,
            Err(e) => ManifestCheck::Unreadable(e.to_string()),
        }
    }

    /// Classify the file behind a module, from cache when already seen.
    pub fn verdict(&mut self, path: &str) -> &Verdict {
        let key = norm(path);
        if !self.cache.contains_key(&key) {
            let location = self.locate(path);
            let v = if location == Location::System {
                Verdict {
                    location,
                    signature: None,
                    shadows_system: false,
                    manifest: ManifestCheck::NotChecked,
                }
            } else {
                let file_name = Path::new(path).file_name();
                Verdict {
                    location,
                    signature: Some(verify_signature(path)),
                    shadows_system: file_name.is_some_and(|n| self.system_dir.join(n).is_file()),
                    manifest: if location == Location::Game {
                        self.check_manifest(path)
                    } else {
                        ManifestCheck::NotChecked
                    },
                }
            };
            self.cache.insert(key.clone(), v);
        }
        &self.cache[&key]
    }
}
