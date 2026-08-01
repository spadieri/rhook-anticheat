// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Cross-process PE export-table walker.
//!
//! `rhook_common::pe::read_exports` parses a module mapped into the
//! *calling* process — it dereferences raw pointers into the local address
//! space. A defender inspecting somebody else's process cannot do that, so
//! this module re-implements the same walk with every read going through
//! `ReadProcessMemory`.
//!
//! Layout knowledge is identical to `rhook_common::pe`; the difference is
//! purely how bytes are obtained. Keeping the two separate avoids
//! contorting the in-process parser into something generic that serves
//! neither case well.

use rhook_common::memory;
use windows::Win32::Foundation::HANDLE;

const DOS_SIGNATURE: u16 = 0x5A4D; // "MZ"
const NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
const OPT_HDR_MAGIC_PE32PLUS: u16 = 0x20B;

/// One exported symbol, as observed in a remote process.
#[derive(Debug, Clone)]
pub struct RemoteExport {
    pub name: String,
    /// RVA within the module.
    pub rva: u32,
    /// Absolute address in the target process (`module_base + rva`).
    pub address: usize,
    pub ordinal: u16,
    /// Forwarder (`KERNEL32.HeapAlloc` style) — the RVA points back into
    /// the export directory rather than at code, so there is no prologue
    /// to check.
    pub forwarded: bool,
}

/// What the walk found, including the shape of the table itself. The
/// counts matter for diagnosis: "0 exports" and "no export directory"
/// are different states and only one of them is suspicious.
#[derive(Debug)]
pub struct ExportScan {
    pub exports: Vec<RemoteExport>,
    pub export_dir_rva: u32,
    pub export_dir_size: u32,
    pub num_functions: usize,
    pub num_names: usize,
    /// Names the walk had to skip, with the reason — surfaced rather than
    /// silently dropped, because a parser quietly discarding half a table
    /// looks exactly like a module with few exports.
    pub skipped: Vec<String>,
}

fn u16_at(buf: &[u8], off: usize) -> Option<u16> {
    let b = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Bytes of the export-directory region, cached so the walk costs a
/// couple of `ReadProcessMemory` calls instead of one per symbol.
struct ExportRegion {
    base: usize,
    start_rva: u32,
    bytes: Vec<u8>,
}

impl ExportRegion {
    /// Resolve `rva` to a slice of at least `len` bytes, preferring the
    /// cached region and falling back to a targeted remote read for
    /// tables a linker placed outside the advertised directory extent.
    fn slice(&self, handle: HANDLE, rva: u32, len: usize) -> Option<Vec<u8>> {
        if rva >= self.start_rva {
            let off = (rva - self.start_rva) as usize;
            if let Some(b) = self.bytes.get(off..off + len) {
                return Some(b.to_vec());
            }
        }
        memory::read_bytes(handle, self.base + rva as usize, len).ok()
    }

    /// Read a NUL-terminated ASCII string at `rva`.
    fn cstr(&self, handle: HANDLE, rva: u32) -> Option<String> {
        const MAX: usize = 512;
        if rva >= self.start_rva {
            let off = (rva - self.start_rva) as usize;
            if let Some(tail) = self.bytes.get(off..) {
                let end = tail.iter().position(|&c| c == 0)?;
                return std::str::from_utf8(&tail[..end]).ok().map(str::to_owned);
            }
        }
        let buf = memory::read_bytes(handle, self.base + rva as usize, MAX).ok()?;
        let end = buf.iter().position(|&c| c == 0)?;
        std::str::from_utf8(&buf[..end]).ok().map(str::to_owned)
    }
}

/// Walk the export table of `module_base` inside the process behind
/// `handle`.
///
/// Returns `Ok` with an empty export list when the module genuinely has
/// no export directory (most EXEs); `Err` only when the headers do not
/// parse, which means we are not looking at a PE32+ image at all.
pub fn read_exports_remote(handle: HANDLE, module_base: usize) -> Result<ExportScan, String> {
    if module_base == 0 {
        return Err("module base is null".into());
    }

    // DOS header: "MZ" then e_lfanew at 0x3C.
    let dos = memory::read_bytes(handle, module_base, 0x40)
        .map_err(|e| format!("read DOS header: {e}"))?;
    let dos_magic = u16_at(&dos, 0).ok_or("DOS header truncated")?;
    if dos_magic != DOS_SIGNATURE {
        return Err(format!("DOS signature mismatch (got 0x{dos_magic:04X})"));
    }
    let e_lfanew = u32_at(&dos, 0x3C).ok_or("e_lfanew truncated")? as usize;

    // NT headers: signature + FileHeader(20) + OptionalHeader. 0x108 covers
    // the PE32+ optional header through the full DataDirectory array.
    let nt = memory::read_bytes(handle, module_base + e_lfanew, 0x108)
        .map_err(|e| format!("read NT headers: {e}"))?;
    let nt_sig = u32_at(&nt, 0).ok_or("NT signature truncated")?;
    if nt_sig != NT_SIGNATURE {
        return Err(format!("PE signature mismatch (got 0x{nt_sig:08X})"));
    }

    // OptionalHeader = signature(4) + FileHeader(20).
    let opt = 24usize;
    let magic = u16_at(&nt, opt).ok_or("optional header truncated")?;
    if magic != OPT_HDR_MAGIC_PE32PLUS {
        return Err(format!(
            "only PE32+ (x86-64) supported (magic 0x{magic:04X})"
        ));
    }

    // DataDirectory[0] = export table, at OptionalHeader + 0x70.
    let data_dir = opt + 0x70;
    let export_dir_rva = u32_at(&nt, data_dir).ok_or("data directory truncated")?;
    let export_dir_size = u32_at(&nt, data_dir + 4).ok_or("data directory truncated")?;

    if export_dir_rva == 0 || export_dir_size == 0 {
        return Ok(ExportScan {
            exports: Vec::new(),
            export_dir_rva,
            export_dir_size,
            num_functions: 0,
            num_names: 0,
            skipped: Vec::new(),
        });
    }

    // Pull the whole advertised region in one read. Linkers normally place
    // the EAT / ENT / EOT arrays and the name strings inside it, so this
    // one call usually serves the entire walk.
    let region_bytes = memory::read_bytes(
        handle,
        module_base + export_dir_rva as usize,
        export_dir_size as usize,
    )
    .map_err(|e| format!("read export directory: {e}"))?;

    let region = ExportRegion {
        base: module_base,
        start_rva: export_dir_rva,
        bytes: region_bytes,
    };

    // IMAGE_EXPORT_DIRECTORY fields we need.
    let hdr = region
        .slice(handle, export_dir_rva, 0x28)
        .ok_or("export directory header unreadable")?;
    let ordinal_base = u32_at(&hdr, 0x10).ok_or("export header truncated")?;
    let num_functions = u32_at(&hdr, 0x14).ok_or("export header truncated")? as usize;
    let num_names = u32_at(&hdr, 0x18).ok_or("export header truncated")? as usize;
    let eat_rva = u32_at(&hdr, 0x1C).ok_or("export header truncated")?;
    let ent_rva = u32_at(&hdr, 0x20).ok_or("export header truncated")?;
    let eot_rva = u32_at(&hdr, 0x24).ok_or("export header truncated")?;

    // A corrupt or hostile header could claim a table of billions of
    // entries; refuse to allocate on its word alone.
    const SANE_MAX: usize = 1_000_000;
    if num_functions > SANE_MAX || num_names > SANE_MAX {
        return Err(format!(
            "implausible export counts (functions={num_functions}, names={num_names})"
        ));
    }

    let eat = region
        .slice(handle, eat_rva, num_functions * 4)
        .ok_or("export address table unreadable")?;
    let ent = region
        .slice(handle, ent_rva, num_names * 4)
        .ok_or("export name table unreadable")?;
    let eot = region
        .slice(handle, eot_rva, num_names * 2)
        .ok_or("export ordinal table unreadable")?;

    let dir_end = export_dir_rva + export_dir_size;
    let mut exports = Vec::with_capacity(num_names);
    let mut skipped = Vec::new();

    for i in 0..num_names {
        let Some(name_rva) = u32_at(&ent, i * 4) else {
            skipped.push(format!("name[{i}]: ENT entry out of range"));
            continue;
        };
        let Some(func_index) = u16_at(&eot, i * 2).map(usize::from) else {
            skipped.push(format!("name[{i}]: EOT entry out of range"));
            continue;
        };
        if func_index >= num_functions {
            skipped.push(format!(
                "name[{i}]: ordinal {func_index} beyond {num_functions} functions"
            ));
            continue;
        }
        let Some(func_rva) = u32_at(&eat, func_index * 4) else {
            skipped.push(format!("name[{i}]: EAT entry out of range"));
            continue;
        };
        if func_rva == 0 {
            continue; // absent export — normal, not worth reporting
        }
        let Some(name) = region.cstr(handle, name_rva) else {
            skipped.push(format!(
                "name[{i}]: name string at RVA 0x{name_rva:X} unreadable"
            ));
            continue;
        };

        exports.push(RemoteExport {
            name,
            rva: func_rva,
            address: module_base + func_rva as usize,
            ordinal: (func_index as u32 + ordinal_base) as u16,
            forwarded: func_rva >= export_dir_rva && func_rva < dir_end,
        });
    }

    Ok(ExportScan {
        exports,
        export_dir_rva,
        export_dir_size,
        num_functions,
        num_names,
        skipped,
    })
}
