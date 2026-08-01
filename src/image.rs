// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The clean on-disk image of a loaded module.
//!
//! Inline-hook detection compares the bytes executing in the target
//! against the bytes the module was built with. The comparison baseline
//! has to come from **disk**, not from the live process: a baseline
//! sampled after attach blesses whatever was already installed, which is
//! exactly the case a scanner exists to catch.
//!
//! Three things make a naive byte-compare produce false alarms, and all
//! three are handled here:
//!
//! - **Section mapping.** On disk a section sits at `PointerToRawData`;
//!   in memory at `VirtualAddress`. The two differ, so every RVA must be
//!   translated before it indexes the file.
//! - **Base relocations.** The loader rewrites absolute addresses baked
//!   into the image when it lands somewhere other than its preferred
//!   base. Those bytes legitimately differ from disk forever after.
//! - **Data exports.** `NvOptimusEnablement` and friends are exported
//!   `DWORD`s, not functions. Comparing them as prologues is meaningless.

use std::collections::HashSet;
use std::mem;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32, Module32First, Module32Next, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};

/// Base address of `module_name` inside *this* process, when it is
/// loaded here too.
///
/// The scanner's own copy makes a far better reference than the file on
/// disk for anything the loader rewrites at load time. Windows patches
/// mapped images through mechanisms base relocations do not describe:
/// the `fothk` function-override thunk section is rewritten wholesale,
/// and ucrtbase retargets its math thunks to a CPU-specific
/// implementation at startup. Compared against disk those read as
/// tampering in every process on the machine. Compared against another
/// process that received the *same* treatment, they cancel, and what
/// survives is specific to the target.
///
/// Only valid when both processes mapped the image at the same base:
/// Windows randomises system-image bases per boot, not per process, so
/// that normally holds — but the caller must check rather than assume,
/// because a mismatch means the relocations differ and every pointer in
/// the image would read as modified.
pub fn own_module_base(module_name: &str) -> Option<usize> {
    let name = std::ffi::CString::new(module_name).ok()?;
    let h = unsafe {
        windows::Win32::System::LibraryLoader::GetModuleHandleA(windows::core::PCSTR(
            name.as_ptr() as *const u8
        ))
    }
    .ok()?;
    if h.0.is_null() {
        None
    } else {
        Some(h.0 as usize)
    }
}

/// Full on-disk path of the module loaded at `module_base` in `pid`.
///
/// `rhook_common::module::ModuleInfo` carries only the base name, and the
/// clean-image comparison needs the actual file, so the toolhelp walk is
/// repeated here for `szExePath`.
///
/// Keyed on the base address, never on the name: Windows happily maps two
/// different files under the same base name -- side-by-side assemblies,
/// MSIX packages and app-local redirection all do it. Observed live, with
/// two `Microsoft.UI.Xaml.dll` of different sizes in one process. Matching
/// by name paired the second one with the first one's file and reported
/// its entire `.text` as modified. The base address is unique by
/// construction; the name is not.
pub fn module_path(pid: u32, module_base: usize) -> Option<String> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }.ok()?;

    let mut entry = MODULEENTRY32 {
        dwSize: mem::size_of::<MODULEENTRY32>() as u32,
        ..Default::default()
    };

    let mut found = None;
    if unsafe { Module32First(snapshot, &mut entry) }.is_ok() {
        loop {
            if entry.modBaseAddr as usize == module_base {
                found = Some(
                    entry
                        .szExePath
                        .iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as u8 as char)
                        .collect(),
                );
                break;
            }
            if unsafe { Module32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    let _ = unsafe { CloseHandle(snapshot) };
    found
}

const NT_SIGNATURE: u32 = 0x0000_4550;
const OPT_HDR_MAGIC_PE32PLUS: u16 = 0x20B;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
/// `IMAGE_REL_BASED_DIR64` — the only relocation type x86-64 images use
/// in practice; it rewrites an 8-byte absolute address.
const IMAGE_REL_BASED_DIR64: u16 = 10;

#[derive(Debug)]
struct Section {
    name: String,
    va: u32,
    vsize: u32,
    raw_ptr: u32,
    raw_size: u32,
    executable: bool,
}

/// A module's file, parsed enough to answer "what should be at this RVA".
pub struct CleanImage {
    pub path: String,
    bytes: Vec<u8>,
    sections: Vec<Section>,
    /// RVAs the loader patches, sorted. Each covers 8 bytes.
    reloc_sites: Vec<u32>,
    pub reloc_count: usize,
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl CleanImage {
    pub fn load(path: &str) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;

        let e_lfanew = u32_at(&bytes, 0x3C).ok_or("truncated DOS header")? as usize;
        if u32_at(&bytes, e_lfanew).ok_or("truncated NT header")? != NT_SIGNATURE {
            return Err("PE signature mismatch on disk image".into());
        }

        // FileHeader sits right after the 4-byte signature.
        let file_hdr = e_lfanew + 4;
        let num_sections = u16_at(&bytes, file_hdr + 2).ok_or("truncated file header")? as usize;
        let opt_hdr_size = u16_at(&bytes, file_hdr + 16).ok_or("truncated file header")? as usize;
        let opt_hdr = file_hdr + 20;

        if u16_at(&bytes, opt_hdr).ok_or("truncated optional header")? != OPT_HDR_MAGIC_PE32PLUS {
            return Err("on-disk image is not PE32+".into());
        }

        // Section table follows the optional header.
        let sec_table = opt_hdr + opt_hdr_size;
        let mut sections = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let s = sec_table + i * 40;
            let raw_name = bytes.get(s..s + 8).ok_or("truncated section table")?;
            let name: String = raw_name
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as char)
                .collect();
            sections.push(Section {
                name,
                vsize: u32_at(&bytes, s + 0x08).ok_or("truncated section")?,
                va: u32_at(&bytes, s + 0x0C).ok_or("truncated section")?,
                raw_size: u32_at(&bytes, s + 0x10).ok_or("truncated section")?,
                raw_ptr: u32_at(&bytes, s + 0x14).ok_or("truncated section")?,
                executable: u32_at(&bytes, s + 0x24).ok_or("truncated section")?
                    & IMAGE_SCN_MEM_EXECUTE
                    != 0,
            });
        }

        // DataDirectory[5] = base relocation table.
        let data_dir = opt_hdr + 0x70;
        let reloc_rva = u32_at(&bytes, data_dir + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8).unwrap_or(0);
        let reloc_size =
            u32_at(&bytes, data_dir + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4).unwrap_or(0);

        let mut img = CleanImage {
            path: path.to_string(),
            bytes,
            sections,
            reloc_sites: Vec::new(),
            reloc_count: 0,
        };
        img.parse_relocs(reloc_rva, reloc_size);
        Ok(img)
    }

    fn parse_relocs(&mut self, reloc_rva: u32, reloc_size: u32) {
        if reloc_rva == 0 || reloc_size == 0 {
            return;
        }
        let Some(base) = self.rva_to_offset(reloc_rva) else {
            return;
        };
        let end = base + reloc_size as usize;
        let mut cur = base;
        let mut sites = HashSet::new();

        // Blocks of { u32 PageRVA; u32 BlockSize; u16 entries[] }.
        while cur + 8 <= end && cur + 8 <= self.bytes.len() {
            let Some(page_rva) = u32_at(&self.bytes, cur) else {
                break;
            };
            let Some(block_size) = u32_at(&self.bytes, cur + 4) else {
                break;
            };
            if block_size < 8 {
                break; // malformed; refuse to spin
            }
            let entries = (block_size as usize - 8) / 2;
            for i in 0..entries {
                let Some(raw) = u16_at(&self.bytes, cur + 8 + i * 2) else {
                    break;
                };
                if (raw >> 12) == IMAGE_REL_BASED_DIR64 {
                    sites.insert(page_rva + (raw & 0x0FFF) as u32);
                }
            }
            cur += block_size as usize;
        }

        self.reloc_count = sites.len();
        let mut v: Vec<u32> = sites.into_iter().collect();
        v.sort_unstable();
        self.reloc_sites = v;
    }

    fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for s in &self.sections {
            if rva >= s.va && rva < s.va + s.vsize.max(s.raw_size) {
                let delta = rva - s.va;
                if delta >= s.raw_size {
                    return None; // in the zero-filled tail, nothing on disk
                }
                return Some((s.raw_ptr + delta) as usize);
            }
        }
        None
    }

    /// The bytes the linker wrote at `rva`, or `None` when the RVA has no
    /// on-disk backing (uninitialised data, or outside every section).
    pub fn slice_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let off = self.rva_to_offset(rva)?;
        self.bytes.get(off..off + len)
    }

    /// Whether `rva` lands in a section marked executable — the only
    /// place a function prologue can be.
    pub fn is_executable(&self, rva: u32) -> bool {
        self.sections
            .iter()
            .any(|s| s.executable && rva >= s.va && rva < s.va + s.vsize.max(s.raw_size))
    }

    /// Section name containing `rva`, for diagnostics.
    pub fn section_of(&self, rva: u32) -> Option<&str> {
        self.sections
            .iter()
            .find(|s| rva >= s.va && rva < s.va + s.vsize.max(s.raw_size))
            .map(|s| s.name.as_str())
    }

    /// True when `[rva, rva+len)` touches any 8-byte relocation site, in
    /// which case the loader is expected to have rewritten those bytes
    /// and a mismatch proves nothing.
    pub fn overlaps_reloc(&self, rva: u32, len: usize) -> bool {
        let lo = rva.saturating_sub(7);
        let hi = rva + len as u32;
        // First site that could still reach into the window.
        let idx = self.reloc_sites.partition_point(|&r| r < lo);
        matches!(self.reloc_sites.get(idx), Some(&r) if r < hi)
    }

    pub fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Executable sections as `(name, rva, length)`, clamped to what the
    /// file actually contains. Whole-section comparison is what catches
    /// hooks on functions that are not exported -- which, on an IL2CPP
    /// build, is essentially all of the game's own code.
    pub fn executable_ranges(&self) -> Vec<(String, u32, usize)> {
        self.sections
            .iter()
            .filter(|s| s.executable && s.raw_size > 0)
            .map(|s| {
                let len = s.vsize.min(s.raw_size).max(1) as usize;
                (s.name.clone(), s.va, len)
            })
            .collect()
    }

    /// Whether a single byte at `rva` sits inside a relocation site.
    /// Cheap enough to call only on a mismatch.
    pub fn byte_is_relocated(&self, rva: u32) -> bool {
        let lo = rva.saturating_sub(7);
        let idx = self.reloc_sites.partition_point(|&r| r < lo);
        matches!(self.reloc_sites.get(idx), Some(&r) if r <= rva)
    }
}
