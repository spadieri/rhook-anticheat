// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Executable memory that does not belong to a loaded image.
//!
//! The other checks all start from the module list: they compare what a
//! module *should* contain against what it does. Code that was never a
//! module -- a manually mapped DLL, shellcode, a detour's trampoline --
//! sits outside that list entirely, and if it runs on a thread it
//! borrowed (APC, hijacked context, a callback it registered) the thread
//! check cannot see it either.
//!
//! This walks the whole user address space with `VirtualQueryEx` and
//! reports two shapes:
//!
//! - **Private or mapped executable memory** (`MEM_PRIVATE` / `MEM_MAPPED`
//!   with an `EXECUTE` protection). A plain IL2CPP game has none: it
//!   compiles ahead of time and never generates code. Every such region
//!   is either a JIT (Mono, CLR, a browser engine), a hook trampoline
//!   (overlays install them too), or injected code. The scanner cannot
//!   tell those apart, so it reports them all with their bytes and lets
//!   the reader judge.
//! - **Image mappings missing from the module list** (`MEM_IMAGE` whose
//!   allocation base is not any listed module). The loader links every
//!   image it maps; an image the module list does not know about was
//!   either unlinked after loading to hide it, or mapped as an image
//!   section by hand.

use std::collections::HashSet;
use std::mem;

use rhook_common::{memory, module::ModuleInfo};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_GUARD,
    PAGE_NOACCESS, VirtualQueryEx,
};

/// `PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
/// PAGE_EXECUTE_WRITECOPY`.
const EXECUTE_MASK: u32 = 0x10 | 0x20 | 0x40 | 0x80;
/// Writable and executable at once: what an unsophisticated injector
/// allocates, and what a JIT avoids on a modern system.
const WRITE_EXECUTE_MASK: u32 = 0x40 | 0x80;
/// Top of the x86-64 user address space on Windows.
const USER_SPACE_END: usize = 0x7FFF_FFFF_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `MEM_PRIVATE`: `VirtualAlloc`-style memory.
    Private,
    /// `MEM_MAPPED`: a non-image file or pagefile section.
    Mapped,
    /// `MEM_IMAGE` whose allocation base is not in the module list.
    UnlistedImage,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Private => "private",
            Kind::Mapped => "mapped",
            Kind::UnlistedImage => "image not in module list",
        }
    }
}

/// One executable allocation, its regions coalesced by allocation base.
#[derive(Debug, Clone)]
pub struct ExecRegion {
    pub allocation_base: usize,
    /// First executable byte inside the allocation.
    pub first_exec: usize,
    /// Executable bytes in the allocation (not its total size).
    pub exec_bytes: usize,
    pub kind: Kind,
    /// Any page in the allocation is writable as well as executable.
    pub writable: bool,
    /// Up to 16 bytes from `first_exec`, empty when unreadable.
    pub head: Vec<u8>,
}

impl ExecRegion {
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.first_exec && addr < self.first_exec + self.exec_bytes
    }
}

/// Result of a full address-space walk.
#[derive(Debug, Default)]
pub struct ExecScan {
    pub regions: Vec<ExecRegion>,
    /// Committed executable bytes inside listed modules -- the expected
    /// case, counted so the summary shows the walk really happened.
    pub image_exec_bytes: usize,
    /// Regions `VirtualQueryEx` described, of any kind.
    pub regions_walked: usize,
    /// Set when the walk stopped early, so coverage is partial.
    pub stopped_at: Option<usize>,
}

/// Walk the address space of the process behind `handle`.
pub fn scan(handle: HANDLE, modules: &[ModuleInfo]) -> ExecScan {
    let bases: HashSet<usize> = modules.iter().map(|m| m.base_address).collect();
    let mut out = ExecScan::default();
    let mut addr = 0usize;

    while addr < USER_SPACE_END {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: `mbi` is a correctly sized output buffer; the address is
        // only a query key and is never dereferenced locally.
        let got = unsafe {
            VirtualQueryEx(
                handle,
                Some(addr as *const _),
                &mut mbi,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if got == 0 {
            // End of the address space, or a handle without
            // PROCESS_QUERY_INFORMATION. Only the second is a gap.
            if addr < 0x7FF0_0000_0000 {
                out.stopped_at = Some(addr);
            }
            break;
        }
        out.regions_walked += 1;

        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let next = base.saturating_add(size);
        if next <= addr {
            out.stopped_at = Some(addr); // would loop forever
            break;
        }
        addr = next;

        let protect = mbi.Protect.0;
        let executable = mbi.State == MEM_COMMIT
            && protect & EXECUTE_MASK != 0
            && protect & PAGE_GUARD.0 == 0
            && protect & PAGE_NOACCESS.0 == 0;
        if !executable {
            continue;
        }

        let alloc = mbi.AllocationBase as usize;
        let kind = if mbi.Type == MEM_IMAGE {
            if bases.contains(&alloc) {
                out.image_exec_bytes += size;
                continue;
            }
            Kind::UnlistedImage
        } else if mbi.Type == MEM_PRIVATE {
            Kind::Private
        } else if mbi.Type == MEM_MAPPED {
            Kind::Mapped
        } else {
            continue;
        };
        let writable = protect & WRITE_EXECUTE_MASK != 0;

        match out.regions.last_mut() {
            Some(r) if r.allocation_base == alloc && r.kind == kind => {
                r.exec_bytes = base + size - r.first_exec;
                r.writable |= writable;
            }
            _ => out.regions.push(ExecRegion {
                allocation_base: alloc,
                first_exec: base,
                exec_bytes: size,
                kind,
                writable,
                head: memory::read_bytes(handle, base, 16.min(size)).unwrap_or_default(),
            }),
        }
    }

    out
}
