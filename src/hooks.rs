// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Where a hook goes.
//!
//! The integrity check says *that* code changed; this says *where the
//! change sends execution*. That is what separates a cheat from the
//! other software that hooks a game for a living. Run against a modded
//! IL2CPP game with Steam open, the integrity check reports around 300
//! modified regions. More than half belong to the Steam overlay, which
//! hooks input, cursor, window-message and `LoadLibrary` APIs in every
//! game it is injected into. Without a destination, those look exactly
//! like an aimbot's input hooks.
//!
//! An inline hook is a jump, usually reached through one or two
//! intermediate stubs (a trampoline allocated within ±2 GB of the target
//! so a 5-byte `jmp rel32` can reach it, then an absolute jump to the
//! handler). This follows those jumps in the target's memory until it
//! reaches an instruction that is not one, and reports where that is: a
//! listed module, an executable allocation outside every module, or
//! nowhere known.
//!
//! The chain is followed *through* modules, not just to the first one: a
//! hook that bounced off a `jmp` gadget inside a signed DLL would
//! otherwise be credited to that DLL. Only the address where real code
//! starts counts.
//!
//! A chain that passes through a *context-carrying thunk* is never
//! credited to where it ends. CoreCLR's unmanaged-to-managed thunk loads
//! a data pointer into `r10` and jumps to one generic stub inside
//! `coreclr.dll`, which reads the real target from that data at run
//! time. Every Harmony patch on an IL2CPP game ends in that stub, and so
//! would a cheat written in C# on top of BepInEx: crediting the hook to
//! the stub's module would wave all of them through on Microsoft's
//! signature. Observed on TLSA + BepInEx, where it did exactly that to
//! 111 Harmony hooks before this rule existed.
//!
//! Only the jump shapes hook engines actually emit are decoded. Anything
//! else -- a patched `mov`, a `call`-based detour, an `int3` breakpoint
//! hook -- ends the chain at hop zero, and the finding stays an
//! unattributed alert. Failing towards "alert" is the point.

use std::fmt;

use rhook_common::{memory, module::ModuleInfo};
use windows::Win32::Foundation::HANDLE;

use crate::exec_memory::{ExecScan, Kind};

/// Hops followed before giving up. Real chains are one to three long;
/// the bound only exists so a jump loop cannot hang the scan.
const MAX_HOPS: usize = 8;

/// How far before a differing region the jump may start. A region begins
/// at the first byte that *differs*, and a hook's first byte can match
/// the original by chance: `48 B8 imm64` (`mov rax, imm64`) written over
/// a prologue that also starts with a REX.W `48` is reported one byte
/// late.
const MAX_BACKTRACK: usize = 7;

/// Where a chain of jumps ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    /// Inside a listed module.
    Module {
        name: String,
        base: usize,
        addr: usize,
    },
    /// Inside an executable allocation the exec-memory walk found.
    Exec {
        allocation_base: usize,
        kind: Kind,
        addr: usize,
    },
    /// Neither: unmapped, freed since, or not executable.
    Unknown(usize),
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Destination::Module { name, base, addr } => {
                write!(f, "{name}+0x{:X} (0x{addr:X})", addr - base)
            }
            Destination::Exec {
                allocation_base,
                kind,
                addr,
            } => write!(
                f,
                "{} executable memory at 0x{addr:X} (allocation 0x{allocation_base:X})",
                kind.label()
            ),
            Destination::Unknown(addr) => write!(
                f,
                "0x{addr:X}, outside every module and executable allocation"
            ),
        }
    }
}

/// A followed chain.
#[derive(Debug, Clone)]
pub struct Redirect {
    pub dest: Destination,
    /// Jumps followed. Never zero: a region that does not start with a
    /// recognised jump has no `Redirect` at all.
    pub hops: usize,
    /// Some hop loaded a context register for a generic dispatcher, so
    /// `dest` is that dispatcher, not the code that will actually run.
    pub via_thunk: bool,
}

/// One decoded jump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hop {
    target: usize,
    /// The jump also loaded a context register (see the module docs).
    context: bool,
}

/// Decode one jump at `at`, given the bytes there.
///
/// `read_slot` reads the 8-byte pointer of a `jmp [rip+disp32]`.
fn decode(at: usize, b: &[u8], read_slot: impl Fn(usize) -> Option<usize>) -> Option<Hop> {
    let plain = |target: usize| {
        Some(Hop {
            target,
            context: false,
        })
    };
    let imm64 = |o: usize| -> Option<usize> {
        let s: [u8; 8] = b.get(o..o + 8)?.try_into().ok()?;
        Some(u64::from_le_bytes(s) as usize)
    };
    let imm32 = |o: usize| -> Option<u32> {
        let s: [u8; 4] = b.get(o..o + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(s))
    };
    let at_off = |o: usize, want: &[u8]| b.get(o..).is_some_and(|r| r.starts_with(want));
    // `jmp rax` at `o`, with or without a redundant REX.W: CoreCLR's
    // thunks emit `48 FF E0`.
    let jmp_rax = |o: usize| at_off(o, &[0xFF, 0xE0]) || at_off(o, &[0x48, 0xFF, 0xE0]);

    // jmp rel32
    if at_off(0, &[0xE9]) {
        return plain(
            at.wrapping_add(5)
                .wrapping_add_signed(imm32(1)? as i32 as isize),
        );
    }
    // jmp qword ptr [rip+disp32]
    if at_off(0, &[0xFF, 0x25]) {
        return plain(read_slot(
            at.wrapping_add(6)
                .wrapping_add_signed(imm32(2)? as i32 as isize),
        )?);
    }
    // mov rax, imm64 ; jmp rax
    if at_off(0, &[0x48, 0xB8]) && jmp_rax(10) {
        return plain(imm64(2)?);
    }
    // mov r11, imm64 ; jmp r11
    if at_off(0, &[0x49, 0xBB]) && at_off(10, &[0x41, 0xFF, 0xE3]) {
        return plain(imm64(2)?);
    }
    if at_off(0, &[0x49, 0xBA]) {
        // mov r10, imm64 ; jmp r10
        if at_off(10, &[0x41, 0xFF, 0xE2]) {
            return plain(imm64(2)?);
        }
        // mov r10, imm64 ; mov rax, imm64 ; jmp rax -- the CoreCLR
        // unmanaged-to-managed thunk a Harmony patch on IL2CPP ends in.
        // `r10` is the context the generic stub at `rax` dispatches on.
        if at_off(10, &[0x48, 0xB8]) && jmp_rax(20) {
            return Some(Hop {
                target: imm64(12)?,
                context: true,
            });
        }
    }
    // push imm32 ; mov dword ptr [rsp+4], imm32 ; ret
    if at_off(0, &[0x68]) && at_off(5, &[0xC7, 0x44, 0x24, 0x04]) && at_off(13, &[0xC3]) {
        return plain((imm32(9)? as usize) << 32 | imm32(1)? as usize);
    }
    None
}

/// Resolves addresses in the target to the module or allocation that
/// holds them.
pub struct Resolver<'a> {
    handle: HANDLE,
    modules: &'a [ModuleInfo],
    exec: &'a ExecScan,
}

impl<'a> Resolver<'a> {
    pub fn new(handle: HANDLE, modules: &'a [ModuleInfo], exec: &'a ExecScan) -> Self {
        Resolver {
            handle,
            modules,
            exec,
        }
    }

    fn locate(&self, addr: usize) -> Destination {
        if let Some(m) = self
            .modules
            .iter()
            .find(|m| addr >= m.base_address && addr < m.base_address + m.size)
        {
            return Destination::Module {
                name: m.name.clone(),
                base: m.base_address,
                addr,
            };
        }
        if let Some(r) = self.exec.regions.iter().find(|r| r.contains(addr)) {
            return Destination::Exec {
                allocation_base: r.allocation_base,
                kind: r.kind,
                addr,
            };
        }
        Destination::Unknown(addr)
    }

    fn step(&self, at: usize) -> Option<Hop> {
        let bytes = memory::read_bytes(self.handle, at, 24).ok()?;
        decode(at, &bytes, |slot| {
            let p = memory::read_bytes(self.handle, slot, 8).ok()?;
            Some(u64::from_le_bytes(p.try_into().ok()?) as usize)
        })
    }

    /// Follow the jumps starting at `addr`, until the code is not a jump.
    fn follow_from(&self, addr: usize) -> Option<Redirect> {
        let first = self.step(addr)?;
        let mut cur = first.target;
        let mut via_thunk = first.context;
        let mut hops = 1;
        while hops < MAX_HOPS {
            match self.step(cur) {
                Some(next) => {
                    cur = next.target;
                    via_thunk |= next.context;
                    hops += 1;
                }
                None => break,
            }
        }
        Some(Redirect {
            dest: self.locate(cur),
            hops,
            via_thunk,
        })
    }

    /// Where the hook in a region starting at `addr` sends execution.
    ///
    /// Tries the region start and then up to `MAX_BACKTRACK` bytes before
    /// it (see there). A backtracked decode is only accepted when its
    /// first target lands somewhere known: decoding from an arbitrary
    /// byte offset will occasionally "find" a jump in the middle of an
    /// unrelated instruction, and such a jump points at noise.
    pub fn follow(&self, addr: usize) -> Option<Redirect> {
        if let Some(r) = self.follow_from(addr) {
            return Some(r);
        }
        (1..=MAX_BACKTRACK).find_map(|back| {
            let start = addr.checked_sub(back)?;
            let first = self.step(start)?;
            if matches!(self.locate(first.target), Destination::Unknown(_)) {
                return None;
            }
            self.follow_from(start)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_slot(_: usize) -> Option<usize> {
        None
    }

    /// `(target, context)` of the jump at the start of `b`.
    fn hop(at: usize, b: &[u8]) -> Option<(usize, bool)> {
        decode(at, b, no_slot).map(|h| (h.target, h.context))
    }

    #[test]
    fn jmp_rel32_forward_and_backward() {
        assert_eq!(hop(0x1000, &[0xE9, 0x10, 0, 0, 0]), Some((0x1015, false)));
        assert_eq!(
            hop(0x1000, &[0xE9, 0xFB, 0xFF, 0xFF, 0xFF]),
            Some((0x1000, false))
        );
    }

    #[test]
    fn jmp_rip_indirect_reads_the_slot() {
        let b = [0xFF, 0x25, 0, 0, 0, 0];
        let got = decode(0x2000, &b, |slot| {
            assert_eq!(slot, 0x2006);
            Some(0xDEAD_BEEF)
        });
        assert_eq!(
            got.map(|h| (h.target, h.context)),
            Some((0xDEAD_BEEF, false))
        );
    }

    #[test]
    fn mov_reg_imm64_jmp_reg() {
        let mut b = vec![0x48, 0xB8];
        b.extend_from_slice(&0x7FFE_1234_5678u64.to_le_bytes());
        b.extend_from_slice(&[0xFF, 0xE0]);
        assert_eq!(hop(0, &b), Some((0x7FFE_1234_5678, false)));

        let mut b = vec![0x49, 0xBB];
        b.extend_from_slice(&0x1111u64.to_le_bytes());
        b.extend_from_slice(&[0x41, 0xFF, 0xE3]);
        assert_eq!(hop(0, &b), Some((0x1111, false)));
    }

    #[test]
    fn coreclr_thunk_is_a_context_jump_to_the_second_immediate() {
        let mut b = vec![0x49, 0xBA];
        b.extend_from_slice(&0xAAAAu64.to_le_bytes());
        b.extend_from_slice(&[0x48, 0xB8]);
        b.extend_from_slice(&0xBBBBu64.to_le_bytes());
        b.extend_from_slice(&[0xFF, 0xE0]);
        assert_eq!(hop(0, &b), Some((0xBBBB, true)));

        // As observed in a running TLSA + BepInEx: `48 FF E0`.
        let live = [
            0x49, 0xBA, 0x00, 0x38, 0x4B, 0x5D, 0xFE, 0x7F, 0x00, 0x00, 0x48, 0xB8, 0x10, 0x42,
            0x0D, 0x5E, 0xFE, 0x7F, 0x00, 0x00, 0x48, 0xFF, 0xE0,
        ];
        assert_eq!(hop(0, &live), Some((0x7FFE_5E0D_4210, true)));
    }

    #[test]
    fn push_ret_abs64() {
        let b = [
            0x68, 0x78, 0x56, 0x34, 0x12, 0xC7, 0x44, 0x24, 0x04, 0xFE, 0x7F, 0, 0, 0xC3,
        ];
        assert_eq!(hop(0, &b), Some((0x7FFE_1234_5678, false)));
    }

    #[test]
    fn ordinary_code_is_not_a_jump() {
        // push rbp ; sub rsp, 0x60 -- a handler's prologue ends the chain.
        assert_eq!(hop(0, &[0x55, 0x48, 0x83, 0xEC, 0x60]), None);
        // mov rax, imm64 not followed by jmp rax.
        let mut b = vec![0x48, 0xB8];
        b.extend_from_slice(&0x1234u64.to_le_bytes());
        b.extend_from_slice(&[0xC3, 0x90]);
        assert_eq!(hop(0, &b), None);
    }
}
