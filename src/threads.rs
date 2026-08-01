// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Thread-origin classification.
//!
//! Every thread has a Win32 start address. A thread whose start address
//! falls outside every mapped module did not come from a normally loaded
//! image — the classic fingerprint of shellcode or a manually mapped DLL.
//!
//! Toolhelp does not expose that address, so this reaches for
//! `NtQueryInformationThread(ThreadQuerySetWin32StartAddress)`, resolved
//! at runtime from `ntdll`. It is undocumented but stable since Windows
//! XP and is what production tools use short of a kernel driver.
//!
//! **What this check does not catch.** `LoadLibrary`-based injection —
//! including rhook's own — produces threads that start *inside* a
//! properly loaded module, because the injected DLL really is in the
//! module list. Those threads are indistinguishable here from legitimate
//! ones; catching that case is the module-baseline check's job. This
//! check earns its place against manual mapping and raw shellcode, where
//! there is no module to point at.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem;

use rhook_common::module::ModuleInfo;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    OpenThread, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
};
use windows::core::s;

/// `THREADINFOCLASS::ThreadQuerySetWin32StartAddress`.
const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;

type NtQueryInformationThreadFn = unsafe extern "system" fn(
    thread: HANDLE,
    info_class: u32,
    info: *mut c_void,
    info_len: u32,
    return_len: *mut u32,
) -> i32;

/// One classified thread.
#[derive(Debug)]
pub struct ThreadOrigin {
    pub tid: u32,
    /// `None` when the start address could not be queried at all.
    pub start: Option<usize>,
    /// Module containing `start`, if any.
    pub module: Option<String>,
    /// Why the query failed, when it did.
    pub error: Option<String>,
}

impl ThreadOrigin {
    /// A thread is foreign when we successfully read a start address and
    /// it belongs to no mapped module. An *unreadable* thread is never
    /// foreign — absence of evidence is not evidence.
    pub fn is_foreign(&self) -> bool {
        self.start.is_some() && self.module.is_none()
    }
}

/// Outcome of a full pass, including whether the primitive was available
/// at all. Callers must distinguish "no foreign threads" from "could not
/// look".
#[derive(Debug)]
pub struct ThreadScan {
    pub threads: Vec<ThreadOrigin>,
    /// False when `NtQueryInformationThread` could not be resolved, which
    /// makes every result in `threads` uninformative.
    pub primitive_available: bool,
}

impl ThreadScan {
    pub fn foreign(&self) -> impl Iterator<Item = &ThreadOrigin> {
        self.threads.iter().filter(|t| t.is_foreign())
    }
    pub fn unreadable(&self) -> usize {
        self.threads.iter().filter(|t| t.start.is_none()).count()
    }
}

fn resolve_nt_query() -> Option<NtQueryInformationThreadFn> {
    // SAFETY: ntdll is mapped into every Win32 process; the symbol is a
    // plain exported function and the signature matches the documented
    // NTAPI shape.
    unsafe {
        let ntdll = GetModuleHandleA(s!("ntdll.dll")).ok()?;
        let proc = GetProcAddress(ntdll, s!("NtQueryInformationThread"))?;
        Some(mem::transmute::<
            unsafe extern "system" fn() -> isize,
            NtQueryInformationThreadFn,
        >(proc))
    }
}

/// Classify every thread of `pid` against `modules`.
pub fn scan(pid: u32, modules: &[ModuleInfo]) -> Result<ThreadScan, String> {
    let Some(nt_query) = resolve_nt_query() else {
        return Ok(ThreadScan {
            threads: Vec::new(),
            primitive_available: false,
        });
    };

    // Sorted ranges would allow a binary search; module counts are in the
    // low hundreds, so a linear scan per thread is not worth optimising.
    let ranges: Vec<(&str, usize, usize)> = modules
        .iter()
        .map(|m| (m.name.as_str(), m.base_address, m.base_address + m.size))
        .collect();
    let owner = |addr: usize| -> Option<String> {
        ranges
            .iter()
            .find(|(_, lo, hi)| addr >= *lo && addr < *hi)
            .map(|(n, _, _)| (*n).to_string())
    };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map_err(|e| format!("thread snapshot: {e}"))?;

    let mut entry = THREADENTRY32 {
        dwSize: mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut threads = Vec::new();

    if unsafe { Thread32First(snap, &mut entry) }.is_ok() {
        loop {
            if entry.th32OwnerProcessID == pid {
                threads.push(classify(nt_query, entry.th32ThreadID, &owner));
            }
            if unsafe { Thread32Next(snap, &mut entry) }.is_err() {
                break;
            }
        }
    }

    let _ = unsafe { CloseHandle(snap) };

    Ok(ThreadScan {
        threads,
        primitive_available: true,
    })
}

fn classify(
    nt_query: NtQueryInformationThreadFn,
    tid: u32,
    owner: &impl Fn(usize) -> Option<String>,
) -> ThreadOrigin {
    // ThreadQuerySetWin32StartAddress wants QUERY_INFORMATION; fall back
    // to the limited right so a partial answer beats none on hardened
    // processes.
    let handle = unsafe { OpenThread(THREAD_QUERY_INFORMATION, false, tid) }
        .or_else(|_| unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) });

    let handle = match handle {
        Ok(h) => h,
        Err(e) => {
            return ThreadOrigin {
                tid,
                start: None,
                module: None,
                error: Some(format!("OpenThread: {e}")),
            };
        }
    };

    let mut start: usize = 0;
    // SAFETY: `start` is a correctly sized, aligned output buffer for the
    // pointer-width value this information class returns.
    let status = unsafe {
        nt_query(
            handle,
            THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &mut start as *mut usize as *mut c_void,
            mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        )
    };
    let _ = unsafe { CloseHandle(handle) };

    if status < 0 {
        return ThreadOrigin {
            tid,
            start: None,
            module: None,
            error: Some(format!("NtQueryInformationThread: NTSTATUS 0x{status:08X}")),
        };
    }

    ThreadOrigin {
        tid,
        module: owner(start),
        start: Some(start),
        error: None,
    }
}

/// Group threads by owning module for a compact log summary.
pub fn by_module(scan: &ThreadScan) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for t in &scan.threads {
        let key = match (&t.module, t.start) {
            (Some(m), _) => m.clone(),
            (None, Some(_)) => "<outside any module>".to_string(),
            (None, None) => "<unreadable>".to_string(),
        };
        *counts.entry(key).or_default() += 1;
    }
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}
