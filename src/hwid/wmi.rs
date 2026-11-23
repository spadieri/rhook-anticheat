// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The one WMI read this stage needs: the raw SMBIOS table from
//! `root\WMI:MSSmBios_RawSMBiosTables`.
//!
//! The raw table is read rather than `Win32_BaseBoard.SerialNumber` and
//! its siblings so the comparison is byte-for-byte against the
//! firmware-table API's copy, with one parser, instead of trusting `cimwin32`'s formatting of
//! each field to match ours.

use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    CoInitializeSecurity, CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, SAFEARRAY,
};
use windows::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayUnaccessData,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::{VARIANT, VT_ARRAY, VT_I4, VT_UI1, VT_UI4, VariantClear};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    WBEM_INFINITE, WbemLocator,
};
use windows::core::{BSTR, w};

use super::smbios::Table;

/// Balances `CoInitializeEx` only when this call is the one that
/// initialised COM on the thread.
struct ComGuard(bool);

impl Drop for ComGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

/// A `VARIANT` that is cleared on every exit path.
struct Var(VARIANT);

impl Drop for Var {
    fn drop(&mut self) {
        let _ = unsafe { VariantClear(&mut self.0) };
    }
}

fn get(obj: &IWbemClassObject, name: windows::core::PCWSTR) -> Result<Var, String> {
    let mut v = Var(VARIANT::default());
    unsafe { obj.Get(name, 0, &mut v.0, None, None) }.map_err(|e| e.message())?;
    Ok(v)
}

fn get_u8(obj: &IWbemClassObject, name: windows::core::PCWSTR) -> Option<u8> {
    let v = get(obj, name).ok()?;
    // SAFETY: the union member read is the one `vt` names.
    unsafe {
        let inner = &v.0.Anonymous.Anonymous;
        match inner.vt {
            VT_UI1 => Some(inner.Anonymous.bVal),
            VT_I4 => u8::try_from(inner.Anonymous.lVal).ok(),
            VT_UI4 => u8::try_from(inner.Anonymous.ulVal).ok(),
            _ => None,
        }
    }
}

/// Copy a `VT_ARRAY | VT_UI1` property out.
fn get_bytes(obj: &IWbemClassObject, name: windows::core::PCWSTR) -> Result<Vec<u8>, String> {
    let v = get(obj, name)?;
    // SAFETY: `parray` is read only after `vt` says it is a byte array,
    // and the data pointer only between Access and Unaccess.
    unsafe {
        let inner = &v.0.Anonymous.Anonymous;
        if inner.vt != (VT_ARRAY | VT_UI1) {
            return Err(format!("unexpected VARIANT type 0x{:X}", inner.vt.0));
        }
        let psa: *const SAFEARRAY = inner.Anonymous.parray;
        if psa.is_null() {
            return Err("null array".into());
        }
        let lo = SafeArrayGetLBound(psa, 1).map_err(|e| e.message())?;
        let hi = SafeArrayGetUBound(psa, 1).map_err(|e| e.message())?;
        let len = (hi - lo + 1).max(0) as usize;
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut p: *mut core::ffi::c_void = core::ptr::null_mut();
        SafeArrayAccessData(psa, &mut p).map_err(|e| e.message())?;
        if p.is_null() {
            let _ = SafeArrayUnaccessData(psa);
            return Err("null array data".into());
        }
        let out = core::slice::from_raw_parts(p as *const u8, len).to_vec();
        let _ = SafeArrayUnaccessData(psa);
        Ok(out)
    }
}

/// The SMBIOS table as WMI serves it.
pub fn raw_smbios() -> Result<Table, String> {
    unsafe {
        let hr = CoInitializeEx(None, COINIT_MULTITHREADED);
        // RPC_E_CHANGED_MODE: COM is already up on this thread in another
        // apartment, which is fine for a synchronous query, but not ours
        // to tear down.
        let _com = ComGuard(hr.is_ok());

        // Fails with RPC_E_TOO_LATE if anything in the process already set
        // it; the proxy blanket below is what the query actually relies on.
        let _ = CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        );

        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("WbemLocator: {}", e.message()))?;
        let services = locator
            .ConnectServer(
                &BSTR::from(r"ROOT\WMI"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
            .map_err(|e| format!("ROOT\\WMI: {}", e.message()))?;
        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
        .map_err(|e| format!("proxy blanket: {}", e.message()))?;

        let rows = services
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from("SELECT * FROM MSSmBios_RawSMBiosTables"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(|e| format!("query: {}", e.message()))?;

        let mut row = [None];
        let mut returned = 0u32;
        rows.Next(WBEM_INFINITE, &mut row, &mut returned)
            .ok()
            .map_err(|e| format!("query: {}", e.message()))?;
        let Some(obj) = row[0].take().filter(|_| returned == 1) else {
            return Err("MSSmBios_RawSMBiosTables returned no instance".into());
        };

        let data = get_bytes(&obj, w!("SMBiosData"))?;
        Ok(Table {
            major: get_u8(&obj, w!("SmbiosMajorVersion")).unwrap_or(0),
            minor: get_u8(&obj, w!("SmbiosMinorVersion")).unwrap_or(0),
            data,
        })
    }
}
