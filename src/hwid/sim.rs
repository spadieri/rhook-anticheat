// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Simulated spoofing, to prove the stage fires. Compiled only with
//! `--features spoof-sim`, and active only when `RHOOK_SPOOF_SIM` names
//! what to alter (comma-separated):
//!
//! | Name     | Altered, in this process's memory only              | Expected            |
//! | -------- | ---------------------------------------------------- | ------------------- |
//! | `smbios` | the system UUID in the firmware-table API's copy      | alert               |
//! | `disk`   | the first disk's serial in the storage descriptor     | alert               |
//! | `mac`    | the first adapter's address as IP Helper reports it   | alert, and a warning against the permanent address |
//! | `cpu`    | the signature CPUID returned                          | warning             |
//!
//! Each one changes the answer of exactly one path after it was read for
//! real, which is what an incomplete spoofer leaves behind. Nothing is
//! written anywhere: the registry, the firmware, the disks and the
//! adapters are only read, as in a normal run.

use super::smbios::Table;

const VAR: &str = "RHOOK_SPOOF_SIM";

pub fn enabled(what: &str) -> bool {
    std::env::var(VAR).is_ok_and(|v| v.split(',').any(|w| w.trim().eq_ignore_ascii_case(what)))
}

/// The names set, for the banner.
pub fn active() -> Vec<&'static str> {
    ["smbios", "disk", "mac", "cpu"]
        .into_iter()
        .filter(|w| enabled(w))
        .collect()
}

/// Flip one bit in the last byte of the system UUID.
pub fn smbios(t: &mut Table) {
    if enabled("smbios")
        && let Some(off) = super::smbios::uuid_offset(t)
    {
        t.data[off + 15] ^= 0x01;
    }
}

/// Change the last hex digit of a serial, keeping it a plausible serial
/// (and, for the NVMe namespace-identifier form, still hex).
pub fn disk_serial(serial: &mut String) {
    if !enabled("disk") {
        return;
    }
    let mut c: Vec<char> = serial.chars().collect();
    if let Some(i) = c.iter().rposition(char::is_ascii_hexdigit) {
        c[i] = if c[i] == '0' { '1' } else { '0' };
        *serial = c.into_iter().collect();
    }
}

pub fn mac(m: &mut [u8; 6]) {
    if enabled("mac") {
        m[5] ^= 0x01;
    }
}

pub fn cpuid(sig: u32) -> u32 {
    if enabled("cpu") { sig ^ 0x01 } else { sig }
}
