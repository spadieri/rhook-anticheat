// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Hardware identity -- is something lying about it?
//!
//! Hardware bans are built on a handful of identifiers: the SMBIOS UUID
//! and serials of the board, chassis and memory, each disk's serial, each
//! network adapter's MAC. A *spoofer* rewrites what Windows reports for
//! them, so a banned player looks like a new machine.
//!
//! This stage does not identify the machine. It never stores or sends a
//! value, and masks every one it prints that could identify the machine.
//! It asks a different
//! question: **do the different ways of reading the same identifier
//! agree?** On an honest machine they do. A spoofer that hooks one path
//! and forgets another disagrees with itself, and that disagreement is
//! visible from user mode without knowing anything about the spoofer:
//!
//! - SMBIOS: the firmware-table API and WMI (`smbios`, `wmi`).
//! - Disks: the storage descriptor, and the drive's IDENTIFY data fetched
//!   now (`disks`).
//! - Network: the current MAC from IP Helper and from the driver, the
//!   permanent MAC, and the registry override (`nics`).
//! - CPU: SMBIOS type 4's ProcessorID against the processor's own
//!   CPUID. ProcessorID is not an identity -- every CPU of a model and
//!   stepping shares it -- but tools sold as "HWID changers" rewrite it.
//!
//! A *complete* spoofer -- one that answers every path consistently, or
//! patches the firmware table before Windows reads it -- passes. So does
//! one that changes the hardware itself. This is a check for incomplete
//! spoofers, and the summary says which paths it could not compare.
//!
//! Severity: two answers for the *same* datum that disagree are an alert,
//! because no honest configuration produces them. A difference with an
//! honest explanation (a MAC set in the adapter's properties, a CPUID
//! signature a hypervisor masks) is a warning or a note.

mod disks;
mod nics;
#[cfg(feature = "spoof-sim")]
mod sim;
mod smbios;
mod wmi;

use std::collections::BTreeMap;

use crate::log::Log;
use smbios::{Field, FieldKind, Table};

/// Values firmware vendors ship in place of a real serial. A field holding
/// one cannot identify the machine -- which is common on retail boards and
/// also what a lazy spoofer writes.
const PLACEHOLDERS: &[&str] = &[
    "default string",
    "to be filled by o.e.m.",
    "to be filled by oem",
    "system serial number",
    "base board serial number",
    "chassis serial number",
    "not specified",
    "not applicable",
    "not available",
    "none",
    "n/a",
    "oem",
    "o.e.m.",
    "unknown",
    "serial",
    "serialnumber",
    "0123456789",
    "123456789",
    "1234567890",
    "03000200-0400-0500-0006-000700080009", // a common AMI template UUID
];

pub fn placeholder(v: &str) -> bool {
    let t = v.trim().to_ascii_lowercase();
    if t.is_empty() || PLACEHOLDERS.contains(&t.as_str()) {
        return true;
    }
    // "00000000", "FFFFFFFF-FFFF-...", "xxxxxxxx": one character repeated.
    let mut chars = t
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '_' | '.' | ':'));
    match chars.next() {
        None => true,
        Some(first) => chars.all(|c| c == first),
    }
}

/// Enough of a value to tell two apart in a log, not enough to rebuild
/// it: the first and last two characters.
pub fn mask(v: &str) -> String {
    let c: Vec<char> = v.chars().collect();
    if c.len() <= 6 {
        return "*".repeat(c.len());
    }
    let head: String = c[..2].iter().collect();
    let tail: String = c[c.len() - 2..].iter().collect();
    format!(
        "{head}{}{tail} ({} chars)",
        "*".repeat(c.len() - 4),
        c.len()
    )
}

/// "the first difference at character N", for two masked values that may
/// differ only where the mask hides.
fn first_diff(a: &str, b: &str) -> String {
    match a.chars().zip(b.chars()).position(|(x, y)| x != y) {
        Some(i) => format!("first difference at character {}", i + 1),
        None => format!(
            "same prefix, lengths {} and {}",
            a.chars().count(),
            b.chars().count()
        ),
    }
}

/// Show a value: masked when it could identify the machine, as is when it
/// is a placeholder or a CPU signature everyone with that CPU shares.
fn show(f: &Field) -> String {
    if f.kind == FieldKind::ProcessorId || placeholder(&f.value) {
        format!("\"{}\"", f.value)
    } else {
        mask(&f.value)
    }
}

pub fn check(log: &mut Log) {
    #[cfg(feature = "spoof-sim")]
    {
        let on = sim::active();
        if on.is_empty() {
            log.info("spoof-sim build, RHOOK_SPOOF_SIM not set: nothing is simulated");
        } else {
            log.warn(format!(
                "spoof-sim: simulating a spoofer on {} -- the findings for those are simulated; nothing on this machine was changed",
                on.join(", ")
            ));
        }
    }
    check_smbios(log);
    check_disks(log);
    check_nics(log);
}

// ---- SMBIOS ----------------------------------------------------------

fn check_smbios(log: &mut Log) {
    #[allow(unused_mut)]
    let mut firmware = smbios::from_firmware_api();
    #[cfg(feature = "spoof-sim")]
    if let Ok(t) = &mut firmware {
        sim::smbios(t);
    }
    let views: [(&str, Result<Table, String>); 2] = [
        ("the firmware-table API", firmware),
        ("WMI", wmi::raw_smbios()),
    ];

    let mut read: Vec<(&str, Table, BTreeMap<String, Field>)> = Vec::new();
    for (name, view) in views {
        match view {
            Ok(t) => {
                let fields = smbios::identity_fields(&t)
                    .into_iter()
                    .map(|f| (f.key.clone(), f))
                    .collect();
                log.debug(format!(
                    "  smbios: {name}: SMBIOS {}.{}, {} byte(s)",
                    t.major,
                    t.minor,
                    t.data.len()
                ));
                read.push((name, t, fields));
            }
            Err(e) => log.warn(format!(
                "smbios: {name} could not be read, so it was NOT compared: {e}"
            )),
        }
    }
    let Some(((ref_name, ref_table, ref_fields), others)) = read.split_first() else {
        log.warn("smbios: no view of the table could be read, nothing was checked");
        return;
    };

    for f in ref_fields.values() {
        log.debug(format!("  smbios: {} = {}", f.key, show(f)));
    }

    let mut disagreements = 0;
    for (name, table, fields) in others {
        if table.data == ref_table.data {
            log.debug(format!("  smbios: {name} is byte-identical to {ref_name}"));
            continue;
        }
        let mut keys: Vec<&String> = ref_fields.keys().chain(fields.keys()).collect();
        keys.sort();
        keys.dedup();
        let mut field_diffs = 0;
        for key in keys {
            match (ref_fields.get(key), fields.get(key)) {
                (Some(a), Some(b)) if a.value == b.value => {}
                (Some(a), Some(b)) => {
                    field_diffs += 1;
                    log.alert(format!(
                        "smbios: {key} differs -- {ref_name} says {}, {name} says {} ({})",
                        show(a),
                        show(b),
                        first_diff(&a.value, &b.value)
                    ));
                }
                (Some(_), None) => {
                    field_diffs += 1;
                    log.alert(format!(
                        "smbios: {key} is in {ref_name} but missing from {name}"
                    ));
                }
                (None, Some(_)) => {
                    field_diffs += 1;
                    log.alert(format!(
                        "smbios: {key} is in {name} but missing from {ref_name}"
                    ));
                }
                (None, None) => unreachable!(),
            }
        }
        if field_diffs == 0 {
            let n = ref_table
                .data
                .iter()
                .zip(&table.data)
                .filter(|(a, b)| a != b)
                .count()
                + ref_table.data.len().abs_diff(table.data.len());
            log.debug(format!(
                "  smbios: {name} differs from {ref_name} in {n} byte(s), none of them in an identity field"
            ));
        }
        disagreements += field_diffs;
    }

    let serials = ref_fields
        .values()
        .filter(|f| f.kind == FieldKind::Serial)
        .count();
    log.info(format!(
        "smbios: {serials} identity field(s) in {} view(s) of the table, {disagreements} disagreement(s)",
        read.len()
    ));
    if read.len() < 2 {
        log.warn("smbios: only one view could be read, so nothing was cross-checked");
    }

    for f in ref_fields.values() {
        if f.kind == FieldKind::Serial && placeholder(&f.value) {
            log.info(format!(
                "smbios: {} is a placeholder ({}), so it cannot identify this machine -- normal on many retail boards",
                f.key,
                show(f)
            ));
        }
    }

    // ---- CPU: SMBIOS ProcessorID against CPUID --------------------------
    let cpuid = smbios::cpuid_signature();
    #[cfg(feature = "spoof-sim")]
    let cpuid = sim::cpuid(cpuid);
    for f in ref_fields
        .values()
        .filter(|f| f.kind == FieldKind::ProcessorId)
    {
        match smbios::signature_of(&f.value) {
            Some(sig) if sig == cpuid => log.info(format!(
                "cpu: {} carries signature 0x{sig:08X}, the same as CPUID",
                f.key
            )),
            Some(sig) => log.warn(format!(
                "cpu: {} carries signature 0x{sig:08X}, CPUID says 0x{cpuid:08X} -- the firmware table was edited, or a hypervisor masks CPUID",
                f.key
            )),
            None => log.debug(format!("  cpu: {} is not 8 bytes of hex", f.key)),
        }
    }
}

// ---- disks -----------------------------------------------------------

fn check_disks(log: &mut Log) {
    let found = disks::scan();
    let (mut agree, mut disagree, mut unchecked) = (0, 0, 0);
    for d in &found {
        let what = format!("disk {} ({}, {})", d.index, d.bus, d.model);
        let serial = d.serial.as_deref().unwrap_or("");
        let shown = if placeholder(serial) {
            format!("\"{serial}\"")
        } else {
            mask(serial)
        };
        match &d.second {
            disks::Second::Agree => {
                agree += 1;
                log.debug(format!(
                    "  {what}: serial {shown}, the drive's IDENTIFY data agrees"
                ));
            }
            disks::Second::Disagree(other) => {
                disagree += 1;
                log.alert(format!(
                    "{what}: the storage descriptor reports serial {shown}, the drive itself says {} ({})",
                    mask(other),
                    first_diff(serial, other)
                ));
            }
            disks::Second::NotChecked(why) => {
                unchecked += 1;
                log.debug(format!(
                    "  {what}: serial {shown}, NOT cross-checked: {why}"
                ));
            }
        }
        if d.serial.is_some() && placeholder(serial) {
            log.info(format!("{what}: serial is a placeholder ({shown})"));
        }
    }
    log.info(format!(
        "disks: {} examined, {agree} agree with the drive, {disagree} disagree, {unchecked} not cross-checked",
        found.len()
    ));
    if unchecked > 0 {
        log.warn(format!(
            "disks: {unchecked} disk(s) could not be cross-checked, coverage is incomplete (see --verbose)"
        ));
    }
}

// ---- network adapters ------------------------------------------------

/// The manufacturer prefix and the last byte; the rest hidden.
fn mask_mac(m: &nics::Mac) -> String {
    let s = nics::fmt(m);
    format!("{}-**-**-{}", &s[..8], &s[15..])
}

fn check_nics(log: &mut Log) {
    let adapters = match nics::scan() {
        Ok(a) => a,
        Err(e) => {
            log.warn(format!(
                "nics: adapters could not be listed, nothing was checked: {e}"
            ));
            return;
        }
    };
    let (mut compared, mut unchecked) = (0, 0);
    for a in &adapters {
        let what = format!("nic \"{}\" ({})", a.name, a.description);
        let cur = mask_mac(&a.current);

        let zero = |m: &nics::Mac| m.iter().all(|&b| b == 0);
        match &a.driver_current {
            // A miniport that has not started yet (an unpaired Bluetooth
            // PAN, a disabled virtual adapter) answers zeros: no answer.
            Ok(dc) if zero(dc) || zero(&a.current) => {
                log.debug(format!("  {what}: no current address on one side, NOT compared"))
            }
            // Wi-Fi random addresses are applied per connection; whether
            // both paths always switch together has not been verified, so
            // a difference involving one is a warning, not an alert.
            Ok(dc)
                if *dc != a.current
                    && a.wifi
                    && (nics::locally_administered(dc) || nics::locally_administered(&a.current)) =>
            {
                log.warn(format!(
                    "{what}: IP Helper reports {cur}, NDIS reports {} for the same current address -- one is a random Wi-Fi address, which may be mid-change",
                    mask_mac(dc)
                ))
            }
            Ok(dc) if *dc != a.current => log.alert(format!(
                "{what}: IP Helper reports {cur}, NDIS reports {} for the same current address",
                mask_mac(dc)
            )),
            Ok(_) => {}
            Err(e) => log.debug(format!("  {what}: NDIS current address not read: {e}")),
        }

        let perm = match &a.permanent {
            Ok(p) if p.iter().all(|&b| b == 0) => {
                unchecked += 1;
                log.debug(format!(
                    "  {what}: reports no permanent address, NOT compared"
                ));
                continue;
            }
            Ok(p) => *p,
            Err(e) => {
                unchecked += 1;
                log.debug(format!(
                    "  {what}: permanent address not read, NOT compared: {e}"
                ));
                continue;
            }
        };
        compared += 1;

        if perm == a.current {
            log.debug(format!("  {what}: {cur}, the permanent address"));
        } else if a.override_addr == Some(a.current) {
            log.warn(format!(
                "{what}: {cur} is set in the adapter's Network Address property (registry NetworkAddress); the card's own address is {} -- an administrator setting, and the most common MAC spoof",
                mask_mac(&perm)
            ));
        } else if a.wifi && nics::locally_administered(&a.current) {
            log.info(format!(
                "{what}: {cur} is a random hardware address (Windows Wi-Fi privacy setting), the card's own is {}",
                mask_mac(&perm)
            ));
        } else {
            log.warn(format!(
                "{what}: {cur} differs from the card's own address {} with no registry override -- a driver-level spoofer, or a bridge, team or virtual switch",
                mask_mac(&perm)
            ));
        }
    }
    log.info(format!(
        "nics: {} Ethernet/Wi-Fi adapter(s), {compared} compared against their permanent address, {unchecked} could not be",
        adapters.len()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders() {
        for v in [
            "",
            "Default string",
            "To Be Filled By O.E.M.",
            "00000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "03000200-0400-0500-0006-000700080009",
        ] {
            assert!(placeholder(v), "{v:?}");
        }
        for v in ["S4EWNX0R123456", "4C4C4544-0042-3510-8051-B4C04F4E4D32"] {
            assert!(!placeholder(v), "{v:?}");
        }
    }

    #[test]
    fn masking_hides_the_middle() {
        assert_eq!(mask("S4EWNX0R123456"), "S4**********56 (14 chars)");
        assert_eq!(mask("ABC"), "***");
        assert_eq!(
            // RFC 7042 documentation range.
            mask_mac(&[0x00, 0x00, 0x5E, 0x00, 0x53, 0x01]),
            "00-00-5E-**-**-01"
        );
    }

    #[test]
    fn first_difference() {
        assert_eq!(
            first_diff("ABCD", "ABXD"),
            "first difference at character 3"
        );
    }
}
