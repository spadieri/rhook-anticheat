// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The SMBIOS table, read two ways.
//!
//! The firmware publishes one SMBIOS table at boot. Windows hands it out
//! through two paths that share no user-mode code:
//!
//! - `GetSystemFirmwareTable('RSMB')` -- `NtQuerySystemInformation`,
//!   served by the kernel's firmware-table provider.
//! - WMI `root\WMI:MSSmBios_RawSMBiosTables` -- a WMI data block served by
//!   the kernel's WMI provider, not by the firmware-table handler.
//!
//! They are copies of the same bytes, and the table cannot change without
//! a reboot, so on an honest machine every identity field agrees. A
//! spoofer that rewrites the answer of one path -- a hook on the
//! firmware-table handler, a patched WMI block -- and forgets the other
//! is caught here. One that patches the table in physical memory before
//! Windows reads it, or rewrites both paths consistently, is not: this is
//! a check for incomplete spoofers, and the report says so.
//!
//! **Not a third view:** the registry value `mssmbios\Data\SMBiosData`.
//! It looks like one -- the same `RawSMBIOSData` blob, written by
//! `mssmbios.sys` at boot -- but Windows scrubs it: the system UUID is
//! zeroed and the chassis and memory serials are emptied. Compared against
//! it, every honest machine would raise alerts.

use windows::Win32::System::SystemInformation::{GetSystemFirmwareTable, RSMB};

/// Size of the `RawSMBIOSData` header the firmware-table API puts in
/// front of the table: calling method, major, minor, DMI revision, then
/// the table length.
const RAW_HEADER: usize = 8;

/// One view of the table: just the structure bytes, header stripped, so
/// the views compare like for like.
pub struct Table {
    pub major: u8,
    pub minor: u8,
    pub data: Vec<u8>,
}

/// Split a `RawSMBIOSData` blob (header + table) into a `Table`.
fn from_raw(raw: &[u8]) -> Result<Table, String> {
    if raw.len() < RAW_HEADER {
        return Err(format!("{} byte(s), shorter than the header", raw.len()));
    }
    let len = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    let body = &raw[RAW_HEADER..];
    if len > body.len() {
        return Err(format!(
            "header claims {len} byte(s) of table, {} present",
            body.len()
        ));
    }
    Ok(Table {
        major: raw[1],
        minor: raw[2],
        data: body[..len].to_vec(),
    })
}

/// The table as `GetSystemFirmwareTable` returns it.
pub fn from_firmware_api() -> Result<Table, String> {
    // SAFETY: a `None` buffer asks for the required size; the second call
    // writes at most `buf.len()` bytes.
    let need = unsafe { GetSystemFirmwareTable(RSMB, 0, None) } as usize;
    if need == 0 {
        return Err(format!(
            "GetSystemFirmwareTable failed: {}",
            windows::core::Error::from_win32()
        ));
    }
    let mut buf = vec![0u8; need];
    let got = unsafe { GetSystemFirmwareTable(RSMB, 0, Some(&mut buf)) } as usize;
    if got == 0 || got > buf.len() {
        return Err(format!("GetSystemFirmwareTable returned {got} byte(s)"));
    }
    buf.truncate(got);
    from_raw(&buf)
}

/// One SMBIOS structure: the formatted area and its string set.
struct Structure<'a> {
    kind: u8,
    handle: u16,
    formatted: &'a [u8],
    strings: Vec<&'a [u8]>,
}

impl Structure<'_> {
    /// The string a formatted-area byte at `offset` points at. Index 0
    /// means "no string"; a structure too short to have the field has none
    /// either.
    fn string(&self, offset: usize) -> Option<String> {
        let idx = *self.formatted.get(offset)? as usize;
        if idx == 0 {
            return None;
        }
        let s = self.strings.get(idx - 1)?;
        Some(String::from_utf8_lossy(s).trim().to_string())
    }

    fn bytes(&self, offset: usize, len: usize) -> Option<&[u8]> {
        self.formatted.get(offset..offset + len)
    }
}

/// Walk the table. Stops at the end-of-table structure (type 127) or at
/// the first malformed one: a truncated table yields fewer fields, and
/// the comparison reports the fields one view has and another lacks.
fn structures(data: &[u8]) -> Vec<Structure<'_>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= data.len() {
        let kind = data[i];
        let len = data[i + 1] as usize;
        if len < 4 || i + len > data.len() {
            break;
        }
        let handle = u16::from_le_bytes([data[i + 2], data[i + 3]]);
        let formatted = &data[i..i + len];

        // The string set: NUL-terminated strings, ended by an extra NUL.
        // A structure with no strings is followed by two NULs.
        let mut j = i + len;
        let mut strings = Vec::new();
        if data.get(j) == Some(&0) && data.get(j + 1) == Some(&0) {
            j += 2;
        } else {
            loop {
                let start = j;
                while j < data.len() && data[j] != 0 {
                    j += 1;
                }
                if j >= data.len() {
                    break;
                }
                strings.push(&data[start..j]);
                j += 1; // the string's own NUL
                if data.get(j) == Some(&0) {
                    j += 1; // the set's terminating NUL
                    break;
                }
            }
        }

        out.push(Structure {
            kind,
            handle,
            formatted,
            strings,
        });
        if kind == 127 {
            break;
        }
        i = j;
    }
    out
}

/// Format a type 1 UUID. From SMBIOS 2.6 the first three fields are
/// little-endian, as RFC 4122 wire format is not; before 2.6 the order was
/// never pinned down. It is always read little-endian here, regardless of
/// the version a view reports: the formatting must not depend on anything
/// but the 16 bytes, or two views of the same bytes could print -- and
/// compare -- differently.
fn format_uuid(b: &[u8]) -> String {
    let (d1, d2, d3) = (
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
    );
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{}",
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect::<String>()
    )
}

/// One identity field: a stable key (field name and structure handle,
/// which is the same in every copy of the table) and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub key: String,
    pub value: String,
    /// The value is a placeholder or a number a spoofer can write, not
    /// something that names this machine. Decided by `super::placeholder`.
    pub kind: FieldKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// A serial or UUID meant to be unique to this unit.
    Serial,
    /// Type 4's ProcessorID: CPUID leaf 1, the same for every CPU of a
    /// model and stepping. Compared, never treated as an identity.
    ProcessorId,
}

/// Where the first type 1 structure's UUID sits in `t.data`.
#[cfg(feature = "spoof-sim")]
pub fn uuid_offset(t: &Table) -> Option<usize> {
    let s = structures(&t.data).into_iter().find(|s| s.kind == 1)?;
    s.bytes(0x08, 16)?;
    Some(s.formatted.as_ptr() as usize - t.data.as_ptr() as usize + 0x08)
}

/// The fields hardware bans are built on, in table order.
///
/// - Type 1 (system): UUID and serial number.
/// - Type 2 (baseboard): serial number.
/// - Type 3 (chassis): serial number.
/// - Type 4 (processor): ProcessorID, for the CPUID cross-check.
/// - Type 17 (memory device): serial number of each populated slot.
pub fn identity_fields(t: &Table) -> Vec<Field> {
    let mut out = Vec::new();
    let mut push = |key: String, value: Option<String>, kind| {
        if let Some(value) = value {
            out.push(Field { key, value, kind });
        }
    };
    for s in structures(&t.data) {
        let h = s.handle;
        match s.kind {
            1 => {
                push(
                    format!("system UUID [0x{h:04X}]"),
                    s.bytes(0x08, 16).map(format_uuid),
                    FieldKind::Serial,
                );
                push(
                    format!("system serial [0x{h:04X}]"),
                    s.string(0x07),
                    FieldKind::Serial,
                );
            }
            2 => push(
                format!("baseboard serial [0x{h:04X}]"),
                s.string(0x07),
                FieldKind::Serial,
            ),
            3 => push(
                format!("chassis serial [0x{h:04X}]"),
                s.string(0x07),
                FieldKind::Serial,
            ),
            4 => push(
                format!("processor ID [0x{h:04X}]"),
                s.bytes(0x08, 8)
                    .filter(|b| b.iter().any(|&x| x != 0))
                    .map(|b| b.iter().map(|x| format!("{x:02X}")).collect()),
                FieldKind::ProcessorId,
            ),
            17 => {
                // Size 0 is an empty slot, whose "serial" is whatever the
                // firmware fills empty slots with.
                let populated = s
                    .bytes(0x0C, 2)
                    .is_some_and(|b| u16::from_le_bytes([b[0], b[1]]) != 0);
                if populated {
                    let slot = s.string(0x10).unwrap_or_else(|| "?".into());
                    push(
                        format!("memory serial {slot} [0x{h:04X}]"),
                        s.string(0x18),
                        FieldKind::Serial,
                    );
                }
            }
            _ => {}
        }
    }
    out
}

/// CPUID leaf 1 EAX -- family, model, stepping -- read from the processor
/// itself. SMBIOS type 4 stores the same dword as the first four bytes of
/// ProcessorID; `Win32_Processor.ProcessorId` is built from it.
pub fn cpuid_signature() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // CPUID leaf 1 exists on every x86-64 processor.
        core::arch::x86_64::__cpuid(1).eax
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// The CPUID signature a ProcessorID field value (16 hex digits, bytes as
/// stored) carries in its first four bytes.
pub fn signature_of(processor_id: &str) -> Option<u32> {
    let b: Vec<u8> = (0..8)
        .map(|i| u8::from_str_radix(processor_id.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Type 1 with a UUID and one string, type 2 with no strings, end.
    fn sample() -> Vec<u8> {
        let mut t = vec![1u8, 0x1B, 0x01, 0x00, 0, 0, 0, 1];
        t.extend_from_slice(&[
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ]);
        t.extend_from_slice(&[0, 0, 0]);
        t.extend_from_slice(b"SER123\0\0");
        t.extend_from_slice(&[2, 0x08, 0x02, 0x00, 0, 0, 0, 0, 0, 0]);
        t.extend_from_slice(&[127, 4, 0xFF, 0xFF, 0, 0]);
        t
    }

    #[test]
    fn walks_strings_and_empty_sets() {
        let data = sample();
        let s = structures(&data);
        assert_eq!(s.iter().map(|s| s.kind).collect::<Vec<_>>(), [1, 2, 127]);
        assert_eq!(s[0].string(7).as_deref(), Some("SER123"));
        assert_eq!(s[1].string(7), None);
    }

    #[test]
    fn uuid_is_little_endian_from_2_6() {
        let t = Table {
            major: 3,
            minor: 0,
            data: sample(),
        };
        let f = identity_fields(&t);
        assert_eq!(f[0].value, "00112233-4455-6677-8899-AABBCCDDEEFF");
        assert_eq!(f[1].value, "SER123");
    }

    #[test]
    fn processor_id_signature() {
        assert_eq!(signature_of("71060A00FFFBEBBF"), Some(0x000A0671));
        assert_eq!(signature_of("71"), None);
    }

    #[test]
    fn raw_header_is_stripped() {
        let mut raw = vec![0u8, 3, 6, 0];
        raw.extend_from_slice(&4u32.to_le_bytes());
        raw.extend_from_slice(&[127, 4, 0, 0, 0, 0]);
        let t = from_raw(&raw).unwrap();
        assert_eq!((t.major, t.minor), (3, 6));
        assert_eq!(t.data, [127, 4, 0, 0]);
    }
}
