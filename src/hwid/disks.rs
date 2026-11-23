// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Each physical disk's serial number, read two ways.
//!
//! - **Storage descriptor** -- `IOCTL_STORAGE_QUERY_PROPERTY` with
//!   `StorageDeviceProperty`. What `Win32_DiskDrive.SerialNumber`, Disk
//!   Management and nearly every ban system read. The storage port driver
//!   fills it from the drive's own IDENTIFY data, once, when the device
//!   starts.
//! - **The drive's IDENTIFY data, fetched now** -- NVMe Identify
//!   Controller through the protocol-specific property query, or ATA
//!   IDENTIFY DEVICE through `SMART_RCV_DRIVE_DATA`. Both go out to the
//!   device on every call.
//!
//! A spoofer that rewrites the descriptor (the common one: a hook on the
//! disk driver's `IRP_MJ_DEVICE_CONTROL` for that one property) and not
//! the pass-through path disagrees with itself here. One that answers
//! every query consistently, or reflashes the drive, does not.
//!
//! Both IDENTIFY paths need an administrator. Without one, or for a bus
//! with no IDENTIFY path here (USB bridges, RAID volumes, virtual disks),
//! the disk is counted as examined but not cross-checked.

use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{IOCTL_STORAGE_QUERY_PROPERTY, SMART_RCV_DRIVE_DATA};
use windows::core::HSTRING;

/// How many `\\.\PhysicalDriveN` to try. Numbers can have gaps (a removed
/// USB disk), so the walk does not stop at the first miss.
const MAX_DRIVES: u32 = 32;

const STORAGE_DEVICE_PROPERTY: u32 = 0;
const STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY: u32 = 49;
const STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY: u32 = 50;
const PROPERTY_STANDARD_QUERY: u32 = 0;
const PROTOCOL_TYPE_NVME: u32 = 3;
const NVME_DATA_TYPE_IDENTIFY: u32 = 1;
const NVME_IDENTIFY_CNS_SPECIFIC_NAMESPACE: u32 = 0;
const NVME_IDENTIFY_CNS_CONTROLLER: u32 = 1;
/// `sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA)`: ten `DWORD`s.
const PROTOCOL_SPECIFIC_DATA_LEN: usize = 40;
/// `FIELD_OFFSET(STORAGE_PROPERTY_QUERY, AdditionalParameters)`.
const QUERY_HEADER_LEN: usize = 8;
/// `FIELD_OFFSET(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData)`.
const DATA_DESCRIPTOR_HEADER_LEN: usize = 8;
const NVME_IDENTIFY_LEN: usize = 4096;

const BUS_ATA: u32 = 3;
const BUS_SATA: u32 = 11;
const BUS_NVME: u32 = 17;

/// ATA IDENTIFY DEVICE.
const ATA_IDENTIFY: u8 = 0xEC;
/// `sizeof(SENDCMDINPARAMS)` and the offset of `bBuffer` in
/// `SENDCMDOUTPARAMS`; both structures are byte-packed.
const SENDCMDIN_LEN: usize = 33;
const SENDCMDOUT_HEADER_LEN: usize = 16;
const ATA_SECTOR: usize = 512;

fn bus_name(bus: u32) -> &'static str {
    match bus {
        1 => "SCSI",
        3 => "ATA",
        7 => "USB",
        8 => "RAID",
        10 => "SAS",
        11 => "SATA",
        14 => "virtual",
        15 => "file-backed virtual",
        16 => "Storage Spaces",
        17 => "NVMe",
        18 => "SCM",
        19 => "UFS",
        _ => "other",
    }
}

/// What the second path said about one disk.
pub enum Second {
    /// Both reads succeeded and say the same thing.
    Agree,
    /// Both succeeded and disagree. Carries the IDENTIFY value.
    Disagree(String),
    /// Not compared, and why.
    NotChecked(String),
}

pub struct Disk {
    pub index: u32,
    pub bus: &'static str,
    pub model: String,
    /// Serial from the storage descriptor, as reported.
    pub serial: Option<String>,
    pub second: Second,
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn open(path: &str, access: u32) -> windows::core::Result<Handle> {
    unsafe {
        CreateFileW(
            &HSTRING::from(path),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    }
    .map(Handle)
}

/// `DeviceIoControl` into `out`, returning the bytes written.
fn ioctl(h: &Handle, code: u32, input: &[u8], out: &mut [u8]) -> windows::core::Result<usize> {
    let mut got = 0u32;
    unsafe {
        DeviceIoControl(
            h.0,
            code,
            Some(input.as_ptr().cast()),
            input.len() as u32,
            Some(out.as_mut_ptr().cast()),
            out.len() as u32,
            Some(&mut got),
            None,
        )
    }?;
    Ok(got as usize)
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    b.get(off..off + 4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
        .unwrap_or(0)
}

/// NUL-terminated ASCII at `off`, if the offset is set and in range.
fn cstr_at(b: &[u8], off: usize) -> Option<String> {
    if off == 0 || off >= b.len() {
        return None;
    }
    let end = b[off..]
        .iter()
        .position(|&c| c == 0)
        .map_or(b.len(), |p| off + p);
    let s = String::from_utf8_lossy(&b[off..end]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Fixed-width ASCII field from IDENTIFY data, space-padded.
fn ascii_field(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_matches(|c: char| c == ' ' || c == '\0')
        .to_string()
}

/// Storage descriptor: bus type, model, serial.
fn descriptor(h: &Handle) -> windows::core::Result<(u32, String, Option<String>)> {
    let mut query = [0u8; 12];
    query[0..4].copy_from_slice(&STORAGE_DEVICE_PROPERTY.to_le_bytes());
    query[4..8].copy_from_slice(&PROPERTY_STANDARD_QUERY.to_le_bytes());
    let mut out = vec![0u8; 4096];
    let n = ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, &query, &mut out)?;
    out.truncate(n);
    // STORAGE_DEVICE_DESCRIPTOR: ProductIdOffset @16, SerialNumberOffset
    // @24, BusType @28.
    let model = cstr_at(&out, u32_at(&out, 16) as usize).unwrap_or_default();
    let serial = cstr_at(&out, u32_at(&out, 24) as usize);
    Ok((u32_at(&out, 28), model, serial))
}

/// NVMe Identify (controller or namespace 1) through the protocol-specific
/// property query. The query and its answer share one buffer.
fn nvme_identify(h: &Handle, cns: u32) -> windows::core::Result<Vec<u8>> {
    let (property, nsid) = if cns == NVME_IDENTIFY_CNS_CONTROLLER {
        (STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY, 0)
    } else {
        (STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY, 1)
    };
    let mut buf = vec![0u8; QUERY_HEADER_LEN + PROTOCOL_SPECIFIC_DATA_LEN + NVME_IDENTIFY_LEN];
    let mut put = |off: usize, v: u32| buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    put(0, property);
    put(4, PROPERTY_STANDARD_QUERY);
    let p = QUERY_HEADER_LEN;
    put(p, PROTOCOL_TYPE_NVME);
    put(p + 4, NVME_DATA_TYPE_IDENTIFY);
    put(p + 8, cns); // ProtocolDataRequestValue
    put(p + 12, nsid); // ProtocolDataRequestSubValue
    put(p + 16, PROTOCOL_SPECIFIC_DATA_LEN as u32); // ProtocolDataOffset
    put(p + 20, NVME_IDENTIFY_LEN as u32); // ProtocolDataLength

    let input = buf.clone();
    let n = ioctl(h, IOCTL_STORAGE_QUERY_PROPERTY, &input, &mut buf)?;

    // STORAGE_PROTOCOL_DATA_DESCRIPTOR: Version, Size, then the protocol
    // data block, whose ProtocolDataOffset is relative to itself. The
    // answer overwrites the query in place, so a driver that succeeds
    // without writing would leave our own offset there: only trust bytes
    // the call says it returned.
    let block = DATA_DESCRIPTOR_HEADER_LEN;
    let off = block + u32_at(&buf, block + 16) as usize;
    let len = u32_at(&buf, block + 20) as usize;
    let end = (off + len.min(NVME_IDENTIFY_LEN)).min(n);
    match buf.get(off..end) {
        Some(d) if len != 0 && d.len() >= 128 => Ok(d.to_vec()),
        _ => Err(windows::core::Error::new(
            windows::core::HRESULT(0x8007_000Du32 as i32), // ERROR_INVALID_DATA
            "identify data out of range",
        )),
    }
}

/// ATA IDENTIFY DEVICE through the SMART interface.
fn ata_identify(h: &Handle, index: u32) -> windows::core::Result<Vec<u8>> {
    let mut input = [0u8; SENDCMDIN_LEN];
    input[0..4].copy_from_slice(&(ATA_SECTOR as u32).to_le_bytes()); // cBufferSize
    // IDEREGS at 4: features, sector count, sector number, cyl low,
    // cyl high, drive/head, command, reserved.
    input[5] = 1;
    input[6] = 1;
    input[9] = 0xA0 | (((index & 1) as u8) << 4);
    input[10] = ATA_IDENTIFY;
    input[12] = index as u8; // bDriveNumber
    let mut out = vec![0u8; SENDCMDOUT_HEADER_LEN + ATA_SECTOR];
    let n = ioctl(h, SMART_RCV_DRIVE_DATA, &input, &mut out)?;
    // DRIVERSTATUS at 4: bDriverError, bIDEError. The IOCTL can succeed
    // while the command failed, leaving a buffer of zeros.
    if out[4] != 0 || out[5] != 0 {
        return Err(windows::core::Error::new(
            windows::core::HRESULT(0x8007_001Fu32 as i32), // ERROR_GEN_FAILURE
            format!("drive error 0x{:02X}, IDE error 0x{:02X}", out[4], out[5]),
        ));
    }
    match out.get(SENDCMDOUT_HEADER_LEN..n.min(out.len())) {
        Some(d) if d.len() >= 40 => Ok(d.to_vec()),
        _ => Err(windows::core::Error::new(
            windows::core::HRESULT(0x8007_000Du32 as i32),
            "short IDENTIFY reply",
        )),
    }
}

/// Upper-case, whitespace removed.
fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_uppercase)
        .collect()
}

/// The two readings of an ATA IDENTIFY string field. ATA stores strings
/// as big-endian 16-bit words, and drivers have disagreed for twenty years
/// over whether to swap them back, so the descriptor may hold either.
///
/// The swap must happen on the raw field, before the padding is trimmed:
/// a serial right-justified behind an odd number of spaces has a pad space
/// inside its first word, and trimming first shifts every pair after it.
fn ata_forms(raw: &[u8]) -> [String; 2] {
    let swapped: Vec<u8> = raw
        .chunks(2)
        .flat_map(|p| p.iter().rev().copied())
        .collect();
    [ascii_field(&swapped), ascii_field(raw)]
}

/// The descriptor serial some NVMe drivers report instead of the drive's
/// serial number: the namespace's NGUID or EUI-64 as hex groups,
/// `0025_3881_..._ABCD.`. Returns the bare hex digits.
fn eui_form(s: &str) -> Option<String> {
    let t = s.trim().trim_end_matches('.');
    let ok = t.contains('_') && t.chars().all(|c| c == '_' || c.is_ascii_hexdigit());
    ok.then(|| t.replace('_', "").to_ascii_uppercase())
}

/// Hex digits back into the descriptor's `XXXX_XXXX_..._XXXX.` form.
fn eui_display(hex: &str) -> String {
    let groups: Vec<&str> = hex
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!("{}.", groups.join("_"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// The descriptor serial against the drive's, given as one or more
/// readings of its IDENTIFY field. An empty or all-zero field is no
/// answer at all -- a drive or driver that did not fill it -- and is not
/// compared.
fn compare(descriptor: &str, readings: &[String]) -> Second {
    let first = readings.first().cloned().unwrap_or_default();
    if readings.iter().all(|r| r.trim_matches('0').is_empty()) {
        return Second::NotChecked("the drive's IDENTIFY data has no serial".into());
    }
    let want = norm(descriptor);
    if readings.iter().any(|r| norm(r) == want) {
        Second::Agree
    } else {
        Second::Disagree(first)
    }
}

fn reason(e: &windows::core::Error) -> String {
    if e.code() == ERROR_ACCESS_DENIED.to_hresult() {
        "needs administrator".into()
    } else {
        e.message()
    }
}

/// Compare the descriptor serial with what the drive says now.
fn cross_check(index: u32, bus: u32, serial: &str) -> Second {
    let path = format!(r"\\.\PhysicalDrive{index}");
    let h = match open(&path, GENERIC_READ.0 | GENERIC_WRITE.0) {
        Ok(h) => h,
        Err(e) => {
            return Second::NotChecked(format!("cannot open for pass-through: {}", reason(&e)));
        }
    };
    match bus {
        BUS_NVME => {
            if let Some(want) = eui_form(serial) {
                // The descriptor carries a namespace identifier, so that
                // is what to fetch: NGUID at 104, EUI-64 at 120.
                return match nvme_identify(&h, NVME_IDENTIFY_CNS_SPECIFIC_NAMESPACE) {
                    Ok(ns) if ns.len() >= 128 => {
                        let nguid = hex(&ns[104..120]);
                        let eui = hex(&ns[120..128]);
                        if (nguid.trim_matches('0').is_empty()) && eui.trim_matches('0').is_empty()
                        {
                            Second::NotChecked("namespace has neither NGUID nor EUI-64".into())
                        } else if want == nguid || want == eui {
                            Second::Agree
                        } else {
                            // Shown in the descriptor's own form, so the two
                            // values line up character for character.
                            Second::Disagree(eui_display(if want.len() == 16 {
                                &eui
                            } else {
                                &nguid
                            }))
                        }
                    }
                    Ok(_) => Second::NotChecked("short namespace identify".into()),
                    Err(e) => {
                        Second::NotChecked(format!("NVMe identify namespace: {}", reason(&e)))
                    }
                };
            }
            match nvme_identify(&h, NVME_IDENTIFY_CNS_CONTROLLER) {
                // Identify Controller: SN is bytes 4..24.
                Ok(id) => compare(serial, &[ascii_field(&id[4..24])]),
                Err(e) => Second::NotChecked(format!("NVMe identify controller: {}", reason(&e))),
            }
        }
        BUS_ATA | BUS_SATA => match ata_identify(&h, index) {
            // IDENTIFY DEVICE: serial is words 10..19, bytes 20..40.
            Ok(id) => compare(serial, &ata_forms(&id[20..40])),
            Err(e) => Second::NotChecked(format!("ATA identify: {}", reason(&e))),
        },
        other => Second::NotChecked(format!("no IDENTIFY path for a {} disk", bus_name(other))),
    }
}

pub fn scan() -> Vec<Disk> {
    let mut out = Vec::new();
    for index in 0..MAX_DRIVES {
        // No access rights: enough for the descriptor, and works without
        // an administrator.
        let Ok(h) = open(&format!(r"\\.\PhysicalDrive{index}"), 0) else {
            continue;
        };
        let (bus, model, serial) = match descriptor(&h) {
            Ok(d) => d,
            Err(e) => {
                out.push(Disk {
                    index,
                    bus: "unknown",
                    model: String::new(),
                    serial: None,
                    second: Second::NotChecked(format!("storage descriptor: {}", e.message())),
                });
                continue;
            }
        };
        drop(h);
        #[cfg(feature = "spoof-sim")]
        let serial = {
            let mut serial = serial;
            if let Some(s) = serial
                .as_mut()
                .filter(|_| out.iter().all(|d| d.serial.is_none()))
            {
                super::sim::disk_serial(s);
            }
            serial
        };
        let second = match &serial {
            Some(s) => cross_check(index, bus, s),
            None => Second::NotChecked("the descriptor reports no serial".into()),
        };
        out.push(Disk {
            index,
            bus: bus_name(bus),
            model,
            serial,
            second,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ATA string field as the drive stores it: padded to 20 bytes,
    /// then each 16-bit word byte-swapped.
    fn stored(logical: &str) -> Vec<u8> {
        logical
            .as_bytes()
            .chunks(2)
            .flat_map(|p| p.iter().rev().copied())
            .collect()
    }

    fn agrees(s: Second) -> bool {
        matches!(s, Second::Agree)
    }

    #[test]
    fn ata_serial_either_byte_order() {
        let raw = stored("S3EWNX0K123456      ");
        // A driver that swapped back, and one that did not.
        assert!(agrees(compare("S3EWNX0K123456", &ata_forms(&raw))));
        assert!(agrees(compare("3SWEXNK0214365", &ata_forms(&raw))));
        assert!(!agrees(compare("S3EWNX0K123457", &ata_forms(&raw))));
    }

    #[test]
    fn ata_serial_right_justified_odd_length() {
        // WD's habit: 15 characters behind 5 spaces, so the first word is
        // half padding.
        let raw = stored("     WD-WCC4N1234567");
        assert!(agrees(compare("WD-WCC4N1234567", &ata_forms(&raw))));
    }

    #[test]
    fn empty_identify_serial_is_not_a_disagreement() {
        assert!(matches!(
            compare("S3EWNX0K123456", &ata_forms(&[0u8; 20])),
            Second::NotChecked(_)
        ));
        assert!(matches!(
            compare("S3EWNX0K123456", &["".into()]),
            Second::NotChecked(_)
        ));
    }

    #[test]
    fn nvme_eui_form() {
        assert_eq!(
            eui_form("0025_3881_9150_E3A1.").as_deref(),
            Some("002538819150E3A1")
        );
        assert_eq!(eui_form("S4EWNX0R123456"), None);
        assert_eq!(eui_display("002538819150E3A1"), "0025_3881_9150_E3A1.");
        let s = "0025_3881_9150_E3A1.";
        assert_eq!(eui_display(&eui_form(s).unwrap()), s);
    }
}
