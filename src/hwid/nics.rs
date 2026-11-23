// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Each network adapter's MAC address, from three places.
//!
//! - **IP Helper** (`GetAdaptersAddresses`) -- the current address, as
//!   `ipconfig /all`, `Get-NetAdapter` and most ban systems see it.
//! - **NDIS** -- `IOCTL_NDIS_QUERY_GLOBAL_STATS` on the adapter's device
//!   object, for `OID_802_3_CURRENT_ADDRESS` and
//!   `OID_802_3_PERMANENT_ADDRESS`. For NDIS 6 miniports NDIS answers both
//!   from what the miniport reported when it started, so this is not a
//!   fresh read of the hardware: it catches a hook on IP Helper's path or
//!   on the OID path, not a miniport that lies from the start. The
//!   permanent address is normally the one in the card's EEPROM, but it
//!   too is whatever the miniport said.
//! - **The registry** -- the `NetworkAddress` value of the adapter's class
//!   key, which is where the driver's "Network Address" advanced property
//!   lives. It is a legitimate administrator setting and also the most
//!   common software MAC spoof: no driver needed.
//!
//! Two answers for the current address that disagree is the signature of
//! a spoofer that hooked one path. A current address that differs from
//! the permanent one has honest explanations -- the registry override,
//! Windows' random hardware addresses on Wi-Fi, a bridge or a team -- and
//! is reported with whichever applies, or as unexplained.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::{
    OID_802_3_CURRENT_ADDRESS, OID_802_3_PERMANENT_ADDRESS,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use windows::core::HSTRING;

/// `CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 0, METHOD_OUT_DIRECT,
/// FILE_ANY_ACCESS)`, from `ntddndis.h`; the crate does not carry it.
const IOCTL_NDIS_QUERY_GLOBAL_STATS: u32 = 0x0017_0002;
/// `AF_UNSPEC`.
const AF_UNSPEC: u32 = 0;
/// The network adapter device class.
const NET_CLASS: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";
/// Class instance keys are `0000`, `0001`, ...; gaps happen when adapters
/// are removed, so the walk does not stop at the first missing one.
const MAX_CLASS_KEYS: u32 = 256;

pub type Mac = [u8; 6];

pub fn fmt(m: &Mac) -> String {
    m.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("-")
}

/// The locally administered bit: set on every address not assigned by
/// the manufacturer, randomised Wi-Fi addresses included.
pub fn locally_administered(m: &Mac) -> bool {
    m[0] & 0x02 != 0
}

pub struct Adapter {
    pub name: String,
    pub description: String,
    pub wifi: bool,
    /// From IP Helper.
    pub current: Mac,
    /// From the driver; `Err` carries why it could not be read.
    pub driver_current: Result<Mac, String>,
    pub permanent: Result<Mac, String>,
    /// The registry `NetworkAddress` override, parsed, if one is set.
    pub override_addr: Option<Mac>,
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

fn query_oid(h: &Handle, oid: u32) -> Result<Mac, String> {
    let mut out = [0u8; 6];
    let mut got = 0u32;
    unsafe {
        DeviceIoControl(
            h.0,
            IOCTL_NDIS_QUERY_GLOBAL_STATS,
            Some((&oid as *const u32).cast()),
            4,
            Some(out.as_mut_ptr().cast()),
            6,
            Some(&mut got),
            None,
        )
    }
    .map_err(|e| e.message())?;
    if got != 6 {
        return Err(format!("{got} byte(s) returned"));
    }
    Ok(out)
}

/// Both driver views, read through the adapter's `\\.\{GUID}` device.
fn driver_addresses(guid: &str) -> (Result<Mac, String>, Result<Mac, String>) {
    let h = unsafe {
        CreateFileW(
            &HSTRING::from(format!(r"\\.\{guid}")),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        )
    };
    match h {
        Ok(h) => {
            let h = Handle(h);
            (
                query_oid(&h, OID_802_3_CURRENT_ADDRESS),
                query_oid(&h, OID_802_3_PERMANENT_ADDRESS),
            )
        }
        Err(e) => {
            let m = format!("cannot open the adapter device: {}", e.message());
            (Err(m.clone()), Err(m))
        }
    }
}

fn reg_string(subkey: &str, value: &str) -> Option<String> {
    let (subkey, value) = (HSTRING::from(subkey), HSTRING::from(value));
    let mut buf = [0u16; 256];
    let mut size = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            &subkey,
            &value,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut size),
        )
    };
    if rc.is_err() {
        return None;
    }
    let n = (size as usize / 2).min(buf.len());
    let s = String::from_utf16_lossy(&buf[..n]);
    Some(s.trim_end_matches('\0').trim().to_string())
}

/// 12 hex digits, separators tolerated -- the forms the "Network
/// Address" property accepts.
fn parse_mac(s: &str) -> Option<Mac> {
    let hex: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    if hex.len() != 12
        || s.chars()
            .any(|c| !(c.is_ascii_hexdigit() || "-:. ".contains(c)))
    {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, b) in m.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(m)
}

/// `NetCfgInstanceId` (lower-case GUID) -> `NetworkAddress`, for every
/// adapter that has an override set.
fn registry_overrides() -> Vec<(String, Mac)> {
    let mut out = Vec::new();
    for i in 0..MAX_CLASS_KEYS {
        let key = format!(r"{NET_CLASS}\{i:04}");
        let Some(id) = reg_string(&key, "NetCfgInstanceId") else {
            continue;
        };
        if let Some(addr) = reg_string(&key, "NetworkAddress")
            .as_deref()
            .and_then(parse_mac)
        {
            out.push((id.to_ascii_lowercase(), addr));
        }
    }
    out
}

fn pstr(p: windows::core::PSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { p.to_string() }.unwrap_or_default()
}

fn pwstr(p: windows::core::PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe { p.to_string() }.unwrap_or_default()
}

/// Every Ethernet and Wi-Fi adapter with a 6-byte hardware address.
/// Tunnels, loopback and other link types have no burned-in address to
/// compare against.
pub fn scan() -> Result<Vec<Adapter>, String> {
    // Not GAA_FLAG_INCLUDE_ALL_INTERFACES: that adds an interface per NDIS
    // filter bound to each adapter (WFP, QoS...), which repeat the
    // adapter's address and have no device object of their own.
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    // The list can grow between the size query and the read; retry a few
    // times with whatever size the last call asked for.
    let mut size = 16 * 1024u32;
    let mut buf: Vec<u64> = Vec::new(); // u64 for the struct's alignment
    let mut rc = 0;
    for _ in 0..4 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                None,
                Some(buf.as_mut_ptr().cast()),
                &mut size,
            )
        };
        if rc != 111 {
            // ERROR_BUFFER_OVERFLOW
            break;
        }
    }
    if rc != 0 {
        return Err(format!("GetAdaptersAddresses failed: error {rc}"));
    }

    let overrides = registry_overrides();
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        // SAFETY: a linked list inside `buf`, which outlives the walk.
        let a = unsafe { &*p };
        p = a.Next;
        if a.PhysicalAddressLength != 6
            || !(a.IfType == IF_TYPE_ETHERNET_CSMACD || a.IfType == IF_TYPE_IEEE80211)
        {
            continue;
        }
        let mut current = [0u8; 6];
        current.copy_from_slice(&a.PhysicalAddress[..6]);
        #[cfg(feature = "spoof-sim")]
        if out.is_empty() {
            super::sim::mac(&mut current);
        }
        let guid = pstr(a.AdapterName);
        let (driver_current, permanent) = driver_addresses(&guid);
        let override_addr = overrides
            .iter()
            .find(|(id, _)| id.eq_ignore_ascii_case(&guid))
            .map(|(_, m)| *m);
        out.push(Adapter {
            name: pwstr(a.FriendlyName),
            description: pwstr(a.Description),
            wifi: a.IfType == IF_TYPE_IEEE80211,
            current,
            driver_current,
            permanent,
            override_addr,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_address_forms() {
        let want = Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(parse_mac("021122334455"), want);
        assert_eq!(parse_mac("02-11-22-33-44-55"), want);
        assert_eq!(parse_mac("02:11:22:33:44:55"), want);
        assert_eq!(parse_mac("0211223344"), None);
        assert_eq!(parse_mac("02112233445G"), None);
    }

    #[test]
    fn laa_bit() {
        assert!(locally_administered(&[0x02, 0, 0x5E, 0, 0x53, 0x01]));
        assert!(!locally_administered(&[0x00, 0, 0x5E, 0, 0x53, 0x01]));
    }
}
