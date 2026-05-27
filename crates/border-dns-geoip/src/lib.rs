//! GeoIP lookup for BorderDNS routing.
//!
//! Provides IP-to-country classification and CN/foreign/private/reserved scoping.
//! This is a basic implementation that can be replaced with a full GeoIP database
//! (e.g., MaxMind GeoLite2) in a later sprint.
//!
//! This crate must not depend on runtime, pipeline, or network crates.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use dns_types::IpGeoScope;

// ─── Core trait ──────────────────────────────────────────────────

/// GeoIP lookup interface.
pub trait GeoIpLookup: Send + Sync {
    /// Look up the geographic scope of an IP address.
    fn lookup(&self, ip: IpAddr) -> GeoIpResult;
}

/// Result of a GeoIP lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoIpResult {
    pub scope: IpGeoScope,
    pub country_code: Option<String>,
}

// ─── Simple rule-based implementation ────────────────────────────

/// Simple rule-based GeoIP implementation.
///
/// For production use, replace with a proper GeoIP database lookup.
#[derive(Debug, Clone)]
pub struct SimpleGeoIp;

impl GeoIpLookup for SimpleGeoIp {
    fn lookup(&self, ip: IpAddr) -> GeoIpResult {
        match ip {
            IpAddr::V4(v4) => self.lookup_v4(v4),
            IpAddr::V6(v6) => self.lookup_v6(v6),
        }
    }
}

impl SimpleGeoIp {
    fn lookup_v4(&self, ip: Ipv4Addr) -> GeoIpResult {
        let octets = ip.octets();

        if is_reserved_v4(&octets) {
            return GeoIpResult {
                scope: IpGeoScope::Reserved,
                country_code: None,
            };
        }
        if is_private_v4(&octets) {
            return GeoIpResult {
                scope: IpGeoScope::Private,
                country_code: None,
            };
        }
        if is_likely_china_v4(&octets) {
            return GeoIpResult {
                scope: IpGeoScope::Cn,
                country_code: Some("CN".into()),
            };
        }
        GeoIpResult {
            scope: IpGeoScope::Foreign,
            country_code: None,
        }
    }

    fn lookup_v6(&self, ip: Ipv6Addr) -> GeoIpResult {
        let segments = ip.segments();

        if ip.is_loopback() || ip.is_unspecified() {
            return GeoIpResult {
                scope: IpGeoScope::Reserved,
                country_code: None,
            };
        }
        if let Some(v4) = ip.to_ipv4_mapped() {
            return self.lookup_v4(v4);
        }
        if is_private_v6(&segments) {
            return GeoIpResult {
                scope: IpGeoScope::Private,
                country_code: None,
            };
        }
        // 2400:0000::/12 — China (APNIC allocated).
        if segments[0] >= 0x2400 && segments[0] < 0x2500 {
            return GeoIpResult {
                scope: IpGeoScope::Cn,
                country_code: Some("CN".into()),
            };
        }
        GeoIpResult {
            scope: IpGeoScope::Foreign,
            country_code: None,
        }
    }
}

// ─── Private / reserved helpers ──────────────────────────────────

fn is_reserved_v4(octets: &[u8; 4]) -> bool {
    match octets[0] {
        0 => true,
        127 => true,
        169 if octets[1] == 254 => true,
        192 if octets[1] == 0 && octets[2] == 0 => true,
        192 if octets[1] == 0 && octets[2] == 2 => true,
        198 if octets[1] == 18 || octets[1] == 19 => true,
        224..=239 => true,
        240..=255 => true,
        _ => false,
    }
}

fn is_private_v4(octets: &[u8; 4]) -> bool {
    match octets[0] {
        10 => true,
        172 if octets[1] >= 16 && octets[1] <= 31 => true,
        192 if octets[1] == 168 => true,
        _ => false,
    }
}

fn is_likely_china_v4(octets: &[u8; 4]) -> bool {
    match octets[0] {
        1 if octets[1] == 0 && (octets[2] >= 1 && octets[2] <= 3) => true,
        1 if octets[1] == 0 && octets[2] == 8 => true,
        14 => true,
        27 if octets[1] <= 63 => true,
        36 => true,
        39 => true,
        42 => true,
        49 => true,
        58 => true,
        59 => true,
        60 => true,
        61 => true,
        101 => true,
        103 if octets[1] >= 224 => true,
        106 => true,
        110 => true,
        111 => true,
        112 => true,
        113 => true,
        114 => true,
        115 => true,
        116 => true,
        117 => true,
        118 => true,
        119 => true,
        120 => true,
        121 => true,
        122 => true,
        123 => true,
        124 => true,
        125 => true,
        180 => true,
        182 => true,
        183 => true,
        202 if octets[1] >= 96 && octets[1] <= 127 => true,
        210 => true,
        211 => true,
        218 => true,
        219 => true,
        220 => true,
        221 => true,
        222 => true,
        223 => true,
        _ => false,
    }
}

fn is_private_v6(segments: &[u16; 8]) -> bool {
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    if segments.iter().all(|&s| s == 0)
        || (segments[7] == 1 && segments[..7].iter().all(|&s| s == 0))
    {
        return true;
    }
    false
}

#[cfg(test)]
#[path = "geoip_tests.rs"]
mod tests;
