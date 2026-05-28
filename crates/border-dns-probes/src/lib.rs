//! TLS identity and latency probes for BorderDNS governance loop.
//!
//! This crate provides probe implementations that produce **evidence**,
//! never route authority.
//!
//! Hard rules:
//! ```text
//! Probe results are evidence, not route authority.
//! DNS correctness must not depend on TLS probe success.
//! IP latency is quality evidence only — it must NOT directly
//! determine china/foreign route.
//! ```

use std::net::IpAddr;
use std::time::Duration;

use dns_types::IpGeoScope;
use dns_types::ResolverLocation;
use facts::ProbeQuality;
use facts::TlsIdentityStatus;
use geoip::GeoIpLookup;
use serde::Deserialize;
use serde::Serialize;

// ─── Probe Result Types ──────────────────────────────────────────

/// Result of a TLS identity probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProbeResult {
    /// The domain that was used as SNI.
    pub sni_domain: String,
    /// The IP address that was probed.
    pub target_ip: IpAddr,
    /// Identity match status.
    pub identity_status: TlsIdentityStatus,
    /// Certificate SANs (if successfully extracted).
    pub cert_sans: Vec<String>,
    /// Certificate CN (if successfully extracted).
    pub cert_cn: Option<String>,
    /// Connection latency in milliseconds (if connected).
    pub connect_ms: Option<u64>,
    /// Error message (if probe failed).
    pub error: Option<String>,
}

/// Result of a latency probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProbeResult {
    /// The IP address that was probed.
    pub target_ip: IpAddr,
    /// TCP connect latency in milliseconds.
    pub connect_ms: Option<u64>,
    /// Quality classification.
    pub quality: ProbeQuality,
    /// Error message (if probe failed).
    pub error: Option<String>,
}

// ─── Probe Traits ────────────────────────────────────────────────

/// TLS identity probe trait.
///
/// Implementations connect to an IP with a given SNI and check whether
/// the certificate identity matches the expected domain.
pub trait TlsProbe: Send + Sync {
    /// Probe TLS identity for a target IP with given SNI domain.
    fn probe_tls_identity(
        &self,
        target_ip: IpAddr,
        port: u16,
        sni_domain: &str,
        cname_targets: Vec<String>,
    ) -> impl std::future::Future<Output = TlsProbeResult> + Send;
}

/// Latency probe trait.
///
/// Implementations measure TCP connect latency to classify probe quality.
pub trait LatencyProbe: Send + Sync {
    /// Probe TCP connect latency to a target IP.
    fn probe_latency(
        &self,
        target_ip: IpAddr,
        port: u16,
        timeout: Duration,
    ) -> impl std::future::Future<Output = LatencyProbeResult> + Send;
}

// ─── Speed Test (Candidate IP Ranking) ───────────────────────────

/// An IP address ranked by measured latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedIp {
    /// The IP address.
    pub addr: IpAddr,
    /// Measured latency in milliseconds (`None` if probe failed).
    pub latency_ms: Option<u64>,
    /// Quality classification based on latency.
    pub quality: ProbeQuality,
}

/// Speed test trait — ranks a set of candidate IPs by latency.
///
/// Used by the prefetch system and route-scoped answer selection
/// to pick the fastest IP from a candidate set. This is a **quality
/// signal only** — it must NOT directly determine china/foreign route.
pub trait SpeedTest: Send + Sync {
    /// Probe all candidates concurrently and return them sorted by
    /// latency (ascending). Failed probes are placed at the end.
    fn rank_by_latency(
        &self,
        candidates: &[IpAddr],
        port: u16,
        timeout: Duration,
    ) -> impl std::future::Future<Output = Vec<RankedIp>> + Send;
}

/// TCP-connect-based speed test.
///
/// Measures TCP connect latency to each candidate IP concurrently.
/// No raw socket or ICMP privileges required — works in any sandbox.
///
/// Hard rules:
/// ```text
/// Probe results are evidence, not route authority.
/// IP latency is quality evidence only — it must NOT directly
/// determine china/foreign route.
/// ```
#[derive(Debug, Clone, Default)]
pub struct TcpSpeedTest;

impl TcpSpeedTest {
    /// Create a new TCP speed test instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Rank candidate IPs by latency, filtered by resolver location.
    ///
    /// - `ResolverLocation::China` → only probes IPs with `IpGeoScope::Cn`
    /// - `ResolverLocation::Foreign` → only probes IPs with `IpGeoScope::Foreign`
    /// - `ResolverLocation::Unknown` → probes all candidates (no filter)
    ///
    /// Private and Reserved IPs are always excluded from speed testing.
    pub async fn rank_by_location(
        &self,
        candidates: &[IpAddr],
        port: u16,
        timeout: Duration,
        location: ResolverLocation,
        geo: &dyn GeoIpLookup,
    ) -> Vec<RankedIp> {
        let filtered = filter_ips_by_location(candidates, location, geo);
        self.rank_by_latency(&filtered, port, timeout).await
    }
}

impl SpeedTest for TcpSpeedTest {
    async fn rank_by_latency(
        &self,
        candidates: &[IpAddr],
        port: u16,
        timeout: Duration,
    ) -> Vec<RankedIp> {
        if candidates.is_empty() {
            return Vec::new();
        }

        let futs = candidates.iter().map(|ip| async move {
            let result = tcp_connect_time(*ip, port, timeout).await;
            RankedIp {
                addr: *ip,
                latency_ms: result.as_ref().ok().map(|d| d.as_millis() as u64),
                quality: match &result {
                    Ok(d) => classify_latency(d.as_millis() as u64),
                    Err(_) => ProbeQuality::Unstable,
                },
            }
        });

        let mut results: Vec<RankedIp> = futures::future::join_all(futs).await;

        // Sort: successful probes ascending by latency, failed probes last.
        results.sort_by(|a, b| match (a.latency_ms, b.latency_ms) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });

        results
    }
}

// ─── IP Filtering by Location ────────────────────────────────────

/// Filter candidate IPs by resolver location and GeoIP classification.
///
/// - `ResolverLocation::China` → keep only `IpGeoScope::Cn` IPs.
/// - `ResolverLocation::Foreign` → keep only `IpGeoScope::Foreign` IPs.
/// - `ResolverLocation::Unknown` → keep all except Private/Reserved.
///
/// Private and Reserved IPs are always excluded.
///
/// If filtering removes all candidates, returns the original list unmodified
/// to avoid breaking DNS resolution entirely — degraded speed test is better
/// than no answer.
#[must_use]
pub fn filter_ips_by_location(
    candidates: &[IpAddr],
    location: ResolverLocation,
    geo: &dyn GeoIpLookup,
) -> Vec<IpAddr> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let want_scope = match location {
        ResolverLocation::China => Some(IpGeoScope::Cn),
        ResolverLocation::Foreign => Some(IpGeoScope::Foreign),
        ResolverLocation::Unknown => None,
    };

    let filtered: Vec<IpAddr> = candidates
        .iter()
        .copied()
        .filter(|ip| {
            let result = geo.lookup(*ip);
            match result.scope {
                // Always exclude private and reserved.
                IpGeoScope::Private | IpGeoScope::Reserved => false,
                // If we have a target scope, match only that.
                scope => match want_scope {
                    Some(want) => scope == want,
                    None => true, // Unknown location → keep all (except private/reserved).
                },
            }
        })
        .collect();

    // Fallback: if filtering eliminated everything, return unfiltered list
    // so DNS resolution still works. Degraded speed test > no answer.
    if filtered.is_empty() {
        candidates.to_vec()
    } else {
        filtered
    }
}

// ─── Quality Classification ──────────────────────────────────────

/// Classify TCP connect latency into a probe quality bucket.
///
/// Thresholds are deliberately coarse. Exact numbers will be tuned
/// with real-world data.
#[must_use]
pub fn classify_latency(connect_ms: u64) -> ProbeQuality {
    if connect_ms < 50 {
        ProbeQuality::Good
    } else if connect_ms < 200 {
        ProbeQuality::Acceptable
    } else if connect_ms < 1000 {
        ProbeQuality::Poor
    } else {
        ProbeQuality::Unstable
    }
}

// ─── Identity Match Helper ───────────────────────────────────────

/// Check whether a certificate identity matches the expected domain or CNAME targets.
///
/// Performs case-insensitive comparison against SANs and CN.
/// Returns the match status.
#[must_use]
pub fn check_identity_match(
    sni_domain: &str,
    cert_sans: &[String],
    cert_cn: Option<&str>,
    cname_targets: &[String],
) -> TlsIdentityStatus {
    let sni_lower = sni_domain.to_lowercase();

    // Check exact SAN match
    for san in cert_sans {
        let san_lower = san.to_lowercase();
        if san_lower == sni_lower {
            return TlsIdentityStatus::ExactMatch;
        }
        // Wildcard match: *.example.com matches foo.example.com
        if san_lower.starts_with("*.") {
            let suffix = &san_lower[1..]; // .example.com
            if sni_lower.ends_with(suffix) {
                let prefix = &sni_lower[..sni_lower.len() - suffix.len()];
                if !prefix.contains('.') {
                    return TlsIdentityStatus::ExactMatch;
                }
            }
        }
    }

    // Check CN match
    if let Some(cn) = cert_cn {
        let cn_lower = cn.to_lowercase();
        if cn_lower == sni_lower {
            return TlsIdentityStatus::ExactMatch;
        }
        if cn_lower.starts_with("*.") {
            let suffix = &cn_lower[1..];
            if sni_lower.ends_with(suffix) {
                let prefix = &sni_lower[..sni_lower.len() - suffix.len()];
                if !prefix.contains('.') {
                    return TlsIdentityStatus::ExactMatch;
                }
            }
        }
    }

    // Check CNAME target match
    for cname in cname_targets {
        let cname_lower = cname.to_lowercase().trim_end_matches('.').to_string();
        for san in cert_sans {
            if san.to_lowercase() == cname_lower {
                return TlsIdentityStatus::CnameMatch;
            }
            if san.to_lowercase().starts_with("*.") {
                let suffix = &san.to_lowercase()[1..];
                if cname_lower.ends_with(suffix) {
                    let prefix = &cname_lower[..cname_lower.len() - suffix.len()];
                    if !prefix.contains('.') {
                        return TlsIdentityStatus::CnameMatch;
                    }
                }
            }
        }
        if let Some(cn) = cert_cn {
            if cn.to_lowercase() == cname_lower {
                return TlsIdentityStatus::CnameMatch;
            }
        }
    }

    // If we have SANs or CN but no match, it's a mismatch
    if !cert_sans.is_empty() || cert_cn.is_some() {
        return TlsIdentityStatus::Mismatch;
    }

    TlsIdentityStatus::Unknown
}

// ─── TCP Connect Helper ──────────────────────────────────────────

/// Measure TCP connect time to an IP:port with a timeout.
///
/// Returns `Ok(duration)` if connection succeeds, `Err(error_msg)` otherwise.
pub async fn tcp_connect_time(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<Duration, String> {
    let addr = std::net::SocketAddr::new(ip, port);
    let start = std::time::Instant::now();

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Ok(start.elapsed()),
        Ok(Err(e)) => Err(format!("tcp_connect_error: {e}")),
        Err(_) => Err("tcp_connect_timeout".into()),
    }
}

#[cfg(test)]
#[path = "probes_tests.rs"]
mod tests;
