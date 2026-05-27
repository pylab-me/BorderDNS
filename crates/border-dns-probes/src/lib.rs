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

use facts::ProbeQuality;
use facts::TlsIdentityStatus;
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
