//! Route model types for BorderDNS.
//!
//! Defines the core routing enums and structs used throughout the pipeline
//! to make location-aware DNS routing decisions.

use serde::Deserialize;
use serde::Serialize;

// ─── Route ───────────────────────────────────────────────────────

/// Execution route for a DNS query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Route {
    /// China route — queries resolve via China upstream group.
    China,
    /// Foreign route — queries resolve via foreign upstream group.
    Foreign,
    /// Bootstrap route — initial bootstrapping phase.
    Bootstrap,
    /// Fallback route — used when no specific route can be determined.
    Fallback,
}

impl Route {
    /// Human-readable name for logging and metrics.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::China => "china",
            Self::Foreign => "foreign",
            Self::Bootstrap => "bootstrap",
            Self::Fallback => "fallback",
        }
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for Route {
    fn default() -> Self {
        Self::Fallback
    }
}

// ─── Resolver Location ───────────────────────────────────────────

/// Physical or logical location of the resolver instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverLocation {
    /// Resolver is located in mainland China.
    China,
    /// Resolver is located outside mainland China.
    Foreign,
    /// Location is unknown or not configured.
    Unknown,
}

impl ResolverLocation {
    /// Human-readable name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::China => "china",
            Self::Foreign => "foreign",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for ResolverLocation {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for ResolverLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Route Source ────────────────────────────────────────────────

/// How a route decision was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSource {
    /// Route was determined by domain prior classification.
    DomainPrior,
    /// Route was determined by IP GeoIP evidence.
    GeoIpEvidence,
    /// Route was determined by CNAME provider hint.
    CnameEvidence,
    /// Route is the default policy (no specific evidence).
    DefaultPolicy,
    /// Route is a fallback when no other evidence applies.
    FallbackPolicy,
}

impl RouteSource {
    /// Human-readable name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DomainPrior => "domain_prior",
            Self::GeoIpEvidence => "geoip_evidence",
            Self::CnameEvidence => "cname_evidence",
            Self::DefaultPolicy => "default_policy",
            Self::FallbackPolicy => "fallback_policy",
        }
    }
}

// ─── Domain Prior ────────────────────────────────────────────────

/// Classification of a domain name for routing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainPrior {
    /// Domain is likely served from China (e.g., qq.com, taobao.com).
    China,
    /// Domain is likely served from outside China (e.g., openai.com).
    Foreign,
    /// Domain is a global CDN (e.g., cloudflare, akamai, fastly).
    GlobalCdn,
    /// Domain classification is unknown.
    Unknown,
}

impl DomainPrior {
    /// Human-readable name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::China => "china",
            Self::Foreign => "foreign",
            Self::GlobalCdn => "global_cdn",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for DomainPrior {
    fn default() -> Self {
        Self::Unknown
    }
}

// ─── Cname Hint ──────────────────────────────────────────────────

/// Hint derived from CNAME chain analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnameHint {
    /// CNAME chain points to a known China provider.
    ChinaProvider,
    /// CNAME chain points to a known foreign provider.
    ForeignProvider,
    /// CNAME chain points to a global CDN.
    GlobalCdn,
    /// No meaningful CNAME hint available.
    None,
}

impl CnameHint {
    /// Human-readable name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChinaProvider => "china_provider",
            Self::ForeignProvider => "foreign_provider",
            Self::GlobalCdn => "global_cdn",
            Self::None => "none",
        }
    }
}

impl Default for CnameHint {
    fn default() -> Self {
        Self::None
    }
}

// ─── IP Geo Scope ────────────────────────────────────────────────

/// Geographic scope of an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpGeoScope {
    /// IP is in China.
    Cn,
    /// IP is outside China.
    Foreign,
    /// IP is in a private/reserved range (RFC 1918, RFC 4193).
    Private,
    /// IP is in a reserved range (0.0.0.0, 127.x, etc.).
    Reserved,
    /// Geo scope is unknown (e.g., GeoIP data not available).
    Unknown,
}

impl IpGeoScope {
    /// Human-readable name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cn => "cn",
            Self::Foreign => "foreign",
            Self::Private => "private",
            Self::Reserved => "reserved",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for IpGeoScope {
    fn default() -> Self {
        Self::Unknown
    }
}

// ─── Confidence ──────────────────────────────────────────────────

/// Confidence level for a route decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// No evidence; using default.
    None,
    /// Weak evidence; single signal only.
    Weak,
    /// Moderate evidence; multiple signals agree.
    Moderate,
    /// Strong evidence; multiple strong signals agree.
    Strong,
}

impl Confidence {
    /// Human-readable name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Weak => "weak",
            Self::Moderate => "moderate",
            Self::Strong => "strong",
        }
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self::None
    }
}

// ─── Reason Code ─────────────────────────────────────────────────

/// Explainable reason codes for route decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// Domain was classified by prior knowledge.
    DomainPriorCn,
    DomainPriorForeign,
    /// GeoIP evidence from answer IPs.
    GeoIpCn,
    GeoIpForeign,
    /// CNAME chain provided a hint.
    CnameHint,
    /// Mixed Geo evidence (no single clear signal).
    MixedGeo,
    /// Global CDN detected.
    GlobalCdn,
    /// Default route applied.
    DefaultRoute,
    /// Fallback route applied.
    FallbackRoute,
}

impl ReasonCode {
    /// Human-readable name.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DomainPriorCn => "domain_prior_cn",
            Self::DomainPriorForeign => "domain_prior_foreign",
            Self::GeoIpCn => "geoip_cn",
            Self::GeoIpForeign => "geoip_foreign",
            Self::CnameHint => "cname_hint",
            Self::MixedGeo => "mixed_geo",
            Self::GlobalCdn => "global_cdn",
            Self::DefaultRoute => "default_route",
            Self::FallbackRoute => "fallback_route",
        }
    }
}

#[cfg(test)]
#[path = "route_tests.rs"]
mod tests;
