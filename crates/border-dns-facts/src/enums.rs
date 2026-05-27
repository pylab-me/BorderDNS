//! Core governance enums for BorderDNS facts-aware governance loop.
//!
//! All enum variants are stable. Additive changes only — never rename or
//! remove existing variants (schema compatibility guarantee).

use serde::Deserialize;
use serde::Serialize;

// ─── Governance Phase ────────────────────────────────────────────

/// Domain governance lifecycle phase.
///
/// State machine:
/// ```text
/// New -> Learning -> Suggested -> Stable
///                       ↘ Review -> Learning / Fallback
///                                       ↘ Learning
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernancePhase {
    /// First query, no state exists yet.
    New,
    /// Accumulating evidence, keep prior route.
    Learning,
    /// Evidence sufficient to influence next-query route, but not yet stable.
    Suggested,
    /// Stable and trusted — can use longer TTL.
    Stable,
    /// Repeatedly challenged, needs review — stop promotion, re-evaluate.
    Review,
    /// Governance unavailable or sustained conflict — default route + ordinary TTL.
    Fallback,
}

impl GovernancePhase {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Learning => "learning",
            Self::Suggested => "suggested",
            Self::Stable => "stable",
            Self::Review => "review",
            Self::Fallback => "fallback",
        }
    }
}

impl Default for GovernancePhase {
    fn default() -> Self {
        Self::New
    }
}

impl std::fmt::Display for GovernancePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Observer Scope ──────────────────────────────────────────────

/// Source of a fact observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverScope {
    /// Observation from this BorderDNS instance.
    Local,
    /// Observation from a configured third-party peer.
    ThirdParty,
    /// Observation from a peer in the same BorderDNS cluster.
    Peer,
    /// Synthetically generated observation (replay, test, etc.).
    Synthetic,
}

impl ObserverScope {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::ThirdParty => "third_party",
            Self::Peer => "peer",
            Self::Synthetic => "synthetic",
        }
    }
}

impl Default for ObserverScope {
    fn default() -> Self {
        Self::Local
    }
}

// ─── Observer Location ───────────────────────────────────────────

/// Geographic location of a third-party observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverLocation {
    China,
    Foreign,
    Unknown,
}

impl ObserverLocation {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::China => "china",
            Self::Foreign => "foreign",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for ObserverLocation {
    fn default() -> Self {
        Self::Unknown
    }
}

// ─── Domain Intent ───────────────────────────────────────────────

/// High-level classification of domain routing intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainIntent {
    ChinaIntent,
    ForeignIntent,
    GlobalIntent,
    MixedIntent,
    UnknownIntent,
}

impl DomainIntent {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ChinaIntent => "china_intent",
            Self::ForeignIntent => "foreign_intent",
            Self::GlobalIntent => "global_intent",
            Self::MixedIntent => "mixed_intent",
            Self::UnknownIntent => "unknown_intent",
        }
    }
}

impl Default for DomainIntent {
    fn default() -> Self {
        Self::UnknownIntent
    }
}

// ─── Cname Scope ─────────────────────────────────────────────────

/// Classification of a CNAME chain's routing significance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CnameScope {
    None,
    SameSite,
    /// CNAME chain points to a known China provider.
    CnProvider,
    /// CNAME chain points to a known foreign provider.
    ForeignProvider,
    /// CNAME chain points to a global CDN (neutral).
    GlobalCdn,
    CdnLike,
    ThirdParty,
    /// CNAME chain has mixed China/foreign providers.
    MixedChain,
    Unknown,
}

impl CnameScope {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SameSite => "same_site",
            Self::CnProvider => "cn_provider",
            Self::ForeignProvider => "foreign_provider",
            Self::GlobalCdn => "global_cdn",
            Self::CdnLike => "cdn_like",
            Self::ThirdParty => "third_party",
            Self::MixedChain => "mixed_chain",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for CnameScope {
    fn default() -> Self {
        Self::Unknown
    }
}

// ─── TLS Identity Status ─────────────────────────────────────────

/// Result of TLS certificate identity consistency check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsIdentityStatus {
    /// Certificate SAN/CN matches the query domain.
    ExactMatch,
    /// Certificate SAN/CN matches the CNAME target.
    CnameMatch,
    /// Certificate identity does not match — hard conflict.
    Mismatch,
    /// TLS probe failed (connection refused, timeout, etc.).
    ProbeFailed,
    /// TLS check not applicable (no TLS endpoint).
    NotApplicable,
    /// Status unknown (not yet probed).
    Unknown,
}

impl TlsIdentityStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ExactMatch => "exact_match",
            Self::CnameMatch => "cname_match",
            Self::Mismatch => "mismatch",
            Self::ProbeFailed => "probe_failed",
            Self::NotApplicable => "not_applicable",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for TlsIdentityStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

// ─── Probe Quality ───────────────────────────────────────────────

/// Classification of probe result quality.
///
/// Probe latency is quality evidence only — it must NOT directly
/// determine china/foreign route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeQuality {
    Good,
    Acceptable,
    Poor,
    Failed,
    Unstable,
    Unknown,
}

impl ProbeQuality {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Acceptable => "acceptable",
            Self::Poor => "poor",
            Self::Failed => "failed",
            Self::Unstable => "unstable",
            Self::Unknown => "unknown",
        }
    }
}

impl Default for ProbeQuality {
    fn default() -> Self {
        Self::Unknown
    }
}

// ─── Evidence Strength ───────────────────────────────────────────

/// Overall strength of route evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    None,
    Weak,
    Moderate,
    Strong,
    Conflicting,
}

impl EvidenceStrength {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Weak => "weak",
            Self::Moderate => "moderate",
            Self::Strong => "strong",
            Self::Conflicting => "conflicting",
        }
    }
}

impl Default for EvidenceStrength {
    fn default() -> Self {
        Self::None
    }
}

// ─── Conflict Kind ───────────────────────────────────────────────

/// Classification of evidence conflict type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// Same answer contains both CN and non-CN IPs.
    MixedGeoSoft,
    /// Multiple strong evidence points opposite to current stable route.
    RouteOppositeHard,
    /// TLS certificate identity does not match — identity hard conflict.
    TlsIdentityMismatchHard,
    /// Only third-party observation disagrees with local view.
    ThirdPartyMismatchSoft,
    /// Probe quality is weak or failed.
    ProbeQualityWeak,
}

impl ConflictKind {
    /// Whether this conflict kind directly triggers degrade at threshold.
    #[must_use]
    pub fn is_hard(&self) -> bool {
        matches!(
            self,
            Self::RouteOppositeHard | Self::TlsIdentityMismatchHard
        )
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MixedGeoSoft => "mixed_geo_soft",
            Self::RouteOppositeHard => "route_opposite_hard",
            Self::TlsIdentityMismatchHard => "tls_identity_mismatch_hard",
            Self::ThirdPartyMismatchSoft => "third_party_mismatch_soft",
            Self::ProbeQualityWeak => "probe_quality_weak",
        }
    }
}

// ─── Meaningful Event Kind ───────────────────────────────────────

/// Types of governance events worth persisting.
///
/// Ordinary queries and cache hits are NOT meaningful events — they only
/// contribute to metrics counters and optional ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeaningfulEventKind {
    FirstSeenDomain,
    RouteDecisionChanged,
    PhaseChanged,
    SuggestedPromoted,
    StablePromoted,
    ReviewEntered,
    FallbackEntered,
    MixedGeoObserved,
    TlsIdentityMismatch,
    ThirdPartyAlignment,
    ThirdPartyMismatch,
    CnameChainChanged,
    GeoScopeChanged,
    UpstreamRepeatedFailure,
    ManualCorrection,
}

impl MeaningfulEventKind {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstSeenDomain => "first_seen_domain",
            Self::RouteDecisionChanged => "route_decision_changed",
            Self::PhaseChanged => "phase_changed",
            Self::SuggestedPromoted => "suggested_promoted",
            Self::StablePromoted => "stable_promoted",
            Self::ReviewEntered => "review_entered",
            Self::FallbackEntered => "fallback_entered",
            Self::MixedGeoObserved => "mixed_geo_observed",
            Self::TlsIdentityMismatch => "tls_identity_mismatch",
            Self::ThirdPartyAlignment => "third_party_alignment",
            Self::ThirdPartyMismatch => "third_party_mismatch",
            Self::CnameChainChanged => "cname_chain_changed",
            Self::GeoScopeChanged => "geo_scope_changed",
            Self::UpstreamRepeatedFailure => "upstream_repeated_failure",
            Self::ManualCorrection => "manual_correction",
        }
    }
}

// ─── Third Party Mode ────────────────────────────────────────────

/// Whether third-party observation is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyMode {
    Disabled,
    Enabled,
}

impl ThirdPartyMode {
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
        }
    }
}

impl Default for ThirdPartyMode {
    fn default() -> Self {
        Self::Disabled
    }
}

// ─── Fact Status ─────────────────────────────────────────────────

/// Governance-level status of a fact observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactStatus {
    Observed,
    Candidate,
    Promoted,
    Rejected,
    Expired,
    Degraded,
    Conflicting,
}

impl FactStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Candidate => "candidate",
            Self::Promoted => "promoted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Degraded => "degraded",
            Self::Conflicting => "conflicting",
        }
    }
}

impl Default for FactStatus {
    fn default() -> Self {
        Self::Observed
    }
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
#[path = "enums_tests.rs"]
mod tests;
