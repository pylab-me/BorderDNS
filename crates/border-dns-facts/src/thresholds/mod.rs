//! Governance threshold configurations.
//!
//! Contains:
//! - `MixedEvidenceThresholds` — mixed evidence behavior thresholds
//! - `StablePromotionThresholds` — stable promotion with third-party peers
//! - `LocalOnlyStableThresholds` — stable promotion local-only strict
//! - `ReviewThresholds` — review entry thresholds
//! - `FallbackThresholds` — fallback entry thresholds
//! - `GovernanceThresholds` — combined threshold configuration

pub mod thresholds;

pub use thresholds::*;
