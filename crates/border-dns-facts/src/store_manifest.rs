//! Fact store manifest and retention policy for BorderDNS.
//!
//! The manifest tracks the current state of the facts store:
//! active event file, sealed files, derived state files,
//! high-watermark, and retention configuration.
//!
//! JSONL is source of truth. Parquet is compaction artifact.
//! DuckDB is optional inspect cache (rebuildable).

use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;

// ─── Retention Config ────────────────────────────────────────────

/// Retention policy for the fact store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Keep active event file for this many hours before sealing. Default: 1.
    pub keep_active_hours: u32,
    /// Keep sealed JSONL files for this many hours. Default: 24.
    pub keep_sealed_hours: u32,
    /// Compact sealed files after this many hours. Default: 24.
    pub compact_after_hours: u32,
    /// Keep compacted Parquet files for this many days. Default: 14.
    pub keep_compact_days: u32,
    /// Whether DuckDB inspect cache is rebuildable. Default: true.
    pub duckdb_rebuildable: bool,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            keep_active_hours: 1,
            keep_sealed_hours: 24,
            compact_after_hours: 24,
            keep_compact_days: 14,
            duckdb_rebuildable: true,
        }
    }
}

// ─── Manifest Counters ───────────────────────────────────────────

/// Summary counters for the manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestCounters {
    pub meaningful_events_total: u64,
    pub review_candidates_total: u64,
    pub mixed_review_candidates: u64,
    pub tls_mismatch_candidates: u64,
    pub review_domains: u64,
    pub fallback_domains: u64,
}

// ─── Fact Store Manifest ─────────────────────────────────────────

/// Fact store manifest — the index of the facts store.
///
/// Persisted as `derived-manifest.json`. Tracks current active event file,
/// sealed files, derived state files, and retention configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactStoreManifest {
    /// Schema version (must match `borderdns.fact.v1`).
    pub schema_version: String,
    /// Store format version.
    pub store_version: u32,
    /// Currently active hourly event file.
    pub active_event_file: String,
    /// Sealed event files (ready for compaction).
    pub sealed_event_files: Vec<String>,
    /// Derived governance state file.
    pub derived_state_file: String,
    /// Derived review candidates file.
    pub review_candidates_file: String,
    /// Inspect cache file (DuckDB, optional).
    pub inspect_cache_file: Option<String>,
    /// High-watermark event ID.
    pub high_watermark_event_id: Option<String>,
    /// High-watermark observed_at timestamp.
    pub high_watermark_observed_at: Option<DateTime<Utc>>,
    /// Retention configuration.
    pub retention: RetentionConfig,
    /// Summary counters.
    pub counters: ManifestCounters,
    /// When this manifest was last updated.
    pub updated_at: DateTime<Utc>,
}

impl FactStoreManifest {
    /// Create a new empty manifest for the given hour.
    #[must_use]
    pub fn new(hour_tag: &str) -> Self {
        Self {
            schema_version: "borderdns.fact.v1".into(),
            store_version: 1,
            active_event_file: format!("events-active-{hour_tag}.jsonl"),
            sealed_event_files: Vec::new(),
            derived_state_file: "derived-domain-governance-state.json".into(),
            review_candidates_file: "derived-review-candidates.json".into(),
            inspect_cache_file: Some("inspect.duckdb".into()),
            high_watermark_event_id: None,
            high_watermark_observed_at: None,
            retention: RetentionConfig::default(),
            counters: ManifestCounters::default(),
            updated_at: Utc::now(),
        }
    }

    /// Seal the current active file and create a new active file.
    pub fn rotate(&mut self, new_hour_tag: &str) {
        self.sealed_event_files.push(self.active_event_file.clone());
        self.active_event_file = format!("events-active-{new_hour_tag}.jsonl");
        self.updated_at = Utc::now();
    }

    /// Serialize to JSON (for `derived-manifest.json`).
    #[must_use]
    pub fn to_json(&self) -> Option<String> {
        serde_json::to_string_pretty(self).ok()
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }

    /// Get list of sealed files that are eligible for compaction.
    #[must_use]
    pub fn compaction_candidates(&self, now: DateTime<Utc>) -> Vec<&str> {
        let threshold = chrono::Duration::hours(self.retention.compact_after_hours as i64);
        self.sealed_event_files
            .iter()
            .filter(|f| {
                // Parse timestamp from filename: events-sealed-YYYY-MM-DDTHH.jsonl
                if let Some(ts_str) = f
                    .strip_prefix("events-sealed-")
                    .and_then(|s| s.strip_suffix(".jsonl"))
                {
                    if let Ok(ts) = chrono::NaiveDateTime::parse_from_str(
                        &format!("{ts_str}:00:00"),
                        "%Y-%m-%dT%H:%M:%S",
                    ) {
                        let sealed_at = DateTime::<Utc>::from_naive_utc_and_offset(ts, Utc);
                        return now - sealed_at > threshold;
                    }
                }
                false
            })
            .map(|s| s.as_str())
            .collect()
    }
}

// ─── Review Candidates Artifact ──────────────────────────────────

/// Review candidates artifact — persisted as `derived-review-candidates.json`.
///
/// Contains domains that are in Review or Fallback phase and need attention.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReviewCandidatesArtifact {
    /// Schema version.
    pub schema_version: String,
    /// When this artifact was generated.
    pub generated_at: DateTime<Utc>,
    /// Domains in Review phase.
    pub review_domains: Vec<ReviewDomainEntry>,
    /// Domains in Fallback phase.
    pub fallback_domains: Vec<ReviewDomainEntry>,
    /// Summary counts.
    pub summary: ReviewSummary,
}

/// A single domain entry in the review candidates list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewDomainEntry {
    pub domain: String,
    pub phase: String,
    pub reason: String,
    pub observation_count: u64,
    pub hard_conflict_count_24h: u32,
    pub tls_mismatch_count_24h: u32,
    pub mixed_count_24h: u32,
    pub last_observed_at: DateTime<Utc>,
}

/// Summary counts for the review artifact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReviewSummary {
    pub total_review: u32,
    pub total_fallback: u32,
    pub mixed_review: u32,
    pub tls_mismatch_review: u32,
    pub hard_conflict_review: u32,
}

#[cfg(test)]
#[path = "store_manifest_tests.rs"]
mod tests;
