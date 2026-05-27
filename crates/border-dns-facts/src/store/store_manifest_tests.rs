use chrono::Utc;

use super::*;

#[test]
fn test_manifest_new() {
    let m = FactStoreManifest::new("2026-05-28T03");
    assert_eq!(m.schema_version, "borderdns.fact.v1");
    assert_eq!(m.store_version, 1);
    assert_eq!(m.active_event_file, "events-active-2026-05-28T03.jsonl");
    assert!(m.sealed_event_files.is_empty());
    assert!(m.high_watermark_event_id.is_none());
}

#[test]
fn test_manifest_rotate() {
    let mut m = FactStoreManifest::new("2026-05-28T03");
    m.rotate("2026-05-28T04");
    assert_eq!(m.active_event_file, "events-active-2026-05-28T04.jsonl");
    assert_eq!(m.sealed_event_files.len(), 1);
    assert_eq!(m.sealed_event_files[0], "events-active-2026-05-28T03.jsonl");
}

#[test]
fn test_manifest_json_roundtrip() {
    let m = FactStoreManifest::new("2026-05-28T03");
    let json = m.to_json().unwrap();
    let parsed = FactStoreManifest::from_json(&json).unwrap();
    assert_eq!(parsed.schema_version, "borderdns.fact.v1");
    assert_eq!(parsed.active_event_file, m.active_event_file);
}

#[test]
fn test_manifest_compaction_candidates() {
    let mut m = FactStoreManifest::new("2026-05-28T03");
    // Add some sealed files with old timestamps
    m.sealed_event_files
        .push("events-sealed-2026-05-27T01.jsonl".into());
    m.sealed_event_files
        .push("events-sealed-2026-05-28T02.jsonl".into());

    // Query with a time that makes the first one old enough (>24h) and the second one not
    let now =
        chrono::NaiveDateTime::parse_from_str("2026-05-28T05:00:00", "%Y-%m-%dT%H:%M:%S").unwrap();
    let now = DateTime::<Utc>::from_naive_utc_and_offset(now, Utc);
    let candidates = m.compaction_candidates(now);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0], "events-sealed-2026-05-27T01.jsonl");
}

#[test]
fn test_retention_config_defaults() {
    let r = RetentionConfig::default();
    assert_eq!(r.keep_active_hours, 1);
    assert_eq!(r.keep_sealed_hours, 24);
    assert_eq!(r.compact_after_hours, 24);
    assert_eq!(r.keep_compact_days, 14);
    assert!(r.duckdb_rebuildable);
}

#[test]
fn test_review_candidates_artifact_json() {
    let artifact = ReviewCandidatesArtifact {
        schema_version: "borderdns.fact.v1".into(),
        generated_at: Utc::now(),
        review_domains: vec![ReviewDomainEntry {
            domain: "example.com".into(),
            phase: "review".into(),
            reason: "tls_mismatch".into(),
            observation_count: 42,
            hard_conflict_count_24h: 3,
            tls_mismatch_count_24h: 2,
            mixed_count_24h: 5,
            last_observed_at: Utc::now(),
        }],
        fallback_domains: Vec::new(),
        summary: ReviewSummary {
            total_review: 1,
            total_fallback: 0,
            mixed_review: 0,
            tls_mismatch_review: 1,
            hard_conflict_review: 0,
        },
    };

    let json = serde_json::to_string_pretty(&artifact).unwrap();
    let parsed: ReviewCandidatesArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.review_domains.len(), 1);
    assert_eq!(parsed.review_domains[0].domain, "example.com");
    assert_eq!(parsed.summary.total_review, 1);
}
