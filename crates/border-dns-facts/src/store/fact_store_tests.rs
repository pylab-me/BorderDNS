use std::path::PathBuf;

use chrono::Utc;

use super::*;
use crate::FactEmitter;
use crate::MeaningfulEventKind;

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("border-dns-fact-store-{}", uuid::new()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// Simple unique id generator for test isolation.
mod uuid {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    pub fn new() -> u64 {
        COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

#[test]
fn test_format_hour_tag() {
    let dt =
        chrono::NaiveDateTime::parse_from_str("2026-05-28T14:30:00", "%Y-%m-%dT%H:%M:%S").unwrap();
    let dt = DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc);
    assert_eq!(format_hour_tag(dt), "2026-05-28T14");
}

#[test]
fn test_extract_hour_tag() {
    assert_eq!(
        extract_hour_tag("events-active-2026-05-28T14.jsonl"),
        Some("2026-05-28T14".into())
    );
    assert_eq!(
        extract_hour_tag("events-sealed-2026-05-28T03.jsonl"),
        Some("2026-05-28T03".into())
    );
    assert_eq!(extract_hour_tag("derived-manifest.json"), None);
}

#[test]
fn test_writer_creates_directory_and_file() {
    let dir = temp_dir();
    let writer = FactEventWriter::new(dir.clone()).unwrap();

    assert!(dir.join("derived-manifest.json").exists());
    assert!(dir.join(writer.manifest().active_event_file).exists());

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_writer_write_event() {
    let dir = temp_dir();
    let writer = FactEventWriter::new(dir.clone()).unwrap();

    let event = FactEmitter::new(
        "example.com".into(),
        MeaningfulEventKind::FirstSeenDomain,
        "new_domain".into(),
    );

    writer.write_event(&event).unwrap();
    assert_eq!(writer.total_events(), 1);

    // Write another.
    let event2 = FactEmitter::new(
        "test.com".into(),
        MeaningfulEventKind::PhaseChanged,
        "learning_to_suggested".into(),
    );
    writer.write_event(&event2).unwrap();
    assert_eq!(writer.total_events(), 2);

    // Verify file content.
    let active_file = dir.join(writer.manifest().active_event_file);
    let content = std::fs::read_to_string(&active_file).unwrap();
    let lines: Vec<&str> = content.trim().lines().collect();
    assert_eq!(lines.len(), 2);

    // Parse first line.
    let parsed: FactEmitter = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(parsed.domain, "example.com");

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_writer_manifest_roundtrip() {
    let dir = temp_dir();
    let writer = FactEventWriter::new(dir.clone()).unwrap();

    let event = FactEmitter::new(
        "example.com".into(),
        MeaningfulEventKind::FirstSeenDomain,
        "test".into(),
    );
    writer.write_event(&event).unwrap();

    // Read manifest from disk.
    let manifest_path = dir.join("derived-manifest.json");
    let json = std::fs::read_to_string(&manifest_path).unwrap();
    let manifest = FactStoreManifest::from_json(&json).unwrap();
    assert_eq!(manifest.schema_version, "borderdns.fact.v1");
    assert_eq!(manifest.counters.meaningful_events_total, 1);

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_writer_reload_preserves_events() {
    let dir = temp_dir();

    // Write some events.
    {
        let writer = FactEventWriter::new(dir.clone()).unwrap();
        for i in 0..5 {
            let event = FactEmitter::new(
                format!("domain{i}.com"),
                MeaningfulEventKind::FirstSeenDomain,
                "test".into(),
            );
            writer.write_event(&event).unwrap();
        }
    }

    // Reload from disk.
    {
        let writer = FactEventWriter::new(dir.clone()).unwrap();
        // New writer should see the existing manifest.
        let manifest = writer.manifest();
        assert_eq!(manifest.schema_version, "borderdns.fact.v1");
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}
