//! JSONL fact store writer for BorderDNS governance events.
//!
//! Handles writing meaningful fact events to hourly JSONL files,
//! rotating/sealing old files, and managing the store manifest.
//!
//! JSONL is source of truth. Parquet is compaction artifact (future).
//! DuckDB is optional inspect cache (future, rebuildable).

use std::fs;
use std::io::BufWriter;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::DateTime;
use chrono::Utc;

use crate::FactEmit;
use crate::FactStoreManifest;
use crate::RetentionConfig;

// ─── Fact Store Writer ───────────────────────────────────────────

/// Writes `FactEmit` events to hourly JSONL files under a base directory.
///
/// File layout:
/// ```text
/// <base_dir>/
///   events-active-YYYY-MM-DDTHH.jsonl
///   events-sealed-YYYY-MM-DDTHH.jsonl
///   derived-manifest.json
/// ```
///
/// Thread-safe: internal state is protected by a `Mutex`.
pub struct FactStoreWriter {
    base_dir: PathBuf,
    inner: Mutex<WriterState>,
    retention: RetentionConfig,
}

impl std::fmt::Debug for FactStoreWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactStoreWriter")
            .field("base_dir", &self.base_dir)
            .finish_non_exhaustive()
    }
}

struct WriterState {
    /// Current hour tag (e.g., "2026-05-28T14").
    current_hour_tag: String,
    /// Buffered writer for the active event file.
    writer: Option<BufWriter<fs::File>>,
    /// The manifest (kept up to date on rotation).
    manifest: FactStoreManifest,
    /// Total events written since store creation.
    total_events: u64,
}

impl FactStoreWriter {
    /// Create a new fact store writer.
    ///
    /// Creates the base directory if it doesn't exist. If an existing
    /// manifest is found on disk, it is loaded; otherwise a fresh one
    /// is created.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the directory cannot be created or
    /// the active file cannot be opened.
    pub fn new(base_dir: PathBuf) -> std::io::Result<Self> {
        Self::with_retention(base_dir, RetentionConfig::default())
    }

    /// Create with explicit retention config.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the directory cannot be created or
    /// the active file cannot be opened.
    pub fn with_retention(base_dir: PathBuf, retention: RetentionConfig) -> std::io::Result<Self> {
        fs::create_dir_all(&base_dir)?;

        let now = Utc::now();
        let hour_tag = format_hour_tag(now);
        let manifest_path = base_dir.join("derived-manifest.json");

        // Try to load existing manifest.
        let (manifest, writer) = if manifest_path.exists() {
            let json = fs::read_to_string(&manifest_path)?;
            if let Some(mut m) = FactStoreManifest::from_json(&json) {
                // Check if the active file needs rotation.
                let active_tag = extract_hour_tag(&m.active_event_file);
                if active_tag.as_deref() == Some(&hour_tag) {
                    // Same hour — append to existing file.
                    let path = base_dir.join(&m.active_event_file);
                    let file = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&path)?;
                    (m, Some(BufWriter::new(file)))
                } else {
                    // Different hour — seal old file and start new one.
                    m.rotate(&hour_tag);
                    let path = base_dir.join(&m.active_event_file);
                    let file = fs::OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(&path)?;
                    (m, Some(BufWriter::new(file)))
                }
            } else {
                // Corrupt manifest — start fresh.
                let m = FactStoreManifest::new(&hour_tag);
                let path = base_dir.join(&m.active_event_file);
                let file = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&path)?;
                (m, Some(BufWriter::new(file)))
            }
        } else {
            // No existing manifest — create fresh.
            let m = FactStoreManifest::new(&hour_tag);
            let path = base_dir.join(&m.active_event_file);
            let file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)?;
            (m, Some(BufWriter::new(file)))
        };

        let state = WriterState {
            current_hour_tag: hour_tag,
            writer,
            manifest,
            total_events: 0,
        };

        let sw = Self {
            base_dir,
            inner: Mutex::new(state),
            retention,
        };

        // Persist manifest on initial creation so it's available on reload.
        {
            let state = sw.inner.lock().expect("fact store lock poisoned");
            sw.persist_manifest(&state)?;
        }

        Ok(sw)
    }

    /// Write a single `FactEmit` event to the active JSONL file.
    ///
    /// If the hour has changed since the last write, the current file is
    /// sealed and a new hourly file is opened.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` on write failure.
    pub fn write_event(&self, event: &FactEmit) -> std::io::Result<()> {
        let now = Utc::now();
        let hour_tag = format_hour_tag(now);

        let mut state = self.inner.lock().expect("fact store lock poisoned");

        // Rotate if the hour has changed.
        if hour_tag != state.current_hour_tag {
            self.rotate_locked(&mut state, &hour_tag)?;
        }

        // Serialize and write.
        if let Some(line) = event.to_jsonl_line() {
            if let Some(ref mut writer) = state.writer {
                writer.write_all(line.as_bytes())?;
                writer.write_all(b"\n")?;
                writer.flush()?;
            }
        }

        state.total_events += 1;

        // Update manifest counters.
        state.manifest.counters.meaningful_events_total = state.total_events;
        state.manifest.updated_at = now;

        // Persist manifest on disk (governance events are infrequent).
        self.persist_manifest(&state)?;

        Ok(())
    }

    /// Seal the current active file and open a new one for `new_hour_tag`.
    ///
    /// Called automatically when the hour changes, but can also be called
    /// manually for testing.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if the new file cannot be opened.
    pub fn rotate(&self, new_hour_tag: &str) -> std::io::Result<()> {
        let mut state = self.inner.lock().expect("fact store lock poisoned");
        self.rotate_locked(&mut state, new_hour_tag)
    }

    fn rotate_locked(&self, state: &mut WriterState, new_hour_tag: &str) -> std::io::Result<()> {
        // Flush and close current writer.
        if let Some(mut writer) = state.writer.take() {
            writer.flush()?;
        }

        // Rename active file to sealed.
        let old_active = self.base_dir.join(&state.manifest.active_event_file);
        if old_active.exists() {
            let sealed_name = state
                .manifest
                .active_event_file
                .replace("events-active-", "events-sealed-");
            let sealed_path = self.base_dir.join(&sealed_name);
            // If sealed file already exists (e.g., restart within same hour),
            // just append to sealed_event_files list.
            if !sealed_path.exists() {
                fs::rename(&old_active, &sealed_path)?;
            }
            state.manifest.sealed_event_files.push(sealed_name);
        }

        // Start new active file.
        state.manifest.rotate(new_hour_tag);
        state.current_hour_tag = new_hour_tag.to_string();

        let new_path = self.base_dir.join(&state.manifest.active_event_file);
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&new_path)?;
        state.writer = Some(BufWriter::new(file));

        // Persist manifest.
        self.persist_manifest(state)?;

        Ok(())
    }

    /// Persist the manifest to `derived-manifest.json`.
    fn persist_manifest(&self, state: &WriterState) -> std::io::Result<()> {
        if let Some(json) = state.manifest.to_json() {
            let path = self.base_dir.join("derived-manifest.json");
            fs::write(&path, json)?;
        }
        Ok(())
    }

    /// Get the current manifest snapshot.
    #[must_use]
    pub fn manifest(&self) -> FactStoreManifest {
        let state = self.inner.lock().expect("fact store lock poisoned");
        state.manifest.clone()
    }

    /// Get total events written.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        let state = self.inner.lock().expect("fact store lock poisoned");
        state.total_events
    }

    /// Apply retention: remove sealed files older than `keep_sealed_hours`.
    ///
    /// # Errors
    ///
    /// Returns `std::io::Error` if file deletion fails.
    pub fn apply_retention(&self, now: DateTime<Utc>) -> std::io::Result<()> {
        let mut state = self.inner.lock().expect("fact store lock poisoned");
        let threshold = chrono::Duration::hours(self.retention.keep_sealed_hours as i64);

        let mut kept = Vec::new();
        for sealed_name in &state.manifest.sealed_event_files {
            if let Some(ts_str) = extract_hour_tag(sealed_name) {
                if let Ok(ts) = chrono::NaiveDateTime::parse_from_str(
                    &format!("{ts_str}:00:00"),
                    "%Y-%m-%dT%H:%M:%S",
                ) {
                    let sealed_at = DateTime::<Utc>::from_naive_utc_and_offset(ts, Utc);
                    if now - sealed_at > threshold {
                        let path = self.base_dir.join(sealed_name);
                        if path.exists() {
                            let _ = fs::remove_file(&path);
                        }
                        continue;
                    }
                }
            }
            kept.push(sealed_name.clone());
        }
        state.manifest.sealed_event_files = kept;

        // Persist updated manifest.
        self.persist_manifest(&state)?;
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────

/// Format a `DateTime<Utc>` as an hour tag: `YYYY-MM-DDTHH`.
fn format_hour_tag(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H").to_string()
}

/// Extract the hour tag from a filename like `events-active-2026-05-28T14.jsonl`
/// or `events-sealed-2026-05-28T14.jsonl`.
fn extract_hour_tag(filename: &str) -> Option<String> {
    filename
        .strip_prefix("events-active-")
        .or_else(|| filename.strip_prefix("events-sealed-"))
        .and_then(|s| s.strip_suffix(".jsonl"))
        .map(String::from)
}

#[cfg(test)]
#[path = "fact_store_tests.rs"]
mod tests;
