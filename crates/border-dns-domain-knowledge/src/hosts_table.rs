//! Static domain → IP overrides (like /etc/hosts).
//!
//! Loads entries from inline config and external hosts files.
//! Supports A (IPv4) and AAAA (IPv6) lookups by `QType`.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;

use dns_types::QType;
use dns_types::RecordType;

/// A single parsed hosts entry (domain → IP).
#[derive(Debug, Clone)]
pub struct HostEntry {
    pub domain: String,
    pub ip: IpAddr,
}

/// Static hosts override table.
///
/// Loads entries from:
/// 1. Inline config entries (domain → list of IPs).
/// 2. External hosts files (standard `/etc/hosts` format: `IP domain [domain2 ...]`).
///
/// Supports A (IPv4) and AAAA (IPv6) lookups by `QType`.
/// Supports file mtime-based hot reload via [`HostsTable::reload_if_changed`].
///
/// # Example
///
/// ```text
/// HostsTable::new()
///     .with_entry("blocked.local", "127.0.0.1")
///     .with_file(Path::new("/etc/hosts"))
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct HostsTable {
    entries: Vec<HostEntry>,
    file_paths: Vec<PathBuf>,
    file_mtimes: Vec<Option<SystemTime>>,
}

impl HostsTable {
    /// Create an empty hosts table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an inline entry (domain → IP string).
    #[must_use]
    pub fn with_entry(mut self, domain: &str, ip: &str) -> Self {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            self.entries.push(HostEntry {
                domain: domain.to_lowercase(),
                ip: addr,
            });
        }
        self
    }

    /// Add a hosts file path.
    #[must_use]
    pub fn with_file(mut self, path: PathBuf) -> Self {
        self.file_paths.push(path);
        self.file_mtimes.push(None);
        self
    }

    /// Build the final table (loads all files).
    #[must_use]
    pub fn build(mut self) -> Self {
        self.reload_all_files();
        self
    }

    /// Match a domain and return IPs for the given qtype.
    ///
    /// Returns `None` if no match (caller should continue to upstream).
    #[must_use]
    pub fn match_domain(&self, domain: &str, qtype: QType) -> Vec<IpAddr> {
        let name = domain.strip_suffix('.').unwrap_or(domain).to_lowercase();

        let want_v4 = matches!(qtype, QType::Type(RecordType::A));
        let want_v6 = matches!(qtype, QType::Type(RecordType::AAAA));

        if !want_v4 && !want_v6 {
            return Vec::new();
        }

        self.entries
            .iter()
            .filter(|e| e.domain == name)
            .filter(|e| (want_v4 && e.ip.is_ipv4()) || (want_v6 && e.ip.is_ipv6()))
            .map(|e| e.ip)
            .collect()
    }

    /// Check if any file has changed since last load.
    #[must_use]
    pub fn has_file_changes(&self) -> bool {
        self.file_paths.iter().enumerate().any(|(i, path)| {
            let current_mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
            current_mtime != self.file_mtimes.get(i).and_then(|t| *t)
        })
    }

    /// Reload all files (inline entries are preserved).
    pub fn reload_if_changed(&mut self) -> bool {
        if !self.has_file_changes() {
            return false;
        }
        self.reload_all_files();
        true
    }

    fn reload_all_files(&mut self) {
        for (i, path) in self.file_paths.iter().enumerate() {
            self.file_mtimes[i] = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());

            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 2 {
                        continue;
                    }
                    if let Ok(ip) = parts[0].parse::<IpAddr>() {
                        for domain_part in &parts[1..] {
                            let domain = domain_part
                                .strip_suffix('.')
                                .unwrap_or(domain_part)
                                .to_lowercase();
                            if !domain.is_empty() {
                                self.entries.push(HostEntry { domain, ip });
                            }
                        }
                    }
                }
            }
        }
    }
}
