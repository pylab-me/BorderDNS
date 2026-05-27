//! DNS TTL cache with basic metrics.
//!
//! Sprint 1 cache is simple: `qtype + domain` as cache key.
//! Route-scoped cache is Sprint 2.

use std::time::Instant;

use dashmap::DashMap;
use dns_protocol::message::DnsMessage;
use dns_protocol::name::DomainName;
use dns_types::QType;

/// Cache key: combined qtype + domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Query type.
    qtype: QType,
    /// Domain name (labels).
    labels: Vec<Vec<u8>>,
}

impl CacheKey {
    fn new(qtype: QType, name: &DomainName) -> Self {
        Self {
            qtype,
            labels: name.labels().map(|l| l.to_vec()).collect(),
        }
    }
}

/// A cached DNS response entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The DNS response message.
    message: DnsMessage,
    /// When this entry was stored.
    inserted_at: Instant,
    /// Effective TTL in seconds (clamped between min_ttl and max_ttl).
    ttl_secs: u32,
}

impl CacheEntry {
    /// Whether this entry has expired.
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed().as_secs() >= u64::from(self.ttl_secs)
    }
}

/// Cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total cache hits.
    pub hits: u64,
    /// Total cache misses.
    pub misses: u64,
    /// Total entries evicted (expired or capacity).
    pub evictions: u64,
    /// Current number of entries.
    pub entries: usize,
}

/// DNS response cache.
///
/// Thread-safe via `DashMap`. Supports TTL-based expiration.
#[derive(Debug)]
pub struct DnsCache {
    entries: DashMap<CacheKey, CacheEntry>,
    stats: CacheMetrics,
    config: CacheConfig,
}

/// Internal metrics counters.
#[derive(Debug, Default)]
struct CacheMetrics {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    evictions: std::sync::atomic::AtomicU64,
}

use std::sync::atomic::Ordering;

use border_dns_config::CacheConfig;

impl CacheMetrics {
    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }
}

impl DnsCache {
    /// Create a new cache with the given configuration.
    #[must_use]
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: DashMap::with_capacity(config.max_entries),
            stats: CacheMetrics::default(),
            config,
        }
    }

    /// Look up a cached response for the given query.
    ///
    /// Returns `Some(message)` if a valid (non-expired) entry exists.
    pub fn get(&self, qtype: QType, name: &DomainName) -> Option<DnsMessage> {
        let key = CacheKey::new(qtype, name);
        if let Some(entry) = self.entries.get(&key) {
            if entry.is_expired() {
                drop(entry);
                self.entries.remove(&key);
                self.stats.record_miss();
                return None;
            }
            self.stats.record_hit();
            tracing::trace!(qtype = ?qtype, domain = %name, "cache hit");
            Some(entry.message.clone())
        } else {
            self.stats.record_miss();
            None
        }
    }

    /// Insert a DNS response into the cache.
    ///
    /// The TTL is extracted from the first answer record, clamped
    /// between `min_ttl` and `max_ttl`. The answer record TTLs in
    /// the stored message are also updated to the clamped value.
    pub fn insert(&self, qtype: QType, name: &DomainName, mut message: DnsMessage) {
        let ttl = self.clamp_ttl(extract_min_ttl(&message));

        // Update answer record TTLs to the clamped value.
        for rr in &mut message.answers {
            rr.ttl = ttl;
        }

        // Evict oldest if at capacity.
        if self.entries.len() >= self.config.max_entries {
            self.evict_oldest();
        }

        let key = CacheKey::new(qtype, name);
        let entry = CacheEntry {
            message,
            inserted_at: Instant::now(),
            ttl_secs: ttl,
        };
        self.entries.insert(key, entry);
        tracing::trace!(
            qtype = ?qtype,
            domain = %name,
            ttl = ttl,
            "cache insert"
        );
    }

    /// Insert a negative cache entry (NXDOMAIN, SERVFAIL, etc.).
    ///
    /// Uses the configured negative TTL.
    pub fn insert_negative(&self, qtype: QType, name: &DomainName, message: DnsMessage) {
        let key = CacheKey::new(qtype, name);
        let entry = CacheEntry {
            message,
            inserted_at: Instant::now(),
            ttl_secs: self.config.negative_ttl_secs,
        };
        self.entries.insert(key, entry);
        tracing::trace!(
            qtype = ?qtype,
            domain = %name,
            ttl = self.config.negative_ttl_secs,
            "negative cache insert"
        );
    }

    /// Get cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.stats.hits.load(Ordering::Relaxed),
            misses: self.stats.misses.load(Ordering::Relaxed),
            evictions: self.stats.evictions.load(Ordering::Relaxed),
            entries: self.entries.len(),
        }
    }

    /// Clear all cache entries.
    pub fn clear(&self) {
        self.entries.clear();
    }

    fn clamp_ttl(&self, ttl: u32) -> u32 {
        ttl.clamp(self.config.min_ttl_secs, self.config.max_ttl_secs)
    }

    fn evict_oldest(&self) {
        let mut oldest_key: Option<CacheKey> = None;
        let mut oldest_time = Instant::now();

        for entry in self.entries.iter() {
            if entry.inserted_at < oldest_time {
                oldest_time = entry.inserted_at;
                oldest_key = Some(entry.key().clone());
            }
        }

        if let Some(key) = oldest_key {
            self.entries.remove(&key);
            self.stats.record_eviction();
        }
    }
}

/// Extract the minimum TTL from all answer records in a DNS message.
fn extract_min_ttl(message: &DnsMessage) -> u32 {
    message.answers.iter().map(|rr| rr.ttl).min().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use dns_protocol::question::DnsQuestion;
    use dns_protocol::rr::RData;
    use dns_protocol::rr::ResourceRecord;
    use dns_types::QClass;
    use dns_types::RecordClass;
    use dns_types::RecordType;

    use super::*;

    fn make_test_response(name: &str, ip: Ipv4Addr, ttl: u32) -> DnsMessage {
        let q = DnsQuestion::new(
            DomainName::from_str(name).unwrap(),
            QType::Type(RecordType::A),
            QClass::Class(RecordClass::In),
        );
        let mut msg = DnsMessage::query(0x1234, q);
        msg.header.qr = true;
        msg.add_answer(ResourceRecord {
            name: DomainName::from_str(name).unwrap(),
            rr_type: RecordType::A,
            class: RecordClass::In,
            ttl,
            rdata: RData::A(ip),
        });
        msg
    }

    #[test]
    fn test_cache_hit_and_miss() {
        let config = CacheConfig::default();
        let cache = DnsCache::new(config);
        let name = DomainName::from_str("example.com").unwrap();
        let qtype = QType::Type(RecordType::A);

        // Miss.
        assert!(cache.get(qtype, &name).is_none());
        assert_eq!(cache.stats().misses, 1);

        // Insert.
        let resp = make_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        cache.insert(qtype, &name, resp.clone());

        // Hit.
        let cached = cache.get(qtype, &name).unwrap();
        assert_eq!(cached.header.id, 0x1234);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn test_ttl_clamping() {
        let config = CacheConfig {
            min_ttl_secs: 10,
            max_ttl_secs: 3600,
            ..CacheConfig::default()
        };
        let cache = DnsCache::new(config);
        let name = DomainName::from_str("example.com").unwrap();
        let qtype = QType::Type(RecordType::A);

        // TTL below min should be clamped to min.
        let resp = make_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 1);
        cache.insert(qtype, &name, resp);

        let cached = cache.get(qtype, &name).unwrap();
        assert_eq!(cached.answers[0].ttl, 10);
    }

    #[test]
    fn test_negative_cache() {
        let config = CacheConfig {
            negative_ttl_secs: 5,
            ..CacheConfig::default()
        };
        let cache = DnsCache::new(config);
        let name = DomainName::from_str("nonexistent.example.com").unwrap();
        let qtype = QType::Type(RecordType::A);

        let resp = make_test_response("nonexistent.example.com", Ipv4Addr::new(0, 0, 0, 0), 0);
        cache.insert_negative(qtype, &name, resp);

        // Should be in cache.
        assert!(cache.get(qtype, &name).is_some());
    }

    #[test]
    fn test_clear() {
        let config = CacheConfig::default();
        let cache = DnsCache::new(config);
        let name = DomainName::from_str("example.com").unwrap();
        let qtype = QType::Type(RecordType::A);

        let resp = make_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        cache.insert(qtype, &name, resp);
        assert!(cache.get(qtype, &name).is_some());

        cache.clear();
        assert!(cache.get(qtype, &name).is_none());
    }
}
