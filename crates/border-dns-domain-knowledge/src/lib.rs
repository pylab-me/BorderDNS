//! Domain-level business knowledge for BorderDNS routing.
//!
//! Provides domain classification (China/foreign/global CDN/CNAME hints)
//! using a trie-based rule matcher. This replaces the semantic parts of
//! Python `structures/domain_sets.py`, `structures/domain_rules.py`,
//! and `structures/dns_filters.py`.
//!
//! Also provides:
//! - `HostsTable`: static domain → IP overrides (like /etc/hosts).
//! - `BlockMatcher`: domain blocking by exact name or suffix.
//!
//! This crate must not depend on runtime, upstream, or network crates.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::SystemTime;

use dns_types::CnameHint;
use dns_types::DomainPrior;
use dns_types::QType;
use dns_types::RecordType;

// ─── Core trait ──────────────────────────────────────────────────

/// Domain knowledge interface.
///
/// Implementations classify domains and CNAME chains for routing.
pub trait DomainKnowledge: Send + Sync {
    /// Classify a domain for routing purposes.
    fn classify_domain(&self, domain: &str) -> DomainPrior;

    /// Classify a CNAME chain for routing hints.
    fn classify_cname_chain(&self, cnames: &[&str]) -> CnameHint;
}

// ─── Trie-based domain matcher ───────────────────────────────────

/// A set of domain names stored as reversed-label tries for fast matching.
#[derive(Debug, Clone, Default)]
struct DomainSet {
    children: std::collections::HashMap<String, DomainSet>,
    terminal: bool,
}

impl DomainSet {
    fn insert(&mut self, domain: &str) {
        let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).rev().collect();
        let mut node = self;
        for label in labels {
            node = node.children.entry(label.to_lowercase()).or_default();
        }
        node.terminal = true;
    }

    fn contains(&self, domain: &str) -> bool {
        let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).rev().collect();
        self.contains_labels(&labels)
    }

    fn contains_labels(&self, labels: &[&str]) -> bool {
        if labels.is_empty() {
            return self.terminal;
        }
        if let Some(child) = self.children.get(labels[0].to_lowercase().as_str()) {
            if child.contains_labels(&labels[1..]) {
                return true;
            }
        }
        false
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        let mut count = usize::from(self.terminal);
        for child in self.children.values() {
            count += child.len();
        }
        count
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── Built-in domain knowledge implementation ────────────────────

/// Built-in domain knowledge with hardcoded China/foreign/CDN domain lists.
///
/// The lists are derived from the Python `structures/domain_sets.py`
/// reference implementation and extended for production use.
#[derive(Debug, Clone)]
pub struct BuiltInDomainKnowledge {
    /// Domains classified as China-origin.
    pub(crate) china_domains: DomainSet,
    /// Domains classified as foreign-origin.
    pub(crate) foreign_domains: DomainSet,
    /// Global CDN domains (cloudflare, akamai, fastly, etc.).
    cdn_domains: DomainSet,
    /// Known China CNAME providers.
    china_cname_providers: HashSet<String>,
    /// Known foreign CNAME providers.
    foreign_cname_providers: HashSet<String>,
}

impl BuiltInDomainKnowledge {
    /// Create a new instance with built-in domain lists.
    #[must_use]
    pub fn new() -> Self {
        let mut knowledge = Self {
            china_domains: DomainSet::default(),
            foreign_domains: DomainSet::default(),
            cdn_domains: DomainSet::default(),
            china_cname_providers: HashSet::new(),
            foreign_cname_providers: HashSet::new(),
        };
        knowledge.init_china_domains();
        knowledge.init_foreign_domains();
        knowledge.init_cdn_domains();
        knowledge.init_cname_providers();
        knowledge
    }

    fn init_china_domains(&mut self) {
        for domain in CHINA_DOMAINS {
            self.china_domains.insert(domain);
        }
    }

    fn init_foreign_domains(&mut self) {
        for domain in FOREIGN_DOMAINS {
            self.foreign_domains.insert(domain);
        }
    }

    fn init_cdn_domains(&mut self) {
        for domain in CDN_DOMAINS {
            self.cdn_domains.insert(domain);
        }
    }

    fn init_cname_providers(&mut self) {
        for provider in CHINA_CNAME_PROVIDERS {
            self.china_cname_providers.insert(provider.to_lowercase());
        }
        for provider in FOREIGN_CNAME_PROVIDERS {
            self.foreign_cname_providers.insert(provider.to_lowercase());
        }
    }
}

impl Default for BuiltInDomainKnowledge {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainKnowledge for BuiltInDomainKnowledge {
    fn classify_domain(&self, domain: &str) -> DomainPrior {
        let normalized = domain.strip_suffix('.').unwrap_or(domain);

        if self.cdn_domains.contains(normalized) {
            return DomainPrior::GlobalCdn;
        }
        if self.china_domains.contains(normalized) {
            return DomainPrior::China;
        }
        if self.foreign_domains.contains(normalized) {
            return DomainPrior::Foreign;
        }
        DomainPrior::Unknown
    }

    fn classify_cname_chain(&self, cnames: &[&str]) -> CnameHint {
        for cname in cnames {
            let normalized = cname.strip_suffix('.').unwrap_or(cname);
            let lower = normalized.to_lowercase();

            if self.cdn_domains.contains(normalized) {
                return CnameHint::GlobalCdn;
            }
            for provider in &self.china_cname_providers {
                if lower.contains(provider.as_str()) {
                    return CnameHint::ChinaProvider;
                }
            }
            for provider in &self.foreign_cname_providers {
                if lower.contains(provider.as_str()) {
                    return CnameHint::ForeignProvider;
                }
            }
        }
        CnameHint::None
    }
}

// ─── Built-in domain lists ───────────────────────────────────────

const CHINA_DOMAINS: &[&str] = &[
    "qq.com",
    "taobao.com",
    "tmall.com",
    "alipay.com",
    "alibaba.com",
    "jd.com",
    "baidu.com",
    "weibo.com",
    "sina.com",
    "163.com",
    "126.com",
    "sohu.com",
    "zhihu.com",
    "douyin.com",
    "toutiao.com",
    "bilibili.com",
    "xiaomi.com",
    "huawei.com",
    "meituan.com",
    "ele.me",
    "dianping.com",
    "csdn.net",
    "cnblogs.com",
    "aliyun.com",
    "tencent.com",
    "weixin.qq.com",
    "qq邮箱",
    "ctrip.com",
    "ly.com",
    "mafengwo.cn",
    "ximalaya.com",
    "iqiyi.com",
    "youku.com",
    "tudou.com",
    "pptv.com",
    "mgtv.com",
    "snssdk.com",
    "bytedance.com",
    "feishu.cn",
    "larksuite.com",
    "dingtalk.com",
    "pinduoduo.com",
    "pdd.com",
    "suning.com",
    "zhangxinxu.com",
    "runoob.com",
    "gitee.com",
    "coding.net",
    "juejin.cn",
    "segmentfault.com",
    "cnbeta.com",
    "ithome.com",
    "36kr.com",
    "huxiu.com",
    "ifanr.com",
    "sspai.com",
    "smzdm.com",
    "duokan.com",
    "wps.cn",
    "naver.com",
    "naver.kr",
    "nhn.com",
];

const FOREIGN_DOMAINS: &[&str] = &[
    "openai.com",
    "chatgpt.com",
    "anthropic.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "youtube.com",
    "ytimg.com",
    "googlevideo.com",
    "facebook.com",
    "fbcdn.net",
    "instagram.com",
    "cdninstagram.com",
    "twitter.com",
    "x.com",
    "twimg.com",
    "reddit.com",
    "redd.it",
    "redditstatic.com",
    "redditmedia.com",
    "amazon.com",
    "amazonaws.com",
    "cloudfront.net",
    "aws.amazon.com",
    "microsoft.com",
    "live.com",
    "office.com",
    "office365.com",
    "azure.com",
    "github.com",
    "github.io",
    "githubusercontent.com",
    "githubassets.com",
    "github.dev",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "slack.com",
    "slack-edge.com",
    "t.me",
    "telegram.org",
    "telegram.me",
    "whatsapp.com",
    "whatsapp.net",
    "signal.org",
    "signal-cdn.org",
    "netflix.com",
    "nflxvideo.net",
    "nflximg.net",
    "spotify.com",
    "spotifycdn.com",
    "soundcloud.com",
    "twitch.tv",
    "ttvnw.net",
    "jtvnw.net",
    "npmjs.com",
    "npmjs.org",
    "pypi.org",
    "crates.io",
    "docker.com",
    "docker.io",
    "dockerhub.com",
    "dockerusercontent.com",
    "vercel.com",
    "vercel.app",
    "netlify.com",
    "netlify.app",
    "heroku.com",
    "herokuapp.com",
    "digitalocean.com",
    "cloudflare.com",
    "wikipedia.org",
    "wikimedia.org",
    "medium.com",
    "substack.com",
    "stackexchange.com",
    "stackoverflow.com",
    "superuser.com",
    "bbc.com",
    "bbc.co.uk",
    "cnn.com",
    "nytimes.com",
    "wsj.com",
    "reuters.com",
    "theguardian.com",
    "bloomberg.com",
    "line.me",
    "lycorp.com",
];

const CDN_DOMAINS: &[&str] = &[
    "cloudflare.com",
    "cloudfront.net",
    "akamaized.net",
    "akamai.net",
    "akamaiedge.net",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "fastlylb.net",
    "fastly.com",
    "cdn77.org",
    "cdn77.com",
    "stackpath.com",
    "stackpathdns.com",
    "incapsula.com",
    "imperva.com",
    "sucuri.net",
    "quantil.com",
    "band-cdn.com",
    "cdnetworks.com",
    "chinanetcenter.com",
    "wsdvs.com",
    "kunlun.com",
    "kunlunca.com",
    "alikunlun.com",
    "alicdn.com",
    "taobaocdn.com",
    "tmallcdn.com",
];

const CHINA_CNAME_PROVIDERS: &[&str] = &[
    "alicdn.com",
    "alikunlun.com",
    "taobaocdn.com",
    "tmallcdn.com",
    "alibaba",
    "aliyun",
    "kunlun",
    "china",
    "chinacache",
    "cdnetworks",
    "wangsu",
];

const FOREIGN_CNAME_PROVIDERS: &[&str] = &[
    "cloudflare",
    "cloudfront",
    "amazonaws",
    "akamai",
    "fastly",
    "cdn77",
    "stackpath",
    "incapsula",
    "imperva",
    "vercel",
    "netlify",
    "heroku",
    "google",
    "googleapis",
    "azure",
    "microsoft",
];

// ═══════════════════════════════════════════════════════════════════
// HostsTable: static domain → IP overrides
// ═══════════════════════════════════════════════════════════════════

/// A single parsed hosts entry (domain → IP).
#[derive(Debug, Clone)]
pub struct HostEntry {
    pub domain: String,
    pub ip: std::net::IpAddr,
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
        if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
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
    pub fn match_domain(&self, domain: &str, qtype: QType) -> Vec<std::net::IpAddr> {
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
                    if let Ok(ip) = parts[0].parse::<std::net::IpAddr>() {
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

// ═══════════════════════════════════════════════════════════════════
// BlockMatcher: domain blocking by exact name or suffix
// ═══════════════════════════════════════════════════════════════════

/// Domain blocking matcher.
///
/// Checks domains against:
/// 1. Exact domain names.
/// 2. Domain suffixes (any domain ending with the suffix is blocked).
///
/// This is pure data matching — no DNS encoding, no response building.
/// Response construction belongs to the pipeline stage.
#[derive(Debug, Clone)]
pub struct BlockMatcher {
    /// Exact domain names to block (lowercase, no trailing dot).
    exact: HashSet<String>,
    /// Domain suffixes to block (lowercase, no trailing dot).
    suffixes: Vec<String>,
}

impl BlockMatcher {
    /// Create a matcher from lists of exact domains and suffixes.
    #[must_use]
    pub fn new(exact_domains: &[&str], suffixes: &[&str]) -> Self {
        let exact = exact_domains
            .iter()
            .map(|d| d.strip_suffix('.').unwrap_or(d).to_lowercase())
            .collect();
        let suffixes = suffixes
            .iter()
            .map(|s| s.strip_suffix('.').unwrap_or(s).to_lowercase())
            .collect();
        Self { exact, suffixes }
    }

    /// Check if a domain should be blocked.
    #[must_use]
    pub fn is_blocked(&self, domain: &str) -> bool {
        let name = domain.strip_suffix('.').unwrap_or(domain).to_lowercase();

        if self.exact.contains(&name) {
            return true;
        }

        for suffix in &self.suffixes {
            if name == *suffix || name.ends_with(&format!(".{suffix}")) {
                return true;
            }
        }

        false
    }

    /// Whether this matcher has any rules.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffixes.is_empty()
    }

    /// Number of rules (exact + suffixes).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }
}

impl Default for BlockMatcher {
    fn default() -> Self {
        Self {
            exact: HashSet::new(),
            suffixes: Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "domain_knowledge_tests.rs"]
mod tests;
