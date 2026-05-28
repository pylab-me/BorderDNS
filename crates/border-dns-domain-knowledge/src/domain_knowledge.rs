//! Domain-level business knowledge for BorderDNS routing.
//!
//! Provides domain classification (China/foreign/global CDN/CNAME hints)
//! using a trie-based rule matcher. This replaces the semantic parts of
//! Python `structures/domain_sets.py`, `structures/domain_rules.py`,
//! and `structures/dns_filters.py`.

use std::collections::HashSet;

use dns_types::CnameHint;
use dns_types::DomainPrior;

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
pub(crate) struct DomainSet {
    children: std::collections::HashMap<String, DomainSet>,
    terminal: bool,
}

impl DomainSet {
    pub(crate) fn insert(&mut self, domain: &str) {
        let labels: Vec<&str> = domain.split('.').filter(|l| !l.is_empty()).rev().collect();
        let mut node = self;
        for label in labels {
            node = node.children.entry(label.to_lowercase()).or_default();
        }
        node.terminal = true;
    }

    pub(crate) fn contains(&self, domain: &str) -> bool {
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

    pub(crate) fn len(&self) -> usize {
        let mut count = usize::from(self.terminal);
        for child in self.children.values() {
            count += child.len();
        }
        count
    }

    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
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

pub(crate) const CHINA_DOMAINS: &[&str] = &[
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

pub(crate) const FOREIGN_DOMAINS: &[&str] = &[
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

pub(crate) const CDN_DOMAINS: &[&str] = &[
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

pub(crate) const CHINA_CNAME_PROVIDERS: &[&str] = &[
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

pub(crate) const FOREIGN_CNAME_PROVIDERS: &[&str] = &[
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
