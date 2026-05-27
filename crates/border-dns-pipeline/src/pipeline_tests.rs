use std::sync::Arc;

use border_dns_cache::DnsCache;
use border_dns_config::Config;
use border_dns_config::{self};
use border_dns_domain_knowledge::BuiltInDomainKnowledge;
use border_dns_geoip::SimpleGeoIp;

use super::Pipeline;

fn test_config() -> Config {
    let toml_str = r#"
[server]

[listeners.udp]
enabled = true
listen = "0.0.0.0:5353"

[[upstreams.default]]
name = "test"
endpoint = "223.5.5.5:53"
"#;
    border_dns_config::load_from_str(toml_str).unwrap()
}

#[test]
fn test_pipeline_creation() {
    let config = Arc::new(test_config());
    let cache = Arc::new(DnsCache::new(config.cache.clone()));
    let knowledge = Arc::new(BuiltInDomainKnowledge::new());
    let geoip = Arc::new(SimpleGeoIp);
    let _pipeline = Pipeline::new(config, cache, knowledge, geoip);
}
