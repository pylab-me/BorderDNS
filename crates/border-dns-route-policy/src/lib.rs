//! Route decision and scoring logic for BorderDNS.
//!
//! Implements the core routing pipeline:
//! ```text
//! domain prior > cname hint > answer geo > default route
//! ```
//!
//! Hard rule:
//! ```text
//! Geo first, ms second.
//! IP latency is quality evidence, not route authority.
//! ```
//!
//! This crate should be as close to pure functions as practical.
//! It must not depend on runtime or upstream network clients.

use std::net::IpAddr;

use border_dns_domain_knowledge::DomainKnowledge;
use border_dns_geoip::GeoIpLookup;
use dns_protocol::rr::RData;
use dns_types::CnameHint;
use dns_types::Confidence;
use dns_types::DomainPrior;
use dns_types::IpGeoScope;
use dns_types::ReasonCode;
use dns_types::ResolverLocation;
use dns_types::Route;
use dns_types::RouteSource;

// ─── Route Decision ──────────────────────────────────────────────

/// Complete route decision output.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub execution_route: Route,
    pub route_source: RouteSource,
    pub confidence: Confidence,
    pub china_score: f64,
    pub foreign_score: f64,
    pub score_margin: f64,
    pub reason_codes: Vec<ReasonCode>,
}

impl Default for RouteDecision {
    fn default() -> Self {
        Self {
            execution_route: Route::Fallback,
            route_source: RouteSource::FallbackPolicy,
            confidence: Confidence::None,
            china_score: 0.0,
            foreign_score: 0.0,
            score_margin: 0.0,
            reason_codes: vec![ReasonCode::FallbackRoute],
        }
    }
}

// ─── Geo Evidence Input ──────────────────────────────────────────

/// IP addresses extracted from a DNS response.
#[derive(Debug, Clone, Default)]
pub struct AnswerGeoEvidence {
    pub cn_count: usize,
    pub foreign_count: usize,
    pub private_count: usize,
    pub total: usize,
}

// ─── Route Policy Engine ─────────────────────────────────────────

/// Pure route decision engine.
#[derive(Debug)]
pub struct RoutePolicy {
    resolver_location: ResolverLocation,
}

impl RoutePolicy {
    #[must_use]
    pub fn new(resolver_location: ResolverLocation) -> Self {
        Self { resolver_location }
    }

    #[must_use]
    pub fn decide_by_domain_prior(
        &self,
        domain: &str,
        knowledge: &dyn DomainKnowledge,
    ) -> RouteDecision {
        let prior = knowledge.classify_domain(domain);
        let mut decision = RouteDecision::default();

        match prior {
            DomainPrior::China => {
                decision.execution_route = Route::China;
                decision.route_source = RouteSource::DomainPrior;
                decision.confidence = Confidence::Strong;
                decision.china_score = 1.0;
                decision.foreign_score = 0.0;
                decision.score_margin = 1.0;
                decision.reason_codes = vec![ReasonCode::DomainPriorCn];
            }
            DomainPrior::Foreign => {
                decision.execution_route = Route::Foreign;
                decision.route_source = RouteSource::DomainPrior;
                decision.confidence = Confidence::Strong;
                decision.china_score = 0.0;
                decision.foreign_score = 1.0;
                decision.score_margin = 1.0;
                decision.reason_codes = vec![ReasonCode::DomainPriorForeign];
            }
            DomainPrior::GlobalCdn => {
                decision.route_source = RouteSource::DomainPrior;
                decision.confidence = Confidence::Weak;
                decision.reason_codes = vec![ReasonCode::GlobalCdn];
                match self.resolver_location {
                    ResolverLocation::China => {
                        decision.execution_route = Route::China;
                        decision.china_score = 0.3;
                        decision.foreign_score = 0.1;
                    }
                    ResolverLocation::Foreign => {
                        decision.execution_route = Route::Foreign;
                        decision.china_score = 0.1;
                        decision.foreign_score = 0.3;
                    }
                    ResolverLocation::Unknown => {
                        decision.execution_route = Route::Fallback;
                        decision.china_score = 0.0;
                        decision.foreign_score = 0.0;
                    }
                }
                decision.score_margin = (decision.china_score - decision.foreign_score).abs();
            }
            DomainPrior::Unknown => {
                decision.route_source = RouteSource::DefaultPolicy;
                decision.confidence = Confidence::None;
                decision.reason_codes = vec![ReasonCode::DefaultRoute];
                match self.resolver_location {
                    ResolverLocation::China => {
                        decision.execution_route = Route::China;
                    }
                    ResolverLocation::Foreign => {
                        decision.execution_route = Route::Foreign;
                    }
                    ResolverLocation::Unknown => {
                        decision.execution_route = Route::Fallback;
                        decision.reason_codes = vec![ReasonCode::FallbackRoute];
                    }
                }
            }
        }

        decision
    }

    pub fn refine_by_cname(
        &self,
        decision: &mut RouteDecision,
        cnames: &[&str],
        knowledge: &dyn DomainKnowledge,
    ) {
        let hint = knowledge.classify_cname_chain(cnames);

        match hint {
            CnameHint::ChinaProvider => {
                if decision.execution_route == Route::China {
                    decision.confidence = Confidence::Strong;
                    decision.china_score = (decision.china_score + 0.2).min(1.0);
                    decision.reason_codes.push(ReasonCode::CnameHint);
                } else if decision.execution_route == Route::Foreign {
                    decision.reason_codes.push(ReasonCode::MixedGeo);
                    decision.confidence = Confidence::Weak;
                }
            }
            CnameHint::ForeignProvider => {
                if decision.execution_route == Route::Foreign {
                    decision.confidence = Confidence::Strong;
                    decision.foreign_score = (decision.foreign_score + 0.2).min(1.0);
                    decision.reason_codes.push(ReasonCode::CnameHint);
                } else if decision.execution_route == Route::China {
                    decision.reason_codes.push(ReasonCode::MixedGeo);
                    decision.confidence = Confidence::Weak;
                }
            }
            CnameHint::GlobalCdn => {
                decision.reason_codes.push(ReasonCode::GlobalCdn);
            }
            CnameHint::None => {}
        }
    }

    #[must_use]
    pub fn analyze_answer_geo(
        &self,
        answers: &[dns_protocol::rr::ResourceRecord],
        geoip: &dyn GeoIpLookup,
    ) -> AnswerGeoEvidence {
        let mut evidence = AnswerGeoEvidence::default();

        for rr in answers {
            let ip = match &rr.rdata {
                RData::A(addr) => Some(IpAddr::V4(*addr)),
                RData::AAAA(addr) => Some(IpAddr::V6(*addr)),
                _ => None,
            };

            if let Some(ip) = ip {
                evidence.total += 1;
                let result = geoip.lookup(ip);
                match result.scope {
                    IpGeoScope::Cn => evidence.cn_count += 1,
                    IpGeoScope::Foreign => evidence.foreign_count += 1,
                    IpGeoScope::Private | IpGeoScope::Reserved => evidence.private_count += 1,
                    IpGeoScope::Unknown => {}
                }
            }
        }

        evidence
    }

    pub fn refine_by_answer_geo(&self, decision: &mut RouteDecision, evidence: &AnswerGeoEvidence) {
        if evidence.total == 0 {
            return;
        }

        let classified = evidence.cn_count + evidence.foreign_count;
        if classified == 0 {
            return;
        }

        let cn_ratio = evidence.cn_count as f64 / classified as f64;
        let foreign_ratio = evidence.foreign_count as f64 / classified as f64;

        decision.china_score = (decision.china_score + cn_ratio * 0.3).min(1.0);
        decision.foreign_score = (decision.foreign_score + foreign_ratio * 0.3).min(1.0);
        decision.score_margin = (decision.china_score - decision.foreign_score).abs();

        if evidence.cn_count > 0 && evidence.foreign_count > 0 {
            if !decision.reason_codes.contains(&ReasonCode::MixedGeo) {
                decision.reason_codes.push(ReasonCode::MixedGeo);
            }
            if decision.confidence > Confidence::Weak {
                decision.confidence = Confidence::Weak;
            }
            return;
        }

        if evidence.cn_count > 0 {
            decision.reason_codes.push(ReasonCode::GeoIpCn);
        } else if evidence.foreign_count > 0 {
            decision.reason_codes.push(ReasonCode::GeoIpForeign);
        }

        if decision.confidence == Confidence::None {
            decision.confidence = Confidence::Moderate;
        }
    }

    #[must_use]
    pub fn select_answer_candidates(
        &self,
        answers: &[dns_protocol::rr::ResourceRecord],
        geoip: &dyn GeoIpLookup,
        route: Route,
    ) -> Vec<dns_protocol::rr::ResourceRecord> {
        let is_china_route =
            self.resolver_location == ResolverLocation::China && route == Route::China;

        if !is_china_route {
            return answers.to_vec();
        }

        let mut cn_candidates = Vec::new();
        let mut other_candidates = Vec::new();

        for rr in answers {
            let ip = match &rr.rdata {
                RData::A(addr) => Some(IpAddr::V4(*addr)),
                RData::AAAA(addr) => Some(IpAddr::V6(*addr)),
                _ => None,
            };

            if let Some(ip) = ip {
                let result = geoip.lookup(ip);
                if result.scope == IpGeoScope::Cn {
                    cn_candidates.push(rr.clone());
                } else {
                    other_candidates.push(rr.clone());
                }
            } else {
                other_candidates.push(rr.clone());
            }
        }

        if cn_candidates.is_empty() {
            return other_candidates;
        }

        cn_candidates.extend(other_candidates);
        cn_candidates
    }
}

#[cfg(test)]
#[path = "route_policy_tests.rs"]
mod tests;
