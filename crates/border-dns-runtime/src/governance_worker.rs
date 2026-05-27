//! Background workers for BorderDNS governance.
//!
//! - `FactWriterWorker`: consumes `FactEmit` from the channel and writes to JSONL.
//! - `ObservationWorker`: consumes `ObservationJob` from the channel (currently logs only).
//! - `GovernanceMaintenanceWorker`: periodically decays 24h counters and generates
//!   review candidate artifacts.

use std::sync::Arc;
use std::time::Duration;

use border_dns_facts::FactEmit;
use border_dns_facts::FactStoreWriter;
use border_dns_facts::GovernancePhase;
use border_dns_facts::GovernanceStore;
use border_dns_facts::ObservationJob;
use border_dns_facts::ReviewCandidatesArtifact;
use border_dns_facts::ReviewDomainEntry;
use border_dns_facts::ReviewSummary;
use chrono::Utc;
use tokio::sync::mpsc;
use tracing::error;
use tracing::info;
use tracing::warn;

/// Spawn the fact writer background worker.
///
/// Consumes `FactEmit` messages from the channel and writes them to the
/// JSONL fact store. Runs until the channel is closed.
pub fn spawn_fact_writer(
    mut rx: mpsc::UnboundedReceiver<FactEmit>,
    store: Arc<FactStoreWriter>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("fact writer worker started");
        while let Some(event) = rx.recv().await {
            if let Err(e) = store.write_event(&event) {
                error!(error = %e, domain = %event.domain, "failed to write fact event");
            }
        }
        info!("fact writer worker stopped (channel closed)");
    })
}

/// Spawn the observation background worker.
///
/// Consumes `ObservationJob` messages. Currently logs jobs; TLS/latency
/// probe execution will be added in a future sprint.
pub fn spawn_observation_worker(
    mut rx: mpsc::UnboundedReceiver<ObservationJob>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!("observation worker started");
        while let Some(job) = rx.recv().await {
            // TODO: execute TLS/latency probes and third-party fetches.
            // For now, log the observation job for visibility.
            info!(
                job_id = %job.job_id,
                domain = %job.domain,
                phase = %job.current_phase,
                route = %job.current_route,
                "observation job received"
            );
        }
        info!("observation worker stopped (channel closed)");
    })
}

/// Spawn the governance maintenance worker.
///
/// Periodically:
/// 1. Decays 24h rolling window counters on all governance states.
/// 2. Generates a review candidates artifact.
/// 3. Applies fact store retention (seals/removes old JSONL files).
pub fn spawn_governance_maintenance(
    governance_store: Arc<GovernanceStore>,
    fact_store: Option<Arc<FactStoreWriter>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        info!(
            interval_secs = interval.as_secs(),
            "governance maintenance worker started"
        );
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            let now = Utc::now();

            // 1. Decay 24h counters on all domains.
            let domains = governance_store.domains();
            let mut decayed = 0u32;
            for domain in &domains {
                if let Some(state) = governance_store.get(domain) {
                    let mut new_state = (*state).clone();
                    new_state.decay_24h_counters(now);
                    if new_state.state_version != state.state_version
                        || new_state.mixed_count_24h != state.mixed_count_24h
                        || new_state.hard_conflict_count_24h != state.hard_conflict_count_24h
                    {
                        new_state.state_version += 1;
                        governance_store.force_update(domain, new_state);
                        decayed += 1;
                    }
                }
            }
            if decayed > 0 {
                info!(domains_decayed = decayed, "24h counter decay completed");
            }

            // 2. Apply fact store retention.
            if let Some(ref fs) = fact_store {
                if let Err(e) = fs.apply_retention(now) {
                    warn!(error = %e, "fact store retention failed");
                }
            }
        }
    })
}

/// Generate a `ReviewCandidatesArtifact` from the current governance store state.
///
/// Collects domains in Review or Fallback phase and builds the artifact.
pub fn generate_review_candidates(governance_store: &GovernanceStore) -> ReviewCandidatesArtifact {
    let mut review_domains = Vec::new();
    let mut fallback_domains = Vec::new();

    for domain in governance_store.domains() {
        if let Some(state) = governance_store.get(&domain) {
            match state.phase {
                GovernancePhase::Review => {
                    review_domains.push(ReviewDomainEntry {
                        domain: domain.clone(),
                        phase: "review".into(),
                        reason: determine_review_reason(&state),
                        observation_count: state.observation_count,
                        hard_conflict_count_24h: state.hard_conflict_count_24h,
                        tls_mismatch_count_24h: state.tls_mismatch_count_24h,
                        mixed_count_24h: state.mixed_count_24h,
                        last_observed_at: state.last_observed_at,
                    });
                }
                GovernancePhase::Fallback => {
                    fallback_domains.push(ReviewDomainEntry {
                        domain: domain.clone(),
                        phase: "fallback".into(),
                        reason: determine_review_reason(&state),
                        observation_count: state.observation_count,
                        hard_conflict_count_24h: state.hard_conflict_count_24h,
                        tls_mismatch_count_24h: state.tls_mismatch_count_24h,
                        mixed_count_24h: state.mixed_count_24h,
                        last_observed_at: state.last_observed_at,
                    });
                }
                _ => {}
            }
        }
    }

    let total_review = review_domains.len() as u32;
    let total_fallback = fallback_domains.len() as u32;

    let mixed_review = review_domains
        .iter()
        .filter(|d| d.mixed_count_24h >= 3)
        .count() as u32;
    let tls_mismatch_review = review_domains
        .iter()
        .filter(|d| d.tls_mismatch_count_24h >= 2)
        .count() as u32;
    let hard_conflict_review = review_domains
        .iter()
        .filter(|d| d.hard_conflict_count_24h >= 3)
        .count() as u32;

    ReviewCandidatesArtifact {
        schema_version: "borderdns.fact.v1".into(),
        generated_at: Utc::now(),
        review_domains,
        fallback_domains,
        summary: ReviewSummary {
            total_review,
            total_fallback,
            mixed_review,
            tls_mismatch_review,
            hard_conflict_review,
        },
    }
}

/// Determine the primary reason a domain is in Review.
fn determine_review_reason(state: &border_dns_facts::DomainGovernanceState) -> String {
    if state.tls_mismatch_count_24h >= 2 {
        "tls_mismatch".into()
    } else if state.hard_conflict_count_24h >= 3 {
        "hard_conflict".into()
    } else if state.mixed_count_24h >= 10 {
        "mixed_geo_repeated".into()
    } else if state.route_opposite_count_24h >= 3 {
        "route_opposite".into()
    } else if state.consecutive_failure_count >= 5 {
        "upstream_failure".into()
    } else {
        "unknown".into()
    }
}

/// Print startup review summary to the log.
pub fn log_startup_review_summary(
    governance_store: &GovernanceStore,
    third_party_enabled: bool,
    fact_store_path: &str,
) {
    let artifact = generate_review_candidates(governance_store);

    let stable_profile = if third_party_enabled {
        "peer_assisted"
    } else {
        "local_strict"
    };

    info!(
        third_party_mode = if third_party_enabled {
            "enabled"
        } else {
            "disabled"
        },
        stable_profile,
        fact_store_path,
        total_domains = governance_store.len(),
        "BorderDNS governance startup"
    );

    if artifact.summary.total_review > 0
        || artifact.summary.total_fallback > 0
        || artifact.summary.mixed_review > 0
        || artifact.summary.tls_mismatch_review > 0
    {
        info!(
            review_domains = artifact.summary.total_review,
            fallback_domains = artifact.summary.total_fallback,
            mixed_review_candidates = artifact.summary.mixed_review,
            tls_mismatch_candidates = artifact.summary.tls_mismatch_review,
            hard_conflict_review = artifact.summary.hard_conflict_review,
            "governance review summary"
        );
    }
}
