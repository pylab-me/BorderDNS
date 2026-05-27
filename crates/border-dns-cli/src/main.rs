//! CLI entrypoint for BorderDNS.
//!
//! Commands:
//!   - `border-cli run -c <config>` — Start the DNS resolver runtime.
//!   - `border-cli validate-config -c <config>` — Validate a config file.
//!   - `border-cli inspect-cache` — Show cache statistics (placeholder).
//!   - `border-cli inspect-domain <domain>` — Explain a domain's route decision.
//!   - `border-cli inspect-governance <domain>` — Show governance state for a domain.
//!   - `border-cli inspect-review-candidates` — Show domains needing review.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use domain_knowledge::DomainKnowledge;

/// BorderDNS — facts-aware DNS governance loop.
#[derive(Parser)]
#[command(name = "border-cli", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the DNS resolver runtime.
    Run {
        /// Path to configuration file (TOML).
        #[arg(short, long, default_value = "border-dns.toml")]
        config: PathBuf,

        /// Enable verbose (debug) logging.
        #[arg(short, long)]
        verbose: bool,
    },

    /// Validate a configuration file.
    ValidateConfig {
        /// Path to configuration file (TOML).
        #[arg(short, long, default_value = "border-dns.toml")]
        config: PathBuf,
    },

    /// Show cache statistics (placeholder for future inspect-cache API).
    InspectCache {
        /// Path to configuration file (TOML).
        #[arg(short, long, default_value = "border-dns.toml")]
        config: PathBuf,
    },

    /// Explain a domain's route decision (offline, no running server required).
    InspectDomain {
        /// The domain to inspect (e.g., "example.com").
        domain: String,

        /// Path to configuration file (TOML).
        #[arg(short, long, default_value = "border-dns.toml")]
        config: PathBuf,

        /// Output as JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Show governance state for a domain (offline simulation).
    InspectGovernance {
        /// The domain to inspect.
        domain: String,

        /// Path to configuration file (TOML).
        #[arg(short, long, default_value = "border-dns.toml")]
        config: PathBuf,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Show domains that would be review candidates (offline simulation).
    InspectReviewCandidates {
        /// Path to configuration file (TOML).
        #[arg(short, long, default_value = "border-dns.toml")]
        config: PathBuf,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config, verbose } => {
            let config = runtime_config::load_from_file(&config)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(border_dns_runtime::run(config, verbose))?;
        }
        Commands::ValidateConfig { config } => match runtime_config::load_from_file(&config) {
            Ok(_) => {
                println!("✓ Configuration is valid: {}", config.display());
            }
            Err(e) => {
                eprintln!("✗ Configuration error: {e}");
                std::process::exit(1);
            }
        },
        Commands::InspectCache { config } => {
            let config = runtime_config::load_from_file(&config)?;
            let cache = route_cache::DnsCache::new(config.cache.clone());
            let stats = cache.stats();
            println!("Cache statistics:");
            println!("  entries: {}", stats.entries);
            println!("  hits:    {}", stats.hits);
            println!("  misses:  {}", stats.misses);
            println!("  evictions: {}", stats.evictions);
            println!("\n(Note: cache is empty on fresh start. Run the server to populate.)");
        }
        Commands::InspectDomain {
            domain,
            config,
            json,
        } => {
            cmd_inspect_domain(&domain, &config, json)?;
        }
        Commands::InspectGovernance {
            domain,
            config,
            json,
        } => {
            cmd_inspect_governance(&domain, &config, json)?;
        }
        Commands::InspectReviewCandidates { config, json } => {
            cmd_inspect_review_candidates(&config, json)?;
        }
    }

    Ok(())
}

// ─── Inspect Domain ──────────────────────────────────────────────

fn cmd_inspect_domain(domain: &str, config_path: &PathBuf, json: bool) -> Result<()> {
    let config = runtime_config::load_from_file(config_path)?;
    let knowledge = domain_knowledge::BuiltInDomainKnowledge::new();
    let route_policy = route_policy::RoutePolicy::new(config.resolver.location);

    // Step 1: Domain prior classification
    let decision = route_policy.decide_by_domain_prior(domain, &knowledge);
    let prior = knowledge.classify_domain(domain);

    // Step 2: Run scoring engine with domain prior evidence
    let prior_route_str = match decision.execution_route {
        dns_types::Route::China => "china",
        dns_types::Route::Foreign => "foreign",
        dns_types::Route::Bootstrap => "bootstrap",
        dns_types::Route::Fallback => "unknown",
    };
    let score_input = route_policy::scoring::RouteEvidenceInput {
        prior_route: prior_route_str.to_string(),
        runtime_confidence: 0.0,
        ..route_policy::scoring::RouteEvidenceInput::default()
    };
    let score = route_policy::scoring::score_route_evidence(&score_input);

    if json {
        let output = serde_json::json!({
            "domain": domain,
            "resolver_location": config.resolver.location.as_str(),
            "domain_prior": format!("{:?}", prior),
            "execution_route": decision.execution_route.as_str(),
            "route_source": decision.route_source.as_str(),
            "confidence": decision.confidence.as_str(),
            "china_score": score.china_score,
            "foreign_score": score.foreign_score,
            "score_margin": score.score_margin,
            "domain_intent": score.domain_intent.as_str(),
            "evidence_strength": score.evidence_strength.as_str(),
            "can_promote": score.can_promote,
            "decision_phase": score.decision_phase.as_str(),
            "decision_timing": score.decision_timing.as_str(),
            "reason_code": score.reason_code,
            "component_scores": score.component_scores,
            "notes": score.notes,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("╔══════════════════════════════════════════════════════╗");
        println!("║           BorderDNS Route Decision                  ║");
        println!("╚══════════════════════════════════════════════════════╝");
        println!();
        println!("  domain            : {}", domain);
        println!("  resolver_location : {}", config.resolver.location);
        println!("  domain_prior      : {:?}", prior);
        println!();
        println!("  ── Route Decision ──────────────────────────────────");
        println!("  execution_route   : {}", decision.execution_route);
        println!("  route_source      : {}", decision.route_source.as_str());
        println!("  confidence        : {}", decision.confidence.as_str());
        println!();
        println!("  ── Evidence Score ──────────────────────────────────");
        println!("  china_score       : {:.4}", score.china_score);
        println!("  foreign_score     : {:.4}", score.foreign_score);
        println!("  score_margin      : {:.4}", score.score_margin);
        println!("  domain_intent     : {}", score.domain_intent.as_str());
        println!("  evidence_strength : {}", score.evidence_strength.as_str());
        println!("  can_promote       : {}", score.can_promote);
        println!("  decision_phase    : {}", score.decision_phase);
        println!("  decision_timing   : {}", score.decision_timing.as_str());
        println!("  reason_code       : {}", score.reason_code);
        if !score.component_scores.is_empty() {
            println!();
            println!("  ── Component Scores ────────────────────────────────");
            for (k, v) in &score.component_scores {
                println!("  {:<24} : {:.4}", k, v);
            }
        }
        if !score.notes.is_empty() {
            println!();
            println!("  ── Notes ───────────────────────────────────────────");
            for note in &score.notes {
                println!("  • {}", note);
            }
        }
    }

    Ok(())
}

// ─── Inspect Governance ──────────────────────────────────────────

fn cmd_inspect_governance(domain: &str, config_path: &PathBuf, json: bool) -> Result<()> {
    let config = runtime_config::load_from_file(config_path)?;
    let knowledge = domain_knowledge::BuiltInDomainKnowledge::new();
    let route_policy = route_policy::RoutePolicy::new(config.resolver.location);

    let decision = route_policy.decide_by_domain_prior(domain, &knowledge);
    let prior_route_str = match decision.execution_route {
        dns_types::Route::China => "china",
        dns_types::Route::Foreign => "foreign",
        dns_types::Route::Bootstrap => "bootstrap",
        dns_types::Route::Fallback => "unknown",
    };

    let now = chrono::Utc::now();
    let gov_state =
        facts::DomainGovernanceState::new(domain.to_string(), prior_route_str.to_string(), now);

    if json {
        let output = serde_json::json!({
            "domain": domain,
            "phase": gov_state.phase.as_str(),
            "current_route": gov_state.current_route,
            "prior_route": gov_state.prior_route,
            "observation_count": gov_state.observation_count,
            "can_promote": gov_state.can_promote,
            "promotion_frozen": gov_state.promotion_frozen,
            "third_party_mode": gov_state.third_party_summary.enabled,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("╔══════════════════════════════════════════════════════╗");
        println!("║         BorderDNS Governance State                  ║");
        println!("╚══════════════════════════════════════════════════════╝");
        println!();
        println!("  domain               : {}", domain);
        println!("  phase                : {}", gov_state.phase);
        println!("  current_route        : {}", gov_state.current_route);
        println!("  prior_route          : {}", gov_state.prior_route);
        println!("  observation_count    : {}", gov_state.observation_count);
        println!("  can_promote          : {}", gov_state.can_promote);
        println!("  promotion_frozen     : {}", gov_state.promotion_frozen);
        println!();
        println!("  ── Third-Party ─────────────────────────────────────");
        println!(
            "  enabled              : {}",
            gov_state.third_party_summary.enabled
        );
        println!(
            "  distinct_observers   : {}",
            gov_state.third_party_summary.distinct_observers
        );
        println!();
        println!("  ── Conflict Counters (24h) ─────────────────────────");
        println!("  mixed_count          : {}", gov_state.mixed_count_24h);
        println!(
            "  soft_conflict_count  : {}",
            gov_state.soft_conflict_count_24h
        );
        println!(
            "  hard_conflict_count  : {}",
            gov_state.hard_conflict_count_24h
        );
        println!(
            "  tls_mismatch_count   : {}",
            gov_state.tls_mismatch_count_24h
        );
        println!(
            "  route_opposite_count : {}",
            gov_state.route_opposite_count_24h
        );
        println!();
        println!("  ── Streaks ─────────────────────────────────────────");
        println!(
            "  no_conflict_streak   : {}",
            gov_state.consecutive_no_conflict_count
        );
        println!(
            "  failure_streak       : {}",
            gov_state.consecutive_failure_count
        );
        println!();
        println!("  Note: This is a fresh state (no runtime history).");
        println!("  Run the server to accumulate real governance data.");
    }

    Ok(())
}

// ─── Inspect Review Candidates ───────────────────────────────────

fn cmd_inspect_review_candidates(config_path: &PathBuf, json: bool) -> Result<()> {
    let _config = runtime_config::load_from_file(config_path)?;

    // Without a running server, there are no review candidates.
    // This command is a placeholder that shows the format.
    if json {
        let output = serde_json::json!({
            "review_candidates": [],
            "note": "No runtime data. Start the server to populate governance state."
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("╔══════════════════════════════════════════════════════╗");
        println!("║       BorderDNS Review Candidates                   ║");
        println!("╚══════════════════════════════════════════════════════╝");
        println!();
        println!("  No review candidates (no runtime data available).");
        println!();
        println!("  This command queries the governance state of the running");
        println!("  server. Start `border-dns run` and accumulate domain");
        println!("  observations before review candidates will appear.");
    }

    Ok(())
}
