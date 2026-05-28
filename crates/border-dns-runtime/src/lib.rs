//! BorderDNS production DNS runtime.
//!
//! Owns the UDP/TCP/DoT/DoH/DoJ DNS servers, bootstrap, and graceful shutdown.
//! No reusable business logic should live here.

pub mod blackhole;
pub mod governance_worker;
pub mod handler;
pub mod server;

use std::sync::Arc;

use dns_transport::MetricsRegistry;
use facts::FactEmitter;
use facts::FactEventWriter;
use facts::GovernanceStateStore;
use facts::ObservationTask;
use route_cache::RouteScopedCache;
use runtime_config::RuntimeConfig;
use tokio::sync::Notify;
use tokio::sync::mpsc;
use tracing::info;

/// Shared runtime state accessible by all server tasks.
#[derive(Debug)]
pub struct RuntimeContext {
    /// Loaded configuration.
    pub config: RuntimeConfig,
    /// DNS response cache.
    pub cache: Arc<RouteScopedCache>,
    /// Per-transport metrics.
    pub metrics: Arc<MetricsRegistry>,
    /// Shutdown signal.
    pub shutdown: Arc<Notify>,
}

impl RuntimeContext {
    /// Create a new runtime context from configuration.
    #[must_use]
    pub fn new(config: RuntimeConfig) -> Self {
        let cache = Arc::new(RouteScopedCache::new(config.cache.clone()));
        Self {
            config,
            cache,
            metrics: Arc::new(MetricsRegistry::default()),
            shutdown: Arc::new(Notify::new()),
        }
    }
}

/// Initialize tracing subscriber.
///
/// # Errors
///
/// Returns error if the tracing subscriber fails to initialize.
pub fn init_tracing(verbose: bool) -> anyhow::Result<()> {
    let filter = if verbose {
        "border_dns_runtime=debug,border_dns_upstream=debug,route_cache=debug,border_dns=debug,dns_transport=debug"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()),
        )
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .init();

    Ok(())
}

/// Run the BorderDNS runtime.
///
/// Starts all enabled listeners (UDP, TCP, DoT, DoH, DoJ) and waits for shutdown signal.
///
/// # Errors
///
/// Returns error on server startup failure.
pub async fn run(config: RuntimeConfig, verbose: bool) -> anyhow::Result<()> {
    // Install the ring crypto provider for rustls before any TLS operations.
    // With `default-features = false` + `features = ["ring"]`, rustls does not
    // auto-install a provider. Without this call, the first TLS handshake panics.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // ok() ignores "already installed" error

    init_tracing(verbose)?;

    let ctx = Arc::new(RuntimeContext::new(config));

    info!("BorderDNS runtime starting");

    // ── Governance infrastructure ────────────────────────────────
    let governance_store = Arc::new(GovernanceStateStore::new());

    // Fact store writer — writes JSONL to state/facts/ under current directory.
    let fact_store_dir = std::path::PathBuf::from("state/facts");
    let fact_store = match FactEventWriter::new(fact_store_dir) {
        Ok(writer) => Some(Arc::new(writer)),
        Err(e) => {
            tracing::warn!(error = %e, "failed to create fact store writer, JSONL persistence disabled");
            None
        }
    };

    // Create channels for fact emission and observation jobs.
    let (_fact_tx, fact_rx) = mpsc::unbounded_channel::<FactEmitter>();
    let (_observation_tx, observation_rx) = mpsc::unbounded_channel::<ObservationTask>();

    // Spawn background workers.
    if let Some(ref fs) = fact_store {
        let _writer_handle = governance_worker::spawn_fact_writer(fact_rx, Arc::clone(fs));
    }
    let _obs_handle = governance_worker::spawn_observation_worker(observation_rx);

    let _maint_handle = governance_worker::spawn_governance_maintenance(
        Arc::clone(&governance_store),
        fact_store.as_ref().map(Arc::clone),
        std::time::Duration::from_secs(300), // every 5 minutes
    );

    // ── Startup review summary ───────────────────────────────────
    let fact_store_path = fact_store
        .as_ref()
        .map(|_| "state/facts/")
        .unwrap_or("disabled");
    governance_worker::log_startup_review_summary(
        &governance_store,
        ctx.config.third_party.enabled,
        fact_store_path,
    );

    // ── DNS listeners ────────────────────────────────────────────
    let mut handles = Vec::new();

    // Start blackhole HTTP acceptor (before DNS listeners).
    if ctx.config.blackhole.enabled {
        let blackhole = blackhole::BlackholeAcceptor::new(
            ctx.config.blackhole.clone(),
            Arc::clone(&ctx.shutdown),
        );
        if let Err(e) = blackhole.start().await {
            tracing::error!(error = %e, "blackhole acceptor failed to start");
        }
    }

    // Start UDP listener.
    if let Some(ref udp) = ctx.config.listeners.udp {
        if udp.enabled {
            let addr = udp.listen.clone();
            let ctx = Arc::clone(&ctx);
            info!(address = %addr, "UDP server starting");
            handles.push(tokio::spawn(
                async move { server::run_udp(addr, ctx).await },
            ));
        }
    }

    // Start TCP listener.
    if let Some(ref tcp) = ctx.config.listeners.tcp {
        if tcp.enabled {
            let addr = tcp.listen.clone();
            let ctx = Arc::clone(&ctx);
            info!(address = %addr, "TCP server starting");
            handles.push(tokio::spawn(
                async move { server::run_tcp(addr, ctx).await },
            ));
        }
    }

    // Start DoT listener.
    if let Some(ref dot) = ctx.config.listeners.dot {
        if dot.enabled {
            let cfg = dot.clone();
            let ctx = Arc::clone(&ctx);
            info!(address = %cfg.listen, "DoT server starting");
            handles.push(tokio::spawn(async move { server::run_dot(cfg, ctx).await }));
        }
    }

    // Start DoH listener.
    if let Some(ref doh) = ctx.config.listeners.doh {
        if doh.enabled {
            let cfg = doh.clone();
            let ctx = Arc::clone(&ctx);
            info!(address = %cfg.listen, "DoH server starting");
            handles.push(tokio::spawn(async move { server::run_doh(cfg, ctx).await }));
        }
    }

    // Start DoJ listener.
    if let Some(ref doj) = ctx.config.listeners.doj {
        if doj.enabled {
            let cfg = doj.clone();
            let ctx = Arc::clone(&ctx);
            info!(address = %cfg.listen, "DoJ server starting");
            handles.push(tokio::spawn(async move { server::run_doj(cfg, ctx).await }));
        }
    }

    if handles.is_empty() {
        anyhow::bail!("no listeners enabled in configuration");
    }

    info!(
        upstreams = ?ctx.config.upstreams.default_upstreams().len(),
        cache_max = ctx.config.cache.max_entries,
        "configuration loaded"
    );

    // Wait for Ctrl+C.
    let shutdown_ctx = Arc::clone(&ctx);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("shutdown signal received");
        shutdown_ctx.shutdown.notify_waiters();
    });

    // Wait for all server tasks.
    for handle in handles {
        let _ = handle.await;
    }

    info!("BorderDNS runtime stopped");
    Ok(())
}
