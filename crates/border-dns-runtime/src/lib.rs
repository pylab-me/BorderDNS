//! BorderDNS production DNS runtime.
//!
//! Owns the UDP/TCP/DoT/DoH/DoJ DNS servers, bootstrap, and graceful shutdown.
//! No reusable business logic should live here.

pub mod handler;
pub mod server;

use std::sync::Arc;

use border_dns_cache::DnsCache;
use border_dns_config::Config;
use dns_transport::MetricsRegistry;
use tokio::sync::Notify;
use tracing::info;

/// Shared runtime state accessible by all server tasks.
#[derive(Debug)]
pub struct RuntimeContext {
    /// Loaded configuration.
    pub config: Config,
    /// DNS response cache.
    pub cache: Arc<DnsCache>,
    /// Per-transport metrics.
    pub metrics: Arc<MetricsRegistry>,
    /// Shutdown signal.
    pub shutdown: Arc<Notify>,
}

impl RuntimeContext {
    /// Create a new runtime context from configuration.
    #[must_use]
    pub fn new(config: Config) -> Self {
        let cache = Arc::new(DnsCache::new(config.cache.clone()));
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
        "border_dns_runtime=debug,border_dns_upstream=debug,border_dns_cache=debug,border_dns=debug,dns_transport=debug"
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
pub async fn run(config: Config, verbose: bool) -> anyhow::Result<()> {
    init_tracing(verbose)?;

    let ctx = Arc::new(RuntimeContext::new(config));

    info!("BorderDNS runtime starting");

    let mut handles = Vec::new();

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
