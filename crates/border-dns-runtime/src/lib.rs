//! BorderDNS production DNS runtime.
//!
//! Owns the UDP/TCP DNS servers, bootstrap, and graceful shutdown.
//! No reusable business logic should live here.

pub mod server;

use std::sync::Arc;

use border_dns_cache::DnsCache;
use border_dns_config::Config;
use tokio::sync::Notify;
use tracing::info;

/// Shared runtime state accessible by all server tasks.
#[derive(Debug)]
pub struct RuntimeContext {
    /// Loaded configuration.
    pub config: Config,
    /// DNS response cache.
    pub cache: Arc<DnsCache>,
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
        "border_dns_runtime=debug,border_dns_upstream=debug,border_dns_cache=debug,border_dns=debug"
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
/// Starts UDP and TCP servers on configured addresses, waits for shutdown signal.
///
/// # Errors
///
/// Returns error on server startup failure.
pub async fn run(config: Config, verbose: bool) -> anyhow::Result<()> {
    init_tracing(verbose)?;

    let ctx = Arc::new(RuntimeContext::new(config));

    info!("BorderDNS runtime starting");
    info!(
        listeners = ?ctx.config.server.listen,
        upstreams = ?ctx.config.upstreams.default.len(),
        cache_max = ctx.config.cache.max_entries,
        "configuration loaded"
    );

    let mut handles = Vec::new();

    // Start listener tasks.
    for listener_str in &ctx.config.server.listen {
        let addr: border_dns_config::ListenerAddr = listener_str
            .parse()
            .map_err(|e: String| anyhow::anyhow!(e))?;
        let ctx = Arc::clone(&ctx);
        let handle = match addr.protocol {
            border_dns_config::DnsProtocol::Udp => {
                tokio::spawn(async move { server::run_udp(addr.addr, ctx).await })
            }
            border_dns_config::DnsProtocol::Tcp => {
                tokio::spawn(async move { server::run_tcp(addr.addr, ctx).await })
            }
        };
        handles.push(handle);
    }

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
