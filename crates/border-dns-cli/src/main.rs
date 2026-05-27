//! CLI entrypoint for BorderDNS.
//!
//! Commands:
//!   - `border-dns run -c <config>` — Start the DNS resolver runtime.
//!   - `border-dns validate-config -c <config>` — Validate a config file.
//!   - `border-dns inspect-cache` — Show cache statistics (placeholder).

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use clap::Subcommand;

/// BorderDNS — facts-aware DNS governance loop.
#[derive(Parser)]
#[command(name = "border-dns", version, about)]
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { config, verbose } => {
            let config = border_dns_config::load_from_file(&config)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(border_dns_runtime::run(config, verbose))?;
        }
        Commands::ValidateConfig { config } => match border_dns_config::load_from_file(&config) {
            Ok(_) => {
                println!("✓ Configuration is valid: {}", config.display());
            }
            Err(e) => {
                eprintln!("✗ Configuration error: {e}");
                std::process::exit(1);
            }
        },
        Commands::InspectCache { config } => {
            let config = border_dns_config::load_from_file(&config)?;
            let cache = border_dns_cache::DnsCache::new(config.cache.clone());
            let stats = cache.stats();
            println!("Cache statistics:");
            println!("  entries: {}", stats.entries);
            println!("  hits:    {}", stats.hits);
            println!("  misses:  {}", stats.misses);
            println!("  evictions: {}", stats.evictions);
            println!("\n(Note: cache is empty on fresh start. Run the server to populate.)");
        }
    }

    Ok(())
}
