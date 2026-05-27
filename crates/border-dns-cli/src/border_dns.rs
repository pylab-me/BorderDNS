//! Simple entrypoint: start the DNS resolver runtime with default config.
//!
//! Equivalent to `border-cli run -c border-dns.toml`.

use std::path::PathBuf;

use anyhow::Result;

fn main() -> Result<()> {
    let config_path = resolve_config("border-dns.toml");
    let verbose = std::env::var("BORDER_DNS_VERBOSE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let config = runtime_config::load_from_file(&config_path)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(border_dns_runtime::run(config, verbose))?;

    Ok(())
}

/// Resolve config path from the first positional arg, or fall back to the
/// default file next to the executable.
fn resolve_config(default: &str) -> PathBuf {
    let args: Vec<String> = std::env::args().collect();

    // border-dns <config-path>
    if args.len() >= 2 && !args[1].starts_with('-') {
        return PathBuf::from(&args[1]);
    }

    // border-dns -c <config-path>
    for i in 0..args.len() {
        if (args[i] == "-c" || args[i] == "--config") && i + 1 < args.len() {
            return PathBuf::from(&args[i + 1]);
        }
    }

    // Fallback: next to the binary, or current dir
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(default);
            if candidate.exists() {
                return candidate;
            }
        }
    }

    PathBuf::from(default)
}
