//! Embargo L3 sandbox CLI: run an install command under egress control.
//!
//!   embargo-sandbox run --allow 10.0.0.5 --package evil --version 1.0.0 -- npm ci

mod allowlist;
mod chain;
mod report;
mod runner;
mod seccomp;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "embargo-sandbox",
    about = "Egress-controlled install runner (L3 containment)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command with the network egress allowlist enforced.
    Run(RunArgs),
    /// Attempt TCP connections and report which were blocked. Used as the
    /// payload in containment tests (and handy for verifying a deployment).
    Probe(ProbeArgs),
}

#[derive(Parser)]
struct ProbeArgs {
    /// Read these files first (simulating a credential read) before connecting.
    #[arg(long = "read-secret")]
    read_secret: Vec<String>,
    /// Destination IP:port to attempt (repeatable).
    #[arg(long = "connect")]
    connect: Vec<String>,
}

#[derive(Parser)]
struct RunArgs {
    /// Allowed destination IPs or hostnames (repeatable). Loopback is always allowed.
    #[arg(long = "allow")]
    allow: Vec<String>,
    /// Package name for the containment report.
    #[arg(long, default_value = "")]
    package: String,
    /// Package version for the containment report.
    #[arg(long, default_value = "")]
    version: String,
    /// Engine address for ReportEvent (host:port). When unset, events are logged only.
    #[arg(long)]
    engine: Option<String>,
    /// Pipeline label for the report.
    #[arg(long, default_value = "local")]
    pipeline: String,
    /// Repo label for the report.
    #[arg(long, default_value = "")]
    repo: String,
    /// Disable namespace isolation (egress still enforced via seccomp).
    #[arg(long)]
    no_isolate: bool,
    /// Detect the runtime compromise chain (secret read → non-allowlisted egress).
    /// Also observes openat(), so it is heavier than plain egress control.
    #[arg(long)]
    detect_chain: bool,
    /// Chain correlation window in milliseconds.
    #[arg(long, default_value_t = 5_000)]
    chain_window_ms: u64,
    /// Write blocked-egress + chain events as JSON to this path.
    #[arg(long)]
    report_file: Option<String>,
    /// The install command, after `--`.
    #[arg(last = true, required = true, num_args = 1..)]
    command: Vec<String>,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Command::Run(args) => run(args),
        Command::Probe(args) => probe(args),
    }
}

/// Attempt each connection (as a raw IP connect, so it hits connect() directly)
/// and print the outcome. Exit 0 regardless — the supervising parent records
/// which destinations were blocked.
fn probe(args: ProbeArgs) -> Result<()> {
    use std::net::TcpStream;
    use std::time::Duration;
    // Read "secrets" first (these openat() calls are observed by the supervisor).
    for path in &args.read_secret {
        match std::fs::read(path) {
            Ok(_) => println!("read: {path}"),
            Err(e) => println!("read-error({}): {path}", e.kind()),
        }
    }
    for spec in &args.connect {
        let addr: std::net::SocketAddr =
            spec.parse().with_context(|| format!("bad addr {spec}"))?;
        match TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
            Ok(_) => println!("connected: {addr}"),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                println!("blocked: {addr}")
            }
            Err(e) => println!("error({}): {addr}", e.kind()),
        }
    }
    Ok(())
}

fn run(args: RunArgs) -> Result<()> {
    use seccomp::SupervisorEvent as Ev;
    let allow = seccomp::resolve_allow_specs(&args.allow).context("resolve allowlist")?;
    let cfg = runner::RunConfig {
        allow,
        command: args.command.clone(),
        isolate: !args.no_isolate,
        detect_chain: args.detect_chain,
        chain_window_ms: args.chain_window_ms,
    };

    let outcome = runner::run(&cfg, |ev| match ev {
        Ev::Blocked(b) => tracing::warn!(pid = b.pid, dest = %b.dest, "blocked egress attempt"),
        Ev::Chain(c) => {
            tracing::error!(pid = c.pid, secret = %c.secret_path, dest = %c.dest, "RUNTIME COMPROMISE CHAIN")
        }
    })?;

    // Report containment events + chains to the engine.
    let has_events = !outcome.blocked.is_empty() || !outcome.chains.is_empty();
    if let Some(engine) = args.engine.as_ref().filter(|_| has_events) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("tokio runtime")?;
        for b in &outcome.blocked {
            let req =
                report::build_request(&args.package, &args.version, b, &args.pipeline, &args.repo);
            if let Err(e) = rt.block_on(report::report(engine, req)) {
                tracing::error!(error = %e, "failed to report containment event");
            }
        }
        for c in &outcome.chains {
            let req = report::build_chain_request(
                &args.package,
                &args.version,
                c,
                &args.pipeline,
                &args.repo,
            );
            if let Err(e) = rt.block_on(report::report(engine, req)) {
                tracing::error!(error = %e, "failed to report chain event");
            }
        }
    }

    if let Some(path) = &args.report_file {
        let report = serde_json::json!({
            "blocked": outcome.blocked,
            "chains": outcome.chains,
        });
        std::fs::write(path, serde_json::to_vec_pretty(&report)?)
            .with_context(|| format!("writing report to {path}"))?;
    }

    tracing::info!(
        exit_code = outcome.exit_code,
        blocked = outcome.blocked.len(),
        chains = outcome.chains.len(),
        "sandbox run complete"
    );
    std::process::exit(outcome.exit_code);
}
