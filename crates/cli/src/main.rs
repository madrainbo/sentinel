//! `sentinel` — deterministic Docker Compose security scanner.
//!
//!   sentinel scan compose.yml
//!   cat compose.yml | sentinel scan -
//!   sentinel scan compose.yml --format json
//!   sentinel scan compose.yml --fail-on high     # exit 1 if any High/Critical

use std::io::Read;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use compose_parser::try_parse;
use engine::{full_report_json, pack_version_hash, run_pack, sarif_json, Pack, ReportCore, Severity};
use pack_sentinel_core::SentinelCorePack;

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Deterministic Docker Compose security scanner"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a Docker Compose file for security misconfigurations.
    Scan(ScanArgs),
    /// Re-check that a saved JSON report reproduces its digest for a compose file.
    Verify(VerifyArgs),
}

#[derive(Args)]
struct VerifyArgs {
    /// Path to a saved JSON report (from `sentinel scan --format json`).
    report: String,
    /// Path to the compose file to re-scan, or "-" to read from stdin.
    compose: String,
    /// Use the strict rule set (must match how the report was produced).
    #[arg(long)]
    strict: bool,
}

#[derive(Args)]
struct ScanArgs {
    /// Path to a compose file, or "-" to read from stdin.
    path: String,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    /// Exit non-zero if any finding is at or above this severity (for CI).
    #[arg(long, value_name = "SEVERITY")]
    fail_on: Option<SeverityArg>,

    /// Only print the verdict line and digest.
    #[arg(long)]
    quiet: bool,

    /// Include best-practice hardening rules (no-new-privileges, cap-drop, memory limits).
    #[arg(long)]
    strict: bool,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum SeverityArg {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Critical => Severity::Critical,
            SeverityArg::High => Severity::High,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::Low => Severity::Low,
            SeverityArg::Info => Severity::Info,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => scan(args),
        Command::Verify(args) => verify(args),
    }
}

fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))
    }
}

fn scan(args: ScanArgs) -> ExitCode {
    let input = match read_input(&args.path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let model = match try_parse(&input) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let pack = SentinelCorePack::with_options(args.strict);
    let findings = run_pack(&pack, &model);
    let verdict = pack.verdict(&findings);

    let core = ReportCore {
        model: &model,
        pack_id: pack.id().to_string(),
        pack_version_hash: pack_version_hash(&pack),
        findings: &findings,
        verdict: &verdict,
    };
    let digest = core.report_digest();
    let report_id = format!("rpt_{}", digest.trim_start_matches("sha256:").get(..12).unwrap_or(""));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    match args.format {
        Format::Json => {
            println!(
                "{}",
                full_report_json(&core, &report_id, now).to_canonical_string()
            );
        }
        Format::Sarif => {
            let uri = if args.path == "-" { "docker-compose.yml" } else { args.path.as_str() };
            println!("{}", sarif_json(&findings, uri).to_canonical_string());
        }
        Format::Text => print_text(&args, &model, &findings, &verdict, &digest),
    }

    // CI gate: exit non-zero if any finding >= fail-on threshold.
    if let Some(threshold) = args.fail_on {
        let threshold: Severity = threshold.into();
        if findings.iter().any(|f| f.severity >= threshold) {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

fn print_text(
    args: &ScanArgs,
    model: &fact_model::FactModel,
    findings: &[engine::Finding],
    verdict: &engine::Verdict,
    digest: &str,
) {
    if !args.quiet {
        println!("sentinel {} — sentinel-core", env!("CARGO_PKG_VERSION"));
        println!(
            "facts: {} entities, {} relations",
            model.entities.len(),
            model.relations.len()
        );
        if model.entities.is_empty() {
            println!("(no services found — nothing to assess)");
        }
        println!();

        if findings.is_empty() {
            println!("No findings.");
        } else {
            println!("Findings ({}):", findings.len());
            for f in findings {
                println!("  [{:<8}] {:<34} {}", f.severity.as_str(), f.rule_id, f.message);
                println!("             fix: {}", f.remediation);
                println!("             {} | {}", f.controls.join(", "), f.evidence.join(", "));
            }
        }
        println!();
    }

    let c = &verdict.counts;
    println!(
        "verdict: {}  (C:{} H:{} M:{} L:{} I:{})",
        verdict.status.as_str().to_uppercase(),
        c.critical,
        c.high,
        c.medium,
        c.low,
        c.info
    );
    println!("digest:  {digest}");
    if !args.quiet && !findings.is_empty() {
        println!("reference: https://github.com/madrainbo/sentinel/blob/main/RULES.md");
    }
}

fn verify(args: VerifyArgs) -> ExitCode {
    let report_text = match std::fs::read_to_string(&args.report) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read {}: {e}", args.report);
            return ExitCode::from(2);
        }
    };
    let report: serde_json::Value = match serde_json::from_str(report_text.trim_start_matches('\u{feff}')) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: invalid report JSON: {e}");
            return ExitCode::from(2);
        }
    };
    let claimed = match report
        .get("envelope")
        .and_then(|e| e.get("report_digest"))
        .and_then(|d| d.as_str())
    {
        Some(s) => s.to_string(),
        None => {
            eprintln!("error: report has no envelope.report_digest");
            return ExitCode::from(2);
        }
    };

    let input = match read_input(&args.compose) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let model = match try_parse(&input) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let pack = SentinelCorePack::with_options(args.strict);
    let findings = run_pack(&pack, &model);
    let verdict = pack.verdict(&findings);
    let core = ReportCore {
        model: &model,
        pack_id: pack.id().to_string(),
        pack_version_hash: pack_version_hash(&pack),
        findings: &findings,
        verdict: &verdict,
    };
    let recomputed = core.report_digest();

    if recomputed == claimed {
        println!("verified: report reproduces");
        println!("digest: {recomputed}");
        ExitCode::SUCCESS
    } else {
        eprintln!("MISMATCH — report does not reproduce");
        eprintln!("  claimed:    {claimed}");
        eprintln!("  recomputed: {recomputed}");
        eprintln!("(digests differ if the compose file, engine version, or pack changed)");
        ExitCode::from(1)
    }
}
