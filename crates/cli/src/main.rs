//! `sentinel` — deterministic security scanner for Docker Compose and Dockerfiles.
//!
//!   sentinel scan docker-compose.yml
//!   sentinel scan Dockerfile
//!   cat Dockerfile | sentinel scan - --type dockerfile
//!   sentinel scan compose.yml --format sarif --fail-on high

use std::io::Read;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand, ValueEnum};
use engine::{
    detect_input, full_report_json, pack_version_hash, run_pack, sarif_json, InputKind, Pack,
    ReportCore, Severity,
};
use fact_model::FactModel;
use pack_dockerfile_core::DockerfileCorePack;
use pack_gha_core::GhaCorePack;
use pack_k8s_core::K8sCorePack;
use pack_secrets_core::SecretsCorePack;
use pack_sentinel_core::SentinelCorePack;
use pack_terraform_core::TerraformCorePack;

#[derive(Clone, Copy, ValueEnum)]
enum InputType {
    /// Auto-detect from filename/content.
    Auto,
    Compose,
    Dockerfile,
    Kubernetes,
    #[value(name = "github-actions")]
    GithubActions,
    Terraform,
    Secrets,
}

/// Parse the input and pick the matching rule pack.
fn build_model_and_pack(
    input: &str,
    kind: InputType,
    path: &str,
    strict: bool,
) -> Result<(FactModel, Box<dyn Pack>), String> {
    // Boundary size cap — covers every format uniformly, including the
    // fail-open parsers (Dockerfile/Terraform/secrets) that don't return Result.
    fact_model::limits::check_input_size(input)?;
    let resolved = match kind {
        InputType::Auto => detect_input(path, input),
        InputType::Compose => InputKind::Compose,
        InputType::Dockerfile => InputKind::Dockerfile,
        InputType::Kubernetes => InputKind::Kubernetes,
        InputType::GithubActions => InputKind::GithubActions,
        InputType::Terraform => InputKind::Terraform,
        InputType::Secrets => InputKind::Secrets,
    };
    match resolved {
        InputKind::Dockerfile => Ok((
            dockerfile_parser::parse(input),
            Box::new(DockerfileCorePack::new()),
        )),
        InputKind::Kubernetes => Ok((
            k8s_parser::try_parse(input)?,
            Box::new(K8sCorePack::with_options(strict)),
        )),
        InputKind::GithubActions => Ok((
            gha_parser::try_parse(input)?,
            Box::new(GhaCorePack::new()),
        )),
        InputKind::Terraform => Ok((
            terraform_parser::parse(input),
            Box::new(TerraformCorePack::new()),
        )),
        InputKind::Secrets => Ok((
            secrets_parser::parse(input),
            Box::new(SecretsCorePack::new()),
        )),
        InputKind::Compose => Ok((
            compose_parser::try_parse(input)?,
            Box::new(SentinelCorePack::with_options(strict)),
        )),
    }
}

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Deterministic security scanner (Docker Compose, Dockerfile, Kubernetes, GitHub Actions, Terraform, secrets)"
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
    /// Print the full rule catalog as Markdown (the source of truth for RULES.md).
    Rules(RulesArgs),
}

#[derive(Args)]
struct RulesArgs {
    /// Emit the catalog as JSON instead of Markdown.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct VerifyArgs {
    /// Path to a saved JSON report (from `sentinel scan --format json`).
    report: String,
    /// Path to the file to re-scan, or "-" to read from stdin.
    compose: String,
    /// Input type (auto-detected by default).
    #[arg(long, value_enum, default_value_t = InputType::Auto)]
    r#type: InputType,
    /// Use the strict rule set (must match how the report was produced).
    #[arg(long)]
    strict: bool,
}

#[derive(Args)]
struct ScanArgs {
    /// Path to a compose file or Dockerfile, or "-" to read from stdin.
    path: String,

    /// Input type (auto-detected by default).
    #[arg(long, value_enum, default_value_t = InputType::Auto)]
    r#type: InputType,

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
        Command::Rules(args) => rules(args),
    }
}

/// Every shipped rule, in reader-friendly target order (compose → secrets).
/// Order drives RULES.md section order only; rule ids are unique so anchors
/// never collide.
fn all_catalog() -> Vec<engine::RuleMeta> {
    let mut metas = pack_sentinel_core::catalog();
    metas.extend(pack_dockerfile_core::catalog());
    metas.extend(pack_k8s_core::catalog());
    metas.extend(pack_gha_core::catalog());
    metas.extend(pack_terraform_core::catalog());
    metas.extend(pack_secrets_core::catalog());
    metas
}

fn rules(args: RulesArgs) -> ExitCode {
    let metas = all_catalog();
    if args.json {
        println!("{}", engine::catalog_json(&metas).to_canonical_string());
    } else {
        print!("{}", engine::catalog_md(&metas));
    }
    ExitCode::SUCCESS
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

    let (model, pack) = match build_model_and_pack(&input, args.r#type, &args.path, args.strict) {
        Ok(mp) => mp,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let mut findings = run_pack(pack.as_ref(), &model);
    // Attach source lines for text/SARIF output. Excluded from the hashed core,
    // so the report digest is unaffected.
    engine::attach_lines(&mut findings, &model);
    let verdict = pack.verdict(&findings);

    let core = ReportCore {
        model: &model,
        pack_id: pack.id().to_string(),
        pack_version_hash: pack_version_hash(pack.as_ref()),
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
        Format::Text => print_text(&args, pack.id(), &model, &findings, &verdict, &digest),
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
    pack_id: &str,
    model: &fact_model::FactModel,
    findings: &[engine::Finding],
    verdict: &engine::Verdict,
    digest: &str,
) {
    if !args.quiet {
        println!("sentinel {} — {}", env!("CARGO_PKG_VERSION"), pack_id);
        println!(
            "facts: {} entities, {} relations",
            model.entities.len(),
            model.relations.len()
        );
        if model.entities.is_empty() {
            println!("(nothing to assess)");
        }
        println!();

        if findings.is_empty() {
            println!("No findings.");
        } else {
            println!("Findings ({}):", findings.len());
            for f in findings {
                let loc = match f.lines.as_slice() {
                    [] => String::new(),
                    [l] => format!("  (line {l})"),
                    ls => format!("  (lines {})", ls.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")),
                };
                println!("  [{:<8}] {:<34} {}{loc}", f.severity.as_str(), f.rule_id, f.message);
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
    let (model, pack) = match build_model_and_pack(&input, args.r#type, &args.compose, args.strict) {
        Ok(mp) => mp,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let findings = run_pack(pack.as_ref(), &model);
    let verdict = pack.verdict(&findings);
    let core = ReportCore {
        model: &model,
        pack_id: pack.id().to_string(),
        pack_version_hash: pack_version_hash(pack.as_ref()),
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
