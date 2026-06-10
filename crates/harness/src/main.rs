//! Eval harness for the sentinel-core pack.
//!
//! Runs the engine over a labeled corpus and reports precision / recall /
//! critical+high recall, plus per-fixture determinism. Exits non-zero if the
//! gate fails, so it can run in CI.
//!
//! Labels live in each fixture's `# EXPECT:` / `# EXPECT-GAP:` header comments:
//!   # EXPECT: Critical DOCKER-SOCKET-MOUNT     (a finding the engine MUST produce)
//!   # EXPECT-GAP: Medium SENSITIVE-PORT-...     (a known limitation, surfaced not failed)
//! A fixture with no EXPECT lines is a clean case (expect zero findings).

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use engine::{detect_input, pack_version_hash, run_pack, InputKind, Pack, ReportCore, Severity};
use fact_model::FactModel;
use pack_dockerfile_core::DockerfileCorePack;
use pack_gha_core::GhaCorePack;
use pack_k8s_core::K8sCorePack;
use pack_secrets_core::SecretsCorePack;
use pack_sentinel_core::SentinelCorePack;
use pack_terraform_core::TerraformCorePack;

const MIN_RECALL: f64 = 0.90;

/// Pick parser + pack the same way the CLI/web do: filename hint + content
/// (Kubernetes/GitHub-Actions/Compose fixtures all use `.yml`, so content decides).
fn build(path: &Path, content: &str) -> (FactModel, Box<dyn Pack>) {
    let name = path.to_string_lossy();
    match detect_input(&name, content) {
        InputKind::Dockerfile => {
            (dockerfile_parser::parse(content), Box::new(DockerfileCorePack::new()))
        }
        InputKind::Kubernetes => (k8s_parser::parse(content), Box::new(K8sCorePack::new())),
        InputKind::GithubActions => (gha_parser::parse(content), Box::new(GhaCorePack::new())),
        InputKind::Terraform => (terraform_parser::parse(content), Box::new(TerraformCorePack::new())),
        InputKind::Secrets => (secrets_parser::parse(content), Box::new(SecretsCorePack::new())),
        InputKind::Compose => (compose_parser::parse(content), Box::new(SentinelCorePack::new())),
    }
}

struct Expect {
    sev: Severity,
    rule: String,
    gap: bool,
}

fn sev_from_str(s: &str) -> Option<Severity> {
    match s {
        "Critical" => Some(Severity::Critical),
        "High" => Some(Severity::High),
        "Medium" => Some(Severity::Medium),
        "Low" => Some(Severity::Low),
        "Info" => Some(Severity::Info),
        _ => None,
    }
}

fn is_crit_high(s: Severity) -> bool {
    matches!(s, Severity::Critical | Severity::High)
}

fn parse_expects(yml: &str) -> Vec<Expect> {
    let mut out = Vec::new();
    for line in yml.lines() {
        let l = line.trim();
        if !l.starts_with('#') {
            continue;
        }
        let body = l.trim_start_matches('#').trim();
        let (rest, gap) = if let Some(r) = body.strip_prefix("EXPECT-GAP:") {
            (r, true)
        } else if let Some(r) = body.strip_prefix("EXPECT:") {
            (r, false)
        } else {
            continue;
        };
        let mut it = rest.split_whitespace();
        if let (Some(sev_s), Some(rule)) = (it.next(), it.next()) {
            if let Some(sev) = sev_from_str(sev_s) {
                out.push(Expect {
                    sev,
                    rule: rule.to_string(),
                    gap,
                });
            }
        }
    }
    out
}

#[derive(Default)]
struct Totals {
    tp: u32,
    fp: u32,
    fn_real: u32,
    ch_tp: u32,
    ch_fn: u32,
    gaps_closed: u32,
    gaps_open: u32,
    det_pass: u32,
    det_fail: u32,
    fixtures: u32,
}

fn main() -> ExitCode {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let mut files: Vec<_> = match fs::read_dir(&corpus) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .map(|x| {
                        x == "yml" || x == "tf" || x == "env" || x.eq_ignore_ascii_case("dockerfile")
                    })
                    .unwrap_or(false)
            })
            .collect(),
        Err(e) => {
            eprintln!("cannot read corpus dir {}: {e}", corpus.display());
            return ExitCode::from(2);
        }
    };
    files.sort();

    let mut t = Totals::default();
    let mut miss_lines: Vec<String> = Vec::new();
    let mut fp_lines: Vec<String> = Vec::new();
    let mut gap_lines: Vec<String> = Vec::new();

    println!(
        "{:<26} {:>4} {:>4} {:>4} {:>4} {:>5}",
        "fixture", "exp", "TP", "FP", "FN", "det"
    );
    println!("{}", "-".repeat(54));

    for path in &files {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let yml = fs::read_to_string(path).unwrap_or_default();
        let expects = parse_expects(&yml);

        let (model, pack) = build(path, &yml);
        let findings = run_pack(pack.as_ref(), &model);

        // determinism: same input -> same report_digest twice
        let digest = |m: &fact_model::FactModel, f: &[engine::Finding]| {
            let v = pack.verdict(f);
            ReportCore {
                model: m,
                pack_id: pack.id().to_string(),
                pack_version_hash: pack_version_hash(pack.as_ref()),
                findings: f,
                verdict: &v,
            }
            .report_digest()
        };
        let (m2, _) = build(path, &yml);
        let f2 = run_pack(pack.as_ref(), &m2);
        let det_ok = digest(&model, &findings) == digest(&m2, &f2);
        if det_ok {
            t.det_pass += 1;
        } else {
            t.det_fail += 1;
        }

        // produced multiset by rule_id (+ a severity sample per rule)
        let mut prod: HashMap<String, u32> = HashMap::new();
        for f in &findings {
            *prod.entry(f.rule_id.clone()).or_insert(0) += 1;
        }

        let expects_real: Vec<&Expect> = expects.iter().filter(|e| !e.gap).collect();
        let expects_gap: Vec<&Expect> = expects.iter().filter(|e| e.gap).collect();

        let mut tp = 0u32;
        let mut fp = 0u32;
        let mut fnr = 0u32;

        for e in &expects_real {
            match prod.get_mut(&e.rule) {
                Some(c) if *c > 0 => {
                    *c -= 1;
                    tp += 1;
                    t.tp += 1;
                    if is_crit_high(e.sev) {
                        t.ch_tp += 1;
                    }
                }
                _ => {
                    fnr += 1;
                    t.fn_real += 1;
                    if is_crit_high(e.sev) {
                        t.ch_fn += 1;
                    }
                    miss_lines.push(format!("  MISS {name}: {} {}", e.sev.as_str(), e.rule));
                }
            }
        }
        for e in &expects_gap {
            match prod.get_mut(&e.rule) {
                Some(c) if *c > 0 => {
                    *c -= 1;
                    t.gaps_closed += 1;
                }
                _ => {
                    t.gaps_open += 1;
                    gap_lines.push(format!("  GAP  {name}: {} {} (known, not yet detected)", e.sev.as_str(), e.rule));
                }
            }
        }
        for (rule, c) in &prod {
            for _ in 0..*c {
                fp += 1;
                t.fp += 1;
                fp_lines.push(format!("  FP   {name}: {rule}"));
            }
        }

        t.fixtures += 1;
        println!(
            "{:<26} {:>4} {:>4} {:>4} {:>4} {:>5}",
            name,
            expects_real.len(),
            tp,
            fp,
            fnr,
            if det_ok { "ok" } else { "FAIL" }
        );
    }

    let precision = ratio(t.tp, t.tp + t.fp);
    let recall = ratio(t.tp, t.tp + t.fn_real);
    let ch_recall = ratio(t.ch_tp, t.ch_tp + t.ch_fn);

    println!("\n{}", "=".repeat(54));
    println!("fixtures:            {}", t.fixtures);
    println!("TP / FP / FN:        {} / {} / {}", t.tp, t.fp, t.fn_real);
    println!("precision:           {:.3}", precision);
    println!("recall:              {:.3}", recall);
    println!("crit+high recall:    {:.3}  (FN crit/high: {})", ch_recall, t.ch_fn);
    println!("determinism:         {} pass / {} fail", t.det_pass, t.det_fail);
    println!("known gaps:          {} open / {} closed", t.gaps_open, t.gaps_closed);

    for l in miss_lines.iter().chain(fp_lines.iter()).chain(gap_lines.iter()) {
        println!("{l}");
    }

    // Gate: no missed critical/high, recall >= MIN_RECALL, all determinism passing.
    let gate_ok = t.ch_fn == 0 && recall >= MIN_RECALL && t.det_fail == 0;
    println!("\nGATE: {}", if gate_ok { "PASS" } else { "FAIL" });
    if gate_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn ratio(num: u32, den: u32) -> f64 {
    if den == 0 {
        1.0
    } else {
        num as f64 / den as f64
    }
}
