//! Engine core: findings, verdict, the `Rule` / `Pack` traits, and the
//! content-addressed report (ADR 0003).
#![allow(dead_code)]

use fact_model::{sha256_hex, sha256_prefixed, FactModel, Json};

pub const ENGINE_VERSION: &str = "0.1.0";

/// Static metadata describing a rule, for the in-app rule catalog. Lets the UI
/// render exactly the rules the engine ships, instead of a separate doc.
pub struct RuleMeta {
    pub id: &'static str,
    pub title: &'static str,
    pub target: &'static str,
    pub severity: Severity,
    pub controls: &'static [&'static str],
    pub summary: &'static str,
    pub fix: &'static str,
    pub strict: bool,
}

/// Serialize a rule catalog to a JSON array (order preserved).
pub fn catalog_json(metas: &[RuleMeta]) -> Json {
    Json::Arr(
        metas
            .iter()
            .map(|m| {
                Json::Obj(vec![
                    ("id".into(), Json::Str(m.id.into())),
                    ("title".into(), Json::Str(m.title.into())),
                    ("target".into(), Json::Str(m.target.into())),
                    ("severity".into(), Json::Str(m.severity.as_str().into())),
                    (
                        "controls".into(),
                        Json::Arr(m.controls.iter().map(|c| Json::Str((*c).into())).collect()),
                    ),
                    ("summary".into(), Json::Str(m.summary.into())),
                    ("fix".into(), Json::Str(m.fix.into())),
                    ("strict".into(), Json::Bool(m.strict)),
                ])
            })
            .collect(),
    )
}

/// Render a rule catalog as the full RULES.md reference document (Markdown).
///
/// This is the single source of truth for RULES.md — regenerate with
/// `sentinel rules > RULES.md` (CI checks it stays in sync). Each rule heading
/// is the verbatim rule id so finding / SARIF deep-links (see [`rule_help_url`])
/// resolve to the matching GitHub anchor.
pub fn catalog_md(metas: &[RuleMeta]) -> String {
    // Targets in first-seen order (drives section order; not the anchors).
    let mut targets: Vec<&str> = Vec::new();
    for m in metas {
        if !targets.contains(&m.target) {
            targets.push(m.target);
        }
    }

    let mut out = String::new();
    out.push_str("# Sentinel vulnerability reference\n\n");
    out.push_str(
        "<!-- GENERATED — do not edit by hand. Regenerate with `sentinel rules > RULES.md`. -->\n\n",
    );
    out.push_str(
        "The master catalog of everything Sentinel detects. Each finding in a scan links here\n\
         by its rule id (e.g. a `DOCKER-SOCKET-MOUNT` finding → [#docker-socket-mount](#docker-socket-mount)).\n\
         Control mappings are documented in [CONTROLS.md](CONTROLS.md).\n\n",
    );
    out.push_str(&format!(
        "Sentinel ships **{} rules** across **{} targets** ({}).\n\n",
        metas.len(),
        targets.len(),
        targets.join(", "),
    ));
    out.push_str(
        "> Severity: **Critical** (host/root compromise) · **High** (likely exploitable) ·\n\
         > **Medium** (environment-dependent) · **Low** (hardening). Rules marked _strict_ only\n\
         > run with `--strict`.\n",
    );

    for target in targets {
        out.push_str(&format!("\n---\n\n## {target}\n"));
        for m in metas.iter().filter(|m| m.target == target) {
            let strict = if m.strict { " · _strict_" } else { "" };
            out.push_str(&format!(
                "\n### {id}\n**{sev}** · {controls}{strict}\n\n{summary}\n\n**Fix:** {fix}\n",
                id = m.id,
                sev = m.severity.as_str(),
                controls = m.controls.join(", "),
                summary = m.summary,
                fix = m.fix,
            ));
        }
    }
    out
}

/// Severity, ordered so that `Critical` is greatest (for descending sort).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Info => "Info",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub controls: Vec<String>,
    pub severity: Severity,
    pub evidence: Vec<String>,
    pub message: String,
    pub remediation: String,
    /// 1-based source line(s) this finding points at, derived from the
    /// triggering entities' provenance by [`attach_lines`]. A UX/locator aid
    /// (shown in SARIF/text/exports) — deliberately NOT part of the hashed
    /// report core, so it never affects `report_digest`.
    pub lines: Vec<u32>,
}

/// Fill each finding's `lines` from its `evidence` (which holds entity ids),
/// looking up the source line recorded on each entity's provenance. Call once
/// after a pack evaluates, before rendering SARIF / text / exports. Does not
/// touch the canonical JSON, so the report digest is unchanged.
pub fn attach_lines(findings: &mut [Finding], model: &FactModel) {
    let id_line: std::collections::BTreeMap<&str, u32> = model
        .entities
        .iter()
        .filter_map(|e| e.provenance.line.map(|l| (e.id.as_str(), l)))
        .collect();
    for f in findings.iter_mut() {
        let mut ls: Vec<u32> = f
            .evidence
            .iter()
            .filter_map(|ev| id_line.get(ev.as_str()).copied())
            .collect();
        ls.sort_unstable();
        ls.dedup();
        f.lines = ls;
    }
}

/// Shared status vocabulary (DESIGN_SYSTEM.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    InReview,
    FlaggedGap,
    Cleared,
    Escalated,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Pending => "pending",
            Status::InReview => "in_review",
            Status::FlaggedGap => "flagged_gap",
            Status::Cleared => "cleared",
            Status::Escalated => "escalated",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub counts: SeverityCounts,
    pub status: Status,
    pub pack_policy: String,
}

/// A deterministic rule: a pure function of the fact model.
pub trait Rule {
    fn id(&self) -> &str;
    fn evaluate(&self, model: &FactModel) -> Vec<Finding>;
}

/// A pack: a versioned set of rules plus a deterministic verdict policy.
pub trait Pack {
    fn id(&self) -> &str;
    fn rules(&self) -> &[Box<dyn Rule>];
    fn verdict(&self, findings: &[Finding]) -> Verdict;
}

/// Run every rule and return findings in canonical order
/// (severity desc, then rule_id, then evidence) per ADR 0003.
pub fn run_pack(pack: &dyn Pack, model: &FactModel) -> Vec<Finding> {
    let mut findings: Vec<Finding> = pack
        .rules()
        .iter()
        .flat_map(|r| r.evaluate(model))
        .collect();
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
    findings
}

pub fn count_severities(findings: &[Finding]) -> SeverityCounts {
    let mut c = SeverityCounts::default();
    for f in findings {
        match f.severity {
            Severity::Critical => c.critical += 1,
            Severity::High => c.high += 1,
            Severity::Medium => c.medium += 1,
            Severity::Low => c.low += 1,
            Severity::Info => c.info += 1,
        }
    }
    c
}

/// Deterministic pack version: hash of sorted rule ids + policy.
pub fn pack_version_hash(pack: &dyn Pack) -> String {
    let mut ids: Vec<String> = pack.rules().iter().map(|r| r.id().to_string()).collect();
    ids.sort();
    sha256_prefixed(ids.join(",").as_bytes())
}

/// Placeholder build digest. TODO(P1): replace with a real hermetic build hash.
pub fn engine_build_digest() -> String {
    sha256_prefixed(format!("engine-{}-skeleton", ENGINE_VERSION).as_bytes())
}

// ---------------------------------------------------------------------------
// Content-addressed report (ADR 0003)
// ---------------------------------------------------------------------------

fn finding_to_json(f: &Finding) -> Json {
    let mut controls = f.controls.clone();
    controls.sort();
    let mut evidence = f.evidence.clone();
    evidence.sort();
    Json::Obj(vec![
        ("rule_id".into(), Json::Str(f.rule_id.clone())),
        (
            "controls".into(),
            Json::Arr(controls.into_iter().map(Json::Str).collect()),
        ),
        ("severity".into(), Json::Str(f.severity.as_str().into())),
        (
            "evidence".into(),
            Json::Arr(evidence.into_iter().map(Json::Str).collect()),
        ),
        ("message".into(), Json::Str(f.message.clone())),
        ("remediation".into(), Json::Str(f.remediation.clone())),
    ])
}

fn verdict_to_json(v: &Verdict) -> Json {
    Json::Obj(vec![
        (
            "counts".into(),
            Json::Obj(vec![
                ("critical".into(), Json::Int(v.counts.critical as i64)),
                ("high".into(), Json::Int(v.counts.high as i64)),
                ("medium".into(), Json::Int(v.counts.medium as i64)),
                ("low".into(), Json::Int(v.counts.low as i64)),
                ("info".into(), Json::Int(v.counts.info as i64)),
            ]),
        ),
        ("status".into(), Json::Str(v.status.as_str().into())),
        ("pack_policy".into(), Json::Str(v.pack_policy.clone())),
    ])
}

/// The hashed core of a report. `report_digest = sha256(canonical_json(core))`.
pub struct ReportCore<'a> {
    pub model: &'a FactModel,
    pub pack_id: String,
    pub pack_version_hash: String,
    pub findings: &'a [Finding],
    pub verdict: &'a Verdict,
}

impl<'a> ReportCore<'a> {
    pub fn to_canonical_json(&self) -> Json {
        Json::Obj(vec![
            ("schema_version".into(), Json::Str("0".into())),
            (
                "input".into(),
                Json::Obj(vec![
                    ("kind".into(), Json::Str(self.model.source.kind.clone())),
                    ("input_hash".into(), Json::Str(self.model.source.input_hash.clone())),
                ]),
            ),
            ("model_hash".into(), Json::Str(self.model.model_hash())),
            (
                "engine".into(),
                Json::Obj(vec![
                    ("version".into(), Json::Str(ENGINE_VERSION.into())),
                    ("build_digest".into(), Json::Str(engine_build_digest())),
                ]),
            ),
            (
                "packs".into(),
                Json::Arr(vec![Json::Obj(vec![
                    ("id".into(), Json::Str(self.pack_id.clone())),
                    ("version_hash".into(), Json::Str(self.pack_version_hash.clone())),
                ])]),
            ),
            (
                "findings".into(),
                Json::Arr(self.findings.iter().map(finding_to_json).collect()),
            ),
            ("verdict".into(), verdict_to_json(self.verdict)),
        ])
    }

    /// `"sha256:" + sha256(canonical_json(core))`.
    pub fn report_digest(&self) -> String {
        format!(
            "sha256:{}",
            sha256_hex(self.to_canonical_json().to_canonical_string().as_bytes())
        )
    }
}

fn sarif_level(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn sarif_security_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "9.0",
        Severity::High => "7.5",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

/// Deep link to a rule's entry in the public vulnerability reference (RULES.md).
/// The heading anchor is the lowercased rule id.
/// The kind of input Sentinel can scan. Detection is shared across the CLI,
/// the WASM entry point, and the eval harness so routing stays consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Compose,
    Dockerfile,
    Kubernetes,
    GithubActions,
    Terraform,
    Secrets,
}

/// Detect the input kind from an optional filename hint and the content.
///
/// Content wins over the filename for YAML, because Compose and Kubernetes both
/// use `.yml`/`.yaml`. A Kubernetes manifest is recognised by top-level
/// `apiVersion:` + `kind:`; a Dockerfile by a leading `FROM`.
pub fn detect_input(filename: &str, content: &str) -> InputKind {
    let base = filename
        .rsplit(|c| c == '/' || c == '\\')
        .next()
        .unwrap_or(filename)
        .to_lowercase();
    if base == "dockerfile" || base.ends_with(".dockerfile") || base == "containerfile" {
        return InputKind::Dockerfile;
    }
    // dotenv / env files are a secrets sweep target.
    if base == ".env" || base.ends_with(".env") || base.starts_with(".env.") {
        return InputKind::Secrets;
    }

    // First non-comment line starting with FROM -> Dockerfile.
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.len() >= 5 && t[..5].eq_ignore_ascii_case("from ") {
            return InputKind::Dockerfile;
        }
        break;
    }

    if looks_like_kubernetes(content) {
        return InputKind::Kubernetes;
    }
    if looks_like_terraform(&base, content) {
        return InputKind::Terraform;
    }
    if looks_like_github_actions(&base, content) {
        return InputKind::GithubActions;
    }
    if looks_like_secrets(content) {
        return InputKind::Secrets;
    }
    InputKind::Compose
}

/// A secrets/dotenv blob: it carries a high-confidence credential token, or it is
/// shaped like a `.env` file (KEY=VALUE lines). Guarded so structured YAML
/// (Compose `services:`) is never misrouted here.
fn looks_like_secrets(content: &str) -> bool {
    if content.lines().any(|l| l.trim_start().starts_with("services:")) {
        return false;
    }
    // High-confidence credential prefixes (a single hit is decisive).
    const STRONG: &[&str] = &[
        "AKIA", "ASIA", "-----BEGIN", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
        "xoxb-", "xoxp-", "xoxa-", "xoxr-", "AIza", "sk_live_", "rk_live_", "SG.",
    ];
    if STRONG.iter().any(|p| content.contains(p)) {
        return true;
    }
    // Dotenv shape: at least two KEY=VALUE lines and no YAML/HCL block structure.
    let mut kv = 0;
    for line in content.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let t = t.strip_prefix("export ").unwrap_or(t);
        if let Some((k, _)) = t.split_once('=') {
            let k = k.trim();
            if !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                kv += 1;
                continue;
            }
        }
        // a non-blank, non-KV line that isn't a comment -> probably not dotenv
        return false;
    }
    kv >= 2
}

/// Terraform/HCL: a `.tf` file, or content with a top-level HCL block such as
/// `resource "..." {`, `provider "..." {`, `terraform {`, `module "..." {`.
fn looks_like_terraform(base: &str, content: &str) -> bool {
    if base.ends_with(".tf") || base.ends_with(".hcl") {
        return true;
    }
    for line in content.lines() {
        let t = line.trim_start();
        if t.starts_with("resource \"")
            || t.starts_with("provider \"")
            || t.starts_with("module \"")
            || t.starts_with("data \"")
            || t.starts_with("terraform {")
            || t.starts_with("variable \"")
        {
            return true;
        }
    }
    false
}

/// A GitHub Actions workflow has top-level `jobs:` and an `on:` trigger block
/// (YAML `on` may be quoted). Files under `.github/workflows/` also qualify.
fn looks_like_github_actions(base: &str, content: &str) -> bool {
    let path_hint = base.contains(".github") || base.contains("workflow");
    let mut has_jobs = false;
    let mut has_on = false;
    for line in content.lines() {
        if line.starts_with("jobs:") {
            has_jobs = true;
        } else if line.starts_with("on:")
            || line.starts_with("'on':")
            || line.starts_with("\"on\":")
            || line.starts_with("on :")
        {
            has_on = true;
        }
    }
    has_jobs && (has_on || path_hint)
}

/// A Kubernetes manifest has a top-level `apiVersion:` and a top-level `kind:`
/// (in at least one YAML document). `services:` without those is Compose.
fn looks_like_kubernetes(content: &str) -> bool {
    let mut has_api_version = false;
    let mut has_kind = false;
    for line in content.lines() {
        // Top-level keys only (no leading whitespace), ignore list markers.
        if line.starts_with("apiVersion:") {
            has_api_version = true;
        } else if line.starts_with("kind:") {
            has_kind = true;
        }
        if has_api_version && has_kind {
            return true;
        }
    }
    false
}

pub fn rule_help_url(rule_id: &str) -> String {
    format!(
        "https://github.com/madrainbo/sentinel/blob/main/RULES.md#{}",
        rule_id.to_lowercase()
    )
}

/// Render findings as a Markdown report — human- and code-assistant-friendly,
/// with per-finding source lines so the reader (or an AI assistant) can jump
/// straight to the spot to fix. Call [`attach_lines`] first to populate lines.
pub fn findings_markdown(findings: &[Finding], kind: &str, file: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Sentinel findings — {kind}\n\n"));
    out.push_str(&format!("Source: `{file}`\n\n"));
    if findings.is_empty() {
        out.push_str("No findings.\n");
        return out;
    }
    out.push_str(&format!("{} finding(s), highest severity first.\n\n", findings.len()));

    // Highest severity first; stable within a severity (preserves pack order).
    let mut ordered: Vec<&Finding> = findings.iter().collect();
    ordered.sort_by(|a, b| b.severity.cmp(&a.severity));

    for f in ordered {
        let loc = match f.lines.as_slice() {
            [] => String::new(),
            [l] => format!(" — line {l}"),
            ls => format!(
                " — lines {}",
                ls.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(", ")
            ),
        };
        out.push_str(&format!(
            "## [{}] {}{}\n\n",
            f.severity.as_str().to_uppercase(),
            f.rule_id,
            loc
        ));
        out.push_str(&format!("{}\n\n", f.message));
        out.push_str(&format!("- **Fix:** {}\n", f.remediation));
        if !f.controls.is_empty() {
            out.push_str(&format!("- **Controls:** {}\n", f.controls.join(", ")));
        }
        out.push_str(&format!("- **Reference:** {}\n\n", rule_help_url(&f.rule_id)));
    }
    out
}

/// Render findings as SARIF 2.1.0 — the format GitHub code scanning ingests
/// (findings show up in the Security tab and as PR annotations).
pub fn sarif_json(findings: &[Finding], file_uri: &str) -> Json {
    // Unique rule descriptors, first occurrence wins (stable order).
    let mut seen: Vec<String> = Vec::new();
    let mut rules: Vec<Json> = Vec::new();
    for f in findings {
        if seen.iter().any(|r| r == &f.rule_id) {
            continue;
        }
        seen.push(f.rule_id.clone());
        rules.push(Json::Obj(vec![
            ("id".into(), Json::Str(f.rule_id.clone())),
            (
                "shortDescription".into(),
                Json::Obj(vec![("text".into(), Json::Str(f.message.clone()))]),
            ),
            ("helpUri".into(), Json::Str(rule_help_url(&f.rule_id))),
            (
                "properties".into(),
                Json::Obj(vec![(
                    "tags".into(),
                    Json::Arr(f.controls.iter().cloned().map(Json::Str).collect()),
                )]),
            ),
        ]));
    }

    let results: Vec<Json> = findings
        .iter()
        .map(|f| {
            Json::Obj(vec![
                ("ruleId".into(), Json::Str(f.rule_id.clone())),
                ("level".into(), Json::Str(sarif_level(f.severity).into())),
                (
                    "message".into(),
                    Json::Obj(vec![(
                        "text".into(),
                        Json::Str(format!("{} (evidence: {})", f.message, f.evidence.join(", "))),
                    )]),
                ),
                (
                    "locations".into(),
                    Json::Arr(vec![Json::Obj(vec![(
                        "physicalLocation".into(),
                        Json::Obj(vec![
                            (
                                "artifactLocation".into(),
                                Json::Obj(vec![("uri".into(), Json::Str(file_uri.to_string()))]),
                            ),
                            (
                                "region".into(),
                                Json::Obj(vec![(
                                    "startLine".into(),
                                    // The finding's first known source line (SARIF
                                    // lines are 1-based); fall back to 1 if unknown.
                                    Json::Int(f.lines.first().copied().unwrap_or(1) as i64),
                                )]),
                            ),
                        ]),
                    )])]),
                ),
                (
                    "properties".into(),
                    Json::Obj(vec![(
                        "security-severity".into(),
                        Json::Str(sarif_security_severity(f.severity).into()),
                    )]),
                ),
            ])
        })
        .collect();

    Json::Obj(vec![
        (
            "$schema".into(),
            Json::Str("https://json.schemastore.org/sarif-2.1.0.json".into()),
        ),
        ("version".into(), Json::Str("2.1.0".into())),
        (
            "runs".into(),
            Json::Arr(vec![Json::Obj(vec![
                (
                    "tool".into(),
                    Json::Obj(vec![(
                        "driver".into(),
                        Json::Obj(vec![
                            ("name".into(), Json::Str("sentinel".into())),
                            ("version".into(), Json::Str(ENGINE_VERSION.into())),
                            (
                                "informationUri".into(),
                                Json::Str("https://github.com/madrainbo/sentinel".into()),
                            ),
                            ("rules".into(), Json::Arr(rules)),
                        ]),
                    )]),
                ),
                ("results".into(), Json::Arr(results)),
            ])]),
        ),
    ])
}

/// Build the full report JSON: a non-hashed `envelope` wrapping the hashed
/// `core` (ADR 0003). `report_id` and `generated_at_unix` are operational
/// metadata and are deliberately NOT part of the digest.
pub fn full_report_json(core: &ReportCore, report_id: &str, generated_at_unix: i64) -> Json {
    Json::Obj(vec![
        (
            "envelope".into(),
            Json::Obj(vec![
                ("report_id".into(), Json::Str(report_id.to_string())),
                ("generated_at_unix".into(), Json::Int(generated_at_unix)),
                ("report_digest".into(), Json::Str(core.report_digest())),
            ]),
        ),
        ("core".into(), core.to_canonical_json()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_md_uses_rule_id_as_anchor_and_groups_by_target() {
        let metas = vec![
            RuleMeta {
                id: "DOCKER-SOCKET-MOUNT",
                title: "Docker socket mounted",
                target: "Docker Compose",
                severity: Severity::Critical,
                controls: &["CWE-250", "CIS-Docker-5.31"],
                summary: "Grants full control of the Docker daemon.",
                fix: "Remove the mount.",
                strict: false,
            },
            RuleMeta {
                id: "NO-RESOURCE-LIMITS",
                title: "No memory limit",
                target: "Docker Compose",
                severity: Severity::Low,
                controls: &["CWE-400"],
                summary: "A runaway container can exhaust host memory.",
                fix: "Set a memory limit.",
                strict: true,
            },
        ];
        let md = catalog_md(&metas);

        // Heading is the verbatim id, so the GitHub anchor matches rule_help_url.
        assert!(md.contains("### DOCKER-SOCKET-MOUNT"));
        assert!(rule_help_url("DOCKER-SOCKET-MOUNT").ends_with("#docker-socket-mount"));
        // Grouped under its target, with severity + controls rendered.
        assert!(md.contains("## Docker Compose"));
        assert!(md.contains("**Critical** · CWE-250, CIS-Docker-5.31"));
        // Strict rules are tagged.
        assert!(md.contains("**Low** · CWE-400 · _strict_"));
        // Header reports the live counts.
        assert!(md.contains("**2 rules** across **1 targets**"));
    }

    #[test]
    fn attach_lines_maps_evidence_to_entity_lines_and_markdown_shows_them() {
        use fact_model::{Entity, EntityKind, FactModel, Provenance, SourceDescriptor};
        let model = FactModel {
            schema_version: "0".into(),
            source: SourceDescriptor {
                kind: "docker_compose".into(),
                input_hash: "sha256:x".into(),
                parser_version: "0".into(),
            },
            entities: vec![Entity {
                id: "service:web".into(),
                kind: EntityKind::Service,
                attributes: std::collections::BTreeMap::new(),
                provenance: Provenance::explicit("services.web").with_line(Some(7)),
            }],
            relations: vec![],
        };
        let mut findings = vec![Finding {
            rule_id: "PRIVILEGED-CONTAINER".into(),
            controls: vec!["CWE-250".into()],
            severity: Severity::Critical,
            evidence: vec!["service:web".into()],
            message: "Service 'web' runs privileged".into(),
            remediation: "Drop privileged.".into(),
            lines: vec![],
        }];
        attach_lines(&mut findings, &model);
        assert_eq!(findings[0].lines, vec![7]);

        // Lines must NOT leak into the hashed canonical JSON (digest stability).
        let json = finding_to_json(&findings[0]).to_canonical_string();
        assert!(!json.contains("line"), "lines must stay out of the hashed core");

        // Markdown export surfaces the line for the reader / code assistant.
        let md = findings_markdown(&findings, "docker_compose", "docker-compose.yml");
        assert!(md.contains("PRIVILEGED-CONTAINER"));
        assert!(md.contains("line 7"));
    }
}
