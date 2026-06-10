//! gha-core pack — deterministic GitHub Actions workflow security rules. Pure
//! functions of the fact model produced by `gha-parser`.
//!
//! The headline rule is cross-resource: a pwn-request — a privileged untrusted
//! trigger (pull_request_target / workflow_run) combined with a step that checks
//! out the attacker-controlled PR ref — which runs fork code with the repo's
//! write token and secrets.

use engine::{count_severities, Finding, Pack, Rule, Severity, Status, Verdict};
use fact_model::{Entity, EntityKind, FactModel};

pub const PACK_ID: &str = "gha-core";

struct FnRule {
    id: &'static str,
    f: fn(&FactModel) -> Vec<Finding>,
}
impl Rule for FnRule {
    fn id(&self) -> &str {
        self.id
    }
    fn evaluate(&self, m: &FactModel) -> Vec<Finding> {
        (self.f)(m)
    }
}

fn finding(
    rule_id: &str,
    controls: &[&str],
    severity: Severity,
    evidence: Vec<String>,
    message: String,
    fix: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        controls: controls.iter().map(|s| s.to_string()).collect(),
        severity,
        evidence,
        message,
        remediation: fix.to_string(),
        lines: Vec::new(),
    }
}

fn short(id: &str) -> &str {
    id.split_once(':').map(|(_, r)| r).unwrap_or(id)
}

fn steps(m: &FactModel) -> impl Iterator<Item = &Entity> {
    m.entities.iter().filter(|e| e.kind == EntityKind::Step)
}

fn workflow(m: &FactModel) -> Option<&Entity> {
    m.entities.iter().find(|e| e.kind == EntityKind::Workflow)
}

// --- pwn-request (cross-resource) -----------------------------------------
fn r_pwn_request(m: &FactModel) -> Vec<Finding> {
    let wf = match workflow(m) {
        Some(w) if w.attr("pr_target_trigger").and_then(|v| v.as_bool()) == Some(true) => w,
        _ => return Vec::new(),
    };
    let triggers = wf
        .attr("triggers")
        .and_then(|v| match v {
            fact_model::AttrValue::List(xs) => Some(
                xs.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            _ => None,
        })
        .unwrap_or_default();
    steps(m)
        .filter(|s| s.attr("checkout_untrusted").and_then(|v| v.as_bool()) == Some(true))
        .map(|s| {
            finding(
                "GHA-PWN-REQUEST",
                &["CWE-94", "CWE-829"],
                Severity::Critical,
                vec![wf.id.clone(), s.id.clone()],
                format!(
                    "Workflow runs on a privileged untrusted trigger ({triggers}) and step '{}' checks out the attacker-controlled PR ref — fork code executes with the repo's write token and secrets (pwn-request)",
                    short(&s.id)
                ),
                "Don't check out and run untrusted PR code under pull_request_target/workflow_run. Use 'pull_request' for untrusted code (read-only token, no secrets), or split into a safe build + a separate privileged job that never runs fork code.",
            )
        })
        .collect()
}

// --- script injection -----------------------------------------------------
fn r_script_injection(m: &FactModel) -> Vec<Finding> {
    steps(m)
        .filter(|s| s.attr("injection").and_then(|v| v.as_bool()) == Some(true))
        .map(|s| {
            let ctx = s.attr("injection_context").and_then(|v| v.as_str()).unwrap_or("github.event.*");
            finding(
                "GHA-SCRIPT-INJECTION",
                &["CWE-94", "CWE-78"],
                Severity::High,
                vec![s.id.clone()],
                format!(
                    "Step '{}' interpolates attacker-controlled '${{{{ {ctx} }}}}' directly into a run: shell — an attacker sets that value to inject shell commands",
                    short(&s.id)
                ),
                "Never interpolate ${{ github.event.* }} into run:. Pass it through an env: variable and reference \"$VAR\" (quoted) in the script, or use an action input instead.",
            )
        })
        .collect()
}

// --- unpinned third-party action ------------------------------------------
fn r_unpinned_action(m: &FactModel) -> Vec<Finding> {
    steps(m)
        .filter(|s| {
            s.attr("step_type").and_then(|v| v.as_str()) == Some("uses")
                && s.attr("pinned").and_then(|v| v.as_bool()) == Some(false)
                && s.attr("is_local").and_then(|v| v.as_bool()) != Some(true)
                && s.attr("ref").and_then(|v| v.as_str()).map(|r| !r.is_empty()) == Some(true)
        })
        .map(|s| {
            let action = s.attr("action").and_then(|v| v.as_str()).unwrap_or("?");
            let reference = s.attr("ref").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "GHA-UNPINNED-ACTION",
                &["CWE-494", "CWE-829"],
                Severity::Low,
                vec![s.id.clone()],
                format!("Action '{action}' is pinned to the mutable ref '{reference}', not a commit SHA — whoever controls that tag/branch can change the code your workflow runs"),
                "Pin third-party actions to a full commit SHA (uses: owner/repo@<40-char-sha>); track updates with Dependabot.",
            )
        })
        .collect()
}

// --- broad token permissions ----------------------------------------------
fn r_broad_permissions(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Workflow | EntityKind::Job))
        .filter(|e| e.attr("permissions_write_all").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let scope = if e.kind == EntityKind::Workflow { "Workflow" } else { "Job" };
            finding(
                "GHA-BROAD-PERMISSIONS",
                &["CWE-272", "CWE-250"],
                Severity::Medium,
                vec![e.id.clone()],
                format!("{scope} sets 'permissions: write-all' — the GITHUB_TOKEN gets write access to every scope (contents, packages, deployments, …), so any compromised step can tamper widely"),
                "Set least-privilege permissions: default to 'permissions: {}' (or contents: read) and grant only the specific write scopes a job needs.",
            )
        })
        .collect()
}

// --- self-hosted runner ---------------------------------------------------
fn r_self_hosted(m: &FactModel) -> Vec<Finding> {
    let untrusted = workflow(m)
        .and_then(|w| w.attr("untrusted_trigger"))
        .and_then(|v| v.as_bool())
        == Some(true);
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Job)
        .filter(|e| e.attr("self_hosted").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let sev = if untrusted { Severity::Medium } else { Severity::Low };
            let extra = if untrusted {
                " — combined with an untrusted trigger, a fork PR can run attacker code on your runner, which is persistent and often has network/credentials access"
            } else {
                ""
            };
            finding(
                "GHA-SELF-HOSTED-RUNNER",
                &["CWE-668"],
                sev,
                vec![e.id.clone()],
                format!("Job '{}' runs on a self-hosted runner{extra}", short(&e.id)),
                "Avoid self-hosted runners for workflows reachable by untrusted triggers; if required, use ephemeral/isolated runners and never expose them to fork PRs.",
            )
        })
        .collect()
}

// --- secrets: inherit -----------------------------------------------------
fn r_secrets_inherit(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Job)
        .filter(|e| e.attr("secrets_inherit").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            finding(
                "GHA-SECRETS-INHERIT",
                &["CWE-200", "CWE-668"],
                Severity::Medium,
                vec![e.id.clone()],
                format!("Job '{}' calls a reusable workflow with 'secrets: inherit' — it passes ALL of the caller's secrets, not just the ones needed", short(&e.id)),
                "Pass only the specific secrets the reusable workflow needs ('secrets: { TOKEN: ${{ secrets.TOKEN }} }') instead of inherit.",
            )
        })
        .collect()
}

/// Static catalog of every rule this pack can emit (for the in-app catalog).
pub fn catalog() -> Vec<engine::RuleMeta> {
    use engine::RuleMeta;
    use engine::Severity::{Critical, High, Low, Medium};
    let t = "GitHub Actions";
    vec![
        RuleMeta { id: "GHA-PWN-REQUEST", title: "pwn-request (untrusted checkout)", target: t, severity: Critical, controls: &["CWE-94", "CWE-829"], summary: "Cross-resource: a privileged untrusted trigger (pull_request_target / workflow_run) plus a step that checks out the attacker-controlled PR ref — fork code runs with the repo's write token and secrets.", fix: "Don't run untrusted PR code under pull_request_target; use pull_request, or split safe build from privileged job.", strict: false },
        RuleMeta { id: "GHA-SCRIPT-INJECTION", title: "Script injection in run:", target: t, severity: High, controls: &["CWE-94", "CWE-78"], summary: "A run: step interpolates attacker-controlled ${{ github.event.* }} (issue/PR title/body, comment, head_ref, …) straight into the shell — command injection.", fix: "Pass the value via env: and reference \"$VAR\" quoted; never interpolate github.event.* into run:.", strict: false },
        RuleMeta { id: "GHA-BROAD-PERMISSIONS", title: "Over-broad token permissions", target: t, severity: Medium, controls: &["CWE-272", "CWE-250"], summary: "permissions: write-all grants the GITHUB_TOKEN write to every scope, so any compromised step can tamper widely.", fix: "Default to read-only permissions and grant only the specific write scopes a job needs.", strict: false },
        RuleMeta { id: "GHA-SELF-HOSTED-RUNNER", title: "Self-hosted runner", target: t, severity: Medium, controls: &["CWE-668"], summary: "A job runs on a self-hosted runner; with an untrusted trigger a fork PR can run attacker code on a persistent runner (Medium), otherwise informational (Low).", fix: "Use ephemeral/isolated runners; never expose self-hosted runners to fork PRs.", strict: false },
        RuleMeta { id: "GHA-SECRETS-INHERIT", title: "secrets: inherit", target: t, severity: Medium, controls: &["CWE-200", "CWE-668"], summary: "A job calls a reusable workflow with secrets: inherit, passing ALL caller secrets rather than only those needed.", fix: "Pass only the specific secrets the reusable workflow needs.", strict: false },
        RuleMeta { id: "GHA-UNPINNED-ACTION", title: "Action not pinned to SHA", target: t, severity: Low, controls: &["CWE-494", "CWE-829"], summary: "A third-party action is pinned to a mutable tag/branch instead of a commit SHA — whoever controls that ref can change the code your workflow runs.", fix: "Pin actions to a full commit SHA; track updates with Dependabot.", strict: false },
    ]
}

pub struct GhaCorePack {
    rules: Vec<Box<dyn Rule>>,
}

impl GhaCorePack {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(FnRule { id: "GHA-PWN-REQUEST", f: r_pwn_request }),
            Box::new(FnRule { id: "GHA-SCRIPT-INJECTION", f: r_script_injection }),
            Box::new(FnRule { id: "GHA-BROAD-PERMISSIONS", f: r_broad_permissions }),
            Box::new(FnRule { id: "GHA-SELF-HOSTED-RUNNER", f: r_self_hosted }),
            Box::new(FnRule { id: "GHA-SECRETS-INHERIT", f: r_secrets_inherit }),
            Box::new(FnRule { id: "GHA-UNPINNED-ACTION", f: r_unpinned_action }),
        ];
        Self { rules }
    }
}

impl Default for GhaCorePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Pack for GhaCorePack {
    fn id(&self) -> &str {
        PACK_ID
    }
    fn rules(&self) -> &[Box<dyn Rule>] {
        &self.rules
    }
    fn verdict(&self, findings: &[Finding]) -> Verdict {
        let counts = count_severities(findings);
        let status = if counts.critical > 0 || counts.high > 0 {
            Status::FlaggedGap
        } else {
            Status::Cleared
        };
        Verdict {
            counts,
            status,
            pack_policy: "any Critical or High => Flagged-Gap".to_string(),
        }
    }
}
