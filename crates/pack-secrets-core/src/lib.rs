//! secrets-core pack — turns the `Secret` entities found by `secrets-parser`
//! into findings, one per detected credential, keyed by secret type.

use engine::{count_severities, Finding, Pack, Rule, Severity, Status, Verdict};
use fact_model::{EntityKind, FactModel};

pub const PACK_ID: &str = "secrets-core";

/// (rule_id, severity, human name of the credential).
const SECRET_TYPES: &[(&str, Severity, &str)] = &[
    ("SECRET-AWS-ACCESS-KEY", Severity::High, "AWS access key id"),
    ("SECRET-PRIVATE-KEY", Severity::High, "private key"),
    ("SECRET-GITHUB-TOKEN", Severity::High, "GitHub token"),
    ("SECRET-SLACK-TOKEN", Severity::High, "Slack token"),
    ("SECRET-STRIPE-KEY", Severity::High, "Stripe secret key"),
    ("SECRET-SENDGRID-KEY", Severity::High, "SendGrid API key"),
    ("SECRET-GOOGLE-API-KEY", Severity::Medium, "Google API key"),
    ("SECRET-GENERIC-CREDENTIAL", Severity::Medium, "credential"),
];

fn meta_for(rule: &str) -> (Severity, &'static str) {
    SECRET_TYPES
        .iter()
        .find(|(id, _, _)| *id == rule)
        .map(|(_, s, n)| (*s, *n))
        .unwrap_or((Severity::Medium, "credential"))
}

struct SecretsRule;
impl Rule for SecretsRule {
    fn id(&self) -> &str {
        "SECRETS-SWEEP"
    }
    fn evaluate(&self, m: &FactModel) -> Vec<Finding> {
        let mut out = Vec::new();
        for e in m.entities.iter().filter(|e| e.kind == EntityKind::Secret) {
            let rule = match e.attr("secret_type").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };
            let (severity, name) = meta_for(rule);
            let line = e.attr("line").and_then(|v| v.as_i64()).unwrap_or(0);
            let redacted = e.attr("redacted").and_then(|v| v.as_str()).unwrap_or("");
            let detail = e.attr("detail").and_then(|v| v.as_str()).unwrap_or("");
            let where_ = if detail.is_empty() {
                format!("line {line}")
            } else {
                format!("'{detail}' on line {line}")
            };
            out.push(Finding {
                rule_id: rule.to_string(),
                controls: vec!["CWE-798".to_string(), "CWE-312".to_string()],
                severity,
                evidence: vec![e.id.clone()],
                message: format!(
                    "A {name} appears to be hardcoded at {where_} ({redacted}) — committed secrets are exposed in version control and history"
                ),
                remediation:
                    "Remove the secret from the file, rotate/revoke it immediately (assume it is compromised once committed), and load it at runtime from a secret manager or an untracked .env."
                        .to_string(),
                lines: Vec::new(),
            });
        }
        out
    }
}

pub fn catalog() -> Vec<engine::RuleMeta> {
    use engine::RuleMeta;
    let t = "Secrets";
    vec![
        RuleMeta { id: "SECRET-AWS-ACCESS-KEY", title: "AWS access key", target: t, severity: Severity::High, controls: &["CWE-798", "CWE-312"], summary: "An AWS access key id (AKIA/ASIA…) is hardcoded in the file.", fix: "Remove it, rotate the key in IAM, and load credentials from the AWS credential chain / a secret manager.", strict: false },
        RuleMeta { id: "SECRET-PRIVATE-KEY", title: "Private key", target: t, severity: Severity::High, controls: &["CWE-798", "CWE-312"], summary: "A PEM private-key block (-----BEGIN … PRIVATE KEY-----) is embedded in the file.", fix: "Remove the key, rotate it, and store private keys outside the repo (secret manager / KMS).", strict: false },
        RuleMeta { id: "SECRET-GITHUB-TOKEN", title: "GitHub token", target: t, severity: Severity::High, controls: &["CWE-798", "CWE-312"], summary: "A GitHub personal access / OAuth token (ghp_/gho_/…/github_pat_) is hardcoded.", fix: "Revoke the token on GitHub and use a secret store or GitHub Actions secrets.", strict: false },
        RuleMeta { id: "SECRET-SLACK-TOKEN", title: "Slack token", target: t, severity: Severity::High, controls: &["CWE-798", "CWE-312"], summary: "A Slack API token (xoxb-/xoxp-/…) is hardcoded.", fix: "Revoke the token in Slack and load it from a secret manager.", strict: false },
        RuleMeta { id: "SECRET-STRIPE-KEY", title: "Stripe secret key", target: t, severity: Severity::High, controls: &["CWE-798", "CWE-312"], summary: "A live Stripe secret key (sk_live_/rk_live_) is hardcoded.", fix: "Roll the key in the Stripe dashboard and load it from a secret manager.", strict: false },
        RuleMeta { id: "SECRET-SENDGRID-KEY", title: "SendGrid API key", target: t, severity: Severity::High, controls: &["CWE-798", "CWE-312"], summary: "A SendGrid API key (SG.…) is hardcoded.", fix: "Revoke the key in SendGrid and load it from a secret manager.", strict: false },
        RuleMeta { id: "SECRET-GOOGLE-API-KEY", title: "Google API key", target: t, severity: Severity::Medium, controls: &["CWE-798", "CWE-312"], summary: "A Google API key (AIza…) is hardcoded.", fix: "Restrict/rotate the key in Google Cloud and load it from a secret manager.", strict: false },
        RuleMeta { id: "SECRET-GENERIC-CREDENTIAL", title: "Hardcoded credential", target: t, severity: Severity::Medium, controls: &["CWE-798", "CWE-312"], summary: "A password/secret/token-named key is assigned a literal value (e.g. in a .env or config file).", fix: "Move the value to a secret manager / untracked .env and reference it at runtime; rotate the exposed value.", strict: false },
    ]
}

pub struct SecretsCorePack {
    rules: Vec<Box<dyn Rule>>,
}

impl SecretsCorePack {
    pub fn new() -> Self {
        Self {
            rules: vec![Box::new(SecretsRule)],
        }
    }
}

impl Default for SecretsCorePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Pack for SecretsCorePack {
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
