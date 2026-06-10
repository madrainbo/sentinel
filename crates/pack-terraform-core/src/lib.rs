//! terraform-core pack — deterministic Terraform/IaC security rules. Pure
//! functions of the fact model produced by `terraform-parser`.

use engine::{count_severities, Finding, Pack, Rule, Severity, Status, Verdict};
use fact_model::{Entity, EntityKind, FactModel};

pub const PACK_ID: &str = "terraform-core";

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

fn finding(rule_id: &str, controls: &[&str], severity: Severity, evidence: &str, message: String, fix: &str) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        controls: controls.iter().map(|s| s.to_string()).collect(),
        severity,
        evidence: vec![evidence.to_string()],
        message,
        remediation: fix.to_string(),
        lines: Vec::new(),
    }
}

fn resources(m: &FactModel) -> impl Iterator<Item = &Entity> {
    m.entities.iter().filter(|e| e.kind == EntityKind::Resource)
}

fn label(e: &Entity) -> String {
    let rt = e.attr("resource_type").and_then(|v| v.as_str()).unwrap_or("");
    let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("");
    format!("{rt}.{name}")
}

// --- open security group --------------------------------------------------
fn r_open_security_group(m: &FactModel) -> Vec<Finding> {
    resources(m)
        .filter(|e| e.attr("open_ingress").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let detail = e.attr("open_ingress_detail").and_then(|v| v.as_str()).unwrap_or("a port");
            finding(
                "TF-OPEN-SECURITY-GROUP",
                &["CWE-284", "CWE-668"],
                Severity::High,
                &e.id,
                format!("Security group '{}' allows ingress from 0.0.0.0/0 on {detail} — open to the entire internet", label(e)),
                "Restrict cidr_blocks to known networks (your VPC/office ranges); never expose admin ports (22/3389) or datastores to 0.0.0.0/0.",
            )
        })
        .collect()
}

// --- public S3 bucket -----------------------------------------------------
fn r_public_s3(m: &FactModel) -> Vec<Finding> {
    resources(m)
        .filter(|e| e.attr("public_acl").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            finding(
                "TF-PUBLIC-S3-BUCKET",
                &["CWE-732", "CWE-284"],
                Severity::High,
                &e.id,
                format!("S3 bucket ACL on '{}' is public (public-read / authenticated-read) — its objects are world-readable", label(e)),
                "Remove the public ACL; keep buckets private and use aws_s3_bucket_public_access_block, with presigned URLs or CloudFront for controlled access.",
            )
        })
        .collect()
}

// --- unencrypted storage --------------------------------------------------
fn r_unencrypted_storage(m: &FactModel) -> Vec<Finding> {
    resources(m)
        .filter(|e| e.attr("unencrypted_storage").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let kind = e.attr("storage_kind").and_then(|v| v.as_str()).unwrap_or("storage");
            finding(
                "TF-UNENCRYPTED-STORAGE",
                &["CWE-311"],
                Severity::Medium,
                &e.id,
                format!("{kind} '{}' is not encrypted at rest", label(e)),
                "Enable encryption at rest (encrypted = true / storage_encrypted = true), ideally with a customer-managed KMS key.",
            )
        })
        .collect()
}

// --- IAM wildcard action --------------------------------------------------
fn r_iam_action_wildcard(m: &FactModel) -> Vec<Finding> {
    resources(m)
        .filter(|e| e.attr("iam_action_wildcard").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            finding(
                "TF-IAM-WILDCARD-ACTION",
                &["CWE-269", "CWE-250"],
                Severity::High,
                &e.id,
                format!("IAM policy '{}' allows Action \"*\" — grants every permission (admin) to whoever holds it", label(e)),
                "Scope the policy to the specific actions required; never grant Action \"*\" outside break-glass admin roles.",
            )
        })
        .collect()
}

// --- IAM public principal -------------------------------------------------
fn r_iam_public_principal(m: &FactModel) -> Vec<Finding> {
    resources(m)
        .filter(|e| e.attr("iam_principal_wildcard").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            finding(
                "TF-IAM-PUBLIC-PRINCIPAL",
                &["CWE-284", "CWE-732"],
                Severity::High,
                &e.id,
                format!("Resource policy '{}' allows Principal \"*\" with Effect Allow — any AWS account/anonymous caller is granted access", label(e)),
                "Set an explicit, least-privilege Principal (specific account/role ARNs); never combine Principal \"*\" with Allow on a sensitive resource.",
            )
        })
        .collect()
}

// --- plaintext secret -----------------------------------------------------
fn r_plaintext_secret(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Secret)
        .map(|e| {
            let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("?");
            let owner = e.attr("owner").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "TF-PLAINTEXT-SECRET",
                &["CWE-798", "CWE-312"],
                Severity::High,
                &e.id,
                format!("'{name}' in {owner} is set to a hardcoded literal — the secret is committed to version control and the Terraform state"),
                "Never hardcode secrets in .tf. Use variables fed from a secret store (Vault/SSM/secrets manager), TF_VAR_ env, or a sensitive variable — and rotate the exposed value.",
            )
        })
        .collect()
}

/// Static catalog of every rule this pack can emit (for the in-app catalog).
pub fn catalog() -> Vec<engine::RuleMeta> {
    use engine::RuleMeta;
    use engine::Severity::{High, Medium};
    let t = "Terraform";
    vec![
        RuleMeta { id: "TF-OPEN-SECURITY-GROUP", title: "Security group open to 0.0.0.0/0", target: t, severity: High, controls: &["CWE-284", "CWE-668"], summary: "An aws_security_group ingress rule allows 0.0.0.0/0 — open to the entire internet (critical for admin ports / datastores).", fix: "Restrict cidr_blocks to known networks; never expose 22/3389 or databases to 0.0.0.0/0.", strict: false },
        RuleMeta { id: "TF-PUBLIC-S3-BUCKET", title: "Public S3 bucket ACL", target: t, severity: High, controls: &["CWE-732", "CWE-284"], summary: "An S3 bucket ACL is public-read / public-read-write / authenticated-read — objects are world-readable.", fix: "Keep buckets private; use a public access block and presigned URLs / CloudFront.", strict: false },
        RuleMeta { id: "TF-IAM-WILDCARD-ACTION", title: "IAM policy allows Action *", target: t, severity: High, controls: &["CWE-269", "CWE-250"], summary: "An IAM policy statement allows Action \"*\" with Effect Allow — full admin to whoever holds it.", fix: "Scope to the specific actions required; avoid Action \"*\".", strict: false },
        RuleMeta { id: "TF-IAM-PUBLIC-PRINCIPAL", title: "Resource policy Principal *", target: t, severity: High, controls: &["CWE-284", "CWE-732"], summary: "A resource policy allows Principal \"*\" with Allow — any AWS account / anonymous caller gets access.", fix: "Use explicit least-privilege Principal ARNs.", strict: false },
        RuleMeta { id: "TF-PLAINTEXT-SECRET", title: "Hardcoded secret in HCL", target: t, severity: High, controls: &["CWE-798", "CWE-312"], summary: "A credential attribute (password/secret_key/token/…) is set to a literal string — committed to VCS and Terraform state.", fix: "Use variables from a secret store / TF_VAR_ env; mark sensitive; rotate the exposed value.", strict: false },
        RuleMeta { id: "TF-UNENCRYPTED-STORAGE", title: "Storage not encrypted at rest", target: t, severity: Medium, controls: &["CWE-311"], summary: "An EBS volume or RDS database does not enable encryption at rest.", fix: "Set encrypted = true / storage_encrypted = true, ideally with a customer-managed KMS key.", strict: false },
    ]
}

pub struct TerraformCorePack {
    rules: Vec<Box<dyn Rule>>,
}

impl TerraformCorePack {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(FnRule { id: "TF-OPEN-SECURITY-GROUP", f: r_open_security_group }),
            Box::new(FnRule { id: "TF-PUBLIC-S3-BUCKET", f: r_public_s3 }),
            Box::new(FnRule { id: "TF-IAM-WILDCARD-ACTION", f: r_iam_action_wildcard }),
            Box::new(FnRule { id: "TF-IAM-PUBLIC-PRINCIPAL", f: r_iam_public_principal }),
            Box::new(FnRule { id: "TF-PLAINTEXT-SECRET", f: r_plaintext_secret }),
            Box::new(FnRule { id: "TF-UNENCRYPTED-STORAGE", f: r_unencrypted_storage }),
        ];
        Self { rules }
    }
}

impl Default for TerraformCorePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Pack for TerraformCorePack {
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
