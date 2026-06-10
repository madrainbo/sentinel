//! Terraform (HCL) -> FactModel. Deterministic, dependency-free, no LLM.
//!
//! Parses HCL structure (see `hcl`) and projects the security-relevant facts
//! onto `Resource` entities (one per `resource` block) with computed flags the
//! rule pack reads — open security groups, public S3 ACLs, unencrypted storage,
//! wildcard IAM — plus `Secret` entities for plaintext credentials found in any
//! block (resource, provider, variable default, …).

mod hcl;

use std::collections::BTreeMap;

use fact_model::{
    sha256_prefixed, AttrValue, Entity, EntityKind, FactModel, Provenance, Relation,
    RelationKind, SourceDescriptor,
};
use hcl::{Block, Value};

pub const PARSER_VERSION: &str = "0.1.0";

/// Attribute-name fragments (lowercased, separators removed) that indicate a
/// credential, when assigned a literal string.
const SECRET_NAME_FRAGMENTS: &[&str] = &[
    "password", "passwd", "secretkey", "accesskey", "privatekey", "apikey", "token",
    "clientsecret", "secret",
];

struct Builder {
    entities: Vec<Entity>,
    relations: Vec<Relation>,
}

pub fn parse(input: &str) -> FactModel {
    let input_hash = sha256_prefixed(input.as_bytes());
    let mut b = Builder {
        entities: Vec::new(),
        relations: Vec::new(),
    };

    let blocks = hcl::parse_document(input);
    for block in &blocks {
        if block.typ == "resource" && block.labels.len() >= 2 {
            parse_resource(&mut b, block);
        }
        // Plaintext secrets can live in any block (provider creds, variable
        // defaults, locals, resources). Scan the whole subtree.
        scan_secrets(&mut b, block, &owner_label(block));
    }

    FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "terraform".to_string(),
            input_hash,
            parser_version: PARSER_VERSION.to_string(),
        },
        entities: b.entities,
        relations: b.relations,
    }
}

fn owner_label(block: &Block) -> String {
    if block.labels.is_empty() {
        block.typ.clone()
    } else {
        format!("{}.{}", block.typ, block.labels.join("."))
    }
}

fn parse_resource(b: &mut Builder, block: &Block) {
    let rtype = &block.labels[0];
    let name = &block.labels[1];
    let id = format!("resource:{rtype}.{name}");

    let mut a = BTreeMap::new();
    a.insert("resource_type".into(), AttrValue::Str(rtype.clone()));
    a.insert("name".into(), AttrValue::Str(name.clone()));

    match rtype.as_str() {
        "aws_security_group" => {
            let (open, detail) = security_group_open(block);
            a.insert("open_ingress".into(), AttrValue::Bool(open));
            if let Some(d) = detail {
                a.insert("open_ingress_detail".into(), AttrValue::Str(d));
            }
        }
        "aws_security_group_rule" => {
            let is_ingress = block.attr("type").map(|v| v.text() == "ingress").unwrap_or(false);
            let open = is_ingress && cidr_open(block);
            a.insert("open_ingress".into(), AttrValue::Bool(open));
            if open {
                a.insert("open_ingress_detail".into(), AttrValue::Str(port_detail(block)));
            }
        }
        "aws_s3_bucket" => {
            a.insert("public_acl".into(), AttrValue::Bool(is_public_acl(block.attr("acl"))));
        }
        "aws_s3_bucket_acl" => {
            // acl may be a top-level attr or inside an access_control_policy block.
            a.insert("public_acl".into(), AttrValue::Bool(is_public_acl(block.attr("acl"))));
        }
        "aws_ebs_volume" => {
            a.insert("storage_kind".into(), AttrValue::Str("EBS volume".into()));
            a.insert(
                "unencrypted_storage".into(),
                AttrValue::Bool(!bool_attr_true(block.attr("encrypted"))),
            );
        }
        "aws_db_instance" | "aws_rds_cluster" => {
            a.insert("storage_kind".into(), AttrValue::Str("RDS database".into()));
            a.insert(
                "unencrypted_storage".into(),
                AttrValue::Bool(!bool_attr_true(block.attr("storage_encrypted"))),
            );
        }
        "aws_iam_policy" | "aws_iam_role_policy" | "aws_iam_group_policy"
        | "aws_iam_user_policy" | "aws_iam_role" => {
            let policy_text = iam_policy_text(block);
            a.insert(
                "iam_action_wildcard".into(),
                AttrValue::Bool(policy_action_wildcard(&policy_text)),
            );
            a.insert(
                "iam_principal_wildcard".into(),
                AttrValue::Bool(policy_principal_wildcard(&policy_text)),
            );
        }
        _ => {}
    }

    b.entities.push(Entity {
        id,
        kind: EntityKind::Resource,
        attributes: a,
        provenance: Provenance::explicit(format!("resource.{rtype}.{name}"))
            .with_line(Some(block.line)),
    });
}

// --- security groups ------------------------------------------------------

fn cidr_open(block: &Block) -> bool {
    block
        .attr("cidr_blocks")
        .map(|v| v.contains_scalar("0.0.0.0/0"))
        .unwrap_or(false)
        || block
            .attr("ipv6_cidr_blocks")
            .map(|v| v.contains_scalar("::/0"))
            .unwrap_or(false)
}

fn port_detail(block: &Block) -> String {
    let from = block.attr("from_port").map(|v| v.text()).unwrap_or_default();
    let to = block.attr("to_port").map(|v| v.text()).unwrap_or_default();
    if from.is_empty() && to.is_empty() {
        "all ports".to_string()
    } else if from == to {
        format!("port {from}")
    } else {
        format!("ports {from}-{to}")
    }
}

fn security_group_open(block: &Block) -> (bool, Option<String>) {
    for ing in block.child_blocks("ingress") {
        if cidr_open(ing) {
            return (true, Some(port_detail(ing)));
        }
    }
    (false, None)
}

// --- s3 acl ---------------------------------------------------------------

fn is_public_acl(v: Option<&Value>) -> bool {
    match v.map(|v| v.text()) {
        Some(s) => s == "public-read" || s == "public-read-write" || s == "authenticated-read",
        None => false,
    }
}

// --- encryption -----------------------------------------------------------

fn bool_attr_true(v: Option<&Value>) -> bool {
    matches!(v.map(|v| v.text().to_lowercase()), Some(s) if s == "true")
}

// --- IAM ------------------------------------------------------------------

fn iam_policy_text(block: &Block) -> String {
    let mut parts = Vec::new();
    for key in ["policy", "assume_role_policy", "inline_policy"] {
        if let Some(v) = block.attr(key) {
            parts.push(v.text());
        }
    }
    // inline_policy can also be a nested block.
    for ip in block.child_blocks("inline_policy") {
        if let Some(v) = ip.attr("policy") {
            parts.push(v.text());
        }
    }
    parts.join("\n")
}

/// Whitespace-stripped policy text contains an Allow effect (heredoc JSON
/// `"Effect":"Allow"` or jsonencode HCL `Effect="Allow"`).
fn has_allow(norm: &str) -> bool {
    norm.contains("\"Effect\":\"Allow\"") || norm.contains("Effect=\"Allow\"")
}

/// Detects an Allow statement granting Action "*" (admin). Handles both the
/// heredoc/JSON form (`"Action":"*"`) and the jsonencode HCL form (`Action="*"`).
fn policy_action_wildcard(text: &str) -> bool {
    let norm: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let action_star = norm.contains("\"Action\":\"*\"")
        || norm.contains("\"Action\":[\"*\"")
        || norm.contains("Action=\"*\"")
        || norm.contains("Action=[\"*\"");
    action_star && has_allow(&norm)
}

/// Detects a resource policy granting access to Principal "*" (public). Handles
/// `"Principal":"*"`, the AWS-object form, and the jsonencode HCL form.
fn policy_principal_wildcard(text: &str) -> bool {
    let norm: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let principal_star = norm.contains("\"Principal\":\"*\"")
        || norm.contains("Principal=\"*\"")
        || (norm.contains("Principal")
            && (norm.contains("\"AWS\":\"*\"") || norm.contains("AWS=\"*\"")));
    principal_star && has_allow(&norm)
}

// --- plaintext secrets ----------------------------------------------------

fn is_secret_name(name: &str) -> bool {
    let norm: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    // a `*_id` / `*_arn` is a reference, not a secret value
    if norm.ends_with("id") || norm.ends_with("arn") {
        return false;
    }
    SECRET_NAME_FRAGMENTS.iter().any(|f| norm.contains(f))
}

/// A literal string value that is not a reference/interpolation.
fn is_literal_secret(v: &Value) -> bool {
    match v {
        Value::Str(s) => !s.is_empty() && !s.contains("${"),
        _ => false,
    }
}

fn scan_secrets(b: &mut Builder, block: &Block, owner: &str) {
    let mut all = Vec::new();
    block.walk(&mut all);
    for blk in all {
        for (name, value) in &blk.attrs {
            if is_secret_name(name) && is_literal_secret(value) {
                let id = format!("secret:{owner}/{name}");
                // de-dup identical ids
                if b.entities.iter().any(|e| e.id == id) {
                    continue;
                }
                let mut a = BTreeMap::new();
                a.insert("name".into(), AttrValue::Str(name.clone()));
                a.insert("owner".into(), AttrValue::Str(owner.to_string()));
                b.entities.push(Entity {
                    id: id.clone(),
                    kind: EntityKind::Secret,
                    attributes: a,
                    provenance: Provenance::explicit(format!("{owner}.{name}"))
                        .with_line(Some(blk.line)),
                });
                if owner.starts_with("resource.") {
                    let res_id = format!("resource:{}", owner.trim_start_matches("resource."));
                    b.relations.push(Relation {
                        kind: RelationKind::Reads,
                        from: res_id,
                        to: id,
                        attributes: BTreeMap::new(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism() {
        let y = "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n";
        assert_eq!(parse(y).model_hash(), parse(y).model_hash());
    }

    #[test]
    fn open_security_group_flagged() {
        let src = "resource \"aws_security_group\" \"web\" {\n  ingress {\n    from_port = 22\n    to_port = 22\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n";
        let fm = parse(src);
        let r = fm.entities.iter().find(|e| e.kind == EntityKind::Resource).unwrap();
        assert_eq!(r.attr("open_ingress").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn plaintext_secret_flagged() {
        let src = "provider \"aws\" {\n  secret_key = \"AKIAREALSECRET\"\n}\n";
        let fm = parse(src);
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Secret));
    }

    #[test]
    fn bom_and_unicode_do_not_panic() {
        // UTF-8 BOM prefix (common on Windows) + non-ASCII content must not panic.
        let src = "\u{feff}resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"caf\u{e9}-data\"\n  acl = \"public-read\"\n}\n";
        let fm = parse(src);
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Resource
            && e.attr("public_acl").and_then(|v| v.as_bool()) == Some(true)));
    }

    #[test]
    fn secret_reference_not_flagged() {
        let src = "resource \"x\" \"y\" {\n  password = var.db_password\n}\n";
        let fm = parse(src);
        assert!(!fm.entities.iter().any(|e| e.kind == EntityKind::Secret));
    }
}
