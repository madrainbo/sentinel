//! Secrets & config sweep -> FactModel. Deterministic, dependency-free, no LLM.
//!
//! Scans arbitrary text (`.env`, config dumps, source) line-by-line for
//! high-confidence credential tokens (AWS keys, private keys, provider tokens)
//! plus generic `SECRET=...` style assignments, and emits one `Secret` entity
//! per finding with a redacted preview (the secret value itself is never stored
//! in full). The rule pack turns these into findings by `secret_type`.

use std::collections::BTreeMap;

use fact_model::{
    sha256_prefixed, AttrValue, Entity, EntityKind, FactModel, Provenance, SourceDescriptor,
};

pub const PARSER_VERSION: &str = "0.1.0";

/// Attribute-name fragments (uppercased, separators removed) that mark a generic
/// credential assignment when set to a literal value.
const SECRET_NAME_FRAGMENTS: &[&str] = &[
    "PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY", "ACCESSKEY", "PRIVATEKEY", "CREDENTIAL",
    "CLIENTSECRET", "AUTHTOKEN", "PASSPHRASE",
];

struct Match {
    rule: &'static str,
    line: usize,
    detail: String,
    redacted: String,
}

pub fn parse(input: &str) -> FactModel {
    let input_hash = sha256_prefixed(input.as_bytes());
    let mut entities = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for m in scan(input) {
        let id = format!("secret:L{}:{}", m.line, m.rule);
        if !seen.insert(id.clone()) {
            continue;
        }
        let mut a = BTreeMap::new();
        a.insert("secret_type".into(), AttrValue::Str(m.rule.to_string()));
        a.insert("line".into(), AttrValue::Int(m.line as i64));
        a.insert("redacted".into(), AttrValue::Str(m.redacted));
        if !m.detail.is_empty() {
            a.insert("detail".into(), AttrValue::Str(m.detail));
        }
        entities.push(Entity {
            id,
            kind: EntityKind::Secret,
            attributes: a,
            provenance: Provenance::explicit(format!("line {}", m.line)).with_line(Some(m.line as u32)),
        });
    }

    FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "secrets".to_string(),
            input_hash,
            parser_version: PARSER_VERSION.to_string(),
        },
        entities,
        relations: Vec::new(),
    }
}

fn scan(input: &str) -> Vec<Match> {
    let mut out = Vec::new();
    for (i, raw) in input.lines().enumerate() {
        let line = raw;
        let lineno = i + 1;
        let trimmed = line.trim_start();
        let is_comment = trimmed.starts_with('#') || trimmed.starts_with("//");

        let mut strong_hit = false;

        // Private key block header.
        if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
            out.push(Match {
                rule: "SECRET-PRIVATE-KEY",
                line: lineno,
                detail: String::new(),
                redacted: "-----BEGIN … PRIVATE KEY-----".to_string(),
            });
            strong_hit = true;
        }

        // Prefixed provider tokens (exact-ish lengths to keep precision high).
        for (rule, prefix, min, max, cls) in TOKEN_PATTERNS {
            for tok in find_tokens(line, prefix, *min, *max, *cls) {
                out.push(Match {
                    rule,
                    line: lineno,
                    detail: String::new(),
                    redacted: redact(&tok, prefix),
                });
                strong_hit = true;
            }
        }

        // Generic dotenv-style credential assignment (only if no strong token on
        // this line, to avoid double-reporting e.g. AWS_KEY=AKIA...).
        if !is_comment && !strong_hit {
            if let Some((key, val)) = dotenv_kv(trimmed) {
                if is_secret_key(&key) && is_literal_secret(&val) {
                    out.push(Match {
                        rule: "SECRET-GENERIC-CREDENTIAL",
                        line: lineno,
                        detail: key,
                        redacted: redact(&val, ""),
                    });
                }
            }
        }
    }
    out
}

type Cls = fn(u8) -> bool;
/// (rule_id, prefix, min body len, max body len, body char class).
const TOKEN_PATTERNS: &[(&str, &str, usize, usize, Cls)] = &[
    ("SECRET-AWS-ACCESS-KEY", "AKIA", 16, 16, is_upper_alnum),
    ("SECRET-AWS-ACCESS-KEY", "ASIA", 16, 16, is_upper_alnum),
    ("SECRET-GITHUB-TOKEN", "ghp_", 36, 36, is_alnum),
    ("SECRET-GITHUB-TOKEN", "gho_", 36, 36, is_alnum),
    ("SECRET-GITHUB-TOKEN", "ghu_", 36, 36, is_alnum),
    ("SECRET-GITHUB-TOKEN", "ghs_", 36, 36, is_alnum),
    ("SECRET-GITHUB-TOKEN", "github_pat_", 20, 120, is_alnum_us),
    ("SECRET-SLACK-TOKEN", "xoxb-", 10, 80, is_alnum_dash),
    ("SECRET-SLACK-TOKEN", "xoxp-", 10, 80, is_alnum_dash),
    ("SECRET-SLACK-TOKEN", "xoxa-", 10, 80, is_alnum_dash),
    ("SECRET-GOOGLE-API-KEY", "AIza", 35, 35, is_alnum_kd),
    ("SECRET-STRIPE-KEY", "sk_live_", 10, 80, is_alnum),
    ("SECRET-STRIPE-KEY", "rk_live_", 10, 80, is_alnum),
    ("SECRET-SENDGRID-KEY", "SG.", 30, 90, is_alnum_kd_dot),
];

fn is_upper_alnum(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn is_alnum_us(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
fn is_alnum_dash(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}
fn is_alnum_kd(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
fn is_alnum_kd_dot(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'
}
fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Find every token = prefix + (min..=max) chars of `cls`, with a non-identifier
/// boundary before the prefix and after the body.
fn find_tokens(line: &str, prefix: &str, min: usize, max: usize, cls: Cls) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(rel) = line[search..].find(prefix) {
        let start = search + rel;
        let before_ok = start == 0 || !is_ident(bytes[start - 1]);
        let body_start = start + prefix.len();
        let mut k = body_start;
        while k < bytes.len() && cls(bytes[k]) {
            k += 1;
        }
        let body = k - body_start;
        let after_ok = k >= bytes.len() || !is_ident(bytes[k]) || body >= max;
        if before_ok && body >= min && body <= max && after_ok {
            out.push(line[start..(start + prefix.len() + body.min(max)).min(bytes.len())].to_string());
        }
        search = start + prefix.len();
    }
    out
}

fn dotenv_kv(line: &str) -> Option<(String, String)> {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let (k, v) = line.split_once('=')?;
    let key = k.trim().to_string();
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let mut val = v.trim().to_string();
    // strip surrounding quotes
    if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
        || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
    {
        val = val[1..val.len() - 1].to_string();
    }
    Some((key, val))
}

fn is_secret_key(key: &str) -> bool {
    let norm: String = key.to_uppercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if norm.ends_with("ID") || norm.ends_with("ARN") || norm.ends_with("URL") || norm.ends_with("USER")
    {
        return false;
    }
    SECRET_NAME_FRAGMENTS.iter().any(|f| norm.contains(f))
}

fn is_literal_secret(val: &str) -> bool {
    if val.len() < 8 {
        return false;
    }
    // references / interpolations / command substitutions are not literals
    !(val.contains("${") || val.starts_with('$') || val.contains("$("))
}

/// Build a non-reversible display preview. The secret's entropy is never shown:
/// `marker` is a known, non-secret type prefix from our own pattern table
/// (e.g. `AKIA`, `sk_live_`) revealed verbatim so the user can recognise the
/// credential class — empty for opaque values — and the secret body is always
/// masked. Only the total length leaks, which is low-sensitivity and helps
/// locate the match. Previously this echoed the first 6 chars of the raw value,
/// which exposed a meaningful fraction of short credentials in shared reports.
fn redact(value: &str, marker: &str) -> String {
    let len = value.chars().count();
    if marker.is_empty() {
        format!("•••• ({len} chars)")
    } else {
        format!("{marker}•••• ({len} chars)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism() {
        let s = "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n";
        assert_eq!(parse(s).model_hash(), parse(s).model_hash());
    }

    #[test]
    fn detects_aws_key() {
        let fm = parse("key = AKIAIOSFODNN7EXAMPLE\n");
        assert!(fm.entities.iter().any(|e| e.attr("secret_type").and_then(|v| v.as_str())
            == Some("SECRET-AWS-ACCESS-KEY")));
    }

    #[test]
    fn detects_private_key_header() {
        let fm = parse("-----BEGIN RSA PRIVATE KEY-----\n");
        assert!(fm.entities.iter().any(|e| e.attr("secret_type").and_then(|v| v.as_str())
            == Some("SECRET-PRIVATE-KEY")));
    }

    #[test]
    fn generic_credential_and_no_double_report() {
        // AWS line should report AWS key once, not also as generic.
        let fm = parse("AWS_SECRET=AKIAIOSFODNN7EXAMPLE\n");
        let n = fm.entities.len();
        assert_eq!(n, 1);
        // a non-token secret value still caught generically
        let fm2 = parse("DB_PASSWORD=hunter2pass\n");
        assert!(fm2.entities.iter().any(|e| e.attr("secret_type").and_then(|v| v.as_str())
            == Some("SECRET-GENERIC-CREDENTIAL")));
    }

    #[test]
    fn reference_value_not_flagged() {
        let fm = parse("DB_PASSWORD=${DB_PASSWORD}\n");
        assert!(fm.entities.is_empty());
    }

    /// The redacted preview must not expose the secret's entropy: only the known
    /// type marker (e.g. `AKIA`) may appear; the secret body must never leak.
    #[test]
    fn redaction_does_not_leak_secret_body() {
        // Prefixed token: the public marker may show, but the entropy body
        // ("IOSFODNN7EXAMPLE") must be masked, not echoed.
        let fm = parse("AWS_KEY = AKIAIOSFODNN7EXAMPLE\n");
        let r = fm.entities[0].attr("redacted").and_then(|v| v.as_str()).unwrap();
        assert!(r.starts_with("AKIA"), "marker should be shown: {r}");
        assert!(!r.contains("IOSFODNN"), "secret body must not leak: {r}");
        assert!(r.contains("chars)"), "length hint expected: {r}");

        // Opaque generic credential: no part of the value body may appear (only
        // the `(N chars)` length hint is allowed).
        let fm2 = parse("DB_PASSWORD=hunterpassphrase\n");
        let r2 = fm2.entities[0].attr("redacted").and_then(|v| v.as_str()).unwrap();
        assert!(!r2.contains("hunter"), "generic secret value must not leak: {r2}");
        assert!(!r2.contains("passphrase"), "generic secret value must not leak: {r2}");
        assert!(r2.contains("chars)"), "length hint expected: {r2}");
    }
}
