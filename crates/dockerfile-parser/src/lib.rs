//! Dockerfile -> FactModel. Deterministic, line-based, no LLM.
//!
//! Models a Dockerfile as: an `Image` per `FROM` (base images), a single `Stage`
//! entity for the final stage (carrying `runs_as` from the last `USER`), and an
//! `Instruction` entity per risky line (remote `ADD`, `curl | sh`, `sudo`,
//! inline build secrets). The Dockerfile rule pack evaluates these.

use std::collections::BTreeMap;

use fact_model::{
    sha256_prefixed, AttrValue, Entity, EntityKind, FactModel, Provenance, Relation,
    RelationKind, SourceDescriptor,
};

pub const PARSER_VERSION: &str = "0.1.0";

const SECRET_NAME_FRAGMENTS: &[&str] = &[
    "PASSWORD", "PASSWD", "PWD", "SECRET", "TOKEN", "APIKEY", "ACCESSKEY", "PRIVATEKEY",
    "CREDENTIAL",
];

struct Builder {
    entities: Vec<Entity>,
    relations: Vec<Relation>,
}

/// Parse a Dockerfile into the fact model (never fails; malformed lines are skipped).
pub fn parse(input: &str) -> FactModel {
    let input_hash = sha256_prefixed(input.as_bytes());
    let mut b = Builder {
        entities: Vec::new(),
        relations: Vec::new(),
    };

    let stage_id = "stage:final".to_string();
    let mut runs_as = "unknown".to_string(); // Docker default is root; "unknown" = no USER seen
    let mut stage_names: Vec<String> = Vec::new();
    let mut instr_n = 0usize;
    let mut final_from_line: Option<u32> = None; // line of the final stage's FROM

    for (lineno, line) in logical_lines(input) {
        let (instr, args) = split_instruction(&line);
        match instr.to_uppercase().as_str() {
            "FROM" => {
                runs_as = "unknown".to_string(); // USER resets at each stage
                final_from_line = Some(lineno);
                parse_from(&mut b, &stage_id, &args, &mut stage_names, lineno);
            }
            "USER" => {
                runs_as = classify_user(&args);
            }
            "ADD" => {
                if add_has_remote_src(&args) {
                    add_instruction(&mut b, &stage_id, &mut instr_n, "ADD", "add_remote", &args, lineno);
                }
            }
            "RUN" => {
                if is_curl_pipe(&args) {
                    add_instruction(&mut b, &stage_id, &mut instr_n, "RUN", "curl_pipe", &args, lineno);
                }
                if mentions_sudo(&args) {
                    add_instruction(&mut b, &stage_id, &mut instr_n, "RUN", "sudo", &args, lineno);
                }
                if is_world_writable(&args) {
                    add_instruction(&mut b, &stage_id, &mut instr_n, "RUN", "world_writable", &args, lineno);
                }
                if disables_tls_verification(&args) {
                    add_instruction(&mut b, &stage_id, &mut instr_n, "RUN", "tls_disabled", &args, lineno);
                }
            }
            "ENV" | "ARG" => {
                if let Some(name) = secret_inline_name(&args) {
                    add_instruction(&mut b, &stage_id, &mut instr_n, &instr.to_uppercase(), "secret", &name, lineno);
                }
            }
            _ => {}
        }
    }

    // Final stage entity (points at the final stage's FROM line, if any).
    let mut attrs = BTreeMap::new();
    attrs.insert("runs_as".into(), AttrValue::Enum(runs_as));
    b.entities.push(Entity {
        id: stage_id,
        kind: EntityKind::Stage,
        attributes: attrs,
        provenance: Provenance::explicit("Dockerfile").with_line(final_from_line),
    });

    FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "dockerfile".to_string(),
            input_hash,
            parser_version: PARSER_VERSION.to_string(),
        },
        entities: b.entities,
        relations: b.relations,
    }
}

/// Join line continuations (`\`), drop comments and blank lines. Each entry is
/// `(start_line, text)` where `start_line` is the 1-based physical line the
/// (possibly continued) instruction begins on.
fn logical_lines(input: &str) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut acc = String::new();
    let mut start: u32 = 0;
    for (i, raw) in input.lines().enumerate() {
        let lineno = (i + 1) as u32;
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if acc.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        if acc.is_empty() {
            start = lineno; // first physical line of this logical instruction
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            acc.push_str(stripped);
            acc.push(' ');
        } else {
            acc.push_str(line);
            out.push((start, acc.trim().to_string()));
            acc = String::new();
        }
    }
    if !acc.trim().is_empty() {
        out.push((start, acc.trim().to_string()));
    }
    out
}

fn split_instruction(line: &str) -> (String, String) {
    match line.split_once(char::is_whitespace) {
        Some((i, rest)) => (i.to_string(), rest.trim().to_string()),
        None => (line.to_string(), String::new()),
    }
}

fn parse_from(b: &mut Builder, stage_id: &str, args: &str, stage_names: &mut Vec<String>, line: u32) {
    let mut toks = args.split_whitespace();
    let img_ref = match toks.next() {
        Some(r) => r,
        None => return,
    };
    // `FROM x AS name` -> remember the stage name.
    let mut iter = toks;
    while let Some(t) = iter.next() {
        if t.eq_ignore_ascii_case("as") {
            if let Some(name) = iter.next() {
                stage_names.push(name.to_string());
            }
        }
    }
    // `FROM <previous-stage>` references a build stage, not an external image.
    if stage_names.iter().any(|n| n == img_ref) {
        return;
    }
    if img_ref.starts_with("${") {
        return; // unresolved build-arg image
    }

    let (repo, tag, digest_pinned) = parse_image_ref(img_ref);
    let id = format!("image:{img_ref}");
    let mut a = BTreeMap::new();
    a.insert("repo".into(), AttrValue::Str(repo));
    a.insert("tag".into(), AttrValue::Str(tag.unwrap_or_else(|| "latest".into())));
    a.insert("digest_pinned".into(), AttrValue::Bool(digest_pinned));
    b.entities.push(Entity {
        id: id.clone(),
        kind: EntityKind::Image,
        attributes: a,
        provenance: Provenance::explicit("FROM").with_line(Some(line)),
    });
    b.relations.push(Relation {
        kind: RelationKind::Uses,
        from: stage_id.to_string(),
        to: id,
        attributes: BTreeMap::new(),
    });
}

fn parse_image_ref(s: &str) -> (String, Option<String>, bool) {
    if let Some(idx) = s.find("@sha256:") {
        let (repo, tag) = split_repo_tag(&s[..idx]);
        (repo, tag, true)
    } else {
        let (repo, tag) = split_repo_tag(s);
        (repo, tag, false)
    }
}

fn split_repo_tag(s: &str) -> (String, Option<String>) {
    let last = s.rfind('/').map(|i| i + 1).unwrap_or(0);
    if let Some(rel) = s[last..].find(':') {
        let c = last + rel;
        (s[..c].to_string(), Some(s[c + 1..].to_string()))
    } else {
        (s.to_string(), None)
    }
}

fn classify_user(args: &str) -> String {
    let u = args.split_whitespace().next().unwrap_or("");
    let uid = u.split(':').next().unwrap_or(u);
    if uid == "root" || uid == "0" {
        "root".into()
    } else if uid.is_empty() {
        "unknown".into()
    } else {
        "nonroot".into()
    }
}

fn add_has_remote_src(args: &str) -> bool {
    args.split_whitespace()
        .any(|t| t.starts_with("http://") || t.starts_with("https://"))
}

fn is_curl_pipe(args: &str) -> bool {
    let lower = args.to_lowercase();
    (lower.contains("curl") || lower.contains("wget"))
        && lower.contains('|')
        && (lower.contains("sh") || lower.contains("bash"))
}

fn mentions_sudo(args: &str) -> bool {
    args.split(|c: char| c.is_whitespace() || c == '&' || c == ';')
        .any(|t| t == "sudo")
}

/// `chmod 777` / `chmod -R 0777` / `chmod a+rwx` — makes files world-writable,
/// so any user (or a compromised process) in the container can tamper with them.
fn is_world_writable(args: &str) -> bool {
    let lower = args.to_lowercase();
    if !lower.contains("chmod") {
        return false;
    }
    // numeric mode whose "other" digit grants write (2,3,6,7), e.g. 777/666/0777,
    // or a symbolic mode that adds write-for-all/other (a+w, o+w, +w).
    lower.split(|c: char| c.is_whitespace()).any(|t| {
        let t = t.trim_start_matches('-');
        (t.len() == 3 || t.len() == 4)
            && t.bytes().all(|b| b.is_ascii_digit())
            && matches!(t.bytes().last(), Some(b'2' | b'3' | b'6' | b'7'))
    }) || lower.contains("a+w") || lower.contains("o+w") || lower.contains("+rwx")
}

/// `curl -k` / `curl --insecure` / `wget --no-check-certificate` — disables TLS
/// certificate verification, opening the download to man-in-the-middle tampering.
fn disables_tls_verification(args: &str) -> bool {
    let lower = args.to_lowercase();
    let fetches = lower.contains("curl") || lower.contains("wget");
    if !fetches {
        return false;
    }
    lower.contains("--insecure")
        || lower.contains("--no-check-certificate")
        || lower.split(|c: char| c.is_whitespace()).any(|t| t == "-k")
}

/// If an ENV/ARG sets a secret-like name to an inline literal, return the name.
fn secret_inline_name(args: &str) -> Option<String> {
    // ENV KEY=VALUE or ENV KEY VALUE
    let (name, value) = if let Some((k, v)) = args.split_once('=') {
        (k.trim().to_string(), v.trim().to_string())
    } else {
        let mut it = args.split_whitespace();
        let k = it.next()?.to_string();
        let v = it.collect::<Vec<_>>().join(" ");
        (k, v)
    };
    if value.is_empty() || value.starts_with('$') {
        return None;
    }
    let norm: String = name.to_uppercase().chars().filter(|c| *c != '_').collect();
    if name.to_uppercase().ends_with("_FILE") {
        return None;
    }
    if SECRET_NAME_FRAGMENTS.iter().any(|f| norm.contains(f)) {
        Some(name)
    } else {
        None
    }
}

fn add_instruction(b: &mut Builder, stage_id: &str, n: &mut usize, instr: &str, flag: &str, detail: &str, line: u32) {
    *n += 1;
    let id = format!("instruction:{n}");
    let mut a = BTreeMap::new();
    a.insert("instruction".into(), AttrValue::Enum(instr.to_string()));
    a.insert("flag".into(), AttrValue::Enum(flag.to_string()));
    a.insert(
        "detail".into(),
        AttrValue::Str(detail.chars().take(120).collect()),
    );
    b.entities.push(Entity {
        id: id.clone(),
        kind: EntityKind::Instruction,
        attributes: a,
        provenance: Provenance::explicit(instr.to_string()).with_line(Some(line)),
    });
    b.relations.push(Relation {
        kind: RelationKind::Uses,
        from: stage_id.to_string(),
        to: id,
        attributes: BTreeMap::new(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_root_default_and_unpinned_base() {
        let df = "FROM nginx:latest\nRUN echo hi\n";
        let fm = parse(df);
        let stage = fm.entities.iter().find(|e| e.kind == EntityKind::Stage).unwrap();
        assert_eq!(stage.attr("runs_as").and_then(|v| v.as_str()), Some("unknown"));
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Image
            && e.attr("digest_pinned").and_then(|v| v.as_bool()) == Some(false)));
    }

    #[test]
    fn detects_curl_pipe_and_user() {
        let df = "FROM debian@sha256:aaaa\nUSER 1001\nRUN curl -sSL https://x.sh | bash\n";
        let fm = parse(df);
        let stage = fm.entities.iter().find(|e| e.kind == EntityKind::Stage).unwrap();
        assert_eq!(stage.attr("runs_as").and_then(|v| v.as_str()), Some("nonroot"));
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Instruction
            && e.attr("flag").and_then(|v| v.as_str()) == Some("curl_pipe")));
    }
}
