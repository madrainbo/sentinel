//! GitHub Actions workflows -> FactModel. Deterministic YAML, no LLM.
//!
//! Models the supply-chain / injection surface of a workflow:
//!   * Workflow — triggers (and whether any are attacker-influenced), top-level
//!     token permissions.
//!   * Job — runner (self-hosted?), job-level permissions, `secrets: inherit`.
//!   * Step — a `uses:` action (pinned by SHA or a mutable tag/branch; a
//!     checkout of an untrusted PR ref) or a `run:` script (untrusted
//!     `${{ github.event.* }}` expression interpolated into the shell).

use std::collections::BTreeMap;

use fact_model::{
    sha256_prefixed, AttrValue, Entity, EntityKind, FactModel, Provenance, Relation,
    RelationKind, SourceDescriptor,
};
use yaml_rust2::{Yaml, YamlLoader};

pub const PARSER_VERSION: &str = "0.1.0";

/// Workflow triggers that can be influenced by an outside contributor (fork PRs,
/// issue/comment text, etc.) — the entry point for injection / pwn-request.
pub const UNTRUSTED_TRIGGERS: &[&str] = &[
    "pull_request_target", "pull_request", "issue_comment", "issues", "workflow_run",
    "discussion", "discussion_comment", "fork", "watch", "pull_request_review",
    "pull_request_review_comment",
];

/// Triggers that run with a privileged (write) token AND repo secrets while
/// potentially handling untrusted input — the dangerous half of a pwn-request.
pub const PRIVILEGED_UNTRUSTED_TRIGGERS: &[&str] = &["pull_request_target", "workflow_run"];

/// `${{ github.event.* }}` (and friends) sub-expressions an attacker controls.
/// If one of these is interpolated into a `run:` shell, it is command injection.
pub const INJECTION_CONTEXTS: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.head_commit.message",
    "github.event.commits",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
];

struct Builder {
    entities: Vec<Entity>,
    relations: Vec<Relation>,
    /// node-path -> 1-based source line (for finding line references).
    lines: BTreeMap<String, u32>,
}
impl Builder {
    fn entity(&mut self, e: Entity) {
        self.entities.push(e);
    }
    /// Source line for a node path (e.g. `jobs.build.steps[0]`), if known.
    fn line(&self, path: &str) -> Option<u32> {
        self.lines.get(path).copied()
    }
    fn relation(&mut self, kind: RelationKind, from: &str, to: &str) {
        self.relations.push(Relation {
            kind,
            from: from.to_string(),
            to: to.to_string(),
            attributes: BTreeMap::new(),
        });
    }
}

/// Parse a GitHub Actions workflow into the fact model, returning an empty model
/// on invalid YAML. Prefer [`try_parse`] when you need to surface parse errors —
/// silently yielding zero findings on an unparseable workflow is a fail-open.
pub fn parse(input: &str) -> FactModel {
    try_parse(input).unwrap_or_else(|_| FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "github_actions".to_string(),
            input_hash: sha256_prefixed(input.as_bytes()),
            parser_version: PARSER_VERSION.to_string(),
        },
        entities: Vec::new(),
        relations: Vec::new(),
    })
}

/// Parse a GitHub Actions workflow, returning a human-readable error on invalid
/// YAML. A valid document with no `jobs:` yields an empty (but Ok) model.
pub fn try_parse(input: &str) -> Result<FactModel, String> {
    // Reject oversized / alias-bomb input before the YAML loader materializes it.
    fact_model::limits::check_input_size(input)?;
    fact_model::limits::check_yaml_aliases(input)?;
    let input_hash = sha256_prefixed(input.as_bytes());
    let mut b = Builder {
        entities: Vec::new(),
        relations: Vec::new(),
        lines: yaml_loc::line_index(input),
    };

    let docs = YamlLoader::load_from_str(input).map_err(|e| format!("invalid YAML: {e}"))?;
    if let Some(doc) = docs.first() {
        parse_workflow(&mut b, doc);
    }

    Ok(FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "github_actions".to_string(),
            input_hash,
            parser_version: PARSER_VERSION.to_string(),
        },
        entities: b.entities,
        relations: b.relations,
    })
}

fn parse_workflow(b: &mut Builder, doc: &Yaml) {
    let name = doc["name"].as_str().unwrap_or("workflow");
    let wf_id = "workflow:main".to_string();

    let triggers = trigger_names(doc);
    let untrusted = triggers.iter().any(|t| UNTRUSTED_TRIGGERS.contains(&t.as_str()));
    let pr_target = triggers
        .iter()
        .any(|t| PRIVILEGED_UNTRUSTED_TRIGGERS.contains(&t.as_str()));

    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(name.to_string()));
    a.insert("untrusted_trigger".into(), AttrValue::Bool(untrusted));
    a.insert("pr_target_trigger".into(), AttrValue::Bool(pr_target));
    a.insert(
        "permissions_write_all".into(),
        AttrValue::Bool(permissions_write_all(&doc["permissions"])),
    );
    a.insert(
        "triggers".into(),
        AttrValue::List(triggers.iter().map(|t| AttrValue::Str(t.clone())).collect()),
    );
    let wf_line = b.line("on").or_else(|| b.line("name")).or_else(|| b.line("jobs"));
    b.entity(Entity {
        id: wf_id.clone(),
        kind: EntityKind::Workflow,
        attributes: a,
        provenance: Provenance::explicit("on").with_line(wf_line),
    });

    if let Some(jobs) = doc["jobs"].as_hash() {
        for (jid, job) in jobs {
            if let Some(jid) = jid.as_str() {
                parse_job(b, &wf_id, jid, job);
            }
        }
    }
}

fn parse_job(b: &mut Builder, wf_id: &str, jid: &str, job: &Yaml) {
    let job_id = format!("job:{jid}");
    let runs_on = runs_on_string(&job["runs-on"]);
    let self_hosted = runs_on.to_lowercase().contains("self-hosted");
    let secrets_inherit = job["secrets"].as_str() == Some("inherit");

    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(jid.to_string()));
    a.insert("runs_on".into(), AttrValue::Str(runs_on));
    a.insert("self_hosted".into(), AttrValue::Bool(self_hosted));
    a.insert("secrets_inherit".into(), AttrValue::Bool(secrets_inherit));
    a.insert(
        "permissions_write_all".into(),
        AttrValue::Bool(permissions_write_all(&job["permissions"])),
    );
    let job_path = format!("jobs.{jid}");
    let job_line = b.line(&job_path);
    b.entity(Entity {
        id: job_id.clone(),
        kind: EntityKind::Job,
        attributes: a,
        provenance: Provenance::explicit(job_path).with_line(job_line),
    });
    b.relation(RelationKind::Uses, wf_id, &job_id);

    if let Some(steps) = job["steps"].as_vec() {
        for (i, step) in steps.iter().enumerate() {
            parse_step(b, &job_id, jid, i, step);
        }
    }
}

fn parse_step(b: &mut Builder, job_id: &str, jid: &str, idx: usize, step: &Yaml) {
    let step_id = format!("step:{jid}#{idx}");
    let name = step["name"].as_str().unwrap_or("");
    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(name.to_string()));

    if let Some(uses) = step["uses"].as_str() {
        let (action, reference) = split_uses(uses);
        let is_local = uses.starts_with("./") || uses.starts_with("../");
        let is_docker = uses.starts_with("docker://");
        let pinned = is_sha(&reference);
        let checkout_untrusted = action == "actions/checkout"
            && refers_to_untrusted_ref(step["with"]["ref"].as_str().unwrap_or(""));

        a.insert("step_type".into(), AttrValue::Enum("uses".into()));
        a.insert("action".into(), AttrValue::Str(action));
        a.insert("ref".into(), AttrValue::Str(reference));
        a.insert("pinned".into(), AttrValue::Bool(pinned));
        a.insert("is_local".into(), AttrValue::Bool(is_local || is_docker));
        a.insert("checkout_untrusted".into(), AttrValue::Bool(checkout_untrusted));
        a.insert("injection".into(), AttrValue::Bool(false));
    } else if let Some(run) = step["run"].as_str() {
        let ctx = injection_context(run);
        a.insert("step_type".into(), AttrValue::Enum("run".into()));
        a.insert("injection".into(), AttrValue::Bool(ctx.is_some()));
        if let Some(c) = ctx {
            a.insert("injection_context".into(), AttrValue::Str(c));
        }
        a.insert("checkout_untrusted".into(), AttrValue::Bool(false));
    } else {
        a.insert("step_type".into(), AttrValue::Enum("other".into()));
        a.insert("injection".into(), AttrValue::Bool(false));
        a.insert("checkout_untrusted".into(), AttrValue::Bool(false));
    }

    let step_path = format!("jobs.{jid}.steps[{idx}]");
    let step_line = b.line(&step_path);
    b.entity(Entity {
        id: step_id.clone(),
        kind: EntityKind::Step,
        attributes: a,
        provenance: Provenance::explicit(step_path).with_line(step_line),
    });
    b.relation(RelationKind::Uses, job_id, &step_id);
}

// --- helpers --------------------------------------------------------------

/// The list of trigger event names, handling `on:` as a string, a list, or a
/// mapping — and the YAML 1.1 quirk where `on` may parse as the boolean key true.
fn trigger_names(doc: &Yaml) -> Vec<String> {
    let node = on_node(doc);
    match node {
        Some(Yaml::String(s)) => vec![s.clone()],
        Some(Yaml::Array(xs)) => xs.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect(),
        Some(Yaml::Hash(h)) => h
            .keys()
            .filter_map(|k| k.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

fn on_node(doc: &Yaml) -> Option<&Yaml> {
    if let Some(h) = doc.as_hash() {
        for (k, v) in h {
            match k {
                Yaml::String(s) if s == "on" => return Some(v),
                Yaml::Boolean(true) => return Some(v),
                _ => {}
            }
        }
    }
    None
}

/// `permissions: write-all` (string form) — the broadest token grant.
fn permissions_write_all(node: &Yaml) -> bool {
    node.as_str() == Some("write-all")
}

fn runs_on_string(node: &Yaml) -> String {
    match node {
        Yaml::String(s) => s.clone(),
        Yaml::Array(xs) => xs
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(","),
        _ => String::new(),
    }
}

/// Split `owner/repo/path@ref` into (owner/repo, ref).
fn split_uses(uses: &str) -> (String, String) {
    let (path, reference) = match uses.split_once('@') {
        Some((p, r)) => (p, r.to_string()),
        None => (uses, String::new()),
    };
    // action identity is owner/repo (first two path segments).
    let parts: Vec<&str> = path.splitn(3, '/').collect();
    let action = if parts.len() >= 2 {
        format!("{}/{}", parts[0], parts[1])
    } else {
        path.to_string()
    };
    (action, reference)
}

/// A full 40-char hex commit SHA (the only safe way to pin an action).
fn is_sha(reference: &str) -> bool {
    reference.len() == 40 && reference.bytes().all(|b| b.is_ascii_hexdigit())
}

fn refers_to_untrusted_ref(ref_value: &str) -> bool {
    let v = ref_value.replace(' ', "");
    v.contains("pull_request.head") || v.contains("github.head_ref")
}

/// If a `run:` script interpolates an attacker-controlled context inside a
/// `${{ ... }}` block, return the offending context string.
fn injection_context(run: &str) -> Option<String> {
    let bytes = run.as_bytes();
    let mut i = 0;
    while let Some(start) = find_from(bytes, b"${{", i) {
        let after = start + 3;
        if let Some(end) = find_from(bytes, b"}}", after) {
            let expr = &run[after..end];
            for ctx in INJECTION_CONTEXTS {
                if expr.contains(ctx) {
                    return Some((*ctx).to_string());
                }
            }
            i = end + 2;
        } else {
            break;
        }
    }
    None
}

fn find_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism() {
        let y = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";
        assert_eq!(parse(y).model_hash(), parse(y).model_hash());
    }

    #[test]
    fn detects_pwn_request_facts() {
        let y = "on:\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n";
        let fm = parse(y);
        let wf = fm.entities.iter().find(|e| e.kind == EntityKind::Workflow).unwrap();
        assert_eq!(wf.attr("pr_target_trigger").and_then(|v| v.as_bool()), Some(true));
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Step
            && e.attr("checkout_untrusted").and_then(|v| v.as_bool()) == Some(true)));
    }

    #[test]
    fn invalid_yaml_is_an_error() {
        // Unterminated flow sequence -> the YAML loader must reject it rather than
        // fail open to an empty (zero-findings) model.
        assert!(try_parse("on: [push").is_err());
    }

    #[test]
    fn detects_script_injection() {
        let y = "on: issues\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n";
        let fm = parse(y);
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Step
            && e.attr("injection").and_then(|v| v.as_bool()) == Some(true)));
    }
}
