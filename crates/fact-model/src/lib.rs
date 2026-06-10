//! Sentinel fact model v0 — normalized, input-agnostic representation of an
//! architecture as a directed graph of typed entities and relations.
//!
//! Spec: `docs/adr/0002-fact-model-schema.md`.
//!
//! Includes canonical-JSON serialization + SHA-256 so `model_hash` is a pure
//! function of the input (ADR 0001 D5/D6, ADR 0003).
#![allow(dead_code)]

pub mod limits;

use std::collections::BTreeMap;

/// Top-level fact model. Contains no timestamps or random ids so its canonical
/// serialization is a pure function of the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactModel {
    pub schema_version: String,
    pub source: SourceDescriptor,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDescriptor {
    pub kind: String,         // e.g. "docker_compose"
    pub input_hash: String,   // "sha256:<hex>"
    pub parser_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    pub id: String,
    pub kind: EntityKind,
    pub attributes: BTreeMap<String, AttrValue>,
    pub provenance: Provenance,
}

impl Entity {
    pub fn attr(&self, key: &str) -> Option<&AttrValue> {
        self.attributes.get(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityKind {
    Service,
    Image,
    PortBinding,
    Mount,
    Network,
    EnvVar,
    Secret,
    Volume,
    Endpoint,
    Datastore,
    Capability,
    Host,
    /// A Dockerfile build stage (one per `FROM`).
    Stage,
    /// A notable Dockerfile instruction flagged for risk (RUN/ADD/COPY/...).
    Instruction,
    /// A Kubernetes workload controller (Deployment/Pod/StatefulSet/DaemonSet/Job/CronJob/...).
    Workload,
    /// A single container within a workload's pod template.
    Container,
    /// A Kubernetes RBAC Role or ClusterRole (a set of permission rules).
    Role,
    /// A Kubernetes RBAC RoleBinding or ClusterRoleBinding.
    RoleBinding,
    /// A Kubernetes ServiceAccount.
    ServiceAccount,
    /// A CI/CD workflow (e.g. a GitHub Actions workflow file).
    Workflow,
    /// A job within a workflow.
    Job,
    /// A single step within a job (a `uses:` action or a `run:` script).
    Step,
    /// An infrastructure-as-code resource (e.g. a Terraform `resource` block).
    Resource,
}

impl EntityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityKind::Service => "service",
            EntityKind::Image => "image",
            EntityKind::PortBinding => "port_binding",
            EntityKind::Mount => "mount",
            EntityKind::Network => "network",
            EntityKind::EnvVar => "env_var",
            EntityKind::Secret => "secret",
            EntityKind::Volume => "volume",
            EntityKind::Endpoint => "endpoint",
            EntityKind::Datastore => "datastore",
            EntityKind::Capability => "capability",
            EntityKind::Host => "host",
            EntityKind::Stage => "stage",
            EntityKind::Instruction => "instruction",
            EntityKind::Workload => "workload",
            EntityKind::Container => "container",
            EntityKind::Role => "role",
            EntityKind::RoleBinding => "role_binding",
            EntityKind::ServiceAccount => "service_account",
            EntityKind::Workflow => "workflow",
            EntityKind::Job => "job",
            EntityKind::Step => "step",
            EntityKind::Resource => "resource",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relation {
    pub kind: RelationKind,
    pub from: String,
    pub to: String,
    pub attributes: BTreeMap<String, AttrValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationKind {
    Uses,
    Exposes,
    Mounts,
    Reads,
    ConnectsTo,
    DependsOn,
    RunsOn,
    GrantsCapability,
    StoresData,
}

impl RelationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelationKind::Uses => "uses",
            RelationKind::Exposes => "exposes",
            RelationKind::Mounts => "mounts",
            RelationKind::Reads => "reads",
            RelationKind::ConnectsTo => "connects_to",
            RelationKind::DependsOn => "depends_on",
            RelationKind::RunsOn => "runs_on",
            RelationKind::GrantsCapability => "grants_capability",
            RelationKind::StoresData => "stores_data",
        }
    }
}

/// A typed attribute value. `Unknown` is load-bearing: it means the input did
/// not specify and there is no known default — rules must flag, never assume safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Enum(String),
    List(Vec<AttrValue>),
    Unknown,
}

impl AttrValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AttrValue::Str(s) | AttrValue::Enum(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            AttrValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            AttrValue::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn is_unknown(&self) -> bool {
        matches!(self, AttrValue::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    pub source_path: String,
    pub origin: Origin,
    /// 1-based source line the entity was declared on, when the parser can
    /// determine it. `None` = unknown. This is a UX/locator aid (surfaced in
    /// findings and exports) and is deliberately NOT part of the hashed
    /// canonical JSON, so reformatting a file never changes the report digest.
    pub line: Option<u32>,
}

impl Provenance {
    /// Provenance with an explicit (author-written) origin and no known line.
    pub fn explicit(source_path: impl Into<String>) -> Self {
        Self { source_path: source_path.into(), origin: Origin::Explicit, line: None }
    }

    /// Provenance with the given origin and no known line.
    pub fn new(source_path: impl Into<String>, origin: Origin) -> Self {
        Self { source_path: source_path.into(), origin, line: None }
    }

    /// Builder: attach a 1-based source line (no-op if `None`).
    pub fn with_line(mut self, line: Option<u32>) -> Self {
        self.line = line;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Explicit,
    Default,
    Inferred,
}

impl Origin {
    pub fn as_str(&self) -> &'static str {
        match self {
            Origin::Explicit => "explicit",
            Origin::Default => "default",
            Origin::Inferred => "inferred",
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical JSON + hashing (ADR 0002 canonicalization, ADR 0003 digests)
// ---------------------------------------------------------------------------

/// A minimal JSON value with a single canonical serialization: object keys are
/// emitted in sorted order, arrays as given (callers pre-sort), no insignificant
/// whitespace. This is the byte stream that gets hashed.
#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn to_canonical_string(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => out.push_str(&i.to_string()),
            Json::Str(s) => write_json_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            Json::Obj(pairs) => {
                let mut sorted = pairs.clone();
                sorted.sort_by(|a, b| a.0.cmp(&b.0));
                out.push('{');
                for (i, (k, v)) in sorted.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_json_string(k, out);
                    out.push(':');
                    v.write_canonical(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// SHA-256 of bytes, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// `"sha256:" + sha256_hex(bytes)`.
pub fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn attr_to_json(v: &AttrValue) -> Json {
    match v {
        AttrValue::Str(s) => Json::Obj(vec![
            ("type".into(), Json::Str("str".into())),
            ("value".into(), Json::Str(s.clone())),
        ]),
        AttrValue::Int(i) => Json::Obj(vec![
            ("type".into(), Json::Str("int".into())),
            ("value".into(), Json::Int(*i)),
        ]),
        AttrValue::Bool(b) => Json::Obj(vec![
            ("type".into(), Json::Str("bool".into())),
            ("value".into(), Json::Bool(*b)),
        ]),
        AttrValue::Enum(s) => Json::Obj(vec![
            ("type".into(), Json::Str("enum".into())),
            ("value".into(), Json::Str(s.clone())),
        ]),
        AttrValue::List(xs) => Json::Obj(vec![
            ("type".into(), Json::Str("list".into())),
            ("value".into(), Json::Arr(xs.iter().map(attr_to_json).collect())),
        ]),
        AttrValue::Unknown => Json::Obj(vec![("type".into(), Json::Str("unknown".into()))]),
    }
}

fn attrs_to_json(attrs: &BTreeMap<String, AttrValue>) -> Json {
    Json::Obj(
        attrs
            .iter()
            .map(|(k, v)| (k.clone(), attr_to_json(v)))
            .collect(),
    )
}

fn entity_to_json(e: &Entity) -> Json {
    Json::Obj(vec![
        ("id".into(), Json::Str(e.id.clone())),
        ("kind".into(), Json::Str(e.kind.as_str().into())),
        ("attributes".into(), attrs_to_json(&e.attributes)),
        (
            "provenance".into(),
            Json::Obj(vec![
                ("source_path".into(), Json::Str(e.provenance.source_path.clone())),
                ("origin".into(), Json::Str(e.provenance.origin.as_str().into())),
            ]),
        ),
    ])
}

fn relation_to_json(r: &Relation) -> Json {
    Json::Obj(vec![
        ("kind".into(), Json::Str(r.kind.as_str().into())),
        ("from".into(), Json::Str(r.from.clone())),
        ("to".into(), Json::Str(r.to.clone())),
        ("attributes".into(), attrs_to_json(&r.attributes)),
    ])
}

impl FactModel {
    /// Canonical JSON of the model with entities/relations in canonical order.
    pub fn to_canonical_json(&self) -> Json {
        let mut entities = self.entities.clone();
        entities.sort_by(|a, b| a.id.cmp(&b.id));
        let mut relations = self.relations.clone();
        relations.sort_by(|a, b| {
            a.kind
                .as_str()
                .cmp(b.kind.as_str())
                .then_with(|| a.from.cmp(&b.from))
                .then_with(|| a.to.cmp(&b.to))
        });

        Json::Obj(vec![
            ("schema_version".into(), Json::Str(self.schema_version.clone())),
            (
                "source".into(),
                Json::Obj(vec![
                    ("kind".into(), Json::Str(self.source.kind.clone())),
                    ("input_hash".into(), Json::Str(self.source.input_hash.clone())),
                    ("parser_version".into(), Json::Str(self.source.parser_version.clone())),
                ]),
            ),
            (
                "entities".into(),
                Json::Arr(entities.iter().map(entity_to_json).collect()),
            ),
            (
                "relations".into(),
                Json::Arr(relations.iter().map(relation_to_json).collect()),
            ),
        ])
    }

    /// `"sha256:" + sha256(canonical_json(self))`.
    pub fn model_hash(&self) -> String {
        sha256_prefixed(self.to_canonical_json().to_canonical_string().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn canonical_object_keys_are_sorted() {
        let j = Json::Obj(vec![
            ("b".into(), Json::Int(1)),
            ("a".into(), Json::Int(2)),
        ]);
        assert_eq!(j.to_canonical_string(), "{\"a\":2,\"b\":1}");
    }
}
