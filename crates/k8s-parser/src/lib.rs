//! Kubernetes manifests -> FactModel. Deterministic, multi-document YAML, no LLM.
//!
//! Models the security-relevant surface of K8s objects as a graph:
//!   * Workload  (Deployment/Pod/StatefulSet/DaemonSet/Job/CronJob/...) — pod-level
//!     namespace settings (hostNetwork/PID/IPC, service account, automount).
//!   * Container — per-container securityContext (privileged, allowPrivilegeEscalation,
//!     readOnlyRootFilesystem, runAsNonRoot/runAsUser, capabilities, seccomp).
//!   * Image — pinned-by-digest or not.
//!   * Mount — hostPath volumes (host filesystem exposed to the pod).
//!   * Service — type (ClusterIP/NodePort/LoadBalancer) + selector; an external
//!     Service that selects a Workload becomes a `ConnectsTo` edge (the reachability
//!     spine the attack-path rules walk).
//!   * Role / RoleBinding / ServiceAccount — RBAC permission surface.
//!   * Secret — secret material embedded in a manifest.

use std::collections::{BTreeMap, HashSet};

use fact_model::{
    sha256_prefixed, AttrValue, Entity, EntityKind, FactModel, Provenance, Relation,
    RelationKind, SourceDescriptor,
};
use yaml_rust2::{Yaml, YamlLoader};

pub const PARSER_VERSION: &str = "0.1.0";

/// Linux capabilities considered dangerous when added to a container.
pub const DANGEROUS_CAPS: &[&str] = &[
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE",
    "SYS_RAWIO", "BPF", "SYS_BOOT", "SYS_TIME", "MAC_ADMIN", "MAC_OVERRIDE", "AUDIT_CONTROL",
    "LINUX_IMMUTABLE", "NET_RAW",
];

/// Host paths that are dangerous to expose via a hostPath volume.
pub const SENSITIVE_HOST_PATHS: &[&str] = &[
    "/", "/etc", "/root", "/proc", "/sys", "/boot", "/dev", "/var/run", "/var/lib/docker",
    "/usr", "/bin", "/sbin", "/lib", "/var/run/docker.sock",
];

struct Builder {
    entities: Vec<Entity>,
    relations: Vec<Relation>,
    seen_entities: HashSet<String>,
}

impl Builder {
    fn entity(&mut self, e: Entity) {
        if self.seen_entities.insert(e.id.clone()) {
            self.entities.push(e);
        }
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

/// Collected service/workload label data used for a post-pass selector match.
struct ServiceInfo {
    id: String,
    namespace: String,
    selector: Vec<(String, String)>,
}
struct WorkloadInfo {
    id: String,
    namespace: String,
    labels: Vec<(String, String)>,
}

/// Parse Kubernetes manifests into the fact model, returning an empty model on
/// invalid YAML. Prefer [`try_parse`] when you need to surface parse errors —
/// silently yielding zero findings on an unparseable manifest is a fail-open.
pub fn parse(input: &str) -> FactModel {
    try_parse(input).unwrap_or_else(|_| FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "kubernetes".to_string(),
            input_hash: sha256_prefixed(input.as_bytes()),
            parser_version: PARSER_VERSION.to_string(),
        },
        entities: Vec::new(),
        relations: Vec::new(),
    })
}

/// Parse Kubernetes manifests, returning a human-readable error on invalid YAML.
/// A valid manifest with no recognised objects yields an empty (but Ok) model.
pub fn try_parse(input: &str) -> Result<FactModel, String> {
    // Reject oversized / alias-bomb input before the YAML loader materializes it.
    fact_model::limits::check_input_size(input)?;
    fact_model::limits::check_yaml_aliases(input)?;
    let input_hash = sha256_prefixed(input.as_bytes());
    let mut b = Builder {
        entities: Vec::new(),
        relations: Vec::new(),
        seen_entities: HashSet::new(),
    };
    let mut services: Vec<ServiceInfo> = Vec::new();
    let mut workloads: Vec<WorkloadInfo> = Vec::new();

    let docs = YamlLoader::load_from_str(input).map_err(|e| format!("invalid YAML: {e}"))?;
    // Per-document source lines (K8s manifests are commonly multi-doc). Both this
    // and YamlLoader consume the same document boundaries, so index i aligns.
    let lines = yaml_loc::line_index_per_doc(input);
    for (i, doc) in docs.iter().enumerate() {
        let lm = lines.get(i);
        // A manifest may be a List object containing `items`. List items share the
        // document's map under `items[n].*` paths we don't compute, so we fall back
        // to no precise line for them.
        if let Some(items) = doc["items"].as_vec() {
            for item in items {
                parse_doc(&mut b, item, None, &mut services, &mut workloads);
            }
        } else {
            parse_doc(&mut b, doc, lm, &mut services, &mut workloads);
        }
    }

    // Post-pass: connect each external/internal Service to the Workloads it selects
    // (same namespace, selector is a subset of the pod labels). This is the
    // reachability spine the K8s attack-path rule walks.
    for s in &services {
        if s.selector.is_empty() {
            continue;
        }
        for w in &workloads {
            if w.namespace == s.namespace
                && s.selector.iter().all(|kv| w.labels.contains(kv))
            {
                b.relation(RelationKind::ConnectsTo, &s.id, &w.id);
            }
        }
    }

    Ok(FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "kubernetes".to_string(),
            input_hash,
            parser_version: PARSER_VERSION.to_string(),
        },
        entities: b.entities,
        relations: b.relations,
    })
}

/// A document's path→line map (see `yaml_loc::line_index_per_doc`).
type LineMap = BTreeMap<String, u32>;

/// 1-based line of an object's declaration — the anchor for every finding on it.
/// Prefers `metadata.name`, falling back to `metadata` then `kind`.
fn obj_line(lm: Option<&LineMap>) -> Option<u32> {
    let lm = lm?;
    lm.get("metadata.name")
        .or_else(|| lm.get("metadata"))
        .or_else(|| lm.get("kind"))
        .copied()
}

/// 1-based line of a specific structural path, if known.
fn path_line(lm: Option<&LineMap>, path: &str) -> Option<u32> {
    lm?.get(path).copied()
}

/// Structural YAML path prefix to the pod `spec` for a workload kind.
fn spec_path(kind: &str) -> &'static str {
    match kind {
        "Pod" => "spec",
        "CronJob" => "spec.jobTemplate.spec.template.spec",
        _ => "spec.template.spec",
    }
}

fn parse_doc(
    b: &mut Builder,
    doc: &Yaml,
    lm: Option<&LineMap>,
    services: &mut Vec<ServiceInfo>,
    workloads: &mut Vec<WorkloadInfo>,
) {
    let kind = match doc["kind"].as_str() {
        Some(k) => k,
        None => return,
    };
    let name = doc["metadata"]["name"].as_str().unwrap_or("unnamed");
    let namespace = doc["metadata"]["namespace"].as_str().unwrap_or("default");

    match kind {
        "Pod" | "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet"
        | "ReplicationController" | "Job" | "CronJob" => {
            parse_workload(b, doc, lm, kind, name, namespace, workloads);
        }
        "Service" => parse_service(b, doc, lm, name, namespace, services),
        "Role" | "ClusterRole" => parse_role(b, doc, lm, kind, name, namespace),
        "RoleBinding" | "ClusterRoleBinding" => {
            parse_role_binding(b, doc, lm, kind, name, namespace)
        }
        "ServiceAccount" => parse_service_account(b, doc, lm, name, namespace),
        "Secret" => parse_secret(b, doc, lm, name, namespace),
        _ => {}
    }
}

/// Resolve the pod template's `spec` for any workload kind.
fn pod_spec<'a>(doc: &'a Yaml, kind: &str) -> &'a Yaml {
    match kind {
        "Pod" => &doc["spec"],
        "CronJob" => &doc["spec"]["jobTemplate"]["spec"]["template"]["spec"],
        _ => &doc["spec"]["template"]["spec"],
    }
}

/// Pod-template label set (for Service selector matching).
fn pod_labels(doc: &Yaml, kind: &str) -> Vec<(String, String)> {
    let labels = match kind {
        "Pod" => &doc["metadata"]["labels"],
        "CronJob" => &doc["spec"]["jobTemplate"]["spec"]["template"]["metadata"]["labels"],
        _ => &doc["spec"]["template"]["metadata"]["labels"],
    };
    hash_to_pairs(labels)
}

#[allow(clippy::too_many_arguments)]
fn parse_workload(
    b: &mut Builder,
    doc: &Yaml,
    lm: Option<&LineMap>,
    kind: &str,
    name: &str,
    namespace: &str,
    workloads: &mut Vec<WorkloadInfo>,
) {
    let spec = pod_spec(doc, kind);
    let sp = spec_path(kind);
    let wl_id = format!("workload:{namespace}/{name}");

    let host_network = yaml_bool(&spec["hostNetwork"]).unwrap_or(false);
    let host_pid = yaml_bool(&spec["hostPID"]).unwrap_or(false);
    let host_ipc = yaml_bool(&spec["hostIPC"]).unwrap_or(false);
    // automountServiceAccountToken: unset defaults to true (token IS mounted).
    let automount = yaml_bool(&spec["automountServiceAccountToken"]);
    let sa = spec["serviceAccountName"]
        .as_str()
        .or_else(|| spec["serviceAccount"].as_str())
        .unwrap_or("default");

    let mut a = BTreeMap::new();
    a.insert("kind".into(), AttrValue::Enum(kind.to_string()));
    a.insert("name".into(), AttrValue::Str(name.to_string()));
    a.insert("namespace".into(), AttrValue::Str(namespace.to_string()));
    a.insert("host_network".into(), AttrValue::Bool(host_network));
    a.insert("host_pid".into(), AttrValue::Bool(host_pid));
    a.insert("host_ipc".into(), AttrValue::Bool(host_ipc));
    a.insert("service_account".into(), AttrValue::Str(sa.to_string()));
    a.insert(
        "automount_sa_token".into(),
        match automount {
            Some(v) => AttrValue::Bool(v),
            None => AttrValue::Unknown, // defaults to true
        },
    );
    let wl_line = obj_line(lm);
    b.entity(Entity {
        id: wl_id.clone(),
        kind: EntityKind::Workload,
        attributes: a,
        provenance: Provenance::explicit(format!("{kind}/{name}")).with_line(wl_line),
    });

    // hostPath volumes -> Mount entities.
    if let Some(vols) = spec["volumes"].as_vec() {
        for (j, v) in vols.iter().enumerate() {
            if let Some(path) = v["hostPath"]["path"].as_str() {
                let vname = v["name"].as_str().unwrap_or("vol");
                let mid = format!("mount:{namespace}/{name}/{vname}");
                let mut ma = BTreeMap::new();
                ma.insert("source".into(), AttrValue::Str(path.to_string()));
                ma.insert("host_path".into(), AttrValue::Bool(true));
                let vol_line = path_line(lm, &format!("{sp}.volumes[{j}]")).or(wl_line);
                b.entity(Entity {
                    id: mid.clone(),
                    kind: EntityKind::Mount,
                    attributes: ma,
                    provenance: Provenance::explicit(format!("{kind}/{name}.volumes.{vname}"))
                        .with_line(vol_line),
                });
                b.relation(RelationKind::Mounts, &wl_id, &mid);
            }
        }
    }

    // Pod-level security context (defaults inherited by containers).
    let pod_sc = &spec["securityContext"];
    let pod_run_as_non_root = yaml_bool(&pod_sc["runAsNonRoot"]);
    let pod_run_as_user = pod_sc["runAsUser"].as_i64();
    let pod_seccomp = pod_sc["seccompProfile"]["type"].as_str();

    // Containers (regular + init + ephemeral all share the threat surface).
    for group in ["containers", "initContainers", "ephemeralContainers"] {
        if let Some(cs) = spec[group].as_vec() {
            for (i, c) in cs.iter().enumerate() {
                let c_line = path_line(lm, &format!("{sp}.{group}[{i}]")).or(wl_line);
                parse_container(
                    b, c, c_line, &wl_id, namespace, name, pod_run_as_non_root,
                    pod_run_as_user, pod_seccomp,
                );
            }
        }
    }

    workloads.push(WorkloadInfo {
        id: wl_id,
        namespace: namespace.to_string(),
        labels: pod_labels(doc, kind),
    });
}

#[allow(clippy::too_many_arguments)]
fn parse_container(
    b: &mut Builder,
    c: &Yaml,
    line: Option<u32>,
    wl_id: &str,
    namespace: &str,
    wl_name: &str,
    pod_run_as_non_root: Option<bool>,
    pod_run_as_user: Option<i64>,
    pod_seccomp: Option<&str>,
) {
    let cname = c["name"].as_str().unwrap_or("container");
    let cid = format!("container:{namespace}/{wl_name}/{cname}");
    let sc = &c["securityContext"];

    let privileged = yaml_bool(&sc["privileged"]).unwrap_or(false);
    let read_only_root = yaml_bool(&sc["readOnlyRootFilesystem"]);
    let allow_priv_esc = yaml_bool(&sc["allowPrivilegeEscalation"]);
    // Effective: container overrides pod.
    let run_as_non_root = yaml_bool(&sc["runAsNonRoot"]).or(pod_run_as_non_root);
    let run_as_user = sc["runAsUser"].as_i64().or(pod_run_as_user);
    let seccomp = sc["seccompProfile"]["type"]
        .as_str()
        .or(pod_seccomp)
        .map(|s| s.to_string());

    // "Provably non-root" only if runAsNonRoot==true or runAsUser>0.
    let provably_non_root = run_as_non_root == Some(true) || run_as_user.map(|u| u > 0) == Some(true);

    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(cname.to_string()));
    a.insert("privileged".into(), AttrValue::Bool(privileged));
    a.insert("provably_non_root".into(), AttrValue::Bool(provably_non_root));
    a.insert(
        "read_only_root_fs".into(),
        bool_or_unknown(read_only_root),
    );
    a.insert(
        "allow_privilege_escalation".into(),
        bool_or_unknown(allow_priv_esc),
    );
    a.insert(
        "seccomp".into(),
        match &seccomp {
            Some(s) => AttrValue::Enum(s.clone()),
            None => AttrValue::Unknown,
        },
    );
    b.entity(Entity {
        id: cid.clone(),
        kind: EntityKind::Container,
        attributes: a,
        provenance: Provenance::explicit(format!("{wl_name}.containers.{cname}")).with_line(line),
    });
    b.relation(RelationKind::Uses, wl_id, &cid);

    // Image.
    if let Some(img) = c["image"].as_str() {
        let (repo, tag, pinned) = parse_image_ref(img);
        let iid = format!("image:{img}");
        let mut ia = BTreeMap::new();
        ia.insert("repo".into(), AttrValue::Str(repo));
        ia.insert("tag".into(), AttrValue::Str(tag));
        ia.insert("digest_pinned".into(), AttrValue::Bool(pinned));
        b.entity(Entity {
            id: iid.clone(),
            kind: EntityKind::Image,
            attributes: ia,
            provenance: Provenance::explicit(format!("{cname}.image")).with_line(line),
        });
        b.relation(RelationKind::Uses, &cid, &iid);
    }

    // Added capabilities.
    if let Some(adds) = sc["capabilities"]["add"].as_vec() {
        for cap in adds {
            if let Some(cap) = cap.as_str() {
                let capn = cap.trim_start_matches("CAP_").to_uppercase();
                let capid = format!("capability:{namespace}/{wl_name}/{cname}/{capn}");
                let mut ca = BTreeMap::new();
                ca.insert("cap".into(), AttrValue::Str(capn.clone()));
                b.entity(Entity {
                    id: capid.clone(),
                    kind: EntityKind::Capability,
                    attributes: ca,
                    provenance: Provenance::explicit(format!("{cname}.securityContext.capabilities.add"))
                        .with_line(line),
                });
                b.relation(RelationKind::GrantsCapability, &cid, &capid);
            }
        }
    }
}

fn parse_service(
    b: &mut Builder,
    doc: &Yaml,
    lm: Option<&LineMap>,
    name: &str,
    namespace: &str,
    services: &mut Vec<ServiceInfo>,
) {
    let spec = &doc["spec"];
    let svc_type = spec["type"].as_str().unwrap_or("ClusterIP");
    let external = matches!(svc_type, "NodePort" | "LoadBalancer");
    let sid = format!("service:{namespace}/{name}");
    let svc_line = obj_line(lm);

    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(name.to_string()));
    a.insert("namespace".into(), AttrValue::Str(namespace.to_string()));
    a.insert("service_type".into(), AttrValue::Enum(svc_type.to_string()));
    a.insert("external".into(), AttrValue::Bool(external));
    b.entity(Entity {
        id: sid.clone(),
        kind: EntityKind::Service,
        attributes: a,
        provenance: Provenance::explicit(format!("Service/{name}")).with_line(svc_line),
    });

    if let Some(ports) = spec["ports"].as_vec() {
        for (i, p) in ports.iter().enumerate() {
            if let Some(port) = p["port"].as_i64() {
                let pid = format!("port:{namespace}/{name}/{port}");
                let mut pa = BTreeMap::new();
                pa.insert("target".into(), AttrValue::Int(port));
                if let Some(np) = p["nodePort"].as_i64() {
                    pa.insert("node_port".into(), AttrValue::Int(np));
                }
                pa.insert("external".into(), AttrValue::Bool(external));
                let port_line = path_line(lm, &format!("spec.ports[{i}]")).or(svc_line);
                b.entity(Entity {
                    id: pid.clone(),
                    kind: EntityKind::PortBinding,
                    attributes: pa,
                    provenance: Provenance::explicit(format!("Service/{name}.ports"))
                        .with_line(port_line),
                });
                b.relation(RelationKind::Exposes, &sid, &pid);
            }
        }
    }

    services.push(ServiceInfo {
        id: sid,
        namespace: namespace.to_string(),
        selector: hash_to_pairs(&spec["selector"]),
    });
}

fn parse_role(b: &mut Builder, doc: &Yaml, lm: Option<&LineMap>, kind: &str, name: &str, namespace: &str) {
    let cluster = kind == "ClusterRole";
    let scope_key = if cluster { "cluster" } else { namespace };
    let rid = format!("role:{scope_key}/{name}");

    let mut wildcard_all = false;
    let mut grants_secrets = false;
    if let Some(rules) = doc["rules"].as_vec() {
        for r in rules {
            let verbs = str_list(&r["verbs"]);
            let resources = str_list(&r["resources"]);
            let verb_all = verbs.iter().any(|v| v == "*");
            let res_all = resources.iter().any(|r| r == "*");
            if verb_all && res_all {
                wildcard_all = true;
            }
            let reads = verb_all
                || verbs.iter().any(|v| matches!(v.as_str(), "get" | "list" | "watch"));
            if reads && (res_all || resources.iter().any(|r| r == "secrets")) {
                grants_secrets = true;
            }
        }
    }

    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(name.to_string()));
    a.insert("scope".into(), AttrValue::Enum(kind.to_string()));
    a.insert("cluster_scope".into(), AttrValue::Bool(cluster));
    a.insert("wildcard_all".into(), AttrValue::Bool(wildcard_all));
    a.insert("grants_secret_read".into(), AttrValue::Bool(grants_secrets));
    b.entity(Entity {
        id: rid,
        kind: EntityKind::Role,
        attributes: a,
        provenance: Provenance::explicit(format!("{kind}/{name}")).with_line(obj_line(lm)),
    });
}

fn parse_role_binding(b: &mut Builder, doc: &Yaml, lm: Option<&LineMap>, kind: &str, name: &str, namespace: &str) {
    let cluster = kind == "ClusterRoleBinding";
    let scope_key = if cluster { "cluster" } else { namespace };
    let bid = format!("rolebinding:{scope_key}/{name}");
    let role_ref = doc["roleRef"]["name"].as_str().unwrap_or("");
    let role_ref_kind = doc["roleRef"]["kind"].as_str().unwrap_or("");

    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(name.to_string()));
    a.insert("cluster_scope".into(), AttrValue::Bool(cluster));
    a.insert("role_ref".into(), AttrValue::Str(role_ref.to_string()));
    a.insert("role_ref_kind".into(), AttrValue::Str(role_ref_kind.to_string()));
    // cluster-admin is the built-in superuser role.
    a.insert(
        "binds_cluster_admin".into(),
        AttrValue::Bool(role_ref == "cluster-admin"),
    );
    b.entity(Entity {
        id: bid,
        kind: EntityKind::RoleBinding,
        attributes: a,
        provenance: Provenance::explicit(format!("{kind}/{name}")).with_line(obj_line(lm)),
    });
}

fn parse_service_account(b: &mut Builder, doc: &Yaml, lm: Option<&LineMap>, name: &str, namespace: &str) {
    let automount = yaml_bool(&doc["automountServiceAccountToken"]);
    let said = format!("serviceaccount:{namespace}/{name}");
    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(name.to_string()));
    a.insert("namespace".into(), AttrValue::Str(namespace.to_string()));
    a.insert("automount_sa_token".into(), bool_or_unknown(automount));
    b.entity(Entity {
        id: said,
        kind: EntityKind::ServiceAccount,
        attributes: a,
        provenance: Provenance::explicit(format!("ServiceAccount/{name}")).with_line(obj_line(lm)),
    });
}

fn parse_secret(b: &mut Builder, doc: &Yaml, lm: Option<&LineMap>, name: &str, namespace: &str) {
    let secret_type = doc["type"].as_str().unwrap_or("Opaque");
    let has_inline = doc["data"].as_hash().map(|h| !h.is_empty()).unwrap_or(false)
        || doc["stringData"].as_hash().map(|h| !h.is_empty()).unwrap_or(false);
    let sid = format!("secret:{namespace}/{name}");
    let mut a = BTreeMap::new();
    a.insert("name".into(), AttrValue::Str(name.to_string()));
    a.insert("secret_type".into(), AttrValue::Str(secret_type.to_string()));
    a.insert("has_inline_data".into(), AttrValue::Bool(has_inline));
    b.entity(Entity {
        id: sid,
        kind: EntityKind::Secret,
        attributes: a,
        provenance: Provenance::explicit(format!("Secret/{name}")).with_line(obj_line(lm)),
    });
}

// --- helpers --------------------------------------------------------------

fn bool_or_unknown(v: Option<bool>) -> AttrValue {
    match v {
        Some(b) => AttrValue::Bool(b),
        None => AttrValue::Unknown,
    }
}

/// YAML booleans may arrive as a real bool or the strings "true"/"false".
fn yaml_bool(y: &Yaml) -> Option<bool> {
    match y {
        Yaml::Boolean(b) => Some(*b),
        Yaml::String(s) => match s.to_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn str_list(y: &Yaml) -> Vec<String> {
    y.as_vec()
        .map(|v| v.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

/// A YAML mapping -> sorted (key, value) string pairs (for labels/selectors).
fn hash_to_pairs(y: &Yaml) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(h) = y.as_hash() {
        for (k, v) in h {
            if let (Some(k), Some(v)) = (k.as_str(), yaml_scalar_str(v)) {
                out.push((k.to_string(), v));
            }
        }
    }
    out.sort();
    out
}

fn yaml_scalar_str(y: &Yaml) -> Option<String> {
    match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Boolean(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Split an image reference into (repo, tag, digest_pinned).
fn parse_image_ref(s: &str) -> (String, String, bool) {
    if let Some(idx) = s.find("@sha256:") {
        let (repo, tag) = split_repo_tag(&s[..idx]);
        (repo, tag.unwrap_or_else(|| "".into()), true)
    } else {
        let (repo, tag) = split_repo_tag(s);
        (repo, tag.unwrap_or_else(|| "latest".into()), false)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism_same_input_same_hash() {
        let y = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:1.25\n";
        assert_eq!(parse(y).model_hash(), parse(y).model_hash());
    }

    #[test]
    fn privileged_container_is_modeled() {
        let y = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: x@sha256:aa\n      securityContext:\n        privileged: true\n";
        let fm = parse(y);
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Container
            && e.attr("privileged").and_then(|v| v.as_bool()) == Some(true)));
    }

    #[test]
    fn provenance_lines_are_per_document() {
        // Multi-doc manifest: each container must carry the (absolute) line from
        // *its own* document, not a merged/last-wins line. Doc 1's container is at
        // line 7; doc 2's (after `---` at line 9) container is at line 17.
        let y = "\
apiVersion: v1
kind: Pod
metadata:
  name: a
spec:
  containers:
    - name: ca
      image: nginx:1
---
apiVersion: v1
kind: Pod
metadata:
  name: b
spec:
  hostPID: true
  containers:
    - name: cb
      image: nginx:2
";
        let fm = parse(y);
        let line_of = |id: &str| {
            fm.entities
                .iter()
                .find(|e| e.id == id)
                .and_then(|e| e.provenance.line)
        };
        assert_eq!(line_of("container:default/a/ca"), Some(7));
        assert_eq!(line_of("container:default/b/cb"), Some(17));
        // The workload object anchors to its metadata.name line.
        assert_eq!(line_of("workload:default/b"), Some(13));
    }

    #[test]
    fn invalid_yaml_is_an_error() {
        // Unterminated flow mapping -> the YAML loader must reject it rather than
        // fail open to an empty (zero-findings) model.
        assert!(try_parse("kind: Pod\nmetadata: {unclosed").is_err());
    }

    #[test]
    fn service_selector_connects_to_workload() {
        let y = "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\nspec:\n  type: LoadBalancer\n  selector:\n    app: web\n  ports:\n    - port: 80\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    metadata:\n      labels:\n        app: web\n    spec:\n      containers:\n        - name: c\n          image: nginx@sha256:aa\n";
        let fm = parse(y);
        assert!(fm.relations.iter().any(|r| r.kind == RelationKind::ConnectsTo
            && r.from == "service:default/web"
            && r.to == "workload:default/web"));
    }
}
