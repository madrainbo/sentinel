//! k8s-core pack — deterministic Kubernetes manifest security rules. Pure
//! functions of the fact model produced by `k8s-parser`.
//!
//! Includes a cross-resource attack-path rule: an externally-reachable Service
//! that routes (by selector) to a Workload holding a node-takeover surface
//! (privileged container / dangerous capability / sensitive hostPath) — the
//! exploitable chain, not a single flag.

use engine::{count_severities, Finding, Pack, Rule, Severity, Status, Verdict};
use fact_model::{AttrValue, Entity, EntityKind, FactModel, RelationKind};
use k8s_parser::{DANGEROUS_CAPS, SENSITIVE_HOST_PATHS};
use std::collections::HashMap;

pub const PACK_ID: &str = "k8s-core";

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
    evidence: &str,
    message: String,
    fix: &str,
) -> Finding {
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

/// "container:ns/workload/name" -> "workload/name" for human messages.
fn short(id: &str) -> &str {
    id.split_once(':').map(|(_, r)| r).unwrap_or(id)
}

fn containers(m: &FactModel) -> impl Iterator<Item = &Entity> {
    m.entities.iter().filter(|e| e.kind == EntityKind::Container)
}
fn workloads(m: &FactModel) -> impl Iterator<Item = &Entity> {
    m.entities.iter().filter(|e| e.kind == EntityKind::Workload)
}

// --- privileged container -------------------------------------------------
fn r_privileged(m: &FactModel) -> Vec<Finding> {
    containers(m)
        .filter(|e| e.attr("privileged").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            finding(
                "K8S-PRIVILEGED-CONTAINER",
                &["CWE-250", "CIS-K8s-5.2.2"],
                Severity::Critical,
                &e.id,
                format!("Container '{}' runs privileged — full access to host devices and kernel; trivial node takeover", short(&e.id)),
                "Remove 'securityContext.privileged: true'; grant only the specific capabilities required.",
            )
        })
        .collect()
}

// --- cap_add ALL ----------------------------------------------------------
fn r_cap_add_all(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Capability)
        .filter(|e| {
            e.attr("cap").and_then(|v| v.as_str()).map(|c| c.eq_ignore_ascii_case("ALL")) == Some(true)
        })
        .map(|e| {
            finding(
                "K8S-CAP-ADD-ALL",
                &["CWE-250", "CIS-K8s-5.2.9"],
                Severity::Critical,
                &e.id,
                "Container adds ALL Linux capabilities — equivalent to privileged".into(),
                "Drop all capabilities ('capabilities.drop: [ALL]') and add back only the few needed.",
            )
        })
        .collect()
}

// --- dangerous capability -------------------------------------------------
fn r_dangerous_cap(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Capability)
        .filter_map(|e| {
            let cap = e.attr("cap").and_then(|v| v.as_str())?;
            if DANGEROUS_CAPS.contains(&cap) {
                Some(finding(
                    "K8S-DANGEROUS-CAPABILITY",
                    &["CWE-250", "CIS-K8s-5.2.9"],
                    Severity::High,
                    &e.id,
                    format!("Dangerous Linux capability '{cap}' added — can enable container escape or host tampering"),
                    "Remove the capability; if required, justify and isolate the workload.",
                ))
            } else {
                None
            }
        })
        .collect()
}

// --- host namespaces ------------------------------------------------------
fn r_host_namespaces(m: &FactModel) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in workloads(m) {
        let n = short(&e.id);
        if e.attr("host_network").and_then(|v| v.as_bool()) == Some(true) {
            out.push(finding(
                "K8S-HOST-NETWORK",
                &["CWE-668", "CIS-K8s-5.2.5"],
                Severity::High,
                &e.id,
                format!("Workload '{n}' uses hostNetwork — shares the node's network stack, bypassing NetworkPolicies"),
                "Remove 'hostNetwork: true'; use a Service for connectivity.",
            ));
        }
        if e.attr("host_pid").and_then(|v| v.as_bool()) == Some(true) {
            out.push(finding(
                "K8S-HOST-PID",
                &["CWE-668", "CIS-K8s-5.2.3"],
                Severity::High,
                &e.id,
                format!("Workload '{n}' uses hostPID — can see and signal processes on the node"),
                "Remove 'hostPID: true'.",
            ));
        }
        if e.attr("host_ipc").and_then(|v| v.as_bool()) == Some(true) {
            out.push(finding(
                "K8S-HOST-IPC",
                &["CWE-668", "CIS-K8s-5.2.4"],
                Severity::High,
                &e.id,
                format!("Workload '{n}' uses hostIPC — shares the node's IPC namespace"),
                "Remove 'hostIPC: true'.",
            ));
        }
    }
    out
}

// --- hostPath mounts ------------------------------------------------------
fn r_hostpath(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Mount)
        .filter(|e| e.attr("host_path").and_then(|v| v.as_bool()) == Some(true))
        .filter_map(|e| {
            let src = e.attr("source").and_then(|v| v.as_str())?;
            let sensitive = src == "/var/run/docker.sock"
                || SENSITIVE_HOST_PATHS.iter().any(|p| {
                    src == *p || (*p != "/" && src.starts_with(&format!("{p}/")))
                })
                || src == "/";
            let severity = if src == "/var/run/docker.sock" {
                Severity::Critical
            } else if sensitive {
                Severity::High
            } else {
                Severity::Medium
            };
            let extra = if src == "/var/run/docker.sock" {
                " (the Docker socket — full control of the node's container runtime)"
            } else if sensitive {
                " (a sensitive host path)"
            } else {
                ""
            };
            Some(finding(
                "K8S-HOSTPATH-MOUNT",
                &["CWE-552", "CIS-K8s-5.2.12"],
                severity,
                &e.id,
                format!("hostPath volume mounts '{src}' from the node{extra} — escapes container isolation"),
                "Avoid hostPath; use a PersistentVolume, configMap, or emptyDir. If unavoidable, mount a specific non-sensitive subdirectory read-only.",
            ))
        })
        .collect()
}

// --- seccomp unconfined ---------------------------------------------------
fn r_seccomp_unconfined(m: &FactModel) -> Vec<Finding> {
    containers(m)
        .filter(|e| e.attr("seccomp").and_then(|v| v.as_str()) == Some("Unconfined"))
        .map(|e| {
            finding(
                "K8S-SECCOMP-UNCONFINED",
                &["CWE-693", "CIS-K8s-5.7.2"],
                Severity::High,
                &e.id,
                format!("Container '{}' sets seccompProfile Unconfined — removes the syscall filter that blocks dangerous kernel calls", short(&e.id)),
                "Use seccompProfile type 'RuntimeDefault' (or a scoped Localhost profile).",
            )
        })
        .collect()
}

// --- allowPrivilegeEscalation: true ---------------------------------------
fn r_allow_priv_esc(m: &FactModel) -> Vec<Finding> {
    containers(m)
        .filter(|e| e.attr("allow_privilege_escalation").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            finding(
                "K8S-ALLOW-PRIVILEGE-ESCALATION",
                &["CWE-250", "CIS-K8s-5.2.6"],
                Severity::Medium,
                &e.id,
                format!("Container '{}' sets allowPrivilegeEscalation: true — a process can gain more privileges than its parent (e.g. via setuid)", short(&e.id)),
                "Set 'allowPrivilegeEscalation: false'.",
            )
        })
        .collect()
}

// --- RBAC wildcard --------------------------------------------------------
fn r_rbac_wildcard(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Role)
        .filter(|e| e.attr("wildcard_all").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let cluster = e.attr("cluster_scope").and_then(|v| v.as_bool()) == Some(true);
            let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("?");
            let (sev, scope) = if cluster {
                (Severity::Critical, "ClusterRole")
            } else {
                (Severity::High, "Role")
            };
            finding(
                "K8S-RBAC-WILDCARD",
                &["CWE-269", "CIS-K8s-5.1.3"],
                sev,
                &e.id,
                format!("{scope} '{name}' grants all verbs on all resources (*/*) — effectively unrestricted access within its scope"),
                "Scope the rule to the specific apiGroups, resources, and verbs actually needed.",
            )
        })
        .collect()
}

// --- RBAC secret read -----------------------------------------------------
fn r_rbac_secret_read(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Role)
        // wildcard_all already flagged by its own rule; report secret-read on its own only.
        .filter(|e| {
            e.attr("grants_secret_read").and_then(|v| v.as_bool()) == Some(true)
                && e.attr("wildcard_all").and_then(|v| v.as_bool()) != Some(true)
        })
        .map(|e| {
            let cluster = e.attr("cluster_scope").and_then(|v| v.as_bool()) == Some(true);
            let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("?");
            let (sev, scope) = if cluster {
                (Severity::High, "ClusterRole")
            } else {
                (Severity::Medium, "Role")
            };
            finding(
                "K8S-RBAC-SECRET-READ",
                &["CWE-522", "CIS-K8s-5.1.2"],
                sev,
                &e.id,
                format!("{scope} '{name}' can read Secrets — exposes every credential it can reach if the bound identity is compromised"),
                "Avoid granting get/list/watch on secrets broadly; scope to named secrets or use a workload-identity / external secrets store.",
            )
        })
        .collect()
}

// --- cluster-admin binding ------------------------------------------------
fn r_cluster_admin_binding(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::RoleBinding)
        .filter(|e| e.attr("binds_cluster_admin").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "K8S-CLUSTER-ADMIN-BINDING",
                &["CWE-269", "CIS-K8s-5.1.1"],
                Severity::Critical,
                &e.id,
                format!("Binding '{name}' grants the built-in cluster-admin role — full control of the entire cluster to its subjects"),
                "Bind a least-privilege role instead of cluster-admin; reserve cluster-admin for break-glass human operators.",
            )
        })
        .collect()
}

// --- secret in manifest ---------------------------------------------------
fn r_secret_in_manifest(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Secret)
        .filter(|e| e.attr("has_inline_data").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "K8S-SECRET-IN-MANIFEST",
                &["CWE-312", "CWE-798"],
                Severity::Medium,
                &e.id,
                format!("Secret '{name}' embeds its data inline in the manifest (base64 is not encryption) — it ends up in version control and CI logs"),
                "Keep Secret material out of manifests: use sealed-secrets/SOPS, an external secrets operator, or a cloud secret store.",
            )
        })
        .collect()
}

// --- image unpinned -------------------------------------------------------
fn r_image_unpinned(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Image)
        .filter(|e| e.attr("digest_pinned").and_then(|v| v.as_bool()) == Some(false))
        .map(|e| {
            let repo = e.attr("repo").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "K8S-IMAGE-UNPINNED",
                &["CWE-494", "CWE-1357"],
                Severity::Low,
                &e.id,
                format!("Image '{repo}' is not pinned by digest — what runs can change silently (supply-chain risk)"),
                "Pin images by digest (repo@sha256:...).",
            )
        })
        .collect()
}

// --- runs as root ---------------------------------------------------------
fn r_runs_as_root(m: &FactModel) -> Vec<Finding> {
    containers(m)
        .filter(|e| e.attr("provably_non_root").and_then(|v| v.as_bool()) == Some(false))
        .map(|e| {
            finding(
                "K8S-CONTAINER-RUNS-AS-ROOT",
                &["CWE-250", "CIS-K8s-5.2.7"],
                Severity::Low,
                &e.id,
                format!("Container '{}' is not provably non-root (no runAsNonRoot: true and no non-zero runAsUser)", short(&e.id)),
                "Set 'securityContext.runAsNonRoot: true' and a non-zero 'runAsUser'.",
            )
        })
        .collect()
}

// --- Attack-path: externally-reachable node-takeover surface --------------
fn r_reachable_node_compromise(m: &FactModel) -> Vec<Finding> {
    let by_id: HashMap<&str, &Entity> = m.entities.iter().map(|e| (e.id.as_str(), e)).collect();

    // workload -> (reason, evidence resource id) for any node-takeover surface.
    let mut danger: HashMap<&str, (String, String)> = HashMap::new();
    // privileged / dangerous-cap containers (via Uses: workload -> container).
    let mut container_owner: HashMap<&str, &str> = HashMap::new();
    for r in &m.relations {
        if r.kind == RelationKind::Uses {
            if let Some(e) = by_id.get(r.to.as_str()) {
                if e.kind == EntityKind::Container {
                    container_owner.insert(r.to.as_str(), r.from.as_str());
                }
            }
        }
    }
    for c in containers(m) {
        if c.attr("privileged").and_then(|v| v.as_bool()) == Some(true) {
            if let Some(&wl) = container_owner.get(c.id.as_str()) {
                danger
                    .entry(wl)
                    .or_insert_with(|| ("runs a privileged container".to_string(), c.id.clone()));
            }
        }
    }
    for cap in m.entities.iter().filter(|e| e.kind == EntityKind::Capability) {
        let capv = cap.attr("cap").and_then(|v| v.as_str()).unwrap_or("");
        let dangerous = capv.eq_ignore_ascii_case("ALL") || DANGEROUS_CAPS.contains(&capv);
        if !dangerous {
            continue;
        }
        // capability:ns/wl/container/CAP -> owning container -> owning workload.
        // Find the container that grants it.
        for r in &m.relations {
            if r.kind == RelationKind::GrantsCapability && r.to == cap.id {
                if let Some(&wl) = container_owner.get(r.from.as_str()) {
                    danger
                        .entry(wl)
                        .or_insert_with(|| (format!("grants the dangerous capability {capv}"), cap.id.clone()));
                }
            }
        }
    }
    // sensitive hostPath mounts (workload -Mounts-> mount).
    for r in &m.relations {
        if r.kind == RelationKind::Mounts {
            if let Some(mnt) = by_id.get(r.to.as_str()) {
                let src = mnt.attr("source").and_then(|v| v.as_str()).unwrap_or("");
                let sensitive = src == "/var/run/docker.sock"
                    || SENSITIVE_HOST_PATHS.iter().any(|p| {
                        src == *p || (*p != "/" && src.starts_with(&format!("{p}/")))
                    })
                    || src == "/";
                if sensitive {
                    danger
                        .entry(r.from.as_str())
                        .or_insert_with(|| (format!("mounts the sensitive host path {src}"), mnt.id.clone()));
                }
            }
        }
    }
    if danger.is_empty() {
        return Vec::new();
    }

    // external services -ConnectsTo-> workload.
    let mut out = Vec::new();
    let mut emitted: std::collections::HashSet<(&str, &str)> = std::collections::HashSet::new();
    let mut conns: Vec<(&str, &str)> = m
        .relations
        .iter()
        .filter(|r| r.kind == RelationKind::ConnectsTo)
        .map(|r| (r.from.as_str(), r.to.as_str()))
        .collect();
    conns.sort();
    for (svc_id, wl_id) in conns {
        let svc = match by_id.get(svc_id) {
            Some(s) if s.kind == EntityKind::Service => s,
            _ => continue,
        };
        if svc.attr("external").and_then(|v| v.as_bool()) != Some(true) {
            continue;
        }
        let (reason, res_id) = match danger.get(wl_id) {
            Some(x) => x,
            None => continue,
        };
        if !emitted.insert((svc_id, wl_id)) {
            continue;
        }
        let svc_type = svc.attr("service_type").and_then(|v| v.as_str()).unwrap_or("external");
        out.push(Finding {
            rule_id: "K8S-REACHABLE-NODE-COMPROMISE".to_string(),
            controls: vec!["CWE-668".to_string(), "CWE-250".to_string()],
            severity: Severity::Critical,
            evidence: vec![svc_id.to_string(), wl_id.to_string(), res_id.to_string()],
            message: format!(
                "Externally-exposed Service '{}' ({svc_type}) routes to workload '{}', which {reason} — an attacker reaching the service has a path to node/cluster compromise",
                short(svc_id),
                short(wl_id)
            ),
            remediation:
                "Don't expose node-takeover workloads externally: drop privileged/dangerous capabilities and sensitive hostPath mounts on anything an external Service selects, or front it with a hardened gateway."
                    .to_string(),
            lines: Vec::new(),
        });
    }
    out
}

// --- strict-only hardening ------------------------------------------------
fn h_readonly_rootfs(m: &FactModel) -> Vec<Finding> {
    containers(m)
        .filter(|e| e.attr("read_only_root_fs").and_then(|v| v.as_bool()) != Some(true))
        .map(|e| {
            finding(
                "K8S-READONLY-ROOTFS-MISSING",
                &["CWE-732"],
                Severity::Low,
                &e.id,
                format!("Container '{}' does not set readOnlyRootFilesystem: true", short(&e.id)),
                "Set 'securityContext.readOnlyRootFilesystem: true' and mount writable paths explicitly.",
            )
        })
        .collect()
}

fn h_allow_priv_esc_unset(m: &FactModel) -> Vec<Finding> {
    containers(m)
        .filter(|e| matches!(e.attr("allow_privilege_escalation"), Some(AttrValue::Unknown) | None))
        .map(|e| {
            finding(
                "K8S-ALLOW-PRIV-ESC-NOT-DISABLED",
                &["CWE-250"],
                Severity::Low,
                &e.id,
                format!("Container '{}' does not explicitly set allowPrivilegeEscalation: false (defaults to true)", short(&e.id)),
                "Set 'allowPrivilegeEscalation: false'.",
            )
        })
        .collect()
}

fn h_automount_token(m: &FactModel) -> Vec<Finding> {
    workloads(m)
        .filter(|e| e.attr("automount_sa_token").and_then(|v| v.as_bool()) != Some(false))
        .map(|e| {
            finding(
                "K8S-AUTOMOUNT-SA-TOKEN",
                &["CWE-668", "CIS-K8s-5.1.6"],
                Severity::Low,
                &e.id,
                format!("Workload '{}' does not disable automountServiceAccountToken (its API token is mounted into every pod)", short(&e.id)),
                "Set 'automountServiceAccountToken: false' unless the workload calls the Kubernetes API.",
            )
        })
        .collect()
}

/// Static catalog of every rule this pack can emit (for the in-app catalog).
pub fn catalog() -> Vec<engine::RuleMeta> {
    use engine::RuleMeta;
    use engine::Severity::{Critical, High, Low, Medium};
    let t = "Kubernetes";
    vec![
        RuleMeta { id: "K8S-REACHABLE-NODE-COMPROMISE", title: "Reachable node-compromise path", target: t, severity: Critical, controls: &["CWE-668", "CWE-250"], summary: "Cross-resource: an external Service (NodePort/LoadBalancer) selects a Workload that runs privileged / adds a dangerous capability / mounts a sensitive hostPath — reaching the service chains to node or cluster takeover.", fix: "Keep node-takeover surfaces off anything an external Service selects; front with a hardened gateway.", strict: false },
        RuleMeta { id: "K8S-PRIVILEGED-CONTAINER", title: "Privileged container", target: t, severity: Critical, controls: &["CWE-250", "CIS-K8s-5.2.2"], summary: "A container sets securityContext.privileged: true — full host device/kernel access, trivial node takeover.", fix: "Remove privileged; grant only the specific capabilities required.", strict: false },
        RuleMeta { id: "K8S-CAP-ADD-ALL", title: "All capabilities added", target: t, severity: Critical, controls: &["CWE-250", "CIS-K8s-5.2.9"], summary: "A container adds ALL Linux capabilities — equivalent to privileged.", fix: "Drop all capabilities and add back only the few needed.", strict: false },
        RuleMeta { id: "K8S-CLUSTER-ADMIN-BINDING", title: "cluster-admin granted", target: t, severity: Critical, controls: &["CWE-269", "CIS-K8s-5.1.1"], summary: "A (Cluster)RoleBinding binds the built-in cluster-admin role — full control of the cluster.", fix: "Bind a least-privilege role; reserve cluster-admin for break-glass.", strict: false },
        RuleMeta { id: "K8S-HOST-NETWORK", title: "Host network namespace", target: t, severity: High, controls: &["CWE-668", "CIS-K8s-5.2.5"], summary: "hostNetwork: true shares the node's network stack and bypasses NetworkPolicies.", fix: "Remove hostNetwork; use a Service.", strict: false },
        RuleMeta { id: "K8S-HOST-PID", title: "Host PID namespace", target: t, severity: High, controls: &["CWE-668", "CIS-K8s-5.2.3"], summary: "hostPID: true lets the pod see and signal processes on the node.", fix: "Remove hostPID.", strict: false },
        RuleMeta { id: "K8S-HOST-IPC", title: "Host IPC namespace", target: t, severity: High, controls: &["CWE-668", "CIS-K8s-5.2.4"], summary: "hostIPC: true shares the node's IPC namespace.", fix: "Remove hostIPC.", strict: false },
        RuleMeta { id: "K8S-HOSTPATH-MOUNT", title: "hostPath volume", target: t, severity: High, controls: &["CWE-552", "CIS-K8s-5.2.12"], summary: "A hostPath volume mounts a node directory into the pod, escaping isolation (Critical for the Docker socket / sensitive paths).", fix: "Use a PersistentVolume/configMap/emptyDir; if unavoidable, mount a specific non-sensitive subdir read-only.", strict: false },
        RuleMeta { id: "K8S-DANGEROUS-CAPABILITY", title: "Dangerous capability added", target: t, severity: High, controls: &["CWE-250", "CIS-K8s-5.2.9"], summary: "capabilities.add includes a high-risk capability (SYS_ADMIN, NET_ADMIN, …) enabling escape or host tampering.", fix: "Remove the capability; if required, justify and isolate.", strict: false },
        RuleMeta { id: "K8S-SECCOMP-UNCONFINED", title: "Seccomp unconfined", target: t, severity: High, controls: &["CWE-693", "CIS-K8s-5.7.2"], summary: "seccompProfile type Unconfined removes the syscall filter that blocks dangerous kernel calls.", fix: "Use seccompProfile RuntimeDefault (or a scoped Localhost profile).", strict: false },
        RuleMeta { id: "K8S-RBAC-WILDCARD", title: "Wildcard RBAC permissions", target: t, severity: High, controls: &["CWE-269", "CIS-K8s-5.1.3"], summary: "A Role/ClusterRole grants all verbs on all resources (*/*) — unrestricted within scope (Critical at cluster scope).", fix: "Scope rules to the specific apiGroups/resources/verbs needed.", strict: false },
        RuleMeta { id: "K8S-RBAC-SECRET-READ", title: "Broad Secret read access", target: t, severity: Medium, controls: &["CWE-522", "CIS-K8s-5.1.2"], summary: "A Role/ClusterRole can get/list/watch Secrets — exposes credentials if the bound identity is compromised (High at cluster scope).", fix: "Scope to named secrets or use an external secrets store.", strict: false },
        RuleMeta { id: "K8S-ALLOW-PRIVILEGE-ESCALATION", title: "Privilege escalation allowed", target: t, severity: Medium, controls: &["CWE-250", "CIS-K8s-5.2.6"], summary: "Container sets allowPrivilegeEscalation: true — a process can gain more privileges than its parent.", fix: "Set allowPrivilegeEscalation: false.", strict: false },
        RuleMeta { id: "K8S-SECRET-IN-MANIFEST", title: "Secret embedded in manifest", target: t, severity: Medium, controls: &["CWE-312", "CWE-798"], summary: "A Secret embeds its data inline (base64 is not encryption) — it lands in version control and CI logs.", fix: "Use sealed-secrets/SOPS, an external secrets operator, or a cloud secret store.", strict: false },
        RuleMeta { id: "K8S-IMAGE-UNPINNED", title: "Image not pinned by digest", target: t, severity: Low, controls: &["CWE-494", "CWE-1357"], summary: "A container image uses a tag rather than a digest — what runs can change silently.", fix: "Pin images by digest (repo@sha256:…).", strict: false },
        RuleMeta { id: "K8S-CONTAINER-RUNS-AS-ROOT", title: "Not provably non-root", target: t, severity: Low, controls: &["CWE-250", "CIS-K8s-5.2.7"], summary: "No runAsNonRoot: true and no non-zero runAsUser, so the container can't be confirmed non-root.", fix: "Set runAsNonRoot: true and a non-zero runAsUser.", strict: false },
        RuleMeta { id: "K8S-READONLY-ROOTFS-MISSING", title: "Writable root filesystem", target: t, severity: Low, controls: &["CWE-732"], summary: "readOnlyRootFilesystem is not set, so an attacker can persist tooling in the container filesystem.", fix: "Set readOnlyRootFilesystem: true and mount writable paths explicitly.", strict: true },
        RuleMeta { id: "K8S-ALLOW-PRIV-ESC-NOT-DISABLED", title: "Priv-escalation not disabled", target: t, severity: Low, controls: &["CWE-250"], summary: "allowPrivilegeEscalation is not explicitly false (defaults to true).", fix: "Set allowPrivilegeEscalation: false.", strict: true },
        RuleMeta { id: "K8S-AUTOMOUNT-SA-TOKEN", title: "SA token auto-mounted", target: t, severity: Low, controls: &["CWE-668", "CIS-K8s-5.1.6"], summary: "automountServiceAccountToken is not disabled, so the API token is mounted into every pod.", fix: "Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.", strict: true },
    ]
}

pub struct K8sCorePack {
    rules: Vec<Box<dyn Rule>>,
}

impl K8sCorePack {
    pub fn new() -> Self {
        Self::with_options(false)
    }

    pub fn with_options(strict: bool) -> Self {
        let mut rules: Vec<Box<dyn Rule>> = vec![
            Box::new(FnRule { id: "K8S-PRIVILEGED-CONTAINER", f: r_privileged }),
            Box::new(FnRule { id: "K8S-CAP-ADD-ALL", f: r_cap_add_all }),
            Box::new(FnRule { id: "K8S-DANGEROUS-CAPABILITY", f: r_dangerous_cap }),
            Box::new(FnRule { id: "K8S-HOST-NAMESPACES", f: r_host_namespaces }),
            Box::new(FnRule { id: "K8S-HOSTPATH-MOUNT", f: r_hostpath }),
            Box::new(FnRule { id: "K8S-SECCOMP-UNCONFINED", f: r_seccomp_unconfined }),
            Box::new(FnRule { id: "K8S-ALLOW-PRIVILEGE-ESCALATION", f: r_allow_priv_esc }),
            Box::new(FnRule { id: "K8S-RBAC-WILDCARD", f: r_rbac_wildcard }),
            Box::new(FnRule { id: "K8S-RBAC-SECRET-READ", f: r_rbac_secret_read }),
            Box::new(FnRule { id: "K8S-CLUSTER-ADMIN-BINDING", f: r_cluster_admin_binding }),
            Box::new(FnRule { id: "K8S-SECRET-IN-MANIFEST", f: r_secret_in_manifest }),
            Box::new(FnRule { id: "K8S-IMAGE-UNPINNED", f: r_image_unpinned }),
            Box::new(FnRule { id: "K8S-CONTAINER-RUNS-AS-ROOT", f: r_runs_as_root }),
            Box::new(FnRule { id: "K8S-REACHABLE-NODE-COMPROMISE", f: r_reachable_node_compromise }),
        ];
        if strict {
            rules.push(Box::new(FnRule { id: "K8S-READONLY-ROOTFS-MISSING", f: h_readonly_rootfs }));
            rules.push(Box::new(FnRule { id: "K8S-ALLOW-PRIV-ESC-NOT-DISABLED", f: h_allow_priv_esc_unset }));
            rules.push(Box::new(FnRule { id: "K8S-AUTOMOUNT-SA-TOKEN", f: h_automount_token }));
        }
        Self { rules }
    }
}

impl Default for K8sCorePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Pack for K8sCorePack {
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
