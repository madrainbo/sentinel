//! sentinel-core pack v0 — Docker Compose security rules R1..R10.
//!
//! Each rule is a pure function of the fact model. Control mappings (CWE / CIS
//! Docker Benchmark) are documented and verified in `CONTROLS.md`.

use engine::{count_severities, Finding, Pack, Rule, Severity, Status, Verdict};
use fact_model::{AttrValue, EntityKind, FactModel};

pub const PACK_ID: &str = "sentinel-core";

const DANGEROUS_CAPS: &[&str] = &[
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE",
    "SYS_RAWIO", "BPF", "SYS_BOOT", "SYS_TIME", "MAC_ADMIN", "MAC_OVERRIDE", "AUDIT_CONTROL",
    "LINUX_IMMUTABLE",
];
const SENSITIVE_PORTS: &[i64] = &[
    2375, 2376, // docker daemon
    5432, 5433, 3306, 1433, 1521, // SQL databases
    6379, 6380, 11211, // redis / memcached
    27017, 28015, 9042, 7000, 7001, 26257, 8123, // mongo / rethink / cassandra / cockroach / clickhouse
    9200, 9300, 5984, // elasticsearch / couchdb
    2181, 2379, 2380, 9092, 5672, 15672, // zookeeper / etcd / kafka / rabbitmq
    8500, // consul
];

/// Host paths that should never be bind-mounted into a container (besides the
/// Docker socket, which has its own dedicated rule R1).
const SENSITIVE_HOST_PATHS: &[&str] = &[
    "/", "/etc", "/root", "/proc", "/sys", "/boot", "/dev", "/var/run", "/var/lib/docker",
    "/usr", "/bin", "/sbin", "/lib",
];

/// Benign exceptions that match a sensitive prefix but are common, low-risk
/// read-only mounts (e.g. timezone sync). Not flagged by R11.
const BENIGN_HOST_PATHS: &[&str] = &["/etc/localtime", "/etc/timezone"];

/// A rule backed by a plain function pointer.
struct FnRule {
    id: &'static str,
    f: fn(&FactModel) -> Vec<Finding>,
}

impl Rule for FnRule {
    fn id(&self) -> &str {
        self.id
    }
    fn evaluate(&self, model: &FactModel) -> Vec<Finding> {
        (self.f)(model)
    }
}

fn finding(
    rule_id: &str,
    controls: &[&str],
    severity: Severity,
    evidence: &str,
    message: String,
    remediation: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        controls: controls.iter().map(|s| s.to_string()).collect(),
        severity,
        evidence: vec![evidence.to_string()],
        message,
        remediation: remediation.to_string(),
    }
}

fn svc_name(id: &str) -> &str {
    id.strip_prefix("service:").unwrap_or(id)
}

// --- R1 -------------------------------------------------------------------
fn r1_docker_socket(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Mount)
        .filter(|e| e.attr("source").and_then(|v| v.as_str()) == Some("/var/run/docker.sock"))
        .map(|e| {
            finding(
                "DOCKER-SOCKET-MOUNT",
                &["CWE-250", "CIS-Docker-5.31"],
                Severity::Critical,
                &e.id,
                "Container mounts the Docker socket (/var/run/docker.sock) — grants full control of the Docker daemon (host root)".into(),
                "Remove the mount; if daemon access is required, use a scoped socket proxy with an allow-list, read-only.",
            )
        })
        .collect()
}

// --- R2 -------------------------------------------------------------------
fn r2_privileged(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Service)
        .filter(|e| e.attr("privileged").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            finding(
                "PRIVILEGED-CONTAINER",
                &["CWE-250", "CIS-Docker-5.4"],
                Severity::Critical,
                &e.id,
                format!("Service '{}' runs privileged — disables container isolation (near root-on-host)", svc_name(&e.id)),
                "Drop 'privileged'; grant only the specific capabilities required.",
            )
        })
        .collect()
}

// --- R3 -------------------------------------------------------------------
fn r3_dangerous_cap(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Capability)
        .filter_map(|e| {
            let cap = e.attr("cap").and_then(|v| v.as_str())?;
            if DANGEROUS_CAPS.contains(&cap) {
                Some(finding(
                    "DANGEROUS-CAPABILITY",
                    &["CWE-250", "CIS-Docker-5.3"],
                    Severity::High,
                    &e.id,
                    format!("Dangerous Linux capability '{cap}' granted — can enable container escape or host tampering"),
                    "Remove the capability; if required, justify and isolate the workload.",
                ))
            } else {
                None
            }
        })
        .collect()
}

// --- R4 -------------------------------------------------------------------
fn r4_host_network(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Service)
        .filter(|e| e.attr("network_mode").and_then(|v| v.as_str()) == Some("host"))
        .map(|e| {
            finding(
                "HOST-NETWORK-MODE",
                &["CWE-668", "CIS-Docker-5.9"],
                Severity::High,
                &e.id,
                format!("Service '{}' uses host network mode — removes network namespace isolation", svc_name(&e.id)),
                "Use a user-defined bridge network and publish only the needed ports.",
            )
        })
        .collect()
}

// --- R5 -------------------------------------------------------------------
fn r5_weak_default_cred(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::EnvVar)
        .filter(|e| e.attr("value_is_weak_default").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "WEAK-DEFAULT-CREDENTIAL",
                &["CWE-798", "CWE-1392"],
                Severity::High,
                &e.id,
                format!("Environment variable '{name}' uses a weak/default credential value"),
                "Set a strong unique secret; inject via a secrets manager, not inline.",
            )
        })
        .collect()
}

// --- R6 -------------------------------------------------------------------
fn r6_secret_in_env(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::EnvVar)
        .filter(|e| {
            e.attr("value_class").and_then(|v| v.as_str()) == Some("secret_like")
                && e.attr("has_inline_value").and_then(|v| v.as_bool()) == Some(true)
                && e.attr("value_is_weak_default").and_then(|v| v.as_bool()) != Some(true)
        })
        .map(|e| {
            let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "SECRET-IN-ENVIRONMENT",
                &["CWE-256", "CWE-798"],
                Severity::Medium,
                &e.id,
                format!("Secret-like variable '{name}' has an inline literal value — ends up in VCS and `docker inspect`"),
                "Use Compose/Docker secrets or an external secrets manager; reference, don't inline.",
            )
        })
        .collect()
}

// --- R7 -------------------------------------------------------------------
fn r7_port_exposure(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::PortBinding)
        .filter(|e| e.attr("host_ip").and_then(|v| v.as_str()) == Some("0.0.0.0"))
        .filter_map(|e| {
            let target = e.attr("target").and_then(|v| v.as_i64());
            match target {
                Some(t) if SENSITIVE_PORTS.contains(&t) => Some(finding(
                    "SENSITIVE-PORT-PUBLISHED-ALL-IFACES",
                    &["CWE-668"],
                    Severity::Medium,
                    &e.id,
                    format!("Sensitive port {t} published on all interfaces (0.0.0.0)"),
                    "Bind to 127.0.0.1 or an internal network; do not publish datastores.",
                )),
                Some(_) | None => {
                    // generic published port (only flag when a host port is actually published)
                    if matches!(e.attr("published"), Some(AttrValue::Int(_))) {
                        Some(finding(
                            "PORT-PUBLISHED-ALL-IFACES",
                            &["CWE-668"],
                            Severity::Low,
                            &e.id,
                            "Port published on all interfaces (0.0.0.0)".into(),
                            "Bind to a specific interface (e.g. 127.0.0.1) unless external access is intended.",
                        ))
                    } else {
                        None
                    }
                }
            }
        })
        .collect()
}

// --- R8 -------------------------------------------------------------------
fn r8_image_unpinned(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Image)
        .filter(|e| e.attr("digest_pinned").and_then(|v| v.as_bool()) == Some(false))
        .map(|e| {
            let repo = e.attr("repo").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "IMAGE-UNPINNED",
                &["CWE-494", "CWE-1357"],
                Severity::Low,
                &e.id,
                format!("Image '{repo}' is not pinned by digest — non-reproducible and a supply-chain risk"),
                "Pin by digest (image@sha256:...).",
            )
        })
        .collect()
}

// --- R9 -------------------------------------------------------------------
fn r9_runs_as(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Service)
        .filter_map(|e| {
            let runs_as = e.attr("runs_as")?;
            let (detail, is_flag) = match runs_as {
                AttrValue::Enum(s) if s == "root" => ("runs as root", true),
                AttrValue::Unknown => ("user is unspecified (cannot confirm non-root)", true),
                _ => ("", false),
            };
            if is_flag {
                Some(finding(
                    "CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN",
                    &["CWE-250", "CIS-Docker-4.1"],
                    Severity::Low,
                    &e.id,
                    format!("Service '{}' {detail}", svc_name(&e.id)),
                    "Set a non-root 'user:'; declare it explicitly even if the base image sets one.",
                ))
            } else {
                None
            }
        })
        .collect()
}

// --- R10 ------------------------------------------------------------------
fn r10_writable_rootfs(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Service)
        .filter(|e| {
            matches!(
                e.attr("read_only_root_fs"),
                Some(AttrValue::Bool(false)) | Some(AttrValue::Unknown)
            )
        })
        .map(|e| {
            finding(
                "WRITABLE-ROOT-FILESYSTEM",
                &["CWE-732", "CIS-Docker-5.12"],
                Severity::Low,
                &e.id,
                format!("Service '{}' has a writable root filesystem", svc_name(&e.id)),
                "Set 'read_only: true' and mount specific writable paths as tmpfs/volumes.",
            )
        })
        .collect()
}

// --- R11 ------------------------------------------------------------------
fn r11_sensitive_host_mount(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Mount)
        .filter_map(|e| {
            let src = e.attr("source").and_then(|v| v.as_str())?;
            // The Docker socket has its own dedicated rule (R1).
            if src == "/var/run/docker.sock" {
                return None;
            }
            // Benign common mounts (timezone, etc.) are not flagged.
            if BENIGN_HOST_PATHS.contains(&src) {
                return None;
            }
            let is_sensitive = SENSITIVE_HOST_PATHS.iter().any(|p| {
                src == *p || (*p != "/" && src.starts_with(&format!("{p}/")))
            }) || src == "/";
            if !is_sensitive {
                return None;
            }
            let severity = if src == "/" || src == "/etc" || src == "/root" {
                Severity::Critical
            } else {
                Severity::High
            };
            Some(finding(
                "SENSITIVE-HOST-PATH-MOUNT",
                &["CWE-552", "CWE-668"],
                severity,
                &e.id,
                format!("Sensitive host path '{src}' is bind-mounted into a container — exposes host files to the container"),
                "Remove the bind mount or scope it to a specific, non-sensitive subdirectory (read-only where possible).",
            ))
        })
        .collect()
}

// --- R12 ------------------------------------------------------------------
fn r12_host_pid_ipc(m: &FactModel) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in m.entities.iter().filter(|e| e.kind == EntityKind::Service) {
        if e.attr("pid_mode").and_then(|v| v.as_str()) == Some("host") {
            out.push(finding(
                "HOST-PID-NAMESPACE",
                &["CWE-668", "CIS-Docker-5.15"],
                Severity::High,
                &e.id,
                format!("Service '{}' shares the host PID namespace (pid: host) — can see/signal host processes", svc_name(&e.id)),
                "Remove 'pid: host'; containers should use their own PID namespace.",
            ));
        }
        if e.attr("ipc_mode").and_then(|v| v.as_str()) == Some("host") {
            out.push(finding(
                "HOST-IPC-NAMESPACE",
                &["CWE-668", "CIS-Docker-5.16"],
                Severity::High,
                &e.id,
                format!("Service '{}' shares the host IPC namespace (ipc: host) — breaks process isolation", svc_name(&e.id)),
                "Remove 'ipc: host'; containers should use their own IPC namespace.",
            ));
        }
    }
    out
}

// --- Hardening rules (--strict only) --------------------------------------
fn services_missing<'a>(
    m: &'a FactModel,
    attr: &'a str,
) -> impl Iterator<Item = &'a fact_model::Entity> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Service)
        .filter(move |e| e.attr(attr).and_then(|v| v.as_bool()) == Some(false))
}

fn h1_no_new_privileges(m: &FactModel) -> Vec<Finding> {
    services_missing(m, "no_new_privileges")
        .map(|e| {
            finding(
                "NO-NEW-PRIVILEGES-MISSING",
                &["CWE-250"],
                Severity::Low,
                &e.id,
                format!("Service '{}' does not set no-new-privileges — processes can gain privileges via setuid binaries", svc_name(&e.id)),
                "Add 'security_opt: [\"no-new-privileges:true\"]'.",
            )
        })
        .collect()
}

fn h2_cap_drop_all(m: &FactModel) -> Vec<Finding> {
    services_missing(m, "caps_dropped_all")
        .map(|e| {
            finding(
                "CAP-DROP-ALL-MISSING",
                &["CWE-250"],
                Severity::Low,
                &e.id,
                format!("Service '{}' does not drop all capabilities — keeps Docker's default capability set", svc_name(&e.id)),
                "Add 'cap_drop: [ALL]' and 'cap_add' only the capabilities you need.",
            )
        })
        .collect()
}

fn h3_no_resource_limits(m: &FactModel) -> Vec<Finding> {
    services_missing(m, "has_mem_limit")
        .map(|e| {
            finding(
                "NO-RESOURCE-LIMITS",
                &["CWE-400"],
                Severity::Low,
                &e.id,
                format!("Service '{}' has no memory limit — a runaway container can exhaust host memory (DoS)", svc_name(&e.id)),
                "Set a memory limit (deploy.resources.limits.memory, or mem_limit in v2).",
            )
        })
        .collect()
}

pub struct SentinelCorePack {
    rules: Vec<Box<dyn Rule>>,
}

impl SentinelCorePack {
    /// Default rule set (high-signal rules only).
    pub fn new() -> Self {
        Self::with_options(false)
    }

    /// Build the pack; `strict` adds best-practice hardening rules that fire
    /// broadly (no-new-privileges, cap-drop-all, resource limits).
    pub fn with_options(strict: bool) -> Self {
        let mut rules: Vec<Box<dyn Rule>> = vec![
            Box::new(FnRule { id: "DOCKER-SOCKET-MOUNT", f: r1_docker_socket }),
            Box::new(FnRule { id: "PRIVILEGED-CONTAINER", f: r2_privileged }),
            Box::new(FnRule { id: "DANGEROUS-CAPABILITY", f: r3_dangerous_cap }),
            Box::new(FnRule { id: "HOST-NETWORK-MODE", f: r4_host_network }),
            Box::new(FnRule { id: "WEAK-DEFAULT-CREDENTIAL", f: r5_weak_default_cred }),
            Box::new(FnRule { id: "SECRET-IN-ENVIRONMENT", f: r6_secret_in_env }),
            Box::new(FnRule { id: "PORT-EXPOSURE", f: r7_port_exposure }),
            Box::new(FnRule { id: "IMAGE-UNPINNED", f: r8_image_unpinned }),
            Box::new(FnRule { id: "CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN", f: r9_runs_as }),
            Box::new(FnRule { id: "WRITABLE-ROOT-FILESYSTEM", f: r10_writable_rootfs }),
            Box::new(FnRule { id: "SENSITIVE-HOST-PATH-MOUNT", f: r11_sensitive_host_mount }),
            Box::new(FnRule { id: "HOST-PID-IPC", f: r12_host_pid_ipc }),
        ];
        if strict {
            rules.push(Box::new(FnRule { id: "NO-NEW-PRIVILEGES-MISSING", f: h1_no_new_privileges }));
            rules.push(Box::new(FnRule { id: "CAP-DROP-ALL-MISSING", f: h2_cap_drop_all }));
            rules.push(Box::new(FnRule { id: "NO-RESOURCE-LIMITS", f: h3_no_resource_limits }));
        }
        Self { rules }
    }
}

impl Default for SentinelCorePack {
    fn default() -> Self {
        Self::new()
    }
}

impl Pack for SentinelCorePack {
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

#[cfg(test)]
mod tests {
    use super::*;
    use engine::run_pack;
    use fact_model::{Entity, Origin, Provenance, SourceDescriptor};
    use std::collections::BTreeMap;

    fn bare_service_model() -> FactModel {
        let mut attrs = BTreeMap::new();
        attrs.insert("no_new_privileges".into(), AttrValue::Bool(false));
        attrs.insert("caps_dropped_all".into(), AttrValue::Bool(false));
        attrs.insert("has_mem_limit".into(), AttrValue::Bool(false));
        FactModel {
            schema_version: "0".into(),
            source: SourceDescriptor {
                kind: "docker_compose".into(),
                input_hash: String::new(),
                parser_version: String::new(),
            },
            entities: vec![Entity {
                id: "service:app".into(),
                kind: EntityKind::Service,
                attributes: attrs,
                provenance: Provenance {
                    source_path: String::new(),
                    origin: Origin::Explicit,
                },
            }],
            relations: vec![],
        }
    }

    #[test]
    fn strict_adds_three_hardening_findings() {
        let m = bare_service_model();
        let default_n = run_pack(&SentinelCorePack::new(), &m).len();
        let strict_n = run_pack(&SentinelCorePack::with_options(true), &m).len();
        assert_eq!(strict_n - default_n, 3);
    }
}
