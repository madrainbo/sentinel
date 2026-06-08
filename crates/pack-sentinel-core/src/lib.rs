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

pub struct SentinelCorePack {
    rules: Vec<Box<dyn Rule>>,
}

impl SentinelCorePack {
    pub fn new() -> Self {
        let rules: Vec<Box<dyn Rule>> = vec![
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
