//! sentinel-core pack v0 — Docker Compose security rules R1..R10.
//!
//! Each rule is a pure function of the fact model. Control mappings (CWE / CIS
//! Docker Benchmark) are documented and verified in `CONTROLS.md`.

use engine::{count_severities, Finding, Pack, Rule, Severity, Status, Verdict};
use fact_model::{AttrValue, Entity, EntityKind, FactModel, RelationKind};
use std::collections::{HashMap, HashSet, VecDeque};

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
        lines: Vec::new(),
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

// --- R13: security profile disabled ---------------------------------------
fn r_security_profile_disabled(m: &FactModel) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in m.entities.iter().filter(|e| e.kind == EntityKind::Service) {
        let seccomp = e.attr("seccomp_disabled").and_then(|v| v.as_bool()) == Some(true);
        let apparmor = e.attr("apparmor_disabled").and_then(|v| v.as_bool()) == Some(true);
        if seccomp || apparmor {
            let which = match (seccomp, apparmor) {
                (true, true) => "seccomp and AppArmor",
                (true, false) => "seccomp",
                _ => "AppArmor",
            };
            out.push(finding(
                "SECURITY-PROFILE-DISABLED",
                &["CWE-693", "CIS-Docker-5.1"],
                Severity::High,
                &e.id,
                format!("Service '{}' disables {which} (unconfined) — removes a key kernel-hardening layer that blocks dangerous syscalls", svc_name(&e.id)),
                "Remove the 'seccomp:unconfined' / 'apparmor:unconfined' security_opt; use the default profiles or a scoped custom one.",
            ));
        }
    }
    out
}

// --- R14: host user namespace ---------------------------------------------
fn r_host_userns(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Service)
        .filter(|e| e.attr("userns_mode").and_then(|v| v.as_str()) == Some("host"))
        .map(|e| {
            finding(
                "HOST-USERNS-MODE",
                &["CWE-281", "CIS-Docker-5.30"],
                Severity::High,
                &e.id,
                format!("Service '{}' uses userns_mode: host — disables user-namespace remapping, so root in the container is root on the host", svc_name(&e.id)),
                "Remove 'userns_mode: host' and enable user-namespace remapping for the daemon.",
            )
        })
        .collect()
}

// --- R15: cap_add ALL -----------------------------------------------------
fn r_cap_add_all(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::Capability)
        .filter(|e| {
            e.attr("cap")
                .and_then(|v| v.as_str())
                .map(|c| c.eq_ignore_ascii_case("ALL"))
                == Some(true)
        })
        .map(|e| {
            finding(
                "CAP-ADD-ALL",
                &["CWE-250", "CIS-Docker-5.3"],
                Severity::Critical,
                &e.id,
                "Service grants ALL Linux capabilities (cap_add: ALL) — equivalent to running privileged; trivially escapable to the host".into(),
                "Remove 'cap_add: [ALL]'; drop all caps ('cap_drop: [ALL]') and add back only the few the workload needs.",
            )
        })
        .collect()
}

// --- R16: database authentication disabled --------------------------------
fn r_database_auth_disabled(m: &FactModel) -> Vec<Finding> {
    m.entities
        .iter()
        .filter(|e| e.kind == EntityKind::EnvVar)
        .filter(|e| e.attr("disables_auth").and_then(|v| v.as_bool()) == Some(true))
        .map(|e| {
            let name = e.attr("name").and_then(|v| v.as_str()).unwrap_or("?");
            finding(
                "DATABASE-AUTH-DISABLED",
                &["CWE-287", "CWE-1392"],
                Severity::High,
                &e.id,
                format!("Environment variable '{name}' disables database authentication (empty-password / trust mode) — anyone who can reach the database connects with no credentials"),
                "Remove the empty-password/trust switch and set a strong password (injected via secrets), or restrict the database to an internal network.",
            )
        })
        .collect()
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

// --- Attack-path rule (cross-resource graph traversal) -------------------
//
// Unlike the single-resource rules above, this reasons over the whole graph:
// it finds services that are internet-reachable (publish a port on 0.0.0.0),
// then walks `depends_on` edges to see if that reachable surface has a path to
// a service holding a weak/default credential. That chain — reachable -> ... ->
// weak secret — is the actual exploitable path, which flat per-resource scanners
// and one-shot LLM reviews don't surface deterministically.
struct GraphCtx<'a> {
    by_id: HashMap<&'a str, &'a Entity>,
    services: HashSet<&'a str>,
    exposed: HashSet<&'a str>,
    deps: HashMap<&'a str, Vec<&'a str>>,
}

/// Precompute the shared graph context: id lookup, services, internet-reachable
/// entry points (publish a port on 0.0.0.0), and depends_on adjacency.
fn graph_ctx(m: &FactModel) -> GraphCtx<'_> {
    let by_id: HashMap<&str, &Entity> = m.entities.iter().map(|e| (e.id.as_str(), e)).collect();
    let services: HashSet<&str> = m
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Service)
        .map(|e| e.id.as_str())
        .collect();
    let mut exposed: HashSet<&str> = HashSet::new();
    let mut deps: HashMap<&str, Vec<&str>> = HashMap::new();
    for r in &m.relations {
        match r.kind {
            RelationKind::Exposes => {
                if by_id
                    .get(r.to.as_str())
                    .and_then(|e| e.attr("host_ip"))
                    .and_then(|v| v.as_str())
                    == Some("0.0.0.0")
                {
                    exposed.insert(r.from.as_str());
                }
            }
            RelationKind::DependsOn => {
                deps.entry(r.from.as_str()).or_default().push(r.to.as_str());
            }
            _ => {}
        }
    }
    GraphCtx { by_id, services, exposed, deps }
}

/// BFS from each internet-reachable service over depends_on edges, returning the
/// ordered service chain (entry .. target) to each service matching `is_target`.
fn reachable_paths<'a>(ctx: &GraphCtx<'a>, is_target: impl Fn(&str) -> bool) -> Vec<Vec<&'a str>> {
    let mut results = Vec::new();
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let mut entries: Vec<&str> = ctx.exposed.iter().copied().collect();
    entries.sort();
    for entry in entries {
        let mut pred: HashMap<&str, &str> = HashMap::new();
        let mut visited: HashSet<&str> = HashSet::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        queue.push_back(entry);
        visited.insert(entry);
        while let Some(node) = queue.pop_front() {
            if is_target(node) && seen.insert((entry, node)) {
                let mut path = vec![node];
                let mut cur = node;
                while let Some(&p) = pred.get(cur) {
                    path.push(p);
                    cur = p;
                }
                path.reverse();
                results.push(path);
            }
            if let Some(adj) = ctx.deps.get(node) {
                for &n in adj {
                    if ctx.services.contains(n) && visited.insert(n) {
                        pred.insert(n, node);
                        queue.push_back(n);
                    }
                }
            }
        }
    }
    results
}

fn r_reachable_weak_credential(m: &FactModel) -> Vec<Finding> {
    let ctx = graph_ctx(m);
    if ctx.exposed.is_empty() {
        return Vec::new();
    }
    let mut weak_cred: HashMap<&str, &str> = HashMap::new();
    for r in &m.relations {
        if r.kind == RelationKind::Reads {
            if let Some(ev) = ctx.by_id.get(r.to.as_str()) {
                if ev.kind == EntityKind::EnvVar
                    && ev.attr("value_is_weak_default").and_then(|v| v.as_bool()) == Some(true)
                {
                    weak_cred.entry(r.from.as_str()).or_insert(r.to.as_str());
                }
            }
        }
    }
    if weak_cred.is_empty() {
        return Vec::new();
    }
    let remediation = "Don't expose this service directly — put it behind a gateway/reverse \
        proxy, bind the port to 127.0.0.1, and replace weak/default credentials with strong secrets.";
    let mut out = Vec::new();
    for path in reachable_paths(&ctx, |s| weak_cred.contains_key(s)) {
        let entry = path[0];
        let target = *path.last().unwrap();
        let env_id = weak_cred[target];
        let env_name = ctx
            .by_id
            .get(env_id)
            .and_then(|e| e.attr("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let message = if entry == target {
            format!("Service '{}' is reachable on all interfaces AND uses a weak/default credential ('{env_name}') — an attacker reaching it gets a working credential", svc_name(entry))
        } else {
            format!("Internet-reachable service '{}' has a dependency path to '{}', which uses a weak/default credential ('{env_name}') — reaching '{}' opens a pivot to a weakly-protected service", svc_name(entry), svc_name(target), svc_name(entry))
        };
        // Evidence is the ordered path (services) + the offending resource, so the
        // UI can highlight the whole chain on the dependency map.
        let mut evidence: Vec<String> = path.iter().map(|s| s.to_string()).collect();
        evidence.push(env_id.to_string());
        out.push(Finding {
            rule_id: "REACHABLE-WEAK-CREDENTIAL".to_string(),
            controls: vec!["CWE-668".to_string(), "CWE-1390".to_string()],
            severity: Severity::High,
            evidence,
            message,
            remediation: remediation.to_string(),
            lines: Vec::new(),
        });
    }
    out
}

fn r_reachable_host_takeover(m: &FactModel) -> Vec<Finding> {
    let ctx = graph_ctx(m);
    if ctx.exposed.is_empty() {
        return Vec::new();
    }
    // Host-control surfaces, each with a reason and the resource id (if any):
    // a service that mounts the Docker socket, runs privileged, or holds a
    // dangerous capability — any of which turns container compromise into host
    // takeover.
    let mut takeover: HashMap<&str, (&'static str, Option<&str>)> = HashMap::new();
    for r in &m.relations {
        match r.kind {
            RelationKind::Mounts => {
                if ctx.by_id.get(r.to.as_str()).and_then(|e| e.attr("source")).and_then(|v| v.as_str())
                    == Some("/var/run/docker.sock")
                {
                    takeover.entry(r.from.as_str()).or_insert(("mounts the Docker socket", Some(r.to.as_str())));
                }
            }
            RelationKind::GrantsCapability => {
                if let Some(cap) = ctx.by_id.get(r.to.as_str()).and_then(|e| e.attr("cap")).and_then(|v| v.as_str()) {
                    if DANGEROUS_CAPS.contains(&cap) {
                        takeover.entry(r.from.as_str()).or_insert(("holds a dangerous capability", Some(r.to.as_str())));
                    }
                }
            }
            _ => {}
        }
    }
    for e in m.entities.iter().filter(|e| e.kind == EntityKind::Service) {
        if e.attr("privileged").and_then(|v| v.as_bool()) == Some(true) {
            takeover.entry(e.id.as_str()).or_insert(("runs privileged", None));
        }
    }
    if takeover.is_empty() {
        return Vec::new();
    }
    let remediation = "Keep host-control surfaces off any internet-reachable path: don't expose the front-end directly, and don't mount the Docker socket, run privileged, or grant dangerous capabilities on services it can reach.";
    let mut out = Vec::new();
    for path in reachable_paths(&ctx, |s| takeover.contains_key(s)) {
        let entry = path[0];
        let target = *path.last().unwrap();
        let (reason, reason_id) = takeover[target];
        let message = if entry == target {
            format!("Service '{}' is internet-reachable AND {reason} — compromising it means full host takeover", svc_name(entry))
        } else {
            format!("Internet-reachable service '{}' has a dependency path to '{}', which {reason} — reaching '{}' chains to host takeover", svc_name(entry), svc_name(target), svc_name(entry))
        };
        let mut evidence: Vec<String> = path.iter().map(|s| s.to_string()).collect();
        if let Some(mid) = reason_id {
            evidence.push(mid.to_string());
        }
        out.push(Finding {
            rule_id: "REACHABLE-HOST-TAKEOVER".to_string(),
            controls: vec!["CWE-668".to_string(), "CWE-250".to_string()],
            severity: Severity::Critical,
            evidence,
            message,
            remediation: remediation.to_string(),
            lines: Vec::new(),
        });
    }
    out
}

/// Static catalog of every rule this pack can emit (for the in-app catalog).
/// Keep in sync with the rule functions above.
pub fn catalog() -> Vec<engine::RuleMeta> {
    use engine::RuleMeta;
    use engine::Severity::{Critical, High, Low, Medium};
    let t = "Docker Compose";
    vec![
        RuleMeta { id: "DOCKER-SOCKET-MOUNT", title: "Docker socket mounted", target: t, severity: Critical, controls: &["CWE-250", "CIS-Docker-5.31"], summary: "A container bind-mounts /var/run/docker.sock, giving it full control of the Docker daemon — effectively root on the host.", fix: "Remove the mount; if daemon access is required, use a scoped socket proxy, read-only.", strict: false },
        RuleMeta { id: "REACHABLE-HOST-TAKEOVER", title: "Reachable host-takeover path", target: t, severity: Critical, controls: &["CWE-668", "CWE-250"], summary: "Cross-resource: an internet-reachable service has a depends_on path to a service that mounts the Docker socket or runs privileged — reaching the front door chains to full host compromise.", fix: "Keep docker.sock/privileged off any internet-reachable path; don't expose the front-end directly.", strict: false },
        RuleMeta { id: "PRIVILEGED-CONTAINER", title: "Privileged container", target: t, severity: Critical, controls: &["CWE-250", "CIS-Docker-5.4"], summary: "privileged: true disables container isolation — near-equivalent to root on the host.", fix: "Drop 'privileged'; grant only the specific capabilities required.", strict: false },
        RuleMeta { id: "CAP-ADD-ALL", title: "All capabilities granted", target: t, severity: Critical, controls: &["CWE-250", "CIS-Docker-5.3"], summary: "cap_add: [ALL] grants every Linux capability — equivalent to privileged and trivially escapable to the host.", fix: "Remove cap_add: ALL; drop all caps and add back only the few needed.", strict: false },
        RuleMeta { id: "DANGEROUS-CAPABILITY", title: "Dangerous capability added", target: t, severity: High, controls: &["CWE-250", "CIS-Docker-5.3"], summary: "cap_add grants a high-risk Linux capability (e.g. SYS_ADMIN, NET_ADMIN) that can enable container escape.", fix: "Remove the capability; if required, justify and isolate the workload.", strict: false },
        RuleMeta { id: "HOST-NETWORK-MODE", title: "Host network mode", target: t, severity: High, controls: &["CWE-668", "CIS-Docker-5.9"], summary: "network_mode: host removes network namespace isolation; the container shares the host's network stack.", fix: "Use a user-defined bridge network and publish only the needed ports.", strict: false },
        RuleMeta { id: "WEAK-DEFAULT-CREDENTIAL", title: "Weak / default credential", target: t, severity: High, controls: &["CWE-798", "CWE-1392"], summary: "A secret-like env var is set to a weak or default value (admin, password, changeme…).", fix: "Set a strong unique secret; inject via a secrets manager, not inline.", strict: false },
        RuleMeta { id: "DATABASE-AUTH-DISABLED", title: "Database auth disabled", target: t, severity: High, controls: &["CWE-287", "CWE-1392"], summary: "An env var disables database authentication entirely (MYSQL_ALLOW_EMPTY_PASSWORD, POSTGRES_HOST_AUTH_METHOD=trust, …) — anyone who reaches the DB connects with no credentials.", fix: "Remove the empty-password/trust switch; set a strong password and restrict the DB to an internal network.", strict: false },
        RuleMeta { id: "REACHABLE-WEAK-CREDENTIAL", title: "Reachable weak-credential path", target: t, severity: High, controls: &["CWE-668", "CWE-1390"], summary: "Cross-resource: an internet-reachable service (0.0.0.0 port) has a depends_on path to a service that uses a weak/default credential — an exploitable chain, not a single flag.", fix: "Don't expose the service directly; bind to 127.0.0.1 or use a gateway, and replace weak/default credentials.", strict: false },
        RuleMeta { id: "SENSITIVE-HOST-PATH-MOUNT", title: "Sensitive host path mounted", target: t, severity: High, controls: &["CWE-552", "CWE-668"], summary: "A sensitive host directory (/, /etc, /proc, /sys, …) is bind-mounted into a container.", fix: "Remove the bind mount or scope it to a specific non-sensitive subdirectory (read-only).", strict: false },
        RuleMeta { id: "HOST-PID-NAMESPACE", title: "Host PID namespace", target: t, severity: High, controls: &["CWE-668", "CIS-Docker-5.15"], summary: "pid: host shares the host PID namespace — the container can see and signal host processes.", fix: "Remove 'pid: host'; containers should use their own PID namespace.", strict: false },
        RuleMeta { id: "HOST-IPC-NAMESPACE", title: "Host IPC namespace", target: t, severity: High, controls: &["CWE-668", "CIS-Docker-5.16"], summary: "ipc: host shares the host IPC namespace — breaks process isolation.", fix: "Remove 'ipc: host'; containers should use their own IPC namespace.", strict: false },
        RuleMeta { id: "SECURITY-PROFILE-DISABLED", title: "Seccomp/AppArmor disabled", target: t, severity: High, controls: &["CWE-693", "CIS-Docker-5.1"], summary: "security_opt sets seccomp:unconfined or apparmor:unconfined, removing a kernel-hardening layer that blocks dangerous syscalls.", fix: "Use the default seccomp/AppArmor profiles or a scoped custom one.", strict: false },
        RuleMeta { id: "HOST-USERNS-MODE", title: "Host user namespace", target: t, severity: High, controls: &["CWE-281", "CIS-Docker-5.30"], summary: "userns_mode: host disables user-namespace remapping, so root in the container maps to root on the host.", fix: "Remove 'userns_mode: host' and enable user-namespace remapping.", strict: false },
        RuleMeta { id: "SECRET-IN-ENVIRONMENT", title: "Secret in environment", target: t, severity: Medium, controls: &["CWE-256", "CWE-798"], summary: "A secret-like env var has an inline literal value — it ends up in version control and `docker inspect`.", fix: "Use Compose/Docker secrets or an external secrets manager; reference, don't inline.", strict: false },
        RuleMeta { id: "SENSITIVE-PORT-PUBLISHED-ALL-IFACES", title: "Datastore port on all interfaces", target: t, severity: Medium, controls: &["CWE-668"], summary: "A database/cache/admin port is published on 0.0.0.0 — often reachable externally.", fix: "Bind to 127.0.0.1 or an internal network; do not publish datastores.", strict: false },
        RuleMeta { id: "IMAGE-UNPINNED", title: "Image not pinned by digest", target: t, severity: Low, controls: &["CWE-494", "CWE-1357"], summary: "An image uses a tag (or :latest) rather than a digest — what runs can change silently.", fix: "Pin by digest (image@sha256:…).", strict: false },
        RuleMeta { id: "CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN", title: "Runs as root / unknown user", target: t, severity: Low, controls: &["CWE-250", "CIS-Docker-4.1"], summary: "The service runs as root, or no user is declared so it can't be confirmed non-root.", fix: "Set a non-root 'user:'; declare it explicitly even if the base image sets one.", strict: false },
        RuleMeta { id: "WRITABLE-ROOT-FILESYSTEM", title: "Writable root filesystem", target: t, severity: Low, controls: &["CWE-732", "CIS-Docker-5.12"], summary: "read_only is not set, so an attacker can persist tooling in the container filesystem.", fix: "Set 'read_only: true' and mount specific writable paths as tmpfs/volumes.", strict: false },
        RuleMeta { id: "PORT-PUBLISHED-ALL-IFACES", title: "Port on all interfaces", target: t, severity: Low, controls: &["CWE-668"], summary: "A port is published on 0.0.0.0 — reachable from any interface.", fix: "Bind to a specific interface (e.g. 127.0.0.1) unless external access is intended.", strict: false },
        RuleMeta { id: "NO-NEW-PRIVILEGES-MISSING", title: "no-new-privileges not set", target: t, severity: Low, controls: &["CWE-250"], summary: "Processes can gain privileges via setuid binaries because no-new-privileges isn't set.", fix: "Add 'security_opt: [\"no-new-privileges:true\"]'.", strict: true },
        RuleMeta { id: "CAP-DROP-ALL-MISSING", title: "Capabilities not dropped", target: t, severity: Low, controls: &["CWE-250"], summary: "The service keeps Docker's default capability set instead of dropping all and adding back only what's needed.", fix: "Add 'cap_drop: [ALL]' and 'cap_add' only the capabilities you need.", strict: true },
        RuleMeta { id: "NO-RESOURCE-LIMITS", title: "No memory limit", target: t, severity: Low, controls: &["CWE-400"], summary: "No memory limit is set — a runaway container can exhaust host memory (DoS).", fix: "Set a memory limit (deploy.resources.limits.memory, or mem_limit in v2).", strict: true },
    ]
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
            Box::new(FnRule { id: "SECURITY-PROFILE-DISABLED", f: r_security_profile_disabled }),
            Box::new(FnRule { id: "HOST-USERNS-MODE", f: r_host_userns }),
            Box::new(FnRule { id: "CAP-ADD-ALL", f: r_cap_add_all }),
            Box::new(FnRule { id: "DATABASE-AUTH-DISABLED", f: r_database_auth_disabled }),
            Box::new(FnRule { id: "REACHABLE-WEAK-CREDENTIAL", f: r_reachable_weak_credential }),
            Box::new(FnRule { id: "REACHABLE-HOST-TAKEOVER", f: r_reachable_host_takeover }),
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
                provenance: Provenance::explicit(String::new()),
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
