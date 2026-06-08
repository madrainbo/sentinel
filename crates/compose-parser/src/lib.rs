//! Docker Compose -> FactModel.
//!
//! Spec: `docs/parsers/docker-compose-v0.md`. Deterministic, no LLM.
//! v0 covers the service keys the first rule pack needs.
#![allow(clippy::needless_range_loop)]

use std::collections::BTreeMap;

use fact_model::{
    sha256_prefixed, AttrValue, Entity, EntityKind, FactModel, Origin, Provenance, Relation,
    RelationKind, SourceDescriptor,
};
use yaml_rust2::yaml::Hash as YamlHash;
use yaml_rust2::{Yaml, YamlLoader};

pub const PARSER_VERSION: &str = "0.1.0";

/// Secret-like env var name fragments (uppercased, underscores removed).
const SECRET_NAME_FRAGMENTS: &[&str] = &[
    "PASSWORD", "PASSWD", "PWD", "SECRET", "TOKEN", "APIKEY", "ACCESSKEY", "PRIVATEKEY",
    "CREDENTIAL",
];

/// Weak / default credential values (lowercased).
const WEAK_VALUES: &[&str] = &[
    "admin", "password", "root", "changeme", "123456", "secret", "test", "guest", "",
];

/// Capabilities considered dangerous (used by the pack, exposed for reuse).
pub const DANGEROUS_CAPS: &[&str] =
    &["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH"];

/// Sensitive target ports (datastores / admin / daemon).
pub const SENSITIVE_PORTS: &[i64] =
    &[5432, 3306, 6379, 27017, 9200, 5984, 11211, 2375, 2376];

struct Builder {
    entities: Vec<Entity>,
    relations: Vec<Relation>,
}

impl Builder {
    fn entity(&mut self, e: Entity) {
        self.entities.push(e);
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

/// Parse a Docker Compose document into the fact model, returning an empty model
/// on invalid YAML. Prefer [`try_parse`] when you need to surface parse errors.
pub fn parse(input: &str) -> FactModel {
    try_parse(input).unwrap_or_else(|_| FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "docker_compose".to_string(),
            input_hash: sha256_prefixed(input.as_bytes()),
            parser_version: PARSER_VERSION.to_string(),
        },
        entities: Vec::new(),
        relations: Vec::new(),
    })
}

/// Parse a Docker Compose document, returning a human-readable error on invalid
/// YAML. A valid document with no `services:` yields an empty (but Ok) model.
pub fn try_parse(input: &str) -> Result<FactModel, String> {
    // Tolerate a leading UTF-8 BOM (common from Windows editors).
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let input_hash = sha256_prefixed(input.as_bytes());
    let mut b = Builder {
        entities: Vec::new(),
        relations: Vec::new(),
    };

    let docs = YamlLoader::load_from_str(input).map_err(|e| format!("invalid YAML: {e}"))?;
    if let Some(doc) = docs.first() {
        if let Some(services) = doc["services"].as_hash() {
            for (name_y, svc) in services {
                if let Some(name) = name_y.as_str() {
                    // Resolve YAML merge keys (`<<`) so anchored services are
                    // assessed with their inherited keys.
                    let merged = merge_anchors(svc);
                    parse_service(&mut b, name, &merged);
                }
            }
        }
    }

    Ok(FactModel {
        schema_version: "0".to_string(),
        source: SourceDescriptor {
            kind: "docker_compose".to_string(),
            input_hash,
            parser_version: PARSER_VERSION.to_string(),
        },
        entities: b.entities,
        relations: b.relations,
    })
}

/// Resolve YAML merge keys (`<<: *anchor` or `<<: [*a, *b]`) into a flat hash.
/// Explicit keys win over merged ones; merge sources are resolved recursively.
fn merge_anchors(node: &Yaml) -> Yaml {
    let h = match node.as_hash() {
        Some(h) => h,
        None => return node.clone(),
    };
    let mut out = YamlHash::new();
    if let Some(mv) = h.get(&Yaml::String("<<".to_string())) {
        let sources: Vec<&Yaml> = match mv {
            Yaml::Array(arr) => arr.iter().collect(),
            other => vec![other],
        };
        for s in sources {
            if let Some(sh) = merge_anchors(s).into_hash() {
                for (k, v) in sh {
                    out.insert(k, v);
                }
            }
        }
    }
    for (k, v) in h {
        if k.as_str() == Some("<<") {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    Yaml::Hash(out)
}

fn parse_service(b: &mut Builder, name: &str, svc: &Yaml) {
    let svc_id = format!("service:{name}");
    let base = format!("services.{name}");
    let mut attrs: BTreeMap<String, AttrValue> = BTreeMap::new();

    // privileged (default false)
    attrs.insert(
        "privileged".into(),
        AttrValue::Bool(svc["privileged"].as_bool().unwrap_or(false)),
    );
    // network_mode (default bridge)
    attrs.insert(
        "network_mode".into(),
        AttrValue::Enum(svc["network_mode"].as_str().unwrap_or("bridge").to_string()),
    );
    // read_only root fs (default false)
    attrs.insert(
        "read_only_root_fs".into(),
        AttrValue::Bool(svc["read_only"].as_bool().unwrap_or(false)),
    );
    // runs_as: root | nonroot | unknown
    attrs.insert("runs_as".into(), parse_runs_as(svc));
    // pid / ipc namespace modes ("" = not set)
    attrs.insert(
        "pid_mode".into(),
        AttrValue::Enum(svc["pid"].as_str().unwrap_or("").to_string()),
    );
    attrs.insert(
        "ipc_mode".into(),
        AttrValue::Enum(svc["ipc"].as_str().unwrap_or("").to_string()),
    );
    // hardening flags (used by --strict rules)
    attrs.insert(
        "no_new_privileges".into(),
        AttrValue::Bool(yaml_list_contains(&svc["security_opt"], "no-new-privileges:true")),
    );
    attrs.insert(
        "caps_dropped_all".into(),
        AttrValue::Bool(yaml_list_contains(&svc["cap_drop"], "ALL")),
    );
    attrs.insert(
        "has_mem_limit".into(),
        AttrValue::Bool(
            !svc["mem_limit"].is_badvalue()
                || !svc["deploy"]["resources"]["limits"]["memory"].is_badvalue(),
        ),
    );

    b.entity(Entity {
        id: svc_id.clone(),
        kind: EntityKind::Service,
        attributes: attrs,
        provenance: Provenance {
            source_path: base.clone(),
            origin: Origin::Explicit,
        },
    });

    // image
    if let Some(img) = svc["image"].as_str() {
        parse_image(b, &svc_id, &base, img);
    }
    // ports
    if let Some(ports) = svc["ports"].as_vec() {
        for (i, p) in ports.iter().enumerate() {
            parse_port(b, name, &svc_id, &format!("{base}.ports[{i}]"), p);
        }
    }
    // volumes (bind mounts)
    if let Some(vols) = svc["volumes"].as_vec() {
        for (i, v) in vols.iter().enumerate() {
            parse_volume(b, name, &svc_id, &format!("{base}.volumes[{i}]"), v);
        }
    }
    // environment (hash or array)
    parse_environment(b, name, &svc_id, &base, &svc["environment"]);
    // cap_add
    if let Some(caps) = svc["cap_add"].as_vec() {
        for c in caps {
            if let Some(cap) = c.as_str() {
                let cid = format!("capability:{name}/{cap}");
                let mut a = BTreeMap::new();
                a.insert("cap".into(), AttrValue::Str(cap.to_string()));
                b.entity(Entity {
                    id: cid.clone(),
                    kind: EntityKind::Capability,
                    attributes: a,
                    provenance: Provenance {
                        source_path: format!("{base}.cap_add"),
                        origin: Origin::Explicit,
                    },
                });
                b.relation(RelationKind::GrantsCapability, &svc_id, &cid);
            }
        }
    }
    // depends_on (array or hash)
    if let Some(deps) = svc["depends_on"].as_vec() {
        for d in deps {
            if let Some(dep) = d.as_str() {
                b.relation(RelationKind::DependsOn, &svc_id, &format!("service:{dep}"));
            }
        }
    } else if let Some(deps) = svc["depends_on"].as_hash() {
        for (k, _) in deps {
            if let Some(dep) = k.as_str() {
                b.relation(RelationKind::DependsOn, &svc_id, &format!("service:{dep}"));
            }
        }
    }
}

fn parse_runs_as(svc: &Yaml) -> AttrValue {
    let user = &svc["user"];
    let val = user
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| user.as_i64().map(|i| i.to_string()));
    match val {
        Some(u) => {
            let uid = u.split(':').next().unwrap_or(&u);
            if uid == "root" || uid == "0" {
                AttrValue::Enum("root".into())
            } else {
                AttrValue::Enum("nonroot".into())
            }
        }
        // Compose can't see the image's USER -> genuinely unknown, flag (R9).
        None => AttrValue::Unknown,
    }
}

fn split_repo_tag(s: &str) -> (String, Option<String>) {
    let last_seg_start = s.rfind('/').map(|i| i + 1).unwrap_or(0);
    if let Some(rel) = s[last_seg_start..].find(':') {
        let colon = last_seg_start + rel;
        (s[..colon].to_string(), Some(s[colon + 1..].to_string()))
    } else {
        (s.to_string(), None)
    }
}

fn parse_image(b: &mut Builder, svc_id: &str, base: &str, img: &str) {
    let (repo, tag, digest_pinned) = if let Some(idx) = img.find("@sha256:") {
        let (repo, tag) = split_repo_tag(&img[..idx]);
        (repo, tag, true)
    } else {
        let (repo, tag) = split_repo_tag(img);
        (repo, tag, false)
    };

    let id = format!("image:{img}");
    let mut a = BTreeMap::new();
    a.insert("repo".into(), AttrValue::Str(repo));
    match &tag {
        Some(t) => a.insert("tag".into(), AttrValue::Str(t.clone())),
        None => a.insert("tag".into(), AttrValue::Str("latest".into())),
    };
    a.insert("digest_pinned".into(), AttrValue::Bool(digest_pinned));

    b.entity(Entity {
        id: id.clone(),
        kind: EntityKind::Image,
        attributes: a,
        provenance: Provenance {
            source_path: format!("{base}.image"),
            origin: Origin::Explicit,
        },
    });
    b.relation(RelationKind::Uses, svc_id, &id);
}

fn parse_port(b: &mut Builder, svc: &str, svc_id: &str, path: &str, p: &Yaml) {
    // Long syntax: a mapping with target/published/host_ip/protocol keys.
    if p.as_hash().is_some() {
        let target = p["target"]
            .as_i64()
            .map(|i| i.to_string())
            .or_else(|| p["target"].as_str().map(|s| s.to_string()));
        let target = match target {
            Some(t) => t,
            None => return,
        };
        let published = p["published"]
            .as_i64()
            .map(|i| i.to_string())
            .or_else(|| p["published"].as_str().map(|s| s.to_string()));
        let (host_ip, host_ip_default) = match p["host_ip"].as_str() {
            Some(h) => (h.to_string(), false),
            None => ("0.0.0.0".to_string(), true),
        };
        let proto = p["protocol"].as_str().unwrap_or("tcp").to_string();
        emit_port(b, svc, svc_id, path, published, target, host_ip, host_ip_default, proto);
        return;
    }

    // Short syntax: "[host_ip:][published:]target[/proto]" or a bare integer.
    let spec = match p.as_str() {
        Some(s) => s.to_string(),
        None => match p.as_i64() {
            Some(i) => i.to_string(),
            None => return,
        },
    };

    let (main, proto) = match spec.rfind('/') {
        Some(i) => (spec[..i].to_string(), spec[i + 1..].to_string()),
        None => (spec.clone(), "tcp".to_string()),
    };
    let parts: Vec<&str> = main.split(':').collect();
    let (host_ip, host_ip_default, published, target) = match parts.len() {
        1 => ("0.0.0.0".to_string(), true, None, parts[0].to_string()),
        2 => (
            "0.0.0.0".to_string(),
            true,
            Some(parts[0].to_string()),
            parts[1].to_string(),
        ),
        _ => (
            parts[0].to_string(),
            false,
            Some(parts[1].to_string()),
            parts[2].to_string(),
        ),
    };

    emit_port(b, svc, svc_id, path, published, target, host_ip, host_ip_default, proto);
}

#[allow(clippy::too_many_arguments)]
fn emit_port(
    b: &mut Builder,
    svc: &str,
    svc_id: &str,
    path: &str,
    published: Option<String>,
    target: String,
    host_ip: String,
    host_ip_default: bool,
    proto: String,
) {
    let pub_label = published.clone().unwrap_or_else(|| "x".to_string());
    let id = format!("port_binding:{svc}/{pub_label}-{target}/{proto}");
    let mut a = BTreeMap::new();
    match published.as_ref().and_then(|s| s.parse::<i64>().ok()) {
        Some(n) => a.insert("published".into(), AttrValue::Int(n)),
        None => a.insert("published".into(), AttrValue::Unknown),
    };
    match target.parse::<i64>() {
        Ok(n) => a.insert("target".into(), AttrValue::Int(n)),
        Err(_) => a.insert("target".into(), AttrValue::Str(target.clone())),
    };
    a.insert("host_ip".into(), AttrValue::Str(host_ip));
    a.insert("protocol".into(), AttrValue::Enum(proto));

    b.entity(Entity {
        id: id.clone(),
        kind: EntityKind::PortBinding,
        attributes: a,
        provenance: Provenance {
            source_path: path.to_string(),
            origin: if host_ip_default {
                Origin::Default
            } else {
                Origin::Explicit
            },
        },
    });
    b.relation(RelationKind::Exposes, svc_id, &id);
}

fn parse_volume(b: &mut Builder, svc: &str, svc_id: &str, path: &str, v: &Yaml) {
    // Long syntax: a mapping with type/source/target/read_only.
    if v.as_hash().is_some() {
        if let (Some(source), Some(target)) = (v["source"].as_str(), v["target"].as_str()) {
            let read_only = v["read_only"].as_bool().unwrap_or(false);
            emit_volume(b, svc, svc_id, path, source, target, read_only);
        }
        return;
    }

    // Short syntax: "source:target[:mode]".
    let spec = match v.as_str() {
        Some(s) => s.to_string(),
        None => return,
    };
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() < 2 {
        return; // anonymous volume; nothing to assess
    }
    let read_only = parts.get(2).map(|m| *m == "ro").unwrap_or(false);
    emit_volume(b, svc, svc_id, path, parts[0], parts[1], read_only);
}

/// Emit a Mount (bind mount with a host path) or a Volume (named volume). Only
/// bind mounts carry a host path, so only they are subject to host-path rules.
fn emit_volume(b: &mut Builder, svc: &str, svc_id: &str, path: &str, source: &str, target: &str, read_only: bool) {
    let is_bind =
        source.starts_with('/') || source.starts_with('.') || source.starts_with('~');

    let (id, kind) = if is_bind {
        (format!("mount:{svc}:{source}->{target}"), EntityKind::Mount)
    } else {
        (format!("volume:{source}"), EntityKind::Volume)
    };

    let mut a = BTreeMap::new();
    a.insert("source".into(), AttrValue::Str(source.to_string()));
    a.insert("target".into(), AttrValue::Str(target.to_string()));
    a.insert("read_only".into(), AttrValue::Bool(read_only));

    b.entity(Entity {
        id: id.clone(),
        kind,
        attributes: a,
        provenance: Provenance {
            source_path: path.to_string(),
            origin: Origin::Explicit,
        },
    });
    b.relation(RelationKind::Mounts, svc_id, &id);
}

/// True if a YAML sequence contains the given string (case-insensitive).
fn yaml_list_contains(y: &Yaml, needle: &str) -> bool {
    y.as_vec().is_some_and(|items| {
        items
            .iter()
            .any(|i| i.as_str().is_some_and(|s| s.eq_ignore_ascii_case(needle)))
    })
}

fn is_secret_like(name: &str) -> bool {
    let upper = name.to_uppercase();
    // `*_FILE` points to a secret file (the recommended Docker secrets pattern) —
    // it is a path, not an inline secret, so don't treat it as secret-bearing.
    if upper.ends_with("_FILE") {
        return false;
    }
    let norm: String = upper.chars().filter(|c| *c != '_').collect();
    SECRET_NAME_FRAGMENTS.iter().any(|frag| norm.contains(frag))
}

fn parse_environment(b: &mut Builder, svc: &str, svc_id: &str, base: &str, env: &Yaml) {
    let mut pairs: Vec<(String, Option<String>)> = Vec::new();
    if let Some(hash) = env.as_hash() {
        for (k, v) in hash {
            if let Some(name) = k.as_str() {
                let val = v
                    .as_str()
                    .map(|s| s.to_string())
                    .or_else(|| v.as_i64().map(|i| i.to_string()))
                    .or_else(|| v.as_bool().map(|x| x.to_string()));
                pairs.push((name.to_string(), val));
            }
        }
    } else if let Some(arr) = env.as_vec() {
        for item in arr {
            if let Some(s) = item.as_str() {
                match s.split_once('=') {
                    Some((k, v)) => pairs.push((k.to_string(), Some(v.to_string()))),
                    None => pairs.push((s.to_string(), None)),
                }
            }
        }
    }

    for (name, val) in pairs {
        let secret_like = is_secret_like(&name);
        // A "${...}" placeholder or absent value is a reference, not an inline literal.
        let has_inline = match &val {
            Some(v) => !(v.starts_with("${") || v.is_empty() && val.is_none()),
            None => false,
        };
        let weak = match &val {
            Some(v) => WEAK_VALUES.contains(&v.to_lowercase().as_str()),
            None => false,
        };

        let id = format!("env_var:{svc}/{name}");
        let mut a = BTreeMap::new();
        a.insert("name".into(), AttrValue::Str(name.clone()));
        a.insert(
            "value_class".into(),
            AttrValue::Enum(if secret_like { "secret_like" } else { "normal" }.into()),
        );
        a.insert("has_inline_value".into(), AttrValue::Bool(has_inline));
        a.insert(
            "value_is_weak_default".into(),
            AttrValue::Bool(secret_like && weak && has_inline),
        );

        b.entity(Entity {
            id: id.clone(),
            kind: EntityKind::EnvVar,
            attributes: a,
            provenance: Provenance {
                source_path: format!("{base}.environment.{name}"),
                origin: Origin::Explicit,
            },
        });
        b.relation(RelationKind::Reads, svc_id, &id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn determinism_same_input_same_hash() {
        let yaml = "services:\n  web:\n    image: nginx:latest\n    ports: [\"8080:80\"]\n";
        let a = parse(yaml).model_hash();
        let b = parse(yaml).model_hash();
        assert_eq!(a, b);
    }

    #[test]
    fn merge_keys_are_resolved() {
        let yaml = "x-base: &base\n  privileged: true\n  image: nginx:1.25\nservices:\n  app:\n    <<: *base\n";
        let fm = parse(yaml);
        let svc = fm
            .entities
            .iter()
            .find(|e| e.id == "service:app")
            .expect("service entity");
        assert_eq!(svc.attr("privileged").and_then(|v| v.as_bool()), Some(true));
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Image));
    }

    #[test]
    fn long_syntax_volume_is_parsed_as_bind_mount() {
        let yaml = "services:\n  app:\n    image: nginx:1.25\n    volumes:\n      - type: bind\n        source: /var/run/docker.sock\n        target: /var/run/docker.sock\n";
        let fm = parse(yaml);
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Mount
            && e.attr("source").and_then(|v| v.as_str()) == Some("/var/run/docker.sock")));
    }

    #[test]
    fn named_volume_is_not_a_host_mount() {
        let yaml = "services:\n  app:\n    image: nginx:1.25\n    volumes:\n      - db-data:/var/lib/mysql\n";
        let fm = parse(yaml);
        // named volume -> Volume kind, not a host bind Mount
        assert!(fm.entities.iter().any(|e| e.kind == EntityKind::Volume && e.id == "volume:db-data"));
        assert!(!fm.entities.iter().any(|e| e.kind == EntityKind::Mount));
    }

    #[test]
    fn password_file_is_not_treated_as_inline_secret() {
        let yaml = "services:\n  app:\n    image: nginx:1.25\n    environment:\n      DB_PASSWORD_FILE: /run/secrets/db\n";
        let fm = parse(yaml);
        let ev = fm
            .entities
            .iter()
            .find(|e| e.id == "env_var:app/DB_PASSWORD_FILE")
            .expect("env var entity");
        assert_eq!(ev.attr("value_class").and_then(|v| v.as_str()), Some("normal"));
    }

    #[test]
    fn invalid_yaml_is_an_error() {
        assert!(try_parse("services: [unclosed").is_err());
    }

    #[test]
    fn bom_prefixed_input_parses() {
        let yaml = "\u{feff}services:\n  app:\n    image: nginx:1.25\n";
        assert!(try_parse(yaml).is_ok());
    }

    #[test]
    fn long_syntax_port_is_parsed() {
        let yaml = "services:\n  app:\n    image: nginx\n    ports:\n      - target: 5432\n        published: 5432\n        protocol: tcp\n";
        let fm = parse(yaml);
        let pb = fm
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::PortBinding)
            .expect("port binding entity");
        assert_eq!(pb.attr("target").and_then(|v| v.as_i64()), Some(5432));
        assert_eq!(pb.attr("host_ip").and_then(|v| v.as_str()), Some("0.0.0.0"));
    }

    #[test]
    fn detects_socket_mount_entity() {
        let yaml = "services:\n  web:\n    image: nginx\n    volumes: [\"/var/run/docker.sock:/var/run/docker.sock\"]\n";
        let fm = parse(yaml);
        assert!(fm
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Mount
                && e.attr("source").and_then(|v| v.as_str()) == Some("/var/run/docker.sock")));
    }
}
