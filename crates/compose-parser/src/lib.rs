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
                    parse_service(&mut b, name, svc);
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
    let spec = match v.as_str() {
        Some(s) => s.to_string(),
        None => return, // long syntax deferred
    };
    let parts: Vec<&str> = spec.split(':').collect();
    if parts.len() < 2 {
        return; // anonymous volume; not a bind mount
    }
    let source = parts[0].to_string();
    let target = parts[1].to_string();
    let read_only = parts.get(2).map(|m| *m == "ro").unwrap_or(false);

    let id = format!("mount:{svc}:{source}->{target}");
    let mut a = BTreeMap::new();
    a.insert("source".into(), AttrValue::Str(source));
    a.insert("target".into(), AttrValue::Str(target));
    a.insert("read_only".into(), AttrValue::Bool(read_only));

    b.entity(Entity {
        id: id.clone(),
        kind: EntityKind::Mount,
        attributes: a,
        provenance: Provenance {
            source_path: path.to_string(),
            origin: Origin::Explicit,
        },
    });
    b.relation(RelationKind::Mounts, svc_id, &id);
}

fn is_secret_like(name: &str) -> bool {
    let norm: String = name.to_uppercase().chars().filter(|c| *c != '_').collect();
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
