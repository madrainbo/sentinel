# Sentinel

**Deterministic Docker Compose security scanner.** Paste or point it at a
`docker-compose.yml` and get a reproducible list of security misconfigurations —
exposed Docker sockets, default credentials, privileged containers, unpinned images,
and more.

- **Deterministic** — same input always produces the same findings and the same
  `report_digest` (a real SHA-256 over the normalized facts + engine/pack versions +
  verdict). No LLM, no flakiness, fully auditable.
- **Private by design** — runs locally and in your CI. Your compose file is never
  uploaded anywhere; the tool makes no network calls.
- **CI-ready** — one exit code gates your pipeline; the same binary runs on your laptop.

> ⚠️ **Early preview — actively developed.** Today Sentinel scans **Docker Compose**.
> Broader coverage (Dockerfiles, Kubernetes manifests, and more) is on the way toward
> the first tagged release. There is **no stable release yet** — build from source to try it.

## Install

From source (Rust toolchain):

```sh
cargo install --git https://github.com/madrainbo/sentinel sentinel
# or, from a clone:
cargo install --path crates/cli
```

Prebuilt binaries and a GitHub Action will be published with the first tagged release.

## Usage

```sh
sentinel scan docker-compose.yml                  # human-readable findings
cat docker-compose.yml | sentinel scan -          # read from stdin
sentinel scan docker-compose.yml --format json    # machine-readable report
sentinel scan docker-compose.yml --format sarif   # SARIF for GitHub code scanning
sentinel scan docker-compose.yml --fail-on high   # exit 1 if any High/Critical (CI gate)
sentinel scan docker-compose.yml --strict         # + best-practice hardening checks
sentinel verify report.json docker-compose.yml    # re-check a saved report reproduces
```

**SARIF** output drops findings straight into the GitHub Security tab:

```yaml
- run: sentinel scan docker-compose.yml --format sarif > sentinel.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

**`verify`** re-runs the scan and checks the result reproduces the report's
`report_digest` — the content-addressing guarantee, usable by an auditor.

## Use in CI (GitHub Actions) — *coming with the first release*

Once the first version is tagged, a one-line Action will gate your pipeline:

```yaml
- uses: madrainbo/sentinel@v0.1.0      # available after the first release
  with:
    path: docker-compose.yml
    fail-on: high      # fail the job on any High/Critical finding
```

The Action downloads a pinned, checksum-verified prebuilt binary for the runner and
runs the **same** `sentinel scan` you run locally — your CI never compiles anything.

## What it checks (v0)

| Rule | Severity | What it catches |
|---|---|---|
| `DOCKER-SOCKET-MOUNT` | Critical | `/var/run/docker.sock` mounted into a container (host root) |
| `SENSITIVE-HOST-PATH-MOUNT` | Critical/High | bind mount of `/`, `/etc`, `/proc`, `/sys`, … |
| `PRIVILEGED-CONTAINER` | Critical | `privileged: true` |
| `DANGEROUS-CAPABILITY` | High | `cap_add` of SYS_ADMIN / NET_ADMIN / SYS_PTRACE / … |
| `HOST-NETWORK-MODE` | High | `network_mode: host` |
| `HOST-PID-NAMESPACE` / `HOST-IPC-NAMESPACE` | High | `pid: host` / `ipc: host` (namespace isolation loss) |
| `WEAK-DEFAULT-CREDENTIAL` | High | secret-like env var set to a weak/default value |
| `SECRET-IN-ENVIRONMENT` | Medium | secret-like env var with an inline literal value |
| `SENSITIVE-PORT-PUBLISHED-ALL-IFACES` | Medium | datastore/admin port published on `0.0.0.0` |
| `PORT-PUBLISHED-ALL-IFACES` | Low | any port published on all interfaces |
| `IMAGE-UNPINNED` | Low | image not pinned by digest |
| `CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN` | Low | runs as root, or user unspecified |
| `WRITABLE-ROOT-FILESYSTEM` | Low | `read_only` not set |

> Full details for every rule — what it is, why it matters, and how to fix it — are in
> the **[vulnerability reference (RULES.md)](RULES.md)**. Findings deep-link to it, and
> SARIF results carry the per-rule `helpUri`. Control mappings: **[CONTROLS.md](CONTROLS.md)**.

## How it works

```
docker-compose.yml  →  parser  →  fact model (entity/relation graph)
                                      → rules engine → findings
                                      → content-addressed report (SHA-256)
```

The parser normalizes Compose into a technology-agnostic fact graph; rules are pure
predicates over that graph; the report is hashed so it can be reproduced and verified.

## Build & test

```sh
cargo build --release
cargo test --workspace
cargo run -p harness        # eval harness: precision/recall over a labeled corpus
```

## License

MIT — see [LICENSE](LICENSE).
