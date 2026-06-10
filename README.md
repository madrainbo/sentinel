# Sentinel

**Deterministic security scanner for your infrastructure configs.** Point it at a
Docker Compose file, Dockerfile, Kubernetes manifest, GitHub Actions workflow,
Terraform file, or `.env`/config — and get a reproducible list of security
misconfigurations: exposed Docker sockets, default credentials, privileged
containers, cluster-admin bindings, pwn-request workflows, open security groups,
hardcoded keys, and more.

> ### 🚀 [Try the live demo →](https://sentinel-engine-ggaj.onrender.com/)
> Paste any supported config and scan it **entirely in your browser**
> (WebAssembly — nothing is uploaded). Same engine as this CLI.

- **Deterministic** — same input always produces the same findings and the same
  `report_digest` (a real SHA-256 over the normalized facts + engine/pack versions +
  verdict). No LLM, no flakiness, fully auditable.
- **Private by design** — runs locally and in your CI. Your config is never
  uploaded anywhere; the tool makes no network calls.
- **CI-ready** — one exit code gates your pipeline; the same binary runs on your laptop.

> ⚠️ **Early preview — actively developed.** There is **no stable release yet** —
> build from source to try the CLI. Prebuilt binaries and the GitHub Action arrive
> with the first tagged release.

## What it scans

| Target | Rules | Highlights |
|---|---|---|
| **Docker Compose** | 23 | Docker-socket mounts, privileged containers, weak/default credentials, host namespaces, attack-path chains |
| **Kubernetes** | 19 | privileged/hostPath, cluster-admin & wildcard RBAC, seccomp unconfined, reachable node-compromise chains |
| **Dockerfile** | 8 | `curl \| sh`, disabled TLS verification, root user, build secrets, unpinned base images |
| **Secrets / config** | 8 | AWS/GitHub/Stripe/Slack/SendGrid/Google keys, private keys, generic credentials |
| **GitHub Actions** | 6 | pwn-request, script injection, write-all permissions, unpinned actions |
| **Terraform** | 6 | open security groups, public S3 ACLs, IAM wildcards, plaintext secrets, unencrypted storage |

**70 rules total** (64 default + 6 opt-in `--strict` hardening checks). Full
per-rule reference — what each finds, why it matters, how to fix it — in
**[RULES.md](RULES.md)** (generated from the engine itself; findings and SARIF
deep-link into it). Control mappings (CWE, CIS): **[CONTROLS.md](CONTROLS.md)**.

## Install

From source (requires the [Rust toolchain](https://rustup.rs) and Git):

```sh
cargo install --git https://github.com/madrainbo/sentinel sentinel
# or, from a clone:
cargo install --path crates/cli
```

## Usage

```sh
sentinel scan docker-compose.yml                  # type auto-detected
sentinel scan Dockerfile
sentinel scan deployment.yaml                     # Kubernetes (multi-doc aware)
sentinel scan .github/workflows/ci.yml            # GitHub Actions
sentinel scan main.tf                             # Terraform (HCL)
sentinel scan .env                                # secrets sweep
cat docker-compose.yml | sentinel scan -          # read from stdin
sentinel scan compose.yml --format json           # machine-readable report
sentinel scan compose.yml --format sarif          # SARIF for GitHub code scanning
sentinel scan compose.yml --fail-on high          # exit 1 on High/Critical (CI gate)
sentinel scan compose.yml --strict                # + best-practice hardening checks
sentinel verify report.json compose.yml           # re-check a saved report reproduces
sentinel rules                                    # the full rule catalog as Markdown
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

## How it works

```
config file  →  parser  →  fact model (entity/relation graph)
                               → rules engine → findings (with source lines)
                               → content-addressed report (SHA-256)
```

Each parser normalizes its format into a technology-agnostic fact graph; rules are
pure predicates over that graph; the report is hashed so it can be reproduced and
verified. Findings carry the source line(s) they came from.

## Build & test

```sh
cargo build --release
cargo test --workspace
cargo run -p harness        # eval harness: precision/recall over a labeled corpus
```

The harness runs the engine over a labeled corpus (74 fixtures across all six
formats) and gates CI on precision/recall 1.000 and per-fixture determinism.

## License

MIT — see [LICENSE](LICENSE).
