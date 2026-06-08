# Sentinel vulnerability reference

The master catalog of everything Sentinel detects. Each finding in a scan links here
by its rule id (e.g. a `DOCKER-SOCKET-MOUNT` finding → [#docker-socket-mount](#docker-socket-mount)).
Control mappings are documented in [CONTROLS.md](CONTROLS.md).

> Severity: **Critical** (host/root compromise) · **High** (likely exploitable) ·
> **Medium** (environment-dependent) · **Low** (hardening). Rules marked _strict_ only
> run with `--strict`.

---

## DOCKER-SOCKET-MOUNT
**Critical** · CWE-250 · CIS-Docker 5.31

Mounting `/var/run/docker.sock` gives the container full control of the Docker daemon —
equivalent to root on the host.

```yaml
# bad
volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
```
**Fix:** remove the mount. If daemon access is genuinely required, use a scoped socket
proxy (e.g. tecnativa/docker-socket-proxy) with an allow-list, mounted read-only.

## SENSITIVE-HOST-PATH-MOUNT
**Critical/High** · CWE-552, CWE-668

Bind-mounting sensitive host paths (`/`, `/etc`, `/proc`, `/sys`, `/root`, …) exposes
host files to the container, even read-only.

```yaml
# bad
volumes: ["/etc:/host-etc:ro"]
```
**Fix:** remove the mount or scope it to a specific, non-sensitive subdirectory.

## PRIVILEGED-CONTAINER
**Critical** · CWE-250 · CIS-Docker 5.4

`privileged: true` disables almost all container isolation — near-equivalent to root on
the host.

**Fix:** drop `privileged`; grant only the specific capabilities you need via `cap_add`.

## DANGEROUS-CAPABILITY
**High** · CWE-250 · CIS-Docker 5.3

Adding capabilities like `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `BPF`, `SYS_RAWIO`
enables container escape or host tampering.

**Fix:** remove the capability; if required, justify and isolate the workload.

## HOST-NETWORK-MODE
**High** · CWE-668 · CIS-Docker 5.9

`network_mode: host` removes network-namespace isolation; the container shares the
host's network stack and can reach host-local services.

**Fix:** use a user-defined bridge network and publish only the ports you need.

## HOST-PID-NAMESPACE
**High** · CWE-668 · CIS-Docker 5.15

`pid: host` lets the container see and signal host processes.

**Fix:** remove `pid: host`.

## HOST-IPC-NAMESPACE
**High** · CWE-668 · CIS-Docker 5.16

`ipc: host` shares the host IPC namespace, breaking process isolation.

**Fix:** remove `ipc: host`.

## WEAK-DEFAULT-CREDENTIAL
**High** · CWE-798, CWE-1392

A secret-like environment variable is set to a weak/default value (`admin`, `password`,
`changeme`, …) — trivially guessed.

**Fix:** set a strong unique secret; inject it via a secrets manager or `*_FILE`, not inline.

## SECRET-IN-ENVIRONMENT
**Medium** · CWE-256, CWE-798

A secret-like variable has an inline literal value, which ends up in version control and
`docker inspect`.

```yaml
# bad
environment: { API_KEY: "sk-live-abc123" }
# good
environment: { API_KEY_FILE: /run/secrets/api_key }
```
**Fix:** use Docker/Compose secrets or the `*_FILE` convention; reference, don't inline.

## SENSITIVE-PORT-PUBLISHED-ALL-IFACES
**Medium** · CWE-668

A datastore/admin port (Postgres 5432, MySQL 3306, Redis 6379, Mongo 27017, Elastic
9200, Kafka 9092, RabbitMQ mgmt 15672, …) is published on `0.0.0.0`.

```yaml
# bad
ports: ["5432:5432"]
# good
ports: ["127.0.0.1:5432:5432"]
```
**Fix:** bind to `127.0.0.1` or an internal network; don't publish datastores.

## PORT-PUBLISHED-ALL-IFACES
**Low** · CWE-668

Any port published on all interfaces (`0.0.0.0`).

**Fix:** bind to a specific interface unless external access is intended.

## IMAGE-UNPINNED
**Low** · CWE-494, CWE-1357

An image is referenced by a mutable tag (or `latest`) rather than a digest — what runs
can change silently, with no integrity check.

```yaml
# bad
image: nginx:latest
# good
image: nginx@sha256:<digest>
```
**Fix:** pin by digest.

## CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN
**Low** · CWE-250 · CIS-Docker 4.1

The service runs as root, or no `user:` is set so it cannot be confirmed non-root.

**Fix:** set a non-root `user:` explicitly.

## WRITABLE-ROOT-FILESYSTEM
**Low** · CWE-732 · CIS-Docker 5.12

A writable root filesystem lets an attacker persist tooling in the container.

**Fix:** set `read_only: true` and mount specific writable paths as tmpfs/volumes.

---

## NO-NEW-PRIVILEGES-MISSING _(strict)_
**Low** · CWE-250

The service doesn't set `no-new-privileges`, so a process can gain privileges via setuid
binaries.

**Fix:** `security_opt: ["no-new-privileges:true"]`.

## CAP-DROP-ALL-MISSING _(strict)_
**Low** · CWE-250

The service keeps Docker's default capability set instead of dropping all and adding back
only what's needed.

**Fix:** `cap_drop: [ALL]`, then `cap_add` the minimum required.

## NO-RESOURCE-LIMITS _(strict)_
**Low** · CWE-400

No memory limit is set; a runaway container can exhaust host memory (DoS).

**Fix:** set `deploy.resources.limits.memory` (or `mem_limit` in Compose v2).
