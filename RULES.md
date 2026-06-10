# Sentinel vulnerability reference

<!-- GENERATED — do not edit by hand. Regenerate with `sentinel rules > RULES.md`. -->

The master catalog of everything Sentinel detects. Each finding in a scan links here
by its rule id (e.g. a `DOCKER-SOCKET-MOUNT` finding → [#docker-socket-mount](#docker-socket-mount)).
Control mappings are documented in [CONTROLS.md](CONTROLS.md).

Sentinel ships **70 rules** across **6 targets** (Docker Compose, Dockerfile, Kubernetes, GitHub Actions, Terraform, Secrets).

> Severity: **Critical** (host/root compromise) · **High** (likely exploitable) ·
> **Medium** (environment-dependent) · **Low** (hardening). Rules marked _strict_ only
> run with `--strict`.

---

## Docker Compose

### DOCKER-SOCKET-MOUNT
**Critical** · CWE-250, CIS-Docker-5.31

A container bind-mounts /var/run/docker.sock, giving it full control of the Docker daemon — effectively root on the host.

**Fix:** Remove the mount; if daemon access is required, use a scoped socket proxy, read-only.

### REACHABLE-HOST-TAKEOVER
**Critical** · CWE-668, CWE-250

Cross-resource: an internet-reachable service has a depends_on path to a service that mounts the Docker socket or runs privileged — reaching the front door chains to full host compromise.

**Fix:** Keep docker.sock/privileged off any internet-reachable path; don't expose the front-end directly.

### PRIVILEGED-CONTAINER
**Critical** · CWE-250, CIS-Docker-5.4

privileged: true disables container isolation — near-equivalent to root on the host.

**Fix:** Drop 'privileged'; grant only the specific capabilities required.

### CAP-ADD-ALL
**Critical** · CWE-250, CIS-Docker-5.3

cap_add: [ALL] grants every Linux capability — equivalent to privileged and trivially escapable to the host.

**Fix:** Remove cap_add: ALL; drop all caps and add back only the few needed.

### DANGEROUS-CAPABILITY
**High** · CWE-250, CIS-Docker-5.3

cap_add grants a high-risk Linux capability (e.g. SYS_ADMIN, NET_ADMIN) that can enable container escape.

**Fix:** Remove the capability; if required, justify and isolate the workload.

### HOST-NETWORK-MODE
**High** · CWE-668, CIS-Docker-5.9

network_mode: host removes network namespace isolation; the container shares the host's network stack.

**Fix:** Use a user-defined bridge network and publish only the needed ports.

### WEAK-DEFAULT-CREDENTIAL
**High** · CWE-798, CWE-1392

A secret-like env var is set to a weak or default value (admin, password, changeme…).

**Fix:** Set a strong unique secret; inject via a secrets manager, not inline.

### DATABASE-AUTH-DISABLED
**High** · CWE-287, CWE-1392

An env var disables database authentication entirely (MYSQL_ALLOW_EMPTY_PASSWORD, POSTGRES_HOST_AUTH_METHOD=trust, …) — anyone who reaches the DB connects with no credentials.

**Fix:** Remove the empty-password/trust switch; set a strong password and restrict the DB to an internal network.

### REACHABLE-WEAK-CREDENTIAL
**High** · CWE-668, CWE-1390

Cross-resource: an internet-reachable service (0.0.0.0 port) has a depends_on path to a service that uses a weak/default credential — an exploitable chain, not a single flag.

**Fix:** Don't expose the service directly; bind to 127.0.0.1 or use a gateway, and replace weak/default credentials.

### SENSITIVE-HOST-PATH-MOUNT
**High** · CWE-552, CWE-668

A sensitive host directory (/, /etc, /proc, /sys, …) is bind-mounted into a container.

**Fix:** Remove the bind mount or scope it to a specific non-sensitive subdirectory (read-only).

### HOST-PID-NAMESPACE
**High** · CWE-668, CIS-Docker-5.15

pid: host shares the host PID namespace — the container can see and signal host processes.

**Fix:** Remove 'pid: host'; containers should use their own PID namespace.

### HOST-IPC-NAMESPACE
**High** · CWE-668, CIS-Docker-5.16

ipc: host shares the host IPC namespace — breaks process isolation.

**Fix:** Remove 'ipc: host'; containers should use their own IPC namespace.

### SECURITY-PROFILE-DISABLED
**High** · CWE-693, CIS-Docker-5.1

security_opt sets seccomp:unconfined or apparmor:unconfined, removing a kernel-hardening layer that blocks dangerous syscalls.

**Fix:** Use the default seccomp/AppArmor profiles or a scoped custom one.

### HOST-USERNS-MODE
**High** · CWE-281, CIS-Docker-5.30

userns_mode: host disables user-namespace remapping, so root in the container maps to root on the host.

**Fix:** Remove 'userns_mode: host' and enable user-namespace remapping.

### SECRET-IN-ENVIRONMENT
**Medium** · CWE-256, CWE-798

A secret-like env var has an inline literal value — it ends up in version control and `docker inspect`.

**Fix:** Use Compose/Docker secrets or an external secrets manager; reference, don't inline.

### SENSITIVE-PORT-PUBLISHED-ALL-IFACES
**Medium** · CWE-668

A database/cache/admin port is published on 0.0.0.0 — often reachable externally.

**Fix:** Bind to 127.0.0.1 or an internal network; do not publish datastores.

### IMAGE-UNPINNED
**Low** · CWE-494, CWE-1357

An image uses a tag (or :latest) rather than a digest — what runs can change silently.

**Fix:** Pin by digest (image@sha256:…).

### CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN
**Low** · CWE-250, CIS-Docker-4.1

The service runs as root, or no user is declared so it can't be confirmed non-root.

**Fix:** Set a non-root 'user:'; declare it explicitly even if the base image sets one.

### WRITABLE-ROOT-FILESYSTEM
**Low** · CWE-732, CIS-Docker-5.12

read_only is not set, so an attacker can persist tooling in the container filesystem.

**Fix:** Set 'read_only: true' and mount specific writable paths as tmpfs/volumes.

### PORT-PUBLISHED-ALL-IFACES
**Low** · CWE-668

A port is published on 0.0.0.0 — reachable from any interface.

**Fix:** Bind to a specific interface (e.g. 127.0.0.1) unless external access is intended.

### NO-NEW-PRIVILEGES-MISSING
**Low** · CWE-250 · _strict_

Processes can gain privileges via setuid binaries because no-new-privileges isn't set.

**Fix:** Add 'security_opt: ["no-new-privileges:true"]'.

### CAP-DROP-ALL-MISSING
**Low** · CWE-250 · _strict_

The service keeps Docker's default capability set instead of dropping all and adding back only what's needed.

**Fix:** Add 'cap_drop: [ALL]' and 'cap_add' only the capabilities you need.

### NO-RESOURCE-LIMITS
**Low** · CWE-400 · _strict_

No memory limit is set — a runaway container can exhaust host memory (DoS).

**Fix:** Set a memory limit (deploy.resources.limits.memory, or mem_limit in v2).

---

## Dockerfile

### DOCKERFILE-CURL-PIPE-EXECUTION
**High** · CWE-494

A RUN pipes a downloaded script straight into a shell (curl | sh) with no integrity check.

**Fix:** Download to a file, verify a checksum/signature, then execute.

### DOCKERFILE-TLS-VERIFICATION-DISABLED
**High** · CWE-295

A RUN downloads with curl -k / wget --no-check-certificate, disabling TLS certificate verification — the payload can be swapped in transit.

**Fix:** Remove the insecure flag; fix CA trust and verify a checksum/signature of the download.

### DOCKERFILE-WORLD-WRITABLE
**Medium** · CWE-732, CWE-276

A RUN sets world-writable permissions (chmod 777 / a+w) — any process or user in the container can overwrite the files.

**Fix:** Grant the narrowest permissions needed (755 / 644); avoid 777.

### DOCKERFILE-ROOT-USER
**Medium** · CWE-250, CIS-Docker-4.1

The image sets USER root or never sets a USER, so it defaults to root.

**Fix:** Add a non-root USER instruction (and create the user) before the entrypoint.

### DOCKERFILE-ADD-REMOTE-URL
**Medium** · CWE-494

ADD fetches a remote URL with no integrity check (and auto-extracts archives).

**Fix:** Use COPY for local files, or RUN curl with a checksum verification step.

### DOCKERFILE-BUILD-SECRET
**Medium** · CWE-798

A secret-like ENV/ARG has an inline value — it is baked into image layers.

**Fix:** Use BuildKit secrets (RUN --mount=type=secret) or runtime env, not ENV/ARG.

### DOCKERFILE-BASE-IMAGE-UNPINNED
**Low** · CWE-494, CWE-1357

The base image is not pinned by digest — the build is not reproducible.

**Fix:** Pin the base image by digest: FROM repo@sha256:…

### DOCKERFILE-SUDO
**Low** · CWE-250

A RUN uses sudo — unnecessary in a build and can mask privilege issues.

**Fix:** Run build steps as the appropriate user directly; drop sudo.

---

## Kubernetes

### K8S-REACHABLE-NODE-COMPROMISE
**Critical** · CWE-668, CWE-250

Cross-resource: an external Service (NodePort/LoadBalancer) selects a Workload that runs privileged / adds a dangerous capability / mounts a sensitive hostPath — reaching the service chains to node or cluster takeover.

**Fix:** Keep node-takeover surfaces off anything an external Service selects; front with a hardened gateway.

### K8S-PRIVILEGED-CONTAINER
**Critical** · CWE-250, CIS-K8s-5.2.2

A container sets securityContext.privileged: true — full host device/kernel access, trivial node takeover.

**Fix:** Remove privileged; grant only the specific capabilities required.

### K8S-CAP-ADD-ALL
**Critical** · CWE-250, CIS-K8s-5.2.9

A container adds ALL Linux capabilities — equivalent to privileged.

**Fix:** Drop all capabilities and add back only the few needed.

### K8S-CLUSTER-ADMIN-BINDING
**Critical** · CWE-269, CIS-K8s-5.1.1

A (Cluster)RoleBinding binds the built-in cluster-admin role — full control of the cluster.

**Fix:** Bind a least-privilege role; reserve cluster-admin for break-glass.

### K8S-HOST-NETWORK
**High** · CWE-668, CIS-K8s-5.2.5

hostNetwork: true shares the node's network stack and bypasses NetworkPolicies.

**Fix:** Remove hostNetwork; use a Service.

### K8S-HOST-PID
**High** · CWE-668, CIS-K8s-5.2.3

hostPID: true lets the pod see and signal processes on the node.

**Fix:** Remove hostPID.

### K8S-HOST-IPC
**High** · CWE-668, CIS-K8s-5.2.4

hostIPC: true shares the node's IPC namespace.

**Fix:** Remove hostIPC.

### K8S-HOSTPATH-MOUNT
**High** · CWE-552, CIS-K8s-5.2.12

A hostPath volume mounts a node directory into the pod, escaping isolation (Critical for the Docker socket / sensitive paths).

**Fix:** Use a PersistentVolume/configMap/emptyDir; if unavoidable, mount a specific non-sensitive subdir read-only.

### K8S-DANGEROUS-CAPABILITY
**High** · CWE-250, CIS-K8s-5.2.9

capabilities.add includes a high-risk capability (SYS_ADMIN, NET_ADMIN, …) enabling escape or host tampering.

**Fix:** Remove the capability; if required, justify and isolate.

### K8S-SECCOMP-UNCONFINED
**High** · CWE-693, CIS-K8s-5.7.2

seccompProfile type Unconfined removes the syscall filter that blocks dangerous kernel calls.

**Fix:** Use seccompProfile RuntimeDefault (or a scoped Localhost profile).

### K8S-RBAC-WILDCARD
**High** · CWE-269, CIS-K8s-5.1.3

A Role/ClusterRole grants all verbs on all resources (*/*) — unrestricted within scope (Critical at cluster scope).

**Fix:** Scope rules to the specific apiGroups/resources/verbs needed.

### K8S-RBAC-SECRET-READ
**Medium** · CWE-522, CIS-K8s-5.1.2

A Role/ClusterRole can get/list/watch Secrets — exposes credentials if the bound identity is compromised (High at cluster scope).

**Fix:** Scope to named secrets or use an external secrets store.

### K8S-ALLOW-PRIVILEGE-ESCALATION
**Medium** · CWE-250, CIS-K8s-5.2.6

Container sets allowPrivilegeEscalation: true — a process can gain more privileges than its parent.

**Fix:** Set allowPrivilegeEscalation: false.

### K8S-SECRET-IN-MANIFEST
**Medium** · CWE-312, CWE-798

A Secret embeds its data inline (base64 is not encryption) — it lands in version control and CI logs.

**Fix:** Use sealed-secrets/SOPS, an external secrets operator, or a cloud secret store.

### K8S-IMAGE-UNPINNED
**Low** · CWE-494, CWE-1357

A container image uses a tag rather than a digest — what runs can change silently.

**Fix:** Pin images by digest (repo@sha256:…).

### K8S-CONTAINER-RUNS-AS-ROOT
**Low** · CWE-250, CIS-K8s-5.2.7

No runAsNonRoot: true and no non-zero runAsUser, so the container can't be confirmed non-root.

**Fix:** Set runAsNonRoot: true and a non-zero runAsUser.

### K8S-READONLY-ROOTFS-MISSING
**Low** · CWE-732 · _strict_

readOnlyRootFilesystem is not set, so an attacker can persist tooling in the container filesystem.

**Fix:** Set readOnlyRootFilesystem: true and mount writable paths explicitly.

### K8S-ALLOW-PRIV-ESC-NOT-DISABLED
**Low** · CWE-250 · _strict_

allowPrivilegeEscalation is not explicitly false (defaults to true).

**Fix:** Set allowPrivilegeEscalation: false.

### K8S-AUTOMOUNT-SA-TOKEN
**Low** · CWE-668, CIS-K8s-5.1.6 · _strict_

automountServiceAccountToken is not disabled, so the API token is mounted into every pod.

**Fix:** Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.

---

## GitHub Actions

### GHA-PWN-REQUEST
**Critical** · CWE-94, CWE-829

Cross-resource: a privileged untrusted trigger (pull_request_target / workflow_run) plus a step that checks out the attacker-controlled PR ref — fork code runs with the repo's write token and secrets.

**Fix:** Don't run untrusted PR code under pull_request_target; use pull_request, or split safe build from privileged job.

### GHA-SCRIPT-INJECTION
**High** · CWE-94, CWE-78

A run: step interpolates attacker-controlled ${{ github.event.* }} (issue/PR title/body, comment, head_ref, …) straight into the shell — command injection.

**Fix:** Pass the value via env: and reference "$VAR" quoted; never interpolate github.event.* into run:.

### GHA-BROAD-PERMISSIONS
**Medium** · CWE-272, CWE-250

permissions: write-all grants the GITHUB_TOKEN write to every scope, so any compromised step can tamper widely.

**Fix:** Default to read-only permissions and grant only the specific write scopes a job needs.

### GHA-SELF-HOSTED-RUNNER
**Medium** · CWE-668

A job runs on a self-hosted runner; with an untrusted trigger a fork PR can run attacker code on a persistent runner (Medium), otherwise informational (Low).

**Fix:** Use ephemeral/isolated runners; never expose self-hosted runners to fork PRs.

### GHA-SECRETS-INHERIT
**Medium** · CWE-200, CWE-668

A job calls a reusable workflow with secrets: inherit, passing ALL caller secrets rather than only those needed.

**Fix:** Pass only the specific secrets the reusable workflow needs.

### GHA-UNPINNED-ACTION
**Low** · CWE-494, CWE-829

A third-party action is pinned to a mutable tag/branch instead of a commit SHA — whoever controls that ref can change the code your workflow runs.

**Fix:** Pin actions to a full commit SHA; track updates with Dependabot.

---

## Terraform

### TF-OPEN-SECURITY-GROUP
**High** · CWE-284, CWE-668

An aws_security_group ingress rule allows 0.0.0.0/0 — open to the entire internet (critical for admin ports / datastores).

**Fix:** Restrict cidr_blocks to known networks; never expose 22/3389 or databases to 0.0.0.0/0.

### TF-PUBLIC-S3-BUCKET
**High** · CWE-732, CWE-284

An S3 bucket ACL is public-read / public-read-write / authenticated-read — objects are world-readable.

**Fix:** Keep buckets private; use a public access block and presigned URLs / CloudFront.

### TF-IAM-WILDCARD-ACTION
**High** · CWE-269, CWE-250

An IAM policy statement allows Action "*" with Effect Allow — full admin to whoever holds it.

**Fix:** Scope to the specific actions required; avoid Action "*".

### TF-IAM-PUBLIC-PRINCIPAL
**High** · CWE-284, CWE-732

A resource policy allows Principal "*" with Allow — any AWS account / anonymous caller gets access.

**Fix:** Use explicit least-privilege Principal ARNs.

### TF-PLAINTEXT-SECRET
**High** · CWE-798, CWE-312

A credential attribute (password/secret_key/token/…) is set to a literal string — committed to VCS and Terraform state.

**Fix:** Use variables from a secret store / TF_VAR_ env; mark sensitive; rotate the exposed value.

### TF-UNENCRYPTED-STORAGE
**Medium** · CWE-311

An EBS volume or RDS database does not enable encryption at rest.

**Fix:** Set encrypted = true / storage_encrypted = true, ideally with a customer-managed KMS key.

---

## Secrets

### SECRET-AWS-ACCESS-KEY
**High** · CWE-798, CWE-312

An AWS access key id (AKIA/ASIA…) is hardcoded in the file.

**Fix:** Remove it, rotate the key in IAM, and load credentials from the AWS credential chain / a secret manager.

### SECRET-PRIVATE-KEY
**High** · CWE-798, CWE-312

A PEM private-key block (-----BEGIN … PRIVATE KEY-----) is embedded in the file.

**Fix:** Remove the key, rotate it, and store private keys outside the repo (secret manager / KMS).

### SECRET-GITHUB-TOKEN
**High** · CWE-798, CWE-312

A GitHub personal access / OAuth token (ghp_/gho_/…/github_pat_) is hardcoded.

**Fix:** Revoke the token on GitHub and use a secret store or GitHub Actions secrets.

### SECRET-SLACK-TOKEN
**High** · CWE-798, CWE-312

A Slack API token (xoxb-/xoxp-/…) is hardcoded.

**Fix:** Revoke the token in Slack and load it from a secret manager.

### SECRET-STRIPE-KEY
**High** · CWE-798, CWE-312

A live Stripe secret key (sk_live_/rk_live_) is hardcoded.

**Fix:** Roll the key in the Stripe dashboard and load it from a secret manager.

### SECRET-SENDGRID-KEY
**High** · CWE-798, CWE-312

A SendGrid API key (SG.…) is hardcoded.

**Fix:** Revoke the key in SendGrid and load it from a secret manager.

### SECRET-GOOGLE-API-KEY
**Medium** · CWE-798, CWE-312

A Google API key (AIza…) is hardcoded.

**Fix:** Restrict/rotate the key in Google Cloud and load it from a secret manager.

### SECRET-GENERIC-CREDENTIAL
**Medium** · CWE-798, CWE-312

A password/secret/token-named key is assigned a literal value (e.g. in a .env or config file).

**Fix:** Move the value to a secret manager / untracked .env and reference it at runtime; rotate the exposed value.
