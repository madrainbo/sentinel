# Control mappings

Every Sentinel finding cites the standards it maps to. This table documents those
mappings and their basis.

- **CWE** titles are from the public [MITRE CWE](https://cwe.mitre.org/) list (CWE 4.x).
- **CIS** references are section numbers from the **CIS Docker Benchmark** (Section 4 =
  Container Images, Section 5 = Container Runtime). The benchmark itself is published by
  the Center for Internet Security under their own license; the section numbers below are
  the stable identifiers used across recent v1.x releases. Confirm against the licensed
  copy for your target version. Mappings without a CIS entry are best captured by CWE
  alone.

| Rule | Severity | CWE | CIS Docker Benchmark |
|---|---|---|---|
| `DOCKER-SOCKET-MOUNT` | Critical | CWE-250 Execution with Unnecessary Privileges | 5.31 Docker socket not mounted in containers |
| `SENSITIVE-HOST-PATH-MOUNT` | Critical/High | CWE-552 Files/Dirs Accessible to External Parties; CWE-668 Exposure to Wrong Sphere | — |
| `PRIVILEGED-CONTAINER` | Critical | CWE-250 | 5.4 Privileged containers not used |
| `DANGEROUS-CAPABILITY` | High | CWE-250 | 5.3 Linux kernel capabilities restricted |
| `HOST-NETWORK-MODE` | High | CWE-668 | 5.9 Host network namespace not shared |
| `HOST-PID-NAMESPACE` | High | CWE-668 | 5.15 Host process namespace not shared |
| `HOST-IPC-NAMESPACE` | High | CWE-668 | 5.16 Host IPC namespace not shared |
| `WEAK-DEFAULT-CREDENTIAL` | High | CWE-798 Use of Hard-coded Credentials; CWE-1392 Use of Default Credentials | — |
| `SECRET-IN-ENVIRONMENT` | Medium | CWE-256 Plaintext Storage of a Password; CWE-798 | — |
| `SENSITIVE-PORT-PUBLISHED-ALL-IFACES` | Medium | CWE-668 | — |
| `PORT-PUBLISHED-ALL-IFACES` | Low | CWE-668 | — |
| `IMAGE-UNPINNED` | Low | CWE-494 Download of Code Without Integrity Check; CWE-1357 Reliance on Insufficiently Trustworthy Component | — |
| `CONTAINER-RUNS-AS-ROOT-OR-UNKNOWN` | Low | CWE-250 | 4.1 Run containers as a non-root user |
| `WRITABLE-ROOT-FILESYSTEM` | Low | CWE-732 Incorrect Permission Assignment for Critical Resource | 5.12 Root filesystem mounted read-only |

## Verification status

- **CWE mappings: verified** against MITRE CWE. (Notably, `IMAGE-UNPINNED` maps to
  **CWE-494** — pulling an image by mutable tag runs code without an integrity check;
  pinning by digest is that check. An earlier draft used CWE-1104, which is about
  *unmaintained* components and was incorrect.)
- **CIS section numbers: standard v1.x identifiers**, cross-check against your licensed
  CIS Docker Benchmark copy for the exact target version.
