# Naming scheme for examples, fixtures, tests and docs

The repository is public. Real lab names never appear here, in current files or in history (see `CLAUDE.md`, standing directives).
This scheme gives every role in a typical lab a generic, readable name that mirrors the lab's structure without revealing it. The
real-to-generic mapping is kept only in `C:\ClaudeCode\private\NAME-MAP.txt` (outside the repository, never committed).

IP addresses may be real. Prefer the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in new fixtures.

## Reserved DNS names
Only `example.test` and its sub-domains are used (`.test` is reserved by RFC 6761 and never resolves on the public internet).
Documentation examples, screenshots, `demo/` and the demo site use the fictional company in `docs/DEMO-WORLD.md` instead
(`alcyone-orbital.example`; `.example` is reserved by RFC 2606). Tests and fixtures keep `example.test`.

| Role | Generic name | Notes |
|---|---|---|
| Forest root and primary domain | `corp.example.test` | NetBIOS name `CORP` |
| Second tree in the same forest | `branch.example.test` | a tree root, not a child of `corp` |
| Child domain | `child.corp.example.test` | |
| Forest trusted from outside (inbound or outbound) | `partner.example.test` | |
| An unrelated outside host | `elsewhere.example.test`, `other.example.test` | for scope tests (External / OtherForest) |
| PKI zone (CA, CDP, AIA, OCSP hosts) | `pki.example.test` | the DNS zone for PKI roles |

## Hosts
Names say the role, then a two-digit number. A new host gets the next number (`sub-ca02`).

| Role | Generic name |
|---|---|
| Domain controller | `dc01.corp.example.test`, `dc02.corp.example.test` |
| Offline or online root CA | `root-ca01.pki.example.test` |
| Issuing (subordinate) CA | `sub-ca01.pki.example.test`, `sub-ca02.pki.example.test` |
| NDES / SCEP server | `ndes01.pki.example.test` |
| Certificate Enrollment Web Service / Policy Web Service | `ces01.pki.example.test`, `cep01.pki.example.test` |
| Online Responder (OCSP) | `ocsp01.pki.example.test` |
| CDP / AIA web server | `crl01.pki.example.test` (or `pki.example.test` for a shared alias) |
| Ordinary web server or the computer the tool runs on | `web01.corp.example.test`, `ws01.corp.example.test` |
| A DNS alias that has no record | `app.corp.example.test` |

Older fixtures use `ca01`, `ca02` (CA hosts), `scep-gw01` to `scep-gw09` (NDES hosts) and `ces`, `ocsp`, `pki`, `pki2` under
`corp.example.test`. They are generic as well and stay valid; do not rename them only to follow this table. New fixtures should use the
table above.

## Names inside Active Directory
| Role | Generic name |
|---|---|
| Root CA (the CA's own name) | `Example-Root-CA` |
| Subordinate CA | `Example-Sub-CA` (a second one: `Example-Sub-CA2`) |
| Custom certificate template | `Example-<purpose>`, for example `Example-WebServer`, `Example-RDPServerAuth`, `Example-NDES-01` |
| Template applied to an application | `ExampleApp`, `ExampleApp2` |
| NDES service account | `svc-ndes` (registration-authority account: `svc-ndes-ra`) |
| Ordinary administrator / standard account used in examples | `CORP\pki-admin`, `CORP\std-user` |
| A device certificate subject | `device01` |
| Group policy object | `Example RDP Certificate Binding` |
| Site | `Default-First-Site-Name` (a Microsoft default) |

Microsoft's own names (`SubCA`, `CA`, `WebServer`, `User`, `Machine`, `EnrollmentAgent`, `MSCEP-RA`, container names such as
`Public Key Services`) are not lab names and stay as they are.

## Rules
1. A new fixture, test, example or doc line uses a name from this file. If a role is missing, add it here first (in the same style), then use it.
2. Distinguishing parts of a real name (a company, project, person, or lab prefix) are never carried over, not even as a prefix, suffix or
   part of a certificate subject. The generic name replaces the whole real name.
3. Never write the real name next to its generic name anywhere in the repository. The mapping lives only in `NAME-MAP.txt`.
4. A local pre-commit hook (not committed) blocks any commit whose staged content, message or author contains a name from `NAME-MAP.txt`.
5. The M14 history check (`tests/Hygiene.Tests.ps1`) accepts `MSPKI_PRIVATE_NAMES_FILE` pointing at `NAME-MAP.txt` and counts every name in every
   commit, message, path and identity.
