# The demo world: Alcyone Orbital Systems

A fictional company used for screenshots, documentation examples, the public demo site and the GUI prototype.
**Test fixtures keep `example.test`** (`docs/NAMING.md`). Real lab names never appear here or anywhere in the repository.

## Why this name
The brief asked for "Halcyon Orbital Systems". A quick check (2026-11-23) found that **Halcyon** is a well-known cybersecurity vendor
(anti-ransomware, including "key material interception"). A security tool's demo company with the same name would look affiliated, so the
name was adjusted. **Alcyone** is the star that *halcyon* comes from (the brightest of the Pleiades). The check found no company or brand
called "Alcyone Orbital" (only a small CubeSat mission uses "Alcyone"). Sources: web searches for "Halcyon Orbital", "Halcyon" with space
and security, and "Alcyone Orbital" (2026-11-23).

**Alcyone Orbital Systems** runs a small constellation of Earth-observation satellites. Engineering runs the ground stations; a separate
tree in the same forest runs flight operations; a launch partner's forest trusts it. The PKI is two-tier, partly modernised, and carries
the kind of drift real estates have: an older CA certificate generation left behind, LDAP-only publication, an Online Responder nobody
points to, and an NDES server for the ground-station devices.

## DNS and domains
`.example` is reserved by RFC 2606 and never resolves on the public internet.

| Role | Name | Notes |
|---|---|---|
| Forest root and primary domain | `alcyone-orbital.example` | NetBIOS `ALCYONE` |
| Second tree in the same forest | `flightops.example` | tree root, two-way transitive within the forest |
| Forest trusted from outside (inbound only) | `launchpartner.example` | outside bounded discovery: never probed |
| PKI zone (CA, CDP, AIA, OCSP, NDES hosts) | `vault.alcyone-orbital.example` | the PKI hosts live here |
| Site | `Default-First-Site-Name` | a Microsoft default |

## Hosts
Addresses come from the documentation range `192.0.2.0/24` (RFC 5737).

| Role | Host | Address | What the demo shows |
|---|---|---|---|
| Domain controller (PDC) | `dc-north.alcyone-orbital.example` | 192.0.2.10 | |
| Enterprise Root CA (online, domain-joined) | `root-ca.vault.alcyone-orbital.example` | 192.0.2.21 | IIS answers on 80; `/certsrv/` returns 403; HTTPS resets the connection; an Online Responder service runs but no certificate names it (`/ocsp/` returns 500); no PTR record |
| Enterprise issuing CA | `issuing-ca.vault.alcyone-orbital.example` | 192.0.2.22 | no web server; 80/443 filtered; no PTR record |
| NDES / SCEP server | `scep-gateway.vault.alcyone-orbital.example` | 192.0.2.24 | GetCACaps and GetCACert answer on HTTP and HTTPS; remote service control refused (RPC 1722); TLS certificate from the issuing CA |
| Ground-station web server, where the tool runs | `groundstation-web.alcyone-orbital.example` | 192.0.2.32 | an RDP certificate from a GPO-driven template and a manually requested web certificate whose SAN names an alias with no DNS record |
| Dead alias in that web certificate | `telemetry.alcyone-orbital.example` | (none) | no record: shown as expected but missing |
| Shared CDP/AIA web alias (the `healthy` scenario only) | `pki.alcyone-orbital.example` | CNAME to root-ca | |

## Certification authorities
| CA | Host | Certificate generations | Notes |
|---|---|---|---|
| **Alcyone Lodestar Root CA** (Enterprise Root) | root-ca | one: 5 years, RSA 2048, SHA-256 | no CDP or AIA in its own certificate; in Certification Authorities, AIA, NTAuth, Enrollment Services; publishes 3 templates (CA, CrossCA, SubCA) |
| **Alcyone Meridian Issuing CA** (Enterprise Subordinate) | issuing-ca | two: the current one (2 years) and an older one 11 days earlier | the older generation is in NTAuth but not in AIA, and the CA's own signing list holds only the current one: "no clear current/historical split" |

- **Publication: LDAP only.** Every AIA and CDP URL written by both CAs is `ldap:///CN=...,CN=AIA|CDP,CN=Public Key Services,...`. No HTTP
  CDP or AIA, no OCSP URL (the CA's OCSP property is empty). The issuing CA's CDP URL has no attribute part (valid: clients use the defaults).
- **CRLs:** base and delta for both CAs, all fresh; the numbers in AD match the CAs' own CRLs.
- **Templates:** 43 template objects, 25 published (3 on the root, 22 on the issuing CA), 18 published nowhere. Custom templates:

| Template | Purpose |
|---|---|
| `Alcyone-WebServer` | IIS and ground-station HTTPS |
| `Alcyone-RDPServerAuth` | RDP, deployed by the GPO `Alcyone RDP Certificate Binding` |
| `Alcyone-NDES-Agent`, `Alcyone-NDES-Encryption` | NDES registration authority (Enrollment Agent offline, CEP Encryption) |
| `Alcyone-NDES-Device`, `Alcyone-NDES-HTTPS` | ground-station device certificates issued through SCEP; the gateway's HTTPS |
| `Alcyone-Telemetry`, `Alcyone-Telemetry2` | application certificates for the telemetry service |

## Accounts and NDES trail
| Object | Name | Notes |
|---|---|---|
| NDES service account | `svc-scep` | a user account with SPN `HTTP/scep-gateway...`; holds Enroll on the four NDES templates |
| Second RA account | `svc-scep-ra` | user, no SPN |
| RA certificate subject | `scep-gateway-mscep-ra` | from `Alcyone-NDES-Agent` |
| Test device | `groundstation-unit01` | from `Alcyone-NDES-Device` |
| Administrator / standard user in examples | `ALCYONE\pki-admin`, `ALCYONE\ops-analyst` | |

## Scenarios (variants of the same world, for the demo site and screenshots)
Each scenario changes one thing in the simulated environment and lets the real analysers grade it (`docs/DEMO-SITE.md`).

| Id | Scenario | What changes |
|---|---|---|
| `healthy` | Healthy PKI | HTTP CDP/AIA added on `pki.alcyone-orbital.example`, old generation removed from NTAuth, the responder configured, HTTPS fixed |
| `baseline` | As found (the default) | exactly the world described above |
| `expired-crl` | Expired CRL | the issuing CA's base CRL is 3 days past Next Update in AD and at the CA |
| `rpc-denied` | CA read refused | DCOM access denied to the standard user on the root CA host (0x800706BA; RPC fault 5) |
| `ldap-only` | LDAP-only publication seen from outside | the tool runs on a workgroup laptop in a partner network: every `ldap:///` URL is unreachable |
| `esc8` | Web enrollment over HTTP | `/certsrv/` on root-ca answers 200 over plain HTTP with NTLM offered |
| `forged-aia` | A forged certificate at an AIA URL | the AIA URL serves a certificate with the right name but a different key; the signature check fails |
| `ndes-found` | NDES found without the CA database view | the gateway is found from template permissions and SPNs, then confirmed by GetCACaps |
| `renewal-drift` | Renewal leftovers | a third CA generation, an expired one still in NTAuth and AIA |

## Rules for this world
1. Use it in documentation examples, screenshots, the demo site and `demo/`. Tests and `tests/fixtures/` keep `example.test`.
2. A new role is added to the tables above first, in the same style, then used.
3. Never mix it with `example.test` names in one example, and never put a real lab name next to a world name.
4. The hygiene scan allows `alcyone-orbital.example`, `flightops.example`, `launchpartner.example` and their sub-domains; any other
   `.example` name fails the scan.
