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
| Domain controller of the second tree | `dc-flight.flightops.example` | 192.0.2.11 | named by the forest's SRV records and server objects; never bound to |
| Enterprise Root CA (online, domain-joined) | `root-ca.vault.alcyone-orbital.example` | 192.0.2.21 | IIS answers on 80; `/certsrv/` returns 403; HTTPS resets the connection; an Online Responder service runs but no certificate names it (`/ocsp/` returns 500); no PTR record |
| Enterprise issuing CA | `issuing-ca.vault.alcyone-orbital.example` | 192.0.2.22 | no web server; 80/443 filtered; no PTR record |
| NDES / SCEP server | `scep-gateway.vault.alcyone-orbital.example` | 192.0.2.24 | GetCACaps and GetCACert answer on HTTP and HTTPS; remote service control refused (RPC 1722); TLS certificate from the issuing CA |
| Ground-station web server, where the tool runs (NetBIOS `GROUND-WEB`) | `ground-web.alcyone-orbital.example` | 192.0.2.32 | an RDP certificate from a GPO-driven template and a manually requested web certificate whose SAN names an alias with no DNS record |
| Dead alias in that web certificate | `telemetry.alcyone-orbital.example` | (none) | no record: shown as expected but missing |
| Shared CDP/AIA web alias (`healthy`, `mixed-sample`) | `pki.alcyone-orbital.example` | CNAME to root-ca | |
| Second CDP/AIA web alias (`mixed-sample`) | `pki-dr.alcyone-orbital.example` | 192.0.2.41 | serves an older CRL |
| Second issuing CA (`mixed-sample`) | `issuing-ca2.vault.alcyone-orbital.example` | 192.0.2.23 | the standard user cannot read its properties |
| Certificate Enrollment Web Service (`mixed-sample`) | `enroll.vault.alcyone-orbital.example` | 192.0.2.25 | |
| Online Responder (`mixed-sample`) | `ocsp.vault.alcyone-orbital.example` | 192.0.2.26 | |
| Retired PKI web host, still named in an AIA URL (`mixed-sample`) | `legacy-pki.alcyone-orbital.example` | (none) | no DNS record |
| PKI zone apex, used in older URLs (`mixed-sample`) | `vault.alcyone-orbital.example` | | |

## Certification authorities
| CA | Host | Certificate generations | Notes |
|---|---|---|---|
| **Alcyone Lodestar Root CA** (Enterprise Root) | root-ca | one: 5 years, RSA 2048, SHA-256 | no CDP or AIA in its own certificate; in Certification Authorities, AIA, NTAuth, Enrollment Services; publishes 3 templates (CA, CrossCA, SubCA) |
| **Alcyone Meridian Issuing CA** (Enterprise Subordinate) | issuing-ca | two: the current one (2 years, from 19 May 2026) and an older one 11 days earlier | the older generation is in NTAuth but not in AIA, and the CA's own signing list holds only the current one: "no clear current/historical split" |
| **Alcyone Zenith Issuing CA** (`mixed-sample` only) | issuing-ca2 | unknown (not readable) | the flight-operations issuing CA; DCOM refuses the standard user |

- **Publication: LDAP only.** Every AIA and CDP URL written by both CAs is `ldap:///CN=...,CN=AIA|CDP,CN=Public Key Services,...`. No HTTP
  CDP or AIA, no OCSP URL (the CA's OCSP property is empty). The issuing CA's CDP URL has no attribute part (valid: clients use the defaults).
- **CRLs:** base and delta for both CAs, all fresh; the numbers in AD match the CAs' own CRLs.
- **Templates:** 41 template objects (the 33 Windows defaults and 8 of Alcyone's own), 25 published (3 on the root, 22 on the issuing CA), 16 published nowhere. Custom templates:

| Template | Purpose |
|---|---|
| `Alcyone-WebServer` | IIS and ground-station HTTPS |
| `Alcyone-RDPServerAuth` | RDP, deployed by the GPO `Alcyone RDP Certificate Binding` |
| `Alcyone-NDES-Agent`, `Alcyone-NDES-Encryption` | NDES registration authority (Enrollment Agent offline, CEP Encryption) |
| `Alcyone-NDES-Device`, `Alcyone-NDES-HTTPS` | ground-station device certificates issued through SCEP; the gateway's HTTPS |
| `Alcyone-Telemetry`, `Alcyone-Telemetry2` | application certificates for the telemetry service |
| `AlcyoneGroundDevice` (`mixed-sample`) | ground-station device certificates (an older naming style) |

## Accounts and NDES trail
| Object | Name | Notes |
|---|---|---|
| NDES service account | `svc-scep` | a user account with SPN `HTTP/scep-gateway...`; holds Enroll on the four NDES templates |
| Second RA account | `svc-scep-ra` | user, no SPN |
| RA certificate subject | `scep-gateway-mscep-ra` | from `Alcyone-NDES-Agent` |
| Test device | `groundstation-unit01` | from `Alcyone-NDES-Device` |
| Administrator / standard user in examples | `ALCYONE\pki-admin`, `ALCYONE\ops-analyst` | the simulated runs are made as `ops-analyst` on GROUND-WEB |
| Web certificate enrollers | `Web Admins` (group) | holds Enroll on `Alcyone-WebServer` |

## Scenarios (variants of the same world, for the demo site and screenshots)
Each scenario changes one thing in the simulated environment and lets the real analysers grade it (`docs/DEMO-SITE.md`).

| Id | Scenario | What changes |
|---|---|---|
| `healthy` | Healthy PKI | HTTP CDP/AIA added on `pki.alcyone-orbital.example`, old generation removed from NTAuth, the responder configured, HTTPS fixed |
| `baseline` | As found (the default) | exactly the world described above |
| `expired-crl` | Expired CRL | the issuing CA's base CRL is 3 days past Next Update in AD and at the CA |
| `rpc-denied` | CA read refused | DCOM access denied to the standard user on the root CA host (0x800706BA within 25 ms; RPC fault 5) |
| `ldap-only` | LDAP-only publication seen from outside | the tool runs on `GROUND-LAPTOP`, a laptop outside the domain: it cannot read Active Directory, the only place an LDAP-only CDP or AIA can be read, so it reports what it could not check |
| `esc8` | Web enrollment over HTTP | `/certsrv/` on root-ca answers 200 over plain HTTP with NTLM offered |
| `forged-aia` | A forged certificate at an AIA URL | the AIA URL serves a certificate with the right name but a different key; the signature check fails |
| `ndes-found` | NDES found without the CA database view | no CA database is readable (both refuse the view); the gateway is found from template permissions and SPNs, then confirmed by GetCACaps |
| `renewal-drift` | Renewal leftovers | a third CA generation, an expired one still in NTAuth and AIA |
| `mixed-sample` | Mixed estate (the GUI prototype's sample) | an offline root (certificate only), HTTP and LDAP publication on `pki` and `pki-dr`, a retired host still in an AIA URL, CES and OCSP, a second issuing CA the standard user cannot read |

**Sample files.** `demo/world/alcyone-mixed-results.json` is the `mixed-sample` scenario. It is a **hand-made sample**: the `example.test`
demo results (`tests/fixtures/demo-results-v2.json`) with every name replaced by this world's names. It was **not** produced by the
analysers. The generator in `docs/DEMO-SITE.md` (DS3) replaces it with results the real analysers produce from simulated fixtures.
`demo/world/alcyone-expired-crl-results.json` (`expired-crl`) and `demo/world/alcyone-renewal-drift-results.json` (`renewal-drift`) are hand-made
samples too, derived from the mixed sample by the developer-only `tools/dev/New-MspkiDemoLifecycleSample.ps1` (idempotent; it also adds the CRL
objects the mixed sample's findings already describe). They feed the Timeline and Chain snapshots (GX7). The DS3 generator replaces all three.

## The simulated world (DS1)
The world above is data in `site/world`: `world.json` (directory objects, what each CA answers, DNS, TCP, TLS and HTTP answers, this
computer's stores, policy and services), written by `tools/dev/demo-site/New-MspkiDemoWorld.ps1`, and one overlay per scenario in
`site/world/scenarios/<id>.json`. `tools/dev/demo-site/Invoke-MspkiScenario.ps1` runs the real engine on it (`docs/DEMO-SITE.md` section 3).

Every scenario is generated by the real engine (DS3): `tools/dev/demo-site/Invoke-MspkiScenario.ps1 -Scenario all` writes `results.json`,
`events.json` (the replay) and `manifest.json` per scenario under `out\site-data`; a scenario fails on any question the world cannot answer,
any Error finding, or a permission refusal it does not expect (`expect.permissionDenied`).

## Demo clock and PKI material (DS2)
The world runs at a fixed **demo clock: 20 Nov 2026, 09:00 UTC** (`site/world/pki/pki.json`, `DemoClock`), so nothing looks expired unless a
scenario wants it to. `tools/dev/demo-site/New-MspkiWorldPki.ps1` (developer-only, Windows PowerShell 5.1) creates the public material once with
throw-away keys that exist only in memory; the DER files and `pki.json` (subject, issuer, thumbprint, dates and role of each file) are committed.
`tests/DemoGenerator.Tests.ps1` verifies every certificate and CRL with the engine's own signature code and checks that the forged root
verifies nothing.

| Files | What they are |
|---|---|
| `lodestar-root.cer`, `lodestar-root.crl` | the root (5 years, no CDP or AIA) and its base CRL (0x12) |
| `meridian-g0.cer`, `meridian-g1.cer` | the issuing CA's older (V0.0) and current (V1.1) generations, 11 days apart, LDAP-only URLs |
| `meridian.crl`, `meridian+.crl` | the issuing CA's base (0x2B) and delta (0x2C) CRLs |
| `meridian-healthy.cer`, `ground-web-rdp-healthy.cer`, `root-ca-tls-healthy.cer` | `healthy`: HTTP first, LDAP second; the PKI web host's HTTPS certificate |
| `meridian-expired-crl.crl`, `meridian-expired-delta.crl` | `expired-crl`: base 0x29 three days past Next Update, its delta |
| `meridian-g2.cer`, `meridian-g2.crl`, `meridian-expired.cer` | `renewal-drift`: a third generation (V2.2) and an expired one still published |
| `zenith.cer`, `zenith.crl` | `mixed-sample`: the flight-operations issuing CA |
| `lodestar-forged.cer` | `forged-aia`: the root's name with another key |
| `ground-web-rdp.cer`, `ground-web-tls.cer` | this computer's RDP certificate and web certificate (SAN with the dead `telemetry` alias) |
| `scep-gateway-tls.cer`, `ndes-ra-signing.cer`, `ndes-ra-encryption.cer` | the NDES gateway's HTTPS certificate and its registration authority certificates |

## Rules for this world
1. Use it in documentation examples, screenshots, the demo site and `demo/`. Tests and `tests/fixtures/` keep `example.test`.
2. A new role is added to the tables above first, in the same style, then used.
3. Never mix it with `example.test` names in one example, and never put a real lab name next to a world name.
4. The hygiene scan allows `alcyone-orbital.example`, `flightops.example`, `launchpartner.example` and their sub-domains; any other
   `.example` name fails the scan.
