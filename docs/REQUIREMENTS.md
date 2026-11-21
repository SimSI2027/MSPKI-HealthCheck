# MSPKI Health Check: requirements

## 1. Goal
Run `Invoke-MspkiHealthCheck.ps1` from any domain-joined Windows computer with no configuration. The tool
works out the Microsoft PKI infrastructure on its own, checks its health and produces an evidence-based
report. Every result says where it came from and how sure the tool is.

The rules in `CLAUDE.md` apply everywhere and take priority over anything below.

## 2. Ways of running it
- `.\Invoke-MspkiHealthCheck.ps1`: full run with defaults. Output goes to `out\<yyyyMMdd-HHmmss>\`.
- Optional parameters: `-OutputPath`, `-TimeoutSeconds` (default 5), threshold overrides, `-SkipNetwork`,
  `-CertificateFile <path.cer>` (end-to-end validation), `-IncludeCertUtilVerify` (opt-in).
- No administrative rights needed. Checks that need extra rights record `PermissionDenied` and the run continues.
- Exit codes: `0` passed or not applicable, `2` informational, `3` warnings, `4` failures or critical,
  `5` incomplete because something is unsupported, `6` incomplete because of permissions.

## 3. Finding model (build this first; everything else depends on it)
Every result is one object created by `New-MspkiFinding`:

| Field | Meaning |
|---|---|
| `Id`, `Timestamp`, `Stage` | unique id, UTC time, discovery/check stage |
| `Category` | CA, Hierarchy, CRL, AIA, CDP, OCSP, ADContainer, Template, CEP, CES, NDES, IntuneConnector, StaleRef, ADDependency, Run |
| `Role` | PKI role of the target (EnterpriseRoot, StandaloneRoot, Intermediate, IssuingCA, CDPEndpoint, …, Unknown) |
| `Target` / `Endpoint` | object or host / normalised URL |
| `RelatedCA` | CA (and certificate thumbprint) this belongs to, where known |
| `Sources` | **array** of every discovery source (e.g. `AD:EnrollmentServices`, `Cert:<thumbprint>:CDP`, `Policy:CEP`) |
| `Confidence` | `Confirmed` (authoritative and validated) · `Referenced` (explicitly in a cert/CRL/AD object/policy) · `Inferred` (built from strong evidence, not validated) · `Unknown` |
| Layer statuses | `DiscoveryStatus`, `DnsStatus`, `TcpStatus`, `HttpStatus`, `RedirectStatus`, `TlsStatus`, `ContentStatus`, `ChainStatus`, each `NotTested` until it is tested |
| `Status` | Pass · Information · Warning · Fail · Critical · NotApplicable · Skipped · Error |
| `Severity` | (templates/security) High · Medium · Low · Information · ReviewRequired |
| `StatusCode` | stable machine code (see below) |
| `Scope` | Local · OtherForest · External (from the DNS suffix compared with the current forest's domains) |
| `Forest`, `Domain` | context the run discovered |
| `Message`, `Evidence` (array of strings), `Remediation`, `Notes` | human-readable details; Evidence lists every condition behind the result |

**StatusCode values (keep them separate, never merge them):** `DNS_FAIL`, `TCP_FAIL`, `TIMEOUT`, `HTTP_REDIRECT`,
`HTTP_400`, `HTTP_401_403`, `HTTP_404`, `HTTP_500`, `TLS_HANDSHAKE_FAIL`, `TLS_UNTRUSTED_ROOT`, `TLS_PARTIAL_CHAIN`,
`TLS_NAME_MISMATCH`, `CONTENT_WRONG_TYPE`, `SIGNATURE_INVALID`, `OBJECT_EXPIRED`, `OBJECT_EXPIRING`, `STALE_DATA`,
`PUBLICATION_FAIL`, `RETRIEVAL_FAIL`, `EXPECTED_OFFLINE`, `PERMISSION_DENIED`, `NOT_CONFIGURED`, `NOT_DISCOVERED`,
`NOT_APPLICABLE`, `UNSUPPORTED`, `OK`.
Added in build phase B for CA chains (local trust, not TLS): `CHAIN_UNTRUSTED_ROOT`, `CHAIN_PARTIAL`, `CHAIN_INVALID`.

Rules:
- An endpoint failure is not the same thing as local trust failure.
- A TLS name mismatch is not service unavailability.
- A redirect is recorded on its own, separately from the final download result.
- "Not discovered", "not configured", "not reachable" and "not applicable" must stay distinct.

## 4. Discovery design
### 4.1 Seeds (authoritative starting points)
- RootDSE: `configurationNamingContext`, `rootDomainNamingContext`, `dnsHostName` (the DC selected for the run).
- `System.DirectoryServices.ActiveDirectory` for the current domain, forest, forest domains, AD site and trusts.
- `CN=Public Key Services,CN=Services,<ConfigNC>`: `Enrollment Services`, `Certification Authorities`,
  `AIA`, `CDP`, `Certificate Templates`, `OID`, `KRA`, `NTAuthCertificates`. Use targeted one-level/base
  searches with explicit attribute lists. Never search the whole forest.
- Each Enterprise CA's `pKIEnrollmentService` object: `dNSHostName`, `cACertificate`, `certificateTemplates`,
  `msPKI-Enrollment-Servers` (CES URLs, so CES URLs never have to be built from names).
- CA properties through `CertificateAuthority.Request` → `GetCAProperty` (the same call `certutil -CAInfo` uses):
  CA certificates (current and previous), chain, CRL state, CA type. This replaces `certutil -ping`.
- Local computer: enrollment policy servers under `HKLM`/`HKCU\Software\Policies\Microsoft\Cryptography\PolicyServers`
  (CEP), machine certificate stores, installed services and products (Intune Connector, read locally only).

### 4.2 Leads (only these get probed)
- A lead is a host or URL taken from a seed, certificate (AIA caIssuers, OCSP, CDP), CRL (Freshest CRL,
  IDP), AD object or policy. Each lead records **which object it came from**.
- Probing a lead may add new leads only by parsing objects it downloads (e.g. an issuer certificate's CDP).
  Maximum depth 5. Cap of 1000 leads per run. Both limits are logged and shown under Run details if reached.
- **Normalise before deduplicating:** host-name case; scheme (keep http and https as variants of one
  endpoint); `%20` and spaces; trailing slash; short name → FQDN only where DNS proves the same host (the short name resolves to
  that FQDN, or both resolve to one canonical name; a shared IP alone is not proof; the short URL stays as an alias). When duplicates
  merge, combine `Sources`; never drop any.
- **Scope:** compare the DNS suffix with the current forest's domains → `Local`, with trusted forests →
  `OtherForest`, anything else → `External`. A cross-environment reference goes to review; it is never a
  failure by default.

### 4.3 Probes (shared, cached for the run)
- DNS (`[System.Net.Dns]`), TCP connect, HTTP(S) via `HttpWebRequest` with `AllowAutoRedirect = $false`
  (follow redirects manually and record each hop), TLS server certificate, chain and name check, LDAP/LDAPS bind and latency.
- Cache results by normalised key. Every probe has a timeout. Check for cancellation (Ctrl+C) between probes.

## 5. Checks by area
### 5.1 CA, hierarchy and lifecycle
- Role from the evidence: self-signed and not an Enterprise CA → StandaloneRoot; in Enrollment Services →
  Enterprise; also check Basic Constraints and path length. Otherwise `Unknown`. Don't assume a two-tier design.
- For each CA certificate show: valid from/to, days left, parent, chain status, key algorithm/length, signature
  algorithm, Basic Constraints, Key Usage, current vs historical, self-signed as expected, and whether it
  expires after its parent.
- Thresholds (parameters): root CA certificate warning 730 days / critical 365 days. Issuing CA certificate
  warning 180 / critical 90.
- An offline root with a valid certificate and CRL is `EXPECTED_OFFLINE`, not a failure.

### 5.2 CRLs (base and delta)
- Show ThisUpdate, NextUpdate, validity period, % of lifetime used, time remaining, CRL number,
  base/delta, issuer, whether the issuer matches, signature check, download source.
- Decode with the CertEnroll COM CRL object or a small pure-PowerShell ASN.1 reader. Use `certutil` only if neither works.
- Thresholds (parameters, separate for offline roots and issuing CAs): Pass < 75% · Warning 75–95% · Critical ≥ 95% ·
  Fail when expired · NotApplicable when delta CRLs are disabled · Unknown when it can't be validated.
- Enabled or disabled delta CRLs are a configuration fact, not an error.
- The CA's own current base and delta CRL are read with `GetCAProperty` (CR_PROP_BASECRL 17 / DELTACRL 18, Base64
  data decoded only by `ConvertFrom-MspkiBase64Data`) and compared with each CDP location by issuer, base/delta and
  CA version. Same CRL number = published correctly (Pass). Older number = `PUBLICATION_FAIL` (the served CRL has
  expired, or the CA's newer CRL is older than `-CrlPublicationGraceMinutes`, default 60) or `STALE_DATA` (the CA's
  newer CRL is younger than that, so publication may still be in progress).

### 5.3 AIA / CDP / OCSP endpoints
- Check every lead's layers separately (§3). Validate downloaded content (is it a certificate or CRL, and the right one?).
- OCSP: find the URL from AIA. Reachability is not health. Do a full validation only with `-CertificateFile`.

### 5.4 AD PKI container consistency (review only, never recommend deletion)
- An Enterprise CA without matching AIA or Certification Authorities data
- An authentication CA missing from NTAuth
- A template published by no active CA, or a published template name with no template object
- Several CA certificates with no clear current/historical split
- KRA configured but its certificate is missing or expired
- An OID linked to a group that can't be resolved
- AD publication that disagrees with the CA's properties

### 5.5 Certificate templates (defensive review, no enrollment code)
- Read `msPKI-Certificate-Name-Flag`, `msPKI-Enrollment-Flag`, `pKIExtendedKeyUsage`,
  `msPKI-Certificate-Application-Policy`, `msPKI-RA-Signature`, `msPKI-RA-Application-Policies`, `msPKI-RA-Policies`,
  `msPKI-Certificate-Policy`, the security descriptor, and `msDS-OIDToGroupLink` on OIDs. Resolve each SID **once per run** (cache).
- "Broad groups" means Everyone, Authenticated Users, Domain Users, Domain Computers, plus their forest equivalents.
- A finding needs **every** condition below and lists each one in `Evidence`. One flag on its own is never a finding:
  - **ESC1**: published + broad enroll + enrollee supplies subject + client-auth-capable EKU (Client Auth, PKINIT,
    Smart Card Logon, Any Purpose, or no EKU) + no manager approval + no authorised signatures.
  - **ESC2**: published + broad enroll + Any Purpose or no EKU + no approval + no signatures.
  - **ESC3**: published + broad enroll + Certificate Request Agent EKU + no approval, **and** another published
    template that accepts enrollment-agent signatures and is client-auth capable.
  - **ESC4**: broad groups with write/owner/full-control rights on a template object.
  - **ESC9**: `CT_FLAG_NO_SECURITY_EXTENSION` + client-auth EKU + broad enroll. Severity `ReviewRequired`, because DC
    certificate-binding enforcement can't be confirmed from here.
  - **ESC13**: an issuance policy linked to a group by `msDS-OIDToGroupLink` + a template carrying that policy + broad enroll.
- Unpublished templates are reported at one severity step lower and marked `Unpublished`.

### 5.6 CEP / CES
- CES: from `msPKI-Enrollment-Servers` (format: priority, auth type, renewal-only, URL) → `Referenced`.
- CEP: from local policy → `Referenced`. A URL built from a CA's host name is `Inferred` and labelled "constructed candidate".
- A response such as HTTP 400, 401 or 405 proves the service is reachable. Report reachability, authentication required,
  TLS trust, TLS name match and content as separate fields.
- Classifications: Configured (policy) · Discovered (AD) · ConstructedCandidate · ConfirmedResponding · Unreachable.

### 5.7 NDES / SCEP
- Evidence for a candidate host:
  1. CA database (read-only `CertificateAuthority.View`, needs CA Read rights; otherwise `PermissionDenied`):
     hosts issued certificates from the **CEP Encryption** and **Exchange Enrollment Agent (Offline request)** templates.
  2. Templates and EKUs typically used for SCEP.
  3. Enrollment URLs in policy or certificates.
- Probe only candidate hosts, and only these requests:
  - `GET /certsrv/mscep/mscep.dll?operation=GetCACaps` and `GetCACert`. These are standard read-only SCEP operations.
  - `/certsrv/mscep_admin/` **anonymously only** (`UseDefaultCredentials = $false`, no credentials). A 401 proves the
    admin endpoint exists. **Never send credentials there**: an authenticated request generates a challenge password.
- Classifications: ConfirmedEndpoint · ReferencedEndpoint · ProbableCandidate · UnconfirmedCandidate · NotDiscovered.

### 5.8 Intune Certificate Connector
- Check only the local machine: services (name, status, start type, executable path), installed products, certificate stores
  (metadata only).
- Keep the signature list of service and product names in one file, `src/Discovery/IntuneConnectorSignatures.ps1`, with a
  comment pointing to the Microsoft source it came from.
- Hosts other than the local one: report `UNSUPPORTED` with the note "remote connector discovery is not reliable without
  Microsoft Graph". Never assume an NDES host is a connector host.

### 5.9 Historical and stale references (review only)
- Compare active Enterprise CA objects, current and historical CA certificates, AIA/CDP in AD, URLs in current and expired
  certificates, DNS results, reachability.
- Classifications: ActiveConfirmed · CurrentReference · HistoricalReference · UnreachableReference · StaleReferenceCandidate.
- Never classify by host name, OS, age or reachability alone. An old URL may still be needed by certificates that haven't
  expired; say so in the Evidence.

### 5.10 Focused AD dependencies
- Selected DC, site, DNS, LDAP/LDAPS bind and latency, time offset to the DC, and Configuration-partition replication health
  only if it can be read without admin rights. Record how long each stage takes. Do not turn this into a general AD health check.

### 5.11 Optional
- `-CertificateFile`: `X509Chain` with online revocation, listing each embedded URL and its result. `-IncludeCertUtilVerify`
  also runs `certutil -verify -urlfetch` and parses the output.
- Later phase: CES SPNs and service-account encryption types (read-only, informational).

## 6. Outputs
- `results.json` (all findings plus run metadata: forest, domain, DC, user context, admin yes/no, stage timings,
  methods tried and their outcome), `findings.csv` (opens in Excel), `report.html`, `run.log`.
- `report.html` is a single offline file: inline CSS/JS, no CDN, no web fonts. Sections: Summary, Discovery Map
  (hierarchical tree: forest → CAs → certs → endpoints/templates/CES/NDES, each showing confidence and source),
  Findings (filter by category/status/confidence), Evidence, Run details.
- Native Excel (.xlsx) is deferred. If it's added later, use pure OpenXML with no Excel COM.
- Exports are cleaned: no private keys, secrets or raw security descriptors beyond the resolved names.

## 7. Phases (test before moving on)
The work is tracked as five build phases. Each one groups the detailed steps in the table below.

| Build phase | Scope | Steps |
|---|---|---|
| **A** | Skeleton + AD/CA discovery: module, finding model, log, JSON, Pester; forest, domain, DC, PKI containers, Enterprise CAs, every CA certificate generation, CA properties (or permission denied) | 0, 1 |
| **B** | Following links (lead registry, normalisation, scope, probes), web checks, CRL and CA certificate health | 2, 3 |
| **C** | HTML report, CSV, exit codes | 4 |
| **D** | Template/CA security review, CEP/CES, NDES, Intune Connector (local), stale references | 5, 6, 7 |
| **E** | Extras | 8, 9 |

| # | Phase | Done when |
|---|---|---|
| 0 | REF-INVENTORY + skeleton: module, `New-MspkiFinding`, log, JSON writer, Pester harness, entry point | empty run writes a valid `results.json` |
| 1 | Seeds: forest/domain/DC, PKI containers, Enterprise CAs, CA properties | fixture tests pass; live run lists CAs with sources |
| 2 | Lead registry + normalisation + scope; Probes with cache/timeouts | dedup tests pass; AIA/CDP leads probed with separate layer statuses |
| 3 | CA lifecycle, hierarchy, CRL analysis | thresholds tested with fixtures |
| 4 | HTML report + CSV + exit codes | report opens offline; exit codes tested |
| 5 | AD container consistency + template review | each ESC rule has a positive and negative fixture test |
| 6 | CEP/CES, NDES/SCEP, Intune local | NDES probes limited to the allowed requests (test asserts it) |
| 7 | Stale-reference analysis | every classification has evidence |
| 8 | Optional: `-CertificateFile`, AD dependencies, Kerberos/CES review | — |
| 9 | Optional: WPF launcher (XAML in its own file) and xlsx | — |

## 8. Testing
- Fixtures: sanitised samples (LDAP results as JSON, `.cer` and `.crl` files from a lab) using `example.test` names only.
- Zero-configuration test: run on a domain-joined computer as a standard user with no parameters. It must finish, report
  every discovery method's outcome, and show no false Confirmed results.
- Side-by-side: the same computer, v2.5.0 vs this tool. Compare the CAs, templates, AIA/CDP and CES each one found and
  explain every difference.
- Rollback: keep using v2.5.0 from its original location. This project never touches it.

## 9. Known limits (state them in the report)
- NDES detection depends on CA read rights or on references existing.
- Intune Connector detection is local only.
- ESC9 can't be fully judged without DC registry settings.
- CEP URLs only appear if policy on this computer points to them.
