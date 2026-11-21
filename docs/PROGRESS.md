# Progress log

Newest entry first. Keep each entry to 3–6 lines: phase, what was done, what is next, open issues.
Build phases A–E map to the numbered steps in REQUIREMENTS §7.

## Phase C: HTML report, CSV, exit codes, demo — done
- Done: `report.html` (one offline file, CSP blocks all network; summary, exit-code card, Discovery Map tree
  forest > CAs > certificates > endpoints/templates/CES with confidence + sources, filterable findings with
  evidence, run details, limits); `findings.csv` (UTF-8 BOM, formula-safe); exit codes 0/2/3/4/5/6 (an interrupted
  run is >= 5, meaning table, deciding findings); a reporter failure becomes a finding. `demo\Invoke-MspkiDemo.ps1`
  builds `out\demo\report.html` from `tests\fixtures\demo-results.json` (example.test only). 319 tests.
- Fixed on the way: `$PSScriptRoot` is empty in the entry script's parameter defaults (default `-OutputPath` would
  have failed); the default is now set in the script body.
- Next: Phase D (template/CA security review, CEP/CES, NDES, Intune local, stale references).
- Open: report regeneration from a results.json above ~2 MB is limited by Windows PowerShell 5.1 `ConvertFrom-Json`
  (live runs are not affected). Not yet run against a live AD CS.

## Fixes before Phase C (Base64 data, link following, short names) — done
- Base64: CLAUDE.md rule 6 now allows decoding Base64 DATA (certificates/CRLs from CA properties) only in
  `ConvertFrom-MspkiBase64Data` (DER-shaped, size-limited); hygiene test enforces one file. The CA's own base/delta CRL
  (GetCAProperty 17/18) is compared with each CDP location by issuer, base/delta and CA version: same number =
  published correctly; older = `PUBLICATION_FAIL` (expired, or the CA's newer CRL older than `-CrlPublicationGraceMinutes`,
  default 60) or `STALE_DATA` (within the grace period).
- Link following: depth 5, 1000 leads; each cap is logged and shown under Run details (final counts in run.log).
- Short name -> FQDN merge only when DNS proves the same host (short name resolves to the FQDN, or both share a
  canonical name; a shared IP alone is not proof); sources/origins are combined, the short URL stays as an alias.
- Decisions: the publish-status flags of the CA are shown raw, not interpreted (not verified on a live CA).
  Lead ids are now a monotonic counter (merging removes leads).

## Phase B (steps 2–3), part 2: endpoints + CRL health — done (Phase B complete)
- Done: anonymous HTTP GET (no credentials, manual redirects recorded per hop, 10 MB cap, cached); TLS handshake
  probe (name match, untrusted root, partial chain kept apart); LDAP-URL fetch (PUBLICATION_FAIL vs
  PERMISSION_DENIED); per-lead findings with DNS/TCP/TLS/HTTP/redirect/content layers; AIA content checked
  against the expected issuer; downloaded certificates and Freshest CRL links add leads at depth + 1; CRL decode
  and health (signature, issuer, base/delta, % of lifetime with separate root/issuing thresholds); STALE_DATA when
  one location serves an older CRL number. OCSP: reachability only. 235 tests (loopback HTTP server, no internet).
- Next: Phase C — HTML report (single offline file), findings.csv, exit-code polish; then Phase D.
- Open: still not run against a live AD CS. (Resolved later: the CA's own CRL via GetCAProperty is now read, see above.)

## Phase B (steps 2–3), part 1: leads + CA certificate health — done
- Done: pure-PowerShell DER reader; CDP/Freshest CRL/AIA/OCSP URL extraction from certificates; lead registry
  (normalised keys: host case, http/https, default ports, %20, trailing slash; merged sources/origins/variants;
  scope; depth 3 and cap 300 logged as a run limit); leads from CA certificates, CA properties and CES.
  Signature check (RSA, RSA-PSS, ECDSA) with the issuer key; CA certificate health: validity vs thresholds
  (limited by the parent), chain (partial / bad signature / untrusted root on this computer). 209 tests.
- Next (part 2): HTTP (anonymous GET, manual redirects, size cap) and LDAP fetch of AIA/CDP leads with separate
  layer statuses; content validation; CRL decoding and health (base/delta, % of lifetime, issuer, signature).
- Decision: added status codes `CHAIN_UNTRUSTED_ROOT`, `CHAIN_PARTIAL`, `CHAIN_INVALID` (REQUIREMENTS §3) so CA
  chain problems are not reported with TLS codes. Chains are built from discovered certificates only (no
  CryptoAPI chain engine), so no hidden AIA downloads happen, also with `-SkipNetwork`.

## Phase A (steps 0–1): skeleton + AD/CA discovery — done
- Done: module (`src/`), `New-MspkiFinding` + schema, error classification (permission vs unreachable vs
  timeout vs not found vs unsupported), run context, log, output-folder write guard, `results.json`, exit
  codes, DNS/TCP probes with cache, time-limited runspace for DCOM; discovery of forest, domains, trusts,
  DC, site, the 8 PKI containers, Enterprise CAs (incl. CES URLs), AD-published CA certificates and CA
  properties via `CertificateAuthority.Request.GetCAProperty`; every CA certificate generation merged by
  thumbprint with combined sources and current/historical. 167 Pester tests (incl. hygiene/name scan).
- Next: Phase B — lead registry (AIA/CDP/OCSP from certificates, CA properties and AD), normalisation,
  HTTP/LDAP/TLS probes, CRL decoding (CertEnroll `X509Enrollment.CX509CertificateRevocationList`) and
  CA certificate / CRL health with thresholds.
- Open: not yet run against a live AD CS (dev machine is not domain-joined; that path ends with exit 5).
  Verify the CR_PROP ids (41–43 URLs, 39 version) and CA-name-vs-cn config strings on a real CA.

### Decisions (Phase A)
- Discovery facts are `Information` + `OK`; they do not raise the exit code. Exit precedence 4 > 6 > 5 > 3 > 2 > 0.
- CA COM calls run only after DNS and TCP 135 succeed, inside a runspace with a hard limit (max(15, 4×timeout) s).
- CA binary properties are requested as Base64 data. (Superseded: they are now decoded by `ConvertFrom-MspkiBase64Data`,
  the one place where Base64 data decoding is allowed; see the fixes entry above.)
- CA config string = `dNSHostName\displayName` (falls back to `cn`). CA_DISP 4 is reported as `Invalid`.
- Role/lifecycle without CA data: Enterprise CA from AD → `Referenced`; same-subject dating → `Inferred`; only the
  CA's own signing-certificate list gives `Confirmed`.
- Dev only: Pester 6.2 installed for the current user (in-box Pester 3.4 is too old). The tool has no dependency.
