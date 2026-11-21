# Progress log

Newest entry first. Keep each entry to 3–6 lines: phase, what was done, what is next, open issues.
Build phases A–E map to the numbered steps in REQUIREMENTS §7.

## GUI (WPF): `Start-MspkiHealthCheckGui.ps1`, `src\Gui\` — done (725 tests)
- Engine: optional `-Control` on `Start-MspkiHealthCheck` (`New-MspkiRunControl`: cancel flag + ConcurrentQueue; `src\Model\RunControl.ps1`). Stage starts, probes (DNS/TCP/TLS/HTTP/LDAP/COM)
  and log lines feed the queue; stage starts and probes throw `OperationCanceledException` once cancelled, DNS/TCP/COM waits poll every 200 ms (cancel ~1.5 s on the lab). A cancelled run writes
  the same four files, `RunInfo.Completed = false`, exit code at least 5, one Run finding saying so. Without `-Control` nothing changes (CLI untouched).
- GUI: XAML + `GuiModel.ps1` (pure helpers) + `GuiApp.ps1` (window, background STA runspace, DispatcherTimer reading the queue). Tabs: Summary (tiles, CAs), Discovery Map (TreeView over
  `Get-MspkiDiscoveryTree`), Findings (sortable DataGrid, text/status/category/confidence filters), Details (all fields, layers, evidence), Run Log (live, errors red). Open results.json
  without scanning. Closing mid-run cancels, waits, closes (forced after 45 s or a second close).
- Rule clarification added to CLAUDE.md: `Add-Type -AssemblyName` for PresentationFramework/PresentationCore/WindowsBase only; `-TypeDefinition`/`-MemberDefinition` still banned (Hygiene test updated, GUI files scanned).
- Tested here without seeing the screen: Pester (cancel flag, queue, helpers, XAML loads, window shows the example.test fixture, filter/sort in an STA runspace) and a harness that pumps the WPF
  dispatcher: full run on the lab (47 findings), Cancel mid-run, close mid-run (results.json Completed=false, no leftover runspace), open earlier results.json; screenshots rendered to a temp folder, not kept.
- Known limits: findings appear when the run ends (the engine returns them at the end); HTTP GET and TLS handshake are synchronous, so a cancel can wait up to one probe timeout for those;
  a results.json above ~2 MB cannot be opened (Windows PowerShell 5.1 `ConvertFrom-Json`), the window says so and points to report.html.
- Next: the user's click-through on the real screen (docs\TESTING.md, "Using the window"); fix what they report.

## Second live run on the lab computer + audit L5 — done (688 tests)
- Re-ran the tool (normal user): same result as the first live run, 47 findings, exit 4. The only Fail items are the two `RETRIEVAL_FAIL` (0x800706BA) from
  `GetCAProperty`; the finding already says "TCP 135 answered but the CA did not: the Certificate Services service may be stopped, or dynamic RPC ports are
  blocked". Nothing else is wrong in the log (all stages 10-760 ms except CES/CEP probing, 5 s). Not a tool bug; a firewall/CertSvc issue to fix on the lab side.
- Fixed audit L5: local-policy read errors were classified by English message text (`denied|unauthorized`); the exception is now kept and classified by type
  / HRESULT (`SecurityException` added to the permission types). Tests: type classification and a non-English message.
- Dev note: Pester 5.7.1 unpacked from the gallery package into `C:\ClaudeCode\tools\pester571` (outside the repo).
- Next: a run from a computer that reaches the CAs over RPC (or fix the lab RPC path), then fix what the CA-property/CA-database log shows; then the other Low
  findings (L4 timeouts on forest/domain/trust/bind/SID calls is the most relevant live) and Phase E.

## First live run: RootDSE fix, two false positives, -NoOpen — done (687 tests)
- Root cause of "RootDSE UNSUPPORTED, everything skipped": RootDSE was read with a `DirectorySearcher`, and the LDAP provider refuses searches on
  RootDSE ("The provider does not support searching and cannot search LDAP://RootDSE"). `Get-MspkiRootDse` now reads a `DirectoryEntry` (RefreshCache);
  a test checks that it never uses a searcher. `[ADSI]"LDAP://RootDSE"` worked on its own, so the bug was in the tool, not the lab.
- Discovery is harder to break: `Find-MspkiRootDse` tries serverless, the DC locator, `LDAP://<domain>/RootDSE`, a Global Catalog and last builds the
  Configuration NC from the forest root name (Warning / Inferred, DC unknown, later reads are serverless). Each attempt is logged as `AD:RootDSE:<name>`
  and listed in the evidence. Error findings now show the error code and message in the Message itself.
- False positives fixed: (1) ESC4 fired on every Enroll/Autoenroll ACE (mask 0x130 with the extended-right GUID looks like WriteProperty) for 11 templates;
  (2) an empty KRA object (the normal state without key archival) was a Warning, now Information. Tests for both.
- Live result on a normal user (lab, 1 enterprise root + 1 enterprise sub CA, 43 template objects, 3 and 22 published templates): AD side works (containers, CAs,
  CA certificates, templates and their ACLs, AIA/CDP leads, LDAP CDP/AIA checks). Counts agree with `certutil -ADCA` and the Enrollment Services objects.
- `-NoOpen` added; report.html now opens at the end of a run (`Invoke-Item` on the one report file; the suite passes -NoOpen).
- Still broken / not verifiable from this computer: `GetCAProperty` fails with 0x800706BA (RPC server unavailable) on both CAs and `certutil -CAInfo/-ping`
  fails the same way, although TCP 135 answers: a firewall or CertSvc problem outside the tool, correctly reported as Fail RETRIEVAL_FAIL. So the CR_PROP ids
  (they match certcli.h), the `CertificateAuthority.View` columns and the live CA-database NDES read are still not exercised; the connection string
  (host\name) is the one certutil uses. `msPKI-Enrollment-Servers` is not exercised either (no CES in this lab).
- Next: run from a computer that can reach the CAs over RPC (or an administrator account) and fix what that log shows; then Phase E and the Low findings.
  Dev note: Pester 5 is not installed on this lab computer; the suite was run with a Pester 5.7.1 copy unpacked in a temporary folder.

## Audit fixes (every High and Medium), first-live-run logging, docs/TESTING.md — done (675 tests; the new audit tests fail on the old code)
- Done, High: H1 an LDAP URL naming a host is contacted only for the selected DC or a host of the forest's own domains (never with -SkipNetwork,
  except the DC), and links in a downloaded AIA certificate are followed only when its key is proven; H2 CES/CEP HTTP 5xx = `Failing` / Fail /
  `HTTP_500`; H3 a lead carried only by expired or historical certificates or an older CA signing-certificate index is a review item (leads now
  keep `Carriers`; `LeadGrading.ps1`; the stale review still sees the failure).
- Done, Medium: M1 direct HTTP, no proxy (`-UseSystemProxy` opt-in, no credentials); M2 NDES admin GET only with `-IncludeNdesAdminProbe`; M3 "could not
  check" is never `SIGNATURE_INVALID`, issuer chosen by AKI/SKI, .NET release and signature-API check recorded; M4 expired + unconfirmed lifecycle =
  review; M5 External/OtherForest capped at Warning/ReviewRequired; M6 explicit TLS 1.2/1.1/1.0(+1.3) for the probe and, for the run, the process
  setting; M7 NDES `ConfirmedEndpoint` needs GetCACaps or GetCACert; M8 AIA Confirmed only with a proven key, NDES NotDiscovered Inferred/Unknown, Deny ACE =
  ReviewRequired/Inferred; M9 NTAuth warning only for a CA with a sign-in template; M10 new codes `INTERNAL_ERROR`, `HTTP_OTHER`, `CLOCK_SKEW`,
  `CONFIG_MISMATCH`, `STALE_REFERENCE`, TLS trust failures named by a handshake, first CA call classified at the call site; M11 tests (TLS listener, proxy, -SkipNetwork).
- Live-run logging: every CA connection string tried (display name, then common name after "no such CA"), every GetCAProperty call (name, id, index, data
  type, raw result type, size, time, error code; never a value), CA database view queries, `Stage ... started/took` lines, a closing summary line, run options.
  `docs/TESTING.md` explains the first run (normal user, administrator, what to send back, warning that the files hold real names).
- Decisions: `External`/`OtherForest` hosts are review items (a PKI published under another DNS name shows review items, not failures: check on the live run);
  the demo fixture is unchanged; CLAUDE.md rule 4 clarification and REQUIREMENTS updated for the opt-in admin request and the LDAP rule.
- Next: the first live run (docs/TESTING.md), then fix what the log shows; then Phase E and the Low findings below.
- Open Low findings (docs/AUDIT.md): L1 PFX bytes loaded by `X509Certificate2(byte[])` (check `GetCertContentType`); L2 the Windows chain engine can fetch
  intermediates unseen; L3 redirect targets not scoped or recorded as leads; L4 no timeout on forest/domain/trust calls, the LDAP bind and SID translation;
  L5 local-policy errors classified by localised text; L6 `results.json` exports template ACLs; L7 no CRL `Unknown` state, `EXPECTED_OFFLINE` never emitted,
  path length not validated, PEM CRLs rejected; L8 template review details (single-attribute write rights, BUILTIN\Users, v4 RA policies); L9 weak CES/CEP
  content check; L10 AMSI note for `Invoke-MspkiTimeLimitedScript` (README now tells operators to warn their security team); L11 hygiene test blind spots.
- Open: nothing has run against a live AD CS. Still assumptions: the CR_PROP ids, `CertificateAuthority.View` columns, `msPKI-Enrollment-Servers` layout, v4
  template attributes, IIS behaviours. The TLS-listener tests create a throw-away key container on the dev machine (removed again in AfterAll).
## Audit after Phase D (docs/AUDIT.md) — done, no code changed
- Done: full audit of src/, tests/, docs/ and git history against CLAUDE.md and REQUIREMENTS: 3 High, 11 Medium, 11 Low.
  572 tests pass under Windows PowerShell 5.1; no real names, e-mails or IPs; no forbidden AV/EDR pattern.
- High: LDAP URLs naming a host get an authenticated bind (also from unvalidated downloads, also with -SkipNetwork);
  CES/CEP HTTP 5xx reported as Pass/Confirmed; dead URLs in expired CA certificates graded Fail (exit 4).
- Next: fix H1, M1, M2 (credentials, proxy/WPAD, NDES admin GET), then the false Pass/Fail/Confirmed items with tests.
## Phase D: templates, CEP/CES, NDES, Intune connector, stale references — done (572 tests)
- Done: (1) AD container consistency + `CN=Certificate Templates` / `KRA` / `OID` read (SIDs named once per run, budgeted);
  `Test-MspkiAdContainerObject` (published name without object, unpublished templates, KRA missing/expired, OID group link
  that does not resolve; a failed read is never "missing"). (2) `Test-MspkiTemplateEnrollmentRisk`: patterns ESC1, 2, 3, 4,
  9, 13, each needing every condition (listed in Evidence) with a firing and a non-firing test; new status code `CONFIG_RISK`.
  (3) CEP (local policy keys, read-only) and CES (AD) probed anonymously with DNS/TCP/TLS/HTTP/content as separate facts;
  standard CES/CEP paths on Enterprise CA hosts are `Inferred` constructed candidates. (4) NDES: candidates from the CA
  database (`CertificateAuthority.View`) and from referenced SCEP URLs; `src/Probes/NdesProbe.ps1` is the only code that can
  send NDES requests (GetCACaps, GetCACert, one anonymous admin GET, no redirects, admin body never read); a loopback-server
  test records every request. (5) Intune connector: local services/products/certificate metadata only; other NDES hosts are
  `UNSUPPORTED`. (6) Stale references: ActiveConfirmed / CurrentReference / HistoricalReference / UnreachableReference /
  StaleReferenceCandidate (needs expired carriers only + no current reference + host not answering), evidence on every result.
- Decisions: severity High -> Fail, Medium/ReviewRequired -> Warning, Low -> Information; unpublished templates one step lower.
  ESC3's second template follows the spec literally (approval and broad-enroll state of it are shown in Evidence). CA-side
  patterns (ESC6/7/11: CA flags, CA permissions) are not done: they need the CA registry or admin COM, which the rules forbid.
  `mscep_admin` may be named only in `NdesProbe.ps1` (hygiene test updated). Constructed candidate URLs and NDES hosts built
  from CA-database names are checked in DNS first; unresolvable ones are never contacted.
- Next (Phase E, optional): `-CertificateFile`, AD dependencies, CES SPN review; add Phase D rows to the demo fixture; an audit
  of src/ against CLAUDE.md (docs/SESSION-PROMPTS.md, after Phase 7).
- Open: nothing in Phase D has run against a live AD CS. Unverified live: the `CertificateAuthority.View` column names and
  restrictions (NDES evidence), the msPKI-Enrollment-Servers CES paths on a real CES, CEP policy key layout, Intune connector
  service names (only the three Microsoft-documented ones are "Documented"). A standard account sees only its own CA-database
  rows, so "NotDiscovered" for NDES is not proof that none exists.
## Phase D, part 1: AD container consistency (REQUIREMENTS 5.4) — done
- Done: `Test-MspkiAdContainerConsistency` (pure, review only, never says "delete"): per Enterprise CA, current certificate in
  AIA / NTAuthCertificates and chain root in Certification Authorities; no clear current/historical split; AD template list
  vs the CA's own list and Enrollment Services certificates vs the CA's valid signing certificates (`STALE_DATA`).
- Open: whether the CA publish-status flags can be interpreted is unverified (shown raw).
## Phase C: HTML report, CSV, exit codes, demo — done
- Done: `report.html` (one offline file, CSP blocks all network; summary, exit-code card, Discovery Map tree
  forest > CAs > certificates > endpoints/templates/CES with confidence + sources, filterable findings with
  evidence, run details, limits); `findings.csv` (UTF-8 BOM, formula-safe); exit codes 0/2/3/4/5/6 (an interrupted
  run is >= 5, meaning table, deciding findings); a reporter failure becomes a finding. `demo\Invoke-MspkiDemo.ps1`
  builds `out\demo\report.html` from `tests\fixtures\demo-results.json` (example.test only). 319 tests.
- Fixed on the way: `$PSScriptRoot` is empty in the entry script's parameter defaults (default `-OutputPath` would
  have failed); the default is now set in the script body.
- Next: Phase D (started, see above).
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
