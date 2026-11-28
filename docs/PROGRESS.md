# Progress log

Newest entry first. Keep each entry to 3–6 lines: phase, what was done, what is next, open issues.
Build phases A–E map to the numbered steps in REQUIREMENTS §7.

## Fact-finding session (RPC blocker, lab map, admin vs standard) - done, no features (746 tests)
- Setup: elevated terminal confirmed; Pester 5.7.1 installed for the current user; CLAUDE.md got the "lab dev machine" rule; `docs/ROADMAP.md`, `docs/RESEARCH.md` written; real names only in `C:\ClaudeCode\private\LAB-FACTS.md` (outside the repo).
- RPC 0x800706BA: not reproducible as admin (CA hosts were rebuilt after the last failing run); `pktmon` capture shows 135 + dynamic ports answering; CR_PROP ids verified live (23/24). Open: the same run as the standard-user account (steps in RESEARCH.md).
- One product bug fixed because it blocked D1: the endpoint stage crashed whenever a CA answered (analysers graded the JSON-safe CA summary, string dates, instead of the live CRL); now `CAProperties` (live, not exported) is passed to `Get-MspkiCaOwnCrl`; regression test added; stack trace now in the run.log line.
- Found, not fixed: false Fail for a CDP LDAP URL with no attribute; NDES missed without the CA database view (`CertificateAuthority.View` is not in-box on clients); `runas /trustlevel` is not a standard-user test for a domain admin.
- Next: D2 endpoint identity (A/PTR/CNAME/TLS names/server header), D3 local evidence, D4 NDES via template ACE + SPN, then the false-Fail fix. Push: this account has no GitHub credentials (commits stay local until someone runs `gh auth login`).

## GUI look rebuilt (enterprise style) + developer snapshots - done (744 tests)
- Look: `src\Gui\Theme.xaml` (palette and shapes from the old window, see `docs\GUI-DESIGN.md`) and a new `MainWindow.xaml`: two-row header (title, context strip with forest / domain / DC / user,
  Administrator or Standard user badge), toolbar with Segoe MDL2 icons (Run is the accent button), collapsible options with a one-line summary, status bar (state icon + text, target, elapsed, findings, output path),
  welcome state, health banner, KPI tiles, status and severity tiles that open the Findings tab filtered, CA cards, top issues, discovery coverage (problems first, successes under an expander), split Findings view
  (status chips, filters, group by category, right-click copy, CSV export of the filtered view into the run folder), Discovery Map with icons, confidence badges, Expand/Collapse all and the same details pane, coloured Run Log
  with filter and auto-scroll. Icon + text on every status. Keyboard: F5, Esc, Ctrl+1..4, Ctrl+F, Ctrl+O.
- Data: `GuiView.ps1` (new) builds the view models; no engine change was needed (RunInfo.Methods, Inventory and findings already carry everything). Where the engine has nothing (no CA properties, no severity rating) the window says so
  in words instead of leaving a blank.
- `Start-MspkiHealthCheckGui.ps1 -Snapshot out\<folder> [-ResultsFile ...]` renders every tab to PNG with RenderTargetBitmap (refused outside `out\`, guard tested; hygiene test allows `GuiSnapshot.ps1` to write for that reason only).
- Verified by looking at snapshots (demo fixture and a real run of this lab computer: 47 findings, 7 s), including the minimum window size (1080 x 700). Tests: theme and window load, view models, filters, export, snapshot guard.
- Next: the user's click-through (checklist in the last message of this session); then fix what they report. Open: no WPF per-monitor DPI manifest is possible from powershell.exe (system DPI is used, text stays sharp);
  Expand all on a very large map can take a moment; severity is "None" for every finding unless an analyzer names a risk, so the severity tiles collapse to a note in a clean run.
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

## GUI redesign (adversarial generator/discriminator loop): round 1 of 5 done
- Done: reference standard + fixed rubric in docs/GUI-DESIGN.md; new Fluent-style Theme.xaml and MainWindow.xaml (WindowChrome
  title bar, nav pane bound to the pages, command bar, options strip, cards, light grid header, details panes); caption buttons
  and a "run ended without results" notice in GuiApp.ps1; snapshots now render running, error, partial, no-CA, no-match and
  drill-in states and take -SnapshotMaximized. Engine untouched.
- Round 1 scores: 7/7/7/8/6/8/8/6/6/6 (not a pass). Defects and the round 2 plan are in docs/GUI-DESIGN.md.
- Open: Pester 5 was not on the module path in this session, so Gui.Tests.ps1 / Hygiene.Tests.ps1 were NOT run after this
  change; run them first next session (the snapshot test still expects >= 8 files; the window loads and renders all 15).

## GUI redesign: rounds 2-5 done (rubric PASS in round 5)
- Done: compact navigation under 1280 px, running panel on the Overview, self-labelled filters, icon-only tree status, proper
  plurals (`Format-MspkiGuiCount`) and separators, responsive status tiles, capped details pane, single error/partial notices.
  Filter choice "(all)" is now "All". Engine untouched. Snapshots: `-SnapshotMaximized`; states rendered under out\ only.
- Tests: full suite 745 passed, 0 failed (Pester 5.7.1). New: count wording, running panel, pre-run facts, WindowChrome, icon font.
- Final scores 9/8/8/9/8/8/8/9/8/8. Remaining gaps (themed dialogs, snap layouts, dark theme, saved layout) are in GUI-DESIGN.md.
- Next: confirm on screen with the checklist (real mouse/keyboard: caption buttons, drag, resize, Alt+Space, Tab order).

## Step 0 (2026-11-21 evening): the standard-user CA read failure is solved
- Reproduced as the standard domain account (elevated and filtered token alike): the Root CA host answers the DCOM activation on TCP 135 with RPC
  fault 5 (access denied) and closes; DCOM reports it as 0x800706BA. The Sub CA answers the same account. Details and owner steps: RESEARCH.md.
- Product: a 0x800706BA within 5 s after TCP 135 answered is now `PERMISSION_DENIED` / Inferred with timing evidence, owner remediation, and the
  names of other CAs that answered the same account; a slow one stays `RETRIEVAL_FAIL` (firewall). Tests updated (113 passed in the touched files).
- Next: Step 1 entity graph (docs/DATA-MODEL.md), then Step 2 hierarchy health.

## Step 1 (2026-11-21): entity graph (results.json format 2)
- Done: `docs/DATA-MODEL.md`; `src/Model/EntityGraph.ps1` (deterministic ids, observations Seen/Referenced/ExpectedMissing, relations,
  export, `ConvertFrom-MspkiResultsDocument` adapter) and `EntityGraphBuilder.ps1` (from inventory, probe hooks, CA own CRLs, finding
  linker: every finding has `EntityIds`). Schema `mspki-healthcheck/2`; the GUI and report re-export read format 1 through the adapter.
- Lab run: 86 entities, 119 observations, 91 relations, 1.4 MB JSON (PS 5.1 limit ~2 MB). Expected-but-missing found: the older Sub CA
  generation (NTAuth, not AIA). LocalCertificate is defined but filled only by D3; WebEnrollment service entities come with Step 2/D2.
- Also: an LDAP AIA/CDP URL without an attribute now reads the default attribute (cACertificate / certificateRevocationList /
  deltaRevocationList) instead of failing (false positive in the lab); tests added. Full suite 770 passed before this; touched areas pass.

## Step 2 (2026-11-21): hierarchy health (D1) on the graph
- New `src/Analyzers/HierarchyHealth.ps1` (stage Analysis:Hierarchy): per CA generation (chain parent, validity vs issuer, key/signature,
  overlap, current); AIA/CDP published only over LDAP; URLs in the order Windows tries them; NTAuth generation missing from AIA;
  offline-root CRL lifetime; OCSP responder on a CA host's /ocsp/ that no certificate names (Inferred); HTTPS that closes the TLS
  handshake (`ServerClosed` in the TLS probe); certificate SAN names with no DNS record (served TLS certificates and LocalMachine\My
  certificates issued by a discovered CA: read-only, public part only; they become LocalCertificate entities). 19 new tests;
  full suite 795 passed, 0 failed (after updating three expectations for the new stage, the /ocsp/ request and the hygiene word ban).
- Lab re-run as the standard user (filtered token): every Warning matches a confirmed lab fact; exit 6 (was 4 from the CDP false positive).
- Decisions: /ocsp/ is probed only on Enterprise CA hosts (proven PKI, anonymous GET, no redirects, body discarded). SAN names are resolved
  only when they come from a certificate. results.json is now 1.5 MB in the lab: watch the 2 MB `ConvertFrom-Json` limit of PS 5.1.
- Next: G1/G2 drill-down on the graph; D2 endpoint identity (PTR, CNAME → `resolvesTo`); NDES via template ACE / SPN route.

## WP1 (2026-11-21): results.json without a size limit
- New `src/Model/JsonReader.ps1`: `ConvertFrom-MspkiJson` / `Read-MspkiResultsJson` (in-box JavaScriptSerializer, `MaxJsonLength = [int]::MaxValue`,
  dictionaries become PSCustomObjects; arrays are converted in place so they never serialise as `{ value, Count }`). The GUI, the report re-export
  and every test that reads a results.json use it. Hygiene: `Add-Type -AssemblyName System.Web.Extensions` is allowed in that one file only (CLAUDE.md rule 6).
- New `tests/JsonReader.Tests.ps1`: same shape as ConvertFrom-Json; a 10+ MB results.json written by `Export-MspkiJson` opens in the reader, the GUI model and
  the report re-export. Found and fixed on the way: the report tree crashed on an inventory without `Containers` (`@($null)` gave one empty node).
- Note: on this machine PS 5.1 `ConvertFrom-Json` also read the 10 MB file; the ~2 MB limit noted earlier was not reproduced. The tool no longer depends on it.
- Full suite 805 passed, 0 failed. Next: WP2 endpoint identity (D2).

## WP2 (2026-11-21): endpoint identity (D2)
- New stage Analysis:Identity (`src/Analyzers/EndpointIdentity.ps1`, `src/Probes/DnsIdentity.ps1`): every Host in the graph gets A/AAAA, the CNAME
  chain (`resolvesTo`), PTR per address, the TLS certificate names and the HTTP Server header (now captured by `Invoke-MspkiHttpGet`, with the
  names of the offered sign-in schemes). DNS-only via the in-box `Resolve-DnsName`; .NET fallback is Inferred. One runspace, time-limited, cached.
- Findings (new categories Identity, WebEnrollment): missing PTR (Information), PTR short name / other host (Warning), alias with no address
  (Warning), alias not covered by the TLS certificate (Warning when an https URL uses it), a per-host identity summary; Web Enrollment on CA hosts
  as a Service entity, with an ESC8 Warning when plain HTTP offers NTLM/Negotiate. All `/certsrv` paths stay in `NdesProbe.ps1` (NDES test rule).
- Adversarial check: 2 rounds (RESEARCH.md); lab shows no PTR records in DNS at all (earlier "short name" came from NetBIOS).
- Tests: `tests/EndpointIdentity.Tests.ps1` (17). Next: WP3 NDES without the CA database view.

## WP3 (2026-11-22): NDES without the CA database view (D4)
- New `src/Discovery/NdesTemplateAccess.ps1`: NDES RA templates (standard names, or Certificate Request Agent EKU + subject in request), their
  Enroll ACEs minus default admins / broad groups, one `<SID=...>` read per account (groups one level, gMSA allowed computers), host from
  dNSHostName or `HTTP/` SPNs -> Probable NDES leads probed with GetCACaps/GetCACert only. Lab: NDES Confirmed as the standard user.
- GetCACert certificates: role (CA / RA), issuer, EKU, key usage, template (new `src/Model/CertificateTemplateInfo.ps1`, v1 + v2 extension);
  graph: Account, RACertificate, mayEnroll, identifies, certificateOf, issuedBy, enrollsVia (issuing CA only). Missing CA database reader in words.
- Fixed: wrapped GetCACert list (false "expired"), invented Intune connector entity, NDES candidates shown as Seen. 3 adversarial rounds (RESEARCH.md).
- Tests: `tests/NdesTemplateAccess.Tests.ps1` (14). Next: WP4 local evidence (D3).

## WP4 (2026-11-22): local evidence (D3)
- New `src/Discovery/LocalEvidence.ps1` (stores read-only, Enterprise store key names, Lifecycle System/User logs, AutoEnrollment / CertEnroll
  events, template cache, AEPolicy, Remote Desktop template policy) and `src/Analyzers/LocalEvidence.ps1` (stage Analysis:LocalEvidence, category
  LocalEvidence): "how this certificate got here" per certificate from this PKI, trust-store coverage of AD's Certification Authorities / AIA /
  NTAuth (ExpectedMissing when absent), lifecycle summary, expiry warnings, enrollment policy. Graph: LocalCertificate issuedBy / references
  Template, EventLog and LocalStore observations, template-cache observations on Template entities.
- Lab (standard user): both Lifecycle logs readable; origins of both machine certificates match the lab facts. 2 adversarial rounds.
- Tests: `tests/LocalEvidence.Tests.ps1` (10). Next: WP5 GUI drill-down (G1, G2, G4).

## WP5 (2026-11-22): GUI drill-down (G1, G2, G4, G5) - DONE
- `src/Gui/GuiEntity.ps1` (pure view models): graph index, object details (what it is and why it matters per type, properties, host identity,
  "where this exists" with the expected-but-missing places in their own amber block, related objects both ways, findings, breadcrumbs, Back),
  Objects list (worst-status and missing pills, needs-attention flag), filter, type choices, trail steps, map item -> object mapping.
- Window: new Objects page (Ctrl+5, grouped by type, search, type filter, "only objects that need attention"); `EntityPane` template; every
  details pane (Findings, Discovery map, Objects) routes `ent:` / `crumb:` / finding / Back / Copy through `Invoke-MspkiGuiPaneCommand`;
  findings and map items list their objects; KPI tiles open the Objects page for their type; CA cards open their CA. A live run reads the
  graph back from results.json. Endpoint names are shown decoded (%20 -> space); ids are unchanged.
- New fixture `tests/fixtures/demo-results-v2.json` (format 2, example.test only, built from the demo fixture by the module's own graph
  builder). Lesson: the builder adds THIS computer as a host, so the generator must set `$env:COMPUTERNAME` to the fixture's name first
  (caught by the LAB-FACTS grep before any commit).
- Tests: `tests/GuiEntity.Tests.ps1` (9), a new window test in `tests/Gui.Tests.ps1` (Objects page, tiles, cards, panes, trail, Back).
  Snapshots 32-33 and 70-74 cover the new views. Pester 5.7.1 is at `C:\ClaudeCode\tools\pester571` (not on this user's module path).
- Full suite 884 passed, 0 failed. Open: one earlier full run had 10 LocalEvidence failures with empty messages that did not repeat (file
  alone, files in order, and a second full run all pass): watch for a flaky test there.
- Next: WP6 PKI Services page (G3). Then WP7 polish (minimum size of the Objects page and the details pane not yet judged).

## WP6 (2026-11-22): PKI Services page (G3) - DONE
- `Get-MspkiGuiServiceSection` (`src/Gui/GuiEntity.ps1`): one card per kind (Web Enrollment, CES, CEP, NDES/SCEP, OCSP, Intune Certificate
  Connector) with a plain-language note, every instance (answers or only named, confidence, host, evidence, worst finding), the findings of
  the kind and "what this run can see". States kept apart: N found / named, not confirmed / not found (looked, nothing there) / cannot be
  checked from here / not checked in this run. When a kind was not found where the run could look but other places could not be checked
  (Intune on the NDES host), the card says so. A service's details pane uses its kind's note.
- Window: PKI services page (Ctrl+6), services and findings open in the pane on the right (`Open-MspkiGuiServiceItem`). Snapshots 80-82.
- Found: `@($list)` on the GUI's generic row list throws "Argument types do not match" in Windows PowerShell 5.1; pass rows through the
  pipeline. A load error in snapshot mode opens a modal message box and the snapshot waits for it (pre-existing behaviour).
- Lab check (normal user via `runas /trustlevel:0x20000`): Web Enrollment on the root CA host (HTTP 403, Inferred), no CES, no CEP, NDES
  Confirmed, OCSP answers but no certificate names it (Warning), Intune not on this computer and not checkable on the NDES host: all match.
  NOTE: this Claude terminal runs at High integrity (IsAdmin true), not as a normal user; normal-user runs need the filtered token.
- Tests: services states in `tests/GuiEntity.Tests.ps1`, the page in the window test; full suite 885 passed, 0 failed. (The NDES path
  rule test caught the Web Enrollment path in a GUI note; the note now names the service, not the path.) Next: WP7 GUI adversarial polish.

## WP7 (2026-11-22): GUI adversarial polish - DONE (PASS in round 2)
- Round 1 (8/8/8/9/7/8/8/8/7/7): duplicated host facts, a tall note box, redundant/orphan breadcrumbs, a state line broken at a switch name.
  Round 2 (8/8/8/9/8/8/8/8/8/8, PASS) after also capping card prose at 880 px on ultra-wide screens. Details in `docs/GUI-DESIGN.md`.
- Breadcrumbs now show from the third object and list the objects before the current one; Back always goes one step.
- Next: WP8 ready for audit (normal-user lab run with the filtered token, discriminator check against the lab facts, README/TESTING).

## WP8 (2026-11-22): ready for audit - DONE
- Normal-user lab runs (filtered token, IsAdmin false): exit 6, 99 findings. Discriminator check against the private lab facts, 2 rounds:
  no false positive or false negative found; LDAP-only AIA/CDP, the TLS reset on the root CA host, the dead SAN alias, the OCSP responder
  that nothing names, the DCOM permission test case, NDES (Confirmed) and the Intune connector (not checkable on the NDES host) all match.
- Fixed (unclear explanation): the AD-container "current/historical split" warning said "2 CA certificates but 1 of them are current";
  it now says one is current and which one could not be placed, and its note no longer claims the CA could not be read when it was.
- README (Objects, PKI services, known limitations) and docs/TESTING.md (checks 6-8) updated. ROADMAP: every work package DONE.
- Open: this Claude terminal runs elevated (High integrity); normal-user runs were made with `runas /trustlevel:0x20000`. One full test run
  earlier today had a flaky LocalEvidence failure that never repeated.

## Audit 2 after WP1-WP8 (docs/AUDIT-2.md) - done, no code changed (886 tests pass)
- Whole-project audit at commit `50a26a2`: 2 High, 14 Medium, 19 Low, each with file and line. Two defects confirmed at runtime
  (a 3xx with redirects off is recorded as "no answer"; the retrieval-order check misses URLs spelled differently in the certificate).
- High: Freshest CRL links in unverified downloaded CRLs become leads (LDAP binds to any forest-zone name); ESC3 ignores schema
  version 1 targets. Several Medium false Pass / Confirmed results survive because unit tests compare a value with itself.
- No real names or personal details in the tree or the 39 commits (also checked against the private lab facts, counts only).
- Next: fix in the order at the end of AUDIT-2.md, each with a test that fails on today's code.

## Audit 2 Batch A, H1 (2026-11-22): CRL links and LDAP binds - DONE (901 tests)
- Freshest CRL links are followed only from CRLs whose signature verified with a discovered CA certificate; leads carry a trust
  level (Authoritative / Verified / Unverified). LDAP binds go only to the selected DC, a forest DC (new: server objects under
  CN=Sites, one subtree search) or a forest-zone host named by trusted evidence. CLAUDE.md rule 4, REQUIREMENTS 4.2, README updated.
- Red then green: `tests/Audit2.Security.Tests.ps1` (H1 blocks). Normal-user lab run: 99 findings, exit 6, no difference from the
  WP8 baseline; 2 forest DCs read; all LDAP locations still read.
- Next: M10 (PFX), M9 (redirects/TLS), H2 (ESC3), M11 (template confidence). Fix log in docs/AUDIT-2.md.

## Audit 2 Batch A, M10 (2026-11-22): no key from downloaded bytes - DONE (906 tests)
- Certificate bytes are loaded only in `src/Model/Certificate.ps1`: content type first (`GetCertContentType`), only Cert and
  PKCS #7 are loaded, PKCS #12 / PFX is refused before any object exists; `EphemeralKeySet` where available. AIA and NDES readers
  use it; Hygiene forbids key-persisting flags and certificate loading elsewhere.
- Red then green (red shown in a worktree of the H1 commit: one key file per PFX load). Lab run (normal user): 99 findings, exit 6,
  no difference from the baseline. Next: M9.

## Audit 2 Batch A, M9 (2026-11-22): redirects and TLS to undiscovered hosts - DONE
- A redirect is followed only to the request's own host or a host trusted evidence named (`Test-MspkiTrustedLeadHost`); other
  targets are recorded (`RedirectNotFollowed`, evidence) and never contacted; the separate TLS handshake obeys the same rule.
  An AIA/CDP location that redirects to such a host is a Warning naming the target, not a download failure.
- Test helper fix: an issued test certificate is clamped to its issuer's validity (the old race failed LocalEvidence.Tests in
  about half of the runs). Runner note: a loopback server runspace can keep a finished test process alive; force-exit after results.
- Red then green (M9 block in tests/Audit2.Security.Tests.ps1). Lab run (normal user): 99 findings, exit 6, no difference.

## Audit 2 Batch A, H2 (2026-11-22): ESC3 counts schema version 1 targets - DONE (921 tests)
- Schema version 1 templates (the default User template) are ESC3 targets; every condition is required on both templates
  (agent: no signatures; target: no approval, client authentication, agent principals may enroll).
- Red then green: "Audit 2 H2" block in tests/TemplateSecurity.Tests.ps1 (default-forest model, positive and negative cases).
  Lab run (normal user): 99 findings, exit 6, no difference (the lab has no broad agent template). Next: M11.

## Audit 2 Batch A, M11 (2026-11-22): template confidence - PARTIALLY DONE (927 tests)
- Template review findings are never Confirmed while effective access is not computed (now Referenced, with the reason in the
  evidence); Deny ACEs for a containing well-known group (Everyone, Authenticated Users) make a match an Inferred review item.
- Red then green: "Audit 2 M11" block in tests/TemplateSecurity.Tests.ps1. Lab run (normal user): 99 findings, exit 6, no difference.
- Open from M11: the ESC4 single-attribute WriteProperty rule (Batch B). Batch A is complete; next is Batch B (AUDIT-2.md order).

## Audit 2 Batch B, M1 (2026-11-22): AIA serving the old CA certificate - DONE (929 tests)
- Identity with a known CA certificate counts as proof of the key only when no referencing certificate is known; with a
  referencing certificate its signature must verify (KeyMismatch otherwise). Red then green: "Audit 2 M1" in tests/Audit2.Results.Tests.ps1.
- Next in Batch B: M2 (CES/CEP 401/403/3xx), M7 (GUI Inferred), M4, M5, M3, M6, M8, M12, M13, M14, fixture rename, Lows.

## Audit 2 Batch B, M2, M7, M4, M5, M3 (2026-11-22): DONE (951 tests)
- M2: CES/CEP 401/403 is AuthRequired and a 3xx is Redirected (Information, Referenced), never Confirmed. M7: the services page says
  "Something answers (not confirmed)" for Inferred services; "N found" counts only Confirmed ones. M4: retrieval order compares
  normalised URLs per scheme from per-URL outcomes (Usable/Failed/NotTested). M5: a redirect that is not followed keeps its
  status and Location. M3: CRLs up to 64 MB are read; larger ones are Information / SIZE_LIMIT, not Fail.
- Red then green for each (tests/Audit2.Results.Tests.ps1, EnrollmentServices, GuiEntity). Fix log in docs/AUDIT-2.md.
- Next: M6 (GUI crash safety), M8 (status codes), M12, M13, M14, fixture rename, then the Lows. Lab run after M8/M12.

## Audit 2 Batch B, M6, M8, M12, M13 (2026-11-22): DONE (984 tests); lab check after items 1-8
- M6: GUI catch-all (Dispatcher and AppDomain) logs, shows one message, keeps the window alive and cancels a run cleanly; a throwing timer
  tick no longer stops the timer. M8: one status code per cause (RPC_FAIL, RETRIEVAL_ORDER, CONTENT_MISMATCH, ENROLLMENT_FAIL, CHAIN_INVALID,
  SIZE_LIMIT; docs updated). M12: member accounts of NDES groups and gMSAs are entities (memberOf, mayUse) and identify the hosts they name.
  M13: both entry points detect Constrained Language Mode first and stop with exit code 5 and a plain explanation.
- Lab run as a normal (non-elevated) user after items 1-8: 99 findings, exit 6, the same set and shape as the baseline and as the lab facts
  (LDAP-only AIA/CDP warnings, unreferenced OCSP responder, filtered or reset HTTPS, NDES confirmed, 12 constructed CEP/CES candidates silent).
  No new Fail or Warning, no new false positive or negative. The services page now says "Something answers (not confirmed)" for the Web
  Enrollment path that answers 403 and "1 of 6 service types confirmed" (it said "found" before).
- Next: M14 (tests that hide bugs), the fixture rename to neutral names, then the Low items.

## Audit 2 Batch B, M3-M14 and the Low items (2026-11-22): DONE (1029 tests)
- Every Medium finding is fixed (M8 with two items explained); the last open part, M11's ESC4 attribute rule, counts only writes that can
  change what a certificate may be used for (schema IDs read from the lab schema). Fixture host names are neutral (scep-gw01...).
- Lows: L1, L12-L15 (limits recorded, runspaces disposed, cancel keeps discovery, report opens only interactively), L2-L9, L11, L19 fixed or
  decided; L10, L16, L17, L18 explained in the Fix log (docs/AUDIT-2.md, "Fix log: Low items").
- Lab run after the Lows: a regression of my first L7 change (explicit LDAP authentication type) showed only in the lab (exit 5, 18 findings).
  Fixed and covered by a live-directory regression test; the lab is back at 99 findings, exit 6, as in the baseline. Lesson recorded: after
  any change to a directory or network read, run the lab, because the unit tests mock those reads.
- A local pre-commit check against the private lab facts now exists outside the repository (an untracked git hook).
- Next: the verification audit.

## Audit 2 verification (2026-11-22): docs/AUDIT-2-VERIFY.md, no code changed
- Every Fixed item was checked in the code, and its tests were run against the parent commit's code (behavioural versus signature-only
  red recorded). Full suite at f8ed721: 1029 passed.
- Verified: H1 (CRL path), M1-M2, M4-M7, M9-M13, the Lows claimed. Partly: M8, M14. Regressed: H2 (ESC3 shared-principal check misses
  Authenticated Users / Everyone agents; a schema 2 case that matched before no longer does). M3 has a small AIA side effect.
- New: N1 (High) a forged AIA certificate with the real CA key is Pass/Confirmed and its LDAP link reaches a bind; N4-N7 Low/nit.
- Next: fix N1, then N2 (H2), then N3-N7.

## Audit 2 verification fixes, Batch D (2026-11-22)
- N1: a downloaded CA certificate is trusted (used as an issuer, links followed) only as an exact SHA-256 copy of an AD/CA certificate,
  or when its own signature verifies with a trusted CA key; a self-signed root needs both its self-signature and an exact copy. Public-key
  match alone is never enough; non-CA certificates are never issuers. Forged self-signed roots are Fail / SIGNATURE_INVALID.
  Tests: tests/Audit2.Verify.Tests.ps1 (N1). Lab: 99 findings, exit 6, unchanged. Fix log 2 in docs/AUDIT-2-VERIFY.md.
- N5: the forest DC list counts a server object only with an NTDS Settings child AND a DNS SRV record (_ldap._tcp.dc._msdcs.<domain>,
  DC locator as fallback); excluded objects are one Information / STALE_REFERENCE finding and never get a bind. -SkipNetwork skips the
  DNS lookup. Lab: 2 DCs counted, 0 excluded, 99 findings, exit 6.
- N6: every directory search sets ReferralChasing = None; a referral (0x8007202B) is a Warning with evidence, never a second bind. Disposal
  after a failed bind no longer hides the first error. Credential harness added (tests/CredentialHarness.ps1). Lab: 99 findings, exit 6.
- H2 regression (N2): ESC3 shares principals when either broad group contains the other (Everyone ⊇ BUILTIN\Users ⊇ Authenticated Users
  ⊇ Domain Users / Domain Computers), whichever template they sit on; probes A, B, D fire again, 11 negatives stay silent. Lab unchanged.
- N8 (new): the LDAP host gate got the forest domains and DC list nested in one string (a second @() around "return , @()"), so the H1 DC
  rule never applied and multi-domain forests refused every named forest host (failed closed). Lists now passed as they are. Lab unchanged.
- Item 5: tests/CredentialHarness.ps1 records binds, HTTP and TLS; tests/Credential.Behaviour.Tests.ps1 proves no bind for a forged
  certificate, an unverified CRL, a referral or a stale DC. Against 9b43bb1: 3 of 4 red on behaviour (stale DC passed by the N8 accident);
  with the two N8 lines corrected, 4 of 4. Full suite 1071 passed.
- Next (Batch E): N3 (AIA download above 10 MB), N4 (CES/CEP 200 on a word match), N7 (hygiene test gaps, one store open).

## Audit 2 verification fixes, Batch E (2026-11-22)
- M8 remainder: the Unreachable class is named by error number (DIRECTORY_UNAVAILABLE, RPC_FAIL, NETWORK_PATH_FAIL), an unclassified LDAP
  error is DIRECTORY_ERROR, a Configuration NC built from the name is DC_NOT_FOUND; RETRIEVAL_FAIL stays only where the number says nothing
  (explained in Fix log 2). N3: an AIA answer above 10 MB is Fail / SIZE_LIMIT naming the real limit. N4: a 200 from CES/CEP is Confirmed only
  for a WSDL, a SOAP envelope or enrollment XML, otherwise Inferred. N7: tighter hygiene patterns plus AST scans; every store opened
  OpenExistingOnly. M14: the history scan covers author and committer, messages, paths and the content of every commit, counts only.
  M4: a behavioural test that is red on the old result (Skipped, Skipped, false Pass), not on a missing function.
- Lab (normal user) after the M8 remainder, N3 + N4 and N7: 99 findings, exit 6, identical histograms. Full suite at the end: 1143 passed,
  0 failed, 1 skipped.
- **Open issue (owner decision):** the public repository's history still contains lab names in the content of older commits (private-list check:
  2 of 19 names, 47 of 78 commits; HEAD is clean). Removing them needs a history rewrite and a force push.
- Next: the verification of Batch E.

## Audit 3 verification (2026-11-22): docs/AUDIT-3-VERIFY.md, no code changed
- Fix log 2 items checked in the code and run against their pre-fix commits; all reproduce (behavioural red where claimed). Full suite at
  64ac786: 1143 passed, 0 failed, 1 skipped. The M14 committer self-test does not separate old from new logic (N14). History names still open.
- Credential safety end to end: verified; no bind or credentialed request can be steered by an unverified object. One plain-HTTP answer
  can stop the endpoint stage with a file:/ftp:/ldap: redirect (N9). The TLS chain engine contacts certificate-named hosts anonymously (N13).
- ESC3 on the lab's default templates: correct for every broad-agent case; any Deny ACE (even Delete) silently removes the match (N10).
- Next: fix N9, then N10, N11 (SIZE_LIMIT counted usable outside the forest), N12 (local certificate URLs garbled), then the nits.

## Batch G, steps 1-4: standing directives, naming scheme, Fix log 3 (N9-N15), local name guard - done (1186 tests)
- `CLAUDE.md`: standing directives (GUI-only users, no lab names in files or history, lab access is observation only, every non-passing finding
  explains itself, research is encouraged but never copy code). `docs/NAMING.md`: the generic naming scheme. The real-to-generic map is only in
  `C:\ClaudeCode\private\NAME-MAP.txt` (never committed); the M14 history check now accepts that file (text left of `=>`).
- Fix log 3 in `docs/AUDIT-3-VERIFY.md`: N9 (non-HTTP redirect is evidence, per-URL guard), N10 (a Deny counts only when it covers the right; the
  summary names a suppressed rule), N11, N12, N13 (documented as a limit), N14, N15 (leads Unverified by default), the leftover test key removed and
  a baseline/leftover test pair added. Each fix is red on the old behaviour, green now. Non-elevated lab run: same 99 findings, same tally, 0 stage errors.
- Local hooks (not committed): `pre-commit` and `commit-msg` call `C:\ClaudeCode\private\precommit-namemap.ps1`, which blocks a real name in staged
  content, paths, message or identity; tested with planted names in all four places.
- Step 5 (history clean-up) is paused at 5b/5c for an owner decision. Done: everything committed and pushed; a mirror backup was taken outside the
  repository. Finding: the whole reachable history, and a fresh clone from the public repository (92 commits), hold 0 names from the full private
  name map (content, paths, messages, identities). The "2 of 19 names in 47 commits" of the audits are the bare short names `ndes01` and
  `ndes01-mscep-ra` (47 of the 84 commits at the audited commit), which `docs/NAMING.md` uses as generic names. A rewrite would change nothing unless
  the owner decides those two are lab names; then NAMING.md changes and 47 commits are rewritten.
- Step 5 CLOSED (2026-11-23, owner decision): `ndes01` and `ndes01-mscep-ra` are acceptable generic names. No history rewrite, no repo recreation.
  The mirror backup stays in `C:\ClaudeCode\private\`; the local name-guard hooks stay as they are. Batch G is closed.

## Batch H, step 1: "Probable causes and next steps" for every non-passing finding (2026-11-22)
- Research: Microsoft Learn, Tech Community / AskDS, SpecterOps and Certipy pages were fetched or searched (RPC/DCOM, CRL/AIA/delta, OCSP, CES/CEP, NDES, Intune, TLS, NTAuth, ESC1-16,
  CA renewal, time skew). 42 sources with how far each was read and the date: `docs/KNOWLEDGE-SOURCES.md`. Paraphrased only; nothing copied.
- Knowledge base (data only): `src/Knowledge/Diagnosis.psd1` (sources, a default topic per status code, ordered rules) and five `Diagnosis.Topics.<Area>.psd1` files (120 topics: ranked causes, read-only
  checks, fixes marked as PKI-owner actions). It is split because `Import-PowerShellDataFile` refuses a data file above a node limit (one 170 KB file failed between 98 and 119 topics).
- Engine `src/Model/Diagnosis.ps1`: topic by rule then status code; causes ranked by the knowledge order plus signals from the finding's own text, evidence and layers; `Basis` says whether anything
  observed separated the causes ("Observed") or the order is only how common each is ("Typical"). Added to results.json (`Diagnosis` per finding), the HTML report (plain-text sources, no link) and the GUI details pane.
- Tests: `tests/Diagnosis.Tests.ps1` (322): every schema status code has an entry, every topic is complete and cited, no check is a write, ESC1-16 covered, rule routing, ranking, round trip, HTML, GUI view model.
  Hygiene: `Diagnosis*.psd1` may name certutil in advice text; public documentation hosts allowed for the source addresses. CLAUDE.md clarified.
- Next: adversarial check against the lab (normal user, max 3 rounds), then ROADMAP and the full suite. Round 1 on the saved lab result already fixed two rankings (NTAuth/AIA leftover versus renewal; a timeout is not proof of a missing role).

## Batch H, step 2: adversarial check against the lab (3 rounds) and honest wording (2026-11-22)
- Normal-user run on the lab: 99 findings, exit 6, identical tally; all 27 non-passing findings carry the section (the others are all-clear Information/Pass). Details (sanitised) in `docs/RESEARCH.md`.
- Round 1: NTAuth-versus-AIA now ranks "earlier installation" first on the tool's own evidence (lifecycle Unknown) instead of "renewal"; Web Enrollment no longer reads a timeout as proof of a missing role.
  Round 2: signals no longer see Notes/Remediation (boilerplate was shown as an observation); "Most likely" only when something observed backs that cause, otherwise "Most common"; CES Kerberos cause needs a 401.
  Round 3: every top cause matches the lab facts; no overclaim left.
- Docs: README, TESTING (step 9 of the click-through), ROADMAP (WP9), RESEARCH. Tests: `tests/Diagnosis.Tests.ps1` 325.
- Next: GUI program (a "what to do" overview over all findings, copy-the-checks, Observed highlighting). Open: the PTR, template and KRA topics are "Typical" (nothing observed separates the causes).

## GUI program, design (2026-11-23): demo world, experience design, upgraded rubric, demo site plan, work packages
- Batch G closed (Step 5: `ndes01` names accepted as generic). Demo world `docs/DEMO-WORLD.md`: **Alcyone Orbital Systems** (`alcyone-orbital.example`),
  the lab's PKI structure with invented names. "Halcyon" was dropped after a web check: a well-known security vendor uses it. CLAUDE.md, NAMING.md and the
  hygiene scan allow the world's three `.example` domains for docs, screenshots and the demo; any other `.example` name fails; tests keep `example.test`.
- `docs/GUI-EXPERIENCE.md` (personas, journeys J1-J6 with targets, pages and one drill-down pattern, features must/should/could, honest score model, motion
  tokens, feasibility in PS 5.1 WPF), `docs/GUI-DESIGN.md` §6 (fixed rubric: A1-A10 visual, B1-B5 usability, C1-C4 delight), `docs/DEMO-SITE.md`
  (generator = the real module with only the I/O boundary replaced; static site; Pages workflow), ROADMAP GX0-GX11 and DS1-DS8 with acceptance criteria.
- Open: DS2 needs an owner decision (a developer-only tool that generates throw-away keys to sign the world's certificates and CRLs). Next: GX0 prototype.

## GX0 (2026-11-23): mission-control Overview + discovery map prototype - DONE (PASS in round 2)
- `src/Gui/GuiMission.ps1` (pure: health score per docs/GUI-EXPERIENCE.md §6, "What to do next" grouped by diagnosis topic, map model, column layout,
  build timeline) and `src/Gui/GuiMapView.ps1` (WPF: score ring, area bars, map canvas, one Storyboard; reduced motion = final state at once). Loaded by
  `GuiApp.ps1`. Overview hero = ring + headline + top 3 actions + area bars; full-width map below; area bars filter Findings by area; data colours in Theme.xaml.
- Demo-world sample `demo/world/alcyone-mixed-results.json` (hand-made: the example.test demo results renamed; DEMO-WORLD says so). `-Snapshot` adds build
  frames at 300/1250/2100 ms (`05-build-*`, `06-build-map-*`) and `12-summary-map`. Two discriminator rounds logged in GUI-DESIGN §7; lessons in GUI-EXPERIENCE §11.
- Tests: `tests/GuiMission.Tests.ps1` (16); the window test also checks the names used in GuiMapView.ps1.
- Open: the map replays the finished graph (live build needs GX1 engine events); 1920 x 1080 frames need a larger screen than this session's; next is GX1.

## Owner decisions applied (2026-11-23)
- The Alcyone Orbital Systems rename is approved (the demo world stays as in `docs/DEMO-WORLD.md`). DS2 is approved as a developer-only tool: CLAUDE.md has the new
  section "Developer-only tools (`tools\dev\`)" (keys in memory only, only public certificates and CRLs committed, PowerShell 7 or OpenSSL allowed for the developer, fixed demo clock).
  `tests/Hygiene.Tests.ps1` enforces it: `src\`, the entry scripts and `demo\` never reference `tools\dev\`; no private-key file type or PEM private-key block is in the repository.
- Snapshots render off-window at a fixed size: `Set-MspkiGuiSnapshotLayout` (Measure/Arrange at exactly Width x Height, content drawn through a VisualBrush on the window background),
  `-SnapshotWidth/-SnapshotHeight` now mean the frame size (1920 x 1080 works on this 1386 x 788 VM), `-SnapshotMinimum` renders at the window minimum. Tests: exact PNG size, minimum, 3000 x 2000.
- Next: GX1 (engine events for the live map).

## GX1 (2026-11-23): engine events for the live map - DONE
- `-Control` now also queues `Entity` (id, type, name, parent ids), `Relation` (from, type, to) and `Probe` (Start/End, keyed by endpoint id or host id, with the outcome) items:
  `src/Model/RunControl.ps1` (`Send-MspkiGraphEvent`, `Send-MspkiProbeEvent`, `Send-MspkiLeadEntityEvent`), `Add-MspkiEntity -Parents`, probes in `Probes/NetworkProbes.ps1` and `WebProbes.ps1`.
  Without a control nothing is queued; a test proves the graph built with and without one is identical (the CLI results.json is unchanged). Format in `docs/DATA-MODEL.md`.
- Lab (normal user, read-only): 100 of 100 entities and 122 of 122 relations announced, none twice; all 100 before the last stage ended (first version had 88: CES/CEP endpoints are
  only in the final pass, so the lead registry's endpoints are now announced early, announce-only); 26 probe starts, 26 ends; run time 19.5 s with and 19.4 s without a control (limit 5 %).
- Tests: `tests/RunEvents.Tests.ps1` (9). Full suite: 1575 passed, 0 failed, 1 skipped, 163 s. No GUI change, so there is no new snapshot to judge (rubric pass skipped; the next package uses the events).
- Next: GX2 (mission-control Overview, production quality; the running state becomes the live map fed by these events).

## GX2 (2026-11-23): mission-control Overview, production quality - DONE (PASS in round 2)
- The running state is the live mission control (no separate panel): same hero (progress ring, what is being checked, found so far, Cancel / View live log), neutral area rows, and the map fills
  from the engine's Entity / Relation / Probe items (`Add-MspkiGuiLiveItem`, `Get-MspkiGuiLiveMapModel`, `Update-MspkiGuiLiveMap`: redraw at most twice a second; new nodes fade in 280 ms, a node pulses while its probe runs, at most 6).
  When results arrive the map is not built again; its health colours settle. Engine: events carry the few display properties; the lead registry's endpoints and who references them are announced early (announce-only).
- Finished state: headline sentence (`Get-MspkiGuiHeadline`: "N actions need attention. Most urgent: ..."), 5 actions with "All N actions" / "Show fewer" in place, the ring opens the Findings page filtered to what lowers the score,
  "How is this scored?" is a themed popup, "Top issues" removed (it repeated the actions). Score bands, cap, partial and no-CA are covered by tests.
- Snapshots: width-dependent rules (compact navigation, tile columns) follow the fixed render width and the fixed size is the content's own size, so 1080 x 700, 1360 x 860 and 1920 x 1080 frames are faithful on this 1386 x 788 VM; live frames `03a-d`, `03e-live-motion`.
- Tests: Gui 39, GuiMission 32 (+16), RunEvents 10. Round 1 found a snapshot defect of mine (frames cut at minimum size), a Windows message box, and unseen motion; all fixed (GUI-DESIGN section 7).
- Next: GX3 (guided troubleshooting walkthrough, Observed highlighting, copy the checks, mark as checked).

## GX3 (2026-11-27): guided troubleshooting walkthrough - DONE (PASS in round 2)
- Details pane: "What to do about it" right after "What was found": what it means, causes ranked (a 3 px accent strip and "Observed in this run" when the run saw evidence),
  each read-only check on its own row with a copy button and a "mark as checked" box, "Copy all checks", the fix with its owner and a copy button, sources with a copy button.
  Copy buttons answer with a check mark for 1.4 s (also the pane's main Copy). `src/Gui/GuiState.ps1`: marks kept in `<run>\gui-state.json` only when the run folder is
  inside the output folder (otherwise in memory, and the pane says so); every write goes through `Test-MspkiGuiPathInside`; hygiene allows this one writer.
- J3: Overview action -> finding with the walkthrough in view -> copy a check = 2 clicks. The pane never runs anything: `tests/GuiWalkthrough.Tests.ps1` (16) checks by AST that the
  pane handler only calls the clipboard and named window helpers. Snapshots `23-walkthrough`, `24-walkthrough-causes`, `25-walkthrough-checked`; lab run (normal user) under out\ only.
- Fixed in passing: README and TESTING had a carriage return where a backtick-r had been eaten (`results.json`, `report.html`).
- Next: GX4 (Ctrl+K command palette, keyboard-first paths, in-app toasts replacing the Windows message boxes).

## GX4 (2026-11-27): Ctrl+K command palette, keyboard-first paths, in-app toasts - DONE (PASS in round 2)
- `src/Gui/GuiPalette.ps1` (pure): pages, the command-bar commands (only those available now), objects by name and findings by text; every word must match; title starts
  first, then word starts, then anywhere; stable order. Window: an overlay with a dimmed backdrop, a search box and a virtualised list; Enter opens, Esc closes and returns
  the focus, Tab stays inside. Palette commands click the same buttons the command bar has.
- All shortcuts in `Invoke-MspkiGuiShortcut` (Ctrl+K, F5, Esc, Ctrl+1..6, Ctrl+F, Ctrl+O, new F6 / Shift+F6 regions, Alt+Left back). Toasts (`Show-MspkiGuiToast`) replace the
  Windows message boxes once the window is shown (at most 3; 5/8/12 s by tone; pause on hover; X to dismiss; screen-reader live region); "Run finished", "Run cancelled", "Export finished".
- Found and fixed: Windows PowerShell 5.1 throws "Argument types do not match" for `@($list)` of the window's row list in one binder path; the palette index takes `.ToArray()`.
  A failure while opening results before the window shows still falls back to a message box (that is how the hang showed up in the first test run).
- Tests: `tests/GuiPalette.Tests.ps1` (12), `tests/GuiKeyboard.Tests.ps1` (9: real window off-screen, keyboard-only replay, open time under 100 ms, toasts).
- Next: GX5 (themes: every brush a DynamicResource, dark and light following Windows, high contrast, reduced motion, contrast test).

## GX5 (2026-11-27): themes (dark and light following Windows, high contrast, reduced motion) - DONE (PASS in round 2)
- Colours moved to data files `src/Gui/Palette.Light.xaml` and `Palette.Dark.xaml` (66 keys each, same keys); Theme.xaml and MainWindow.xaml refer to them only as
  DynamicResource (no StaticResource B.*, no fixed colour except the header role badge, the palette backdrop and shadows). High contrast: the same keys mapped to SystemColors.
- `src/Gui/GuiTheme.ps1`: choice Auto (follow Windows: one read of AppsUseLightTheme, plus SystemParameters.HighContrast, every 2 s), Light, Dark; high contrast always wins;
  live switch from the title-bar button or Ctrl+K "theme"; `-Theme` on Start-MspkiHealthCheckGui.ps1 (also for snapshots). Reduced motion: no Storyboard, no animation, no popup fade.
- Found: WPF's own control styles (TabControl, TabItem, ListBox, DataGrid, ...) set the system text colour, which the light theme hid. Each now sets the theme colour.
- Tests: `tests/GuiTheme.Tests.ps1` (12: same keys, every key used exists, no static or fixed colours, WCAG pairs in both palettes, theme choice, high-contrast mapping,
  live switch in the window, reduced motion). Gui.Tests merges the light palette when it loads Theme.xaml alone.
- Next: GX6 (map page: full-page canvas, zoom and pan, clustering, hover "Where this exists").

## GX6 (2026-11-27): full-page Discovery map and the owner's map review - DONE (PASS in round 2)
- `src/Gui/GuiMap.ps1` (pure, moved out of GuiMission.ps1 and rewritten without pipelines): the map model with an "issuer not confirmed" link (or an "Unknown issuer" node) for
  every orphan CA, path health on links (failing red dashed + cross marker, warning amber + marker), plain-word link texts, median sweeps that order each column (crossings on
  the demo world 12 -> 0, asserted), order-keeping placement, the page views (status, type, CA focus, only problems with the path as context, search marks, groups of a host's
  addresses above 120 nodes), keyboard neighbours, zoom arithmetic, "Where this exists" hover text, and `Invoke-MspkiGuiMapJob` (the same job inline or in the worker).
- `src/Gui/GuiMapPage.ps1`: a background runspace computes model, view and layout; the window draws and builds animations in slices of about 20 ms on a new canvas (no flicker).
  The page: Map | Tree switch, search (dims), filters, CA focus, only problems, zoom (Ctrl+wheel, Ctrl +/-, Ctrl+0, slider, buttons), pan (drag, wheel, Shift+arrows), minimap,
  arrow keys between nodes + Enter, Esc clears search then filters, selection on the pane's trail (Back / Alt+Left), groups expand on click or Enter, replay, PNG export
  (`Export-MspkiGuiMapPng` in GuiState.ps1: the run folder inside out\, else out\ itself). Overview: same visuals, map capped at 560 px with "Open the whole map".
- Owner items 7-9: one icon table and a term list in GUI-DESIGN sections 8 and 9 (banner "Action needed" now the circled cross, days-left pills a clock, failure toasts the
  cross); an earlier run is "Showing an earlier run" with the info icon; the banner says when and where, with "Run now"; Open report follows report.html (or
  <name>-report.html) beside the loaded file and is re-checked when the window is activated.
- Measured (this VM): 500-object estate grouped view 91 ms and layout 67 ms (best of five, pure; acceptance < 300 ms; ordering sweeps stop when they bring no gain);
  model about 340 ms in the worker; map work on the UI thread in 15 ms slices: 74 ticks, 95th percentile 19 ms, worst 39 ms in the window test; page switch 58-69 ms
  (budget 150); pan or zoom 0.25-0.4 ms per step; palette open under 100 ms (GX4 test, unchanged). The first calls of the drawing code are compiled at start-up (warm-up).
  Ticks during which .NET ran a full garbage collection are counted apart; the window test asserts 99 % of the other ticks under 50 ms and the worst under 100 ms. Clean full
  run: 72 ticks, 95th percentile 18 ms, worst 25 ms. (Spikes of 54 and 197 ms seen earlier came while two of my finished test runs had not exited and held about 7 GB; the
  runner now exits explicitly.) Open for GX11: opening a results file parses it and fills the grids on the UI thread once (pre-existing, before GX6).
- Full suite: 1695 passed, 0 failed, 1 skipped, 183 s.
- Tests: `tests/GuiMap.Tests.ps1` (33: orphan CA, crossings, path health, link words, views, groups, keyboard, zoom, performance, export path, report path, and the real window
  on a generated 500-object estate: worker, slices, keyboard, Back, Enter on a group, Esc, palette, PNG export, tree); `tests/GuiMapFixture.ps1` generates LARGE estates (example.test).
- Next: GX7 (lifecycle timeline and interactive chain view).

## GX7 (2026-11-27/28): lifecycle timeline and chain view - DONE (PASS in round 2)
- Engine: Next CRL Publish is kept on the CRL entity (`NextPublish`; EntityGraph test). Lab run (non-elevated, under out\ only): both CRLs carry it.
- `src/Gui/GuiLifecycle.ps1` (pure, runs in the map worker): lifecycle model (countdowns from the run's time, never from today), the copy of each CRL at every address
  and at the CA, axis range, ticks and bars as star widths, each view's own CA status and "runs out first", the chain leaf -> root with each AIA/CDP/OCSP result and the
  link headings. `src/Gui/GuiTimelinePage.ps1`: Certificates / CRLs / Chain on one page (Ctrl+4; Run log moved to Ctrl+7), rows open in the details pane, Back syncs the
  selection, the axis leaves out labels that would be cut or crossed by the run's line and redraws on resize. Palette: page and tlcerts / tlcrls / tlchain.
- Details pane everywhere: property names in sentence case with acronyms (`Get-MspkiGuiPropertyLabel`), UTC times as "17 Nov 2026, 08:00 UTC", headings use the common
  name (`Get-MspkiGuiReadableName`; the DN stays in the properties).
- Demo: `tools/dev/New-MspkiDemoLifecycleSample.ps1` (developer-only, idempotent) adds CRLs to the hand-made mixed sample and writes the `expired-crl` and `renewal-drift`
  samples; snapshot frames 35-35f. Fixed: `@()` around a generic List property throws "Argument types do not match" in PS 5.1 (the job returns a plain array now).
- Measured: timeline job (model + 99 CRL rows, 300-object estate) 147-157 ms in the worker; rows on screen 9-10 ms of UI-thread work; switch to the Timeline 92-118 ms (budget 150).
- Tests: GuiTimeline 31 (model, countdowns, copies, axis, rows, per-view status, chain, link headings, budget, the real window), GuiEntity +3, GuiPalette for 7 pages.
- Full suite: 1737 passed, 1 skipped, 206 s (the one failure was a GX8 export added mid-run and removed; GX8 is not in this commit).
- Next: GX8 (finding Key, History page, compare two runs).

## GX8 (2026-11-28): run history and compare two runs - DONE (PASS in round 2)
- Engine: every finding gets a deterministic `Key` (`src/Model/FindingKey.ps1`, after the diagnosis is added): k1- + SHA-256 of category, status code, rule (knowledge
  topic), target and endpoint; the order tells duplicates apart; the status is not in it. Results written before keep working (findings paired by what they are about).
- `src/Gui/GuiHistory.ps1` (pure, runs in the map worker; the worker imports the module the first time it reads a results file): run files one and two folders down (60
  newest), run summaries (score, counts, finished, -SkipNetwork), `Compare-MspkiGuiRun` (pairs by Key, then by subject; new problems, changed worse/better, resolved or no
  longer reported, still open, objects added/gone by id, score per area, notes on what it cannot know), the comparison's view. Reading is stepped (250 ms of work per job,
  at least one file), so the list fills in while the worker stays free for the map; a worker failure is shown, never redone on the UI thread.
- `src/Gui/GuiHistoryPage.ps1` + History tab (Ctrl+7; Run log Ctrl+8): forest choice, score over time, runs newest first ("On show", "Did not finish"), Compare / Open per run,
  What changed opens on the run on show against the run before it (J4: one click, two for another run); a new problem opens its finding. Palette: page, histprev, histrefresh.
- Found and fixed: PowerShell variable names ignore case (`$root` replaced `[string]$Root`; `$new` would have replaced `$New`); two GUI files defined the same script variable
  (the Findings sort order changed) - a test now forbids it; `[bool]'False'` is true (yes/no values read as true/false or text). CRLs view glyph is now the CRL glyph (E81C is History).
- Measured: compare of two 300-object estates (read + compare, worker) 366-386 ms; switch to History 19 ms; a big comparison on screen 19 ms of UI-thread work; the real lab
  history (54 runs, under out\ only) read in the background while the window stayed usable.
- Dev: `tools/dev/New-MspkiDemoHistory.ps1` writes a three-run demo history under out\demo-history (snapshot frames 36-36b).
- Tests: `tests/FindingKey.Tests.ps1` (3) + the e2e Key check in Discovery.Tests; `tests/GuiHistory.Tests.ps1` (17: run files, summaries, stepped reading, comparison,
  notes, plain words, long sections, rows and trend, performance, the real window: J4, Compare, finding opens, palette, F6, names, UI budget; GUI script-scope guard).
- Full suite: 1770 passed, 0 failed, 1 skipped, 201 s. Next: the Opus review checkpoint (GX9 is not started).

## Independent GUI review after GX8 (2026-11-28) - DONE (review only, no product code changed)
- `docs/REVIEW-GX.md`: 14 snapshot sets (Alcyone world + LARGE estate; light, dark, reduced motion; minimum, 1360 x 860, 1920 x 1080), per-page scores, J1-J4 walk, consistency audit, 49 defects (1 Blocker, 9 High), top 10 changes, plan changes for GX9-GX11.
- Blocker D-01: the walkthrough's "Observed in this run" pill shows for any hint (GuiView `[bool]$bt`), while the engine and the Overview need support >= 10.
- Snapshot method defects (D-07): partial / no-CA frames are captured before the map worker finishes; frames 31-34 render the History page.
- Next: GX8b consistency pass (D-01..D-28), then GX9.

## GX8b (2026-11-28): consistency pass after the independent review - DONE
- Every Blocker, High and Medium of `docs/REVIEW-GX.md` is fixed, most Lows and one Polish item too; §8 of that file lists each defect with
  its commit. Open for GX11: D-09 (Overview card centring; opening focused on one CA was tried and declined), D-34, D-46, D-47.
- Honesty (D-01): the diagnosis carries a per-cause `Supported` flag; "Observed in this run" appears only for supported causes, everywhere
  (pane, copied text, Overview, HTML report). One status vocabulary (D-03/D-14): "Could not check" (lock) for permission and support skips.
- New pure helpers with tests (`tests/GuiConsistency.Tests.ps1`): status key and words, finding title and qualifier, grid column plan, time
  formatter, check placeholders, plain grouped actions, run-error view; a guard that no GUI function is defined twice (a History helper had
  silently replaced a new one).
- Snapshot method (D-07): settles after the map worker, tree frames on the map page, `frames.csv` checked by the window test.
- Next: GX9 (Explain, Learn, glossary, tour, celebration) with the review's changes in ROADMAP.

## GX9 (2026-11-28): Explain mode, Learn page, glossary, tour, celebration - DONE (PASS in round 2)
- `src/Knowledge/Glossary.psd1` (data only, 33 terms keyed on the GUI-DESIGN §9 words and the Overview's acronyms); `src/Gui/GuiLearn.ps1`
  (pure: glossary lookup, Learn items = concept cards from the existing object notes + terms, tour stops, settings read, celebration rule);
  `Save-MspkiGuiSettings` in GuiState.ps1 (out\gui-settings.json only); `src/Gui/GuiLearnPage.ps1` (window: Learn page Ctrl+9, Explain mode
  toggle in the command bar, tour layer, celebration pulse + notice). Toasts can carry one action ("Take the tour").
- The tour is offered once in a notice after the first results (never starts by itself); Ctrl+K "Take the tour" and "Explain mode on or off".
- Tests: `tests/GuiLearn.Tests.ps1` (13: data-only glossary, §9 keys, J5 term coverage, no match inside words, Learn items, tour targets,
  settings guard, celebration rule, real window: explain budget < 400 ms, Ctrl+9, tour steps, settings file). Palette tests for nine pages.
- Next: GX10 (executive summary).

## GX10 (2026-11-28): executive summary - DONE (PASS in round 2)
- `src/Gui/GuiSummary.ps1`: one printable HTML page from the Overview's own helpers (score + band + "held down by" + partial note, areas, the
  first three actions with their honest cause wording, score over time when History has two scored runs, what was not checked, limits in
  the footer); "As of" and the earlier-run notice come first. Every value HTML-encoded; no script, no link, no external resource; A4 print CSS.
- Written by `Save-MspkiGuiExecutiveSummary` (GuiState.ps1): `.html` only, inside the output folder (the run's folder when it is inside).
  J6: "Executive summary" under the score ring (one click) or Ctrl+K "Executive summary".
- Tests: `tests/GuiSummary.Tests.ps1` (7, including the real window). Printed-page check: headless Edge render and PDF under out\ only.
- Next: GX11 (adversarial round, separate discriminator session) - see the open IDs in REVIEW-GX §8.

## GX11 (2026-11-28): adversarial round, builder's own - PASS in round 2; independent session pending
- Round 1 on the LARGE estate (dark, minimum) and 150 %: address targets now "host · file (HTTP)" in the grid and titles; layer chips hide when
  nothing was tested; the Error status is "check failed" everywhere (headline counts, grouped actions). Tests in GuiConsistency.
- Not done (needs the owner or a physical setup): an independent discriminator session (single-agent rule), real high-contrast and maximised
  frames, keyboard-focus frames (WPF draws focus visuals only after real key input). Open IDs: D-09 centring, D-34, D-46, D-47.

## GX11 open items and DS2 (2026-11-28)
- D-34 (map tree follows the pane's trail) and the rest of D-09 (Overview card opens on the CA columns, captions pinned) fixed and
  tested (b3ba5f1); REVIEW-GX §8 updated. D-46 and D-47 stay open (not cheap). Hygiene: a host match that continues into ".exa" is a
  cut-off reserved name in prose (the GX11 notes quoted "pki28.corp.exa..."), not a host.
- Full suite before that commit: 1831 passed; three timing budgets failed only while the runner held 10 GB (the suite took 672 s) and
  pass alone. Watch the runner's memory (see the Pester memory note).
- DS2: `tools/dev/demo-site/New-MspkiWorldPki.ps1` writes `site/world/pki` (15 certificates, 7 CRLs, `pki.json`; demo clock 20 Nov 2026
  09:00 UTC; keys in memory only). `tests/DemoGenerator.Tests.ps1` verifies each object with the engine's signature code by key id.
- Next: DS1 (clock and run-identity seams in the engine, the boundary list, the simulated boundary, the baseline world) and DS3.
