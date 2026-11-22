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
