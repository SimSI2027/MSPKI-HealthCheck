# Roadmap

Statuses: **DONE**, **BLOCKER**, **DISCOVERY** (top priority), **GUI**, **HOUSEKEEPING**.
Product rule that never changes: a normal user on a clean machine with Windows PowerShell 5.1 only. Research tools (packet
capture, RSAT, PSPKI, Sysinternals) are for understanding on the lab machine; the product never depends on them (D5).

## Work packages (plan of record)
From 2026-11-22 this section is the plan of record. Statuses: DONE, IN PROGRESS, TODO.

| WP | Scope | Status |
|---|---|---|
| WP1 | results.json read without a size limit (in-box JavaScriptSerializer) | DONE (2026-11-21) |
| WP2 | D2 endpoint identity: A/AAAA, PTR, CNAME chain, TLS names, Server header, Web Enrollment | DONE (2026-11-21) |
| WP3 | D4 NDES without the CA database view: template permissions and SPNs, RA certificates, graph links | DONE (2026-11-22) |
| WP4 | D3 local evidence: stores, template extension, Lifecycle and autoenrollment events, enrollment policy cache | DONE (2026-11-22) |
| WP5 | GUI drill-down (G1, G2, G4, G5) | DONE (2026-11-22) |
| WP6 | PKI Services page (G3) | DONE (2026-11-22) |
| WP7 | GUI adversarial polish (max 3 rounds) | DONE (2026-11-22, PASS in round 2) |
| WP8 | Ready for audit | DONE (2026-11-22) |
| WP9 (Batch H) | "Probable causes and next steps": researched knowledge base (`src/Knowledge`, `docs/KNOWLEDGE-SOURCES.md`), ranking from each finding's own evidence, in results.json, the HTML report and the details pane | DONE (2026-11-22) |

**WP9 Batch H: probable causes and next steps.** DONE (2026-11-22). Every non-passing finding explains itself:
- Researched knowledge base, data only: `src/Knowledge/Diagnosis.psd1` (42 dated sources, a default topic for every status code, ordered rules) and
  five `Diagnosis.Topics.<Area>.psd1` files (120 topics: plain explanation, causes ranked, a read-only check and a fix for each cause, sources).
  Covers RPC/DCOM, CRL/AIA/delta, LDAP versus HTTP, OCSP, CES/CEP, NDES, Intune, TLS, NTAuth, ESC1-16, CA renewal, time skew. `docs/KNOWLEDGE-SOURCES.md` lists each source with the date and how far it was read.
- Ranking (`src/Model/Diagnosis.ps1`): the knowledge order is the prior; signals from the finding's own message, evidence and layer results move causes; Notes and Remediation are never evidence. Wording is honest: "Most likely" only
  when something observed backs the cause, otherwise "Most common"; a cause is probable, never proven.
- Shown in results.json (`Diagnosis` on each finding), the HTML report (plain text, no link) and the GUI details pane; results.json from older runs get it computed when read.
- Checked against the lab as a normal user in three rounds (`docs/RESEARCH.md`). Tests: `tests/Diagnosis.Tests.ps1`.
- Next for the GUI program: a "what to do" overview (the top causes of all findings grouped), a one-click copy of the checks, and highlighting `Observed` evidence in the Findings table.

**WP5 GUI drill-down (G1, G2, G4).** DONE: Objects page, object details pane, links from every pane, tiles and cards. Scope was:
- Load the helpers in the window.
- An object details pane, and an Objects page (Ctrl+5) listing every entity with search and type filter.
- Every object and finding anywhere in the GUI opens its details: Findings, Discovery Map, Overview tiles and cards, and the
  PKI Services page once it exists.
- Clickable related-object links (certificate > issuer > CRL > endpoint > host) with breadcrumbs and Back.
- A "Where this exists" panel: every observation with confidence and time, and the expected-but-missing places clearly marked apart.
- Host identity: IPs, PTR, alias chain, TLS names, Server header.
- Plain-language "What is this and why it matters" note per object type.
- Use the existing Theme.xaml and design language. Check with -Snapshot.

**WP6 PKI Services page (G3).**
- Web Enrollment, CES, CEP, NDES/SCEP (with RA certificates and their CA), OCSP and the Intune Connector.
- Each shows status, confidence, host, evidence and security notes (e.g. the ESC8 warning), and drills down to its details.
- Clearly show "not found" versus "can't be checked from here" (e.g. Intune on other hosts).

**WP7 GUI adversarial polish (GAN loop, maximum 3 rounds).**
- Generator builds and fixes.
- Render every page and the new detail views with -Snapshot (welcome, running, finished, partial, error; minimum size,
  1920x1080, maximised).
- Discriminator judges only the PNGs against the fixed rubric in GUI-DESIGN.md; assumes it is not enterprise grade until
  proven; lists every defect by page and control; scores it.
- PASS = every category at 8 or more and no defect a Fortune 500 customer would notice. Scores are logged in GUI-DESIGN.md.

**WP8 Ready for audit.**
- A full normal-user run against the lab.
- Discriminator check against the private lab facts: false positives, false negatives, wrong confidence and unclear
  explanations; fix them, maximum 3 rounds.
- Update README.md and docs/TESTING.md (plain language, including the new pages), the statuses here and the known limitations.

Every new check or GUI helper needs tests (sanitised example.test fixtures). The full suite stays passing.

## GUI program (plan of record from 2026-11-23)
Design: `docs/GUI-EXPERIENCE.md`. Judged on the upgraded rubric (`docs/GUI-DESIGN.md` §6). Screenshots use the demo world
(`docs/DEMO-WORLD.md`). Every WP: tests for each new helper, -Snapshot frames of every new state, the full suite green.

| WP | Scope (build order) | Status |
|---|---|---|
| GX0 | Prototype: mission-control Overview + live discovery map (replay), world fixture, mid-animation snapshots, 2 discriminator rounds | DONE (2026-11-23, PASS in round 2) |
| GX1 | Engine events for the live map (`Entity`, `Relation`, `Probe` queue items) | DONE (2026-11-23) |
| GX2 | Mission-control Overview, production quality | DONE (2026-11-23, PASS in round 2) |
| GX3 | Guided troubleshooting walkthrough, Observed highlighting, copy the checks, mark as checked | DONE (2026-11-27, PASS in round 2) |
| GX4 | Ctrl+K command palette, keyboard-first paths, in-app toasts | DONE (2026-11-27, PASS in round 2) |
| GX5 | Themes: dark and light (follow Windows), high contrast, reduced motion | DONE (2026-11-27, PASS in round 2) |
| GX6 | Map page: full-page canvas, zoom and pan, clustering, hover "Where this exists" | DONE (2026-11-27, PASS in round 2) |
| GX7 | Lifecycle timeline (expiry countdowns, CRL heartbeat) and interactive chain view | DONE (2026-11-28, PASS in round 2) |
| GX8 | Run history and compare two runs | DONE (2026-11-28, PASS in round 2) |
| GX8b | Consistency pass after the independent review (`docs/REVIEW-GX.md`): D-01..D-28, terms check against GUI-DESIGN §9 | DONE (2026-11-28; every Blocker, High and Medium fixed; D-34, D-46, D-47 and part of D-09 open for GX11) |
| GX9 | "Explain it to me" mode, Learn page, glossary, first-run tour, healthy celebration | DONE (2026-11-28, PASS in round 2) |
| GX10 | Executive summary export (printable HTML) | DONE (2026-11-28, PASS in round 2) |
| GX11 | Adversarial round on the upgraded rubric (max 3 rounds; PASS gate for the program) | DONE as the builder's own round (2026-11-28, PASS in round 2); the independent discriminator session is still to be started by the owner |

**Acceptance criteria**
- **GX0** The Overview shows the score ring, per-area bars, "What to do next" and a map that builds itself (staggered Storyboards,
  pulses), from a results file in the demo world; `-Snapshot` renders start, mid-build, probing and finished frames by seeking the
  Storyboards; reduced motion sets the final state; the score helper has tests; findings in the rubric are logged in GUI-DESIGN §7.
- **GX1** With `-Control`, the engine queues one `Entity` item per new entity (id, type, name, parent ids) and one `Relation` item per
  relation, and `Probe` start/end items keyed by endpoint id; without `-Control` nothing changes (CLI byte-identical results.json). At
  least 95 % of the final graph's entities arrive before the run ends; run time grows by under 5 % on the lab; tests with a recording control.
- **GX2** Score model in `Get-MspkiGuiHealthScore` exactly as GUI-EXPERIENCE §6, with tests for every band, the cap, partial and no-CA;
  "How is this scored?" in plain words; area bars and the ring open Findings filtered; "What to do next" lists every action (Overview shows
  5, a full list one click away); headline sentence; the running state is the live mission control (no separate panel); journeys J1 and
  J2 meet their targets; Overview scores 8+ on A1-A10 and B1-B5 at minimum size, 1920 x 1080 and maximised.
- **GX3** Walkthrough in the details pane (meaning, causes ranked, Observed marks, a copy button per check and per cause, mark as checked
  kept in `out\<run>\gui-state.json`, fix with its owner, sources); J3 in 3 clicks from the Overview; no check text is ever executed
  (static test: the pane only calls the clipboard).
- **GX4** Ctrl+K opens in under 100 ms; finds pages, commands, objects by name and findings by text with a virtualised list; Esc closes and
  returns focus; every command of the command bar is reachable; toasts replace the Windows message boxes; a keyboard-only replay of J1-J6.
- **GX5** Every brush is a `DynamicResource`; dark and light palettes meet WCAG AA (checked by a contrast test over the palette pairs); the
  theme follows Windows and can be switched live; high contrast uses `SystemColors`; with reduced motion no Storyboard runs.
- **GX6** Full-page map: zoom (wheel, Ctrl +/-), pan, fit, focus a CA; clusters above 120 nodes; arrow keys between nodes; the tree stays as
  the alternative; a generated 500-entity fixture lays out in under 300 ms and never blocks the UI thread for more than 50 ms.
- **GX7** Timeline: one row per CA generation and CRL, now-line, countdowns, next-update windows and the overlap; chain view leaf → root
  with each AIA/CDP link's result; both drill into details; snapshots in the demo world's `renewal-drift` and `expired-crl` scenarios.
- **GX8** Findings carry a deterministic `Key` (category, code, rule, target; engine change with tests); History lists runs under `out\`
  (read-only) with the score sparkline; compare shows new, resolved and changed findings and objects added or gone; J4 in 2 clicks.
- **GX8b** No Blocker or High open; every Medium fixed or accepted by the owner in writing; the §9 terms are the only status words (test against the icon table).
- **GX9** Glossary in `src/Knowledge/Glossary.psd1` (data only, tested like the diagnosis files); explain mode underlines terms with hover
  definitions; concept card per object type; a 4-stop tour offered once (`out\gui-settings.json`); the celebration runs once per healthy run.
  Review changes (REVIEW-GX §7): concept cards reuse the existing "What it is" notes (no second set); glossary keys are the §9 terms; the J5
  check ("no term on the Overview unexplained") also covers AIA, CDP, LDAP, CES, OCSP and "partial score" (the exit code left the Overview,
  D-36); tour stops: the score line with "held down by", What to do next, the map, Ctrl+K, each rendered at minimum size, in dark and with
  reduced motion; the celebration is built last and kept small.
- **GX10** Executive summary reporter: one printable page (score, trend when history exists, areas, top 3 actions in plain words, what was
  not checked); written under `out\` only; J6 in 2 clicks; hygiene and report tests. Review changes: reuse the Overview helpers after D-21
  and D-12 (grouped plain actions, readable titles: done in GX8b); print the "as of" date and the earlier-run notice prominently; judge the
  HTML with print CSS in a browser frame, saved under `out\` only.
- **GX11** Discriminator on PNGs and journey click paths, all states, three sizes, both themes, reduced motion on and off: every category
  8+, no Fortune 500 defect. Rounds logged in GUI-DESIGN §7. Review changes: the snapshot method is fixed first (D-07, done: `frames.csv`
  and its test); add frames for keyboard focus on nav, buttons, chips, pane links and palette rows, the options strip open, the error state
  with its actions, History with a single run, the LARGE estate on every page, a real high-contrast theme (dev VM user only, never a lab
  server), maximised on a 1920 x 1080+ screen, 150 % and 200 %; a LARGE fixture whose findings carry real status codes; a discriminator
  that runs apart from the generator (a fresh session given only the PNGs, the rubric and REVIEW-GX); every REVIEW-GX defect ID closed with
  a frame that proves it (open: D-09 Overview card centring, D-34, D-46, D-47).

## Demo site (plan of record from 2026-11-23)
Plan: `docs/DEMO-SITE.md`. World: `docs/DEMO-WORLD.md`.

| WP | Scope (build order) | Status |
|---|---|---|
| DS1 | Simulation boundary and world fixture format (baseline scenario) | TODO |
| DS2 | World PKI material (certificates and CRLs); developer tool in `tools/dev/` (owner approved 2026-11-23, CLAUDE.md rule added) | DONE (2026-11-28; 15 certificates, 7 CRLs, verified with the engine) |
| DS3 | Generator: real engine per scenario, recorded events, manifest, guards | TODO |
| DS4 | Site shell, design tokens generated from Theme.xaml | TODO |
| DS5 | Scenario view: mission control, map replay, findings, details with the walkthrough | TODO |
| DS6 | Mobile, accessibility, performance budget | TODO |
| DS7 | GitHub Pages workflow (Windows PowerShell 5.1 generate job, deploy job) | TODO |
| DS8 | Launch check on the upgraded rubric; README link | TODO |

**Acceptance criteria**
- **DS1** A list of boundary functions, enforced by a test against the module (every function using an I/O API is listed); fixture schema
  for directory, CA, network and local data; the baseline world runs end to end with no real network, AD or COM call (a guard throws).
- **DS2** Owner approval recorded and a CLAUDE.md clarification for the developer-only tool; keys exist only in memory; only public DER is
  committed; every certificate and CRL of the world verifies with the engine's own signature code; the `forged-aia` certificate does not.
- **DS3** Every scenario of DEMO-WORLD produces `results.json`, `events.json` and `manifest.json`; output byte-identical for the same commit;
  no unexpected Error/PermissionDenied finding; the hygiene scan over the output finds only world names.
- **DS4** Plain HTML/CSS/JS, no third-party runtime; `tokens.css` generated from Theme.xaml with a drift test; CSP `default-src 'self'`; the
  "Simulated environment" banner with version and commit on every page.
- **DS5** The scenario view matches the WPF Overview, Findings and details for the same results.json (a test compares the computed score,
  areas and actions with the GUI helpers' output); replay with play, pause, speed and scrub; deep links to findings.
- **DS6** One column below 720 px, bottom-sheet details, 44 px targets; `prefers-reduced-motion`, `prefers-color-scheme`, `forced-colors`;
  first view under 150 KB compressed; Lighthouse 95+ (performance, accessibility) on the mobile profile.
- **DS7** `.github/workflows/pages.yml` as in DEMO-SITE §5; actions pinned by SHA; least-privilege permissions; generated data not committed.
- **DS8** Desktop and phone screenshots pass the upgraded rubric; README links the site and says its data is simulated.

## DONE
- Entity graph (results.json format 2, `docs/DATA-MODEL.md`): the base for G1/G2 drill-down. GUI reads format 1 and 2.
- WP1 (2026-11-21): results.json is read with the in-box JavaScriptSerializer (no size limit; 10 MB tested).
- Engine phases A-C (discovery, endpoint and CRL health, reports, exit codes); live AD discovery.
- GUI redesign passed the rubric (round 5); cancel, progress, developer snapshots.
- Audit High and Medium findings fixed (`docs/AUDIT.md`).

## BLOCKER
- SOLVED (2026-11-21): the 0x800706BA CA read failure is a DCOM access-denied for the standard account on the Root CA host (RPC fault 5 seen
  in a capture). The tool now reports it as an Inferred PERMISSION_DENIED with owner steps (`docs/RESEARCH.md`). The CA database view is still
  not in-box on clients.
- FIXED: a CDP LDAP URL without an attribute part was graded Fail (false positive). Still open: NDES is missed when the CA
  database view is unavailable (FIXED 2026-11-22: template-ACE / SPN route); the HTTPS reset on a CA host is now reported with its meaning (FIXED).

## DISCOVERY (top priority)
- **D1 Full hierarchy health.** STATUS 2026-11-21: DONE for Enterprise hierarchies (generations, AIA/CDP design and order, NTAuth vs AIA,
  offline-root CRL lifetime, OCSP unused, TLS reset, SAN without DNS); a standalone offline root is graded only from its AD-published certificate.
  Original scope: Every root, intermediate and issuing CA; every CA certificate generation; every AIA, CDP and OCSP
  URI (HTTP, LDAP, file) actually tested; CRL freshness and publication (AD vs HTTP vs the CA's own CRL); delta CRLs;
  offline-root CRL risk; NTAuth and AIA containers. For anything not working, explain WHY (layered diagnosis).
- **D2 Endpoint identity.** STATUS 2026-11-21: DONE (WP2: A/AAAA, PTR, CNAME chain, TLS names, Server header, Web Enrollment). Original scope: For every link that responds or issues certificates: resolved IPs, reverse DNS, the CNAME/alias
  chain to the real host, the TLS certificate names and the server header.
- **D3 Local evidence.** STATUS 2026-11-22: DONE (WP4: stores, template extension, Lifecycle and autoenrollment events, policy cache). Original scope: Work out how this computer's certificates got here (stores, template extension, issuing CA,
  autoenrollment and lifecycle event logs, CEP policy) and use that as discovery.
- **D4 NDES / SCEP / Intune Certificate Connector.** STATUS 2026-11-22: DONE (WP3: template-permission / SPN route, RA certificates, graph; the connector is checked on this computer only).
- **D5 Research tools.** Allowed in the lab for understanding; the product stays in-box only.

## GUI
- **G1** STATUS 2026-11-22: DONE (WP5). Drill into any object or result (CA, certificate, CRL, endpoint, template, finding), with links between related objects
  (certificate > issuer > CRL > endpoint) and a way back.
- **G2** STATUS 2026-11-22: DONE (WP5). "Where this exists" panel: every place an object was seen (AD container, CA server, HTTP, LDAP, local store, event log)
  with confidence, plus places where it is expected but missing.
- **G3** STATUS 2026-11-22: DONE (WP6, PKI services page). NDES / SCEP / Intune section.
- **G4** STATUS 2026-11-22: DONE (WP5). Show endpoint identity (IP, host, alias).
- **G5** STATUS 2026-11-22: DONE (WP5, one note per object type). A short "what is this and why it matters" note per object type; the tool should help people understand PKI.
- **G6** Superseded by the GUI program (GX4 toasts, GX5 themes, remembered layout in GX4/GX9).

## HOUSEKEEPING
- Remaining Low audit items (L1-L4, L6-L11; L5 is fixed).
- Phase E (`-CertificateFile`, `-IncludeCertUtilVerify`, AD dependencies, CES SPN review).
- A fresh audit after major changes.
