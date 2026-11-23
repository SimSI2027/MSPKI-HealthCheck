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
- **G6** Low priority: custom dialogs, dark theme, remember column widths.

## HOUSEKEEPING
- Remaining Low audit items (L1-L4, L6-L11; L5 is fixed).
- Phase E (`-CertificateFile`, `-IncludeCertUtilVerify`, AD dependencies, CES SPN review).
- A fresh audit after major changes.
