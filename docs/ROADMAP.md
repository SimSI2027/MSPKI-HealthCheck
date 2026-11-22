# Roadmap

Statuses: **DONE**, **BLOCKER**, **DISCOVERY** (top priority), **GUI**, **HOUSEKEEPING**.
Product rule that never changes: a normal user on a clean machine with Windows PowerShell 5.1 only. Research tools (packet
capture, RSAT, PSPKI, Sysinternals) are for understanding on the lab machine; the product never depends on them (D5).

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
- **G1** STATUS 2026-11-22: IN PROGRESS (WP5: view models done, window wiring next). Drill into any object or result (CA, certificate, CRL, endpoint, template, finding), with links between related objects
  (certificate > issuer > CRL > endpoint) and a way back.
- **G2** STATUS 2026-11-22: IN PROGRESS (WP5, view model done). "Where this exists" panel: every place an object was seen (AD container, CA server, HTTP, LDAP, local store, event log)
  with confidence, plus places where it is expected but missing.
- **G3** NDES / SCEP / Intune section.
- **G4** STATUS 2026-11-22: IN PROGRESS (WP5, view model done). Show endpoint identity (IP, host, alias).
- **G5** A short "what is this and why it matters" note per object type; the tool should help people understand PKI.
- **G6** Low priority: custom dialogs, dark theme, remember column widths.

## HOUSEKEEPING
- Remaining Low audit items (L1-L4, L6-L11; L5 is fixed).
- Phase E (`-CertificateFile`, `-IncludeCertUtilVerify`, AD dependencies, CES SPN review).
- A fresh audit after major changes.
