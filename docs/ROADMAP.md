# Roadmap

Statuses: **DONE**, **BLOCKER**, **DISCOVERY** (top priority), **GUI**, **HOUSEKEEPING**.
Product rule that never changes: a normal user on a clean machine with Windows PowerShell 5.1 only. Research tools (packet
capture, RSAT, PSPKI, Sysinternals) are for understanding on the lab machine; the product never depends on them (D5).

## DONE
- Entity graph (results.json format 2, `docs/DATA-MODEL.md`): the base for G1/G2 drill-down. GUI reads format 1 and 2.
- Engine phases A-C (discovery, endpoint and CRL health, reports, exit codes); live AD discovery.
- GUI redesign passed the rubric (round 5); cancel, progress, developer snapshots.
- Audit High and Medium findings fixed (`docs/AUDIT.md`).

## BLOCKER
- SOLVED (2026-11-21): the 0x800706BA CA read failure is a DCOM access-denied for the standard account on the Root CA host (RPC fault 5 seen
  in a capture). The tool now reports it as an Inferred PERMISSION_DENIED with owner steps (`docs/RESEARCH.md`). The CA database view is still
  not in-box on clients.
- FIXED: a CDP LDAP URL without an attribute part was graded Fail (false positive). Still open: NDES is missed when the CA
  database view is unavailable (add the template-ACE / SPN route); the HTTPS reset on a CA host is reported without its meaning.

## DISCOVERY (top priority)
- **D1 Full hierarchy health.** Every root, intermediate and issuing CA; every CA certificate generation; every AIA, CDP and OCSP
  URI (HTTP, LDAP, file) actually tested; CRL freshness and publication (AD vs HTTP vs the CA's own CRL); delta CRLs;
  offline-root CRL risk; NTAuth and AIA containers. For anything not working, explain WHY (layered diagnosis).
- **D2 Endpoint identity.** For every link that responds or issues certificates: resolved IPs, reverse DNS, the CNAME/alias
  chain to the real host, the TLS certificate names and the server header.
- **D3 Local evidence.** Work out how this computer's certificates got here (stores, template extension, issuing CA,
  autoenrollment and lifecycle event logs, CEP policy) and use that as discovery.
- **D4 NDES / SCEP / Intune Certificate Connector.** Observe and report.
- **D5 Research tools.** Allowed in the lab for understanding; the product stays in-box only.

## GUI
- **G1** Drill into any object or result (CA, certificate, CRL, endpoint, template, finding), with links between related objects
  (certificate > issuer > CRL > endpoint) and a way back.
- **G2** "Where this exists" panel: every place an object was seen (AD container, CA server, HTTP, LDAP, local store, event log)
  with confidence, plus places where it is expected but missing.
- **G3** NDES / SCEP / Intune section.
- **G4** Show endpoint identity (IP, host, alias).
- **G5** A short "what is this and why it matters" note per object type; the tool should help people understand PKI.
- **G6** Low priority: custom dialogs, dark theme, remember column widths.

## HOUSEKEEPING
- Remaining Low audit items (L1-L4, L6-L11; L5 is fixed).
- Phase E (`-CertificateFile`, `-IncludeCertUtilVerify`, AD dependencies, CES SPN review).
- A fresh audit after major changes.
