# Progress log

Newest entry first. Keep each entry to 3–6 lines: phase, what was done, what is next, open issues.
Build phases A–E map to the numbered steps in REQUIREMENTS §7.

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
- CA binary properties are requested as Base64 and decoded by the `X509Certificate2` constructor, so the code
  needs no `FromBase64String` (forbidden by the hygiene test).
- CA config string = `dNSHostName\displayName` (falls back to `cn`). CA_DISP 4 is reported as `Invalid`.
- Role/lifecycle without CA data: Enterprise CA from AD → `Referenced`; same-subject dating → `Inferred`; only the
  CA's own signing-certificate list gives `Confirmed`.
- Dev only: Pester 6.2 installed for the current user (in-box Pester 3.4 is too old). The tool has no dependency.
