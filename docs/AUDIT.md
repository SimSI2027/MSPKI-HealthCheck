# Audit: MSPKI Health Check against CLAUDE.md and REQUIREMENTS

- **Date:** 2026-11-20
- **Commit audited:** `b136283` (end of build phase D)
- **Scope:** every file in `src/`, the entry point, `demo/`, `tests/`, `docs/` and the git history. `ref/` was used for
  ideas only, through `docs/REF-INVENTORY.md` and a function-name grep. Nothing from `ref/` was copied, and no
  environment name from it appears here.
- **Method:** I read every source file in full, ran static greps for the risky patterns, parsed every script with the
  Windows PowerShell 5.1 parser, ran the full Pester suite under Windows PowerShell 5.1 (Pester 6.2), and scanned the
  tracked files and the full history for names, e-mail addresses and IP addresses. No code was changed.
- **Test run:** 572 tests, 572 passed, 0 failed.

> **Status after the fix session:** H1-H3 and M1-M11 are fixed, each with tests that fail on the audited code; see
> `docs/PROGRESS.md`. The Low findings (L1-L11) are still open and listed there. This document is the audit as it stood at
> commit `b136283`; the line numbers below refer to that commit.

## Summary

| Rank | Count | Main themes |
|---|---|---|
| High | 3 | Windows credentials sent in LDAP binds to hosts named in downloaded content; a stopped CES/CEP reported as a confirmed Pass; dead URLs in expired CA certificates graded Fail |
| Medium | 11 | system proxy and WPAD; an NDES admin GET that can change server state; "could not check" reported as "invalid"; Confirmed results that were never validated; scope ignored; merged status codes; test gaps |
| Low | 11 | key import from downloaded PFX, hidden chain-engine fetches, missing timeouts, localised error matching, ACLs in the export, smaller ESC-rule gaps, hygiene-test blind spots |

The hard rules mostly hold. Nothing writes outside the output folder through the tool's own code, no forbidden
AV/EDR pattern exists, the code is PS 5.1-clean, and no real names are in the repo. The serious problems are in three
places. LDAP URLs are fetched with an authenticated bind. Some results are graded more confidently than the evidence
supports. And a few behaviours that the current tests lock in will give false results on real PKIs.

### Hard rules at a glance

| Rule (CLAUDE.md) | Result |
|---|---|
| 1 Read-only | Holds in the tool's own code. Two edge cases are listed below: M2 (the NDES admin GET) and L1 (PFX import). |
| 2 No environment data | Holds. Only `example.test` names, `192.0.2.10` (a documentation range) and public Microsoft Learn links appear. |
| 3 No configuration | Holds. |
| 4 Bounded discovery | Mostly holds. Exceptions: H1 (LDAP hosts from unvalidated downloads), M1 (proxy/WPAD) and L3 (redirect hosts). |
| 5 PS 5.1 / .NET 4.x only | Holds for syntax. M6 (TLS defaults) and M3 (.NET 4.6+ crypto APIs) depend on the .NET 4.x release. |
| 6 AV/EDR-safe | Holds. `FromBase64String` appears only in `src/Model/BinaryData.ps1:33`, on data. See L10 for notes. |
| 7 No secrets | Holds for reading and logging. H1 and M1 concern credentials that leave the machine during authentication. |
| 8 Honest results | Several gaps: H2, M3, M4, M7 and M8. |

---

## High

### H1 Authenticated LDAP bind to any host named in an LDAP URL, including URLs from unvalidated downloads; ignores `-SkipNetwork`
- `src/Analyzers/EndpointHealth.ps1:89-103`: the LDAP branch runs before any `-SkipNetwork`, DNS or scope check (the
  `-SkipNetwork` test is only in the HTTP branch at line 105).
- `src/Probes/WebProbes.ps1:255-259`: the server is the host taken from the URL.
- `src/Discovery/Ldap.ps1:20-21`: `New-Object DirectoryEntry('LDAP://<host>/<dn>')` uses the default
  `AuthenticationTypes.Secure`, which means Negotiate with the current user's credentials, falling back to NTLM for hosts without an SPN.
- `src/Analyzers/EndpointHealth.ps1:189` and `:369-376`: a certificate downloaded from an AIA location is kept, and its
  URLs become new leads, even when it is not the expected issuer (the subject check at line 191 runs after line 189).
- **Scenario:** an `http://` AIA location (cleartext, so it can be tampered with on the network) returns a certificate whose
  CDP is `ldap://ldap.example.test/CN=x?certificateRevocationList`. On the next round the tool binds to that host
  with the running user's Windows credentials. This happens at link depth up to 5, and also with `-SkipNetwork` for LDAP URLs
  already present in AD-published certificates. No test covers this path: the `-SkipNetwork` test at
  `tests/Discovery.Tests.ps1:288` stops after discovery.
- **Fix:** contact LDAP only when the URL is serverless or names a domain controller of the current forest (check the host
  against `ForestDomains`, then DNS). Report other LDAP hosts as "not contacted" with the reason. Honour `-SkipNetwork`
  for every LDAP URL that names a host. Follow links from a downloaded certificate only when it is the expected issuer
  and the referencing certificate's signature verifies with its key.

### H2 A CES/CEP that answers HTTP 500, 501 or 503 is reported as Pass, OK, ConfirmedResponding and Confirmed
- `src/Analyzers/EnrollmentServices.ps1:9` lists 500, 501 and 503 as "responding". Lines 212-237 then classify the
  endpoint as `ConfirmedResponding`, give it `Pass`/`OK`, and set `Confidence = Confirmed` (line 230).
- `tests/EnrollmentServices.Tests.ps1:240` asserts this behaviour for HTTP 500.
- **Scenario:** the CES application pool is stopped, IIS answers 503, and the report says the referenced CES is healthy.
  REQUIREMENTS §5.6 names only 400, 401 and 405 as proof of reachability.
- **Fix:** treat 5xx as "reachable but failing": `Fail` (or `Warning`) with `HTTP_500` and state `Failing`, and keep
  "the host answered" in the Evidence. Change the test to match.

### H3 Every URL in every discovered CA certificate is graded, including expired and leftover certificates, so dead historical URLs give `Fail` and exit code 4
- `src/Model/LeadRegistry.ps1:297-315`: leads are registered from every certificate in the discovery map. That covers
  expired CA certificates, old roots left in Certification Authorities or NTAuth, and every signing-certificate index of
  each CA.
- `src/Analyzers/EndpointHealth.ps1:113`, `:121`, `:137` and `:157`, plus the expired-CRL path in `Test-MspkiCrlHealth`
  (line 267 onwards): these grade the URL `Fail` regardless of what carries it.
- `src/Analyzers/StaleReferences.ps1:212`: the stale-reference review then classifies the same URL as a
  `StaleReferenceCandidate` (Information, review only). The report contradicts itself, and the exit code follows the `Fail`.
- **Scenario:** a CA renewed years ago, whose expired certificate points to a CDP host that has since been retired.
  The result is `DNS_FAIL`/`Fail` and exit code 4 on most mature PKIs. REQUIREMENTS §5.9 says historical
  references are for review only.
- **Fix:** before grading, work out the carriers of each lead (the logic already exists in
  `Get-MspkiLeadReferenceFact`). When every carrier has expired, or the lead comes only from a historical signing-certificate
  index, report probe failures as review items (`Information` or `Warning`, `ReviewRequired`), not `Fail`.

---

## Medium

### M1 HTTP probes use the system proxy, which can trigger WPAD and send credentials to the proxy
- `src/Probes/WebProbes.ps1:64-73` never sets `$req.Proxy`, so `WebRequest.DefaultWebProxy` (the WinINET settings) is used.
- **Effects:**
  - Every internal PKI URL goes to a proxy host that did not come from discovery. With "Automatically detect
    settings" turned on, the first request can start WPAD discovery.
  - If the session sets `DefaultWebProxy.Credentials` (a common corporate profile line), each probe sends the user's
    credentials to the proxy.
  - Results describe the proxy, not the endpoint: a proxy 502/504 for an internal name that does not resolve becomes
    `HTTP_500`, not `DNS_FAIL`.
- `tests/Ndes.Tests.ps1:144` only checks `.Proxy` assignments that exist (there are none), and loopback requests bypass
  proxies, so the tests cannot see this.
- **Fix:** set `$req.Proxy = $null` by default, which matches the DNS, TCP and TLS layers that are already probed directly.
  Offer an opt-in switch for the system proxy, and record its use in RunInfo and in each Evidence entry.

### M2 The anonymous NDES admin request can create a challenge password on the server
- `src/Probes/NdesProbe.ps1:15` and `src/Analyzers/Ndes.ps1:185`. When the admin page is (wrongly) open to anonymous
  users, the request returns HTTP 200, and NDES generates and caches a new one-time password while rendering the page. The
  body is never read, but the password exists and takes a slot in the password cache until it expires. In exactly the
  misconfiguration this probe looks for, the request writes to a remote system. The CLAUDE.md rule 4 clarification allows
  the request, but in that case it conflicts with rule 1.
- **Fix:** make the admin request opt-in (a switch with a default), or drop it and rely on GetCACaps and GetCACert.
  Document the trade-off in the README.

### M3 "Could not check" is reported as `SIGNATURE_INVALID`, and the wrong key generation looks like a bad signature
- `src/Analyzers/EndpointHealth.ps1:238-242` sets `$sigOk = $false` for any result that is not `$true`, including
  `Valid = $null`, which `src/Model/Signature.ps1:96-123` uses for "unsupported algorithm" or "exception". Lines 281-284
  then report `Fail`/`SIGNATURE_INVALID`.
- `src/Analyzers/CACertificateHealth.ps1:48-59`: issuer candidates are matched by subject name only, with no AKI/SKI
  match. When only another key generation with the same name was discovered, the result is `SIGNATURE_INVALID`/`Fail`,
  where the correct result is "issuer not found" (`CHAIN_PARTIAL`).
- `src/Model/Signature.ps1:103-117` uses APIs that exist only from .NET 4.6 or 4.6.1 (`HashAlgorithmName`,
  `GetRSAPublicKey`, `ECDsaCertificateExtensions`). On a host with .NET 4.5.2 (still possible with WMF 5.1), every CRL
  would then be reported as `SIGNATURE_INVALID`. The .NET release is not checked or recorded.
- **Fix:** treat `$null` as Unknown (`ChainStatus = Unknown`, no change to Status), match the issuer by AKI and SKI first,
  and record the .NET release in RunInfo. If it is below 4.6, report a single `UNSUPPORTED` finding for signature checks.

### M4 Expired or leftover CA certificates are graded as if in use: `Critical` with `OBJECT_EXPIRED`
- `src/Analyzers/CACertificateHealth.ps1:170-191` grades every certificate that is not `Historical`. That includes
  `Lifecycle = Unknown`, set at `src/Discovery/CACertificates.ps1:106-108` for an AD copy that is not among the CA's own
  signing certificates, and inferred `Current`, set at `CACertificates.ps1:152-160` when a certificate is the only one
  with its subject (for example an old root left in Certification Authorities).
- **Scenario:** an old root CA certificate left in AD gives a `Critical` finding and exit code 4, based on an inferred
  lifecycle.
- **Fix:** grade validity at `Critical` only for `Current` with Confirmed or Referenced lifecycle. Report expired
  certificates with an inferred or unknown lifecycle as review items and leave them to the stale-reference review.

### M5 Scope is recorded but never changes the status
- REQUIREMENTS §4.2 says a cross-environment reference "goes to review; it is never a failure by default". The code
  ignores this: `src/Analyzers/EndpointHealth.ps1:113-158`, `src/Analyzers/EnrollmentServices.ps1:152-199` and
  `src/Discovery/CAProperty.ps1:264` and `:272` report `Fail` for `External` and `OtherForest` hosts. The only uses of `Scope`
  copy it into the finding.
- **Fix:** cap the status at `Warning`/`ReviewRequired` when the scope is `External` or `OtherForest`, and say so in the
  Evidence. Add a test.

### M6 TLS protocol versions are left to the .NET defaults
- `src/Probes/WebProbes.ps1:176` calls `AuthenticateAsClient($h)`, and `HttpWebRequest` relies on
  `ServicePointManager.SecurityProtocol`. With .NET 4.6.x, or 4.7+ without `SystemDefaultTlsVersions` or
  `SchUseStrongCrypto`, Windows PowerShell 5.1 offers only SSL 3 and TLS 1.0. A CES, CEP, NDES or HTTPS CDP that
  allows only TLS 1.2 then shows `TLS_HANDSHAKE_FAIL`. On the dev machine (.NET 4.8.1) the default is `SystemDefault`,
  so the tests cannot show this.
- **Fix:** pass the protocols explicitly (`Tls12 | Tls11 | Tls`, plus TLS 1.3 where the enum value exists) to
  `AuthenticateAsClient(host, $null, protocols, $false)`, and record the client defaults in RunInfo.

### M7 NDES `ConfirmedEndpoint` (`Pass`, Confirmed) is based on an anonymous 401 or 403 from the admin path alone
- `src/Analyzers/Ndes.ps1:174-183`. `tests/Ndes.Tests.ps1:213` asserts `ConfirmedEndpoint` while GetCACaps returns 404.
- IIS returns 401 for any path under a site or application that requires Windows authentication, before it checks
  whether the path exists. CA Web Enrollment `/certsrv` on the same host is an example. WAFs and IP restrictions return
  403 for every path. Both give a false "Confirmed".
- **Fix:** require a SCEP capability list from GetCACaps or a certificate from GetCACert before reporting
  `ConfirmedEndpoint`. When only the admin page answers 401 or 403, report `ProbableCandidate`, `Inferred`.

### M8 Other results marked Confirmed that were not validated
- `src/Analyzers/EndpointHealth.ps1:191-200`: an AIA location gets `Pass`/Confirmed when the downloaded certificate's
  subject string matches. Another key generation, or any certificate with that name, also passes. Compare SKI with the
  referencing certificate's AKI, or verify the referencing certificate with the downloaded key.
- `src/Analyzers/Ndes.ps1:330`: `NotDiscovered` is marked Confirmed even when no CA database could be read (the evidence
  says "0 of N"), and the finding's own note says the result is not proof. Use `Inferred`, or `Unknown` when nothing was read.
- `src/Analyzers/TemplateSecurity.ps1:66` and `:275-276`: a pattern match stays `Fail`/Confirmed when a Deny ACE exists
  for the same principal and effective access was not computed. Use `ReviewRequired` with `Inferred` in that case.

### M9 The NTAuth check applies to every Enterprise CA
- `src/Analyzers/AdContainerConsistency.ps1:79-91` warns whenever the current CA certificate is missing from
  NTAuthCertificates. REQUIREMENTS §5.4 limits this to "an authentication CA". Removing CAs that do not issue logon
  certificates from NTAuth is a recommended hardening step, and this check would flag it.
- **Fix:** warn only when the CA publishes a template that can be used for client authentication (the template facts
  are already computed). Otherwise report `Information`.

### M10 Different failures reported under the same status code
- **`RETRIEVAL_FAIL`** covers several different failures:
  - an unreachable server and any unclassified exception, including bugs in the tool's own code
    (`src/Model/New-MspkiFinding.ps1:194-197`, locked in by `tests/Model.Tests.ps1:105-106`). Analyzer crashes caught in
    `src/Start-MspkiHealthCheck.ps1:94-97` and similar blocks also end up here;
  - HTTP 1xx, 2xx other than 200, 3xx without a Location header, 405, 407 and 410, plus "response too large"
    (`src/Probes/WebProbes.ps1:88`, `:110` and `:118`);
  - unreadable template ACLs (`src/Analyzers/TemplateSecurity.ps1:245`);
  - "no SCEP answer" (`src/Analyzers/Ndes.ps1:204`).
- **`STALE_DATA`** covers:
  - an older CRL number at a location (`EndpointHealth.ps1:325`);
  - the CA's newer CRL still inside the grace period (`CrlPublication.ps1:115`);
  - a CRL whose thisUpdate is in the future, which is clock skew (`src/Model/Crl.ps1:270`);
  - a mismatch between the template lists in AD and on the CA (`AdContainerConsistency.ps1:110`);
  - Enrollment Services certificates (`:122`);
  - stale-reference candidates (`StaleReferences.ps1:212` and `:244`).
- **`UNSUPPORTED` and `NOT_DISCOVERED` for CA-wide failures:** `src/Model/ErrorInfo.ps1:11`, `:21` and `:23` map
  generic HRESULTs (`ERROR_FILE_NOT_FOUND`, `E_INVALIDARG`, `REGDB_E_CLASSNOTREG`) to NotFound or Unsupported, and
  `src/Discovery/CAProperty.ps1:300-309` applies that table to the first, fatal call. A registered Enterprise CA whose
  host no longer runs AD CS, or whose CA name does not match, then becomes `Skipped`/`UNSUPPORTED` or
  `Information`/`NOT_DISCOVERED` instead of a failure.
- **`TLS_UNTRUSTED_ROOT`** is used for every `WebException` with `TrustFailure` (`WebProbes.ps1:86`). That status also covers
  a name mismatch, an expired certificate and a revoked certificate. It is reachable after a redirect to another HTTPS host,
  because the TLS probe runs only for the first host.
- **`CHAIN_INVALID`** covers "signature could not be checked", "not marked as a CA" and "root role but not
  self-issued" (`src/Analyzers/CACertificateHealth.ps1:117-136`).
- **Fix:** add distinct codes through the REQUIREMENTS §3 process (for example an internal-error code, `HTTP_OTHER` and
  `CLOCK_SKEW`). For the fatal CA call, classify HRESULTs at the call site rather than through the generic table.

### M11 Weak or missing tests
- `Test-MspkiTlsEndpoint` is only ever mocked. No test runs it against a TLS listener, so the separation of untrusted root,
  partial chain, name mismatch and expired certificate is untested.
- `-SkipNetwork` is tested for discovery only (`tests/Discovery.Tests.ps1:288`). The endpoint, CEP/CES and NDES stages
  are not covered under `-SkipNetwork`, and neither are LDAP URLs that name a host (H1).
- Some tests lock in behaviour that this audit questions: `tests/EnrollmentServices.Tests.ps1:240` (H2),
  `tests/Ndes.Tests.ps1:213` (M7) and `tests/Model.Tests.ps1:105-106` (M10).
- Several cases have no test at all: the `Valid = $null` signature path (CRL or chain), an AKI/SKI generation mismatch,
  grading by scope (M5), leads carried only by expired certificates (H3), and HTTP 5xx and 503 results for CES and CEP.
- The proxy assertion at `tests/Ndes.Tests.ps1:144` is vacuous, and the loopback server cannot observe proxy use (M1).
- There are no recorded samples from a real AD CS (REQUIREMENTS §8 asks for lab `.cer`, `.crl` and LDAP samples). The CR_PROP ids,
  the CertificateAuthority.View column names, the `msPKI-Enrollment-Servers` layout, the v4 template attribute formats
  and the IIS behaviours above are all still assumptions, as `docs/PROGRESS.md` notes. The zero-configuration live run in
  REQUIREMENTS §8 has not been done.

---

## Low

### L1 Downloaded bytes are loaded with APIs that also accept PKCS #12
- `src/Model/Certificate.ps1:24`, `src/Analyzers/EndpointHealth.ps1:174-178` and `src/Analyzers/Ndes.ps1:32-36` use
  `X509Certificate2(byte[])` and `X509Certificate2Collection.Import(byte[])`. If an endpoint serves a PFX with an
  empty password, .NET imports its private key into a key container in the user profile. That is a write outside
  `out/`, triggered by remote content.
- **Fix:** check `[X509Certificate2]::GetCertContentType($bytes)` first and accept only `Cert` and `Pkcs7`.

### L2 The Windows chain engine can make network fetches the tool does not see
- The TLS probe's validation callback (`src/Probes/WebProbes.ps1:168-176`) and HTTPS through `HttpWebRequest` both build
  the chain with CryptoAPI. CryptoAPI can download missing intermediates from the AIA of the server certificate. These
  fetches are not bounded, cached or logged.
- **Fix:** list this as a known limit in the report, or build the TLS chain from discovered certificates, as the CA
  chain check already does.

### L3 Redirect targets are not scoped or recorded as leads
- `src/Probes/WebProbes.ps1:97-101` follows a Location header to any host, for up to 5 hops. REQUIREMENTS §4.3 allows
  following redirects, but each hop's host should at least show its scope. Consider not following redirects that lead
  to an `External` host.

### L4 Some network calls have no timeout and bypass the probe cache
- The forest, domain, trust and site calls (`src/Discovery/AdContext.ps1:41`, `:47`, `:56`, `:58` and `:83`).
- `DirectoryEntry` binds (`src/Discovery/Ldap.ps1:21`): `ClientTimeout` and `ServerTimeLimit` cover the search, not the bind.
- SID translation (`src/Model/SecurityDescriptor.ps1:99-100`).
- CLAUDE.md says that every network call takes a timeout.

### L5 Local policy errors are classified by localised message text (FIXED: exception type, tests added)
- `src/Discovery/LocalPolicy.ps1:96` and `:119-120` match `denied|unauthorized` in the exception message. The rest of the
  tool classifies by HRESULT and exception type (`src/Model/ErrorInfo.ps1:1-3`). On a Windows installed in another
  language, a permission error becomes `Error`/`RETRIEVAL_FAIL`.
- **Fix:** keep the exception and pass it to `Get-MspkiErrorInfo`.

### L6 `results.json` exports every template's parsed ACL
- `src/Discovery/Templates.ps1:67-70` keeps the `Acl` (SIDs, access masks, object GUIDs) and `OwnerSid`, and
  `src/Discovery/Invoke-MspkiDiscovery.ps1` puts the template objects into the inventory. REQUIREMENTS §6 says: "no raw
  security descriptors beyond the resolved names".
- **Fix:** export principal names and named rights only.

### L7 Smaller gaps against REQUIREMENTS §5.1 and §5.2
- There is no `Unknown` status when a CRL's issuer is not found. The freshness status is used with `Referenced`
  (`src/Analyzers/EndpointHealth.ps1:285-290`).
- `EXPECTED_OFFLINE` is never emitted.
- The Basic Constraints path length is shown but never validated against the chain (`CACertificateHealth.ps1:134-137`).
- A future-dated CRL is labelled `STALE_DATA` (`src/Model/Crl.ps1:270`).
- PEM CRLs are rejected (`src/Model/Crl.ps1:154-165`), although REF-INVENTORY says to keep tolerating PEM input.

### L8 Details of the template review
- **(a) Write rights:** the Write check counts `WriteProperty` limited to any single attribute
  (`src/Analyzers/TemplateSecurity.ps1:48-49`). An ACE for one harmless attribute becomes an ESC4 High.
- **(b) BUILTIN\Users:** the group (`S-1-5-32-545`, which includes Authenticated Users on domain controllers) does not count as
  a broad group (`src/Model/SecurityDescriptor.ps1:129-133`), which can cause false negatives.
- **(c) v4 templates:** these templates store crypto settings in `msPKI-RA-Application-Policies` as backtick-separated strings
  (v2.5.0 parsed them separately). `AcceptsAgentSig` compares raw values with the OID (`TemplateSecurity.ps1:97` and
  `:109`). It is not verified whether an agent-signature policy can sit inside that format, which would be an ESC3
  false negative.

### L9 The CES/CEP content check is weak
- At `src/Analyzers/EnrollmentServices.ps1:223`, any XML, HTML or text body that contains "service", "policy" and
  similar words passes, including an IIS default page.

### L10 Notes on AV/EDR (no forbidden pattern was found)
- `Invoke-MspkiTimeLimitedScript` turns a script block into text and runs it in a new runspace
  (`src/Probes/NetworkProbes.ps1:157-165`). The text is static and the use is legitimate, but AMSI and EDR tools inspect this
  pattern. Keep the text static and document why the pattern is there.
- The LDAP and RPC pattern matches what AD CS attack tools do for reconnaissance: every template with its security
  descriptor, OID group links, the CA database view and SCEP GETs. Directory monitoring may raise alerts. The README
  should tell operators to warn their security team before a run.

### L11 Blind spots in the hygiene test
- The forbidden-pattern list (`tests/Hygiene.Tests.ps1:25-38`) does not cover writes to the certificate store
  (`OpenFlags.ReadWrite`, `X509Store.Add` or `Remove`), ADSI `.Invoke(` and `.DeleteObject(`, or `OpenSubKey(..., $true)`. None of
  these exist in the code today, but nothing stops them from being added.

---

## Checked and found clean
- **Writes:** all file output goes through `Write-MspkiOutputFile` with the path guard
  (`src/Reporters/OutputFolder.ps1:62-95`). The registry (`LocalPolicy.ps1:79`, `IntuneConnector.ps1:100`) and the
  certificate stores (`Signature.ps1:136`, `IntuneConnector.ps1:134`) are opened read-only. COM use is limited to
  `GetCAProperty` and `CertificateAuthority.View`. There are no AD or CA write calls, and HTTP is GET only.
- **AV/EDR:** there is no `Invoke-Expression`, `Add-Type`, encoded command, download cmdlet, process start, `certutil`,
  private reflection or hidden window. `FromBase64String` appears only in `src/Model/BinaryData.ps1:33`, on data.
- **Windows PowerShell 5.1:** every file parses with the 5.1 parser, and there are no PS 7 operators. `::new()` is valid in 5.1. The
  manifest targets `Desktop` and 5.1. All code files are pure ASCII, so the ANSI reading of files without a BOM does no harm. The suite
  passes under 5.1.
- **Credentials over HTTP:** `HttpWebRequest` is anonymous (`WebProbes.ps1:69-71`). NDES requests are limited to three
  GETs with no redirects, which the loopback-server tests prove.
- **Names:** no real host, domain, IP address or e-mail address appears in any tracked file or in the history. Every
  commit is by `ED` with the GitHub noreply address, and `ref/` and `out/` were never committed.
- **Bounded discovery:** every probe target comes from AD, CA properties, certificates and CRLs, local policy or the CA
  database. Constructed CES and CEP paths are tried only on Enterprise CA hosts, after a DNS check.

---

## What v2.5.0 could do that this tool cannot yet
From `docs/REF-INVENTORY.md` and a function-name grep of `ref/`.

| v2.5.0 capability | State in this tool |
|---|---|
| CA registry configuration (`-getreg`): publication targets including file/UNC, CRL and delta periods and overlap | Not available (needs CA admin or remote registry; out of scope by design) |
| Checking the publication folder through UNC listings, with "file present but not served" hints (IIS MIME type, double escaping) | Only the `+` / double-escaping hint for HTTP 404 |
| Remote CA service state (`ServiceController`) and `certutil -ping` | Replaced: a successful `GetCAProperty` shows the CA answers; the service state is not reported |
| Chain validation with online revocation on a given certificate; `certutil -verify -urlfetch` | Not yet (`-CertificateFile` and `-IncludeCertUtilVerify` are Phase E) |
| CEP SOAP `GetPolicies` POST and parsing the policy response (templates offered) | Not available (GET reachability only; REF-INVENTORY suggests an opt-in) |
| Template details: key size below 2048, exportable key, crypto from v4 `msPKI-RA-Application-Policies`, property GUID to attribute name for write rights | Not reported; write rights are shown as raw GUIDs |
| Local issued-certificate view (CurrentUser and LocalMachine Personal, Remote Desktop stores, matched to the discovered CAs) | Only LocalMachine\My, and only for Intune patterns |
| CA-database query with filters the user chooses (requester, date, template) and a CSV export | Fixed to the two NDES templates; the rows appear only in Evidence |
| Endpoint inventory CSV | Partly: `findings.csv`, plus leads in `results.json` |
| A plan preview listing what will be probed before probing | Not available (closest: `-SkipNetwork`) |
| Every place that still points at a legacy host, with counts per host | Partly: per-URL classifications, no roll-up per host |
| GUI (tabs, grids, filters, cancel button, native certificate dialog, open in browser, save certificate) | Not available (WPF launcher optional, Phase E) |
| Excel export | Deferred (OpenXML, no COM) |
| PEM tolerance for downloaded CRLs and certificates | Rejected (L7) |
| Downloads from endpoints that require Windows authentication | Dropped on purpose (anonymous only); such endpoints show `HTTP_401_403` |

Dropped on purpose and not counted as gaps: the environment configuration file, configured or legacy host lists, ICMP ping,
and Excel COM.

## Items in REQUIREMENTS that are not implemented yet
- §2: `-CertificateFile` and `-IncludeCertUtilVerify`.
- §5.10: LDAPS bind and latency, time offset to the DC (only `DcTimeUtc` is recorded), and Configuration-partition
  replication health.
- §5.11: CES SPN and service-account encryption types; full OCSP validation.
- §5.1 and §5.2: `EXPECTED_OFFLINE`, the CRL `Unknown` state and path-length validation (L7).

## Suggested order
1. H1, M1 and M2: credentials and remote state.
2. H2, H3, M3, M4 and M7: false Pass, false Fail and false Confirmed results, each with a test that changes with it.
3. M5, M6, M8, M9 and M10.
4. M11 and the Low items. Then run the zero-configuration live test described in REQUIREMENTS §8.
