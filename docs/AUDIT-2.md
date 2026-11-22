# Audit 2: MSPKI Health Check after WP1-WP8

- **Date:** 2026-11-22
- **Commit audited:** `50a26a2` (WP8, "ready for audit")
- **Scope:** `src/`, both entry points, `demo/`, `tests/`, `docs/`, and the git history (39 commits). `ref/` was not opened.
  The first audit is `docs/AUDIT.md`. Its High and Medium items were fixed. Its Low items are re-checked at the end of this document.
- **Method:** I read the engine, the probes, the discovery files, the endpoint, NDES, CEP/CES, template, identity and hierarchy
  analysers, the reporters and `GuiApp.ps1` in full. For the other analysers, the GUI view models and the XAML I read the parts
  that set statuses, confidence, entities and controls. I also:
  - ran static greps for write, AV/EDR, credential and network patterns;
  - parsed all 99 script files with the Windows PowerShell 5.1 parser and checked their encoding;
  - checked two suspected defects at runtime (a loopback HTTP server answering 302, and the retrieval-order function);
  - timed the GUI view-model build on a lab-size results.json, printing counts only;
  - scanned the tree and the full history for e-mail addresses, IP addresses and domain names, and against the private lab
    facts kept outside the repo. Only counts were printed. No name from that file is written here.

  No code was changed.
- **Test run:** Pester 5.7.1 under Windows PowerShell 5.1: **886 tests, 886 passed, 0 failed** (2 min 26 s).

## Summary

| Rank | Count | Main themes |
|---|---|---|
| High | 2 | Links in unverified downloaded CRLs choose where an authenticated LDAP bind goes; ESC3 misses its standard (schema version 1) target |
| Medium | 14 | False Pass / false "not tested" in AIA, CES/CEP and the retrieval-order check; a valid large CRL graded Fail; a lost 3xx; GUI crash on any handler error; Inferred services shown as "found"; overloaded status codes; unscoped redirects; PFX import; template confidence; graph provenance; Constrained Language Mode; tests that hide bugs |
| Low | 19 | Missing timeouts, hidden chain-engine fetches, ACLs in the export, timing-based permission verdict, NDES candidate breadth, LDAPS read over LDAP, graph linker heuristics, GUI performance and accessibility, older Low items still open |

The hard rules mostly hold. No real name or personal detail is in the tree or the history. No PS 7 syntax and no forbidden
AV/EDR pattern were found. All writes go through the output-folder guard, and HTTP stays anonymous.

The two serious problems are these:

1. The work done after audit 1 protected *certificate* links (they are followed only when the certificate is proven), but
   *CRL* links are still followed straight from the download.
2. One review pattern (ESC3) cannot fire in a default forest.

The Medium items are mostly results that are more confident than the evidence. Several of them survive because the unit tests
pass the same value on both sides of a comparison.

### Hard rules at a glance

| Rule (CLAUDE.md) | Result |
|---|---|
| 1 Read-only | Holds in the tool's own code: stores opened read-only, registry opened without write access, COM limited to `GetCAProperty` and the CA database view, HTTP GET only. One remote-triggered exception: M10 (a PFX at an AIA URL writes a key container). |
| 2 No environment data | Holds. Tree and history are clean; see "Names and personal details" below. |
| 3 No configuration | Holds. |
| 4 Bounded discovery | Gaps: H1 (CRL links followed before verification), M9 (redirect hops to any host, plus a TLS handshake there), L5 (NDES candidates from group members). |
| 5 PS 5.1 / .NET 4.x | Holds: 0 parse errors, no PS 7 tokens, no non-ASCII script without a BOM, the XAML is read explicitly as UTF-8, and results.json has no `{ value, Count }` wrappers. M13: Constrained Language Mode is not detected. |
| 6 AV/EDR-safe | Holds. `FromBase64String` appears only in `src/Model/BinaryData.ps1:33`. `Add-Type -AssemblyName` is used only for the allowed assemblies. Notes in L16. |
| 7 No secrets | Holds for reading, logging and export. H1 is a credential exposure *during authentication* (an LDAP bind), not a secret that is read. |
| 8 Honest results | Gaps: M1, M2, M4, M5, M7, M11. |

---

## High

### H1 Links in a downloaded CRL are followed before the CRL is verified, and can steer an authenticated LDAP bind
- `src/Analyzers/EndpointHealth.ps1:516-521`: every Freshest CRL URL inside a downloaded CRL becomes a new lead (depth + 1) at once.
  The signature and issuer of that CRL are checked only after all rounds of link following (`:535`, `Test-MspkiCrlHealth`).
  Certificates are treated differently, as REQUIREMENTS 4.2 asks: their links are followed only when the certificate is proven
  (`:502-515`, `$r.Validated`).
- LDAP leads go to any host whose DNS name ends in one of the forest's domains (`src/Model/HostScope.ps1:102-103`). The check is a
  test of the name only. The bind uses the running user's Windows credentials: `src/Discovery/Ldap.ps1:20-21` uses the
  `DirectoryEntry` default, Negotiate, which falls back to NTLM when the host has no SPN.
- HTTP leads from the same CRL can name any host (anonymous GET, but outside rule 4).
- **Scenario:** an `http://` CDP location (cleartext, so it can be changed on the network) returns a CRL whose Freshest CRL
  extension names `ldap://anyname.corp.example.test/CN=x?deltaRevocationList`. In a default AD-integrated DNS zone any
  authenticated user can create a new record, so that name can point at a host the attacker controls. On the next round the tool
  binds there with the operator's credentials, and the operator is often a PKI administrator. With no SPN this is NTLM, which can be
  relayed (for example to a Web Enrollment page, ESC8).
- **No test** covers a Freshest CRL link from a CRL that does not verify.
- **Fix:** follow Freshest CRL links only from CRLs whose signature verified with a known CA certificate, or that were read through
  the selected domain controller. Consider allowing LDAP hosts only when they are the selected DC or a domain controller of the
  forest (from the DC locator), not any name in the zone. The rule 4 clarification in CLAUDE.md would then be updated to match.

### H2 ESC3 never matches the standard target: schema version 1 templates
- `src/Analyzers/TemplateSecurity.ps1:114`: `AcceptsAgentSig` needs `msPKI-RA-Signature >= 1` and the Certificate Request Agent EKU in
  the RA application policies. `:173` uses only that fact to find the second template of the pattern.
- A schema version 1 template accepts enroll-on-behalf-of requests from any enrollment agent. The default **User** template is
  schema version 1, allows client authentication, lets Domain Users enroll and is published by default. It is the usual second
  half of ESC3.
- **Effect:** a template that gives a broad group the Certificate Request Agent EKU without approval is the real misconfiguration.
  In a forest that has only the default templates besides it, that template produces no ESC3 finding, and the summary line says
  "no review pattern matched". This is a silent false negative of a High-severity pattern.
- Smaller point (possible false positive): the second template's Enroll permission for the agent's principals is shown in the
  evidence but not required.
- **Fix:** count published schema version 1 templates that allow client authentication as ESC3 targets. Add a test with a
  schema version 1 fixture.

---

## Medium

### M1 An AIA location that serves the wrong key generation is graded Pass, Confirmed
- `src/Analyzers/EndpointHealth.ps1:64-67`: the result is `Verified` as soon as the downloaded thumbprint is *any* known CA
  certificate. That happens before the check that a referencing certificate verifies with it (`:68-83`).
- `KnownCertificate` holds every CA certificate that was discovered, every generation included (`:476`, `:493`).
- **Scenario:** a root was renewed with a new key, but the AIA URL in the subordinate certificate still serves the old root
  certificate, and the old generation is in AD (AIA or Certification Authorities). The result is Pass, "returns the CA
  certificate", Confirmed, although clients cannot build the chain for the new key. The `KeyMismatch` result was written for
  exactly this case, but it cannot happen in a real run.
- The test hides it: `tests/Audit.Grading.Tests.ps1:282-286` passes a `KnownCertificates` map that does not contain the downloaded
  certificate.
- **Fix:** when referencing certificates are known, require the key proof (AKI = SKI, or the signature). Use identity with a known
  certificate only when there is no referencing certificate.

### M2 CES/CEP is "ConfirmedResponding" (Pass, Confirmed) on 401, 403, 405 or a 3xx
- `src/Analyzers/EnrollmentServices.ps1:10` (responding = 200, 400, 401, 403, 405), `:219` (3xx also counts), `:246` (Confidence
  Confirmed).
- A 403 from a WAF, an IP restriction or "SSL required", or a site-wide 401, comes back for every path, including a CES application
  that was removed. REQUIREMENTS 5.7 uses this very argument to refuse 401/403 as proof for NDES. The content check runs only on a
  200 and is weak (`:237-243`, L17).
- **Fix:** treat 401/403/3xx as "reachable, not confirmed" (Referenced). Confirmed only for a service-shaped answer, such as a WSDL,
  policy XML, or a 400/405 from the WCF endpoint itself. Update REQUIREMENTS 5.6 to match.

### M3 A valid CRL larger than 10 MB is graded Fail / CONTENT_WRONG_TYPE
- `src/Probes/WebProbes.ps1:123` sets a 10 MB default cap. `:198` turns "too large" into `CONTENT_WRONG_TYPE`, and
  `src/Analyzers/EndpointHealth.ps1:235-241` reports it as `Fail`, "could not be downloaded".
- Large PKIs publish base CRLs of 10-50 MB. Such a CRL gets a false Fail and exit code 4, under a code that means something else.
  Its freshness is never checked.
- Also, `src/Model/Crl.ps1:49` turns every revoked entry into a PowerShell object just to count them, which is slow on big CRLs.
- **Fix:** use a larger, separate cap for CDP downloads. Report "larger than the cap" with its own status (Skipped, plus a size
  code or `UNSUPPORTED`). Count revoked entries without building objects.

### M4 The retrieval-order check misses failing URLs and counts Warnings as working
- `src/Analyzers/HierarchyHealth.ps1:398-401` keys the per-URL status by the finding's Endpoint, which is the normalised probe URL
  (`src/Model/LeadRegistry.ps1:56-62`, `AbsoluteUri`). `:408` takes the raw URLs from the certificate, and `:80` looks them up
  exactly.
- **Verified:** a failing CDP URL that contains a space (`.../Example Issuing CA.crl`) gives `Skipped`, "None of the 1 CDP URLs ...
  was tested from here", instead of Fail. An explicit default port (`:80`) has the same effect.
- `:82` counts `Warning` as "this URL works". Warnings include an AIA URL with the wrong subject or the wrong key
  (`EndpointHealth.ps1:275-287`), a CRL from another issuer, and any scope-capped failure (`HostScope.ps1:65-68` turns Fail into
  Warning). The result can be a false Pass, "clients get it from the first URL".
- `:81` and `:103-104`: a URL that was not contacted (Skipped) is not counted as tested, but the Fail message says "None of the N
  URLs returned ...", and N includes it. The finding is Confirmed.
- The tests pass the same string on both sides (`tests/HierarchyHealth.Tests.ps1:29-39`), so they cannot catch the mismatch.
- **Fix:** normalise both sides with `ConvertTo-MspkiNormalizedUrl`. Record per URL whether a usable object came back, instead of
  the worst status. Say how many URLs were really tested.

### M5 A redirect is recorded as "no answer" when redirects are not followed
- `src/Probes/WebProbes.ps1:185-192`: with `-MaxRedirects 0` a 3xx sets `Code = HTTP_REDIRECT`, but `HttpStatus` stays 0, because it
  is set only at `:192` for the final answer.
- `src/Analyzers/EndpointIdentity.ps1:49` treats status 0 as "nothing there". The redirect branch at `:56` can never run. The report
  then says "no web server answered (HTTP_REDIRECT)" (`:319`) and "No web server answered at all on ..." (`:337`), which is false.
- **Verified** with a loopback server: a 302 gave `HttpStatus 0`, hop status 302, and Web Enrollment state `$null`.
- Web Enrollment is missed when http redirects (for example to https) and 443 is filtered from here. The NDES GETs also use
  `-MaxRedirects 0`, so a redirected GetCACaps looks like no answer as well.
- **Fix:** when a redirect is not followed, take `HttpStatus` from the last hop. Add a 301/302 test through `Invoke-MspkiHttpGet`.

### M6 GUI: any exception in an event handler closes the window and ends the process, also during a run
- **Verified** in Windows PowerShell 5.1: a .NET exception inside a scriptblock used as a delegate escapes the delegate
  (`MethodInvocationException`).
- The handlers wired in `src/Gui/GuiApp.ps1:1132-1298` call helpers without try/catch, and there is no
  `Dispatcher.UnhandledException` handler. The exception therefore leaves `ShowDialog()` (`Start-MspkiHealthCheckGui.ps1:108`), the
  launcher prints one line and exits with code 5. A running engine runspace is abandoned, so results.json may never be written. A
  window started from Explorer just disappears.
- The riskiest paths are the 200 ms timer tick (`:1132`, `Receive-MspkiGuiProgress`) and `Complete-MspkiGuiRun` ->
  `Show-MspkiGuiResult` (`:917`), which builds every view model from the run's data. PROGRESS already records one 5.1-only
  exception there ("Argument types do not match").
- **Fix:** wrap every handler in one helper (try/catch -> error row in the log and a message box), and add a dispatcher handler that
  sets `Handled`. Add a test that makes a helper throw inside a handler.

### M7 The PKI services page shows Inferred services as "found" (green)
- `src/Gui/GuiEntity.ps1:435`: any `Seen` observation gives the instance the green "Answers" pill, whatever its confidence. `:453`
  then gives the whole kind a green "N found" heading.
- Web Enrollment is `Seen` / Inferred for any answer other than 404, including 403 and 5xx
  (`src/Analyzers/EndpointIdentity.ps1:39-60`, `:327`). An IP restriction on a CA host therefore shows "Web Enrollment: 1 found".
- The confidence pill sits next to it, but the heading claims more than the evidence shows (rule 8).
- **Fix:** show "Answers" and "found" only for Confirmed instances. For Inferred ones, say "something answers at the standard path
  (not confirmed)".

### M8 Different failures are reported under the same status code
REQUIREMENTS §3 says to keep status codes separate.
- **RETRIEVAL_FAIL** is used for all of these:
  - a CA host that answers but has no CA by that name (`src/Discovery/CAProperty.ps1:437-441`);
  - a slow RPC failure, usually a firewall (`:322`);
  - "service not running", "server down" and "bad network path" (`src/Model/ErrorInfo.ps1:13-17` via
    `New-MspkiFinding.ps1:138`);
  - any unclassified LDAP error (`src/Probes/WebProbes.ps1:431`);
  - a failing retrieval order (`HierarchyHealth.ps1:98`, `:103`);
  - RootDSE built from the name (`AdContext.ps1:312-316`);
  - autoenrollment errors in the Application log (`src/Analyzers/LocalEvidence.ps1:205`).
- **CONTENT_WRONG_TYPE** is used for:
  - not a certificate or CRL (`EndpointHealth.ps1:267`, `:307`);
  - the wrong subject (`:277`) and the wrong key (`:283`);
  - a response over the size cap (`WebProbes.ps1:198`);
  - a Freshest CRL URL that returns a base CRL, and a CRL from another issuer (`EndpointHealth.ps1:390-398`);
  - unexpected CES content (`EnrollmentServices.ps1:251`).
- **TLS_HANDSHAKE_FAIL** covers real handshake failures, and also completed handshakes whose chain has an error other than the three
  named ones (`WebProbes.ps1:308`), for example `NotSignatureValid` or `NotValidForUsage`.
- **One cause, two codes:** "COM class not registered" is Skipped / `UNSUPPORTED` for `CertificateAuthority.Request`
  (`CAProperty.ps1:443-447`) but Skipped / `NOT_APPLICABLE` for `CertificateAuthority.View` (`src/Discovery/NdesEvidence.ps1:250`).
- **UNSUPPORTED** also comes from any `E_INVALIDARG` (`ErrorInfo.ps1:21`). A bad argument, possibly a fault in the tool, then reads
  "Not supported" and gives exit code 5. "Not domain-joined" shares the code as well.
- **OK** is given to a host identity summary whose DNS lookup timed out or failed (`EndpointIdentity.ps1:231`; the confidence is
  Unknown, but the code says OK).
- **Fix:** use `CONFIG_MISMATCH` or `NOT_DISCOVERED` for "no CA of that name", give the size limit its own code, use
  `CHAIN_INVALID` for chain errors after a completed handshake, and use one code for a missing COM class.

### M9 Redirects lead to hosts no authoritative source named (audit 1 L3, still open, now with a TLS handshake too)
- `src/Probes/WebProbes.ps1:185-189` follows any `Location` for up to 5 hops for AIA, CDP, CES and CEP URLs. On a TLS trust failure,
  `:169` and `:217-231` also make a separate TLS handshake to the redirect hop's host.
- These hosts get no scope, are not leads and do not appear in the graph. The requests are anonymous, but they are outside rule 4.
- **Fix:** follow a redirect only to a host that is in scope Local or is already a lead. Register each hop host with its scope.
  Never make a handshake with an unscoped host.

### M10 Bytes from the network can still import a private key into the user profile (audit 1 L1, rule 1)
- These calls get bytes that came from HTTP:
  - `src/Model/Certificate.ps1:25`: `X509Certificate2(byte[])`;
  - `src/Analyzers/EndpointHealth.ps1:256-260` and `src/Analyzers/Ndes.ps1:32-36`: `X509Certificate2Collection.Import(byte[])`.
- Both accept a PFX with an empty password. .NET Framework then writes its key to a key container under the user profile, removed
  only when the object is finalised. Remote content causes a write outside `out\`.
- The hygiene test does not look for this.
- **Fix:** accept only `[X509Certificate2]::GetCertContentType($bytes)` = `Cert` or `Pkcs7` before loading. Add a test with a
  passwordless PFX (ephemeral key).

### M11 Template review: likely false positives graded Confirmed
- `src/Analyzers/TemplateSecurity.ps1:293` marks a published match Confirmed, but the conclusion "a broad group can enroll / can
  write" is not computed:
  - Deny ACEs are checked only for the same SID (`:71`). A `Deny Everyone` does not cancel an `Allow Authenticated Users` in this
    check.
  - Group nesting is not computed.
  - The CA's own "Request Certificates" permission and its enrollment agent restrictions are not read.
- The ESC4 write check counts `WriteProperty` limited to any single attribute (`:48-54`, audit 1 L8a). One harmless attribute then
  becomes a High / Fail, Confirmed.
- **Fix:** Referenced (conditions read from AD, effect not computed) unless effective access is computed. Count only property
  writes that change enrollment or EKU settings, or ACEs with no property set.

### M12 Entity graph: hosts found through a group or gMSA are attached to the group, and the member accounts are missing
- `src/Discovery/NdesTemplateAccess.ps1:193-212` collects the hosts of a group's members (one level) and of a gMSA's allowed
  computers into the principal's own `Hosts`.
- `src/Analyzers/Ndes.ps1:266` then writes `identifies` from the group or gMSA Account to each host. Members are not entities, and
  `memberOf` (reserved in DATA-MODEL.md) is never written.
- The drill-down therefore says "group X identifies host Y", and does not show which member account or which SPN named the host.
- **Fix:** add Account entities for the members, `memberOf` relations, and `identifies` from the member that names the host.

### M13 The tool needs Full Language mode, and does not detect when it lacks it
- Nothing checks `$ExecutionContext.SessionState.LanguageMode`, and the scripts are not signed.
- On a client with AppLocker or WDAC script enforcement, unsigned scripts run in Constrained Language Mode. There `New-Object
  -ComObject`, `System.DirectoryServices`, sockets, runspaces and WPF are blocked, so the run fails part-way with generic errors.
  Under an `AllSigned` policy it does not start at all.
- README and TESTING do not mention this, although the tool promises to run on any domain-joined computer.
- **Fix:** check the language mode in both entry points and exit with code 5 and a plain message. Document that the operator's
  organisation may need to sign or allow the scripts.

### M14 Weak or missing tests (several of them hide the defects above)
- **Tests that cannot fail on the real defect:**
  - `tests/HierarchyHealth.Tests.ps1:29-39` uses the same URL string on both sides (M4);
  - `tests/Audit.Grading.Tests.ps1:282-286` passes a known-certificate map without the downloaded certificate (M1);
  - `tests/EndpointIdentity.Tests.ps1:152-156` builds the HTTP results by hand, so it has no 3xx through `Invoke-MspkiHttpGet` (M5).
- **Missing tests:**
  - a Freshest CRL link in a CRL that does not verify (H1);
  - an ESC3 match through a schema version 1 target (H2);
  - a CRL above the size cap (M3);
  - CES/CEP grading of 401, 403 and 3xx (M2);
  - an exception in a GUI handler or in the timer tick (M6);
  - an Inferred-only service on the PKI services page (M7);
  - PFX bytes at an AIA URL (M10);
  - Constrained Language Mode (M13).
- **Hygiene test** (`tests/Hygiene.Tests.ps1`):
  - The name scan checks only the working tree, and only dotted names with listed suffixes (`:125-131`). It does not look at
    history or commit messages, single-label host names or organisation names.
  - There is no local-only check against the private lab facts (for example as a pre-commit hook outside the repo).
  - The forbidden list (`:26-47`) still lacks writes to a certificate store (`OpenFlags.ReadWrite`, `.Add(` / `.Remove(` on a
    store), ADSI `.Invoke(` / `.DeleteObject(`, `X509KeyStorageFlags.PersistKeySet`, and `Invoke-Item` (audit 1 L11).

---

## Low

### L1 Hidden network fetches by the Windows chain engine (audit 1 L2, open)
- The TLS validation callback (`src/Probes/WebProbes.ps1:286-295`) and HTTPS through `HttpWebRequest` let CryptoAPI build the chain.
  CryptoAPI may fetch missing intermediates from the AIA of the server certificate (LDAP URLs included). These fetches are not
  bounded, cached or logged.
- **Fix:** record this as a run limit, or validate TLS chains only against discovered certificates.

### L2 Calls without a timeout (audit 1 L4, open)
- Forest, DC locator, trust and site calls: `src/Discovery/AdContext.ps1:51`, `:62`, `:77`, `:177`, `:183`, `:194`, `:219`.
- The `DirectoryEntry` bind: `src/Discovery/Ldap.ps1:21`. `ClientTimeout` covers the search, not the bind.
- SID translation: `src/Model/SecurityDescriptor.ps1:99-100`.
- Cancel is only checked between probes, so a hung DC call cannot be cancelled.

### L3 results.json exports every template's parsed ACL and owner SID (audit 1 L6, open)
- `src/Discovery/Templates.ps1:68-70`.

### L4 A timing heuristic decides PERMISSION_DENIED and exit code 6
- `src/Discovery/CAProperty.ps1:312-321`: an `0x800706BA` within 5 s becomes `PERMISSION_DENIED`.
- The finding is honestly marked Inferred and carries the timing evidence. But a network device that rejects the dynamic RPC port
  (a fast reset) gives the same timing, and the exit code and the "permission" wording then rest on timing alone.
- **Fix:** consider a separate code, or `RETRIEVAL_FAIL` with permission named as the most likely cause.

### L5 NDES candidates from group members and gMSA computers get SCEP requests
- `src/Discovery/NdesTemplateAccess.ps1:193-211`: up to 25 members per group, and the computers allowed to use a gMSA, become NDES
  candidates. Each gets a TCP connect, a TLS handshake and GetCACaps / GetCACert.
- A human account with `HTTP/` SPNs, or a custom group with many computers, then yields hosts that are not proven to be PKI
  (CLAUDE.md rule 4).
- BUILTIN\Users and Anonymous do not count as broad groups (`src/Model/SecurityDescriptor.ps1:129-133`, audit 1 L8b). They are read
  as candidates, and missed as broad enrollers.
- **Decide** whether hosts derived from members count as "candidates" under REQUIREMENTS 5.7.

### L6 Localised message text is still matched in one place
- `src/Discovery/NdesTemplateAccess.ps1:150` (`'no such object'`). The HRESULT is checked first, so the effect is small.

### L7 `ldaps://` locations are read over plain LDAP
- `src/Discovery/Ldap.ps1:20` always builds `LDAP://`, and `src/Probes/WebProbes.ps1:349` accepts both schemes. An LDAPS location
  that is broken on port 636 is graded Pass (false negative).

### L8 Cross-location CRL comparison trusts CRLs that may not have verified
- `src/Analyzers/EndpointHealth.ps1:426-458` (`STALE_DATA`, Confirmed at `:447`) compares CRL numbers without regard to signature
  status. A CRL with an unverified signature and a higher number marks the good locations as stale.

### L9 Graph linker heuristics and smaller graph gaps
- `src/Model/EntityGraphBuilder.ps1:496` matches hosts by their first label. A Target of `pki` links to the first host called
  `pki.<anything>`.
- The thumbprint scan links only CA certificates.
- Findings that link to nothing fall back to the forest (`:508`), so the forest's worst status mixes unrelated findings.
- Not modelled: delta CRL <-> base CRL, template -> issuance policy / OID group link (ESC13 evidence is text only), KRA and
  cross-certificates.

### L10 GUI performance
- On every timer tick with new log lines, `Update-MspkiGuiLogView` refreshes the whole view (`src/Gui/GuiApp.ps1:210`, `:860`)
  through a PowerShell predicate (`:1110`), up to 40,000 rows.
- Loading results.json and building the view models run on the UI thread (`:700-724`, `:917`). This measured about 1 s for a
  lab-size 1.7 MB file, which is fine today but grows with the PKI.
- `run.log` is added line by line on the UI thread (`:695`).

### L11 GUI accessibility
- About 20 of the 32 buttons in `src/Gui/MainWindow.xaml` have no `AutomationProperties.Name`. Examples:
  - the toolbar (`:680-693`);
  - row and link templates (`:70`, `:147`, `:155`, `:253`, `:467`);
  - the welcome and running panels (`:796-837`);
  - filter and log buttons (`:964`, `:985`, `:1086-1089`, `:1131`, `:1179`).
- Their content is a Segoe MDL2 private-use glyph plus a text block, so a screen reader may announce an unnamed button or the glyph.
- Count tiles name only the label, not the count (`:425-426`).
- Status is never shown by colour alone (pills carry text and a glyph), which is good.

### L12 Probe runspaces that time out are never disposed
- `src/Probes/NetworkProbes.ps1:218-223` leaves timed-out probe runspaces behind. With many unreachable CAs, blocked threads add up.
- On close during a run, the GUI waits 45 s and then calls `BeginStop` (`src/Gui/GuiApp.ps1:865-866`), which cannot stop a call
  blocked in DCOM.

### L13 A cancel during discovery discards what discovery found
- `src/Discovery/Invoke-MspkiDiscovery.ps1:163` breaks the loop, the next stage timer throws, and the catch at
  `src/Start-MspkiHealthCheck.ps1:107-111` leaves `$d` null. results.json then has no inventory, although the AD context was read.

### L14 Logging stops silently when run.log cannot be written
- `src/Model/Logging.ps1:30` raises no finding.

### L15 The report opens in the browser by default
- `Invoke-MspkiHealthCheck.ps1:107-110`. A PowerShell process that starts the default browser is something EDR tools score, and it
  makes no sense in a scheduled task. Consider opening the report only when `[Environment]::UserInteractive` is true.

### L16 AV/EDR notes (no forbidden pattern found)
- Runspaces run static script text (`NetworkProbes.ps1:193`, `GuiApp.ps1:748`).
- Reading every template's security descriptor, the CA database view and the SCEP GETs together looks like AD CS reconnaissance.
  README already tells operators to warn their security team.

### L17 Low items from audit 1 that are still open
- **L7:** `EXPECTED_OFFLINE` is never emitted. The path length is read (`src/Model/Certificate.ps1:165-169`) but never checked
  against the chain. PEM CRLs are rejected (`src/Model/Crl.ps1:13-24`). There is no CRL `Unknown` state. (A future-dated CRL is now
  `CLOCK_SKEW`, which is better.)
- **L8c:** the v4 format of `msPKI-RA-Application-Policies` is still not parsed separately.
- **L9:** the CES/CEP content check is still a word match (`src/Analyzers/EnrollmentServices.ps1:237-243`).

### L18 Reading the Lifecycle logs may need an interactive logon
- They were readable for a normal interactive user in the lab. Under a scheduled task or a remote session the channel access may
  deny the read, and the result is `PERMISSION_DENIED` and exit code 6. This was not tested.

### L19 Repository and documentation details
- `docs/PROGRESS.md:13` has a broken dash ("â€”"): UTF-8 text was once read as ANSI.
- CLAUDE.md and PROGRESS.md name the local folder layout of the dev machine (tool and private paths). This is harmless, but not
  needed in a public repo.

---

## Names and personal details
- **Tree:** no e-mail address, no IP outside the documentation ranges (the `*.2.0.192.in-addr.arpa` names are 192.0.2.x), no
  domain other than `example.test` and Microsoft documentation and schema hosts. `ref/` and `out/` were never committed. No
  binary files are tracked.
- **History:** all 39 commits are by `ED` with the GitHub noreply address. No personal name or e-mail address is in any commit
  message or diff.
- **Against the private lab facts:** counts only. No lab-specific host prefix, domain, IP or account name is in the tree or the
  history. One generic short name used in NDES test fixtures also appears inside a lab host name; the lab-specific part of that
  name appears nowhere. Renaming the fixture host to a neutral name removes even that overlap. The details were given to the
  owner outside the repo.

## Checked and found clean
- **Writes:**
  - Every file write goes through `Write-MspkiOutputFile` (`src/Reporters/OutputFolder.ps1:62-95`).
  - The GUI export stays inside the output root (`GuiApp.ps1:1009-1038`), and snapshots are written only under `out\`.
  - Stores are opened `ReadOnly` / `OpenExistingOnly`, and the registry is opened without write access.
  - COM use is limited to `GetCAProperty` and the read-only CA database view. There is no AD write and no HTTP verb other than GET.
  - The NDES admin request is opt-in, never reads the body and never follows redirects.
- **Credentials:** `HttpWebRequest` is anonymous (`UseDefaultCredentials = $false`, `Credentials = $null`, no `PreAuthenticate`) and
  uses no proxy unless `-UseSystemProxy`. LDAP binds go only to the DC or to forest-domain names (see H1 for the gap). File/UNC
  locations are never touched. DNS identity uses `Resolve-DnsName -DnsOnly` (no LLMNR or NetBIOS) where it exists.
- **Reports:** every value in the HTML is encoded (`WebUtility.HtmlEncode`) under a strict CSP. CSV fields that start with
  `= + - @` or a tab are neutralised. The JSON has no certificate bytes or keys.
- **PS 5.1:** 0 parse errors in 99 files and no PS 7 tokens. The deepest results.json object nests about 8 levels, under
  `-Depth 12`. The 5.1 `@($genericList)` trap is handled in the GUI.
- **Admin / installed software:** nothing needs admin. `CertificateAuthority.View` (RSAT) is optional, and its absence is
  explained. WPF and `System.Web.Extensions` are in-box. `Resolve-DnsName` has a fallback.
- **Cancellation:** a cancel inside a stage becomes a Skipped "cancelled" finding, not an error, and a partial results.json is
  always written.

## Suggested order
1. H1 and M10 (credentials and remote-triggered writes), then M9.
2. H2, M1, M2, M3, M4 and M5, each with a test that fails on today's code. Fix the masking tests in M14 first.
3. M6 and M7 (GUI), M8 (status codes), M11 and M12.
4. M13, then the Low items. Run the hygiene name scan over history as well.

## Fix log

Batch A (security-critical items). Each fix started with a test that failed on the code before it, then the fix, then the
test passing. Commits are listed under the fix; the commit of a fix is the one that carries its tests.

| ID | Status | Commit | Tests |
|---|---|---|---|
| H1 | Fixed | `3b4c3af` | `tests/Audit2.Security.Tests.ps1`: "Audit 2 H1: links in a downloaded CRL are followed only when its signature verified" (3 tests) and "Audit 2 H1: an LDAP bind goes only to hosts proven by authoritative discovery" (12 tests); updated audit 1 cases in `tests/Audit.Probes.Tests.ps1` |
| M10 | Fixed | `a95e566` | `tests/Audit2.Security.Tests.ps1`: "Audit 2 M10: downloaded bytes never create a private key on disk" (5 tests: content type, New-MspkiCertificate, AIA endpoint, NDES reader, PKCS #7 still read); new Hygiene patterns "key persistence" and "certificate loading" |
| M9 | Fixed | `4aa6a91` | `tests/Audit2.Security.Tests.ps1`: "Audit 2 M9: a redirect or a TLS handshake never goes to a host that no trusted evidence named" (5 tests); audit 1 test "looks at the host of the failing hop ..." now registers the HTTPS host as a lead first |
| H2 | Fixed | `59a2f72` | `tests/TemplateSecurity.Tests.ps1`: "Audit 2 H2: ESC3 in a forest modelled on the default templates" (10 tests: default forest does not fire; broad agent template + default User fires; two targets counted; 7 negative cases, one condition each) |
| M11 | Partially fixed: confidence and Deny ACEs done; the ESC4 rule that counts a WriteProperty on any single attribute is not changed (Batch B) | `3aad084` | `tests/TemplateSecurity.Tests.ps1`: "Audit 2 M11: a permission-based template finding is never Confirmed while effective permissions are not computed" (6 tests); two older assertions updated to the new rule and wording |
| M1 | Fixed | `7842317` | `tests/Audit2.Results.Tests.ps1`: "Audit 2 M1" (2 tests: the old root is known too and the subordinate needs the new key gives KeyMismatch; the new root is still Verified) |
| M2 | Fixed | `d1f7f55` | `tests/EnrollmentServices.Tests.ps1`: 401 and 403 are AuthRequired (Information, Referenced, `HTTP_401_403`), never Pass or Confirmed; a 3xx is not a responding service; 400/405/200-with-service-page stay Confirmed; a 200 with other content is Referenced; the plain-HTTP risk is kept for AuthRequired. 5 tests were red on the old code |
| M7 | Fixed | `2a2bf0c` | `tests/GuiEntity.Tests.ps1`: "Audit 2 M7" (2 tests): an Inferred-only kind shows "Something answers (not confirmed)" in a Warn tone and the list is titled "Answers at the standard path (not confirmed)"; with one Confirmed and one Inferred instance the heading counts 1 found and says "1 more ... not confirmed". The summary line counts confirmed kinds |
| M4 | Fixed | `dce392b` | `tests/Audit2.Results.Tests.ps1`: "Audit 2 M4" (9 tests, red on the old code): a URL with a space (%20 in the probe), an explicit :80 and a different host case are found; http and https stay apart; a Warning for a wrong issuer, a wrong key, a scope-capped failure or an unfollowed redirect is not a working URL; an age Warning still is; an expired CRL is not; the message says how many URLs were tested and is not Confirmed when some were not. `tests/HierarchyHealth.Tests.ps1` updated to the new parameter |
| M5 | Fixed | `d52359b` | `tests/Audit2.Results.Tests.ps1`: "Audit 2 M5" (5 tests, 3 red on the old code): a 302 through `Invoke-MspkiHttpGet -MaxRedirects 0` has HttpStatus 302, the Location and an explanatory Error; the hop limit takes the last hop's status; redirects within the limit are still followed; Web Enrollment state and finding exist for a redirecting host |
| M3 | Fixed | `9715e0b` | `tests/Audit2.Results.Tests.ps1`: "Audit 2 M3" (4 tests, all red on the old code): the CRL cap is at least 32 MB; a CRL above the cap is Information / `SIZE_LIMIT` (not Fail, not CONTENT_WRONG_TYPE) and does not give exit code 4; `Measure-MspkiDerChild` counts 3000 entries without objects and throws on truncated data. `tests/Endpoint.Tests.ps1` and `tests/Model.Tests.ps1` updated for the new code |
| M6 | Fixed | `PENDING` | `tests/Gui.Tests.ps1`: "Audit 2 M6" (3 tests, red on the old code): error text without stack trace; `Invoke-MspkiGuiUnhandledError` logs a Run log row and gui-error.log, shows the same error once, cancels a run in progress through the Cancel flag and returns Handled; in a real dispatcher loop a throwing event delegate reaches the hook and a throwing timer tick does not stop the timer |

### H1 notes
- Freshest CRL links are queued and followed only after the CRL's signature verified with a discovered CA certificate (or one
  proven by key after download). The check runs after each round, so a CA certificate proven in the same round counts. A CRL that
  does not verify, or whose issuer was not discovered, keeps its links unfollowed; the CRL finding and run.log say so. The
  Issuing Distribution Point is read as a fact only and was never followed.
- Every lead now carries a trust level (Authoritative, Verified, Unverified; the strongest wins on merge). Links from downloaded
  certificates and CRLs are Verified, because they are followed only after proof.
- LDAP binds: the forest's domain controllers are read from the server objects under CN=Sites of the Configuration partition
  (one subtree search on the selected DC). An LDAP URL that names a host is contacted only for the selected DC, a forest DC, or a
  host in the forest's own DNS domains named by an Authoritative or Verified lead. A name in the forest zone alone is no longer
  enough. The rule 4 clarification in CLAUDE.md, REQUIREMENTS 4.2 and the README now say so.
- Review of every place where credentials or a handshake can go out: LDAP binds (the selected DC for all discovery reads,
  serverless for a group in another domain, URL hosts as above); DCOM to CAs (hosts from Enrollment Services in AD); HTTP is
  anonymous (`UseDefaultCredentials = $false`, `Credentials = $null`, no pre-authentication); TLS handshakes send no client
  certificate. Redirect and TLS targets are covered by M9 below. Still open: the Windows chain engine's own fetches during TLS
  validation (L1).

### M10 notes
- All certificate bytes are loaded in one file, `src/Model/Certificate.ps1`. `Get-MspkiCertificateContentType` asks
  `X509Certificate2::GetCertContentType` first (it only identifies the data). Only `Cert` (one certificate) and `Pkcs7` are
  loaded; PKCS #12 / PFX and every other type is refused before any certificate object is built, and the finding says why.
- Loading uses `EphemeralKeySet` where the .NET Framework has it (4.7.2 and later), otherwise `DefaultKeySet`; no persisting flag
  is used anywhere (Hygiene test). Certificates copied from local stores and from discovered CA certificates also go through
  `New-MspkiCertificate`.
- The tests snapshot the user and machine key folders under `%APPDATA%\Microsoft\Crypto` and `%ProgramData%\Microsoft\Crypto`
  before and after each call. On the old code one key file appeared per PFX load.

### M9 notes
- `Invoke-MspkiHttpGet` follows a redirect only to the host the request named or to a host for which `Test-MspkiTrustedLeadHost`
  is true (an Authoritative or Verified lead names it, or it is a forest domain controller). Any other target is recorded
  (`RedirectNotFollowed`, the hop list, the evidence) and never contacted: no DNS lookup, no connection, no TLS handshake.
  The result then carries the 3xx status, not 0.
- `Get-MspkiTrustFailureCode` makes its separate handshake only with the request's own host or a trusted host.
- An AIA / CDP / Freshest CRL location that redirects to such a host is a Warning (`HTTP_REDIRECT`) that names the target and says
  the object there was not checked; it is no longer a download failure.
- Not changed here: with `-MaxRedirects 0` (NDES) or after the hop limit, `HttpStatus` is still 0 (audit 2 M5, Batch B).
- Test helper: `New-TestCertificate` now clamps an issued certificate to its issuer's validity. The old race (child created a
  second after the issuer with the same lifetime) made `LocalEvidence.Tests.ps1` fail in about half of the runs (the "flaky
  LocalEvidence failure" in PROGRESS); 8 of 8 runs pass now.

### H2 notes
- Agent template conditions: a broad group can enroll, Certificate Request Agent EKU, no manager approval, and (new) no
  authorised signatures.
- Target template conditions, all required: published, accepts an enrollment agent's signature (new: every schema version 1
  template; version 2+ only with msPKI-RA-Signature >= 1 and the Certificate Request Agent signature policy), allows client
  authentication, (new) no manager approval, and (new) the agent's principals may enroll for it (the same broad group, or
  Everyone / Authenticated Users). The evidence counts the targets and lists each with its schema version and reason.
- The fixtures model a new forest: User (schema 1, Domain Users), Machine (schema 1, Domain Computers) and EnrollmentAgent
  (schema 1, administrators only). That forest gives no ESC3; adding a broad, approval-free agent template gives one, with User
  as the target and Machine excluded.

### M11 notes
- Effective access is not computed (group nesting, Deny ACEs on groups that contain the principal, ACE order, the CA's own
  Request Certificates permission and enrollment agent restrictions). So every template review finding is now Referenced,
  never Confirmed, including templates the CA's own list names. The evidence says so in one line ("Confidence Referenced,
  not Confirmed: ..."). The code keeps the place where Confirmed would be allowed, behind `$effectiveAccessComputed`, which
  stays `$false` until that computation exists.
- Deny ACEs now count when they are for the same principal or for a well-known group that contains it (Everyone contains every
  principal; Authenticated Users contains Domain Users and Domain Computers). Such a match is Inferred with severity
  ReviewRequired, and the evidence names the denying group. A Deny for a narrower group does not cancel an Allow for a wider
  one.
- Still open from M11 (Batch B): the ESC4 write check counts a `WriteProperty` limited to one harmless attribute as a write.
  REQUIREMENTS 5.5 now states the confidence rule and the full ESC3 conditions (from H2).

### M1 notes (Batch B)
- `Test-MspkiAiaCertificateMatch` now collects the referencing certificates first. Identity with a known CA certificate (same
  thumbprint) proves the key only when no referencing certificate is known; otherwise the signature of a referencing certificate
  must verify with the downloaded key. After a renewal the old CA certificate is known too, so it no longer passes at the
  location of the new one (KeyMismatch, Warning, Confirmed).

### M2 notes (Batch B)
- `Test-MspkiEnrollmentEndpoint`: only 200 (service page), 400 and 405 are `ConfirmedResponding`. 401 and 403 give state `AuthRequired`
  (Information, `HTTP_401_403`, Referenced; Inferred for a constructed candidate), a 3xx gives `Redirected` (Information, `HTTP_REDIRECT`).
  Neither counts as `Responding`. A 200 whose content does not look like the service is a Warning and Referenced. REQUIREMENTS 5.6 says so.

### M7 notes (Batch B)
- `Get-MspkiGuiServiceSection`: the green "Answers" pill and the "N found" heading need a Confirmed observation. Something that answers
  at a standard path (Inferred) is "Something answers (not confirmed)" in the Warn tone, the confidence pill stays visible, and the
  heading of a mixed kind counts only the confirmed instances and says how many more are not confirmed. The page summary now reads
  "N of M service types confirmed in this run".

### M4 notes (Batch B)
- `Get-MspkiRetrievalOutcome` builds one outcome per URL (Usable, Failed or NotTested) from the findings of the probes and CRL checks; the
  key is `Get-MspkiRetrievalUrlKey` (scheme plus `ConvertTo-MspkiNormalizedUrl`'s key), applied to both sides. A Warning counts as a
  retrieval failure when its code names a retrieval, content or TLS problem (this also covers failures that the scope rule reduced to a
  Warning); a Warning about the age of the object still counts as retrieved. `Test-MspkiRetrievalOrder` counts only URLs that really
  failed as "failing", names how many URLs could be tested, and is Referenced (not Confirmed) when some were not tested.

### M5 notes (Batch B)
- `Invoke-MspkiHttpGet`: when a redirect is not followed because redirects are off (`-MaxRedirects 0`, as for the NDES and Web
  Enrollment probes) or the hop limit is reached, `HttpStatus` is the status of that hop (not 0), `FinalUrl` is the redirecting URL, and
  `Error` names the status and the Location. A Web Enrollment host that only redirects is therefore "present" (Inferred, with the
  redirect in the evidence) instead of "no web server answered", and NDES shows "HTTP 302 ... (redirect not followed)".

### M3 notes (Batch B)
- CDP and Freshest CRL downloads use `$script:MspkiCrlMaxBytes` (64 MB); other downloads keep the 10 MB cap. A response above the cap gets
  the new code `SIZE_LIMIT` (an HTTP probe result, and an Information finding for a CRL that says it was not read, so freshness, issuer
  and signature were not checked). `ConvertFrom-MspkiCrl` counts revoked entries with `Measure-MspkiDerChild` (no object per entry).
  The probe cache key includes a non-default cap.

### M6 notes (Batch B)
- `Register-MspkiGuiCrashGuard` (called in `Initialize-MspkiGuiApplication`) adds `Dispatcher.UnhandledException` (sets Handled) and
  `AppDomain.UnhandledException` (log only: the runtime ends the process after an error on a non-UI thread). Both call
  `Invoke-MspkiGuiUnhandledError`: Run log row (Error), `gui-error.log` in the output folder (through the output-folder guard), one
  message per distinct error and at most three per session, and a run in progress is cancelled through the Cancel flag (partial
  results are still written). If the engine had already finished and the error repeats three times, the run is given up and the window
  returns to idle with the output folder named.
- Finding from a prototype in Windows PowerShell 5.1: an exception in a `DispatcherTimer` tick stops the timer for good even when
  `Handled` is set. The tick therefore catches its own errors, and the guard re-arms the timer while a run is active.
