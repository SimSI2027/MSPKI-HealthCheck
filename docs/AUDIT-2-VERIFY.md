# Audit 2 verification: the Fix log checked against the code

- **Date:** 2026-11-22
- **Commit verified:** `f8ed721` (last commit of the audit 2 Fix log). The audit itself is `docs/AUDIT-2.md` (audited commit `50a26a2`).
- **Scope:** every item that the Fix log marks Fixed (or "recorded" / "partly fixed"), plus two areas checked end to end: where
  credentials or a handshake can go out (H1), and anything that can write to disk or to a key store (M10, the PFX item). `ref/` was
  not opened. No product code was changed.
- **Method:**
  - Read the source diff of every fix commit and the code around it at `f8ed721`.
  - **Old-code test runs.** For each fix commit, the tree of its parent commit was exported (`git archive`) to a temporary folder
    outside the repository. The `tests/` folder of the fix commit was laid over it, and the new tests were run there with Pester 5.7.1
    under Windows PowerShell 5.1. A test that fails there "would fail on the old code". I record whether it fails because of the old
    behaviour (**behavioural**) or only because a function or parameter it calls did not exist yet (**signature**).
  - **Probes.** Extra tests were run against a temporary copy of `f8ed721`. They are not committed. They used only loopback servers
    and `example.test` names, with `Get-MspkiLdapObject` mocked.
  - **Lab reads.** Two read-only checks ran against the lab directory: the referral behaviour of a base search for a DN under the
    reserved name `example.test`, and the schema IDs and property sets of the template attributes used by the ESC4 rule. Only error
    codes, Microsoft attribute names and schema GUIDs were printed.
  - **Full suite at `f8ed721`:** **1029 tests, 1029 passed, 0 failed** (8 min 13 s, with other runs in parallel).

## Summary

| Result | Items |
|---|---|
| Verified | H1 (CRL path and LDAP host gate), M1, M2, M4, M5, M6, M7, M9, M10, M11 (both parts), M12, M13, Names, L1, L2 (as a recorded limit), L3, L4, L5, L6, L7, L8, L9 (the part claimed), L11, L12, L13, L14, L15, L19 |
| Verified, with a regression nearby | M3 (an oversized AIA download is no longer a failure, N3) |
| Partly fixed | M8 (three RETRIEVAL_FAIL uses are unchanged and not explained), M14 (history check and some patterns narrower than stated) |
| Regressed | H2: schema version 1 targets now count, but the new "shared principals" condition misses the most common broad grants and drops ESC3 matches that fired before (N2) |
| Not fixed | none of the items marked Fixed |

**New issues**

| ID | Rank | Short |
|---|---|---|
| N1 | High | A forged CA certificate at an AIA URL is graded Pass / Confirmed. Its links are followed as Verified and can reach an authenticated LDAP bind. Pre-existing, but it defeats the guarantee H1 was meant to give |
| N2 | Medium | ESC3 shared-principal check (the H2 regression above) |
| N3 | Low | M3 side effect: an AIA URL that returns more than 10 MB is Information / Confirmed, with CRL wording and a wrong limit |
| N4 | Low | The CES/CEP word match still decides Confirmed for a 200, although the L17 row says it no longer does |
| N5 | Low | The forest DC list accepts any server object under CN=Sites, including stale ones |
| N6 | Low (hardening, not shown) | LDAP searches keep the default referral chasing (External) |
| N7 | Nit | Hygiene test gaps (certificate loading, store and file writes, history), and one store opened without OpenExistingOnly |

**First steps:** N1 first, because it reopens the H1 credential path. Then N2, then the rest.

---

## High

### H1 Links in a downloaded CRL / LDAP binds only to proven hosts: **Verified** (but see N1)
- **Code:**
  - `src/Analyzers/EndpointHealth.ps1:581-601`: Freshest CRL links are queued. They become leads (Trust `Verified`) only after
    `Test-MspkiCrlIssuerSignature` verified the CRL with a certificate in `$certMap`. The check is repeated after each round, and the
    links left in the queue are logged as not followed.
  - `$certMap` holds only CA certificates from AD and the CAs (`src/Discovery/Invoke-MspkiDiscovery.ps1:198-201`), plus downloaded
    AIA certificates that were `Validated`.
  - Only the Freshest CRL extension is followed. The IDP and any CRL AIA are not.
  - The LDAP host gate is `src/Model/HostScope.ps1:72-122`. A host is allowed only as serverless, the selected DC, a forest DC, or a
    forest-zone host named by an Authoritative or Verified lead. With `-SkipNetwork`, only the selected DC is allowed.
  - Trust is carried on leads (`src/Model/LeadRegistry.ps1:11`, `:98`); the strongest trust wins on merge (`:124`). The forest DCs
    are read in `src/Discovery/AdContext.ps1:43-60` and `:389-410`.
  - `Get-MspkiLdapUrlContent` (`src/Probes/WebProbes.ps1:428-501`), reached only from `Test-MspkiLeadEndpoint`, is the single place
    where an LDAP URL is read.
  - **Other binds:** every other `Get-MspkiLdapObject` call uses the selected DC, or a serverless bind for a group DN in another domain
    (`src/Discovery/Templates.ps1:283`). DCOM goes to the CA hosts from Enrollment Services. HTTP is anonymous
    (`WebProbes.ps1:156-160`).
- **Old-code test:** 15 of 15 red.
  - **Behavioural:** the CRL links of a CRL whose issuer was not discovered are followed (`Expected 0, but got 1`), and no lead is
    marked Verified.
  - **Signature:** the other 13 fail because `-DomainControllers` / `-Trust` / `Get-MspkiForestDomainController` did not exist. The old
    gate allowed any forest-zone name, as the diff of `3b4c3af` shows.
- **Regressions nearby:** none found in this path. The audit 1 tests changed in `tests/Audit.Probes.Tests.ps1` now pass
  `-Trust 'Authoritative'` / `-DomainControllers`. They were not weakened.
- **Limits:**
  - The guarantee in the rule 4 clarification ("a downloaded certificate ... whose signature was verified") does not hold for
    certificates. See **N1**.
  - See also N5 and N6.

### H2 ESC3 and schema version 1 targets: **Regressed**
- **Code:** `src/Analyzers/TemplateSecurity.ps1:149-158` (every schema version 1 template accepts an agent signature) and `:227-249`
  (ESC3 with all conditions on both templates).
- **Old-code test:** 2 of 10 red, both behavioural: "fires when ... the default User template (schema version 1) is published" and
  "counts every target". The 8 negative cases pass on the old code too, as expected.
- **Regression (N2):** `:235` treats the agent template and the target template as shared only when the target's broad principal has
  the same SID as one of the agent's, or is Everyone / Authenticated Users. That is containment in one direction only. Probes at
  `f8ed721`:

  | Probe | Agent template (Certificate Request Agent EKU, no approval, no signatures) | Target | ESC3 at `f8ed721` | Before `59a2f72` |
  |---|---|---|---|---|
  | A | Authenticated Users may enroll | default User (schema 1, Domain Users) | **none** | none (by reading: schema 1 never matched) |
  | B | Everyone may enroll | default User (schema 1, Domain Users) | **none** | none (by reading) |
  | C | Domain Users | schema 1 target, Authenticated Users | fires | none (by reading) |
  | D | Authenticated Users | schema 2 target with the agent signature policy, Domain Users | **none** | **fired** (run on the code before `59a2f72`) |

  - **A and B** are the commonest form of this misconfiguration: the agent template is granted to Authenticated Users or Everyone. They
    still give no ESC3, and the summary says "no review pattern matched". Any domain user is in both groups.
  - **D** is a real regression: it matched before the fix and no longer does.
  - The same containment table (`Test-MspkiSidContains`, `:82-96`) also does not know that BUILTIN\Users contains Authenticated Users
    and Domain Users. `src/Model/SecurityDescriptor.ps1:131` says it does since L5.
- **Fix:** treat the two principal sets as shared when either broad group contains the other (Everyone ⊇ Authenticated Users ⊇
  Domain Users / Domain Computers; BUILTIN\Users ⊇ Authenticated Users). Add probes A, B and D as tests.

## Medium

### M1 AIA location serving another key generation: **Verified**
- **Code:** `src/Analyzers/EndpointHealth.ps1:67-91`. The referencing certificates are collected first. Identity with a known
  certificate proves the key only when none is known. Otherwise the signature of a referencing certificate must verify.
- **Old-code test:** 1 of 2 red, behavioural (`KeyMismatch` expected). The other test, "the new root is still Verified", is a guard
  and passes on both.
- **Nearby:**
  - The key proof checks only the referencing certificate, never the downloaded certificate's own signature. That gap existed before
    and is **N1**.
  - On .NET Framework older than 4.6.2, no signature can be checked (a Run finding says so), so an AIA location is at most Referenced.
    That is honest, not a defect.

### M2 CES/CEP on 401, 403, 405 or 3xx: **Verified**
- **Code:** `src/Analyzers/EnrollmentServices.ps1:222-257`. A 3xx is `Redirected` and 401/403 are `AuthRequired`: Information,
  Referenced, never Responding. Only 200 with a service-like page, 400 and 405 are `ConfirmedResponding`.
- **Old-code test:** 5 red, behavioural, as the Fix log says.
- **Nearby (N4):** on a 200, `:266-285` still grades Confirmed when the body contains one of the words wsdl, service, svc, policy or
  enrollment. The L17 row says the content check "is no longer the proof for Confirmed after M2". That is not true for a 200.

### M3 A valid CRL larger than 10 MB: **Verified, with a regression nearby (N3)**
- **Code:**
  - `src/Analyzers/EndpointHealth.ps1:9` (64 MB cap) and `:232` (only CDP and Freshest CRL downloads use it).
  - `src/Probes/WebProbes.ps1:225` (`SIZE_LIMIT`).
  - `EndpointHealth.ps1:256-263`: Information, ContentStatus Skipped.
  - `Measure-MspkiDerChild` counts the revoked entries.
- **Old-code test:** 4 of 4 red. 2 are behavioural (Fail / `CONTENT_WRONG_TYPE`, exit code 4). 2 are signature (`$script:MspkiCrlMaxBytes` and
  `Measure-MspkiDerChild` did not exist).
- **Regression (N3):** the `SIZE_LIMIT` branch at `:256-263` runs for every lead kind.
  - An **AIA** URL that returns more than 10 MB (it uses the general cap) was a Fail before. Now it is Information, `SIZE_LIMIT`,
    Confirmed. The message says it is larger than the **64 MB** limit, which is not the limit that applied, and the note says "a large
    base CRL is normal".
  - A CA certificate never comes near 10 MB, so such an answer is wrong content. The retrieval-order check (M4) then counts the URL
    as not tested instead of failed.
  - **Fix:** keep `SIZE_LIMIT` / Information for CRL kinds only. For AIA, report a failure, or at least use the cap that applied and
    certificate wording.

### M4 Retrieval-order check: **Verified**
- **Code:** `src/Analyzers/HierarchyHealth.ps1:57-99`: one key (scheme plus the normalised key) on both sides; Usable, Failed or
  NotTested per URL; the Warning codes that count as failures, including `CHAIN_` and `CONTENT_MISMATCH`. `:101-167` counts only real
  failures and is Referenced when some URLs were not tested. Normalisation was checked by reading `ConvertTo-MspkiNormalizedUrl`
  (`src/Model/LeadRegistry.ps1:31-79`).
- **Old-code test:** 9 of 9 red, but all **signature** (`Get-MspkiRetrievalOutcome` did not exist). The M14 version of
  `tests/HierarchyHealth.Tests.ps1`, run against the audited code (`82d6e30`), also fails only on the missing `-UrlOutcome` parameter.
  So no test in the repository shows the old behaviour. That behaviour (a URL with a space gives "not tested") was shown at runtime in
  audit 2 itself.

### M5 A redirect recorded as "no answer": **Verified**
- **Code:** `src/Probes/WebProbes.ps1:205-214`. With `-MaxRedirects 0`, or at the hop limit, `HttpStatus`, `FinalUrl` and `Error` come
  from the last hop.
- **Old-code test:** 4 red, all behavioural (`Expected 302, but got 0`; Web Enrollment state `$null`). The Fix log says 3; the fourth
  is the Web Enrollment finding.

### M6 GUI exception in a handler: **Verified**
- **Code:**
  - `src/Gui/GuiApp.ps1:87-147` (`Invoke-MspkiGuiUnhandledError`).
  - `:149-165` (the Dispatcher handler sets Handled; the AppDomain handler only logs).
  - `:1211` (registered) and `:1239` (the timer tick catches its own errors).
  - `gui-error.log` goes through `Use-MspkiOutputFolder` / `Write-MspkiOutputFile`.
- **Old-code test:** 3 red (2 signature; 1 behavioural: in a real dispatcher loop, `Run` threw "handler failure").
- **Note:** the AppDomain handler is a script block on a thread that may have no runspace, so it may not run at all. It is untested,
  and the only effect is a missing log line.

### M7 Inferred services shown as found: **Verified**
- **Code:** `src/Gui/GuiEntity.ps1:433-475`. "Answers" and "N found" need a Confirmed observation; Referenced and Inferred show "Something
  answers (not confirmed)".
- **Old-code test:** 2 red, behavioural (`'1 found'` matched).

### M8 Status codes: **Partly fixed**
- **Verified:**
  - The new codes are in `src/Model/Schema.ps1:27-30`.
  - `CONFIG_MISMATCH` for "no CA of that name": `src/Discovery/CAProperty.ps1:436-441`.
  - `NOT_APPLICABLE` for both missing COM classes: `CAProperty.ps1:443-447` and `src/Discovery/NdesEvidence.ps1:250`.
  - `CHAIN_INVALID` after a completed handshake: `WebProbes.ps1:270-284`.
  - A host identity summary is not `OK` without an address: `src/Analyzers/EndpointIdentity.ps1:231`.
  - `RPC_FAIL`, `RETRIEVAL_ORDER`, `CONTENT_MISMATCH` and `ENROLLMENT_FAIL` are where the Fix log says.
  - Nothing else in `src` tests the old codes in a way the split would break. The EnrollmentServices TLS text at `:179-180` handles
    `CHAIN_INVALID` through its chain errors.
- **Old-code test:** 11 red (4 behavioural, 7 signature: `Get-MspkiTlsChainCode`).
- **Unchanged and not explained in the Fix log** (audit M8 listed them):
  - `RETRIEVAL_FAIL` is still used for "server down / service not running / bad network path" (`src/Model/ErrorInfo.ps1:13-17` via
    `src/Model/New-MspkiFinding.ps1:138`).
  - It is still used for any unclassified LDAP error (`WebProbes.ps1:494`).
  - It is still used for "RootDSE built from the name" (`src/Discovery/AdContext.ps1:335`).
  - These may be fine as "could not retrieve", but the Fix log should say so, as it does for `E_INVALIDARG`.

### M9 Redirects and TLS to undiscovered hosts: **Verified**
- **Code:** `src/Probes/WebProbes.ps1:191-204`. A hop goes only to the request's own host or to a host that
  `Test-MspkiTrustedLeadHost` accepts (`src/Model/LeadRegistry.ps1:325-340`). The extra handshake is gated at `WebProbes.ps1:244-268`.
- **Old-code test:** 4 red (3 behavioural, 1 signature: `-RequestHost`).
- **Regressions nearby:** none found. Same-host redirects (http to https) are still followed. The audit 1 redirect test now registers
  its HTTPS host first, which is correct.

### M10 Downloaded bytes and private keys: **Verified** (end to end, see below)
- **Code:** `src/Model/Certificate.ps1:13-31` (`GetCertContentType` first; only `Cert` is built), `:33-52`, `:63-74` (`EphemeralKeySet`
  where available) and `:76-100` (only `Cert` and `Pkcs7` are loaded).
- **Old-code test:** 4 red. 3 are behavioural (a key file appeared and the PFX was loaded, at the AIA location, in
  `New-MspkiCertificate` and in the NDES reader). 1 is signature (`Get-MspkiCertificateContentType`).
- **Nearby:** see N7 for the hygiene pattern, which is narrower than the rule it guards.

### M11 Template review confidence, Deny ACEs, ESC4 attribute rule: **Verified**
- **Code:** `src/Analyzers/TemplateSecurity.ps1:360-363` (always Referenced while `$effectiveAccessComputed` is `$false`), `:112-116` and
  `:82-96` (Deny ACEs for the same SID or a containing well-known group), `:36-47` and `:49-80` (ESC4 counts only sensitive attributes,
  no object type, or whole-object write rights; not the Enroll / Autoenroll ACE).
- **Old-code tests:** first part 7 red, behavioural. Second part 3 red: 2 behavioural (a harmless attribute and the display name
  fired), 1 signature (the list did not exist).
- **Lab schema check:** the ten schema IDs in `:36-47` match the lab schema exactly. None of the ten attributes is in a property set,
  so an ACE on a property set cannot hide a write to them.
- **For review (judgment, not verified):** `msPKI-Template-Schema-Version` and `flags` are not in the list. Both change how the CA reads
  the other settings (see H2 for what schema version 1 means for enrollment-agent requests).

### M12 Group / gMSA members as entities: **Verified**
- **Code:** `src/Discovery/NdesTemplateAccess.ps1:158` onwards (member records) and `src/Analyzers/Ndes.ps1:261-270` (Account entities,
  `memberOf` / `mayUse`, and `identifies` from the member).
- **Old-code test:** 2 of 3 red, behavioural, as the Fix log says.

### M13 Constrained Language Mode: **Verified**
- **Code:** `Invoke-MspkiHealthCheck.ps1:75-79` and `Start-MspkiHealthCheckGui.ps1:57-61` (after `param`, before anything is loaded);
  `src/Start-MspkiHealthCheck.ps1:55-56`; `src/Model/LanguageMode.ps1`.
- **Old-code test:** 8 of 9 red, as the Fix log says. 3 are behavioural: both entry points and `Start-MspkiHealthCheck` ran on in a child
  process that really was in Constrained Language Mode. 5 are signature (`Get-MspkiLanguageModeStatus`).

### M14 Weak or missing tests: **Partly fixed**
- **Verified:**
  - The three masking tests were replaced. Run against the audited code (`82d6e30`), the new M1 test in `Audit.Grading` and the new
    redirect test in `EndpointIdentity` are red (behavioural). The M4 one is red only on a missing parameter (see M4).
  - `Get-CodeText` now rejoins method calls (`tests/Hygiene.Tests.ps1`, start of the file). With the old joining, `$de . CommitChanges
    ( )` could never match `\.CommitChanges\(`, so the self-test would have been red. This was checked by reading.
  - The M14 hygiene tests pass against the code before `34d30e1` (298 passed; the history test was skipped because the export has no
    `.git`). So the repaired scan finds nothing in the product code.
  - The tests listed as missing in the audit now exist.
- **Narrower than stated:**
  - The history check (`:223-239`) scans commit messages and the author name and e-mail. It does not check the committer fields, and
    it does not scan the content of older commits. The audit asked for history as well as messages.
  - The store-write pattern (`:186`) matches only variables whose name contains `store`.
  - The rest is in N7.

### Names (fixture rename `b0a352a`): **Verified**
- The four host and account names removed by `b0a352a` appear in **0** files at `f8ed721` (counted, not printed). They remain in the git
  history, as the Fix log says.

## Low

| ID | Result | Where | Old-code test |
|---|---|---|---|
| L1 | Verified (recorded as a limit) | `src/Model/RunContext.ps1:68-70` | red, behavioural |
| L2 | Verified (recorded as a limit, not fixed, as stated) | `src/Model/RunContext.ps1:65-66` | red, behavioural |
| L3 | Verified | `src/Discovery/Templates.ps1:77` (`ConvertTo-MspkiTemplateExport`), `src/Reporters/Export-MspkiJson.ps1` | red, behavioural |
| L4 | Verified (wording and evidence; exit code unchanged, as stated) | `src/Discovery/CAProperty.ps1:312-320` | red, behavioural |
| L5 | Verified | `src/Model/SecurityDescriptor.ps1:131-132`; REQUIREMENTS 5.7 decision | 2 red, behavioural. See H2: the containment table does not know BUILTIN\Users |
| L6 | Verified | `src/Discovery/NdesTemplateAccess.ps1:153` (HRESULT only) | red, behavioural |
| L7 | Verified | `src/Discovery/Ldap.ps1:5-21`, `:41-43`; `src/Probes/WebProbes.ps1:410-416`, `:476` | 3 red (1 signature). The regression test from `f8ed721` is red on `0d3f56e` (a live read of this computer's directory). Not tested against a real LDAPS server, as stated |
| L8 | Verified | `src/Analyzers/EndpointHealth.ps1:486-496` | 3 red (2 signature, 1 behavioural) |
| L9 | Verified, for the part claimed | `src/Model/EntityGraphBuilder.ps1:496-500` | red, behavioural |
| L11 | Verified (no screen reader used, as stated) | `src/Gui/MainWindow.xaml`, `src/Gui/GuiView.ps1` | 2 red, behavioural |
| L12 | Verified | `src/Probes/NetworkProbes.ps1:167-169` onwards | red (signature) |
| L13 | Verified | `src/Discovery/Invoke-MspkiDiscovery.ps1:118-229`. The engine keeps the partial inventory (`src/Start-MspkiHealthCheck.ps1:104-108`), and the next stage timer stops the run | red, behavioural |
| L14 | Verified | `src/Model/Logging.ps1:30-33` | red, behavioural |
| L15 | Verified | `Invoke-MspkiHealthCheck.ps1:114` | red, behavioural |
| L17 | Not changed, as stated; but the row's reason is partly wrong (N4) | - | - |
| L19 | Verified | `docs/PROGRESS.md` has no broken dash | - |

L10, L16 and L18 were marked "not changed", "no action" and "not tested". Nothing was claimed for them, so there was nothing to verify.

---

## End-to-end check 1: where credentials or a handshake can go out (H1)
- **Directory binds** (Windows credentials):
  - the selected DC for all discovery reads;
  - a serverless bind for an OID group link in another domain;
  - LDAP URLs through the gate in `HostScope.ps1:72-122`.
  
  No other `DirectoryEntry` is built. The gate itself is correct. What it trusts is not always correct:
  - **N1:** a forged downloaded certificate is "Verified", so its LDAP links pass the gate.
  - **N5:** the DC list includes stale server objects.
  - **N6:** a referral could take the bind elsewhere.
- **DCOM:** only to CA hosts from the Enrollment Services objects in AD.
- **HTTP:** always anonymous (`UseDefaultCredentials = $false`, `Credentials = $null`, no pre-authentication). No proxy unless
  `-UseSystemProxy`. Redirects are scoped (M9).
- **TLS:** no client certificate. The extra handshake is scoped (M9). The chain engine's own fetches are recorded as a run limit (L1).

## End-to-end check 2: writes to disk or to a key store (M10, the PFX item)
- **Certificate loading:**
  - Every load of certificate bytes in `src` goes through `src/Model/Certificate.ps1`, which checks the content type first and refuses
    PKCS #12. This was checked by grepping for `X509Certificate2`, `.Import(` and key-storage flags. No persisting flag is used anywhere.
  - The TLS callback copies the `X509Certificate` it was given (`WebProbes.ps1:342`), never bytes.
  - Certificates copied from local stores go through `New-MspkiCertificate`.
- **Stores:** every store is opened `ReadOnly`. All but one also use `OpenExistingOnly`; the exception is in N7. No store `Add` /
  `Remove` exists.
- **Signatures:** signature checks use the public key only (`src/Model/Signature.ps1`). No `RSACryptoServiceProvider`, `CspParameters` or
  `CngKey` is created.
- **Files:** every write goes through `Write-MspkiOutputFile` (`src/Reporters/OutputFolder.ps1`). The only exception is
  `src/Gui/GuiSnapshot.ps1:47-48` (`[IO.File]::Create` / `.Save`), which is the allowed developer snapshot inside `out\`. No
  `Tee-Object`, transcript, `OpenWrite` or output redirection exists in `src` or the entry points. The GUI's `gui-error.log` goes through
  the guard.
- **Result:** no path from remote content to a key container or a file outside the output folder was found.

---

## New issues

### N1 (High) A forged CA certificate at an AIA URL is Pass / Confirmed, and its links reach an authenticated LDAP bind
- **Where:** `src/Analyzers/EndpointHealth.ps1:80-87` (`Test-MspkiAiaCertificateMatch`), `:317-321` and `:561-568`.
- **What happens:**
  - A downloaded certificate is `Verified` (Pass, Confirmed, `Validated = $true`) when the signature of a referencing certificate
    verifies with the downloaded certificate's public key.
  - Its **own** signature is never checked. The public key of a CA is public.
  - So anyone who can change the answer of an `http://` AIA location (cleartext, the same threat as in H1) can serve a certificate with
    the expected subject and the real CA's public key, signed by any other key, carrying any AIA / CDP / OCSP URLs.
  - It is graded "returns the CA certificate", Confirmed. It is added to the certificate map, and its links are registered with Trust
    `Verified`. An `ldap://` link to any name in the forest's DNS zone then passes the H1 gate, and the bind goes there with the
    operator's Windows credentials (NTLM when the name has no SPN). An `http://` link can name any host (rule 4).
- **Shown:**
  - The probe used a loopback server, `example.test` names and a mocked `Get-MspkiLdapObject`. It served a certificate with subject
    `CN=Example Root CA, DC=example, DC=test`, the root's public key, issuer `CN=Someone Else`, and a CDP of
    `ldap://planted.corp.example.test/...`, at the AIA URL of a discovered subordinate.
  - Result at `f8ed721`: the AIA finding was Pass / OK / Confirmed. One lead for `planted.corp.example.test` was created with Trust
    `Verified`, and `Get-MspkiLdapObject` was called once with `Server = planted.corp.example.test`.
- **Age:** this logic predates audit 2, and the M1 change neither caused nor fixed it. Audit 2 treated "the certificate is proven" as
  enough. The rule 4 clarification in CLAUDE.md and REQUIREMENTS 4.2 say "a downloaded certificate ... whose signature was verified with
  a discovered CA certificate", which the code does not do.
- **Fix:** a downloaded certificate becomes `Validated`, and gets Confirmed or link following, only when one of two things holds:
  - it is identical to a discovered certificate (same thumbprint); or
  - its own signature verifies: a self-signed certificate with its own key, any other certificate with a discovered or already proven
    CA certificate.
  
  The key proof for the referencing certificate (M1) stays as an extra condition. Add the probe as a test in
  `tests/Audit2.Security.Tests.ps1`.

### N2 (Medium) ESC3: agent templates open to Authenticated Users or Everyone never match
See H2 above (probes A, B and D, and the fix).

### N3 (Low) An AIA download above the 10 MB cap is no longer a failure
See M3 above.

### N4 (Low) CES/CEP: a 200 is Confirmed on a word match
- **Where:** `src/Analyzers/EnrollmentServices.ps1:266-285`.
- **What happens:** a 200 page (`xml|html|text`) that contains one of five words is `ConfirmedResponding`, Pass, Confirmed. A catch-all
  portal or landing page can match.
- **Effect:** the L17 row of the Fix log says the content check no longer decides Confirmed, which is not true for a 200.
- **Fix:** grade a 200 Confirmed only for a service-shaped answer (WSDL, or the policy / enrollment XML namespaces). Otherwise grade it
  Referenced. Correct the L17 row.

### N5 (Low) The forest DC list accepts stale server objects
- **Where:** `src/Discovery/AdContext.ps1:43-60`, filter `(&(objectClass=server)(dNSHostName=*))` under CN=Sites.
- **What happens:** a server object stays behind when a DC is removed without metadata cleanup, and it has no NTDS Settings child. Its
  name is still accepted for a directory bind. If its DNS record was scavenged, any authenticated user can register that name again in
  a default AD-integrated zone.
- **Fix:** count a server object only when it has an `nTDSDSA` child (one more one-level read per site, or a subtree search for
  `objectClass=nTDSDSA` and take the parents).

### N6 (Low, hardening, not shown) LDAP searches chase referrals by default
- **Where:** `src/Discovery/Ldap.ps1:44-55`. `ReferralChasing` is not set, so it keeps the .NET default `External` (checked on this
  computer).
- **What could happen:** a base search for a DN outside the DC's naming contexts makes the DC return a referral, and ADSI may follow it
  to the referred host with the same credentials, outside the H1 gate.
- **What was shown:** with an unresolvable referral (`example.test`), ADSI returned `0x8007202B` (referral returned) with both `None` and
  `External`. So chasing to another host was **not** shown.
- **Exposure:** today the DNs come only from Authoritative or Verified leads. N1 widens "Verified".
- **Fix:** set `ReferralChasing = None` for every search. A referral then becomes a reported error, never a second bind.

### N7 (Nit) Hygiene test gaps, and one store open
- **Certificate loading pattern:** `'certificate loading'` (`tests/Hygiene.Tests.ps1:55`) catches only `X509Certificate2(`. It misses
  `[X509Certificate2]::new(`, `New-Object ... -ArgumentList`, a cast from bytes, and PowerShell's conversion of bytes or a path string to
  a parameter typed `[X509Certificate2]`. Any of these would build a certificate from bytes, a PFX included, without the content-type
  check. None is used today.
- **Write pattern:** `writePattern` (`:57`) misses `[IO.File]::Create`, `.Save(`, `OpenWrite` and `>` / `>>` redirection. Today only the
  allowed `GuiSnapshot.ps1` uses any of them.
- **History check:** see M14.
- **Store open:** `src/Discovery/IntuneConnector.ps1:134` opens `LocalMachine\My` with `ReadOnly` only. Every other store open adds
  `OpenExistingOnly`. This is harmless, because that store always exists, but it is inconsistent with the "checked and found clean" note.

---

## Old-code test runs (raw counts)

Code of the parent commit, tests of the fix commit, filtered to the fix's tests. "Red" is the number of failed tests; "behavioural" is
the part that failed on the old behaviour rather than on a missing function or parameter.

| Fix | Commit | Ran | Red | Behavioural |
|---|---|---|---|---|
| H1 | `3b4c3af` | 15 | 15 | 2 |
| M10 | `a95e566` | 5 | 4 | 3 |
| M9 | `4aa6a91` | 5 | 4 | 3 |
| H2 | `59a2f72` | 10 | 2 | 2 |
| M11 (1) | `3aad084` | 7 | 7 | 7 |
| M11 (2) | `a4a76e1` | 81 (file) | 3 | 2 |
| M1 | `7842317` | 2 | 1 | 1 |
| M2 | `d1f7f55` | 28 (file) | 5 | 5 |
| M7 | `2a2bf0c` | 2 | 2 | 2 |
| M4 | `dce392b` | 9 | 9 | 0 |
| M5 | `d52359b` | 5 | 4 | 4 |
| M3 | `9715e0b` | 4 | 4 | 2 |
| M6 | `96e3ee8` | 3 | 3 | 1 |
| M8 | `759bb77` | 13 | 11 | 4 |
| M12 | `d73534f` | 3 | 2 | 2 |
| M13 | `ea37054` | 9 | 8 | 3 |
| M14 (realistic inputs, against `82d6e30`) | `34d30e1` | 87 (3 files) | 6 | 4 (2 of them are M8 assertions in the same files) |
| L1, L12-L15 | `3384568` | 6 | 5 | 4 |
| L2-L9, L11 | `0d3f56e` | 20 | 15 | 12 |
| L7 live regression (against `0d3f56e`) | `f8ed721` | 1 | 1 | 1 |

"Ran" counts the tests the filter selected. Where a whole file was run, it is marked "(file)".

## What was not done
- No lab run of the product: the code was not changed, and the Fix log records a lab run after the last fix.
- N6 was not shown against a resolvable referral. The L7 LDAPS path was not tested against a real LDAPS server.
- The probe tests and the old-code trees were kept outside the repository and are not committed.

---

## Fix log 2 (Batch D)

Each fix was tested red then green. "Pre-fix run": the new tests of the fix commit were run against the code of its parent commit
(`git archive` of the parent, the fix commit's `tests/` laid over it, outside the repository), as in the table above. "Behavioural"
counts the tests that failed because of the old behaviour; "signature" counts those that failed only because a new function was missing.

| ID | Status | Commit | Tests | Pre-fix run |
|---|---|---|---|---|
| N1 | Fixed | `eccbc02` | `tests/Audit2.Verify.Tests.ps1`: "Audit 2 N1: a downloaded CA certificate is trusted only as an authoritative copy or by its own verified signature" (6), "Audit 2 N1: a forged certificate at an AIA location is not followed" (4) | against `9b43bb1`: 10 ran, 8 red. Behavioural 2: the forged certificate was Pass / **Confirmed** (expected Referenced), and the forged self-signed root was **Pass** (expected Fail / SIGNATURE_INVALID). Signature 6: `Test-MspkiDownloadedCertificateTrust` did not exist. The 2 positive cases (exact root copy, proven subordinate) pass on both, as they should |
| N5 | Fixed | `204c0cc` | `tests/Audit2.Verify.Tests.ps1`: "Audit 2 N5: the forest domain controller list holds live domain controllers only" (4); `tests/Audit2.Security.Tests.ps1` "reads the forest domain controllers ..." updated (two reads now) | against `eccbc02`: 5 ran, 5 red. Behavioural 1: "reports the server objects that were not counted" got all three server objects (a stale one without NTDS Settings and one without an SRV record included), expected one. Signature 4: `Get-MspkiLiveDomainControllerName` did not exist |
| N6 | Fixed | `d8f92f4` | `tests/Audit2.Verify.Tests.ps1`: "Audit 2 N6: LDAP referrals are never chased" (3), with the credential harness `tests/CredentialHarness.ps1` | against `204c0cc`: 3 ran, 3 red. Behavioural 2: the searcher kept `ReferralChasing` External, and the referral was chased (one bind recorded to the referred server). Signature 1: `Test-MspkiLdapReferralError` did not exist |
| H2 (N2) | Fixed | `2b836db` | `tests/TemplateSecurity.Tests.ps1`: "Audit 2 H2 regression (verification N2): ESC3 matches whichever template the broad principals sit on" (18: 7 positive, 11 negative) | against `d8f92f4`: 18 ran, 4 red, all behavioural: probe A (Authenticated Users agent + default User), probe B (Everyone agent + default User), BUILTINUsers agent + default User, and probe D (the schema version 2 case that fired before `59a2f72`) gave no ESC3. The 3 other positives (same group on both, group on the target) and the 11 negatives pass on both, as they should |
| N8 (new) | Fixed | `1571ee0` | `tests/Audit2.Verify.Tests.ps1`: "Audit 2 N8: the LDAP host gate gets the forest domains and domain controllers as a list" (3) | against `2b836db`: 3 ran, 2 red, both behavioural: no bind to a host in the second domain of a two-domain forest named by an authoritative source, and no bind to a live DC named outside the forest zones (expected one each). The negative case passes on both |
| Item 5 | Done | `4ad3a05` | `tests/Credential.Behaviour.Tests.ps1`: "Credential behaviour: no bind, no handshake and no credentials because of an unverified object" (4), with `tests/CredentialHarness.ps1` | against `9b43bb1` (before Batch D): 4 ran, 3 red, all behavioural (`Expected 0, but got 1` binds): forged certificate, unverified CRL, referral chased. The stale DC case **passes on the old code by accident** (N8: the old DC list never reached the gate). Against `9b43bb1` with only the two N8 nesting lines corrected (so the old H1 DC rule works as designed): 4 ran, **4 red, all behavioural**, the stale DC object received a bind |
| M8 remainder | Fixed | `d182c51` | `tests/Audit2.BatchE.Tests.ps1` (M8 part, 35 cases: error number to code, real exception, LDAP URL read, retrieval-order check, schema, GUI search, report filter); `tests/Discovery.Tests.ps1` (2) and `tests/Ndes.Tests.ps1` (1) updated to the new codes | against `edc4900`: 17 ran in the new and updated tests, 17 red. Behavioural 11: every case returned `RETRIEVAL_FAIL` where a code of its own was expected (5 error numbers, the real `0x8007203A` exception, 2 LDAP URL reads, the RootDSE failure, the RootDSE guess, the NDES RPC case). Schema 6 (the new code was not allowed yet): 4 schema cases, 2 retrieval-order cases. The GUI search and report filter cases need the new codes too, so they fail on old code for the same schema reason |
| N3 | Fixed | `5cdbc23` | `tests/Audit2.BatchE.Size.Tests.ps1`: "Audit 2 N3: an AIA download above the size cap is not an Information / Confirmed result" (3) | against `25ae790`: 3 ran, 2 red, both behavioural: the AIA answer above the cap was Information (expected Fail), and the message named the 64 MB CRL limit instead of the 10 MB that applied. The negative case (a 10.6 MB CRL is read under the 64 MB cap) passes on both |
| N4 | Fixed | `72646fb` | `tests/Audit2.BatchE.N4.Tests.ps1`: "Audit 2 N4: a 200 answer from a CES or CEP is Confirmed only for a valid service response" (9); `tests/EnrollmentServices.Tests.ps1` updated | against `5cdbc23`: 9 ran, 8 red, all behavioural: an HTML portal, XML that only contains the words, `definitions` in the wrong namespace, a cut-off WSDL and a DTD document were all Pass / Confirmed / responding (expected Inferred, not responding); both SOAP faults were a Warning because they contain none of the five words (expected Confirmed); the evidence did not say why. The real WSDL passes on both |
| N7 | Fixed | `32da0b8` | `tests/Hygiene.Tests.ps1`: "Audit 2 N7: the hygiene patterns match the rules they guard" (27 tests: 10 certificate-building forms, 1 text pattern, 12 file-writing forms, 1 store-open self-test, 3 scans of src); `tests/IntuneConnector.Tests.ps1` updated | the tests were written before the fix, with the old patterns still in place: 6 red, all behavioural. The old certificate-loading text pattern did not match `[X509Certificate2]::new`; the old write pattern missed `File.Create`, `OpenWrite`, `.Save(` and `Tee-Object` (4 cases); the store scan found `IntuneConnector.ps1` opened without `OpenExistingOnly`. The AST scans of the code files pass from the start (nothing in `src` builds a certificate or redirects to a file outside the allowed places), so they guard against new code, not against old behaviour |
| M14 remainder | Fixed (check); history **not** clean | `3432c1e` | `tests/Hygiene.Tests.ps1`: "Audit 2 M14: the whole history is checked ..." (8: 6 planted-history self-tests, the real-history scan, and the private-list self-test; plus the private-list scan, which runs only with `MSPKI_PRIVATE_NAMES_FILE`) | planted-history self-tests run with the old logic (author and message only): 3 red, all behavioural (a name in the committer fields, in an old commits file, in an old path). On this repository: pattern scan 0 hits; private list 2 of 19 names in the content of 47 of 78 commits (see above) |
| M4 (behavioural) | Done | `M4B_HASH` | `tests/Audit2.BatchE.M4.Tests.ps1`: "Audit 2 M4, behaviour of the whole retrieval-order analysis" (3) | against `dce392b^`: 3 ran, 3 red, **all behavioural**: Skipped where Fail belongs, Skipped where Pass belongs, Pass where Fail belongs (a false Pass). On the current code: 3 passed |

### N1: what changed
- `Test-MspkiDownloadedCertificateTrust` (`src/Analyzers/EndpointHealth.ps1`) decides whether a downloaded CA certificate is trusted:
  - not self-signed: byte for byte (SHA-256 of the DER) a CA certificate read from AD or the CA, **or** its own signature verifies with
    the public key of an already trusted CA certificate (found by issuer name and Authority Key Identifier);
  - self-signed: the self-signature verifies **and** it is byte for byte a copy read from AD or the CA;
  - a certificate whose Basic Constraints say "not a CA" is never trusted, and is never used as an issuer (also for CRLs).
- The M1 key proof (a referencing certificate verifies with the downloaded key) stays, as an extra condition. A certificate is Validated
  (Pass / Confirmed, added to the trusted set, links followed as Verified) only when both hold. Key proven but certificate not
  trusted: Pass / Referenced, nothing followed (a cross-certificate looks like this, and so does a forgery). Its own signature checked
  and invalid: Fail / SIGNATURE_INVALID.
- CRLs use the same issuer search (`Find-MspkiIssuerSignature`), against the same trusted set. Signatures are checked with the public
  key only (`Test-MspkiSignature`); no `X509Chain` is built, so Windows fetches nothing in the background.
- Lab run as a normal (non-elevated) user after N1: 99 findings, exit 6, the same categories, statuses, codes and confidences as the
  baseline (the lab's AIA certificates are exact copies of the AD ones, so they stay Confirmed).

### N5: what changed
- `Get-MspkiForestDomainController` (`src/Discovery/AdContext.ps1`) counts a domain controller only when its server object under
  CN=Sites has an NTDS Settings (nTDSDSA) child **and** live evidence names it: the SRV records `_ldap._tcp.dc._msdcs.<domain>` of every
  forest domain (`Get-MspkiLiveDomainControllerName`, `Resolve-DnsName -DnsOnly` in one time-limited runspace; the in-box DC locator only
  where the DnsClient module is missing). No directory bind is made for this.
- Server objects that are not counted are reported once (Information / STALE_REFERENCE, with the reason per name) and never receive a
  bind. If DNS cannot be read, no other domain controller is counted and a run limit says so. With `-SkipNetwork` the DNS lookup is
  skipped (only the selected domain controller can receive a bind then).
- Lab check: 2 domains, 2 server objects, both with NTDS Settings and SRV records, 0 excluded.

### N6: what changed
- `Get-MspkiLdapObject` (`src/Discovery/Ldap.ps1`), the only place that searches the directory, sets `ReferralChasing = None` on every
  search. A referral then comes back as 0x8007202B. `Get-MspkiLdapUrlContent` reports it (Referral = true, the error names the
  server that referred and says the referral was not followed); the endpoint finding is a Warning with that evidence, not a Fail.
- RootDSE reads (`Get-MspkiRootDse`) use a DirectoryEntry with RefreshCache. RootDSE is the server's own entry, so it is never
  referred, and it has no object options (`Options` is `$null` on the lab DC), so there is no referral setting to change there.
- Dispose after a failed bind can throw the bind error a second time; every Dispose is now wrapped so the first error is reported.
- **Lab check (read-only, codes only):** a base search on the selected DC for the root DN of the forest's other tree fails at bind time
  with 0x8007202B for `None`, `External` and `All` alike. So a live chase could not be shown here; with `External` ADSI chases only
  referrals that come back inside a search. The harness models that documented search preference: with External it follows the
  referral (and records the bind), with None it throws 0x8007202B.

### H2 (N2): what changed
- `Test-MspkiSidOverlap` (`src/Analyzers/TemplateSecurity.ps1`): two broad principals share members when either contains the other
  (`Test-MspkiSidContains` in both directions). ESC3 now counts a target when any non-denied broad principal on it overlaps any
  non-denied broad principal on the agent template, whichever template the larger group sits on.
- `Test-MspkiSidContains` knows that BUILTIN\Users contains Authenticated Users and, through it, Domain Users and Domain Computers
  (the L5 statement in `SecurityDescriptor.ps1`). A Deny for BUILTIN\Users therefore also marks those grants as possibly cancelled.
- Still not matched: Domain Users vs Domain Computers, the Domain Users groups of two domains, Anonymous Logon vs Domain Users.

### N8 (new, found while writing the item 5 tests): the forest DC list and domains never reached the LDAP host gate intact
- **What happened:** `Get-MspkiLeadLocalDomain` and `Get-MspkiLeadDomainController` return their list with `return , @(...)`. The only
  caller, `Test-MspkiLeadEndpoint`, wrapped them in `@()` again, so the gate got a one-element array whose element was the list, which
  PowerShell turned into one string of all names. Before N5, `Get-MspkiAdContext` nested the DC list the same way.
- **Effect:** no forest domain controller other than the selected one was ever allowed (the H1 DC rule never applied), and in a forest
  with two or more DNS domains no named host passed the zone check, so authoritative LDAP URLs naming a forest host were "not contacted".
  This failed closed (no credentials went anywhere extra), which is why no test or lab run showed it: the lab's LDAP URLs are serverless.
- **Fix:** the lists are passed as they are (`src/Analyzers/EndpointHealth.ps1`). N5 made the DC list flat. Now that the DC rule works,
  N5's live-only list is what keeps stale objects out.

### Item 5: credential harness and end-to-end tests
- `tests/CredentialHarness.ps1` records every directory bind (fake DirectoryEntry / DirectorySearcher via a module-scoped `New-Object`
  mock; nothing reaches a network), every HTTP request and every TLS handshake (`Invoke-MspkiHttpGet` and `Test-MspkiTlsEndpoint` are
  wrapped and then run), and lists requests that reached the loopback server with credentials. It mocks only things that existed before
  Batch D, so on old code the tests fail on behaviour, not on a missing function.
- `tests/Credential.Behaviour.Tests.ps1` runs the real endpoint stage (and, for the stale DC, the real AD context stage):
  1. forged certificate (root's public key, attacker signature) with a planted `ldap://` CDP: no bind to the planted host, no TLS to a
     planted https AIA, no credentials on any HTTP request;
  2. CRL at the issuing CA's CDP signed by an attacker key, with the attacker's CA certificate reachable through a forged chain: no bind
     to the host in its Freshest CRL link, and the CRL is not Confirmed;
  3. referral from the selected DC: one bind (to the selected DC), none to the referred server, a Warning with the evidence;
  4. stale DC object (no NTDS Settings, no SRV record, name outside the forest zones) named by an authoritative LDAP URL: no bind.
- **Limits:** the referral is modelled (see N6). DCOM calls to CA hosts are not covered by the harness; they go only to the CA hosts in
  the Enrollment Services objects of AD, unchanged in this batch.

### M8 remainder (Batch E): what changed
- The three causes that still reported `RETRIEVAL_FAIL` now have codes of their own (`src/Model/ErrorInfo.ps1`, `src/Model/Schema.ps1`):
  1. **Unreachable class** (server down / service not running / bad network path): `Get-MspkiUnreachableStatusCode` names it by error number.
     `0x8007203A` (server not operational) and `0x8007054B` (domain cannot be contacted) are `DIRECTORY_UNAVAILABLE`; `0x800706BA` (RPC
     server unavailable) and `0x800706D9` (no RPC endpoint: service not running) are `RPC_FAIL`; `0x80070035` is `NETWORK_PATH_FAIL`.
  2. **Unclassified LDAP error** in `Get-MspkiLdapUrlContent`: an unreachable directory gets the code above, any other error is
     `DIRECTORY_ERROR` ("the directory returned an error that no rule classifies"; the error number stays in the evidence).
  3. **RootDSE built from the name**: `DC_NOT_FOUND` (Warning, Inferred). When every method fails and nothing can be built, the failure
     finding gets the unreachable code by error number (the lab-style `0x8007203A` case is `DIRECTORY_UNAVAILABLE`).
- **What cannot be told apart, and stays `RETRIEVAL_FAIL`:** an Unreachable-class failure whose error number is not one of the five above
  (for example one built by hand with no number). The class was set by a caller, not by an error number this tool knows, so naming a cause
  would be a guess. Also unchanged: the three non-directory uses (HTTP probe fallback in `Invoke-MspkiHttpGet`, the NDES transport
  fallback, an AD container group lookup that failed for a reason other than permission). They are generic "answer could not be read"
  cases and are what the `RETRIEVAL_FAIL` definition in `docs/REQUIREMENTS.md` now says.
- `RPC_FAIL` is wider than before (any RPC connection failure, not only a slow CA read); the CA-specific diagnosis in
  `Get-MspkiCaRpcFailureDiagnosis` is unchanged. NDES evidence now reports an unavailable RPC server as `RPC_FAIL`.
- The retrieval-order check counts the new codes as failures, as it did `RETRIEVAL_FAIL` (`src/Analyzers/HierarchyHealth.ps1`).
- **GUI and report:** neither lists status codes by name. The GUI grid finds a finding by its status code in the search box
  (`SearchText` includes it); the report's status code filter is built from the codes present in the findings. Both are now covered by a
  test with the new codes. No GUI code change was needed. `docs/REQUIREMENTS.md` documents the four new codes and the narrowed
  `RETRIEVAL_FAIL` / wider `RPC_FAIL`.
- Lab run as a normal user: 99 findings, exit 6, and an identical category / status / code / confidence histogram to the previous run. The
  lab's directory answers, so none of the new codes appears in it.

### N3 (Batch E): what changed
- `src/Analyzers/EndpointHealth.ps1`: the `SIZE_LIMIT` Information / Confirmed result is kept for CRL kinds only (CDP, Freshest CRL), where
  the cap is 64 MB and a large base CRL is normal. An **AIA** answer above the general cap is **Fail / `SIZE_LIMIT`**, ContentStatus Fail,
  not Confirmed (Referenced, the lead's usual grade). A CA certificate is a few KB, so such an answer is not a certificate.
- The message states the limit that applied (10 MB). The general cap is now one named value (`$script:MspkiGeneralMaxBytes`) passed
  explicitly to `Invoke-MspkiHttpGet`, so the number in the message cannot drift from the cap used. The note about "a large base CRL is
  normal" is no longer shown for AIA.
- The retrieval-order check (M4) counts such an AIA URL as failed (it is a Fail), no longer as not tested.
- `docs/REQUIREMENTS.md`: `SIZE_LIMIT` says Information for a CRL, Fail for an AIA certificate.

### N4 (Batch E): what changed
- `Test-MspkiServiceResponseBody` (`src/Analyzers/EnrollmentServices.ps1`) decides whether the body of a 200 answer from a CES or CEP is a
  valid service response: it must parse completely as XML (a DTD is refused, no resolver is set, nothing is fetched) and its root must be
  a WSDL `definitions` element, a SOAP 1.1 / 1.2 `Envelope` (a fault included) or an element in the Microsoft enrollment policy /
  enrollment namespaces. HTML, XML that only contains the old words, a root named `definitions` in another namespace, and cut-off XML are
  not.
- Only a valid service response is Pass / OK / **Confirmed** (state ConfirmedResponding). Any other 200 is Warning / `CONTENT_WRONG_TYPE`
  with **Inferred** confidence (it was Referenced before for a non-match, and Confirmed for a word match), state NotConfirmed,
  `Responding` false. The evidence says why it was not accepted, and the message no longer says "ConfirmedResponding" for it.
- The word match (`wsdl|service|svc|policy|enrollment`) is gone. A real WCF help page (HTML) is therefore Inferred, not Confirmed, on a
  bare anonymous GET; that is deliberate. 400 and 405 still count as the service answering (unchanged, not part of N4).
- The L9/L17 wording in `docs/AUDIT-2.md` ("still a word match") is corrected below the row it sits in.
- Existing test updated: the `/page/service.svc` fixture of `tests/EnrollmentServices.Tests.ps1` is now a WSDL, and a new
  `/mention/service.svc` HTML page that only mentions the service is a warning.
- Lab run after N3 and N4 (normal user): 99 findings, exit 6, identical category / status / code / confidence histogram.

### N7 (Batch E): what changed
- **Certificate loading:** the text pattern now also matches `[X509Certificate2]::<any static member except GetCertContentType>`
  (`::new`, `CreateFromCertFile`, ...). A new AST scan (`Get-CertificateBuildSite` in `tests/Hygiene.Tests.ps1`) finds every way a certificate
  can be built from bytes or a path: any static member, `New-Object` (constructor or `-ArgumentList`), a cast, a typed variable, and a
  **parameter typed `[X509Certificate2]`**, because PowerShell converts a byte array or a path string to that type when a caller passes one.
  Allowed: all of `src/Model/Certificate.ps1`, the TLS callback copy in `WebProbes.ps1` (its argument is the `$cert` the callback
  received), and typed parameters in seven listed files (they take certificates that were already built there). A typed parameter anywhere
  else fails the test, so it becomes a decision made on purpose. Limit: whether a caller passes bytes to such a parameter is not checked.
- **Write pattern:** the text pattern now also matches `File::Create`, `CreateText`, `OpenWrite`, `AppendText`, `Replace`, `Move`, `Copy`,
  `Delete`, `SetAttributes`, `.Save(`, `SaveAs(` and `Tee-Object`. An AST scan finds redirection to a file (`>`, `>>`, `2>`, ...) in every
  code file that is not allowed to write; `> $null` and merges such as `2>&1` are not files, and a string containing `>` is not a redirection.
  Only `GuiSnapshot.ps1` (allowed) and `OutputFolder.ps1` match today, as before.
- **Store open:** `src/Discovery/IntuneConnector.ps1` now opens `LocalMachine\My` with `ReadOnly, OpenExistingOnly`. A test finds every
  `X509Store.Open(...OpenFlags...)` in `src` and requires `OpenExistingOnly`; it was red on that one line.
- The history check of N7 is item 2 (M14) of this batch.
- Lab run as a normal user: 99 findings, exit 6, identical histogram.

### M14 remainder (Batch E): the history check
- `tests/Hygiene.Tests.ps1`, "Audit 2 M14: the whole history is checked ...": `scanHistory` checks **every commit on every ref** (`git rev-list --all`):
  - **author and committer** (name and e-mail of both): each must be the project identity (name `ED`, GitHub noreply address); the old test checked
    the author only (the committer fields were only searched for host-like text);
  - **messages** (subject and body);
  - **file paths** of every commit (`git log --name-only`), because a name can sit in a path that a later commit removed;
  - the **full content of every file in every commit**: `git grep -a -h -o -P` for the host, IP and e-mail patterns of the working-tree scan,
    over the revisions in batches of 40, text and binary files alike. The old test never read old file content.
- **Counts only.** The matches are collected inside the helper and never leave it; the result and the failure message hold numbers
  ("commits scanned 78; identities 0; distinct names in messages 0, in file paths 0, in file content 0"). A test shows the result holds no
  match text. The old history `It` was replaced by this one.
- **Private list (optional).** `MSPKI_PRIVATE_NAMES_FILE` may name a file of names, one per line, kept outside the repository; a second test
  counts them per place (content, messages, paths, identities) and the commits affected. It is skipped when the variable is not set, and the
  tool never needs it. Its logic is covered by a self-test on a planted history.
- Self-tests on planted repositories (in `$TestDrive`): a name in the committer fields only, a name in a file of an old commit that a later
  commit removed, a name in an old path, a name in a message, a clean history, and "counts only". Run first with the old logic
  (author and message only): 3 red, all behavioural (committer, old content, old path); the message, clean and counts-only cases passed on
  both, as they should.
- **Result on this repository (counts only):** the pattern scan finds nothing (78 commits; identities 0, messages 0, paths 0, content 0). The
  patterns look for host names with a top-level domain, IP addresses and e-mail addresses. **The private-list check does find lab names:
  2 of the 19 names on the lab list are in the file content of 47 of 78 commits** (the older ones, commits 11 to 57 counted from the
  oldest); none in HEAD, in any message, path or identity. They are the short names that the fixture rename (`b0a352a`) removed from the
  current tree; the pattern scan cannot know a short name. **Removing them needs a history rewrite and a force push of a public
  repository. That is the owner's decision and was not done.**

### M4 behavioural test (Batch E)
- The M4 tests of `dce392b` call functions that did not exist before it (`Get-MspkiRetrievalOutcome`, `-UrlOutcome`), so on the old code they
  were red on a missing function and showed nothing of the old behaviour. `tests/Audit2.BatchE.M4.Tests.ps1` uses only what exists on both
  sides: the whole `Invoke-MspkiHierarchyAnalysis` with a certificate that carries the CDP URLs, and probe findings built by hand (Endpoint
  as the probes record it, a space as `%20`).
- Run against the code of `dce392b^` (`git archive` outside the repository, the new test file laid over it): **3 ran, 3 red, all behavioural,
  none on a missing function.** The old wrong results:
  | Case | Old result | Right result |
  |---|---|---|
  | a failing CDP URL with a space in the certificate, `%20` in the probe | **Skipped** ("not tested from here") | Fail |
  | a working URL written with `:80` and another host case | **Skipped** | Pass |
  | the only URL answered with a Warning for the wrong content | **Pass** (a false "clients get it from the first URL") | Fail |
- Against the current code: 3 passed.

### Fix log 2: runs
- Timed full suite before each commit (Pester 5.7.1, Windows PowerShell 5.1): N1 1039 passed; N5 1043; N6 1064 run, 8 red (7 were the
  H2 tests written ahead of the H2 fix, 1 a static test that matched a function name in a new comment; the comment was reworded and
  that file re-run green before the commit); H2 1064 passed; N8 and item 5 1071 passed.
- Lab run as a normal (non-elevated) user after each fix: 99 findings, exit 6, the same categories, statuses, codes and confidences as
  the baseline every time. The lab has 2 domains and 2 live DCs; no server object was excluded; all its AIA/CDP URLs are serverless LDAP.
- Not done: a live referral chase could not be produced in the lab (see N6). N3, N4 and N7 of the verification are not part of this
  batch.
