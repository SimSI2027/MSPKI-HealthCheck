# Audit 3 verification: Fix log 2, credential safety end to end, ESC3 on a default forest

- **Date:** 2026-11-22
- **Commit verified:** `64ac786` (last commit of Fix log 2 in `docs/AUDIT-2-VERIFY.md`).
- **Scope:**
  1. every item of Fix log 2: the fix in the code, its tests run against the pre-fix commit, and regressions nearby;
  2. every code path that can bind to LDAP, send a credentialed request or make a TLS handshake, attacked as someone who controls
     one plain-HTTP download;
  3. ESC3 on a default forest whose agent templates have broad permissions, with the default User template as the target.
- **No product code was changed.** `ref/` was not opened.
- **Method:**
  - **Pre-fix runs.** For each fix, the tree of its parent commit was exported with `git archive` to a scratch folder outside the
    repository. The `tests/` folder of the fix commit was laid over it, and the fix's tests were run with Pester 5.7.1 under Windows
    PowerShell 5.1. A red test is counted as **behavioural** when it failed on the old result. It is counted as **signature** when it
    failed only because a function or parameter did not exist yet. The same runs on the fix commits are green.
  - **Probes.** These were scripts run against `64ac786` in a scratch folder and are not committed. They used loopback servers, the
    test certificate helpers, a loopback LDAP responder that records only operation types and booleans (never a token), and
    `example.test` names.
  - **Lab reads.** These were read-only. The tool's own template reader read the lab's certificate templates, and the ESC3 scenarios
    were evaluated in memory. Only Microsoft template names, rule names and labels of well-known groups were printed. A counts-only
    scan checked the git history against the private name list.
  - **Full suite at `64ac786`:** see "Runs" at the end.

## Summary

| Result | Items |
|---|---|
| **Verified** | N1, N5, N6, H2 (N2), N8, item 5, M8 remainder, N4, N7, M4 (behavioural test) |
| **Verified, with a gap nearby** | N3 (an AIA host outside the forest that answers above 10 MB counts as a *working* URL in the retrieval-order check: N11) |
| **Verified, but one Fix log claim is wrong** | M14 remainder: the check works, but the committer self-test does not separate old from new logic (N14) |
| **Not fixed (owner decision, as stated)** | Lab names remain in the history of this public repository: 2 of the 19 names on the private list, in the file content of 47 of 83 commits. None are in HEAD, in commit messages, in paths or in identities |
| **Regressed** | none |
| **Credential safety (part 2)** | **Verified.** No path sends Windows credentials to a host chosen by an unverified object. One plain-HTTP answer can stop the whole endpoint stage (N9). The TLS chain engine contacts hosts named by the server certificate, anonymously (N13) |
| **ESC3 on a default forest (part 3)** | **Verified** for every broad-agent case (16 scenarios on the lab's 33 Microsoft default templates). False negative: a Deny ACE for any right silently removes the match (N10) |

**New issues**

| ID | Rank | Short |
|---|---|---|
| N9 | Medium | A redirect to `file:`, `ftp:` or `ldap:` on the same host throws out of `Invoke-MspkiHttpGet` and stops the endpoint stage. Every AIA/CDP/OCSP/CRL result of the run is lost. One plain-HTTP answer is enough. No credentials go out |
| N10 | Medium | ESC3 ignores which right a Deny ACE denies. An unrelated Deny (for example Deny Everyone *Delete*) on the agent or target template removes the match, and the summary then says "no review pattern matched". The other patterns are downgraded for the same reason |
| N11 | Low | N3 side effect: an AIA URL outside the forest whose answer is above 10 MB is capped to Warning / `SIZE_LIMIT`, and the retrieval-order check counts it as Usable |
| N12 | Low (pre-existing) | Same nesting bug class as N8: a local certificate with two or more AIA/CDP URLs is recorded as `System.Object[]: System.Object[]` |
| N13 | Low (hardening / documentation) | During every TLS handshake the Windows chain engine connects to the `ldap://` and `http://` hosts in the server certificate's AIA, which can be any host. Measured: anonymous searches only, never a bind. The L1 run limit does not say that the host can be any host, LDAP included |
| N14 | Nit | M14 committer self-test: the old test would have caught the planted committer e-mail too. The case the old test really missed (a committer name with a noreply e-mail) is not tested |
| N15 | Nit | `Add-MspkiLead` defaults to `-Trust Authoritative` (fail-open), and NDES leads derived from Verified leads become Authoritative. This has no effect today |

**First steps:** N9 (one plain-HTTP answer removes every endpoint result), then N10, then N11 and N12.

---

## Part 1: Fix log 2, item by item

Pre-fix runs: the code of the parent commit with the tests of the fix commit (see Method). My counts are first; where the Fix log says the
same, it is marked "as stated".

| Item | Commit | Code checked | Pre-fix run (mine) | Fix commit run | Result |
|---|---|---|---|---|---|
| N1 | `eccbc02` | `src/Analyzers/EndpointHealth.ps1:96-108` (non-CA never an issuer), `:110-157` (issuer by name + AKI, public-key check only), `:159-230` (`Test-MspkiDownloadedCertificateTrust`), `:466-501` (Validated only when key proof **and** trust), `:719-727` (links followed only when Validated) | against `9b43bb1`: 10 ran, 8 red. 2 behavioural (forged cert was Confirmed; forged self-signed root was Pass), 6 signature. As stated | 10/10 green | **Verified** |
| N5 | `204c0cc` | `src/Discovery/AdContext.ps1:46-96` (SRV records, DNS only, one time-limited runspace), `:98-158` (nTDSDSA child **and** SRV name), `:488-529` (-SkipNetwork: selected DC only; read failure: selected DC only) | against `eccbc02`: 5 ran, 5 red. 1 behavioural (all three server objects counted, and nested: `@(@(...), 'dc01...')`), 4 signature. As stated | green (full suite) | **Verified** |
| N6 | `d8f92f4` | `src/Discovery/Ldap.ps1:53-56` (`ReferralChasing = None` on every search), `:76-91`, `src/Probes/WebProbes.ps1:490-495` | against `204c0cc`: 3 ran, 3 red. 2 behavioural (External kept; one bind to the referred server), 1 signature. As stated | green | **Verified** (the referral is modelled by the harness, as stated) |
| H2 (N2) | `2b836db` | `src/Analyzers/TemplateSecurity.ps1:82-99` (containment), `:101-111` (overlap both ways), `:244-266` | against `d8f92f4`: 18 ran, 4 red, all behavioural (probes A, B, BUILTIN\Users, D). 14 negatives and positives green on both. As stated | green | **Verified**; see Part 3 and N10 |
| N8 | `1571ee0` | `EndpointHealth.ps1:309-315` (lists passed as they are); the only caller of the two getters (`src/Model/LeadRegistry.ps1:304-323`) | against `2b836db`: 3 ran, 2 red, both behavioural. As stated | green | **Verified**. A search for the same pattern found one more, older case (N12) |
| Item 5 | `4ad3a05` | `tests/CredentialHarness.ps1`, `tests/Credential.Behaviour.Tests.ps1` | against `9b43bb1`: 4 ran, 3 red (behavioural); the stale-DC case green by the N8 accident. With only the two N8 nesting lines corrected in that old tree: **4 ran, 4 red, all behavioural**. As stated | 4/4 green on `1571ee0` and at HEAD | **Verified** |
| M8 remainder | `d182c51` | `src/Model/ErrorInfo.ps1` (`Get-MspkiUnreachableStatusCode`), `src/Model/New-MspkiFinding.ps1`, `WebProbes.ps1:496-504`, `AdContext.ps1:434`, `src/Analyzers/HierarchyHealth.ps1:82` | against `edc4900`, whole files (BatchE, Discovery, Ndes, Model): 127 ran, 22 red. 11 behavioural (5 error numbers, the real exception, 2 LDAP URL reads, the 2 RootDSE cases, NDES RPC). 11 schema (the new codes were not allowed yet: 4 schema, 2 retrieval-order, 4 GUI search, 1 code count) | green | **Verified** (the Fix log counts 17; the difference is the GUI and code-count tests, which it names) |
| N3 | `5cdbc23` | `EndpointHealth.ps1:7-12`, `:379-380`, `:403-421` | against `25ae790`: 3 ran, 2 red, both behavioural. As stated | green | **Verified, gap nearby: N11** |
| N4 | `72646fb` | `src/Analyzers/EnrollmentServices.ps1:15-50`: DTD prohibited, no resolver, whole document read, root by namespace and name | against `5cdbc23`: 37 ran (N4 file + EnrollmentServices file), 9 red, all behavioural (8 in the N4 file, and the updated `/page/service.svc` test). As stated | green | **Verified** |
| N7 | `32da0b8` | `tests/Hygiene.Tests.ps1` (patterns, AST scans), `src/Discovery/IntuneConnector.ps1` | new tests on the old code: 1 red (the store scan, IntuneConnector). New tests with the **old patterns** put back (on `6223583`): **6 red, all behavioural** (certificate `::new`, 4 file-write forms, store open). As stated | green | **Verified** |
| M14 remainder | `3432c1e` | `tests/Hygiene.Tests.ps1:372-558` | the exact old logic (from `5f54566`) applied to the planted histories: old content **missed**, old path **missed**, committer e-mail **found** (the old test also searched `%cn\|%ce` with the e-mail pattern). A committer *name* with a noreply e-mail: **missed** by the old logic | green; real-history pattern scan 0 | **Verified**; the Fix log's "3 red (committer, ...)" is wrong for the committer case (**N14**) |
| M4 behavioural | `380c389` | `tests/Audit2.BatchE.M4.Tests.ps1` | against `dce392b^`: 3 ran, 3 red, all behavioural (Skipped, Skipped, false Pass). As stated | 3/3 green on `dce392b` and HEAD | **Verified** |

**History (M14 remainder, open for the owner).** I re-ran the private-list check, counts only. The list holds 19 names. 2 of them are in
the file content of 47 of the 83 commits; there are 0 in HEAD, 0 in messages, 0 in paths and 0 in identities. That matches the Fix log
(it counted 78 commits; 5 have been added since). Removing them needs a history rewrite and a force push, which is still the owner's
decision.

### Regressions looked for nearby
- **N1:** none. A certificate without Basic Constraints is still allowed as an issuer (`EndpointHealth.ps1:103`), and most end-entity
  certificates of a Microsoft CA have none. It still cannot become trusted from a download. Trust needs an identical AD/CA copy or a
  signature by a trusted CA key, *and* the key proof. The key proof needs the CA's own public key in a certificate that a CA signed,
  which a requester cannot get without the private key (proof of possession).
- **N5:** none. An RODC's NTDS Settings object is a subclass of nTDSDSA, so it still matches. The selected DC is always added
  (`AdContext.ps1:506`).
- **N6:** not shown, a risk only. The serverless group lookup for an OID link in another domain (`src/Discovery/Templates.ps1:277-283`)
  can no longer follow a referral. If ADSI binds to a DC of the user's own domain, the group is reported as "not looked up". It is not
  a false "missing". The lab has no such link, so this was not tested.
- **N8:** one more nesting bug of the same class, older than Fix log 2 (N12).
- **H2:** the containment logic is right. The false negative is in the Deny handling (N10).
- **N3:** N11.
- **M8:** the failure-code list in `HierarchyHealth.ps1:82` does not include `SIZE_LIMIT` (N11).

---

## Part 2: credential safety end to end

### Every path that can bind to LDAP, make a credentialed request or a TLS handshake

| # | Path | Where | Target host comes from | Credentials | Verdict |
|---|---|---|---|---|---|
| 1 | Discovery reads (Configuration partition, templates, OIDs, KRA, containers, NDES accounts, CN=Sites) | `src/Discovery/Ldap.ps1:23-74` via `EnterpriseCA.ps1:100`, `Templates.ps1:127/206/261`, `PkiContainers.ps1:33-116`, `NdesTemplateAccess.ps1:144`, `NdesEvidence.ps1:154`, `AdContext.ps1:126-128` | the selected DC (RootDSE `dnsHostName`), or serverless (DC locator) when none answered | Windows (Negotiate) | proven host |
| 2 | RootDSE | `AdContext.ps1:15-44`, `:241-256` | serverless; DC locator; this computer's domain name (WMI); a GC of the current forest | Windows | proven host |
| 3 | `System.DirectoryServices.ActiveDirectory`: forest, domains, trusts, GC, site, DC locator | `AdContext.ps1:160-196`, `:286-338`, `:75-76` | the DC locator (DNS SRV of the forest's own domains); site from Netlogon | Windows (LDAP, LSA RPC) | proven host |
| 4 | Group of an OID link in another domain | `Templates.ps1:277-283` | serverless bind for a DN read from the Configuration partition (a DN-syntax value, so it names an object in the forest) | Windows | proven host |
| 5 | SID to name | `src/Model/SecurityDescriptor.ps1:84-100` (`Translate`) | the local LSA and its secure channel to the DCs | machine/user | proven host |
| 6 | **LDAP URLs (AIA/CDP/Freshest CRL)** | `src/Probes/WebProbes.ps1:428-510`, gate `src/Model/HostScope.ps1:72-122`, only caller `EndpointHealth.ps1:313` | serverless → the selected DC; the selected DC; a live forest DC (N5); a forest-zone host named by an **Authoritative or Verified** lead; with `-SkipNetwork` only the first two | Windows | **gate holds** (attacks below) |
| 7 | DCOM `CertificateAuthority.Request` / `.View` | `src/Discovery/CAProperty.ps1:56`, `:71`; `NdesEvidence.ps1:27-28` | `dNSHostName` of the Enrollment Services objects in AD | Windows | proven host |
| 8 | HTTP GET (AIA/CDP, CES/CEP, NDES, Web Enrollment, OCSP path) | `WebProbes.ps1:149-237` | leads (AD, CA properties, local policy, verified objects); standard paths only on CA hosts (`EndpointIdentity.ps1:305-314`, `HierarchyHealth.ps1:506-509`) | **none**: `UseDefaultCredentials = $false`, `Credentials = $null`, `PreAuthenticate = $false` (`:157-160`); proxy only with `-UseSystemProxy`, with no proxy credentials | anonymous |
| 9 | Redirect hops | `WebProbes.ps1:191-216` | the request's own host, or a host `Test-MspkiTrustedLeadHost` accepts (`LeadRegistry.ps1:325-340`) | none | host check holds; **scheme not checked: N9** |
| 10 | TLS handshake (probe, HTTPS request, CES/CEP, NDES, Web Enrollment, the extra trust-failure handshake) | `WebProbes.ps1:286-389`, `:244-268` | the hosts of 8 and 9; the extra handshake only to the request host or a trusted lead host | no client certificate (`AuthenticateAsClient($h, $null, ...)`, `:348`) | host check holds; **chain engine: N13** |
| 11 | Windows chain engine during 10 | inside `SslStream` / `HttpWebRequest` | the AIA URLs **of the server certificate** (any host) | measured: **anonymous** LDAP search and HTTP GET, never a bind | outside rule 4's bounds, no credentials (N13) |

No other `DirectoryEntry`, `DirectorySearcher`, `LdapConnection`, `WebClient`, `Invoke-WebRequest`, `-ComputerName`, remote CIM/WMI,
UNC or SMB access exists in `src` or the entry points. I checked this by grep. File/UNC leads are never probed (`EndpointHealth.ps1:296-300`).

### Attacks by someone who controls one plain-HTTP download

All of these ran against `64ac786` unless marked "by reading".

| # | Attack | Result |
|---|---|---|
| A1 | A forged CA certificate at an AIA URL: the root's name and public key, signed by another key, with a planted `ldap://` CDP and an `https://` AIA | Pass / Referenced, nothing followed, no bind, no TLS (item 5 test 1, green; red on `9b43bb1`) |
| A2 | A forged self-signed root at the root's AIA | Fail / `SIGNATURE_INVALID`, nothing followed (N1 test) |
| A3 | A CRL at the CDP signed by an attacker key, with a Freshest CRL link to a planted LDAP host, and the attacker's CA certificate served through a forged chain | no bind; the CRL is not Confirmed (item 5 test 2) |
| A4 | A genuine but older CA certificate of the same CA (an exact AD copy) at the new certificate's AIA | `KeyMismatch`: Warning, nothing followed (M1, by reading `:478-484`) |
| A5 | A genuine certificate that a trusted CA signed, carrying the expected name and key | trusted (IssuerSignature). Its links were written by that CA, so the attacker chooses nothing. An attacker cannot get such a certificate issued without the CA's private key |
| A6 | `302 Location: ldap://<attacker host>/...` | not followed: the host is not trusted (`WebProbes.ps1:197-203`) |
| A7 | `302 Location: https://<same host>:<port>/` | followed: TLS to the same host. No credentials. The chain engine then contacts the server certificate's AIA hosts anonymously (A10) |
| A8 | `302 Location: file://<same host>/share/ca.crt` (also `ftp://`, and `ldap://<same host>/...`) | **no request is sent** (the cast to `HttpWebRequest` fails at `:152` before `GetResponse`, so there is no SMB and no LDAP), **but the exception stops the whole endpoint stage**: **N9** |
| A9 | Referral from the selected DC to another server | not chased; one bind (the selected DC), none to the referred server (item 5 test 3) |
| A10 | A TLS server (reached directly or through A7) whose certificate has AIA `ldap://127.0.0.1:<sink>/...`, against a loopback LDAP responder that claims to be AD (supportedCapabilities with the AD OIDs, GSS-SPNEGO offered) | `Test-MspkiTlsEndpoint`: 4 connections to the sink. `Invoke-MspkiHttpGet https`: 4 more. Every message was an anonymous search (the AIA object, RootDSE `supportedCapabilities`, `supportedSASLMechanisms`) or an unbind. **0 bind requests, 0 NTLM/Kerberos tokens.** The same holds for `X509Chain.Build` with revocation off. Bounded discovery is not met here, but no credentials go out (**N13**) |
| A11 | Make a forest-zone name receive a bind (scavenged record re-registered) | only live DCs (nTDSDSA **and** SRV), the selected DC, or hosts named by Authoritative/Verified evidence pass the gate; a stale DC object gets no bind (item 5 test 4). Not reachable through a plain-HTTP answer |

**Residual, not tested:** if a forest host named by an authoritative LDAP URL has no DNS record, Windows name resolution may fall back to
LLMNR or NetBIOS for the bind (`Get-MspkiLdapUrlContent` does not check that the name resolves in DNS first). That needs an attacker on
the local subnet, not control of an HTTP download.

**Verdict:** **Verified.** Every credentialed path goes only to hosts from AD, the CA's properties, local policy or a verified object.
One plain-HTTP answer cannot choose a bind target. It can stop the endpoint stage (N9), and through a same-host TLS redirect it can make
Windows open anonymous connections to hosts it names (N13).

---

## Part 3: ESC3 on a default forest

The 33 Microsoft default templates were read from the lab directory with the tool's own reader (read-only). Their facts as read:

| Template | Schema | EKU | Agent EKU | Client auth | Accepts agent signature | Broad enroll |
|---|---|---|---|---|---|---|
| User | 1 | EFS, Secure Email, Client Auth | no | yes | yes (schema 1) | Domain Users |
| Machine | 1 | Client Auth, Server Auth | no | yes | yes | Domain Computers |
| EnrollmentAgent, MachineEnrollmentAgent, EnrollmentAgentOffline | 1 | Certificate Request Agent | yes | no | - | none (admins only) |
| Administrator, SmartcardUser, SmartcardLogon | 1 | include Client Auth | no | yes | yes | none |
| ClientAuth, UserSignature | 1 | include Client Auth | no | yes | yes | Domain Users |

No template had a Deny ACE. Besides the default administrators, the lab adds two groups that are not broad. Scenarios (in memory: one
ACE was added to the template named; published set = the default set of an Enterprise CA, plus the agent template where stated):

| # | Scenario | ESC3 | Target(s) named | Expected |
|---|---|---|---|---|
| S0 | default forest, EnrollmentAgent published | none | - | none ✔ |
| S1 | EnrollmentAgent: Enroll for Domain Users | Fail / High / Referenced | User | ✔ |
| S2 | ... for Authenticated Users | Fail / High / Referenced | Machine, User | ✔ |
| S3 | ... for Everyone | Fail / High / Referenced | Machine, User | ✔ |
| S4 | ... for BUILTIN\Users | Fail / High / Referenced | Machine, User | ✔ |
| S5 | ... for Domain Computers | Fail / High / Referenced | Machine | ✔ |
| S6 | ... Full Control (GenericAll) for Authenticated Users | Fail / High (plus ESC4) | Machine, User | ✔ |
| S7 | ... all extended rights (0x100, no object type) for Authenticated Users | Fail / High | Machine, User | ✔ |
| S8 | S2 with the agent template **not** published | Warning / Medium / Referenced ("[Unpublished]") | Machine, User | ✔ |
| S9 | MachineEnrollmentAgent: Enroll for Authenticated Users | Fail / High | Machine, User | ✔ |
| S10 | EnrollmentAgentOffline: Enroll for Authenticated Users | Fail / High | Machine, User | ✔ |
| S11 | S2 + **Deny Everyone Delete** (0x10000) on the agent template | **none**; summary "no review pattern matched" | - | a review item ✘ |
| S12 | S2 + Deny Everyone Delete on the User template | Fail / High | Machine only | User missing ✘ |
| S13 | S2 + Deny Domain Users **Autoenroll** on User (Enroll not denied) | Fail / High | Machine only | User missing ✘ |
| S14 | S2 + Deny Domain Users **Enroll** on User | Fail / High | Machine only | ✔ (User correctly dropped) |
| S15 | S1 + Deny Everyone Delete on the User template | **none** | - | a match ✘ |
| S16 | S1 + Deny Everyone Delete on the agent template | **none** | - | a review item ✘ |

**Verdict:** the H2/N2 fix is **verified** for every way broad enrollment is granted to an agent template on a default forest. The User
template is matched as schema version 1 with Domain Users, and Machine is matched through Domain Computers. The false negatives come
from the Deny handling (N10).

---

## New issues

### N9 (Medium) One plain-HTTP answer stops the endpoint stage: a redirect to a non-HTTP scheme on the same host
- **Where:**
  - `src/Probes/WebProbes.ps1:191-216`: the redirect check compares only the host, so `file://`, `ftp://` and `ldap://` on the
    request's own host are accepted.
  - `:152`: `[System.Net.HttpWebRequest][System.Net.WebRequest]::Create($current)` throws for a `FileWebRequest` or `FtpWebRequest`
    ("Cannot convert"), and `Create` itself throws for `ldap:` ("The URI prefix is not recognized"). The surrounding `try` has only a
    `finally`.
  - `src/Analyzers/EndpointHealth.ps1:379-380` and `:705-707`: there is no `try` per URL.
  - `src/Start-MspkiHealthCheck.ps1:168-177`: the stage catch keeps none of the stage's findings.
- **Shown:** an AIA lead `http://127.0.0.1:<port>/redir.crt` from a discovered certificate answers `302 Location: file://127.0.0.1/share/ca.crt`.
  `Invoke-MspkiEndpointAnalysis` throws. The second AIA URL of the same certificate, a normal one, is never probed, and no finding of
  the stage is returned. The same happens with `ftp://` and `ldap://` Locations. The loopback server saw one request. No SMB, FTP or
  LDAP connection is made, because the failure comes before `GetResponse`.
- **Effect:** someone who controls one plain-HTTP AIA/CDP answer can remove every AIA, CDP, OCSP and CRL result of the run, including the
  findings that would expose a forged object. Only one Run error remains ("Endpoint checks stopped"). The CES/CEP stage uses the same
  function with up to 5 redirects (`src/Analyzers/EnrollmentServices.ps1:232`), so it is affected the same way (by reading).
- **Fix:**
  - Follow a hop only when its scheme is `http` or `https`. Otherwise record it as `HTTP_REDIRECT`, not followed.
  - Never cast the result of `WebRequest.Create` without checking its type.
  - Wrap each URL probe in `Invoke-MspkiEndpointAnalysis` in its own try/catch, so that a failure becomes one finding for that URL.
  - Add the `file:` / `ftp:` / `ldap:` Locations as tests, including a check that the second URL is still probed.

### N10 (Medium) ESC3 ignores which right a Deny ACE denies
- **Where:**
  - `src/Analyzers/TemplateSecurity.ps1:127-131`: `Denied` is set by **any** Deny ACE whose SID contains the principal, whatever right
    it denies.
  - `:245` and `:252`: ESC3 drops the Denied principals on both templates, instead of keeping them as a review item.
- **Shown:** Part 3, S11, S12, S13, S15 and S16.
  - With a Deny Everyone *Delete* ACE (part of what "protect object from accidental deletion" writes) on the agent template, a High ESC3
    disappears, and the summary says "no review pattern matched".
  - With a Deny Domain Users *Autoenroll* ACE on User, the User target is dropped even though Enroll is not denied.
- **Also:** the other patterns use the same flag. An unrelated Deny turns a real ESC1/ESC2/ESC4 match into an Inferred review item. That
  over-reports rather than hiding, but it is the same defect.
- **Fix:**
  - Count a Deny ACE as possibly cancelling only when it covers the right that was granted: Enroll (control access with the Enroll GUID
    or no object type, or generic all) for enrollment, and the write rights for ESC4.
  - In ESC3, keep a Denied principal as a review item (Inferred), as the other patterns do, instead of dropping the match.
  - Add S11, S13 and S15 as tests. S14 is the negative.

### N11 (Low) An AIA URL outside the forest that answers above 10 MB counts as a working URL
- **Where:**
  - `EndpointHealth.ps1:403-411`: the AIA answer above 10 MB is Fail / `SIZE_LIMIT` (N3).
  - `Resolve-MspkiScopeStatus` (`src/Model/HostScope.ps1:52-70`): it caps a Fail to Warning for scope External/OtherForest.
  - `src/Analyzers/HierarchyHealth.ps1:82` and `:89-91`: a Warning whose code is not in the failure list counts as **Usable**, and
    `SIZE_LIMIT` is not in the list.
- **Shown:** a lead for `pki.other.example.test` (scope External) gives Warning / `SIZE_LIMIT`, and `Get-MspkiRetrievalOutcome` returns
  `Usable`. `CONTENT_WRONG_TYPE` returns `Failed`, as it should.
- **Effect:** in the retrieval-order check, such a URL can give a false "clients get it from this URL". The N3 entry of the Fix log says
  the check counts it as failed. That holds only inside the forest.
- **Fix:** count a Warning with `SIZE_LIMIT` as Failed for AIA, and as NotTested for CRLs (not read). Consider failing closed: count as
  Usable only a Warning with a code known to mean "retrieved".

### N12 (Low, pre-existing since `207770e`) Local certificate URLs are garbled when a certificate has two or more
- **Where:** `src/Discovery/LocalEvidence.ps1:83`. `Get-MspkiCertificateUrl` returns `, $out.ToArray()`, so the pipeline gets the whole
  array as one object. `Where-Object` and `ForEach-Object` then format it as one string. This is the same class as N8.
- **Shown:** one CDP URL gives `CDP: http://pki.example.test/one.crl`. One CDP and one AIA URL give `System.Object[]: System.Object[]`.
  The `Error` entries are not filtered out in that case either.
- **Effect:** only the local evidence record (`Urls`) is affected; nothing links or probes from it.
- **Fix:** `foreach ($u in (Get-MspkiCertificateUrl ...))`, and add a test with two URLs.

### N13 (Low, hardening / documentation) The TLS chain engine contacts hosts that the server certificate names
- **Where:** every TLS handshake (Part 2 rows 10 and 11), and the run limit `src/Model/RunContext.ps1:67-71` (audit 2 L1).
- **Shown:** A10. For a server certificate from an unknown issuer with an `ldap://` AIA, Windows opened 4 LDAP connections per
  handshake to the host in that URL. It sent anonymous searches only (the AIA object, `supportedCapabilities`,
  `supportedSASLMechanisms`). There was no bind and no token, even when the responder claimed to be Active Directory and offered
  GSS-SPNEGO.
- **Effect:** no credentials go out. But a TLS server reached through the scoped rules (directly, or through a same-host redirect) can make
  this computer connect to any host. The L1 text says only that Windows "may fetch missing intermediate certificates ... from the AIA",
  not that the host can be anywhere, LDAP included.
- **Fix:** state this in the run limit and in the rule 4 clarification: the hosts are chosen by the server certificate, and the access is
  anonymous (measured on Windows 11 / .NET Framework 4.8). Keep a probe like A10 as a regression test. If a later Windows build ever
  binds there, the credential guarantee breaks.

### N14 (Nit) The M14 committer self-test does not separate the old logic from the new
- **Where:** `tests/Hygiene.Tests.ps1:484-489` plants a committer e-mail address that is not the noreply address. The old test (before
  `3432c1e`) searched `%an|%ae|%cn|%ce` with the e-mail pattern, so it found that too.
- **Effect:** the Fix log's "3 red ... (committer, old content, old path)" is wrong for the committer case. The case the old logic
  really missed is a committer *name* other than `ED` with a noreply e-mail. The new logic catches it (`:404`), but no test plants it.
- **Fix:** plant `Some Name|<noreply address>` as the committer, and correct the Fix log entry.

### N15 (Nit) Lead trust defaults to Authoritative
- **Where:**
  - `src/Model/LeadRegistry.ps1:98`: the default is `-Trust 'Authoritative'`.
  - `src/Analyzers/Ndes.ps1:407`: an NDES lead derived from any lead is registered without `-Trust`, so a Verified source becomes
    Authoritative.
  - Also the constructed CES/CEP and NDES leads (`EnrollmentServices.ps1:93`, `Ndes.ps1:467-468`, `:506-507`).
- **Effect today:** none. Both trust values pass the same gates, every constructed lead is on a CA host or a host from AD, and Trust is
  not exported. It is fail-open for the next caller that forgets `-Trust`.
- **Fix:** make `-Trust` mandatory, and pass the source lead's trust in `Ndes.ps1:407`.

---

## Runs

- **Pre-fix runs:** the table in Part 1 (14 runs plus 2 derived runs: item 5 with the N8 lines corrected, and N7 with the old patterns).
- **Probes A7-A10, N9, N11, N12 and the ESC3 scenarios:** scripts in the scratch folder, run against `64ac786`; not committed.
- **Full suite at `64ac786`** (Pester 5.7.1, Windows PowerShell 5.1): **1144 run, 1143 passed, 0 failed, 1 skipped** (138 s). The skipped
  test is the private-list scan, which runs only when `MSPKI_PRIVATE_NAMES_FILE` is set. This is the same as the final run of Fix log 2.

## What was not done
- The product was not run against the lab. No code changed, and Fix log 2 records lab runs after each fix.
- N6: a live referral chase is still not shown. The serverless cross-domain group lookup was not tested (no such link in the lab).
- The LLMNR/NetBIOS fallback for LDAP binds (Part 2, residual) was not tested.
- N9 was shown on the endpoint stage. The CES/CEP stage was checked by reading only.

---

## Fix log 3

Each fix is red first: the new tests were run against the code before the fix and failed on the old behaviour (an exception, or a wrong
result), then pass after it. Hosts are `127.0.0.1` and `example.test` names only.

### N9 (Medium): a redirect to a non-HTTP scheme never throws
- **Fix:** `src/Probes/WebProbes.ps1` (`Invoke-MspkiHttpGet`). A `Location` is followed only when it is an absolute `http` or `https` URI.
  `file:`, `ftp:`, `ldap:`, `gopher:`, `javascript:` and an unreadable value are recorded as evidence: `Code = HTTP_REDIRECT`, `HttpStatus` = the
  redirect's own status (302), `RedirectNotFollowed` = the target (capped at 300 characters), and one hop. No request is sent to it. The
  request is no longer cast blindly (`WebRequest.Create(...) -as HttpWebRequest`, and the scheme of every URL is checked first), and an
  unexpected exception inside a hop becomes that URL's `RETRIEVAL_FAIL` (a cancel still reaches the caller).
  `src/Analyzers/EndpointHealth.ps1` (`Invoke-MspkiEndpointAnalysis`): each URL is probed in its own try/catch; a failure is one `Error` /
  `INTERNAL_ERROR` finding for that URL and the other URLs are still probed. The CES/CEP stage uses the same function, so it is covered too.
- **Tests:** `tests/Audit3.N9.Tests.ps1` (9). Before the fix: 8 red, all behavioural (`PSInvalidCastException` for `file:` and `ftp:`,
  `NotSupportedException` for `ldap:` and `gopher:`, `UriFormatException` for a malformed `Location`, and the stage threw so the second AIA URL
  of the same certificate was never probed). After: 9 green, and the loopback server saw exactly one request per redirect.

### N10 (Medium): ESC3 and the other patterns look at what a Deny ACE denies
- **Fix:** `src/Analyzers/TemplateSecurity.ps1`. `Get-MspkiBroadAce` marks a grant as `Denied` only when a Deny ACE for the same principal, or a
  well-known group that contains it, covers the **same right** (`Test-MspkiAceGrant -AnyType`: Enroll = control access with the Enroll GUID, no
  object type, or generic/full control; Write = the write rights of ESC4). Deny Everyone *Delete*, or a Deny of *AutoEnroll*, no longer hides
  or downgrades a match, for ESC3 or for any other pattern. A Deny that really removes Enroll still suppresses ESC3 for that principal, and
  now the summary says so: `<template>: ESC3 not reported: the target template User is not enrollable by the agent principals: a Deny ACE for
  Domain Users removes Enroll for Domain Users` (or the agent-side reason), never "no review pattern matched". Templates that match nothing
  still say that.
- **Tests:** `tests/Audit3.N10.Tests.ps1` (12): S11, S12, S13, S15 and S16 of part 3, S14 as the negative, the two summary cases, and the
  same rule for ESC1 and ESC4. Before the fix: 9 red, all behavioural (no ESC3 for S11, S15, S16; User missing for S12, S13; the summary text;
  ESC1 and ESC4 downgraded to Inferred by an unrelated Deny). After: 12 green; `TemplateSecurity.Tests.ps1`, `Audit2.Security.Tests.ps1` and
  `Audit2.Verify.Tests.ps1` stay green (156 in the four files).
- **Decision:** a Deny that covers Enroll still suppresses ESC3 (not a review item), because for ESC3 the agent and target principals are
  matched by fixed group containment and the Deny ACE comes first in a canonical ACL. The suppression is visible in the summary evidence.

### N11 (Low): an AIA answer above the size cap is not a working URL, also outside the forest
- **Fix:** `src/Analyzers/HierarchyHealth.ps1` (`Get-MspkiRetrievalOutcome`). A Warning with `SIZE_LIMIT` on an AIA is counted as **Failed** (the scope
  rule had turned the Fail into a Warning, and the old failure-code list did not name `SIZE_LIMIT`). On a CRL (not read, Information, or a
  capped Warning) it is neither working nor failing: **NotTested**. A Warning about the age of a retrieved certificate is still Usable.
- **Tests:** `tests/Audit3.N11N12.Tests.ps1`. Before the fix: 2 of the 4 N11 tests red, both behavioural (the capped AIA was `Usable`, and so was a
  capped CRL Warning). After: green.

### N12 (Low, pre-existing): local certificate URLs
- **Fix:** `src/Discovery/LocalEvidence.ps1` (`ConvertTo-MspkiLocalCertificateInfo`). `Get-MspkiCertificateUrl` returns its list as one object, so a
  pipeline treated the whole list as one item. The URLs are now enumerated with `foreach` (the same fix as N8). Two CDP and one AIA URL are
  recorded as `CDP: ...`, `CDP: ...`, `AIA: ...`; `Error` entries are filtered on every item.
- **Tests:** `tests/Audit3.N11N12.Tests.ps1`. Before: red, behavioural (1 entry, `System.Object[]: System.Object[]`, instead of 3). After: 3 entries.

### N13 (Low, documentation): the Windows chain engine and hosts named by the server certificate
- **Done:** the run limit in `src/Model/RunContext.ps1` now says the host is chosen by the server's certificate, can be any host (an `ldap://` one
  too), and that it was measured as anonymous searches and GETs only, never a directory bind; `docs/RESEARCH.md` has a section with the
  measurement and when to repeat it (after a Windows upgrade); `CLAUDE.md` rule 4 carries a clarification (a limit, not an exception).
- **Tests:** `tests/Audit3.N13.Tests.ps1` (3): the limit text, the `-SkipNetwork` case, and the two documents. The old limit text did not say
  "any host", "ldap://", "anonymous" or "never a directory bind" (red on the old text).
- **Not done:** a regression probe with a loopback TLS server and an LDAP responder (the A10 probe) is not part of the suite. It would assert
  the behaviour of the Windows chain engine, which a Windows update may change. Repeat the measurement by hand after a Windows upgrade.

### N14 (Nit): the M14 committer self-test now separates the old logic from the new
- **Fix:** `tests/Hygiene.Tests.ps1`. A new self-test plants a committer **name** that is not `ED` with the allowed noreply e-mail address, the case
  the old check really missed, asserts that the new check finds it, and runs the old logic (e-mail addresses searched with the e-mail pattern)
  on the same history and asserts that it finds **nothing**.
- **Checked:** with the identity line of the scan replaced by the old logic, the new test is red (behavioural: expected more than 0, got 0), and
  the older committer test (a committer e-mail that is not the noreply address) stays green, which confirms that it never separated the two.
  The wrong claim in `docs/AUDIT-2-VERIFY.md` ("3 red ... committer") is corrected there to 2 red.

### N15 (Nit): lead trust is fail-closed
- **Fix:** `src/Model/LeadRegistry.ps1`: `Add-MspkiLead` defaults to `-Trust Unverified`. Every discovery caller now names its source:
  Authoritative for AD, CA properties and local policy (`Register-MspkiDiscoveredLead`, the CEP leads from local policy, the NDES leads from
  template ACEs and the CA database), Verified for links in a downloaded object, and an NDES lead derived from another lead takes **that lead's
  trust** (`src/Analyzers/Ndes.ps1`). The constructed CES/CEP candidates on a CA host (standard paths, nothing proves they exist) are Unverified.
- **Tests:** `tests/Audit3.N15.Tests.ps1` (7). Before: 4 red, all behavioural (a lead without `-Trust` was Authoritative and its host trusted; the
  trust was not kept for a derived NDES lead; constructed candidates were Authoritative). The discovery test is green before and after (it guards
  against the new default breaking discovery).

### Test key leftover
- **Removed:** one leftover RSA test key container (a CNG key created by a test at 19:28 on 2026-11-22, in this user's key store, referenced by no
  certificate) was deleted with `certutil -user -csp "Microsoft Software Key Storage Provider" -delkey`. The other key in the store is a
  Windows system key and was left alone.
- **Cause:** `tests/Audit.Probes.Tests.ps1` created three server certificates with a persisted key and added them to its cleanup list only after
  all three existed; a failure while creating the second or third left the first one behind.
- **Fix:** each certificate is registered for cleanup the moment it exists, `AfterAll` removes every key with the new `Remove-TestCertificateKey`
  (`tests/TestHelpers.ps1`: CNG and CryptoAPI keys, safe to call twice), and one failing removal does not stop the others.
- **New tests:** `tests/000-KeyStoreBaseline.Tests.ps1` records the key containers and personal certificates before the suite;
  `tests/zzz-KeyStoreLeftovers.Tests.ps1` (runs last, Pester runs a folder in name order) fails when a new one exists, checks statically that
  every test file that uses `PersistKeySet` removes the key in `finally`/`AfterAll`, and has a self-test that creates a persisted key and
  proves the helper removes it. A run of the old `Audit.Probes` file in that sequence is red on the static check.

### Existing tests that relied on the old default
Three older tests added a lead without `-Trust` and expected it to be trusted (they stand for a lead from AD or a CA property): the strongest-trust
test, the redirect-host test in `Audit.Probes`, and the second-domain LDAP test in `Audit2.Verify`. They now name `-Trust Authoritative`, which is
what the source they model would pass. This is the intended effect of N15, not a regression.

### Lab run (observation only, non-elevated)
Run as the standard (non-elevated) account after all fixes: exit code 6, 99 findings, **the same tally by category, status and status code as the
last baseline run** (no difference in any bucket), 0 stage errors. Against `C:\ClaudeCode\private\LAB-FACTS.md`: 2 Enterprise CAs, 43
template objects, 3 CA certificates (the root and two generations of the sub CA), 3 and 22 published templates, an NDES host found, no
RPC failure, and the template review reports the same 4 review findings as before. No regression.

### Commits and the final run
| Item | Commit |
|---|---|
| N9, N10 | `0cb8925` |
| Test key leftover (cleanup, baseline and leftover tests; the key itself was deleted by hand) | `3dd4d58` |
| N11, N12 | `7c8939a` |
| N13 | `9bcab27` |
| N14 | `8159830` |
| N15 | `84dadff` |

**Full suite after all fixes** (Pester 5.7.1, Windows PowerShell 5.1, with `MSPKI_PRIVATE_NAMES_FILE` pointing at the private name map, so the
private-list history scan ran and found 0 names): **1186 run, 1186 passed, 0 failed, 0 skipped** (5 min 55 s). The run before the three older
tests were corrected had 3 red, all because they relied on the old default trust (see above). After the suite the key store holds the same
entries as before it (the new leftover test checks this).
