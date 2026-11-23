# Lab research: what exists, how it was found, how the product can find it in-box

Sanitised: roles only ("Root CA", "Sub CA", "NDES host", "dev computer"). Real names live in a private file outside the repo.
Research used admin rights and in-box tools (`certutil`, `pktmon`, `sc.exe`, `nltest`, `Get-WinEvent`, ADSI). The product must reach the
same facts as a normal user on Windows PowerShell 5.1 with nothing installed. "Admin?" = needs administrator rights on this computer
or on the remote host. Confidence: C = confirmed by direct observation, L = likely (indirect), U = untested.

## Lab shape (one forest with two trees, one inbound forest trust, two Enterprise CAs, one NDES host, all on one subnet)
| Fact | How found (research) | How the product finds it in-box as a normal user | Admin? | Conf. |
|---|---|---|---|---|
| Forest, domains, trusts (tree root in the same forest, one inbound forest trust) | `nltest /trusted_domains`, .NET `Forest`/`Domain` | Already done: `AdContext` (`Forest`, `Domain`, trusts) | No | C |
| Exactly two Enterprise CAs (a Root, a Subordinate) | AD Enrollment Services container | Already done: `EnterpriseCAs` | No | C |
| Root CA self-signed; Sub CA issued by it; the Sub CA has two certificate generations, the older one only in NTAuth, not in AIA | ADSI dump of Certification Authorities, AIA, NTAuth, Enrollment Services | Already done (`CACertificates`); the "Unknown" lifecycle and the warning are correct | No | C |
| Every CA/CRL URI is LDAP only: no HTTP CDP/AIA, no OCSP URI | Certificate extensions + CA properties 41-43 | Already done (leads); CA property read needs RPC to the CA, the certificate extensions do not | No | C |
| CRLs: AD copy and the CA's own copy have the same number; base/delta freshness | `certutil`-free: CA properties 17/18 and the AD CDP objects | Already done once the CRL-stage bug (below) was fixed | No | C |
| Standalone/offline CA | None exists here | Cannot be found from AD alone (only the certificates in AD); a standalone root shows as "seen in AD only" | No | U |
| An NDES/SCEP server exists (answers GetCACaps and GetCACert anonymously, HTTP and HTTPS, valid TLS) | AD computer lookup by name; certificates published in a user object; anonymous GETs | DONE (WP3): found as a standard user through route (1); was NOT found before. In-box routes: (1) Enroll ACEs on published templates with an Enrollment Agent / CEP-Encryption EKU name a service account; its SPN `HTTP/<host>` names the host; (2) the CA database view (not available, see below) | No | C (exists) / L (route 1) |
| NDES service account is a normal user account with an `HTTP/` SPN | LDAP lookup of the account named in the template ACL | Read the account object named in a template ACE (a bounded lookup of a principal that came from AD) | No | C |
| Online Responder role installed on the Root CA host, but no certificate points to it and `/ocsp/` answers HTTP 500 | `sc.exe \\host query`, anonymous GET | Not in-box as a standard user: the service state needs admin. The HTTP 500 on a standard path of a proven PKI host is visible | Service state: yes | C |
| Root CA host runs IIS: `/certsrv/` and `/certenroll/` answer 403, HTTPS is reset on every TLS version | Anonymous GET, raw TLS handshakes | Already in scope (standard paths on proven PKI hosts); the TLS reset should be reported as "TLS handshake closed by the server" | No | C |
| Sub CA host has no web server (80/443 time out) | TCP connect | Already done (TCP probe) | No | C |
| No CES, no CEP, no Intune Certificate Connector on the CA hosts | AD `msPKI-Enrollment-Servers`, constructed candidates, `sc.exe` | Already done for AD/HTTP; the connector on a remote NDES host is not visible (remote SCM blocked by firewall) | Remote services: yes | L |
| Reverse DNS: DNS holds NO PTR record for any lab host (DNS-only lookups, also the DC). The "short name" and "full name" seen earlier came from NetBIOS / .NET name resolution, not DNS. One certificate SAN names an alias with no DNS record | `Resolve-DnsName -Type PTR -DnsOnly` vs. without `-DnsOnly` vs. .NET `Dns.GetHostEntry(IP)`; SAN of the served certificate | DONE (D2): `Resolve-DnsName -DnsOnly` (in-box DnsClient), .NET fallback reported as Inferred | No | C |
| How this computer's certificates got here: one from a policy-driven machine enrollment (the RDS "certificate template" policy), one requested by an administrator in MMC | Certificate template extension (OID 1.3.6.1.4.1.311.21.7 / 20.2), `Microsoft-Windows-CertificateServicesClient-Lifecycle-*/Operational` events (template name+OID, thumbprint, process, account), `HKLM\...\Terminal Services\CertTemplateName`, `gpresult` | DONE (WP4): stores, template extension, Lifecycle logs, policy cache. A standard user CAN read both Lifecycle logs here | No | C |
| Autoenrollment is not configured by registry policy here; no CEP policy servers | Registry (read-only) | Already done for CEP keys (`LocalPolicy`); add the autoenrollment keys | No | C |
| Standard-user COM/RPC reads of the CA | `pktmon` capture, `certutil -ping` as each account | `GetCAProperty` (in-box); a quick 0x800706BA after TCP 135 is now reported as an Inferred refusal of this account | No | C |
| CA database view (`CertificateAuthority.View`) is NOT registered on this computer | ProgID lookup fails with class-not-registered; `certadm.dll` absent | Not available on a clean client: it ships with the AD CS management tools. The product must report "CA database not read: management tools missing" instead of an opaque CLSID error, and rely on route (1) for NDES | n/a | C |

## RPC failure (0x800706BA) - result (SOLVED 2026-11-21 evening)
- **Answer: the Root CA host refuses the ordinary domain account at the DCOM layer. It is a per-account permission on that host, not the network,
  not the CA service and not this tool.** Reproduced as the standard domain account, both from an elevated and a `runas /trustlevel:0x20000` token
  (same result: the remote side sees the same domain identity, so local elevation does not matter). The Sub CA answers the same account in the
  same run; the domain administrator account reads both CAs. `certutil -ping` as the standard account gives the same 0x800706BA in 15 ms.
- Packet capture (`pktmon`, dev computer, filtered to the Root CA host): the client connects to TCP 135 three times. The second connection does a Kerberos
  bind and sends the DCOM activation request; the host answers with a 32-byte RPC **fault PDU, status 0x00000005 (access denied)**, and closes the
  connection. The third connection (fallback authentication) gets the same fault. **No connection to a dynamic port is ever attempted.** The DCOM
  client then reports this to the caller as `RPC_S_SERVER_UNAVAILABLE` (0x800706BA), which is why the message was misleading.
- Kerberos tickets were fresh (`RPCSS/<host>` issued for both CA hosts); only the Sub CA host also got a `host/` ticket for the second hop.
- Earlier morning failures (both CAs, then only the Root CA host) fit the same cause; the Sub CA host was rebuilt and now admits the account.
- **What the product now says (in-box, no admin):** a 0x800706BA that comes back within 5 s after TCP 135 answered is reported as
  `PERMISSION_DENIED`, confidence **Inferred** (the fault code itself is not visible to the COM API), with the measured time, a note that a blocked dynamic
  port would take many seconds, and, when another CA answered the same account in the run, that fact as evidence. A slow 0x800706BA stays
  `RETRIEVAL_FAIL` with the firewall explanation. (`Get-MspkiCaRpcFailureDiagnosis`, tests in Discovery and Audit.Grading.)
- **Owner fix steps on the Root CA host (nothing was changed by us):** (1) `lusrmgr.msc` > Groups > "Certificate Service DCOM Access" must contain
  Authenticated Users or Domain Users (CA setup adds it; a rebuild/upgrade can lose it); (2) `dcomcnfg` > Component Services > Computers > My Computer >
  Properties > COM Security: "Edit Limits" for Access and for Launch and Activation must allow that group Remote Access / Remote Activation;
  (3) System log on the CA host: DCOM events 10027/10028/10036 at the time of a failing run name the account and the reason; (4) CA console >
  Properties > Security: Authenticated Users need Read or Request Certificates; (5) from the dev computer as the standard account:
  `certutil -config "<host>\<CA>" -ping` must say "interface is alive".
## What a standard user and an administrator can see
- The administrator account here is the domain's built-in administrator, which gets no filtered token: `runas /trustlevel:0x20000` still reports High
  integrity and the same network identity, so it is NOT a standard-user test. The evening runs used the standard domain account (see above).
- Same engine, two runs: the admin run and the earlier standard-user run found identical AD-side facts (containers, 43 templates and ACLs, CA certificates,
  leads, LDAP CDP/AIA reads). The only difference is the Root CA read: proven user-dependent (DCOM access denied for the standard account).
- Needs admin (research only, the product never does it): remote service state, remote event logs, remote WMI/CIM, the CA registry.
- Does not need admin: AD Configuration partition, template ACLs, anonymous web probes, certificates in the stores (public parts), `GetCAProperty`.

## Product findings from this research (not yet fixed unless marked)
1. FIXED: the endpoint stage crashed on every run with a CA that answers (`Cannot convert value "<date>" to type Int32`): analysers read the JSON-safe CA summary
   (string dates) instead of the decoded CRL. Now they receive the live properties (`CAProperties`, not exported). Test added.
2. FIXED: A CDP LDAP URL with no attribute part (as the CA writes it) is graded Fail/`RETRIEVAL_FAIL` although Windows accepts it (default attribute). False Fail, exit 4.
3. NDES is reported as "not discovered" although it answers: add the template-ACE/SPN route; report the missing CA database view in words.
4. PARTLY FIXED: SAN names with no DNS record and an HTTPS port that resets are now reported; missing PTR records wait for D2.
5. `CertificateAuthority.View` is not in-box on clients: CLAUDE.md rule 5 and REQUIREMENTS list it as in-box; they should say "if the management tools are installed".

## WP2 endpoint identity (D2): adversarial check (2026-11-21, standard user, sanitised)
- **Round 1.** Generator: full run as the standard user. Discriminator against the private lab facts:
  - false positive / duplicate: this computer appeared twice (its certificate SAN holds the single-label name, which DNS completes to the
    same FQDN), so its identity findings were doubled. Fixed: such a name gets `resolvesTo` (Source `DNS:SuffixSearch`) and no findings.
  - unclear explanation: the Sub CA host, where no web server answers (80/443 filtered), was reported as "Web Enrollment not found",
    as if a server had answered 404. Fixed: the finding now says "no web server answered at all" and lists what each URL gave.
  - wrong lab fact, not a tool error: the private notes said the Root CA host has a short-name PTR. A DNS-only lookup shows no PTR at all;
    the short name came from NetBIOS. The tool (DNS only) was right; the notes were corrected.
  - crash: duplicate keys when merging finding parameters (`Sources`, `Target`, `Confidence`); fixed before any result was judged.
  - expected gap (WP3): the NDES host is not in the graph yet, because nothing in AD names it and the CA database view is unavailable.
- **Round 2.** Every Identity / Web Enrollment result matches the lab: Web Enrollment on the Root CA host (HTTP 403, HTTPS closes the
  handshake, Server `Microsoft-IIS/10.0`; Inferred), none on the Sub CA host, no PTR for any address (Information, Confirmed), the dead
  SAN alias (no DNS record), A records for every host. No false positives, no wrong confidence. The lab has no CNAMEs, no wrong PTR and
  no ESC8 exposure, so those paths are proven by unit tests only (`tests/EndpointIdentity.Tests.ps1`).

## WP3 NDES without the CA database view (D4): adversarial check (2026-11-22, standard user, sanitised)
- **Before:** NotDiscovered (Unknown). The Root CA refuses DCOM for this account and the CA database reader is not registered on the dev
  computer, so the only NDES route was closed: a false negative.
- **Round 1.** Template route added. Discriminator: (a) false negative remained: the two `HTTP/` SPNs of the NDES service account came back
  as one string joined by a space (a wrapped LDAP value list), so the "host" did not resolve; (b) the missing CA database reader was shown as
  an opaque CLSID error. Fixed both (plain message: "the CA database reader is not installed on this computer").
- **Round 2.** NDES host Confirmed (GetCACaps + GetCACert, HTTPS, valid TLS), classification before the probe ProbableCandidate, found from
  the NDES service account (a user account with `HTTP/<host>` SPNs) that holds Enroll on the two NDES RA template copies. Discriminator:
  (a) false positive: "a certificate returned by GetCACert has expired" - with several certificates the parsed list was wrapped once more and
  every field became an array (pre-existing bug, hidden because no NDES had ever answered); (b) wrong relation: the service `enrollsVia` the
  Root CA as well, although the Root certificate is only the chain; (c) RA certificate template not decoded. All fixed: `enrollsVia` only the
  CA whose SKI is the RA certificates' AKI; the v2 template extension is decoded (another wrapped DER child list).
- **Round 3.** Matches the lab: CA + Root + two RA certificates (signing = Enrollment Agent copy, encryption = CEP Encryption copy) issued by
  the Sub CA; no expiry; the second account in the template ACLs (an RA user per the private notes) is not readable by the standard user and is
  reported as "deleted, or this account may not read it" (never "deleted"). Wrong confidence: none.
- Also found in this package: the graph listed an "Intune Certificate Connector on this computer" (Seen, Confirmed) although nothing matched
  (`@(0).Count` is 1). Fixed; tested.
- **Intune Certificate Connector (lab):** none on this computer (checked locally: services, installed products, certificates). On the NDES host
  it cannot be checked: the product reads only the local computer, and remote service control is blocked there anyway. Not installed on the CA hosts.

## WP4 local evidence (D3): what a standard user can read, and the adversarial check (2026-11-22, sanitised)
| Source | Readable as a standard user here | Used for |
|---|---|---|
| `Cert:\CurrentUser\My`, `Cert:\LocalMachine\My` (public parts) | Yes | template extension, issuer (AKI), EKU, DNS names, URLs |
| `Cert:\LocalMachine\Root`, `\CA`, `\NTAuth` (logical stores) | Yes | did AD's Certification Authorities / AIA / NTAuth reach this computer |
| `HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\{Root,CA,NTAuth}\Certificates` (key names only) | Yes | which copies came from AD (Enterprise physical store) |
| `CertificateServicesClient-Lifecycle-System/Operational` | Yes (was untested before) | enroll / delete / expire events: template name + OID, thumbprint, process, account, context |
| `CertificateServicesClient-Lifecycle-User/Operational` | Yes | the same for user certificates |
| Application log, AutoEnrollment / CertEnroll providers | Yes | expiry warnings (event 64), enrollment failures |
| `HKLM` / `HKCU\...\CertificateTemplateCache` | Yes | when autoenrollment last downloaded the templates, which templates |
| `...\Policies\...\AutoEnrollment` (AEPolicy), `...\Terminal Services\CertTemplateName` | Yes | autoenrollment policy, Remote Desktop certificate template policy |
- **Round 1.** Every result matched the private lab facts: the Remote Desktop certificate was enrolled by Windows (svchost, machine context) for the
  Remote Desktop template policy; the web server certificate was a manual request in the Certificates console by the administrator; Root, CA and
  NTAuth hold everything AD publishes (including the older Sub CA generation in NTAuth, from the Enterprise store). One wording problem: an old
  autoenrollment expiry warning for a certificate that is no longer present was reported as STALE_DATA (raises the exit code for history). Fixed (OK).
- **Round 2.** No false positives or negatives found; confidence: Confirmed only where the event and the policy agree, Inferred for a background
  enrollment without a policy that names the template, or a certificate with no Lifecycle event.
- The Lifecycle logs also show deleted certificates of an earlier CA with another name (history). They are listed in the lifecycle summary;
  turning them into stale-reference leads is left for later.

## TLS handshakes: the Windows chain engine contacts hosts the server certificate names (audit 3 N13, measured 2026-11-22)
- **What happens.** When this tool opens a TLS connection (a TLS probe, an HTTPS request, CES/CEP, NDES, Web Enrollment) and the server's
  certificate chain is not complete or not trusted, the Windows chain engine (CryptoAPI, inside `SslStream` / `HttpWebRequest`) may fetch
  the issuer certificate from the **AIA of the server's certificate**. That AIA can hold an `ldap://` or an `http://` URL, and the host in it
  can be **any host**, inside the forest or not. This tool does not choose it, bound it, cache it or log it.
- **What was measured** (Windows 11, .NET Framework 4.8, a TLS server on the loopback interface whose certificate carried an `ldap://`
  AIA that pointed at a loopback responder claiming to be Active Directory and offering GSS-SPNEGO): the engine opened about four connections
  per handshake. Every message was an **anonymous search** (the AIA object, `supportedCapabilities`, `supportedSASLMechanisms`) or an
  unbind. There was **no bind request and no Kerberos or NTLM token**. Building a chain with revocation checking off behaves the same.
- **What it means.** No Windows credentials go to that host through this path. But a TLS server that the tool reaches under its own rules
  (directly, or through a redirect to the same host) can make this computer open anonymous connections to a host it names. Rule 4 of
  `CLAUDE.md` (bounded discovery) does not cover that, because the connection is made by Windows, not by this tool.
- **What the tool does.** The run limits of every run that makes network checks say so ("Run limits" in the report and the window).
  With `-SkipNetwork` no TLS handshake is made. If a later Windows build ever binds on that path, the credential guarantee would be
  broken: repeat this measurement after a Windows upgrade (a loopback TLS server with an `ldap://` AIA, and a responder that records only
  the operation types and never a token).

## Batch H: "Probable causes and next steps" checked against the lab (2026-11-22, standard user, sanitised)
- **Setup.** A normal-user run of the product (99 findings, exit code 6, the same finding tally as before the change) and the lab facts kept outside the repository. Every non-passing
  finding (27 of 99) now has the section; the 72 others are passing or informational all-clear results. The check compared the top-ranked cause of each finding with the real cause.
- **Round 1.** Wrong or weak rankings found and fixed: (a) the NTAuth-versus-AIA warning blamed a CA renewal, but the lab fact is a Sub CA rebuilt with the same name (a new key); the
  tool's own evidence ("lifecycle Unknown": the CA does not list that certificate among its signing certificates) separates the two, so "earlier installation" is now ranked first
  on that evidence, and a new topic covers the two-certificates-no-clear-split warning the same way; (b) Web Enrollment "no web server answered" claimed more than a timeout can show: on
  a CA host with no web server both a missing role and a filtering firewall give a timeout, so the hint is weak and only a refusal raises "missing role".
- **Round 2.** Overclaims found and fixed: (a) a signal fired on the standing explanation in a finding's Notes ("an administrator account read the same CA") and showed it as something observed in
  this run; signals now see only the message, the evidence and the layer results; (b) "most likely" was shown even when the only supporting observation was weak; the wording now follows
  the support of each cause ("Most likely" only when something observed backs it, otherwise "Most common"); (c) the CES Kerberos cause fired for every CES failure instead of an HTTP 401.
- **Round 3.** No wrong top cause left. Matches the lab: the Root CA refusal ranks the DCOM access group of the CA host first (the lab cause, a per-account DCOM permission); the HTTPS
  reset ranks "an HTTPS binding without a usable certificate" first; the unused Online Responder (HTTP 500 on its path) ranks "role installed, OCSP URL never published" first; the
  LDAP-only CDP/AIA ranks "LDAP only by choice" first; the dead certificate alias ranks "never created" first; the Intune connector is reported as "not checked from here", never as fine.
- **Limits left.** The ranking cannot see what only the CA host or a domain controller knows (its registry, event logs, firewall); the section says so by listing checks for the PKI owner. PTR
  causes and the template/KRA topics are "Typical" (no observation separates the causes).
