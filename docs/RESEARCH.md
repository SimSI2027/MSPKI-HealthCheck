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
| An NDES/SCEP server exists (answers GetCACaps and GetCACert anonymously, HTTP and HTTPS, valid TLS) | AD computer lookup by name; certificates published in a user object; anonymous GETs | NOT found today. In-box routes: (1) Enroll ACEs on published templates with an Enrollment Agent / CEP-Encryption EKU name a service account; its SPN `HTTP/<host>` names the host; (2) the CA database view (not available, see below) | No | C (exists) / L (route 1) |
| NDES service account is a normal user account with an `HTTP/` SPN | LDAP lookup of the account named in the template ACL | Read the account object named in a template ACE (a bounded lookup of a principal that came from AD) | No | C |
| Online Responder role installed on the Root CA host, but no certificate points to it and `/ocsp/` answers HTTP 500 | `sc.exe \\host query`, anonymous GET | Not in-box as a standard user: the service state needs admin. The HTTP 500 on a standard path of a proven PKI host is visible | Service state: yes | C |
| Root CA host runs IIS: `/certsrv/` and `/certenroll/` answer 403, HTTPS is reset on every TLS version | Anonymous GET, raw TLS handshakes | Already in scope (standard paths on proven PKI hosts); the TLS reset should be reported as "TLS handshake closed by the server" | No | C |
| Sub CA host has no web server (80/443 time out) | TCP connect | Already done (TCP probe) | No | C |
| No CES, no CEP, no Intune Certificate Connector on the CA hosts | AD `msPKI-Enrollment-Servers`, constructed candidates, `sc.exe` | Already done for AD/HTTP; the connector on a remote NDES host is not visible (remote SCM blocked by firewall) | Remote services: yes | L |
| Reverse DNS is incomplete (one PTR missing, one short name, one full name); one certificate SAN names an alias with no DNS record | `Resolve-DnsName` on A/PTR, SAN of the served certificate | D2 not done yet: resolve A, PTR, CNAME chain and compare with the certificate names | No | C |
| How this computer's certificates got here: one from a policy-driven machine enrollment (the RDS "certificate template" policy), one requested by an administrator in MMC | Certificate template extension (OID 1.3.6.1.4.1.311.21.7 / 20.2), `Microsoft-Windows-CertificateServicesClient-Lifecycle-*/Operational` events (template name+OID, thumbprint, process, account), `HKLM\...\Terminal Services\CertTemplateName`, `gpresult` | D3 not done yet. Public certificate data in `LocalMachine\My` and the template extension are readable by any user; the Lifecycle-User log is the user's own; whether the System lifecycle log is readable by a standard user is untested | Possibly (System log) | C / U |
| Autoenrollment is not configured by registry policy here; no CEP policy servers | Registry (read-only) | Already done for CEP keys (`LocalPolicy`); add the autoenrollment keys | No | C |
| Standard-user COM/RPC reads of the CA | See "RPC failure" | `CertificateAuthority.Request.GetCAProperty` (in-box) | No | see below |
| CA database view (`CertificateAuthority.View`) is NOT registered on this computer | ProgID lookup fails with class-not-registered; `certadm.dll` absent | Not available on a clean client: it ships with the AD CS management tools. The product must report "CA database not read: management tools missing" instead of an opaque CLSID error, and rely on route (1) for NDES | n/a | C |

## RPC failure (0x800706BA) - result
- Not reproducible now. As an administrator both CAs answer `certutil -ping`, `-CAInfo` and 23 of 24 `GetCAProperty` calls (the 24th, `ParentCA`,
  returns file-not-found: normal for a root). A packet capture (`pktmon`) shows the expected flow: TCP 135 answers, the endpoint mapper hands back
  one dynamic port per CA, and both ports accept.
- Earlier failures came from a standard-user account on the same computer: both CAs failed until mid-morning, then only the Root CA host failed.
  Both CA hosts were rebuilt/upgraded after the last failing run (their event logs start at that boot), so the original cause cannot be read from them.
- The dev computer and both CA hosts are on one subnet; the pfSense router is not on this path, so no router hop dropped it.
- Evidence points to a host-side state (service not registered in the endpoint mapper, or a host firewall rule) rather than the tool: 135 open +
  "RPC server unavailable" is the signature of a CertSvc/EPM or dynamic-port block. Other hosts in this lab show the same family today: the NDES host refuses
  remote service control (`1722`) and the Sub CA host refuses remote event-log reads (`1722`) while their web/DCOM ports work.
- **Open:** whether the standard-user account passes now. Run, as that account: `powershell -File <repo>\Invoke-MspkiHealthCheck.ps1 -OutputPath <repo>\out\std -NoOpen`
  and send back `run.log` lines `CA connection string ... Answered|Failed`. If it fails while the admin passes, capture with `pktmon start --capture -f 10.x` on the dev
  computer during the run and look for a SYN to the dynamic port with no answer (host firewall) versus an RST (service not listening).
- **If it recurs, fix on the CA host (owner action, nothing was changed):** (1) `sc query certsvc` must be RUNNING; (2) `netsh advfirewall firewall show rule name=all dir=in`
  must allow "DCOM-In" (TCP 135) and the CertSvc dynamic-port group ("Active Directory Certificate Services (RPC)") from the dev subnet; (3) any
  host or network firewall must allow TCP 49152-65535 to the CA; (4) `certutil -config "<host>\<CA>" -ping` from the dev computer must return "alive".

## What a standard user and an administrator can see
- The administrator account here is the domain's built-in administrator, which gets no filtered token: `runas /trustlevel:0x20000` still reports High
  integrity and the same network identity, so it is NOT a standard-user test. A real standard domain account is needed.
- Same engine, two runs: the admin run and the earlier standard-user run found identical AD-side facts (containers, 43 templates and ACLs, CA certificates,
  leads, LDAP CDP/AIA reads). The only difference was the Root CA read (host-side failure at the time, not proven user-dependent).
- Needs admin (research only, the product never does it): remote service state, remote event logs, remote WMI/CIM, the CA registry.
- Does not need admin: AD Configuration partition, template ACLs, anonymous web probes, certificates in the stores (public parts), `GetCAProperty`.

## Product findings from this research (not yet fixed unless marked)
1. FIXED: the endpoint stage crashed on every run with a CA that answers (`Cannot convert value "<date>" to type Int32`): analysers read the JSON-safe CA summary
   (string dates) instead of the decoded CRL. Now they receive the live properties (`CAProperties`, not exported). Test added.
2. A CDP LDAP URL with no attribute part (as the CA writes it) is graded Fail/`RETRIEVAL_FAIL` although Windows accepts it (default attribute). False Fail, exit 4.
3. NDES is reported as "not discovered" although it answers: add the template-ACE/SPN route; report the missing CA database view in words.
4. alias SAN names with no DNS record, missing PTR records, and an HTTPS port that resets are real, reportable facts (D2).
5. `CertificateAuthority.View` is not in-box on clients: CLAUDE.md rule 5 and REQUIREMENTS list it as in-box; they should say "if the management tools are installed".
