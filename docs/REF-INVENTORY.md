# REF inventory: the previous toolkit (v2.5.0)

Summary of `ref/` (one ~7,900-line script with a WinForms GUI, a headless mode and a self-test).
Ideas only: no code is copied, and no environment names are carried over. Examples use `example.test`.

## Overall shape
- One file: helpers → AD/LDAP → certificate and DER parsing → HTTP/TLS probes → "health plan" → exports → GUI.
- Global `$script:State` holds everything (context, caches, results). Results are table rows added by one
  `Add-HealthResult` function (Status, Category, Target, Check, Endpoint, Result).
- Depends on a JSON **environment configuration file** (endpoint folders, expected CES URLs, extra hosts,
  legacy hosts, thresholds). The template for that file embeds real host names. **Avoid**: this project has
  no config file and every lead comes from discovery.

## Discovery (AD)
- Does: RootDSE via `DirectoryEntry` (`configurationNamingContext`, `rootDomainNamingContext`,
  `defaultNamingContext`, `dnsHostName`), then one-level `DirectorySearcher` queries under
  `CN=Public Key Services`. Forest/domain names are built by splitting the DN.
- Keep: RootDSE as the seed; one-level searches with explicit property lists; `PageSize`; requesting the
  DACL only (`SecurityMasks = Dacl`) for templates; reading `cACertificate` from Enrollment Services, AIA,
  Certification Authorities and NTAuth and indexing all certificates by thumbprint.
- Avoid: no `ClientTimeout`/`ServerTimeLimit` on searches; forest name derived from a DN instead of
  `System.DirectoryServices.ActiveDirectory`; no trusts or site context; failures only logged as warnings
  (they never become a result row); "primary" CA certificate picked by latest `NotAfter` only.

## CA checks
- Does: TCP 135 test, then `certutil -config <host\CA> -ping`, `-cainfo`, `-getreg CA\...` (publication
  URLs, delta CRL period), `-getcrl` to a temp file; remote service state via `ServiceController`.
- Keep: TCP pre-check before any RPC call; a hard timeout around every CA call; parsing the CA's own CRL.
- Avoid: `certutil` as the main engine (AV/EDR noise, localised output, temp files outside `out/`).
  Replace with `CertificateAuthority.Request.GetCAProperty` (CA type, signing-cert count and each
  generation, cert/CRL state, base/delta CRL, CDP/AIA/OCSP URLs). Remote `ServiceController` needs admin
  rights and is not evidence of health. `-getreg` registry reads are out of scope (needs CA admin).

## Certificates and chains
- Does: `X509Certificate2` from bytes, SHA-256 thumbprint, key info, extensions as text, days left,
  template name from the template extensions, `X509Chain` with `NoCheck` or `Online` revocation.
- Keep: chain build with explicit revocation mode and `UrlRetrievalTimeout`; disposing chain objects;
  SHA-256 thumbprint alongside SHA-1.
- Avoid: one "primary" cert per CA; generations (CA Version extension, previous-CA-hash) not modelled.

## DER / CRL parsing
- Does: a small pure-PowerShell DER reader (header, children, OID, time, integer) to decode CRLs
  (issuer, thisUpdate, nextUpdate, CRL number, delta indicator, revoked count), PEM-or-DER input, AIA
  access methods, CDP general names, SAN DNS names, ECDSA signature conversion and CRL signature check.
- Keep: the approach (own ASN.1 reader, no `certutil -dump`); percentage-of-lifetime freshness; CRL
  signature verified against the issuer's public key; tolerating PEM input.
- Avoid: thresholds coming from the config file; silent `catch {}` blocks that hide parse errors.

## HTTP / AIA / CDP / OCSP
- Does: `HttpWebRequest` one request per hop with `AllowAutoRedirect = $false`, timeouts, size cap,
  system proxy, `UseDefaultCredentials = $true`, `KeepAlive = $false`; separate verdicts for DNS,
  redirect, status code, content; folder-listing parsing to explain "file present but not served"
  (IIS MIME / double-escaping hints); ICMP ping for extra hosts.
- Keep: manual redirect following with every hop recorded; size cap; per-host DNS cache; content
  validation (is it the right certificate/CRL); helpful IIS hints as `Notes`.
- Avoid: default credentials on every request (send none unless a check needs it, and never to
  `/certsrv/mscep_admin/`); ICMP ping (not evidence, often blocked); URLs **built** from configured
  "mirror" folders and host aliases (only probe leads from AD, CA, certificates, CRLs or policy).

## TLS
- Does: a HEAD request over HTTPS and reads the server certificate from `ServicePointManager`.
- Keep: standard Windows validation result reported as a TLS trust result.
- Avoid: the `ServicePoint` cache trick (stale certificates between runs); trust failure, name
  mismatch and partial chain merged into one message. Use a `TcpClient` + `SslStream` callback that
  records `SslPolicyErrors` and chain status separately, with a timeout.

## Templates
- Does: reads templates with the DACL, resolves SIDs through a batch cache, decodes rights
  (GenericAll, WriteProperty, WriteDacl, WriteOwner, ExtendedRight with the Enroll/AutoEnroll GUIDs),
  flags: enrollee-supplies-subject, Any Purpose/no EKU, request-agent EKU, broad write ACL, single
  property write, no security extension, RSA key < 2048, exportable key.
- Keep: ACE decoding with `ActiveDirectorySecurity`; schema-GUID resolution for property writes; one SID
  cache per run; "broad principal" test by well-known SID/RID; listing the principals in the result.
- Avoid: single-flag findings (exportable key, no security extension, key size) reported as if they were
  attack paths; no check that the template is published by an active CA; ESC3 without the second
  template; no ESC13 (`msDS-OIDToGroupLink`). Rules in REQUIREMENTS §5.5 replace these.

## CEP / CES
- Does: CEP URLs from `HKLM`/`HKCU\Software\Policies\Microsoft\Cryptography\PolicyServers\*\URL`; CES URLs
  from `msPKI-Enrollment-Servers` (regex for `https?://`); a SOAP `GetPolicies` POST to CEP and parsing of
  the policy response; expected CES URLs from the config file.
- Keep: the policy registry paths; taking CES URLs from AD rather than building them.
- Avoid: dropping the priority / auth-type / renewal-only fields of `msPKI-Enrollment-Servers`; a SOAP
  POST by default (keep it as a later opt-in, GET-level reachability first); config-file CES lists.

## NDES / SCEP
- Does: `GET mscep.dll?operation=GetCACaps/GetCACert` on configured hosts (base URL built as
  `https://<host>/certsrv/mscep/mscep.dll`); a CA-database query with `certutil -view` (restrict by
  template/requester/date, CSV parsing, row cap) to list certificates issued through SCEP.
- Keep: only the two read-only SCEP operations; a row cap; showing evidence per host.
- Avoid: hosts from the config file; `certutil -view` (use `CertificateAuthority.View`, read-only);
  "planned server" labels; any request to `mscep_admin` with credentials.

## Legacy / stale references
- Does: compares everything against a config list of "legacy hosts" (CAs, URLs, CES, AD objects) and
  reports blockers.
- Keep: the idea of listing every place that still points at a host, with counts.
- Avoid: the decision coming from a hand-made host list. REQUIREMENTS §5.9 classifies from evidence.

## Exports and GUI
- Does: CSV (own field quoting), Excel via COM, HTML tables with inline CSS, file names from forest
  label + timestamp; WinForms GUI with tabs, grids, filters, dialogs, cancel button, themes.
- Keep: inline CSS, no external resources; per-run timestamped names; Ctrl+C / cancel checks between probes.
- Avoid: Excel COM; GUI in the same file as the engine; writing outside the output folder.

## Self-test
- Does: in-script `Invoke-SelfTest` building synthetic DER certificates/CRLs and sample CEP responses.
- Keep: synthetic fixtures built at test time. Move to Pester tests with `example.test` data.

## Risky patterns found (counts in v2.5.0)
| Pattern | Count | Decision |
|---|---|---|
| `Add-Type -AssemblyName` | 5 | Not needed: use in-box types; load extra assemblies via the manifest only if required |
| `certutil` calls | ~15 call sites | Replace with COM/.NET; only the opt-in uses in REQUIREMENTS |
| `FromBase64String` | 1 (PEM input) | Data decoding only, never code; prefer DER / `X509Certificate2` PEM support |
| ICMP `Ping` | several | Drop |
| `Invoke-Expression`, encoded commands, downloads | 0 | Keep it that way |
| Real host names in the embedded config template | yes | Never copy |

## Gaps vs REQUIREMENTS
1. No finding model: no Sources array, no Confidence, no per-layer statuses, no stable status codes.
2. No lead registry, no URL normalisation/dedup with merged sources, no depth or lead cap.
3. No Scope (Local / OtherForest / External) and no trust discovery.
4. CA generations and current vs historical certificates not modelled; CA type never confirmed.
5. Permission failures and infrastructure failures are mixed; failures often logged, not reported.
6. Template rules are single-flag; ESC3 second template, ESC9, ESC13 and published-state missing.
7. CEP/CES classification (Configured/Discovered/ConstructedCandidate/ConfirmedResponding) missing.
8. NDES candidate evidence from the CA database uses `certutil`; Intune Connector only via config hosts.
9. No JSON output, no run metadata (user context, admin yes/no, stage timings, methods tried), no exit codes.
10. Stale references depend on a manual list instead of evidence.
