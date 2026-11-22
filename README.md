# MSPKI Health Check

A read-only health check for Microsoft Active Directory Certificate Services (AD CS).

Run it on any domain-joined Windows computer with Windows PowerShell 5.1 in Full Language mode (on a computer where AppLocker or Windows Defender Application Control forces Constrained Language Mode, it says so and stops; your administrator may need to allow or sign the scripts). It needs no configuration file,
no installation and no external modules. It discovers the PKI by itself from Active Directory, the CAs,
certificates, CRLs and local policy, then checks:

- Certification Authorities, CA certificates (every generation) and the hierarchy
- CRLs (base and delta) and the AIA / CDP / OCSP locations they publish
- Certificate templates (defensive configuration review)
- Certificate Enrollment Policy / Enrollment Web Services (CEP/CES), NDES/SCEP
- The Intune Certificate Connector (local computer only)

Every result states where it came from and how sure the tool is: **Confirmed**, **Referenced**,
**Inferred** or **Unknown**. An inferred result is never shown as confirmed.

## Usage

```powershell
.\Invoke-MspkiHealthCheck.ps1
.\Invoke-MspkiHealthCheck.ps1 -OutputPath D:\Reports -TimeoutSeconds 10
.\Invoke-MspkiHealthCheck.ps1 -SkipNetwork            # read AD only, contact no other host
.\Invoke-MspkiHealthCheck.ps1 -NoOpen                 # do not open report.html at the end (it opens by default in an interactive session, never in a scheduled task)
```

Two opt-in switches are off by default: `-UseSystemProxy` (the web checks use the system proxy settings, without
credentials; by default they connect directly, so no proxy and no automatic proxy detection is involved) and
`-IncludeNdesAdminProbe` (also send the one anonymous request to the NDES admin page, see Safety).

Thresholds are parameters with defaults: `-RootCaWarningDays 730`, `-RootCaCriticalDays 365`,
`-IssuingCaWarningDays 180`, `-IssuingCaCriticalDays 90`, and CRL lifetime percentages
`-RootCrlWarningPercent` / `-IssuingCrlWarningPercent` (75) and `-RootCrlCriticalPercent` /
`-IssuingCrlCriticalPercent` (95). `-CrlPublicationGraceMinutes` (60) separates a CDP location that is only
behind (STALE_DATA) from one where publication failed (PUBLICATION_FAIL).

Output goes to `out\<yyyyMMdd-HHmmss>\`: `results.json`, `findings.csv` (opens in Excel), a single offline
`report.html` (summary, Discovery Map, filterable findings with source, confidence and evidence, run details) and
`run.log`.

To see what the report looks like without a domain, run the demo (it uses sanitised `example.test` data only):

```powershell
.\demo\Invoke-MspkiDemo.ps1 -Open       # writes out\demo\report.html and findings.csv
```

Exit codes: `0` passed · `2` informational · `3` warnings · `4` failures · `5` incomplete (unsupported or
error) · `6` incomplete (permissions).

## Using the GUI

If you prefer a window to a command line, start it from a normal Windows PowerShell 5.1 prompt (the blue one, not PowerShell 7):

```powershell
.\Start-MspkiHealthCheckGui.ps1
```

If it says it needs a single-threaded session, start it as `powershell.exe -STA -File .\Start-MspkiHealthCheckGui.ps1`.

- **Run** starts the same read-only check as the command line and writes the same four files (`results.json`, `findings.csv`,
  `report.html`, `run.log`) to a new folder under `out\`. The window stays usable while it runs: the progress bar and the line
  under it show the current step, and the **Run Log** tab shows the log live (errors in red).
- **Cancel** stops the run within a few seconds. What was found so far is still saved and shown, marked as partial. Closing the
  window during a run does the same and then closes by itself.
- **Open results.json...** shows an earlier run without scanning anything. **Open HTML report** and **Open output folder** open
  the files of the run on screen.
- **Options**: the timeout for each probe, *Skip network* (read Active Directory only), *Use the system proxy* and *Also probe the
  NDES admin page*. These are the same switches as on the command line and all start switched off.
- **Summary**: forest, domain, the domain controller used, who ran it and whether that account is an administrator, a coloured
  tile per status, and the CAs that were found. **Discovery Map**: a tree of forest, CAs, CA certificates and their endpoints,
  templates, CES and NDES, each with its status and confidence. **Findings**: every finding in a table you can search, filter
  by status, category and confidence, and sort by clicking a column heading. **Details**: select a finding to see all of it
  (sources, evidence, the DNS/TCP/TLS/HTTP/redirect/content/chain results, remediation, notes).
- **Objects** (Ctrl+5): everything the run found (forest, domains, CAs, CA certificates, CRLs, URLs, hosts, PKI services,
  templates, certificates on this computer, AD objects, accounts), grouped by type, with a search box, a type filter and
  "Only objects that need attention". Select one to see what it is and why it matters, its properties, **where it exists** (every
  place it was read or named, with confidence and time) and, in an amber block of its own, **where it is expected but missing**.
  A host also shows its identity: addresses, reverse DNS, the alias (CNAME) chain, the names in its TLS certificate and its web
  server header. Related objects are links (for example certificate > issuer > CRL > URL > host); a path at the top and **Back**
  take you back.
- The same object view opens from a finding (its objects are listed under "Objects this finding is about"), from a Discovery Map
  item, from the Overview tiles (they open the Objects page for that type) and from a CA card.
- **PKI services** (Ctrl+6): one card each for Web Enrollment, CES, CEP, NDES/SCEP, OCSP and the Intune Certificate Connector, with
  what was found (host, confidence, evidence), the findings about it (for example the NTLM relay warning, ESC8, for Web
  Enrollment on plain HTTP) and what this run can see. "Not found" (looked, nothing there), "cannot be checked from here" (for
  example the Intune connector on another server) and "not checked in this run" are shown apart.

The window only shows and filters what the engine found; it checks nothing itself, and it changes nothing on any server.

### Known limitations

- Read-only and anonymous web checks: a page that needs a sign-in shows as "answers" (for example HTTP 403), never as working.
- The Intune Certificate Connector is only checked on the computer that runs the tool; its state in Intune (Microsoft Graph) is not read.
- Without the CA database reader (`CertificateAuthority.View`, not in-box on clients) NDES is found from template permissions and
  service accounts instead of from the issued certificates.
- A CA that refuses this account over DCOM is reported as "permission denied" (Inferred); its properties and CRLs are then not read.
- Web Enrollment, CES or OCSP on a server that nothing in AD or the certificates names cannot be found: the tool never scans.
- Results written before the object graph (results.json format 1) open without the Objects page and service instances.

## Safety

- Read-only. It never enrolls, requests, revokes, publishes, restarts or changes anything. It writes only
  to its output folder.
- It probes only hosts and URLs it found in authoritative sources. No network or port scans.
- No `Invoke-Expression`, no `Add-Type`, no encoded commands, no downloaded code.
- It never reads or exports private keys, passwords or challenge passwords.
- NDES: by default it sends exactly two anonymous GET requests to a NDES host (SCEP GetCACaps and GetCACert). A third,
  anonymous request to the admin page is sent only with `-IncludeNdesAdminProbe`, because an admin page that is wrongly
  open to anonymous users creates a one-time challenge password when it is requested (a write on a remote server). The
  response body is never read. It never enrolls and never follows a redirect.
- LDAP locations named in certificates are contacted only when they are the selected domain controller, a domain controller
  of the forest, or a host in this forest's own DNS domains named by AD, the CA or a verified download: a directory bind sends the Windows credentials of the user running the tool, so it is never
  sent to a host named by a (possibly downloaded) certificate. With `-SkipNetwork` only the selected domain controller is used.
- Links inside a certificate that was downloaded from an AIA location are followed only when that certificate is proven to
  be the expected issuer (the signature of the certificate that references it verifies with its key).
- Web checks are anonymous and direct (no proxy). A redirect to a host that no authoritative source or verified object named is
  recorded and not followed. The TLS versions offered are set explicitly (1.2, 1.1 and 1.0, and 1.3 where
  the .NET Framework has it) for the run only and restored afterwards.
- The Intune Certificate Connector is detected on the local computer only.
- Warn your security team before a run. The tool reads every template with its security descriptor, the CA properties,
  the CA database view and SCEP capabilities; directory and CA monitoring may see that as reconnaissance.

## First live run

[docs/TESTING.md](docs/TESTING.md) explains in plain language how to run the tool as a normal user and as an administrator,
what a good result looks like and which files to send back (they contain real names and must never be committed or
posted publicly).

## Status

Work packages WP1-WP8 are done and the tool is ready for an audit. The plan of record is [docs/ROADMAP.md](docs/ROADMAP.md);
history in [docs/PROGRESS.md](docs/PROGRESS.md), requirements in [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Development

Tests use Pester 5 or later on the development machine only: `Invoke-Pester .\tests`.

Author: ED
