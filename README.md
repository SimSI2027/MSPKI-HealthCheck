# MSPKI Health Check

A read-only health check for Microsoft Active Directory Certificate Services (AD CS).

Run it on any domain-joined Windows computer with Windows PowerShell 5.1. It needs no configuration file,
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
.\Invoke-MspkiHealthCheck.ps1 -NoOpen                 # do not open report.html at the end (it opens by default)
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
- LDAP locations named in certificates are contacted only when they are the selected domain controller or in one of this
  forest's own DNS domains: a directory bind sends the Windows credentials of the user running the tool, so it is never
  sent to a host named by a (possibly downloaded) certificate. With `-SkipNetwork` only the selected domain controller is used.
- Links inside a certificate that was downloaded from an AIA location are followed only when that certificate is proven to
  be the expected issuer (the signature of the certificate that references it verifies with its key).
- Web checks are anonymous and direct (no proxy). The TLS versions offered are set explicitly (1.2, 1.1 and 1.0, and 1.3 where
  the .NET Framework has it) for the run only and restored afterwards.
- The Intune Certificate Connector is detected on the local computer only.
- Warn your security team before a run. The tool reads every template with its security descriptor, the CA properties,
  the CA database view and SCEP capabilities; directory and CA monitoring may see that as reconnaissance.

## First live run

[docs/TESTING.md](docs/TESTING.md) explains in plain language how to run the tool as a normal user and as an administrator,
what a good result looks like and which files to send back (they contain real names and must never be committed or
posted publicly).

## Status

Work in progress. See [docs/PROGRESS.md](docs/PROGRESS.md) and [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Development

Tests use Pester 5 or later on the development machine only: `Invoke-Pester .\tests`.

Author: ED
