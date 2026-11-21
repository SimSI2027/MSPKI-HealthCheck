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
```

Output goes to `out\<yyyyMMdd-HHmmss>\`: `results.json`, `run.log`, and (later phases) `findings.csv`
and a single offline `report.html`.

Exit codes: `0` passed · `2` informational · `3` warnings · `4` failures · `5` incomplete (unsupported or
error) · `6` incomplete (permissions).

## Safety

- Read-only. It never enrolls, requests, revokes, publishes, restarts or changes anything. It writes only
  to its output folder.
- It probes only hosts and URLs it found in authoritative sources. No network or port scans.
- No `Invoke-Expression`, no `Add-Type`, no encoded commands, no downloaded code.
- It never reads or exports private keys, passwords or challenge passwords.

## Status

Work in progress. See [docs/PROGRESS.md](docs/PROGRESS.md) and [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Development

Tests use Pester 5 or later on the development machine only: `Invoke-Pester .\tests`.

Author: ED
