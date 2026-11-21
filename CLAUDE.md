# MSPKI Health Check: rules for Claude Code

## What this project is
A read-only health check for Microsoft AD CS that discovers everything itself. It runs on any
domain-joined Windows computer with Windows PowerShell 5.1. It needs no config file, no install and no hardcoded
environment data. Requirements and phases: `docs/REQUIREMENTS.md`. Current state: `docs/PROGRESS.md`.
**The repository is public on GitHub: treat everything written here as visible to the world.**

## Hard rules (never break these)
1. **Read-only.** Never install, enroll, request, revoke, publish, restart, repair or configure anything.
   Never write to AD, the registry, a CA or any remote system. The only writes allowed are files under `out/`.
2. **No environment data in the project.** No real domain, forest, host, server, URL, IP, OU, account or
   organisation name may appear in code, comments, tests, fixtures, docs or commit messages. Use the reserved
   names `example.test`, `corp.example.test` and `pki.example.test` in examples and fixtures.
3. **No configuration.** Everything comes from discovery. The only optional inputs are parameters with
   defaults (thresholds, timeouts, output path, opt-in switches).
4. **Bounded discovery.** Only probe hosts and URLs that came from an authoritative source: the AD
   Configuration partition, CA properties, certificates, CRLs or local policy. No subnet scans, no port scans,
   no enumerating domain computers. Standard Microsoft PKI web paths may be tried only on hosts already proven
   to be PKI. Web probes are anonymous GETs; never send credentials to `/certsrv/mscep_admin/`.
5. **Windows PowerShell 5.1 and .NET Framework 4.x only.** No PS7-only syntax (`? :`, `??`, `&&`, `||`,
   `-Parallel`). No external runtime modules (no RSAT ActiveDirectory module, no PSPKI, no ImportExcel).
   Use `System.DirectoryServices`, `System.Security.Cryptography.X509Certificates`, `System.Net` and
   in-box COM (`CertificateAuthority.Request`, `CertificateAuthority.View`, `X509Enrollment.*`).
6. **AV/EDR-safe.** Never use `Invoke-Expression`/`iex`, encoded commands, Base64 payloads, `Add-Type`, private
   reflection, downloaded code, hidden windows or `-ExecutionPolicy Bypass`. Keep `certutil` to the few
   opt-in uses listed in REQUIREMENTS. Use defensive names (`Test-MspkiTemplateEnrollmentRisk`, not
   `Find-Vulnerable*` / `Invoke-ESC*`).
7. **No secrets.** Never read, log or export private keys, passwords, tokens, challenge passwords or
   protected configuration values.
8. **Honest results.** Every finding carries its sources, evidence and confidence. Never present an Inferred
   result as Confirmed, and never claim a remote file exists without evidence.

## The `ref/` folder
- `ref/` holds the previous toolkit (v2.5.0). Use it for **ideas only**.
- Never edit, move, rename, run or dot-source anything in `ref/`. Do not copy code blocks from it.
- `ref/` may contain real environment names. **Never carry a hostname, domain, URL or organisation name
  from `ref/` into this project**, and that includes `docs/REF-INVENTORY.md`.
- Read `docs/REF-INVENTORY.md` instead of `ref/`. If you must look at `ref/`, `grep` first and read only the
  line range you need.

## Layout
```
Invoke-MspkiHealthCheck.ps1   # thin entry point: parameters, exit code
src/MspkiHealthCheck.psd1/.psm1
src/Model/       # New-MspkiFinding, lead registry, URL/host normalisation
src/Discovery/   # AD Configuration partition, CA COM properties, local policy and services
src/Probes/      # DNS, TCP, HTTP, TLS, LDAP: cached and time-limited
src/Analyzers/   # CA/hierarchy, CRL, endpoints, AD containers, templates, CEP/CES, NDES, stale refs
src/Reporters/   # JSON, CSV, HTML, log
tests/fixtures/  # sanitised recorded samples (example.test only)
tests/*.Tests.ps1
out/             # run output (git-ignored)
ref/             # old toolkit (git-ignored, read-only)
```

## Code conventions
- Function prefix `Mspki`. Use approved verbs, `[CmdletBinding()]` and comment-based help on public functions.
- Engine functions return objects only (no `Write-Host`). Every result is built with `New-MspkiFinding`.
- Every network call takes a timeout and goes through the Probes cache.
- Wrap each discovery method in its own try/catch. A failure becomes a Finding (Error,
  PermissionDenied or Unsupported) and the run continues.
- Keep permission failures separate from infrastructure failures.

## Before calling a change done
1. Syntax-check every changed file:
   `[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$null,[ref]$e)` must give no errors.
2. Run the Pester tests for the area you touched (Pester 5 on the dev machine only. The tool itself has no
   dependency.)
3. Run `grep -rniE` over `src tests docs` for anything that looks like a real hostname or domain.
4. Add 3–6 lines to `docs/PROGRESS.md`: what was done, what is next, any open issues.

## Git
- Commit author is `ED` with the GitHub noreply address. Never put a real name or personal email in any
  file or commit.
- Never commit `ref/` or `out/`.
- Before every commit, grep for anything that looks like a real hostname, domain, IP or email and remove it.
- After each working step: syntax-check, run tests, run the name grep, commit, push.

## Working style (usage limits matter)
- Single agent only: never use subagents or parallel agents.
- Work autonomously: make sensible decisions and record them in `docs/PROGRESS.md`. Stop to ask only if a
  safety rule would have to bend.
- One phase per session: plan, then implement, then test, then update PROGRESS, then stop.
- Use `grep` and line ranges instead of reading whole large files. Don't re-read files you just wrote.
- Keep replies short. Don't recap; finish with what changed and what's next.
