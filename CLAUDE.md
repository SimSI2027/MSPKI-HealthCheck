# MSPKI Health Check: rules for Claude Code

## What this project is
A read-only health check for Microsoft AD CS that discovers everything itself. It runs on any
domain-joined Windows computer with Windows PowerShell 5.1. It needs no config file, no install and no hardcoded
environment data. Requirements and phases: `docs/REQUIREMENTS.md`. Current state: `docs/PROGRESS.md`.
**The repository is public on GitHub: treat everything written here as visible to the world.**

## Standing directives (they apply to every session)
- **Users only ever use the GUI.** Once the backend is solid, the GUI gets major investment and must be outstanding: polished,
  engaging, even enjoyable. Backend work is judged by what the window can show.
- **GitHub never contains lab host or domain names**, in current files or in history. IP addresses are allowed. Replace names with the
  generic ones in `docs/NAMING.md`. The real-to-generic map lives only in `C:\ClaudeCode\private\NAME-MAP.txt` (never committed).
- **Lab infrastructure access is for OBSERVATION ONLY:** collecting information and understanding how things work. Never change
  anything on a lab server.
- **Every non-passing finding must explain itself:** likely causes (ranked), how to confirm each one, how to fix it, and sources.
- **Online research is encouraged** (Microsoft Learn, GitHub, other reputable sources). Learn from it and cite it, but never copy code
  from other projects (licences).

## Hard rules (never break these)
1. **Read-only.** Never install, enroll, request, revoke, publish, restart, repair or configure anything.
   Never write to AD, the registry, a CA or any remote system. The only writes allowed are files under `out/`.
2. **No environment data in the project.** No real domain, forest, host, server, URL, IP, OU, account or
   organisation name may appear in code, comments, tests, fixtures, docs or commit messages. Use the reserved
   names `example.test`, `corp.example.test` and `pki.example.test` in examples and fixtures.
   *Clarification:* documentation examples, screenshots, `demo/` and the demo site may instead use the fictional demo world in
   `docs/DEMO-WORLD.md` (`alcyone-orbital.example`, reserved `.example` TLD). Tests and `tests/fixtures/` keep `example.test`.
3. **No configuration.** Everything comes from discovery. The only optional inputs are parameters with
   defaults (thresholds, timeouts, output path, opt-in switches).
4. **Bounded discovery.** Only probe hosts and URLs that came from an authoritative source: the AD
   Configuration partition, CA properties, certificates, CRLs or local policy. No subnet scans, no port scans,
   no enumerating domain computers. Standard Microsoft PKI web paths may be tried only on hosts already proven
   to be PKI. Web probes are anonymous GETs; never send credentials to `/certsrv/mscep_admin/`.
   *Clarification:* the SCEP request paths (including `/certsrv/mscep_admin/`) are named in one file only,
   `src/Probes/NdesProbe.ps1`. By default it sends two anonymous GETs (GetCACaps, GetCACert). The third, one anonymous request to
   the admin page whose body is never read, is sent only when the run was started with `-IncludeNdesAdminProbe` (an open admin
   page creates a challenge password when requested, which would be a write to a remote system, rule 1). It never follows a
   redirect and never sends credentials. `tests/Ndes.Tests.ps1` enforces this with static checks and a loopback server that
   records every request.
   *Clarification:* an LDAP URL that names a host is contacted only when the host is the selected domain controller, a domain
   controller of the forest (server objects in the Configuration partition), or a host in this forest's own DNS domains named by
   trusted evidence (AD, CA properties, or a downloaded certificate or CRL whose signature was verified with a discovered CA
   certificate); never with `-SkipNetwork` unless it is the selected domain controller, because a directory bind sends the running
   user's Windows credentials. A DNS name in the forest zone alone is not proof. Links inside a downloaded CRL are followed only
   when its signature verified. HTTP probes connect directly with no proxy unless `-UseSystemProxy` is given.
   *Clarification (a limit, not an exception):* during a TLS handshake the Windows chain engine may itself contact an `ldap://` or `http://`
   host named in the **server's certificate** (its AIA), which can be any host. Measured: anonymous searches only, never a bind, so no
   credentials go out. The tool cannot bound it; it is listed in the run limits and in `docs/RESEARCH.md`. With `-SkipNetwork` no handshake is made.
5. **Windows PowerShell 5.1 and .NET Framework 4.x only.** No PS7-only syntax (`? :`, `??`, `&&`, `||`,
   `-Parallel`). No external runtime modules (no RSAT ActiveDirectory module, no PSPKI, no ImportExcel).
   Use `System.DirectoryServices`, `System.Security.Cryptography.X509Certificates`, `System.Net` and
   in-box COM (`CertificateAuthority.Request`, `CertificateAuthority.View`, `X509Enrollment.*`).
6. **AV/EDR-safe.** Never use `Invoke-Expression`/`iex`, encoded commands, Base64 payloads, `Add-Type`, private
   reflection, downloaded code, hidden windows or `-ExecutionPolicy Bypass`. Keep `certutil` to the few
   opt-in uses listed in REQUIREMENTS. Use defensive names (`Test-MspkiTemplateEnrollmentRisk`, not
   `Find-Vulnerable*` / `Invoke-ESC*`).
   *Clarification:* the ban is on encoded commands and Base64 **code**. Decoding Base64 **data** (certificates
   and CRLs returned by CA COM properties such as `GetCAProperty`) with `[Convert]::FromBase64String` is
   allowed. Do it only in `ConvertFrom-MspkiBase64Data` (`src/Model/BinaryData.ps1`), which accepts only
   certificate/CRL-shaped DER data. Never decode and then run, load, dot-source or write anything.
   *Clarification:* `Add-Type -AssemblyName` to load the in-box WPF assemblies (`PresentationFramework`, `PresentationCore`,
   `WindowsBase`) is allowed, for the GUI only (`Start-MspkiHealthCheckGui.ps1`, `src/Gui/`). `Add-Type -AssemblyName System.Web.Extensions`
   is allowed in `src/Model/JsonReader.ps1` only (the in-box JavaScriptSerializer reads results.json above PS 5.1's ~2 MB
   `ConvertFrom-Json` limit; data only). `Add-Type` with `-TypeDefinition` or
   `-MemberDefinition`, which compiles code, stays banned. Everything else in this rule still applies. `tests/Hygiene.Tests.ps1`
   enforces it.
   *Clarification:* `src/Knowledge/Diagnosis*.psd1` is DATA that is shown to the user ("Probable causes and next steps"). It is read only
   with `Import-PowerShellDataFile`, never run, and its advice text may name `certutil` and other commands as read-only checks or as
   actions for the PKI owner (the hygiene test exempts those files from the `certutil` pattern only). `tests/Diagnosis.Tests.ps1`
   checks that the file holds only literals and that no "how to confirm" step is a change.
7. **No secrets.** Never read, log or export private keys, passwords, tokens, challenge passwords or
   protected configuration values.
8. **Honest results.** Every finding carries its sources, evidence and confidence. Never present an Inferred
   result as Confirmed, and never claim a remote file exists without evidence.

## Lab dev machine
On the lab dev machine, admin rights and research tools (Wireshark/Npcap, RSAT, PSPKI, Sysinternals and so on) are allowed for
investigation only. The product must never depend on them: a normal user on a clean machine with Windows PowerShell 5.1 only.
Never change anything on other lab servers; if a lab fix is needed, write exact steps for the owner. Captures, logs, `out\` and
`C:\ClaudeCode\private\LAB-FACTS.md` hold real names: keep them outside the repo and never commit them.

## Developer-only tools (`tools\dev\`)
(Owner decision, 2026-11-23, for the demo site, DS2.) `tools\dev\` holds developer-only generators that never ship and that the product
never references.
- The demo-certificate generator may create throw-away signing keys IN MEMORY ONLY. Never write a key to disk or to any key store, and commit
  only public certificates and CRLs, clearly fictional.
- It may use PowerShell 7 or OpenSSL installed for this user (lab dev-tool rule).
- The demo uses a fixed demo-clock date so CRLs and certificates never appear expired.
`tests/Hygiene.Tests.ps1` enforces it: `src\`, the entry scripts and `demo\` never reference `tools\dev\`, and no private-key file (by type
or by content) is anywhere in the repository.

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
Start-MspkiHealthCheckGui.ps1 # Windows GUI entry point (WPF, STA); engine runs in a background runspace
src/MspkiHealthCheck.psd1/.psm1
src/Model/       # New-MspkiFinding, lead registry, URL/host normalisation
src/Discovery/   # AD Configuration partition, CA COM properties, local policy and services
src/Probes/      # DNS, TCP, HTTP, TLS, LDAP: cached and time-limited
src/Analyzers/   # CA/hierarchy, CRL, endpoints, AD containers, templates, CEP/CES, NDES, stale refs
src/Reporters/   # JSON, CSV, HTML, log
src/Knowledge/   # Diagnosis.psd1 (sources, status-code defaults, rules) + Diagnosis.Topics.<Area>.psd1 (causes, checks, fixes): data only; loader and ranking in src/Model/Diagnosis.ps1;
                 # sources with dates in docs/KNOWLEDGE-SOURCES.md
src/Gui/         # GUI only: MainWindow.xaml + Theme.xaml (look: see docs/GUI-DESIGN.md), GuiModel.ps1 / GuiView.ps1 (pure data helpers and view models),
                 # GuiApp.ps1 (window, runspace, events), GuiSnapshot.ps1 (developer PNG snapshots; writes only inside out\)
demo/            # demo script: runs the reporters on the example.test fixture, writes out/demo
tools/dev/       # developer-only generators (demo world PKI, demo site data); never shipped, never referenced by the product
site/            # the demo site: world/ (simulated world as data: world.json, scenarios/, pki/ public DER); generated data is not committed
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
