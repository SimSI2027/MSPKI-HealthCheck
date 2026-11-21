# Session prompts

## Session 1: inventory and Phase 0 plan (use Sonnet)

```
Read CLAUDE.md and docs/REQUIREMENTS.md. This session covers Phase 0 only.

Step 1 – Build docs/REF-INVENTORY.md from ref/.
- Start with grep for function definitions, Add-Type, certutil, Invoke-Expression, DirectoryServices,
  HttpWebRequest, X509Chain and XAML. Then read only the line ranges you need. Never read ref/ in one go.
- For each area (discovery, CA checks, CRL, AIA/CDP, templates, CES/CEP, TLS, exports, GUI) write:
  what v2.5.0 does · the method it uses · what's worth keeping · what to avoid (AV risk, false positives,
  slow parts, hardcoded data).
- Keep it under 200 lines. Replace every real host, domain, URL or organisation name with an example.test
  placeholder. None may appear in the file.

Step 2 – Add a short "Gaps vs REQUIREMENTS" list at the end of the inventory.

Step 3 – Propose the Phase 0 plan: files, functions, the New-MspkiFinding schema as PowerShell, and the
Pester tests. Plan only. Wait for my approval before writing anything under src/ or tests/.
```

## Each later phase (use Sonnet; plan mode first)

```
Read CLAUDE.md, docs/PROGRESS.md and the Phase <N> section of docs/REQUIREMENTS.md.
Use docs/REF-INVENTORY.md for ideas. Open ref/ only with grep and line ranges.
Plan Phase <N> (files, functions, tests), then wait for my approval.
After approval: implement, syntax-check, run the tests, grep for real names, update docs/PROGRESS.md, stop.
```

## Audit (use Fable 5.2, High effort, after Phase 4 and after Phase 7)

```
Audit src/ and tests/ against CLAUDE.md hard rules and docs/REQUIREMENTS.md, up to Phase <N>.
Check: read-only guarantee, AV-unsafe patterns, PS 5.1 compatibility, Inferred shown as Confirmed,
merged status codes, probes outside the lead registry, leaked environment names, missing tests.
Report findings ranked by severity with file:line. Do not change code.
```
