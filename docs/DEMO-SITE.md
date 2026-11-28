# Demo site plan (GitHub Pages)

An interactive, static demo of the window, for people who cannot (or do not yet want to) run the tool. Visitors pick a scenario in
the fictional company of `docs/DEMO-WORLD.md`, watch discovery animate, explore the map, drill into findings and read the probable
causes. Build order and acceptance criteria: `docs/ROADMAP.md` (DS work packages).

## 1. Goals and non-goals
- **Goal:** in under a minute, a visitor understands what the tool finds, how it explains a problem, and why it is safe (read-only).
- **Goal:** the site looks and moves like the WPF window (same tokens, same layout, same motion), so screenshots and the real thing agree.
- **Honesty goal:** every result shown was produced by the tool's **real analysers**; nothing is hand-written into the page.
- **Non-goals:** no backend, no accounts, no analytics or tracking cookies, no upload of a visitor's own results (a later "open your own
  results.json in the browser, locally" is a Could, never a server upload).

## 2. Scenarios
The `baseline` world plus one change each (definitions in `docs/DEMO-WORLD.md`, "Scenarios"):

| Scenario | What the visitor learns |
|---|---|
| Healthy PKI | what "good" looks like; the celebration; the score model |
| As found (baseline) | a realistic estate: drift, LDAP-only publication, an unused responder, NDES |
| Expired CRL | how revocation failures look, why clients fail, the exact read-only checks |
| CA read refused (RPC blocked by permissions) | permission problems are reported apart from outages; owner steps |
| LDAP-only publication seen from outside | why non-domain clients fail; HTTP CDP/AIA design |
| ESC8: web enrollment over HTTP | an enrollment risk with evidence and sources, never overstated |
| Forged certificate at an AIA URL | the signature check; why the tool never trusts a downloaded file by name |
| NDES found | discovery without the CA database view: template permissions, SPNs, then GetCACaps |
| Renewal leftovers | CA generations, NTAuth versus AIA, the lifecycle timeline |

## 3. The generator: real analysers on a simulated environment
`tools/dev/demo-site/` (developer and build tools; never part of the product download, never referenced by it; CLAUDE.md "Developer-only tools") turns **world fixtures** into **scenario data**.

**World fixtures** (`site/world/`, data only, Alcyone names only; as built in DS1: one `world.json` for the baseline plus one overlay per scenario in `site/world/scenarios/<id>.json`, merged by property, and the DER files in `site/world/pki`):
- `directory.json`: the Configuration partition objects the engine reads (Public Key Services containers, Enrollment Services, templates with
  their security descriptors as SDDL, NTAuth, AIA/CDP objects with their certificate and CRL bytes), RootDSE, sites, domains and trusts.
- `ca/<ca>.json`: what `GetCAProperty` answers for each CA (or the error it returns, e.g. 0x800706BA for `rpc-denied`).
- `network.json`: per URL, what the anonymous GET returns (status, headers, body file), per host what DNS, TCP and TLS answer.
- `local.json`: this computer's store certificates, Lifecycle events, policy keys, services.
- `pki/`: the DER certificates and CRLs, generated once by `tools/dev/demo-site/New-MspkiWorldPki.ps1` with throw-away keys that live only in
  memory during that script and are never written. **Gate:** this script creates keys and signs, which the product rules forbid for the
  product. It is a separate developer tool, but it must be cleared by the owner and written into `CLAUDE.md` as a clarification before
  DS2 starts. Only public DER bytes are committed.

**How the engine runs** (`tools/dev/demo-site/Invoke-MspkiScenario.ps1`, Windows PowerShell 5.1):
1. Import the real module (`src/MspkiHealthCheck.psd1`) unchanged.
2. Replace only the **I/O boundary**, inside the module scope, with functions that answer from the world fixture: LDAP and
   DirectoryEntry reads (`Discovery/AdContext.ps1`, `Discovery/Ldap.ps1`), CA COM reads (`Discovery/CAProperty.ps1`), HTTP, TCP and TLS
   (`Probes/WebProbes.ps1`, `Probes/NetworkProbes.ps1`), DNS (`Probes/DnsIdentity.ps1`), local stores, events and policy
   (`Discovery/LocalEvidence.ps1`, `Discovery/LocalPolicy.ps1`, `Discovery/IntuneConnector.ps1`), run context (`Model/RunContext.ps1`).
   Everything above that line (parsers, signature checks, chain logic, analysers, diagnosis, reporters, graph builder) is the shipped code.
3. Run `Start-MspkiHealthCheck` with a run control, record every queue item (stage, target, log and, after GX1, entity, relation and
   probe events) with its time offset.
4. Write `site/data/<scenario>/results.json` (the real results document), `events.json` (the recorded stream, used for the replay),
   and `manifest.json` (tool version, commit, scenario, the boundary functions replaced, the time of generation).

**Guards** (tests in `tests/DemoGenerator.Tests.ps1`):
- The list of replaced functions is checked against the module: every function that calls an I/O API (the patterns above) must be in the
  list, so new I/O cannot silently reach a real network. A replaced function that is called with an unknown key throws instead of
  falling back to a real call.
- A scenario with an unexpected Error or PermissionDenied finding fails the build (except where the scenario expects it).
- The output is scanned with the hygiene patterns: only world names, documentation IP ranges and public documentation hosts.
- Determinism: the same commit and fixture give byte-identical `results.json` (fixed clock and run id are boundary inputs).

**Labelling on every page:** "Simulated environment. Alcyone Orbital Systems is fictional. These results were produced by MSPKI Health
Check <version> (commit <sha>) running its real analysers against a simulated directory, CAs and network (scenario <name>). Nothing here
touched a real network." The banner links to the scenario's fixture and to this document.

## 4. The site
- **Pages:** *Home* (what the tool is, the read-only promise, scenario cards with their health band) → *Scenario* (the mission control
  view) → *How this demo is made* → *Get the tool* (GitHub release).
- **Scenario view** mirrors the window: title bar with "Read-only" and a "Simulated" badge; navigation (Overview, Findings, Map, Services);
  score ring and areas; "What to do next"; the live map **replaying `events.json`** with play, pause, 1x/2x/4x and a scrubber; the Findings
  list with filters; the details pane with the walkthrough (causes, copy the checks, sources). Deep links: `#/<scenario>/finding/<id>`.
- **Design language:** tokens (colours, radii, spacing, type ramp, durations, easing) are generated from `src/Gui/Theme.xaml` into
  `site/assets/tokens.css` by the build, and a test fails if they drift. Segoe UI with a system-font fallback stack; icons as inline SVG
  drawn to match the Fluent glyphs (no icon font download, no copied assets).
- **Technology:** plain HTML, CSS and JavaScript (ES2017 modules), no framework, no bundler, no third-party runtime; the map is SVG with
  CSS transitions and the Web Animations API; `prefers-reduced-motion` and `prefers-color-scheme` honoured; `forced-colors` for high contrast.
- **Fast:** first view under 150 KB compressed (HTML, CSS, JS, fonts excluded); scenario data loads on demand (about 30 KB compressed each);
  Lighthouse 95+ for performance and accessibility on a mid-range phone profile.
- **Mobile-friendly:** one column below 720 px; the map pans and pinch-zooms, with a list view toggle; the details pane is a bottom sheet;
  44 px touch targets.
- **Privacy and safety:** no cookies, no trackers, no external requests at runtime (fonts and scripts are local); a strict
  Content-Security-Policy meta tag (`default-src 'self'`).

## 5. Build and deploy
- `.github/workflows/pages.yml`: on push to `main` that touches `site/**`, `src/**` or the workflow.
  1. Job `generate` on `windows-latest` with `shell: powershell` (Windows PowerShell 5.1): run the generator for every scenario, run
     `tests/DemoGenerator.Tests.ps1` and the hygiene scan over the output, upload the site as the Pages artifact.
  2. Job `deploy`: `actions/deploy-pages` with `pages: write` and `id-token: write` only; the environment is `github-pages`.
- Third-party actions are pinned to a full commit SHA; the workflow has `permissions: contents: read` by default.
- Generated data is not committed (`site/data/` is git-ignored); a local preview is `tools/dev/demo-site/Build-MspkiDemoSite.ps1 -Output out\site`
  (writes under `out\` only) and any static file server.

## 6. Acceptance (summary; full criteria per DS work package in the roadmap)
- Every scenario's data comes from the generator in CI on the current commit; the page shows that commit.
- The site passes the upgraded rubric (`docs/GUI-DESIGN.md` §6) on desktop and phone screenshots, and the hygiene scan finds only world names.
- No result on the site disagrees with what the real window shows for the same `results.json`.

## 7. As built (DS4-DS6, 2026-11-28)
- **Build:** `tools/dev/demo-site/Build-MspkiDemoSite.ps1` (writes under `out\site` only) runs every scenario (or reuses `out\site-data` with
  `-SkipGenerate`), then computes each scenario's `data/<id>/view.json` with the window's own pure helpers (`Get-MspkiGuiHealthScore`,
  `Get-MspkiGuiNextAction`, `Get-MspkiGuiHeadline`, `ConvertTo-MspkiGuiRowList`, `Get-MspkiGuiFindingDetail`, `Invoke-MspkiGuiMapJob`) and the
  replay stream (entities, probes, stages with their simulated times). `data/scenarios.json` lists the scenarios with score and band.
- **Shell:** `site/index.html` (CSP `default-src 'self'`, no inline code, no third-party request, the simulated-environment banner with the
  version and commit), `site/assets/app.css`, `site/assets/app.js` (an ES module; the DOM is built from text nodes only; nothing stored),
  `site/assets/tokens.css` generated from `Palette.Light.xaml`, `Palette.Dark.xaml` and `Theme.xaml` (`-TokensOnly`; a test fails on drift).
- **Pages:** Home (hero clip, the read-only promise, scenario cards with score and band), the scenario view (Overview: headline, score ring
  and areas, What to do next; Findings: status chips, search, the details pane with the walkthrough and copy buttons for the read-only
  checks; Discovery map: the window's layout with replay play/pause, 1x/2x/4x and a scrubber), How this demo is made. Deep links:
  `#/s/<id>`, `#/s/<id>/findings`, `#/s/<id>/finding/<finding id>`, `#/s/<id>/map`.
- **Motion:** `Start-MspkiHealthCheckGui.ps1 -Snapshot <out folder> -ResultsFile out\site-data\baseline\results.json -SnapshotReplayFrames 60`
  captures the window's own discovery build; `tools/dev/demo-site/New-MspkiDemoMotion.ps1` stitches the frames with ffmpeg into
  `site/assets/media/discovery.mp4` (hero, autoplay muted loop; a still with reduced motion) and `discovery.gif` (README).
- **Not measured yet:** Lighthouse (no Lighthouse run on this machine). Phone frames below 500 px could not be rendered by headless Edge
  (it keeps a 500 px window); 540 px frames show one column, the scrolling navigation and 44 px targets.
