# GUI experience design

The window is the product: users only ever use the GUI. This document says who it is for, what they come to do, how the pages fit
together, which features are worth building (and in what order), how it moves, and what is possible in Windows PowerShell 5.1 WPF with
pure XAML. The visual system is in `docs/GUI-DESIGN.md` (palette, type, spacing, rubric). The build order is in `docs/ROADMAP.md` (GX and DS
work packages). Examples use the demo world in `docs/DEMO-WORLD.md`.

## 1. Principles
1. **Health first, then why, then what to do.** The first screen answers "is my PKI healthy?" in one glance, then "why not?", then
   "what do I do next?". Detail is always one click away, never in the way.
2. **Every claim shows its evidence.** A score, a colour or a sentence can always be opened to the findings, sources and observations
   behind it. Nothing is decoration: if it animates, it means something was found or checked.
3. **Honest by design.** Confidence words (Confirmed, Inferred, Unverified), "Most likely" only when something observed backs it,
   "partial" whenever a check could not run. A score never hides that part of the estate could not be seen.
4. **Calm by default, delightful at the right moments.** Dense and quiet while you work; motion when something is discovered, when a
   run finishes and when everything is healthy. Motion never delays a task.
5. **It never freezes.** The engine runs in its own runspace; the window does small, batched work per tick; lists are virtualised.
6. **Read-only, visibly.** The "Read-only" badge, "this tool changes nothing" on every fix, and copy-the-check buttons that only
   ever copy text.

## 2. Who uses it
| Persona | Knows PKI | Comes to the tool to | Success looks like |
|---|---|---|---|
| **Priya, PKI administrator** (owns AD CS at Alcyone) | expert | check the estate after a change, prove a CRL or renewal problem, find drift (old generations, stale NTAuth) | finds the root cause and the exact check in under 2 minutes; trusts every finding |
| **Sam, generalist sysadmin** (inherited the CAs) | basic | find out whether the warnings in the event log matter, fix what is broken without breaking more | understands each problem in plain words; knows who must fix it and how; never feels lost |
| **Morgan, security reviewer** | medium, security-focused | review enrollment risks (ESC1-16, ESC8 web enrollment, NDES), collect evidence for an audit | a filtered, exportable list of risks with evidence and sources; nothing overstated |
| **Dana, IT manager** | none | know whether the PKI is a risk and whether it got better | a one-page summary with a score, the trend and the three things being done; printable |

## 3. Top journeys
Each journey has a target that the usability rubric checks (`docs/GUI-DESIGN.md` §6).

| # | Journey | Who | Path through the window | Target |
|---|---|---|---|---|
| J1 | **First run** | all | Welcome (what it does, what it never does, the three steps) → Run → mission control fills in live: the map builds itself, stages tick, probes pulse → finished: score ring settles, "What to do next" appears. A short tour (4 stops) is offered once. | a first-time user starts a run within 10 s and can say what the score means after it finishes |
| J2 | **"Is my PKI healthy?"** | Dana, Priya | Overview: the score and band, per-area bars, one headline sentence ("2 problems need action; the issuing CA's CRL is the most urgent") | answered in 5 s without scrolling at 1360 x 860 |
| J3 | **"Why is this failing and what do I do?"** | Sam, Priya | "What to do next" item (or a red map node, or a Findings row) → guided walkthrough: what it means, probable causes ranked with what was observed, a copy button per read-only check, "mark as checked", the fix and who owns it, sources | from Overview to a copied check in 3 clicks; the walkthrough never needs the Findings grid |
| J4 | **"What changed since last time?"** | Priya, Dana | History page: runs listed with score sparkline → pick two → new, resolved and changed findings; objects added or gone; score delta per area | the difference between two runs in 2 clicks |
| J5 | **"Explain this to me"** | Sam, Dana | "Explain" toggle (or F1): every PKI term underlined; hover gives a one-line definition; a concept card per object type ("What a CRL is and why it expires"); the map's legend explains each shape | no term on the Overview is unexplained |
| J6 | **"Give me a report for my boss"** | Priya → Dana | Command palette "Export executive summary" or the Overview's export button → one printable HTML page: score, trend, per-area status, top 3 actions in plain words, what was not checked | a one-page summary in 2 clicks, readable by someone who knows no PKI |

## 4. Information architecture
### Pages (left navigation, Ctrl+1..9)
| # | Page | Purpose | Status |
|---|---|---|---|
| 1 | **Overview (mission control)** | score, areas, what to do next, live map, CA cards, top issues, coverage | exists; redesigned in GX2 |
| 2 | **Findings** | the full list; filters; the guided walkthrough in the details pane | exists; walkthrough in GX4 |
| 3 | **Map** | the hierarchy as a full-page interactive canvas (zoom, pan, focus a CA), with the existing tree as an alternative view | done in GX6 (map and tree) |
| 4 | **Timeline** | CA certificate and CRL lifecycle: expiry countdowns, the CRL "heartbeat" (publish, next update, overlap) | new, GX5 |
| 5 | **Objects** | every object of the graph, searchable | exists |
| 6 | **PKI services** | Web Enrollment, CES, CEP, NDES, OCSP, Intune connector | exists |
| 7 | **History** | earlier runs, score trend, compare two runs | new, GX6 |
| 8 | **Run log** | the live log | exists |
| 9 | **Learn** | concept cards and the glossary, opened from any "Explain" link | new, GX7 |

### One drill-down pattern everywhere
- Anything that stands for an object or a finding (a map node, a score bar, an action, a tile, a row, a chip, a timeline bar) opens the
  **details pane** on the right of the current page. The pane is the same component everywhere: title, status, what it is, the
  walkthrough or properties, **Where this exists**, related objects, findings, breadcrumbs and Back (Alt+Left).
- **Where this exists** is a section of every object pane and a hover card on every map node: each place the object was seen, referenced,
  or expected and missing, with source, confidence and time. Expected-but-missing places are always set apart in red.
- A score, a bar or a count opens the Findings page filtered to exactly the findings behind it (the filter is shown as removable chips).
- The **command palette** (Ctrl+K) reaches every page, every object by name, every finding by text, and every command (run, cancel, open,
  export, theme, explain mode, tour).

## 5. Features, prioritised
Must = needed for the GUI to pass the new rubric. Should = clearly better, planned. Could = if time allows. Every item says how it is built
in WPF on Windows PowerShell 5.1 (details in §8).

| Feature | Priority | Value | Notes and verdict |
|---|---|---|---|
| **Mission-control Overview**: overall score, per-area scores, headline sentence | Must | answers J2 in 5 s | score model in §6; built from findings only, never invented; "partial" when checks could not run |
| **"What to do next"**: ranked actions from the knowledge base | Must | turns 30 findings into 3-5 actions (J3) | findings grouped by diagnosis topic; ranked by worst status, severity and count; each action opens the walkthrough |
| **Live discovery visualisation**: the map builds itself as objects are found; probes pulse; colour by health | Must | the "wow" moment of J1, and it teaches the hierarchy | Canvas layout computed in PowerShell, one Storyboard per build batch; needs graph events from the engine (GX1). Prototype in this session replays the graph |
| **Guided troubleshooting walkthrough**: causes, copy-the-check buttons, mark as checked | Must | J3; Batch H's knowledge in a usable form | the details pane, in steps; "mark as checked" is kept per run in `out\<run>\gui-state.json` (a file under `out\`) |
| **Highlight Observed evidence** | Must | separates "seen in this run" from "typical" | a quiet accent mark and the word "Observed" on causes and rows backed by this run's evidence |
| **Copy the checks** | Must | Sam can run the check right away | one button per check and one for all checks of a cause; plain text only |
| **Ctrl+K command palette**, keyboard-first | Must | findability; experts never touch the mouse | an overlay with a search box and a virtualised result list |
| **Reduced motion and high contrast** | Must | accessibility; Fortune 500 requirement | `SystemParameters.ClientAreaAnimation` and `SystemParameters.HighContrast` are read in-box; a high-contrast theme maps to `SystemColors` |
| **Dark and light themes** | Should | comfort, modern feel | needs `DynamicResource` for every brush (a mechanical change across Theme.xaml and MainWindow.xaml); follows the Windows app theme by default (read from the registry, read-only) |
| **Interactive certificate-chain view** | Should | shows why a chain fails (which link, which URL) | a vertical chain on Canvas: leaf → issuing → root, each link with its AIA/CDP URLs and their results |
| **CRL and certificate lifecycle timeline** (expiry countdowns, CRL heartbeat) | Should | sees trouble before it happens | a horizontal time axis on Canvas; one row per CA generation and CRL; publish marks and next-update windows |
| **Run history and compare two runs** | Should | J4; shows progress to managers | reads earlier `out\*\results.json` (read-only); entity ids are deterministic, findings matched by category, code, rule and target |
| **Executive summary export** (printable HTML) | Should | J6 | a new reporter beside report.html; one page, print CSS; written under `out\` only |
| **"Explain it to me" mode** (concept cards, glossary on hover) | Should | J5; the tool helps people understand PKI | glossary data in `src/Knowledge/Glossary.psd1` (data only); tooltips with rich content |
| **First-run guided tour** | Should | J1 | 4 stops with a spotlight overlay (§8); offered once, remembered in `out\gui-settings.json` |
| **Tasteful celebration when everything is healthy** | Should | delight; makes a clean run feel earned | the score ring completes with a soft glow and a check mark that draws itself, once per run, 900 ms; never with reduced motion |
| **Full-page Map canvas** (zoom, pan, focus, minimap) | Should | explore large estates | ScaleTransform/TranslateTransform on the canvas; mouse wheel and keyboard; tree view stays as the accessible alternative |
| **Saved views and remembered layout** (columns, splitter, last page) | Could | power users | `out\gui-settings.json` |
| **In-app toasts** ("Report exported", "Run finished") | Could | replace Windows message boxes | an overlay Border with a fade; replaces themed-dialog gap noted in GUI-DESIGN round 5 |
| **Windows toast notifications, Mica backdrop, snap-layout flyout** | Won't | | need WinRT activation or P/Invoke: banned or out of scope (§8) |

## 6. The health score (honest by construction)
- **Areas** (each finding belongs to one by its category): *CA hierarchy* (CA, hierarchy, certificate generations), *Revocation* (CRL, delta,
  OCSP), *Publication* (AIA and CDP endpoints, TLS), *Enrollment security* (templates, ESC rules), *Enrollment services* (Web Enrollment,
  CES, CEP, NDES, Intune), *Directory* (AD containers, NTAuth, stale references).
- **Penalty** per finding: Critical 35, Fail 20, Warning 6; severity multiplies (High x1.4, Low x0.6, any other x1). Information,
  Pass and NotApplicable cost nothing. Error and Skipped (permission denied, unsupported, not tested) cost nothing but count as
  **not checked**. Run and LocalEvidence findings (about the run or this computer) are not scored.
- **Area score** = round(100 x 0.5 ^ (penalties / 40)): every 40 penalty points halve it. One failure gives 71; one warning 90.
- **Overall** = the mean of the checked areas, capped at the worst area + 30 (one critical area always pulls the whole down).
- **Bands**: 90-100 *Healthy* (good tone), 60-89 *Needs attention* (warning tone), 0-59 *At risk* (danger tone).
- **Coverage**: an area with a not-checked finding shows "partial" and the count; the overall score says "partial" when any area is partial
  or the run was cancelled. With no CA found there is no score (overall or per area), only the reason, shown as text under the ring.
- The ring's tooltip and a "How is this scored?" link show this formula in plain words. The score summarises findings; it is not a
  certification. The formula lives in one GUI helper (`Get-MspkiGuiHealthScore`) with tests.

## 7. Motion and interaction design
### What moves, and why
| Moment | Motion | Duration and easing |
|---|---|---|
| A node is discovered | fades in and scales from 0.6 to 1; its link draws in after it | 280 ms, CubicEase out; links 220 ms; nodes in one batch stagger by 45 ms, at most 1.6 s per batch |
| A probe runs against a node | a ring expands from the node and fades (a pulse), repeating while the probe runs | 1.2 s per pulse, QuadraticEase out; at most 6 pulsing nodes at once |
| A node's health becomes known | its fill crossfades from neutral to the status tint | 240 ms |
| The run finishes | the score ring sweeps to its value, area bars grow left to right, "What to do next" rows slide up 8 px and fade in | ring 900 ms CubicEase in-out; bars 500 ms staggered 60 ms; rows 200 ms staggered 40 ms |
| Everything is healthy | the ring closes with a soft glow; a check mark draws itself | 900 ms, once per run |
| Page change | the content fades in and rises 6 px | 150 ms |
| Details pane opens | slides in 12 px and fades | 160 ms |
| Hover and press | background tints | 100 ms (no motion) |

Never animated: numbers in grids, filters, typing, the log, anything during keyboard navigation, anything that would delay input.

### Staying smooth
- **No PowerShell work per frame.** Every animation is a WPF Storyboard or `BeginAnimation` with `BeginTime` offsets; the composition engine
  runs it. PowerShell only creates the elements and starts one Storyboard per batch.
- **Small ticks.** The progress timer (every 150 ms) handles at most a bounded number of queue items and adds at most 24 map nodes per tick;
  the rest wait for the next tick.
- **Bounded layout.** The map layout is computed once per batch in PowerShell (layered, deterministic, O(n log n)); above 120 nodes, endpoints
  and hosts collapse into counted clusters per CA that expand on click.
- **Virtualised lists.** Findings, Objects, Run log and palette results use `VirtualizingStackPanel` with recycling; the map culls nodes
  outside the viewport on the full-page canvas.
- **Reduced motion.** When Windows "Show animations" is off (`SystemParameters.ClientAreaAnimation` is false) or high contrast is on, every
  Storyboard is skipped and the final state is set at once; pulses become a static ring.
- **Snapshots.** Storyboards are started as controllable and the snapshot seeks them (`SeekAlignedToLastTick`) to set times, so mid-animation
  frames render exactly what the user would see.

## 8. Technical feasibility (Windows PowerShell 5.1, .NET Framework 4.x, in-box WPF, pure XAML, no compiled code, no P/Invoke)
| Need | Technique | Feasible |
|---|---|---|
| Animations | `Storyboard`, `DoubleAnimation`, `ColorAnimation`, easing functions, `BeginTime`; started from PowerShell with `Storyboard.SetTarget` | yes |
| Map layout | `Canvas` with `Ellipse`/`Border` nodes and `Path` (Bezier) links; positions computed in PowerShell | yes |
| Force-directed live physics | needs per-frame code | **no**: use the deterministic layered layout and animate between layouts with Storyboards |
| Score ring | `Ellipse` with `StrokeDashArray`, animated `StrokeDashOffset`, rotated -90 degrees | yes |
| Vector icons | `Segoe Fluent Icons` / `Segoe MDL2 Assets` glyphs; `Path` geometry for the few shapes the fonts lack | yes |
| Command palette, toasts, tour | overlay `Grid` in the window's top layer; the tour's spotlight is a `Path` with a `CombinedGeometry` (Exclude) of the window and the target's bounds | yes (an Adorner would need a subclass: **no**) |
| Dark / light theme | `DynamicResource` brushes, swap the palette dictionary at runtime | yes (a mechanical conversion) |
| Follow the Windows theme | read `HKCU\...\Themes\Personalize\AppsUseLightTheme` (read-only) | yes |
| High contrast | `SystemParameters.HighContrast` + a theme built from `SystemColors` | yes |
| Reduced motion | `SystemParameters.ClientAreaAnimation` | yes |
| Mica / acrylic backdrop, snap layouts | DWM attributes need P/Invoke | **no**: keep the solid title bar |
| Windows toast notifications | WinRT activation from script | **no** (out of scope): in-app toasts |
| Shader effects (blur, glow) | `BlurEffect` and `DropShadowEffect` are in-box; custom `ShaderEffect` needs a compiled shader | in-box effects only, used sparingly (they are rendered in software on some machines) |
| Charts, sparklines | `Polyline` / `Path` on Canvas | yes |
| Printable summary | HTML with print CSS (same as report.html) | yes |
| Live map during a run | the engine's queue sends `Entity`/`Relation`/`Probe` items when the graph changes (an engine change, GX1) | yes, with GX1 |
| Per-monitor DPI | needs an application manifest for powershell.exe | **no**: system DPI with layout rounding stays sharp |

## 9. Accessibility and content
- Keyboard: every action has a key path; Ctrl+K palette; F6 cycles nav, command bar, content, details; arrow keys move between map nodes
  (in reading order of the layout); Enter opens; Alt+Left back.
- Screen readers: `AutomationProperties.Name` and `HelpText` on every control; map nodes expose name, type and health; the tree stays as
  the text alternative of the map.
- Never colour alone: icon + word on every status, also on map nodes (glyph badge).
- Voice: short, plain, active sentences. Say what was seen, how sure the tool is, and who can fix it. No blame, no alarm words, no
  exclamation marks except the healthy celebration ("Everything checked is healthy.").

## 10. Risks and open questions
- Large estates (hundreds of endpoints) need clustering on the map: done in GX6 (the addresses of one host become a counted group above 120 nodes); tested with a generated 500-entity fixture.
- Animations on a software-rendered remote session (RDP) can be slow: when `RenderCapability.Tier` is 0 the window uses reduced motion.
- Comparing runs needs a stable finding identity; findings do not carry one yet (GX8 adds a deterministic `Key`).
- A score can be misread as a certification: the wording and the "How is this scored?" link are part of the Must.

## 10b. What the full-page map taught (GX6, 2026-11-27)
- **Work off the UI thread, then in slices.** The map model, view and layout run in a background runspace (pure functions only); the window creates elements and build
  animations in slices of 15 ms on a new canvas that replaces the old one when complete. Creating a large build storyboard in one go took 363 ms; in slices 95 % of the
  ticks stay under 20 ms. Attaching 700 elements at once costs about 40 ms, so the new canvas is attached (collapsed) before the first slice. Windows PowerShell compiles a
  function after about 16 calls: the drawing code is warmed up at start-up so that compile never lands in a slice. Panning and zooming change two transforms (0.3 ms).
- **Order before position.** Median sweeps fix the order inside each column (the mean oscillates when a shared host has one far address); positions then follow the order
  (least squares under a minimum gap). Crossings are counted, not guessed.
- **Keyboard on a canvas.** Arrow keys move a focus ring between nodes in reading order (linked nodes first when changing column), Enter opens, Shift+arrows pan; selection
  pushes onto the pane's trail, so Back and Alt+Left also move the map selection.
- **Windows PowerShell 5.1 traps met here:** `[Array]::Sort($keys, $items)` sorts a copy of the items unless both are cast to `[Array]`; `Key.Enter` is `Key.Return`, so
  compare enums, not names; variables are case-insensitive (`$p` overwrote a typed `$P`); `-in` on an enum compares strings.

## 11. What the GX0 prototype taught (2026-11-23)
The mission-control Overview and the discovery map were built in the real window (`src/Gui/GuiMission.ps1`, `src/Gui/GuiMapView.ps1`) and
judged on PNGs in two rounds (`docs/GUI-DESIGN.md` §7). Decisions that change this design:
- **Composition.** One hero card is the control strip: score ring with band (left), the run's headline and the top 3 "What to do next"
  rows (middle), the area bars (right). The map gets the **full width** below it: four columns need about 1000 px for readable labels,
  and side by side with the actions they were cut to 110 px. At 1360 x 860 the hero and the top of the map share the first screen.
- **One status voice.** The run-state icon next to the headline was removed: the ring and its band carry health, so a red icon never
  sits beside an amber band. "Partial score" is a small pill under the band with the full sentence in its tooltip.
- **Data colours.** The status foreground colours (#7A4F00 for warning) read as muddy brown on a ring or bar. Mid-tone data colours were
  added (`B.GoodData`, `B.WarnData`, `B.BadData`, `B.AdminData`, `B.NeutralData`, `B.InfoData`), each at least 3:1 on white.
- **Map columns.** Root CAs, issuing CAs, the addresses the CAs publish, and what serves them (a host, or Active Directory for `ldap:///`
  addresses). Column widths follow the longest label; labels drop the first word all CA names share (the organisation) and keep the full
  name in the tooltip; two addresses with the same file name show their host. A CA whose properties could not be read sits with the
  issuing CAs in the "could not check" colour. Hosts follow the **median** of their addresses, so one far-away link does not pull a
  shared host out of its group. Links start where the label text ends; the chain link is the accent colour.
- **Honest motion.** The build is a replay of the finished graph in discovery order (CAs, then each address with two probe pulses, then
  its health colour; hosts after their first address; CAs graded last; about 3 s). During a live run the map cannot build yet: the engine
  sends no graph events until GX1. "Replay discovery" plays it again; reduced motion shows the final state at once.
- **Snapshots.** `-Snapshot` holds the one Storyboard at 300, 1250 and 2100 ms (`05-build-*`, `06-build-map-*`) and at the end for every
  other frame. WPF clamps the window to the screen, so a 1920 x 1080 frame needs a screen at least that large.
- **Open for GX2.** "Top issues" further down repeats part of "What to do next" (merge or drop it); a healthy-run celebration; the
  count-up of the score; the area bars as filters are in, the actions page ("All actions" opens Findings filtered for now).
