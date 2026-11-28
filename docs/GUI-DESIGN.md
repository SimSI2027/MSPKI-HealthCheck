# GUI design

The window (`Start-MspkiHealthCheckGui.ps1`, `src/Gui/`) is pure XAML on Windows PowerShell 5.1 / .NET Framework 4.x, in-box WPF
only. Styles live in `src/Gui/Theme.xaml`; `src/Gui/MainWindow.xaml` only uses them. No environment data appears here.

The design is judged with an adversarial loop: a **generator** builds the window, a **discriminator** judges only the rendered
PNGs (never the code) against the reference standard below, using the fixed rubric. Rounds are logged at the end of this file.

## 1. Reference standard ("real" enterprise admin software)

Qualities shared by Windows 11 Fluent design, Windows Admin Center and Microsoft's web admin portals. Qualities only: no logo,
brand asset or product name is copied.

**Layout**
- A fixed frame: a slim title bar, a left navigation pane with icon + label items, a command bar of verbs above the content, a
  thin status bar. The frame never moves; only the content area scrolls.
- One primary action per screen (filled accent button); every other command is a quiet secondary or subtle button.
- Content is built from cards on a light neutral canvas: white surfaces, 1 px hairline strokes, no heavy shadows.
- Master/detail: a list or tree on the left, a details pane on the right with a resizable divider.
- Every page starts with a page title and one line that says what the page is for.
- Layout adapts to width without overlap, clipping or horizontal page scroll; wide screens get more data, not bigger gaps.

**Spacing**
- A 4 px base grid (4, 8, 12, 16, 20, 24, 32). Page gutters 24, card padding 16–20, gaps between cards 16.
- Controls share one height (32 px); grid rows 32–36 px; nav items 36–40 px. Labels align to a common left edge.

**Typography**
- Segoe UI throughout; a small type ramp used consistently: caption 12, body 13–14, body strong (semibold), subtitle 16–20,
  title 20–28, display numbers 28+. Sentence case for labels and headings (no shouting caps).
- Monospace only for machine data (evidence, logs, identifiers). Long text truncates with an ellipsis and a tooltip.

**Colour**
- Neutral greys carry the structure (canvas ~#F5F5F5, surfaces #FFFFFF, strokes ~#E0E0E0, text ~#242424, secondary ~#616161).
- One accent (a Microsoft-style blue) for the primary button, selection, focus and links.
- Status colours are soft tints with dark foregrounds (success green, warning amber, danger red, info blue, a purple for
  "needs elevation"), always paired with an icon and a word. WCAG AA: 4.5:1 for text, 3:1 for icons and control boundaries.

**Density and data**
- Admin tools are dense but calm: many rows on screen, light header rows, hairline row separators, clear selection.
- Status is a compact tinted badge (icon + word), not a big coloured block.
- Grids sort, filter and group; counts are always visible ("Showing 12 of 47").

**Controls and states**
- One family of controls: same corner radius (4 px for controls, 8 px for cards), same border, same hover/pressed/disabled
  behaviour, a visible keyboard focus ring on everything focusable.
- Icons from one monoline icon font, one size per context (16 in nav and command bars, 12–14 inline).
- Every view has designed empty, loading, error and partial states: an icon, a sentence that says what happened and what to do,
  and the action to do it. Never a blank area, never a raw exception.
- Busy work never freezes the window; progress is shown in place (progress bar, current step, elapsed time).

## 2. Scoring rubric (fixed; do not change after round 0)

Each category is scored 1–10 by the discriminator from the PNGs only.

| # | Category | 10 means | 5 means |
|---|---|---|---|
| 1 | Visual hierarchy | The eye lands on health first, then KPIs, then detail; one primary action per screen | Several elements compete; primary action unclear |
| 2 | Alignment and spacing grid | Every edge sits on the 4 px grid; equal gutters; columns line up across cards | Uneven gaps, ragged edges, odd one-offs |
| 3 | Typography | One ramp, sentence case, clear weights, no truncation of key text | Mixed sizes/weights, caps labels, cramped text |
| 4 | Colour and contrast (WCAG AA) | Neutral frame, one accent, soft status tints, all text ≥ 4.5:1 | Loud blocks, low-contrast greys, colour as the only signal |
| 5 | Information density (admin tool) | Lots of data visible without crowding; no wasted bands | Sparse or crammed |
| 6 | Control consistency | Same heights, radii, borders and states everywhere | Mixed control styles, default OS controls leaking through |
| 7 | Iconography | One icon family, consistent sizes and alignment, meaningful glyphs | Mixed sizes, misaligned or missing glyphs (boxes) |
| 8 | Empty, loading, error and partial states | Every state designed, with guidance and an action | Blank areas or bare text |
| 9 | Data readability (grid, tree, details) | Scannable columns, clear selection, readable details | Dense walls of text, unclear selection |
| 10 | Polish | No clipping, blur, overlap, overflow or misalignment at any size | Visible glitches |

**PASS** = every category scores 8 or more **and** there are zero defects a Fortune 500 customer would notice.

Checked at three sizes (minimum size, 1920 x 1080, maximised) and in every state: welcome, running, finished, cancelled/partial,
error (run ended without results), no CAs found, plus every tab and the details panes.

## 3. Design specification (the generator's target)

**Frame.** Custom title bar (in-box `WindowChrome`, no compiled code): app mark, name, version, a "Read-only" badge, the user
badge and caption buttons (minimise, maximise/restore, close; close turns red on hover). Under it, left: navigation pane
(Overview, Findings, Discovery map, Timeline, Objects, PKI services, History, Run log, with Ctrl+1..8; Learn joins as Ctrl+9 in GX9) and the environment the run sees (forest, domain, domain
controller, run as). Right: command bar (Run = the only primary button, Cancel, Open results, Open report, Open folder), the
run-options strip (collapsed summary; expands to the form), a 3 px progress bar while running, then the page.

**Palette (light).**
| Role | Colour | Role | Colour |
|---|---|---|---|
| Title bar | `#1C1F26` | Title bar secondary text | `#AEB6C2` |
| Accent / hover / pressed | `#0F6CBD` / `#115EA3` / `#0C3B5E` | Accent tint / tint stroke | `#EBF3FC` / `#B4D6FA` |
| Canvas | `#F5F5F5` | Surface (cards, grid, panes) | `#FFFFFF` |
| Nav pane | `#FAFAFA` | Subtle hover / pressed | `#F0F0F0` / `#E6E6E6` |
| Stroke (cards, dividers) | `#E0E0E0` | Control stroke / strong | `#D1D1D1` / `#8A8A8A` |
| Text / secondary | `#242424` / `#616161` | Disabled text | `#A6A6A6` |
| Success fg / tint / stroke | `#0E700E` / `#F1FAF1` / `#9FD89F` | Warning fg / tint / stroke | `#7A4F00` / `#FFF8E6` / `#F2CF7A` |
| Danger fg / tint / stroke | `#B10E1C` / `#FDF3F4` / `#EEACB2` | Info fg / tint / stroke | `#0F548C` / `#EBF3FC` / `#B4D6FA` |
| Elevation (admin) fg / tint / stroke | `#5C2E91` / `#F7F4FB` / `#C6B1DE` | Neutral fg / tint / stroke | `#424242` / `#F5F5F5` / `#D1D1D1` |
| Data: good / warning / danger | `#107C10` / `#C27C0E` / `#D13438` | Data: admin / neutral / info | `#8764B8` / `#8A8A8A` / `#0F6CBD` |

Data colours fill the score ring and the area bars only (at least 3:1 on white); text and icons keep the foreground colours.

Tones: Good = Pass / succeeded, Warn = Warning / unsupported, Bad = Fail / Critical / failed, Info = Information,
Admin = Error / permission denied / administrator, Neutral = skipped / not applicable / not tested.

**Type.** Segoe UI. Caption 12, body 13, body strong 13 semibold, card title 14 semibold, page title 20 semibold, KPI 28
semibold. Sentence-case section labels (12 semibold, secondary colour). Consolas 12 for evidence, logs and identifiers.

**Shape and spacing.** 4 px grid; page gutter 24; card padding 16–20; card radius 8; control radius 4; badges radius 4; filter
chips fully rounded. Controls 32 px; grid rows 36 px; nav items 36 px; title bar 40 px; command bar 48 px; status bar 28 px.

**Icons.** `Segoe Fluent Icons` with `Segoe MDL2 Assets` as the fallback (one `FontFamily` value; WPF falls back per glyph).
16 px in nav and command bar, 12–14 px inline. Glyph code points for data live in `GuiModel.ps1` / `GuiView.ps1`.

**Accessibility.** Icon + text on every status, never colour alone. Full keyboard path: Tab order through the frame, arrow keys in
nav, grid and tree; F5 run, Esc cancel / clear filter, Ctrl+F search, Ctrl+O open, Ctrl+K command palette, Ctrl+1..8 pages, F6 to the details pane, Alt+Left back. Visible focus ring on every
focusable control. Layout rounding on, so lines stay crisp from 100 % to 200 % DPI.

## 4. Feature inventory (every one must survive a redesign)

Mission control on the Overview (GX0): health score ring with band, "Partial score" and "How is this scored?"; area bars that open the
Findings page filtered to the area; "What to do next" (top 3 ranked actions with their most probable cause and an Observed mark, "All
actions"); the discovery map that builds itself (Replay discovery; each node opens its object; legend; reduced motion respected).
Run (F5) / Cancel (Esc) with a background runspace; open an earlier results.json (Ctrl+O); open report and output folder;
run options (timeout, skip network, system proxy, NDES admin probe opt-in) with a one-line summary; header facts and the
Administrator / standard-user badge; welcome state; health banner with exit code, state and start time; partial/loaded note;
KPI tiles; status and severity tiles that filter the Findings page; CA cards; top issues that open a finding; discovery
coverage (problems listed, successes collapsed) and run limits; Findings grid with free-text search, status chips, severity /
category / confidence filters, group by category, clear filters, sort, multi-select copy (Ctrl+C and context menu), export of the
filtered view, empty-grid text, split details pane with copy; Discovery map tree with expand/collapse all, item count, details
pane, drill into a finding and back; Run log with filter, level filter, auto-scroll, copy shown lines, count and empty text;
status bar with state icon, current stage, current target, elapsed time, finding count and output folder; Objects page (Ctrl+5:
every object of the graph grouped by type, search, type filter, "needs attention", count, empty text); object details pane (what it is
and why it matters, properties, host identity, where it exists, expected-but-missing places apart, related objects, findings,
breadcrumbs and Back) opened from the Findings pane, the Discovery map pane, the Objects list, KPI tiles and CA cards; PKI services page
(Ctrl+6: Web Enrollment, CES, CEP, NDES/SCEP, OCSP, Intune connector, each with its state, instances, findings and what this run
can see; "not found", "cannot be checked from here" and "not checked in this run" kept apart; opens details on the right); developer snapshots
(`-Snapshot`, writes only under `out\`).

## 5. Rounds

### Round 1 (generator: new design; discriminator: PNGs at 1080x700, 1920x1080, maximised)
Scores: hierarchy 7, alignment 7, typography 7, colour 8, density 6, controls 8, icons 8, states 6, data readability 6,
polish 6. **Not a pass.**
Top defects: KPI labels cut off at minimum size ("Certification aut..."); Findings filter header takes half the panel at
minimum size and the grid hides Message/Confidence behind a horizontal scroll; tree rows show an Information + Confirmed
badge on every row (noise) and the root's "worst below" text is clipped; Overview has no running state (only welcome text);
the error state repeats its message in a second notice; "Needs review: 0 item(s) need a review" contradicts itself;
"(s)" plurals and " | " separators read as debug text; coverage reasons wrap in a narrow column; top-issue badge column
leaves a gap; details-pane badges wrap under the Copy button; Environment shows dashes before a run.
Fixed in round 1: maximised padding measured at 8 px (overhang = (3856 - 3840) / 2).
Next (round 2): value-first KPI tiles; compact nav under 1280 px; grid columns Status, Target, Message first; self-labelled
filter combos on one wrap row; icon-only status in the tree; a running panel on Overview bound to the status bar; single error
notice; proper plurals and separators; pill + title on one line in top issues and coverage; icon-only Copy.

### Round 2
Generator: value-first KPI tiles; compact navigation (icons only, environment in a tooltip) under 1280 px; grid columns
Status, Target, Message first; self-labelled filter drop-downs ("Severity: All"); icon-only status in the tree with confidence
as quiet text and "worst below" as a small badge; running panel on the Overview bound to the status bar; one error notice;
proper plurals (`Format-MspkiGuiCount`) and middle-dot separators; badge + title on one line in top issues and coverage;
icon-only Copy; "Known after a run" instead of dashes; "Needs review" no longer says "0 items need a review".
Scores: 8/7/8/8/7/8/7/8/7/7. Top defects: status chips overflow the panel at minimum size; "Information" badge clipped in the
grid; status tiles 380 px wide with little in them at 1920; expand/collapse icons do not match; "CA  name" double space.

### Round 3
Generator: chips on their own wrapping row; wider Status column; status tiles in one row of eight from 1600 px; chevron icons
for expand/collapse; "Category · Target" titles.
Scores: 8/8/8/8/7/8/8/7/7/8. Top defects: partial run said "partial" three times (banner, note, meta); on an ultra-wide maximised
screen the details pane and search box stretch to 200-character lines; Findings shows only ~4 rows at minimum size.

### Round 4
Generator: partial note removed (the banner says it); details pane capped at 640 px and search box at 640 px; page subtitles
hidden in compact navigation. Also rendered at 200 % DPI (crisp, no blur).
Scores: 9/8/8/9/8/8/8/9/8/8. Remaining defect: long URL rows in the tree pushed their confidence text past the panel edge.

### Round 5 (final)
Generator: tree labels capped so the confidence text stays visible; the stopwatch in the status bar hides when no time is shown.
Discriminator (PNGs at 1080x700, 1920x1080, maximised on a 3840 px screen, 200 % DPI): **PASS** on the rubric.
Scores: hierarchy 9, alignment 8, typography 8, colour 9, density 8, controls 8, icons 8, states 9, data readability 8, polish 8.

What still separates it from a top-tier product (known, not fixable within the constraints or out of scope):
- Message boxes (export done, open errors) are the standard Windows dialog, not themed content dialogs.
- No Windows 11 snap-layout flyout on the maximise button and no Mica backdrop (both need P/Invoke, which is banned).
- Light theme only: no dark theme and no tailored high-contrast theme (system high contrast falls back to these colours).
- At the minimum size the Findings grid shows about five rows; Category, Severity and Confidence scroll horizontally.
- No column chooser or remembered layout (column widths, splitter position, last page) between sessions.
- No motion (page transitions, progress shimmer); the container icon in the tree is a generic library glyph.

### WP7 round 1 (2026-11-22, new views: Objects page, object details, PKI services; example fixture at 1080x700 and 1920x1080)
Scores: hierarchy 8, alignment 8, typography 8, colour 9, density 7, controls 8, icons 8, states 8, data readability 7, polish 7. **Not a pass.**
Defects: host details listed its DNS/TLS facts twice (Host identity and Properties); the "what this is" box took four lines of the details
pane at minimum size; breadcrumbs repeated the Back link and pushed the current object onto an orphan second line; a state line broke
inside "-SkipNetwork"; long ids wrapped and were clipped in Objects rows (fixed during WP5).
Generator: host identity facts shown once; the note is one compact line-wrapped paragraph ("What it is: ..."); breadcrumbs only from the
third object, listing the objects before the current one; state texts without switch names.

### WP7 round 2 (1080x700 and maximised on a 3856 px screen)
Defect found and fixed: on the ultra-wide screen the service card prose ran to 200+ character lines (capped at 880 px, as the details pane
and search box already are).
Scores: hierarchy 8, alignment 8, typography 8, colour 9, density 8, controls 8, icons 8, states 8, data readability 8, polish 8. **PASS.**
Known, accepted: on an ultra-wide screen the state badge of a service card sits far from its title (right-aligned in a wide card); the object
id is a second, long monospace line under the title; generator and discriminator were the same model in this loop.

## 6. Upgraded rubric (fixed from 2026-11-23; do not change after its round 0)

Replaces §2 for every round from the GUI program (GX work packages in `docs/ROADMAP.md`) on. The experience it judges is in
`docs/GUI-EXPERIENCE.md`. The discriminator judges only rendered PNGs (still frames, including frames captured mid-animation) and, for
the usability and delight categories, a written click path of the journeys J1-J6 replayed on those PNGs. It assumes the window is **not**
enterprise grade until the images prove otherwise, lists every defect by page and control, and scores 1-10 per category.

### A. Visual (the ten categories of §2, unchanged)
| # | Category | 10 means | 5 means |
|---|---|---|---|
| A1 | Visual hierarchy | The eye lands on health first, then KPIs, then detail; one primary action per screen | Several elements compete; primary action unclear |
| A2 | Alignment and spacing grid | Every edge sits on the 4 px grid; equal gutters; columns line up across cards | Uneven gaps, ragged edges, odd one-offs |
| A3 | Typography | One ramp, sentence case, clear weights, no truncation of key text | Mixed sizes/weights, caps labels, cramped text |
| A4 | Colour and contrast (WCAG AA) | Neutral frame, one accent, soft status tints, all text >= 4.5:1 | Loud blocks, low-contrast greys, colour as the only signal |
| A5 | Information density (admin tool) | Lots of data visible without crowding; no wasted bands | Sparse or crammed |
| A6 | Control consistency | Same heights, radii, borders and states everywhere | Mixed control styles, default OS controls leaking through |
| A7 | Iconography | One icon family, consistent sizes and alignment, meaningful glyphs | Mixed sizes, misaligned or missing glyphs (boxes) |
| A8 | Empty, loading, error and partial states | Every state designed, with guidance and an action | Blank areas or bare text |
| A9 | Data readability (grid, tree, map, details) | Scannable columns, clear selection, readable details and node labels | Dense walls of text, unclear selection, overlapping labels |
| A10 | Polish | No clipping, blur, overlap, overflow or misalignment at any size or animation frame | Visible glitches |

### B. Usability
| # | Category | 10 means | 5 means |
|---|---|---|---|
| B1 | First-run clarity | A first-time user knows what the tool does, that it changes nothing, and what to press, from the welcome screen alone; the finished screen explains its own score | The user must guess what Run does or what the numbers mean |
| B2 | Findability | Every journey's goal is visible or one obvious click away; the palette, nav labels and links name things the way users think of them | Key functions hidden in menus or only reachable from one place |
| B3 | Task-completion speed | Journeys J1-J6 meet their targets in `docs/GUI-EXPERIENCE.md` §3 (clicks and seconds) | Each journey needs detours, scrolling or the Findings grid |
| B4 | Error recovery | Every failure says what happened, what it means and what to do, with the action next to it; nothing is lost; Back always works | Raw errors, dead ends, lost context after an error |
| B5 | Feedback and responsiveness | Every action answers within 100 ms (visual change); long work shows live progress and what is being checked; the window never freezes | Silent clicks, frozen frames, progress that does not move |

### C. Delight
| # | Category | 10 means | 5 means |
|---|---|---|---|
| C1 | Engagement | The window invites exploring: the map, the walkthrough and the history reward curiosity; users want to open it again | Functional but inert |
| C2 | Moments of insight | At least one "now I see it" moment per journey (the chain shows which link breaks; the timeline shows the CRL will lapse on Friday) | Facts without meaning; users must connect the dots |
| C3 | Motion quality | Motion has meaning (something found, checked or done), is smooth and short, never delays input, and stops with reduced motion; mid-animation frames look composed | No motion, gratuitous motion, or janky frames |
| C4 | "Would users show it to colleagues" | A PKI admin would put it on a shared screen in a meeting without apology | It works, but nobody would show it off |

**PASS** = every category (A1-A10, B1-B5, C1-C4) scores **8 or more** **and** there are **zero defects a Fortune 500 customer would
notice**. Checked at minimum size, 1920 x 1080 and maximised, light and dark (once dark exists), in every state of §2 plus the live
discovery frames (start, mid-build, probing, finished, healthy celebration), with reduced motion on and off.

## 7. Rounds on the upgraded rubric

### GX0 round 1 (2026-11-23; prototype: mission-control Overview + discovery map; demo-world `mixed-sample` results; PNGs at 1080 x 700 and 1360 x 788, build frames at 300 / 1250 / 2100 ms)
Before the round, the generator fixed what its own first render showed: status foreground brown on the ring and bars (data colours added),
a red run-state icon beside the amber band (icon removed), causes wrapping to three lines, the map below the fold (note moved under the map).
Scores: A1 8, A2 8, A3 7, A4 8, A5 8, A6 8, A7 7, A8 7, A9 8, A10 7; B1-B5 8; C1 8, C2 8, C3 8, C4 8. **Not a pass.**
Defects: action titles cut at minimum size ("...ends at a root that is n..."); map status badges 14 px with a 7 px glyph (unreadable); no-CA
state showed "no score" on the ring but scored the areas, and the reason was only a tooltip; at 300 ms the area numbers stood next to empty
bars; links from shared hosts crossed three times.
Generator: titles wrap to two lines; badges 16 px with a 9 px bold glyph; without a CA no area is scored and the reason is shown under the
ring; each number fades in with its bar; addresses grouped by host inside each CA, hosts placed at the median of their addresses.

### GX0 round 2 (same sizes and frames)
Scores: A1 9, A2 8, A3 8, A4 8, A5 8, A6 8, A7 8, A8 8, A9 8, A10 8; B1 8, B2 8, B3 8, B4 8, B5 8; C1 8, C2 9, C3 8, C4 8. **PASS** (prototype scope:
the Overview and its states; the other pages were not changed).
Known, accepted for the prototype (each has a GX work package): one long link remains where a root's own CRL is served by a shared host;
"Top issues" lower on the page repeats part of "What to do next" (GX2); the map replays the finished graph instead of building during a
live run (GX1); no healthy celebration yet (GX9); a 1920 x 1080 frame could not be rendered because WPF clamps the window to this
session's 1386 x 788 screen; in the synthetic no-CA frame the map still shows the CAs of the unchanged graph (a real run without a CA has
none); generator and discriminator were the same model.

### GX2 round 1 (2026-11-23; Overview in production form; Alcyone `mixed-sample` results plus a real lab run kept under out\ only; PNGs at 1080 x 700 (minimum), 1360 x 860 and 1920 x 1080; live frames at 6 / 28 / 55 / 86 percent and one with motion on)
Scores: A1 9, A2 8, A3 8, A4 8, A5 8, A6 7, A7 8, A8 8, A9 8, A10 7; B1-B5 8; C1 8, C2 8, C3 7, C4 8. **Not a pass.**
Defects: (1) the first minimum-size frames were cut at the right edge (area bars missing): the snapshot laid the content out at the fixed size but left the
navigation at its wide mode, because the compact-navigation rule read the real window's width (a method defect, fixed: width-dependent rules read the fixed
width, and the fixed size is now the content's own size so later layout passes keep it); (2) "How is this scored?" opened a Windows message box (A6);
(3) the live motion had never been seen (C3); (4) at minimum size the cause line of an action was cut hard (kept: one line keeps the map near the first screen,
the full text is in the tooltip and the walkthrough).
Generator: the score explanation is a themed popup in the window; animations are asserted in tests (the first batch of nodes fades in, a node pulses exactly while
its probe runs and stops when it ends); a frame is captured 150 ms into the live motion.

### GX2 round 2 (same sizes and frames)
Scores: A1 9, A2 8, A3 8, A4 8, A5 8, A6 8, A7 8, A8 8, A9 8, A10 8; B1 8, B2 8, B3 8, B4 8, B5 8; C1 8, C2 8, C3 8, C4 8. **PASS** (scope: the Overview, in its running,
finished, partial and no-CA states).
Journeys: J1 starts on the Overview (Run, then the same hero turns into the live mission control: ring = progress, the map fills as the engine announces objects,
probes pulse, the controls stay in the hero); J2 is answered by the headline sentence at the top (no scrolling at 1360 x 860); the ring, the area bars and "All N actions"
lead to the Findings page or the full list.
Known, accepted (each has a work package): the popup is a separate window, so it is not in the PNGs (judged from its code and a test); the live colours say "answered" or
"did not answer", health is graded when the run ends (findings only exist then); a redraw of the live map repositions earlier nodes when a batch changes the columns (GX6
adds clustering and a stable layout); no healthy celebration yet (GX9); generator and discriminator are the same model.

### GX3 round 1 (2026-11-27; guided walkthrough in the details pane; Alcyone `mixed-sample` results plus a real lab run kept under out\ only; PNGs at 1360 x 860; frames 23 opened from the first Overview action, 24 the causes, 25 one check marked and its copy button answering)
Scores: A1 8, A2 7, A3 7, A4 8, A5 8, A6 8, A7 8, A8 7, A9 8, A10 8; B1 7, B2 8, B3 8, B4 8, B5 8; C1 7, C2 8, C3 8, C4 8. **Not a pass.**
Defects: (1) three nested cards (section, accent frame, cause) left a cause heading about 200 px wide, wrapped to seven lines (A2, A3); (2) the walkthrough sat
below the fold, under the finding's own "Suggested action" (B1, J3 needed scrolling); (3) the storage note ("checked marks last...") stood between the heading
and the causes (A8); (4) the snapshot of a marked check showed nothing new: the frame scrolled to the section heading, not to the check (a method defect).
Generator: one card per cause with a 3 px accent strip when this run observed something for it and the pills ("Most likely", "Observed in this run") on their own
row above the heading; no outer card; the walkthrough follows "What was found" directly and the suggestion moves below it; the storage note sits under the causes
and is shorter; a marked check turns muted at once (bound to its own box, not to the view model); frame 25 scrolls to the first check.

### GX3 round 2 (same frames at 1080 x 700 (minimum), 1360 x 860 and 1920 x 1080, world and lab)
Scores: A1 9, A2 8, A3 8, A4 8, A5 8, A6 8, A7 8, A8 8, A9 8, A10 8; B1-B5 8; C1 8, C2 8, C3 8, C4 8. **PASS** (scope: the walkthrough). One defect fixed in the
round: a tick box sat about 10 px below the first line of its check (now aligned). J3: the first Overview action opens the finding with the walkthrough in view (1
click), a check's copy button copies it (2 clicks); the button answers with a green check mark for 1.4 s, with no animation (reduced motion needs nothing).
Known, accepted: the details pane keeps its width (about 400 px at 1360 x 860), so long checks wrap; the tick boxes are keyboard-reachable but there is no shortcut yet
(GX4 command palette); generator and discriminator are the same model.

### GX4 round 1 (2026-11-27; command palette and toasts; Alcyone `mixed-sample` results; PNGs at 1080 x 700 (minimum) and 1360 x 860; frames 26 palette opened, 27 a search, 28 no match, 29 two toasts)
Scores: A1 8, A2 7, A3 7, A4 8, A5 8, A6 7, A7 8, A8 7, A9 8, A10 8; B1 8, B2 7, B3 8, B4 8, B5 8; C1 8, C2 8, C3 7, C4 8. **Not a pass.**
Defects: (1) an empty grey box stood where a result's status pill should be, and findings showed no pill (the visibility binding sat on the ContentPresenter whose own
data is the pill: A6); (2) a search for "crl" gave seven results with the same title ("CRL - CN=...": B2), and their detail wrapped to three lines (A3); (3) with
nothing typed, "How is this scored?" came first and "Run health check" sixth (Sort-Object in Windows PowerShell 5.1 is not stable: A8); (4) the toast frame was caught
mid-fade (a method defect).
Generator: the pill sits in a Border that carries the visibility; a finding's title is its message and the detail line is category, target and id, both trimmed to one
line; every entry has a sequence number, so commands keep the command-bar order and findings the worst first; the snapshot shows toasts at full opacity.

### GX4 round 2 (same frames and sizes)
Scores: A1 9, A2 8, A3 8, A4 8, A5 8, A6 8, A7 8, A8 8, A9 8, A10 8; B1-B5 8; C1 8, C2 8, C3 8, C4 8. **PASS** (scope: palette, toasts, keyboard paths). The backdrop dims
the window (measured: 250 -> 169 grey) so the card reads as the one thing in focus; toasts carry a tone strip, an icon and a word, never colour alone.
Journeys by keyboard only (tests/GuiKeyboard.Tests.ps1): J1 Ctrl+K "run" (or F5); J2 Ctrl+1; J3 Ctrl+K, part of the finding, Enter, then F6 to the walkthrough; J4 Ctrl+O or
Ctrl+K "open results" until history arrives (GX8); J5 and J6 arrive with GX9 and GX10. Palette opens in under 100 ms (measured in the test, five opens).
Known, accepted: a Windows message box remains for a failure before the window is on screen; the palette has no fuzzy matching (every typed word must appear);
generator and discriminator are the same model.

### GX5 round 1 (2026-11-27; themes; Alcyone `mixed-sample` results and a real lab run kept under out\ only; dark at 1080 x 700, 1360 x 860 and 1920 x 1080; light at 1360 x 860; a high-contrast mapping frame)
Scores (dark): A1 6, A2 8, A3 8, A4 6, A5 8, A6 5, A7 8, A8 7, A9 8, A10 7; B1-B5 7; C1 7, C2 7, C3 8, C4 7. **Not a pass.**
Defects: (1) black text on the dark surface in the details pane, the walkthrough, the welcome steps and the map labels (WPF's own styles for TabControl, TabItem,
ListBox, DataGrid and others set the system text colour, which overrides the inherited one; the light theme hid it because #000 and #242424 look alike: A4, A6);
(2) the caption buttons and the selected navigation item were invisible (white "on accent" text on the dark header; a fixed #EBEBEB selection: A6); (3) about twenty
fixed colours in the templates (focus ring, scroll bars, check boxes, badges, hover lines) stayed light (A1).
Generator: every control style that WPF gives a system colour now sets the theme text colour, and the root sets it too; two new keys (B.OnHeader for text on the dark
header, B.OnData for glyphs on data colours) and twelve more for the fixed colours, in both palettes; map and area labels take the theme colour by reference.

### GX5 round 2 (same frames)
Scores (dark): A1 8, A2 8, A3 8, A4 8, A5 8, A6 8, A7 8, A8 8, A9 8, A10 8; B1-B5 8; C1 8, C2 8, C3 8, C4 8. Light unchanged (0.5 to 1 % of sampled pixels differ: the new
theme button and #242424 text where WPF drew #000). **PASS** (scope: theming). Contrast is measured, not judged: tests/GuiTheme.Tests.ps1 checks 43 pairs in each palette
(text 4.5:1, data colours, control borders and badge glyphs 3:1).
Known, accepted: the high-contrast frame shows this computer's normal SystemColors (a real high-contrast theme changes them; the mapping is tested key by key); the role
badge in the header keeps its fixed colours (the header is dark in every theme); the palette backdrop and shadows are fixed; generator and discriminator are the same model.

### GX6 round 1 (2026-11-27; full-page Discovery map and the owner's nine review items; Alcyone `mixed-sample` results; light at 1360 x 860; frames 12 Overview map, 30 map, 30a opened, 30b keyboard focus, 30c only problems, 30d search, 30e zoomed with minimap, 30f no match, 30g replay at 1400 ms)
Scores: A1 8, A2 8, A3 7, A4 8, A5 7, A6 6, A7 8, A8 7, A9 7, A10 7; B1 8, B2 8, B3 8, B4 8, B5 8; C1 8, C2 8, C3 8, C4 7. **Not a pass.**
Defects: (1) the three filter boxes showed "@{Text=All statuses; Value=All}" (the FilterCombo template ignores DisplayMemberPath: A3, A6); (2) Replay and Export image stayed
disabled after the map was drawn (A6); (3) the details pane opened on the tree's forest item, unrelated to the map (A8); (4) with "Only problems", the directory node stood
alone without the addresses that lead to it (A9); (5) the map opened at 64 % because of generous column spacing (A5).
Generator: plain-text choices with the value looked up by position; the buttons follow the drawn map; the pane belongs to the view on show (a hint on the map, the tree's
item in Tree); the context of a shown problem is everything upstream of it (a host's addresses, an address's CA, the CA's issuers); link spacing 52 px and labels 200 px.

### GX6 round 2 (same frames, plus a generated 500-object estate (light, 1360 x 860), a 300-object estate (dark, 1920 x 1080), the world at minimum size (dark), at 150 % (dark) and 200 % (light), and a real lab run kept under out\ only)
First pass of the round: (1) on a dense fan the link markers stacked in one column in the middle of the links (A10); (2) the 500-object map opened at 25 % (unreadable, A9);
(3) the Overview card grew to about 1100 px for the large estate (A5); (4) at 150 % the "shown for context" line wrapped onto the next label (A10).
Generator: one marker per target and tone, 78 % along the link, beside the node it belongs to; a new run opens at 67 % or more, centred, with the minimap showing the whole
(Fit and Ctrl+0 still show everything); the Overview map is at most 560 px tall and fades into an "Open the whole map (N objects)" button; map labels never wrap.
Scores after the fixes: A1 9, A2 8, A3 8, A4 8, A5 8, A6 8, A7 8, A8 8, A9 8, A10 8; B1 8, B2 9, B3 8, B4 8, B5 9; C1 9, C2 9, C3 8, C4 8. **PASS** (scope: the Discovery map page,
the Overview map card, the status bar and banner of an earlier run).
Owner review: (1) Zenith Issuing CA has a dashed "issuer not confirmed" link to Lodestar Root CA (the only root found), with the reason on hover; a placeholder "Unknown issuer"
when there is no single root; (2) crossings on the demo world go from 12 to 0 (asserted); (3) pulses stay under the opaque label boxes and within the row spacing, the canvas
clips; (4) badges are 18 px with a 9 px glyph, up and right of the circle (never on the icon), with the status word in the tooltip and the pane; (5) a link into a failing
address is red dashed with a cross marker, a warning amber with a warning marker; (6) every link explains itself in plain words on hover; (7) one icon table (section 8), an
earlier run is information; (8) the status bar keeps "Showing an earlier run", the banner has the full sentence and "Run now"; (9) Open report follows report.html (or
<name>-report.html) beside the loaded file, checked again when the window comes back to the front (verified on the lab run).
Known, accepted: link hover text and node hover cards are tooltips (popups are not in the PNGs; their text is asserted in tests); links between a root and an address skip
the issuing column, and such long links can pass behind a label box (the box hides them, by design); the generated estate's random host assignment keeps many crossings
(the count still goes down: 6694 to 6028); generator and discriminator are the same model.

### GX7 round 1 (2026-11-28; Timeline page: Certificates, CRLs and Chain views; Alcyone `expired-crl` and `renewal-drift` samples; light at 1360 x 860; frames 35 CRLs, 35a certificates, 35b range 3 months, 35c a row opened, 35d Back, 35e chain, 35f an address of the chain opened)
Scores: A1 8, A2 8, A3 7, A4 8, A5 7, A6 7, A7 8, A8 7, A9 7, A10 7; B1 8, B2 8, B3 7, B4 8, B5 8; C1 8, C2 8, C3 8, C4 7. **Not a pass.**
Defects: (1) CA names cut in the group rows ("Alcyone Meridian Issuin...", A10); (2) in Certificates the CA pill said Failing because of its CRL (A8, honesty of
the view); (3) "Runs out first" listed CRLs in the Certificates view (A8); (4) "Replaced · expired 2 years 6 months ag" cut (A10); (5) the leaf card of the chain was
green while every CDP address failed (A8); (6) the chain's start was cut in its box (A10); (7) the details pane showed raw property names ("CAVersion", "Crl Number")
and ISO times ("2026-11-17T08:00:00Z") and a distinguished name as the heading (A3, B3); (8) a month axis said "2027" between "Dec 2026" and "Feb 2027" (A3); (9) the page
subtitle left "it." alone on a line (A2).
Generator: group titles wrap (two lines at most); each view has its own CA status and its own "runs out first"; a replaced generation's countdown uses the largest unit;
a card whose CDP addresses all fail is failing, some failing or warning is a warning; the chain's start fills the toolbar, name first, full text in its tooltip; pane
property names in sentence case with the usual acronyms (one helper), UTC times as "17 Nov 2026, 08:00 UTC", headings use the common name (the DN stays in the properties);
months always carry their year; subtitle shortened.

### GX7 round 2 (same frames, plus dark at minimum size (renewal-drift), light at 150 % (expired-crl), and a real lab run kept under out\ only)
First pass of the round: (1) at minimum size "Copies at each address" was cut (the toolbar no longer wrapped, A5); (2) the last date of the axis was cut at the right edge
(A10); (3) on the lab run, a root that could not be read showed "Could not check" in the CRLs view although its CRLs were read from AD (A8); (4) "Issued by · 0 of 1 AIA
addresses served it" above an address that served it with a warning (A8, B3); (5) the run's line crossed a date label (A10); (6) a CA card whose only CDP answered with a
warning was shown failing (A8).
Generator: the range and copies wrap again and the chain's start overlays them in the Chain view; date labels that would be cut, crowd the one before, or sit under the
run's line are left out (the tick stays) and the axis is redrawn when the lane's width changes; "could not check" per view only when that view has nothing read (the CA row's
tooltip says the CA itself was not read); an address with a warning served the issuer ("its AIA address served it, with a warning"); only all-failing CDPs fail a card.
Scores after the fixes: A1 9, A2 8, A3 8, A4 8, A5 8, A6 8, A7 8, A8 9, A9 8, A10 8; B1 8, B2 8, B3 8, B4 8, B5 9; C1 8, C2 9, C3 8, C4 8. **PASS** (scope: the Timeline
page in its three views, the details pane's properties and headings everywhere).
Known, accepted: a long copy title ("Active Directory (LDAP) · ...") and a long chain start are cut with the full text in the tooltip; the root's own CDP (a root that names
one) is shown as it is; the CRL heartbeat of a CA this run could not read appears only when its CRLs were read elsewhere; generator and discriminator are the same model.

### GX8 round 1 (2026-11-28; History page: runs of a forest, score over time, What changed; three-run demo history (`tools/dev/New-MspkiDemoHistory.ps1`, under out\ only); light at 1360 x 860; frames 36 the run on show against the run before it, 36a against the oldest, 36b the bottom of the comparison)
Scores: A1 8, A2 8, A3 7, A4 8, A5 8, A6 7, A7 8, A8 6, A9 7, A10 7; B1 8, B2 8, B3 7, B4 8, B5 8; C1 8, C2 8, C3 8, C4 7. **Not a pass.**
Defects: (1) a resolved finding said "Was pass, now warning": the before and after were swapped (A8, data honesty); (2) status words as codes ("pass", "critical") and
distinguished names as titles ("CRL · CN=Alcyone Meridian Issuing CA, DC=...", A3, B3); (3) an area scored in neither run showed "— → —" (A3); (4) the run count stood twice,
in the forest box and beside it (A6); (5) a first render failed: a local variable named like a parameter replaced it (PowerShell names ignore case), and the page's own
status-rank table replaced the Findings page's sort order (one script scope for all GUI files).
Generator: every compared finding carries Before and After; "Was failing, now passing", "Not in the older run; now failing"; titles use the common name; "not scored";
the count beside the forest box only says what the box does not (other forests, runs still being read); renamed the clashing variables and added a test that no two GUI files
define the same script variable; a results file's yes/no read as true/false or "True"/"False" ([bool]'False' is true in PowerShell).

### GX8 round 2 (same frames, plus dark at minimum size, a single saved run (light), and the real lab history under out\ only: 54 runs read in the background)
First pass of the round: (1) the "On show" mark took the row's score colour (red on a failing run, A8: a mark is not a status); (2) at minimum size the counts line wrapped (A5);
(3) with 54 runs the trend's dots crowded and the text said "53 runs" beside "54 runs" (one run had no score, A9); (4) the empty comparison used a library glyph (A7).
Generator: the marks carry their own (information) tone; counts and folder never wrap (full text in the tooltip); smaller dots above 20 runs, "over 53 scored runs"; the
History glyph for the empty comparison.
Scores after the fixes: A1 9, A2 8, A3 8, A4 8, A5 8, A6 8, A7 8, A8 9, A9 8, A10 8; B1 9, B2 8, B3 8, B4 8, B5 9; C1 8, C2 9, C3 8, C4 8. **PASS** (scope: the History page,
its palette commands and shortcuts; J4 is Ctrl+7 or one click on History, and a second click on Compare for another run).
Known, accepted: at most 60 runs are listed (the newest); a run without a score is listed but is not a point of the trend; findings of the older run cannot be opened
(that run is not on show: Open shows it); the demo history's runs are hand-made samples; generator and discriminator are the same model.

## 8. Icon meanings (one table for the whole window; GX6 audit)
One glyph means one thing everywhere: status pills, badges on map nodes and links, banners, toasts, the status bar and the palette. Icons
are Segoe Fluent Icons with Segoe MDL2 Assets as the fallback; colour is never the only signal (the word or the tooltip is always there).
| Glyph | Code | Meaning | Tone | Where |
|---|---|---|---|---|
| circled cross | EA39 | Critical finding; the overall level "At risk" / "Action needed" | Bad | status pills, score band, health banner |
| cross | E711 | Failing (Fail status, a failed check, a failing map node or link, an expired item, a failed action); in a button: Cancel / close | Bad | pills, map badges and link markers, toasts, status bar, Cancel |
| warning triangle | E7BA | Warning, or a risk rated High/Medium (severity), or a place where an object is expected and missing | Warn (Bad for High severity) | pills, map badges and link markers, banner "Needs review", missing places |
| lock | E72E | Could not check: permission denied or not supported here (the engine's Skipped with PERMISSION_DENIED or UNSUPPORTED), or a CA whose properties could not be read | Admin | pills, chips, CA cards, tiles, coverage, map badges |
| error badge | E783 | The check itself failed (Error status) | Admin | pills |
| stopwatch | E916 | Timed out | Warn / Bad | pills, coverage rows |
| clock | E823 | Days left before an expiry; a countdown ("Expires in", "Next update in", "As of the run") | Warn / Bad (Neutral on the as-of pill) | CA card pills, timeline countdowns, validity pills |
| check mark | E73E | Pass, done, confirmed, copied | Good | pills, status bar, copy buttons |
| info | E946 | Information: a note, an earlier run loaded, a hint; never a problem | Info | banners, status bar, toasts, pills |
| sync | E895 | Running / updating | Info | status bar, run hero, "Updating the map" |
| question in a circle | E9CE | Not confirmed / unknown (the "Unknown issuer" node, the "issuer not confirmed" link marker), and "How is this scored?" | Neutral | map, palette |
| question | E897 | Inferred or unknown confidence | Warn / Neutral | confidence pills |
| dash (minus) | E738 | Not applicable, not tested, not scored; on History, an object only the older run found (paired with plus E710, an object only the newer run found) | Neutral | pills, History |
| skip (next track) | E893 | Skipped on purpose (for example a cancelled run or a check that does not apply). Never the power button E7E8 | Neutral | pills, coverage |
Object glyphs (no status): CA EB95, address E774, web host E968, directory E8D4, address group E8B7 (the group shows its count instead), map E81E,
tree E8A4, timeline page E787 (calendar), Certificates view EB95 (the CA glyph), CRLs view and every CRL EA41 (a list; E8C9 is an exclamation mark and read as a warning), History page E81C (history), Chain view E71B
(link), certificate on this computer E977 (a computer; never the key E8D7: the tool never reads keys), AD container E8D4 (the directory glyph); History: better E70E (chevron up), worse E70D (chevron down), changed E8AB (switch), object added
E710 (plus), object gone E738 (minus, see the table). Commands: refresh E72C, run E768, open E8E5, folder E838, export E896 (CSV) and EB9F (image), copy E8C8, search E721, zoom in E8A3, zoom out
E71F, fit E9A6.

## 9. Terms (use these words, and only these)
| Say | Not | Meaning |
|---|---|---|
| finding | issue, alert, result | one thing the run checked and what it saw |
| failing / warning / could not check / healthy / no finding | error, broken, red, OK | the five map and status words (Error status = "the check failed") |
| published address (address) | URL, endpoint, link | an AIA, CDP, OCSP or enrollment URL a CA names |
| host | server, machine | the computer an address names |
| link (on the map) | edge, line, arrow | a relationship between two objects; its hover text says what it means |
| issuer not confirmed | orphan, unknown parent | the CA's issuer could not be read; the most likely one is shown dashed |
| group | cluster | the addresses one host serves, folded into one counted node |
| earlier run | old run, history file | a results.json opened from disk; nothing is scanned |
| run | scan | one health check |
| Discovery map | graph, topology | the page and the Overview card |
| Explain cards | tooltips | the "What it is" notes (GX9 adds the glossary) |
| runs out / expires | lapses, EOL | the end of a certificate's validity (Not After) or a CRL's Next Update, counted from the run |
| next update | NextUpdate | when a CRL stops being valid; "next publish" is when the CA writes the next one (the overlap between them is drawn) |
| copy (of a CRL) | replica, instance | the CRL as one address (or the CA itself) served it; copies can differ |
| chain | path, trust path | from a certificate up to its root, with the result of each AIA and CDP address |
| as of the run | now, today | every countdown counts from the time the run read the data, not from today |
| replaced | historical, superseded | an older CA certificate generation that a newer one replaced |
| run on show | current run, loaded run | the run whose results the window shows now (a live run or an opened results.json) |
| History / compare | diff, delta | the History page; "What changed" compares an older run with a newer one of the same forest |
| new problem / resolved / changed / still open | added, fixed, modified | a failure or warning the newer run has and the older did not / the older had and the newer does not / in both with another status, code or severity / in both, the same |
| objects added / gone | new entities, deleted | objects (by their ids, which are the same in every run) found by only one of the two runs |

### GX9 round 1 (2026-11-28; Explain mode, Learn page, tour, celebration; Alcyone `expired-crl`; light at 1360 x 860; frames 15 explain, 16-tour-1..4, 37 Learn, 37a search, 37b no match)
- Defects: Explain mode underlined everyday words ("3 findings", "1 finding", action titles through "finding") so the page looked like a page of links
  (A7, B2); tour stop 4 pointed at Run while its text was about Ctrl+K and Explain (B1). Strong: the Learn page (two panes, search, designed
  no-match), tour cards placed beside their target inside the window, the scrim keeps the page readable.
- Fixes: everyday words are explained only when they are the whole label; stop 4 points at the Explain button.

### GX9 round 2 (same frames, plus dark at minimum size)
- Explain mode marks the terms only (area names, acronyms, "Partial score", "Held down by", "Could not check"); the tour fits at minimum size in
  dark with its card inside the window; Learn reads well in dark. Celebration has no frame (it needs a healthy live run; its rule is unit-tested,
  and with reduced motion only the notice shows). Verdict: PASS (generator and discriminator are the same model; GX11 uses a separate session).

### GX10 round 1 (2026-11-28; executive summary; Alcyone `expired-crl` as an earlier run with a three-run trend; the HTML rendered by headless Edge at 820 x 1180 and printed to PDF, both under out\ only)
- Defects: "out of 100" wrapped under the score; the not-checked line repeated the method name ("Reading the CA's properties: Reading the
  CA's properties for ..."); the trend had no numbers (A9, B2). Strong: "As of" and the earlier-run notice before the score, the held-down
  sentence, plain causes with honest wording, the footer's limits.
- Fixes: the score block keeps its width; the reason is used alone when it already names the method; a caption under the trend.

### GX10 round 2 (same render)
- One page, nothing wraps badly, every section reads in under a minute. Verdict: PASS (same-model caveat as before).
