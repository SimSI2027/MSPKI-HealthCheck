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
(Overview, Findings, Discovery map, Run log, with Ctrl+1..4) and the environment the run sees (forest, domain, domain
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

Tones: Good = Pass / succeeded, Warn = Warning / unsupported, Bad = Fail / Critical / failed, Info = Information,
Admin = Error / permission denied / administrator, Neutral = skipped / not applicable / not tested.

**Type.** Segoe UI. Caption 12, body 13, body strong 13 semibold, card title 14 semibold, page title 20 semibold, KPI 28
semibold. Sentence-case section labels (12 semibold, secondary colour). Consolas 12 for evidence, logs and identifiers.

**Shape and spacing.** 4 px grid; page gutter 24; card padding 16–20; card radius 8; control radius 4; badges radius 4; filter
chips fully rounded. Controls 32 px; grid rows 36 px; nav items 36 px; title bar 40 px; command bar 48 px; status bar 28 px.

**Icons.** `Segoe Fluent Icons` with `Segoe MDL2 Assets` as the fallback (one `FontFamily` value; WPF falls back per glyph).
16 px in nav and command bar, 12–14 px inline. Glyph code points for data live in `GuiModel.ps1` / `GuiView.ps1`.

**Accessibility.** Icon + text on every status, never colour alone. Full keyboard path: Tab order through the frame, arrow keys in
nav, grid and tree; F5 run, Esc cancel / clear filter, Ctrl+F search, Ctrl+O open, Ctrl+1..4 pages. Visible focus ring on every
focusable control. Layout rounding on, so lines stay crisp from 100 % to 200 % DPI.

## 4. Feature inventory (every one must survive a redesign)

Run (F5) / Cancel (Esc) with a background runspace; open an earlier results.json (Ctrl+O); open report and output folder;
run options (timeout, skip network, system proxy, NDES admin probe opt-in) with a one-line summary; header facts and the
Administrator / standard-user badge; welcome state; health banner with exit code, state and start time; partial/loaded note;
KPI tiles; status and severity tiles that filter the Findings page; CA cards; top issues that open a finding; discovery
coverage (problems listed, successes collapsed) and run limits; Findings grid with free-text search, status chips, severity /
category / confidence filters, group by category, clear filters, sort, multi-select copy (Ctrl+C and context menu), export of the
filtered view, empty-grid text, split details pane with copy; Discovery map tree with expand/collapse all, item count, details
pane, drill into a finding and back; Run log with filter, level filter, auto-scroll, copy shown lines, count and empty text;
status bar with state icon, current stage, current target, elapsed time, finding count and output folder; developer snapshots
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
