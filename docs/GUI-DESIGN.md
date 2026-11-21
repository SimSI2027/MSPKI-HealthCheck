# GUI design notes

The window (`Start-MspkiHealthCheckGui.ps1`, `src/Gui/`) follows the look of the previous toolkit's window (a WinForms
design) and its HTML report. The styles live in `src/Gui/Theme.xaml`; `MainWindow.xaml` only uses them.
Pure XAML, in-box WPF only, no third-party libraries. No environment data appears here.

## Palette (from the old window; one change: muted grey darkened for contrast)
| Role | Colour | Role | Colour |
|---|---|---|---|
| Header bar | `#16233F` | Header sub text | `#B0BED6` |
| Accent (primary button, focus, links) | `#0067B8` | Accent hover | `#005499` |
| Window background | `#F3F5F8` | Card / grid background | `#FFFFFF` |
| Border | `#D6DBE3` | Grid header | `#2C3E60` (white text) |
| Alternating row | `#F7F9FC` | Body text | `#1F2937` |
| Muted text | `#5F6877` (old `#6E7684`) | Selection row | `#D6E8F8` |
| Good back / fore | `#DFF1E4` / `#166E36` | Warning back / fore | `#FFF3CD` / `#8A5C00` |
| Bad back / fore | `#FDE2E2` / `#A82020` | Info back / fore | `#E2EEFC` / `#1F4F8A` |
| Admin / permission back / fore | `#EDE7F6` / `#5E35B1` | Neutral back / fore | `#EDEFF3` / `#4B5563` |

Tones: Good = Pass / succeeded, Warn = Warning / unsupported, Bad = Fail / Critical / failed, Info = Information,
Admin = Error / permission denied / administrator, Neutral = skipped / not applicable / not tested.

## Fonts
Segoe UI 13 px body; Segoe UI Semibold for headings, buttons and table headers; title 20 px, section 15 px,
KPI numbers 26 px, small labels 11-12 px; Consolas 12 px for evidence, logs and identifiers.
Icons: the in-box **Segoe MDL2 Assets** font (glyph code points live in `GuiModel.ps1` for data-driven icons).

## Spacing and shape
8 px grid: gaps 8 / 16 / 24, card padding 16, controls 32 px high, table rows at least 28 px.
Rounded corners only where the old design had them: cards, tiles and banners (6 px). Buttons, inputs, pills and
tabs are square. Minimum window 1000 x 640; everything resizes (wrap panels, star columns, scrolling panes).

## Control styles (Theme.xaml)
Window, Button (secondary default, `PrimaryButton` accent, flat disabled), TabControl with accent underline,
DataGrid (dark header, alternating rows, light-blue selection, sort arrows), TreeView with chevrons,
TextBox with placeholder (`Tag` is the hint), ComboBox, CheckBox, GroupBox, Expander, ScrollBar (thin), ToolTip,
ProgressBar (4 px), filter chips (`ToggleButton`), status pill (`PillTemplate`: icon + text, tone from the data).

## What the old window did well (new window must match or beat)
- Dark header bar with title and connection line; white toolbar; status strip with output folder.
- Coloured status tiles that act as filters; one-click open of grids; empty-state text inside a grid.
- Alternating rows, a Filter box on every grid with a count, Esc clears, tooltips on every button.
- Resizes without overlap (wrapping rows), busy cursor and disabled buttons while working.
- Admin badge in purple so "needs elevation" is obvious.

## What the new window adds
- Overall health banner, KPI tiles, CA cards, top issues, discovery coverage with reasons.
- Split findings view (grid + full details), group by category, status chips, CSV export of the filtered view.
- Icon plus text on every status (never colour alone), keyboard navigation (Tab order, F5 run, Esc cancel,
  Ctrl+F search, Ctrl+1..4 tabs), high-DPI layout rounding, welcome state before the first run.
- Developer snapshots: `Start-MspkiHealthCheckGui.ps1 -Snapshot out\snap [-ResultsFile ...]` renders each tab to a PNG
  with `RenderTargetBitmap` (never a screen capture). Snapshots hold real names, so they stay under `out\` (git-ignored).
