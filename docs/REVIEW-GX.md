# Independent GUI review after GX8 (2026-11-28)

Reviewer stance: an outside, demanding reviewer for a Fortune 500 customer. The builder scored GX0-GX8 itself, and every round notes
"generator and discriminator are the same model", so this review assumes those scores were generous. Visual scores come from the PNGs
only, judged against `docs/GUI-DESIGN.md` §6. Usability comes from walking J1-J4 of `docs/GUI-EXPERIENCE.md` §3 on those PNGs.
Code was read in only two places: to explain why some frames were wrong (§1.3) and to confirm the cause of the one Blocker (D-01).
No product code was changed.

**Verdict: not a pass.** On the visual side, A3, A5, A6, A7, A9 and A10 are below 8 on at least one page. On usability, B3 and B4 are
below 8. The worst defect is about honesty, not looks: the walkthrough marks causes "Observed in this run" when nothing observed backs
them (D-01). Two snapshot-method defects also mean that the partial, no-CA, tree and drill-down trail states were never really judged
in GX6-GX8 (D-07).

## 1. What was rendered

### 1.1 Sets (all with `-Snapshot`, written under `out\review-gx\` only, never committed)
| Set | Data | Theme | Size | Frames |
|---|---|---|---|---|
| A | Alcyone `expired-crl` + 3-run demo history | light | 1360 x 860 | 66 |
| B | same | light | minimum (1080 x 700) | 66 |
| C | same | light | 1920 x 1080 | 66 |
| D | same | dark | 1360 x 860 | 66 |
| E | same | dark | minimum | 66 |
| F | same | dark | 1920 x 1080 | 66 |
| G | generated LARGE estate (12 CAs, 200 addresses, 500 objects, an unread CA, lifecycle) | light | 1920 x 1080 | 62 |
| H | same LARGE estate | dark | minimum | 62 |
| I | Alcyone `mixed-sample`, no history | light | 1360 x 860 | 64 |
| J | no results (welcome, options, running, error, log) | light | minimum | 6 |
| K | `expired-crl`, snapshot settle fixed (see 1.3) | light | 1360 x 860 | 66 |
| L | same, **reduced motion forced** | light | 1360 x 860 | 65 |
| M | same, reduced motion | dark | minimum | 65 |
| N | same, tree and trail frames on the right page (see 1.3) | light | 1360 x 860 | 66 |

Pages covered: Overview (welcome, running at 6/28/55/86 %, live motion, finished, partial, error, no CA), Discovery map (map, selected,
keyboard focus, only problems, search, zoomed, no match, replay, fit, tree, finding drill-in, object trail), Findings (list, grouped, no
match, walkthrough, causes, a check marked), palette (open, search, no match), toasts, Timeline (CRLs, certificates, range, row open, Back,
chain, chain address), History (on show vs previous, vs oldest, bottom, single run), Objects (list, host, missing, attention, no match),
PKI services (list, detail, bottom), Run log, and the high-contrast mapping.

### 1.2 Limits of this review
- High contrast is the GX5 "mapping" frame: this computer's normal SystemColors, not a real high-contrast theme. It cannot be judged
  beyond "nothing disappears".
- Maximised was not rendered. 1920 x 1080 uses the fixed off-window layout.
- Tooltips, hover cards and the score popup are separate windows, so they are not in any PNG.
- The keyboard-only walk follows the documented key map (`docs/GUI-DESIGN.md` §3, GX4 and GX6 notes) and the focus frame 30b. No live
  key input was replayed.
- J5 (Explain) and J6 (executive summary) are GX9 and GX10 work, so they were not judged.

### 1.3 Snapshot-method defects found (they hid real states from the earlier rounds)
1. **Partial and no-CA frames are captured too early.** `50-partial`, `60-no-ca` and `61-no-ca-section` show an empty ring with no
   number, empty area bars and an empty "What to do next" under a headline that says "7 actions need attention". The `$settle` step
   seeks the mission storyboard *before* the map worker has finished. When the new map arrives it restarts the build at 0 ms, and
   the frame is taken then. A patched copy that waits for the map first (set K) shows the states correctly. Since GX6, when the map moved
   to the worker, these three states have been "judged" on broken frames.
2. **Tree and trail frames show the History page.** `31-map-finding`, `32-map-object`, `33-map-object-trail` and `34-map-tree` render
   the History page. GX8 inserted the History frames before them and the page is never switched back to the map. Set N switches the
   page and shows the real frames. So the breadcrumb trail and Back in the tree have had no visual check since GX8.

## 2. Scores per page (upgraded rubric, 1-10; "-" = not applicable to that page)

| Page / state | A1 | A2 | A3 | A4 | A5 | A6 | A7 | A8 | A9 | A10 | B1 | B2 | B3 | B4 | B5 | C1 | C2 | C3 | C4 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Welcome (+ options) | 8 | 8 | 8 | 9 | 6 | 8 | 8 | 8 | - | 8 | 8 | 8 | 8 | 8 | 8 | 6 | 6 | - | 7 |
| Overview, running | 8 | 8 | 8 | 8 | 7 | 8 | 8 | 8 | 8 | 7 | 8 | 8 | 8 | 8 | 9 | 8 | 8 | 8 | 8 |
| Overview, finished | 8 | 8 | 7 | 8 | 8 | 8 | 6 | 7 | 8 | 8 | 7 | 8 | 8 | 6 | 8 | 8 | 7 | 8 | 8 |
| Overview, partial (settled) | 8 | 8 | 8 | 8 | 8 | 8 | 7 | 8 | 8 | 8 | 8 | 8 | 8 | 7 | 8 | 8 | 7 | 8 | 8 |
| Overview, no CA (settled) | 8 | 8 | 7 | 8 | 7 | 8 | 7 | 7 | 7 | 8 | 7 | 8 | 7 | 6 | 8 | 7 | 6 | - | 7 |
| Error (run ended without results) | 8 | 8 | 8 | 8 | 6 | 8 | 8 | 6 | - | 8 | 7 | 7 | 6 | 5 | 8 | 6 | 5 | - | 6 |
| Findings + walkthrough | 7 | 8 | 6 | 8 | 7 | 6 | 7 | 8 | 5 | 5 | 7 | 7 | 7 | 7 | 8 | 7 | 6 | - | 6 |
| Command palette | 9 | 8 | 7 | 8 | 8 | 8 | 6 | 8 | 6 | 8 | 8 | 7 | 8 | 8 | 9 | 8 | 7 | - | 8 |
| Discovery map (Alcyone) | 8 | 8 | 7 | 8 | 6 | 8 | 8 | 8 | 6 | 7 | 8 | 8 | 8 | 8 | 8 | 9 | 9 | 8 | 8 |
| Discovery map (LARGE estate) | 6 | 7 | 6 | 8 | 5 | 8 | 8 | 8 | 4 | 6 | 7 | 7 | 6 | 8 | 8 | 7 | 6 | 8 | 5 |
| Map tree + drill-down trail | 7 | 8 | 7 | 8 | 7 | 7 | 6 | 8 | 7 | 7 | 7 | 7 | 7 | 7 | 8 | 7 | 7 | - | 7 |
| Timeline | 9 | 8 | 8 | 8 | 8 | 8 | 6 | 8 | 8 | 8 | 8 | 8 | 8 | 8 | 9 | 9 | 9 | - | 9 |
| Objects | 8 | 8 | 7 | 8 | 6 | 8 | 8 | 8 | 6 | 8 | 7 | 8 | 7 | 8 | 8 | 7 | 7 | - | 7 |
| PKI services | 8 | 8 | 8 | 8 | 7 | 8 | 6 | 8 | 7 | 8 | 7 | 8 | 7 | 7 | 8 | 7 | 7 | - | 7 |
| History | 9 | 8 | 7 | 8 | 7 | 8 | 8 | 7 | 7 | 8 | 8 | 8 | 9 | 8 | 9 | 8 | 9 | - | 8 |
| Run log | 8 | 8 | 8 | 8 | 6 | 8 | 8 | 5 | 8 | 8 | 7 | 8 | 8 | 6 | 8 | 5 | 5 | - | 5 |
| Dark theme (all pages) | same as light within ±0; no theme-specific defect found | | | | | | | | | | | | | | | | | | |
| Reduced motion (L, M) | final state at once in every build frame, no half-drawn element: **C3 9** | | | | | | | | | | | | | | | | | | |

**What is genuinely strong:** the Timeline (the CRL heartbeat and the chain are real "now I see it" moments), History's "What changed",
the live mission control, the dark theme, and reduced motion. The weakest page is the Findings page, which is the one a security reviewer
lives in.

## 3. Journeys

| Journey | Target | Result | Verdict |
|---|---|---|---|
| J1 First run | start a run within 10 s; can say what the score means | Welcome has one filled "Run health check" and the three steps; Run turns the same hero into live mission control (ring, stage, "Now checking …", objects found so far). **But:** with Run options open, the card's Run button drops below the fold (01). After the run, "34" with areas 81 / 4 / 71 / 100 / 100 cannot be explained without the popup (D-24). | met for starting; **not met** for "say what the score means" |
| J2 Is my PKI healthy? | 5 s, no scroll at 1360 x 860 | Headline + ring + band answer it. **But** when an earlier run is on show, the only notice in the first screen is the status bar; the banner sits below the map (D-02). Dana can read a week-old run as today's. | met for live runs; **misleading** for loaded runs |
| J3 Why and what do I do? | Overview to a copied check in 3 clicks | Click 1: the action opens Findings with the walkthrough. At 1360 x 860 the first cause starts at the bottom edge and the first copy button is below the fold (frame 23), so it needs a scroll before click 2. The check that is copied contains `<Url>` placeholders the tool already knows (D-17). | 2 clicks **+ a scroll**; partly met |
| J4 What changed? | 2 clicks | History (Ctrl+7 or 1 click) opens on the run on show vs the run before; "Compare" on another run is the second click. Three "New problems" share the same title (D-11). | met |
| Keyboard only | every journey by keys | J1 F5 / Ctrl+K "run"; J2 Ctrl+1; J3 Ctrl+K, text, Enter, F6 to the pane, Tab to a copy button; J4 Ctrl+7, Tab to Compare, Enter. Map: arrows + Enter, focus ring visible but thin (D-38). **No frame shows the focus ring on a normal button, the nav, a chip or a pane link**, so focus visibility outside the map is unproven. | plausible; focus visibility **unverified** |

## 4. Consistency across pages
| Aspect | Finding |
|---|---|
| Spacing | Consistent 24 px gutters, 16 px card gaps and 32 px controls on every page. One exception: the Findings chip row (D-04). |
| Type scale | One ramp. Exceptions: Title Case tile labels ("Not Applicable", "Review Required"), and prose checks set in Consolas (D-17). |
| Icons | Three meanings break the icon table: "Skipped" is drawn with the **power-button** glyph (E7E8); the CRL glyph is **"Important"** (E8C9, an exclamation mark), which reads as a warning; commands and objects share one glyph in the palette. AD containers in the tree use a library glyph that is not in the table. |
| Terminology (§9) | Permission denied is "Skipped" (grid, chips, CA card, pane pill), "Not checked in this run" (PKI services), "Could not check" (map, legend) and "Permission denied" (coverage): four names for one thing. The KPI tile says "Endpoints … URLs" (§9: published address). A breadcrumb says "Machine" (§9: host, by name). Status tiles say "Fail", "Error". |
| Titles and names | GX7's readable-name rule applies to object panes only. Finding panes, palette rows, History lines and the grid's Target column still show distinguished names. |
| Times | Four formats: "17 Nov 2026, 08:00 UTC" (properties), "2026-11-22 05:40:43 UTC" (Where this exists), "2026-11-17T08:00:00Z" (finding text), "Started: 2026-11-20 09:29 UTC" (Overview). |
| Empty states | Good on Findings, Map, Services and History (icon + sentence). Bare text on Run log. No action inside the empty state on Findings ("Use Clear filters" names a button elsewhere) or on single-run History. |
| Error wording | The error banner says what happened but not what it means or what to do, and has no button (D-08). The coverage row shows `CA:GetCAProperty` and `0x80070005` raw (D-20). |
| Details pane | One component for objects (type glyph, title, id, "Seen or named in N places", "N findings"). The finding pane has a different header (pills first, no type glyph, a "None" severity pill). Both show an internal id line in Consolas that users do not need (D-13). |
| Back | Back and Alt+Left work on Map, Timeline and the trail (set N). The tree's selected row stays on the forest while the pane shows a CA two steps in (D-34). |

## 5. Defects
Severity: **Blocker** = misleads the user or breaks the product's own promises; **High** = a Fortune 500 customer notices it in the first
session; **Medium** = noticed with use, weakens trust or speed; **Low** = small but visible; **Polish** = only a designer notices.

### Blocker
| ID | Page / control | Defect | Fix |
|---|---|---|---|
| D-01 | Findings, Map, Objects details pane / walkthrough cause card | "Observed in this run" pill and the accent strip appear for **any** hint, including a 5-point category hint ("Why this run points to it: the finding is about a CRL"). The same card says "Most common", and the note above says "Nothing this run observed separates these causes". The Overview row, the engine (`src/Model/Diagnosis.ps1:173`, support ≥ 10) and the pane (`src/Gui/GuiView.ps1:193`, `[bool]$bt`) use different rules. This overstates the evidence (hard rule 8). | Use one rule: the diagnosis exposes a per-cause `Supported` (support ≥ 10). The pill, the strip and the copied text "Observed in this run:" appear only when `Supported`. Weaker hints show as muted "Hint: …" lines, or not at all. Add a test that the pill never appears with Likelihood "Most common" or "Common". |

### High
| ID | Page / control | Defect | Fix |
|---|---|---|---|
| D-02 | Overview / earlier-run banner | "Showing an earlier run from 2026-11-20 … Nothing was scanned" sits **below the map**, about 700 px down. The first screen shows a confident score with no date beside it. | Put a one-line info banner above the hero whenever the run on show was loaded ("Earlier run · 20 Nov 2026, 09:29 UTC · Run now"), and add "as of <date>" to the headline. |
| D-03 | All pages / status words and glyphs | Permission denied is "Skipped" with the **power-button** glyph (E7E8) in the grid, chips, CA card ("Skipped" on Zenith while coverage says permission denied), finding pills and Overview tiles. PKI services "Not checked in this run" uses the same glyph. The map says "Could not check" with a lock. | Map PermissionDenied / Unsupported findings to the "Could not check" pill (lock, Admin tone) everywhere. Give true Skipped a glyph that means skip, chosen by rendering it (not by code point), and update the §8 table. Add a test that every status-to-pill mapping matches the table. |
| D-04 | Findings / status chips | At 1360 x 860 the chips are clipped: "Warning" and "Skipped" lose their counts, "Informatio…" is cut, and Error and Not applicable are missing. At minimum size "Warninc", "Skippec", "Informa". At 1920 each chip stretches to about 240 px. | Use a WrapPanel of auto-width chips (text + count + 12 px padding) that wrap to a second line. Never a uniform grid. |
| D-05 | Findings / grid | Target shows distinguished names cut to "CN=Alcyone M…". Message is cut after about 25 characters, so the first two rows look identical. Severity shows "None". There is a horizontal scroll bar at 1360. At minimum size the Severity column is cut to "Se"/"Hi". At 1920 Target stays narrow while Message has room. | Target = readable name (`Get-MspkiGuiReadableName`, full text in the tooltip). Message is star-width (minimum 240). Category 90, Severity 80 (blank for None). Confidence shows as an icon below 1200 px. No horizontal scroll. Recheck at all three sizes. |
| D-06 | Discovery map / layout with the pane | At 1360 the canvas opens at 68 % (labels about 8 px) because a "Nothing selected" pane takes 400 px (600 px at 1920). At minimum size the map viewport is about 240 px tall and the zoom bar covers nodes. Filters take two rows and the legend two or three lines. | Keep the pane collapsed until something is selected; the map gets the full width. Filters go in one row (search, status, show, CA, only problems), with overflow in a "Filters" flyout. Legend in one line or a "Legend" button. Zoom bar in the bottom-right beside the minimap. Never open with labels under 10 px. |
| D-07 | Snapshot tool (developer) | See 1.3: frames 50, 60 and 61 are taken before the map worker finishes, and frames 31-34 render the History page. | In `GuiSnapshot.ps1`, `$settle` waits for `Wait-MspkiGuiMapIdle` first, and the tree block starts with `& $page $ui.TabMap`. Add a test: every frame's selected nav item matches the page its name claims, and the Overview frames have a non-empty ring. |
| D-08 | Overview / error state | "The last run ended without results. The domain controller could not be reached (LDAP bind timed out after 5 s). See the Run log page for details, then try again." It gives no meaning, no likely causes and no button. | Rank the likely causes from the knowledge base (network or VPN, DNS for the DC, firewall to 389/636, a timeout that is too short), with read-only checks. Add buttons: "Open run log", "Run again", "Change options" (opens the options strip with the timeout focused). |
| D-09 | Discovery map, LARGE estate | About 200 links between the issuing CAs and the address groups are squeezed into a band about 70 px wide, a solid "rope". The CA columns use 20 % of the width, and the canvas uses 40 % of a 1920 screen. On the Overview card the CA columns are below the fold, so the first screen shows only groups and a fan of links from nowhere. | Scale the column gap with the link count (at least 160 px above 30 links). Bundle links per CA (one trunk that fans out near the targets). Above 120 nodes, open with "Focus a CA" on the CA with the most problems. Centre the Overview card on the CA columns. |
| D-10 | Map pane, PKI services pane / Where this exists and counts | Zenith, an Enterprise CA known *from Active Directory*, shows "Seen or named in 0 places … This run did not record where the object was seen". The CES pane says "0 findings" while the PKI services card lists 1 finding for the same service. | Record the Enrollment Services object as an observation of each CA (engine graph). Count a pane's findings from the same entity links the cards use. Add a test that card counts and pane counts agree. |

### Medium
| ID | Page / control | Defect | Fix |
|---|---|---|---|
| D-11 | Palette, History "New problems", Findings | Lists hold identical titles: three "CRL · Alcyone Meridian Issuing CA" in History; three "Base CRL of CN=Alcyone Meridian Issuing CA, DC=…" in the palette. The part that differs (address, at the CA) is cut off. | Titles carry the distinguishing part: "Base CRL · Meridian Issuing CA · at pki (HTTP)" / "· at the CA" / "· in AD". |
| D-12 | Finding pane title, palette objects, History lines | Distinguished names as titles ("CRL · CN=Alcyone Meridian Issuing CA, DC=alcyone-orbital, DC=example"). | One title helper for findings, objects, palette and History (common name, DN in the properties). |
| D-13 | Every details pane, Objects list | An internal id line (`ca:issuing-ca2…\alcyone zenith issuing ca`, `crl:4d5e…:base`, `service:ces:endpoint:web://…`) in Consolas under each title. The Objects list repeats each URL in lower case as `endpoint:web://…` on a second line. | Move the id to a "Technical id" property at the bottom (still copied by the copy button). The Objects second line = type · host · status in words. |
| D-14 | Overview / status and KPI tiles | "Not Applicable", "Review Required" (Title Case); "Fail", "Error", "Skipped" are raw status names; the "Endpoints · AIA, CDP, OCSP and enrollment URLs" tile breaks §9. | Use the §9 words in sentence case: "Failing", "Check failed", "Could not check", "Not applicable", "Review required", "Published addresses". |
| D-15 | Timeline tab, pane header, palette / CRL glyph | The CRL glyph E8C9 is an exclamation mark ("Important"), so CRL rows look like warnings. | Use a document or list glyph for CRLs (check it by rendering) and update §8. |
| D-16 | Palette / result icons | Commands and objects share one glyph. Object rows do not use their type glyph. | Object rows use the type glyph from §8; commands use their own command glyph. |
| D-17 | Walkthrough / checks | `certutil -URL <Url>` keeps the placeholder although the finding has the URL. Prose checks ("On the CA (owner): Application log, …") are set in Consolas. | Fill placeholders from the finding's own evidence (copy-only, never run). Use the body font for prose and Consolas only for the command part. |
| D-18 | Walkthrough / J3 | At 1360 x 860 the first copy button is below the fold of the pane. | When opened from an action, scroll the pane to the first cause. Fold "What was found" to 3 lines with "Show more". Move the basis note under the causes. |
| D-19 | Run log / loaded run without a log | Bare text "(no run.log was found next to this results.json)" is counted as "1 of 1 line shown". | A designed empty state (icon, sentence, "Open folder"), with the count "No log for this run". |
| D-20 | Overview / Discovery coverage | `CA:GetCAProperty` and `…: 0x80070005` raw, with no words or action. | "Reading the CA's properties was refused (access denied, 0x80070005)", with "Why and what to do" opening the finding's walkthrough. |
| D-21 | Overview / What to do next (LARGE estate) | Findings without a knowledge topic become one action each, titled with the raw message ("AIA address 103 checked."): 59 actions. | Group topic-less findings by category + status ("22 AIA addresses failing") with a plain title. The executive summary (GX10) will reuse this. |
| D-22 | Welcome / Run options | Opening the options pushes the welcome card, and its Run button, below the fold. | Make the options a flyout over the page, or keep a Run button in the options strip. |
| D-23 | Finding pane / Details and Checked layers | Raw property names ("RelatedCA", "StatusCode") and many "—" rows. Layer chips are cut ("DNS: I", "Redire", "Conte", "Discov"). | Hide empty properties, use `Get-MspkiGuiPropertyLabel` for labels, and let the layer chips wrap with full text. |
| D-24 | Overview / score | 34 next to areas 81 / 4 / 71 / 100 / 100: the cap rule is only in the popup. | One line under the band: "Held down by Revocation (4): the overall is at most the worst area + 30". |
| D-25 | Overview / area rows | "—" for Enrollment security (and for every area with no CA) has no explanation. | Write "not scored" (as History already does), with a tooltip giving the reason. |
| D-26 | Map tree / breadcrumbs | "Back to Machine", crumb "Machine": a type, not a name, and not a §9 term. | Crumbs and Back use the object's readable name, with the type in the tooltip. |
| D-27 | History / single run | A lone dot in an empty chart, and the empty comparison has no action. | Hide the chart below two scored runs; add "Run health check" to the empty state. |
| D-28 | Overview, running | Three progress indicators for the same 55 % (top bar, ring, inline bar). | Keep the ring and the stage line, and drop the inline bar on the Overview (the top bar stays for other pages). |

### Low
| ID | Page / control | Defect | Fix |
|---|---|---|---|
| D-29 | Finding pane, grid | A "None" severity pill or cell. | Hide it. |
| D-30 | All | Four time formats (see §4). | One formatter everywhere, including Where-this-exists and the Overview line. Times inside engine messages are formatted when shown. |
| D-31 | Timeline, pane | CRL numbers: "0C", "0A", "2B" next to "42" and "28" (all hex, but "42" reads as decimal); "number" next to "Number". | "CRL 0x2B" everywhere, with the decimal value in the tooltip; one capitalisation. |
| D-32 | Timeline / CA group rows | "Alcyone Lodestar Root / CA" wraps although there is free space before the pill. | Let the title take the width up to the pill. |
| D-33 | Timeline / copies | "until 1 Jun 08:00" has no year. | Add the year when it is not the run's year. |
| D-34 | Map tree | The selected row stays on the forest while the pane shows a CA two steps in. | Sync the tree's selection with the pane's trail (as the map already does). |
| D-35 | Status bar | "0 findings" on the welcome screen. | Hide the count before the first result. |
| D-36 | Overview | "Exit code: 4 - Failures" is command-line jargon for Dana. In the LARGE run "Exit code: 2 - Informational" sits beside "At risk". | Move the exit code to the run details tooltip. |
| D-37 | Tree | "worst below: Critical", "V1.0 - Current" (hyphen), library glyph for containers. | "Contains critical", "V1.0 · current", the directory glyph E8D4. |
| D-38 | Map / keyboard focus | The node focus ring is a thin dashed circle. | A 2 px accent ring with a 2 px surface halo (3:1 on both themes). |
| D-39 | Finding texts | "(not probed in this phase)" (developer word); the topic heading "…was not allowed to read something" is vague. | "(not contacted in this run)"; name what was read ("the CA's properties"). |
| D-40 | Findings / no match | "Use "Clear filters"" names a button at the top. | Put a "Clear filters" button in the empty state. |
| D-41 | Timeline chain, pane | A key glyph for "certificate on this computer" suggests a private key (the tool never reads keys). | Use the certificate glyph with a computer badge. |
| D-42 | Palette | Detail line "CRL - CN=…" uses a hyphen; elsewhere "·". | Use "·". |
| D-43 | Navigation at minimum size | The Findings count badge disappears; the environment block collapses to an unlabeled globe. | A small count dot on the icon; a tooltip on the globe. |
| D-44 | PKI services pane | The title is a three-line URL. | "CES on enroll" as the title, with the URL in the properties. |
| D-45 | Docs | `GUI-EXPERIENCE.md` §4 still says Timeline "new, GX5" and Learn "GX7"; `GUI-DESIGN.md` §3 still lists six pages, Ctrl+1..6 and Ctrl+1..4. | Update both to the eight pages and Ctrl+1..8. |

### Polish
| ID | Page / control | Defect | Fix |
|---|---|---|---|
| D-46 | Overview map | The amber link from the root to "Lodestar Root CA.crl" runs just under Zenith's subtitle; the "issuer not confirmed" marker crowds Zenith's left edge. | Route that link below the label box; put the marker at 40 % of the link. |
| D-47 | Map build frames | Links turn red/dashed before their nodes are graded. | Colour a link with its target node's health step. |
| D-48 | Overview actions | The number circles are tinted by tone only. | Fine with the row's words, but add the status glyph on hover or keep the tone neutral. |
| D-49 | Welcome at 1360 / 1920 | A large empty band under the card. | Centre the card vertically or add "What it never does" (no writes, no credentials sent, no scanning) as a fourth, quiet row. |

## 6. Top 10 changes that would most raise the perceived quality
1. **Make "Observed" honest (D-01).** One rule for the pill, the strip, the Overview mark and the copied text. Trust is the product.
2. **Rebuild the Findings page for reading (D-04, D-05, D-23, D-29).** Wrapping chips, readable names, a wide Message column, no
   horizontal scroll, no empty properties. It is the page security reviewers and auditors live in.
3. **Say which run is on show, at the top (D-02).** Banner above the hero and "as of" in the headline.
4. **One status vocabulary and one icon per meaning (D-03, D-14, D-15, D-16).** Could not check = lock, everywhere; no power button;
   a CRL glyph that is not a warning.
5. **Readable, distinct titles everywhere (D-11, D-12, D-13, D-26).** Common names plus the part that differs; ids out of sight.
6. **Give the map its space (D-06, D-09).** No empty pane, one filter row, never below readable zoom, a large-estate layout that is not a rope.
7. **Error and coverage states that help (D-08, D-20, D-19, D-27, D-40).** Meaning, likely causes, and the button next to them.
8. **Explain the score in the first screen (D-24, D-25).** "Held down by Revocation (4)" turns the most confusing number into an insight.
9. **J3 without scrolling (D-17, D-18).** The pane opens on the first cause, and the check is ready to paste with the real URL.
10. **Fix the snapshot method and add focus frames (D-07, D-38).** Otherwise the next rounds keep passing states nobody saw.

## 7. Changes to the GX9-GX11 plan
- **Add GX8b, a consistency pass, before GX9.** It covers D-01 to D-28, with a written terms check against §9. The glossary and the
  tour (GX9) will otherwise *codify* today's four names for "could not check" and the DN titles. Acceptance: no Blocker or High
  open; every Medium fixed or accepted by the owner in writing.
- **GX9 (Explain, Learn, tour, celebration).**
  - Build concept cards from the existing "What it is" notes; do not write a second set.
  - Glossary keys must be the §9 terms. The J5 check ("no term on the Overview unexplained") must also cover AIA, CDP, LDAP, CES,
    OCSP, "partial score" and the exit code (or remove the exit code, D-36).
  - Tour stops: the score line with "held down by", What to do next, the map, Ctrl+K. Each stop must render at minimum size, in dark
    and with reduced motion.
  - Build the celebration last and keep it small. It matters less than every High above.
- **GX10 (executive summary).**
  - Reuse the Overview helpers, but only after D-21 (grouped fallback actions) and D-12 (readable titles), or the "top 3 actions" can
    read "AIA address 103 checked." or carry DNs.
  - Print the "as of" date and the earlier-run notice prominently.
  - Add a printed-page snapshot (HTML to PNG is out of scope, so judge the HTML with print CSS in a browser frame) under `out\` only.
- **GX11 (adversarial round).**
  - Fix the method first (D-07).
  - Add frames for: keyboard focus on nav, buttons, chips, pane links and palette rows; the options flyout; the error state with its
    actions; History with a single run; the LARGE estate on every page; a real high-contrast theme (switched on a dev VM user, not on
    any lab server); maximised on a screen of at least 1920 x 1080; 150 % and 200 %.
  - Use a LARGE fixture whose findings carry real status codes, so the diagnosis topics apply (the current one uses `TEST`).
  - Have the discriminator run independently of the generator (a fresh session given only the PNGs, the rubric and this review),
    since every round so far notes that both were the same model.
  - Carry this file's defect IDs forward and close each one with a frame that proves it.

REVIEW DONE: run the fixes.
