# GX10 executive summary: one printable HTML page for a manager or an auditor (journey J6), built from the same helpers as the Overview
# (score, areas, "What to do next", coverage) so the page and the window always agree. ConvertTo-MspkiGuiExecutiveSummaryHtml is pure
# (text in, text out; every value HTML-encoded, no script, no external resource); the file is written by Save-MspkiGuiExecutiveSummary
# in GuiState.ps1, inside the output folder only.

function ConvertTo-MspkiGuiHtmlText {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Get-MspkiGuiTrendSvg {
    <#
    .SYNOPSIS
    The score over time as a small inline SVG (oldest left), with the 60 and 90 band lines; '' below two scored runs.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Trend = @(), [int]$Width = 300, [int]$Height = 64)
    $pts = @($Trend | Where-Object { $null -ne $_ -and $null -ne $_.Score })
    if ($pts.Count -lt 2) { return '' }
    $c = [System.Globalization.CultureInfo]::InvariantCulture
    $step = ($Width - 16) / [double]($pts.Count - 1)
    $y = { param($s) (6 + ($Height - 12) * (1 - ([double]$s / 100.0))).ToString('0.0', $c) }
    $line = (@(for ($i = 0; $i -lt $pts.Count; $i++) { '{0},{1}' -f (8 + $i * $step).ToString('0.0', $c), (& $y $pts[$i].Score) }) -join ' ')
    $dots = (@(for ($i = 0; $i -lt $pts.Count; $i++) { '<circle cx="{0}" cy="{1}" r="3"/>' -f (8 + $i * $step).ToString('0.0', $c), (& $y $pts[$i].Score) }) -join '')
    return ('<svg class="trend" viewBox="0 0 {0} {1}" width="{0}" height="{1}" role="img" aria-label="Score over the last {2} runs, from {3} to {4}"><line x1="0" x2="{0}" y1="{5}" y2="{5}" class="band"/><line x1="0" x2="{0}" y1="{6}" y2="{6}" class="band"/><polyline points="{7}"/>{8}</svg>' -f
        $Width, $Height, $pts.Count, $pts[0].Score, $pts[$pts.Count - 1].Score, (& $y 90), (& $y 60), $line, $dots)
}

function ConvertTo-MspkiGuiExecutiveSummaryHtml {
    <#
    .SYNOPSIS
    The executive summary page: when the run was (an earlier run says so prominently), the score with its band and what holds it down, the
    areas, the top three actions in plain words with their most common or most likely cause, the score over time when history exists, and
    what this run could not check. Honest by construction: the cause wording is the knowledge base's own, a partial score says so, and the
    page says it is not a certification.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Score,
        $Actions = $null,
        $Health = $null,
        $Coverage = $null,
        [string]$Forest = '',
        [string]$AsOf = '',
        [bool]$IsEarlierRun = $false,
        [AllowEmptyCollection()][object[]]$Trend = @(),
        [AllowEmptyCollection()][string[]]$Limits = @(),
        [string]$ToolVersion = '',
        [string]$Generated = ''
    )
    $e = { param($t) ConvertTo-MspkiGuiHtmlText $t }
    $sb = New-Object System.Text.StringBuilder
    $title = $(if ($Forest) { 'PKI health summary: {0}' -f $Forest } else { 'PKI health summary' })
    [void]$sb.Append('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendFormat('<title>{0}</title><style>', (& $e $title))
    [void]$sb.Append('@page{size:A4;margin:16mm}body{font-family:"Segoe UI",system-ui,sans-serif;color:#242424;margin:0 auto;max-width:760px;padding:24px;font-size:13px;line-height:1.45}')
    [void]$sb.Append('h1{font-size:22px;margin:0 0 4px}h2{font-size:14px;margin:22px 0 8px;color:#424242;text-transform:none}.sub{color:#616161}')
    [void]$sb.Append('.asof{display:inline-block;margin-top:10px;padding:4px 10px;border:1px solid #B4D6FA;background:#EBF3FC;color:#0F548C;border-radius:4px;font-weight:600}')
    [void]$sb.Append('.earlier{margin-top:10px;padding:10px 12px;border:1px solid #F2CF7A;background:#FFF8E6;color:#7A4F00;border-radius:6px;font-weight:600}')
    [void]$sb.Append('.hero{display:flex;gap:24px;align-items:center;margin-top:18px;padding:16px;border:1px solid #E0E0E0;border-radius:8px}.score{font-size:44px;font-weight:600;line-height:1}.of{color:#616161;white-space:nowrap}.hero>div:first-child{min-width:96px;text-align:center}')
    [void]$sb.Append('.band{font-weight:600;padding:2px 8px;border-radius:4px;border:1px solid #D1D1D1}.Good{color:#0E700E;background:#F1FAF1;border-color:#9FD89F}.Warn{color:#7A4F00;background:#FFF8E6;border-color:#F2CF7A}.Bad{color:#B10E1C;background:#FDF3F4;border-color:#EEACB2}.Neutral{color:#424242;background:#F5F5F5}')
    [void]$sb.Append('table{border-collapse:collapse;width:100%}td{padding:5px 6px;border-bottom:1px solid #EEE;vertical-align:top}.bar{background:#EEE;height:6px;border-radius:3px;width:160px}.fill{height:6px;border-radius:3px}')
    [void]$sb.Append('.fGood{background:#107C10}.fWarn{background:#C27C0E}.fBad{background:#D13438}.num{text-align:right;font-weight:600;width:70px}.muted{color:#616161}')
    [void]$sb.Append('ol{padding-left:20px;margin:0}li{margin:0 0 10px}.cause{color:#424242}.trend polyline{fill:none;stroke:#0F6CBD;stroke-width:2}.trend circle{fill:#0F6CBD}.trend .band{stroke:#D1D1D1;stroke-dasharray:3 3}')
    [void]$sb.Append('footer{margin-top:26px;padding-top:10px;border-top:1px solid #E0E0E0;color:#616161;font-size:11px}@media print{body{padding:0}.hero{break-inside:avoid}li{break-inside:avoid}}')
    [void]$sb.Append('</style></head><body>')
    [void]$sb.AppendFormat('<h1>{0}</h1><div class="sub">Microsoft Active Directory Certificate Services, as one read-only health check saw it.</div>', (& $e $title))
    if ($AsOf) { [void]$sb.AppendFormat('<div class="asof">As of {0}</div>', (& $e $AsOf)) }
    if ($IsEarlierRun) { [void]$sb.Append('<div class="earlier">This summary is of an earlier run opened from disk. Nothing was scanned for it: it shows what that run saw on the date above.</div>') }
    # Score
    [void]$sb.Append('<div class="hero">')
    if ($Score.HasScore) {
        [void]$sb.AppendFormat('<div><div class="score">{0}</div><div class="of">out of 100</div></div><div>', (& $e ([string]$Score.Overall)))
        [void]$sb.AppendFormat('<span class="band {0}">{1}</span>', (& $e ([string]$Score.Tone)), (& $e ([string]$Score.Band)))
        if ($Score.HeldText) { [void]$sb.AppendFormat('<p>{0}. {1}</p>', (& $e ([string]$Score.HeldText)), (& $e ([string]$Score.HeldTip))) }
        if ($Score.Partial -and $Score.PartialText) { [void]$sb.AppendFormat('<p><b>Partial score.</b> {0}</p>', (& $e (([string]$Score.PartialText) -replace '^Partial:\s*', ''))) }
        if ($null -ne $Health -and $Health.Title) { [void]$sb.AppendFormat('<p class="muted">{0}</p>', (& $e ([string]$Health.Title))) }
        [void]$sb.Append('</div>')
    }
    else { [void]$sb.AppendFormat('<div><b>Not scored.</b> {0}</div>', (& $e ([string]$Score.Reason))) }
    [void]$sb.Append('</div>')
    # Areas
    [void]$sb.Append('<h2>By area</h2><table>')
    foreach ($a in @($Score.Areas)) {
        if ($null -ne $a.Score) {
            $cls = $(switch ([string]$a.Tone) { 'Good' { 'fGood' } 'Bad' { 'fBad' } default { 'fWarn' } })
            [void]$sb.AppendFormat('<tr><td>{0}</td><td><div class="bar"><div class="fill {1}" style="width:{2}%"></div></div></td><td class="num">{3}</td><td class="muted">{4}</td></tr>', (& $e ([string]$a.Name)), $cls, [int]$a.Score, [int]$a.Score, (& $e ([string]$a.Detail)))
        }
        else { [void]$sb.AppendFormat('<tr><td>{0}</td><td></td><td class="num muted">not scored</td><td class="muted">No finding in this run belongs to this area.</td></tr>', (& $e ([string]$a.Name))) }
    }
    [void]$sb.Append('</table>')
    # Top three actions
    [void]$sb.Append('<h2>What to do first</h2>')
    $items = @(); if ($null -ne $Actions) { $items = @($Actions.Items | Select-Object -First 3) }
    if ($items.Count -eq 0) { [void]$sb.Append('<p>Nothing this run could check needs attention.</p>') }
    else {
        [void]$sb.Append('<ol>')
        foreach ($i in $items) {
            [void]$sb.AppendFormat('<li><b>{0}</b> <span class="muted">({1}; {2})</span>', (& $e ([string]$i.Title)), (& $e ([string]$i.CountText)), (& $e ([string]$i.AreaName)))
            if ($i.Cause) { [void]$sb.AppendFormat('<div class="cause">{0}</div>', (& $e ([string]$i.Cause))) }
            [void]$sb.Append('</li>')
        }
        [void]$sb.Append('</ol>')
        if ([int]$Actions.Total -gt 3) { [void]$sb.AppendFormat('<p class="muted">{0} more in the window (Overview, What to do next).</p>', ([int]$Actions.Total - 3)) }
    }
    # Trend
    $svg = Get-MspkiGuiTrendSvg -Trend $Trend
    if ($svg) {
        $tp = @($Trend | Where-Object { $null -ne $_ -and $null -ne $_.Score })
        [void]$sb.AppendFormat('<h2>Score over time</h2>{0}<div class="muted">{1} runs of this forest, oldest first: from {2} to {3}. Dashed lines: 90 (healthy) and 60 (at risk below).</div>', $svg, $tp.Count, [int]$tp[0].Score, [int]$tp[$tp.Count - 1].Score)
    }
    # Not checked
    $gaps = New-Object System.Collections.ArrayList
    if ($null -ne $Coverage) { foreach ($c in @($Coverage.Attention)) { $t = [string]$c.Reason; if ($t -notlike ([string]$c.MethodText + '*')) { $t = '{0}: {1}' -f $c.MethodText, $t }; [void]$gaps.Add($t) } }
    foreach ($l in @($Limits)) { if ($l) { [void]$gaps.Add([string]$l) } }
    [void]$sb.Append('<h2>What this run did not check</h2>')
    if ($gaps.Count -eq 0) { [void]$sb.Append('<p>Every discovery method succeeded.</p>') }
    else { [void]$sb.Append('<ul>'); foreach ($x in $gaps) { [void]$sb.AppendFormat('<li>{0}</li>', (& $e $x)) }; [void]$sb.Append('</ul>') }
    [void]$sb.AppendFormat('<footer>Generated {0} by MSPKI Health Check {1}. The tool only reads: it changed nothing in Active Directory, on a CA or on any server. The score summarises the findings; it is not a certification. Causes are probable, never proven: the full findings, evidence and read-only checks are in the window and the HTML report.</footer>', (& $e $Generated), (& $e $ToolVersion))
    [void]$sb.Append('</body></html>')
    return $sb.ToString()
}

function Invoke-MspkiGuiExecutiveSummary {
    <#
    .SYNOPSIS
    J6: writes the executive summary of the run on show (executive-summary.html in the run's folder inside the output folder, else in the
    output folder itself) and opens it. -NoOpen for tests and snapshots. Returns the path or ''.
    #>
    [CmdletBinding()]
    param([switch]$NoOpen)
    $g = $script:MspkiGui
    if ($null -eq $g.Data -or $null -eq $g.Score) { [void](Show-MspkiGuiToast -Title 'No results yet' -Text 'Run the health check or open an earlier run first.' -Tone Info); return '' }
    $cov = $null; if ($null -ne $g.Summary -and $null -ne $g.Summary.PSObject.Properties['Coverage']) { $cov = $g.Summary.Coverage }
    $trend = @(); if ($null -ne $g.HistView -and $null -ne $g.HistView.PSObject.Properties['Trend']) { $trend = @($g.HistView.Trend) }
    $limits = @(); if ($null -ne $g.Summary -and $null -ne $g.Summary.PSObject.Properties['Limits']) { $limits = @($g.Summary.Limits) }
    $asOf = [string]$g.ShownAsOf
    if (-not $asOf -and $null -ne $g.Data.RunInfo) { $d = ConvertTo-MspkiGuiDateTime -Value $g.Data.RunInfo.StartedUtc; if ($null -ne $d) { $asOf = Format-MspkiGuiTime -Value $d } }
    $forest = ''; if ($null -ne $g.Summary -and $null -ne $g.Summary.PSObject.Properties['Forest']) { $forest = [string]$g.Summary.Forest }
    $html = ConvertTo-MspkiGuiExecutiveSummaryHtml -Score $g.Score -Actions $g.Actions -Health $(if ($null -ne $g.Summary) { $g.Summary.Health } else { $null }) -Coverage $cov `
        -Forest $forest -AsOf $asOf -IsEarlierRun ([bool]$g.ShownAsOf) -Trend $trend -Limits $limits -ToolVersion ([string]$g.Ui.HdrVersion.Text) -Generated (Format-MspkiGuiTime -Value ([datetime]::UtcNow))
    $folder = [string]$g.Data.OutputFolder
    if (-not $folder -or -not (Test-MspkiGuiPathInside -Path (Join-Path $folder 'x') -Root ([string]$g.OutputRoot))) { $folder = [string]$g.OutputRoot }
    $path = Join-Path $folder 'executive-summary.html'
    if (-not (Save-MspkiGuiExecutiveSummary -Html $html -Path $path -AllowedRoot ([string]$g.OutputRoot))) {
        [void](Show-MspkiGuiToast -Title 'The summary was not written' -Text 'It can only be written inside the output folder.' -Tone Warn); return ''
    }
    if (-not $NoOpen) { Open-MspkiGuiPath -Path $path -What 'executive summary' }
    [void](Show-MspkiGuiToast -Title 'Executive summary written' -Text ('{0} (one printable page; it opens in your browser).' -f $path) -Tone Good)
    return $path
}
