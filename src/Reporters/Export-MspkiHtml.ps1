# report.html: one offline file. All CSS and JavaScript are inline; there is no external script, style, font,
# image or link. Every value that comes from the environment is HTML-encoded. A Content-Security-Policy
# meta tag blocks any network access from the page.

$script:MspkiKnownLimits = @(
    'NDES detection depends on read rights on the CA, or on references that exist in AD, policy or certificates.',
    'Intune Certificate Connector detection is local only (this computer).',
    'ESC9-style checks cannot be fully judged without domain controller registry settings.',
    'CEP URLs only appear when policy on this computer points to them.',
    'The tool is read-only: it never enrolls, requests, publishes or changes anything, so some conditions can only be flagged for review.',
    'Confidence is stated per finding: Confirmed (authoritative and validated), Referenced (named by a certificate, CRL, AD object or policy), Inferred (built from strong evidence, not validated), Unknown.'
)

function ConvertTo-MspkiHtmlText {
    <#
    .SYNOPSIS
    HTML-encodes a value (arrays are joined with commas). Null becomes an empty string.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Array] -or $Value -is [System.Collections.IList]) { $Value = (@($Value) | ForEach-Object { [string]$_ }) -join ', ' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-MspkiHtmlStatusBadge {
    [CmdletBinding()]
    param([string]$Status)
    if (-not $Status) { return '' }
    $e = ConvertTo-MspkiHtmlText $Status
    return ('<span class="badge st-{0}">{0}</span>' -f $e)
}

function New-MspkiHtmlConfidenceBadge {
    [CmdletBinding()]
    param([string]$Confidence)
    if (-not $Confidence) { return '' }
    $e = ConvertTo-MspkiHtmlText $Confidence
    return ('<span class="badge cf-{0}" title="Confidence: {0}">{0}</span>' -f $e)
}

function ConvertTo-MspkiHtmlNode {
    <#
    .SYNOPSIS
    Renders one Discovery Map node (and its children) as nested details elements.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Node, [int]$Depth = 0)
    $worstRank = [math]::Max((Get-MspkiStatusRank $Node.Status), (Get-MspkiStatusRank $Node.WorstBelow))
    $problem = 0
    if ($worstRank -ge 4) { $problem = 1 }
    $open = ''
    if ($Depth -le 1 -or $problem -eq 1) { $open = ' open' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendFormat('<li class="node t-{0}" data-problem="{1}"><details{2}><summary>', (ConvertTo-MspkiHtmlText $Node.Type), $problem, $open)
    [void]$sb.AppendFormat('<span class="ntype">{0}</span><span class="nlabel">{1}</span>', (ConvertTo-MspkiHtmlText $Node.Type), (ConvertTo-MspkiHtmlText $Node.Label))
    [void]$sb.Append((New-MspkiHtmlStatusBadge $Node.Status))
    [void]$sb.Append((New-MspkiHtmlConfidenceBadge $Node.Confidence))
    if ($Node.WorstBelow -and (Get-MspkiStatusRank $Node.WorstBelow) -ge 4) {
        [void]$sb.AppendFormat('<span class="below">worst below: {0}</span>', (ConvertTo-MspkiHtmlText $Node.WorstBelow))
    }
    [void]$sb.Append('</summary>')
    $hasBody = (@($Node.Detail).Count -gt 0 -or @($Node.Sources).Count -gt 0 -or @($Node.FindingIds).Count -gt 0)
    if ($hasBody) {
        [void]$sb.Append('<div class="nd">')
        foreach ($d in @($Node.Detail)) { [void]$sb.AppendFormat('<div>{0}</div>', (ConvertTo-MspkiHtmlText $d)) }
        if (@($Node.Sources).Count -gt 0) {
            [void]$sb.Append('<div>Sources: ')
            foreach ($s in @($Node.Sources)) { [void]$sb.AppendFormat('<span class="chip">{0}</span>', (ConvertTo-MspkiHtmlText $s)) }
            [void]$sb.Append('</div>')
        }
        if (@($Node.FindingIds).Count -gt 0) {
            [void]$sb.Append('<div>Findings: ')
            foreach ($id in @($Node.FindingIds | Select-Object -First 40)) { [void]$sb.AppendFormat('<a href="#{0}">{0}</a>', (ConvertTo-MspkiHtmlText $id)) }
            if (@($Node.FindingIds).Count -gt 40) { [void]$sb.AppendFormat('<span class="muted">+{0} more</span>', @($Node.FindingIds).Count - 40) }
            [void]$sb.Append('</div>')
        }
        [void]$sb.Append('</div>')
    }
    if ($Node.Children.Count -gt 0) {
        [void]$sb.Append('<ul>')
        foreach ($c in $Node.Children) { [void]$sb.Append((ConvertTo-MspkiHtmlNode -Node $c -Depth ($Depth + 1))) }
        [void]$sb.Append('</ul>')
    }
    [void]$sb.Append('</details></li>')
    return $sb.ToString()
}

function New-MspkiHtmlDiagnosis {
    <#
    .SYNOPSIS
    The "Probable causes and next steps" block of one finding (causes ranked, how to confirm, how to fix, sources). Source addresses are
    plain text, not links: the report is one offline file with no link in it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Diagnosis)
    $d = $Diagnosis
    $e = { param($v) ConvertTo-MspkiHtmlText $v }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="dg"><h4>Probable causes and next steps</h4>')
    [void]$sb.AppendFormat('<p class="dgt">{0}</p><p>{1}</p><p class="dgb">{2}</p><ol class="dgc">', (& $e $d.Title), (& $e $d.Summary), (& $e $d.BasisNote))
    foreach ($c in @($d.Causes)) {
        [void]$sb.AppendFormat('<li><div class="dgh"><b>{0}</b> <span class="dgl dgl-{1}">{2}</span></div>', (& $e $c.Cause), ((& $e $c.Likelihood) -replace '\s', ''), (& $e $c.Likelihood))
        $because = @($c.Because | Where-Object { $_ })
        # D-01: one rule with the GUI. "What this run observed" only when the cause is supported (>= 10 points); weaker facts are hints.
        $sup = $false
        $sp = $c.PSObject.Properties['Supported']
        if ($null -ne $sp -and $null -ne $sp.Value) { $sup = ([string]$sp.Value -eq 'True') } else { $sup = (@('Most likely', 'Likely') -contains [string]$c.Likelihood) }
        if ($because.Count -gt 0 -and -not $sup) {
            [void]$sb.AppendFormat('<div class="dgb">Hint: {0}</div>', (& $e (($because | ForEach-Object { [string]$_ }) -join '; ')))
        }
        elseif ($because.Count -gt 0) {
            [void]$sb.Append('<div class="dgo"><span class="dgk">What this run observed</span><ul>')
            foreach ($x in $because) { [void]$sb.AppendFormat('<li>{0}</li>', (& $e $x)) }
            [void]$sb.Append('</ul></div>')
        }
        $confirm = @($c.Confirm | Where-Object { $_ })
        if ($confirm.Count -gt 0) {
            [void]$sb.Append('<div><span class="dgk">How to confirm (read-only)</span><ul>')
            foreach ($x in $confirm) { [void]$sb.AppendFormat('<li>{0}</li>', (& $e $x)) }
            [void]$sb.Append('</ul></div>')
        }
        $fix = @($c.Fix | Where-Object { $_ })
        if ($fix.Count -gt 0) {
            [void]$sb.AppendFormat('<div><span class="dgk">How to fix (action for the {0}; this tool changes nothing)</span><ul>', (& $e $c.FixOwner))
            foreach ($x in $fix) { [void]$sb.AppendFormat('<li>{0}</li>', (& $e $x)) }
            [void]$sb.Append('</ul></div>')
        }
        [void]$sb.Append('</li>')
    }
    [void]$sb.Append('</ol>')
    $srcs = @($d.Sources)
    if ($srcs.Count -gt 0) {
        [void]$sb.Append('<div class="dgs"><span class="dgk">Sources</span><ul>')
        foreach ($s in $srcs) { [void]$sb.AppendFormat('<li>{0} ({1}): <code>{2}</code></li>', (& $e $s.Title), (& $e $s.Publisher), (& $e $s.Url)) }
        [void]$sb.Append('</ul></div>')
    }
    [void]$sb.Append('</div>')
    return $sb.ToString()
}

function ConvertTo-MspkiHtmlFinding {
    <#
    .SYNOPSIS
    Renders one finding: a summary row plus the details (fields, sources, layers, evidence, remediation, notes).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $f = $Finding
    $e = { param($v) ConvertTo-MspkiHtmlText $v }
    $search = ((@($f.Id, $f.Status, $f.StatusCode, $f.Category, $f.Role, $f.Target, $f.Endpoint, $f.RelatedCA, $f.Message, ($f.Sources -join ' '), ($f.Evidence -join ' ')) |
        ForEach-Object { [string]$_ }) -join ' ').ToLowerInvariant()
    if ($search.Length -gt 4000) { $search = $search.Substring(0, 4000) }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendFormat('<details class="f" id="{0}" data-status="{1}" data-category="{2}" data-confidence="{3}" data-scope="{4}" data-code="{5}" data-search="{6}">',
        (& $e $f.Id), (& $e $f.Status), (& $e $f.Category), (& $e $f.Confidence), (& $e $f.Scope), (& $e $f.StatusCode), (& $e $search))
    [void]$sb.AppendFormat('<summary><span class="id">{0}</span>{1}<span class="code">{2}</span>{3}<span class="muted">{4}</span><span class="msg">{5}</span></summary>',
        (& $e $f.Id), (New-MspkiHtmlStatusBadge $f.Status), (& $e $f.StatusCode), (New-MspkiHtmlConfidenceBadge $f.Confidence), (& $e $f.Category), (& $e $f.Message))
    [void]$sb.Append('<div class="fd"><dl>')
    foreach ($row in @(@('Target', $f.Target), @('Endpoint', $f.Endpoint), @('Related CA', $f.RelatedCA), @('Role', $f.Role), @('Scope', $f.Scope),
                       @('Stage', $f.Stage), @('Severity', $f.Severity), @('Time (UTC)', $f.Timestamp))) {
        if ($row[1]) { [void]$sb.AppendFormat('<dt>{0}</dt><dd>{1}</dd>', $row[0], (& $e $row[1])) }
    }
    [void]$sb.Append('</dl>')
    [void]$sb.Append('<h4>Sources</h4><div>')
    foreach ($s in @($f.Sources)) { [void]$sb.AppendFormat('<span class="chip">{0}</span>', (& $e $s)) }
    [void]$sb.AppendFormat('</div><h4>Confidence</h4><div>{0}</div>', (New-MspkiHtmlConfidenceBadge $f.Confidence))
    [void]$sb.Append('<h4>Layers</h4><div class="layers">')
    foreach ($l in @('DiscoveryStatus', 'DnsStatus', 'TcpStatus', 'HttpStatus', 'RedirectStatus', 'TlsStatus', 'ContentStatus', 'ChainStatus')) {
        $v = [string]$f.$l
        if (-not $v) { $v = 'NotTested' }
        [void]$sb.AppendFormat('<span class="l-{0}">{1}: {0}</span>', (& $e $v), ($l -replace 'Status$', ''))
    }
    [void]$sb.Append('</div>')
    if (@($f.Evidence).Count -gt 0) {
        [void]$sb.Append('<h4>Evidence</h4><ul>')
        foreach ($x in @($f.Evidence)) { [void]$sb.AppendFormat('<li>{0}</li>', (& $e $x)) }
        [void]$sb.Append('</ul>')
    }
    $dg = Get-MspkiFindingDiagnosis -Finding $f
    if ($null -ne $dg) { [void]$sb.Append((New-MspkiHtmlDiagnosis -Diagnosis $dg)) }
    if ($f.Remediation) { [void]$sb.AppendFormat('<h4>Remediation</h4><div>{0}</div>', (& $e $f.Remediation)) }
    if ($f.Notes) { [void]$sb.AppendFormat('<h4>Notes</h4><div>{0}</div>', (& $e $f.Notes)) }
    [void]$sb.Append('</div></details>')
    return $sb.ToString()
}

function New-MspkiHtmlOptions {
    [CmdletBinding()]
    param([string[]]$Values, [string]$AllLabel)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendFormat('<option value="">{0}</option>', (ConvertTo-MspkiHtmlText $AllLabel))
    foreach ($v in @($Values | Where-Object { $_ } | Sort-Object -Unique)) { [void]$sb.AppendFormat('<option value="{0}">{0}</option>', (ConvertTo-MspkiHtmlText $v)) }
    return $sb.ToString()
}

function Get-MspkiReportHtml {
    <#
    .SYNOPSIS
    Builds the complete report.html text from run info, inventory, findings and the exit code.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$RunInfo,
        [AllowNull()]$Inventory = $null,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [int]$ExitCode = 0
    )
    $all = @($Findings | Where-Object { $null -ne $_ })
    $e = { param($v) ConvertTo-MspkiHtmlText $v }
    $sum = Get-MspkiFindingSummary -Findings $all
    $completed = $true
    if ($null -ne $RunInfo.Completed) { $completed = [bool]$RunInfo.Completed }
    $exit = Get-MspkiExitCodeInfo -Code $ExitCode -Findings $all -Completed $completed
    $tree = Get-MspkiDiscoveryTree -Inventory $Inventory -Findings $all -RunInfo $RunInfo
    $forest = [string]$RunInfo.Forest
    if (-not $forest -and $null -ne $Inventory -and $null -ne $Inventory.AdContext) { $forest = [string]$Inventory.AdContext.Forest }
    $domain = [string]$RunInfo.Domain

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<!DOCTYPE html>`n<html lang=""en""><head><meta charset=""utf-8"">`n")
    [void]$sb.Append("<meta name=""viewport"" content=""width=device-width,initial-scale=1"">`n")
    [void]$sb.Append("<meta http-equiv=""Content-Security-Policy"" content=""default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:"">`n")
    [void]$sb.AppendFormat("<title>MSPKI Health Check{0}</title>`n", $(if ($forest) { ' - ' + (& $e $forest) } else { '' }))
    [void]$sb.Append("<style>`n").Append((Get-MspkiReportCss)).Append("`n</style></head><body>`n")

    # --- header
    [void]$sb.Append('<header class="top"><div class="wrap"><div>')
    [void]$sb.AppendFormat('<h1>MSPKI Health Check</h1><div class="sub">{0}{1}{2} &middot; run started {3} UTC &middot; {4} {5}</div>',
        $(if ($forest) { 'Forest ' + (& $e $forest) } else { 'Forest not discovered' }), $(if ($domain) { ' &middot; domain ' + (& $e $domain) } else { '' }), '',
        (& $e $RunInfo.StartedUtc), (& $e $RunInfo.Tool), (& $e $RunInfo.ToolVersion))
    [void]$sb.Append('</div><div><button class="btn" id="theme" type="button" title="Switch light or dark">Light / dark</button></div></div>')
    [void]$sb.Append('<nav class="tabs" aria-label="Report sections"><a href="#summary">Summary</a><a href="#map">Discovery Map</a><a href="#findings">Findings and evidence</a><a href="#run">Run details</a></nav></header>')
    [void]$sb.Append('<main>')

    # --- summary
    [void]$sb.Append('<section id="summary"><h2>Summary</h2>')
    if (-not $completed) {
        [void]$sb.Append('<div class="warnbox"><b>This run did not finish.</b> The results below are partial.</div>')
    }
    $st = $sum.ByStatus
    $tile = { param($cls, $n, $label, $filter)
        '<button type="button" class="tile {0}" data-filter="{1}"><b>{2}</b><span>{3}</span></button>' -f $cls, $filter, $n, $label }
    [void]$sb.Append('<div class="tiles">')
    [void]$sb.Append((& $tile '' $sum.Total 'All findings' ''))
    [void]$sb.Append((& $tile 's-crit' ([int]$st.Critical + [int]$st.Fail) 'Critical / Fail' 'Critical,Fail'))
    [void]$sb.Append((& $tile 's-warn' $st.Warning 'Warning' 'Warning'))
    [void]$sb.Append((& $tile '' $st.Error 'Error' 'Error'))
    [void]$sb.Append((& $tile 's-info' $st.Information 'Information' 'Information'))
    [void]$sb.Append((& $tile 's-pass' $st.Pass 'Pass' 'Pass'))
    [void]$sb.Append((& $tile '' ([int]$st.Skipped + [int]$st.NotApplicable) 'Skipped / N/A' 'Skipped,NotApplicable'))
    [void]$sb.Append('</div>')

    [void]$sb.Append('<div class="grid g2" style="margin-top:14px">')
    # exit code
    [void]$sb.AppendFormat('<div class="card exit exit-{0}"><div class="code">{0}</div><div><b>{1}</b><div class="muted">{2}</div>', $exit.Code, (& $e $exit.Name), (& $e $exit.Meaning))
    if ($exit.Note) { [void]$sb.AppendFormat('<div class="small">{0}</div>', (& $e $exit.Note)) }
    if ($exit.DriverCount -gt 0) {
        [void]$sb.AppendFormat('<div class="small">Decided by {0} finding(s): ', $exit.DriverCount)
        foreach ($id in @($exit.DriverIds | Select-Object -First 12)) { [void]$sb.AppendFormat('<a href="#{0}">{0}</a> ', (& $e $id)) }
        [void]$sb.Append('</div>')
    }
    [void]$sb.Append('</div></div>')
    # confidence
    $tot = [math]::Max(1, [int]$sum.Total)
    [void]$sb.Append('<div class="card"><b>Confidence</b><div class="bar" role="img" aria-label="Findings by confidence">')
    foreach ($c in @('Confirmed', 'Referenced', 'Inferred', 'Unknown')) {
        $n = [int]$sum.ByConfidence.$c
        if ($n -gt 0) { [void]$sb.AppendFormat('<i class="c-{0}" style="width:{1}%" title="{0}: {2}"></i>', $c, [math]::Round(100.0 * $n / $tot, 2).ToString([System.Globalization.CultureInfo]::InvariantCulture), $n) }
    }
    [void]$sb.Append('</div><div class="legend small">')
    foreach ($c in @('Confirmed', 'Referenced', 'Inferred', 'Unknown')) {
        [void]$sb.AppendFormat('<span><i class="dot c-{0}" style="background:var(--{1})"></i>{0} {2}</span>', $c, $(switch ($c) { 'Confirmed' { 'pass' } 'Referenced' { 'info' } 'Inferred' { 'warn' } default { 'skip' } }), [int]$sum.ByConfidence.$c)
    }
    [void]$sb.Append('</div><div class="small muted" style="margin-top:6px">Confirmed = authoritative and validated. Referenced = named by a certificate, CRL, AD object or policy. Inferred = strong evidence, not validated.</div></div>')
    [void]$sb.Append('</div>')

    # by category
    [void]$sb.Append('<h3>Findings by category</h3><div class="card" style="overflow-x:auto"><table><thead><tr><th>Category</th><th class="n">Total</th><th class="n">Critical/Fail</th><th class="n">Warning</th><th class="n">Error</th><th class="n">Information</th><th class="n">Pass</th></tr></thead><tbody>')
    foreach ($cat in @($all | Group-Object Category | Sort-Object Name)) {
        $g = @($cat.Group)
        $cnt = { param($names) @($g | Where-Object { $names -contains $_.Status }).Count }
        [void]$sb.AppendFormat('<tr><td>{0}</td><td class="n">{1}</td><td class="n">{2}</td><td class="n">{3}</td><td class="n">{4}</td><td class="n">{5}</td><td class="n">{6}</td></tr>',
            (& $e $cat.Name), $g.Count, (& $cnt @('Critical', 'Fail')), (& $cnt @('Warning')), (& $cnt @('Error')), (& $cnt @('Information')), (& $cnt @('Pass')))
    }
    [void]$sb.Append('</tbody></table></div>')

    # needs attention
    $attention = @($all | Where-Object { (Get-MspkiStatusRank $_.Status) -ge 4 } |
        Sort-Object @{ Expression = { Get-MspkiStatusRank $_.Status }; Descending = $true }, Id | Select-Object -First 15)
    [void]$sb.Append('<h3>Needs attention</h3>')
    if ($attention.Count -eq 0) { [void]$sb.Append('<p class="muted">No warnings, failures or errors were found.</p>') }
    else {
        [void]$sb.Append('<div class="card" style="overflow-x:auto"><table><thead><tr><th>Finding</th><th>Status</th><th>Code</th><th>Target</th><th>What</th></tr></thead><tbody>')
        foreach ($a in $attention) {
            [void]$sb.AppendFormat('<tr><td><a href="#{0}">{0}</a></td><td>{1}</td><td class="mono">{2}</td><td>{3}</td><td>{4}</td></tr>',
                (& $e $a.Id), (New-MspkiHtmlStatusBadge $a.Status), (& $e $a.StatusCode), (& $e $a.Target), (& $e $a.Message))
        }
        [void]$sb.Append('</tbody></table></div>')
    }
    [void]$sb.Append('</section>')

    # --- discovery map
    [void]$sb.Append('<section id="map"><h2>Discovery Map</h2>')
    [void]$sb.Append('<p class="muted">Forest, CAs, CA certificates and the links followed from them. Each node shows how sure the tool is and where the information came from; a link used by several certificates appears once.</p>')
    [void]$sb.Append('<div class="toolbar"><label><input type="checkbox" id="tproblems"> Only branches with warnings or worse</label><button class="btn" type="button" id="texpand">Expand all</button><button class="btn" type="button" id="tcollapse">Collapse</button></div>')
    [void]$sb.Append('<div class="card"><ul class="tree" id="tree">').Append((ConvertTo-MspkiHtmlNode -Node $tree)).Append('</ul></div></section>')

    # --- findings
    [void]$sb.Append('<section id="findings"><h2>Findings and evidence</h2>')
    [void]$sb.Append('<div class="toolbar"><input type="search" id="fsearch" placeholder="Search id, target, URL, message, source, evidence" aria-label="Search findings">')
    [void]$sb.AppendFormat('<select id="fcat" aria-label="Category">{0}</select>', (New-MspkiHtmlOptions -Values @($all | ForEach-Object { $_.Category }) -AllLabel 'All categories'))
    [void]$sb.AppendFormat('<select id="fconf" aria-label="Confidence">{0}</select>', (New-MspkiHtmlOptions -Values @('Confirmed', 'Referenced', 'Inferred', 'Unknown') -AllLabel 'Any confidence'))
    [void]$sb.AppendFormat('<select id="fscope" aria-label="Scope">{0}</select>', (New-MspkiHtmlOptions -Values @($all | ForEach-Object { $_.Scope }) -AllLabel 'Any scope'))
    [void]$sb.AppendFormat('<select id="fcode" aria-label="Status code">{0}</select>', (New-MspkiHtmlOptions -Values @($all | ForEach-Object { $_.StatusCode }) -AllLabel 'Any status code'))
    [void]$sb.Append('</div><div class="toolbar">')
    foreach ($s in @('Critical', 'Fail', 'Error', 'Warning', 'Information', 'Pass', 'Skipped', 'NotApplicable')) {
        [void]$sb.AppendFormat('<button type="button" class="chipbtn" data-status="{0}" aria-pressed="false">{0} ({1})</button>', $s, [int]$st.$s)
    }
    [void]$sb.Append('<button type="button" class="btn" id="fproblems">Warnings and worse</button><button type="button" class="btn" id="freset">Reset</button>')
    [void]$sb.Append('<button type="button" class="btn" id="fexpand">Expand evidence</button><button type="button" class="btn" id="fcollapse">Collapse</button><span class="count" id="fcount"></span></div>')
    [void]$sb.Append('<noscript><p class="warnbox">Filtering needs JavaScript. All findings are listed below.</p></noscript><div id="flist">')
    $ordered = @($all | Sort-Object @{ Expression = { Get-MspkiStatusRank $_.Status }; Descending = $true }, Id)
    foreach ($f in $ordered) { [void]$sb.Append((ConvertTo-MspkiHtmlFinding -Finding $f)) }
    [void]$sb.Append('</div></section>')

    # --- run details
    [void]$sb.Append('<section id="run"><h2>Run details</h2><div class="grid g2"><div class="card"><dl class="kv">')
    foreach ($row in @(@('Tool', ('{0} {1}' -f $RunInfo.Tool, $RunInfo.ToolVersion)), @('Run id', $RunInfo.RunId), @('Started (UTC)', $RunInfo.StartedUtc),
                       @('Finished (UTC)', $RunInfo.FinishedUtc), @('Completed', $RunInfo.Completed), @('Computer', $RunInfo.ComputerName),
                       @('Account', $RunInfo.UserContext), @('Administrator', $RunInfo.IsAdmin),
                       @('PowerShell', ('{0} ({1}), CLR {2}' -f $RunInfo.PSVersion, $RunInfo.PSEdition, $RunInfo.ClrVersion)), @('OS version', $RunInfo.OSVersion),
                       @('Forest', $RunInfo.Forest), @('Domain', $RunInfo.Domain), @('Domain controller', $RunInfo.DomainController), @('AD site', $RunInfo.Site))) {
        if ("$($row[1])" -ne '') { [void]$sb.AppendFormat('<dt>{0}</dt><dd>{1}</dd>', $row[0], (& $e $row[1])) }
    }
    [void]$sb.Append('</dl></div><div class="card"><b>Parameters</b><dl class="kv">')
    if ($RunInfo.Parameters -is [System.Collections.IDictionary]) {
        foreach ($k in $RunInfo.Parameters.Keys) { [void]$sb.AppendFormat('<dt>{0}</dt><dd>{1}</dd>', (& $e $k), (& $e $RunInfo.Parameters[$k])) }
    }
    elseif ($null -ne $RunInfo.Parameters) {
        foreach ($p in $RunInfo.Parameters.psobject.Properties) { [void]$sb.AppendFormat('<dt>{0}</dt><dd>{1}</dd>', (& $e $p.Name), (& $e $p.Value)) }
    }
    [void]$sb.Append('</dl>')
    $ls = $null
    if ($null -ne $Inventory) { $ls = $Inventory.LeadStatistic; if ($null -eq $ls) { $ls = $Inventory.LeadStatistics } }
    if ($null -ne $ls) {
        [void]$sb.AppendFormat('<h4>Link following</h4><div>{0} unique link(s); depth limit {1}, cap {2}; {3} dropped by the cap, {4} by the depth limit.</div>',
            (& $e $ls.Count), (& $e $ls.MaxDepth), (& $e $ls.MaxLeads), (& $e $ls.Dropped), (& $e $ls.DepthDropped))
    }
    [void]$sb.Append('</div></div>')

    $limits = @($RunInfo.Limits | Where-Object { $_ })
    [void]$sb.Append('<h3>Limits reached in this run</h3>')
    if ($limits.Count -eq 0) { [void]$sb.Append('<p class="muted">None.</p>') }
    else { [void]$sb.Append('<ul>'); foreach ($l in $limits) { [void]$sb.AppendFormat('<li>{0}</li>', (& $e $l)) }; [void]$sb.Append('</ul>') }

    [void]$sb.Append('<h3>Discovery methods and outcome</h3><div class="card" style="overflow-x:auto"><table><thead><tr><th>Method</th><th>Outcome</th><th>Detail</th><th class="n">ms</th></tr></thead><tbody>')
    foreach ($m in @($RunInfo.Methods)) {
        [void]$sb.AppendFormat('<tr><td class="mono">{0}</td><td>{1}</td><td>{2}</td><td class="n">{3}</td></tr>', (& $e $m.Method), (& $e $m.Outcome), (& $e $m.Detail), (& $e $m.ElapsedMs))
    }
    [void]$sb.Append('</tbody></table></div>')
    [void]$sb.Append('<h3>Stage timings</h3><div class="card" style="overflow-x:auto"><table><thead><tr><th>Stage</th><th class="n">ms</th></tr></thead><tbody>')
    foreach ($t in @($RunInfo.StageTimings)) { [void]$sb.AppendFormat('<tr><td class="mono">{0}</td><td class="n">{1}</td></tr>', (& $e $t.Stage), (& $e $t.ElapsedMs)) }
    [void]$sb.Append('</tbody></table></div>')
    [void]$sb.Append('<h3>Known limits of this tool</h3><ul>')
    foreach ($k in $script:MspkiKnownLimits) { [void]$sb.AppendFormat('<li>{0}</li>', (& $e $k)) }
    [void]$sb.Append('</ul></section></main>')
    [void]$sb.AppendFormat('<footer>Generated by {0} {1}. Read-only health check; this file is self-contained and makes no network requests.</footer>', (& $e $RunInfo.Tool), (& $e $RunInfo.ToolVersion))
    [void]$sb.Append("<script>`n").Append((Get-MspkiReportScript)).Append("`n</script></body></html>`n")
    return $sb.ToString()
}

function Export-MspkiHtml {
    <#
    .SYNOPSIS
    Writes report.html (UTF-8, no BOM) inside the run output folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$RunInfo,
        [AllowNull()]$Inventory = $null,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [int]$ExitCode = 0
    )
    $html = Get-MspkiReportHtml -RunInfo $RunInfo -Inventory $Inventory -Findings $Findings -ExitCode $ExitCode
    Write-MspkiOutputFile -Path $Path -Content $html
    return $Path
}
