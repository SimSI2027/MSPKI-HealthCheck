# Mission-control Overview: the health score, the "What to do next" actions and the discovery map model with its layout.
# Pure functions (no WPF types), so they are tested without a window. The score formula is docs/GUI-EXPERIENCE.md section 6;
# change both together. The map model only uses the results graph and the findings: nothing is invented.

$script:MspkiGuiScoreAreas = @(
    [pscustomobject]@{ Key = 'Hierarchy'; Name = 'CA hierarchy'; Categories = @('CA', 'Hierarchy') }
    [pscustomobject]@{ Key = 'Revocation'; Name = 'Revocation'; Categories = @('CRL', 'CDP', 'OCSP') }
    [pscustomobject]@{ Key = 'Publication'; Name = 'Publication'; Categories = @('AIA', 'Identity') }
    [pscustomobject]@{ Key = 'Security'; Name = 'Enrollment security'; Categories = @('Template') }
    [pscustomobject]@{ Key = 'Services'; Name = 'Enrollment services'; Categories = @('WebEnrollment', 'CES', 'CEP', 'NDES', 'IntuneConnector') }
    [pscustomobject]@{ Key = 'Directory'; Name = 'Directory'; Categories = @('ADContainer', 'ADDependency', 'StaleRef') }
)
$script:MspkiGuiScoreHalfLife = 40.0

# The discovery map model, its column order, layout, views and zoom arithmetic (GX6).
. (Join-Path $PSScriptRoot 'GuiMap.ps1')

function Get-MspkiGuiScoreAreaList {
    <#
    .SYNOPSIS
    The score areas in display order: Key, Name and the finding categories each one covers.
    #>
    [CmdletBinding()]
    param()
    return @($script:MspkiGuiScoreAreas)
}

function Get-MspkiGuiFindingPenalty {
    <#
    .SYNOPSIS
    Score points one finding costs: Critical 35, Fail 20, Warning 6, anything else 0; High severity x1.4, Low x0.6.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $base = 0.0
    switch ([string]$Finding.Status) { 'Critical' { $base = 35.0 } 'Fail' { $base = 20.0 } 'Warning' { $base = 6.0 } }
    $mult = 1.0
    switch ([string]$Finding.Severity) { 'High' { $mult = 1.4 } 'Low' { $mult = 0.6 } }
    return ($base * $mult)
}

function Get-MspkiGuiScoreBand {
    <#
    .SYNOPSIS
    Band, tone and icon of a score: 90-100 Healthy, 60-89 Needs attention, 0-59 At risk.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Score)
    if ($Score -ge 90) { return [pscustomobject]@{ Band = 'Healthy'; Tone = 'Good'; Glyph = [string][char]0xE73E } }
    if ($Score -ge 60) { return [pscustomobject]@{ Band = 'Needs attention'; Tone = 'Warn'; Glyph = [string][char]0xE7BA } }
    return [pscustomobject]@{ Band = 'At risk'; Tone = 'Bad'; Glyph = [string][char]0xEA39 }
}

function Get-MspkiGuiHealthScore {
    <#
    .SYNOPSIS
    The overall health score and one score per area, built only from the findings (docs/GUI-EXPERIENCE.md section 6).

    .DESCRIPTION
    Area score = round(100 x 0.5 ^ (penalties / 40)). Overall = the mean of the areas that have findings, capped at the worst area + 30.
    Error and Skipped findings cost nothing but mark the area "partial" (not checked). Run and LocalEvidence findings are not scored.
    With no Enterprise CA there is no score (HasScore = $false) and Reason says why.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [bool]$Completed = $true,
        [bool]$HasCa = $true
    )
    $all = @($Findings | Where-Object { $null -ne $_ })
    $areas = New-Object System.Collections.ArrayList
    foreach ($a in $script:MspkiGuiScoreAreas) {
        $mine = @($all | Where-Object { $a.Categories -contains [string]$_.Category })
        $pen = 0.0; $fail = 0; $warn = 0; $skip = 0
        foreach ($f in $mine) {
            $pen += (Get-MspkiGuiFindingPenalty -Finding $f)
            switch ([string]$f.Status) { 'Critical' { $fail++ } 'Fail' { $fail++ } 'Warning' { $warn++ } 'Error' { $skip++ } 'Skipped' { $skip++ } }
        }
        $score = $null; $tone = 'Neutral'; $glyph = [string][char]0xE738; $detail = 'Nothing found to check'
        if (-not $HasCa) { $detail = 'Not scored: no CA was found' }
        elseif ($mine.Count -gt 0) {
            $score = [int][math]::Round(100.0 * [math]::Pow(0.5, $pen / $script:MspkiGuiScoreHalfLife))
            $b = Get-MspkiGuiScoreBand -Score $score
            $tone = $b.Tone; $glyph = $b.Glyph
            $parts = @()
            if ($fail -gt 0) { $parts += (Format-MspkiGuiCount -Count $fail -Singular 'failure') }
            if ($warn -gt 0) { $parts += (Format-MspkiGuiCount -Count $warn -Singular 'warning') }
            if ($skip -gt 0) { $parts += ('{0} not checked' -f $skip) }
            $detail = $(if ($parts.Count -gt 0) { $parts -join ', ' } else { 'All checks passed' })
        }
        [void]$areas.Add([pscustomobject][ordered]@{
            Key = $a.Key; Name = $a.Name; Score = $score
            ScoreText = $(if ($null -eq $score) { [string][char]0x2014 } else { [string]$score })
            Tone = $tone; Glyph = $glyph; Detail = $detail; Fail = $fail; Warn = $warn; NotChecked = $skip; Count = $mine.Count
            Partial = ($skip -gt 0); Tag = ('area:' + $a.Key)
            AccessibleName = ('{0}: {1}' -f $a.Name, $(if ($null -eq $score) { 'not scored' } else { '{0} of 100, {1}' -f $score, $detail }))
        })
    }
    $scored = @($areas | Where-Object { $null -ne $_.Score })
    $partial = (-not $Completed) -or (@($areas | Where-Object { $_.Partial }).Count -gt 0)
    $how = 'How it is scored: each area starts at 100. A failure costs 20 points, a critical finding 35 and a warning 6 (high severity x1.4, low x0.6); every 40 points halve the area''s score. The overall score is the average of the areas, at most 30 above the weakest one. Checks that could not run cost nothing but make the score partial. It summarises the findings; it is not a certification.'
    $result = [ordered]@{
        HasScore = $false; Overall = $null; OverallText = [string][char]0x2014; Band = ''; Tone = 'Neutral'; Glyph = ''
        Partial = $partial; PartialText = ''; Reason = ''; Areas = @($areas); HowText = $how
    }
    if (-not $HasCa) { $result.Reason = 'No Enterprise CA was found, so there is nothing to score.' }
    elseif ($scored.Count -eq 0) { $result.Reason = 'No finding in this run can be scored.' }
    else {
        $mean = (@($scored | ForEach-Object { [double]$_.Score }) | Measure-Object -Average).Average
        $min = (@($scored | ForEach-Object { [double]$_.Score }) | Measure-Object -Minimum).Minimum
        $overall = [int][math]::Round([math]::Min($mean, $min + 30.0))
        $b = Get-MspkiGuiScoreBand -Score $overall
        $result.HasScore = $true; $result.Overall = $overall; $result.OverallText = [string]$overall
        $result.Band = $b.Band; $result.Tone = $b.Tone; $result.Glyph = $b.Glyph
    }
    if ($partial) {
        $nc = (@($areas | ForEach-Object { $_.NotChecked }) | Measure-Object -Sum).Sum
        $result.PartialText = $(if (-not $Completed) { 'Partial: the run did not finish, so the score covers only what was checked.' }
                                else { 'Partial: {0} could not run, so the score covers only what was checked.' -f (Format-MspkiGuiCount -Count ([int]$nc) -Singular 'check') })
    }
    return [pscustomobject]$result
}

function Get-MspkiGuiNextAction {
    <#
    .SYNOPSIS
    "What to do next": the non-passing findings grouped by their diagnosis topic, most urgent first, with the top probable cause.

    .DESCRIPTION
    A group's priority: its worst status (Critical 100, Fail 80, Error 50, Warning 30) + 4 x the severity rank + 2 per finding (at most 5).
    Each action opens its worst finding (Tag). The cause wording is the knowledge base's own ("Most likely" only when observed).
    Returns Total (all actions) and Items (the first -Max).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @(), [int]$Max = 5)
    $weight = @{ Critical = 100; Fail = 80; Error = 50; Warning = 30 }
    $groups = [ordered]@{}
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        $st = [string]$f.Status
        if (-not $weight.ContainsKey($st)) { continue }
        $d = $null
        try { $d = Get-MspkiFindingDiagnosis -Finding $f } catch { $d = $null }
        $key = $(if ($null -ne $d -and $d.Topic) { 'topic:' + $d.Topic } else { 'finding:' + [string]$f.Id })
        if (-not $groups.Contains($key)) { $groups[$key] = [pscustomobject]@{ Diagnosis = $d; Findings = (New-Object System.Collections.ArrayList) } }
        [void]$groups[$key].Findings.Add($f)
    }
    $actions = foreach ($k in $groups.Keys) {
        $gr = $groups[$k]
        $worst = @($gr.Findings | Sort-Object -Property @{ Expression = { Get-MspkiGuiRank -Kind Status -Value ([string]$_.Status) }; Descending = $true },
            @{ Expression = { Get-MspkiGuiRank -Kind Severity -Value ([string]$_.Severity) }; Descending = $true }, @{ Expression = { [string]$_.Id } })[0]
        $sevRank = [math]::Max(0, (Get-MspkiGuiRank -Kind Severity -Value ([string]$worst.Severity)))
        $n = $gr.Findings.Count
        $prio = $weight[[string]$worst.Status] + 4 * $sevRank + 2 * [math]::Min($n, 5)
        $d = $gr.Diagnosis
        $title = [string]$worst.Message
        $cause = ''; $observed = $false
        if ($null -ne $d) {
            if ($d.Title) { $title = [string]$d.Title }
            $top = @($d.Causes)[0]
            if ($null -ne $top) { $cause = '{0}: {1}' -f $top.Likelihood, $top.Cause }
            $observed = ([string]$d.Basis -eq 'Observed')
        }
        if ($title.Length -gt 110) { $title = $title.Substring(0, 107) + '...' }
        $area = @($script:MspkiGuiScoreAreas | Where-Object { $_.Categories -contains [string]$worst.Category })[0]
        $pill = Get-MspkiGuiStatusPill -Value ([string]$worst.Status)
        [pscustomobject][ordered]@{
            Priority = $prio; Title = $title; Cause = $cause; HasCause = [bool]$cause; Observed = $observed
            ObservedText = $(if ($observed) { 'Observed' } else { '' })
            Count = $n; CountText = (Format-MspkiGuiCount -Count $n -Singular 'finding')
            AreaName = $(if ($null -ne $area) { $area.Name } else { [string]$worst.Category })
            Tone = $pill.Tone; Glyph = $pill.Glyph; StatusText = $pill.Text; Tag = [string]$worst.Id
        }
    }
    $sorted = @($actions | Where-Object { $_ } | Sort-Object -Property @{ Expression = 'Priority'; Descending = $true }, @{ Expression = 'Title' })
    $i = 0
    foreach ($a in $sorted) { $i++; $a | Add-Member -NotePropertyName Rank -NotePropertyValue $i -Force; $a | Add-Member -NotePropertyName RankText -NotePropertyValue ([string]$i) -Force }
    return [pscustomobject]@{ Total = $sorted.Count; Items = @($sorted | Select-Object -First $Max) }
}

function Get-MspkiGuiHeadline {
    <#
    .SYNOPSIS
    The one sentence at the top of the Overview (journey J2: "Is my PKI healthy?" in 5 seconds): how many actions need attention and
    the most urgent one, or that everything checked is healthy.

    .DESCRIPTION
    -Health is the banner from Get-MspkiGuiHealth (its title is kept when there is no action to name); -Actions comes from
    Get-MspkiGuiNextAction; -Score from Get-MspkiGuiHealthScore.
    #>
    [CmdletBinding()]
    param($Health = $null, $Actions = $null, $Score = $null, [bool]$Completed = $true, [bool]$HasCa = $true)
    $fallback = $(if ($null -ne $Health -and $Health.Title) { [string]$Health.Title } else { 'Overview' })
    if (-not $HasCa) { return 'No Enterprise CA was found' }
    $total = $(if ($null -ne $Actions) { [int]$Actions.Total } else { 0 })
    if ($total -gt 0) {
        $first = [string]@($Actions.Items)[0].Title
        $first = $first.Trim().TrimEnd('.')
        $n = $(if ($total -eq 1) { '1 action needs attention' } else { '{0} actions need attention' -f $total })
        $s = '{0}. Most urgent: {1}.' -f $n, $first
        if (-not $Completed) { $s = 'Partial run: ' + $s.Substring(0, 1).ToLowerInvariant() + $s.Substring(1) }
        return $s
    }
    if (-not $Completed) { return 'This run did not finish, so nothing can be said about the rest' }
    if ($null -ne $Score -and $Score.HasScore -and [int]$Score.Overall -ge 90 -and $null -ne $Health -and [string]$Health.Level -eq 'Green') { return 'Everything checked is healthy.' }
    return $fallback
}

function New-MspkiGuiLiveState {
    <#
    .SYNOPSIS
    The window's picture of a run in progress, built from the engine's Entity, Relation and Probe items (GX1): the entities and relations
    announced so far, the probes running now and the worst outcome of each probed object.
    #>
    [CmdletBinding()]
    param()
    return [pscustomobject]@{
        Entities = [ordered]@{}; Relations = (New-Object System.Collections.ArrayList); RelKeys = @{}
        Probes = [ordered]@{}; Outcomes = @{}; Version = 0; DrawnVersion = -1; LastDraw = [DateTime]::MinValue; Shown = @{}
    }
}

function Add-MspkiGuiLiveItem {
    <#
    .SYNOPSIS
    Applies one queue item to the live state. Returns $true when the picture changed (a new entity, a new relation, a probe starting
    or ending); other kinds of items (stage, target, log) are not its business.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)]$Item)
    switch ([string]$Item.Kind) {
        'Entity' {
            $id = [string]$Item.Id
            if (-not $id -or $State.Entities.Contains($id)) { return $false }
            $props = [ordered]@{}
            if ($null -ne $Item.PSObject.Properties['Props'] -and $null -ne $Item.Props) { foreach ($k in $Item.Props.Keys) { $props[[string]$k] = $Item.Props[$k] } }
            $State.Entities[$id] = [pscustomobject]@{ Id = $id; Type = [string]$Item.Type; Name = [string]$Item.Name; Properties = [pscustomobject]$props; Parents = @($Item.Parents | Where-Object { $_ }) }
            $State.Version++
            return $true
        }
        'Relation' {
            $k = ('{0}|{1}|{2}' -f $Item.From, $Item.Type, $Item.To).ToLowerInvariant()
            if ($State.RelKeys.ContainsKey($k)) { return $false }
            $State.RelKeys[$k] = $true
            [void]$State.Relations.Add([pscustomobject]@{ From = [string]$Item.From; Type = [string]$Item.Type; To = [string]$Item.To })
            $State.Version++
            return $true
        }
        'Probe' {
            $id = [string]$Item.Id
            if (-not $id) { return $false }
            if ([string]$Item.Phase -eq 'Start') { $State.Probes[$id] = $Item.Time }
            else {
                if ($State.Probes.Contains($id)) { $State.Probes.Remove($id) }
                $o = [string]$Item.Outcome
                # The worst outcome wins (a host that resolves but refuses TLS is not "answered"); a probe that was not sent says nothing.
                if ($o -and $o -ne 'NOT_APPLICABLE') {
                    if (-not $State.Outcomes.ContainsKey($id) -or $State.Outcomes[$id] -eq 'OK') { $State.Outcomes[$id] = $o }
                }
            }
            $State.Version++
            return $true
        }
    }
    return $false
}

function Get-MspkiGuiLiveMapModel {
    <#
    .SYNOPSIS
    The discovery map model for the live state, built by the same function as the finished map (Get-MspkiGuiMapModel). Health is not
    known until the run ends: an object that was probed shows "answered" (Info tone) or "did not answer" (Warn tone); the rest stay neutral.
    Returns $null while there is nothing to draw.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State)
    if ($State.Entities.Count -eq 0) { return $null }
    $graph = [pscustomobject]@{ Entities = @($State.Entities.Values); Relations = @($State.Relations); Observations = @() }
    $ix = New-MspkiGuiGraphIndex -Graph $graph -Findings @()
    $model = Get-MspkiGuiMapModel -Index $ix -FindingStatus @{} -Live
    if ($null -eq $model) { return $null }
    foreach ($n in $model.Nodes) {
        $eid = [string]$n.EntityId
        if ($State.Outcomes.ContainsKey($eid)) { $n.Tone = $(if ($State.Outcomes[$eid] -eq 'OK') { 'Info' } else { 'Warn' }) }
        elseif ($n.Kind -eq 'CA') { $n.Tone = 'Neutral' }
    }
    return $model
}

function Get-MspkiGuiLiveFoundText {
    <#
    .SYNOPSIS
    "2 CAs, 6 addresses and 4 hosts found so far" for the running hero; empty until something was found.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State)
    $count = { param($t) @($State.Entities.Values | Where-Object { $_.Type -eq $t }).Count }
    $parts = @()
    $ca = & $count 'CA'; $ep = & $count 'Endpoint'; $hs = & $count 'Host'
    if ($ca -gt 0) { $parts += (Format-MspkiGuiCount -Count $ca -Singular 'CA') }
    if ($ep -gt 0) { $parts += (Format-MspkiGuiCount -Count $ep -Singular 'published address' -Plural 'published addresses') }
    if ($hs -gt 0) { $parts += (Format-MspkiGuiCount -Count $hs -Singular 'host') }
    if ($parts.Count -eq 0) { return '' }
    $text = $(if ($parts.Count -eq 1) { $parts[0] } else { (($parts | Select-Object -First ($parts.Count - 1)) -join ', ') + ' and ' + $parts[-1] })
    return ('{0} found so far' -f $text)
}
