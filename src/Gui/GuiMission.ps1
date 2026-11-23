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

function Get-MspkiGuiNodeHealth {
    # Worst health-bearing status of an entity's findings: Information and NotApplicable say nothing about health.
    param([AllowEmptyCollection()][string[]]$Statuses = @())
    $best = ''; $rank = -2
    foreach ($s in $Statuses) {
        if ($s -in @('Information', 'NotApplicable', '')) { continue }
        $r = Get-MspkiGuiRank -Kind Status -Value $s
        if ($r -gt $rank) { $rank = $r; $best = $s }
    }
    switch ($best) {
        { $_ -in @('Critical', 'Fail') } { return 'Bad' }
        'Error' { return 'Admin' }
        'Warning' { return 'Warn' }
        'Pass' { return 'Good' }
    }
    return 'Neutral'
}

function Get-MspkiGuiShortHost {
    # The first label of a DNS name ("pki" for pki.alcyone-orbital.example); a name without dots stays as it is.
    param([string]$Name)
    if (-not $Name) { return '' }
    $i = $Name.IndexOf('.')
    if ($i -gt 0) { return $Name.Substring(0, $i) }
    return $Name
}

function Get-MspkiGuiEndpointLabel {
    # A short label for an endpoint URL: the last path part (decoded) for HTTP, the object's CN for LDAP.
    param([string]$Url)
    if (-not $Url) { return '' }
    $u = $Url
    try { $u = [System.Uri]::UnescapeDataString($Url) } catch { $u = $Url }
    if ($u -match '^(?i)ldap://[^/]*/CN=([^,]+)') { return $Matches[1] }
    $path = ($u -replace '^[a-zA-Z]+://[^/]*', '').TrimEnd('/')
    $leaf = ($path -split '/')[-1]
    if (-not $leaf) { $leaf = ($u -replace '^[a-zA-Z]+://', '') -replace '/.*$', '' }
    return $leaf
}

function Get-MspkiGuiMapModel {
    <#
    .SYNOPSIS
    The discovery map as columns of nodes and links, from the results graph: root CAs, issuing CAs, the addresses (AIA, CDP, OCSP,
    enrollment) the CAs publish, and the hosts or the directory that serve them. Each node carries its health tone and the times
    (ms) at which the build animation shows it, probes it and reveals its health. Returns $null when there is no graph.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Index, [hashtable]$FindingStatus = @{})
    if ($null -eq $Index) { return $null }
    $ent = $Index.Entities
    $rels = @(foreach ($k in $Index.Out.Keys) { $Index.Out[$k] })
    $relOf = { param($type) @($rels | Where-Object { [string]$_.Type -eq $type }) }
    $statusOf = {
        param([string[]]$ids)
        $st = @(foreach ($id in $ids) { if ($Index.Findings.ContainsKey($id)) { foreach ($fid in $Index.Findings[$id]) { [string]$FindingStatus[[string]$fid] } } })
        Get-MspkiGuiNodeHealth -Statuses $st
    }
    $nodes = [ordered]@{}
    $links = New-Object System.Collections.ArrayList
    $linkSeen = @{}
    $addLink = { param($from, $to, $kind) $k = $from + '>' + $to; if ($from -ne $to -and -not $linkSeen.ContainsKey($k)) { $linkSeen[$k] = $true; [void]$links.Add([pscustomobject]@{ From = $from; To = $to; Kind = $kind }) } }

    # CA nodes: one per CA entity; a CA certificate without a CA entity (an offline root) gets one node per subject.
    $certToCa = @{}
    foreach ($r in (& $relOf 'certificateOf')) { if ($ent.ContainsKey([string]$r.To) -and [string]$ent[[string]$r.To].Type -eq 'CA') { $certToCa[[string]$r.From] = [string]$r.To } }
    $certNode = @{}
    foreach ($e in @($ent.Values | Where-Object { [string]$_.Type -eq 'CACertificate' } | Sort-Object { [string]$_.Id })) {
        $id = [string]$e.Id
        if ($certToCa.ContainsKey($id)) { $certNode[$id] = $certToCa[$id]; continue }
        $subj = [string]$e.Name
        $nid = 'cagroup:' + $subj.ToLowerInvariant()
        $certNode[$id] = $nid
        if (-not $nodes.Contains($nid)) {
            $cn = $subj; if ($subj -match '(?i)CN=([^,]+)') { $cn = $Matches[1].Trim() }
            $nodes[$nid] = [pscustomobject]@{ Id = $nid; EntityId = $id; Kind = 'CA'; Label = $cn; Sub = 'Certificate only'; Glyph = [string][char]0xEB95; Members = (New-Object System.Collections.ArrayList); Layer = 0 }
        }
        [void]$nodes[$nid].Members.Add($id)
    }
    foreach ($e in @($ent.Values | Where-Object { [string]$_.Type -eq 'CA' } | Sort-Object { [string]$_.Name })) {
        $id = [string]$e.Id
        $hostName = ''; if ($id -match '^ca:([^\\]+)\\') { $hostName = Get-MspkiGuiShortHost -Name $Matches[1] }
        $sub = $(if ($hostName) { 'CA on ' + $hostName } else { 'Enterprise CA' })
        if ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['PropertiesRead'] -and -not $e.Properties.PropertiesRead) { $sub += ' ' + [string][char]0x00B7 + ' not read' }
        $caType = ''; if ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['CAType']) { $caType = [string]$e.Properties.CAType }
        $unread = ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['PropertiesRead'] -and -not $e.Properties.PropertiesRead)
        $nodes[$id] = [pscustomobject]@{ Id = $id; EntityId = $id; Kind = 'CA'; Label = [string]$e.Name; Sub = $sub; Glyph = [string][char]0xEB95; Members = (New-Object System.Collections.ArrayList); Layer = 0; CAType = $caType; Unread = $unread }
        [void]$nodes[$id].Members.Add($id)
        foreach ($c in @($certToCa.Keys | Where-Object { $certToCa[$_] -eq $id })) { [void]$nodes[$id].Members.Add($c) }
    }
    # Chain: issuedBy (certificate -> issuer certificate) gives parent CA node -> child CA node.
    $parent = @{}
    foreach ($r in (& $relOf 'issuedBy')) {
        $c = [string]$r.From; $p = [string]$r.To
        if ($certNode.ContainsKey($c) -and $certNode.ContainsKey($p) -and $certNode[$c] -ne $certNode[$p]) {
            $parent[$certNode[$c]] = $certNode[$p]
            & $addLink $certNode[$p] $certNode[$c] 'chain'
        }
    }
    $caIds = @($nodes.Keys)
    $hasRoot = $false
    foreach ($id in $caIds) {
        $d = 0; $cur = $id; $guard = 0
        while ($parent.ContainsKey($cur) -and $guard -lt 8) { $cur = $parent[$cur]; $d++; $guard++ }
        $nodes[$id].Layer = [math]::Min($d, 2)
        if ($d -eq 0 -and [string]$nodes[$id].CAType -notmatch 'Subordinate') { if ($parent.Values -contains $id -or [string]$nodes[$id].CAType -match 'Root') { $hasRoot = $true } }
    }
    # A CA whose chain is unknown (its properties could not be read) sits with the issuing CAs when it is not a root itself.
    foreach ($id in $caIds) {
        $n = $nodes[$id]
        if ($n.Layer -eq 0 -and -not ($parent.Values -contains $id) -and ([string]$n.CAType -match 'Subordinate' -or ($hasRoot -and [string]$n.CAType -notmatch 'Root'))) { $n.Layer = 1 }
    }
    $caLayers = 1 + (@($caIds | ForEach-Object { $nodes[$_].Layer }) | Measure-Object -Maximum).Maximum
    if ($caIds.Count -eq 0) { $caLayers = 0 }
    $epLayer = $caLayers; $hostLayer = $caLayers + 1

    # Endpoints: referenced by a CA or one of its certificates.
    $svcKind = @{}
    foreach ($r in (& $relOf 'servedBy')) { if ($ent.ContainsKey([string]$r.To)) { $svcKind[[string]$r.From] = [string]$ent[[string]$r.To].Properties.Kind } }
    foreach ($r in (& $relOf 'references')) {
        $ep = [string]$r.To
        if (-not $ent.ContainsKey($ep) -or [string]$ent[$ep].Type -ne 'Endpoint') { continue }
        $owner = $(if ($nodes.Contains([string]$r.From)) { [string]$r.From } elseif ($certNode.ContainsKey([string]$r.From)) { $certNode[[string]$r.From] } else { '' })
        if (-not $owner) { continue }
        if (-not $nodes.Contains($ep)) {
            $e = $ent[$ep]
            $url = [string]$e.Properties.Url; if (-not $url) { $url = [string]$e.Name }
            $kinds = @($e.Properties.Kinds | Where-Object { $_ })
            $kind = $(if ($svcKind.ContainsKey($ep) -and $svcKind[$ep]) { $svcKind[$ep] } elseif ($kinds.Count -gt 0) { [string]$kinds[0] } else { 'Address' })
            $scheme = $(if ($url -match '^([a-zA-Z]+):') { $Matches[1].ToUpperInvariant() } else { '' })
            $nodes[$ep] = [pscustomobject]@{ Id = $ep; EntityId = $ep; Kind = 'Endpoint'; Label = (Get-MspkiGuiEndpointLabel -Url $url); Sub = ('{0}{1}{2}' -f $kind, $(if ($scheme) { ' over ' } else { '' }), $scheme); Glyph = [string][char]0xE774; Members = (New-Object System.Collections.ArrayList); Layer = $epLayer; Owner = $owner; Url = $url; KindText = $kind }
            [void]$nodes[$ep].Members.Add($ep)
        }
        & $addLink $owner $ep 'publishes'
    }
    # Hosts behind the endpoints; LDAP addresses without a host are served by the directory (the forest entity).
    $svcOnHost = @{}
    foreach ($r in (& $relOf 'hostedOn')) {
        if ($ent.ContainsKey([string]$r.From) -and [string]$ent[[string]$r.From].Type -eq 'Service') { $svcOnHost[[string]$r.To] = [string]$ent[[string]$r.From].Properties.Kind }
    }
    $forest = @($ent.Values | Where-Object { [string]$_.Type -eq 'Forest' })[0]
    foreach ($ep in @($nodes.Keys | Where-Object { $nodes[$_].Kind -eq 'Endpoint' })) {
        $hosts = @($Index.Out[$ep] | Where-Object { $null -ne $_ -and [string]$_.Type -eq 'hostedOn' } | ForEach-Object { [string]$_.To })
        if ($hosts.Count -eq 0 -and [string]$nodes[$ep].Url -match '^(?i)ldap:///' -and $null -ne $forest) { $hosts = @([string]$forest.Id) }
        foreach ($h in $hosts) {
            if (-not $ent.ContainsKey($h)) { continue }
            if (-not $nodes.Contains($h)) {
                $e = $ent[$h]
                $isForest = ([string]$e.Type -eq 'Forest')
                $sub = $(if ($isForest) { 'Active Directory' } elseif ($svcOnHost.ContainsKey($h) -and $svcOnHost[$h]) { $svcOnHost[$h] + ' host' } else { 'Web host' })
                $nodes[$h] = [pscustomobject]@{ Id = $h; EntityId = $h; Kind = $(if ($isForest) { 'Directory' } else { 'Host' }); Label = $(if ($isForest) { [string]$e.Name } else { Get-MspkiGuiShortHost -Name ([string]$e.Name) }); Sub = $sub; Glyph = $(if ($isForest) { [string][char]0xE8D4 } else { [string][char]0xE968 }); Members = (New-Object System.Collections.ArrayList); Layer = $hostLayer }
                [void]$nodes[$h].Members.Add($h)
            }
            & $addLink $ep $h 'hostedOn'
        }
    }
    # Short labels: the first word every CA name shares (usually the organisation) is left out; the full name stays in the tooltip.
    $caNames = @($nodes.Values | Where-Object { $_.Kind -eq 'CA' } | ForEach-Object { [string]$_.Label })
    $prefix = ''
    if ($caNames.Count -ge 2) {
        $w = ($caNames[0] -split ' ')[0]
        if ($w -and @($caNames | Where-Object { $_.StartsWith($w + ' ') -and ($_ -split ' ').Count -ge 3 }).Count -eq $caNames.Count) { $prefix = $w + ' ' }
    }
    foreach ($n in $nodes.Values) {
        $n | Add-Member -NotePropertyName Tone -NotePropertyValue (& $statusOf ([string[]]@($n.Members))) -Force
        # A CA whose properties this run could not read was not checked: say so instead of showing "no finding".
        if ($null -ne $n.PSObject.Properties['Unread'] -and $n.Unread -and $n.Tone -in @('Neutral', 'Good')) { $n.Tone = 'Admin' }
        $n | Add-Member -NotePropertyName FullName -NotePropertyValue $(if ($ent.ContainsKey([string]$n.EntityId)) { [string]$ent[[string]$n.EntityId].Name } else { $n.Label }) -Force
        if ($prefix -and $n.Kind -in @('CA', 'Endpoint') -and ([string]$n.Label).StartsWith($prefix)) { $n.Label = ([string]$n.Label).Substring($prefix.Length) }
        foreach ($p in 'X', 'Y', 'AppearMs', 'ProbeMs', 'ResultMs', 'LabelWidth') { $n | Add-Member -NotePropertyName $p -NotePropertyValue 0 -Force }
    }
    # Two addresses with the same label and kind (the same file on two web hosts) get their host in the second line.
    foreach ($grp in @($nodes.Values | Where-Object { $_.Kind -eq 'Endpoint' } | Group-Object { [string]$_.Label + '|' + [string]$_.Sub } | Where-Object { $_.Count -gt 1 })) {
        foreach ($n in $grp.Group) { if ([string]$n.Url -match '^[a-zA-Z]+://([^/:]+)') { $n.Sub = '{0} {1} {2}' -f $n.Sub, [char]0x00B7, (Get-MspkiGuiShortHost -Name $Matches[1]) } }
    }
    return [pscustomobject]@{ Nodes = @($nodes.Values); Links = @($links); Layers = $(if ($nodes.Count -gt 0) { $hostLayer + 1 } else { 0 }) }
}

function Set-MspkiGuiMapLayout {
    <#
    .SYNOPSIS
    Places the map nodes in columns (one per layer) for a canvas of the given width, and returns the canvas height it needs.
    The busiest column is spread evenly; every other column follows the average position of its linked nodes, without overlap.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [double]$Width = 640, [double]$LabelWidth = 150)
    $layers = [int]$Model.Layers
    if ($layers -le 0) { return 0 }
    $byLayer = @{}
    foreach ($n in $Model.Nodes) { if (-not $byLayer.ContainsKey([int]$n.Layer)) { $byLayer[[int]$n.Layer] = New-Object System.Collections.ArrayList }; [void]$byLayer[[int]$n.Layer].Add($n) }
    $maxN = (@($byLayer.Values | ForEach-Object { $_.Count }) | Measure-Object -Maximum).Maximum
    $gap = $(if ($maxN -le 6) { 44 } elseif ($maxN -le 10) { 38 } else { 32 })
    $top = 24.0
    $height = [math]::Max(200.0, $top * 2 + ($maxN - 1) * $gap)
    $left = 18.0
    # Column widths follow the longest label in each column (estimated at 6.6 px per character of 12 px Segoe UI, at most
    # -LabelWidth); spare width is shared between the columns, and when there is too little the labels are shortened evenly.
    $node = 20.0; $link = 28.0
    $want = @{}
    foreach ($l in 0..($layers - 1)) {
        $chars = 0
        if ($byLayer.ContainsKey($l)) { $chars = (@($byLayer[$l] | ForEach-Object { [math]::Max(([string]$_.Label).Length, ([string]$_.Sub).Length) }) | Measure-Object -Maximum).Maximum }
        $want[$l] = [math]::Min($LabelWidth, [math]::Max(48.0, $chars * 6.6 + 4))
    }
    $need = $left + ($layers * ($node + 4)) + (($layers - 1) * $link) + (@($want.Values) | Measure-Object -Sum).Sum
    $scale = 1.0; $extra = 0.0
    if ($need -gt $Width) { $scale = [math]::Max(0.45, 1.0 - ($need - $Width) / [math]::Max(1.0, (@($want.Values) | Measure-Object -Sum).Sum)) }
    elseif ($layers -gt 1) { $extra = ($Width - $need) / ($layers - 1) }
    $colX = @{}
    $x = $left
    foreach ($l in 0..($layers - 1)) { $colX[$l] = $x; $x += $node + 4 + [math]::Floor($want[$l] * $scale) + $link + $extra }
    $nb = @{}
    foreach ($l in $Model.Links) {
        foreach ($p in @(@($l.From, $l.To), @($l.To, $l.From))) { if (-not $nb.ContainsKey($p[0])) { $nb[$p[0]] = New-Object System.Collections.ArrayList }; [void]$nb[$p[0]].Add($p[1]) }
    }
    $pos = @{}
    $order = @{}
    $resolve = {
        param($list)
        $sorted = @($list | Sort-Object -Property @{ Expression = { $_.Y } }, @{ Expression = { $order[$_.Id] } })
        $want = (@($sorted | ForEach-Object { $_.Y }) | Measure-Object -Average).Average
        $prev = -1e9
        foreach ($n in $sorted) { $n.Y = [math]::Max($n.Y, $prev + $gap); $prev = $n.Y }
        $shift = $want - (@($sorted | ForEach-Object { $_.Y }) | Measure-Object -Average).Average
        $minY = $sorted[0].Y + $shift; $maxY = $sorted[-1].Y + $shift
        if ($minY -lt $top) { $shift += ($top - $minY) }
        if ($maxY + $shift -gt $height - $top) { $shift -= (($maxY + $shift) - ($height - $top)) }
        foreach ($n in $sorted) { $n.Y = [math]::Round($n.Y + $shift) }
    }
    # Stable order inside each column: CAs by name, endpoints by their CA then kind, hosts by their first endpoint.
    $i = 0
    foreach ($n in @($Model.Nodes | Where-Object { $_.Kind -eq 'CA' } | Sort-Object Layer, Label)) { $order[$n.Id] = $i++ }
    # Addresses of one CA that share a host sit together (fewer crossing links): the directory first, then hosts by name.
    $hostKey = @{}
    foreach ($l in $Model.Links) { if (-not $hostKey.ContainsKey($l.From)) { $t = @($Model.Nodes | Where-Object { $_.Id -eq $l.To -and $_.Kind -in @('Host', 'Directory') })[0]; if ($null -ne $t) { $hostKey[$l.From] = $(if ($t.Kind -eq 'Directory') { ' ' } else { [string]$t.Label }) } } }
    foreach ($n in @($Model.Nodes | Where-Object { $_.Kind -eq 'Endpoint' } | Sort-Object @{ Expression = { $order[$_.Owner] } }, @{ Expression = { $(if ($hostKey.ContainsKey($_.Id)) { $hostKey[$_.Id] } else { '~' }) } }, KindText, Label)) { $order[$n.Id] = $i++ }
    foreach ($n in @($Model.Nodes | Where-Object { $_.Kind -in @('Host', 'Directory') })) {
        $o = @(); if ($nb.ContainsKey($n.Id)) { $o = @($nb[$n.Id] | Where-Object { $_ -and $order.ContainsKey($_) } | ForEach-Object { $order[$_] }) }
        $order[$n.Id] = $(if ($o.Count -gt 0) { 1000 + ($o | Measure-Object -Minimum).Minimum } else { 5000 + $i++ })
    }
    $anchor = @($byLayer.Keys | Sort-Object @{ Expression = { $byLayer[$_].Count }; Descending = $true }, @{ Expression = { $_ } })[0]
    $list = @($byLayer[$anchor] | Sort-Object @{ Expression = { $order[$_.Id] } })
    $y0 = ($height - ($list.Count - 1) * $gap) / 2.0
    for ($k = 0; $k -lt $list.Count; $k++) { $list[$k].Y = [math]::Round($y0 + $k * $gap); $pos[$list[$k].Id] = $list[$k] }
    $sequence = @(@(($anchor + 1)..($layers - 1)) | Where-Object { $_ -gt $anchor -and $_ -lt $layers }) + @(@(($anchor - 1)..0) | Where-Object { $_ -lt $anchor -and $_ -ge 0 })
    foreach ($l in $sequence) {
        if (-not $byLayer.ContainsKey($l)) { continue }
        foreach ($n in $byLayer[$l]) {
            $ys = @(); if ($nb.ContainsKey($n.Id)) { $ys = @($nb[$n.Id] | Where-Object { $_ -and $pos.ContainsKey($_) } | ForEach-Object { $pos[$_].Y }) }
            # The median of the linked positions: one far-away link (a root's own CRL) does not pull a shared host out of its group.
            $ys = @($ys | Sort-Object)
            $n.Y = $(if ($ys.Count -eq 0) { $height / 2.0 } elseif ($ys.Count % 2 -eq 1) { $ys[[int][math]::Floor($ys.Count / 2)] } else { ($ys[$ys.Count / 2 - 1] + $ys[$ys.Count / 2]) / 2.0 })
        }
        & $resolve $byLayer[$l]
        foreach ($n in $byLayer[$l]) { $pos[$n.Id] = $n }
    }
    foreach ($n in $Model.Nodes) {
        $l = [int]$n.Layer
        $n.X = [math]::Round($colX[$l])
        $n.LabelWidth = $(if ($l -eq $layers - 1) { [math]::Floor([math]::Max(48.0, $Width - $colX[$l] - $node - 8)) } else { [math]::Floor($want[$l] * $scale + [math]::Max(0.0, $extra - 8)) })
    }
    return $height
}

function Set-MspkiGuiMapTimeline {
    <#
    .SYNOPSIS
    Sets when each node appears, is probed and shows its health during the build animation (ms), in discovery order:
    CAs layer by layer, then each published address (probed, then graded), each host just after its first address, CAs graded last.
    Returns the total length in ms.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model)
    $t = 0
    foreach ($l in 0..2) {
        $cas = @($Model.Nodes | Where-Object { $_.Kind -eq 'CA' -and [int]$_.Layer -eq $l } | Sort-Object Y)
        $k = 0
        foreach ($n in $cas) { $n.AppearMs = $t + 60 * $k; $k++ }
        if ($cas.Count -gt 0) { $t += 300 + 60 * ($cas.Count - 1) }
    }
    $t += 100
    $eps = @($Model.Nodes | Where-Object { $_.Kind -eq 'Endpoint' } | Sort-Object Y)
    $k = 0
    $last = $t
    foreach ($n in $eps) { $n.AppearMs = $t + 110 * $k; $n.ProbeMs = $n.AppearMs + 100; $n.ResultMs = $n.AppearMs + 1000; $last = $n.ResultMs; $k++ }
    $first = @{}
    foreach ($l in $Model.Links) { foreach ($n in $eps) { if ($n.Id -eq $l.From) { if (-not $first.ContainsKey($l.To) -or $first[$l.To] -gt $n.AppearMs) { $first[$l.To] = $n.AppearMs } } } }
    foreach ($n in @($Model.Nodes | Where-Object { $_.Kind -in @('Host', 'Directory') })) {
        $n.AppearMs = $(if ($first.ContainsKey($n.Id)) { $first[$n.Id] + 250 } else { $last })
        $n.ResultMs = $n.AppearMs + 300
    }
    $k = 0
    foreach ($n in @($Model.Nodes | Where-Object { $_.Kind -eq 'CA' } | Sort-Object Layer, Y)) { $n.ResultMs = [math]::Max($last, $t) + 150 + 60 * $k; $k++ }
    return ((@($Model.Nodes | ForEach-Object { [math]::Max([int]$_.ResultMs, [int]$_.AppearMs) }) | Measure-Object -Maximum).Maximum + 300)
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
    $model = Get-MspkiGuiMapModel -Index $ix -FindingStatus @{}
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
