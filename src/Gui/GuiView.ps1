# GUI view models: pure functions that turn a run (live or from results.json) into the plain objects the window binds to.
# No WPF types here, so they can be tested without a window. Needs GuiModel.ps1 (pills, ranks) to be loaded first.

$script:MspkiGuiNodeStyle = @{
    Forest = @('Forest', 0xE774); Group = @('Group', 0xE8B7); Container = @('Container', 0xE8D4)
    Certificate = @('Certificate', 0xEB95); CA = @('Certification authority', 0xE83D); Endpoint = @('Endpoint', 0xE71B)
}

# Outcome of a discovery method -> bucket, tone, icon and text. Used by the "Discovery coverage" list.
$script:MspkiGuiOutcomeStyle = @{
    Success = @('Succeeded', 'Good', 0xE73E, 'Succeeded', 3)
    PermissionDenied = @('Could not check', 'Admin', 0xE72E, 'Access denied', 0)
    Error = @('Failed', 'Bad', 0xE711, 'Failed', 0)
    Unreachable = @('Failed', 'Bad', 0xE711, 'Unreachable', 0)
    Timeout = @('Failed', 'Bad', 0xE916, 'Timed out', 0)
    Unsupported = @('Failed', 'Warn', 0xE7BA, 'Unsupported', 0)
    NotDomainJoined = @('Failed', 'Warn', 0xE7BA, 'Not domain-joined', 0)
    NotFound = @('Not found', 'Info', 0xE946, 'Not found', 2)
    Skipped = @('Skipped', 'Neutral', 0xE893, 'Skipped', 1)
}

function ConvertTo-MspkiGuiTreeNode {
    <#
    .SYNOPSIS
    Turns a Discovery Map node (Get-MspkiDiscoveryTree) into a plain tree item for the TreeView: label, icon, status,
    confidence, a hint when something worse is below it, and the child items.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Node,
        [int]$Depth = 0
    )
    $kids = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in @($Node.Children)) { if ($null -ne $c) { $kids.Add((ConvertTo-MspkiGuiTreeNode -Node $c -Depth ($Depth + 1))) } }
    $status = [string]$Node.Status
    $below = [string]$Node.WorstBelow
    $belowText = ''
    $belowRank = Get-MspkiGuiRank -Kind Status -Value $below
    if ($below -and $belowRank -gt (Get-MspkiGuiRank -Kind Status -Value $status) -and $belowRank -ge (Get-MspkiGuiRank -Kind Status -Value 'Warning')) {
        $belowText = 'contains {0}' -f (Get-MspkiGuiStatusLabel -Value $below).ToLowerInvariant()
    }
    $conf = [string]$Node.Confidence
    $confText = ''
    if ($conf) { $confText = '({0})' -f $conf }
    $type = [string]$Node.Type
    $style = $script:MspkiGuiNodeStyle[$type]
    if ($null -eq $style) { $style = @($type, 0xE8A5) }
    return [pscustomobject][ordered]@{
        Kind           = 'Node'
        Type           = $type
        TypeText       = [string]$style[0]
        TypeGlyph      = [string][char]$style[1]
        Label          = [string]$Node.Label
        Status         = $status
        StatusPill     = (Get-MspkiGuiStatusPill -Value $status)
        Confidence     = $conf
        ConfidenceText = $confText
        ConfidencePill = (Get-MspkiGuiStatusPill -Value $conf -Kind Confidence)
        BelowText      = $belowText
        HasBelow       = [bool]$belowText
        Expanded       = ($Depth -lt 2)
        Detail         = [string[]]@($Node.Detail)
        Sources        = [string[]]@($Node.Sources)
        FindingIds     = [string[]]@($Node.FindingIds)
        Children       = [object[]]$kids.ToArray()
    }
}

function Get-MspkiGuiNodeSummary {
    <#
    .SYNOPSIS
    Plain text for a Discovery Map node: its type, status, confidence, details and sources (used for copying).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Node)
    if ($null -eq $Node) { return '' }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add([string]$Node.Label)
    $lines.Add(('Type: {0}' -f $Node.Type))
    if ($Node.Status) { $lines.Add(('Status: {0}' -f $Node.Status)) }
    if ($Node.Confidence) { $lines.Add(('Confidence: {0}' -f $Node.Confidence)) }
    if ($Node.BelowText) { $lines.Add([string]$Node.BelowText) }
    foreach ($d in @($Node.Detail)) { $lines.Add([string]$d) }
    if (@($Node.Sources).Count -gt 0) { $lines.Add(('Sources: {0}' -f (@($Node.Sources) -join ', '))) }
    return ($lines -join "`r`n")
}

function Get-MspkiGuiNodeCount {
    <#
    .SYNOPSIS
    The number of items in a Discovery Map tree (the node and everything below it).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Node)
    $n = 1
    foreach ($c in @($Node.Children)) { if ($null -ne $c) { $n += Get-MspkiGuiNodeCount -Node $c } }
    return $n
}

function Get-MspkiGuiNodePane {
    <#
    .SYNOPSIS
    What the right-hand pane shows for a selected Discovery Map node: its facts and the findings that belong to it.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Node, [hashtable]$RowById = @{})
    if ($null -eq $Node) { return (Get-MspkiGuiEmptyPane -Text 'Select an item in the tree to see what was found and why.') }
    $rows = @($Node.FindingIds | Where-Object { $_ -and $RowById.ContainsKey($_) } | ForEach-Object { $RowById[$_] } |
        Sort-Object @{ Expression = { -1 * $_.StatusRank } }, Id)
    $details = @($Node.Detail | Where-Object { $_ })
    $none = ''
    if ($details.Count -eq 0) { $none = 'No further details were recorded for this item.' }
    return [pscustomobject][ordered]@{
        Kind           = 'Node'
        Title          = [string]$Node.Label
        TypeText       = [string]$Node.TypeText
        TypeGlyph      = [string]$Node.TypeGlyph
        StatusPill     = $Node.StatusPill
        ConfidencePill = $Node.ConfidencePill
        BelowText      = [string]$Node.BelowText
        HasBelow       = [bool]$Node.BelowText
        Details        = [string[]]$details
        NoDetailText   = $none
        Sources        = [string[]]@($Node.Sources | Where-Object { $_ })
        Findings       = [object[]]$rows
        FindingCount   = $rows.Count
        HasFindings    = ($rows.Count -gt 0)
        NoFindings     = ($rows.Count -eq 0)
        CopyText       = (Get-MspkiGuiNodeSummary -Node $Node)
    }
}

function Get-MspkiGuiEmptyPane {
    <#
    .SYNOPSIS
    The details pane when nothing is selected: a short hint.
    #>
    [CmdletBinding()]
    param([string]$Text = 'Select a finding to see everything about it.')
    return [pscustomobject][ordered]@{ Kind = 'None'; Title = ''; Text = $Text }
}

function Get-MspkiGuiRunErrorView {
    <#
    .SYNOPSIS
    The error state of a run that ended without results (D-08): what it means and the likely causes with a read-only check each, ranked by
    the knowledge base (the same topics as the findings), plus a timeout hint when the text says something timed out.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Problem = '', [int]$TimeoutSeconds = 0)
    $code = 'INTERNAL_ERROR'
    if ($Problem -match '(?i)access is denied|permission|0x80070005|unauthori[sz]ed') { $code = 'PERMISSION_DENIED' }
    elseif ($Problem -match '(?i)domain controller|ldap|directory|rootdse|bind|not joined|forest') { $code = 'DIRECTORY_UNAVAILABLE' }
    elseif ($Problem -match '(?i)timed? ?out') { $code = 'TIMEOUT' }
    $f = [pscustomobject]@{ Id = 'run'; Status = 'Error'; StatusCode = $code; Category = 'Run'; Target = 'Run'; Message = $Problem; Evidence = @(); Sources = @(); Severity = 'None'; Confidence = 'Inferred' }
    $d = $null
    try { $d = Get-MspkiFindingDiagnosis -Finding $f -Recompute } catch { $d = $null }
    $causes = New-Object System.Collections.ArrayList
    $meaning = 'The run could not read what it needs to start, so there are no findings to show. Nothing was changed anywhere.'
    if ($null -ne $d) {
        $meaning = '{0}. {1}' -f ([string]$d.Title).TrimEnd('.'), [string]$d.Summary
        foreach ($c in @($d.Causes | Select-Object -First 3)) {
            [void]$causes.Add([pscustomobject]@{ Text = [string]$c.Cause; Check = ('Check (read-only): {0}' -f (@($c.Confirm) | Select-Object -First 1)) })
        }
    }
    if ($Problem -match '(?i)timed? ?out') {
        $t = $(if ($TimeoutSeconds -gt 0) { '{0} s' -f $TimeoutSeconds } else { 'set in Run options' })
        [void]$causes.Add([pscustomobject]@{ Text = ('The timeout ({0}) is too short for this network (a slow VPN or a distant domain controller).' -f $t); Check = 'Change options: raise the timeout, then run again.' })
    }
    return [pscustomobject][ordered]@{ Meaning = $meaning; Causes = @($causes); HasCauses = ($causes.Count -gt 0) }
}

function Expand-MspkiGuiCheckText {
    <#
    .SYNOPSIS
    A read-only check with its placeholders filled from what the finding itself says (D-17): <Url>, <Address>, <Host>, <Port>, <CAName>,
    <CAHost>, <DomainDnsName>, <DomainController>, <TemplateName>, <ForestDN>. A placeholder the finding does not answer stays as it is.
    The text is only shown and copied, never run.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text, [AllowNull()]$Finding = $null, [string]$DomainController = '')
    if (-not $Text -or $null -eq $Finding -or $Text -notmatch '<[A-Za-z]+>') { return $Text }
    $v = @{}
    $ep = [string]$Finding.Endpoint
    $m = [regex]::Match($ep, '^(?i)(https?|ldaps?)://([^/:?#]*)(?::(\d+))?')
    if ($m.Success) {
        if ($ep -match '^(?i)https?://') { $v['Url'] = $ep; $v['Address'] = $ep }
        if ($m.Groups[2].Value) { $v['Host'] = $m.Groups[2].Value }
        $v['Port'] = $(if ($m.Groups[3].Value) { $m.Groups[3].Value } else { switch ($m.Groups[1].Value.ToLowerInvariant()) { 'https' { '443' } 'http' { '80' } 'ldaps' { '636' } default { '389' } } })
    }
    $cm = [regex]::Match($ep, '^(?:CA property \S+ of )?([A-Za-z0-9.-]+\.[A-Za-z0-9.-]+)\\(.+)$')
    if ($cm.Success) { $v['CAHost'] = $cm.Groups[1].Value; $v['CAName'] = $cm.Groups[2].Value }
    if (-not $v.ContainsKey('CAName') -and $Finding.RelatedCA) { $v['CAName'] = (Get-MspkiGuiReadableName -Name ([string]$Finding.RelatedCA)) -replace '^.*\\', '' }
    if (-not $v.ContainsKey('CAName') -and [string]$Finding.Category -eq 'CA' -and $Finding.Target) { $v['CAName'] = Get-MspkiGuiReadableName -Name ([string]$Finding.Target) }
    if (-not $v.ContainsKey('Host') -and [string]$Finding.Target -match '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') { $v['Host'] = [string]$Finding.Target }
    if ([string]$Finding.Category -eq 'Template' -and $Finding.Target) { $v['TemplateName'] = [string]$Finding.Target }
    if ($Finding.Domain) { $v['DomainDnsName'] = [string]$Finding.Domain }
    if ($Finding.Forest) { $v['ForestDN'] = ((([string]$Finding.Forest) -split '\.') | ForEach-Object { 'DC=' + $_ }) -join ',' }
    if ($DomainController -and $DomainController -ne [string][char]0x2014) { $v['DomainController'] = $DomainController }
    # A value with a space is quoted, so the line pastes as one argument.
    return [regex]::Replace($Text, '"?<([A-Za-z]+)>"?', { param($x) $k = $x.Groups[1].Value; if ($v.ContainsKey($k) -and $v[$k]) { $s = [string]$v[$k]; if ($s -match '\s' -or $x.Value.StartsWith('"')) { '"' + $s + '"' } else { $s } } else { $x.Value } })
}

function Test-MspkiGuiCheckIsCommand {
    # A check that is a command (Consolas) rather than a sentence (the body font): a lower-case tool name followed by a switch ("tool -x",
    # "tool /x"), or a Verb-Noun cmdlet.
    param([AllowEmptyString()][string]$Text)
    return [bool]($Text -cmatch '^(?:[a-z][a-z0-9]+(?:\.exe)?\s+[-/][A-Za-z]|[A-Z][a-z]+-[A-Z][A-Za-z]+\b)')
}

function Test-MspkiGuiCauseSupported {
    <#
    .SYNOPSIS
    The one rule for "Observed in this run": the engine's per-cause Supported flag (what this run observed adds at least 10 points).
    Results written before the flag existed fall back to the wording the engine already chose from the same rule ("Most likely" / "Likely").
    #>
    [CmdletBinding()]
    param([AllowNull()]$Cause)
    if ($null -eq $Cause) { return $false }
    $p = $Cause.PSObject.Properties['Supported']
    if ($null -ne $p -and $null -ne $p.Value) {
        $v = $p.Value
        if ($v -is [bool]) { return $v }
        return ([string]$v -eq 'True')
    }
    return (@('Most likely', 'Likely') -contains [string]$Cause.Likelihood)
}

function ConvertTo-MspkiGuiDiagnosisView {
    <#
    .SYNOPSIS
    The "Probable causes and next steps" of a finding as view-model data for the guided walkthrough in the details pane (and a
    plain-text copy of it): what it means, the causes ranked, what this run observed for each, each read-only check as its own row
    (with the keys the pane uses to copy it or mark it as checked), the fix with its owner, and the sources.
    A $null diagnosis (a passing finding) gives HasDiagnosis = $false.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Diagnosis, [string[]]$CheckedKeys = @(), [AllowNull()]$Finding = $null, [string]$DomainController = '')
    $d = $Diagnosis
    if ($null -eq $d) {
        return [pscustomobject][ordered]@{ HasDiagnosis = $false; Title = ''; Summary = ''; BasisNote = ''; Causes = @(); SourceItems = @(); SourcesText = ''; CopyText = ''; ObservedCount = 0 }
    }
    $bullet = [string][char]0x2022
    $lines = New-Object 'System.Collections.Generic.List[string]'
    # D-39: a permission refusal names what was read ("... was refused while reading the CA's properties").
    $diagTitle = [string]$d.Title
    if ([string]$d.Topic -eq 'PERMISSION_DENIED' -and $null -ne $Finding) { $pm = [regex]::Match([string]$Finding.Message, '(?i)Permission denied while ([^.]+)'); if ($pm.Success) { $diagTitle = 'The account running the tool was refused while {0}' -f $pm.Groups[1].Value } }
    $lines.Add('Probable causes and next steps: ' + $diagTitle)
    $lines.Add([string]$d.Summary)
    $lines.Add([string]$d.BasisNote)
    $checked = @{}
    foreach ($k in @($CheckedKeys)) { if ($k) { $checked[[string]$k] = $true } }
    $causes = @(foreach ($c in @($d.Causes)) {
        $rank = [int]$c.Rank
        $because = @($c.Because | Where-Object { $_ })
        $confirm = @($c.Confirm | Where-Object { $_ } | ForEach-Object { Expand-MspkiGuiCheckText -Text ([string]$_) -Finding $Finding -DomainController $DomainController })
        $fix = @($c.Fix | Where-Object { $_ })
        $bt = (($because | ForEach-Object { '{0} {1}' -f $bullet, $_ }) -join "`r`n")
        $supported = Test-MspkiGuiCauseSupported -Cause $c
        $ft =(($fix | ForEach-Object { '{0} {1}' -f $bullet, $_ }) -join "`r`n")
        $i = 0
        $checks = @(foreach ($t in $confirm) {
            $key = '{0}:{1}' -f $rank, $i
            $short = [string]$t; if ($short.Length -gt 60) { $short = $short.Substring(0, 57) + '...' }
            [pscustomobject][ordered]@{
                Key = $key; Text = [string]$t; Checked = $checked.ContainsKey($key); IsCommand = (Test-MspkiGuiCheckIsCommand -Text ([string]$t))
                CopyTag = ('copycheck:{0}:{1}' -f $rank, $i); ToggleTag = ('toggle:{0}:{1}' -f $rank, $i)
                ToggleName = ('Mark as checked: {0}' -f $short); CopyName = ('Copy this check: {0}' -f $short)
            }
            $i++
        })
        $ct = (($confirm | ForEach-Object { '{0} {1}' -f $bullet, $_ }) -join "`r`n")
        $lines.Add(('{0}. {1} [{2}]' -f $c.Rank, $c.Cause, $c.Likelihood))
        if ($bt) { if ($supported) { $lines.Add('   Observed in this run:') } else { $lines.Add('   Hint (not enough to rank it higher):') }; $lines.Add($bt) }
        if ($ct) { $lines.Add('   How to confirm (read-only):'); $lines.Add($ct) }
        if ($ft) { $lines.Add(('   How to fix (action for the {0}):' -f $c.FixOwner)); $lines.Add($ft) }
        [pscustomobject][ordered]@{
            Rank        = $rank
            Heading     = ('{0}. {1}' -f $c.Rank, $c.Cause)
            Cause       = [string]$c.Cause
            Likelihood  = [string]$c.Likelihood
            IsTop       = ($rank -eq 1)
            Observed    = $supported
            HasBecause  = ($supported -and [bool]$bt)
            BecauseText = $bt
            HasHint     = ((-not $supported) -and [bool]$bt)
            HintText    = $(if ($bt) { 'Hint: ' + ((@($because) | ForEach-Object { [string]$_ }) -join '; ') } else { '' })
            Checks      = $checks
            HasChecks   = ($checks.Count -gt 0)
            CopyChecksTag = ('copychecks:{0}' -f $rank)
            ChecksCopyText = (($checks | ForEach-Object -Begin { $n = 0 } -Process { $n++; '{0}. {1}' -f $n, $_.Text }) -join "`r`n")
            ConfirmText = $ct
            FixOwner    = [string]$c.FixOwner
            FixLabel    = ('How to fix: an action for the {0} (this tool changes nothing)' -f $c.FixOwner)
            FixText     = $ft
            HasFix      = [bool]$ft
            CopyFixTag  = ('copyfix:{0}' -f $rank)
        }
    })
    $j = 0
    $srcItems = @(foreach ($s in @($d.Sources)) {
        [pscustomobject][ordered]@{ Title = [string]$s.Title; Publisher = [string]$s.Publisher; Url = [string]$s.Url; CopyTag = ('copysource:{0}' -f $j); CopyName = ('Copy the address of: {0}' -f $s.Title) }
        $j++
    })
    $srcText = ((@($d.Sources) | ForEach-Object { '{0} ({1}){2}{3}' -f $_.Title, $_.Publisher, "`r`n", $_.Url }) -join "`r`n`r`n")
    if ($srcText) { $lines.Add('Sources:'); $lines.Add($srcText) }
    return [pscustomobject][ordered]@{
        HasDiagnosis = $true
        Title        = $diagTitle
        Summary      = [string]$d.Summary
        BasisNote    = [string]$d.BasisNote
        Causes       = $causes
        ObservedCount = @($causes | Where-Object { $_.Observed }).Count
        SourceItems  = $srcItems
        SourcesText  = $srcText
        CopyText     = ($lines -join "`r`n")
    }
}

function Get-MspkiGuiFindingDetail {
    <#
    .SYNOPSIS
    Every field of a finding, grouped for the details pane: header fields, sources, layer statuses, evidence, remediation, notes.
    Empty values show as a dash so that no field looks forgotten.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, [bool]$CanGoBack = $false, [string]$BackText = 'Back to the item', [string[]]$CheckedKeys = $null, [string]$CheckNote = '')
    $f = $Finding
    # The checks this user marked as done for this finding (kept with the run); the window passes none in unit tests.
    if ($null -eq $CheckedKeys) {
        $CheckedKeys = @()
        if ($null -ne $script:MspkiGui -and $script:MspkiGui.ContainsKey('CheckState') -and $null -ne $script:MspkiGui.CheckState) {
            $CheckedKeys = @(Get-MspkiGuiCheckedKey -State $script:MspkiGui.CheckState -FindingId ([string]$f.Id))
            $CheckNote = [string]$script:MspkiGui.CheckState.Note
        }
    }
    $dash = [string][char]0x2014
    # D-23: only the properties that have a value, with readable names; the finding id is last ("Finding id").
    $fieldNames = @('Category', 'Target', 'Endpoint', 'RelatedCA', 'Role', 'Status', 'StatusCode', 'Severity', 'Confidence', 'Scope', 'Stage', 'Timestamp', 'Forest', 'Domain', 'Id')
    $hasLabel = [bool](Get-Command -Name 'Get-MspkiGuiPropertyLabel' -ErrorAction SilentlyContinue)
    $fields = @(foreach ($n in $fieldNames) {
        $v = [string]$f.$n
        if (-not $v) { continue }
        if ($n -eq 'Severity' -and $v -eq 'None') { continue }
        if ($n -eq 'Status') { $v = Get-MspkiGuiStatusLabel -Value (Get-MspkiGuiFindingStatusKey -Finding $f) }
        if ($n -eq 'Timestamp') { $dt = ConvertTo-MspkiGuiDateTime -Value $f.Timestamp; if ($null -ne $dt) { $v = Format-MspkiGuiTime -Value $dt } }
        $label = $n
        if ($n -eq 'Id') { $label = 'Finding id' } elseif ($n -eq 'StatusCode') { $label = 'Status code' } elseif ($n -eq 'RelatedCA') { $label = 'Related CA' } elseif ($hasLabel) { $label = Get-MspkiGuiPropertyLabel -Name $n }
        [pscustomobject][ordered]@{ Name = $label; Value = $v }
    })
    $layerMap = @(@('DNS', 'DnsStatus'), @('TCP', 'TcpStatus'), @('TLS', 'TlsStatus'), @('HTTP', 'HttpStatus'), @('Redirect', 'RedirectStatus'),
        @('Content', 'ContentStatus'), @('Chain', 'ChainStatus'), @('Discovery', 'DiscoveryStatus'))
    $layers = @(foreach ($l in $layerMap) {
        $v = [string]$f.($l[1])
        if (-not $v) { $v = 'NotTested' }
        $pill = Get-MspkiGuiStatusPill -Value $v -Text ('{0}: {1}' -f $l[0], (Get-MspkiGuiStatusLabel -Value $v))
        [pscustomobject][ordered]@{ Name = $l[0]; Status = $v; Pill = $pill }
    })
    $sources = [string[]]@($f.Sources | Where-Object { $_ })
    $evidence = ((@($f.Evidence) | Where-Object { $null -ne $_ }) -join "`r`n")
    $title = Get-MspkiGuiFindingTitle -Finding $f
    $dg = $null
    try { $dg = Get-MspkiFindingDiagnosis -Finding $f } catch { $dg = $null }
    $dcName = ''; if ($null -ne $script:MspkiGui -and $script:MspkiGui.ContainsKey('Summary') -and $null -ne $script:MspkiGui.Summary -and $null -ne $script:MspkiGui.Summary.PSObject.Properties['DomainController']) { $dcName = [string]$script:MspkiGui.Summary.DomainController }
    $diag = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $dg -CheckedKeys $CheckedKeys -Finding $f -DomainController $dcName
    $copy = New-Object 'System.Collections.Generic.List[string]'
    $copy.Add(('{0} [{1}] {2}' -f $f.Id, $f.Status, $title))
    $copy.Add([string]$f.Message)
    foreach ($x in $fields) { $copy.Add(('{0}: {1}' -f $x.Name, $x.Value)) }
    if ($sources.Count -gt 0) { $copy.Add(('Sources: {0}' -f ($sources -join '; '))) }
    if ($evidence) { $copy.Add('Evidence:'); $copy.Add($evidence) }
    if ($f.Remediation) { $copy.Add(('Remediation: {0}' -f $f.Remediation)) }
    if ($diag.HasDiagnosis) { $copy.Add(''); $copy.Add($diag.CopyText) }
    if ($f.Notes) { $copy.Add(('Notes: {0}' -f $f.Notes)) }
    return [pscustomobject][ordered]@{
        Kind           = 'Finding'
        HasDiagnosis   = $diag.HasDiagnosis
        DiagTitle      = $diag.Title
        DiagSummary    = $diag.Summary
        DiagBasis      = $diag.BasisNote
        DiagCauses     = $diag.Causes
        DiagSources    = $diag.SourcesText
        DiagSourceItems = $diag.SourceItems
        DiagObservedCount = $diag.ObservedCount
        CheckNote      = $CheckNote
        Id             = [string]$f.Id
        Status         = [string]$f.Status
        StatusPill     = (Get-MspkiGuiStatusPill -Value (Get-MspkiGuiFindingStatusKey -Finding $f))
        SeverityPill   = (Get-MspkiGuiStatusPill -Value ([string]$f.Severity) -Kind Severity)
        ConfidencePill = (Get-MspkiGuiStatusPill -Value ([string]$f.Confidence) -Kind Confidence)
        Title          = $title
        Message        = (Get-MspkiGuiReadableName -Name (Format-MspkiGuiTextTimes -Text ([string]$f.Message)))
        MessageIsLong  = (([string]$f.Message).Length -gt 170)
        Fields         = $fields
        Sources        = $sources
        Layers         = $layers
        HasLayers      = (@($layers | Where-Object { $_.Status -ne 'NotTested' }).Count -gt 0)
        Evidence       = $evidence
        HasEvidence    = [bool]$evidence
        Remediation    = [string]$f.Remediation
        HasRemediation = [bool]$f.Remediation
        Notes          = [string]$f.Notes
        HasNotes       = [bool]$f.Notes
        CanGoBack      = $CanGoBack
        BackText       = $BackText
        CopyText       = ($copy -join "`r`n")
    }
}

function ConvertTo-MspkiGuiDateTime {
    <#
    .SYNOPSIS
    A date from results.json (a string in Windows PowerShell 5.1, a DateTime in newer hosts) as a UTC DateTime, or $null.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value -or '' -eq [string]$Value) { return $null }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
    $d = [DateTime]::MinValue
    if ([DateTime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    return $null
}

function Get-MspkiGuiDurationText {
    <#
    .SYNOPSIS
    "m:ss" (or "h:mm:ss") for a number of seconds.
    #>
    [CmdletBinding()]
    param([double]$Seconds)
    $t = [TimeSpan]::FromSeconds([math]::Max(0, [math]::Round($Seconds)))
    if ($t.TotalHours -ge 1) { return ('{0}:{1:00}:{2:00}' -f [int][math]::Floor($t.TotalHours), $t.Minutes, $t.Seconds) }
    return ('{0}:{1:00}' -f [int][math]::Floor($t.TotalMinutes), $t.Seconds)
}

function Get-MspkiGuiRoleText {
    <#
    .SYNOPSIS
    Plain-language name of a CA role value from the engine (EnterpriseSubordinate -> "Enterprise subordinate CA").
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Role)
    if (-not $Role) { return '' }
    $words = ($Role -creplace '([a-z])([A-Z])', '$1 $2').ToLowerInvariant()
    $words = $words.Substring(0, 1).ToUpperInvariant() + $words.Substring(1)
    if ($words -notmatch '\bCA\b|\bca$') { $words += ' CA' }
    return $words
}

function Get-MspkiGuiWorstStatus {
    <#
    .SYNOPSIS
    The most serious status among findings, as the window names it (Get-MspkiGuiStatusKey: "CouldNotCheck" for a permission or support skip; '' when there are none).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $worst = ''; $rank = -2
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        $r = Get-MspkiGuiRank -Kind Status -Value ([string]$f.Status)
        if ($r -gt $rank) { $rank = $r; $worst = Get-MspkiGuiFindingStatusKey -Finding $f }
    }
    return $worst
}

function Get-MspkiGuiCaCard {
    <#
    .SYNOPSIS
    One CA card: name, host, role, certificate expiry, CRL state, template and finding counts, worst status.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$CA,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowNull()]$Inventory = $null,
        [AllowNull()]$RunInfo = $null
    )
    $name = [string]$CA.Name
    $mine = @($Findings | Where-Object { $_.RelatedCA -eq $name -or ($_.Category -eq 'CA' -and $_.Target -eq $name) })
    $dash = [string][char]0x2014
    $certs = @()
    if ($null -ne $Inventory) {
        $pattern = 'CN=' + [regex]::Escape($name) + '(,|$)'
        $certs = @($Inventory.CACertificates | Where-Object { $_ -and ($_.CAName -eq $name -or ([string]$_.Info.Subject) -match $pattern) })
    }
    $current = @($certs | Where-Object { $_.Lifecycle -eq 'Current' })
    if ($current.Count -eq 0) { $current = $certs }
    $cert = $null
    foreach ($c in $current) {
        if ($null -eq $cert -or ([double]$c.Info.DaysLeft) -gt ([double]$cert.Info.DaysLeft)) { $cert = $c }
    }
    $role = ''
    if ($null -ne $cert) { $role = Get-MspkiGuiRoleText -Role ([string]$cert.Role) }
    if (-not $role -and $CA.Properties -and $CA.Properties.CATypeName) { $role = Get-MspkiGuiRoleText -Role ([string]$CA.Properties.CATypeName) }
    if (-not $role) { $role = 'Enterprise CA (from Active Directory)' }
    $expiry = 'Certificate not found in the results'
    $expiryPill = New-MspkiGuiPill -Text 'Expiry unknown' -Tone Neutral -Code 0xE897
    if ($null -ne $cert -and $null -ne $cert.Info.DaysLeft -and '' -ne [string]$cert.Info.DaysLeft) {
        $days = [int][math]::Floor([double]$cert.Info.DaysLeft)
        $end = ConvertTo-MspkiGuiDateTime -Value $cert.Info.NotAfter
        $endText = $dash
        if ($null -ne $end) { $endText = $end.ToString('yyyy-MM-dd') }
        $isRoot = ([string]$cert.Role) -like '*Root*'
        $warn = 180; $crit = 90
        if ($isRoot) { $warn = 730; $crit = 365 }
        if ($null -ne $RunInfo -and $null -ne $RunInfo.Parameters) {
            $p = $RunInfo.Parameters
            if ($isRoot) { if ($p.RootCaWarningDays) { $warn = [int]$p.RootCaWarningDays }; if ($p.RootCaCriticalDays) { $crit = [int]$p.RootCaCriticalDays } }
            else { if ($p.IssuingCaWarningDays) { $warn = [int]$p.IssuingCaWarningDays }; if ($p.IssuingCaCriticalDays) { $crit = [int]$p.IssuingCaCriticalDays } }
        }
        if ($days -lt 0) { $expiryPill = New-MspkiGuiPill -Text ('Expired {0} days ago' -f (-$days)) -Tone Bad -Code 0xE711 }
        elseif ($days -le $crit) { $expiryPill = New-MspkiGuiPill -Text ('{0} days left' -f $days) -Tone Bad -Code 0xE823 }
        elseif ($days -le $warn) { $expiryPill = New-MspkiGuiPill -Text ('{0} days left' -f $days) -Tone Warn -Code 0xE823 }
        else { $expiryPill = New-MspkiGuiPill -Text ('{0} days left' -f $days) -Tone Good -Code 0xE73E }
        $expiry = 'Certificate expires {0}' -f $endText
    }
    # CRL state: the CRL findings for this CA; else the state the CA itself reported; else "not checked".
    $crlFindings = @($mine | Where-Object { $_.Category -eq 'CRL' })
    $crlPill = New-MspkiGuiPill -Text 'CRL not checked' -Tone Neutral -Code 0xE738
    if (-not $CA.Properties) { $crlPill = New-MspkiGuiPill -Text 'CRL not read: the CA gave no properties' -Tone Neutral -Code 0xE738 }
    if ($crlFindings.Count -gt 0) {
        $w = Get-MspkiGuiWorstStatus -Findings $crlFindings
        switch ($w) {
            'Pass' { $crlPill = New-MspkiGuiPill -Text 'CRL healthy' -Tone Good -Code 0xE73E }
            'Information' { $crlPill = New-MspkiGuiPill -Text 'CRL information only' -Tone Info -Code 0xE946 }
            'Warning' { $crlPill = New-MspkiGuiPill -Text 'CRL warning' -Tone Warn -Code 0xE7BA }
            'Error' { $crlPill = New-MspkiGuiPill -Text 'CRL check failed' -Tone Admin -Code 0xE783 }
            'Skipped' { $crlPill = New-MspkiGuiPill -Text 'CRL check skipped' -Tone Neutral -Code 0xE893 }
            'CouldNotCheck' { $crlPill = New-MspkiGuiPill -Text 'CRL could not be checked' -Tone Admin -Code 0xE72E }
            default { $crlPill = New-MspkiGuiPill -Text 'CRL failing' -Tone Bad -Code 0xE711 }
        }
    }
    elseif ($CA.Properties -and @($CA.Properties.SigningCertificates).Count -gt 0) {
        $st = @($CA.Properties.SigningCertificates | Where-Object { $_.CrlState } | Select-Object -Last 1)
        if ($st.Count -gt 0) { $crlPill = New-MspkiGuiPill -Text ('CRL state: {0}' -f $st[0].CrlState) -Tone Info -Code 0xE946 }
    }
    $worst = Get-MspkiGuiWorstStatus -Findings $mine
    $statusPill = Get-MspkiGuiStatusPill -Value $worst
    if (-not $worst) { $statusPill = New-MspkiGuiPill -Text 'No findings' -Tone Neutral -Code 0xE738 }
    $tplCount = @($CA.Templates | Where-Object { $_ }).Count
    $cesCount = @($CA.EnrollmentServers | Where-Object { $_ }).Count
    $hostName = [string]$CA.DnsHostName
    if (-not $hostName) { $hostName = $dash }
    return [pscustomobject][ordered]@{
        Name         = $name
        Host         = $hostName
        Config       = [string]$CA.Config
        Role         = $role
        Certificate  = $expiry
        ExpiryPill   = $expiryPill
        CrlPill      = $crlPill
        StatusPill   = $statusPill
        Status       = $worst
        Certificates = $certs.Count
        Templates    = $tplCount
        Findings     = $mine.Count
        Ces          = $cesCount
        Facts        = (@(
                (Format-MspkiGuiCount -Count $tplCount -Singular 'published template'),
                (Format-MspkiGuiCount -Count $certs.Count -Singular 'CA certificate'),
                (Format-MspkiGuiCount -Count $cesCount -Singular 'enrollment web service'),
                (Format-MspkiGuiCount -Count $mine.Count -Singular 'finding')) -join $script:MspkiGuiDot)
    }
}

$script:MspkiGuiMethodWords = [ordered]@{
    'AD:RootDSE' = 'Finding the forest and domain controller'; 'AD:PublicKeyServices' = 'Reading the Public Key Services containers'
    'AD:Forest' = 'Reading the forest'; 'AD:Partitions' = 'Reading the domain names'; 'AD:Sites' = 'Reading the sites'; 'AD:Trusts' = 'Reading the trusts'
    'AD:EnrollmentServices' = 'Reading the Enrollment Services objects'; 'AD:KRA' = 'Reading the key recovery agents'; 'AD:OID' = 'Reading the issuance policies'
    'AD:ComputerSite' = 'Finding this computer''s site'; 'CA:GetCAProperty' = 'Reading the CA''s properties'; 'CA:CertificateAuthority.View' = 'Reading the CA database view'
    'Local:EventLog' = 'Reading this computer''s event log'; 'Local:Win32_ComputerSystem' = 'Reading this computer''s domain membership'
}

function Get-MspkiGuiMethodText {
    <#
    .SYNOPSIS
    A discovery method in words ("CA:GetCAProperty" -> "Reading the CA's properties"); the method name itself when no words are known.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Method)
    foreach ($k in $script:MspkiGuiMethodWords.Keys) {
        if ($Method -eq $k -or $Method.StartsWith($k + ':') -or $Method.StartsWith($k + '.')) { return [string]$script:MspkiGuiMethodWords[$k] }
    }
    return $Method
}

function Get-MspkiGuiCoverage {
    <#
    .SYNOPSIS
    The discovery methods of a run with their outcome and the reason, problems first, plus a one-line count.
    #>
    [CmdletBinding()]
    param([AllowNull()]$RunInfo = $null, [AllowEmptyCollection()][object[]]$Findings = @())
    $methods = @()
    if ($null -ne $RunInfo -and $null -ne $RunInfo.Methods) { $methods = @($RunInfo.Methods | Where-Object { $null -ne $_ }) }
    $items = @(foreach ($m in $methods) {
        $o = [string]$m.Outcome
        $st = $script:MspkiGuiOutcomeStyle[$o]
        if ($null -eq $st) { $st = @($o, 'Neutral', 0xE897, $o, 1) }
        $detail = [string]$m.Detail
        $what = Get-MspkiGuiMethodText -Method ([string]$m.Method)
        $subject = ''; $code = ''
        $dm = [regex]::Match($detail, '^(?<s>.+?):\s*(?<c>0x[0-9A-Fa-f]{8})\s*$')
        if ($dm.Success) { $subject = $dm.Groups['s'].Value; $code = $dm.Groups['c'].Value }
        # D-20: the reason in words; the raw code stays at the end for people who search for it.
        $reason = $detail
        if ($code) {
            $name = ($subject -replace '^.*\\', '')
            switch ($o) {
                'PermissionDenied' { $reason = ('{0} for {1} was refused (access denied, {2}). The account running the check is not allowed to read it.' -f $what, $name, $code) }
                'Timeout' { $reason = ('{0} for {1} timed out ({2}).' -f $what, $name, $code) }
                default { $reason = ('{0} for {1} did not work ({2}).' -f $what, $name, $code) }
            }
        }
        if (-not $reason) { $reason = 'No further detail was recorded.' }
        # The finding that explains it (its walkthrough says why and what to do).
        $fid = ''
        if ($o -ne 'Success') {
            $src = [string]$m.Method
            foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
                if ((Get-MspkiGuiFindingStatusKey -Finding $f) -eq 'Pass') { continue }
                $fs = @($f.Sources | ForEach-Object { [string]$_ })
                if ($fs -notcontains $src) { continue }
                if ($subject -and ([string]$f.Endpoint) -ne $subject -and ([string]$f.Target) -ne ($subject -replace '^.*\\', '')) { continue }
                $fid = [string]$f.Id; break
            }
        }
        [pscustomobject][ordered]@{
            Method = [string]$m.Method
            MethodText = $what
            FindingTag = $fid
            HasFinding = [bool]$fid
            Outcome = $o
            Bucket = [string]$st[0]
            Pill = (New-MspkiGuiPill -Text ([string]$st[3]) -Tone $st[1] -Code $st[2])
            Reason = $reason
            Order = [int]$st[4]
            ElapsedMs = [string]$m.ElapsedMs
        }
    })
    $sorted = @($items | Sort-Object Order, Method)
    $counts = @{}
    foreach ($i in $items) { $counts[$i.Bucket] = 1 + [int]$counts[$i.Bucket] }
    $parts = @(foreach ($b in @('Succeeded', 'Could not check', 'Failed', 'Skipped', 'Not found')) { if ($counts.ContainsKey($b)) { '{0} {1}' -f $counts[$b], $b.ToLowerInvariant() } })
    $text = 'No discovery method details were recorded for this run.'
    if ($items.Count -gt 0) { $text = '{0} tried: {1}' -f (Format-MspkiGuiCount -Count $items.Count -Singular 'method'), ($parts -join ', ') }
    $problems = @($items | Where-Object { $_.Bucket -in @('Could not check', 'Failed') }).Count
    $attention = @($sorted | Where-Object { $_.Bucket -ne 'Succeeded' })
    $ok = @($sorted | Where-Object { $_.Bucket -eq 'Succeeded' })
    $okText = ''
    if ($ok.Count -gt 0) { $okText = 'Show the {0} that succeeded' -f (Format-MspkiGuiCount -Count $ok.Count -Singular 'method') }
    if ($items.Count -gt 0 -and $attention.Count -eq 0) { $text = '{0} tried: every one succeeded.' -f (Format-MspkiGuiCount -Count $items.Count -Singular 'method') }
    return [pscustomobject][ordered]@{
        Items = [object[]]$sorted; Attention = [object[]]$attention; Succeeded = [object[]]$ok; SucceededText = $okText
        Text = $text; Total = $items.Count; Problems = $problems
        SucceededCount = [int]$counts['Succeeded']; PermissionDenied = [int]$counts['Could not check']; Failed = [int]$counts['Failed']
        Skipped = [int]$counts['Skipped']; NotFound = [int]$counts['Not found']
    }
}

function Get-MspkiGuiHealth {
    <#
    .SYNOPSIS
    The overall health banner: red (action needed), amber (review) or green (healthy), with a sentence that says why.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowNull()]$RunInfo = $null,
        [int]$CoverageProblems = 0
    )
    $all = @($Findings | Where-Object { $null -ne $_ })
    $n = { param($s) @($all | Where-Object { $_.Status -eq $s }).Count }
    $crit = & $n 'Critical'; $fail = & $n 'Fail'; $err = & $n 'Error'; $warn = & $n 'Warning'; $pass = & $n 'Pass'
    $high = @($all | Where-Object { $_.Severity -eq 'High' }).Count
    $review = @($all | Where-Object { $_.Severity -in @('Medium', 'Low', 'ReviewRequired') -and $_.Status -notin @('Pass', 'Information', 'NotApplicable') }).Count
    $partial = ($null -ne $RunInfo -and $null -ne $RunInfo.Completed -and -not [bool]$RunInfo.Completed)
    $bits = New-Object 'System.Collections.Generic.List[string]'
    if ($crit -gt 0) { $bits.Add(('{0} critical' -f $crit)) }
    if ($fail -gt 0) { $bits.Add(('{0} failed' -f $fail)) }
    if ($err -gt 0) { $bits.Add($(if ($err -eq 1) { '1 check failed' } else { '{0} checks failed' -f $err })) }
    if ($warn -gt 0) { $bits.Add((Format-MspkiGuiCount -Count $warn -Singular 'warning')) }
    $extra = ''
    if ($CoverageProblems -gt 0) {
        $verb = 'could not read its source'
        if ($CoverageProblems -ne 1) { $verb = 'could not read their source' }
        $extra += (' {0} {1} (see Discovery coverage).' -f (Format-MspkiGuiCount -Count $CoverageProblems -Singular 'discovery method'), $verb)
    }
    if ($partial) { $extra += ' The run did not finish, so these results are partial.' }
    if ($crit + $fail + $high -gt 0) {
        return [pscustomobject][ordered]@{ Tone = 'Bad'; Glyph = [string][char]0xEA39; Title = 'Action needed'; Text = ('{0}.{1}' -f ($bits -join ', '), $extra).Trim(); Level = 'Red' }
    }
    if ($err + $warn + $review -gt 0 -or $CoverageProblems -gt 0 -or $partial) {
        $t = ($bits -join ', ')
        if (-not $t -and $review -gt 0) {
            $t = '{0} {1}' -f (Format-MspkiGuiCount -Count $review -Singular 'finding'), $(if ($review -eq 1) { 'needs a review' } else { 'need a review' })
        }
        $text = $extra.Trim()
        if ($t) { $text = ('{0}.{1}' -f $t, $extra).Trim() }
        return [pscustomobject][ordered]@{ Tone = 'Warn'; Glyph = [string][char]0xE7BA; Title = 'Needs review'; Text = $text; Level = 'Amber' }
    }
    $msg = 'No problems found.'
    if ($all.Count -eq 0) { $msg = 'No findings were recorded.' }
    elseif ($pass -gt 0) { $msg = 'No problems found. {0} passed.' -f (Format-MspkiGuiCount -Count $pass -Singular 'check') }
    return [pscustomobject][ordered]@{ Tone = 'Good'; Glyph = [string][char]0xE73E; Title = 'Healthy'; Text = $msg; Level = 'Green' }
}

function Get-MspkiGuiSummary {
    <#
    .SYNOPSIS
    The data for the Summary tab: facts, the health banner, KPI tiles, counts by status and severity, CA cards,
    the worst findings and the discovery coverage.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$RunInfo = $null,
        [AllowNull()]$Inventory = $null,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowNull()]$ExitCode = $null
    )
    $all = @($Findings | Where-Object { $null -ne $_ })
    $dash = [string][char]0x2014
    $ctx = $null
    if ($null -ne $Inventory) { $ctx = $Inventory.AdContext }
    $pick = {
        param([string]$Name)
        $v = ''
        if ($null -ne $RunInfo -and $RunInfo.$Name) { $v = [string]$RunInfo.$Name }
        if (-not $v -and $null -ne $ctx -and $ctx.$Name) { $v = [string]$ctx.$Name }
        return $v
    }
    $exitText = ''
    if ($null -ne $ExitCode -and '' -ne [string]$ExitCode) {
        $exitText = [string]$ExitCode
        if (Get-Command -Name 'Get-MspkiExitCodeInfo' -ErrorAction SilentlyContinue) {
            try { $exitText = '{0} - {1}' -f $ExitCode, (Get-MspkiExitCodeInfo -Code ([int]$ExitCode)).Name } catch { $exitText = [string]$ExitCode }
        }
    }
    $tiles = @(foreach ($s in $script:MspkiGuiStatusOrder) {
        $p = Get-MspkiGuiStatusPill -Value $s
        [pscustomobject][ordered]@{
            Status = $s; Count = @($all | Where-Object { (Get-MspkiGuiFindingStatusKey -Finding $_) -eq $s }).Count
            Label = $p.Text; Tone = $p.Tone; Glyph = $p.Glyph; Tag = $s
            AccessibleName = ('{0}: {1}' -f $p.Text, @($all | Where-Object { (Get-MspkiGuiFindingStatusKey -Finding $_) -eq $s }).Count)
        }
    })
    $sevTiles = @(foreach ($s in @('High', 'Medium', 'Low', 'ReviewRequired', 'Information')) {
        $p = Get-MspkiGuiStatusPill -Value $s -Kind Severity
        [pscustomobject][ordered]@{
            Status = $s; Count = @($all | Where-Object { $_.Severity -eq $s }).Count
            Label = $p.Text; Tone = $p.Tone; Glyph = $p.Glyph; Tag = $s
            AccessibleName = ('{0}: {1}' -f $p.Text, @($all | Where-Object { $_.Severity -eq $s }).Count)
        }
    })

    $cas = @()
    $caCount = 0
    if ($null -ne $Inventory) {
        $cas = @(foreach ($ca in @($Inventory.EnterpriseCAs | Where-Object { $_ })) { Get-MspkiGuiCaCard -CA $ca -Findings $all -Inventory $Inventory -RunInfo $RunInfo })
        $caCount = $cas.Count
    }

    # KPI tiles
    $certs = @()
    if ($null -ne $Inventory) { $certs = @($Inventory.CACertificates | Where-Object { $_ }) }
    $curCerts = @($certs | Where-Object { $_.Lifecycle -eq 'Current' })
    $histCerts = @($certs | Where-Object { $_.Lifecycle -eq 'Historical' })
    $days = @($curCerts | Where-Object { $null -ne $_.Info -and '' -ne [string]$_.Info.DaysLeft } | ForEach-Object { [double]$_.Info.DaysLeft })
    $certSub = '{0} current, {1} historical' -f $curCerts.Count, $histCerts.Count
    if ($days.Count -gt 0) {
        $min = [int][math]::Floor(($days | Measure-Object -Minimum).Minimum)
        if ($min -lt 0) { $certSub += ', one current certificate has expired' } else { $certSub += ', next expiry in {0} days' -f $min }
    }
    $leadCount = 0
    if ($null -ne $Inventory -and $null -ne $Inventory.Leads) { $leadCount = @($Inventory.Leads | Where-Object { $_ }).Count }
    $epProblems = @($all | Where-Object {
        $_.Category -in @('AIA', 'CDP', 'OCSP', 'CES', 'CEP', 'NDES', 'CRL') -and $_.Endpoint -and (Get-MspkiGuiRank -Kind Status -Value ([string]$_.Status)) -ge 4
    } | ForEach-Object { $_.Endpoint } | Select-Object -Unique).Count
    $published = @()
    $adTemplates = $null
    if ($null -ne $Inventory) {
        $published = @($Inventory.EnterpriseCAs | Where-Object { $_ } | ForEach-Object { @($_.Templates) } | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique)
        $tc = @($Inventory.Containers | Where-Object { $_ -and $_.Name -eq 'Certificate Templates' })
        if ($tc.Count -gt 0 -and $null -ne $tc[0].ChildCount) { $adTemplates = [int]$tc[0].ChildCount }
    }
    $tplSub = '{0} published on CAs' -f $published.Count
    if ($null -ne $adTemplates) { $tplSub += ', {0} in Active Directory' -f $adTemplates }
    $epSub = 'none with problems'
    if ($epProblems -gt 0) { $epSub = '{0} with problems' -f $epProblems }
    $kpis = @(
        [pscustomobject][ordered]@{ Label = 'Certification authorities'; Value = $caCount; Sub = 'Enterprise CAs found in Active Directory'; Glyph = [string][char]0xE83D; Tag = 'type:CA' }
        [pscustomobject][ordered]@{ Label = 'CA certificates'; Value = $certs.Count; Sub = $certSub; Glyph = [string][char]0xEB95; Tag = 'type:CACertificate' }
        [pscustomobject][ordered]@{ Label = 'Published addresses'; Value = $leadCount; Sub = ('AIA, CDP, OCSP and enrollment addresses; {0}' -f $epSub); Glyph = [string][char]0xE71B; Tag = 'type:Endpoint' }
        [pscustomobject][ordered]@{ Label = 'Certificate templates'; Value = $published.Count; Sub = $tplSub; Glyph = [string][char]0xE8A5; Tag = 'type:Template' }
    )

    $coverage = Get-MspkiGuiCoverage -RunInfo $RunInfo -Findings $all
    $health = Get-MspkiGuiHealth -Findings $all -RunInfo $RunInfo -CoverageProblems $coverage.Problems

    $top = @($all | Where-Object { (Get-MspkiGuiRank -Kind Status -Value ([string]$_.Status)) -ge 4 } |
        Sort-Object @{ Expression = { -1 * (Get-MspkiGuiRank -Kind Status -Value ([string]$_.Status)) } }, @{ Expression = { -1 * (Get-MspkiGuiRank -Kind Severity -Value ([string]$_.Severity)) } }, Id |
        Select-Object -First 10 | ForEach-Object {
            $msg = ([string]$_.Message) -replace '\s*[\r\n]+\s*', ' '
            if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 197) + '...' }
            $title = Get-MspkiGuiFindingTitle -Finding $_
            [pscustomobject][ordered]@{
                Id = [string]$_.Id; StatusPill = (Get-MspkiGuiStatusPill -Value (Get-MspkiGuiFindingStatusKey -Finding $_)); Title = $title; Message = $msg
                Meta = (@([string]$_.Id, ('Severity {0}' -f $_.Severity), ('Confidence {0}' -f $_.Confidence)) -join $script:MspkiGuiDot)
            }
        })

    $isAdmin = ''
    $adminPill = New-MspkiGuiPill -Text 'Run not read' -Tone Neutral
    if ($null -ne $RunInfo -and $null -ne $RunInfo.IsAdmin) {
        if ([bool]$RunInfo.IsAdmin) { $isAdmin = 'Yes (elevated)'; $adminPill = New-MspkiGuiPill -Text 'Administrator' -Tone Admin -Code 0xE7EF }
        else { $isAdmin = 'No (standard user)'; $adminPill = New-MspkiGuiPill -Text 'Standard user' -Tone Neutral -Code 0xE77B }
    }
    $runState = ''
    if ($null -ne $RunInfo -and $null -ne $RunInfo.Completed) {
        if ([bool]$RunInfo.Completed) { $runState = 'Finished' } else { $runState = 'Did not finish (partial results)' }
    }
    $user = ''; $computer = ''; $started = ''
    if ($null -ne $RunInfo) { $user = [string]$RunInfo.UserContext; $computer = [string]$RunInfo.ComputerName; $started = [string]$RunInfo.StartedUtc }
    $durationText = ''
    $sd = ConvertTo-MspkiGuiDateTime -Value $started
    $fd = $null
    if ($null -ne $RunInfo) { $fd = ConvertTo-MspkiGuiDateTime -Value $RunInfo.FinishedUtc }
    if ($null -ne $sd -and $null -ne $fd) { $durationText = Get-MspkiGuiDurationText -Seconds ($fd - $sd).TotalSeconds }
    $limits = @()
    if ($null -ne $RunInfo -and $null -ne $RunInfo.Limits) { $limits = [string[]]@($RunInfo.Limits | Where-Object { $_ }) }
    return [pscustomobject][ordered]@{
        Forest           = (& $pick 'Forest')
        Domain           = (& $pick 'Domain')
        DomainController = (& $pick 'DomainController')
        Site             = (& $pick 'Site')
        User             = $user
        Computer         = $computer
        IsAdmin          = $isAdmin
        AdminPill        = $adminPill
        ExitCode         = $exitText
        RunState         = $runState
        Started          = $started
        Duration         = $durationText
        Total            = $all.Count
        Health           = $health
        Kpis             = $kpis
        Tiles            = $tiles
        SeverityTiles    = $sevTiles
        CAs              = $cas
        TopIssues        = [object[]]$top
        Coverage         = $coverage
        Limits           = $limits
    }
}

function Get-MspkiGuiContext {
    <#
    .SYNOPSIS
    The header strip: forest, domain, domain controller, user and an Administrator / Standard user badge.
    From a run when there is one; before the first run, from this Windows session only (no network access).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Summary = $null)
    $dash = [string][char]0x2014
    $forest = ''; $domain = ''; $dc = ''; $user = ''; $badge = $null
    if ($null -ne $Summary) {
        $forest = $Summary.Forest; $domain = $Summary.Domain; $dc = $Summary.DomainController; $user = $Summary.User; $badge = $Summary.AdminPill
    }
    else {
        try {
            $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $user = $id.Name
            $p = New-Object System.Security.Principal.WindowsPrincipal($id)
            if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { $badge = New-MspkiGuiPill -Text 'Administrator' -Tone Admin -Code 0xE7EF }
            else { $badge = New-MspkiGuiPill -Text 'Standard user' -Tone Neutral -Code 0xE77B }
        }
        catch { $badge = New-MspkiGuiPill -Text 'User unknown' -Tone Neutral }
        $dom = [string][System.Environment]::GetEnvironmentVariable('USERDNSDOMAIN')
        if ($dom) { $domain = $dom.ToLowerInvariant() }
    }
    # Before the first run the forest and domain controller are not known yet: say so instead of showing a dash.
    if ($null -eq $Summary) { $dash = 'Known after a run' }
    $items = @(
        [pscustomobject][ordered]@{ Label = 'Forest'; Value = $(if ($forest) { $forest } else { $dash }) }
        [pscustomobject][ordered]@{ Label = 'Domain'; Value = $(if ($domain) { $domain } else { $dash }) }
        [pscustomobject][ordered]@{ Label = 'Domain controller'; Value = $(if ($dc) { $dc } else { $dash }) }
        [pscustomobject][ordered]@{ Label = 'Run as'; Value = $(if ($user) { $user } else { $dash }) }
    )
    if ($null -eq $badge) { $badge = New-MspkiGuiPill -Text 'Standard user' -Tone Neutral -Code 0xE77B }
    return [pscustomobject][ordered]@{ Items = $items; Badge = $badge }
}
