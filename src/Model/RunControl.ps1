# Run control: an optional cancel flag and progress queue shared with a caller that runs the engine in another runspace
# (the GUI). Without a control object every function here does nothing, so the command-line run is unchanged.
# Messages are plain data (kind, text, level, time); the queue is thread-safe.

$script:MspkiControl = $null

function New-MspkiRunControl {
    <#
    .SYNOPSIS
    Creates the object a caller passes to Start-MspkiHealthCheck -Control: a cancel flag and a thread-safe progress queue.

    .DESCRIPTION
    Set $control.Cancel = $true to ask the run to stop at the next stage or probe. The engine adds messages to
    $control.Queue (a ConcurrentQueue): Kind StageStart / StageEnd / Target / Log with Text, Level and Time.
    #>
    [CmdletBinding()]
    param()
    $c = [hashtable]::Synchronized(@{})
    $c['Cancel'] = $false
    $c['Queue'] = New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'
    return $c
}

function Set-MspkiRunControl {
    [CmdletBinding()]
    param([AllowNull()]$Control = $null)
    $script:MspkiControl = $Control
}

function Test-MspkiCancelled {
    <#
    .SYNOPSIS
    True when the caller asked the run to stop.
    #>
    [CmdletBinding()]
    param()
    $c = $script:MspkiControl
    if ($null -eq $c) { return $false }
    return [bool]$c['Cancel']
}

function Assert-MspkiNotCancelled {
    <#
    .SYNOPSIS
    Throws an OperationCanceledException when the caller asked the run to stop. Called before each stage and each probe.
    #>
    [CmdletBinding()]
    param()
    if (Test-MspkiCancelled) { throw (New-Object System.OperationCanceledException('The run was cancelled.')) }
}

function Send-MspkiProgress {
    <#
    .SYNOPSIS
    Adds one progress message (StageStart, StageEnd, Target, Log, or the graph events Entity, Relation and Probe) to the caller's
    queue, if there is one. -Data adds fields to the item (the graph events use it).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('StageStart', 'StageEnd', 'Target', 'Log', 'Entity', 'Relation', 'Probe')][string]$Kind,
        [AllowEmptyString()][string]$Text = '',
        [string]$Level = 'Info',
        [hashtable]$Data = $null
    )
    $c = $script:MspkiControl
    if ($null -eq $c) { return }
    $item = [ordered]@{ Kind = $Kind; Text = $Text; Level = $Level; Time = [DateTime]::Now }
    if ($null -ne $Data) { foreach ($k in $Data.Keys) { $item[$k] = $Data[$k] } }
    $c['Queue'].Enqueue([pscustomobject]$item)
}

function Test-MspkiRunControlActive {
    <#
    .SYNOPSIS
    True when a caller passed a run control (the window). The graph and probe events cost nothing without one.
    #>
    [CmdletBinding()]
    param()
    return ($null -ne $script:MspkiControl)
}

function Send-MspkiGraphEvent {
    <#
    .SYNOPSIS
    Queues one live-map event for the window (GX1). Entity: a new entity (Id, Type, Name, Parents). Relation: a new relation
    (From, Type, To). Nothing happens without a run control, and the event never changes the run's results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Entity', 'Relation')][string]$Kind,
        [Parameter(Mandatory = $true)][hashtable]$Data
    )
    if ($null -eq $script:MspkiControl) { return }
    Send-MspkiProgress -Kind $Kind -Text ([string]$(if ($Kind -eq 'Entity') { $Data['Name'] } else { '{0} {1} {2}' -f $Data['From'], $Data['Type'], $Data['To'] })) -Data $Data
}

function Send-MspkiProbeEvent {
    <#
    .SYNOPSIS
    Queues a Probe start or end item (GX1) keyed by the entity the probe is about: the endpoint id of a URL (HTTP, LDAP) or the host
    id (DNS, TCP, TLS). The End item carries the outcome code. Nothing happens without a run control.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Start', 'End')][string]$Phase,
        [Parameter(Mandatory = $true)][ValidateSet('DNS', 'TCP', 'TLS', 'HTTP', 'LDAP')][string]$Probe,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Subject,
        [string]$Outcome = ''
    )
    if ($null -eq $script:MspkiControl) { return }
    $id = ''
    try {
        if ($Probe -in @('HTTP', 'LDAP')) { $id = Get-MspkiEndpointEntityId -Url $Subject }
        else { $id = Get-MspkiEntityId -Type 'Host' -Key (ConvertTo-MspkiHostName $Subject) }
    }
    catch { return }
    Send-MspkiProgress -Kind 'Probe' -Text ('{0} {1} {2}' -f $Probe, $Phase, $Subject) -Data @{ Phase = $Phase; Probe = $Probe; Id = $id; Outcome = $Outcome }
}

function Send-MspkiLeadEntityEvent {
    <#
    .SYNOPSIS
    Announces to the window the endpoints (and their hosts) that the lead registry already holds, before the final graph pass creates them
    (GX1: the live map should not wait for the end of the run). Announce only: the graph is not touched, and the final pass does not
    announce an entity twice. Nothing happens without a run control.
    #>
    [CmdletBinding()]
    param()
    if ($null -eq $script:MspkiControl) { return }
    $g = Get-MspkiEntityGraphState
    foreach ($l in @(Get-MspkiLead)) {
        if (-not $l -or -not $l.Url) { continue }
        try {
            $n = ConvertTo-MspkiNormalizedUrl -Url ([string]$l.Url)
            $id = Get-MspkiEndpointEntityId -Url ([string]$l.Url)
            if ($g.Entities.Contains($id) -or $g.Announced.ContainsKey($id)) { continue }
            $parents = @()
            if ($n.Host) {
                $h = ([string]$n.Host).Trim().TrimEnd('.')
                $hid = Get-MspkiEntityId -Type 'Host' -Key $h
                $parents = @($hid)
                if (-not $g.Entities.Contains($hid) -and -not $g.Announced.ContainsKey($hid)) {
                    $g.Announced[$hid] = $true
                    Send-MspkiGraphEvent -Kind 'Entity' -Data @{ Id = $hid; Type = 'Host'; Name = $h.ToLowerInvariant(); Parents = @() }
                }
            }
            $g.Announced[$id] = $true
            Send-MspkiGraphEvent -Kind 'Entity' -Data @{ Id = $id; Type = 'Endpoint'; Name = [string]$(if ($n.Url) { $n.Url } else { $l.Url }); Parents = $parents }
        }
        catch { continue }
    }
}
