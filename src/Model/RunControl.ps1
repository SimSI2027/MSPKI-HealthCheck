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
    Adds one progress message (StageStart, StageEnd, Target or Log) to the caller's queue, if there is one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('StageStart', 'StageEnd', 'Target', 'Log')][string]$Kind,
        [AllowEmptyString()][string]$Text = '',
        [string]$Level = 'Info'
    )
    $c = $script:MspkiControl
    if ($null -eq $c) { return }
    $c['Queue'].Enqueue([pscustomobject]@{ Kind = $Kind; Text = $Text; Level = $Level; Time = [DateTime]::Now })
}
