# Run metadata: who ran the tool, where, with which parameters, how long each stage took and which
# discovery methods were tried with what outcome. Exported in results.json as RunInfo.

$script:MspkiRun = $null

function Initialize-MspkiRun {
    <#
    .SYNOPSIS
    Starts a new run: resets the finding counter, the probe cache and the log, and records run metadata.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Parameters = @{}
    )
    Reset-MspkiFindingSequence
    Reset-MspkiProbeCache
    Reset-MspkiLog
    Reset-MspkiLeadRegistry

    $isAdmin = $false
    $user = ''
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $user = $id.Name
        $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { $user = [Environment]::UserName }

    $params = [ordered]@{}
    foreach ($k in ($Parameters.Keys | Sort-Object)) { $params[$k] = [string]$Parameters[$k] }
    $net = Get-MspkiDotNetRelease
    $webOpt = Get-MspkiWebProbeOption

    $script:MspkiRun = [ordered]@{
        RunId          = [guid]::NewGuid().ToString()
        Tool           = $script:MspkiToolName
        ToolVersion    = $script:MspkiToolVersion
        StartedUtc     = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        FinishedUtc    = ''
        Completed      = $false
        ComputerName   = [Environment]::MachineName
        UserContext    = $user
        IsAdmin        = [bool]$isAdmin
        PSVersion      = $PSVersionTable.PSVersion.ToString()
        PSEdition      = [string]$PSVersionTable.PSEdition
        ClrVersion     = [Environment]::Version.ToString()
        DotNetRelease  = $net.Release
        DotNetVersion  = $net.Version
        SignatureApisAvailable = [bool](Test-MspkiSignatureApiAvailable)
        TlsSecurityProtocol = [string][System.Net.ServicePointManager]::SecurityProtocol
        HttpProxy      = $webOpt.ProxyMode
        OSVersion      = [Environment]::OSVersion.Version.ToString()
        Parameters     = $params
        Forest         = ''
        Domain         = ''
        DomainController = ''
        Site           = ''
        StageTimings   = New-Object System.Collections.ArrayList
        Methods        = New-Object System.Collections.ArrayList
        Limits         = New-Object System.Collections.ArrayList
    }
    return $script:MspkiRun
}

function Get-MspkiRunValue {
    <#
    .SYNOPSIS
    Reads one value of the current run metadata ('' when no run is active).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $script:MspkiRun) { return '' }
    if (-not $script:MspkiRun.Contains($Name)) { return '' }
    return $script:MspkiRun[$Name]
}

function Set-MspkiRunValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][AllowEmptyString()]$Value
    )
    if ($null -eq $script:MspkiRun) { return }
    $script:MspkiRun[$Name] = $Value
}

function Start-MspkiStageTimer {
    <#
    .SYNOPSIS
    Logs that a stage started (so a hang shows which stage it was in) and returns a running stopwatch for Add-MspkiStageTiming.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Stage)
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'StageStart' -Text $Stage
    Write-MspkiLog -Message ('Stage {0} started' -f $Stage)
    return [System.Diagnostics.Stopwatch]::StartNew()
}

function Get-MspkiDotNetRelease {
    <#
    .SYNOPSIS
    The .NET Framework 4.x release number from the registry (read only; 0 when it cannot be read) and its version name.
    #>
    [CmdletBinding()]
    param()
    $rel = 0
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full')
        if ($null -ne $k) {
            try { $v = $k.GetValue('Release'); if ($null -ne $v) { $rel = [int]$v } } finally { $k.Close() }
        }
    }
    catch { $rel = 0 }
    $name = 'unknown'
    $table = @(@(533320, '4.8.1 or later'), @(528040, '4.8'), @(461808, '4.7.2'), @(461308, '4.7.1'), @(460798, '4.7'), @(394802, '4.6.2'), @(394254, '4.6.1'), @(393295, '4.6'), @(379893, '4.5.2'), @(378675, '4.5.1'), @(378389, '4.5'))
    foreach ($e in $table) { if ($rel -ge $e[0]) { $name = $e[1]; break } }
    return [pscustomobject]@{ Release = $rel; Version = $name }
}

function Add-MspkiStageTiming {
    <#
    .SYNOPSIS
    Records how long a stage took.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][System.Diagnostics.Stopwatch]$Stopwatch
    )
    Send-MspkiProgress -Kind 'StageEnd' -Text $Stage
    if ($null -eq $script:MspkiRun) { return }
    [void]$script:MspkiRun.StageTimings.Add([pscustomobject][ordered]@{
        Stage     = $Stage
        ElapsedMs = [int64]$Stopwatch.ElapsedMilliseconds
    })
    Write-MspkiLog -Message ('Stage {0} took {1} ms' -f $Stage, $Stopwatch.ElapsedMilliseconds)
}

function Add-MspkiMethodOutcome {
    <#
    .SYNOPSIS
    Records a discovery method that was tried and its outcome (Success, PermissionDenied, NotFound,
    Unreachable, Timeout, Unsupported, NotDomainJoined, Skipped, Error).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Outcome,
        [string]$Detail = '',
        [int64]$ElapsedMs = 0
    )
    Write-MspkiLog -Message ('Method {0}: {1} {2}' -f $Method, $Outcome, $Detail).Trim()
    if ($null -eq $script:MspkiRun) { return }
    [void]$script:MspkiRun.Methods.Add([pscustomobject][ordered]@{
        Method    = $Method
        Outcome   = $Outcome
        Detail    = $Detail
        ElapsedMs = $ElapsedMs
    })
}

function Add-MspkiRunLimit {
    <#
    .SYNOPSIS
    Records a known limit of this run (shown in the report's Run details).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Text)
    if ($null -eq $script:MspkiRun) { return }
    if (-not $script:MspkiRun.Limits.Contains($Text)) { [void]$script:MspkiRun.Limits.Add($Text) }
}

function Complete-MspkiRun {
    [CmdletBinding()]
    param([bool]$Completed = $true)
    if ($null -eq $script:MspkiRun) { return }
    $script:MspkiRun.FinishedUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $script:MspkiRun.Completed = $Completed
    # One closing line for whoever reads the log: did the run finish, and where did the time go.
    $slow = @($script:MspkiRun.StageTimings | Where-Object { $_.Stage -ne 'Discovery' } | Sort-Object ElapsedMs -Descending | Select-Object -First 3)
    Write-MspkiLog -Message ('Run finished: completed {0}; {1} stage(s) timed; slowest: {2}' -f $Completed, @($script:MspkiRun.StageTimings).Count, (($slow | ForEach-Object { '{0} {1} ms' -f $_.Stage, $_.ElapsedMs }) -join ', '))
}
