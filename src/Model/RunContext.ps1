# Run metadata: who ran the tool, where, with which parameters, how long each stage took and which
# discovery methods were tried with what outcome. Exported in results.json as RunInfo.

$script:MspkiRun = $null

function Get-MspkiRunHostInfo {
    <#
    .SYNOPSIS
    Who runs the tool and where (read-only): computer name, the Windows identity and whether it is an administrator, and the PowerShell,
    .NET CLR and Windows versions.
    #>
    [CmdletBinding()]
    param()
    $isAdmin = $false
    $user = ''
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $user = $id.Name
        $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch { $user = [Environment]::UserName }
    return [pscustomobject]@{ ComputerName = [Environment]::MachineName; UserContext = $user; IsAdmin = [bool]$isAdmin
        PSVersion = $PSVersionTable.PSVersion.ToString(); PSEdition = [string]$PSVersionTable.PSEdition
        ClrVersion = [Environment]::Version.ToString(); OSVersion = [Environment]::OSVersion.Version.ToString() }
}

function New-MspkiRunId {
    # A new run id (a random GUID).
    [CmdletBinding()]
    param()
    return [guid]::NewGuid().ToString()
}

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
    Reset-MspkiEntityGraph
    Reset-MspkiLog
    Reset-MspkiLeadRegistry

    $hostInfo = Get-MspkiRunHostInfo


    $params = [ordered]@{}
    foreach ($k in ($Parameters.Keys | Sort-Object)) { $params[$k] = [string]$Parameters[$k] }
    $net = Get-MspkiDotNetRelease
    $webOpt = Get-MspkiWebProbeOption

    $script:MspkiRun = [ordered]@{
        RunId          = (New-MspkiRunId)
        Tool           = $script:MspkiToolName
        ToolVersion    = $script:MspkiToolVersion
        StartedUtc     = (Get-MspkiUtcNow).ToString('yyyy-MM-ddTHH:mm:ssZ')
        FinishedUtc    = ''
        Completed      = $false
        ComputerName   = $hostInfo.ComputerName
        UserContext    = $hostInfo.UserContext
        IsAdmin        = [bool]$hostInfo.IsAdmin
        PSVersion      = $hostInfo.PSVersion
        PSEdition      = $hostInfo.PSEdition
        ClrVersion     = $hostInfo.ClrVersion
        DotNetRelease  = $net.Release
        DotNetVersion  = $net.Version
        SignatureApisAvailable = [bool](Test-MspkiSignatureApiAvailable)
        TlsSecurityProtocol = [string][System.Net.ServicePointManager]::SecurityProtocol
        HttpProxy      = $webOpt.ProxyMode
        OSVersion      = $hostInfo.OSVersion
        Parameters     = $params
        Forest         = ''
        Domain         = ''
        DomainController = ''
        Site           = ''
        StageTimings   = New-Object System.Collections.ArrayList
        Methods        = New-Object System.Collections.ArrayList
        Limits         = New-Object System.Collections.ArrayList
    }
    # Audit 2 L2: some directory calls have no timeout parameter (forest and domain controller locator, trusts, the directory bind, SID translation).
    # They run on the calling thread, so a domain controller that stops answering mid-call can delay the run, and Cancel acts only between calls.
    Add-MspkiRunLimit -Text 'Some Active Directory calls have no timeout of their own (forest and domain controller discovery, trusts, the directory bind, SID translation). A domain controller that stops answering in the middle of one of them can delay the run, and Cancel takes effect only between calls.'
    if (-not [bool]$Parameters['SkipNetwork']) {
        # CryptoAPI builds the certificate chain of a TLS server certificate itself and may fetch missing intermediate certificates from its AIA
        # (audit 2 L1). Those fetches are not bounded, cached or logged by this tool; with -SkipNetwork no TLS handshake is made.
        # Audit 3 N13: the host can be any host, an ldap:// one too; measured: anonymous searches and GETs only, never a bind (docs/RESEARCH.md).
        Add-MspkiRunLimit -Text 'While Windows validates a TLS server certificate (chain building) it may itself contact the hosts named in that certificate''s AIA (an ldap:// or http:// URL) to fetch a missing intermediate certificate. That host is chosen by the server''s certificate, not by this tool, and can be any host: inside this forest or not, an ldap:// host too. Measured on Windows 11 with .NET Framework 4.8: only anonymous searches and GET requests, never a directory bind, so no Windows credentials are sent. These contacts are not bounded, cached or logged by this tool.'
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
    return (New-MspkiStopwatch)
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
        [Parameter(Mandatory = $true)]$Stopwatch
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
    [void](Remove-MspkiAbandonedProbe)
    $script:MspkiRun.FinishedUtc = (Get-MspkiUtcNow).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $script:MspkiRun.Completed = $Completed
    # One closing line for whoever reads the log: did the run finish, and where did the time go.
    $slow = @($script:MspkiRun.StageTimings | Where-Object { $_.Stage -ne 'Discovery' } | Sort-Object ElapsedMs -Descending | Select-Object -First 3)
    Write-MspkiLog -Message ('Run finished: completed {0}; {1} stage(s) timed; slowest: {2}' -f $Completed, @($script:MspkiRun.StageTimings).Count, (($slow | ForEach-Object { '{0} {1} ms' -f $_.Stage, $_.ElapsedMs }) -join ', '))
}
