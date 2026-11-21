# DNS and TCP probes: time-limited and cached. Only called for hosts that came from an
# authoritative source (hard rule 4).

function New-MspkiProbeResult {
    [CmdletBinding()]
    param([string]$Probe, [string]$Target)
    return [pscustomobject][ordered]@{
        Probe      = $Probe
        Target     = $Target
        Status     = 'NotTested'
        StatusCode = 'NOT_APPLICABLE'
        Addresses  = @()
        CanonicalName = ''
        Error      = ''
        ElapsedMs  = 0
        FromCache  = $false
    }
}

function Wait-MspkiAsyncResult {
    <#
    .SYNOPSIS
    Waits for an asynchronous call for at most TimeoutMs and returns whether it finished. Waits in short slices and throws an
    OperationCanceledException when the caller cancelled the run, so a cancel does not have to wait for a probe timeout.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$AsyncResult,
        [Parameter(Mandatory = $true)][int]$TimeoutMs
    )
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ($true) {
        $left = ($deadline - [DateTime]::UtcNow).TotalMilliseconds
        if ($left -le 0) { return [bool]$AsyncResult.IsCompleted }
        if ($AsyncResult.AsyncWaitHandle.WaitOne([int][math]::Min(200, $left))) { return $true }
        Assert-MspkiNotCancelled
    }
}

function Resolve-MspkiDnsName {
    <#
    .SYNOPSIS
    Resolves a host name with a timeout. Status Pass/Fail/Timeout, StatusCode OK/DNS_FAIL/TIMEOUT.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000
    )
    $h = ConvertTo-MspkiHostName $HostName
    $key = 'dns|' + $h
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }

    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text ('DNS {0}' -f $h)
    $r = New-MspkiProbeResult -Probe 'DNS' -Target $h
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ar = [System.Net.Dns]::BeginGetHostAddresses($h, $null, $null)
        if (Wait-MspkiAsyncResult -AsyncResult $ar -TimeoutMs $TimeoutMs) {
            $addrs = [System.Net.Dns]::EndGetHostAddresses($ar)
            $r.Addresses = @($addrs | ForEach-Object { $_.IPAddressToString })
            if ($r.Addresses.Count -gt 0) { $r.Status = 'Pass'; $r.StatusCode = 'OK' }
            else { $r.Status = 'Fail'; $r.StatusCode = 'DNS_FAIL'; $r.Error = 'No addresses returned.' }
        }
        else {
            $r.Status = 'Timeout'; $r.StatusCode = 'TIMEOUT'; $r.Error = ('No DNS answer within {0} ms.' -f $TimeoutMs)
        }
    }
    catch {
        if ($_.Exception -is [System.OperationCanceledException]) { throw }
        $r.Status = 'Fail'; $r.StatusCode = 'DNS_FAIL'; $r.Error = (Get-MspkiErrorInfo $_).Message
    }
    $r.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('DNS {0}: {1} {2} ms {3}' -f $h, $r.Status, $r.ElapsedMs, $r.Error).Trim()
    return $r
}

function Resolve-MspkiDnsEntry {
    <#
    .SYNOPSIS
    Resolves a host name to its canonical name and addresses (Dns.GetHostEntry) with a timeout, cached for the run.
    Used only to prove that a short host name and an FQDN are the same host.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000
    )
    $h = ConvertTo-MspkiHostName $HostName
    $key = 'dnsentry|' + $h
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }

    $r = New-MspkiProbeResult -Probe 'DNS' -Target $h
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ar = [System.Net.Dns]::BeginGetHostEntry($h, $null, $null)
        if (Wait-MspkiAsyncResult -AsyncResult $ar -TimeoutMs $TimeoutMs) {
            $entry = [System.Net.Dns]::EndGetHostEntry($ar)
            $r.Addresses = @($entry.AddressList | ForEach-Object { $_.IPAddressToString })
            $r.CanonicalName = ConvertTo-MspkiHostName $entry.HostName
            if ($r.Addresses.Count -gt 0) { $r.Status = 'Pass'; $r.StatusCode = 'OK' }
            else { $r.Status = 'Fail'; $r.StatusCode = 'DNS_FAIL'; $r.Error = 'No addresses returned.' }
        }
        else {
            $r.Status = 'Timeout'; $r.StatusCode = 'TIMEOUT'; $r.Error = ('No DNS answer within {0} ms.' -f $TimeoutMs)
        }
    }
    catch {
        if ($_.Exception -is [System.OperationCanceledException]) { throw }
        $r.Status = 'Fail'; $r.StatusCode = 'DNS_FAIL'; $r.Error = (Get-MspkiErrorInfo $_).Message
    }
    $r.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('DNS entry {0}: {1} canonical {2} {3} ms {4}' -f $h, $r.Status, $r.CanonicalName, $r.ElapsedMs, $r.Error).Trim()
    return $r
}

function Test-MspkiTcpPort {
    <#
    .SYNOPSIS
    Opens one TCP connection with a timeout and closes it. Status Pass/Fail/Timeout,
    StatusCode OK/TCP_FAIL/TIMEOUT. Nothing is sent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][ValidateRange(1, 65535)][int]$Port,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000
    )
    $h = ConvertTo-MspkiHostName $HostName
    $key = 'tcp|{0}|{1}' -f $h, $Port
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }

    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text ('TCP {0}:{1}' -f $h, $Port)
    $r = New-MspkiProbeResult -Probe 'TCP' -Target ('{0}:{1}' -f $h, $Port)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $client.BeginConnect($h, $Port, $null, $null)
        if (Wait-MspkiAsyncResult -AsyncResult $ar -TimeoutMs $TimeoutMs) {
            try { $client.EndConnect($ar); $r.Status = 'Pass'; $r.StatusCode = 'OK' }
            catch { $r.Status = 'Fail'; $r.StatusCode = 'TCP_FAIL'; $r.Error = (Get-MspkiErrorInfo $_).Message }
        }
        else {
            $r.Status = 'Timeout'; $r.StatusCode = 'TIMEOUT'; $r.Error = ('No TCP connection within {0} ms.' -f $TimeoutMs)
        }
    }
    catch {
        if ($_.Exception -is [System.OperationCanceledException]) { throw }
        $r.Status = 'Fail'; $r.StatusCode = 'TCP_FAIL'; $r.Error = (Get-MspkiErrorInfo $_).Message
    }
    finally { $client.Close() }
    $r.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('TCP {0}:{1}: {2} {3} ms {4}' -f $h, $Port, $r.Status, $r.ElapsedMs, $r.Error).Trim()
    return $r
}

function Invoke-MspkiTimeLimitedScript {
    <#
    .SYNOPSIS
    Runs a self-contained script block in a separate runspace and waits at most TimeoutSeconds.
    Used for calls that have no timeout of their own (for example CA COM calls over DCOM).

    .OUTPUTS
    Object with Completed, TimedOut, Output (array), Errors (array of strings), ElapsedMs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @(),
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 30
    )
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text 'Calling a CA (COM)'
    $res = [pscustomobject][ordered]@{
        Completed = $false; TimedOut = $false; Output = @(); Errors = @(); ElapsedMs = 0
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.ApartmentState = [System.Threading.ApartmentState]::STA
    $rs.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $rs.Open()
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript($ScriptBlock.ToString(), $true)
    foreach ($a in $ArgumentList) { [void]$ps.AddArgument($a) }
    $handle = $ps.BeginInvoke()
    # Wait in short slices so that a cancel request is honoured within a fraction of a second.
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $done = $false
    $cancelled = $false
    while (-not $done -and [DateTime]::UtcNow -lt $deadline) {
        if (Test-MspkiCancelled) { $cancelled = $true; break }
        $done = $handle.AsyncWaitHandle.WaitOne(250)
    }
    if ($cancelled) {
        try { [void]$ps.BeginStop($null, $null) } catch { }
        throw (New-Object System.OperationCanceledException('The run was cancelled.'))
    }
    if ($done) {
        try {
            $res.Output = @($ps.EndInvoke($handle) | ForEach-Object { if ($null -ne $_) { $_.psobject.BaseObject } })
            $res.Completed = $true
        }
        catch { $res.Errors = @((Get-MspkiErrorInfo $_).Message) }
        $res.Errors = @($res.Errors) + @($ps.Streams.Error | ForEach-Object { $_.ToString() })
        $ps.Dispose()
        $rs.Dispose()
    }
    else {
        # The call is still blocked (for example in DCOM). Ask it to stop and leave it behind; do not
        # wait for it, so the run continues.
        $res.TimedOut = $true
        try { [void]$ps.BeginStop($null, $null) } catch { }
    }
    $res.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    return $res
}
