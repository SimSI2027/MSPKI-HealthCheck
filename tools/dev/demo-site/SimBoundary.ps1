# DEVELOPER-ONLY (tools\dev, never shipped, never referenced by the product). Dot-sourced INTO the MspkiHealthCheck module scope by
# Enable-MspkiSimulation (MspkiSimulation.ps1): each function below replaces one I/O boundary function of the engine with one that
# answers from the simulated world ($script:MspkiSim). Nothing here opens a socket, binds to a directory, creates a COM object or reads a
# store, the registry or an event log. A question the world has no answer for THROWS: it never falls back to a real call.
# The list of replaced functions is tools\dev\demo-site\Boundary.psd1; tests\DemoGenerator.Tests.ps1 checks it against the engine.

function Assert-MspkiSimKnown {
    param([bool]$Known, [string]$What)
    if (-not $Known) { throw ('SIMULATION: the simulated world has no answer for {0}. Add it to the scenario fixture.' -f $What) }
}

function Step-MspkiSimClock {
    param([double]$Ms)
    $script:MspkiSim.Clock = $script:MspkiSim.Clock.AddMilliseconds($Ms)
}

function Get-MspkiSimLatency {
    param([string]$Kind)
    $l = $script:MspkiSim.Latency
    if ($null -ne $l -and $l.ContainsKey($Kind)) { return [double]$l[$Kind] }
    return 10.0
}

# --- clock -----------------------------------------------------------------------------------------------------------------------

function Get-MspkiUtcNow { return $script:MspkiSim.Clock }

function New-MspkiStopwatch {
    $sw = [pscustomobject]@{ Start = $script:MspkiSim.Clock }
    $sw | Add-Member -MemberType ScriptProperty -Name ElapsedMilliseconds -Value { [int64]($script:MspkiSim.Clock - $this.Start).TotalMilliseconds }
    $sw | Add-Member -MemberType ScriptMethod -Name Stop -Value { }
    return $sw
}

# --- this computer -----------------------------------------------------------------------------------------------------------------

function Get-MspkiRunHostInfo {
    $c = $script:MspkiSim.Computer
    return [pscustomobject]@{ ComputerName = [string]$c.Name; UserContext = [string]$c.User; IsAdmin = [bool]$c.IsAdmin
        PSVersion = '5.1.26100.1'; PSEdition = 'Desktop'; ClrVersion = '4.0.30319.42000'; OSVersion = '10.0.26100.0' }
}

function New-MspkiRunId { return [string]$script:MspkiSim.RunId }

function Get-MspkiDotNetRelease { return [pscustomobject]@{ Release = 533320; Version = '4.8.1 or later' } }

function Get-MspkiLocalComputerName { return [string]$script:MspkiSim.Computer.Name }

function ConvertTo-MspkiAccountName {
    param([Parameter(Mandatory = $true)][string]$Sid)
    $n = $script:MspkiSim.Directory.AccountNames[$Sid.ToUpperInvariant()]
    if (-not $n) { throw (New-Object System.Security.Principal.IdentityNotMappedException('Some or all identity references could not be translated.')) }
    return [string]$n
}

function Get-MspkiLocalComputerIdentity {
    $c = $script:MspkiSim.Computer
    return [pscustomobject]@{ ComputerName = [string]$c.Name; DnsDomain = [string]$c.DnsDomain }
}

function Get-MspkiComputerSystemInfo {
    $c = $script:MspkiSim.Computer
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    return [pscustomobject]@{ PartOfDomain = [bool]$c.PartOfDomain; Domain = [string]$c.Domain }
}

# --- Active Directory --------------------------------------------------------------------------------------------------------------

function Get-MspkiRootDse {
    param([string]$Path = 'LDAP://RootDSE')
    Step-MspkiSimClock (Get-MspkiSimLatency 'Ldap')
    $d = $script:MspkiSim.Directory
    $hostPart = ''
    if ($Path -match '^(LDAP|GC)://([^/]+)/RootDSE$') { $hostPart = $Matches[2].ToLowerInvariant() }
    if ($hostPart -and @($d.Servers) -notcontains $hostPart) { throw (New-Object System.Runtime.InteropServices.COMException('The server is not operational.', -2147016646)) }
    $r = $d.RootDse
    return [pscustomobject][ordered]@{ configurationNamingContext = $r.configurationNamingContext; rootDomainNamingContext = $r.rootDomainNamingContext
        defaultNamingContext = $r.defaultNamingContext; schemaNamingContext = $r.schemaNamingContext; dnsHostName = $r.dnsHostName; serverName = $r.serverName
        currentTime = $script:MspkiSim.Clock.ToString('yyyyMMddHHmmss.0Z'); domainControllerFunctionality = $r.domainControllerFunctionality }
}

function Get-MspkiDomainControllerName { return [string]$script:MspkiSim.Directory.RootDse.dnsHostName }
function Get-MspkiGlobalCatalogName { return [string]$script:MspkiSim.Directory.RootDse.dnsHostName }
function Get-MspkiForestRootName { return [string]$script:MspkiSim.Forest.RootDomain }
function Get-MspkiComputerSiteName { return [string]$script:MspkiSim.Computer.Site }

function Get-MspkiForestInfo {
    Step-MspkiSimClock (Get-MspkiSimLatency 'Ldap')
    $f = $script:MspkiSim.Forest
    return [pscustomobject]@{ Name = [string]$f.Name; RootDomain = [string]$f.RootDomain; ForestMode = [string]$f.ForestMode; Domains = @($f.Domains)
        Trusts = @($f.Trusts | ForEach-Object { [pscustomobject]@{ Source = [string]$_.Source; TargetName = [string]$_.TargetName; TrustType = [string]$_.TrustType; TrustDirection = [string]$_.TrustDirection } })
        TrustErrors = @() }
}

function Get-MspkiLdapObject {
    param([string]$Server = '', [Parameter(Mandatory = $true)][string]$BaseDN, [string]$Filter = '(objectClass=*)',
        [ValidateSet('Base', 'OneLevel', 'Subtree')][string]$Scope = 'OneLevel', [string[]]$Properties = @('distinguishedName'),
        [int]$TimeoutSeconds = 30, [switch]$IncludeDacl, [switch]$Ssl, [int]$Port = 0)
    Step-MspkiSimClock (Get-MspkiSimLatency 'Ldap')
    $d = $script:MspkiSim.Directory
    $srv = ([string]$Server).ToLowerInvariant()
    if ($srv -and @($d.Servers) -notcontains $srv) {
        Assert-MspkiSimKnown ($d.Unreachable -contains $srv) ('a directory bind to {0}' -f $srv)
        throw (New-Object System.Runtime.InteropServices.COMException('The server is not operational.', -2147016646))
    }
    $base = $BaseDN.Trim()
    $denied = $d.Denied[$base.ToLowerInvariant()]
    if ($null -ne $denied) { throw (New-Object System.UnauthorizedAccessException([string]$denied)) }
    $start = $null
    if ($base -match '^<SID=(.+)>$') { $sid = $Matches[1].ToUpperInvariant(); $start = @($d.Objects | Where-Object { $_.Sid -eq $sid })[0] }
    else { $start = $d.ByDn[$base.ToLowerInvariant()] }
    if ($null -eq $start) {
        Assert-MspkiSimKnown ($d.Absent -contains $base.ToLowerInvariant() -or $d.KnownParents -contains (Get-MspkiSimParentDn $base)) ('the LDAP object {0}' -f $base)
        throw (New-Object System.Runtime.InteropServices.COMException('There is no such object on the server.', -2147016656))
    }
    $test = ConvertTo-MspkiSimFilter -Filter $Filter
    $cands = switch ($Scope) {
        'Base' { @($start) }
        'OneLevel' { @($d.Objects | Where-Object { $_.Parent -eq $start.Key }) }
        'Subtree' { @($d.Objects | Where-Object { $_.Key -eq $start.Key -or $_.Key.EndsWith(',' + $start.Key) }) }
    }
    $want = @($Properties | ForEach-Object { ([string]$_).ToLowerInvariant() })
    foreach ($o in $cands) {
        if (-not (Test-MspkiSimFilterNode -Node $test -Attrs $o.Attrs)) { continue }
        $rec = @{}
        foreach ($p in $want) {
            if ($p -eq 'distinguishedname') { $rec['distinguishedname'] = @($o.Dn); continue }
            if ($p -eq 'adspath') { $rec['adspath'] = @('LDAP://' + $o.Dn); continue }
            if ($p -eq 'ntsecuritydescriptor' -and -not $IncludeDacl) { continue }
            if ($o.Attrs.ContainsKey($p)) { $rec[$p] = @($o.Attrs[$p]) }
        }
        $rec['adspath'] = @('LDAP://' + $o.Dn)
        $rec
    }
}

function Get-MspkiSimParentDn {
    param([string]$Dn)
    $i = $Dn.IndexOf(',')
    if ($i -lt 0) { return '' }
    return $Dn.Substring($i + 1).Trim().ToLowerInvariant()
}

function ConvertTo-MspkiSimFilter {
    # A small LDAP filter parser: &, |, !, =, presence (attr=*) and * wildcards. Returns the filter as a tree of hashtables.
    param([string]$Filter)
    $state = @{ Pos = 0; Text = $Filter }
    return (Read-MspkiSimFilterNode -State $state)
}

function Read-MspkiSimFilterNode {
    param([hashtable]$State)
    $f = $State.Text
    if ($f[$State.Pos] -ne '(') { throw ('SIMULATION: unsupported LDAP filter {0}' -f $f) }
    $State.Pos++
    $c = $f[$State.Pos]
    if ($c -eq '&' -or $c -eq '|' -or $c -eq '!') {
        $State.Pos++
        $parts = @()
        while ($f[$State.Pos] -eq '(') { $parts += , (Read-MspkiSimFilterNode -State $State) }
        $State.Pos++
        return @{ Op = [string]$c; Parts = $parts }
    }
    $end = $f.IndexOf(')', $State.Pos)
    $item = $f.Substring($State.Pos, $end - $State.Pos)
    $State.Pos = $end + 1
    $eq = $item.IndexOf('=')
    $val = [regex]::Replace($item.Substring($eq + 1), '\\([0-9A-Fa-f]{2})', { param($m) [string][char][Convert]::ToInt32($m.Groups[1].Value, 16) })
    return @{ Op = '='; Attr = $item.Substring(0, $eq).ToLowerInvariant(); Value = $val }
}

function Test-MspkiSimFilterNode {
    param([hashtable]$Node, [hashtable]$Attrs)
    switch ($Node.Op) {
        '&' { foreach ($p in $Node.Parts) { if (-not (Test-MspkiSimFilterNode -Node $p -Attrs $Attrs)) { return $false } }; return $true }
        '|' { foreach ($p in $Node.Parts) { if (Test-MspkiSimFilterNode -Node $p -Attrs $Attrs) { return $true } }; return $false }
        '!' { return (-not (Test-MspkiSimFilterNode -Node $Node.Parts[0] -Attrs $Attrs)) }
    }
    if (-not $Attrs.ContainsKey($Node.Attr)) { return $false }
    if ($Node.Value -eq '*') { return $true }
    $rx = '(?i)^' + ([regex]::Escape($Node.Value) -replace '\\\*', '.*') + '$'
    foreach ($v in @($Attrs[$Node.Attr])) { if (([string]$v) -match $rx) { return $true } }
    return $false
}
function Get-MspkiLiveDomainControllerName {
    param([AllowEmptyCollection()][string[]]$Domains = @(), [int]$TimeoutSeconds = 15)
    Step-MspkiSimClock (Get-MspkiSimLatency 'Dns')
    $names = @()
    foreach ($dm in $Domains) {
        $k = ([string]$dm).ToLowerInvariant()
        Assert-MspkiSimKnown ($script:MspkiSim.Srv.ContainsKey($k)) ('the domain controller SRV records of {0}' -f $k)
        foreach ($n in @($script:MspkiSim.Srv[$k])) { if ($names -notcontains $n) { $names += $n } }
    }
    return [pscustomobject]@{ Names = $names; Method = 'DnsSrv'; Errors = @(); Completed = $true }
}

# --- name resolution, TCP, TLS, HTTP -----------------------------------------------------------------------------------------------

function Get-MspkiSimDns {
    param([string]$HostName)
    $h = ([string]$HostName).Trim().TrimEnd('.').ToLowerInvariant()
    $dns = $script:MspkiSim.Dns
    Assert-MspkiSimKnown ($dns.ContainsKey($h)) ('the DNS name {0}' -f $h)
    $chain = @()
    $cur = $h
    for ($i = 0; $i -lt 8; $i++) {
        $e = $dns[$cur]
        if ($null -eq $e -or -not $e.Cname) { break }
        $chain += @{ Name = $cur; Target = $e.Cname }
        $cur = $e.Cname
        Assert-MspkiSimKnown ($dns.ContainsKey($cur)) ('the DNS name {0}' -f $cur)
    }
    $final = $dns[$cur]
    return @{ Name = $h; Canonical = $cur; Chain = $chain; A = @($(if ($null -ne $final) { $final.A })); AAAA = @($(if ($null -ne $final) { $final.AAAA })) }
}

function Resolve-MspkiDnsName {
    param([Parameter(Mandatory = $true)][string]$HostName, [int]$TimeoutMs = 5000)
    $h = ConvertTo-MspkiHostName $HostName
    $key = 'dns|' + $h
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text ('DNS {0}' -f $h)
    Send-MspkiProbeEvent -Phase Start -Probe DNS -Subject $h
    $r = New-MspkiProbeResult -Probe 'DNS' -Target $h
    $ms = Get-MspkiSimLatency 'Dns'
    Step-MspkiSimClock $ms
    $x = Get-MspkiSimDns -HostName $h
    $r.Addresses = @(@($x.A) + @($x.AAAA) | Where-Object { $_ })
    if ($r.Addresses.Count -gt 0) { $r.Status = 'Pass'; $r.StatusCode = 'OK' }
    else { $r.Status = 'Fail'; $r.StatusCode = 'DNS_FAIL'; $r.Error = 'No such host is known' }
    $r.ElapsedMs = [int64]$ms
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Send-MspkiProbeEvent -Phase End -Probe DNS -Subject $h -Outcome $r.StatusCode
    Write-MspkiLog -Message ('DNS {0}: {1} {2} ms {3}' -f $h, $r.Status, $r.ElapsedMs, $r.Error).Trim()
    return $r
}

function Resolve-MspkiDnsEntry {
    param([Parameter(Mandatory = $true)][string]$HostName, [int]$TimeoutMs = 5000)
    $h = ConvertTo-MspkiHostName $HostName
    $key = 'dnsentry|' + $h
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }
    $r = New-MspkiProbeResult -Probe 'DNS' -Target $h
    $ms = Get-MspkiSimLatency 'Dns'
    Step-MspkiSimClock $ms
    $x = Get-MspkiSimDns -HostName $h
    $r.Addresses = @(@($x.A) + @($x.AAAA) | Where-Object { $_ })
    $r.CanonicalName = ConvertTo-MspkiHostName $x.Canonical
    if ($r.Addresses.Count -gt 0) { $r.Status = 'Pass'; $r.StatusCode = 'OK' } else { $r.Status = 'Fail'; $r.StatusCode = 'DNS_FAIL'; $r.Error = 'No such host is known' }
    $r.ElapsedMs = [int64]$ms
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('DNS entry {0}: {1} canonical {2} {3} ms {4}' -f $h, $r.Status, $r.CanonicalName, $r.ElapsedMs, $r.Error).Trim()
    return $r
}

function Test-MspkiTcpPort {
    param([Parameter(Mandatory = $true)][string]$HostName, [Parameter(Mandatory = $true)][int]$Port, [int]$TimeoutMs = 5000)
    $h = ConvertTo-MspkiHostName $HostName
    $key = 'tcp|{0}|{1}' -f $h, $Port
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text ('TCP {0}:{1}' -f $h, $Port)
    Send-MspkiProbeEvent -Phase Start -Probe TCP -Subject $h
    $r = New-MspkiProbeResult -Probe 'TCP' -Target ('{0}:{1}' -f $h, $Port)
    $k = '{0}:{1}' -f $h, $Port
    $x = Get-MspkiSimDns -HostName $h
    $state = 'nohost'
    if (@($x.A).Count -gt 0) {
        Assert-MspkiSimKnown ($script:MspkiSim.Tcp.ContainsKey($k)) ('TCP {0}' -f $k)
        $state = [string]$script:MspkiSim.Tcp[$k]
    }
    $ms = Get-MspkiSimLatency 'Tcp'
    switch ($state) {
        'open' { $r.Status = 'Pass'; $r.StatusCode = 'OK' }
        'refused' { $r.Status = 'Fail'; $r.StatusCode = 'TCP_FAIL'; $r.Error = 'No connection could be made because the target machine actively refused it' }
        'filtered' { $ms = $TimeoutMs; $r.Status = 'Timeout'; $r.StatusCode = 'TIMEOUT'; $r.Error = ('No TCP connection within {0} ms.' -f $TimeoutMs) }
        default { $r.Status = 'Fail'; $r.StatusCode = 'TCP_FAIL'; $r.Error = 'No such host is known' }
    }
    Step-MspkiSimClock $ms
    $r.ElapsedMs = [int64]$ms
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Send-MspkiProbeEvent -Phase End -Probe TCP -Subject $h -Outcome $r.StatusCode
    Write-MspkiLog -Message ('TCP {0}:{1}: {2} {3} ms {4}' -f $h, $Port, $r.Status, $r.ElapsedMs, $r.Error).Trim()
    return $r
}

function Test-MspkiTlsEndpoint {
    param([Parameter(Mandatory = $true)][string]$HostName, [int]$Port = 443, [int]$TimeoutMs = 5000)
    $h = ConvertTo-MspkiHostName $HostName
    $key = 'tls|{0}|{1}' -f $h, $Port
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text ('TLS {0}:{1}' -f $h, $Port)
    Send-MspkiProbeEvent -Phase Start -Probe TLS -Subject $h
    $r = [pscustomobject][ordered]@{
        Probe = 'TLS'; Target = ('{0}:{1}' -f $h, $Port); Status = 'Fail'; Code = 'TLS_HANDSHAKE_FAIL'; Protocol = ''
        NameMatch = $null; ChainErrors = @(); Subject = ''; Issuer = ''; Thumbprint = ''; NotAfter = ''; Error = ''; ElapsedMs = 0; FromCache = $false
        DnsNames = @(); ServerClosed = $false; OfferedProtocols = ''
    }
    $start = $script:MspkiSim.Clock
    $tcp = Test-MspkiTcpPort -HostName $h -Port $Port -TimeoutMs $TimeoutMs
    if ($tcp.Status -ne 'Pass') { $r.Code = $tcp.StatusCode; $r.Error = $tcp.Error }
    else {
        $k = '{0}:{1}' -f $h, $Port
        Assert-MspkiSimKnown ($script:MspkiSim.Tls.ContainsKey($k)) ('the TLS handshake with {0}' -f $k)
        $t = $script:MspkiSim.Tls[$k]
        Step-MspkiSimClock (Get-MspkiSimLatency 'Tls')
        $r.OfferedProtocols = 'Tls12, Tls13'
        if ($t.Reset) { $r.ServerClosed = $true; $r.Error = 'Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host.' }
        else {
            $c = New-MspkiCertificate -Bytes ([byte[]]$t.Certificate)
            $r.Protocol = 'Tls12'; $r.Subject = $c.Subject; $r.Issuer = $c.Issuer; $r.Thumbprint = $c.Thumbprint
            $r.NotAfter = $c.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $r.DnsNames = @($t.DnsNames); $r.NameMatch = [bool]$t.NameMatch; $r.ChainErrors = @($t.ChainErrors)
            $r.Code = $(if ($t.Code) { [string]$t.Code } else { 'OK' })
            $r.Status = $(if ($r.Code -eq 'OK') { 'Pass' } else { 'Fail' })
        }
    }
    $r.ElapsedMs = [int64]($script:MspkiSim.Clock - $start).TotalMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Send-MspkiProbeEvent -Phase End -Probe TLS -Subject $h -Outcome $r.Code
    Write-MspkiLog -Message ('TLS {0}: {1} {2} (offered: {3}) {4} ms {5}' -f $r.Target, $r.Code, $r.Protocol, $r.OfferedProtocols, $r.ElapsedMs, $r.Error).Trim()
    return $r
}

function Invoke-MspkiHttpRequest {
    # One simulated anonymous GET (the engine's Invoke-MspkiHttpGet keeps its own redirect, bounding and code logic around it).
    param([Parameter(Mandatory = $true)][string]$Url, [int]$TimeoutMs = 5000, [int]$MaxBytes = 10485760, [switch]$ReadBody, $Proxy = $null)
    $out = [pscustomobject][ordered]@{ Answered = $false; StatusCode = 0; Location = ''; Server = ''; AuthSchemes = @(); ContentType = ''; Bytes = $null; TooLarge = $false; FailStatus = ''; Error = '' }
    $u = [System.Uri]$Url
    $h = ConvertTo-MspkiHostName $u.Host
    $x = Get-MspkiSimDns -HostName $h
    Step-MspkiSimClock (Get-MspkiSimLatency 'Dns')
    if (@($x.A).Count -eq 0) { $out.FailStatus = 'NameResolutionFailure'; $out.Error = ('The remote name could not be resolved: ''{0}''' -f $h); return $out }
    $k = '{0}:{1}' -f $h, $u.Port
    Assert-MspkiSimKnown ($script:MspkiSim.Tcp.ContainsKey($k)) ('TCP {0}' -f $k)
    $state = [string]$script:MspkiSim.Tcp[$k]
    if ($state -eq 'refused') { Step-MspkiSimClock (Get-MspkiSimLatency 'Tcp'); $out.FailStatus = 'ConnectFailure'; $out.Error = 'Unable to connect to the remote server'; return $out }
    if ($state -eq 'filtered') { Step-MspkiSimClock $TimeoutMs; $out.FailStatus = 'Timeout'; $out.Error = 'The operation has timed out'; return $out }
    if ($u.Scheme -eq 'https') {
        Assert-MspkiSimKnown ($script:MspkiSim.Tls.ContainsKey($k)) ('the TLS handshake with {0}' -f $k)
        $t = $script:MspkiSim.Tls[$k]
        Step-MspkiSimClock (Get-MspkiSimLatency 'Tls')
        if ($t.Reset) { $out.FailStatus = 'SecureChannelFailure'; $out.Error = 'The underlying connection was closed: An unexpected error occurred on a send.'; return $out }
        if ($t.Code -and $t.Code -ne 'OK') { $out.FailStatus = 'TrustFailure'; $out.Error = 'The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel.'; return $out }
    }
    $key = $u.AbsoluteUri
    Assert-MspkiSimKnown ($script:MspkiSim.Http.ContainsKey($key)) ('the HTTP GET of {0}' -f $key)
    $resp = $script:MspkiSim.Http[$key]
    Step-MspkiSimClock (Get-MspkiSimLatency 'Http')
    $out.Answered = $true
    $out.StatusCode = [int]$resp.Status
    $out.Location = [string]$resp.Location
    $out.Server = [string]$resp.Server
    $out.AuthSchemes = @($resp.Auth | Where-Object { $_ })
    $out.ContentType = [string]$resp.ContentType
    if ($out.StatusCode -eq 200 -and $ReadBody) {
        $b = [byte[]]$resp.Body
        if ($null -eq $b) { $b = [byte[]]@() }
        if ($b.Length -gt $MaxBytes) { $out.TooLarge = $true } else { $out.Bytes = $b }
    }
    return $out
}

# --- calls the engine runs in a time-limited runspace ------------------------------------------------------------------------------

function Invoke-MspkiTimeLimitedScript {
    param([Parameter(Mandatory = $true)][scriptblock]$ScriptBlock, [object[]]$ArgumentList = @(), [int]$TimeoutSeconds = 30, [string]$ProgressText = 'Calling a CA (COM)')
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text $ProgressText
    $res = [pscustomobject][ordered]@{ Completed = $true; TimedOut = $false; Output = @(); Errors = @(); ElapsedMs = 0 }
    $start = $script:MspkiSim.Clock
    if ([object]::ReferenceEquals($ScriptBlock, $script:MspkiCAPropertyReader)) { $res.Output = @(Get-MspkiSimCaReading -Config ([string]$ArgumentList[0]) -Plain $ArgumentList[2] -Indexed $ArgumentList[3] -MaxIndex ([int]$ArgumentList[4])) }
    elseif ([object]::ReferenceEquals($ScriptBlock, $script:MspkiNdesDbReader)) { $res.Output = @(Get-MspkiSimCaDatabase -Config ([string]$ArgumentList[0]) -TemplateKeys $ArgumentList[1] -MaxRows ([int]$ArgumentList[2])) }
    elseif ($ScriptBlock.ToString() -match 'Resolve-DnsName') {
        # The engine's own lookup script runs unchanged, here, with Resolve-DnsName answered from the world (below).
        $res.Output = @(& $ScriptBlock @ArgumentList | ForEach-Object { $_ })
    }
    else { Assert-MspkiSimKnown $false 'a time-limited script that is not one of the engine''s known readers' }
    $res.ElapsedMs = [int64]($script:MspkiSim.Clock - $start).TotalMilliseconds
    return $res
}

function Resolve-DnsName {
    # Shadows the DnsClient cmdlet inside the module scope only, for the engine's own DNS scripts. Answers A_AAAA, PTR and SRV.
    param([string]$Name, [string]$Type, [switch]$DnsOnly, [switch]$QuickTimeout)
    Step-MspkiSimClock (Get-MspkiSimLatency 'Dns')
    $n = ([string]$Name).TrimEnd('.').ToLowerInvariant()
    if ($Type -eq 'SRV') {
        $dm = $n -replace '^_ldap\._tcp\.dc\._msdcs\.', ''
        Assert-MspkiSimKnown ($script:MspkiSim.Srv.ContainsKey($dm)) ('the SRV records of {0}' -f $dm)
        return @($script:MspkiSim.Srv[$dm] | ForEach-Object { [pscustomobject]@{ Name = $n; Type = 'SRV'; Section = 'Answer'; NameTarget = $_ } })
    }
    if ($Type -eq 'PTR') {
        Assert-MspkiSimKnown ($script:MspkiSim.Ptr.ContainsKey($n)) ('the PTR record of {0}' -f $n)
        $names = @($script:MspkiSim.Ptr[$n])
        if ($names.Count -eq 0) { throw (New-Object System.ComponentModel.Win32Exception(9003, ('{0} : DNS name does not exist' -f $n))) }
        return @($names | ForEach-Object { [pscustomobject]@{ Name = $n; Type = 'PTR'; Section = 'Answer'; NameHost = $_ } })
    }
    $x = Get-MspkiSimDns -HostName $n
    $out = @()
    foreach ($c in @($x.Chain)) { $out += [pscustomobject]@{ Name = $c.Name; Type = 'CNAME'; Section = 'Answer'; NameHost = $c.Target } }
    foreach ($a in @($x.A)) { $out += [pscustomobject]@{ Name = $x.Canonical; Type = 'A'; Section = 'Answer'; IPAddress = $a } }
    foreach ($a in @($x.AAAA)) { $out += [pscustomobject]@{ Name = $x.Canonical; Type = 'AAAA'; Section = 'Answer'; IPAddress = $a } }
    if (@($x.A).Count + @($x.AAAA).Count -eq 0) { throw (New-Object System.ComponentModel.Win32Exception(9003, ('{0} : DNS name does not exist' -f $n))) }
    return $out
}

function Get-MspkiSimCaReading {
    # What CertificateAuthority.Request answers for one CA (values or the error of each call), in the reader's own result format.
    param([string]$Config, [string[]]$Plain, [string[]]$Indexed, [int]$MaxIndex)
    $key = $Config.ToLowerInvariant()
    Assert-MspkiSimKnown ($script:MspkiSim.Cas.ContainsKey($key)) ('the CA configuration {0}' -f $Config)
    $ca = $script:MspkiSim.Cas[$key]
    $result = @{ Values = @{}; Errors = @{}; Fatal = $null; Count = -1; Trace = (New-Object System.Collections.ArrayList); Config = $Config }
    $call = {
        param([string]$Name, [int]$Index, [string]$ValueKey)
        $ms = Get-MspkiSimLatency 'Com'
        Step-MspkiSimClock $ms
        $p = $script:MspkiCAProp[$Name]
        if ($ca.Errors.ContainsKey($ValueKey)) {
            $e = $ca.Errors[$ValueKey]
            [void]$result.Trace.Add(@{ Name = $Name; Id = $p.Id; Index = $Index; DataType = $p.Type; ResultType = 'error'; Size = 0; ElapsedMs = [int64]$ms; HResult = $e.HResult })
            return @{ Error = $e }
        }
        $v = $null
        if ($ca.Values.ContainsKey($ValueKey)) { $v = $ca.Values[$ValueKey] }
        $rt = $(if ($null -eq $v) { 'null' } else { $v.GetType().Name })
        $size = $(if ($v -is [string]) { $v.Length } else { 0 })
        [void]$result.Trace.Add(@{ Name = $Name; Id = $p.Id; Index = $Index; DataType = $p.Type; ResultType = $rt; Size = $size; ElapsedMs = [int64]$ms; HResult = '' })
        return @{ Value = $v }
    }
    if ($null -ne $ca.Fatal) {
        Step-MspkiSimClock ([double]$ca.FatalMs)
        $p = $script:MspkiCAProp['CAType']
        [void]$result.Trace.Add(@{ Name = 'CAType'; Id = $p.Id; Index = 0; DataType = $p.Type; ResultType = 'error'; Size = 0; ElapsedMs = [int64]$ca.FatalMs; HResult = $ca.Fatal.HResult })
        $result.Fatal = $ca.Fatal
        return $result
    }
    $r = & $call 'CAType' 0 'CAType'; $result.Values['CAType'] = $r.Value
    foreach ($n in $Plain) { $r = & $call $n 0 $n; if ($r.ContainsKey('Error')) { $result.Errors[$n] = $r.Error } else { $result.Values[$n] = $r.Value } }
    $r = & $call 'CASigCertCount' 0 'CASigCertCount'
    if ($r.ContainsKey('Error')) { $result.Errors['CASigCertCount'] = $r.Error } else { $result.Count = [int]$r.Value }
    $n = [math]::Min($result.Count, $MaxIndex)
    for ($i = 0; $i -lt $n; $i++) {
        foreach ($name in $Indexed) {
            $vk = '{0}[{1}]' -f $name, $i
            $r = & $call $name $i $vk
            if ($r.ContainsKey('Error')) { $result.Errors[$vk] = $r.Error } else { $result.Values[$vk] = $r.Value }
        }
    }
    return $result
}

function Get-MspkiSimCaDatabase {
    # The CA database view (issued certificates of some templates), in the reader's own result format.
    param([string]$Config, [string[]]$TemplateKeys, [int]$MaxRows)
    $key = $Config.ToLowerInvariant()
    Assert-MspkiSimKnown ($script:MspkiSim.Cas.ContainsKey($key)) ('the CA configuration {0}' -f $Config)
    $ca = $script:MspkiSim.Cas[$key]
    $result = @{ Rows = (New-Object System.Collections.ArrayList); Errors = (New-Object System.Collections.ArrayList); Fatal = $null; Trace = (New-Object System.Collections.ArrayList) }
    $cols = 'Request.RequestID, Request.RequesterName, CommonName, CertificateTemplate, NotBefore, NotAfter'
    foreach ($k in $TemplateKeys) {
        $ms = Get-MspkiSimLatency 'Com'
        Step-MspkiSimClock $ms
        if ($null -ne $ca.DatabaseFatal) {
            [void]$result.Trace.Add(@{ Key = $k; Columns = $cols; Rows = 0; ElapsedMs = [int64]$ms; HResult = $ca.DatabaseFatal.HResult })
            $result.Fatal = $ca.DatabaseFatal
            return $result
        }
        $rows = @($ca.Database | Where-Object { $_.TemplateKey -eq $k } | Select-Object -First $MaxRows)
        foreach ($row in $rows) { $copy = @{}; foreach ($p in $row.Keys) { $copy[$p] = $row[$p] }; [void]$result.Rows.Add($copy) }
        [void]$result.Trace.Add(@{ Key = $k; Columns = $cols; Rows = $rows.Count; ElapsedMs = [int64]$ms; HResult = '' })
    }
    return $result
}

# --- this computer's stores, registry, events and services ---------------------------------------------------------------------------

function Read-MspkiLocalStore {
    param([string]$Location, [Parameter(Mandatory = $true)][string]$Name)
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    $path = 'Cert:\{0}\{1}' -f $Location, $Name
    $k = '{0}\{1}' -f $Location, $Name
    $out = [pscustomobject]@{ Store = $path; Certificates = @(); Error = $null }
    $stores = $script:MspkiSim.Machine.Stores
    if ($stores.ContainsKey($k)) { $out.Certificates = @($stores[$k] | ForEach-Object { New-MspkiCertificate -Bytes ([byte[]]$_) }) }
    return $out
}

function Get-MspkiEnterpriseStoreThumbprint {
    param([string]$Name)
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    $e = $script:MspkiSim.Machine.Enterprise
    $out = [pscustomobject]@{ Store = $Name; Thumbprints = @(); Exists = $false; Error = $null }
    if ($e.ContainsKey($Name)) { $out.Exists = $true; $out.Thumbprints = @($e[$Name] | ForEach-Object { ([string]$_).ToUpperInvariant() }) }
    return $out
}

function Get-MspkiLifecycleEvent {
    param([int]$MaxEvents = 500)
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    $events = @($script:MspkiSim.Machine.LifecycleEvents | ForEach-Object { [pscustomobject]$_ })
    $logs = @($script:MspkiLifecycleLogs | ForEach-Object { $n = $_.Name; [pscustomobject]@{ Name = $n; Read = $true; Count = @($events | Where-Object { $_.Log -eq $n }).Count; Error = $null } })
    return [pscustomobject]@{ Events = $events; Logs = $logs }
}

function Get-MspkiEnrollmentEvent {
    param([int]$MaxEvents = 300)
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    return [pscustomobject]@{ Events = @($script:MspkiSim.Machine.EnrollmentEvents | ForEach-Object { [pscustomobject]$_ }); Read = $true; Error = $null }
}

function Get-MspkiEnrollmentPolicyState {
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    $p = $script:MspkiSim.Machine.Policy
    $cache = @(foreach ($s in @('Computer', 'User')) {
        $hive = $(if ($s -eq 'Computer') { 'HKLM' } else { 'HKCU' })
        $c = $p.TemplateCache[$s]
        [pscustomobject]@{ Scope = $s; Path = ('{0}\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache' -f $hive); Timestamp = $(if ($c) { [string]$c.Timestamp } else { '' })
            Templates = @($(if ($c) { $c.Templates })); Exists = [bool]$c; Error = $null }
    })
    $ae = @(foreach ($s in @('Computer', 'User')) {
        $hive = $(if ($s -eq 'Computer') { 'HKLM' } else { 'HKCU' })
        $v = $p.AEPolicy[$s]
        [pscustomobject]@{ Scope = $s; Path = ('{0}\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment' -f $hive); AEPolicy = $(if ($null -ne $v) { [int64]$v } else { $null }); Configured = ($null -ne $v); Error = $null }
    })
    $rdp = [pscustomobject]@{ Path = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Template = [string]$p.RdpTemplate; Error = $null }
    return [pscustomobject]@{ TemplateCache = $cache; AutoEnrollment = $ae; RdpTemplate = $rdp }
}

function Read-MspkiPolicyServerKey {
    param([Parameter(Mandatory = $true)][hashtable]$Location)
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    $k = '{0}\{1}' -f $Location.Hive, $Location.Path
    $ps = $script:MspkiSim.Machine.PolicyServers
    if (-not $ps.ContainsKey($k)) { return [pscustomobject]@{ Exists = $false; Entries = @(); Error = ''; ErrorInfo = $null } }
    return [pscustomobject]@{ Exists = $true; Entries = @($ps[$k]); Error = ''; ErrorInfo = $null }
}

function Get-MspkiLocalServiceInfo { Step-MspkiSimClock (Get-MspkiSimLatency 'Local'); return , @($script:MspkiSim.Machine.Services | ForEach-Object { [pscustomobject]$_ }) }
function Get-MspkiLocalProductInfo { Step-MspkiSimClock (Get-MspkiSimLatency 'Local'); return , @($script:MspkiSim.Machine.Products | ForEach-Object { [pscustomobject]$_ }) }

function Get-MspkiLocalCertificateMetadata {
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    $list = @()
    foreach ($b in @($script:MspkiSim.Machine.Stores['LocalMachine\My'])) {
        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]]$b)
        $hay = ('{0} {1} {2}' -f $c.Subject, $c.Issuer, '')
        if (@($script:MspkiIntuneCertificatePattern | Where-Object { $hay -match $_ }).Count -gt 0) {
            $list += [pscustomobject][ordered]@{ Subject = $c.Subject; Issuer = $c.Issuer; Thumbprint = $c.Thumbprint; NotAfter = $c.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); FriendlyName = '' }
        }
    }
    return , $list
}

function Get-MspkiLocalIssuedCertificate {
    param([AllowEmptyCollection()][string[]]$IssuerKeyIds = @())
    $keys = @($IssuerKeyIds | ForEach-Object { ConvertTo-MspkiKeyIdHex $_ } | Where-Object { $_ })
    if ($keys.Count -eq 0) { return @() }
    Step-MspkiSimClock (Get-MspkiSimLatency 'Local')
    $list = @()
    foreach ($b in @($script:MspkiSim.Machine.Stores['LocalMachine\My'])) {
        $pub = New-MspkiCertificate -Bytes ([byte[]]$b)
        $aki = ConvertTo-MspkiKeyIdHex (Get-MspkiCertificateAuthorityKeyId -Certificate $pub)
        if ($aki -and $keys -contains $aki) { $list += $pub }
    }
    return @($list)
}

function Test-MspkiTrustedRoot {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    return (@($script:MspkiSim.Machine.TrustedRoots) -contains $Thumbprint.ToUpperInvariant())
}
