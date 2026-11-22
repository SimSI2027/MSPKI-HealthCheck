# DNS identity of the hosts the run touched (D2): A/AAAA, the CNAME (alias) chain and reverse (PTR) names. In-box only, read-only,
# time-limited and cached per name. Only names that came from an authoritative source are looked up (the caller passes Host entities).

function ConvertTo-MspkiDnsIdentity {
    <#
    .SYNOPSIS
    Turns raw DNS answers for one name into the identity record (pure; used by Resolve-MspkiDnsIdentity and by the tests).
    .DESCRIPTION
    Raw = { Name; QueryName; ErrorCode (Win32 DNS code, 0 = answer); Error; Records = @({ Type; Name; Target; Address }); Ptr = @({ Address;
    ErrorCode; Error; Names[] }) }. 9003 (name does not exist) and 9501 (no records of that type) mean "no record"; 1460 is a timeout;
    anything else is a failure. Chain = QueryName followed by every CNAME target in order.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Raw, [string]$Method = 'DnsClient', [int64]$ElapsedMs = 0)
    $classify = {
        param([int]$Code)
        if ($Code -eq 0) { return 'Found' }
        if ($Code -eq 9003 -or $Code -eq 9501) { return 'NoRecord' }
        if ($Code -eq 1460) { return 'Timeout' }
        return 'Error'
    }
    $q = ConvertTo-MspkiHostName ([string]$Raw.QueryName)
    $r = [pscustomobject][ordered]@{
        Probe = 'DNSID'; Target = (ConvertTo-MspkiHostName ([string]$Raw.Name)); QueryName = $q; Method = $Method; Status = 'Fail'; StatusCode = 'DNS_FAIL'
        Lookup = (& $classify ([int]$Raw.ErrorCode)); Chain = @($q); Cnames = @(); A = @(); AAAA = @(); CanonicalName = $q; Ptr = @(); Error = [string]$Raw.Error
        ElapsedMs = $ElapsedMs; FromCache = $false
    }
    $cn = New-Object System.Collections.ArrayList
    $a4 = New-Object System.Collections.ArrayList
    $a6 = New-Object System.Collections.ArrayList
    foreach ($rec in @($Raw.Records | Where-Object { $null -ne $_ })) {
        $t = ([string]$rec.Type).ToUpperInvariant()
        if ($t -eq 'CNAME') {
            $from = ConvertTo-MspkiHostName ([string]$rec.Name); $to = ConvertTo-MspkiHostName ([string]$rec.Target)
            if ($from -and $to) { [void]$cn.Add([pscustomobject][ordered]@{ Name = $from; Target = $to }) }
        }
        elseif ($t -eq 'A' -and $rec.Address -and -not $a4.Contains([string]$rec.Address)) { [void]$a4.Add([string]$rec.Address) }
        elseif ($t -eq 'AAAA' -and $rec.Address -and -not $a6.Contains([string]$rec.Address)) { [void]$a6.Add([string]$rec.Address) }
    }
    # Follow the CNAMEs from the query name, in order (answers can come in any order).
    $chain = New-Object System.Collections.ArrayList
    [void]$chain.Add($q)
    $cur = $q
    for ($i = 0; $i -lt 16; $i++) {
        $next = @($cn | Where-Object { $_.Name -eq $cur }) | Select-Object -First 1
        if ($null -eq $next -or $chain.Contains($next.Target)) { break }
        [void]$chain.Add($next.Target); $cur = $next.Target
    }
    $r.Chain = @($chain); $r.Cnames = @($cn); $r.CanonicalName = $cur; $r.A = @($a4); $r.AAAA = @($a6)
    if ($a4.Count + $a6.Count -gt 0) { $r.Status = 'Pass'; $r.StatusCode = 'OK'; $r.Lookup = 'Found' }
    elseif ($r.Lookup -eq 'Timeout') { $r.Status = 'Timeout'; $r.StatusCode = 'TIMEOUT' }
    elseif ($r.Lookup -eq 'Found') { $r.Lookup = 'NoRecord' }
    $ptr = New-Object System.Collections.ArrayList
    foreach ($p in @($Raw.Ptr | Where-Object { $null -ne $_ })) {
        $names = @(@($p.Names) | Where-Object { $_ } | ForEach-Object { ConvertTo-MspkiHostName ([string]$_) } | Select-Object -Unique)
        $lk = (& $classify ([int]$p.ErrorCode))
        if ($lk -eq 'Found' -and $names.Count -eq 0) { $lk = 'NoRecord' }
        [void]$ptr.Add([pscustomobject][ordered]@{ Address = [string]$p.Address; Lookup = $lk; Error = [string]$p.Error; Names = $names })
    }
    $r.Ptr = @($ptr)
    return $r
}

function Resolve-MspkiDnsIdentity {
    <#
    .SYNOPSIS
    The DNS identity of host names: A and AAAA records, the CNAME (alias) chain and the reverse (PTR) names of every address.
    Cached per name for the run; uncached names are resolved together in one time-limited runspace.
    .DESCRIPTION
    In-box only. With the Windows DnsClient module (Resolve-DnsName) the lookups are DNS-only (no NetBIOS, LLMNR or hosts file), which
    is what other clients see: Method = DnsClient. Without it, .NET Dns is used (canonical name only, and the reverse name may come
    from NetBIOS): Method = DotNet, which the analysis reports as Inferred. A single-label name is tried with each -DnsSuffix first.
    Returns one record per name (see ConvertTo-MspkiDnsIdentity), in the order given.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$HostName,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000,
        [string[]]$DnsSuffix = @()
    )
    $names = @($HostName | ForEach-Object { ConvertTo-MspkiHostName $_ } | Where-Object { $_ } | Select-Object -Unique)
    $out = @{}
    $todo = New-Object System.Collections.ArrayList
    foreach ($n in $names) {
        $c = Get-MspkiProbeCacheEntry -Key ('dnsid|' + $n)
        if ($null -ne $c) { $copy = $c.psobject.Copy(); $copy.FromCache = $true; $out[$n] = $copy } else { [void]$todo.Add($n) }
    }
    if ($todo.Count -gt 0) {
        $suffixes = @($DnsSuffix | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim('.').ToLowerInvariant() } | Select-Object -Unique)
        $hasDnsClient = $null -ne (Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue)
        $method = $(if ($hasDnsClient) { 'DnsClient' } else { 'DotNet' })
        $limit = [int][Math]::Min(600, [Math]::Max(10, [Math]::Ceiling(($TimeoutMs / 1000.0) * (2 + $todo.Count))))
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $call = Invoke-MspkiTimeLimitedScript -ScriptBlock (Get-MspkiDnsIdentityScript) -ArgumentList @([string[]]$todo.ToArray(), [string[]]$suffixes, $hasDnsClient) `
            -TimeoutSeconds $limit -ProgressText ('DNS identity of {0} host(s)' -f $todo.Count)
        $raws = @{}
        foreach ($o in @($call.Output | ForEach-Object { $_ })) { if ($o -is [hashtable] -and $o.Name) { $raws[[string]$o.Name] = $o } }
        foreach ($n in $todo) {
            if ($raws.ContainsKey($n)) { $rec = ConvertTo-MspkiDnsIdentity -Raw $raws[$n] -Method $method -ElapsedMs ([int64]$sw.ElapsedMilliseconds) }
            else {
                $why = $(if ($call.TimedOut) { ('No DNS answer within {0} s.' -f $limit) } else { (@($call.Errors) -join '; ') })
                $code = $(if ($call.TimedOut) { 1460 } else { 9999 })
                $rec = ConvertTo-MspkiDnsIdentity -Raw @{ Name = $n; QueryName = $n; ErrorCode = $code; Error = $why } -Method $method -ElapsedMs ([int64]$sw.ElapsedMilliseconds)
            }
            Set-MspkiProbeCacheEntry -Key ('dnsid|' + $n) -Value $rec
            $ptrText = (@($rec.Ptr) | ForEach-Object { '{0}={1}' -f $_.Address, $(if (@($_.Names).Count) { @($_.Names) -join '/' } else { $_.Lookup }) }) -join ' '
            Write-MspkiLog -Message ('DNS identity {0} ({1}): {2}; chain {3}; A {4}; AAAA {5}; PTR {6} {7}' -f $n, $rec.Method, $rec.Lookup, (@($rec.Chain) -join ' > '),
                (@($rec.A) -join ','), (@($rec.AAAA) -join ','), $ptrText, $rec.Error).Trim()
            $out[$n] = $rec
        }
    }
    return @($names | ForEach-Object { $out[$_] })
}

function Get-MspkiDnsIdentityScript {
    # The self-contained lookup script for the time-limited runspace. Data in, data out (hashtables of strings); nothing is written.
    return {
        param([string[]]$Names, [string[]]$Suffixes, [bool]$UseDnsClient)
        $codeOf = {
            param($Err)
            $ex = $Err.Exception
            while ($null -ne $ex.InnerException -and -not ($ex -is [System.ComponentModel.Win32Exception])) { $ex = $ex.InnerException }
            if ($ex -is [System.Net.Sockets.SocketException] -and [int]$ex.SocketErrorCode -eq 11001) { return 9003 }
            if ($ex -is [System.ComponentModel.Win32Exception]) { return [int]$ex.NativeErrorCode }
            return 9999
        }
        $res = New-Object System.Collections.ArrayList
        foreach ($name in $Names) {
            $o = @{ Name = $name; QueryName = $name; ErrorCode = 0; Error = ''; Records = @(); Ptr = @() }
            $candidates = @($name)
            if ($name -notlike '*.*') { $candidates = @(@($Suffixes | ForEach-Object { '{0}.{1}' -f $name, $_ }) + $name) }
            foreach ($cand in $candidates) {
                $o.QueryName = $cand; $o.ErrorCode = 0; $o.Error = ''; $o.Records = @()
                try {
                    if ($UseDnsClient) {
                        foreach ($a in @(Resolve-DnsName -Name $cand -Type A_AAAA -DnsOnly -QuickTimeout -ErrorAction Stop)) {
                            if ([string]$a.Section -ne 'Answer') { continue }
                            $t = [string]$a.Type
                            if ($t -eq 'CNAME') { $o.Records += @{ Type = 'CNAME'; Name = [string]$a.Name; Target = [string]$a.NameHost } }
                            elseif ($t -eq 'A' -or $t -eq 'AAAA') { $o.Records += @{ Type = $t; Name = [string]$a.Name; Address = [string]$a.IPAddress } }
                        }
                    }
                    else {
                        $e = [System.Net.Dns]::GetHostEntry($cand)
                        if ($e.HostName -and $e.HostName -ne $cand) { $o.Records += @{ Type = 'CNAME'; Name = $cand; Target = [string]$e.HostName } }
                        foreach ($ip in $e.AddressList) {
                            $t = 'A'
                            if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $t = 'AAAA' }
                            $o.Records += @{ Type = $t; Name = [string]$e.HostName; Address = $ip.IPAddressToString }
                        }
                    }
                }
                catch { $o.ErrorCode = (& $codeOf $_); $o.Error = [string]$_.Exception.Message }
                if (@($o.Records | Where-Object { $_.Type -ne 'CNAME' }).Count -gt 0) { break }
            }
            foreach ($ip in @($o.Records | Where-Object { $_.Type -ne 'CNAME' } | ForEach-Object { $_.Address } | Select-Object -Unique)) {
                $p = @{ Address = $ip; ErrorCode = 0; Error = ''; Names = @() }
                try {
                    if ($UseDnsClient) {
                        $p.Names = @(@(Resolve-DnsName -Name $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop) |
                            Where-Object { [string]$_.Section -eq 'Answer' -and [string]$_.Type -eq 'PTR' } | ForEach-Object { [string]$_.NameHost })
                    }
                    else {
                        $e = [System.Net.Dns]::GetHostEntry([System.Net.IPAddress]::Parse($ip))
                        if ($e.HostName -and $e.HostName -ne $ip) { $p.Names = @([string]$e.HostName) }
                    }
                    if ($p.Names.Count -eq 0) { $p.ErrorCode = 9501 }
                }
                catch { $p.ErrorCode = (& $codeOf $_); $p.Error = [string]$_.Exception.Message }
                $o.Ptr += $p
            }
            [void]$res.Add($o)
        }
        return $res.ToArray()
    }
}
