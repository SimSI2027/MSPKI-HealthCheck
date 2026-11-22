# Endpoint identity (ROADMAP D2): for every host the run touched, record what DNS, TLS and HTTP say it is (A/AAAA, reverse DNS, the
# CNAME alias chain, the TLS certificate names, the HTTP Server header) on its Host entity, and flag where these disagree. Also finds
# Web Enrollment (/certsrv/) on the CA hosts (standard path on a proven PKI host, anonymous GET, body never read, no redirects).
# Read-only: DNS queries and anonymous GETs only, time-limited and cached.

function Test-MspkiDnsNameCovered {
    <#
    .SYNOPSIS
    True when a certificate DNS name list covers a host name (exact match, or a wildcard in the left-most label that stands for exactly
    one label, as TLS clients check it).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Name, [AllowEmptyCollection()][string[]]$Patterns = @())
    $n = ConvertTo-MspkiHostName $Name
    if (-not $n) { return $false }
    foreach ($p in @($Patterns | ForEach-Object { ConvertTo-MspkiHostName $_ } | Where-Object { $_ })) {
        if ($p -eq $n) { return $true }
        if ($p.StartsWith('*.')) {
            $rest = $p.Substring(2)
            $i = $n.IndexOf('.')
            if ($i -gt 0 -and $n.Substring($i + 1) -eq $rest -and $rest -like '*.*') { return $true }
        }
    }
    return $false
}

function Get-MspkiReverseName {
    # The in-addr.arpa / ip6.arpa name of an address (for observation locations); the address itself when it does not parse.
    param([string]$Address)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $Address }
    $b = $ip.GetAddressBytes()
    if ($b.Length -eq 4) { return ('{0}.{1}.{2}.{3}.in-addr.arpa' -f $b[3], $b[2], $b[1], $b[0]) }
    $hex = (($b | ForEach-Object { $_.ToString('x2') }) -join '').ToCharArray()
    [array]::Reverse($hex)
    return ((($hex | ForEach-Object { [string]$_ }) -join '.') + '.ip6.arpa')
}

function Get-MspkiWebEnrollmentState {
    <#
    .SYNOPSIS
    What one anonymous GET of /certsrv/ says: $null when nothing is there (no answer or 404), else { Present; Meaning; WindowsSignIn }.
    Every answer other than 404 means an application exists at the standard Web Enrollment path; it is never Confirmed from the status alone.
    #>
    [CmdletBinding()]
    param($Http)
    if ($null -eq $Http) { return $null }
    $sc = [int]$Http.HttpStatus
    if ($sc -eq 0 -or $sc -eq 404) { return $null }
    $schemes = @($Http.AuthSchemes | Where-Object { $_ })
    $win = @($schemes | Where-Object { $_ -match '^(?i)(NTLM|Negotiate)$' }).Count -gt 0
    $meaning = $(switch ($sc) {
        { $_ -eq 200 } { 'answers anonymously (the page itself was not read)'; break }
        { $_ -eq 401 } { $(if ($win) { ('asks for Windows sign-in ({0})' -f ($schemes -join ', ')) } else { 'asks for sign-in' }); break }
        { $_ -eq 403 } { 'refuses anonymous access (often "SSL required" or an IP restriction)'; break }
        { $_ -ge 300 -and $_ -lt 400 } { ('redirects (HTTP {0}) to {1}' -f $sc, $(if (@($Http.Hops).Count) { [string]@($Http.Hops)[-1].Location } else { 'another URL' })); break }
        { $_ -ge 500 } { ('answers with a server error (HTTP {0})' -f $sc); break }
        default { ('answers HTTP {0}' -f $sc) }
    })
    return [pscustomobject][ordered]@{ Present = $true; HttpStatus = $sc; Meaning = $meaning; WindowsSignIn = $win; AuthSchemes = $schemes; Server = [string]$Http.Server }
}

function Test-MspkiWebEnrollment {
    <#
    .SYNOPSIS
    Findings for Web Enrollment on one CA host from the HTTP and HTTPS answers of /certsrv/: Information when it is there, and a Warning
    when it offers Windows sign-in (NTLM / Negotiate) over plain HTTP, the NTLM relay exposure known as ESC8.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$HostName, $Http = $null, $Https = $null, [string]$CAName = '', [string[]]$EntityIds = @())
    $out = New-Object System.Collections.ArrayList
    $sh = Get-MspkiWebEnrollmentState -Http $Http
    $ss = Get-MspkiWebEnrollmentState -Http $Https
    if ($null -eq $sh -and $null -eq $ss) { return @() }
    $ev = New-Object System.Collections.ArrayList
    foreach ($pair in @(@('http', $Http, $sh), @('https', $Https, $ss))) {
        $res = $pair[1]
        if ($null -eq $res) { [void]$ev.Add(('{0}://{1}{2}: not requested' -f $pair[0], $HostName, (Get-MspkiWebEnrollmentPath))); continue }
        $what = $(if ($null -ne $pair[2]) { $pair[2].Meaning } elseif ([int]$res.HttpStatus -eq 404) { 'not found (404)' } else { ('no answer ({0})' -f $res.Code) })
        $line = 'GET {0}: HTTP {1}, {2}' -f $res.Url, $res.HttpStatus, $what
        if ($res.Server) { $line += ('; Server: {0}' -f $res.Server) }
        [void]$ev.Add($line)
    }
    $base = @{ Category = 'WebEnrollment'; Role = 'WebEnrollmentEndpoint'; Target = ('http(s)://{0}{1}' -f $HostName, (Get-MspkiWebEnrollmentPath)); Sources = @('HTTP:StandardPath', 'AD:EnrollmentServices:dNSHostName')
        Confidence = 'Inferred'; RelatedCA = $CAName; Stage = 'Probe'; Scope = 'Local' }
    $p = $base.Clone()
    $p += @{ Status = 'Information'; StatusCode = 'OK'; Message = ('Web Enrollment ({1}) answers on {0}.' -f $HostName, (Get-MspkiWebEnrollmentPath)); Evidence = [string[]]$ev
        Notes = 'Found at the standard Microsoft path on the host of an Enterprise CA. Inferred: any answer other than 404 means an application exists there; the page was not read. Web Enrollment is the old browser enrollment pages; Microsoft recommends HTTPS with Extended Protection for Authentication, or removing the role when nobody uses it.' }
    [void]$out.Add((New-MspkiFinding @p -EntityIds $EntityIds))
    if ($null -ne $sh -and $sh.WindowsSignIn) {
        $p = $base.Clone()
        $p.Target = (New-MspkiWebEnrollmentUrl -HostName $HostName -Scheme http)
        $p += @{ Status = 'Warning'; StatusCode = 'CONFIG_RISK'; Severity = 'Medium'
            Message = ('Web Enrollment on {0} offers Windows sign-in ({1}) over plain HTTP: an NTLM relay target (ESC8).' -f $HostName, ($sh.AuthSchemes -join ', '))
            Evidence = [string[]]$ev
            Notes = 'Over HTTP there is no TLS channel to bind the sign-in to, so Extended Protection cannot work: an attacker who makes a computer (for example a domain controller) authenticate to them can relay that NTLM sign-in to this page and get a certificate for that computer. Seen from the anonymous challenge only (no sign-in was attempted).'
            Remediation = ('On the CA host, in IIS Manager > Default Web Site > the {0} application: require SSL, and under Authentication > Windows Authentication > Advanced Settings set Extended Protection to Required; or remove the Web Enrollment role service if nobody uses it. Afterwards http://<host>{0} should answer 403 (SSL required) or 404.' -f (Get-MspkiWebEnrollmentPath)) }
        [void]$out.Add((New-MspkiFinding @p -EntityIds $EntityIds))
    }
    return $out.ToArray()
}

function Test-MspkiHostIdentity {
    <#
    .SYNOPSIS
    Compares what DNS, reverse DNS and TLS say about one host and returns the findings: missing reverse DNS (Information), reverse DNS
    naming another host or only the short name (Warning), an alias (CNAME) that leads to no address (Warning), and an alias the TLS
    certificate does not cover (Warning when an https URL uses it, else Information). Also one Information summary of the identity.
    .PARAMETER Identity
    The DNS identity record (Resolve-MspkiDnsIdentity / ConvertTo-MspkiDnsIdentity).
    .PARAMETER Tls
    TLS handshake results for this host (any of its names) from the probe cache.
    .PARAMETER HttpsNames
    Host names that https URLs in this run use (so an uncovered alias in that list is a real failure).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)]$Identity,
        [AllowEmptyCollection()][object[]]$Tls = @(),
        [AllowEmptyCollection()][string[]]$HttpServers = @(),
        [AllowEmptyCollection()][string[]]$HttpsNames = @(),
        [string[]]$EntityIds = @()
    )
    $out = New-Object System.Collections.ArrayList
    $h = ConvertTo-MspkiHostName $HostName
    $id = $Identity
    $conf = $(if ($id.Method -eq 'DnsClient') { 'Confirmed' } else { 'Inferred' })
    $how = $(if ($id.Method -eq 'DnsClient') { 'DNS only (Resolve-DnsName -DnsOnly: no NetBIOS, LLMNR or hosts file)' } else { '.NET name resolution (may include NetBIOS / LLMNR / hosts file: Inferred)' })
    $chain = @($id.Chain | Where-Object { $_ })
    $addrs = @(@($id.A) + @($id.AAAA) | Where-Object { $_ })
    $base = @{ Category = 'Identity'; Role = 'Computer'; Target = $h; Sources = @('DNS'); Confidence = $conf; Stage = 'Analysis'; Scope = 'Local' }
    $ev = New-Object System.Collections.ArrayList
    [void]$ev.Add(('Lookup: {0}' -f $how))
    if ($id.QueryName -and $id.QueryName -ne $h) { [void]$ev.Add(('Single-label name; looked up as {0}' -f $id.QueryName)) }
    if ($chain.Count -gt 1) { [void]$ev.Add(('Alias chain (CNAME): {0}' -f ($chain -join ' > '))) }
    [void]$ev.Add(('A: {0}; AAAA: {1}' -f $(if (@($id.A).Count) { @($id.A) -join ', ' } else { 'none' }), $(if (@($id.AAAA).Count) { @($id.AAAA) -join ', ' } else { 'none' })))
    foreach ($p in @($id.Ptr)) { [void]$ev.Add(('PTR {0}: {1}' -f $p.Address, $(if (@($p.Names).Count) { @($p.Names) -join ', ' } elseif ($p.Lookup -eq 'NoRecord') { 'no record' } else { ('not answered ({0})' -f $p.Error) }))) }
    foreach ($t in @($Tls)) {
        if ($t.Thumbprint) { [void]$ev.Add(('TLS {0}: {1}; DNS names {2}; issuer {3}' -f $t.Target, $t.Subject, $(if (@($t.DnsNames).Count) { @($t.DnsNames) -join ', ' } else { 'none' }), $t.Issuer)) }
        else { [void]$ev.Add(('TLS {0}: no certificate ({1})' -f $t.Target, $t.Code)) }
    }
    if (@($HttpServers).Count) { [void]$ev.Add(('HTTP Server header: {0}' -f (@($HttpServers) -join '; '))) }

    # An alias (CNAME) that leads nowhere.
    if ($chain.Count -gt 1 -and $addrs.Count -eq 0 -and $id.Lookup -eq 'NoRecord') {
        $p = $base.Clone()
        $p += @{ Status = 'Warning'; StatusCode = 'DNS_FAIL'; Severity = 'Medium'; Layers = @{ DnsStatus = 'Fail' }
            Message = ('{0} is an alias (CNAME) for {1}, but {1} has no address record: the alias leads nowhere.' -f $h, $chain[-1])
            Evidence = [string[]]$ev
            Notes = 'Every client that uses this name fails at the DNS step. Usually the target host was renamed or removed and the alias was left behind.'
            Remediation = ('Point the CNAME {0} at the host that now serves it, or remove it and the URLs that use it.' -f $h) }
        [void]$out.Add((New-MspkiFinding @p -EntityIds $EntityIds))
    }

    # Reverse DNS for every address.
    if ($addrs.Count -gt 0) {
        $accept = @(@($chain) + $h | Where-Object { $_ } | Select-Object -Unique)
        $first = @($accept | ForEach-Object { ($_ -split '\.')[0] } | Select-Object -Unique)
        $missing = @($id.Ptr | Where-Object { $_.Lookup -eq 'NoRecord' })
        $other = New-Object System.Collections.ArrayList
        $short = New-Object System.Collections.ArrayList
        foreach ($pr in @($id.Ptr | Where-Object { $_.Lookup -eq 'Found' })) {
            $names = @($pr.Names)
            if (@($names | Where-Object { $accept -contains $_ }).Count -gt 0) { continue }
            if (@($names | Where-Object { $_ -notlike '*.*' -and $first -contains $_ }).Count -gt 0) { [void]$short.Add($pr) } else { [void]$other.Add($pr) }
        }
        if ($missing.Count -gt 0) {
            $p = $base.Clone()
            $p += @{ Status = 'Information'; StatusCode = 'NOT_CONFIGURED'; Severity = 'Low'
                Message = ('No reverse DNS (PTR) record for {0} ({1}).' -f $h, ((@($missing) | ForEach-Object { $_.Address }) -join ', '))
                Evidence = [string[]]$ev
                Notes = 'Windows PKI does not need reverse DNS, so this is not a fault. It is flagged because tools and people that look an address up (logs, firewalls, some Kerberos clients, audits) will not get this host''s name back. If a name does come back on this computer, it came from NetBIOS or LLMNR, not DNS.'
                Remediation = 'Optional: create a PTR record for each address in the reverse lookup zone (or let the host register it, "Register this connection''s addresses in DNS" with PTR registration).' }
            [void]$out.Add((New-MspkiFinding @p -EntityIds $EntityIds))
        }
        if ($short.Count -gt 0) {
            $p = $base.Clone()
            $p += @{ Status = 'Warning'; StatusCode = 'CONFIG_MISMATCH'; Severity = 'Low'
                Message = ('Reverse DNS for {0} gives only the short name ({1}), not {2}.' -f ((@($short) | ForEach-Object { $_.Address }) -join ', '), ((@($short) | ForEach-Object { @($_.Names) }) -join ', '), $chain[-1])
                Evidence = [string[]]$ev
                Notes = 'A single-label PTR makes clients that canonicalise names through reverse DNS build the wrong name (for example a Kerberos service name), and logs show a name that is not unique in the forest.'
                Remediation = ('Change the PTR record(s) to the full name {0}.' -f $chain[-1]) }
            [void]$out.Add((New-MspkiFinding @p -EntityIds $EntityIds))
        }
        if ($other.Count -gt 0) {
            $p = $base.Clone()
            $p += @{ Status = 'Warning'; StatusCode = 'CONFIG_MISMATCH'; Severity = 'Low'
                Message = ('Reverse DNS for {0} names another host ({1}), not {2}.' -f ((@($other) | ForEach-Object { $_.Address }) -join ', '), ((@($other) | ForEach-Object { @($_.Names) }) -join ', '), ($accept -join ' / '))
                Evidence = [string[]]$ev
                Notes = 'Forward and reverse DNS disagree: either the address was reused by another host and an old PTR record was left behind, or the name points at the wrong address. Clients that check both directions (and people reading logs) will see a different host.'
                Remediation = 'Find out which host really owns the address; then correct the PTR record, or the A record of this name.' }
            [void]$out.Add((New-MspkiFinding @p -EntityIds $EntityIds))
        }
    }

    # Aliases (every name in the chain before the real host) that the TLS certificate of the host does not cover.
    $certs = @($Tls | Where-Object { $_.Thumbprint -and @($_.DnsNames).Count -gt 0 })
    if ($chain.Count -gt 1 -and $certs.Count -gt 0) {
        $probed = @($Tls | ForEach-Object { ConvertTo-MspkiHostName (([string]$_.Target) -replace ':\d+$', '') })
        foreach ($alias in @($chain[0..($chain.Count - 2)])) {
            if ($probed -contains $alias) { continue }    # a handshake with this very name was made; the endpoint check reports its name match
            foreach ($c in $certs) {
                if (Test-MspkiDnsNameCovered -Name $alias -Patterns @($c.DnsNames)) { continue }
                $used = @($HttpsNames) -contains $alias
                $p = $base.Clone()
                $p.Sources = @('DNS', 'TLS'); $p.Confidence = $(if ($used) { 'Confirmed' } else { 'Inferred' })
                $p += @{ StatusCode = 'TLS_NAME_MISMATCH'; Layers = @{ TlsStatus = $(if ($used) { 'Fail' } else { 'Warning' }) }
                    Status = $(if ($used) { 'Warning' } else { 'Information' }); Severity = $(if ($used) { 'Medium' } else { 'Low' })
                    Message = ('The alias {0} leads to {1}, but the TLS certificate served there ({2}) does not cover {0}.' -f $alias, $chain[-1], $c.Subject)
                    Evidence = [string[]](@($ev) + ('Certificate DNS names: {0}' -f (@($c.DnsNames) -join ', ')) + ('An https URL in this run uses {0}: {1}' -f $alias, $(if ($used) { 'yes' } else { 'no' })))
                    Notes = $(if ($used) { 'Clients that use the alias over HTTPS get a name-mismatch error and stop.' } else { 'No https URL found in this run uses the alias, so nothing fails today; a client that does will get a name-mismatch error.' })
                    Remediation = ('Add {0} to the Subject Alternative Name of the next certificate for {1}, or stop using the alias for HTTPS.' -f $alias, $chain[-1]) }
                [void]$out.Add((New-MspkiFinding @p -EntityIds $EntityIds))
                break
            }
        }
    }

    # Summary of the identity (always), so the report shows what each host is.
    $parts = @()
    if ($chain.Count -gt 1) { $parts += ('alias of {0}' -f $chain[-1]) }
    $parts += $(if ($addrs.Count) { ('addresses {0}' -f ($addrs -join ', ')) } elseif ($id.Lookup -eq 'NoRecord') { 'no DNS record' } else { ('DNS not answered ({0})' -f $id.Lookup) })
    $ptrNames = @(@($id.Ptr) | ForEach-Object { @($_.Names) } | Where-Object { $_ } | Select-Object -Unique)
    if ($addrs.Count) { $parts += $(if ($ptrNames.Count) { ('reverse DNS {0}' -f ($ptrNames -join ', ')) } else { 'no reverse DNS' }) }
    if ($certs.Count) { $parts += ('TLS certificate {0}' -f (@($certs | ForEach-Object { $_.Subject } | Select-Object -Unique) -join '; ')) }
    foreach ($t in @($Tls | Where-Object { -not $_.Thumbprint -and $_.ServerClosed })) { $parts += ('HTTPS on {0} closes the TLS handshake' -f $t.Target) }
    if (@($HttpServers).Count) { $parts += ('web server {0}' -f (@($HttpServers) -join '; ')) }
    $p = $base.Clone()
    $p.Sources = @('DNS', 'TLS', 'HTTP')
    $p += @{ Status = 'Information'; StatusCode = $(if ($addrs.Count) { 'OK' } elseif ($id.Lookup -eq 'Timeout') { 'TIMEOUT' } else { 'DNS_FAIL' }); Message = ('Identity of {0}: {1}.' -f $h, ($parts -join '; ')); Evidence = [string[]]$ev }
    if ($id.Lookup -notin @('Found', 'NoRecord')) { $p.Confidence = 'Unknown' }
    [void]$out.Add((New-MspkiFinding @p -EntityIds $EntityIds))
    return $out.ToArray()
}

function Add-MspkiHostIdentityToGraph {
    <#
    .SYNOPSIS
    Writes the identity of one host into the graph: properties (A, AAAA, PTR, alias chain, TLS certificates, Server header),
    DNS / TLS / HTTP observations, resolvesTo relations along the CNAME chain, and ExpectedMissing for a name or PTR with no record.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$HostId, $Identity = $null, [AllowEmptyCollection()][object[]]$Tls = @(), [AllowEmptyCollection()][object[]]$Http = @())
    $props = @{}
    if ($null -ne $Identity) {
        $conf = $(if ($Identity.Method -eq 'DnsClient') { 'Confirmed' } else { 'Inferred' })
        $chain = @($Identity.Chain | Where-Object { $_ })
        $addrs = @(@($Identity.A) + @($Identity.AAAA) | Where-Object { $_ })
        $props['DnsMethod'] = $Identity.Method
        $props['DnsLookup'] = $Identity.Lookup
        if (@($Identity.A).Count) { $props['A'] = @($Identity.A) }
        if (@($Identity.AAAA).Count) { $props['AAAA'] = @($Identity.AAAA) }
        if ($addrs.Count) { $props['Addresses'] = $addrs }
        if ($chain.Count -gt 1) { $props['AliasChain'] = $chain; $props['CanonicalName'] = $chain[-1] }
        if ($Identity.QueryName) { $props['QueryName'] = $Identity.QueryName }
        $props['Ptr'] = @(@($Identity.Ptr) | ForEach-Object { [ordered]@{ Address = $_.Address; Names = @($_.Names); Lookup = $_.Lookup } })
        if ($addrs.Count) {
            Add-MspkiObservation -EntityId $HostId -Kind 'Seen' -Source 'DNS' -Location $Identity.QueryName -Confidence $conf -Detail ('A/AAAA: {0}' -f ($addrs -join ', '))
        }
        elseif ($Identity.Lookup -eq 'NoRecord') {
            Add-MspkiObservation -EntityId $HostId -Kind 'ExpectedMissing' -Source 'DNS' -Location $Identity.QueryName -Confidence $conf -Detail 'No A or AAAA record'
        }
        foreach ($p in @($Identity.Ptr)) {
            $loc = Get-MspkiReverseName -Address $p.Address
            if ($p.Lookup -eq 'Found') { Add-MspkiObservation -EntityId $HostId -Kind 'Seen' -Source 'DNS' -Location $loc -Confidence $conf -Detail ('PTR: {0}' -f (@($p.Names) -join ', ')) }
            elseif ($p.Lookup -eq 'NoRecord') { Add-MspkiObservation -EntityId $HostId -Kind 'ExpectedMissing' -Source 'DNS' -Location $loc -Confidence $conf -Detail ('No PTR record for {0}' -f $p.Address) }
        }
        for ($i = 0; $i -lt $chain.Count - 1; $i++) {
            $from = Add-MspkiHostEntity -HostName $chain[$i]
            $to = Add-MspkiHostEntity -HostName $chain[$i + 1]
            Add-MspkiRelation -From $from -Type 'resolvesTo' -To $to -Source 'DNS:CNAME' -Confidence $conf
        }
        if ($chain.Count -gt 1 -and $addrs.Count) {
            [void](Add-MspkiEntity -Id (Get-MspkiEntityId -Type 'Host' -Key $chain[-1]) -Type 'Host' -Properties @{ A = @($Identity.A); AAAA = @($Identity.AAAA); Addresses = $addrs } -Overwrite)
        }
    }
    $tlsProps = New-Object System.Collections.ArrayList
    foreach ($t in @($Tls)) {
        $port = ([string]$t.Target -split ':')[-1]
        if ($t.Thumbprint) { [void]$tlsProps.Add([ordered]@{ Port = $port; Subject = [string]$t.Subject; Issuer = [string]$t.Issuer; DnsNames = @($t.DnsNames); Thumbprint = [string]$t.Thumbprint; NotAfter = [string]$t.NotAfter; Result = [string]$t.Code }) }
        else { [void]$tlsProps.Add([ordered]@{ Port = $port; Result = [string]$t.Code; Detail = $(if ($t.ServerClosed) { 'The server closed the TLS handshake before sending a certificate.' } else { [string]$t.Error }) }) }
        if ($t.Thumbprint) { Add-MspkiObservation -EntityId $HostId -Kind 'Seen' -Source 'Certificate' -Location ('tls://{0}' -f $t.Target) -Confidence 'Confirmed' -Detail ('{0} [{1}]; DNS names {2}' -f $t.Subject, $t.Thumbprint, (@($t.DnsNames) -join ', ')) }
    }
    if ($tlsProps.Count) { $props['TlsCertificates'] = $tlsProps.ToArray() }
    $servers = @($Http | Where-Object { $_.Server } | ForEach-Object { [string]$_.Server } | Select-Object -Unique)
    if ($servers.Count) { $props['HttpServer'] = $servers }
    foreach ($x in @($Http | Where-Object { $_.Server })) { Add-MspkiObservation -EntityId $HostId -Kind 'Seen' -Source 'HTTP' -Location $x.Url -Confidence 'Confirmed' -Detail ('HTTP {0}; Server: {1}' -f $x.HttpStatus, $x.Server) }
    [void](Add-MspkiEntity -Id $HostId -Type 'Host' -Properties $props -Overwrite)
}

function Invoke-MspkiEndpointIdentityAnalysis {
    <#
    .SYNOPSIS
    Stage Analysis:Identity. Probes Web Enrollment on the CA hosts, then records the identity of every host in the graph and returns the findings.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Inventory, [int]$TimeoutSeconds = 5, [switch]$SkipNetwork)
    $out = New-Object System.Collections.ArrayList
    $ms = [Math]::Max(1000, $TimeoutSeconds * 1000)
    Add-MspkiInventoryToEntityGraph -Inventory $Inventory
    $ctx = $Inventory.AdContext

    # Web Enrollment on proven PKI hosts (Enterprise CA hosts), standard path, anonymous, body not read, no redirects followed.
    $cas = @($Inventory.EnterpriseCAs | Where-Object { $null -ne $_ -and $_.DnsHostName })
    $absent = New-Object System.Collections.ArrayList
    if (-not $SkipNetwork) {
        foreach ($h in @($cas | ForEach-Object { ([string]$_.DnsHostName).ToLowerInvariant() } | Select-Object -Unique)) {
            if (Test-MspkiCancelled) { break }
            $caNames = @($cas | Where-Object { ([string]$_.DnsHostName).ToLowerInvariant() -eq $h } | ForEach-Object { $_.Name })
            $http = Invoke-MspkiHttpGet -Url (New-MspkiWebEnrollmentUrl -HostName $h -Scheme http) -TimeoutMs $ms -MaxRedirects 0 -DiscardBody
            $https = $null
            $tcp = Test-MspkiTcpPort -HostName $h -Port 443 -TimeoutMs $ms
            if ($tcp.Status -eq 'Pass') { $https = Invoke-MspkiHttpGet -Url (New-MspkiWebEnrollmentUrl -HostName $h -Scheme https) -TimeoutMs $ms -MaxRedirects 0 -DiscardBody }
            $hid = Add-MspkiHostEntity -HostName $h
            $states = @(@(@($http, (Get-MspkiWebEnrollmentState -Http $http)), @($https, (Get-MspkiWebEnrollmentState -Http $https))) | Where-Object { $null -ne $_[1] })
            if ($states.Count -eq 0) {
                $why = @(@($http, $https) | Where-Object { $null -ne $_ } | ForEach-Object {
                    '{0}: {1}' -f $_.Url, $(if ([int]$_.HttpStatus -eq 404) { 'HTTP 404 (no such application)' } else { ('no web server answered ({0})' -f $_.Code) }) })
                if ($null -eq $https) { $why += ('{0}: not requested, TCP 443 {1}' -f (New-MspkiWebEnrollmentUrl -HostName $h -Scheme https), $tcp.StatusCode) }
                [void]$absent.Add([pscustomobject]@{ Host = $h; Why = @($why); Answered = @(@($http, $https) | Where-Object { $null -ne $_ -and [int]$_.HttpStatus -gt 0 }).Count -gt 0 })
                continue
            }
            $eid = Add-MspkiEndpointEntity -Url (New-MspkiWebEnrollmentUrl -HostName $h -Scheme http) -Kind 'WebEnrollment'
            $sid = Add-MspkiEntity -Type 'Service' -Key ('webenrollment:' + $eid) -Name ('Web Enrollment on {0}' -f $h) -Properties @{
                Kind = 'WebEnrollment'; Url = (New-MspkiWebEnrollmentUrl -HostName $h -Scheme http); Answers = @($states | ForEach-Object { '{0}: HTTP {1}, {2}' -f $_[0].Url, $_[1].HttpStatus, $_[1].Meaning }) }
            foreach ($s in $states) { Add-MspkiObservation -EntityId $sid -Kind 'Seen' -Source 'HTTP' -Location $s[0].Url -Confidence 'Inferred' -Detail ('HTTP {0}: {1} (standard path on a CA host)' -f $s[1].HttpStatus, $s[1].Meaning) }
            Add-MspkiRelation -From $eid -Type 'servedBy' -To $sid -Source 'HTTP:StandardPath' -Confidence 'Inferred'
            Add-MspkiRelation -From $sid -Type 'hostedOn' -To $hid -Source 'HTTP:StandardPath'
            foreach ($cn in $caNames) { $caId = Get-MspkiCAIdByName -Name $cn; if ($caId) { Add-MspkiRelation -From $sid -Type 'enrollsVia' -To $caId -Source 'HTTP:StandardPath' -Confidence 'Inferred' } }
            foreach ($f in (Test-MspkiWebEnrollment -HostName $h -Http $http -Https $https -CAName ($caNames -join ', ') -EntityIds @($sid, $hid))) { [void]$out.Add($f) }
        }
        if ($absent.Count -gt 0) {
            $names = @($absent | ForEach-Object { $_.Host })
            $silent = @($absent | Where-Object { -not $_.Answered } | ForEach-Object { $_.Host })
            $msg = 'Web Enrollment ({1}) was not found on {0}.' -f ($names -join ', '), (Get-MspkiWebEnrollmentPath)
            if ($silent.Count -gt 0) { $msg += (' No web server answered at all on {0}.' -f ($silent -join ', ')) }
            [void]$out.Add((New-MspkiFinding -Category 'WebEnrollment' -Role 'WebEnrollmentEndpoint' -Target ($names -join ', ') -Status 'Information' -StatusCode 'NOT_DISCOVERED' `
                -Confidence 'Inferred' -Sources @('HTTP:StandardPath') -Stage 'Probe' -Scope 'Local' -EntityIds @($names | ForEach-Object { Get-MspkiEntityId -Type 'Host' -Key $_ }) `
                -Message $msg -Evidence @($absent | ForEach-Object { @($_.Why) }) `
                -Notes 'Only the standard path on the Enterprise CA hosts was tried. Web Enrollment on another server (not named anywhere in AD) cannot be found without scanning, which this tool never does. When no web server answers, a firewall may also hide it from this computer.'))
        }
    }

    # Identity of every host in the graph (names that came from AD, CA properties, certificates, URLs or this computer).
    $hosts = @(Get-MspkiEntityList -Type 'Host' | Sort-Object { $_.Id })
    $suffixes = @(@($(if ($null -ne $ctx) { $ctx.Domain }), $(if ($null -ne $ctx) { @($ctx.ForestDomains) })) | ForEach-Object { $_ } | Where-Object { $_ } | Select-Object -Unique)
    $ids = @{}
    if (-not $SkipNetwork -and $hosts.Count -gt 0) {
        foreach ($r in (Resolve-MspkiDnsIdentity -HostName @($hosts | ForEach-Object { $_.Name }) -TimeoutMs $ms -DnsSuffix $suffixes)) { if ($null -ne $r) { $ids[$r.Target] = $r } }
    }
    $tlsAll = @(Get-MspkiProbeCacheEntryList -Prefix 'tls|')
    $httpAll = New-Object System.Collections.ArrayList
    foreach ($x in @(Get-MspkiProbeCacheEntryList -Prefix 'http|')) {
        foreach ($hop in @($x.Hops)) { if ($hop.Server -or $hop.HttpStatus) { [void]$httpAll.Add([pscustomobject]@{ Url = [string]$hop.Url; HttpStatus = $hop.HttpStatus; Server = [string]$hop.Server }) } }
    }
    $httpsNames = @(Get-MspkiEntityList -Type 'Endpoint' | ForEach-Object { [string]$_.Properties['Url'] } | Where-Object { $_ -like 'https://*' } |
        ForEach-Object { $u = $null; if ([System.Uri]::TryCreate($_, [System.UriKind]::Absolute, [ref]$u)) { ConvertTo-MspkiHostName $u.Host } } | Select-Object -Unique)
    foreach ($e in $hosts) {
        if (Test-MspkiCancelled) { break }
        $h = $e.Name
        $id = $ids[$h]
        $names = @($h)
        if ($null -ne $id) { $names = @(@($h) + @($id.Chain) | Where-Object { $_ } | Select-Object -Unique) }
        $tls = @($tlsAll | Where-Object { $names -contains (ConvertTo-MspkiHostName (([string]$_.Target) -replace ':\d+$', '')) })
        $http = @($httpAll | Where-Object { $u = $null; [System.Uri]::TryCreate($_.Url, [System.UriKind]::Absolute, [ref]$u) -and $names -contains (ConvertTo-MspkiHostName $u.Host) })
        Add-MspkiHostIdentityToGraph -HostId $e.Id -Identity $id -Tls $tls -Http $http
        # A single-label name (for example in a certificate SAN) that DNS completes to a host already in the graph is that host:
        # link the two and report the identity once, on the full name.
        if ($null -ne $id -and $h -notlike '*.*' -and $id.QueryName -and $id.QueryName -ne $h -and @($id.A).Count + @($id.AAAA).Count -gt 0) {
            $full = Get-MspkiEntityId -Type 'Host' -Key $id.QueryName
            if ((Test-MspkiEntity -Id $full) -and @($hosts | Where-Object { $_.Id -eq $full }).Count -gt 0) {
                Add-MspkiRelation -From $e.Id -Type 'resolvesTo' -To $full -Source 'DNS:SuffixSearch' -Confidence $(if ($id.Method -eq 'DnsClient') { 'Confirmed' } else { 'Inferred' })
                continue
            }
        }
        if ($null -ne $id) {
            $servers = @($http | Where-Object { $_.Server } | ForEach-Object { $_.Server } | Select-Object -Unique)
            foreach ($f in (Test-MspkiHostIdentity -HostName $h -Identity $id -Tls $tls -HttpServers $servers -HttpsNames $httpsNames -EntityIds @($e.Id))) { [void]$out.Add($f) }
        }
    }
    return $out.ToArray()
}
