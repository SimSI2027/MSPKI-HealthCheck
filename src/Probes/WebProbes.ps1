# HTTP, TLS and LDAP-URL probes for leads. All are read-only, time-limited and cached.
# HTTP: anonymous GET only (no credentials are ever sent), redirects followed manually with every hop
# recorded, response size capped. TLS: one handshake, the server certificate and errors are recorded,
# nothing is sent over the connection.

$script:MspkiHttpUserAgent = 'MSPKI-HealthCheck'
# HTTP probes connect directly, without a proxy: the system proxy is not part of discovery, "automatically detect
# settings" could start WPAD discovery, and a session proxy may carry credentials. -UseSystemProxy opts in; the proxy
# is then taken from the system settings WITHOUT credentials, so a proxy that wants authentication answers 407.
$script:MspkiWebSettings = @{ UseSystemProxy = $false }

function Set-MspkiWebProbeOption {
    <#
    .SYNOPSIS
    Sets the run-wide options of the web probes (in memory only). UseSystemProxy is off unless -UseSystemProxy is given.
    #>
    [CmdletBinding()]
    param([switch]$UseSystemProxy)
    $script:MspkiWebSettings.UseSystemProxy = [bool]$UseSystemProxy
}

function Get-MspkiWebProbeOption {
    <#
    .SYNOPSIS
    Returns the run-wide options of the web probes: { UseSystemProxy; ProxyMode (text for the evidence) }.
    #>
    [CmdletBinding()]
    param()
    $mode = 'none (direct connection)'
    if ($script:MspkiWebSettings.UseSystemProxy) { $mode = 'system proxy settings, without credentials (-UseSystemProxy)' }
    return [pscustomobject]@{ UseSystemProxy = [bool]$script:MspkiWebSettings.UseSystemProxy; ProxyMode = $mode }
}

function Get-MspkiTlsClientProtocol {
    <#
    .SYNOPSIS
    The TLS versions the probes offer: TLS 1.2, 1.1 and 1.0, plus 1.3 where this .NET Framework has that enum value.
    They are passed explicitly because the .NET Framework default can be SSL 3 and TLS 1.0 only, which would make every
    TLS 1.2-only server look broken. Offering old versions only lets the probe read the server certificate.
    #>
    [CmdletBinding()]
    param([switch]$WithoutTls13)
    $e = [System.Security.Authentication.SslProtocols]
    $p = $e::Tls12 -bor $e::Tls11 -bor $e::Tls
    if (-not $WithoutTls13 -and ([enum]::GetNames($e) -contains 'Tls13')) { $p = $p -bor ($e.GetEnumValues() | Where-Object { $_.ToString() -eq 'Tls13' } | Select-Object -First 1) }
    return $p
}

function Enable-MspkiClientTlsProtocol {
    <#
    .SYNOPSIS
    Makes sure that the process-wide TLS setting of the .NET Framework (ServicePointManager.SecurityProtocol, in memory only)
    includes TLS 1.2, 1.1 and 1.0 for the HTTP probes, and returns the state for Restore-MspkiClientTlsProtocol. When the setting is
    SystemDefault (0) the operating system chooses and nothing is changed.
    #>
    [CmdletBinding()]
    param()
    $prev = [System.Net.ServicePointManager]::SecurityProtocol
    $state = [pscustomobject]@{ Previous = $prev; Changed = $false; Current = $prev }
    try {
        if ([int]$prev -ne 0) {
            $want = [int](Get-MspkiTlsClientProtocol -WithoutTls13)
            $new = [System.Net.SecurityProtocolType]([int]$prev -bor $want)
            if ($new -ne $prev) { [System.Net.ServicePointManager]::SecurityProtocol = $new; $state.Changed = $true; $state.Current = $new }
        }
    }
    catch { Write-MspkiLog -Level Warning -Message ('The TLS protocol setting of the HTTP requests could not be changed: {0}' -f $_.Exception.Message) }
    return $state
}

function Restore-MspkiClientTlsProtocol {
    <#
    .SYNOPSIS
    Puts the process-wide TLS setting back to what Enable-MspkiClientTlsProtocol found.
    #>
    [CmdletBinding()]
    param([AllowNull()]$State)
    if ($null -eq $State -or -not $State.Changed) { return }
    try { [System.Net.ServicePointManager]::SecurityProtocol = $State.Previous } catch { }
}

function Get-MspkiWebException {
    [CmdletBinding()]
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($null -ne $e -and -not ($e -is [System.Net.WebException])) { $e = $e.InnerException }
    return $e
}

function Read-MspkiResponseBody {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Response, [int]$MaxBytes)
    $stream = $Response.GetResponseStream()
    $ms = New-Object System.IO.MemoryStream
    try {
        $buf = New-Object byte[] 65536
        while ($true) {
            $n = $stream.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $ms.Write($buf, 0, $n)
            if ($ms.Length -gt $MaxBytes) { return [pscustomobject]@{ Bytes = $null; TooLarge = $true } }
        }
        return [pscustomobject]@{ Bytes = $ms.ToArray(); TooLarge = $false }
    }
    finally { $ms.Dispose(); $stream.Dispose() }
}

function Invoke-MspkiHttpGet {
    <#
    .SYNOPSIS
    Anonymous HTTP(S) GET with a timeout, manual redirects (max 5 hops) and a size cap.

    .OUTPUTS
    { Url, FinalUrl, HttpStatus (int, 0 when no response), Code (OK / HTTP_400 / HTTP_401_403 / HTTP_404 / HTTP_500 /
      HTTP_OTHER (any other status) / HTTP_REDIRECT / CONTENT_WRONG_TYPE (response too large) / TIMEOUT / RETRIEVAL_FAIL /
      TLS_* / OBJECT_EXPIRED (the TLS problem found by a separate handshake) / DNS_FAIL / TCP_FAIL), Redirected, Hops,
      ContentType, Bytes, Error, ElapsedMs, ProxyMode }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000,
        [ValidateRange(1024, 104857600)][int]$MaxBytes = 10485760,
        [ValidateRange(0, 10)][int]$MaxRedirects = 5,
        [switch]$DiscardBody
    )
    $opt = Get-MspkiWebProbeOption
    $key = 'http|{0}|{1}' -f [int]$opt.UseSystemProxy, $Url
    if ($DiscardBody) { $key += '|nobody' }
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text ('HTTP {0}' -f $Url)
    $r = [pscustomobject][ordered]@{
        Url = $Url; FinalUrl = $Url; HttpStatus = 0; Code = 'RETRIEVAL_FAIL'; Redirected = $false
        Hops = (New-Object System.Collections.ArrayList); ContentType = ''; Bytes = $null; Error = ''; ElapsedMs = 0; FromCache = $false
        ProxyMode = $opt.ProxyMode; Server = ''; AuthSchemes = @()
    }
    $sysProxy = $null
    if ($opt.UseSystemProxy) { $sysProxy = [System.Net.WebRequest]::GetSystemWebProxy() }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $current = $Url
    for ($hop = 0; $hop -le $MaxRedirects; $hop++) {
        $resp = $null
        try {
            $req = [System.Net.HttpWebRequest][System.Net.WebRequest]::Create($current)
            $req.Method = 'GET'
            $req.Timeout = $TimeoutMs
            $req.ReadWriteTimeout = $TimeoutMs
            $req.AllowAutoRedirect = $false
            $req.UseDefaultCredentials = $false
            $req.Credentials = $null
            if ($opt.UseSystemProxy) { $req.Proxy = $sysProxy } else { $req.Proxy = $null }
            $req.PreAuthenticate = $false
            $req.KeepAlive = $false
            $req.UserAgent = '{0}/{1}' -f $script:MspkiHttpUserAgent, $script:MspkiToolVersion
            try { $resp = $req.GetResponse() }
            catch {
                $we = Get-MspkiWebException $_
                if ($null -ne $we -and $null -ne $we.Response) { $resp = $we.Response }
                else {
                    $status = ''
                    if ($null -ne $we) { $status = [string]$we.Status }
                    $r.Error = (Get-MspkiErrorInfo $_).Message
                    switch ($status) {
                        'Timeout' { $r.Code = 'TIMEOUT' }
                        'NameResolutionFailure' { $r.Code = 'DNS_FAIL' }
                        'ConnectFailure' { $r.Code = 'TCP_FAIL' }
                        'TrustFailure' { $r.Code = Get-MspkiTrustFailureCode -Url $current -TimeoutMs $TimeoutMs }
                        'SecureChannelFailure' { $r.Code = 'TLS_HANDSHAKE_FAIL' }
                        default { $r.Code = 'RETRIEVAL_FAIL' }
                    }
                    [void]$r.Hops.Add([pscustomobject]@{ Url = $current; HttpStatus = 0; Location = ''; Error = ('{0} {1}' -f $status, $r.Error).Trim() })
                    break
                }
            }
            $sc = [int]$resp.StatusCode
            $loc = [string]$resp.Headers['Location']
            # Identity facts only (D2): the Server header (capped) and the names of the offered sign-in schemes, never their tokens.
            $srv = [string]$resp.Headers['Server']
            if ($srv) { $r.Server = $srv.Substring(0, [Math]::Min(200, $srv.Length)) }
            $wa = $resp.Headers.GetValues('WWW-Authenticate')
            if ($null -ne $wa) { $r.AuthSchemes = @($wa | ForEach-Object { ([string]$_ -split '\s+')[0] } | Where-Object { $_ } | Select-Object -Unique) }
            [void]$r.Hops.Add([pscustomobject]@{ Url = $current; HttpStatus = $sc; Location = $loc; Error = ''; Server = $r.Server })
            if ($sc -ge 300 -and $sc -lt 400 -and $loc) {
                $r.Redirected = $true
                $current = (New-Object System.Uri((New-Object System.Uri($current)), $loc)).AbsoluteUri
                if ($hop -eq $MaxRedirects) { $r.Code = 'HTTP_REDIRECT'; $r.Error = ('More than {0} redirects.' -f $MaxRedirects) }
                continue
            }
            $r.FinalUrl = $current
            $r.HttpStatus = $sc
            $r.ContentType = [string]$resp.ContentType
            if ($sc -eq 200) {
                if ($DiscardBody) { $r.Code = 'OK' }   # the body is never read (used for pages that must not be read)
                else {
                    $body = Read-MspkiResponseBody -Response $resp -MaxBytes $MaxBytes
                    if ($body.TooLarge) { $r.Code = 'CONTENT_WRONG_TYPE'; $r.Error = ('Response larger than {0} bytes; not read.' -f $MaxBytes) }
                    else { $r.Bytes = $body.Bytes; $r.Code = 'OK' }
                }
            }
            elseif ($sc -eq 400) { $r.Code = 'HTTP_400' }
            elseif ($sc -eq 401 -or $sc -eq 403) { $r.Code = 'HTTP_401_403' }
            elseif ($sc -eq 404) { $r.Code = 'HTTP_404' }
            elseif ($sc -ge 500) { $r.Code = 'HTTP_500' }
            else { $r.Code = 'HTTP_OTHER' }   # 1xx, 2xx other than 200, 3xx without a Location, 405, 407, 410 and so on
            break
        }
        finally { if ($null -ne $resp) { $resp.Close() } }
    }
    $r.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('HTTP GET {0}: {1} {2} ({3} hop(s), {4} ms, proxy: {5}) {6}' -f $Url, $r.HttpStatus, $r.Code, $r.Hops.Count, $r.ElapsedMs, $r.ProxyMode, $r.Error).Trim()
    return $r
}

function Get-MspkiTrustFailureCode {
    <#
    .SYNOPSIS
    Names the real TLS problem behind an HTTP request that failed with a trust failure. The request API reports an untrusted
    root, a name mismatch, an expired or a revoked certificate all as one error, so one separate handshake to the host of
    the failing hop (cached) tells them apart. When that handshake finds nothing wrong, the code is TLS_HANDSHAKE_FAIL.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Url, [ValidateRange(100, 600000)][int]$TimeoutMs = 5000)
    $u = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$u)) { return 'TLS_HANDSHAKE_FAIL' }
    $tls = Test-MspkiTlsEndpoint -HostName $u.Host -Port $u.Port -TimeoutMs $TimeoutMs
    if ($tls.Code -in @('TLS_UNTRUSTED_ROOT', 'TLS_PARTIAL_CHAIN', 'TLS_NAME_MISMATCH', 'OBJECT_EXPIRED')) { return $tls.Code }
    return 'TLS_HANDSHAKE_FAIL'
}

function Test-MspkiTlsEndpoint {
    <#
    .SYNOPSIS
    One TLS handshake with a timeout. Records the server certificate, name match and chain errors as
    separate facts. Code: OK, TLS_NAME_MISMATCH, TLS_UNTRUSTED_ROOT, TLS_PARTIAL_CHAIN, OBJECT_EXPIRED,
    TLS_HANDSHAKE_FAIL, TCP_FAIL or TIMEOUT.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [ValidateRange(1, 65535)][int]$Port = 443,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000
    )
    $h = ConvertTo-MspkiHostName $HostName
    $key = 'tls|{0}|{1}' -f $h, $Port
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text ('TLS {0}:{1}' -f $h, $Port)
    $r = [pscustomobject][ordered]@{
        Probe = 'TLS'; Target = ('{0}:{1}' -f $h, $Port); Status = 'Fail'; Code = 'TLS_HANDSHAKE_FAIL'; Protocol = ''
        NameMatch = $null; ChainErrors = @(); Subject = ''; Issuer = ''; Thumbprint = ''; NotAfter = ''; Error = ''; ElapsedMs = 0; FromCache = $false
        DnsNames = @(); ServerClosed = $false
        OfferedProtocols = ''
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tcp = Test-MspkiTcpPort -HostName $h -Port $Port -TimeoutMs $TimeoutMs
    if ($tcp.Status -ne 'Pass') {
        $r.Code = $tcp.StatusCode; $r.Error = $tcp.Error
    }
    else {
        # Up to two attempts: first with every protocol this .NET Framework knows (TLS 1.3 included where the enum has
        # it), then, only when the framework rejects that set, without TLS 1.3.
        $attempts = @((Get-MspkiTlsClientProtocol))
        $legacy = Get-MspkiTlsClientProtocol -WithoutTls13
        if ($attempts[0] -ne $legacy) { $attempts += $legacy }
        $attemptNo = 0
        foreach ($protocols in $attempts) {
        $attemptNo++
        $r.OfferedProtocols = [string]$protocols
        $client = New-Object System.Net.Sockets.TcpClient
        $ssl = $null
        $state = @{ Errors = $null; Chain = @(); Cert = $null }
        $retry = $false
        try {
            $ar = $client.BeginConnect($h, $Port, $null, $null)
            if (-not (Wait-MspkiAsyncResult -AsyncResult $ar -TimeoutMs $TimeoutMs)) { throw (New-Object System.TimeoutException('TCP connect timed out.')) }
            $client.EndConnect($ar)
            $ns = $client.GetStream()
            $ns.ReadTimeout = $TimeoutMs
            $ns.WriteTimeout = $TimeoutMs
            # Inspection only: the callback records what Windows reports and lets the handshake finish so the
            # certificate can be read. No data is sent over the connection.
            $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
                param($sender, $cert, $chain, $errors)
                $state.Errors = $errors
                if ($null -ne $cert) { $state.Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert) }
                if ($null -ne $chain) { $state.Chain = @($chain.ChainStatus | ForEach-Object { [string]$_.Status }) }
                return $true
            }
            $ssl = New-Object System.Net.Security.SslStream($ns, $false, $cb)
            # No client certificate, no revocation check by this call, and the protocol set is explicit (see Get-MspkiTlsClientProtocol).
            $ssl.AuthenticateAsClient($h, $null, $protocols, $false)
            $r.Protocol = [string]$ssl.SslProtocol
            $errs = [System.Net.Security.SslPolicyErrors]$state.Errors
            $r.NameMatch = (($errs -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -eq 0)
            $r.ChainErrors = @($state.Chain | Where-Object { $_ -and $_ -ne 'NoError' })
            if ($null -ne $state.Cert) {
                $r.Subject = $state.Cert.Subject; $r.Issuer = $state.Cert.Issuer; $r.Thumbprint = $state.Cert.Thumbprint
                $r.NotAfter = $state.Cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                $r.DnsNames = @(Get-MspkiCertificateDnsName -Certificate $state.Cert)
            }
            if ($r.ChainErrors -contains 'UntrustedRoot') { $r.Code = 'TLS_UNTRUSTED_ROOT' }
            elseif ($r.ChainErrors -contains 'PartialChain') { $r.Code = 'TLS_PARTIAL_CHAIN' }
            elseif ($r.ChainErrors -contains 'NotTimeValid') { $r.Code = 'OBJECT_EXPIRED' }
            elseif ($r.ChainErrors.Count -gt 0) { $r.Code = 'TLS_HANDSHAKE_FAIL' }
            elseif (-not $r.NameMatch) { $r.Code = 'TLS_NAME_MISMATCH' }
            else { $r.Code = 'OK'; $r.Status = 'Pass' }
        }
        catch {
            if ($_.Exception -is [System.OperationCanceledException]) { throw }
            $ei = Get-MspkiErrorInfo $_
            $r.Error = $ei.Message
            if ($ei.Class -eq 'Timeout' -or $ei.ExceptionType -like '*IOException') { $r.Code = 'TLS_HANDSHAKE_FAIL' }
            if ($ei.Class -eq 'Timeout') { $r.Code = 'TIMEOUT' }
            # The server reset or closed the connection during the handshake, before any certificate came back (TCP was open).
            $sock = $false; $io = $false; $e = $_.Exception
            while ($null -ne $e) {
                if ($e -is [System.Net.Sockets.SocketException] -and $e.SocketErrorCode -in @([System.Net.Sockets.SocketError]::ConnectionReset, [System.Net.Sockets.SocketError]::ConnectionAborted)) { $sock = $true }
                if ($e -is [System.IO.IOException]) { $io = $true }
                $e = $e.InnerException
            }
            if ($ei.Class -ne 'Timeout' -and $null -eq $state.Cert -and ($sock -or $io)) { $r.ServerClosed = $true }
            # This .NET Framework rejects the protocol set itself (for example TLS 1.3 on an older Windows): try once without it.
            if ($attemptNo -lt $attempts.Count -and ($ei.Class -eq 'Unsupported' -or $ei.ExceptionType -like '*ArgumentException')) { $retry = $true; $r.Error = '' }
        }
        finally {
            if ($null -ne $ssl) { $ssl.Dispose() }
            $client.Close()
        }
        if (-not $retry) { break }
        }
    }
    $r.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('TLS {0}: {1} {2} (offered: {3}) {4} ms {5}' -f $r.Target, $r.Code, $r.Protocol, $r.OfferedProtocols, $r.ElapsedMs, $r.Error).Trim()
    return $r
}

function ConvertFrom-MspkiLdapUrl {
    <#
    .SYNOPSIS
    Splits ldap://host/DN?attribute?scope?filter (RFC 4516). Host may be empty (serverless).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Url)
    $m = [regex]::Match($Url, '^(?i)ldaps?://([^/]*)/(.*)$')
    if (-not $m.Success) { throw ('Not an LDAP URL: {0}' -f $Url) }
    $parts = $m.Groups[2].Value -split '\?'
    $attr = ''
    if ($parts.Count -gt 1) { $attr = ($parts[1] -split ',')[0] -replace ';binary$', '' }
    $scope = 'base'
    if ($parts.Count -gt 2 -and $parts[2]) { $scope = $parts[2].ToLowerInvariant() }
    $filter = '(objectClass=*)'
    if ($parts.Count -gt 3 -and $parts[3]) {
        $filter = [System.Uri]::UnescapeDataString($parts[3])
        if (-not $filter.StartsWith('(')) { $filter = '(' + $filter + ')' }
    }
    return [pscustomobject]@{
        Host      = ConvertTo-MspkiHostName ([System.Uri]::UnescapeDataString($m.Groups[1].Value))
        DN        = [System.Uri]::UnescapeDataString($parts[0])
        Attribute = $attr
        Scope     = $scope
        Filter    = $filter
    }
}

function Get-MspkiLdapUrlContent {
    <#
    .SYNOPSIS
    Reads the attribute an LDAP URL points to (base search). Code: OK, PUBLICATION_FAIL (object or value
    missing), PERMISSION_DENIED, TIMEOUT, RETRIEVAL_FAIL, or NOT_APPLICABLE with Contacted = $false when the URL names a
    host that may not be contacted (see Test-MspkiLdapHostAllowed): nothing is sent to such a host.

    .DESCRIPTION
    A directory bind authenticates with the Windows credentials of the user running the tool, so a host named in an LDAP URL
    is contacted only when it is the selected domain controller or in one of this forest's own DNS domains (-LocalDomains),
    and never with -SkipNetwork. A serverless URL goes to the selected domain controller (-DefaultServer).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$DefaultServer = '',
        [int]$TimeoutSeconds = 15,
        [string[]]$LocalDomains = @(),
        [switch]$SkipNetwork,
        # Used when the URL names no attribute (valid: Windows then reads the attribute that holds the object type it wants).
        [string]$DefaultAttribute = ''
    )
    $key = 'ldapurl|' + $Url + '|' + $DefaultAttribute
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { return $cached }
    Assert-MspkiNotCancelled
    Send-MspkiProgress -Kind 'Target' -Text ('LDAP {0}' -f $Url)
    $r = [pscustomobject][ordered]@{ Url = $Url; Server = ''; Code = 'RETRIEVAL_FAIL'; Bytes = $null; ValueCount = 0; Error = ''; ElapsedMs = 0; Contacted = $true; Attribute = ''; AttributeDefaulted = $false }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $p = ConvertFrom-MspkiLdapUrl -Url $Url
        $r.Server = $p.Host
        $allowed = Test-MspkiLdapHostAllowed -HostName $p.Host -DefaultServer $DefaultServer -LocalDomains $LocalDomains -SkipNetwork:$SkipNetwork
        if (-not $allowed.Allowed) {
            $r.Contacted = $false; $r.Code = 'NOT_APPLICABLE'; $r.Error = ('Not contacted: {0}.' -f $allowed.Reason)
            Set-MspkiProbeCacheEntry -Key $key -Value $r
            Write-MspkiLog -Message ('LDAP {0}: not contacted ({1})' -f $Url, $allowed.Reason)
            return $r
        }
        if (-not $r.Server) { $r.Server = $DefaultServer }
        if (-not $p.Attribute -and $DefaultAttribute) { $p.Attribute = $DefaultAttribute; $r.AttributeDefaulted = $true }
        $r.Attribute = $p.Attribute
        if (-not $p.Attribute) { throw 'The LDAP URL names no attribute and no default is known for this kind of object.' }
        $recs = @(Get-MspkiLdapObject -Server $r.Server -BaseDN $p.DN -Scope Base -Filter $p.Filter -Properties @($p.Attribute) -TimeoutSeconds $TimeoutSeconds)
        if ($recs.Count -eq 0) { $r.Code = 'PUBLICATION_FAIL'; $r.Error = 'The object does not match the URL filter.' }
        else {
            $vals = Get-MspkiLdapValues -Record $recs[0] -Name $p.Attribute
            $r.ValueCount = $vals.Count
            if ($vals.Count -eq 0 -or $null -eq $vals[0] -or ([byte[]]$vals[0]).Length -eq 0) {
                $r.Code = 'PUBLICATION_FAIL'; $r.Error = ('The object has no {0} value.' -f $p.Attribute)
            }
            else { $r.Bytes = [byte[]]$vals[0]; $r.Code = 'OK' }
        }
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        $r.Error = $ei.Message
        switch ($ei.Class) {
            'NotFound' { $r.Code = 'PUBLICATION_FAIL' }
            'PermissionDenied' { $r.Code = 'PERMISSION_DENIED' }
            'Timeout' { $r.Code = 'TIMEOUT' }
            default { $r.Code = 'RETRIEVAL_FAIL' }
        }
    }
    $r.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('LDAP {0} (server {1}): {2} {3} ms {4}' -f $Url, $r.Server, $r.Code, $r.ElapsedMs, $r.Error).Trim()
    return $r
}
