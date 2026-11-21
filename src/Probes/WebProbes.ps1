# HTTP, TLS and LDAP-URL probes for leads. All are read-only, time-limited and cached.
# HTTP: anonymous GET only (no credentials are ever sent), redirects followed manually with every hop
# recorded, response size capped. TLS: one handshake, the server certificate and errors are recorded,
# nothing is sent over the connection.

$script:MspkiHttpUserAgent = 'MSPKI-HealthCheck'

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
    { Url, FinalUrl, HttpStatus (int, 0 when no response), Code (OK / HTTP_* / TIMEOUT / RETRIEVAL_FAIL /
      TLS_HANDSHAKE_FAIL / DNS_FAIL / TCP_FAIL), Redirected, Hops, ContentType, Bytes, Error, ElapsedMs }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000,
        [ValidateRange(1024, 104857600)][int]$MaxBytes = 10485760,
        [ValidateRange(0, 10)][int]$MaxRedirects = 5,
        [switch]$DiscardBody
    )
    $key = 'http|' + $Url
    if ($DiscardBody) { $key += '|nobody' }
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { $copy = $cached.psobject.Copy(); $copy.FromCache = $true; return $copy }
    $r = [pscustomobject][ordered]@{
        Url = $Url; FinalUrl = $Url; HttpStatus = 0; Code = 'RETRIEVAL_FAIL'; Redirected = $false
        Hops = (New-Object System.Collections.ArrayList); ContentType = ''; Bytes = $null; Error = ''; ElapsedMs = 0; FromCache = $false
    }
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
                        'TrustFailure' { $r.Code = 'TLS_UNTRUSTED_ROOT' }
                        'SecureChannelFailure' { $r.Code = 'TLS_HANDSHAKE_FAIL' }
                        default { $r.Code = 'RETRIEVAL_FAIL' }
                    }
                    [void]$r.Hops.Add([pscustomobject]@{ Url = $current; HttpStatus = 0; Location = ''; Error = ('{0} {1}' -f $status, $r.Error).Trim() })
                    break
                }
            }
            $sc = [int]$resp.StatusCode
            $loc = [string]$resp.Headers['Location']
            [void]$r.Hops.Add([pscustomobject]@{ Url = $current; HttpStatus = $sc; Location = $loc; Error = '' })
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
                    if ($body.TooLarge) { $r.Code = 'RETRIEVAL_FAIL'; $r.Error = ('Response larger than {0} bytes; not read.' -f $MaxBytes) }
                    else { $r.Bytes = $body.Bytes; $r.Code = 'OK' }
                }
            }
            elseif ($sc -eq 400) { $r.Code = 'HTTP_400' }
            elseif ($sc -eq 401 -or $sc -eq 403) { $r.Code = 'HTTP_401_403' }
            elseif ($sc -eq 404) { $r.Code = 'HTTP_404' }
            elseif ($sc -ge 500) { $r.Code = 'HTTP_500' }
            else { $r.Code = 'RETRIEVAL_FAIL' }
            break
        }
        finally { if ($null -ne $resp) { $resp.Close() } }
    }
    $r.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('HTTP GET {0}: {1} {2} ({3} hop(s), {4} ms) {5}' -f $Url, $r.HttpStatus, $r.Code, $r.Hops.Count, $r.ElapsedMs, $r.Error).Trim()
    return $r
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
    $r = [pscustomobject][ordered]@{
        Probe = 'TLS'; Target = ('{0}:{1}' -f $h, $Port); Status = 'Fail'; Code = 'TLS_HANDSHAKE_FAIL'; Protocol = ''
        NameMatch = $null; ChainErrors = @(); Subject = ''; Issuer = ''; Thumbprint = ''; NotAfter = ''; Error = ''; ElapsedMs = 0; FromCache = $false
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tcp = Test-MspkiTcpPort -HostName $h -Port $Port -TimeoutMs $TimeoutMs
    if ($tcp.Status -ne 'Pass') {
        $r.Code = $tcp.StatusCode; $r.Error = $tcp.Error
    }
    else {
        $client = New-Object System.Net.Sockets.TcpClient
        $ssl = $null
        $state = @{ Errors = $null; Chain = @(); Cert = $null }
        try {
            $ar = $client.BeginConnect($h, $Port, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw (New-Object System.TimeoutException('TCP connect timed out.')) }
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
            $ssl.AuthenticateAsClient($h)
            $r.Protocol = [string]$ssl.SslProtocol
            $errs = [System.Net.Security.SslPolicyErrors]$state.Errors
            $r.NameMatch = (($errs -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -eq 0)
            $r.ChainErrors = @($state.Chain | Where-Object { $_ -and $_ -ne 'NoError' })
            if ($null -ne $state.Cert) {
                $r.Subject = $state.Cert.Subject; $r.Issuer = $state.Cert.Issuer; $r.Thumbprint = $state.Cert.Thumbprint
                $r.NotAfter = $state.Cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            if ($r.ChainErrors -contains 'UntrustedRoot') { $r.Code = 'TLS_UNTRUSTED_ROOT' }
            elseif ($r.ChainErrors -contains 'PartialChain') { $r.Code = 'TLS_PARTIAL_CHAIN' }
            elseif ($r.ChainErrors -contains 'NotTimeValid') { $r.Code = 'OBJECT_EXPIRED' }
            elseif ($r.ChainErrors.Count -gt 0) { $r.Code = 'TLS_HANDSHAKE_FAIL' }
            elseif (-not $r.NameMatch) { $r.Code = 'TLS_NAME_MISMATCH' }
            else { $r.Code = 'OK'; $r.Status = 'Pass' }
        }
        catch {
            $ei = Get-MspkiErrorInfo $_
            $r.Error = $ei.Message
            if ($ei.Class -eq 'Timeout' -or $ei.ExceptionType -like '*IOException') { $r.Code = 'TLS_HANDSHAKE_FAIL' }
            if ($ei.Class -eq 'Timeout') { $r.Code = 'TIMEOUT' }
        }
        finally {
            if ($null -ne $ssl) { $ssl.Dispose() }
            $client.Close()
        }
    }
    $r.ElapsedMs = [int64]$sw.ElapsedMilliseconds
    Set-MspkiProbeCacheEntry -Key $key -Value $r
    Write-MspkiLog -Message ('TLS {0}: {1} {2} {3} ms {4}' -f $r.Target, $r.Code, $r.Protocol, $r.ElapsedMs, $r.Error).Trim()
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
    missing), PERMISSION_DENIED, TIMEOUT or RETRIEVAL_FAIL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$DefaultServer = '',
        [int]$TimeoutSeconds = 15
    )
    $key = 'ldapurl|' + $Url
    $cached = Get-MspkiProbeCacheEntry -Key $key
    if ($null -ne $cached) { return $cached }
    $r = [pscustomobject][ordered]@{ Url = $Url; Server = ''; Code = 'RETRIEVAL_FAIL'; Bytes = $null; ValueCount = 0; Error = ''; ElapsedMs = 0 }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $p = ConvertFrom-MspkiLdapUrl -Url $Url
        $r.Server = $p.Host
        if (-not $r.Server) { $r.Server = $DefaultServer }
        if (-not $p.Attribute) { throw 'The LDAP URL names no attribute.' }
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
    Write-MspkiLog -Message ('LDAP {0}: {1} {2}' -f $Url, $r.Code, $r.Error).Trim()
    return $r
}
