# The ONLY requests this tool can ever send to a NDES / SCEP host (REQUIREMENTS 5.7). By default only GetCACaps and
# GetCACert are sent. The anonymous request to the admin page is sent only when the run was started with
# -IncludeNdesAdminProbe: an admin page that is wrongly open to anonymous users generates a one-time challenge password
# when it is requested, so for that request the probe would write to a server. Everything else in the code
# base is unable to build a NDES URL: this file holds the single table of allowed requests, and every request
# goes through Send-MspkiNdesRequest, which
#   - accepts only the three names in the table (a ValidateSet, plus a lookup that throws on anything else),
#   - builds the URL itself from a validated host, scheme and port (no caller-supplied path or query),
#   - sends an anonymous GET through Invoke-MspkiHttpGet (no credentials, no body, no custom headers),
#   - never follows a redirect (MaxRedirects 0), so a redirect cannot lead to a request that is not in the table,
#   - for the admin page, never reads the response body (that page can issue challenge passwords).
# The operation that enrolls (PKIOperation) and every other SCEP operation are not in the table and cannot be sent.
# tests/Ndes.Tests.ps1 proves this against a loopback server and by static checks of this file.

$script:MspkiNdesRequestTable = [ordered]@{
    GetCACaps      = @{ Path = '/certsrv/mscep/mscep.dll'; Query = '?operation=GetCACaps'; DiscardBody = $false; Purpose = 'SCEP capabilities of the CA (read-only, public data)' }
    GetCACert      = @{ Path = '/certsrv/mscep/mscep.dll'; Query = '?operation=GetCACert'; DiscardBody = $false; Purpose = 'CA / RA certificates (read-only, public data)' }
    AdminAnonymous = @{ Path = '/certsrv/mscep_admin/'; Query = ''; DiscardBody = $true; Purpose = 'anonymous request to the admin page: HTTP 401 proves that it exists; the body is never read' }
}

# Web Enrollment lives under the same IIS application root, so its standard path is kept here too: every path below /certsrv is
# named in this file only. These two functions only build a string; the Web Enrollment GET itself (anonymous, no redirects,
# body not read) is sent by the endpoint identity analysis to Enterprise CA hosts, never to a SCEP path.
function Get-MspkiWebEnrollmentPath {
    <#
    .SYNOPSIS
    The standard Web Enrollment path (the root of the browser enrollment pages), for messages and URLs.
    #>
    [CmdletBinding()]
    param()
    return '/certsrv/'
}

function New-MspkiWebEnrollmentUrl {
    <#
    .SYNOPSIS
    Builds the Web Enrollment URL of a host (standard path, default port). Throws for a host name that is not a plain DNS name or IP address.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$HostName, [ValidateSet('http', 'https')][string]$Scheme = 'http')
    $h = ConvertTo-MspkiHostName $HostName
    if ($h -notmatch '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$') { throw ('Not a usable host name: {0}' -f $HostName) }
    return ('{0}://{1}{2}' -f $Scheme, $h, (Get-MspkiWebEnrollmentPath))
}

function Get-MspkiNdesAllowedRequest {
    <#
    .SYNOPSIS
    Lists the only requests that can ever be sent to a NDES host: method, path, query, credentials.
    #>
    [CmdletBinding()]
    param()
    foreach ($k in $script:MspkiNdesRequestTable.Keys) {
        $e = $script:MspkiNdesRequestTable[$k]
        [pscustomobject][ordered]@{ Name = $k; Method = 'GET'; Path = $e.Path; Query = $e.Query; Authentication = 'None'; BodyRead = (-not $e.DiscardBody); Purpose = $e.Purpose }
    }
}

function New-MspkiNdesRequestUrl {
    <#
    .SYNOPSIS
    Builds the URL of one allowed request. Throws for a name that is not in the table, or a host name that is not a
    plain DNS name or IP address.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GetCACaps', 'GetCACert', 'AdminAnonymous')][string]$Name,
        [Parameter(Mandatory = $true)][string]$HostName,
        [ValidateSet('http', 'https')][string]$Scheme = 'https',
        [ValidateRange(0, 65535)][int]$Port = 0
    )
    if (-not $script:MspkiNdesRequestTable.Contains($Name)) { throw ('Not an allowed NDES request: {0}' -f $Name) }
    $h = ConvertTo-MspkiHostName $HostName
    if ($h -notmatch '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$') { throw ('Not a usable NDES host name: {0}' -f $HostName) }
    $e = $script:MspkiNdesRequestTable[$Name]
    $portPart = ''
    if ($Port -gt 0 -and -not (($Scheme -eq 'https' -and $Port -eq 443) -or ($Scheme -eq 'http' -and $Port -eq 80))) { $portPart = ':' + $Port }
    return ('{0}://{1}{2}{3}{4}' -f $Scheme, $h, $portPart, $e.Path, $e.Query)
}

function Get-MspkiNdesBaseUrl {
    <#
    .SYNOPSIS
    The SCEP URL of a host, as it is registered in the lead registry (the SCEP service address, without a query).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [ValidateSet('http', 'https')][string]$Scheme = 'https',
        [ValidateRange(0, 65535)][int]$Port = 0
    )
    $u = New-MspkiNdesRequestUrl -Name GetCACaps -HostName $HostName -Scheme $Scheme -Port $Port
    return ($u -replace '\?.*$', '')
}

function Test-MspkiNdesUrl {
    <#
    .SYNOPSIS
    True when a URL points at a SCEP / NDES service path. Used to find URLs that certificates, policy or AD reference.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Url)
    return ([string]$Url -match '(?i)/certsrv/mscep')
}

function Send-MspkiNdesRequest {
    <#
    .SYNOPSIS
    Sends ONE of the allowed requests as an anonymous GET and returns the Invoke-MspkiHttpGet result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GetCACaps', 'GetCACert', 'AdminAnonymous')][string]$Name,
        [Parameter(Mandatory = $true)][string]$HostName,
        [ValidateSet('http', 'https')][string]$Scheme = 'https',
        [ValidateRange(0, 65535)][int]$Port = 0,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000
    )
    $url = New-MspkiNdesRequestUrl -Name $Name -HostName $HostName -Scheme $Scheme -Port $Port
    $entry = $script:MspkiNdesRequestTable[$Name]
    if ($entry.DiscardBody) {
        return (Invoke-MspkiHttpGet -Url $url -TimeoutMs $TimeoutMs -MaxBytes 1024 -MaxRedirects 0 -DiscardBody)
    }
    return (Invoke-MspkiHttpGet -Url $url -TimeoutMs $TimeoutMs -MaxBytes 262144 -MaxRedirects 0)
}

function Get-MspkiNdesTransport {
    <#
    .SYNOPSIS
    Chooses how to reach a NDES host: https on 443 when it connects and the TLS handshake succeeds, else http on 80
    (or the scheme and port of the referenced URL). Records DNS, TCP and TLS as separate facts. Nothing is sent but
    TCP connects and one TLS handshake.

    .OUTPUTS
    { Dns, Chosen ({Scheme, Port} or $null), Attempts (text lines), FailCode, FailLayer, Tls }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [hashtable[]]$Option = @(),
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000
    )
    $r = [pscustomobject][ordered]@{ Dns = $null; Chosen = $null; Attempts = (New-Object System.Collections.ArrayList); FailCode = ''; FailLayer = ''; Tls = $null }
    $r.Dns = Resolve-MspkiDnsName -HostName $HostName -TimeoutMs $TimeoutMs
    if ($r.Dns.Status -ne 'Pass') { $r.FailCode = $r.Dns.StatusCode; $r.FailLayer = 'Dns'; return $r }
    $options = @($Option)
    if ($options.Count -eq 0) { $options = @(@{ Scheme = 'https'; Port = 443 }, @{ Scheme = 'http'; Port = 80 }) }
    foreach ($o in $options) {
        $tcp = Test-MspkiTcpPort -HostName $HostName -Port $o.Port -TimeoutMs $TimeoutMs
        if ($tcp.Status -ne 'Pass') {
            [void]$r.Attempts.Add(('TCP {0}: {1}' -f $o.Port, $tcp.StatusCode))
            if (-not $r.FailCode) { $r.FailCode = $tcp.StatusCode; $r.FailLayer = 'Tcp' }
            continue
        }
        [void]$r.Attempts.Add(('TCP {0}: connects' -f $o.Port))
        if ($o.Scheme -eq 'https') {
            $tls = Test-MspkiTlsEndpoint -HostName $HostName -Port $o.Port -TimeoutMs $TimeoutMs
            $r.Tls = $tls
            [void]$r.Attempts.Add(('TLS {0}: {1}' -f $o.Port, $tls.Code))
            if ($tls.Code -ne 'OK') { $r.FailCode = $tls.Code; $r.FailLayer = 'Tls'; continue }
        }
        $r.Chosen = $o
        $r.FailCode = ''; $r.FailLayer = ''
        return $r
    }
    return $r
}

function Invoke-MspkiNdesProbe {
    <#
    .SYNOPSIS
    Sends the allowed requests to one host and returns the responses by name: GetCACaps and GetCACert, and the anonymous admin
    request only with -IncludeAdmin (AdminAnonymous is $null otherwise). Nothing else is sent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][ValidateSet('http', 'https')][string]$Scheme,
        [ValidateRange(0, 65535)][int]$Port = 0,
        [ValidateRange(100, 600000)][int]$TimeoutMs = 5000,
        [switch]$IncludeAdmin
    )
    $out = [ordered]@{ AdminAnonymous = $null }
    $names = @('GetCACaps', 'GetCACert')
    if ($IncludeAdmin) { $names += 'AdminAnonymous' }
    foreach ($name in $names) {
        $out[$name] = Send-MspkiNdesRequest -Name $name -HostName $HostName -Scheme $Scheme -Port $Port -TimeoutMs $TimeoutMs
    }
    return [pscustomobject]$out
}
