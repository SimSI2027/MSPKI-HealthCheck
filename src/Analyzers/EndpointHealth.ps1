# AIA / CDP / OCSP endpoints and CRL health (REQUIREMENTS sections 5.2 and 5.3). Every lead is checked
# layer by layer (DNS, TCP, TLS, HTTP, redirect, content). Downloaded certificates and CRLs may add new
# leads (depth + 1). CRLs are then checked for freshness, issuer and signature.

$script:MspkiLeadCategory = @{ AIA = 'AIA'; CDP = 'CDP'; FreshestCRL = 'CDP'; OCSP = 'OCSP' }
$script:MspkiLeadRole = @{ AIA = 'AIAEndpoint'; CDP = 'CDPEndpoint'; FreshestCRL = 'CDPEndpoint'; OCSP = 'OCSPEndpoint' }

function New-MspkiEndpointFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lead,
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Message,
        [hashtable]$Layers = @{},
        [string[]]$Evidence = @(),
        [string]$Confidence = 'Referenced',
        [string]$Notes = '',
        [string]$Category = ''
    )
    if (-not $Category) { $Category = $script:MspkiLeadCategory[$Lead.Kind] }
    $target = $Lead.Host
    if (-not $target) { $target = '(serverless LDAP)' }
    $ev = @(('Lead {0} ({1}), depth {2}' -f $Lead.Id, $Lead.Kind, $Lead.Depth))
    $ev += @($Lead.Origins | ForEach-Object { 'Found in: {0}' -f $_ })
    $ev += $Evidence
    $l = @{ DiscoveryStatus = 'Pass' }
    foreach ($k in $Layers.Keys) { $l[$k] = $Layers[$k] }
    return (New-MspkiFinding -Stage 'Probe' -Category $Category -Role $script:MspkiLeadRole[$Lead.Kind] -Target $target -Endpoint $Url `
        -RelatedCA (@($Lead.RelatedCAs) -join ', ') -Status $Status -StatusCode $Code -Confidence $Confidence `
        -Sources @($Lead.Sources) -Scope $Lead.Scope -Message $Message -Evidence $ev -Notes $Notes -Layers $l)
}

function Get-MspkiExpectedIssuerName {
    <#
    .SYNOPSIS
    Names the object a lead should deliver: for AIA the issuer of the certificates that reference it, for
    CDP the issuer of those certificates (the CRL issuer). From CA properties: the CA's own subject.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Lead, [hashtable]$Certificates = @{}, [object[]]$CACertificates = @())
    $names = New-Object System.Collections.ArrayList
    foreach ($s in $Lead.Sources) {
        $m = [regex]::Match($s, '^Cert:([0-9A-F]+):')
        if ($m.Success -and $Certificates.ContainsKey($m.Groups[1].Value)) {
            $n = $Certificates[$m.Groups[1].Value].Issuer
            if (-not $names.Contains($n)) { [void]$names.Add($n) }
        }
        $m = [regex]::Match($s, '^CA:(.+):Cert(Cdp|Aia)Urls$')
        if ($m.Success) {
            foreach ($c in @($CACertificates | Where-Object { $_.CAName -eq $m.Groups[1].Value })) {
                if (-not $names.Contains($c.Info.Subject)) { [void]$names.Add($c.Info.Subject) }
            }
        }
    }
    return , $names.ToArray()
}

function Test-MspkiLeadEndpoint {
    <#
    .SYNOPSIS
    Checks one URL of a lead. Returns { Findings; Certificate; Crl; Url }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lead,
        [Parameter(Mandatory = $true)][string]$Url,
        [string]$DomainController = '',
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork,
        [string[]]$ExpectedIssuer = @()
    )
    $out = [pscustomobject]@{ Findings = (New-Object System.Collections.ArrayList); Certificate = $null; Crl = $null; Url = $Url }
    $ms = $TimeoutSeconds * 1000
    $n = ConvertTo-MspkiNormalizedUrl -Url $Url
    $what = @{ AIA = 'CA certificate'; CDP = 'CRL'; FreshestCRL = 'delta CRL'; OCSP = 'OCSP responder' }[$Lead.Kind]

    if ($n.UrlType -eq 'File') {
        [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'NotApplicable' -Code 'NOT_APPLICABLE' `
            -Message ('File/UNC location for the {0}; file locations are not probed.' -f $what)))
        return $out
    }

    $bytes = $null
    $layers = @{}
    $ev = New-Object System.Collections.ArrayList
    if ($n.UrlType -eq 'Ldap') {
        $layers = @{ DnsStatus = 'NotApplicable'; TcpStatus = 'NotApplicable'; HttpStatus = 'NotApplicable'; RedirectStatus = 'NotApplicable' }
        $r = Get-MspkiLdapUrlContent -Url $Url -DefaultServer $DomainController -TimeoutSeconds ([math]::Max(10, $TimeoutSeconds * 3))
        [void]$ev.Add(('LDAP server: {0}' -f $(if ($r.Server) { $r.Server } else { '(default)' })))
        if ($r.Code -ne 'OK') {
            $st = 'Fail'
            if ($r.Code -eq 'PERMISSION_DENIED') { $st = 'Skipped' }
            $layers['ContentStatus'] = 'Fail'
            [void]$ev.Add(('Error: {0}' -f $r.Error))
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status $st -Code $r.Code -Layers $layers -Evidence @($ev) `
                -Message ('The {0} could not be read from LDAP: {1}' -f $what, $r.Error)))
            return $out
        }
        $bytes = $r.Bytes
    }
    elseif ($n.UrlType -eq 'Http') {
        if ($SkipNetwork) {
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Skipped' -Code 'NOT_APPLICABLE' `
                -Message ('{0} endpoint not probed because -SkipNetwork was used.' -f $what) -Layers @{ DnsStatus = 'Skipped' }))
            return $out
        }
        $dns = Resolve-MspkiDnsName -HostName $n.Host -TimeoutMs $ms
        $layers['DnsStatus'] = $dns.Status
        if ($dns.Status -ne 'Pass') {
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Fail' -Code $dns.StatusCode -Layers $layers `
                -Message ('{0} does not resolve in DNS.' -f $n.Host) -Evidence @(('DNS: {0} {1}' -f $dns.Status, $dns.Error))))
            return $out
        }
        [void]$ev.Add(('DNS: {0}' -f ($dns.Addresses -join ', ')))
        $tcp = Test-MspkiTcpPort -HostName $n.Host -Port $n.Port -TimeoutMs $ms
        $layers['TcpStatus'] = $tcp.Status
        if ($tcp.Status -ne 'Pass') {
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Fail' -Code $tcp.StatusCode -Layers $layers `
                -Message ('{0} does not accept connections on TCP {1}.' -f $n.Host, $n.Port) -Evidence (@($ev) + ('TCP: {0} {1}' -f $tcp.Status, $tcp.Error))))
            return $out
        }
        if ($Lead.Kind -eq 'OCSP') {
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Information' -Code 'OK' -Layers $layers `
                -Message ('OCSP responder {0} accepts TCP connections. Reachability is not OCSP health; a full check needs -CertificateFile (later phase).' -f $n.Host) `
                -Evidence @($ev)))
            return $out
        }
        if ($n.Scheme -eq 'https') {
            $tls = Test-MspkiTlsEndpoint -HostName $n.Host -Port $n.Port -TimeoutMs $ms
            $layers['TlsStatus'] = $(if ($tls.Code -eq 'OK') { 'Pass' } else { 'Fail' })
            [void]$ev.Add(('TLS: {0} {1}; server certificate {2} (issuer {3}, until {4}); name match {5}; chain errors: {6}' -f `
                $tls.Code, $tls.Protocol, $tls.Subject, $tls.Issuer, $tls.NotAfter, $tls.NameMatch, ($tls.ChainErrors -join ', ')))
            if ($tls.Code -ne 'OK') {
                [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Fail' -Code $tls.Code -Layers $layers -Evidence @($ev) `
                    -Message ('TLS to {0} failed: {1}. The {2} was not downloaded.' -f $n.Host, $tls.Code, $what) `
                    -Notes 'A TLS name mismatch or an untrusted server certificate is not service unavailability; most PKI clients use http for AIA/CDP.'))
                return $out
            }
        }
        $http = Invoke-MspkiHttpGet -Url $Url -TimeoutMs $ms
        foreach ($h in $http.Hops) { [void]$ev.Add(('HTTP hop: {0} -> {1} {2} {3}' -f $h.Url, $h.HttpStatus, $h.Location, $h.Error).Trim()) }
        if ($http.Redirected) {
            $layers['RedirectStatus'] = 'Warning'
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Information' -Code 'HTTP_REDIRECT' `
                -Layers @{ RedirectStatus = 'Warning' } -Evidence @($http.Hops | ForEach-Object { 'Hop: {0} -> {1} {2}' -f $_.Url, $_.HttpStatus, $_.Location }) `
                -Message ('{0} redirects ({1} hop(s)); final URL {2}.' -f $Url, ($http.Hops.Count - 1), $http.FinalUrl) `
                -Notes 'Recorded separately from the download result. Check that every client that fetches this URL follows redirects.'))
        }
        else { $layers['RedirectStatus'] = 'Pass' }
        if ($http.Code -ne 'OK') {
            $layers['HttpStatus'] = 'Fail'
            $notes = ''
            if ($http.Code -eq 'HTTP_404' -and $Url -match '\+') { $notes = 'The URL contains "+" (delta CRL name). IIS rejects it unless double escaping is allowed for that folder.' }
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Fail' -Code $http.Code -Layers $layers -Evidence @($ev) -Notes $notes `
                -Message ('The {0} could not be downloaded: HTTP {1} {2}' -f $what, $http.HttpStatus, $http.Error).Trim()))
            return $out
        }
        $layers['HttpStatus'] = 'Pass'
        [void]$ev.Add(('Content-Type: {0}; {1} bytes' -f $http.ContentType, $http.Bytes.Length))
        $bytes = $http.Bytes
    }
    else {
        [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'NotApplicable' -Code 'UNSUPPORTED' `
            -Message ('Unsupported URL type for the {0}.' -f $what)))
        return $out
    }

    # Content: is it the right kind of object, and the expected one?
    if ($Lead.Kind -eq 'AIA') {
        $cert = $null
        try { $cert = New-MspkiCertificate -Bytes $bytes } catch { }
        if ($null -eq $cert) {
            try {
                $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $col.Import($bytes)
                if ($col.Count -gt 0) { $cert = $col[0]; [void]$ev.Add(('PKCS #7 with {0} certificate(s); the first is checked.' -f $col.Count)) }
            }
            catch { }
        }
        if ($null -eq $cert) {
            $layers['ContentStatus'] = 'Fail'
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Fail' -Code 'CONTENT_WRONG_TYPE' -Layers $layers -Evidence @($ev) `
                -Message 'The AIA location does not return a certificate.'))
            return $out
        }
        $out.Certificate = $cert
        [void]$ev.Add(('Certificate: {0} [{1}] until {2}' -f $cert.Subject, $cert.Thumbprint, $cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')))
        if ($ExpectedIssuer.Count -gt 0 -and $ExpectedIssuer -notcontains $cert.Subject) {
            $layers['ContentStatus'] = 'Warning'
            [void]$ev.Add(('Expected subject: {0}' -f ($ExpectedIssuer -join ' | ')))
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Warning' -Code 'CONTENT_WRONG_TYPE' -Layers $layers -Evidence @($ev) `
                -Confidence 'Confirmed' -Message ('The AIA location returns a certificate for {0}, not the expected issuer.' -f $cert.Subject)))
            return $out
        }
        $layers['ContentStatus'] = 'Pass'
        [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Pass' -Code 'OK' -Layers $layers -Evidence @($ev) `
            -Confidence 'Confirmed' -Message ('The AIA location returns the CA certificate {0}.' -f $cert.Subject)))
        return $out
    }

    $crl = $null
    try { $crl = ConvertFrom-MspkiCrl -Bytes $bytes }
    catch { [void]$ev.Add(('Not a CRL: {0}' -f (Get-MspkiErrorInfo $_).Message)) }
    if ($null -eq $crl) {
        $layers['ContentStatus'] = 'Fail'
        [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Fail' -Code 'CONTENT_WRONG_TYPE' -Layers $layers -Evidence @($ev) `
            -Message ('The location does not return a {0}.' -f $what)))
        return $out
    }
    $out.Crl = $crl
    $layers['ContentStatus'] = 'Pass'
    [void]$ev.Add(('CRL: issuer {0}, number {1}, {2}, next update {3}' -f $crl.Issuer, $crl.CrlNumber, $(if ($crl.IsDelta) { 'delta' } else { 'base' }), $crl.NextUpdate))
    [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Pass' -Code 'OK' -Layers $layers -Evidence @($ev) `
        -Confidence 'Confirmed' -Message ('The location returns a {0} {1} from {2}.' -f $(if ($crl.IsDelta) { 'delta' } else { 'base' }), 'CRL', $crl.Issuer)))
    return $out
}

function Test-MspkiCrlHealth {
    <#
    .SYNOPSIS
    Checks one downloaded CRL: issuer found and signature, expected issuer, base/delta as referenced, and
    freshness against the thresholds (separate for root and subordinate issuers).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Record,
        [AllowEmptyCollection()][object[]]$Certificates = @(),
        [hashtable]$Thresholds = @{},
        [DateTime]$Now = [DateTime]::UtcNow
    )
    $t = Get-MspkiThreshold -Override $Thresholds
    $crl = $Record.Crl
    $lead = $Record.Lead
    $issuer = $null; $sigText = 'issuer certificate not found among the discovered certificates'; $sigOk = $null
    foreach ($c in @($Certificates | Where-Object { $null -ne $_ -and (ConvertTo-MspkiHex $_.SubjectName.RawData) -eq $crl.IssuerRawHex } | Sort-Object NotAfter -Descending)) {
        $v = Test-MspkiSignature -SignedBytes $crl.Bytes -Issuer $c
        if ($v.Valid -eq $true) { $issuer = $c; $sigOk = $true; $sigText = ('verified with {0} [{1}]' -f $c.Subject, $c.Thumbprint); break }
        $sigOk = $false; $sigText = ('does not verify with any certificate named {0} ({1})' -f $crl.Issuer, $v.Reason)
    }
    $isRoot = $false
    if ($null -ne $issuer) { $isRoot = ((ConvertTo-MspkiHex $issuer.SubjectName.RawData) -eq (ConvertTo-MspkiHex $issuer.IssuerName.RawData)) }
    if ($isRoot) { $warn = $t.RootCrlWarningPercent; $crit = $t.RootCrlCriticalPercent; $kind = 'root CA' }
    else { $warn = $t.IssuingCrlWarningPercent; $crit = $t.IssuingCrlCriticalPercent; $kind = 'subordinate CA' }
    $fr = Get-MspkiCrlFreshness -Crl $crl -WarningPercent $warn -CriticalPercent $crit -Now $Now
    $type = 'base'
    if ($crl.IsDelta) { $type = 'delta' }
    $ev = @(
        ('Location: {0}' -f $Record.Url),
        ('Issuer: {0}' -f $crl.Issuer),
        ('Type: {0} CRL{1}' -f $type, $(if ($crl.IsDelta) { ' (base CRL number {0})' -f $crl.BaseCrlNumber } else { '' })),
        ('CRL number: {0}' -f $crl.CrlNumber),
        ('This update: {0}' -f $crl.ThisUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ')),
        ('Next update: {0}' -f $(if ($null -ne $crl.NextUpdate) { $crl.NextUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '(none)' })),
        ('Validity: {0} h; used {1}%; {2} h left' -f $fr.ValidityHours, $fr.PercentUsed, $fr.HoursLeft),
        ('Thresholds ({0}): warning {1}%, critical {2}%' -f $kind, $warn, $crit),
        ('Signature: {0}' -f $sigText),
        ('Revoked entries: {0}' -f $crl.RevokedCount)
    )
    if ($crl.CAVersion) { $ev += ('CA version: {0}' -f $crl.CAVersion) }
    if (-not $crl.IsDelta) {
        if (@($crl.FreshestCrlUrls).Count -gt 0) { $ev += ('Delta CRLs: published ({0})' -f ($crl.FreshestCrlUrls -join ', ')) }
        else { $ev += 'Delta CRLs: not referenced (no Freshest CRL extension) - a configuration fact, not an error.' }
    }
    $status = $fr.Status; $code = $fr.StatusCode
    $msg = '{0} CRL of {1} at {2}: {3}% of its lifetime used, {4} h left.' -f $type, $crl.Issuer, $Record.Url, $fr.PercentUsed, $fr.HoursLeft
    if ($code -eq 'OBJECT_EXPIRED') { $msg = '{0} CRL of {1} at {2} has expired ({3}).' -f $type, $crl.Issuer, $Record.Url, $crl.NextUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($code -eq 'NOT_APPLICABLE') { $msg = '{0} CRL of {1} at {2} has no next update.' -f $type, $crl.Issuer, $Record.Url }
    $expected = @($Record.ExpectedIssuer)
    if ($status -notin @('Fail', 'Critical') -and $expected.Count -gt 0 -and $expected -notcontains $crl.Issuer) {
        $status = 'Warning'; $code = 'CONTENT_WRONG_TYPE'
        $msg = 'The CRL at {0} is issued by {1}, not by the expected CA.' -f $Record.Url, $crl.Issuer
        $ev += ('Expected issuer: {0}' -f ($expected -join ' | '))
    }
    if ($status -notin @('Fail', 'Critical') -and $lead.Kind -eq 'FreshestCRL' -and -not $crl.IsDelta) {
        $status = 'Warning'; $code = 'CONTENT_WRONG_TYPE'
        $msg = 'The Freshest CRL location {0} returns a base CRL, not a delta CRL.' -f $Record.Url
    }
    if ($sigOk -eq $false) {
        $status = 'Fail'; $code = 'SIGNATURE_INVALID'
        $msg = 'The CRL at {0} has a signature that does not verify.' -f $Record.Url
    }
    $confidence = 'Referenced'
    $chain = 'Unknown'
    if ($sigOk -eq $true) { $confidence = 'Confirmed'; $chain = 'Pass' }
    elseif ($sigOk -eq $false) { $chain = 'Fail' }
    $notes = ''
    if ($null -eq $sigOk) { $notes = 'The issuer certificate was not discovered, so the signature and the issuer could not be validated.' }
    return (New-MspkiFinding -Stage 'Analysis' -Category 'CRL' -Role 'CDPEndpoint' -Target $crl.Issuer -Endpoint $Record.Url `
        -RelatedCA (@($lead.RelatedCAs) -join ', ') -Status $status -StatusCode $code -Confidence $confidence -Sources @($lead.Sources) `
        -Scope $lead.Scope -Message $msg -Evidence $ev -Notes $notes -Layers @{ ContentStatus = 'Pass'; ChainStatus = $chain })
}

function Compare-MspkiHexNumber {
    [CmdletBinding()]
    param([string]$A, [string]$B)
    $a1 = ([string]$A).TrimStart('0'); $b1 = ([string]$B).TrimStart('0')
    if ($a1.Length -ne $b1.Length) { return [math]::Sign($a1.Length - $b1.Length) }
    return [math]::Sign([string]::CompareOrdinal($a1.ToUpperInvariant(), $b1.ToUpperInvariant()))
}

function Test-MspkiCrlConsistency {
    <#
    .SYNOPSIS
    Across locations: a location that serves an older CRL (lower CRL number) than another location for the
    same issuer and type is reported as STALE_DATA.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Records = @())
    $out = New-Object System.Collections.ArrayList
    $groups = @($Records | Group-Object { '{0}|{1}|{2}' -f $_.Crl.IssuerRawHex, $_.Crl.IsDelta, $_.Crl.CAVersion })
    foreach ($g in $groups) {
        if ($g.Count -lt 2) { continue }
        $max = ''
        foreach ($r in $g.Group) { if (-not $max -or (Compare-MspkiHexNumber $r.Crl.CrlNumber $max) -gt 0) { $max = $r.Crl.CrlNumber } }
        $newest = @($g.Group | Where-Object { (Compare-MspkiHexNumber $_.Crl.CrlNumber $max) -eq 0 } | ForEach-Object { $_.Url })
        foreach ($r in $g.Group) {
            if ((Compare-MspkiHexNumber $r.Crl.CrlNumber $max) -lt 0) {
                $type = 'base'
                if ($r.Crl.IsDelta) { $type = 'delta' }
                [void]$out.Add((New-MspkiFinding -Stage 'Analysis' -Category 'CRL' -Role 'CDPEndpoint' -Target $r.Crl.Issuer -Endpoint $r.Url `
                    -RelatedCA (@($r.Lead.RelatedCAs) -join ', ') -Status 'Warning' -StatusCode 'STALE_DATA' -Confidence 'Confirmed' `
                    -Sources @($r.Lead.Sources) -Scope $r.Lead.Scope -Layers @{ ContentStatus = 'Warning' } `
                    -Message ('{0} serves {1} CRL number {2}; another location serves the newer number {3}.' -f $r.Url, $type, $r.Crl.CrlNumber, $max) `
                    -Evidence @(('Newest at: {0}' -f ($newest -join ', ')), ('This update here: {0}' -f $r.Crl.ThisUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ'))) `
                    -Notes 'Publication to this location may have stopped or be delayed.'))
            }
        }
    }
    return , $out.ToArray()
}

function Invoke-MspkiEndpointAnalysis {
    <#
    .SYNOPSIS
    Probes every AIA / CDP / Freshest CRL / OCSP lead (all URL variants), follows links found in downloaded
    certificates and CRLs (depth + 1), then checks every CRL and cross-checks CRL numbers between locations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Discovery,
        [hashtable]$Thresholds = @{},
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork
    )
    $findings = New-Object System.Collections.ArrayList
    $records = New-Object System.Collections.ArrayList
    $certMap = @{}
    foreach ($k in $Discovery.Certificates.Keys) { $certMap[$k] = $Discovery.Certificates[$k] }
    $caCerts = @(Get-MspkiDiscoveredCertificateEntry -Discovery $Discovery)
    $dc = ''
    if ($null -ne $Discovery.Inventory.AdContext) { $dc = $Discovery.Inventory.AdContext.DomainController }
    $kinds = @('AIA', 'CDP', 'FreshestCRL', 'OCSP')
    $done = @{}
    $round = 0
    do {
        $pending = @(Get-MspkiLead | Where-Object { $kinds -contains $_.Kind -and -not $done.ContainsKey($_.Key) })
        foreach ($lead in $pending) {
            $done[$lead.Key] = $true
            $expected = Get-MspkiExpectedIssuerName -Lead $lead -Certificates $certMap -CACertificates $caCerts
            foreach ($url in @($lead.Variants)) {
                $r = Test-MspkiLeadEndpoint -Lead $lead -Url $url -DomainController $dc -TimeoutSeconds $TimeoutSeconds `
                    -SkipNetwork:$SkipNetwork -ExpectedIssuer $expected
                foreach ($f in $r.Findings) { [void]$findings.Add($f) }
                if ($null -ne $r.Certificate) {
                    $c = $r.Certificate
                    if (-not $certMap.ContainsKey($c.Thumbprint)) { $certMap[$c.Thumbprint] = $c }
                    foreach ($u in (Get-MspkiCertificateUrl -Certificate $c)) {
                        if ($u.Kind -eq 'Error') { continue }
                        [void](Add-MspkiLead -Url $u.Url -Kind $u.Kind -Source ('Cert:{0}:{1}' -f $c.Thumbprint, $u.Kind) `
                            -Origin ('certificate {0} downloaded from {1}' -f $c.Subject, $url) -Depth ($lead.Depth + 1))
                    }
                }
                if ($null -ne $r.Crl) {
                    [void]$records.Add([pscustomobject]@{ Url = $url; Lead = $lead; Crl = $r.Crl; ExpectedIssuer = $expected })
                    foreach ($u in @($r.Crl.FreshestCrlUrls)) {
                        [void](Add-MspkiLead -Url $u -Kind 'FreshestCRL' -Source ('Crl:{0}:FreshestCRL' -f $r.Crl.Sha1) `
                            -Origin ('CRL of {0} downloaded from {1}' -f $r.Crl.Issuer, $url) -Depth ($lead.Depth + 1) -RelatedCA (@($lead.RelatedCAs) -join ', '))
                    }
                }
            }
        }
        $round++
    } while ($pending.Count -gt 0 -and $round -lt 10)

    $allCerts = @($certMap.Values)
    foreach ($rec in $records) { [void]$findings.Add((Test-MspkiCrlHealth -Record $rec -Certificates $allCerts -Thresholds $Thresholds)) }
    foreach ($f in (Test-MspkiCrlConsistency -Records @($records))) { [void]$findings.Add($f) }
    return , $findings.ToArray()
}
