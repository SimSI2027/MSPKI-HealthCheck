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
    $ev += @($Lead.Aliases | ForEach-Object { 'Also referenced as: {0}' -f $_ })
    $ev += $Evidence
    # A reference to another environment goes to review and is never graded as a failure (REQUIREMENTS 4.2).
    $sc = Resolve-MspkiScopeStatus -Status $Status -Scope $Lead.Scope
    if ($sc.Capped) { $Status = $sc.Status; $ev += $sc.Evidence }
    $l = @{ DiscoveryStatus = 'Pass' }
    foreach ($k in $Layers.Keys) { $l[$k] = $Layers[$k] }
    return (New-MspkiFinding -Stage 'Probe' -Category $Category -Role $script:MspkiLeadRole[$Lead.Kind] -Target $target -Endpoint $Url `
        -RelatedCA (@($Lead.RelatedCAs) -join ', ') -Status $Status -StatusCode $Code -Confidence $Confidence -Severity $sc.Severity `
        -Sources @($Lead.Sources) -Scope $Lead.Scope -Message $Message -Evidence $ev -Notes $Notes -Layers $l)
}

function Test-MspkiAiaCertificateMatch {
    <#
    .SYNOPSIS
    Checks that a certificate downloaded from an AIA location is the one the referencing certificates need: the expected
    name AND the right key. Pure function (signature checks use only the downloaded public key).

    .OUTPUTS
    { Result (Verified, KeyMismatch, NameMismatch or NotVerifiable); Lines (evidence) }
    Verified: the downloaded certificate is identical to a CA certificate already known from AD or the CA, or the signature
    of a referencing certificate verifies with its key. KeyMismatch: it has the expected name, but no referencing
    certificate verifies with its key (for example another key generation of the CA). NotVerifiable: the name matches but
    no referencing certificate is known, or the signature could not be checked. Only Verified is Confirmed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Downloaded,
        [Parameter(Mandatory = $true)]$Lead,
        [hashtable]$KnownCertificates = @{},
        [string[]]$ExpectedIssuer = @()
    )
    $lines = New-Object System.Collections.ArrayList
    if ($ExpectedIssuer.Count -gt 0 -and $ExpectedIssuer -notcontains $Downloaded.Subject) {
        [void]$lines.Add(('Expected subject: {0}' -f ($ExpectedIssuer -join ' | ')))
        return [pscustomobject]@{ Result = 'NameMismatch'; Lines = @($lines) }
    }
    if ($KnownCertificates.ContainsKey($Downloaded.Thumbprint)) {
        [void]$lines.Add('Key check: identical to a CA certificate that is known from Active Directory or from the CA (same thumbprint).')
        return [pscustomobject]@{ Result = 'Verified'; Lines = @($lines) }
    }
    $refs = New-Object System.Collections.ArrayList
    foreach ($s in @($Lead.Sources)) {
        if ($s -match '^Cert:(?<tp>[0-9A-Fa-f]+):') {
            $tp = $Matches['tp'].ToUpperInvariant()
            if ($KnownCertificates.ContainsKey($tp)) { [void]$refs.Add($KnownCertificates[$tp]) }
        }
    }
    $verified = $false; $bad = 0; $unknown = 0
    foreach ($ref in $refs) {
        $v = Test-MspkiSignature -SignedBytes $ref.RawData -Issuer $Downloaded
        if ($v.Valid -eq $true) { $verified = $true; [void]$lines.Add(('Key check: the signature of the referencing certificate {0} [{1}] verifies with this certificate''s key.' -f $ref.Subject, $ref.Thumbprint)) }
        elseif ($v.Valid -eq $false) { $bad++; [void]$lines.Add(('Key check: the signature of the referencing certificate {0} [{1}] does NOT verify with this certificate''s key.' -f $ref.Subject, $ref.Thumbprint)) }
        else { $unknown++; [void]$lines.Add(('Key check: the signature of the referencing certificate {0} [{1}] could not be checked: {2}' -f $ref.Subject, $ref.Thumbprint, $v.Reason)) }
    }
    if ($verified) { return [pscustomobject]@{ Result = 'Verified'; Lines = @($lines) } }
    if ($bad -gt 0 -and $unknown -eq 0) { return [pscustomobject]@{ Result = 'KeyMismatch'; Lines = @($lines) } }
    if ($refs.Count -eq 0) { [void]$lines.Add('Key check: no referencing certificate is known (the URL comes from the CA configuration or from a certificate that was not discovered), so only the subject name was compared.') }
    return [pscustomobject]@{ Result = 'NotVerifiable'; Lines = @($lines) }
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

function Get-MspkiLdapDefaultAttribute {
    <#
    .SYNOPSIS
    The attribute read from an LDAP AIA/CDP URL that names none (RFC 4516 allows it; Windows then returns the object's certificate or
    CRL attribute): cACertificate for AIA, certificateRevocationList for CDP, deltaRevocationList for a Freshest CRL URL.
    #>
    [CmdletBinding()]
    param([string]$Kind)
    switch ($Kind) {
        'AIA' { return 'cACertificate' }
        'CDP' { return 'certificateRevocationList' }
        'FreshestCRL' { return 'deltaRevocationList' }
    }
    return ''
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
        [string[]]$ExpectedIssuer = @(),
        [hashtable]$KnownCertificate = @{}
    )
    $out = [pscustomobject]@{ Findings = (New-Object System.Collections.ArrayList); Certificate = $null; Validated = $false; Crl = $null; Url = $Url }
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
        # The bind uses the running user's Windows credentials, so only the selected domain controller, the forest's domain
        # controllers and forest hosts named by trusted evidence are contacted; with -SkipNetwork only the selected domain controller.
        $trust = ''
        if ($null -ne $Lead.PSObject.Properties['Trust']) { $trust = [string]$Lead.Trust }
        $r = Get-MspkiLdapUrlContent -Url $Url -DefaultServer $DomainController -TimeoutSeconds ([math]::Max(10, $TimeoutSeconds * 3)) `
            -LocalDomains @(Get-MspkiLeadLocalDomain) -DomainControllers @(Get-MspkiLeadDomainController) -Trust $trust `
            -SkipNetwork:$SkipNetwork -DefaultAttribute (Get-MspkiLdapDefaultAttribute -Kind $Lead.Kind)
        [void]$ev.Add(('LDAP server: {0}' -f $(if ($r.Server) { $r.Server } else { '(default)' })))
        if ($r.AttributeDefaulted) { [void]$ev.Add(('The URL names no attribute; read {0}, the attribute Windows clients use for this kind of object. A URL without an attribute is valid.' -f $r.Attribute)) }
        if (-not $r.Contacted) {
            $layers['ContentStatus'] = 'Skipped'
            [void]$ev.Add('No bind and no request was sent to this host.')
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Skipped' -Code 'NOT_APPLICABLE' -Layers $layers -Evidence @($ev) `
                -Message ('The {0} location {1} was not contacted: {2}' -f $what, $Url, $r.Error) `
                -Notes 'A directory bind sends the Windows credentials of the user running this tool. A URL in a certificate, above all one from a downloaded certificate, can name any host, so only this forest''s own domain controllers are contacted.'))
            return $out
        }
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
        [void]$ev.Add(('HTTP proxy: {0}' -f $http.ProxyMode))
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
        # The content type is checked before any certificate object is built: a PKCS #12 / PFX is refused (audit 2 M10).
        $read = ConvertFrom-MspkiCertificateBytes -Bytes $bytes
        if (@($read.Certificates).Count -gt 0) {
            $cert = @($read.Certificates)[0]
            if ($read.ContentType -eq 'Pkcs7') { [void]$ev.Add(('PKCS #7 with {0} certificate(s); the first is checked.' -f @($read.Certificates).Count)) }
        }
        elseif ($read.Error) { [void]$ev.Add(('Content type: {0}. {1}' -f $read.ContentType, $read.Error)) }
        if ($null -eq $cert) {
            $layers['ContentStatus'] = 'Fail'
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Fail' -Code 'CONTENT_WRONG_TYPE' -Layers $layers -Evidence @($ev) `
                -Message 'The AIA location does not return a certificate.'))
            return $out
        }
        $out.Certificate = $cert
        [void]$ev.Add(('Certificate: {0} [{1}] until {2}' -f $cert.Subject, $cert.Thumbprint, $cert.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')))
        $m = Test-MspkiAiaCertificateMatch -Downloaded $cert -Lead $Lead -KnownCertificates $KnownCertificate -ExpectedIssuer $ExpectedIssuer
        foreach ($l in $m.Lines) { [void]$ev.Add($l) }
        if ($m.Result -eq 'NameMismatch') {
            $layers['ContentStatus'] = 'Warning'
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Warning' -Code 'CONTENT_WRONG_TYPE' -Layers $layers -Evidence @($ev) `
                -Confidence 'Confirmed' -Message ('The AIA location returns a certificate for {0}, not the expected issuer.' -f $cert.Subject)))
            return $out
        }
        if ($m.Result -eq 'KeyMismatch') {
            $layers['ContentStatus'] = 'Warning'
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Warning' -Code 'CONTENT_WRONG_TYPE' -Layers $layers -Evidence @($ev) `
                -Confidence 'Confirmed' -Message ('The AIA location returns a certificate with the expected name ({0}), but not the key that signed the certificate(s) that reference it.' -f $cert.Subject) `
                -Notes 'This can be another key generation of the CA (an older CA certificate published at the location of the newer one).'))
            return $out
        }
        $layers['ContentStatus'] = 'Pass'
        if ($m.Result -eq 'Verified') {
            $out.Validated = $true
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Pass' -Code 'OK' -Layers $layers -Evidence @($ev) `
                -Confidence 'Confirmed' -Message ('The AIA location returns the CA certificate {0}.' -f $cert.Subject)))
        }
        else {
            [void]$out.Findings.Add((New-MspkiEndpointFinding -Lead $Lead -Url $Url -Status 'Pass' -Code 'OK' -Layers $layers -Evidence @($ev) `
                -Confidence 'Referenced' -Message ('The AIA location returns a certificate with the expected name ({0}); its key could not be verified.' -f $cert.Subject) `
                -Notes 'The name matches, but nothing proved that this is the right key. Links inside this certificate are not followed.'))
        }
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

function Test-MspkiCrlIssuerSignature {
    <#
    .SYNOPSIS
    Finds the issuer of a CRL among the given CA certificates (name, then Authority Key Identifier) and checks the CRL's signature.

    .OUTPUTS
    { Issuer (certificate or $null); Valid ($true verified, $false checked and does not verify, $null could not be checked); Text }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Crl,
        [AllowEmptyCollection()][object[]]$Certificates = @()
    )
    $issuer = $null; $sigText = 'issuer certificate not found among the discovered certificates'; $sigOk = $null
    $named = @($Certificates | Where-Object { $null -ne $_ -and (ConvertTo-MspkiHex $_.SubjectName.RawData) -eq $Crl.IssuerRawHex } | Sort-Object NotAfter -Descending)
    # When the CRL names the key that signed it (Authority Key Identifier), only a certificate with that key can be its issuer.
    $cands = $named
    if ($Crl.AuthorityKeyId -and $named.Count -gt 0) {
        $byKey = @($named | Where-Object { (Get-MspkiCertificateSubjectKeyId -Certificate $_) -eq $Crl.AuthorityKeyId })
        $noKey = @($named | Where-Object { -not (Get-MspkiCertificateSubjectKeyId -Certificate $_) })
        if ($byKey.Count -gt 0) { $cands = $byKey }
        elseif ($noKey.Count -gt 0) { $cands = $noKey }
        else {
            $cands = @()
            $sigText = ('issuer certificate with key identifier {0} not found: {1} certificate(s) named {2} were discovered, but they carry other keys (another key generation of the CA)' -f $Crl.AuthorityKeyId, $named.Count, $Crl.Issuer)
        }
    }
    $anyFalse = $false; $anyNull = $false; $lastReason = ''
    foreach ($c in $cands) {
        $v = Test-MspkiSignature -SignedBytes $Crl.Bytes -Issuer $c
        if ($v.Valid -eq $true) { $issuer = $c; $sigOk = $true; $sigText = ('verified with {0} [{1}]' -f $c.Subject, $c.Thumbprint); $anyFalse = $false; $anyNull = $false; break }
        if ($v.Valid -eq $false) { $anyFalse = $true } else { $anyNull = $true }
        $lastReason = $v.Reason
    }
    if ($null -eq $issuer -and $cands.Count -gt 0) {
        # "could not be checked" (Valid is $null) is not "invalid": only a signature that was really checked and does not verify is a failure.
        if ($anyNull) { $sigOk = $null; $sigText = ('could not be checked with the certificate(s) named {0}: {1}' -f $Crl.Issuer, $lastReason) }
        elseif ($anyFalse) { $sigOk = $false; $sigText = ('does not verify with any certificate named {0} ({1})' -f $Crl.Issuer, $lastReason) }
    }
    return [pscustomobject]@{ Issuer = $issuer; Valid = $sigOk; Text = $sigText }
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
    $sig = Test-MspkiCrlIssuerSignature -Crl $crl -Certificates $Certificates
    $issuer = $sig.Issuer; $sigOk = $sig.Valid; $sigText = $sig.Text
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
    if ($Record.PSObject.Properties['LinksNotFollowed'] -and @($Record.LinksNotFollowed).Count -gt 0) {
        $ev += ('Links in this CRL not followed (its signature was not verified with a discovered CA certificate): {0}' -f (@($Record.LinksNotFollowed) -join ', '))
    }
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
    if ($null -eq $sigOk) { $notes = 'The signature and the issuer could not be validated (no usable issuer certificate was discovered, or the signature could not be checked): this is not a bad signature.' }
    $sc = Resolve-MspkiScopeStatus -Status $status -Scope $lead.Scope
    if ($sc.Capped) { $status = $sc.Status; $ev += $sc.Evidence }
    $finding = New-MspkiFinding -Stage 'Analysis' -Category 'CRL' -Role 'CDPEndpoint' -Target $crl.Issuer -Endpoint $Record.Url `
        -RelatedCA (@($lead.RelatedCAs) -join ', ') -Status $status -StatusCode $code -Confidence $confidence -Sources @($lead.Sources) `
        -Scope $lead.Scope -Severity $sc.Severity -Message $msg -Evidence $ev -Notes $notes -Layers @{ ContentStatus = 'Pass'; ChainStatus = $chain }
    if ($Record.PSObject.Properties['ReviewOnly'] -and $Record.ReviewOnly) { $finding = ConvertTo-MspkiReviewFinding -Finding $finding -Reason $Record.ReviewReason }
    return $finding
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
    param([AllowEmptyCollection()][object[]]$Records = @(), [string[]]$ExcludeUrl = @())
    $out = New-Object System.Collections.ArrayList
    $groups = @($Records | Group-Object { '{0}|{1}|{2}' -f $_.Crl.IssuerRawHex, $_.Crl.IsDelta, $_.Crl.CAVersion })
    foreach ($g in $groups) {
        if ($g.Count -lt 2) { continue }
        $max = ''
        foreach ($r in $g.Group) { if (-not $max -or (Compare-MspkiHexNumber $r.Crl.CrlNumber $max) -gt 0) { $max = $r.Crl.CrlNumber } }
        $newest = @($g.Group | Where-Object { (Compare-MspkiHexNumber $_.Crl.CrlNumber $max) -eq 0 } | ForEach-Object { $_.Url })
        foreach ($r in $g.Group) {
            if ($ExcludeUrl -contains $r.Url) { continue }
            if ((Compare-MspkiHexNumber $r.Crl.CrlNumber $max) -lt 0) {
                $type = 'base'
                if ($r.Crl.IsDelta) { $type = 'delta' }
                $sf = New-MspkiFinding -Stage 'Analysis' -Category 'CRL' -Role 'CDPEndpoint' -Target $r.Crl.Issuer -Endpoint $r.Url `
                    -RelatedCA (@($r.Lead.RelatedCAs) -join ', ') -Status 'Warning' -StatusCode 'STALE_DATA' -Confidence 'Confirmed' `
                    -Sources @($r.Lead.Sources) -Scope $r.Lead.Scope -Layers @{ ContentStatus = 'Warning' } `
                    -Message ('{0} serves {1} CRL number {2}; another location serves the newer number {3}.' -f $r.Url, $type, $r.Crl.CrlNumber, $max) `
                    -Evidence @(('Newest at: {0}' -f ($newest -join ', ')), ('This update here: {0}' -f $r.Crl.ThisUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ'))) `
                    -Notes 'Publication to this location may have stopped or be delayed.'
                if ($r.PSObject.Properties['ReviewOnly'] -and $r.ReviewOnly) { $sf = ConvertTo-MspkiReviewFinding -Finding $sf -Reason $r.ReviewReason }
                [void]$out.Add($sf)
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
    $crlLinkQueue = New-Object System.Collections.ArrayList
    $certMap = @{}
    foreach ($k in $Discovery.Certificates.Keys) { $certMap[$k] = $Discovery.Certificates[$k] }
    $caCerts = @(Get-MspkiDiscoveredCertificateEntry -Discovery $Discovery)
    $dc = ''
    if ($null -ne $Discovery.Inventory.AdContext) { $dc = $Discovery.Inventory.AdContext.DomainController }
    $kinds = @('AIA', 'CDP', 'FreshestCRL', 'OCSP')
    $done = @{}
    $round = 0
    do {
        $null = @(Merge-MspkiShortNameLead -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork)
        $pending = @(Get-MspkiLead | Where-Object { $kinds -contains $_.Kind -and -not $done.ContainsKey($_.Key) })
        foreach ($lead in $pending) {
            $done[$lead.Key] = $true
            $expected = Get-MspkiExpectedIssuerName -Lead $lead -Certificates $certMap -CACertificates $caCerts
            # What carries this URL decides how a failure is graded: a URL that only expired or historical certificates carry is a review item.
            $grade = Get-MspkiLeadGrading -Lead $lead -Inventory $Discovery.Inventory -KnownCertificates $certMap
            foreach ($url in @($lead.Variants)) {
                $r = Test-MspkiLeadEndpoint -Lead $lead -Url $url -DomainController $dc -TimeoutSeconds $TimeoutSeconds `
                    -SkipNetwork:$SkipNetwork -ExpectedIssuer $expected -KnownCertificate $certMap
                foreach ($f in $r.Findings) {
                    if ($grade.ReviewOnly) { $f = ConvertTo-MspkiReviewFinding -Finding $f -Reason $grade.Reason }
                    [void]$findings.Add($f)
                }
                # Where this object was seen, or expected and missing (entity graph). "Tested" = at least one layer really ran.
                $tested = @($r.Findings | Where-Object { $_.Status -notin @('Skipped', 'NotApplicable') }).Count -gt 0
                try { Register-MspkiProbeResult -Lead $lead -Url $url -Result $r -KnownCertificates $certMap -Tested:$tested }
                catch { Write-MspkiLog -Level Warning -Message ('Entity graph: could not record {0}: {1}' -f $url, $_.Exception.Message) }
                # A downloaded certificate is used (to verify signatures, and for the links inside it) only when it is the expected
                # issuer AND its key is proven: otherwise a changed or planted file could steer where this tool connects next.
                if ($null -ne $r.Certificate -and $r.Validated) {
                    $c = $r.Certificate
                    if (-not $certMap.ContainsKey($c.Thumbprint)) { $certMap[$c.Thumbprint] = $c }
                    foreach ($u in (Get-MspkiCertificateUrl -Certificate $c)) {
                        if ($u.Kind -eq 'Error') { continue }
                        [void](Add-MspkiLead -Url $u.Url -Kind $u.Kind -Source ('Cert:{0}:{1}' -f $c.Thumbprint, $u.Kind) `
                            -Origin ('certificate {0} downloaded from {1}' -f $c.Subject, $url) -Depth ($lead.Depth + 1) -Trust 'Verified')
                    }
                }
                elseif ($null -ne $r.Certificate) {
                    Write-MspkiLog -Level Warning -Message ('Certificate {0} downloaded from {1} was not proven to be the expected issuer; its links are not followed.' -f $r.Certificate.Subject, $url)
                }
                if ($null -ne $r.Crl) {
                    $rec = [pscustomobject]@{ Url = $url; Lead = $lead; Crl = $r.Crl; ExpectedIssuer = $expected; ReviewOnly = $grade.ReviewOnly; ReviewReason = $grade.Reason
                        LinksFollowed = $false; LinksNotFollowed = @() }
                    [void]$records.Add($rec)
                    if (@($r.Crl.FreshestCrlUrls).Count -gt 0) { [void]$crlLinkQueue.Add($rec) }
                }
            }
        }
        # Links inside a downloaded CRL (Freshest CRL) are followed only when the CRL's signature verified with a discovered CA
        # certificate (audit 2 H1): an unsigned or changed CRL, served over plain http, must not choose where this tool connects
        # next. This runs after each round, so a CA certificate proven in this round can verify a CRL of the same round.
        # Other CRL extensions (Issuing Distribution Point) are read as facts only and never followed.
        $verifyWith = @($certMap.Values)
        foreach ($rec in @($crlLinkQueue)) {
            $sig = Test-MspkiCrlIssuerSignature -Crl $rec.Crl -Certificates $verifyWith
            if ($sig.Valid -ne $true) { continue }
            $rec.LinksFollowed = $true
            [void]$crlLinkQueue.Remove($rec)
            foreach ($u in @($rec.Crl.FreshestCrlUrls)) {
                [void](Add-MspkiLead -Url $u -Kind 'FreshestCRL' -Source ('Crl:{0}:FreshestCRL' -f $rec.Crl.Sha1) -Trust 'Verified' `
                    -Origin ('CRL of {0} downloaded from {1} (signature verified)' -f $rec.Crl.Issuer, $rec.Url) -Depth ($rec.Lead.Depth + 1) -RelatedCA (@($rec.Lead.RelatedCAs) -join ', '))
            }
        }
        $round++
    } while ($pending.Count -gt 0 -and $round -lt 10)
    foreach ($rec in @($crlLinkQueue)) {
        $rec.LinksNotFollowed = @($rec.Crl.FreshestCrlUrls)
        Write-MspkiLog -Level Warning -Message ('CRL of {0} downloaded from {1}: its signature was not verified with a discovered CA certificate, so its {2} Freshest CRL link(s) were not followed.' -f $rec.Crl.Issuer, $rec.Url, @($rec.Crl.FreshestCrlUrls).Count)
    }
    $left = @(Get-MspkiLead | Where-Object { $kinds -contains $_.Kind -and -not $done.ContainsKey($_.Key) })
    if ($left.Count -gt 0) {
        Write-MspkiLog -Level Warning -Message ('Stopped after {0} rounds of link following; {1} lead(s) were not probed.' -f $round, $left.Count)
        Add-MspkiRunLimit -Text ('Link following stopped after {0} rounds: {1} URL(s) were not probed.' -f $round, $left.Count)
    }

    Write-MspkiLeadLimitSummary
    $allCerts = @($certMap.Values)
    foreach ($rec in $records) { [void]$findings.Add((Test-MspkiCrlHealth -Record $rec -Certificates $allCerts -Thresholds $Thresholds)) }
    $live = @{}
    if ($null -ne $Discovery.PSObject.Properties['CAProperties'] -and $Discovery.CAProperties -is [hashtable]) { $live = $Discovery.CAProperties }
    $ownCrls = @(Get-MspkiCaOwnCrl -EnterpriseCAs @($Discovery.Inventory.EnterpriseCAs) -LiveProperties $live)
    try { Register-MspkiCaOwnCrl -OwnCrls $ownCrls }
    catch { Write-MspkiLog -Level Warning -Message ('Entity graph: could not record the CAs'' own CRLs: {0}' -f $_.Exception.Message) }
    $judgedUrls = @()
    if ($ownCrls.Count -gt 0) {
        $pub = Test-MspkiCaCrlPublication -CaCrls $ownCrls -Records @($records) -Certificates $allCerts -Thresholds $Thresholds
        foreach ($f in $pub.Findings) { [void]$findings.Add($f) }
        $judgedUrls = @($pub.JudgedUrls)
    }
    foreach ($f in (Test-MspkiCrlConsistency -Records @($records) -ExcludeUrl $judgedUrls)) { [void]$findings.Add($f) }
    return , $findings.ToArray()
}
