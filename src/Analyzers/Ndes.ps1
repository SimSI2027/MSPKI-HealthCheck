# NDES / SCEP (REQUIREMENTS 5.7). Candidate hosts come from (1) the CA database (issued certificates of the CEP
# Encryption and Exchange Enrollment Agent (Offline request) templates), (2) URLs in certificates, policy or AD that
# point at a SCEP path. Every candidate that may be probed is first registered as a lead; the probe sends only the
# requests in src/Probes/NdesProbe.ps1, anonymously.
# Classifications: ConfirmedEndpoint, ReferencedEndpoint, ProbableCandidate, UnconfirmedCandidate, NotDiscovered.

function ConvertFrom-MspkiNdesCapabilities {
    <#
    .SYNOPSIS
    Reads the text answer of GetCACaps (one capability per line). Returns { Known, Lines }.
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return [pscustomobject]@{ Known = $false; Lines = @() } }
    $text = [System.Text.Encoding]::ASCII.GetString($Bytes, 0, [math]::Min($Bytes.Length, 4096))
    $lines = @($text -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[A-Za-z0-9\-]{2,40}$' } | Select-Object -First 20)
    $known = (@($lines | Where-Object { $_ -match '(?i)^(POSTPKIOperation|SHA-1|SHA-256|SHA-512|DES3|AES|Renewal|GetNextCACert|SCEPStandard)$' }).Count -gt 0)
    return [pscustomobject]@{ Known = $known; Lines = $lines }
}

function ConvertFrom-MspkiNdesCaCertificate {
    <#
    .SYNOPSIS
    Reads the answer of GetCACert: one certificate or a PKCS #7 with the CA and RA certificates. Returns the
    certificates as public data (subject, thumbprint, validity).
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Bytes, [DateTime]$Now = [DateTime]::UtcNow)
    $out = New-Object System.Collections.ArrayList
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return , $out.ToArray() }
    $certs = @()
    try { $certs = @(New-MspkiCertificate -Bytes $Bytes) } catch { }
    if ($certs.Count -eq 0) {
        try {
            $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $col.Import($Bytes)
            $certs = @($col | ForEach-Object { $_ })
        }
        catch { }
    }
    foreach ($c in $certs) {
        $na = $c.NotAfter.ToUniversalTime()
        [void]$out.Add([pscustomobject][ordered]@{
            Subject = $c.Subject; Thumbprint = $c.Thumbprint; NotAfter = $na.ToString('yyyy-MM-ddTHH:mm:ssZ'); Expired = ($na -lt $Now.ToUniversalTime()) })
    }
    return , $out.ToArray()
}

function Get-MspkiByteCount {
    [CmdletBinding()]
    param([AllowNull()]$Bytes)
    if ($null -eq $Bytes) { return 0 }
    return $Bytes.Length
}

function Test-MspkiIsLocalHost {
    <#
    .SYNOPSIS
    True when a host name is this computer (short name or FQDN). Pure: the computer's own names are parameters.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$HostName, [string]$ComputerName = $env:COMPUTERNAME, [string]$DnsDomain = '')
    $h = ConvertTo-MspkiHostName $HostName
    $c = ConvertTo-MspkiHostName $ComputerName
    if (-not $h -or -not $c) { return $false }
    if ($h -eq $c) { return $true }
    $d = ConvertTo-MspkiHostName $DnsDomain
    if ($d -and $h -eq ('{0}.{1}' -f $c, $d)) { return $true }
    return $false
}

function Get-MspkiNdesLeadOption {
    <#
    .SYNOPSIS
    The transports a NDES lead allows: its own http/https variants (with port). A lead found by evidence only has
    both default variants; a referenced URL keeps exactly the scheme and port it was referenced with.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Lead)
    $o = New-Object System.Collections.ArrayList
    foreach ($v in @($Lead.Variants)) {
        $n = ConvertTo-MspkiNormalizedUrl -Url $v
        if ($n.Valid -and $n.UrlType -eq 'Http') { [void]$o.Add(@{ Scheme = $n.Scheme; Port = $n.Port }) }
    }
    return , $o.ToArray()
}

function Test-MspkiNdesHost {
    <#
    .SYNOPSIS
    Probes one NDES lead with the allowed requests and returns the findings and the classification.

    .PARAMETER Info
    What is known about the host from evidence: { Origin (Referenced / Probable / Unconfirmed), Lines (evidence text),
    Sources, RelatedCAs }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lead,
        [Parameter(Mandatory = $true)]$Info,
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork,
        [DateTime]$Now = [DateTime]::UtcNow
    )
    $findings = New-Object System.Collections.ArrayList
    $ms = $TimeoutSeconds * 1000
    $hostName = $Lead.Host
    $initial = switch ($Info.Origin) { 'Referenced' { 'ReferencedEndpoint' } 'Probable' { 'ProbableCandidate' } default { 'UnconfirmedCandidate' } }
    $conf = 'Inferred'; if ($Info.Origin -eq 'Referenced') { $conf = 'Referenced' }
    $related = (@($Info.RelatedCAs) -join ', ')
    $ev = New-Object System.Collections.ArrayList
    [void]$ev.Add(('Classification: {0}' -f $initial))
    foreach ($l in @($Info.Lines)) { [void]$ev.Add($l) }
    foreach ($o in @($Lead.Origins)) { [void]$ev.Add(('Found in: {0}' -f $o)) }
    $layers = @{ DiscoveryStatus = 'Pass' }
    $mk = {
        param($st, $cd, $msg, $cf, $extraEv, $notes)
        New-MspkiFinding -Stage 'Probe' -Category 'NDES' -Role 'NDESEndpoint' -Target $hostName -Endpoint $Lead.Url -RelatedCA $related -Status $st -StatusCode $cd `
            -Confidence $cf -Sources @($Info.Sources) -Scope $Lead.Scope -Message $msg -Evidence (@($ev) + @($extraEv)) -Layers $layers -Notes $notes
    }
    $result = [pscustomobject]@{ Findings = $findings; Classification = $initial; Confirmed = $false; Host = $hostName }

    if ($SkipNetwork) {
        $layers['DnsStatus'] = 'Skipped'
        [void]$findings.Add((& $mk 'Skipped' 'NOT_APPLICABLE' ('NDES host {0} ({1}) was not probed because -SkipNetwork was used.' -f $hostName, $initial) $conf @() ''))
        return $result
    }
    $tr = Get-MspkiNdesTransport -HostName $hostName -Option (Get-MspkiNdesLeadOption -Lead $Lead) -TimeoutMs $ms
    $layers['DnsStatus'] = $tr.Dns.Status
    if ($tr.Dns.Status -eq 'Pass') { [void]$ev.Add(('DNS: {0}' -f ($tr.Dns.Addresses -join ', '))) } else { [void]$ev.Add(('DNS: {0} {1}' -f $tr.Dns.Status, $tr.Dns.Error)) }
    foreach ($a in $tr.Attempts) { [void]$ev.Add($a) }
    if ($tr.Dns.Status -eq 'Pass') { $layers['TcpStatus'] = 'Fail' }
    if ($null -ne $tr.Tls) { $layers['TlsStatus'] = $(if ($tr.Tls.Code -eq 'OK') { 'Pass' } else { 'Fail' }) }
    if ($null -eq $tr.Chosen) {
        if ($tr.FailLayer -eq 'Tls') { $layers['TcpStatus'] = 'Pass' }
        $st = 'Information'; if ($Info.Origin -eq 'Referenced') { $st = 'Fail' }
        $what = 'did not answer'
        if ($tr.FailLayer -eq 'Tls') { $st = 'Warning'; $what = 'accepts connections but the TLS handshake failed, so no request was sent' }
        $code = $tr.FailCode; if (-not $code) { $code = 'RETRIEVAL_FAIL' }
        [void]$findings.Add((& $mk $st $code ('NDES host {0} ({1}): {2}. No SCEP request was sent.' -f $hostName, $initial, $what) $conf @() `
            'A TLS trust problem seen from this computer is not the same as the service being down.'))
        return $result
    }
    $layers['TcpStatus'] = 'Pass'
    $scheme = $tr.Chosen.Scheme; $port = $tr.Chosen.Port
    [void]$ev.Add(('Transport chosen: {0} on port {1}' -f $scheme, $port))
    $resp = Invoke-MspkiNdesProbe -HostName $hostName -Scheme $scheme -Port $port -TimeoutMs $ms

    $confirmed = $false
    $extra = New-Object System.Collections.ArrayList
    # GetCACaps
    $caps = $resp.GetCACaps
    if ($caps.HttpStatus -eq 200) {
        $c = ConvertFrom-MspkiNdesCapabilities -Bytes $caps.Bytes
        if ($c.Known) { $confirmed = $true; [void]$extra.Add(('GetCACaps: HTTP 200, SCEP capabilities: {0}' -f ($c.Lines -join ', '))) }
        else { [void]$extra.Add(('GetCACaps: HTTP 200 but the content is not a SCEP capability list ({0} bytes)' -f (Get-MspkiByteCount $caps.Bytes))) }
    }
    else { [void]$extra.Add(('GetCACaps: HTTP {0} {1}{2}' -f $caps.HttpStatus, $caps.Code, $(if ($caps.Redirected) { ' (redirect not followed)' } else { '' }))) }
    # GetCACert
    $cc = $resp.GetCACert
    $certs = @()
    if ($cc.HttpStatus -eq 200) {
        $certs = @(ConvertFrom-MspkiNdesCaCertificate -Bytes $cc.Bytes -Now $Now)
        if ($certs.Count -gt 0) {
            $confirmed = $true
            [void]$extra.Add(('GetCACert: HTTP 200, {0} certificate(s) ({1})' -f $certs.Count, $cc.ContentType))
            foreach ($x in $certs) { [void]$extra.Add(('  certificate {0} [{1}] valid until {2}{3}' -f $x.Subject, $x.Thumbprint, $x.NotAfter, $(if ($x.Expired) { ' (EXPIRED)' } else { '' }))) }
        }
        else { [void]$extra.Add(('GetCACert: HTTP 200 but the content is not a certificate ({0}, {1} bytes)' -f $cc.ContentType, (Get-MspkiByteCount $cc.Bytes))) }
    }
    else { [void]$extra.Add(('GetCACert: HTTP {0} {1}{2}' -f $cc.HttpStatus, $cc.Code, $(if ($cc.Redirected) { ' (redirect not followed)' } else { '' }))) }
    # Anonymous admin request
    $ad = $resp.AdminAnonymous
    $adminExists = ($ad.HttpStatus -eq 401 -or $ad.HttpStatus -eq 403)
    if ($adminExists) { $confirmed = $true; [void]$extra.Add(('Admin page (anonymous request): HTTP {0}: the page exists and asks for authentication. No credentials were sent and the body was not read.' -f $ad.HttpStatus)) }
    else { [void]$extra.Add(('Admin page (anonymous request): HTTP {0} {1}. No credentials were sent and the body was not read.' -f $ad.HttpStatus, $ad.Code)) }

    $layers['HttpStatus'] = $(if ($confirmed) { 'Pass' } else { 'Fail' })
    $layers['ContentStatus'] = $(if ($confirmed) { 'Pass' } else { 'Fail' })
    if ($confirmed) {
        $result.Confirmed = $true; $result.Classification = 'ConfirmedEndpoint'
        $ev[0] = 'Classification: ConfirmedEndpoint (evidence classification before the probe: {0})' -f $initial
        [void]$findings.Add((& $mk 'Pass' 'OK' ('NDES host {0} answers SCEP requests (ConfirmedEndpoint).' -f $hostName) 'Confirmed' @($extra) `
            'Only GetCACaps, GetCACert and one anonymous request to the admin page were sent. Nothing was enrolled and no challenge password was requested.'))
        if ($ad.HttpStatus -eq 200) {
            [void]$findings.Add((New-MspkiFinding -Stage 'Probe' -Category 'NDES' -Role 'NDESEndpoint' -Target $hostName -Endpoint (New-MspkiNdesRequestUrl -Name AdminAnonymous -HostName $hostName -Scheme $scheme -Port $port) `
                -RelatedCA $related -Status 'Fail' -StatusCode 'CONFIG_RISK' -Severity 'High' -Confidence 'Confirmed' -Sources @($Info.Sources) -Scope $Lead.Scope `
                -Layers @{ DiscoveryStatus = 'Pass'; HttpStatus = 'Pass' } `
                -Message ('The NDES admin page on {0} answered an anonymous request with HTTP 200.' -f $hostName) `
                -Evidence @('Classification: ConfirmedEndpoint', 'The anonymous request was answered with HTTP 200; the page is normally protected by Windows authentication (HTTP 401).', 'The response body was not read.') `
                -Remediation 'Review only: no change is made or suggested automatically.' `
                -Notes 'The admin page hands out challenge passwords for SCEP enrollment. Check the authentication settings of this site.'))
        }
        foreach ($x in @($certs | Where-Object { $_.Expired })) {
            [void]$findings.Add((New-MspkiFinding -Stage 'Probe' -Category 'NDES' -Role 'NDESEndpoint' -Target $hostName -Endpoint $Lead.Url -RelatedCA $related -Status 'Warning' `
                -StatusCode 'OBJECT_EXPIRED' -Confidence 'Confirmed' -Sources @($Info.Sources) -Scope $Lead.Scope -Layers @{ DiscoveryStatus = 'Pass'; ContentStatus = 'Fail' } `
                -Message ('A certificate returned by GetCACert on {0} has expired: {1}.' -f $hostName, $x.Subject) `
                -Evidence @(('Certificate {0} [{1}] expired {2}' -f $x.Subject, $x.Thumbprint, $x.NotAfter)) `
                -Notes 'NDES uses an enrollment agent (RA) certificate; devices fail to enroll when it has expired.'))
        }
        return $result
    }
    $st = 'Information'; if ($Info.Origin -eq 'Referenced') { $st = 'Fail' }
    $code = 'RETRIEVAL_FAIL'
    if ($caps.Code -and $caps.Code -ne 'OK') { $code = $caps.Code }
    [void]$findings.Add((& $mk $st $code ('NDES host {0} ({1}) accepts connections but did not answer as a SCEP service.' -f $hostName, $initial) $conf @($extra) `
        'The host may no longer run NDES, may use another site name, or may require a different scheme or port.'))
    return $result
}

function Invoke-MspkiNdesAnalysis {
    <#
    .SYNOPSIS
    Finds NDES candidate hosts (CA database evidence and referenced SCEP URLs), registers them as leads, probes each
    with the allowed anonymous requests and classifies them.

    .OUTPUTS
    { Findings, Hosts } where Hosts lists { Host, Classification, Confirmed } for the Intune connector step.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Discovery,
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork
    )
    $findings = New-Object System.Collections.ArrayList
    $hosts = New-Object System.Collections.ArrayList
    $inv = $Discovery.Inventory
    $ctx = $inv.AdContext
    $info = @{}

    # 1. URLs that point at a SCEP path (certificates, policy, AD): ReferencedEndpoint. Probed on exactly that scheme and port.
    foreach ($l in @(Get-MspkiLead | Where-Object { $_.Kind -ne 'NDES' -and (@($_.Variants) | Where-Object { Test-MspkiNdesUrl $_ }) })) {
        foreach ($v in @($l.Variants | Where-Object { Test-MspkiNdesUrl $_ })) {
            $n = ConvertTo-MspkiNormalizedUrl -Url $v
            if (-not $n.Valid -or $n.UrlType -ne 'Http') { continue }
            $nl = $null
            try { $nl = Add-MspkiLead -Url (Get-MspkiNdesBaseUrl -HostName $n.Host -Scheme $n.Scheme -Port $n.Port) -Kind 'NDES' -Source (@($l.Sources)[0]) -Origin ('SCEP URL {0} referenced by lead {1} ({2})' -f $v, $l.Id, $l.Kind) -RelatedCA (@($l.RelatedCAs) -join ', ') }
            catch { Write-MspkiLog -Level Warning -Message ('SCEP URL ignored: {0}' -f $_.Exception.Message); continue }
            if ($null -eq $nl) { continue }
            if (-not $info.ContainsKey($nl.Host)) { $info[$nl.Host] = @{ Origin = 'Referenced'; Lines = (New-Object System.Collections.ArrayList); Sources = (New-Object System.Collections.ArrayList); RelatedCAs = (New-Object System.Collections.ArrayList) } }
            $i = $info[$nl.Host]; $i.Origin = 'Referenced'
            [void]$i.Lines.Add(('Referenced URL: {0} (source: {1})' -f $v, (@($l.Sources) -join ', ')))
            foreach ($s in @($l.Sources)) { if (-not $i.Sources.Contains($s)) { [void]$i.Sources.Add($s) } }
        }
    }

    # 2. CA database evidence
    $domainMap = @{}
    $forestDomains = @()
    if ($null -ne $ctx) { $forestDomains = @($ctx.ForestDomains) }
    $caRead = 0; $rowsTotal = 0
    $candidates = New-Object System.Collections.ArrayList
    $evidenceCas = @($inv.EnterpriseCAs | Where-Object { $_ -and $_.Config })
    if ($evidenceCas.Count -gt 0 -and -not $SkipNetwork -and $null -ne $ctx -and $ctx.Ready) { $domainMap = Get-MspkiNetBiosDomainMap -Context $ctx -TimeoutSeconds $TimeoutSeconds }
    foreach ($ca in $evidenceCas) {
        $ev = Get-MspkiNdesCaEvidence -CA $ca -Inventory $inv -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork
        foreach ($f in $ev.Findings) { [void]$findings.Add($f) }
        if ($ev.Read) { $caRead++; $rowsTotal += @($ev.Rows).Count }
        $found = Get-MspkiNdesHostCandidate -Rows $ev.Rows -CaName $ca.Name -DomainMap $domainMap -ForestDomains $forestDomains
        foreach ($c in $found) { [void]$candidates.Add($c) }
    }
    $merged = @{}
    foreach ($c in $candidates) {
        $k = $c.ShortName.ToLowerInvariant()
        if (-not $merged.ContainsKey($k)) { $merged[$k] = $c } else { foreach ($ca in $c.CAs) { if (-not $merged[$k].CAs.Contains($ca)) { [void]$merged[$k].CAs.Add($ca) } }; $merged[$k].Rows += $c.Rows }
    }
    foreach ($c in ($merged.Values | Sort-Object ShortName)) {
        $lines = @(('CA database: {0} issued certificate(s) from {1} (latest valid until {2}) on {3}' -f $c.Rows, ($c.Templates -join ', '), $c.LatestNotAfter, ($c.CAs -join ', ')))
        $lines += @($c.Signals | ForEach-Object { 'Signal: {0}' -f $_ })
        $lines += ('Requester(s): {0}' -f ($c.Requesters -join ', '))
        $src = @(@($c.CAs | ForEach-Object { 'CA:{0}:NdesTemplates' -f $_ }) + 'CA:CertificateAuthority.View')
        if (-not $c.Fqdn) {
            $lines += 'No DNS name could be built for this host (the requester''s domain is not known from AD), so nothing was sent to it.'
            [void]$findings.Add((New-MspkiFinding -Stage 'Discovery' -Category 'NDES' -Role 'NDESEndpoint' -Target $c.ShortName -RelatedCA ($c.CAs -join ', ') -Status 'Information' -StatusCode 'NOT_DISCOVERED' `
                -Confidence 'Inferred' -Sources $src -Scope 'Unknown' -Layers @{ DiscoveryStatus = 'Pass' } `
                -Message ('NDES host candidate {0} (UnconfirmedCandidate): the CA issued NDES-template certificates to it, but no DNS name could be built.' -f $c.ShortName) `
                -Evidence (@('Classification: UnconfirmedCandidate') + $lines) -Notes 'Only hosts that resolve in DNS are probed.'))
            [void]$hosts.Add([pscustomobject]@{ Host = $c.ShortName; Classification = 'UnconfirmedCandidate'; Confirmed = $false })
            continue
        }
        $lines += ('Host name built from {0}: {1} (a constructed name; it is checked in DNS before anything is sent)' -f $c.DomainSource, $c.Fqdn)
        $dns = $null
        if (-not $SkipNetwork) { $dns = Resolve-MspkiDnsName -HostName $c.Fqdn -TimeoutMs ($TimeoutSeconds * 1000) }
        if ($null -ne $dns -and $dns.Status -ne 'Pass') {
            $lines += ('DNS: {0} {1}' -f $dns.Status, $dns.Error)
            [void]$findings.Add((New-MspkiFinding -Stage 'Discovery' -Category 'NDES' -Role 'NDESEndpoint' -Target $c.Fqdn -RelatedCA ($c.CAs -join ', ') -Status 'Information' -StatusCode $dns.StatusCode `
                -Confidence 'Inferred' -Sources $src -Scope 'Unknown' -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = $dns.Status } `
                -Message ('NDES host candidate {0} (UnconfirmedCandidate): the CA issued NDES-template certificates to it, but the name does not resolve. Nothing was sent.' -f $c.Fqdn) `
                -Evidence (@('Classification: UnconfirmedCandidate') + $lines) `
                -Notes 'The server may have been retired or renamed. This is a candidate only.'))
            [void]$hosts.Add([pscustomobject]@{ Host = $c.Fqdn; Classification = 'UnconfirmedCandidate'; Confirmed = $false })
            continue
        }
        # Resolves (or not tested with -SkipNetwork): register both variants of the SCEP URL as one NDES lead.
        $u1 = Get-MspkiNdesBaseUrl -HostName $c.Fqdn -Scheme https
        $u2 = Get-MspkiNdesBaseUrl -HostName $c.Fqdn -Scheme http
        $nl = Add-MspkiLead -Url $u1 -Kind 'NDES' -Source $src[0] -Origin ('NDES template evidence in the CA database of {0}' -f ($c.CAs -join ', ')) -RelatedCA ($c.CAs -join ', ') -Confidence 'Inferred'
        $null = Add-MspkiLead -Url $u2 -Kind 'NDES' -Source $src[0] -Origin ('NDES template evidence in the CA database of {0}' -f ($c.CAs -join ', ')) -RelatedCA ($c.CAs -join ', ') -Confidence 'Inferred'
        if ($null -eq $nl) { continue }
        if (-not $info.ContainsKey($nl.Host)) { $info[$nl.Host] = @{ Origin = 'Probable'; Lines = (New-Object System.Collections.ArrayList); Sources = (New-Object System.Collections.ArrayList); RelatedCAs = (New-Object System.Collections.ArrayList) } }
        $i = $info[$nl.Host]
        if ($i.Origin -ne 'Referenced') { $i.Origin = 'Probable' }
        foreach ($l in $lines) { [void]$i.Lines.Add($l) }
        foreach ($s in $src) { if (-not $i.Sources.Contains($s)) { [void]$i.Sources.Add($s) } }
        foreach ($ca in $c.CAs) { if (-not $i.RelatedCAs.Contains($ca)) { [void]$i.RelatedCAs.Add($ca) } }
    }

    # 3. Probe every NDES lead (and only those).
    foreach ($lead in @(Get-MspkiLead -Kind 'NDES')) {
        $i = $info[$lead.Host]
        if ($null -eq $i) { $i = @{ Origin = 'Referenced'; Lines = @(); Sources = @($lead.Sources); RelatedCAs = @($lead.RelatedCAs) } }
        $infoObj = [pscustomobject]@{ Origin = $i.Origin; Lines = @($i.Lines); Sources = @($i.Sources); RelatedCAs = @($i.RelatedCAs) }
        if (@($infoObj.Sources).Count -eq 0) { $infoObj.Sources = @($lead.Sources) }
        $r = Test-MspkiNdesHost -Lead $lead -Info $infoObj -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork
        foreach ($f in $r.Findings) { [void]$findings.Add($f) }
        [void]$hosts.Add([pscustomobject]@{ Host = $lead.Host; Classification = $r.Classification; Confirmed = $r.Confirmed })
    }

    # 4. Nothing found: say why that is not proof.
    if ($hosts.Count -eq 0) {
        $pub = @()
        foreach ($ca in @($inv.EnterpriseCAs)) {
            foreach ($t in $script:MspkiNdesTemplateNames) {
                if (@($ca.Templates | Where-Object { $_ -ieq $t.Name }).Count -gt 0) { $pub += ('Template {0} ({1}) is published by {2}' -f $t.Name, $t.Display, $ca.Name) }
            }
        }
        $ev = @(('CAs whose database was read for NDES evidence: {0} of {1}' -f $caRead, $evidenceCas.Count), ('Issued certificates from the NDES templates visible to this account: {0}' -f $rowsTotal),
            'URLs found in certificates, policy or AD that point at a SCEP path: 0') + $pub
        [void]$findings.Add((New-MspkiFinding -Stage 'Analysis' -Category 'NDES' -Role 'NDESEndpoint' -Target 'NDES' -Status 'NotApplicable' -StatusCode 'NOT_DISCOVERED' -Confidence 'Confirmed' `
            -Sources @('CA:CertificateAuthority.View', 'AD:EnrollmentServices:certificateTemplates') -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } `
            -Message 'Classification NotDiscovered: no NDES / SCEP server was found from the CA databases or from references.' -Evidence (@('Classification: NotDiscovered') + $ev) `
            -Notes 'NDES detection depends on read rights to the CA database or on references existing. An account that is not a CA administrator or certificate manager sees only its own requests, so this does not prove that no NDES server exists.'))
    }
    return [pscustomobject]@{ Findings = @($findings); Hosts = @($hosts) }
}
