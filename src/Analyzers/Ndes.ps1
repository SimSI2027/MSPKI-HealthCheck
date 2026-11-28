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
    param([AllowNull()][byte[]]$Bytes, [DateTime]$Now = (Get-MspkiUtcNow))
    $out = New-Object System.Collections.ArrayList
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return , $out.ToArray() }
    # Only a certificate or a PKCS #7 is read; a PKCS #12 / PFX is refused before any object is built (audit 2 M10).
    $certs = @((ConvertFrom-MspkiCertificateBytes -Bytes $Bytes).Certificates)
    foreach ($c in $certs) {
        $na = $c.NotAfter.ToUniversalTime()
        $isCA = $false
        $bc = Get-MspkiCertificateExtension -Certificate $c -Oid $script:MspkiOid.BasicConstraints
        if ($null -ne $bc) { $isCA = (New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($bc, $bc.Critical)).CertificateAuthority }
        $ekus = @(Get-MspkiCertificateEku -Certificate $c)
        $ku = ''
        $kux = Get-MspkiCertificateExtension -Certificate $c -Oid $script:MspkiOid.KeyUsage
        if ($null -ne $kux) { $ku = [string](New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension($kux, $kux.Critical)).KeyUsages }
        # GetCACert returns the CA certificate(s) and the NDES RA certificates (signing and encryption, Certificate Request Agent EKU).
        $role = $(if ($isCA) { 'CA' } elseif ($ekus -contains $script:MspkiCertRequestAgentOid) { 'RA' } else { 'Other' })
        $ti = ConvertFrom-MspkiTemplateExtension -Certificate $c
        [void]$out.Add([pscustomobject][ordered]@{
            Subject = $c.Subject; Thumbprint = $c.Thumbprint; NotAfter = $na.ToString('yyyy-MM-ddTHH:mm:ssZ'); Expired = ($na -lt $Now.ToUniversalTime())
            Issuer = $c.Issuer; NotBefore = $c.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); Role = $role; Eku = $ekus; KeyUsage = $ku
            SubjectKeyId = (Get-MspkiCertificateSubjectKeyId -Certificate $c); AuthorityKeyId = (Get-MspkiCertificateAuthorityKeyId -Certificate $c)
            TemplateOid = $(if ($null -ne $ti) { $ti.Oid } else { '' }); TemplateName = $(if ($null -ne $ti) { $ti.Name } else { '' }) })
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
    param([AllowEmptyString()][string]$HostName, [string]$ComputerName = (Get-MspkiLocalComputerName), [string]$DnsDomain = '')
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
        [switch]$IncludeAdminProbe,
        [DateTime]$Now = (Get-MspkiUtcNow)
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
        $e = @($ev) + @($extraEv)
        # A reference to another environment goes to review and is never graded as a failure (REQUIREMENTS 4.2).
        $sc = Resolve-MspkiScopeStatus -Status $st -Scope $Lead.Scope
        if ($sc.Capped) { $st = $sc.Status; $e += $sc.Evidence }
        New-MspkiFinding -Stage 'Probe' -Category 'NDES' -Role 'NDESEndpoint' -Target $hostName -Endpoint $Lead.Url -RelatedCA $related -Status $st -StatusCode $cd `
            -Confidence $cf -Sources @($Info.Sources) -Scope $Lead.Scope -Message $msg -Evidence $e -Layers $layers -Notes $notes -Severity $sc.Severity
    }
    $result = [pscustomobject]@{ Findings = $findings; Classification = $initial; Confirmed = $false; Host = $hostName; Certificates = @(); CertUrl = '' }

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
    $resp = Invoke-MspkiNdesProbe -HostName $hostName -Scheme $scheme -Port $port -TimeoutMs $ms -IncludeAdmin:$IncludeAdminProbe
    [void]$ev.Add(('HTTP proxy: {0}' -f $resp.GetCACaps.ProxyMode))

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
        # The parser returns its list as one object; unroll it (with several certificates a wrapped list would turn every field into an array).
        $certs = @(ConvertFrom-MspkiNdesCaCertificate -Bytes $cc.Bytes -Now $Now | ForEach-Object { $_ })
        $result.Certificates = $certs; $result.CertUrl = [string]$cc.Url
        if ($certs.Count -gt 0) {
            $confirmed = $true
            [void]$extra.Add(('GetCACert: HTTP 200, {0} certificate(s) ({1})' -f $certs.Count, $cc.ContentType))
            foreach ($x in $certs) {
                $tn = $(if ($x.TemplateName) { ', template ' + $x.TemplateName } elseif ($x.TemplateOid) { ', template ' + $x.TemplateOid } else { '' })
                [void]$extra.Add(('  {4} certificate {0} [{1}] valid until {2}{3}, issued by {5}{6}' -f $x.Subject, $x.Thumbprint, $x.NotAfter, $(if ($x.Expired) { ' (EXPIRED)' } else { '' }), $x.Role, $x.Issuer, $tn))
            }
        }
        else { [void]$extra.Add(('GetCACert: HTTP 200 but the content is not a certificate ({0}, {1} bytes)' -f $cc.ContentType, (Get-MspkiByteCount $cc.Bytes))) }
    }
    else { [void]$extra.Add(('GetCACert: HTTP {0} {1}{2}' -f $cc.HttpStatus, $cc.Code, $(if ($cc.Redirected) { ' (redirect not followed)' } else { '' }))) }
    # Anonymous admin request: only when it was asked for (-IncludeNdesAdminProbe). It never confirms an endpoint: IIS answers 401 for
    # every path below a site that requires Windows authentication, and a WAF or an IP restriction answers 403 for every path.
    $ad = $resp.AdminAnonymous
    $adminExists = $false
    if ($null -eq $ad) {
        [void]$extra.Add('Admin page: not requested. The anonymous request to the admin page is opt-in (-IncludeNdesAdminProbe), because an admin page that is wrongly open to anonymous users creates a challenge password when it is requested.')
    }
    else {
        $adminExists = ($ad.HttpStatus -eq 401 -or $ad.HttpStatus -eq 403)
        if ($adminExists) { [void]$extra.Add(('Admin page (anonymous request): HTTP {0}: something on this host asks for authentication at that path. This does not confirm NDES. No credentials were sent and the body was not read.' -f $ad.HttpStatus)) }
        else { [void]$extra.Add(('Admin page (anonymous request): HTTP {0} {1}. No credentials were sent and the body was not read.' -f $ad.HttpStatus, $ad.Code)) }
    }

    $layers['HttpStatus'] = $(if ($confirmed) { 'Pass' } else { 'Fail' })
    $layers['ContentStatus'] = $(if ($confirmed) { 'Pass' } else { 'Fail' })
    if ($confirmed) {
        $result.Confirmed = $true; $result.Classification = 'ConfirmedEndpoint'
        $ev[0] = 'Classification: ConfirmedEndpoint (evidence classification before the probe: {0})' -f $initial
        $sent = 'Only GetCACaps and GetCACert were sent. Nothing was enrolled and no challenge password was requested.'
        if ($null -ne $ad) { $sent = 'Only GetCACaps, GetCACert and one anonymous request to the admin page were sent. Nothing was enrolled and no challenge password was requested.' }
        [void]$findings.Add((& $mk 'Pass' 'OK' ('NDES host {0} answers SCEP requests (ConfirmedEndpoint).' -f $hostName) 'Confirmed' @($extra) $sent))
        if ($null -ne $ad -and $ad.HttpStatus -eq 200) {
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
    # HTTP 200 without a SCEP capability list is wrong content, not a failure to retrieve; every other answer keeps its own code.
    $code = 'CONTENT_WRONG_TYPE'
    if ($caps.Code -and $caps.Code -ne 'OK') { $code = $caps.Code }
    $why = 'The host may no longer run NDES, may use another site name, or may require a different scheme or port.'
    if ($adminExists) { $why = 'The admin path answered with an authentication request, but IIS does that for every path below a protected site, so it is not evidence of NDES. ' + $why }
    [void]$findings.Add((& $mk $st $code ('NDES host {0} ({1}) accepts connections but did not answer as a SCEP service.' -f $hostName, $initial) $conf @($extra) $why))
    return $result
}

function Add-MspkiNdesTemplateAccessToGraph {
    <#
    .SYNOPSIS
    Accounts that may enroll from the NDES RA templates: Account entities (Seen in AD, or ExpectedMissing when the SID cannot be read),
    mayEnroll -> Template, and identifies -> Host for every host name the account gives (Inferred: a name, not proof of NDES).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result)
    foreach ($p in @($Result.Principals | Where-Object { $_.Class -eq 'Candidate' })) {
        $a = $p.Account
        $name = $(if ($null -ne $a -and $a.SamAccountName) { $a.SamAccountName } elseif ($p.Principal) { $p.Principal } else { $p.Sid })
        $props = @{ Sid = $p.Sid; Lookup = [string]$p.Lookup }
        if ($null -ne $a) { $props += @{ SamAccountName = $a.SamAccountName; AccountClass = $a.Class; DistinguishedName = $a.DistinguishedName; Spns = @($a.Spns); DnsHostName = $a.DnsHostName; Disabled = [bool]$a.Disabled } }
        $aid = Add-MspkiEntity -Type 'Account' -Key $p.Sid -Name $name -Properties $props
        if ($p.Lookup -eq 'Found') { Add-MspkiObservation -EntityId $aid -Kind 'Seen' -Source 'AD' -Location $a.DistinguishedName -Confidence 'Confirmed' -Detail ('{0}; SPNs: {1}' -f $a.Class, (@($a.Spns) -join ', ')) }
        elseif ($p.Lookup -eq 'NotFound') { Add-MspkiObservation -EntityId $aid -Kind 'ExpectedMissing' -Source 'AD' -Location ('<SID={0}>' -f $p.Sid) -Confidence 'Unknown' -Detail ('Named in the permissions of {0}; not readable: deleted, or hidden from this account' -f (@($p.Templates) -join ', ')) }
        foreach ($t in @($p.Templates)) {
            # The template was read from AD (its ACL is where this account came from), so the entity exists or is added here.
            $tid = Add-MspkiEntity -Type 'Template' -Key $t -Name $t
            Add-MspkiRelation -From $aid -Type 'mayEnroll' -To $tid -Source 'AD:CertificateTemplates:nTSecurityDescriptor' -Confidence 'Confirmed'
        }
        # The hosts the principal names itself; a host that only a member account names is linked from that member (audit 2 M12).
        $own = @($p.Hosts)
        if ($null -ne $p.PSObject.Properties['OwnHosts']) { $own = @($p.OwnHosts) }
        foreach ($h in $own) { Add-MspkiRelation -From $aid -Type 'identifies' -To (Add-MspkiHostEntity -HostName $h) -Source 'AD:servicePrincipalName/dNSHostName' -Confidence 'Inferred' }
        if ($null -ne $p.PSObject.Properties['Members']) {
            foreach ($m in @($p.Members | Where-Object { $_ })) {
                $mkey = $(if ($m.Sid) { $m.Sid } else { 'dn:' + ([string]$m.DistinguishedName).ToLowerInvariant() })
                $mid = Add-MspkiEntity -Type 'Account' -Key $mkey -Name $(if ($m.Name) { $m.Name } else { $m.DistinguishedName }) -Properties @{
                    Sid = $m.Sid; SamAccountName = $m.Name; AccountClass = $m.Class; DistinguishedName = $m.DistinguishedName; Spns = @($m.Spns); DnsHostName = $m.DnsHostName; Disabled = [bool]$m.Disabled; Lookup = 'Found' }
                Add-MspkiObservation -EntityId $mid -Kind 'Seen' -Source 'AD' -Location $m.DistinguishedName -Confidence 'Confirmed' -Detail ('{0}; named by {1} of {2}' -f $m.Class, $(if ($m.Relation -eq 'mayUse') { 'msDS-GroupMSAMembership' } else { 'the member attribute' }), $name)
                $src = $(if ($m.Relation -eq 'mayUse') { 'AD:msDS-GroupMSAMembership' } else { 'AD:member' })
                Add-MspkiRelation -From $mid -Type $m.Relation -To $aid -Source $src -Confidence 'Confirmed'
                foreach ($h in @($m.Hosts)) { Add-MspkiRelation -From $mid -Type 'identifies' -To (Add-MspkiHostEntity -HostName $h) -Source 'AD:servicePrincipalName/dNSHostName' -Confidence 'Inferred' }
            }
        }
    }
}

function Add-MspkiNdesResultToGraph {
    <#
    .SYNOPSIS
    One probed NDES lead in the graph: the NDES Service (Seen only when it answered SCEP), its endpoint and host, and every certificate
    GetCACert returned: the CA certificate (Seen at that URL; the service enrollsVia that CA) and the RA certificates (RACertificate,
    certificateOf the service, issuedBy the CA certificate whose SKI is their AKI).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)]$Lead, [AllowEmptyCollection()][object[]]$Templates = @())
    $h = ConvertTo-MspkiHostName $Result.Host
    if (-not $h) { return }
    $hid = Add-MspkiHostEntity -HostName $h -Role $(if ($Result.Confirmed) { 'NDES' } else { 'NDESCandidate' })
    $sid = Add-MspkiEntity -Type 'Service' -Key ('ndes:' + $h) -Name ('NDES / SCEP on {0}' -f $h) -Properties @{ Kind = 'NDES'; HostName = $h; Url = [string]$Lead.Url }
    (Get-MspkiEntity -Id $sid).Properties['Classification'] = $Result.Classification
    $conf = $(if ($Result.Confirmed) { 'Confirmed' } else { 'Inferred' })
    $eid = Add-MspkiEndpointEntity -Url ([string]$Lead.Url) -Kind 'NDES'
    Add-MspkiRelation -From $eid -Type 'servedBy' -To $sid -Source 'NDES' -Confidence $conf
    Add-MspkiRelation -From $sid -Type 'hostedOn' -To $hid -Source 'NDES' -Confidence $conf
    if ($Result.Confirmed) { Add-MspkiObservation -EntityId $sid -Kind 'Seen' -Source 'HTTP' -Location $(if ($Result.CertUrl) { $Result.CertUrl } else { [string]$Lead.Url }) -Confidence 'Confirmed' -Detail 'Answers GetCACaps / GetCACert' }
    $certs = @($Result.Certificates | Where-Object { $null -ne $_ })
    # NDES enrolls through the CA that issued its RA certificates (RA AKI = CA SKI); the other CA certificates are only the chain.
    $raIssuerKeys = @($certs | Where-Object { $_.Role -ne 'CA' -and $_.AuthorityKeyId } | ForEach-Object { ([string]$_.AuthorityKeyId).ToUpperInvariant() -replace '\s', '' } | Select-Object -Unique)
    foreach ($c in $certs) {
        if ($c.Role -eq 'CA') {
            $cid = Get-MspkiEntityId -Type 'CACertificate' -Key $c.Thumbprint
            if (-not (Test-MspkiEntity -Id $cid)) { [void](Add-MspkiEntity -Type 'CACertificate' -Id $cid -Name $c.Subject -Properties @{ Subject = $c.Subject; Issuer = $c.Issuer; NotBefore = $c.NotBefore; NotAfter = $c.NotAfter; SubjectKeyId = $c.SubjectKeyId; AuthorityKeyId = $c.AuthorityKeyId; Lifecycle = 'Unknown' }) }
            $issuing = $raIssuerKeys -contains (([string]$c.SubjectKeyId).ToUpperInvariant() -replace '\s', '')
            Add-MspkiObservation -EntityId $cid -Kind 'Seen' -Source 'HTTP' -Location $Result.CertUrl -Confidence 'Confirmed' -Detail $(if ($issuing) { 'Returned by GetCACert of NDES on {0}: the CA that issued its RA certificates' -f $h } else { 'Returned by GetCACert of NDES on {0} (chain)' -f $h })
            if ($issuing) {
                foreach ($r in @(Get-MspkiRelation | Where-Object { $_.From -eq $cid -and $_.Type -eq 'certificateOf' })) { Add-MspkiRelation -From $sid -Type 'enrollsVia' -To $r.To -Source 'NDES:GetCACert:RA issuer' -Confidence 'Confirmed' }
            }
            continue
        }
        $tl = $(if ($c.TemplateName) { $c.TemplateName } else { Get-MspkiCertificateTemplateLabel -TemplateInfo ([pscustomobject]@{ Oid = $c.TemplateOid; Name = '' }) -Templates $Templates })
        $rid = Add-MspkiEntity -Type 'RACertificate' -Key $c.Thumbprint -Name $c.Subject -Properties @{
            Subject = $c.Subject; Issuer = $c.Issuer; NotBefore = $c.NotBefore; NotAfter = $c.NotAfter; Expired = [bool]$c.Expired; Role = $c.Role
            Eku = @($c.Eku); KeyUsage = $c.KeyUsage; Template = $tl; Thumbprint = $c.Thumbprint }
        Add-MspkiObservation -EntityId $rid -Kind 'Seen' -Source 'HTTP' -Location $Result.CertUrl -Confidence 'Confirmed' -Detail ('Returned by GetCACert of NDES on {0}' -f $h)
        Add-MspkiRelation -From $rid -Type 'certificateOf' -To $sid -Source 'NDES:GetCACert' -Confidence 'Confirmed'
        foreach ($p in (Get-MspkiCACertificateIdByKeyId -KeyId ([string]$c.AuthorityKeyId))) { Add-MspkiRelation -From $rid -Type 'issuedBy' -To $p -Source 'Certificate:AuthorityKeyIdentifier' -Confidence 'Confirmed' }
        if ($tl) {
            $tid = Get-MspkiEntityId -Type 'Template' -Key $tl
            if (Test-MspkiEntity -Id $tid) { Add-MspkiRelation -From $rid -Type 'references' -To $tid -Source 'Certificate:TemplateExtension' -Confidence 'Confirmed' }
        }
    }
}

function Get-MspkiNdesTemplateAccessFinding {
    <#
    .SYNOPSIS
    The findings that describe the template-permission route (Find-MspkiNdesTemplateAccountHost): which templates have the NDES RA purpose,
    who may enroll from them (default admin groups left out) and which hosts those accounts name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result)
    $out = New-Object System.Collections.ArrayList
    $src = @('AD:CertificateTemplates:nTSecurityDescriptor')
    $tpl = @($Result.Templates)
    if ($tpl.Count -eq 0) {
        [void]$out.Add((New-MspkiFinding -Stage 'Discovery' -Category 'NDES' -Role 'NDESEndpoint' -Target 'NDES RA templates' -Status 'Information' -StatusCode 'NOT_DISCOVERED' -Confidence 'Confirmed' `
            -Sources $src -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } -Message 'No certificate template in AD has the NDES RA purpose (CEP Encryption, Exchange Enrollment Agent (Offline request) or a copy of them).' `
            -Evidence @('Looked for: the template names CEPEncryption and EnrollmentAgentOffline, and templates with the Certificate Request Agent EKU and the subject supplied in the request') `
            -Notes 'An NDES server needs these templates to get its RA certificates, so without them no NDES server can be working in this forest (one that uses a CA outside AD could still exist).'))
        return $out.ToArray()
    }
    $pub = @($tpl | Where-Object { $_.Published })
    $ev = New-Object System.Collections.ArrayList
    foreach ($t in $tpl) { [void]$ev.Add(('Template {0}: {1}; {2}' -f $t.Name, $t.Why, $(if ($t.Published) { 'published on a CA' } else { 'published on no CA' }))) }
    if ($pub.Count -eq 0) {
        [void]$out.Add((New-MspkiFinding -Stage 'Discovery' -Category 'NDES' -Role 'NDESEndpoint' -Target 'NDES RA templates' -Status 'Information' -StatusCode 'NOT_CONFIGURED' -Confidence 'Confirmed' `
            -Sources $src -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } -Message ('Templates with the NDES RA purpose exist ({0}), but no Enterprise CA publishes them: no NDES server can enroll or renew its RA certificates from this forest.' -f (@($tpl | ForEach-Object { $_.Name }) -join ', ')) `
            -Evidence @($ev)))
        return $out.ToArray()
    }
    $hostsFound = 0
    foreach ($p in @($Result.Principals)) {
        $tl = (@($p.Templates) -join ', ')
        switch ($p.Class) {
            'DefaultAdmin' { [void]$ev.Add(('{0}: default administrative group, left out ({1})' -f $p.Principal, $tl)) }
            'Broad' { [void]$ev.Add(('{0}: broad group ({1}), names no host; the template review reports what this permission means ({2})' -f $p.Principal, $p.BroadLabel, $tl)) }
            default {
                $who = $(if ($p.Principal -and $p.Principal -ne $p.Sid) { '{0} [{1}]' -f $p.Principal, $p.Sid } else { $p.Sid })
                if ($p.Lookup -eq 'NotFound') { [void]$ev.Add(('{0}: could not be read in AD: the account was deleted, or this account may not read it ({1})' -f $who, $tl)) }
                elseif ($p.Lookup -eq 'Error') { [void]$ev.Add(('{0}: lookup failed: {1} ({2})' -f $who, $p.LookupError, $tl)) }
                elseif ($null -ne $p.Account) {
                    $a = $p.Account
                    $hs = @($p.Hosts)
                    $hostsFound += $hs.Count
                    $what = $(if ($hs.Count) { 'names {0}' -f ($hs -join ', ') } elseif ($a.Class -eq 'group') { 'a group whose members name no host' } elseif ($a.Class -eq 'computer') { 'a computer account without dNSHostName' } else { 'has no HTTP/ SPN, so it names no host' })
                    [void]$ev.Add(('{0} ({1}{2}): {3}; SPNs: {4} ({5})' -f $a.SamAccountName, $a.Class, $(if ($a.Disabled) { ', disabled' } else { '' }), $what, $(if (@($a.Spns).Count) { @($a.Spns) -join ', ' } else { 'none' }), $tl))
                }
            }
        }
    }
    $cand = @($Result.Principals | Where-Object { $_.Class -eq 'Candidate' })
    $msg = 'Enroll on the NDES RA template(s) {0}: {1} account(s) besides the default admin groups; {2} host name(s) found from them.' -f (@($pub | ForEach-Object { $_.Name }) -join ', '), $cand.Count, @($Result.Hosts).Count
    [void]$ev.Add(('Targeted AD reads (by SID or DN, base scope, on {0}): {1}' -f $(if ($Result.Server) { $Result.Server } else { 'the default domain controller' }), $Result.Lookups))
    [void]$out.Add((New-MspkiFinding -Stage 'Discovery' -Category 'NDES' -Role 'NDESEndpoint' -Target 'NDES RA templates' -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' `
        -Sources @($src + 'AD:Account:servicePrincipalName/dNSHostName') -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } -Message $msg -Evidence @($ev) `
        -Notes 'NDES enrolls for its own RA certificates from these templates, so the accounts that may enroll from them are the NDES service account or computer. The permissions are confirmed (read from AD); that a named host runs NDES is only a candidate until it answers SCEP requests.'))
    return $out.ToArray()
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
        [switch]$SkipNetwork,
        [switch]$IncludeAdminProbe
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
            try { $nl = Add-MspkiLead -Url (Get-MspkiNdesBaseUrl -HostName $n.Host -Scheme $n.Scheme -Port $n.Port) -Kind 'NDES' -Source (@($l.Sources)[0]) -Origin ('SCEP URL {0} referenced by lead {1} ({2})' -f $v, $l.Id, $l.Kind) -RelatedCA (@($l.RelatedCAs) -join ', ') -Trust $l.Trust }
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
        $nl = Add-MspkiLead -Url $u1 -Kind 'NDES' -Source $src[0] -Origin ('NDES template evidence in the CA database of {0}' -f ($c.CAs -join ', ')) -RelatedCA ($c.CAs -join ', ') -Confidence 'Inferred' -Trust 'Authoritative'
        $null = Add-MspkiLead -Url $u2 -Kind 'NDES' -Source $src[0] -Origin ('NDES template evidence in the CA database of {0}' -f ($c.CAs -join ', ')) -RelatedCA ($c.CAs -join ', ') -Confidence 'Inferred' -Trust 'Authoritative'
        if ($null -eq $nl) { continue }
        if (-not $info.ContainsKey($nl.Host)) { $info[$nl.Host] = @{ Origin = 'Probable'; Lines = (New-Object System.Collections.ArrayList); Sources = (New-Object System.Collections.ArrayList); RelatedCAs = (New-Object System.Collections.ArrayList) } }
        $i = $info[$nl.Host]
        if ($i.Origin -ne 'Referenced') { $i.Origin = 'Probable' }
        foreach ($l in $lines) { [void]$i.Lines.Add($l) }
        foreach ($s in $src) { if (-not $i.Sources.Contains($s)) { [void]$i.Sources.Add($s) } }
        foreach ($ca in $c.CAs) { if (-not $i.RelatedCAs.Contains($ca)) { [void]$i.RelatedCAs.Add($ca) } }
    }

    # 2b. Template permissions (works without the CA database view): who may enroll for NDES RA certificates, and which hosts those
    # accounts name (dNSHostName, HTTP/ SPNs). Targeted reads by SID only.
    $ta = $null
    if ($null -ne $ctx -and $ctx.Ready -and @($inv.Templates).Count -gt 0) {
        try { $ta = Find-MspkiNdesTemplateAccountHost -Inventory $inv -TimeoutSeconds $TimeoutSeconds }
        catch { Write-MspkiLog -Level Warning -Message ('NDES template permission route stopped: {0}' -f $_.Exception.Message) }
    }
    if ($null -ne $ta) {
        foreach ($f in (Get-MspkiNdesTemplateAccessFinding -Result $ta)) { [void]$findings.Add($f) }
        try { Add-MspkiNdesTemplateAccessToGraph -Result $ta }
        catch { Write-MspkiLog -Level Warning -Message ('NDES template accounts not written to the graph: {0}' -f $_.Exception.Message) }
        foreach ($h in @($ta.Hosts)) {
            $tLines = @(('Enroll on the NDES RA template(s) {0} is held by {1}' -f (@($h.Templates) -join ', '), (@($h.Principals) -join ', ')))
            $tLines += @($h.How | ForEach-Object { 'Host found from: {0}' -f $_ })
            $src = @('AD:CertificateTemplates:nTSecurityDescriptor', 'AD:Account:servicePrincipalName/dNSHostName')
            $dns = $null
            if (-not $SkipNetwork) { $dns = Resolve-MspkiDnsName -HostName $h.Host -TimeoutMs ($TimeoutSeconds * 1000) }
            if ($null -ne $dns -and $dns.Status -ne 'Pass') {
                $tLines += ('DNS: {0} {1}' -f $dns.Status, $dns.Error)
                if ($info.ContainsKey($h.Host)) { continue }
                [void]$findings.Add((New-MspkiFinding -Stage 'Discovery' -Category 'NDES' -Role 'NDESEndpoint' -Target $h.Host -Status 'Information' -StatusCode $dns.StatusCode `
                    -Confidence 'Inferred' -Sources $src -Scope 'Unknown' -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = $dns.Status } `
                    -Message ('NDES host candidate {0} (UnconfirmedCandidate): an account that may enroll for NDES RA certificates names it, but the name does not resolve. Nothing was sent.' -f $h.Host) `
                    -Evidence (@('Classification: UnconfirmedCandidate') + $tLines) -Notes 'The server may have been retired or renamed, or the SPN is left over. This is a candidate only.'))
                [void]$hosts.Add([pscustomobject]@{ Host = $h.Host; Classification = 'UnconfirmedCandidate'; Confirmed = $false })
                continue
            }
            if ($h.Constructed) { $tLines += 'The host name was completed from a short SPN; it resolves in DNS.' }
            $nl = Add-MspkiLead -Url (Get-MspkiNdesBaseUrl -HostName $h.Host -Scheme https) -Kind 'NDES' -Source $src[0] -Origin ('NDES RA template permissions: {0}' -f (@($h.Principals) -join ', ')) -Confidence 'Inferred' -Trust 'Authoritative'
            $null = Add-MspkiLead -Url (Get-MspkiNdesBaseUrl -HostName $h.Host -Scheme http) -Kind 'NDES' -Source $src[0] -Origin ('NDES RA template permissions: {0}' -f (@($h.Principals) -join ', ')) -Confidence 'Inferred' -Trust 'Authoritative'
            $key = $(if ($null -ne $nl) { $nl.Host } else { ConvertTo-MspkiHostName $h.Host })
            if (-not $info.ContainsKey($key)) { $info[$key] = @{ Origin = 'Probable'; Lines = (New-Object System.Collections.ArrayList); Sources = (New-Object System.Collections.ArrayList); RelatedCAs = (New-Object System.Collections.ArrayList) } }
            $i = $info[$key]
            if ($i.Origin -ne 'Referenced') { $i.Origin = 'Probable' }
            foreach ($l in $tLines) { [void]$i.Lines.Add($l) }
            foreach ($s in $src) { if (-not $i.Sources.Contains($s)) { [void]$i.Sources.Add($s) } }
            foreach ($ca in @($inv.EnterpriseCAs | Where-Object { $null -ne $_ -and @($_.Templates | Where-Object { @($h.Templates) -contains $_ }).Count -gt 0 } | ForEach-Object { $_.Name })) {
                if (-not $i.RelatedCAs.Contains($ca)) { [void]$i.RelatedCAs.Add($ca) }
            }
        }
    }

    # 3. Probe every NDES lead (and only those).
    foreach ($lead in @(Get-MspkiLead -Kind 'NDES')) {
        $i = $info[$lead.Host]
        if ($null -eq $i) { $i = @{ Origin = 'Referenced'; Lines = @(); Sources = @($lead.Sources); RelatedCAs = @($lead.RelatedCAs) } }
        $infoObj = [pscustomobject]@{ Origin = $i.Origin; Lines = @($i.Lines); Sources = @($i.Sources); RelatedCAs = @($i.RelatedCAs) }
        if (@($infoObj.Sources).Count -eq 0) { $infoObj.Sources = @($lead.Sources) }
        $r = Test-MspkiNdesHost -Lead $lead -Info $infoObj -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork -IncludeAdminProbe:$IncludeAdminProbe
        foreach ($f in $r.Findings) { [void]$findings.Add($f) }
        [void]$hosts.Add([pscustomobject]@{ Host = $lead.Host; Classification = $r.Classification; Confirmed = $r.Confirmed })
        try { Add-MspkiNdesResultToGraph -Result $r -Lead $lead -Templates @($inv.Templates) }
        catch { Write-MspkiLog -Level Warning -Message ('NDES graph entry for {0} not written: {1}' -f $lead.Host, $_.Exception.Message) }
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
        $taRead = $false
        if ($null -ne $ta) {
            $taRead = (@($ta.Templates | Where-Object { -not $_.AclRead }).Count -eq 0) -and (@($ta.Principals | Where-Object { $_.Class -eq 'Candidate' -and $_.Lookup -ne 'Found' }).Count -eq 0)
            $ev += ('NDES RA templates: {0}; accounts that may enroll from them (besides default admins): {1}; host names found: {2}' -f @($ta.Templates).Count, @($ta.Principals | Where-Object { $_.Class -eq 'Candidate' }).Count, @($ta.Hosts).Count)
        }
        else { $ev += 'NDES RA template permissions: not read' }
        # "Nothing found" is only as strong as the reading behind it: when neither the CA databases nor every template permission could be
        # read it is not even a weak negative.
        $ndConf = 'Unknown'; if ($caRead -gt 0 -or $taRead) { $ndConf = 'Inferred' }
        [void]$findings.Add((New-MspkiFinding -Stage 'Analysis' -Category 'NDES' -Role 'NDESEndpoint' -Target 'NDES' -Status 'NotApplicable' -StatusCode 'NOT_DISCOVERED' -Confidence $ndConf `
            -Sources @('CA:CertificateAuthority.View', 'AD:EnrollmentServices:certificateTemplates') -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } `
            -Message 'Classification NotDiscovered: no NDES / SCEP server was found from the CA databases, the NDES RA template permissions or references.' -Evidence (@('Classification: NotDiscovered') + $ev) `
            -Notes 'NDES detection depends on read rights to the CA database, on the accounts that may enroll from the NDES RA templates naming a host (SPN or computer account), or on references existing. An account that is not a CA administrator or certificate manager sees only its own requests, so this does not prove that no NDES server exists.'))
    }
    return [pscustomobject]@{ Findings = @($findings); Hosts = @($hosts) }
}
