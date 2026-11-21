# Certificate Enrollment Policy (CEP) and Enrollment Web Service (CES) endpoints (REQUIREMENTS 5.6).
# Sources: CES URLs from msPKI-Enrollment-Servers (Discovered, AD); CEP URLs from the policy on this computer
# (Configured); URLs built from the host name of an Enterprise CA with the standard Microsoft paths
# (ConstructedCandidate, Inferred: only CA hosts, which are already proven to be PKI). Every probe is an anonymous
# GET on a URL that is in the lead registry. Reachability, authentication, TLS trust, TLS name match and content
# are reported as separate facts. An HTTP 400, 401 or 405 answer proves that the service is reachable. An HTTP 5xx answer
# proves only that a web server is there: the service behind it is failing (state Failing, Fail, HTTP_500), never Pass.

$script:MspkiEnrollmentAuthVariant = @('Kerberos', 'UsernamePassword', 'Certificate')
$script:MspkiRespondingStatus = @(200, 400, 401, 403, 405)

function Get-MspkiEnrollmentOrigin {
    <#
    .SYNOPSIS
    Classification by origin: Configured (policy on this computer), Discovered (AD) or ConstructedCandidate.
    The strongest origin among the sources wins.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Lead)
    $s = @($Lead.Sources)
    if (@($s | Where-Object { $_ -like 'Policy:CEP:*' -or $_ -like 'Local:CEP:*' }).Count -gt 0) { return 'Configured' }
    if (@($s | Where-Object { $_ -like 'AD:*' }).Count -gt 0) { return 'Discovered' }
    return 'ConstructedCandidate'
}

function Register-MspkiEnrollmentLead {
    <#
    .SYNOPSIS
    Registers the CEP leads from the local policy and, unless -SkipNetwork, constructed candidates on the hosts of
    Enterprise CAs. A constructed URL that equals a referenced lead is not registered again.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Inventory, [switch]$SkipNetwork)
    $n = 0
    if ($null -eq $Inventory) { return 0 }
    foreach ($p in @($Inventory.CepPolicies | Where-Object { $_ -and $_.IsWebService })) {
        $origin = 'Enrollment policy server on this computer ({0}, key {1}{2})' -f $p.Managed, $p.KeyName, $(if ($p.FriendlyName) { ', ' + $p.FriendlyName } else { '' })
        if ($null -ne (Add-MspkiLead -Url $p.Url -Kind 'CEP' -Source $p.Source -Origin $origin)) { $n++ }
    }
    if ($SkipNetwork) { return $n }
    foreach ($ca in @($Inventory.EnterpriseCAs)) {
        if (-not $ca.DnsHostName) { continue }
        $candidates = @()
        foreach ($a in $script:MspkiEnrollmentAuthVariant) {
            $candidates += @{ Kind = 'CES'; Url = ('https://{0}/{1}_CES_{2}/service.svc' -f $ca.DnsHostName, $ca.Name, $a) }
            $candidates += @{ Kind = 'CEP'; Url = ('https://{0}/ADPolicyProvider_CEP_{1}/service.svc' -f $ca.DnsHostName, $a) }
        }
        foreach ($c in $candidates) {
            $norm = ConvertTo-MspkiNormalizedUrl -Url $c.Url
            if (-not $norm.Valid) { continue }
            $key = '{0}|{1}' -f $c.Kind, $norm.Key
            if (@(Get-MspkiLead -Kind $c.Kind | Where-Object { $_.Key -eq $key }).Count -gt 0) { continue }
            $origin = 'Constructed candidate: standard {0} path on the host of Enterprise CA {1}' -f $c.Kind, $ca.Name
            if ($null -ne (Add-MspkiLead -Url $c.Url -Kind $c.Kind -Source 'Constructed:CAHost' -Origin $origin -RelatedCA $ca.Name -Confidence 'Inferred')) { $n++ }
        }
    }
    return $n
}

function Get-MspkiEnrollmentAuthInfo {
    <#
    .SYNOPSIS
    Finds the authentication type, priority and renewal-only flag that AD (msPKI-Enrollment-Servers) or the local
    policy gives for a URL (compared by the normalised key).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Inventory, [Parameter(Mandatory = $true)][string]$Url)
    $k = (ConvertTo-MspkiNormalizedUrl -Url $Url).Key
    if ($null -eq $Inventory) { return $null }
    foreach ($ca in @($Inventory.EnterpriseCAs)) {
        foreach ($e in @($ca.EnrollmentServers | Where-Object { $_ -and $_.Url })) {
            if ((ConvertTo-MspkiNormalizedUrl -Url $e.Url).Key -eq $k) {
                return [pscustomobject]@{ AuthName = $e.AuthName; AuthType = $e.AuthType; Priority = $e.Priority; RenewalOnly = $e.RenewalOnly; From = 'AD (msPKI-Enrollment-Servers)' }
            }
        }
    }
    foreach ($p in @($Inventory.CepPolicies | Where-Object { $_ -and $_.Url })) {
        if ((ConvertTo-MspkiNormalizedUrl -Url $p.Url).Key -eq $k) {
            return [pscustomobject]@{ AuthName = $p.AuthName; AuthType = $p.AuthFlags; Priority = $p.Cost; RenewalOnly = $null; From = ('policy on this computer ({0})' -f $p.Managed) }
        }
    }
    return $null
}

function Test-MspkiEnrollmentEndpoint {
    <#
    .SYNOPSIS
    Probes one CEP or CES URL (anonymous GET) and reports each layer separately.

    .OUTPUTS
    { Findings, Origin, State (ConfirmedResponding / Unreachable / NotConfirmed / NotTested), Responding, Url, Summary }.
    Findings is empty for a constructed candidate that did not answer (the caller reports those together).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lead,
        [Parameter(Mandatory = $true)][string]$Url,
        [AllowNull()]$Inventory = $null,
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork
    )
    $kind = $Lead.Kind
    $category = $kind
    $role = 'CESEndpoint'; if ($kind -eq 'CEP') { $role = 'CEPEndpoint' }
    $origin = Get-MspkiEnrollmentOrigin -Lead $Lead
    $constructed = ($origin -eq 'ConstructedCandidate')
    $n = ConvertTo-MspkiNormalizedUrl -Url $Url
    $ms = $TimeoutSeconds * 1000
    $out = [pscustomobject]@{ Findings = (New-Object System.Collections.ArrayList); Origin = $origin; State = 'NotTested'; Responding = $false; Url = $Url; Summary = '' }
    $info = Get-MspkiEnrollmentAuthInfo -Inventory $Inventory -Url $Url
    $ev = New-Object System.Collections.ArrayList
    [void]$ev.Add(('Classification: {0}' -f $origin))
    [void]$ev.Add(('Lead {0} ({1}), depth {2}' -f $Lead.Id, $kind, $Lead.Depth))
    foreach ($o in @($Lead.Origins)) { [void]$ev.Add(('Found in: {0}' -f $o)) }
    foreach ($a in @($Lead.Aliases)) { [void]$ev.Add(('Also referenced as: {0}' -f $a)) }
    if ($null -ne $info) {
        $ren = ''
        if ($null -ne $info.RenewalOnly) { $ren = '; renewal only: ' + $(if ($info.RenewalOnly) { 'yes' } else { 'no' }) }
        [void]$ev.Add(('Authentication type from {0}: {1}; priority/cost {2}{3}' -f $info.From, $info.AuthName, $info.Priority, $ren))
    }
    $related = (@($Lead.RelatedCAs) -join ', ')
    $conf = 'Referenced'
    $notes = ''
    if ($constructed) {
        $conf = 'Inferred'
        $notes = 'Constructed candidate: the URL was built from the host name of an Enterprise CA with the standard Microsoft path. It is not referenced by AD or by policy.'
    }
    $layers = @{ DiscoveryStatus = 'Pass' }
    $mk = {
        param($st, $cd, $msg, $extra)
        $e = @($ev) + @($extra)
        # A reference to another environment goes to review and is never graded as a failure (REQUIREMENTS 4.2).
        $sc = Resolve-MspkiScopeStatus -Status $st -Scope $Lead.Scope
        if ($sc.Capped) { $st = $sc.Status; $e += $sc.Evidence }
        New-MspkiFinding -Stage 'Probe' -Category $category -Role $role -Target $(if ($n.Host) { $n.Host } else { $Url }) -Endpoint $Url -RelatedCA $related `
            -Status $st -StatusCode $cd -Confidence $conf -Sources @($Lead.Sources) -Scope $Lead.Scope -Message $msg -Evidence $e -Layers $layers -Notes $notes -Severity $sc.Severity
    }
    $label = '{0} {1}' -f $origin, $kind

    if ($n.UrlType -ne 'Http') {
        [void]$out.Findings.Add((& $mk 'NotApplicable' 'NOT_APPLICABLE' ('{0} URL is not an HTTP(S) URL and is not probed.' -f $label) @()))
        $out.State = 'NotTested'
        return $out
    }
    if ($SkipNetwork) {
        $layers['DnsStatus'] = 'Skipped'
        $out.State = 'NotTested'
        if (-not $constructed) { [void]$out.Findings.Add((& $mk 'Skipped' 'NOT_APPLICABLE' ('{0} endpoint {1} was not probed because -SkipNetwork was used.' -f $label, $n.Host) @())) }
        return $out
    }
    $dns = Resolve-MspkiDnsName -HostName $n.Host -TimeoutMs $ms
    $layers['DnsStatus'] = $dns.Status
    if ($dns.Status -ne 'Pass') {
        $out.State = 'Unreachable'; $out.Summary = ('DNS {0}' -f $dns.StatusCode)
        if (-not $constructed) {
            [void]$out.Findings.Add((& $mk 'Fail' $dns.StatusCode ('{0} endpoint: {1} does not resolve in DNS (Unreachable).' -f $label, $n.Host) @(('DNS: {0} {1}' -f $dns.Status, $dns.Error))))
        }
        return $out
    }
    [void]$ev.Add(('DNS: {0}' -f ($dns.Addresses -join ', ')))
    $tcp = Test-MspkiTcpPort -HostName $n.Host -Port $n.Port -TimeoutMs $ms
    $layers['TcpStatus'] = $tcp.Status
    if ($tcp.Status -ne 'Pass') {
        $out.State = 'Unreachable'; $out.Summary = ('TCP {0} {1}' -f $n.Port, $tcp.StatusCode)
        if (-not $constructed) {
            [void]$out.Findings.Add((& $mk 'Fail' $tcp.StatusCode ('{0} endpoint: {1} does not accept connections on TCP {2} (Unreachable).' -f $label, $n.Host, $n.Port) @(('TCP: {0} {1}' -f $tcp.Status, $tcp.Error))))
        }
        return $out
    }
    [void]$ev.Add(('Reachability (TCP {0}): connects' -f $n.Port))
    $tlsTrust = 'not applicable (http)'; $tlsName = 'not applicable (http)'
    if ($n.Scheme -eq 'https') {
        $tls = Test-MspkiTlsEndpoint -HostName $n.Host -Port $n.Port -TimeoutMs $ms
        $layers['TlsStatus'] = $(if ($tls.Code -eq 'OK') { 'Pass' } else { 'Fail' })
        $tlsTrust = 'trusted by this computer'
        if (@($tls.ChainErrors).Count -gt 0) { $tlsTrust = 'not trusted by this computer: {0}' -f (@($tls.ChainErrors) -join ', ') }
        elseif ($tls.Code -in @('TLS_HANDSHAKE_FAIL', 'TIMEOUT', 'TCP_FAIL')) { $tlsTrust = 'handshake failed' }
        if ($null -eq $tls.NameMatch) { $tlsName = 'not determined' } elseif ($tls.NameMatch) { $tlsName = 'matches the host name' } else { $tlsName = 'does NOT match the host name' }
        [void]$ev.Add(('TLS trust: {0}' -f $tlsTrust))
        [void]$ev.Add(('TLS name match: {0}' -f $tlsName))
        if ($tls.Subject) { [void]$ev.Add(('TLS server certificate: {0} (issuer {1}, until {2}); protocol {3}' -f $tls.Subject, $tls.Issuer, $tls.NotAfter, $tls.Protocol)) }
        if ($tls.Code -ne 'OK') {
            $out.State = 'NotConfirmed'; $out.Summary = ('TLS {0}' -f $tls.Code)
            if (-not $constructed) {
                [void]$out.Findings.Add((& $mk 'Warning' $tls.Code ('{0} endpoint {1} accepts connections, but TLS to it failed ({2}); no HTTP request was sent, so the service is not confirmed to respond.' -f $label, $n.Host, $tls.Code) @(('TLS error: {0}' -f $tls.Error)) ))
                $out.Findings[$out.Findings.Count - 1].Notes = 'A TLS trust or name problem seen from this computer is not the same as the service being down; other computers may trust the certificate.'
            }
            return $out
        }
    }
    else { [void]$ev.Add('TLS trust: not applicable (http)'); [void]$ev.Add('TLS name match: not applicable (http)') }

    $http = Invoke-MspkiHttpGet -Url $Url -TimeoutMs $ms
    [void]$ev.Add(('HTTP proxy: {0}' -f $http.ProxyMode))
    foreach ($h in $http.Hops) { [void]$ev.Add(('HTTP hop: {0} -> {1} {2} {3}' -f $h.Url, $h.HttpStatus, $h.Location, $h.Error).Trim()) }
    if ($http.Redirected) { $layers['RedirectStatus'] = 'Warning' } else { $layers['RedirectStatus'] = 'Pass' }
    $status = [int]$http.HttpStatus
    if ($status -le 0 -or $status -eq 404 -or $status -eq 410) {
        $out.State = 'Unreachable'
        $out.Summary = if ($status -gt 0) { 'HTTP {0}' -f $status } else { $http.Code }
        $layers['HttpStatus'] = 'Fail'
        if (-not $constructed) {
            $code = $http.Code; if ($status -eq 410) { $code = 'HTTP_404' }
            [void]$out.Findings.Add((& $mk 'Fail' $code ('{0} endpoint {1} does not answer as an enrollment service: {2} {3} (Unreachable).' -f $label, $n.Host, $(if ($status -gt 0) { 'HTTP ' + $status } else { $http.Code }), $http.Error).Trim() @()))
        }
        return $out
    }
    if ($status -ge 500) {
        # The web server answered, so the host and the port are fine, but the service behind it is failing (for example a stopped
        # application pool answers 503). That is not "responding": it is reported as a failure, and the answer stays in the Evidence.
        $out.State = 'Failing'; $out.Summary = ('HTTP {0}' -f $status)
        $layers['HttpStatus'] = 'Fail'
        [void]$ev.Add(('Reachability (HTTP): the host answered with HTTP {0}. A web server is there, but the service behind it is failing.' -f $status))
        if (-not $constructed) {
            [void]$out.Findings.Add((& $mk 'Fail' 'HTTP_500' ('{0} endpoint {1} is reachable but failing: HTTP {2} (Failing). The application pool or the service behind this URL may be stopped.' -f $label, $n.Host, $status) @()))
        }
        return $out
    }
    if ($script:MspkiRespondingStatus -notcontains $status -and -not ($status -ge 300 -and $status -lt 400)) {
        $out.State = 'NotConfirmed'; $out.Summary = ('HTTP {0}' -f $status)
        $layers['HttpStatus'] = 'Warning'
        if (-not $constructed) {
            [void]$out.Findings.Add((& $mk 'Warning' $http.Code ('{0} endpoint {1} answered with HTTP {2}, which does not show that the service is running.' -f $label, $n.Host, $status) @()))
        }
        return $out
    }

    # The service answered.
    $out.State = 'ConfirmedResponding'; $out.Responding = $true; $out.Summary = ('HTTP {0}' -f $status)
    $layers['HttpStatus'] = 'Pass'
    $authText = 'no authentication challenge at this URL'
    if ($status -eq 401 -or $status -eq 403) { $authText = ('yes (HTTP {0}); expected for an enrollment service that uses Windows, certificate or user name authentication' -f $status) }
    [void]$ev.Add(('Reachability (HTTP): the service answered with HTTP {0}' -f $status))
    [void]$ev.Add(('Authentication required: {0}' -f $authText))
    $content = 'not checked (no body expected for HTTP {0})' -f $status
    $contentStatus = 'NotApplicable'
    if ($status -eq 200 -and $null -ne $http.Bytes) {
        $text = [System.Text.Encoding]::UTF8.GetString($http.Bytes, 0, [math]::Min($http.Bytes.Length, 20000))
        if ($http.ContentType -match '(?i)xml|html|text' -and $text -match '(?i)wsdl|service|svc|policy|enrollment') {
            $content = 'looks like a web service page ({0}, {1} bytes)' -f $http.ContentType, $http.Bytes.Length; $contentStatus = 'Pass'
        }
        else { $content = 'unexpected content ({0}, {1} bytes)' -f $http.ContentType, $http.Bytes.Length; $contentStatus = 'Warning' }
    }
    [void]$ev.Add(('Content: {0}' -f $content))
    $layers['ContentStatus'] = $contentStatus
    if (-not $constructed) { $conf = 'Confirmed' }
    $state = 'ConfirmedResponding'
    $msg = '{0} endpoint {1} responds (HTTP {2}; {3}). Classification: {4}; {5}.' -f $label, $n.Host, $status, $(if ($status -eq 401 -or $status -eq 403) { 'authentication required, as expected' } else { 'reachable' }), $origin, $state
    if ($constructed) { $msg += ' A service answers at this constructed URL; that it serves this CA is not confirmed.' }
    if ($contentStatus -eq 'Warning') {
        [void]$out.Findings.Add((& $mk 'Warning' 'CONTENT_WRONG_TYPE' $msg @()))
    }
    else { [void]$out.Findings.Add((& $mk 'Pass' 'OK' $msg @())) }

    if ($n.Scheme -eq 'http') {
        $sev = 'Medium'; $st = 'Warning'
        $authName = ''
        if ($null -ne $info) { $authName = [string]$info.AuthName }
        if ($authName -match 'UserName') { $sev = 'High'; $st = 'Fail' }
        $pev = @(('Classification: {0}' -f $origin), ('URL: {0}' -f $Url), ('Authentication type: {0}' -f $(if ($authName) { $authName } else { 'unknown' })),
            ('The service answered over plain HTTP (HTTP {0}).' -f $status))
        $rs = Resolve-MspkiScopeStatus -Status $st -Scope $Lead.Scope
        if ($rs.Capped) { $st = $rs.Status; $sev = $rs.Severity; $pev += $rs.Evidence }
        $risk = New-MspkiFinding -Stage 'Probe' -Category $category -Role $role -Target $n.Host -Endpoint $Url -RelatedCA $related -Status $st -StatusCode 'CONFIG_RISK' `
            -Severity $sev -Confidence $conf -Sources @($Lead.Sources) -Scope $Lead.Scope -Layers @{ DiscoveryStatus = 'Pass'; TlsStatus = 'NotApplicable'; HttpStatus = 'Pass' } `
            -Message ('The {0} endpoint {1} is served over HTTP, not HTTPS, so requests and responses are not protected by TLS.' -f $kind, $n.Host) -Evidence $pev `
            -Remediation 'Review only: no change is made or suggested automatically.' `
            -Notes 'Enrollment web services that are reachable over HTTP can expose credentials and enrollment traffic and are a known target for relaying attacks. Whether HTTPS is also offered is shown by the other variant of this URL.'
        [void]$out.Findings.Add($risk)
    }
    return $out
}

function Invoke-MspkiEnrollmentServiceAnalysis {
    <#
    .SYNOPSIS
    Registers CEP and CES leads (policy, AD and constructed candidates), probes each one and reports every result
    with its classification. Constructed candidates that do not answer are reported together in one finding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Discovery,
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork
    )
    $findings = New-Object System.Collections.ArrayList
    $inv = $Discovery.Inventory
    $null = Register-MspkiEnrollmentLead -Inventory $inv -SkipNetwork:$SkipNetwork
    $leads = @(Get-MspkiLead | Where-Object { $_.Kind -eq 'CES' -or $_.Kind -eq 'CEP' })
    $silent = New-Object System.Collections.ArrayList
    $responding = 0
    foreach ($lead in $leads) {
        foreach ($url in @($lead.Variants)) {
            $r = Test-MspkiEnrollmentEndpoint -Lead $lead -Url $url -Inventory $inv -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork
            foreach ($f in $r.Findings) { [void]$findings.Add($f) }
            if ($r.Origin -eq 'ConstructedCandidate') {
                if ($r.Responding) { $responding++ }
                elseif ($r.State -ne 'NotTested') { [void]$silent.Add(('{0}: {1} ({2})' -f $url, $r.State, $r.Summary)) }
            }
        }
    }
    if ($silent.Count -gt 0) {
        [void]$findings.Add((New-MspkiFinding -Stage 'Probe' -Category 'CES' -Role 'CESEndpoint' -Target 'Constructed candidates' -Status 'NotApplicable' -StatusCode 'NOT_DISCOVERED' `
            -Confidence 'Inferred' -Sources 'Constructed:CAHost' -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } `
            -Message ('{0} constructed CEP/CES candidate URL(s) on Enterprise CA hosts did not answer as a working service; {1} answered.' -f $silent.Count, $responding) `
            -Evidence (@('Classification: ConstructedCandidate', 'Standard Microsoft paths were tried only on hosts of Enterprise CAs found in AD (anonymous GET).') + @($silent)) `
            -Notes 'A CES or CEP on another host, or with another name, cannot be found this way. CES URLs normally come from Active Directory and CEP URLs from policy on this computer.'))
    }
    $cepConfigured = @($inv.CepPolicies | Where-Object { $_ -and $_.IsWebService }).Count
    if ($cepConfigured -eq 0) {
        [void]$findings.Add((New-MspkiFinding -Stage 'Discovery' -Category 'CEP' -Role 'Computer' -Target 'Enrollment policy servers' -Status 'NotApplicable' -StatusCode 'NOT_CONFIGURED' `
            -Confidence 'Confirmed' -Sources @('Policy:CEP:HKLM', 'Policy:CEP:HKCU', 'Local:CEP:HKLM', 'Local:CEP:HKCU') -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } `
            -Message 'No enrollment policy web service (CEP) is configured on this computer by policy or local settings.' `
            -Evidence @('Registry keys read: ...\Cryptography\PolicyServers under HKLM and HKCU (Policies and local settings).', 'A policy URL that is not http(s) (the Active Directory policy) is not a CEP web service.') `
            -Notes 'CEP URLs only appear if policy or settings on this computer point to them. A CEP used by other computers is not visible from here.'))
    }
    $adCes = @($leads | Where-Object { $_.Kind -eq 'CES' -and (Get-MspkiEnrollmentOrigin -Lead $_) -eq 'Discovered' }).Count
    if ($adCes -eq 0 -and @($inv.EnterpriseCAs).Count -gt 0) {
        [void]$findings.Add((New-MspkiFinding -Stage 'Discovery' -Category 'CES' -Role 'CESEndpoint' -Target 'msPKI-Enrollment-Servers' -Status 'NotApplicable' -StatusCode 'NOT_DISCOVERED' `
            -Confidence 'Confirmed' -Sources 'AD:EnrollmentServices:msPKI-Enrollment-Servers' -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } `
            -Message 'No Enrollment Web Service (CES) URL is published on the Enrollment Services objects of the Enterprise CAs.' `
            -Evidence @(('Enterprise CAs checked: {0}' -f @($inv.EnterpriseCAs).Count)) -Notes 'This is normal when CES is not used.'))
    }
    return , $findings.ToArray()
}
