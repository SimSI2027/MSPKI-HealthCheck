# Lead registry (REQUIREMENTS section 4.2). A lead is a URL taken from an authoritative source; only
# leads are ever probed. URLs are normalised before de-duplication and duplicates merge their sources.

$script:MspkiLeads = [ordered]@{}
$script:MspkiLeadSettings = @{ MaxLeads = 1000; MaxDepth = 5; LocalDomains = @(); TrustedDomains = @(); DomainControllers = @(); Dropped = 0; DepthDropped = 0; Seq = 0 }
$script:MspkiLeadKinds = @('AIA', 'CDP', 'FreshestCRL', 'OCSP', 'CES', 'CEP', 'NDES')
# How far the evidence behind a lead can be trusted (audit 2 H1). Authoritative: AD, CA properties, local policy, or a certificate
# discovered from them. Verified: a downloaded object whose signature or key was proven with a discovered CA certificate.
# Unverified: anything else. Only Authoritative and Verified leads can lead to a directory bind (Test-MspkiLdapHostAllowed), and
# only their hosts count as known hosts for redirects (Test-MspkiTrustedLeadHost).
$script:MspkiLeadTrustRank = @{ Unverified = 0; Verified = 1; Authoritative = 2 }

function Reset-MspkiLeadRegistry {
    [CmdletBinding()]
    param(
        [string[]]$LocalDomains = @(),
        [string[]]$TrustedDomains = @(),
        # The forest's domain controllers (server objects under CN=Sites of the Configuration partition).
        [string[]]$DomainControllers = @(),
        [ValidateRange(1, 10000)][int]$MaxLeads = 1000,
        [ValidateRange(0, 10)][int]$MaxDepth = 5
    )
    $script:MspkiLeads = [ordered]@{}
    $script:MspkiLeadSettings = @{
        MaxLeads = $MaxLeads; MaxDepth = $MaxDepth; Dropped = 0; DepthDropped = 0; Seq = 0
        LocalDomains = @($LocalDomains | Where-Object { $_ }); TrustedDomains = @($TrustedDomains | Where-Object { $_ })
        DomainControllers = @($DomainControllers | ForEach-Object { ConvertTo-MspkiHostName $_ } | Where-Object { $_ } | Select-Object -Unique)
    }
}

function ConvertTo-MspkiNormalizedUrl {
    <#
    .SYNOPSIS
    Normalises a URL for de-duplication. http and https of the same host and path share one key;
    host case, default ports, %20 versus spaces and trailing slashes do not change the key.

    .OUTPUTS
    { Original, Url (probe form), UrlType = Http | Ldap | File | Other, Scheme, Host, Port, Key, Valid }
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Url)
    $o = [ordered]@{ Original = $Url; Url = ''; UrlType = 'Other'; Scheme = ''; Host = ''; Port = 0; Key = ''; Valid = $false }
    $u = ([string]$Url).Trim()
    if (-not $u) { return [pscustomobject]$o }

    if ($u -match '^(?i)ldaps?://') {
        $m = [regex]::Match($u, '^(?i)(ldaps?)://([^/]*)/?(.*)$')
        $o.UrlType = 'Ldap'
        $o.Scheme = $m.Groups[1].Value.ToLowerInvariant()
        $o.Host = ConvertTo-MspkiHostName $m.Groups[2].Value
        $rest = $m.Groups[3].Value
        $o.Url = '{0}://{1}/{2}' -f $o.Scheme, $o.Host, ($rest -replace ' ', '%20')
        $o.Key = 'ldap://{0}/{1}' -f $o.Host, ([System.Uri]::UnescapeDataString($rest)).ToLowerInvariant()
        $o.Valid = $true
        return [pscustomobject]$o
    }
    if ($u -match '^(?i)file:' -or $u.StartsWith('\\')) {
        $o.UrlType = 'File'; $o.Scheme = 'file'; $o.Url = $u
        $o.Key = 'file:' + ($u -replace '\\', '/').ToLowerInvariant()
        $o.Valid = $true
        return [pscustomobject]$o
    }
    $uri = $null
    if ([System.Uri]::TryCreate(($u -replace ' ', '%20'), [System.UriKind]::Absolute, [ref]$uri) -and
        ($uri.Scheme -eq 'http' -or $uri.Scheme -eq 'https')) {
        $o.UrlType = 'Http'
        $o.Scheme = $uri.Scheme
        $o.Host = ConvertTo-MspkiHostName $uri.Host
        $o.Port = $uri.Port
        $o.Url = $uri.AbsoluteUri
        $path = [System.Uri]::UnescapeDataString($uri.AbsolutePath).TrimEnd('/')
        $portPart = ''
        if (-not $uri.IsDefaultPort) { $portPart = ':' + $uri.Port }
        $o.Key = 'web://{0}{1}{2}{3}' -f $o.Host, $portPart, $path, $uri.Query
        $o.Key = $o.Key.ToLowerInvariant()
        $o.Valid = $true
    }
    return [pscustomobject]$o
}

function Add-MspkiLead {
    <#
    .SYNOPSIS
    Registers a lead (or merges it into an existing one). Returns the lead, or $null when the URL is not
    usable, deeper than the depth limit, or the lead cap is reached (logged once as a run limit).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Url,
        [Parameter(Mandatory = $true)][ValidateScript({ $script:MspkiLeadKinds -contains $_ })][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Source,
        [string]$Origin = '',
        [int]$Depth = 0,
        [string]$RelatedCA = '',
        [string]$Confidence = 'Referenced',
        [string[]]$Carrier = @(),
        # See $script:MspkiLeadTrustRank. Discovery sources are Authoritative; links in downloaded objects pass Verified.
        [ValidateSet('Authoritative', 'Verified', 'Unverified')][string]$Trust = 'Authoritative'
    )
    $n = ConvertTo-MspkiNormalizedUrl -Url $Url
    if (-not $n.Valid) {
        Write-MspkiLog -Level Warning -Message ('Lead ignored (not a usable URL) from {0}: {1}' -f $Source, $Url)
        return $null
    }
    $s = $script:MspkiLeadSettings
    if ($Depth -gt $s.MaxDepth) {
        $s.DepthDropped++
        Write-MspkiLog -Message ('Lead ignored (depth {0} > {1}): {2}' -f $Depth, $s.MaxDepth, $Url)
        if ($s.DepthDropped -eq 1) {
            Write-MspkiLog -Level Warning -Message ('Link depth limit of {0} reached; links found deeper are not followed.' -f $s.MaxDepth)
            Add-MspkiRunLimit -Text ('Link depth limit of {0} reached: some links found in downloaded certificates or CRLs were not followed.' -f $s.MaxDepth)
        }
        return $null
    }
    $key = '{0}|{1}' -f $Kind, $n.Key
    if ($script:MspkiLeads.Contains($key)) {
        $l = $script:MspkiLeads[$key]
        if (-not $l.Sources.Contains($Source)) { [void]$l.Sources.Add($Source) }
        if ($Origin -and -not $l.Origins.Contains($Origin)) { [void]$l.Origins.Add($Origin) }
        if ($RelatedCA -and -not $l.RelatedCAs.Contains($RelatedCA)) { [void]$l.RelatedCAs.Add($RelatedCA) }
        foreach ($c in $Carrier) { if ($c -and -not $l.Carriers.Contains($c)) { [void]$l.Carriers.Add($c) } }
        if (-not $l.Variants.Contains($n.Url)) { [void]$l.Variants.Add($n.Url) }
        if ($Depth -lt $l.Depth) { $l.Depth = $Depth }
        if ($script:MspkiLeadTrustRank[$Trust] -gt $script:MspkiLeadTrustRank[[string]$l.Trust]) { $l.Trust = $Trust }
        return $l
    }
    if ($script:MspkiLeads.Count -ge $s.MaxLeads) {
        $s.Dropped++
        if ($s.Dropped -eq 1) {
            Write-MspkiLog -Level Warning -Message ('Lead cap of {0} reached; further leads are not probed.' -f $s.MaxLeads)
            Add-MspkiRunLimit -Text ('Lead cap of {0} reached: some URLs were not probed.' -f $s.MaxLeads)
        }
        return $null
    }
    $scope = 'Local'
    if ($n.Host) { $scope = Get-MspkiHostScope -HostName $n.Host -LocalDomains $s.LocalDomains -TrustedDomains $s.TrustedDomains }
    elseif ($n.UrlType -ne 'Ldap') { $scope = 'Unknown' }
    $lead = [pscustomobject][ordered]@{
        Id         = ('L{0:D4}' -f (++$s.Seq))
        Key        = $key
        Kind       = $Kind
        UrlType    = $n.UrlType
        Url        = $n.Url
        Host       = $n.Host
        Scope      = $scope
        Depth      = $Depth
        Confidence = $Confidence
        Trust      = $Trust
        Variants   = (New-Object System.Collections.ArrayList)
        Sources    = (New-Object System.Collections.ArrayList)
        Origins    = (New-Object System.Collections.ArrayList)
        RelatedCAs = (New-Object System.Collections.ArrayList)
        Aliases    = (New-Object System.Collections.ArrayList)
        Carriers   = (New-Object System.Collections.ArrayList)
    }
    foreach ($c in $Carrier) { if ($c -and -not $lead.Carriers.Contains($c)) { [void]$lead.Carriers.Add($c) } }
    [void]$lead.Variants.Add($n.Url)
    [void]$lead.Sources.Add($Source)
    if ($Origin) { [void]$lead.Origins.Add($Origin) }
    if ($RelatedCA) { [void]$lead.RelatedCAs.Add($RelatedCA) }
    $script:MspkiLeads[$key] = $lead
    return $lead
}

function Write-MspkiLeadLimitSummary {
    <#
    .SYNOPSIS
    Logs the final count of leads dropped by the lead cap or the depth limit (nothing is logged when no limit was hit).
    #>
    [CmdletBinding()]
    param()
    $s = $script:MspkiLeadSettings
    if ($s.Dropped -gt 0) {
        Write-MspkiLog -Level Warning -Message ('Lead cap of {0} was hit: {1} further lead(s) were not probed.' -f $s.MaxLeads, $s.Dropped)
    }
    if ($s.DepthDropped -gt 0) {
        Write-MspkiLog -Level Warning -Message ('Link depth limit of {0} was hit: {1} link(s) were not followed.' -f $s.MaxDepth, $s.DepthDropped)
    }
}

function Test-MspkiShortNameHost {
    <#
    .SYNOPSIS
    True for a single-label host name (not an IP address, not empty): a short name such as "pki".
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$HostName)
    $h = ConvertTo-MspkiHostName $HostName
    if (-not $h -or $h.Contains('.') -or $h.Contains(':')) { return $false }
    if ($h -match '^\d+$') { return $false }
    return $true
}

function Test-MspkiSameHostByDns {
    <#
    .SYNOPSIS
    Decides whether a short host name and an FQDN are the same host, using DNS only.

    .DESCRIPTION
    Proof 1: the short name resolves (suffix search) to a canonical name equal to the FQDN.
    Proof 2: both names resolve to the same canonical name (for example CNAME to one server).
    The same IP address alone is not proof (two web sites can share an address). Both names must resolve.
    Returns { Same; Proof; Evidence }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ShortName,
        [Parameter(Mandatory = $true)][string]$Fqdn,
        [int]$TimeoutMs = 5000
    )
    $s = Resolve-MspkiDnsEntry -HostName $ShortName -TimeoutMs $TimeoutMs
    $f = Resolve-MspkiDnsEntry -HostName $Fqdn -TimeoutMs $TimeoutMs
    $ev = @(('DNS {0}: {1} canonical {2} [{3}]' -f $ShortName, $s.Status, $s.CanonicalName, ($s.Addresses -join ', ')),
            ('DNS {0}: {1} canonical {2} [{3}]' -f $Fqdn, $f.Status, $f.CanonicalName, ($f.Addresses -join ', ')))
    $fq = ConvertTo-MspkiHostName $Fqdn
    if ($s.Status -ne 'Pass' -or $f.Status -ne 'Pass') {
        return [pscustomobject]@{ Same = $false; Proof = 'NotResolved'; Evidence = $ev }
    }
    if ($s.CanonicalName -and $s.CanonicalName -eq $fq) {
        return [pscustomobject]@{ Same = $true; Proof = 'ShortNameResolvesToFqdn'; Evidence = $ev }
    }
    if ($s.CanonicalName -and $s.CanonicalName -eq $f.CanonicalName) {
        return [pscustomobject]@{ Same = $true; Proof = 'SameCanonicalName'; Evidence = $ev }
    }
    return [pscustomobject]@{ Same = $false; Proof = 'NotProven'; Evidence = $ev }
}

function Merge-MspkiShortNameLead {
    <#
    .SYNOPSIS
    Merges a lead whose host is a short name into the lead for the same object on the matching FQDN, but only
    when DNS proves that both names are the same host. Sources, origins and related CAs are combined (nothing is
    dropped) and the short-name URL is kept as an alias. Does nothing with -SkipNetwork (no DNS, no proof).

    .OUTPUTS
    One record per merge: { Kept; Merged; Proof }.
    #>
    [CmdletBinding()]
    param([int]$TimeoutSeconds = 5, [switch]$SkipNetwork)
    if ($SkipNetwork) { return }
    $groups = @{}
    foreach ($l in @($script:MspkiLeads.Values)) {
        if (-not $l.Host -or $l.UrlType -eq 'File') { continue }
        $at = $l.Key.IndexOf('//')
        if ($at -lt 0) { continue }
        $rest = $l.Key.Substring($at + 2 + $l.Host.Length)
        $gk = '{0}|{1}|{2}' -f $l.Kind, $l.UrlType, $rest
        if (-not $groups.ContainsKey($gk)) { $groups[$gk] = New-Object System.Collections.ArrayList }
        [void]$groups[$gk].Add($l)
    }
    foreach ($gk in @($groups.Keys)) {
        $g = @($groups[$gk])
        if ($g.Count -lt 2) { continue }
        foreach ($short in @($g | Where-Object { Test-MspkiShortNameHost $_.Host })) {
            if (-not $script:MspkiLeads.Contains($short.Key)) { continue }
            foreach ($fq in @($g | Where-Object { $_.Host.StartsWith($short.Host + '.') })) {
                $proof = Test-MspkiSameHostByDns -ShortName $short.Host -Fqdn $fq.Host -TimeoutMs ($TimeoutSeconds * 1000)
                if (-not $proof.Same) {
                    Write-MspkiLog -Message ('Short name {0} not merged with {1}: {2}' -f $short.Host, $fq.Host, $proof.Proof)
                    continue
                }
                foreach ($x in $short.Sources) { if (-not $fq.Sources.Contains($x)) { [void]$fq.Sources.Add($x) } }
                foreach ($x in $short.Origins) { if (-not $fq.Origins.Contains($x)) { [void]$fq.Origins.Add($x) } }
                foreach ($x in $short.RelatedCAs) { if (-not $fq.RelatedCAs.Contains($x)) { [void]$fq.RelatedCAs.Add($x) } }
                foreach ($x in $short.Carriers) { if (-not $fq.Carriers.Contains($x)) { [void]$fq.Carriers.Add($x) } }
                if ($short.Depth -lt $fq.Depth) { $fq.Depth = $short.Depth }
                foreach ($u in $short.Variants) {
                    $a = '{0} (same host as {1}: {2})' -f $u, $fq.Host, $proof.Proof
                    if (-not $fq.Aliases.Contains($a)) { [void]$fq.Aliases.Add($a) }
                }
                $script:MspkiLeads.Remove($short.Key)
                Write-MspkiLog -Message ('Merged short name {0} into {1} ({2}).' -f $short.Host, $fq.Host, $proof.Proof)
                [pscustomobject]@{ Kept = $fq.Url; Merged = $short.Url; Proof = $proof.Proof; Evidence = $proof.Evidence }
                break
            }
        }
    }
}

function Get-MspkiLead {
    [CmdletBinding()]
    param([string]$Kind = '')
    foreach ($l in $script:MspkiLeads.Values) { if (-not $Kind -or $l.Kind -eq $Kind) { $l } }
}

function Get-MspkiLeadStatistic {
    [CmdletBinding()]
    param()
    return [pscustomobject]@{ Count = $script:MspkiLeads.Count; Dropped = $script:MspkiLeadSettings.Dropped; DepthDropped = $script:MspkiLeadSettings.DepthDropped
        MaxLeads = $script:MspkiLeadSettings.MaxLeads; MaxDepth = $script:MspkiLeadSettings.MaxDepth }
}

function ConvertTo-MspkiLeadExport {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Lead)
    return [pscustomobject][ordered]@{
        Id = $Lead.Id; Kind = $Lead.Kind; UrlType = $Lead.UrlType; Url = $Lead.Url; Host = $Lead.Host; Scope = $Lead.Scope
        Depth = $Lead.Depth; Confidence = $Lead.Confidence; Variants = [string[]]@($Lead.Variants)
        Sources = [string[]]@($Lead.Sources); Origins = [string[]]@($Lead.Origins); RelatedCAs = [string[]]@($Lead.RelatedCAs)
        Aliases = [string[]]@($Lead.Aliases); Carriers = [string[]]@($Lead.Carriers)
    }
}

function Get-MspkiLeadLocalDomain {
    <#
    .SYNOPSIS
    The DNS names of this forest's own domains, as given to the lead registry (used for the scope of a host).
    #>
    [CmdletBinding()]
    param()
    return , @($script:MspkiLeadSettings.LocalDomains)
}

function Get-MspkiLeadDomainController {
    <#
    .SYNOPSIS
    The forest's domain controllers as given to the lead registry: besides the selected domain controller, the only named hosts an
    LDAP URL may reach without other proof (Test-MspkiLdapHostAllowed).
    #>
    [CmdletBinding()]
    param()
    return , @($script:MspkiLeadSettings.DomainControllers)
}

function Test-MspkiTrustedLeadHost {
    <#
    .SYNOPSIS
    True when a host is already known from trusted evidence: it is a forest domain controller, or an Authoritative or Verified
    lead names it. Used before a redirect hop or a TLS handshake goes to a host that the request itself did not name (audit 2 M9).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$HostName)
    $h = ConvertTo-MspkiHostName $HostName
    if (-not $h) { return $false }
    if (@($script:MspkiLeadSettings.DomainControllers) -contains $h) { return $true }
    foreach ($l in $script:MspkiLeads.Values) {
        if ($l.Host -eq $h -and ($l.Trust -eq 'Authoritative' -or $l.Trust -eq 'Verified')) { return $true }
    }
    return $false
}

function Register-MspkiDiscoveredLead {
    <#
    .SYNOPSIS
    Registers the leads found during discovery: URLs in every CA certificate, the URLs each CA puts into
    the certificates it issues (CA properties) and the CES URLs from Enrollment Services.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Discovery)
    $inv = $Discovery.Inventory
    $n = 0
    foreach ($tp in @($Discovery.Certificates.Keys)) {
        $cert = $Discovery.Certificates[$tp]
        $entry = @($inv.CACertificates | Where-Object { $_.Thumbprint -eq $tp }) | Select-Object -First 1
        $ca = ''
        if ($null -ne $entry) { $ca = $entry.CAName }
        foreach ($u in (Get-MspkiCertificateUrl -Certificate $cert)) {
            if ($u.Kind -eq 'Error') { Write-MspkiLog -Level Warning -Message ('Certificate {0}: {1}' -f $tp, $u.Error); continue }
            $origin = 'CA certificate {0} ({1})' -f $cert.Subject, $tp
            if ($null -ne (Add-MspkiLead -Url $u.Url -Kind $u.Kind -Source ('Cert:{0}:{1}' -f $tp, $u.Kind) -Origin $origin -RelatedCA $ca)) { $n++ }
        }
    }
    foreach ($ca in @($inv.EnterpriseCAs)) {
        if ($null -ne $ca.Properties) {
            foreach ($s in @($ca.Properties.SigningCertificates)) {
                $origin = 'URLs the CA {0} writes into issued certificates (signing certificate {1})' -f $ca.Name, $s.Index
                # The newest signing certificate is the one the CA uses now; the URLs of an older index are historical.
                $state = 'Historical'
                if ([int]$s.Index -eq ([int]$ca.Properties.SigningCertCount - 1)) { $state = 'Current' }
                $carrier = @(('CAIndex|{0}|{1}|{2}' -f $ca.Name, $s.Index, $state))
                foreach ($u in @($s.CdpUrls)) { if ($null -ne (Add-MspkiLead -Url $u -Kind 'CDP' -Source ('CA:{0}:CertCdpUrls' -f $ca.Name) -Origin $origin -RelatedCA $ca.Name -Carrier $carrier)) { $n++ } }
                foreach ($u in @($s.AiaUrls)) { if ($null -ne (Add-MspkiLead -Url $u -Kind 'AIA' -Source ('CA:{0}:CertAiaUrls' -f $ca.Name) -Origin $origin -RelatedCA $ca.Name -Carrier $carrier)) { $n++ } }
                foreach ($u in @($s.OcspUrls)) { if ($null -ne (Add-MspkiLead -Url $u -Kind 'OCSP' -Source ('CA:{0}:CertAiaOcspUrls' -f $ca.Name) -Origin $origin -RelatedCA $ca.Name -Carrier $carrier)) { $n++ } }
            }
        }
        foreach ($e in @($ca.EnrollmentServers)) {
            if ($e.Url) {
                if ($null -ne (Add-MspkiLead -Url $e.Url -Kind 'CES' -Source 'AD:EnrollmentServices:msPKI-Enrollment-Servers' `
                    -Origin ('Enrollment Services object of {0}' -f $ca.Name) -RelatedCA $ca.Name)) { $n++ }
            }
        }
    }
    Write-MspkiLog -Message ('Registered {0} lead reference(s); {1} unique lead(s).' -f $n, $script:MspkiLeads.Count)
}
