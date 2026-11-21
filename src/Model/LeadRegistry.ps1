# Lead registry (REQUIREMENTS section 4.2). A lead is a URL taken from an authoritative source; only
# leads are ever probed. URLs are normalised before de-duplication and duplicates merge their sources.

$script:MspkiLeads = [ordered]@{}
$script:MspkiLeadSettings = @{ MaxLeads = 300; MaxDepth = 3; LocalDomains = @(); TrustedDomains = @(); Dropped = 0 }
$script:MspkiLeadKinds = @('AIA', 'CDP', 'FreshestCRL', 'OCSP', 'CES', 'CEP', 'NDES')

function Reset-MspkiLeadRegistry {
    [CmdletBinding()]
    param(
        [string[]]$LocalDomains = @(),
        [string[]]$TrustedDomains = @(),
        [ValidateRange(1, 10000)][int]$MaxLeads = 300,
        [ValidateRange(0, 10)][int]$MaxDepth = 3
    )
    $script:MspkiLeads = [ordered]@{}
    $script:MspkiLeadSettings = @{
        MaxLeads = $MaxLeads; MaxDepth = $MaxDepth; Dropped = 0
        LocalDomains = @($LocalDomains | Where-Object { $_ }); TrustedDomains = @($TrustedDomains | Where-Object { $_ })
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
        [string]$Confidence = 'Referenced'
    )
    $n = ConvertTo-MspkiNormalizedUrl -Url $Url
    if (-not $n.Valid) {
        Write-MspkiLog -Level Warning -Message ('Lead ignored (not a usable URL) from {0}: {1}' -f $Source, $Url)
        return $null
    }
    $s = $script:MspkiLeadSettings
    if ($Depth -gt $s.MaxDepth) {
        Write-MspkiLog -Message ('Lead ignored (depth {0} > {1}): {2}' -f $Depth, $s.MaxDepth, $Url)
        return $null
    }
    $key = '{0}|{1}' -f $Kind, $n.Key
    if ($script:MspkiLeads.Contains($key)) {
        $l = $script:MspkiLeads[$key]
        if (-not $l.Sources.Contains($Source)) { [void]$l.Sources.Add($Source) }
        if ($Origin -and -not $l.Origins.Contains($Origin)) { [void]$l.Origins.Add($Origin) }
        if ($RelatedCA -and -not $l.RelatedCAs.Contains($RelatedCA)) { [void]$l.RelatedCAs.Add($RelatedCA) }
        if (-not $l.Variants.Contains($n.Url)) { [void]$l.Variants.Add($n.Url) }
        if ($Depth -lt $l.Depth) { $l.Depth = $Depth }
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
        Id         = ('L{0:D4}' -f ($script:MspkiLeads.Count + 1))
        Key        = $key
        Kind       = $Kind
        UrlType    = $n.UrlType
        Url        = $n.Url
        Host       = $n.Host
        Scope      = $scope
        Depth      = $Depth
        Confidence = $Confidence
        Variants   = (New-Object System.Collections.ArrayList)
        Sources    = (New-Object System.Collections.ArrayList)
        Origins    = (New-Object System.Collections.ArrayList)
        RelatedCAs = (New-Object System.Collections.ArrayList)
    }
    [void]$lead.Variants.Add($n.Url)
    [void]$lead.Sources.Add($Source)
    if ($Origin) { [void]$lead.Origins.Add($Origin) }
    if ($RelatedCA) { [void]$lead.RelatedCAs.Add($RelatedCA) }
    $script:MspkiLeads[$key] = $lead
    return $lead
}

function Get-MspkiLead {
    [CmdletBinding()]
    param([string]$Kind = '')
    foreach ($l in $script:MspkiLeads.Values) { if (-not $Kind -or $l.Kind -eq $Kind) { $l } }
}

function Get-MspkiLeadStatistic {
    [CmdletBinding()]
    param()
    return [pscustomobject]@{ Count = $script:MspkiLeads.Count; Dropped = $script:MspkiLeadSettings.Dropped
        MaxLeads = $script:MspkiLeadSettings.MaxLeads; MaxDepth = $script:MspkiLeadSettings.MaxDepth }
}

function ConvertTo-MspkiLeadExport {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Lead)
    return [pscustomobject][ordered]@{
        Id = $Lead.Id; Kind = $Lead.Kind; UrlType = $Lead.UrlType; Url = $Lead.Url; Host = $Lead.Host; Scope = $Lead.Scope
        Depth = $Lead.Depth; Confidence = $Lead.Confidence; Variants = [string[]]@($Lead.Variants)
        Sources = [string[]]@($Lead.Sources); Origins = [string[]]@($Lead.Origins); RelatedCAs = [string[]]@($Lead.RelatedCAs)
    }
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
                foreach ($u in @($s.CdpUrls)) { if ($null -ne (Add-MspkiLead -Url $u -Kind 'CDP' -Source ('CA:{0}:CertCdpUrls' -f $ca.Name) -Origin $origin -RelatedCA $ca.Name)) { $n++ } }
                foreach ($u in @($s.AiaUrls)) { if ($null -ne (Add-MspkiLead -Url $u -Kind 'AIA' -Source ('CA:{0}:CertAiaUrls' -f $ca.Name) -Origin $origin -RelatedCA $ca.Name)) { $n++ } }
                foreach ($u in @($s.OcspUrls)) { if ($null -ne (Add-MspkiLead -Url $u -Kind 'OCSP' -Source ('CA:{0}:CertAiaOcspUrls' -f $ca.Name) -Origin $origin -RelatedCA $ca.Name)) { $n++ } }
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
