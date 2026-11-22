# Fills the entity graph (EntityGraph.ps1) from the discovered inventory, records what the probes saw, and links every finding to the
# entities it is about. See docs/DATA-MODEL.md for what each entity, observation and relation means.

function ConvertTo-MspkiKeyIdHex {
    # Key identifiers are compared as bare lower-case hex.
    param([AllowEmptyString()][string]$Value)
    return (([string]$Value) -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
}

function Get-MspkiCACertificateIdByKeyId {
    <#
    .SYNOPSIS
    Ids of the CA certificate entities whose Subject Key Identifier is the given key id (a renewal with the same key gives several).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$KeyId)
    $k = ConvertTo-MspkiKeyIdHex $KeyId
    if (-not $k) { return @() }
    return @(Get-MspkiEntityList -Type 'CACertificate' | Where-Object { $_.Properties.Contains('SubjectKeyId') -and (ConvertTo-MspkiKeyIdHex $_.Properties['SubjectKeyId']) -eq $k } | ForEach-Object { $_.Id })
}

function Get-MspkiCAIdByName {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Name)
    if (-not $Name) { return $null }
    $hit = @(Get-MspkiEntityList -Type 'CA' | Where-Object { $_.Name -eq $Name -or $_.Properties['CommonName'] -eq $Name -or $_.Properties['DisplayName'] -eq $Name }) | Select-Object -First 1
    if ($null -ne $hit) { return $hit.Id }
    return $null
}

function Add-MspkiHostEntity {
    <#
    .SYNOPSIS
    Adds a host by its DNS name, with the addresses this run already resolved (from the probe cache; no new lookup).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$HostName, [string]$Role = '')
    $h = ([string]$HostName).Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $h) { return $null }
    $props = @{}
    if ($Role) { $props['Roles'] = $Role }
    $dns = Get-MspkiProbeCacheEntry -Key ('dns|' + $h)
    if ($null -ne $dns -and @($dns.Addresses).Count -gt 0) { $props['Addresses'] = @($dns.Addresses) }
    $id = Add-MspkiEntity -Type 'Host' -Key $h -Name $h -Properties $props
    $e = Get-MspkiEntity -Id $id
    if ($Role -and @($e.Properties['Roles']) -notcontains $Role) { $e.Properties['Roles'] = @(@($e.Properties['Roles']) + $Role | Where-Object { $_ }) }
    if ($null -ne $dns -and @($dns.Addresses).Count -gt 0) {
        Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'DNS' -Location $h -Confidence 'Confirmed' -Detail ('A/AAAA: {0}' -f (@($dns.Addresses) -join ', '))
    }
    return $id
}

function Add-MspkiEndpointEntity {
    <#
    .SYNOPSIS
    Adds an endpoint (normalised URI) and its host; returns the endpoint id.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Url, [string]$Kind = '', [string]$Scope = '')
    $n = ConvertTo-MspkiNormalizedUrl -Url $Url
    $id = Get-MspkiEndpointEntityId -Url $Url
    $props = @{ Url = $(if ($n.Url) { $n.Url } else { $Url }); UrlType = $n.UrlType }
    if ($Scope) { $props['Scope'] = $Scope }
    [void](Add-MspkiEntity -Type 'Endpoint' -Id $id -Name $props.Url -Properties $props)
    $e = Get-MspkiEntity -Id $id
    if ($Kind -and @($e.Properties['Kinds']) -notcontains $Kind) { $e.Properties['Kinds'] = @(@($e.Properties['Kinds']) + $Kind | Where-Object { $_ }) }
    if ($n.Host) {
        $hid = Add-MspkiHostEntity -HostName $n.Host
        Add-MspkiRelation -From $id -Type 'hostedOn' -To $hid -Source 'URL'
    }
    return $id
}

function Add-MspkiInventoryToEntityGraph {
    <#
    .SYNOPSIS
    Adds the entities, observations and relations that follow from the discovered inventory (AD and CA data, leads, services).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Inventory)
    $ctx = $Inventory.AdContext
    $pks = ''
    $forestId = $null
    if ($null -ne $ctx) {
        $pks = [string]$ctx.PksDN
        if ($ctx.Forest) {
            $forestId = Add-MspkiEntity -Type 'Forest' -Key $ctx.Forest -Name $ctx.Forest -Properties @{ ForestMode = $ctx.ForestMode; ConfigurationNC = $ctx.ConfigNC }
            Add-MspkiObservation -EntityId $forestId -Kind 'Seen' -Source 'AD' -Location ([string]$ctx.ConfigNC) -Confidence 'Confirmed'
        }
        foreach ($d in @($ctx.ForestDomains | Where-Object { $_ })) {
            $did = Add-MspkiEntity -Type 'Domain' -Key $d -Name $d -Properties @{ InForest = $true }
            if ($forestId) { Add-MspkiRelation -From $did -Type 'partOf' -To $forestId -Source 'AD:Forest' -Confidence 'Confirmed' }
        }
        foreach ($d in @($ctx.TrustedDomains | Where-Object { $_ })) {
            if (@($ctx.ForestDomains) -contains $d) { continue }
            [void](Add-MspkiEntity -Type 'Domain' -Key $d -Name $d -Properties @{ InForest = $false; Trusted = $true })
        }
        if ($ctx.DomainController) { [void](Add-MspkiHostEntity -HostName $ctx.DomainController -Role 'DomainController') }
        if ($ctx.ComputerDomain) {
            $local = ('{0}.{1}' -f $env:COMPUTERNAME, $ctx.ComputerDomain)
            [void](Add-MspkiHostEntity -HostName $local -Role 'ThisComputer')
        }
    }

    foreach ($c in @($Inventory.Containers | Where-Object { $_ -and $_.DistinguishedName })) {
        $id = Add-MspkiEntity -Type 'ADObject' -Key $c.DistinguishedName -Name $c.Name -Properties @{ DistinguishedName = $c.DistinguishedName; ObjectKind = $c.Kind; ChildCount = $c.ChildCount; WhenChanged = $c.WhenChanged }
        if ($c.Exists) { Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'AD' -Location $c.DistinguishedName -Confidence 'Confirmed' }
        elseif ($c.Outcome -eq 'Success' -or $c.Outcome -eq 'NotFound') {
            Add-MspkiObservation -EntityId $id -Kind 'ExpectedMissing' -Source 'AD' -Location $c.DistinguishedName -Confidence 'Confirmed' -Detail 'Standard PKI container not found in the Configuration partition.'
        }
        if ($forestId) { Add-MspkiRelation -From $id -Type 'partOf' -To $forestId -Source 'AD' }
    }

    # Certification authorities and their hosts.
    $caIdByName = @{}
    foreach ($ca in @($Inventory.EnterpriseCAs | Where-Object { $_ })) {
        $key = $(if ($ca.Config) { $ca.Config } else { $ca.Name })
        $props = @{ CommonName = $ca.CommonName; DisplayName = $ca.DisplayName; DnsHostName = $ca.DnsHostName; Config = $ca.Config; Kind = 'Enterprise'; DistinguishedName = $ca.DistinguishedName }
        if ($null -ne $ca.Properties) { $props['CAType'] = $ca.Properties.CATypeName; $props['PropertiesRead'] = $true } else { $props['PropertiesRead'] = $false }
        $id = Add-MspkiEntity -Type 'CA' -Key $key -Name $ca.Name -Properties $props
        $caIdByName[[string]$ca.Name] = $id
        if ($ca.DistinguishedName) {
            Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'AD' -Location $ca.DistinguishedName -Confidence 'Confirmed' -Detail 'Enrollment Services object (Enterprise CA)'
        }
        if ($null -ne $ca.Properties) { Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'CA' -Location ([string]$ca.Config) -Confidence 'Confirmed' -Detail 'Answered GetCAProperty' }
        if ($ca.DnsHostName) { Add-MspkiRelation -From $id -Type 'hostedOn' -To (Add-MspkiHostEntity -HostName $ca.DnsHostName -Role 'CA') -Source 'AD:EnrollmentServices:dNSHostName' }
        if ($forestId) { Add-MspkiRelation -From $id -Type 'partOf' -To $forestId -Source 'AD:EnrollmentServices' }
        foreach ($es in @($ca.EnrollmentServers | Where-Object { $_ })) {
            $u = $(if ($es -is [string]) { $es } elseif ($es.Url) { $es.Url } else { [string]$es })
            if (-not $u) { continue }
            $eid = Add-MspkiEndpointEntity -Url $u -Kind 'CES'
            $sid = Add-MspkiEntity -Type 'Service' -Key ('ces:' + (Get-MspkiEndpointEntityId -Url $u)) -Name ('CES {0}' -f $u) -Properties @{ Kind = 'CES'; Url = $u }
            Add-MspkiObservation -EntityId $sid -Kind 'Referenced' -Source 'AD' -Location ([string]$ca.DistinguishedName) -Detail 'msPKI-Enrollment-Servers'
            Add-MspkiRelation -From $eid -Type 'servedBy' -To $sid -Source 'AD:msPKI-Enrollment-Servers'
            Add-MspkiRelation -From $sid -Type 'enrollsVia' -To $id -Source 'AD:msPKI-Enrollment-Servers'
        }
    }

    # CA certificate generations: where each one is, where it should be, and the chain and generation links between them.
    $containerDn = @{}
    if ($pks) {
        $containerDn = @{
            'AD:AIA' = ('CN=AIA,{0}' -f $pks); 'AD:NTAuthCertificates' = ('CN=NTAuthCertificates,{0}' -f $pks)
            'AD:CertificationAuthorities' = ('CN=Certification Authorities,{0}' -f $pks); 'AD:EnrollmentServices' = ('CN=Enrollment Services,{0}' -f $pks)
        }
    }
    $certIds = @()
    foreach ($c in @($Inventory.CACertificates | Where-Object { $_ -and $_.Thumbprint })) {
        $i = $c.Info
        $props = @{ CAName = $c.CAName; Role = $c.Role; Lifecycle = $c.Lifecycle; LifecycleConfidence = $c.LifecycleConfidence; Generation = $c.Generation }
        if ($null -ne $i) {
            foreach ($p in @('Subject', 'Issuer', 'SerialNumber', 'NotBefore', 'NotAfter', 'KeyAlgorithm', 'KeySize', 'SignatureAlgorithm', 'SubjectKeyId', 'AuthorityKeyId', 'SelfIssued', 'CAVersion', 'Sha256')) {
                if ($null -ne $i.PSObject.Properties[$p]) { $props[$p] = $i.$p }
            }
        }
        $name = $(if ($null -ne $i -and $i.Subject) { $i.Subject } else { $c.Thumbprint })
        $id = Add-MspkiEntity -Type 'CACertificate' -Key $c.Thumbprint -Name $name -Properties $props
        $certIds += $id
        foreach ($s in @($c.Sources | Where-Object { $_ })) {
            if ($s -eq 'CA:GetCAProperty') {
                $cfg = ''
                $ca = @($Inventory.EnterpriseCAs | Where-Object { $_.Name -eq $c.CAName }) | Select-Object -First 1
                if ($null -ne $ca) { $cfg = [string]$ca.Config }
                Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'CA' -Location $cfg -Confidence 'Confirmed' -Detail 'CA signing certificate list (GetCAProperty)'
                continue
            }
            $loc = $(if ($containerDn.ContainsKey($s)) { $containerDn[$s] } else { $s })
            Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'AD' -Location $loc -Confidence 'Confirmed' -Detail $s
            if ($containerDn.ContainsKey($s)) {
                $aid = Get-MspkiEntityId -Type 'ADObject' -Key $containerDn[$s]
                if (Test-MspkiEntity -Id $aid) { Add-MspkiRelation -From $id -Type 'publishedAt' -To $aid -Source $s -Confidence 'Confirmed' }
            }
        }
        $caId = $null
        if ($c.CAName -and $caIdByName.ContainsKey([string]$c.CAName)) { $caId = $caIdByName[[string]$c.CAName] }
        if ($caId) { Add-MspkiRelation -From $id -Type 'certificateOf' -To $caId -Source ([string]$c.AssociationBasis) }
        # Expected but missing: an Enterprise CA certificate generation that is not expired belongs in AIA (chain building) and NTAuth.
        $expired = $false
        if ($null -ne $i -and $i.NotAfter) { try { $expired = ([datetime]$i.NotAfter).ToUniversalTime() -lt [DateTime]::UtcNow } catch { } }
        if ($pks -and -not $expired -and $c.Role -like 'Enterprise*') {
            if (-not $c.InAIA) {
                $why = $(if ($c.InNTAuth) { 'In NTAuth but not in AIA: clients that need this generation to build a chain cannot find it in AD.' } else { 'Not in the AIA container: clients cannot find this generation in AD to build a chain.' })
                Add-MspkiObservation -EntityId $id -Kind 'ExpectedMissing' -Source 'AD' -Location $containerDn['AD:AIA'] -Confidence 'Confirmed' -Detail $why
            }
            if (-not $c.InNTAuth) {
                Add-MspkiObservation -EntityId $id -Kind 'ExpectedMissing' -Source 'AD' -Location $containerDn['AD:NTAuthCertificates'] -Confidence 'Confirmed' -Detail 'Not in NTAuth: smart card and certificate logon through this CA generation fail.'
            }
        }
        if ($pks -and -not $expired -and $c.Role -eq 'EnterpriseRoot' -and -not $c.InCertificationAuthorities) {
            Add-MspkiObservation -EntityId $id -Kind 'ExpectedMissing' -Source 'AD' -Location $containerDn['AD:CertificationAuthorities'] -Confidence 'Confirmed' -Detail 'A root that is not in Certification Authorities is not distributed to domain members as trusted.'
        }
    }
    # Chain: issuedBy by key id (AKI of the child = SKI of the issuer); a self-signed root has no issuer edge.
    foreach ($id in $certIds) {
        $e = Get-MspkiEntity -Id $id
        if ($e.Properties['SelfIssued'] -eq $true) { continue }
        $parents = @(Get-MspkiCACertificateIdByKeyId -KeyId ([string]$e.Properties['AuthorityKeyId']))
        foreach ($p in $parents) {
            Add-MspkiRelation -From $id -Type 'issuedBy' -To $p -Source 'Certificate:AuthorityKeyIdentifier' -Confidence 'Confirmed'
        }
        if ($parents.Count -eq 0 -and $e.Properties['Issuer']) {
            # No Authority Key Identifier: by issuer name only, which a renewal with a new key makes ambiguous, so Inferred.
            foreach ($p in @($certIds | Where-Object { $_ -ne $id -and (Get-MspkiEntity -Id $_).Properties['Subject'] -eq $e.Properties['Issuer'] })) {
                Add-MspkiRelation -From $id -Type 'issuedBy' -To $p -Source 'Certificate:IssuerName' -Confidence 'Inferred'
            }
        }
    }
    # Generations of the same CA: the newer one supersedes the older (by NotBefore).
    $byCa = @{}
    foreach ($id in $certIds) {
        $e = Get-MspkiEntity -Id $id
        $n = [string]$e.Properties['CAName']
        if (-not $n) { $n = [string]$e.Properties['Subject'] }
        if (-not $byCa.ContainsKey($n)) { $byCa[$n] = @() }
        $byCa[$n] += $e
    }
    foreach ($n in $byCa.Keys) {
        $gens = @($byCa[$n] | Sort-Object { try { [datetime]$_.Properties['NotBefore'] } catch { [datetime]::MinValue } })
        for ($k = 1; $k -lt $gens.Count; $k++) {
            Add-MspkiRelation -From $gens[$k].Id -Type 'supersedes' -To $gens[$k - 1].Id -Source 'Certificate:NotBefore' -Confidence 'Inferred'
        }
    }

    # Templates: where they are defined and which CA publishes them.
    foreach ($t in @($Inventory.Templates | Where-Object { $_ -and $_.Name })) {
        $id = Add-MspkiEntity -Type 'Template' -Key $t.Name -Name $(if ($t.DisplayName) { $t.DisplayName } else { $t.Name }) -Properties @{ CommonName = $t.Name; Oid = $t.Oid; SchemaVersion = $t.SchemaVersion; DistinguishedName = $t.DistinguishedName }
        if ($t.DistinguishedName) { Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'AD' -Location $t.DistinguishedName -Confidence 'Confirmed' }
    }
    foreach ($ca in @($Inventory.EnterpriseCAs | Where-Object { $_ })) {
        $caId = $caIdByName[[string]$ca.Name]
        foreach ($tn in @($ca.Templates | Where-Object { $_ })) {
            $tid = Get-MspkiEntityId -Type 'Template' -Key ([string]$tn)
            if (-not (Test-MspkiEntity -Id $tid)) {
                [void](Add-MspkiEntity -Type 'Template' -Id $tid -Name ([string]$tn) -Properties @{ CommonName = [string]$tn })
                Add-MspkiObservation -EntityId $tid -Kind 'ExpectedMissing' -Source 'AD' -Location ('CN={0},CN=Certificate Templates,{1}' -f $tn, $pks) -Confidence 'Referenced' -Detail ('Published on {0} but no template object was read.' -f $ca.Name)
            }
            Add-MspkiObservation -EntityId $tid -Kind 'Referenced' -Source 'AD' -Location ([string]$ca.DistinguishedName) -Detail ('certificateTemplates of {0}' -f $ca.Name)
            Add-MspkiRelation -From $tid -Type 'enrollsVia' -To $caId -Source 'AD:EnrollmentServices:certificateTemplates' -Confidence 'Confirmed'
        }
    }

    # Leads (every AIA/CDP/OCSP/service URL): the endpoint, who references it, and the service behind an OCSP URL.
    foreach ($l in @($Inventory.Leads | Where-Object { $_ -and $_.Url })) {
        $eid = Add-MspkiEndpointEntity -Url $l.Url -Kind $l.Kind -Scope $l.Scope
        foreach ($s in @($l.Sources | Where-Object { $_ })) {
            if ($s -match '^Cert:([0-9A-Fa-f]{40}):') {
                $cid = Get-MspkiEntityId -Type 'CACertificate' -Key $Matches[1]
                if (-not (Test-MspkiEntity -Id $cid)) { continue }
                Add-MspkiRelation -From $cid -Type 'references' -To $eid -Source $s -Confidence 'Confirmed'
                Add-MspkiObservation -EntityId $eid -Kind 'Referenced' -Source 'Certificate' -Location $Matches[1].ToUpperInvariant() -Confidence 'Confirmed' -Detail $l.Kind
            }
            elseif ($s -match '^Crl:([0-9A-Fa-f]{40}):') {
                Add-MspkiObservation -EntityId $eid -Kind 'Referenced' -Source 'CRL' -Location $Matches[1].ToUpperInvariant() -Confidence 'Confirmed' -Detail $l.Kind
            }
            else {
                # A constructed candidate (a standard path tried on a proven PKI host) is a guess until it answers: Inferred.
                $conf = $(if ([string]$l.Confidence -in @('Confirmed', 'Referenced', 'Inferred')) { [string]$l.Confidence } else { 'Referenced' })
                Add-MspkiObservation -EntityId $eid -Kind 'Referenced' -Source (($s -split ':')[0]) -Location $s -Confidence $conf -Detail $l.Kind
                foreach ($rc in @($l.RelatedCAs | Where-Object { $_ })) {
                    if ($caIdByName.ContainsKey([string]$rc)) { Add-MspkiRelation -From $caIdByName[[string]$rc] -Type 'references' -To $eid -Source $s }
                }
            }
        }
        if ($l.Kind -eq 'OCSP') {
            $sid = Add-MspkiEntity -Type 'Service' -Key ('ocsp:' + $eid) -Name ('OCSP {0}' -f $l.Url) -Properties @{ Kind = 'OCSP'; Url = $l.Url }
            Add-MspkiRelation -From $eid -Type 'servedBy' -To $sid -Source 'AIA:OCSP'
        }
    }

    # Services found by their own discovery.
    foreach ($n in @($Inventory.NdesHosts | Where-Object { $_ })) {
        $hn = $(if ($n -is [string]) { $n } elseif ($n.HostName) { $n.HostName } elseif ($n.Host) { $n.Host } else { '' })
        if (-not $hn) { continue }
        $cls = $(if ($n -is [string]) { '' } else { [string]$n.Classification })
        $hid = Add-MspkiHostEntity -HostName $hn -Role $(if ($cls -eq 'ConfirmedEndpoint' -or -not $cls) { 'NDES' } else { 'NDESCandidate' })
        $sid = Add-MspkiEntity -Type 'Service' -Key ('ndes:' + $hn.ToLowerInvariant()) -Name ('NDES / SCEP on {0}' -f $hn) -Properties @{ Kind = 'NDES'; HostName = $hn; Classification = $cls }
        if ($cls) { (Get-MspkiEntity -Id $sid).Properties['Classification'] = $cls }
        Add-MspkiRelation -From $sid -Type 'hostedOn' -To $hid -Source 'NDES' -Confidence $(if ($cls -eq 'ConfirmedEndpoint') { 'Confirmed' } else { 'Inferred' })
        # Only a host that answered SCEP requests was seen; every other classification is a candidate that something names.
        if ($cls -eq 'ConfirmedEndpoint') { Add-MspkiObservation -EntityId $sid -Kind 'Seen' -Source 'HTTP' -Location $hn -Confidence 'Confirmed' -Detail 'Answers GetCACaps / GetCACert' }
        else { Add-MspkiObservation -EntityId $sid -Kind 'Referenced' -Source 'AD' -Location $hn -Confidence 'Inferred' -Detail ('NDES candidate ({0})' -f $(if ($cls) { $cls } else { 'from discovery' })) }
    }
    foreach ($p in @($Inventory.CepPolicies | Where-Object { $_ })) {
        $u = [string]$p.Url
        if (-not $u) { continue }
        $eid = Add-MspkiEndpointEntity -Url $u -Kind 'CEP'
        $sid = Add-MspkiEntity -Type 'Service' -Key ('cep:' + $eid) -Name ('CEP {0}' -f $u) -Properties @{ Kind = 'CEP'; Url = $u }
        Add-MspkiRelation -From $eid -Type 'servedBy' -To $sid -Source 'Policy:CEP'
        Add-MspkiObservation -EntityId $sid -Kind 'Referenced' -Source 'LocalPolicy' -Location 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\PolicyServers' -Detail $u
    }
    $ic = $Inventory.IntuneConnector
    # ProductsMatched / CertificatesMatched are counts (numbers); @(0).Count would be 1 and invent a connector.
    if ($null -ne $ic -and ([int]$ic.ProductsMatched -gt 0 -or [int]$ic.CertificatesMatched -gt 0 -or @($ic.Evidence | Where-Object { $_ }).Count -gt 0)) {
        $hn = [string]$ic.ComputerName
        $sid = Add-MspkiEntity -Type 'Service' -Key ('intuneconnector:' + $hn) -Name ('Intune Certificate Connector on {0}' -f $hn) -Properties @{ Kind = 'IntuneConnector'; HostName = $hn }
        Add-MspkiObservation -EntityId $sid -Kind 'Seen' -Source 'LocalStore' -Location $hn -Confidence 'Confirmed' -Detail 'Local services / certificates'
    }
}

function Get-MspkiLeadIssuerKey {
    <#
    .SYNOPSIS
    The key ids (SKI of the CA certificate) whose certificate or CRL a lead's URL should serve.
    .DESCRIPTION
    A URL in the AIA/CDP of a certificate points at the issuer of that certificate (its AKI). A URL from the CA's own CertCdpUrls /
    CertAiaUrls property is what the CA writes into what it issues, so it points at that CA's current key(s). A Freshest CRL URL found
    in a CRL points at the key that signed that CRL.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Lead, [hashtable]$KnownCertificates = @{})
    $keys = New-Object System.Collections.ArrayList
    $g = Get-MspkiEntityGraphState
    foreach ($s in @($Lead.Sources | Where-Object { $_ })) {
        $k = ''
        if ($s -match '^Cert:([0-9A-Fa-f]{40}):') {
            $t = $Matches[1].ToUpperInvariant()
            if ($KnownCertificates.ContainsKey($t)) { $k = Get-MspkiCertificateAuthorityKeyId -Certificate $KnownCertificates[$t] }
            else { $e = Get-MspkiEntity -Id (Get-MspkiEntityId -Type 'CACertificate' -Key $t); if ($null -ne $e) { $k = [string]$e.Properties['AuthorityKeyId'] } }
            $k = ConvertTo-MspkiKeyIdHex $k
            if ($k -and $keys -notcontains $k) { [void]$keys.Add($k) }
        }
        elseif ($s -match '^Crl:([0-9A-Fa-f]{40}):' -and $g.CrlKey.ContainsKey($Matches[1].ToUpperInvariant())) {
            $k = $g.CrlKey[$Matches[1].ToUpperInvariant()]
            if ($k -and $keys -notcontains $k) { [void]$keys.Add($k) }
        }
        elseif ($s -match '^CA:(.+):Cert(Cdp|Aia)Urls$') {
            $caId = Get-MspkiCAIdByName -Name $Matches[1]
            if (-not $caId) { continue }
            foreach ($r in (Get-MspkiRelation -Type 'certificateOf' -To $caId)) {
                $e = Get-MspkiEntity -Id $r.From
                if ($null -eq $e -or $e.Properties['Lifecycle'] -ne 'Current') { continue }
                $k = ConvertTo-MspkiKeyIdHex ([string]$e.Properties['SubjectKeyId'])
                if ($k -and $keys -notcontains $k) { [void]$keys.Add($k) }
            }
        }
    }
    return @($keys)
}

function Register-MspkiProbeResult {
    <#
    .SYNOPSIS
    Records what one AIA/CDP/OCSP URL gave: a CA certificate, a CRL, or nothing where something was expected.
    .DESCRIPTION
    Called by the endpoint analysis for every URL variant it tested. ExpectedMissing is recorded only when the URL was actually tested
    and returned no usable object; with -SkipNetwork nothing is recorded as missing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lead,
        [Parameter(Mandatory = $true)][string]$Url,
        $Result = $null,
        [hashtable]$KnownCertificates = @{},
        [switch]$Tested
    )
    $n = ConvertTo-MspkiNormalizedUrl -Url $Url
    $src = $(switch ($n.UrlType) { 'Ldap' { 'LDAP' } 'Http' { 'HTTP' } 'File' { 'File' } default { 'Other' } })
    $eid = Add-MspkiEndpointEntity -Url $Url -Kind $Lead.Kind -Scope $Lead.Scope
    $issuerKeys = @(Get-MspkiLeadIssuerKey -Lead $Lead -KnownCertificates $KnownCertificates)
    if ($null -ne $Result -and $null -ne $Result.Crl) {
        $crl = $Result.Crl
        $cid = Get-MspkiCrlEntityId -AuthorityKeyId ([string]$crl.AuthorityKeyId) -Issuer $crl.Issuer -CAVersion ([string]$crl.CAVersion) -IsDelta ([bool]$crl.IsDelta)
        [void](Add-MspkiEntity -Type 'CRL' -Id $cid -Name ('{0} CRL of {1}' -f $(if ($crl.IsDelta) { 'Delta' } else { 'Base' }), $crl.Issuer) -Properties @{
            Issuer = $crl.Issuer; IsDelta = [bool]$crl.IsDelta; AuthorityKeyId = [string]$crl.AuthorityKeyId; CAVersion = [string]$crl.CAVersion })
        Set-MspkiCrlEntityDate -Id $cid -Crl $crl
        Add-MspkiObservation -EntityId $cid -Kind 'Seen' -Source $src -Location $Url -Confidence 'Confirmed' `
            -Detail ('CRL number {0}, this update {1}, next update {2}' -f $crl.CrlNumber, (Format-MspkiGraphDate $crl.ThisUpdate), (Format-MspkiGraphDate $crl.NextUpdate))
        Add-MspkiRelation -From $cid -Type 'publishedAt' -To $eid -Source $src -Confidence 'Confirmed'
        foreach ($sig in (Get-MspkiCACertificateIdByKeyId -KeyId ([string]$crl.AuthorityKeyId))) { Add-MspkiRelation -From $cid -Type 'signedBy' -To $sig -Source 'CRL:AuthorityKeyIdentifier' -Confidence 'Confirmed' }
        Register-MspkiUrlCrl -Url $Url -CrlId $cid
        if ($crl.Sha1) { (Get-MspkiEntityGraphState).CrlKey[[string]$crl.Sha1] = (ConvertTo-MspkiKeyIdHex ([string]$crl.AuthorityKeyId)) }
        return
    }
    if ($null -ne $Result -and $null -ne $Result.Certificate) {
        $c = $Result.Certificate
        $cid = Get-MspkiEntityId -Type 'CACertificate' -Key $c.Thumbprint
        if (-not (Test-MspkiEntity -Id $cid)) {
            [void](Add-MspkiEntity -Type 'CACertificate' -Id $cid -Name $c.Subject -Properties @{
                Subject = $c.Subject; Issuer = $c.Issuer; NotBefore = (Format-MspkiGraphDate $c.NotBefore); NotAfter = (Format-MspkiGraphDate $c.NotAfter)
                SubjectKeyId = (Get-MspkiCertificateSubjectKeyId -Certificate $c); AuthorityKeyId = (Get-MspkiCertificateAuthorityKeyId -Certificate $c); Lifecycle = 'Unknown' })
        }
        Add-MspkiObservation -EntityId $cid -Kind 'Seen' -Source $src -Location $Url -Confidence $(if ($Result.Validated) { 'Confirmed' } else { 'Referenced' }) `
            -Detail $(if ($Result.Validated) { 'Expected issuer, key proven' } else { 'Downloaded; not proven to be the expected issuer' })
        Add-MspkiRelation -From $cid -Type 'publishedAt' -To $eid -Source $src -Confidence $(if ($Result.Validated) { 'Confirmed' } else { 'Referenced' })
        # A certificate that is not the proven issuer does not satisfy the AIA reference: the expected one is still missing here.
        if ($Result.Validated) { return }
    }
    if (-not $Tested -or $n.UrlType -notin @('Http', 'Ldap')) { return }
    if ($Lead.Kind -eq 'AIA') {
        foreach ($k in $issuerKeys) {
            foreach ($cid in (Get-MspkiCACertificateIdByKeyId -KeyId $k)) {
                Add-MspkiObservation -EntityId $cid -Kind 'ExpectedMissing' -Source $src -Location $Url -Confidence 'Confirmed' -Detail 'Named in AIA of a certificate it issued; not retrieved from this location.'
            }
        }
    }
    elseif ($Lead.Kind -in @('CDP', 'FreshestCRL')) {
        foreach ($k in $issuerKeys) {
            $cid = Get-MspkiCrlEntityId -AuthorityKeyId $k -IsDelta ($Lead.Kind -eq 'FreshestCRL')
            if (-not (Test-MspkiEntity -Id $cid)) {
                $sig = @(Get-MspkiCACertificateIdByKeyId -KeyId $k) | Select-Object -First 1
                $iname = $(if ($sig) { (Get-MspkiEntity -Id $sig).Name } else { $k })
                [void](Add-MspkiEntity -Type 'CRL' -Id $cid -Name ('{0} CRL of {1}' -f $(if ($Lead.Kind -eq 'FreshestCRL') { 'Delta' } else { 'Base' }), $iname) -Properties @{ AuthorityKeyId = $k; IsDelta = ($Lead.Kind -eq 'FreshestCRL') })
            }
            Add-MspkiObservation -EntityId $cid -Kind 'ExpectedMissing' -Source $src -Location $Url -Confidence 'Confirmed' -Detail ('Named in {0} of a certificate; not retrieved from this location.' -f $Lead.Kind)
            Register-MspkiUrlCrl -Url $Url -CrlId $cid
        }
    }
}

function Register-MspkiCaOwnCrl {
    <#
    .SYNOPSIS
    Records the base and delta CRLs a CA returned about itself (GetCAProperty) as observations at the CA.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$OwnCrls = @())
    foreach ($o in @($OwnCrls | Where-Object { $_ -and $_.Crl })) {
        $crl = $o.Crl
        $cid = Get-MspkiCrlEntityId -AuthorityKeyId ([string]$crl.AuthorityKeyId) -Issuer $crl.Issuer -CAVersion ([string]$crl.CAVersion) -IsDelta ([bool]$crl.IsDelta)
        [void](Add-MspkiEntity -Type 'CRL' -Id $cid -Name ('{0} CRL of {1}' -f $(if ($crl.IsDelta) { 'Delta' } else { 'Base' }), $crl.Issuer) -Properties @{
            Issuer = $crl.Issuer; IsDelta = [bool]$crl.IsDelta; AuthorityKeyId = [string]$crl.AuthorityKeyId; CAVersion = [string]$crl.CAVersion })
        Set-MspkiCrlEntityDate -Id $cid -Crl $crl
        Add-MspkiObservation -EntityId $cid -Kind 'Seen' -Source 'CA' -Location ([string]$o.Config) -Confidence 'Confirmed' `
            -Detail ('The CA''s own current CRL: number {0}, this update {1}, next update {2}' -f $crl.CrlNumber, (Format-MspkiGraphDate $crl.ThisUpdate), (Format-MspkiGraphDate $crl.NextUpdate))
        foreach ($sig in (Get-MspkiCACertificateIdByKeyId -KeyId ([string]$crl.AuthorityKeyId))) { Add-MspkiRelation -From $cid -Type 'signedBy' -To $sig -Source 'CRL:AuthorityKeyIdentifier' -Confidence 'Confirmed' }
        if ($crl.Sha1) { (Get-MspkiEntityGraphState).CrlKey[[string]$crl.Sha1] = (ConvertTo-MspkiKeyIdHex ([string]$crl.AuthorityKeyId)) }
    }
}

function Format-MspkiGraphDate {
    param($Value)
    if ($null -eq $Value -or $Value -eq '') { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$Value
}

function Add-MspkiFindingEntityLink {
    <#
    .SYNOPSIS
    Gives every finding an EntityIds list: the entities it is about (CA, CA certificate, endpoint, CRL, host, template, AD object).
    .DESCRIPTION
    Ids a finding already carries are kept. Links come from the finding's own fields: RelatedCA, Endpoint (URL or CA config string),
    thumbprints in Target or Message, the template or container named in Target. A finding about the run itself links to the forest,
    or to this computer when there is no forest.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $g = Get-MspkiEntityGraphState
    $fallback = @(Get-MspkiEntityList -Type 'Forest' | ForEach-Object { $_.Id }) | Select-Object -First 1
    if (-not $fallback) {
        $me = @(Get-MspkiEntityList -Type 'Host' | Where-Object { @($_.Properties['Roles']) -contains 'ThisComputer' }) | Select-Object -First 1
        if ($null -eq $me) { $fallback = Add-MspkiHostEntity -HostName $env:COMPUTERNAME -Role 'ThisComputer' } else { $fallback = $me.Id }
    }
    $caByConfig = @{}
    foreach ($e in (Get-MspkiEntityList -Type 'CA')) { if ($e.Properties['Config']) { $caByConfig[([string]$e.Properties['Config']).ToLowerInvariant()] = $e.Id } }
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        $ids = New-Object System.Collections.ArrayList
        if ($null -ne $f.PSObject.Properties['EntityIds']) { foreach ($x in @($f.EntityIds | Where-Object { $_ })) { [void]$ids.Add([string]$x) } }
        foreach ($rc in @(([string]$f.RelatedCA) -split ',\s*' | Where-Object { $_ })) {
            $cid = Get-MspkiCAIdByName -Name $rc
            if ($cid) { [void]$ids.Add($cid) }
        }
        $ep = [string]$f.Endpoint
        if ($ep -match '^[A-Za-z][A-Za-z0-9+.-]*://') {
            $eid = Get-MspkiEndpointEntityId -Url $ep
            if (Test-MspkiEntity -Id $eid) {
                [void]$ids.Add($eid)
                if ($f.Category -in @('CRL', 'CDP') -and $g.UrlCrl.ContainsKey($eid)) { foreach ($c in @($g.UrlCrl[$eid])) { [void]$ids.Add($c) } }
            }
            $n = ConvertTo-MspkiNormalizedUrl -Url $ep
            if ($n.Host) { $hid = Get-MspkiEntityId -Type 'Host' -Key $n.Host; if (Test-MspkiEntity -Id $hid) { [void]$ids.Add($hid) } }
        }
        elseif ($ep -and $caByConfig.ContainsKey($ep.ToLowerInvariant())) { [void]$ids.Add($caByConfig[$ep.ToLowerInvariant()]) }
        elseif ($ep) {
            $hid = Get-MspkiEntityId -Type 'Host' -Key $ep
            if (Test-MspkiEntity -Id $hid) { [void]$ids.Add($hid) }
        }
        foreach ($m in [regex]::Matches(('{0} {1}' -f $f.Target, $f.Message), '\b[0-9A-Fa-f]{40}\b')) {
            $cid = Get-MspkiEntityId -Type 'CACertificate' -Key $m.Value
            if (Test-MspkiEntity -Id $cid) { [void]$ids.Add($cid) }
        }
        if ($f.Category -eq 'Template' -and $f.Target) {
            $tid = Get-MspkiEntityId -Type 'Template' -Key ([string]$f.Target)
            if (-not (Test-MspkiEntity -Id $tid)) {
                $hit = @(Get-MspkiEntityList -Type 'Template' | Where-Object { $_.Name -eq $f.Target -or $_.Properties['CommonName'] -eq $f.Target }) | Select-Object -First 1
                if ($null -ne $hit) { $tid = $hit.Id }
            }
            if (Test-MspkiEntity -Id $tid) { [void]$ids.Add($tid) }
        }
        if ($f.Target) {
            # A container, a host (full or short name) or a domain named as the target.
            $t = [string]$f.Target
            $hit = @(Get-MspkiEntityList -Type 'ADObject' | Where-Object { $_.Name -eq $t -or $_.Properties['DistinguishedName'] -eq $t }) | Select-Object -First 1
            if ($null -ne $hit) { [void]$ids.Add($hit.Id) }
            $tl = $t.ToLowerInvariant()
            # The full name matches exactly; a short name matches only when exactly one host has that first label (audit 2 L9: it used to take
            # the first host called pki.<anything>).
            $hostHits = @(Get-MspkiEntityList -Type 'Host' | Where-Object { $_.Name -eq $tl })
            if ($hostHits.Count -eq 0) { $hostHits = @(Get-MspkiEntityList -Type 'Host' | Where-Object { ($_.Name -split '\.')[0] -eq $tl }) }
            if ($hostHits.Count -eq 1) { [void]$ids.Add($hostHits[0].Id) }
            $did = Get-MspkiEntityId -Type 'Domain' -Key $t
            if ($f.Category -eq 'ADDependency' -and (Test-MspkiEntity -Id $did)) { [void]$ids.Add($did) }
        }
        if ($f.Category -eq 'CRL' -and $f.Target -and -not @($ids | Where-Object { $_ -like 'crl:*' })) {
            foreach ($c in (Get-MspkiEntityList -Type 'CRL' | Where-Object { $_.Properties['Issuer'] -eq $f.Target })) { [void]$ids.Add($c.Id) }
        }
        if ($ids.Count -eq 0 -and $f.Target) {
            $cid = Get-MspkiCAIdByName -Name ([string]$f.Target)
            if ($cid) { [void]$ids.Add($cid) }
        }
        if ($ids.Count -eq 0) { [void]$ids.Add($fallback) }
        $list = [string[]]@($ids | Where-Object { $_ } | Select-Object -Unique)
        $f | Add-Member -NotePropertyName 'EntityIds' -NotePropertyValue $list -Force
    }
}

function Set-MspkiCrlEntityDate {
    # Keeps the newest CRL seen (highest CRL number) on the CRL entity: number, this update and next update (UTC, ISO 8601).
    param([string]$Id, $Crl)
    $e = Get-MspkiEntity -Id $Id
    if ($null -eq $e -or $null -eq $Crl) { return }
    $cur = [string]$e.Properties['CrlNumber']
    if ($cur -and (Compare-MspkiHexNumber ([string]$Crl.CrlNumber) $cur) -le 0) { return }
    $e.Properties['CrlNumber'] = [string]$Crl.CrlNumber
    $e.Properties['ThisUpdate'] = Format-MspkiGraphDate $Crl.ThisUpdate
    $e.Properties['NextUpdate'] = Format-MspkiGraphDate $Crl.NextUpdate
}
