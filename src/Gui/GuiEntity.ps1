# GUI view models for the object graph (G1 drill-down, G2 "where this exists", G4 host identity, G5 plain-language notes).
# Pure data helpers: no WPF types, no I/O. Every object view links to the objects it relates to (Tag "ent:<id>"), to its findings
# (Tag = finding id) and back along the breadcrumb trail (Tag "crumb:<n>").

$script:MspkiGuiEntityType = [ordered]@{
    Forest           = @{ Label = 'Forest'; Glyph = [string][char]0xE909; About = 'The Active Directory forest is the boundary of this PKI: Enterprise CAs, certificate templates and the trust lists clients download (Certification Authorities, AIA, NTAuth) are stored once for the whole forest in its Configuration partition.' }
    Domain           = @{ Label = 'Domain'; Glyph = [string][char]0xE774; About = 'A domain of the forest, or a trusted domain. Computers and users of every domain in the forest use the same Enterprise CAs and templates.' }
    CA               = @{ Label = 'Certification authority'; Glyph = [string][char]0xEB95; About = 'A certification authority (CA) signs certificates and publishes the list of the ones it revoked (CRL). An Enterprise CA is registered in AD and issues from certificate templates. If it stops, nothing new is issued and its CRLs expire, after which clients that check revocation reject every certificate it issued.' }
    CACertificate    = @{ Label = 'CA certificate'; Glyph = [string][char]0xEB95; About = 'One generation of a CA''s own certificate. Clients build a chain from a certificate up to a trusted root through these; each generation must be reachable (AIA) and, for logon, trusted in NTAuth until every certificate it signed has expired.' }
    CRL              = @{ Label = 'Certificate revocation list'; Glyph = [string][char]0xE8C9; About = 'A signed list of revoked certificates, one per CA key (base and delta). Clients download it from the CDP URLs in each certificate; an expired or unreachable CRL makes revocation checks fail, which blocks VPN, Wi-Fi, smart card logon and TLS clients that require them.' }
    Endpoint         = @{ Label = 'Endpoint (URL)'; Glyph = [string][char]0xE71B; About = 'A URL where a certificate, a CRL or a service is published (HTTP, LDAP or file). Clients fetch these during chain building; one that does not answer slows every check or makes it fail.' }
    Host             = @{ Label = 'Host'; Glyph = [string][char]0xE7F8; About = 'A server name the run touched. Its identity is what DNS (addresses, aliases, reverse names), TLS (the certificate it serves) and HTTP (its Server header) say about it; when these disagree, clients and people can end up talking to the wrong machine.' }
    Service          = @{ Label = 'PKI service'; Glyph = [string][char]0xE912; About = 'An enrollment or validation service: Web Enrollment, CEP/CES (enrollment over HTTPS), NDES/SCEP (devices), OCSP (online revocation answers) or the Intune Certificate Connector.' }
    Template         = @{ Label = 'Certificate template'; Glyph = [string][char]0xE8A5; About = 'A certificate template says what a certificate is for, who may request it and how the subject is built. Its permissions decide who can enroll; a template that lets anyone supply any subject is a common way to take over a domain.' }
    LocalCertificate = @{ Label = 'Certificate on this computer'; Glyph = [string][char]0xE8D7; About = 'A certificate in a store of this computer that this PKI issued. Its template, issuer and the Lifecycle event that installed it show how it got here: autoenrollment, a policy such as the Remote Desktop template, or a manual request.' }
    ADObject         = @{ Label = 'AD object'; Glyph = [string][char]0xE8B7; About = 'An object in the Public Key Services container of AD. Clients and CAs read these to find CAs, templates and trusted certificates.' }
    Account          = @{ Label = 'Account'; Glyph = [string][char]0xE77B; About = 'An AD account named in a template permission. For NDES it is the service account or computer that requests the RA certificates; its SPNs or computer name point at the NDES server.' }
    RACertificate    = @{ Label = 'NDES RA certificate'; Glyph = [string][char]0xE8D7; About = 'The registration authority (RA) certificates of NDES: one signs, one encrypts SCEP messages. When they expire, devices can no longer enroll through SCEP (for example Intune devices).' }
}

$script:MspkiGuiRelationText = @{
    issuedBy = @('Issued by', 'Issued'); signedBy = @('Signed by', 'Signs'); publishedAt = @('Published at', 'Publishes'); references = @('Refers to', 'Referred to by')
    hostedOn = @('Runs on', 'Hosts'); servedBy = @('Served by', 'Serves'); resolvesTo = @('Resolves to', 'Alias that resolves here'); aliasOf = @('Name in a certificate of', 'Certificate names this host')
    enrollsVia = @('Enrolls through', 'Enrollment path of'); supersedes = @('Newer generation of', 'Superseded by'); certificateOf = @('Certificate of', 'Has certificate')
    partOf = @('Part of', 'Contains'); mayEnroll = @('May enroll from', 'Enrollment allowed for'); identifies = @('Names host', 'Named by account'); memberOf = @('Member of', 'Has member')
}

function Get-MspkiGuiEntityTypeInfo {
    # Label, glyph and plain-language note of an entity type (unknown types get a neutral entry).
    param([string]$Type)
    if ($script:MspkiGuiEntityType.Contains($Type)) { return $script:MspkiGuiEntityType[$Type] }
    return @{ Label = $Type; Glyph = [string][char]0xE8A5; About = '' }
}

function New-MspkiGuiGraphIndex {
    <#
    .SYNOPSIS
    Indexes the results graph for the object views: entities by id, relations out and in, observations and findings per entity.
    Returns $null when the results have no graph (format 1).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Graph, [AllowEmptyCollection()][object[]]$Findings = @())
    if ($null -eq $Graph) { return $null }
    $ix = @{ Entities = @{}; Out = @{}; In = @{}; Obs = @{}; Findings = @{} }
    foreach ($e in @($Graph.Entities | Where-Object { $null -ne $_ -and $_.Id })) { $ix.Entities[[string]$e.Id] = $e }
    foreach ($r in @($Graph.Relations | Where-Object { $null -ne $_ })) {
        foreach ($pair in @(@('Out', [string]$r.From), @('In', [string]$r.To))) {
            if (-not $ix[$pair[0]].ContainsKey($pair[1])) { $ix[$pair[0]][$pair[1]] = New-Object System.Collections.ArrayList }
            [void]$ix[$pair[0]][$pair[1]].Add($r)
        }
    }
    foreach ($o in @($Graph.Observations | Where-Object { $null -ne $_ })) {
        $k = [string]$o.EntityId
        if (-not $ix.Obs.ContainsKey($k)) { $ix.Obs[$k] = New-Object System.Collections.ArrayList }
        [void]$ix.Obs[$k].Add($o)
    }
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        foreach ($id in @($f.EntityIds | Where-Object { $_ })) {
            if (-not $ix.Findings.ContainsKey([string]$id)) { $ix.Findings[[string]$id] = New-Object System.Collections.ArrayList }
            [void]$ix.Findings[[string]$id].Add([string]$f.Id)
        }
    }
    return $ix
}

function ConvertTo-MspkiGuiValueText {
    # A property value as one readable line: arrays joined, nested objects as "Name: value" pairs, booleans as Yes/No.
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { return $(if ($Value) { 'Yes' } else { 'No' }) }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) { return ((@($Value.Keys) | ForEach-Object { '{0}: {1}' -f $_, (ConvertTo-MspkiGuiValueText $Value[$_]) }) -join '; ') }
    if ($Value -is [System.Management.Automation.PSCustomObject]) { return ((@($Value.PSObject.Properties) | ForEach-Object { '{0}: {1}' -f $_.Name, (ConvertTo-MspkiGuiValueText $_.Value) }) -join '; ') }
    if ($Value -is [System.Collections.IEnumerable]) { return ((@($Value) | ForEach-Object { ConvertTo-MspkiGuiValueText $_ }) -join "`r`n") }
    return [string]$Value
}

function Get-MspkiGuiEntityName {
    param($Index, [string]$Id)
    if ($null -ne $Index -and $Index.Entities.ContainsKey($Id)) { $e = $Index.Entities[$Id]; if ($e.Name) { return [string]$e.Name } }
    return $Id
}

function Get-MspkiGuiHostFact {
    <#
    .SYNOPSIS
    The identity of a host in rows for the details view (G4): addresses, reverse DNS, alias chain, TLS names, Server header.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entity)
    $p = $Entity.Properties
    $get = { param($n) if ($null -ne $p -and $null -ne $p.PSObject.Properties[$n]) { $p.$n } else { $null } }
    $rows = New-Object System.Collections.ArrayList
    $a = @(& $get 'A'); $a6 = @(& $get 'AAAA')
    $addr = @(@($a) + @($a6) | Where-Object { $_ })
    if ($addr.Count -eq 0) { $addr = @(& $get 'Addresses' | Where-Object { $_ }) }
    [void]$rows.Add([pscustomobject]@{ Name = 'IP addresses'; Value = $(if ($addr.Count) { $addr -join ', ' } elseif ((& $get 'DnsLookup') -eq 'NoRecord') { 'none: the name has no DNS record' } else { 'not looked up in this run' }) })
    $ptr = @(& $get 'Ptr' | Where-Object { $null -ne $_ })
    $ptrText = $(if ($ptr.Count) { (@($ptr | ForEach-Object { '{0} -> {1}' -f $_.Address, $(if (@($_.Names).Count) { @($_.Names) -join ', ' } elseif ($_.Lookup -eq 'NoRecord') { 'no PTR record' } else { 'not answered' }) }) -join "`r`n") } else { 'not looked up in this run' })
    [void]$rows.Add([pscustomobject]@{ Name = 'Reverse DNS (PTR)'; Value = $ptrText })
    $chain = @(& $get 'AliasChain' | Where-Object { $_ })
    [void]$rows.Add([pscustomobject]@{ Name = 'Alias chain'; Value = $(if ($chain.Count -gt 1) { $chain -join ' > ' } else { 'none (not an alias)' }) })
    $tls = @(& $get 'TlsCertificates' | Where-Object { $null -ne $_ })
    $tlsText = $(if ($tls.Count) { (@($tls | ForEach-Object { if ($_.Subject) { 'Port {0}: {1}; names {2}' -f $_.Port, $_.Subject, (@($_.DnsNames) -join ', ') } else { 'Port {0}: {1}' -f $_.Port, $(if ($_.Detail) { $_.Detail } else { $_.Result }) } }) -join "`r`n") } else { 'no TLS handshake in this run' })
    [void]$rows.Add([pscustomobject]@{ Name = 'TLS certificate names'; Value = $tlsText })
    $srv = @(& $get 'HttpServer' | Where-Object { $_ })
    [void]$rows.Add([pscustomobject]@{ Name = 'Server header'; Value = $(if ($srv.Count) { $srv -join '; ' } else { 'no HTTP answer in this run' }) })
    $method = & $get 'DnsMethod'
    if ($method) { [void]$rows.Add([pscustomobject]@{ Name = 'Looked up with'; Value = $(if ($method -eq 'DnsClient') { 'DNS only (no NetBIOS, LLMNR or hosts file)' } else { '.NET name resolution (may include NetBIOS / LLMNR): Inferred' }) }) }
    return $rows.ToArray()
}

function Get-MspkiGuiEntityPane {
    <#
    .SYNOPSIS
    The object details view (Kind 'Entity'): what it is, its properties, where it was seen and where it is expected but missing, its related
    objects (both directions, clickable), its findings and the breadcrumb trail. An unknown id gives a plain "not in this run" view.
    #>
    [CmdletBinding()]
    param($Index, [Parameter(Mandatory = $true)][string]$Id, [hashtable]$RowById = @{}, [AllowEmptyCollection()][string[]]$Trail = @())
    $crumbs = @(for ($i = 0; $i -lt @($Trail).Count; $i++) { [pscustomobject]@{ Name = (Get-MspkiGuiEntityName -Index $Index -Id $Trail[$i]); Tag = ('crumb:{0}' -f $i); IsLast = ($i -eq @($Trail).Count - 1) } })
    if ($null -eq $Index -or -not $Index.Entities.ContainsKey($Id)) {
        return [pscustomobject][ordered]@{ Kind = 'Entity'; Known = $false; Title = $Id; TypeText = 'Not in this run'; TypeGlyph = [string][char]0xE783; About = 'This object is not in the results of this run (or the results were written by an older version without the object graph).'
            Properties = @(); HostFacts = @(); HasHostFacts = $false; Seen = @(); Missing = @(); HasMissing = $false; NoSeen = $true; Related = @(); NoRelated = $true; Findings = @(); FindingCount = 0; NoFindings = $true
            Breadcrumbs = $crumbs; CanGoBack = (@($Trail).Count -gt 1); Id = $Id; CopyText = $Id }
    }
    $e = $Index.Entities[$Id]
    $ti = Get-MspkiGuiEntityTypeInfo -Type ([string]$e.Type)
    $props = @()
    if ($null -ne $e.Properties) {
        $props = @($e.Properties.PSObject.Properties | Where-Object { $null -ne $_.Value -and [string]$_.Value -ne '' } | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name = ($_.Name -creplace '([a-z])([A-Z])', '$1 $2'); Value = (ConvertTo-MspkiGuiValueText $_.Value) } } | Where-Object { $_.Value })
    }
    $obs = @(); if ($Index.Obs.ContainsKey($Id)) { $obs = @($Index.Obs[$Id]) }
    $toRow = {
        param($o)
        $missing = ([string]$o.Kind -eq 'ExpectedMissing')
        [pscustomobject][ordered]@{
            KindText = $(switch ([string]$o.Kind) { 'Seen' { 'Seen here' } 'Referenced' { 'Named here' } default { 'Expected here, but MISSING' } })
            Source = [string]$o.Source; Location = [string]$o.Location; Detail = [string]$o.Detail; Time = [string]$o.Timestamp; IsMissing = $missing
            ConfidencePill = (Get-MspkiGuiStatusPill -Value ([string]$o.Confidence) -Kind Confidence)
            Glyph = $(if ($missing) { [string][char]0xE7BA } elseif ([string]$o.Kind -eq 'Seen') { [string][char]0xE73E } else { [string][char]0xE71B })
        }
    }
    $seen = @($obs | Where-Object { $_.Kind -ne 'ExpectedMissing' } | Sort-Object @{ Expression = { if ($_.Kind -eq 'Seen') { 0 } else { 1 } } }, Source, Location | ForEach-Object { & $toRow $_ })
    $miss = @($obs | Where-Object { $_.Kind -eq 'ExpectedMissing' } | Sort-Object Source, Location | ForEach-Object { & $toRow $_ })
    $rel = New-Object System.Collections.ArrayList
    foreach ($dir in @('Out', 'In')) {
        if (-not $Index[$dir].ContainsKey($Id)) { continue }
        foreach ($r in @($Index[$dir][$Id])) {
            $other = $(if ($dir -eq 'Out') { [string]$r.To } else { [string]$r.From })
            $txt = $script:MspkiGuiRelationText[[string]$r.Type]
            $label = $(if ($null -ne $txt) { $txt[$(if ($dir -eq 'Out') { 0 } else { 1 })] } else { [string]$r.Type })
            $ot = $(if ($Index.Entities.ContainsKey($other)) { [string]$Index.Entities[$other].Type } else { '' })
            [void]$rel.Add([pscustomobject][ordered]@{ Label = $label; Name = (Get-MspkiGuiEntityName -Index $Index -Id $other); TypeText = (Get-MspkiGuiEntityTypeInfo -Type $ot).Label
                Glyph = (Get-MspkiGuiEntityTypeInfo -Type $ot).Glyph; Tag = ('ent:{0}' -f $other); ConfidencePill = (Get-MspkiGuiStatusPill -Value ([string]$r.Confidence) -Kind Confidence); Known = $Index.Entities.ContainsKey($other) })
        }
    }
    $related = @($rel | Sort-Object Label, Name)
    $fids = @(); if ($Index.Findings.ContainsKey($Id)) { $fids = @($Index.Findings[$Id] | Select-Object -Unique) }
    $rows = @($fids | Where-Object { $RowById.ContainsKey($_) } | ForEach-Object { $RowById[$_] } | Sort-Object @{ Expression = { -1 * $_.StatusRank } }, Id)
    $hostFacts = @()
    if ([string]$e.Type -eq 'Host') { $hostFacts = @(Get-MspkiGuiHostFact -Entity $e) }
    $copy = New-Object 'System.Collections.Generic.List[string]'
    $copy.Add(('{0}: {1} ({2})' -f $ti.Label, $e.Name, $Id))
    foreach ($p in $props) { $copy.Add(('{0}: {1}' -f $p.Name, $p.Value)) }
    foreach ($s in $seen) { $copy.Add(('{0}: {1} {2} [{3}] {4}' -f $s.KindText, $s.Source, $s.Location, $s.ConfidencePill.Text, $s.Detail).Trim()) }
    foreach ($s in $miss) { $copy.Add(('MISSING: {0} {1} {2}' -f $s.Source, $s.Location, $s.Detail).Trim()) }
    foreach ($r in $related) { $copy.Add(('{0}: {1}' -f $r.Label, $r.Name)) }
    return [pscustomobject][ordered]@{
        Kind = 'Entity'; Known = $true; Id = $Id; Title = [string]$e.Name; TypeText = $ti.Label; TypeGlyph = $ti.Glyph; About = $ti.About; HasAbout = [bool]$ti.About
        Properties = $props; HostFacts = $hostFacts; HasHostFacts = ($hostFacts.Count -gt 0)
        Seen = $seen; NoSeen = ($seen.Count -eq 0); Missing = $miss; HasMissing = ($miss.Count -gt 0); MissingCount = $miss.Count
        Related = $related; NoRelated = ($related.Count -eq 0); Findings = [object[]]$rows; FindingCount = $rows.Count; NoFindings = ($rows.Count -eq 0)
        Breadcrumbs = $crumbs; CanGoBack = (@($Trail).Count -gt 1); CopyText = ($copy -join "`r`n")
    }
}

function Get-MspkiGuiEntityLink {
    <#
    .SYNOPSIS
    Link rows ({ Name; TypeText; Glyph; Tag = "ent:<id>" }) for a list of entity ids, for the Findings and Discovery map panes.
    #>
    [CmdletBinding()]
    param($Index, [AllowEmptyCollection()][string[]]$Ids = @(), [int]$Max = 12)
    if ($null -eq $Index) { return @() }
    return @($Ids | Where-Object { $_ -and $Index.Entities.ContainsKey($_) } | Select-Object -Unique -First $Max | ForEach-Object {
        $t = Get-MspkiGuiEntityTypeInfo -Type ([string]$Index.Entities[$_].Type)
        [pscustomobject][ordered]@{ Name = (Get-MspkiGuiEntityName -Index $Index -Id $_); TypeText = $t.Label; Glyph = $t.Glyph; Tag = ('ent:{0}' -f $_) } })
}

function Get-MspkiGuiObjectList {
    <#
    .SYNOPSIS
    Rows for the Objects page: every entity with its type, number of findings and whether something is expected but missing, sorted by type and name.
    #>
    [CmdletBinding()]
    param($Index)
    if ($null -eq $Index) { return @() }
    $order = @($script:MspkiGuiEntityType.Keys)
    return @($Index.Entities.Values | ForEach-Object {
        $t = Get-MspkiGuiEntityTypeInfo -Type ([string]$_.Type)
        $id = [string]$_.Id
        $miss = 0; if ($Index.Obs.ContainsKey($id)) { $miss = @($Index.Obs[$id] | Where-Object { $_.Kind -eq 'ExpectedMissing' }).Count }
        $nf = 0; if ($Index.Findings.ContainsKey($id)) { $nf = @($Index.Findings[$id] | Select-Object -Unique).Count }
        [pscustomobject][ordered]@{ Id = $id; Name = [string]$_.Name; Type = [string]$_.Type; TypeText = $t.Label; Glyph = $t.Glyph; TypeOrder = [Math]::Max(0, [array]::IndexOf($order, [string]$_.Type))
            FindingCount = $nf; MissingCount = $miss; HasMissing = ($miss -gt 0); Tag = ('ent:{0}' -f $id)
            SearchText = ('{0} {1} {2}' -f $_.Name, $id, $t.Label).ToLowerInvariant() }
    } | Sort-Object TypeOrder, Name)
}
