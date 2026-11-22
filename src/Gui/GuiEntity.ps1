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
    $ix = @{ Entities = @{}; Out = @{}; In = @{}; Obs = @{}; Findings = @{}; ByName = @{} }
    foreach ($e in @($Graph.Entities | Where-Object { $null -ne $_ -and $_.Id })) {
        $ix.Entities[[string]$e.Id] = $e
        # Lower-cased name (and the URL of an endpoint) -> ids, to find the object behind a Discovery map item or a CA card.
        $names = @([string]$e.Name)
        if ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['Url']) { $names += [string]$e.Properties.Url }
        if ([string]$e.Type -eq 'Endpoint') { $names += @($names | ForEach-Object { try { [System.Uri]::UnescapeDataString($_) } catch { $_ } }) }
        foreach ($n in @($names | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Select-Object -Unique)) {
            if (-not $ix.ByName.ContainsKey($n)) { $ix.ByName[$n] = New-Object System.Collections.ArrayList }
            [void]$ix.ByName[$n].Add([string]$e.Id)
        }
    }
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
    if ($null -ne $Index -and $Index.Entities.ContainsKey($Id)) {
        $e = $Index.Entities[$Id]
        if ($e.Name) {
            # URLs are stored percent-encoded (as the certificate carries them); people read them decoded.
            if ([string]$e.Type -eq 'Endpoint') { try { return [System.Uri]::UnescapeDataString([string]$e.Name) } catch { } }
            return [string]$e.Name
        }
    }
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
    param($Index, [Parameter(Mandatory = $true)][string]$Id, [hashtable]$RowById = @{}, [AllowEmptyCollection()][string[]]$Trail = @(),
        [string]$OriginText = '')
    # Back goes to the previous object of the trail, or (at the first object) to what the user came from: a finding or a map item.
    $n = @($Trail).Count
    $crumbs = @(for ($i = 0; $i -lt $n; $i++) { [pscustomobject]@{ Name = (Get-MspkiGuiEntityName -Index $Index -Id $Trail[$i]); Tag = ('crumb:{0}' -f $i); IsLast = ($i -eq $n - 1); NotLast = ($i -lt $n - 1); NotFirst = ($i -gt 0) } })
    $backText = ''
    if ($n -gt 1) { $backText = 'Back to {0}' -f (Get-MspkiGuiEntityName -Index $Index -Id $Trail[$n - 2]) }
    elseif ($OriginText) { $backText = $OriginText }
    $nav = @{ Breadcrumbs = $crumbs; ShowCrumbs = ($n -gt 1); CanGoBack = [bool]$backText; BackText = $backText }
    if ($null -eq $Index -or -not $Index.Entities.ContainsKey($Id)) {
        $why = 'This object is not in the results of this run.'
        if ($null -eq $Index) { $why = 'These results were written by an older version of the tool, without the object graph. Run the health check again to see objects.' }
        return [pscustomobject][ordered]@{ Kind = 'Entity'; Known = $false; Title = $Id; TypeText = 'Not in this run'; TypeGlyph = [string][char]0xE783; About = $why; HasAbout = $true
            Facts = @(); HasProperties = $false; HostFacts = @(); HasHostFacts = $false; Seen = @(); SeenCount = 0; Missing = @(); MissingCount = 0; HasMissing = $false; NoSeen = $true
            Related = @(); RelatedCount = 0; NoRelated = $true; Findings = @(); FindingCount = 0; NoFindings = $true; MissingBadge = ''; SeenBadge = 'Not in this run'; FindingBadge = '0 findings'
            Breadcrumbs = $nav.Breadcrumbs; ShowCrumbs = $nav.ShowCrumbs; CanGoBack = $nav.CanGoBack; BackText = $nav.BackText; Id = $Id; CopyText = $Id }
    }
    $e = $Index.Entities[$Id]
    $ti = Get-MspkiGuiEntityTypeInfo -Type ([string]$e.Type)
    # A PKI service gets the note of its own kind (Web Enrollment, CES, CEP, NDES, OCSP, Intune connector).
    if ([string]$e.Type -eq 'Service' -and $null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['Kind'] -and $script:MspkiGuiServiceKind.Contains([string]$e.Properties.Kind)) {
        $sk = $script:MspkiGuiServiceKind[[string]$e.Properties.Kind]
        $ti = @{ Label = $sk.Label; Glyph = [string][char]$sk.Glyph; About = $sk.About }
    }
    $props = @()
    if ($null -ne $e.Properties) {
        $props = @($e.Properties.PSObject.Properties | Where-Object { $null -ne $_.Value -and [string]$_.Value -ne '' } | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name = ($_.Name -creplace '([a-z])([A-Z])', '$1 $2'); Value = (ConvertTo-MspkiGuiValueText $_.Value) } } | Where-Object { $_.Value })
    }
    $obs = @(); if ($Index.Obs.ContainsKey($Id)) { $obs = @($Index.Obs[$Id]) }
    $toRow = {
        param($o)
        $missing = ([string]$o.Kind -eq 'ExpectedMissing')
        [pscustomobject][ordered]@{
            KindText = $(switch ([string]$o.Kind) { 'Seen' { 'Seen here' } 'Referenced' { 'Named here' } default { 'Missing' } })
            Source = [string]$o.Source; Location = [string]$o.Location; Detail = [string]$o.Detail; HasDetail = [bool]$o.Detail; Time = [string]$o.Timestamp; IsMissing = $missing
            TimeText = $(if ($null -ne ($t = ConvertTo-MspkiGuiDateTime -Value $o.Timestamp)) { $t.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' } else { '' })
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
        Kind = 'Entity'; Known = $true; Id = $Id; Title = (Get-MspkiGuiEntityName -Index $Index -Id $Id); TypeText = $ti.Label; TypeGlyph = $ti.Glyph; About = $ti.About; HasAbout = [bool]$ti.About
        Facts = $props; HasProperties = ($props.Count -gt 0); HostFacts = $hostFacts; HasHostFacts = ($hostFacts.Count -gt 0)
        Seen = $seen; SeenCount = $seen.Count; NoSeen = ($seen.Count -eq 0); Missing = $miss; HasMissing = ($miss.Count -gt 0); MissingCount = $miss.Count
        Related = $related; RelatedCount = $related.Count; NoRelated = ($related.Count -eq 0); Findings = [object[]]$rows; FindingCount = $rows.Count; NoFindings = ($rows.Count -eq 0)
        MissingBadge = ('Missing in {0}' -f (Format-MspkiGuiCount -Count $miss.Count -Singular 'expected place'))
        SeenBadge = ('Seen or named in {0}' -f (Format-MspkiGuiCount -Count $seen.Count -Singular 'place')); FindingBadge = (Format-MspkiGuiCount -Count $rows.Count -Singular 'finding')
        Breadcrumbs = $nav.Breadcrumbs; ShowCrumbs = $nav.ShowCrumbs; CanGoBack = $nav.CanGoBack; BackText = $nav.BackText; CopyText = ($copy -join "`r`n")
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
    Rows for the Objects page: every entity with its type, its findings (count and worst status) and whether something is expected but
    missing, sorted by type and name.
    #>
    [CmdletBinding()]
    param($Index, [hashtable]$RowById = @{})
    if ($null -eq $Index) { return @() }
    $order = @($script:MspkiGuiEntityType.Keys)
    $quiet = @('Pass', 'Information', 'Skipped', 'NotApplicable')
    return @($Index.Entities.Values | ForEach-Object {
        $t = Get-MspkiGuiEntityTypeInfo -Type ([string]$_.Type)
        $id = [string]$_.Id
        $miss = 0; if ($Index.Obs.ContainsKey($id)) { $miss = @($Index.Obs[$id] | Where-Object { $_.Kind -eq 'ExpectedMissing' }).Count }
        $fids = @(); if ($Index.Findings.ContainsKey($id)) { $fids = @($Index.Findings[$id] | Select-Object -Unique) }
        $worst = ''; $rank = -1
        foreach ($f in $fids) { if ($RowById.ContainsKey($f) -and [int]$RowById[$f].StatusRank -gt $rank) { $rank = [int]$RowById[$f].StatusRank; $worst = [string]$RowById[$f].Status } }
        $nf = $fids.Count
        $fpill = New-MspkiGuiPill -Text '' -Tone Neutral
        if ($nf -gt 0) {
            $ftext = Format-MspkiGuiCount -Count $nf -Singular 'finding'
            if ($worst) { $fpill = Get-MspkiGuiStatusPill -Value $worst -Text $ftext } else { $fpill = New-MspkiGuiPill -Text $ftext -Tone Neutral -Code 0xE8FD }
        }
        $mpill = New-MspkiGuiPill -Text '' -Tone Neutral
        if ($miss -gt 0) { $mpill = New-MspkiGuiPill -Text ('{0} missing' -f $miss) -Tone Warn -Code 0xE7BA }
        $attention = ($miss -gt 0 -or ($worst -and $quiet -notcontains $worst))
        [pscustomobject][ordered]@{ Id = $id; Name = (Get-MspkiGuiEntityName -Index $Index -Id $id); Type = [string]$_.Type; TypeText = $t.Label; Glyph = $t.Glyph; TypeOrder = [Math]::Max(0, [array]::IndexOf($order, [string]$_.Type))
            FindingCount = $nf; WorstStatus = $worst; FindingPill = $fpill; MissingCount = $miss; HasMissing = ($miss -gt 0); MissingPill = $mpill; NeedsAttention = [bool]$attention
            Tag = ('ent:{0}' -f $id); SearchText = ('{0} {1} {2}' -f $_.Name, $id, $t.Label).ToLowerInvariant() }
    } | Sort-Object TypeOrder, Name)
}

function Test-MspkiGuiObjectFilter {
    <#
    .SYNOPSIS
    True when an Objects row matches the search words (every word somewhere in name, id or type), the type filter ('' or 'All' = any)
    and, with -AttentionOnly, has a finding worse than Information or something expected but missing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row, [AllowEmptyString()][string]$Text = '', [AllowEmptyString()][string]$Type = '', [switch]$AttentionOnly)
    if ($Type -and $Type -ne 'All' -and [string]$Row.TypeText -ne $Type) { return $false }
    if ($AttentionOnly -and -not $Row.NeedsAttention) { return $false }
    foreach ($w in @($Text.ToLowerInvariant() -split '\s+' | Where-Object { $_ })) {
        if (([string]$Row.SearchText).IndexOf($w, [System.StringComparison]::Ordinal) -lt 0) { return $false }
    }
    return $true
}

function Get-MspkiGuiObjectTypeChoice {
    <#
    .SYNOPSIS
    The choices of the Objects type filter: 'All' and every type label that occurs, in the fixed type order.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Rows = @())
    return @(@('All') + @($Rows | Sort-Object TypeOrder | ForEach-Object { [string]$_.TypeText } | Select-Object -Unique))
}

function Step-MspkiGuiTrail {
    <#
    .SYNOPSIS
    The breadcrumb trail after one navigation step: Push an object (an object already in the trail cuts the trail back to it), go Back one
    step, or jump to Crumb <Index>. Returns the new trail (string[]).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Trail = @(), [Parameter(Mandatory = $true)][ValidateSet('Push', 'Back', 'Crumb')][string]$Action, [string]$Id = '', [int]$Index = 0)
    $t = @($Trail | Where-Object { $_ })
    if ($Action -eq 'Push') {
        if (-not $Id) { return [string[]]$t }
        $at = [array]::IndexOf([string[]]$t, $Id)
        if ($at -ge 0) { return [string[]]@($t[0..$at]) }
        return [string[]]@($t + $Id)
    }
    if ($Action -eq 'Back') { if ($t.Count -le 1) { return [string[]]@() }; return [string[]]@($t[0..($t.Count - 2)]) }
    if ($Index -lt 0 -or $Index -ge $t.Count) { return [string[]]$t }
    return [string[]]@($t[0..$Index])
}

function Find-MspkiGuiEntityId {
    <#
    .SYNOPSIS
    The ids of the objects of one type (or any type) with this name or URL, case-insensitive.
    #>
    [CmdletBinding()]
    param($Index, [AllowEmptyString()][string]$Name, [string]$Type = '')
    if ($null -eq $Index -or -not $Name -or $null -eq $Index.ByName) { return @() }
    $k = $Name.Trim().ToLowerInvariant()
    if (-not $Index.ByName.ContainsKey($k)) { return @() }
    return @($Index.ByName[$k] | Where-Object { -not $Type -or [string]$Index.Entities[$_].Type -eq $Type })
}

function Get-MspkiGuiNodeEntityId {
    <#
    .SYNOPSIS
    The objects behind a Discovery map item: the forest, a container (by DN), a CA (by configuration string or name), a CA certificate
    (by thumbprint), an endpoint (by URL and its variants) or the templates of a template list. When none is known, the objects of the
    item's own findings. Only ids that are in the graph are returned.
    #>
    [CmdletBinding()]
    param($Index, [AllowNull()]$Node, [hashtable]$RowById = @{})
    if ($null -eq $Index -or $null -eq $Node) { return @() }
    $ids = New-Object 'System.Collections.Generic.List[string]'
    $add = { param($i) if ($i -and $Index.Entities.ContainsKey($i) -and -not $ids.Contains($i)) { $ids.Add($i) } }
    $detail = @($Node.Detail | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $label = [string]$Node.Label
    switch ([string]$Node.Type) {
        'Forest' { & $add ('forest:' + ($label -replace '^Forest\s+', '').Trim().ToLowerInvariant()) }
        'Container' { foreach ($d in $detail) { if ($d -match '^(CN|OU|DC)=') { & $add ('adobject:' + $d.Trim().ToLowerInvariant()) } } }
        'Certificate' { foreach ($d in $detail) { if ($d -match 'Thumbprint \(SHA-1\):\s*([0-9A-Fa-f ]+)') { & $add ('cacert:' + ($Matches[1] -replace '\s', '').ToLowerInvariant()) } } }
        'CA' {
            foreach ($d in $detail) { if ($d -match '^CA configuration:\s*(.+)$') { & $add ('ca:' + $Matches[1].Trim().ToLowerInvariant()) } }
            if ($ids.Count -eq 0) { foreach ($i in @(Find-MspkiGuiEntityId -Index $Index -Name $label -Type 'CA')) { & $add $i } }
        }
        'Endpoint' {
            $urls = @()
            $cut = $label.IndexOf(': ')
            if ($cut -ge 0) { $urls += $label.Substring($cut + 2) }
            foreach ($d in $detail) { if ($d -match '^URL variants:\s*(.+)$') { $urls += @($Matches[1] -split '\s;\s') } }
            foreach ($u in @($urls | Where-Object { $_ } | ForEach-Object { $_.Trim() })) {
                foreach ($i in @(Find-MspkiGuiEntityId -Index $Index -Name $u -Type 'Endpoint')) { & $add $i }
                # The id key of a web URL: decoded, lower case, http and https as one "web" scheme.
                $k = $u
                try { $k = [System.Uri]::UnescapeDataString($u) } catch { }
                & $add ('endpoint:' + ($k.ToLowerInvariant() -replace '^https?://', 'web://'))
            }
        }
        'Group' {
            if ($label -like 'Published certificate templates*') { foreach ($d in $detail) { & $add ('template:' + $d.Trim().ToLowerInvariant()) } }
        }
    }
    if ($ids.Count -eq 0) {
        foreach ($fid in @($Node.FindingIds | Where-Object { $_ })) {
            if (-not $RowById.ContainsKey($fid)) { continue }
            $f = $RowById[$fid]
            if ($null -ne $f.PSObject.Properties['Finding']) { $f = $f.Finding }
            foreach ($i in @($f.EntityIds | Where-Object { $_ })) { & $add ([string]$i) }
        }
    }
    return [string[]]$ids.ToArray()
}

function Add-MspkiGuiPaneObject {
    <#
    .SYNOPSIS
    Adds the "Related objects" links (Objects, ObjectCount, HasObjects) to a Finding or Discovery map pane, so that each opens its object view.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Pane, $Index, [AllowEmptyCollection()][string[]]$Ids = @())
    $links = @(Get-MspkiGuiEntityLink -Index $Index -Ids $Ids -Max 24)
    $Pane | Add-Member -NotePropertyName Objects -NotePropertyValue ([object[]]$links) -Force
    $Pane | Add-Member -NotePropertyName ObjectCount -NotePropertyValue $links.Count -Force
    $Pane | Add-Member -NotePropertyName HasObjects -NotePropertyValue ($links.Count -gt 0) -Force
    return $Pane
}

# ===== PKI Services page (G3, WP6) =====
# One section per service kind, in a fixed order: what it is, what this run can see of it (scope), every instance found with its state,
# confidence and host, and the findings about it. "Not found" (looked for, nothing there) is kept apart from "can't be checked from here"
# (the run could not look) and from "not checked in this run" (no finding and no object at all).
$script:MspkiGuiServiceKind = [ordered]@{
    WebEnrollment = @{ Label = 'Web Enrollment'; Glyph = 0xE774; Category = 'WebEnrollment'; NotFound = 'Not found on the CA hosts'
        About = 'The Web Enrollment pages of a CA, where people request certificates in a browser. Rarely needed today; on plain HTTP with Windows sign-in it is an NTLM relay target (ESC8) that can lead to a domain takeover.'
        Scope = 'Only the standard Web Enrollment path on the Enterprise CA hosts is tried, anonymously. Web Enrollment on a server that nothing in AD names cannot be found without scanning, which this tool never does.' }
    CES = @{ Label = 'Certificate Enrollment Web Service (CES)'; Glyph = 0xE753; Category = 'CES'; NotFound = 'None registered in AD'
        About = 'Enrollment over HTTPS for computers that cannot reach the CA over RPC/DCOM: other forests, workgroup computers or remote clients. A CA lists its CES servers on its AD object.'
        Scope = 'Read from the Enrollment Services objects in AD (msPKI-Enrollment-Servers): every CES that a CA has registered is listed.' }
    CEP = @{ Label = 'Certificate Enrollment Policy Web Service (CEP)'; Glyph = 0xE7C3; Category = 'CEP'; NotFound = 'No policy server for this computer'
        About = 'Tells clients over HTTPS which templates they may use; works together with CES. Clients learn its URL from Group Policy.'
        Scope = 'Read from the enrollment policy of this computer (Group Policy). Other computers can get a different policy, which cannot be seen from here.' }
    NDES = @{ Label = 'NDES / SCEP'; Glyph = 0xE772; Category = 'NDES'; NotFound = 'Not found'
        About = 'The Network Device Enrollment Service gives certificates over SCEP to devices without a domain account: network devices, and phones and laptops through Intune. Its two RA certificates must stay valid, or every SCEP request fails.'
        Scope = 'Found from the permissions of the NDES RA templates and the accounts that hold them, then asked GetCACaps and GetCACert anonymously. The admin page is only requested with -IncludeNdesAdminProbe.' }
    OCSP = @{ Label = 'Online responder (OCSP)'; Glyph = 0xE895; Category = 'OCSP'; NotFound = 'No OCSP URL found'
        About = 'Answers "is this certificate revoked?" for one certificate at a time, so that clients need not download the whole CRL. Clients use it only when the certificate carries its URL.'
        Scope = 'From the OCSP URLs in CA certificates and CA properties, and the standard /ocsp/ path on the Enterprise CA hosts.' }
    IntuneConnector = @{ Label = 'Intune Certificate Connector'; Glyph = 0xE703; Category = 'IntuneConnector'; NotFound = 'Not on this computer'
        About = 'Connects Microsoft Intune to this PKI, so that managed devices get certificates (PKCS, or SCEP through NDES).'
        Scope = 'Only this computer is checked. The connector on other servers cannot be seen from here: its state is kept in Intune (Microsoft Graph), which this tool does not use.' }
}

function Get-MspkiGuiServiceSection {
    <#
    .SYNOPSIS
    The PKI Services page: one section per service kind (Web Enrollment, CES, CEP, NDES/SCEP, OCSP, Intune Certificate Connector) with its
    state, the instances found (state, confidence, host, evidence; each opens its object), the findings about it and what this run can see.
    #>
    [CmdletBinding()]
    param($Index, [AllowEmptyCollection()][object[]]$Rows = @())
    $out = New-Object System.Collections.ArrayList
    $quiet = @('Pass', 'Information', 'Skipped', 'NotApplicable')
    foreach ($kind in @($script:MspkiGuiServiceKind.Keys)) {
        $k = $script:MspkiGuiServiceKind[$kind]
        $svc = @()
        if ($null -ne $Index) { $svc = @($Index.Entities.Values | Where-Object { [string]$_.Type -eq 'Service' -and $null -ne $_.Properties -and [string]$_.Properties.Kind -eq $kind } | Sort-Object Name) }
        $ids = @($svc | ForEach-Object { [string]$_.Id })
        $mine = @($Rows | Where-Object { $null -ne $_ -and ([string]$_.Category -eq $k.Category -or @(@($_.Finding.EntityIds) | Where-Object { $ids -contains $_ }).Count -gt 0) } |
            Sort-Object @{ Expression = { -1 * [int]$_.StatusRank } }, Id)
        $inst = @(foreach ($s in $svc) {
            $id = [string]$s.Id
            $obs = @(); if ($Index.Obs.ContainsKey($id)) { $obs = @($Index.Obs[$id]) }
            $seen = @($obs | Where-Object { $_.Kind -eq 'Seen' })
            $conf = 'Referenced'
            if (@($seen | Where-Object { $_.Confidence -eq 'Confirmed' }).Count -gt 0) { $conf = 'Confirmed' } elseif ($seen.Count -gt 0) { $conf = 'Inferred' }
            elseif (@($obs | Where-Object { $_.Confidence -eq 'Inferred' }).Count -gt 0) { $conf = 'Inferred' }
            $state = $(if ($seen.Count -gt 0) { New-MspkiGuiPill -Text 'Answers' -Tone Good -Code 0xE73E } else { New-MspkiGuiPill -Text 'Named, not confirmed' -Tone Info -Code 0xE946 })
            $hostId = ''
            if ($Index.Out.ContainsKey($id)) { $hostId = @($Index.Out[$id] | Where-Object { $_.Type -eq 'hostedOn' } | ForEach-Object { [string]$_.To }) | Select-Object -First 1 }
            $hostName = $(if ($hostId) { Get-MspkiGuiEntityName -Index $Index -Id $hostId } elseif ($s.Properties.HostName) { [string]$s.Properties.HostName } else { '' })
            $fr = @($mine | Where-Object { @($_.Finding.EntityIds) -contains $id })
            $worst = $null; foreach ($f in $fr) { if ($null -eq $worst -or [int]$f.StatusRank -gt [int]$worst.StatusRank) { $worst = $f } }
            [pscustomobject][ordered]@{
                Id = $id; Tag = ('ent:{0}' -f $id); Name = (Get-MspkiGuiEntityName -Index $Index -Id $id); HostName = $hostName; HasHost = [bool]$hostName
                StatePill = $state; ConfidencePill = (Get-MspkiGuiStatusPill -Value $conf -Kind Confidence)
                WorstPill = $(if ($null -ne $worst -and $quiet -notcontains [string]$worst.Status) { $worst.StatusPill } else { New-MspkiGuiPill -Text '' -Tone Neutral })
                Evidence = ((@($obs | Where-Object { $_.Kind -ne 'ExpectedMissing' } | ForEach-Object {
                    $place = (@([string]$_.Source, [string]$_.Location) | Where-Object { $_ }) -join ' '
                    $(if ($_.Detail) { '{0}: {1}' -f $place, $_.Detail } else { $place }) }) | Select-Object -First 3) -join "`r`n")
            }
        })
        # Overall state of the kind: found / named only / looked for and not there / could not look / not looked for.
        $codes = @($mine | ForEach-Object { [string]$_.Finding.StatusCode })
        $cannot = @($mine | Where-Object { [string]$_.Status -eq 'Skipped' -or @('UNSUPPORTED', 'PERMISSION_DENIED', 'ERROR', 'TIMEOUT') -contains [string]$_.Finding.StatusCode }).Count -gt 0
        if (@($inst | Where-Object { $_.StatePill.Text -eq 'Answers' }).Count -gt 0) { $st = New-MspkiGuiPill -Text ('{0} found' -f $inst.Count) -Tone Good -Code 0xE73E; $why = '' }
        elseif ($inst.Count -gt 0) { $st = New-MspkiGuiPill -Text 'Named, not confirmed' -Tone Info -Code 0xE946; $why = 'Something names this service, but it did not answer this run.' }
        elseif (@($codes | Where-Object { $_ -in @('NOT_DISCOVERED', 'NOT_CONFIGURED') }).Count -gt 0) {
            $st = New-MspkiGuiPill -Text $k.NotFound -Tone Neutral -Code 0xE711
            $why = $(if ($cannot) { 'Not there where this run could look; some places could not be checked from here, so it may still exist elsewhere (see the findings).' } else { 'Looked for in this run; nothing was there.' })
        }
        elseif ($cannot) { $st = New-MspkiGuiPill -Text 'Cannot be checked from here' -Tone Admin -Code 0xE72E; $why = 'This run could not look (permission, unsupported or unreachable): not found is not the same as not present.' }
        else { $st = New-MspkiGuiPill -Text 'Not checked in this run' -Tone Neutral -Code 0xE7E8; $why = 'No check in this run covered it (for example with -SkipNetwork, or a run that was cancelled).' }
        $risk = @($mine | Where-Object { $quiet -notcontains [string]$_.Status -or [string]$_.Finding.StatusCode -eq 'CONFIG_RISK' })
        [void]$out.Add([pscustomobject][ordered]@{
            Kind = $kind; Label = $k.Label; Glyph = [string][char]$k.Glyph; About = $k.About; Scope = $k.Scope
            StatePill = $st; StateWhy = $why; HasStateWhy = [bool]$why
            Instances = [object[]]$inst; HasInstances = ($inst.Count -gt 0)
            InstancesTitle = $(if (@($inst | Where-Object { $_.StatePill.Text -eq 'Answers' }).Count -gt 0) { 'Found in this run' } else { 'Named in this run (not confirmed)' })
            Findings = [object[]]@($mine | Select-Object -First 5); FindingCount = $mine.Count; HasFindings = ($mine.Count -gt 0)
            MoreText = $(if ($mine.Count -gt 5) { 'and {0} more on the Findings page' -f ($mine.Count - 5) } else { '' })
            RiskCount = $risk.Count; Found = ($inst.Count -gt 0)
        })
    }
    return $out.ToArray()
}
