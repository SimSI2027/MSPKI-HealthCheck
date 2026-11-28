# Discovery map, pure side (GX6): the map model from the results graph, its link meanings and path health, the column order that keeps
# link crossings low (barycentre sweeps), the placement, the filtered and clustered views of the full-page map, keyboard neighbours and
# the zoom arithmetic. No WPF here: GuiMapView.ps1 and GuiMapPage.ps1 draw what these functions return. Loaded by GuiMission.ps1.
# Hot loops use hashtables and foreach (no pipelines), so that a 500-object estate lays out in well under 300 ms (tests\GuiMap.Tests.ps1).
# Note: [Array]::Sort($keys, $items) binds to a generic overload in Windows PowerShell 5.1 and sorts a COPY of the items; every call here
# passes [Array] casts so that the items are sorted in place.

$script:MspkiGuiToneWord = @{ Good = 'healthy'; Warn = 'warning'; Bad = 'failing'; Admin = 'could not be checked'; Neutral = 'no finding'; Info = 'information' }
$script:MspkiGuiToneRank = @{ Neutral = 0; Info = 0; Good = 1; Admin = 2; Warn = 3; Bad = 4 }
# Above this many nodes the full-page map collapses the addresses of one host into a counted group (GUI-EXPERIENCE section 7).
$script:MspkiGuiMapClusterThreshold = 120
$script:MspkiGuiMapZoomStops = @(0.25, 0.33, 0.5, 0.67, 0.75, 0.9, 1.0, 1.1, 1.25, 1.5, 1.75, 2.0, 2.5)

function Get-MspkiGuiNodeHealth {
    # Worst health-bearing status of an entity's findings: Information and NotApplicable say nothing about health.
    param([AllowEmptyCollection()][string[]]$Statuses = @())
    $best = ''; $rank = -2
    foreach ($s in $Statuses) {
        if ($s -in @('Information', 'NotApplicable', '')) { continue }
        $r = Get-MspkiGuiRank -Kind Status -Value $s
        if ($r -gt $rank) { $rank = $r; $best = $s }
    }
    switch ($best) {
        { $_ -in @('Critical', 'Fail') } { return 'Bad' }
        'Error' { return 'Admin' }
        'Warning' { return 'Warn' }
        'Pass' { return 'Good' }
    }
    return 'Neutral'
}

function Get-MspkiGuiShortHost {
    # The first label of a DNS name ("pki" for pki.alcyone-orbital.example); a name without dots stays as it is.
    param([string]$Name)
    if (-not $Name) { return '' }
    $i = $Name.IndexOf('.')
    if ($i -gt 0) { return $Name.Substring(0, $i) }
    return $Name
}

function Get-MspkiGuiEndpointLabel {
    # A short label for an endpoint URL: the last path part (decoded) for HTTP, the object's CN for LDAP.
    param([string]$Url)
    if (-not $Url) { return '' }
    $u = $Url
    try { $u = [System.Uri]::UnescapeDataString($Url) } catch { $u = $Url }
    if ($u -match '^(?i)ldap://[^/]*/CN=([^,]+)') { return $Matches[1] }
    $path = ($u -replace '^[a-zA-Z]+://[^/]*', '').TrimEnd('/')
    $leaf = ($path -split '/')[-1]
    if (-not $leaf) { $leaf = ($u -replace '^[a-zA-Z]+://', '') -replace '/.*$', '' }
    return $leaf
}

function Get-MspkiGuiWorseTone {
    # The more serious of two tones (Bad > Warn > Admin > Good > Neutral/Info).
    param([string]$A, [string]$B)
    $ra = $(if ($script:MspkiGuiToneRank.ContainsKey($A)) { $script:MspkiGuiToneRank[$A] } else { 0 })
    $rb = $(if ($script:MspkiGuiToneRank.ContainsKey($B)) { $script:MspkiGuiToneRank[$B] } else { 0 })
    if ($rb -gt $ra) { return $B }
    if ($A) { return $A }
    return $B
}

function Get-MspkiGuiMapLinkText {
    <#
    .SYNOPSIS
    What a map link means, in plain words, for its hover text (owner review item 6): who names the address and why, or who serves it,
    or who issued whom, followed by what this run saw on it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Link, [Parameter(Mandatory = $true)]$From, [Parameter(Mandatory = $true)]$To, [string]$IssuerName = '')
    $a = [string]$From.DisplayName; $b = [string]$To.DisplayName
    switch ([string]$Link.Kind) {
        'chain' { return ('{0} was issued by {1}: {1} signed the certificate of {0}.' -f $b, $a) }
        'unconfirmed' { return [string]$Link.Reason }
        'hostedOn' {
            $s = $(if ([string]$To.Kind -eq 'Directory') { 'Active Directory serves this LDAP address: clients read it from a domain controller.' } else { '{0} serves this address: the address names this host.' -f $b })
            if ($Link.Tone -eq 'Bad') { $s += ' The address failed when this run fetched it from here.' }
            elseif ($Link.Tone -eq 'Warn') { $s += ' The address gave a warning when this run fetched it from here.' }
            return $s
        }
    }
    $kind = [string]$To.KindText
    $cert = ([string]$Link.Via -eq 'certificate')
    $issuer = $(if ($IssuerName) { ' (' + $IssuerName + ')' } else { '' })
    $s = switch -Regex ($kind) {
        '^AIA$' { $(if ($cert) { '{0}''s certificate says to fetch its issuer''s certificate{1} from this address.' -f $a, $issuer } else { '{0} writes this address into the certificates it issues, so that clients can fetch the certificate of {0} from it.' -f $a }) }
        '^CDP$' { $(if ($cert) { '{0}''s certificate says to check revocation (the CRL) at this address.' -f $a } else { '{0} writes this CRL address into the certificates it issues, so that clients check revocation there.' -f $a }) }
        '^OCSP$' { $(if ($cert) { '{0}''s certificate names this OCSP responder: clients can ask it whether a certificate was revoked.' -f $a } else { '{0} writes this OCSP address into the certificates it issues.' -f $a }) }
        '^(CES|CEP|WebEnrollment|Enrollment)$' { 'Computers can request certificates from {0} through this {1} address.' -f $a, $kind }
        default { '{0} names this address.' -f $a }
    }
    switch ([string]$To.Tone) {
        'Bad' { $s += ' When this run checked it, it failed: this is where the chain breaks.' }
        'Warn' { $s += ' When this run checked it, it gave a warning.' }
        'Admin' { $s += ' This run could not check it.' }
        'Good' { $s += ' It answered correctly when this run checked it.' }
    }
    return $s
}

function Get-MspkiGuiMapModel {
    <#
    .SYNOPSIS
    The discovery map as columns of nodes and links, from the results graph: root CAs, issuing CAs, the addresses (AIA, CDP, OCSP,
    enrollment) the CAs publish, and the hosts or the directory that serve them. Each node carries its health tone; each link its kind,
    its path health (Tone Bad or Warn when the address it leads to failed) and its meaning in plain words. Returns $null without a graph.

    .DESCRIPTION
    A CA that is not a root and whose issuer this run could not confirm (its properties were not read, or its issuer's certificate was not
    found) is never left alone: it gets a dashed "issuer not confirmed" link to the only root CA found, or to an "Unknown issuer"
    placeholder when there is no single candidate. -Live leaves that inference out (during a run the CAs are still being read).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Index, [hashtable]$FindingStatus = @{}, [switch]$Live)
    if ($null -eq $Index) { return $null }
    $ent = $Index.Entities
    $byType = @{}
    $outKeys = [string[]]@($Index.Out.Keys)
    [Array]::Sort([Array]$outKeys, [System.Collections.IComparer][StringComparer]::Ordinal)
    foreach ($k in $outKeys) {
        foreach ($r in $Index.Out[$k]) {
            if ($null -eq $r) { continue }
            $t = [string]$r.Type
            if (-not $byType.ContainsKey($t)) { $byType[$t] = New-Object System.Collections.ArrayList }
            [void]$byType[$t].Add($r)
        }
    }
    $relOf = { param($t) if ($byType.ContainsKey($t)) { return $byType[$t] } else { return @() } }
    $entOf = @{}
    $entKeys = [string[]]@($ent.Keys)
    [Array]::Sort([Array]$entKeys, [System.Collections.IComparer][StringComparer]::Ordinal)
    foreach ($k in $entKeys) { $e = $ent[$k]; $t = [string]$e.Type; if (-not $entOf.ContainsKey($t)) { $entOf[$t] = New-Object System.Collections.ArrayList }; [void]$entOf[$t].Add($e) }
    $listOf = { param($t) if ($entOf.ContainsKey($t)) { return $entOf[$t] } else { return @() } }
    $nodes = [ordered]@{}
    $links = New-Object System.Collections.ArrayList
    $linkSeen = @{}
    $addLink = {
        param($from, $to, $kind, $via = '')
        $k = $from + '>' + $to
        if ($from -ne $to -and -not $linkSeen.ContainsKey($k)) { $linkSeen[$k] = $true; [void]$links.Add([pscustomobject]@{ From = $from; To = $to; Kind = $kind; Via = $via; Tone = ''; Text = ''; Reason = ''; Count = 1 }) }
    }
    $newNode = {
        param($id, $eid, $kind, $label, $sub, $glyph, $layer)
        $n = [pscustomobject]@{ Id = $id; EntityId = $eid; Kind = $kind; Label = $label; Sub = $sub; Glyph = $glyph; Members = (New-Object System.Collections.ArrayList); Layer = $layer; CAType = ''; Unread = $false; Owner = ''; Url = ''; KindText = ''; DisplayName = $label; HostId = ''
            Tone = 'Neutral'; FullName = $label; X = 0; Y = 0; AppearMs = 0; ProbeMs = 0; ResultMs = 0; LabelWidth = 0; Order = 0; Explain = ''; Context = $false; Match = $true; Count = 0; SearchText = ''; Expandable = $false
        }
        $nodes[$id] = $n
        return $n
    }

    # CA nodes: one per CA entity; a CA certificate without a CA entity (an offline root) gets one node per subject.
    $certToCa = @{}
    foreach ($r in (& $relOf 'certificateOf')) { $to = [string]$r.To; if ($ent.ContainsKey($to) -and [string]$ent[$to].Type -eq 'CA') { $certToCa[[string]$r.From] = $to } }
    $certNode = @{}
    foreach ($e in (& $listOf 'CACertificate')) {
        $id = [string]$e.Id
        if ($certToCa.ContainsKey($id)) { $certNode[$id] = $certToCa[$id]; continue }
        $subj = [string]$e.Name
        $nid = 'cagroup:' + $subj.ToLowerInvariant()
        $certNode[$id] = $nid
        if (-not $nodes.Contains($nid)) {
            $cn = $subj; if ($subj -match '(?i)CN=([^,]+)') { $cn = $Matches[1].Trim() }
            $n = & $newNode $nid $id 'CA' $cn 'Certificate only' ([string][char]0xEB95) 0
            $role = ''; if ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['Role']) { $role = [string]$e.Properties.Role }
            $n.CAType = $role
        }
        [void]$nodes[$nid].Members.Add($id)
    }
    $caEnts = @(& $listOf 'CA')
    $caSorted = [object[]]$caEnts
    $caNames = [string[]]@(foreach ($e in $caEnts) { [string]$e.Name })
    [Array]::Sort([Array]$caNames, [Array]$caSorted, [System.Collections.IComparer][StringComparer]::Ordinal)
    $certsOfCa = @{}
    foreach ($c in $certToCa.Keys) { $ca = $certToCa[$c]; if (-not $certsOfCa.ContainsKey($ca)) { $certsOfCa[$ca] = New-Object System.Collections.ArrayList }; [void]$certsOfCa[$ca].Add($c) }
    foreach ($e in $caSorted) {
        $id = [string]$e.Id
        $hostName = ''; if ($id -match '^ca:([^\\]+)\\') { $hostName = Get-MspkiGuiShortHost -Name $Matches[1] }
        $sub = $(if ($hostName) { 'CA on ' + $hostName } else { 'Enterprise CA' })
        $unread = ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['PropertiesRead'] -and -not $e.Properties.PropertiesRead)
        if ($unread) { $sub += ' ' + [string][char]0x00B7 + ' not read' }
        $caType = ''; if ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['CAType']) { $caType = [string]$e.Properties.CAType }
        $n = & $newNode $id $id 'CA' ([string]$e.Name) $sub ([string][char]0xEB95) 0
        $n.CAType = $caType; $n.Unread = $unread
        [void]$n.Members.Add($id)
        if ($certsOfCa.ContainsKey($id)) { foreach ($c in $certsOfCa[$id]) { [void]$n.Members.Add($c) } }
    }
    # Chain: issuedBy (certificate -> issuer certificate) gives parent CA node -> child CA node.
    $parent = @{}
    $isParent = @{}
    foreach ($r in (& $relOf 'issuedBy')) {
        $c = [string]$r.From; $p = [string]$r.To
        if ($certNode.ContainsKey($c) -and $certNode.ContainsKey($p) -and $certNode[$c] -ne $certNode[$p]) {
            $parent[$certNode[$c]] = $certNode[$p]
            $isParent[$certNode[$p]] = $true
            & $addLink $certNode[$p] $certNode[$c] 'chain'
        }
    }
    $caIds = @($nodes.Keys)
    $hasRoot = $false
    foreach ($id in $caIds) {
        $d = 0; $cur = $id; $guard = 0
        while ($parent.ContainsKey($cur) -and $guard -lt 8) { $cur = $parent[$cur]; $d++; $guard++ }
        $nodes[$id].Layer = [math]::Min($d, 2)
        if ($d -eq 0 -and [string]$nodes[$id].CAType -notmatch 'Subordinate') { if ($isParent.ContainsKey($id) -or [string]$nodes[$id].CAType -match 'Root') { $hasRoot = $true } }
    }
    # A CA whose chain is unknown (its properties could not be read) sits with the issuing CAs when it is not a root itself.
    $orphans = New-Object System.Collections.ArrayList
    foreach ($id in $caIds) {
        $n = $nodes[$id]
        if ($n.Layer -eq 0 -and -not $isParent.ContainsKey($id) -and ([string]$n.CAType -match 'Subordinate' -or ($hasRoot -and [string]$n.CAType -notmatch 'Root'))) { $n.Layer = 1; [void]$orphans.Add($n) }
    }
    # Owner review item 1: an orphan CA still shows its relationship, as a dashed "issuer not confirmed" link.
    if (-not $Live -and $orphans.Count -gt 0) {
        $roots = @(foreach ($id in $caIds) { $n = $nodes[$id]; if ($n.Layer -eq 0) { $n } })
        $why = { param($n) $(if ($n.Unread) { 'the properties of {0} could not be read, so this run could not see its certificate' -f $n.DisplayName } else { 'the certificate of {0}''s issuer was not found in this run' -f $n.DisplayName }) }
        foreach ($o in $orphans) {
            if ($roots.Count -eq 1) {
                & $addLink $roots[0].Id $o.Id 'unconfirmed'
                $links[$links.Count - 1].Reason = ('Issuer not confirmed: {0}. {1} is the only root CA this run found, so it is the most likely issuer. Read the CA''s properties (run as a user who may read them) to confirm it.' -f (& $why $o), $roots[0].DisplayName)
            }
            else {
                if (-not $nodes.Contains('unknown-issuer')) {
                    $u = & $newNode 'unknown-issuer' '' 'Unknown' 'Unknown issuer' 'Not confirmed' ([string][char]0xE9CE) 0
                }
                & $addLink 'unknown-issuer' $o.Id 'unconfirmed'
                $links[$links.Count - 1].Reason = ('Issuer not confirmed: {0}. This run found {1} root CAs, so it cannot say which one issued it.' -f (& $why $o), $(if ($roots.Count -eq 0) { 'no' } else { [string]$roots.Count }))
                $nodes['unknown-issuer'].Explain = 'This placeholder stands for the issuer of a CA whose chain this run could not read. Hover the dashed link for the reason, or open the CA itself.'
            }
        }
    }
    $caLayers = 0
    foreach ($id in $caIds) { if ($nodes[$id].Layer + 1 -gt $caLayers) { $caLayers = $nodes[$id].Layer + 1 } }
    $epLayer = $caLayers; $hostLayer = $caLayers + 1

    # Endpoints: referenced by a CA or one of its certificates.
    $svcKind = @{}
    foreach ($r in (& $relOf 'servedBy')) { $to = [string]$r.To; if ($ent.ContainsKey($to)) { $svcKind[[string]$r.From] = [string]$ent[$to].Properties.Kind } }
    foreach ($r in (& $relOf 'references')) {
        $ep = [string]$r.To
        if (-not $ent.ContainsKey($ep) -or [string]$ent[$ep].Type -ne 'Endpoint') { continue }
        $from = [string]$r.From
        $owner = $(if ($nodes.Contains($from) -and $nodes[$from].Kind -eq 'CA') { $from } elseif ($certNode.ContainsKey($from)) { $certNode[$from] } else { '' })
        if (-not $owner) { continue }
        if (-not $nodes.Contains($ep)) {
            $e = $ent[$ep]
            $url = [string]$e.Properties.Url; if (-not $url) { $url = [string]$e.Name }
            $kinds = @($e.Properties.Kinds | Where-Object { $_ })
            $kind = $(if ($svcKind.ContainsKey($ep) -and $svcKind[$ep]) { $svcKind[$ep] } elseif ($kinds.Count -gt 0) { [string]$kinds[0] } else { 'Address' })
            $scheme = $(if ($url -match '^([a-zA-Z]+):') { $Matches[1].ToUpperInvariant() } else { '' })
            $n = & $newNode $ep $ep 'Endpoint' (Get-MspkiGuiEndpointLabel -Url $url) ('{0}{1}{2}' -f $kind, $(if ($scheme) { ' over ' } else { '' }), $scheme) ([string][char]0xE774) $epLayer
            $n.Owner = $owner; $n.Url = $url; $n.KindText = $kind
            [void]$n.Members.Add($ep)
        }
        & $addLink $owner $ep 'publishes' $(if ($certNode.ContainsKey($from)) { 'certificate' } else { 'properties' })
    }
    # Hosts behind the endpoints; LDAP addresses without a host are served by the directory (the forest entity).
    $svcOnHost = @{}
    foreach ($r in (& $relOf 'hostedOn')) { $from = [string]$r.From; if ($ent.ContainsKey($from) -and [string]$ent[$from].Type -eq 'Service') { $svcOnHost[[string]$r.To] = [string]$ent[$from].Properties.Kind } }
    $forest = @(& $listOf 'Forest')
    $forestId = $(if ($forest.Count -gt 0) { [string]$forest[0].Id } else { '' })
    foreach ($ep in @($nodes.Keys)) {
        $en = $nodes[$ep]
        if ($en.Kind -ne 'Endpoint') { continue }
        $hosts = New-Object System.Collections.ArrayList
        if ($Index.Out.ContainsKey($ep)) { foreach ($r in $Index.Out[$ep]) { if ($null -ne $r -and [string]$r.Type -eq 'hostedOn') { [void]$hosts.Add([string]$r.To) } } }
        if ($hosts.Count -eq 0 -and [string]$en.Url -match '^(?i)ldap:///' -and $forestId) { [void]$hosts.Add($forestId) }
        foreach ($h in $hosts) {
            if (-not $ent.ContainsKey($h)) { continue }
            if (-not $nodes.Contains($h)) {
                $e = $ent[$h]
                $isForest = ([string]$e.Type -eq 'Forest')
                $sub = $(if ($isForest) { 'Active Directory' } elseif ($svcOnHost.ContainsKey($h) -and $svcOnHost[$h]) { $svcOnHost[$h] + ' host' } else { 'Web host' })
                $n = & $newNode $h $h $(if ($isForest) { 'Directory' } else { 'Host' }) $(if ($isForest) { [string]$e.Name } else { Get-MspkiGuiShortHost -Name ([string]$e.Name) }) $sub $(if ($isForest) { [string][char]0xE8D4 } else { [string][char]0xE968 }) $hostLayer
                [void]$n.Members.Add($h)
            }
            if (-not $en.HostId) { $en.HostId = $h }
            & $addLink $ep $h 'hostedOn'
        }
    }
    # Short labels: the first word every CA name shares (usually the organisation) is left out; the full name stays in the tooltip.
    $labels = @(foreach ($n in $nodes.Values) { if ($n.Kind -eq 'CA') { [string]$n.Label } })
    $prefix = ''
    if ($labels.Count -ge 2) {
        $w = ($labels[0] -split ' ')[0]
        $all = $true
        foreach ($l in $labels) { if (-not ($l.StartsWith($w + ' ') -and ($l -split ' ').Count -ge 3)) { $all = $false; break } }
        if ($w -and $all) { $prefix = $w + ' ' }
    }
    foreach ($n in $nodes.Values) {
        $st = New-Object System.Collections.Generic.List[string]
        foreach ($id in $n.Members) { if ($Index.Findings.ContainsKey($id)) { foreach ($fid in $Index.Findings[$id]) { $st.Add([string]$FindingStatus[[string]$fid]) } } }
        $tone = Get-MspkiGuiNodeHealth -Statuses $st.ToArray()
        # A CA whose properties this run could not read was not checked: say so instead of showing "no finding".
        if ($n.Unread -and $tone -in @('Neutral', 'Good')) { $tone = 'Admin' }
        $n.Tone = $tone
        if ($n.EntityId -and $ent.ContainsKey([string]$n.EntityId)) { $n.FullName = [string]$ent[[string]$n.EntityId].Name }
        if ($prefix -and $n.Kind -in @('CA', 'Endpoint') -and ([string]$n.Label).StartsWith($prefix)) { $n.Label = ([string]$n.Label).Substring($prefix.Length) }
    }
    # Two addresses with the same label and kind (the same file on two web hosts) get their host in the second line.
    $same = @{}
    foreach ($n in $nodes.Values) { if ($n.Kind -eq 'Endpoint') { $k = [string]$n.Label + '|' + [string]$n.Sub; if (-not $same.ContainsKey($k)) { $same[$k] = New-Object System.Collections.ArrayList }; [void]$same[$k].Add($n) } }
    foreach ($grp in $same.Values) {
        if ($grp.Count -lt 2) { continue }
        foreach ($n in $grp) { if ([string]$n.Url -match '^[a-zA-Z]+://([^/:]+)') { $n.Sub = '{0} {1} {2}' -f $n.Sub, [char]0x00B7, (Get-MspkiGuiShortHost -Name $Matches[1]) } }
    }
    # Path health (owner review item 5) and the meaning of every link (item 6).
    foreach ($l in $links) {
        $a = $nodes[$l.From]; $b = $nodes[$l.To]
        if ($l.Kind -eq 'publishes' -and $b.Tone -in @('Bad', 'Warn')) { $l.Tone = $b.Tone }
        elseif ($l.Kind -eq 'hostedOn' -and $a.Tone -in @('Bad', 'Warn') -and $b.Tone -in @('Bad', 'Warn')) { $l.Tone = $a.Tone }
        $issuer = ''
        if ($l.Kind -eq 'publishes' -and $parent.ContainsKey($l.From)) { $issuer = [string]$nodes[$parent[$l.From]].DisplayName }
        $l.Text = Get-MspkiGuiMapLinkText -Link $l -From $a -To $b -IssuerName $issuer
    }
    $layers = 0
    foreach ($n in $nodes.Values) { if ([int]$n.Layer + 1 -gt $layers) { $layers = [int]$n.Layer + 1 } }
    return [pscustomobject]@{ Nodes = @($nodes.Values); Links = @($links); Layers = $layers }
}

function Get-MspkiGuiMapNeighbourIndex {
    # id -> list of linked ids (both directions), and id -> node.
    param([Parameter(Mandatory = $true)]$Model)
    $nb = @{}; $byId = @{}
    foreach ($n in $Model.Nodes) { $byId[[string]$n.Id] = $n; $nb[[string]$n.Id] = New-Object System.Collections.ArrayList }
    foreach ($l in $Model.Links) {
        $f = [string]$l.From; $t = [string]$l.To
        if ($nb.ContainsKey($f) -and $nb.ContainsKey($t)) { [void]$nb[$f].Add($t); [void]$nb[$t].Add($f) }
    }
    return @{ Nb = $nb; ById = $byId }
}

function Get-MspkiGuiMapCrossing {
    <#
    .SYNOPSIS
    Counts link crossings between columns: two links that join the same pair of columns cross when their ends are in opposite order.
    -By Y uses the laid-out positions, -By Order the column order alone. Counted in O(k log n) per column pair (a Fenwick tree).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [ValidateSet('Y', 'Order')][string]$By = 'Y')
    $byLayer = @{}
    foreach ($n in $Model.Nodes) { $l = [int]$n.Layer; if (-not $byLayer.ContainsKey($l)) { $byLayer[$l] = New-Object System.Collections.ArrayList }; [void]$byLayer[$l].Add($n) }
    $rank = @{}
    foreach ($l in $byLayer.Keys) {
        $arr = $byLayer[$l].ToArray()
        $keys = [double[]]@(foreach ($n in $arr) { if ($By -eq 'Y') { [double]$n.Y + [double]$n.Order * 1e-6 } else { [double]$n.Order } })
        [Array]::Sort([Array]$keys, [Array]$arr)
        for ($i = 0; $i -lt $arr.Count; $i++) { $rank[[string]$arr[$i].Id] = $i }
    }
    $layerOf = @{}
    foreach ($n in $Model.Nodes) { $layerOf[[string]$n.Id] = [int]$n.Layer }
    $groups = @{}
    foreach ($lk in $Model.Links) {
        $f = [string]$lk.From; $t = [string]$lk.To
        if (-not $rank.ContainsKey($f) -or -not $rank.ContainsKey($t)) { continue }
        $la = $layerOf[$f]; $lb = $layerOf[$t]
        if ($la -eq $lb) { continue }
        if ($la -gt $lb) { $x = $f; $f = $t; $t = $x; $x = $la; $la = $lb; $lb = $x }
        $gk = '{0}|{1}' -f $la, $lb
        if (-not $groups.ContainsKey($gk)) { $groups[$gk] = New-Object System.Collections.ArrayList }
        [void]$groups[$gk].Add([long]$rank[$f] * 100000 + [long]$rank[$t])
    }
    $total = 0
    foreach ($g in $groups.Values) {
        $keys = [long[]]$g.ToArray()
        [Array]::Sort($keys)
        $size = 2
        foreach ($k in $keys) { $b = [int]($k % 100000) + 2; if ($b -gt $size) { $size = $b } }
        $tree = New-Object 'int[]' ($size + 1)
        $seen = 0
        foreach ($k in $keys) {
            $b = [int]($k % 100000) + 1
            # Earlier links (smaller start) with a larger end cross this one: seen so far minus those with an end <= b.
            $le = 0; $i = $b; while ($i -gt 0) { $le += $tree[$i]; $i -= ($i -band (-$i)) }
            $total += ($seen - $le)
            $i = $b; while ($i -le $size) { $tree[$i]++; $i += ($i -band (-$i)) }
            $seen++
        }
    }
    return $total
}

function Set-MspkiGuiMapOrder {
    <#
    .SYNOPSIS
    Orders the nodes inside each column so that few links cross (owner review item 2): a stable start order (CAs by name, addresses by
    their CA and host, hosts by their first address), then barycentre sweeps down and up the columns; the order with the fewest crossings
    wins. Sets each node's Order (0..n-1 inside its column) and returns the crossing counts before and after.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [int]$Sweeps = 4)
    $ix = Get-MspkiGuiMapNeighbourIndex -Model $Model
    $nb = $ix.Nb; $byId = $ix.ById
    $layers = [int]$Model.Layers
    $col = @{}
    foreach ($n in $Model.Nodes) { $l = [int]$n.Layer; if (-not $col.ContainsKey($l)) { $col[$l] = New-Object System.Collections.ArrayList }; [void]$col[$l].Add($n) }
    # Stable start order.
    $order = @{}
    $i = 0
    $cas = @(foreach ($n in $Model.Nodes) { if ($n.Kind -in @('CA', 'Unknown')) { $n } })
    $caKey = [string[]]@(foreach ($n in $cas) { '{0:00}|{1}|{2}' -f [int]$n.Layer, $(if ($n.Kind -eq 'Unknown') { '~' } else { [string]$n.Label }), [string]$n.Id })
    $caArr = [object[]]$cas
    [Array]::Sort([Array]$caKey, [Array]$caArr, [System.Collections.IComparer][StringComparer]::Ordinal)
    foreach ($n in $caArr) { $order[[string]$n.Id] = $i++ }
    $hostKey = @{}
    foreach ($n in $Model.Nodes) {
        if ($n.Kind -ne 'Endpoint' -and $n.Kind -ne 'Cluster') { continue }
        foreach ($t in $nb[[string]$n.Id]) { $h = $byId[$t]; if ($h.Kind -in @('Host', 'Directory')) { $hostKey[[string]$n.Id] = $(if ($h.Kind -eq 'Directory') { ' ' } else { [string]$h.Label }); break } }
    }
    $eps = @(foreach ($n in $Model.Nodes) { if ($n.Kind -in @('Endpoint', 'Cluster')) { $n } })
    $epKey = [string[]]@(foreach ($n in $eps) {
            $o = 99999; if ($n.Owner -and $order.ContainsKey([string]$n.Owner)) { $o = $order[[string]$n.Owner] }
            '{0:00000}|{1}|{2}|{3}|{4}' -f $o, $(if ($hostKey.ContainsKey([string]$n.Id)) { $hostKey[[string]$n.Id] } else { '~' }), [string]$n.KindText, [string]$n.Label, [string]$n.Id
        })
    $epArr = [object[]]$eps
    [Array]::Sort([Array]$epKey, [Array]$epArr, [System.Collections.IComparer][StringComparer]::Ordinal)
    foreach ($n in $epArr) { $order[[string]$n.Id] = $i++ }
    foreach ($n in $Model.Nodes) {
        if ($order.ContainsKey([string]$n.Id)) { continue }
        $m = [double]::MaxValue
        foreach ($t in $nb[[string]$n.Id]) { if ($order.ContainsKey($t) -and $order[$t] -lt $m) { $m = $order[$t] } }
        $order[[string]$n.Id] = $(if ($m -lt [double]::MaxValue) { 100000 + $m } else { 200000 + $i++ })
    }
    $ids = @{}
    $pos = @{}
    foreach ($l in $col.Keys) {
        $arr = $col[$l].ToArray()
        $keys = [double[]]@(foreach ($n in $arr) { [double]$order[[string]$n.Id] })
        [Array]::Sort([Array]$keys, [Array]$arr)
        $ids[$l] = [string[]]@(foreach ($n in $arr) { [string]$n.Id })
        $den = [math]::Max(1, $arr.Count - 1)
        for ($k = 0; $k -lt $arr.Count; $k++) { $pos[[string]$arr[$k].Id] = $k / $den }
    }
    $layerOf = @{}
    foreach ($n in $Model.Nodes) { $layerOf[[string]$n.Id] = [int]$n.Layer }
    $apply = { foreach ($l in $ids.Keys) { $a = $ids[$l]; for ($k = 0; $k -lt $a.Count; $k++) { $byId[$a[$k]].Order = $k } } }
    & $apply
    $before = Get-MspkiGuiMapCrossing -Model $Model -By Order
    $best = $before
    $bestIds = @{}; foreach ($l in $ids.Keys) { $bestIds[$l] = $ids[$l].Clone() }
    $layerList = @($ids.Keys | Sort-Object)
    for ($s = 0; $s -lt $Sweeps -and $best -gt 0; $s++) {
        foreach ($down in @($true, $false)) {
            $seq = $(if ($down) { $layerList } else { @($layerList | Sort-Object -Descending) })
            foreach ($l in $seq) {
                $a = $ids[$l]
                $n = $a.Count
                if ($n -lt 2) { continue }
                $keys = New-Object 'double[]' $n
                for ($k = 0; $k -lt $n; $k++) {
                    $ps = New-Object System.Collections.Generic.List[double]
                    foreach ($t in $nb[$a[$k]]) {
                        $tl = $layerOf[$t]
                        if (($down -and $tl -lt $l) -or (-not $down -and $tl -gt $l)) { $ps.Add($pos[$t]) }
                    }
                    # The median of the linked positions (not the mean): one far-away link does not drag a shared host past its neighbours.
                    $v = $pos[$a[$k]]
                    if ($ps.Count -gt 0) { $pa = $ps.ToArray(); [Array]::Sort($pa); $h = [int][math]::Floor($pa.Count / 2); $v = $(if ($pa.Count % 2 -eq 1) { $pa[$h] } else { ($pa[$h - 1] + $pa[$h]) / 2.0 }) }
                    $keys[$k] = $v + $k * 1e-7
                }
                $copy = [string[]]$a.Clone()
                [Array]::Sort([Array]$keys, [Array]$copy)
                $ids[$l] = $copy
                $den = [math]::Max(1, $n - 1)
                for ($k = 0; $k -lt $n; $k++) { $pos[$copy[$k]] = $k / $den }
            }
        }
        # Counted once per down-and-up sweep; the sweeps stop as soon as one brings no gain.
        & $apply
        $c = Get-MspkiGuiMapCrossing -Model $Model -By Order
        if ($c -lt $best) { $best = $c; foreach ($l in $ids.Keys) { $bestIds[$l] = $ids[$l].Clone() } }
        else { break }
    }
    $ids = $bestIds
    & $apply
    return [pscustomobject]@{ Before = $before; After = $best }
}

function Set-MspkiGuiColumnY {
    # Places one column's nodes (already in their order) as close as possible to their wanted Y while keeping the order and a minimum gap:
    # least squares under "y[i+1] >= y[i] + gap" (pool adjacent violators on y - i * gap), then moved inside [Top, Bottom].
    param([object[]]$Nodes, [double[]]$Want, [double]$Gap, [double]$Top, [double]$Bottom)
    $n = $Nodes.Count
    if ($n -eq 0) { return }
    $val = New-Object 'double[]' $n; $wt = New-Object 'int[]' $n; $len = New-Object 'int[]' $n
    $m = 0
    for ($i = 0; $i -lt $n; $i++) {
        $val[$m] = $Want[$i] - $i * $Gap; $wt[$m] = 1; $len[$m] = 1; $m++
        while ($m -gt 1 -and $val[$m - 2] -gt $val[$m - 1]) {
            $w = $wt[$m - 2] + $wt[$m - 1]
            $val[$m - 2] = ($val[$m - 2] * $wt[$m - 2] + $val[$m - 1] * $wt[$m - 1]) / $w
            $wt[$m - 2] = $w; $len[$m - 2] += $len[$m - 1]; $m--
        }
    }
    $k = 0
    for ($b = 0; $b -lt $m; $b++) { for ($j = 0; $j -lt $len[$b]; $j++) { $Nodes[$k].Y = $val[$b] + $k * $Gap; $k++ } }
    $shift = 0.0
    if ($Nodes[0].Y -lt $Top) { $shift = $Top - $Nodes[0].Y }
    if ($Nodes[$n - 1].Y + $shift -gt $Bottom) { $shift = $Bottom - $Nodes[$n - 1].Y }
    if ($Nodes[0].Y + $shift -lt $Top) { $shift = $Top - $Nodes[0].Y }
    foreach ($x in $Nodes) { $x.Y = [math]::Round($x.Y + $shift) }
}

function Set-MspkiGuiMapLayout {
    <#
    .SYNOPSIS
    Places the map nodes in columns (one per layer) and returns the height the canvas needs. The order inside each column comes from
    Set-MspkiGuiMapOrder (few crossings); the busiest column is spread evenly and every other column sits as close as it can to the
    median of its linked nodes, in that order, without overlap.

    .DESCRIPTION
    Overview (default): the columns share -Width; long labels are shortened evenly when it is narrow. -Natural (the full-page map): every
    column gets its labels' own width and the canvas is as wide as it needs (zoom and pan do the rest); the width is in the returned
    model's Width after the call ($Model.Width is set).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [double]$Width = 640, [double]$LabelWidth = 150, [switch]$Natural, [double]$Gap = 0)
    $layers = [int]$Model.Layers
    if ($layers -le 0) { return 0 }
    $ord = Set-MspkiGuiMapOrder -Model $Model
    $Model | Add-Member -NotePropertyName Crossings -NotePropertyValue $ord -Force
    $byLayer = @{}
    foreach ($n in $Model.Nodes) { $l = [int]$n.Layer; if (-not $byLayer.ContainsKey($l)) { $byLayer[$l] = New-Object System.Collections.ArrayList }; [void]$byLayer[$l].Add($n) }
    foreach ($l in @($byLayer.Keys)) {
        $arr = $byLayer[$l].ToArray()
        $keys = [int[]]@(foreach ($n in $arr) { [int]$n.Order })
        [Array]::Sort([Array]$keys, [Array]$arr)
        $byLayer[$l] = $arr
    }
    $maxN = 1
    foreach ($a in $byLayer.Values) { if ($a.Count -gt $maxN) { $maxN = $a.Count } }
    $gap = $(if ($Gap -gt 0) { $Gap } elseif ($maxN -le 6) { 44 } elseif ($maxN -le 10) { 38 } else { 32 })
    $top = 24.0
    $height = [math]::Max(200.0, $top * 2 + ($maxN - 1) * $gap)
    $left = 18.0
    # Column widths follow the longest label in each column (estimated at 6.6 px per character of 12 px Segoe UI, at most
    # -LabelWidth); spare width is shared between the columns, and when there is too little the labels are shortened evenly.
    $node = 20.0; $link = $(if ($Natural) { 52.0 } else { 28.0 })
    $want = @{}
    $sumWant = 0.0
    foreach ($l in 0..($layers - 1)) {
        $chars = 0
        if ($byLayer.ContainsKey($l)) { foreach ($n in $byLayer[$l]) { $c = [math]::Max(([string]$n.Label).Length, ([string]$n.Sub).Length); if ($c -gt $chars) { $chars = $c } } }
        $want[$l] = [math]::Min($LabelWidth, [math]::Max(48.0, $chars * 6.6 + 4))
        $sumWant += $want[$l]
    }
    $need = $left + ($layers * ($node + 4)) + (($layers - 1) * $link) + $sumWant
    $scale = 1.0; $extra = 0.0
    if ($Natural) { $Width = $need + 24 }
    elseif ($need -gt $Width) { $scale = [math]::Max(0.45, 1.0 - ($need - $Width) / [math]::Max(1.0, $sumWant)) }
    elseif ($layers -gt 1) { $extra = ($Width - $need) / ($layers - 1) }
    $colX = @{}
    $x = $left
    foreach ($l in 0..($layers - 1)) { $colX[$l] = $x; $x += $node + 4 + [math]::Floor($want[$l] * $scale) + $link + $extra }
    $nbIx = Get-MspkiGuiMapNeighbourIndex -Model $Model
    $nb = $nbIx.Nb; $byId = $nbIx.ById
    $placed = @{}
    $anchor = -1; $ac = -1
    foreach ($l in 0..($layers - 1)) { if ($byLayer.ContainsKey($l) -and $byLayer[$l].Count -gt $ac) { $ac = $byLayer[$l].Count; $anchor = $l } }
    $list = $byLayer[$anchor]
    $y0 = ($height - ($list.Count - 1) * $gap) / 2.0
    for ($k = 0; $k -lt $list.Count; $k++) { $list[$k].Y = [math]::Round($y0 + $k * $gap); $placed[[string]$list[$k].Id] = $true }
    $sequence = @()
    for ($l = $anchor + 1; $l -lt $layers; $l++) { $sequence += $l }
    for ($l = $anchor - 1; $l -ge 0; $l--) { $sequence += $l }
    foreach ($l in $sequence) {
        if (-not $byLayer.ContainsKey($l)) { continue }
        $arr = $byLayer[$l]
        $wantY = New-Object 'double[]' $arr.Count
        $prev = [double]::NaN
        for ($k = 0; $k -lt $arr.Count; $k++) {
            $ys = New-Object System.Collections.Generic.List[double]
            foreach ($t in $nb[[string]$arr[$k].Id]) { if ($placed.ContainsKey($t)) { $ys.Add([double]$byId[$t].Y) } }
            # The median of the linked positions: one far-away link (a root's own CRL) does not pull a shared host out of its group.
            if ($ys.Count -gt 0) {
                $ya = $ys.ToArray(); [Array]::Sort($ya)
                $wantY[$k] = $(if ($ya.Count % 2 -eq 1) { $ya[[int][math]::Floor($ya.Count / 2)] } else { ($ya[$ya.Count / 2 - 1] + $ya[$ya.Count / 2]) / 2.0 })
            }
            else { $wantY[$k] = $(if ([double]::IsNaN($prev)) { $height / 2.0 } else { $prev + $gap }) }
            $prev = $wantY[$k]
        }
        Set-MspkiGuiColumnY -Nodes $arr -Want $wantY -Gap $gap -Top $top -Bottom ($height - $top)
        foreach ($n in $arr) { $placed[[string]$n.Id] = $true }
    }
    foreach ($n in $Model.Nodes) {
        $l = [int]$n.Layer
        $n.X = [math]::Round($colX[$l])
        $n.LabelWidth = $(if ($Natural) { [math]::Floor($want[$l]) } elseif ($l -eq $layers - 1) { [math]::Floor([math]::Max(48.0, $Width - $colX[$l] - $node - 8)) } else { [math]::Floor($want[$l] * $scale + [math]::Max(0.0, $extra - 8)) })
    }
    $Model | Add-Member -NotePropertyName Width -NotePropertyValue $Width -Force
    $Model | Add-Member -NotePropertyName Height -NotePropertyValue $height -Force
    $Model | Add-Member -NotePropertyName Gap -NotePropertyValue $gap -Force
    return $height
}

function Set-MspkiGuiMapTimeline {
    <#
    .SYNOPSIS
    Sets when each node appears, is probed and shows its health during the build animation (ms), in discovery order:
    CAs layer by layer, then each published address (probed, then graded), each host just after its first address, CAs graded last.
    Returns the total length in ms.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model)
    $t = 0
    $sortY = { param($arr) $a = [object[]]$arr; $k = [double[]]@(foreach ($n in $a) { [double]$n.Y * 1000 + [double]$n.Layer }); [Array]::Sort([Array]$k, [Array]$a); return , $a }
    foreach ($l in 0..2) {
        $cas = & $sortY @(foreach ($n in $Model.Nodes) { if ($n.Kind -in @('CA', 'Unknown') -and [int]$n.Layer -eq $l) { $n } })
        $k = 0
        foreach ($n in $cas) { $n.AppearMs = $t + 60 * $k; $k++ }
        if ($cas.Count -gt 0) { $t += 300 + 60 * ($cas.Count - 1) }
    }
    $t += 100
    $eps = & $sortY @(foreach ($n in $Model.Nodes) { if ($n.Kind -in @('Endpoint', 'Cluster')) { $n } })
    # Long lists build faster, so the whole build stays about 3 to 5 seconds.
    $step = $(if ($eps.Count -le 16) { 110 } else { [math]::Max(12, [math]::Floor(1800 / $eps.Count)) })
    $k = 0
    $last = $t
    $epAt = @{}
    foreach ($n in $eps) { $n.AppearMs = $t + $step * $k; $n.ProbeMs = $n.AppearMs + 100; $n.ResultMs = $n.AppearMs + 1000; $last = $n.ResultMs; $epAt[[string]$n.Id] = $n.AppearMs; $k++ }
    $first = @{}
    foreach ($l in $Model.Links) { if ($epAt.ContainsKey([string]$l.From)) { $to = [string]$l.To; $v = $epAt[[string]$l.From]; if (-not $first.ContainsKey($to) -or $first[$to] -gt $v) { $first[$to] = $v } } }
    foreach ($n in $Model.Nodes) {
        if ($n.Kind -notin @('Host', 'Directory')) { continue }
        $n.AppearMs = $(if ($first.ContainsKey([string]$n.Id)) { $first[[string]$n.Id] + 250 } else { $last })
        $n.ResultMs = $n.AppearMs + 300
    }
    $k = 0
    $caAll = [object[]]@(foreach ($n in $Model.Nodes) { if ($n.Kind -in @('CA', 'Unknown')) { $n } })
    $ck = [double[]]@(foreach ($n in $caAll) { [double]$n.Layer * 100000 + [double]$n.Y })
    [Array]::Sort([Array]$ck, [Array]$caAll)
    foreach ($n in $caAll) { $n.ResultMs = [math]::Max($last, $t) + 150 + 60 * $k; $k++ }
    $max = 0
    foreach ($n in $Model.Nodes) { $v = [math]::Max([int]$n.ResultMs, [int]$n.AppearMs); if ($v -gt $max) { $max = $v } }
    return ($max + 300)
}

function Test-MspkiGuiMapNodeMatch {
    # True when every typed word is in the node's label, full name, second line, address or (for a group) one of its members.
    param([Parameter(Mandatory = $true)]$Node, [AllowEmptyString()][string]$Text)
    if (-not $Text -or -not $Text.Trim()) { return $true }
    $hay = ('{0} {1} {2} {3} {4}' -f $Node.Label, $Node.FullName, $Node.Sub, $Node.Url, $(if ($null -ne $Node.PSObject.Properties['SearchText']) { $Node.SearchText } else { '' })).ToLowerInvariant()
    foreach ($w in ($Text.Trim().ToLowerInvariant() -split '\s+')) { if ($w -and -not $hay.Contains($w)) { return $false } }
    return $true
}

function Get-MspkiGuiMapView {
    <#
    .SYNOPSIS
    The full-page map's view of a model: the focus on one CA, the status and type filters, "only problems", automatic groups of the
    addresses a host serves (above -Threshold nodes, expandable one by one) and the search marks. Returns a new model (the base model is
    never changed), with Total, Hidden, Groups and Matches counts, ready for Set-MspkiGuiMapLayout -Natural.

    .DESCRIPTION
    A node that does not pass a status filter but leads to one that does (its CA, the CA's issuer) stays on the map as Context, so a
    problem is never shown without the path to it. Search does not hide anything: non-matching nodes are dimmed by the window.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Model,
        [ValidateSet('All', 'Bad', 'Warn', 'Admin', 'Good', 'Neutral')][string]$Status = 'All',
        [ValidateSet('All', 'CA', 'Endpoint', 'Host')][string]$Type = 'All',
        [switch]$OnlyProblems,
        [string]$FocusId = '',
        [hashtable]$Expanded = @{},
        [int]$Threshold = $script:MspkiGuiMapClusterThreshold,
        [AllowEmptyString()][string]$Search = ''
    )
    $ix = Get-MspkiGuiMapNeighbourIndex -Model $Model
    $byId = $ix.ById
    $up = @{}; $down = @{}
    foreach ($n in $Model.Nodes) { $up[[string]$n.Id] = New-Object System.Collections.ArrayList; $down[[string]$n.Id] = New-Object System.Collections.ArrayList }
    foreach ($l in $Model.Links) { if ($byId.ContainsKey([string]$l.From) -and $byId.ContainsKey([string]$l.To)) { [void]$up[[string]$l.To].Add([string]$l.From); [void]$down[[string]$l.From].Add([string]$l.To) } }
    $keep = @{}
    foreach ($n in $Model.Nodes) { $keep[[string]$n.Id] = $true }
    # Focus on one CA: the CA, the CAs it issued, their addresses and hosts, and its own issuers (without their addresses).
    if ($FocusId -and $byId.ContainsKey($FocusId)) {
        $keep = @{}
        $stack = New-Object System.Collections.Stack
        $stack.Push($FocusId)
        while ($stack.Count -gt 0) { $c = [string]$stack.Pop(); if ($keep.ContainsKey($c)) { continue }; $keep[$c] = $true; foreach ($d in $down[$c]) { $stack.Push($d) } }
        $c = $FocusId; $guard = 0
        while ($guard -lt 8) { $p = @(foreach ($u in $up[$c]) { if ($byId[$u].Kind -in @('CA', 'Unknown')) { $u } }); if ($p.Count -eq 0) { break }; $c = $p[0]; $keep[$c] = $true; $guard++ }
    }
    $kindOk = {
        param($n)
        switch ($Type) { 'CA' { return ($n.Kind -in @('CA', 'Unknown')) } 'Endpoint' { return ($n.Kind -eq 'Endpoint') } 'Host' { return ($n.Kind -in @('Host', 'Directory')) } }
        return $true
    }
    $statusOk = {
        param($n)
        if ($OnlyProblems -and $n.Tone -notin @('Bad', 'Warn', 'Admin')) { return $false }
        if ($Status -ne 'All' -and [string]$n.Tone -ne $Status) { return $false }
        return $true
    }
    $filtered = ($Status -ne 'All' -or $OnlyProblems -or $Type -ne 'All')
    $show = @{}; $context = @{}
    foreach ($n in $Model.Nodes) {
        $id = [string]$n.Id
        if (-not $keep.ContainsKey($id)) { continue }
        if ((& $kindOk $n) -and (& $statusOk $n)) { $show[$id] = $true }
    }
    # The path to every shown problem stays as context (a host's addresses, an address's CA, the CA's issuers); not for a plain type filter.
    if ($Status -ne 'All' -or $OnlyProblems) {
        foreach ($id in @($show.Keys)) {
            $stack = New-Object System.Collections.Stack
            foreach ($u in $up[$id]) { $stack.Push($u) }
            while ($stack.Count -gt 0) {
                $c = [string]$stack.Pop()
                if ($show.ContainsKey($c) -or $context.ContainsKey($c) -or -not $keep.ContainsKey($c)) { continue }
                $context[$c] = $true
                foreach ($u in $up[$c]) { $stack.Push($u) }
            }
        }
    }
    $copy = @{}
    $nodes = New-Object System.Collections.ArrayList
    foreach ($n in $Model.Nodes) {
        $id = [string]$n.Id
        if (-not ($show.ContainsKey($id) -or $context.ContainsKey($id))) { continue }
        $c = $n.PSObject.Copy()
        $c.Context = $context.ContainsKey($id)
        $copy[$id] = $c
        [void]$nodes.Add($c)
    }
    $links = New-Object System.Collections.ArrayList
    foreach ($l in $Model.Links) { if ($copy.ContainsKey([string]$l.From) -and $copy.ContainsKey([string]$l.To)) { [void]$links.Add($l.PSObject.Copy()) } }
    # Groups: above the threshold, the addresses one host serves become one counted node ("14 addresses on pki"), unless expanded.
    $groups = 0
    if ($nodes.Count -gt $Threshold) {
        $byHost = @{}
        foreach ($c in $nodes) { if ($c.Kind -eq 'Endpoint' -and $c.HostId -and $copy.ContainsKey([string]$c.HostId) -and -not $Expanded.ContainsKey([string]$c.HostId)) { $h = [string]$c.HostId; if (-not $byHost.ContainsKey($h)) { $byHost[$h] = New-Object System.Collections.ArrayList }; [void]$byHost[$h].Add($c) } }
        $hostIds = [string[]]@($byHost.Keys); [Array]::Sort([Array]$hostIds, [System.Collections.IComparer][StringComparer]::Ordinal)
        $gone = @{}
        foreach ($h in $hostIds) {
            $members = $byHost[$h]
            if ($members.Count -lt 3) { continue }
            $hn = $copy[$h]
            $gid = 'cluster:' + $h
            $tone = 'Neutral'; $sb = New-Object System.Text.StringBuilder
            $kinds = @{}
            foreach ($m in $members) { $tone = Get-MspkiGuiWorseTone -A $tone -B ([string]$m.Tone); $gone[[string]$m.Id] = $gid; [void]$sb.Append(' ').Append($m.Label).Append(' ').Append($m.Url); $kinds[[string]$m.KindText] = $true }
            $kindText = $(if ($kinds.Count -eq 1) { @($kinds.Keys)[0] + ' ' } else { '' })
            $word = $(if ([string]$hn.Kind -eq 'Directory') { 'LDAP' } else { 'web' })
            $g = [pscustomobject]@{
                Id = $gid; EntityId = ''; Kind = 'Cluster'; Label = ('{0} {1}{2} addresses' -f $members.Count, $kindText, $word); Sub = ('on {0} {1} select to expand' -f $hn.Label, [char]0x00B7); Glyph = [string][char]0xE8B7
                Members = (New-Object System.Collections.ArrayList); Layer = [int]$members[0].Layer; CAType = ''; Unread = $false; Owner = [string]$members[0].Owner; Url = ''; KindText = 'Group'; DisplayName = ('{0} addresses on {1}' -f $members.Count, $hn.Label); HostId = $h
                Tone = $tone; FullName = ('{0} addresses served by {1}' -f $members.Count, $hn.FullName); X = 0; Y = 0; AppearMs = 0; ProbeMs = 0; ResultMs = 0; LabelWidth = 0; Order = 0
                Context = $false; Match = $true; Count = $members.Count; SearchText = $sb.ToString(); Expandable = $true
            }
            foreach ($m in $members) { [void]$g.Members.Add([string]$m.Id) }
            $copy[$gid] = $g
            [void]$nodes.Add($g)
            $groups++
        }
        if ($groups -gt 0) {
            $nodes = [System.Collections.ArrayList]@(foreach ($c in $nodes) { if (-not $gone.ContainsKey([string]$c.Id)) { $c } })
            $merged = @{}
            $newLinks = New-Object System.Collections.ArrayList
            foreach ($l in $links) {
                $f = [string]$l.From; $t = [string]$l.To
                if ($gone.ContainsKey($f)) { $f = $gone[$f] }
                if ($gone.ContainsKey($t)) { $t = $gone[$t] }
                if ($f -eq [string]$l.From -and $t -eq [string]$l.To) { [void]$newLinks.Add($l); continue }
                $k = $f + '>' + $t
                if ($merged.ContainsKey($k)) { $merged[$k].Tone = Get-MspkiGuiWorseTone -A ([string]$merged[$k].Tone) -B ([string]$l.Tone); $merged[$k].Count++; continue }
                $nl = [pscustomobject]@{ From = $f; To = $t; Kind = $l.Kind; Via = $l.Via; Tone = [string]$l.Tone; Text = ''; Reason = ''; Count = 1 }
                $merged[$k] = $nl
                [void]$newLinks.Add($nl)
            }
            foreach ($nl in $merged.Values) {
                $a = $copy[[string]$nl.From]; $b = $copy[[string]$nl.To]
                $nl.Text = $(if ($nl.Kind -eq 'hostedOn') { '{0} serves these {1} addresses.' -f $b.DisplayName, $a.Count } else { '{0} names {1} of these addresses in its certificates or properties.' -f $a.DisplayName, $nl.Count })
                if ($nl.Tone -eq 'Bad') { $nl.Text += ' At least one failed when this run checked it.' } elseif ($nl.Tone -eq 'Warn') { $nl.Text += ' At least one gave a warning.' }
            }
            $links = $newLinks
        }
    }
    # Columns that ended up empty are closed up.
    $used = @{}
    foreach ($c in $nodes) { $used[[int]$c.Layer] = $true }
    $map = @{}; $k = 0
    for ($l = 0; $l -lt [int]$Model.Layers; $l++) { if ($used.ContainsKey($l)) { $map[$l] = $k; $k++ } }
    foreach ($c in $nodes) { $c.Layer = $map[[int]$c.Layer] }
    $hits = 0
    foreach ($c in $nodes) { $c.Match = Test-MspkiGuiMapNodeMatch -Node $c -Text $Search; if ($Search -and $c.Match) { $hits++ } }
    return [pscustomobject]@{
        Nodes = @($nodes); Links = @($links); Layers = $k
        Total = @($Model.Nodes).Count; Shown = $nodes.Count; Hidden = (@($Model.Nodes).Count - $nodes.Count); Groups = $groups; Matches = $hits; Filtered = ($filtered -or [bool]$FocusId)
    }
}

function Find-MspkiGuiMapNeighbor {
    <#
    .SYNOPSIS
    Keyboard navigation on the map: the node above or below in the same column, or in the next column to the left or right (a linked
    node when there is one, otherwise the nearest by height); Home and End go to the first and last node of the column. Without a current
    node, the first node of the first column. Returns the node id, or the current id when there is nowhere to go.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [AllowEmptyString()][string]$Id, [ValidateSet('Up', 'Down', 'Left', 'Right', 'Home', 'End')][string]$Direction)
    $nodes = @($Model.Nodes)
    if ($nodes.Count -eq 0) { return '' }
    $byId = @{}; foreach ($n in $nodes) { $byId[[string]$n.Id] = $n }
    $colOf = { param($l) $a = [object[]]@(foreach ($n in $nodes) { if ([int]$n.Layer -eq $l) { $n } }); $k = [double[]]@(foreach ($n in $a) { [double]$n.Y }); [Array]::Sort([Array]$k, [Array]$a); return , $a }
    if (-not $Id -or -not $byId.ContainsKey($Id)) {
        for ($l = 0; $l -lt [int]$Model.Layers; $l++) { $c = & $colOf $l; if ($c.Count -gt 0) { return [string]$c[0].Id } }
        return [string]$nodes[0].Id
    }
    $cur = $byId[$Id]
    $col = & $colOf ([int]$cur.Layer)
    $i = [array]::IndexOf($col, $cur)
    switch ($Direction) {
        'Up' { if ($i -gt 0) { return [string]$col[$i - 1].Id }; return $Id }
        'Down' { if ($i -lt $col.Count - 1) { return [string]$col[$i + 1].Id }; return $Id }
        'Home' { return [string]$col[0].Id }
        'End' { return [string]$col[$col.Count - 1].Id }
    }
    $step = $(if ($Direction -eq 'Left') { -1 } else { 1 })
    for ($l = [int]$cur.Layer + $step; $l -ge 0 -and $l -lt [int]$Model.Layers; $l += $step) {
        $c = & $colOf $l
        if ($c.Count -eq 0) { continue }
        $linked = @{}
        foreach ($lk in $Model.Links) { if ([string]$lk.From -eq $Id) { $linked[[string]$lk.To] = $true } elseif ([string]$lk.To -eq $Id) { $linked[[string]$lk.From] = $true } }
        $best = $null; $bd = [double]::MaxValue
        foreach ($pass in 1, 2) {
            foreach ($n in $c) {
                if ($pass -eq 1 -and -not $linked.ContainsKey([string]$n.Id)) { continue }
                $d = [math]::Abs([double]$n.Y - [double]$cur.Y)
                if ($d -lt $bd) { $bd = $d; $best = $n }
            }
            if ($null -ne $best) { break }
        }
        return [string]$best.Id
    }
    return $Id
}

function Get-MspkiGuiMapFit {
    <#
    .SYNOPSIS
    The zoom and offset that fit a map of -ContentWidth x -ContentHeight into a view (with a margin), never above 100 % so that a small
    estate is not blown up, and never below the smallest zoom stop.
    #>
    [CmdletBinding()]
    param([double]$ContentWidth, [double]$ContentHeight, [double]$ViewWidth, [double]$ViewHeight, [double]$Margin = 16)
    if ($ContentWidth -le 0 -or $ContentHeight -le 0 -or $ViewWidth -le 0 -or $ViewHeight -le 0) { return [pscustomobject]@{ Scale = 1.0; X = 0.0; Y = 0.0 } }
    $s = [math]::Min(($ViewWidth - 2 * $Margin) / $ContentWidth, ($ViewHeight - 2 * $Margin) / $ContentHeight)
    $s = [math]::Max($script:MspkiGuiMapZoomStops[0], [math]::Min(1.0, $s))
    return [pscustomobject]@{ Scale = $s; X = [math]::Round(($ViewWidth - $ContentWidth * $s) / 2.0); Y = [math]::Round([math]::Max($Margin, ($ViewHeight - $ContentHeight * $s) / 2.0)) }
}

function Step-MspkiGuiMapZoom {
    # The next zoom stop in (or out) from the current zoom.
    param([double]$Scale, [ValidateSet('In', 'Out')][string]$Direction)
    $stops = $script:MspkiGuiMapZoomStops
    if ($Direction -eq 'In') { foreach ($s in $stops) { if ($s -gt $Scale + 0.001) { return $s } }; return $stops[-1] }
    for ($i = $stops.Count - 1; $i -ge 0; $i--) { if ($stops[$i] -lt $Scale - 0.001) { return $stops[$i] } }
    return $stops[0]
}

function Get-MspkiGuiMapZoomAt {
    <#
    .SYNOPSIS
    New offset for a zoom change that keeps the map point under (-PointX, -PointY) of the view where it is (zoom toward the mouse).
    #>
    [CmdletBinding()]
    param([double]$Scale, [double]$NewScale, [double]$OffsetX, [double]$OffsetY, [double]$PointX, [double]$PointY)
    $r = $NewScale / [math]::Max(0.0001, $Scale)
    return [pscustomobject]@{ X = $PointX - ($PointX - $OffsetX) * $r; Y = $PointY - ($PointY - $OffsetY) * $r }
}

function Get-MspkiGuiMapWhereText {
    # "Where this exists" for a node's hover card: up to four places the object was seen, named or expected and missing.
    param([Parameter(Mandatory = $true)]$Index, [AllowEmptyString()][string]$EntityId)
    if (-not $EntityId -or -not $Index.Obs.ContainsKey($EntityId)) { return '' }
    $rows = New-Object System.Collections.Generic.List[string]
    $obs = @($Index.Obs[$EntityId])
    foreach ($o in $obs) {
        if ($rows.Count -ge 4) { break }
        $k = switch ([string]$o.Kind) { 'Seen' { 'Seen in' } 'Referenced' { 'Named in' } default { 'Missing from' } }
        $loc = [string]$o.Location
        if ($loc.Length -gt 70) { $loc = $loc.Substring(0, 67) + '...' }
        $rows.Add(('{0} {1}: {2}' -f $k, [string]$o.Source, $loc))
    }
    if ($rows.Count -eq 0) { return '' }
    $t = 'Where this exists' + [Environment]::NewLine + ($rows -join [Environment]::NewLine)
    if ($obs.Count -gt 4) { $t += [Environment]::NewLine + ('and {0} more (open it for every place)' -f ($obs.Count - 4)) }
    return $t
}

function Invoke-MspkiGuiMapJob {
    <#
    .SYNOPSIS
    One map computation, the same in the window's background worker and inline: builds the base model once per results generation
    (kept in -Cache), then the view (filters, focus, groups, search) and its layout: -Request.Kind Page = natural width for zoom and pan,
    Overview = fitted to -Request.Width, with the build timeline. Returns the laid-out view, the base model and the time it took.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Request, [AllowNull()]$Index, [hashtable]$Status = @{}, [Parameter(Mandatory = $true)][hashtable]$Cache)
    # The Timeline page's rows (GX7) are computed by the same worker (GuiLifecycle.ps1).
    if ($Request.Kind -eq 'Timeline') { return (Invoke-MspkiGuiTimelineJob -Request $Request -Index $Index -Status $Status -Cache $Cache) }
    # The History page (GX8): reading earlier runs needs the module's JSON reader; the worker imports it the first time.
    if ($Request.Kind -in @('History', 'HistoryCompare')) {
        if (-not (Get-Command -Name ConvertFrom-MspkiResultsDocument -ErrorAction SilentlyContinue) -and $global:MspkiModulePath) { Import-Module -Name $global:MspkiModulePath -ErrorAction Stop }
        return (Invoke-MspkiGuiHistoryJob -Request $Request -Cache $Cache)
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $Cache.ContainsKey('Gen') -or $Cache.Gen -ne $Request.Gen) {
        $Cache.Base = $null
        if ($null -ne $Index) { $Cache.Base = Get-MspkiGuiMapModel -Index $Index -FindingStatus $Status }
        $Cache.Gen = $Request.Gen
        if ($null -ne $Cache.Base -and $null -ne $Index) { foreach ($n in $Cache.Base.Nodes) { $n | Add-Member -NotePropertyName WhereText -NotePropertyValue (Get-MspkiGuiMapWhereText -Index $Index -EntityId ([string]$n.EntityId)) -Force } }
    }
    $modelMs = $sw.ElapsedMilliseconds
    $b = $Cache.Base
    if ($null -eq $b -or @($b.Nodes).Count -eq 0) { return [pscustomobject]@{ Kind = $Request.Kind; Gen = $Request.Gen; Empty = $true; View = $null; Base = $b; ModelMs = $modelMs; LayoutMs = 0 } }
    $o = $(if ($Request.ContainsKey('Options') -and $null -ne $Request.Options) { $Request.Options } else { @{} })
    $p = @{ Model = $b }
    foreach ($k in 'Status', 'Type', 'FocusId', 'Expanded', 'Threshold', 'Search') { if ($o.ContainsKey($k) -and $null -ne $o[$k]) { $p[$k] = $o[$k] } }
    if ($o.ContainsKey('OnlyProblems') -and $o.OnlyProblems) { $p.OnlyProblems = $true }
    $sw.Restart()
    $v = Get-MspkiGuiMapView @p
    if (@($v.Nodes).Count -gt 0) {
        if ($Request.Kind -eq 'Page') { [void](Set-MspkiGuiMapLayout -Model $v -Natural -LabelWidth 200 -Gap 46) }
        else { [void](Set-MspkiGuiMapLayout -Model $v -Width ([double]$Request.Width) -LabelWidth 190) }
        $v | Add-Member -NotePropertyName TotalMs -NotePropertyValue (Set-MspkiGuiMapTimeline -Model $v) -Force
    }
    return [pscustomobject]@{ Kind = $Request.Kind; Gen = $Request.Gen; Empty = $false; View = $v; Base = $b; ModelMs = $modelMs; LayoutMs = $sw.ElapsedMilliseconds }
}
