# Report model: ranks, summaries and the Discovery Map tree (forest > CAs > certificates > endpoints /
# templates / CES). Pure functions over the run data, so they work on live results and on results.json alike.

$script:MspkiStatusRank = @{ Critical = 7; Fail = 6; Error = 5; Warning = 4; Skipped = 3; Information = 2; Pass = 1; NotApplicable = 0 }
$script:MspkiConfidenceRank = @{ Confirmed = 3; Referenced = 2; Inferred = 1; Unknown = 0 }

function Get-MspkiStatusRank {
    [CmdletBinding()]
    param([string]$Status)
    if ($script:MspkiStatusRank.ContainsKey($Status)) { return [int]$script:MspkiStatusRank[$Status] }
    return -1
}

function Get-MspkiWorstStatus {
    <#
    .SYNOPSIS
    The most serious status of a set of findings ('' when there are none).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $best = ''; $rank = -2
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $r = Get-MspkiStatusRank $f.Status
        if ($r -gt $rank) { $rank = $r; $best = $f.Status }
    }
    return $best
}

function Get-MspkiBestConfidence {
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @(), [string]$Default = 'Unknown')
    $best = $Default; $rank = -1
    if ($script:MspkiConfidenceRank.ContainsKey($Default)) { $rank = $script:MspkiConfidenceRank[$Default] }
    foreach ($f in @($Findings)) {
        if ($null -eq $f -or -not $script:MspkiConfidenceRank.ContainsKey([string]$f.Confidence)) { continue }
        if ($script:MspkiConfidenceRank[$f.Confidence] -gt $rank) { $rank = $script:MspkiConfidenceRank[$f.Confidence]; $best = $f.Confidence }
    }
    return $best
}

function New-MspkiMapNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$Label,
        [string[]]$Detail = @(),
        [string[]]$Sources = @(),
        [string]$Confidence = '',
        [AllowEmptyCollection()][object[]]$Findings = @()
    )
    $own = @($Findings | Where-Object { $null -ne $_ })
    $conf = $Confidence
    if ($Confidence) { $conf = Get-MspkiBestConfidence -Findings $own -Default $Confidence }
    return [pscustomobject][ordered]@{
        Type       = $Type
        Label      = $Label
        Detail     = [string[]]@($Detail | Where-Object { $_ })
        Sources    = [string[]]@($Sources | Where-Object { $_ } | Select-Object -Unique)
        Confidence = $conf
        Status     = (Get-MspkiWorstStatus -Findings $own)
        FindingIds = [string[]]@($own | ForEach-Object { $_.Id })
        Children   = (New-Object System.Collections.ArrayList)
        WorstBelow = ''
    }
}

function Set-MspkiMapRollup {
    <#
    .SYNOPSIS
    Fills WorstBelow (the most serious status among all descendants) and returns the node's worst status overall.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Node)
    $worst = $Node.Status
    $below = ''
    foreach ($c in $Node.Children) {
        $w = Set-MspkiMapRollup -Node $c
        if ((Get-MspkiStatusRank $w) -gt (Get-MspkiStatusRank $below)) { $below = $w }
    }
    $Node.WorstBelow = $below
    if ((Get-MspkiStatusRank $below) -gt (Get-MspkiStatusRank $worst)) { $worst = $below }
    return $worst
}

function Get-MspkiDiscoveryTree {
    <#
    .SYNOPSIS
    Builds the Discovery Map: forest > CAs > CA certificates > AIA/CDP/OCSP links, plus published templates,
    CES endpoints, the CA's own CRLs and links that belong to no certificate.

    .DESCRIPTION
    Each node shows its confidence and sources and the findings that belong to it. A link referenced by several
    certificates appears once, under the first of them; its sources list all of them.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Inventory,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowNull()]$RunInfo = $null
    )
    $all = @($Findings | Where-Object { $null -ne $_ })
    $inv = $Inventory
    $ctx = $null
    if ($null -ne $inv) { $ctx = $inv.AdContext }
    $forestName = ''
    if ($null -ne $ctx -and $ctx.Forest) { $forestName = [string]$ctx.Forest }
    elseif ($null -ne $RunInfo -and $RunInfo.Forest) { $forestName = [string]$RunInfo.Forest }
    if (-not $forestName) { $forestName = '(forest not discovered)' }

    $placed = @{}     # finding id -> $true
    $take = {
        param([object[]]$Set)
        foreach ($f in @($Set)) { $placed[$f.Id] = $true }
        return , @($Set)
    }

    # --- root
    $adRoles = @('Forest', 'Domain', 'DomainController', 'Site', 'Trust', 'Computer')
    $rootFindings = @($all | Where-Object { $_.Category -eq 'Run' -or $adRoles -contains $_.Role })
    $detail = @()
    if ($null -ne $ctx) {
        $detail += ('Domain: {0}; domain controller: {1}; site: {2}' -f $ctx.Domain, $ctx.DomainController, $ctx.Site)
        if ($ctx.ForestMode) { $detail += ('Forest functional level: {0}' -f $ctx.ForestMode) }
        $detail += ('Domains in the forest: {0}' -f (@($ctx.ForestDomains) -join ', '))
        $trusts = @($ctx.Trusts)
        if ($trusts.Count -gt 0) { $detail += ('Trusts: {0}' -f (($trusts | ForEach-Object { '{0} ({1}, {2})' -f $_.TargetName, $_.TrustType, $_.TrustDirection }) -join '; ')) }
    }
    $rootSources = @('AD:RootDSE', 'AD:Forest')
    $root = New-MspkiMapNode -Type 'Forest' -Label ('Forest {0}' -f $forestName) -Detail $detail -Sources $rootSources `
        -Confidence 'Confirmed' -Findings (& $take $rootFindings)

    # --- PKI containers
    $containers = @()
    if ($null -ne $inv) { $containers = @($inv.Containers) }
    if ($containers.Count -gt 0) {
        $cn = New-MspkiMapNode -Type 'Group' -Label ('Public Key Services containers ({0})' -f $containers.Count) -Sources @('AD:PublicKeyServices')
        foreach ($c in $containers) {
            $cf = @($all | Where-Object { $_.Category -eq 'ADContainer' -and $_.Target -eq $c.Name })
            $d = @($c.DistinguishedName)
            if ($null -ne $c.ChildCount) { $d += ('Objects: {0}' -f $c.ChildCount) }
            $n = New-MspkiMapNode -Type 'Container' -Label $c.Name -Detail $d -Sources @(@($cf | ForEach-Object { $_.Sources }) + @('AD:PublicKeyServices')) `
                -Confidence 'Referenced' -Findings (& $take $cf)
            [void]$cn.Children.Add($n)
        }
        [void]$root.Children.Add($cn)
    }

    # --- leads
    $leads = @()
    if ($null -ne $inv -and $null -ne $inv.Leads) { $leads = @($inv.Leads) }
    $leadPlaced = @{}
    $newLeadNode = {
        param($Lead)
        $variants = @($Lead.Variants)
        $lf = @($all | Where-Object { $e = [string]$_.Endpoint; $e -and ($variants | Where-Object { $_ -ieq $e }) })
        $d = @(('Host: {0}; scope: {1}; found at depth {2}' -f $(if ($Lead.Host) { $Lead.Host } else { '(serverless)' }), $Lead.Scope, $Lead.Depth))
        if ($variants.Count -gt 1) { $d += ('URL variants: {0}' -f ($variants -join ' ; ')) }
        foreach ($a in @($Lead.Aliases)) { if ($a) { $d += ('Also referenced as: {0}' -f $a) } }
        foreach ($o in @($Lead.Origins)) { $d += ('Found in: {0}' -f $o) }
        if (@($Lead.RelatedCAs).Count -gt 0) { $d += ('Related CA: {0}' -f (@($Lead.RelatedCAs) -join ', ')) }
        $kind = [string]$Lead.Kind
        if ($kind -eq 'FreshestCRL') { $kind = 'Delta CRL (Freshest CRL)' }
        return (New-MspkiMapNode -Type 'Endpoint' -Label ('{0}: {1}' -f $kind, $Lead.Url) -Detail $d -Sources @($Lead.Sources) `
            -Confidence $Lead.Confidence -Findings (& $take $lf))
    }
    $leadsForCert = { param([string]$Tp)
        @($leads | Where-Object { -not $leadPlaced.ContainsKey($_.Id) -and (@($_.Sources) | Where-Object { $_ -like ('Cert:{0}:*' -f $Tp) }) })
    }

    # --- CAs
    $cas = @()
    if ($null -ne $inv) { $cas = @($inv.EnterpriseCAs) }
    $certs = @()
    if ($null -ne $inv) { $certs = @($inv.CACertificates) }
    $certNode = {
        param($C)
        $i = $C.Info
        $d = @(('Subject: {0}' -f $i.Subject), ('Thumbprint (SHA-1): {0}' -f $C.Thumbprint),
            ('Valid {0} to {1} ({2} days left)' -f $i.NotBefore, $i.NotAfter, $i.DaysLeft),
            ('Role: {0} ({1}); lifecycle: {2} [{3}]' -f $C.Role, $C.RoleBasis, $C.Lifecycle, $C.LifecycleConfidence))
        if ($C.ComState) { $d += ('CA certificate state: {0}; CRL state: {1}' -f $C.ComState, $C.ComCrlState) }
        $cf = @($all | Where-Object { $_.RelatedCA -match ('(^|\()' + [regex]::Escape($C.Thumbprint) + '\)?$') })
        $conf = 'Referenced'
        if (@($C.Sources) -contains 'CA:GetCAProperty') { $conf = 'Confirmed' }
        $label = 'CA certificate'
        if ($C.Generation) { $label += ' ' + $C.Generation }
        $label += ' - ' + $C.Lifecycle
        $n = New-MspkiMapNode -Type 'Certificate' -Label $label -Detail $d -Sources @($C.Sources) -Confidence $conf -Findings (& $take $cf)
        foreach ($l in @(& $leadsForCert $C.Thumbprint)) {
            $leadPlaced[$l.Id] = $true
            [void]$n.Children.Add((& $newLeadNode $l))
        }
        return $n
    }
    $own = @{}
    foreach ($ca in $cas) {
        $props = $ca.Properties
        $typeName = 'Enterprise CA (properties not read)'
        $conf = 'Referenced'
        if ($null -ne $props) { $typeName = [string]$props.CATypeName; $conf = 'Confirmed' }
        $d = @(('Host: {0}' -f $ca.DnsHostName), ('CA configuration: {0}' -f $ca.Config), ('Type: {0}' -f $typeName))
        $caFindings = @($all | Where-Object { $_.Target -eq $ca.Name -and $_.RelatedCA -notmatch '[0-9A-F]{40}\)?$' -and "$($_.Endpoint)" -notlike 'CA property *' })
        $src = @('AD:EnrollmentServices')
        if ($null -ne $props) { $src += 'CA:GetCAProperty' }
        $caNode = New-MspkiMapNode -Type 'CA' -Label $ca.Name -Detail $d -Sources $src -Confidence $conf -Findings (& $take $caFindings)

        $mine = @($certs | Where-Object { $_.CAName -eq $ca.Name } | Sort-Object @{ Expression = { $_.Lifecycle -ne 'Current' } }, @{ Expression = { $_.Info.NotBefore }; Descending = $true })
        foreach ($c in $mine) { [void]$caNode.Children.Add((& $certNode $c)); $own[$c.Thumbprint] = $true }

        # CA's own CRLs (read through the CA, not from a CDP location)
        $crlF = @($all | Where-Object { "$($_.Endpoint)" -like 'CA property *' -and @($_.RelatedCA -split ',\s*') -contains $ca.Name })
        if ($crlF.Count -gt 0) {
            [void]$caNode.Children.Add((New-MspkiMapNode -Type 'Group' -Label ('CRLs held by the CA ({0})' -f $crlF.Count) `
                -Sources @('CA:GetCAProperty') -Confidence 'Confirmed' -Findings (& $take $crlF)))
        }
        # URLs the CA writes into issued certificates (from its properties) that no certificate node took
        $propLeads = @($leads | Where-Object { -not $leadPlaced.ContainsKey($_.Id) -and (@($_.Sources) | Where-Object { $_ -like ('CA:{0}:*' -f $ca.Name) }) })
        if ($propLeads.Count -gt 0) {
            $g = New-MspkiMapNode -Type 'Group' -Label ('URLs the CA puts into issued certificates ({0})' -f $propLeads.Count) -Sources @('CA:GetCAProperty')
            foreach ($l in $propLeads) { $leadPlaced[$l.Id] = $true; [void]$g.Children.Add((& $newLeadNode $l)) }
            [void]$caNode.Children.Add($g)
        }
        # Enrollment services (CES)
        $ces = @($ca.EnrollmentServers | Where-Object { $_ -and $_.Url })
        if ($ces.Count -gt 0) {
            $g = New-MspkiMapNode -Type 'Group' -Label ('Certificate Enrollment Web Services ({0})' -f $ces.Count) -Sources @('AD:EnrollmentServices:msPKI-Enrollment-Servers')
            foreach ($e in $ces) {
                $l = @($leads | Where-Object { $_.Kind -eq 'CES' -and @($_.Variants) -contains $e.Url }) | Select-Object -First 1
                if ($null -ne $l) { $leadPlaced[$l.Id] = $true; $n = & $newLeadNode $l }
                else { $n = New-MspkiMapNode -Type 'Endpoint' -Label ('CES: {0}' -f $e.Url) -Sources @('AD:EnrollmentServices:msPKI-Enrollment-Servers') -Confidence 'Referenced' }
                if ($e.AuthName) { $n.Detail = @($n.Detail) + ('Authentication: {0}' -f $e.AuthName) }
                [void]$g.Children.Add($n)
            }
            [void]$caNode.Children.Add($g)
        }
        # Published templates
        $tpl = @($ca.Templates | Where-Object { $_ })
        if ($tpl.Count -gt 0 -or ($null -ne $props -and @($props.Templates).Count -gt 0)) {
            $names = @($tpl)
            if ($names.Count -eq 0) { $names = @($props.Templates | ForEach-Object { $_.Name }) }
            $tf = @($all | Where-Object { $_.Category -eq 'Template' -and $_.RelatedCA -eq $ca.Name })
            $g = New-MspkiMapNode -Type 'Group' -Label ('Published certificate templates ({0})' -f $names.Count) `
                -Detail @($names | Select-Object -First 200) -Sources @('AD:EnrollmentServices:certificateTemplates') -Confidence 'Referenced' -Findings (& $take $tf)
            [void]$caNode.Children.Add($g)
        }
        [void]$root.Children.Add($caNode)
    }

    # --- CA certificates AD knows about but that belong to no CA with data
    $orphans = @($certs | Where-Object { -not $own.ContainsKey($_.Thumbprint) } | Sort-Object { $_.Info.Subject }, @{ Expression = { $_.Info.NotBefore }; Descending = $true })
    if ($orphans.Count -gt 0) {
        $g = New-MspkiMapNode -Type 'Group' -Label ('CA certificates seen only in AD, no CA data ({0})' -f $orphans.Count) -Sources @('AD:AIA', 'AD:CertificationAuthorities', 'AD:NTAuthCertificates')
        foreach ($c in $orphans) { [void]$g.Children.Add((& $certNode $c)) }
        [void]$root.Children.Add($g)
    }

    # --- everything else that was followed
    $rest = @($leads | Where-Object { -not $leadPlaced.ContainsKey($_.Id) })
    if ($rest.Count -gt 0) {
        $g = New-MspkiMapNode -Type 'Group' -Label ('Other links that were followed ({0})' -f $rest.Count) -Sources @('Followed links')
        foreach ($l in $rest) { $leadPlaced[$l.Id] = $true; [void]$g.Children.Add((& $newLeadNode $l)) }
        [void]$root.Children.Add($g)
    }

    # --- findings that belong to no node
    $loose = @($all | Where-Object { -not $placed.ContainsKey($_.Id) })
    if ($loose.Count -gt 0) {
        [void]$root.Children.Add((New-MspkiMapNode -Type 'Group' -Label ('Other findings ({0})' -f $loose.Count) -Sources @('Run') -Findings $loose))
    }
    [void](Set-MspkiMapRollup -Node $root)
    return $root
}

function Get-MspkiNodeCount {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Node)
    $n = 1
    foreach ($c in $Node.Children) { $n += (Get-MspkiNodeCount -Node $c) }
    return $n
}
