# Discovery stage (build phase A): AD context -> PKI containers -> Enterprise CAs -> AD-published CA
# certificates -> CA properties -> CA certificate generations.

function ConvertTo-MspkiCrlSummary {
    <#
    .SYNOPSIS
    JSON-safe summary of a decoded CRL (no raw bytes).
    #>
    [CmdletBinding()]
    param($Crl)
    if ($null -eq $Crl) { return $null }
    return [pscustomobject][ordered]@{
        Issuer = $Crl.Issuer; CrlNumber = $Crl.CrlNumber; IsDelta = $Crl.IsDelta; BaseCrlNumber = $Crl.BaseCrlNumber
        ThisUpdate = $Crl.ThisUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ')
        NextUpdate = $(if ($null -ne $Crl.NextUpdate) { $Crl.NextUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { '' })
        CAVersion = $Crl.CAVersion; RevokedCount = $Crl.RevokedCount; Sha1 = $Crl.Sha1
    }
}

function ConvertTo-MspkiCAPropertiesExport {
    [CmdletBinding()]
    param($Properties)
    if ($null -eq $Properties) { return $null }
    $sig = @($Properties.SigningCertificates | ForEach-Object {
        $tp = ''
        if ($null -ne $_.Certificate) { $tp = $_.Certificate.Thumbprint }
        [pscustomobject][ordered]@{
            Index = $_.Index; Thumbprint = $tp; CertificateError = $_.CertificateError; State = $_.StateName
            CAVersion = $_.CAVersion; CrlState = $_.CrlStateName; BaseCrlPublishStatus = $_.BaseCrlPublishStatus
            DeltaCrlPublishStatus = $_.DeltaCrlPublishStatus; BaseCrlState = $_.BaseCrlState; BaseCrlDetail = $_.BaseCrlDetail
            BaseCrl = (ConvertTo-MspkiCrlSummary -Crl $_.BaseCrl); DeltaCrlState = $_.DeltaCrlState; DeltaCrlDetail = $_.DeltaCrlDetail
            DeltaCrl = (ConvertTo-MspkiCrlSummary -Crl $_.DeltaCrl); CdpUrls = @($_.CdpUrls); AiaUrls = @($_.AiaUrls)
            OcspUrls = @($_.OcspUrls)
        }
    })
    $o = [ordered]@{}
    foreach ($p in $Properties.psobject.Properties) {
        if ($p.Name -eq 'SigningCertificates') { $o[$p.Name] = $sig } else { $o[$p.Name] = $p.Value }
    }
    return [pscustomobject]$o
}

function ConvertTo-MspkiEnterpriseCAExport {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$CA, $Properties = $null)
    return [pscustomobject][ordered]@{
        Name                   = $CA.Name
        CommonName             = $CA.CommonName
        DisplayName            = $CA.DisplayName
        DnsHostName            = $CA.DnsHostName
        Config                 = $CA.Config
        DistinguishedName      = $CA.DistinguishedName
        WhenCreated            = $CA.WhenCreated
        WhenChanged            = $CA.WhenChanged
        Templates              = @($CA.Templates)
        EnrollmentServers      = @($CA.EnrollmentServers)
        CertificateThumbprints = @($CA.Certificates | ForEach-Object { $_.Thumbprint })
        CertificateErrors      = @($CA.CertificateErrors)
        Properties             = (ConvertTo-MspkiCAPropertiesExport -Properties $Properties)
    }
}

function ConvertTo-MspkiCACertificateExport {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry)
    $o = [ordered]@{}
    foreach ($p in $Entry.psobject.Properties) { if ($p.Name -ne 'Certificate') { $o[$p.Name] = $p.Value } }
    return [pscustomobject]$o
}

function Get-MspkiDiscoveredCertificateEntry {
    <#
    .SYNOPSIS
    Rebuilds the merged CA certificate entries (inventory data plus the certificate object) for analyzers.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Discovery)
    foreach ($c in @($Discovery.Inventory.CACertificates)) {
        if (-not $Discovery.Certificates.ContainsKey($c.Thumbprint)) { continue }
        $o = [ordered]@{}
        foreach ($p in $c.psobject.Properties) { $o[$p.Name] = $p.Value }
        $o['Certificate'] = $Discovery.Certificates[$c.Thumbprint]
        [pscustomobject]$o
    }
}

function Invoke-MspkiDiscovery {
    <#
    .SYNOPSIS
    Runs the discovery stage and returns Inventory (JSON-safe), Findings and runtime-only Certificates
    (thumbprint -> X509Certificate2, public certificates only).
    #>
    [CmdletBinding()]
    param(
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork
    )
    Reset-MspkiSidCache
    $findings = New-Object System.Collections.ArrayList
    $inventory = [ordered]@{
        AdContext      = $null
        PksExists      = $null
        Containers     = @()
        EnterpriseCAs  = @()
        CACertificates = @()
        Templates      = @()
        TemplatesRead  = $false
        Kra            = @()
        KraRead        = $false
        OidObjects     = @()
        OidRead        = $false
    }
    $certMap = @{}
    $props = @{}   # live (decoded) CA properties by CA name; never exported, the inventory holds the JSON-safe summary
    $result = { [pscustomobject]@{ Inventory = [pscustomobject]$inventory; Findings = @($findings); Certificates = $certMap; CAProperties = $props } }

    $sw = Start-MspkiStageTimer -Stage 'Discovery:ADContext'
    $ad = Get-MspkiAdContext -TimeoutSeconds $TimeoutSeconds
    foreach ($f in $ad.Findings) { [void]$findings.Add($f) }
    $ctx = $ad.Data
    $inventory.AdContext = $ctx
    Add-MspkiStageTiming -Stage 'Discovery:ADContext' -Stopwatch $sw
    if (-not $ctx.Ready) { return (& $result) }

    $sw = Start-MspkiStageTimer -Stage 'Discovery:PKIContainers'
    $pc = Get-MspkiPkiContainer -Context $ctx -TimeoutSeconds $TimeoutSeconds
    foreach ($f in $pc.Findings) { [void]$findings.Add($f) }
    $inventory.PksExists = $pc.Data.PksExists
    $inventory.Containers = @($pc.Data.Containers)
    Add-MspkiStageTiming -Stage 'Discovery:PKIContainers' -Stopwatch $sw
    if (-not $pc.Data.PksExists) { return (& $result) }

    $sw = Start-MspkiStageTimer -Stage 'Discovery:EnterpriseCAs'
    $ec = Get-MspkiEnterpriseCA -Context $ctx -TimeoutSeconds $TimeoutSeconds
    foreach ($f in $ec.Findings) { [void]$findings.Add($f) }
    $cas = @($ec.Data)
    $adCerts = Get-MspkiAdCACertificate -Context $ctx -TimeoutSeconds $TimeoutSeconds
    foreach ($f in $adCerts.Findings) { [void]$findings.Add($f) }
    Add-MspkiStageTiming -Stage 'Discovery:EnterpriseCAs' -Stopwatch $sw

    $sw = Start-MspkiStageTimer -Stage 'Discovery:TemplatesKraOid'
    foreach ($step in @(
        @{ Name = 'Templates'; Fn = { Get-MspkiTemplateObject -Context $ctx -TimeoutSeconds $TimeoutSeconds }; Data = 'Templates'; Flag = 'TemplatesRead' },
        @{ Name = 'KRA'; Fn = { Get-MspkiKraObject -Context $ctx -TimeoutSeconds $TimeoutSeconds }; Data = 'Kra'; Flag = 'KraRead' },
        @{ Name = 'OID'; Fn = { Get-MspkiOidObject -Context $ctx -TimeoutSeconds $TimeoutSeconds }; Data = 'OidObjects'; Flag = 'OidRead' })) {
        try {
            $r = & $step.Fn
            foreach ($f in $r.Findings) { [void]$findings.Add($f) }
            $inventory[$step.Data] = @($r.Data)
            $inventory[$step.Flag] = [bool]$r.Read
        }
        catch {
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'ADContainer' -Role 'ADContainer' -Target $step.Name `
                -Sources 'AD:PublicKeyServices' -Action ('reading the {0} objects' -f $step.Name) -Scope 'Local'))
        }
    }
    Add-MspkiStageTiming -Stage 'Discovery:TemplatesKraOid' -Stopwatch $sw

    $sw = Start-MspkiStageTimer -Stage 'Discovery:CAProperties'
    $props = @{}
    $propFindings = New-Object System.Collections.ArrayList
    foreach ($ca in $cas) {
        if (Test-MspkiCancelled) { break }
        try {
            $r = Get-MspkiCAProperty -CA $ca -Context $ctx -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork
            if ($null -ne $r.Data) { $props[$ca.Name] = $r.Data }
            foreach ($f in $r.Findings) { [void]$propFindings.Add($f) }
        }
        catch {
            [void]$propFindings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'CA' -Target $ca.Name `
                -Endpoint $ca.Config -RelatedCA $ca.Name -Sources @('AD:EnrollmentServices', 'CA:GetCAProperty') `
                -Action 'reading CA properties'))
        }
    }
    # A CA that refused this account is easier to understand when another CA answered the same account in the same run: the
    # client, the account and Kerberos then work, and the difference is on that CA host.
    if ($props.Count -gt 0) {
        $answered = @($props.Keys | Sort-Object) -join ', '
        foreach ($f in @($propFindings | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' -and $_.Confidence -eq 'Inferred' })) {
            $f.Evidence = [string[]](@($f.Evidence) + ('Other CA(s) answered the same account from this computer in this run: {0}. So this computer, the account and Kerberos work; the refusal is specific to this CA host.' -f $answered))
        }
    }
    Add-MspkiStageTiming -Stage 'Discovery:CAProperties' -Stopwatch $sw

    $sw = Start-MspkiStageTimer -Stage 'Discovery:CACertificates'
    $entries = @(Merge-MspkiCACertificate -EnterpriseCAs $cas -CAProperties $props -AdEntries @($adCerts.Data))
    foreach ($ca in $cas) {
        $p = $null
        if ($props.ContainsKey($ca.Name)) { $p = $props[$ca.Name] }
        [void]$findings.Add((New-MspkiEnterpriseCAFinding -CA $ca -Properties $p -Certificates $entries -Context $ctx))
        foreach ($f in @($propFindings | Where-Object { $_.Target -eq $ca.Name })) { [void]$findings.Add($f) }
    }
    $sorted = @($entries | Sort-Object @{ Expression = { $_.CAName -eq '' } }, CAName, @{ Expression = { $_.Info.NotBefore }; Descending = $true })
    foreach ($e in $sorted) {
        [void]$findings.Add((New-MspkiCACertificateFinding -Entry $e -Context $ctx))
        $certMap[$e.Thumbprint] = $e.Certificate
    }
    $inventory.EnterpriseCAs = @($cas | ForEach-Object {
        $p = $null
        if ($props.ContainsKey($_.Name)) { $p = $props[$_.Name] }
        ConvertTo-MspkiEnterpriseCAExport -CA $_ -Properties $p
    })
    $inventory.CACertificates = @($sorted | ForEach-Object { ConvertTo-MspkiCACertificateExport -Entry $_ })

    $read = $props.Count
    $msg = 'Discovery: forest {0}, {1} Enterprise CA(s) ({2} answered), {3} CA certificate(s).' -f $ctx.Forest, $cas.Count, $read, $entries.Count
    $ev = @(
        ('Enterprise CAs: {0}' -f (($cas | ForEach-Object { $_.Name }) -join ', ')),
        ('CA certificates: {0} current, {1} historical, {2} unknown' -f @($entries | Where-Object { $_.Lifecycle -eq 'Current' }).Count,
            @($entries | Where-Object { $_.Lifecycle -eq 'Historical' }).Count, @($entries | Where-Object { $_.Lifecycle -eq 'Unknown' }).Count),
        ('Standalone roots / other CAs seen only in AD: {0}' -f @($entries | Where-Object { -not $_.CAName }).Count)
    )
    [void]$findings.Add((New-MspkiFinding -Category 'Run' -Role 'Run' -Target $ctx.Forest -Status 'Information' -StatusCode 'OK' `
        -Confidence 'Confirmed' -Sources @('AD:EnrollmentServices', 'AD:AIA', 'AD:CertificationAuthorities', 'AD:NTAuthCertificates') `
        -Scope 'Local' -Message $msg -Evidence $ev -Layers @{ DiscoveryStatus = 'Pass' }))
    Add-MspkiStageTiming -Stage 'Discovery:CACertificates' -Stopwatch $sw
    return (& $result)
}
