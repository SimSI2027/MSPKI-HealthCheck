# Discovery stage (build phase A): AD context -> PKI containers -> Enterprise CAs -> AD-published CA
# certificates -> CA properties -> CA certificate generations.

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
            DeltaCrlPublishStatus = $_.DeltaCrlPublishStatus; CdpUrls = @($_.CdpUrls); AiaUrls = @($_.AiaUrls)
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
    $findings = New-Object System.Collections.ArrayList
    $inventory = [ordered]@{
        AdContext      = $null
        PksExists      = $null
        Containers     = @()
        EnterpriseCAs  = @()
        CACertificates = @()
    }
    $certMap = @{}
    $result = { [pscustomobject]@{ Inventory = [pscustomobject]$inventory; Findings = @($findings); Certificates = $certMap } }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ad = Get-MspkiAdContext -TimeoutSeconds $TimeoutSeconds
    foreach ($f in $ad.Findings) { [void]$findings.Add($f) }
    $ctx = $ad.Data
    $inventory.AdContext = $ctx
    Add-MspkiStageTiming -Stage 'Discovery:ADContext' -Stopwatch $sw
    if (-not $ctx.Ready) { return (& $result) }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $pc = Get-MspkiPkiContainer -Context $ctx -TimeoutSeconds $TimeoutSeconds
    foreach ($f in $pc.Findings) { [void]$findings.Add($f) }
    $inventory.PksExists = $pc.Data.PksExists
    $inventory.Containers = @($pc.Data.Containers)
    Add-MspkiStageTiming -Stage 'Discovery:PKIContainers' -Stopwatch $sw
    if (-not $pc.Data.PksExists) { return (& $result) }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ec = Get-MspkiEnterpriseCA -Context $ctx -TimeoutSeconds $TimeoutSeconds
    foreach ($f in $ec.Findings) { [void]$findings.Add($f) }
    $cas = @($ec.Data)
    $adCerts = Get-MspkiAdCACertificate -Context $ctx -TimeoutSeconds $TimeoutSeconds
    foreach ($f in $adCerts.Findings) { [void]$findings.Add($f) }
    Add-MspkiStageTiming -Stage 'Discovery:EnterpriseCAs' -Stopwatch $sw

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $props = @{}
    $propFindings = New-Object System.Collections.ArrayList
    foreach ($ca in $cas) {
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
    Add-MspkiStageTiming -Stage 'Discovery:CAProperties' -Stopwatch $sw

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
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
