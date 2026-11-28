# Every CA certificate generation: merges the certificates from the CAs themselves (GetCAProperty),
# Enrollment Services, Certification Authorities, AIA and NTAuthCertificates by thumbprint, keeping every
# source. Decides current vs historical and the CA role from the strongest evidence available.

function Merge-MspkiCACertificate {
    <#
    .SYNOPSIS
    Merges all discovered CA certificates into one entry per certificate with combined sources.
    Pure function: no network access.

    .PARAMETER CAProperties
    Hashtable: Enterprise CA name -> CA properties object (or $null when the CA could not be read).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$EnterpriseCAs = @(),
        [hashtable]$CAProperties = @{},
        [AllowEmptyCollection()][object[]]$AdEntries = @(),
        [DateTime]$Now = (Get-MspkiUtcNow)
    )
    $index = [ordered]@{}
    $add = {
        param($cert, [string]$source, [string]$caName, [string]$basis, $comItem)
        $tp = $cert.Thumbprint
        if (-not $index.Contains($tp)) {
            $index[$tp] = [ordered]@{
                Certificate = $cert; Sources = New-Object System.Collections.ArrayList
                ObjectNames = New-Object System.Collections.ArrayList
                CAName = ''; AssociationBasis = ''; ComIndex = $null; ComState = ''; ComCAVersion = ''; ComCrlState = ''
                InEnrollmentServices = $false; InAIA = $false; InCertificationAuthorities = $false; InNTAuth = $false
            }
        }
        $e = $index[$tp]
        if (-not $e.Sources.Contains($source)) { [void]$e.Sources.Add($source) }
        if ($caName -and -not $e.CAName) { $e.CAName = $caName; $e.AssociationBasis = $basis }
        if ($null -ne $comItem) {
            $e.ComIndex = $comItem.Index; $e.ComState = $comItem.StateName; $e.ComCAVersion = $comItem.CAVersion
            $e.ComCrlState = $comItem.CrlStateName
        }
        switch ($source) {
            'AD:EnrollmentServices' { $e.InEnrollmentServices = $true }
            'AD:AIA' { $e.InAIA = $true }
            'AD:CertificationAuthorities' { $e.InCertificationAuthorities = $true }
            'AD:NTAuthCertificates' { $e.InNTAuth = $true }
        }
    }

    # 1. The CAs' own signing certificates (authoritative), 2. Enrollment Services cACertificate.
    foreach ($ca in $EnterpriseCAs) {
        $p = $null
        if ($CAProperties.ContainsKey($ca.Name)) { $p = $CAProperties[$ca.Name] }
        if ($null -ne $p) {
            foreach ($s in $p.SigningCertificates) {
                if ($null -ne $s.Certificate) { & $add $s.Certificate 'CA:GetCAProperty' $ca.Name 'CA signing certificate (GetCAProperty)' $s }
            }
        }
        foreach ($c in $ca.Certificates) { & $add $c 'AD:EnrollmentServices' $ca.Name 'cACertificate on the Enrollment Services object' $null }
    }
    # 3. AD containers. An object named after the CA's common name belongs to that CA.
    foreach ($a in $AdEntries) {
        $owner = ''
        foreach ($ca in $EnterpriseCAs) {
            if ($a.ObjectName -and ($a.ObjectName -eq $ca.CommonName -or $a.ObjectName -eq $ca.Name)) { $owner = $ca.Name; break }
        }
        $basis = ''
        if ($owner) { $basis = ('AD object {0} has the CA''s name' -f $a.ObjectName) }
        & $add $a.Certificate $a.Source $owner $basis $null
        if ($a.ObjectName -and -not $index[$a.Certificate.Thumbprint].ObjectNames.Contains($a.ObjectName)) {
            [void]$index[$a.Certificate.Thumbprint].ObjectNames.Add($a.ObjectName)
        }
    }
    # 4. Same subject as a certificate already tied to a CA (inferred association).
    $subjects = @{}
    foreach ($tp in $index.Keys) {
        $e = $index[$tp]
        if ($e.CAName) { $subjects[$e.Certificate.Subject] = $e.CAName }
    }
    foreach ($tp in $index.Keys) {
        $e = $index[$tp]
        if (-not $e.CAName -and $subjects.ContainsKey($e.Certificate.Subject)) {
            $e.CAName = $subjects[$e.Certificate.Subject]
            $e.AssociationBasis = 'Inferred: same subject as a certificate of this CA'
        }
    }

    $caByName = @{}
    foreach ($ca in $EnterpriseCAs) { $caByName[$ca.Name] = $ca }
    $out = New-Object System.Collections.ArrayList
    foreach ($tp in $index.Keys) {
        $e = $index[$tp]
        $info = Get-MspkiCertificateInfo -Certificate $e.Certificate -Now $Now
        $lifecycle = 'Unknown'; $lifecycleBasis = ''; $lifecycleConfidence = 'Unknown'
        $role = 'Unknown'; $roleBasis = ''
        $p = $null
        if ($e.CAName -and $CAProperties.ContainsKey($e.CAName)) { $p = $CAProperties[$e.CAName] }
        if ($e.CAName -and $caByName.ContainsKey($e.CAName)) {
            # Enterprise CA certificate.
            if ($null -ne $p) {
                $role = Get-MspkiCARoleFromType -CATypeName $p.CATypeName
                $roleBasis = ('CA type reported by the CA: {0}' -f $p.CATypeName)
                if ($null -ne $e.ComIndex) {
                    if ($e.ComIndex -eq ($p.SigningCertCount - 1)) { $lifecycle = 'Current' } else { $lifecycle = 'Historical' }
                    $lifecycleBasis = ('CA signing certificate index {0} of {1}' -f $e.ComIndex, $p.SigningCertCount)
                    $lifecycleConfidence = 'Confirmed'
                }
                else {
                    $lifecycleBasis = 'Published in AD but not among the CA''s own signing certificates (may belong to an earlier installation with the same name).'
                }
            }
            else {
                if ($info.SelfIssued) { $role = 'EnterpriseRoot' } else { $role = 'EnterpriseSubordinate' }
                $roleBasis = 'Enterprise CA (Enrollment Services); root or subordinate from the certificate (self-issued or not)'
                if ($e.InEnrollmentServices) {
                    $lifecycle = 'Current'; $lifecycleBasis = 'cACertificate on the Enrollment Services object'; $lifecycleConfidence = 'Referenced'
                }
                else {
                    $lifecycle = 'Historical'; $lifecycleConfidence = 'Inferred'
                    $lifecycleBasis = 'Inferred: belongs to the CA but is not the cACertificate on the Enrollment Services object'
                }
            }
        }
        else {
            if ($info.SelfIssued) { $role = 'StandaloneRoot'; $roleBasis = 'Self-issued and not an Enterprise CA' }
            else { $role = 'Intermediate'; $roleBasis = 'Not self-issued and not an Enterprise CA' }
        }
        [void]$out.Add([pscustomobject][ordered]@{
            Thumbprint          = $tp
            CAName              = $e.CAName
            AssociationBasis    = $e.AssociationBasis
            Role                = $role
            RoleBasis           = $roleBasis
            Lifecycle           = $lifecycle
            LifecycleBasis      = $lifecycleBasis
            LifecycleConfidence = $lifecycleConfidence
            Generation          = $(if ($e.ComCAVersion) { $e.ComCAVersion } else { $info.CAVersion })
            ComIndex            = $e.ComIndex
            ComState            = $e.ComState
            ComCrlState         = $e.ComCrlState
            Sources             = [string[]]@($e.Sources)
            ObjectNames         = [string[]]@($e.ObjectNames)
            InEnrollmentServices = $e.InEnrollmentServices
            InAIA               = $e.InAIA
            InCertificationAuthorities = $e.InCertificationAuthorities
            InNTAuth            = $e.InNTAuth
            Info                = $info
            Certificate         = $e.Certificate
        })
    }

    # Lifecycle still unknown: among certificates with the same subject, the latest NotBefore is
    # taken as current (inferred) and the others as historical (inferred).
    $groups = @($out | Where-Object { $_.Lifecycle -eq 'Unknown' -and -not $_.LifecycleBasis } | Group-Object { $_.Info.Subject })
    foreach ($g in $groups) {
        $sorted = @($g.Group | Sort-Object { $_.Info.NotBefore } -Descending)
        for ($i = 0; $i -lt $sorted.Count; $i++) {
            if ($i -eq 0) { $sorted[$i].Lifecycle = 'Current' } else { $sorted[$i].Lifecycle = 'Historical' }
            $sorted[$i].LifecycleBasis = ('Inferred: {0} of {1} certificate(s) with this subject, ordered by NotBefore' -f ($i + 1), $sorted.Count)
            $sorted[$i].LifecycleConfidence = 'Inferred'
        }
    }
    return @($out)
}

function New-MspkiCACertificateFinding {
    <#
    .SYNOPSIS
    One discovery finding per CA certificate generation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Entry,
        $Context = $null
    )
    $i = $Entry.Info
    $confidence = 'Referenced'
    if ($Entry.Sources -contains 'CA:GetCAProperty') { $confidence = 'Confirmed' }
    $target = $i.Subject
    if ($Entry.CAName) { $target = $Entry.CAName }
    $gen = ''
    if ($Entry.Generation) { $gen = ' ' + $Entry.Generation }
    $msg = 'CA certificate{0} of {1} ({2}, {3}): valid until {4} ({5} days).' -f $gen, $target, $Entry.Role, $Entry.Lifecycle, $i.NotAfter, $i.DaysLeft
    $bc = 'absent'
    if ($null -ne $i.IsCA) {
        $bc = 'CA={0}' -f $i.IsCA
        if ($null -ne $i.PathLength) { $bc += (', path length {0}' -f $i.PathLength) }
    }
    $ev = @(
        ('Subject: {0}' -f $i.Subject),
        ('Issuer: {0}' -f $i.Issuer),
        ('Thumbprint (SHA-1): {0}' -f $i.Thumbprint),
        ('SHA-256: {0}' -f $i.Sha256),
        ('Serial number: {0}' -f $i.SerialNumber),
        ('Valid from {0} to {1} ({2} days left)' -f $i.NotBefore, $i.NotAfter, $i.DaysLeft),
        ('Self-issued: {0}' -f $i.SelfIssued),
        ('Key: {0} {1}; signature: {2}' -f $i.KeyAlgorithm, $i.KeySize, $i.SignatureAlgorithm),
        ('Basic Constraints: {0}' -f $bc),
        ('Key Usage: {0}' -f $i.KeyUsage),
        ('Role: {0} ({1})' -f $Entry.Role, $Entry.RoleBasis),
        ('Lifecycle: {0} [{1}] ({2})' -f $Entry.Lifecycle, $Entry.LifecycleConfidence, $Entry.LifecycleBasis)
    )
    if ($Entry.CAName) { $ev += ('Belongs to CA: {0} ({1})' -f $Entry.CAName, $Entry.AssociationBasis) }
    if ($null -ne $Entry.ComIndex) { $ev += ('CA certificate state: {0}; CRL state: {1}' -f $Entry.ComState, $Entry.ComCrlState) }
    if ($i.PreviousCAHash) { $ev += ('Previous CA certificate hash: {0}' -f $i.PreviousCAHash) }
    if ($Entry.ObjectNames.Count -gt 0) { $ev += ('AD object(s): {0}' -f ($Entry.ObjectNames -join ', ')) }
    $ev += ('Published in: Enrollment Services={0}, AIA={1}, Certification Authorities={2}, NTAuth={3}' -f `
        $Entry.InEnrollmentServices, $Entry.InAIA, $Entry.InCertificationAuthorities, $Entry.InNTAuth)
    $notes = ''
    if ($Entry.LifecycleConfidence -eq 'Inferred') { $notes = 'Current/historical is inferred from certificate dates, not confirmed by a CA.' }
    $related = $i.Thumbprint
    if ($Entry.CAName) { $related = '{0} ({1})' -f $Entry.CAName, $i.Thumbprint }
    return (New-MspkiFinding -Category 'CA' -Role $Entry.Role -Target $target -RelatedCA $related `
        -Status 'Information' -StatusCode 'OK' -Confidence $confidence -Sources $Entry.Sources -Scope 'Local' `
        -Message $msg -Evidence $ev -Notes $notes -Layers @{ DiscoveryStatus = 'Pass' })
}

function New-MspkiEnterpriseCAFinding {
    <#
    .SYNOPSIS
    One discovery finding per Enterprise CA, combining AD and (when read) the CA's own properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$CA,
        $Properties = $null,
        [AllowEmptyCollection()][object[]]$Certificates = @(),
        $Context = $null
    )
    $scope = 'Unknown'
    if ($null -ne $Context) {
        $scope = Get-MspkiHostScope -HostName $CA.DnsHostName -LocalDomains @($Context.ForestDomains) -TrustedDomains @($Context.TrustedDomains)
    }
    $mine = @($Certificates | Where-Object { $_.CAName -eq $CA.Name })
    $current = @($mine | Where-Object { $_.Lifecycle -eq 'Current' })
    $sources = @('AD:EnrollmentServices')
    if ($null -ne $Properties) {
        $role = Get-MspkiCARoleFromType -CATypeName $Properties.CATypeName
        $confidence = 'Confirmed'
        $sources += 'CA:GetCAProperty'
        $roleText = '{0} (reported by the CA)' -f $Properties.CATypeName
    }
    else {
        $role = 'EnterpriseSubordinate'
        if (@($current | Where-Object { $_.Info.SelfIssued }).Count -gt 0) { $role = 'EnterpriseRoot' }
        $confidence = 'Referenced'
        $roleText = '{0} (from the AD certificate; the CA was not read)' -f $role
    }
    $ev = @(
        ('Distinguished name: {0}' -f $CA.DistinguishedName),
        ('dNSHostName: {0}' -f $CA.DnsHostName),
        ('Config: {0}' -f $CA.Config),
        ('Role: {0}' -f $roleText),
        ('Templates published (AD): {0}' -f @($CA.Templates).Count),
        ('CA certificates found: {0} ({1} current)' -f $mine.Count, $current.Count)
    )
    foreach ($c in $current) { $ev += ('Current certificate: {0} valid until {1}' -f $c.Thumbprint, $c.Info.NotAfter) }
    foreach ($s in $CA.EnrollmentServers) {
        $ev += ('CES (msPKI-Enrollment-Servers): {0} auth {1} priority {2} renewal-only {3}' -f $s.Url, $s.AuthName, $s.Priority, $s.RenewalOnly)
    }
    foreach ($e in $CA.CertificateErrors) { $ev += ('Unreadable cACertificate value: {0}' -f $e) }
    $ev += ('Scope: {0}' -f $scope)
    $msg = 'Enterprise CA {0} on {1}: {2}, {3} template(s), {4} CA certificate(s).' -f $CA.Name, $CA.DnsHostName, $role, @($CA.Templates).Count, $mine.Count
    return (New-MspkiFinding -Category 'CA' -Role $role -Target $CA.Name -Endpoint $CA.Config -RelatedCA $CA.Name `
        -Status 'Information' -StatusCode 'OK' -Confidence $confidence -Sources $sources -Scope $scope `
        -Message $msg -Evidence $ev -Layers @{ DiscoveryStatus = 'Pass' })
}
