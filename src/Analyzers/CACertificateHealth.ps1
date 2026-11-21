# CA certificate health (REQUIREMENTS section 5.1): validity against thresholds, effective expiry limited by
# the parent, and the chain built from the discovered certificates (signature, parent found, local trust).

$script:MspkiDefaultThresholds = @{
    RootCaWarningDays     = 730
    RootCaCriticalDays    = 365
    IssuingCaWarningDays  = 180
    IssuingCaCriticalDays = 90
    RootCrlWarningPercent     = 75
    RootCrlCriticalPercent    = 95
    IssuingCrlWarningPercent  = 75
    IssuingCrlCriticalPercent = 95
    CrlPublicationGraceMinutes = 60
}

function Get-MspkiThreshold {
    <#
    .SYNOPSIS
    Returns the thresholds in use: defaults overridden by any values given.
    #>
    [CmdletBinding()]
    param([hashtable]$Override = @{})
    $t = @{}
    foreach ($k in $script:MspkiDefaultThresholds.Keys) { $t[$k] = $script:MspkiDefaultThresholds[$k] }
    foreach ($k in $Override.Keys) { if ($t.ContainsKey($k) -and $null -ne $Override[$k]) { $t[$k] = [int]$Override[$k] } }
    return $t
}

function Get-MspkiCertificateParent {
    <#
    .SYNOPSIS
    Finds the issuer of a certificate among the given certificates: subject name equals the issuer name and
    the signature verifies. Returns { Parent; Status = Found | SelfSigned | NotFound | SignatureInvalid | Unverifiable; Reason }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [AllowEmptyCollection()][object[]]$Candidates = @()
    )
    $issuerHex = ConvertTo-MspkiHex $Certificate.IssuerName.RawData
    $selfIssued = ($issuerHex -eq (ConvertTo-MspkiHex $Certificate.SubjectName.RawData))
    if ($selfIssued) {
        $v = Test-MspkiSignature -SignedBytes $Certificate.RawData -Issuer $Certificate
        if ($v.Valid -eq $true) { return [pscustomobject]@{ Parent = $Certificate; Status = 'SelfSigned'; Reason = '' } }
        if ($v.Valid -eq $false) { return [pscustomobject]@{ Parent = $null; Status = 'SignatureInvalid'; Reason = $v.Reason } }
        return [pscustomobject]@{ Parent = $null; Status = 'Unverifiable'; Reason = $v.Reason }
    }
    $cands = @($Candidates | Where-Object { $null -ne $_ -and (ConvertTo-MspkiHex $_.SubjectName.RawData) -eq $issuerHex -and $_.Thumbprint -ne $Certificate.Thumbprint })
    if ($cands.Count -eq 0) { return [pscustomobject]@{ Parent = $null; Status = 'NotFound'; Reason = 'No discovered certificate has the issuer name.' } }
    $reason = ''
    $unverifiable = $false
    foreach ($m in @($cands | Sort-Object NotAfter -Descending)) {
        $v = Test-MspkiSignature -SignedBytes $Certificate.RawData -Issuer $m
        if ($v.Valid -eq $true) { return [pscustomobject]@{ Parent = $m; Status = 'Found'; Reason = '' } }
        if ($null -eq $v.Valid) { $unverifiable = $true }
        $reason = $v.Reason
    }
    if ($unverifiable) { return [pscustomobject]@{ Parent = $null; Status = 'Unverifiable'; Reason = $reason } }
    return [pscustomobject]@{ Parent = $null; Status = 'SignatureInvalid'; Reason = ('{0} certificate(s) with the issuer name, none verifies the signature.' -f $cands.Count) }
}

function Test-MspkiCACertificateHealth {
    <#
    .SYNOPSIS
    Checks each discovered CA certificate: validity (thresholds, limited by the parent) and chain
    (parent found, signature, self-signed as expected, Basic Constraints, root trusted on this computer).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Entries = @(),
        [hashtable]$Thresholds = @{},
        [DateTime]$Now = [DateTime]::UtcNow,
        [scriptblock]$TrustTest = $null
    )
    $t = Get-MspkiThreshold -Override $Thresholds
    if ($null -eq $TrustTest) { $TrustTest = { param($tp) Test-MspkiTrustedRoot -Thumbprint $tp } }
    $all = @($Entries | ForEach-Object { $_.Certificate })
    $findings = New-Object System.Collections.ArrayList
    foreach ($e in $Entries) {
        $c = $e.Certificate
        $i = $e.Info
        $target = $i.Subject
        if ($e.CAName) { $target = $e.CAName }
        $related = '{0} ({1})' -f $target, $i.Thumbprint
        $sources = @($e.Sources)
        $confidence = 'Referenced'
        if ($sources -contains 'CA:GetCAProperty') { $confidence = 'Confirmed' }
        $lifeConfidence = $confidence
        if ($e.LifecycleConfidence -eq 'Inferred') { $lifeConfidence = 'Inferred' }

        # Chain: walk up through the discovered certificates.
        $path = New-Object System.Collections.ArrayList
        $chainStatus = 'Pass'; $chainCode = 'OK'; $chainLayer = 'Pass'
        $chainEv = New-Object System.Collections.ArrayList
        $cur = $c
        $parent = $null
        for ($depth = 0; $depth -lt 8; $depth++) {
            [void]$path.Add($cur)
            $p = Get-MspkiCertificateParent -Certificate $cur -Candidates $all
            if ($depth -eq 0 -and $p.Status -eq 'Found') { $parent = $p.Parent }
            if ($p.Status -eq 'SelfSigned') {
                $trusted = $null
                try { $trusted = [bool](& $TrustTest $cur.Thumbprint) } catch { [void]$chainEv.Add(('Trust store not readable: {0}' -f (Get-MspkiErrorInfo $_).Message)) }
                [void]$chainEv.Add(('Root {0} ({1}) trusted on this computer: {2}' -f $cur.Subject, $cur.Thumbprint, $trusted))
                if ($trusted -eq $false) { $chainStatus = 'Warning'; $chainCode = 'CHAIN_UNTRUSTED_ROOT'; $chainLayer = 'Warning' }
                break
            }
            if ($p.Status -eq 'Found') { $cur = $p.Parent; continue }
            if ($p.Status -eq 'NotFound') {
                $chainStatus = 'Warning'; $chainCode = 'CHAIN_PARTIAL'; $chainLayer = 'Fail'
                [void]$chainEv.Add(('Issuer of {0} not found among the discovered certificates: {1}' -f $cur.Subject, $cur.Issuer))
            }
            elseif ($p.Status -eq 'SignatureInvalid') {
                $chainStatus = 'Fail'; $chainCode = 'SIGNATURE_INVALID'; $chainLayer = 'Fail'
                [void]$chainEv.Add(('Signature of {0} does not verify: {1}' -f $cur.Subject, $p.Reason))
            }
            else {
                $chainStatus = 'Warning'; $chainCode = 'CHAIN_INVALID'; $chainLayer = 'Unknown'
                [void]$chainEv.Add(('Signature of {0} could not be checked: {1}' -f $cur.Subject, $p.Reason))
            }
            break
        }
        $pathText = @($path | ForEach-Object { '{0} [{1}]' -f $_.Subject, $_.Thumbprint }) -join ' -> '
        [void]$chainEv.Insert(0, ('Path: {0}' -f $pathText))
        $isRootRole = @('EnterpriseRoot', 'StandaloneRoot') -contains $e.Role
        if ($isRootRole -and -not $i.SelfIssued) {
            if ($chainStatus -eq 'Pass') { $chainStatus = 'Warning'; $chainCode = 'CHAIN_INVALID'; $chainLayer = 'Warning' }
            [void]$chainEv.Add(('Role {0} but the certificate is not self-issued.' -f $e.Role))
        }
        if (-not $isRootRole -and $i.SelfIssued -and $e.Role -ne 'Unknown') {
            if ($chainStatus -eq 'Pass') { $chainStatus = 'Warning'; $chainCode = 'CHAIN_INVALID'; $chainLayer = 'Warning' }
            [void]$chainEv.Add(('Role {0} but the certificate is self-issued.' -f $e.Role))
        }
        if ($i.IsCA -ne $true) {
            if ($chainStatus -eq 'Pass') { $chainStatus = 'Warning'; $chainCode = 'CHAIN_INVALID'; $chainLayer = 'Warning' }
            [void]$chainEv.Add('Basic Constraints does not mark this certificate as a CA.')
        }
        if ($e.Lifecycle -eq 'Historical' -and $chainStatus -eq 'Warning') { $chainStatus = 'Information' }
        $chainMsg = switch ($chainCode) {
            'OK' { 'Chain of {0} is complete and every signature verifies.' -f $target }
            'CHAIN_UNTRUSTED_ROOT' { 'Chain of {0} ends in a root that this computer does not trust.' -f $target }
            'CHAIN_PARTIAL' { 'Chain of {0} is incomplete: an issuer certificate was not found in AD or on the CA.' -f $target }
            'SIGNATURE_INVALID' { 'Chain of {0} has a signature that does not verify.' -f $target }
            default { 'Chain of {0} needs review.' -f $target }
        }
        $notes = ''
        if ($chainCode -eq 'CHAIN_UNTRUSTED_ROOT') { $notes = 'This is local trust on this computer, not an endpoint failure. Domain members normally receive AD roots through Group Policy.' }
        [void]$findings.Add((New-MspkiFinding -Stage Analysis -Category 'Hierarchy' -Role $e.Role -Target $target -RelatedCA $related `
            -Status $chainStatus -StatusCode $chainCode -Confidence $confidence -Sources $sources -Scope 'Local' `
            -Message $chainMsg -Evidence @($chainEv) -Notes $notes -Layers @{ ChainStatus = $chainLayer }))

        # Validity, limited by the parent's expiry.
        $isRoot = [bool]$i.SelfIssued
        if ($isRoot) { $warn = $t.RootCaWarningDays; $crit = $t.RootCaCriticalDays; $kind = 'root' }
        else { $warn = $t.IssuingCaWarningDays; $crit = $t.IssuingCaCriticalDays; $kind = 'subordinate' }
        $days = $i.DaysLeft
        $limitedBy = ''
        if ($null -ne $parent) {
            $pDays = [int][math]::Floor(($parent.NotAfter.ToUniversalTime() - $Now.ToUniversalTime()).TotalDays)
            if ($pDays -lt $days) { $days = $pDays; $limitedBy = $parent.Subject }
        }
        $ev = @(
            ('Valid from {0} to {1}' -f $i.NotBefore, $i.NotAfter),
            ('Days left: {0}{1}' -f $days, $(if ($limitedBy) { ' (limited by the parent {0}, which expires first)' -f $limitedBy } else { '' })),
            ('Thresholds ({0}): warning {1} days, critical {2} days' -f $kind, $warn, $crit),
            ('Lifecycle: {0} [{1}] ({2})' -f $e.Lifecycle, $e.LifecycleConfidence, $e.LifecycleBasis),
            ('Key: {0} {1}; signature: {2}' -f $i.KeyAlgorithm, $i.KeySize, $i.SignatureAlgorithm)
        )
        if ($null -ne $parent) { $ev += ('Parent: {0} [{1}] valid until {2}' -f $parent.Subject, $parent.Thumbprint, $parent.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) }
        if ($e.Lifecycle -eq 'Historical') {
            if ($i.DaysLeft -lt 0) {
                $st = 'NotApplicable'; $code = 'NOT_APPLICABLE'
                $msg = 'Historical CA certificate of {0} expired on {1} (expected for a renewed CA).' -f $target, $i.NotAfter
            }
            else {
                $st = 'Pass'; $code = 'OK'
                $msg = 'Historical CA certificate of {0} is still valid for {1} days.' -f $target, $i.DaysLeft
            }
        }
        elseif ($days -lt 0) {
            $st = 'Critical'; $code = 'OBJECT_EXPIRED'
            $msg = 'CA certificate of {0} has expired ({1}).' -f $target, $(if ($limitedBy) { 'its parent expired' } else { $i.NotAfter })
        }
        elseif ($days -le $crit) {
            $st = 'Critical'; $code = 'OBJECT_EXPIRING'
            $msg = 'CA certificate of {0} expires in {1} days (critical threshold {2}).' -f $target, $days, $crit
        }
        elseif ($days -le $warn) {
            $st = 'Warning'; $code = 'OBJECT_EXPIRING'
            $msg = 'CA certificate of {0} expires in {1} days (warning threshold {2}).' -f $target, $days, $warn
        }
        else {
            $st = 'Pass'; $code = 'OK'
            $msg = 'CA certificate of {0} is valid for {1} more days.' -f $target, $days
        }
        $notes = ''
        if ($lifeConfidence -eq 'Inferred') { $notes = 'Current/historical is inferred from certificate dates; the status assumes this is the certificate in use.' }
        if ($e.Lifecycle -eq 'Historical') { $notes = 'An expired historical CA certificate may still be needed to validate older certificates and CRLs.' }
        [void]$findings.Add((New-MspkiFinding -Stage Analysis -Category 'CA' -Role $e.Role -Target $target -RelatedCA $related `
            -Status $st -StatusCode $code -Confidence $lifeConfidence -Sources $sources -Scope 'Local' `
            -Message $msg -Evidence $ev -Notes $notes -Layers @{ ContentStatus = 'Pass' }))
    }
    return , $findings.ToArray()
}
