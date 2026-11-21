# CRL decoding (RFC 5280 CertificateList) with the DER reader. Read-only; nothing is cached on disk.

$script:MspkiCrlOid = @{
    CrlNumber      = '2.5.29.20'
    DeltaIndicator = '2.5.29.27'
    Idp            = '2.5.29.28'
    FreshestCRL    = '2.5.29.46'
    AuthorityKeyId = '2.5.29.35'
    CAVersion      = '1.3.6.1.4.1.311.21.1'
    NextPublish    = '1.3.6.1.4.1.311.21.4'
}

function ConvertFrom-MspkiPem {
    <#
    .SYNOPSIS
    Returns DER bytes unchanged. PEM/Base64 CRLs are not decoded here (no Base64 handling in the tool);
    the caller reports them as an unexpected format.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Bytes.Length -gt 0 -and $Bytes[0] -eq 0x30) { return , $Bytes }
    throw 'Not DER encoded (the first byte is not a SEQUENCE). PEM or other formats are not expected at CDP locations.'
}

function ConvertFrom-MspkiCrl {
    <#
    .SYNOPSIS
    Decodes a DER CRL: issuer, thisUpdate, nextUpdate, CRL number, base or delta, Freshest CRL URLs,
    revoked entry count and signature algorithm.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $b = ConvertFrom-MspkiPem -Bytes $Bytes
    $root = Read-MspkiDerElement -Bytes $b -Offset 0
    if ($root.End -ne $b.Length) { throw 'CRL: trailing data after the CertificateList.' }
    $top = Get-MspkiDerChild -Bytes $b -Element $root
    if ($top.Count -ne 3 -or $top[0].Tag -ne 0x30) { throw 'CRL: CertificateList structure not found.' }
    $kids = Get-MspkiDerChild -Bytes $b -Element $top[0]
    $i = 0
    if ($kids[$i].Tag -eq 0x02) { $i++ }          # version
    $i++                                          # signature algorithm
    $issuerEl = $kids[$i]; $i++
    if ($issuerEl.Tag -ne 0x30) { throw 'CRL: issuer name not found.' }
    $thisUpdate = ConvertFrom-MspkiDerTime -Bytes $b -Element $kids[$i]; $i++
    $nextUpdate = $null
    if ($i -lt $kids.Count -and ($kids[$i].Tag -eq 0x17 -or $kids[$i].Tag -eq 0x18)) { $nextUpdate = ConvertFrom-MspkiDerTime -Bytes $b -Element $kids[$i]; $i++ }
    $revoked = 0
    if ($i -lt $kids.Count -and $kids[$i].Tag -eq 0x30) { $revoked = (Get-MspkiDerChild -Bytes $b -Element $kids[$i]).Count; $i++ }

    $crlNumber = ''; $isDelta = $false; $baseNumber = ''; $freshest = @(); $caVersion = ''; $nextPublish = $null; $hasIdp = $false
    if ($i -lt $kids.Count -and $kids[$i].Tag -eq 0xA0) {
        $extSeq = (Get-MspkiDerChild -Bytes $b -Element $kids[$i])[0]
        foreach ($ext in (Get-MspkiDerChild -Bytes $b -Element $extSeq)) {
            $parts = Get-MspkiDerChild -Bytes $b -Element $ext
            $oid = ConvertFrom-MspkiDerOid -Content (Get-MspkiDerBytes -Bytes $b -Element $parts[0])
            $valEl = $parts[$parts.Count - 1]
            $val = Get-MspkiDerBytes -Bytes $b -Element $valEl
            switch ($oid) {
                ($script:MspkiCrlOid.CrlNumber) {
                    $n = Read-MspkiDerElement -Bytes $val
                    $crlNumber = ConvertFrom-MspkiDerInteger -Content (Get-MspkiDerBytes -Bytes $val -Element $n)
                }
                ($script:MspkiCrlOid.DeltaIndicator) {
                    $isDelta = $true
                    $n = Read-MspkiDerElement -Bytes $val
                    $baseNumber = ConvertFrom-MspkiDerInteger -Content (Get-MspkiDerBytes -Bytes $val -Element $n)
                }
                ($script:MspkiCrlOid.FreshestCRL) { $freshest = Get-MspkiGeneralNameUri -Bytes $val }
                ($script:MspkiCrlOid.Idp) { $hasIdp = $true }
                ($script:MspkiCrlOid.CAVersion) {
                    $v = ConvertFrom-MspkiCAVersionExtension -RawData $val
                    if ($null -ne $v) { $caVersion = $v.Label }
                }
                ($script:MspkiCrlOid.NextPublish) {
                    $n = Read-MspkiDerElement -Bytes $val
                    try { $nextPublish = ConvertFrom-MspkiDerTime -Bytes $val -Element $n } catch { }
                }
            }
        }
    }
    $algKids = Get-MspkiDerChild -Bytes $b -Element $top[1]
    $issuerRaw = Get-MspkiDerBytes -Bytes $b -Element $issuerEl -WithHeader
    $issuerName = (New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName(, $issuerRaw)).Name
    return [pscustomobject][ordered]@{
        Issuer             = $issuerName
        IssuerRawHex       = (ConvertTo-MspkiHex $issuerRaw)
        ThisUpdate         = $thisUpdate
        NextUpdate         = $nextUpdate
        NextPublish        = $nextPublish
        CrlNumber          = $crlNumber
        IsDelta            = $isDelta
        BaseCrlNumber      = $baseNumber
        FreshestCrlUrls    = $freshest
        HasIdp             = $hasIdp
        CAVersion          = $caVersion
        RevokedCount       = $revoked
        SignatureAlgorithm = (ConvertFrom-MspkiDerOid -Content (Get-MspkiDerBytes -Bytes $b -Element $algKids[0]))
        Sha1               = (ConvertTo-MspkiHex ([System.Security.Cryptography.SHA1]::Create().ComputeHash($b)))
        Bytes              = $b
    }
}

function Get-MspkiCrlFreshness {
    <#
    .SYNOPSIS
    Percentage of the CRL lifetime used and time remaining. Status Pass < warn% <= Warning < crit% <= Critical;
    Fail when expired; NotApplicable when there is no nextUpdate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Crl,
        [int]$WarningPercent = 75,
        [int]$CriticalPercent = 95,
        [DateTime]$Now = [DateTime]::UtcNow
    )
    $now = $Now.ToUniversalTime()
    if ($null -eq $Crl.NextUpdate) {
        return [pscustomobject]@{ Status = 'NotApplicable'; StatusCode = 'NOT_APPLICABLE'; PercentUsed = $null; HoursLeft = $null; ValidityHours = $null }
    }
    $total = ($Crl.NextUpdate - $Crl.ThisUpdate).TotalHours
    $used = ($now - $Crl.ThisUpdate).TotalHours
    $pct = 100
    if ($total -gt 0) { $pct = [math]::Round(($used / $total) * 100, 1) }
    $left = [math]::Round(($Crl.NextUpdate - $now).TotalHours, 1)
    if ($left -lt 0) { $st = 'Fail'; $code = 'OBJECT_EXPIRED' }
    elseif ($pct -ge $CriticalPercent) { $st = 'Critical'; $code = 'OBJECT_EXPIRING' }
    elseif ($pct -ge $WarningPercent) { $st = 'Warning'; $code = 'OBJECT_EXPIRING' }
    elseif ($Crl.ThisUpdate -gt $now.AddMinutes(10)) { $st = 'Warning'; $code = 'STALE_DATA' }
    else { $st = 'Pass'; $code = 'OK' }
    return [pscustomobject]@{ Status = $st; StatusCode = $code; PercentUsed = $pct; HoursLeft = $left; ValidityHours = [math]::Round($total, 1) }
}
