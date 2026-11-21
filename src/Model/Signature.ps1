# Signature checks for certificates and CRLs (both are SEQUENCE { tbs, signatureAlgorithm, BIT STRING }).
# Verified with the issuer's public key through .NET, so no chain engine and no hidden network fetches.

$script:MspkiSignatureAlgorithms = @{
    '1.2.840.113549.1.1.5'  = @{ Key = 'RSA'; Hash = 'SHA1' }
    '1.2.840.113549.1.1.11' = @{ Key = 'RSA'; Hash = 'SHA256' }
    '1.2.840.113549.1.1.12' = @{ Key = 'RSA'; Hash = 'SHA384' }
    '1.2.840.113549.1.1.13' = @{ Key = 'RSA'; Hash = 'SHA512' }
    '1.2.840.113549.1.1.10' = @{ Key = 'RSAPSS'; Hash = '' }
    '1.2.840.10045.4.1'     = @{ Key = 'ECDSA'; Hash = 'SHA1' }
    '1.2.840.10045.4.3.2'   = @{ Key = 'ECDSA'; Hash = 'SHA256' }
    '1.2.840.10045.4.3.3'   = @{ Key = 'ECDSA'; Hash = 'SHA384' }
    '1.2.840.10045.4.3.4'   = @{ Key = 'ECDSA'; Hash = 'SHA512' }
}
$script:MspkiHashOids = @{
    '1.3.14.3.2.26' = 'SHA1'; '2.16.840.1.101.3.4.2.1' = 'SHA256'; '2.16.840.1.101.3.4.2.2' = 'SHA384'; '2.16.840.1.101.3.4.2.3' = 'SHA512'
}

function Split-MspkiSignedData {
    <#
    .SYNOPSIS
    Splits a DER certificate or CRL into the signed bytes, the signature algorithm OID (and PSS hash) and
    the signature value.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $root = Read-MspkiDerElement -Bytes $Bytes -Offset 0
    if ($root.Tag -ne 0x30) { throw 'Signed data: outer SEQUENCE missing.' }
    $top = Get-MspkiDerChild -Bytes $Bytes -Element $root
    if ($top.Count -ne 3 -or $top[0].Tag -ne 0x30 -or $top[1].Tag -ne 0x30 -or $top[2].Tag -ne 0x03) {
        throw 'Signed data: expected SEQUENCE { tbs, algorithm, BIT STRING }.'
    }
    $algKids = Get-MspkiDerChild -Bytes $Bytes -Element $top[1]
    $oid = ConvertFrom-MspkiDerOid -Content (Get-MspkiDerBytes -Bytes $Bytes -Element $algKids[0])
    $pssHash = ''
    if ($oid -eq '1.2.840.113549.1.1.10') {
        $pssHash = 'SHA1'
        if ($algKids.Count -gt 1 -and $algKids[1].Tag -eq 0x30) {
            foreach ($p in (Get-MspkiDerChild -Bytes $Bytes -Element $algKids[1])) {
                if ($p.Tag -eq 0xA0) {
                    $hashSeq = (Get-MspkiDerChild -Bytes $Bytes -Element $p)[0]
                    $hashOid = ConvertFrom-MspkiDerOid -Content (Get-MspkiDerBytes -Bytes $Bytes -Element (Get-MspkiDerChild -Bytes $Bytes -Element $hashSeq)[0])
                    if ($script:MspkiHashOids.ContainsKey($hashOid)) { $pssHash = $script:MspkiHashOids[$hashOid] }
                }
            }
        }
    }
    $bits = Get-MspkiDerBytes -Bytes $Bytes -Element $top[2]
    if ($bits.Length -lt 2 -or $bits[0] -ne 0) { throw 'Signed data: unexpected BIT STRING padding.' }
    $sig = New-Object byte[] ($bits.Length - 1)
    [Array]::Copy($bits, 1, $sig, 0, $sig.Length)
    return [pscustomobject]@{
        Tbs          = (Get-MspkiDerBytes -Bytes $Bytes -Element $top[0] -WithHeader)
        AlgorithmOid = $oid
        PssHash      = $pssHash
        Signature    = $sig
    }
}

function ConvertTo-MspkiP1363Signature {
    <#
    .SYNOPSIS
    Converts a DER ECDSA signature SEQUENCE { r, s } to the fixed-length r||s form .NET expects.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Der, [Parameter(Mandatory = $true)][int]$KeySize)
    $n = [int][math]::Ceiling($KeySize / 8)
    $root = Read-MspkiDerElement -Bytes $Der -Offset 0
    $kids = Get-MspkiDerChild -Bytes $Der -Element $root
    $out = New-Object byte[] ($n * 2)
    for ($k = 0; $k -lt 2; $k++) {
        $v = Get-MspkiDerBytes -Bytes $Der -Element $kids[$k]
        $start = 0
        while ($start -lt $v.Length - 1 -and $v[$start] -eq 0) { $start++ }
        $len = $v.Length - $start
        if ($len -gt $n) { throw 'ECDSA signature value is longer than the key size.' }
        [Array]::Copy($v, $start, $out, ($k * $n) + ($n - $len), $len)
    }
    return , $out
}

function Test-MspkiSignatureApiAvailable {
    <#
    .SYNOPSIS
    True when this .NET Framework has the public-key signature APIs that Test-MspkiSignature uses (HashAlgorithmName, the RSA and
    ECDsa certificate extensions): .NET Framework 4.6.2 or later. Without them nothing can be verified, and that is reported
    as "could not be checked", never as an invalid signature.
    #>
    [CmdletBinding()]
    param()
    foreach ($n in @('System.Security.Cryptography.HashAlgorithmName', 'System.Security.Cryptography.RSASignaturePadding',
            'System.Security.Cryptography.X509Certificates.RSACertificateExtensions', 'System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions')) {
        if (-not ($n -as [type])) { return $false }
    }
    return $true
}

function Test-MspkiSignature {
    <#
    .SYNOPSIS
    Verifies the signature of a DER certificate or CRL with the public key of Issuer.

    .OUTPUTS
    { Valid = $true | $false | $null (could not be checked); Algorithm; Reason }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$SignedBytes,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Issuer
    )
    $r = [pscustomobject]@{ Valid = $null; Algorithm = ''; Reason = '' }
    try { $sd = Split-MspkiSignedData -Bytes $SignedBytes }
    catch { $r.Reason = (Get-MspkiErrorInfo $_).Message; return $r }
    $r.Algorithm = $sd.AlgorithmOid
    if (-not (Test-MspkiSignatureApiAvailable)) {
        $r.Reason = 'This .NET Framework lacks the public-key signature APIs (4.6.2 or later is needed), so signatures cannot be checked.'
        return $r
    }
    if (-not $script:MspkiSignatureAlgorithms.ContainsKey($sd.AlgorithmOid)) { $r.Reason = 'Unsupported signature algorithm.'; return $r }
    $alg = $script:MspkiSignatureAlgorithms[$sd.AlgorithmOid]
    $hashName = $alg.Hash
    if ($alg.Key -eq 'RSAPSS') { $hashName = $sd.PssHash }
    try {
        $hash = New-Object System.Security.Cryptography.HashAlgorithmName($hashName)
        if ($alg.Key -eq 'RSA' -or $alg.Key -eq 'RSAPSS') {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Issuer)
            if ($null -eq $rsa) { $r.Reason = 'The issuer key is not RSA.'; $r.Valid = $false; return $r }
            $pad = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
            if ($alg.Key -eq 'RSAPSS') { $pad = [System.Security.Cryptography.RSASignaturePadding]::Pss }
            try { $r.Valid = [bool]$rsa.VerifyData($sd.Tbs, $sd.Signature, $hash, $pad) } finally { $rsa.Dispose() }
        }
        else {
            $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Issuer)
            if ($null -eq $ec) { $r.Reason = 'The issuer key is not ECDSA.'; $r.Valid = $false; return $r }
            try {
                $p1363 = ConvertTo-MspkiP1363Signature -Der $sd.Signature -KeySize $ec.KeySize
                $r.Valid = [bool]$ec.VerifyData($sd.Tbs, $p1363, $hash)
            }
            finally { $ec.Dispose() }
        }
        if (-not $r.Valid) { $r.Reason = 'The signature does not verify with the issuer public key.' }
    }
    catch { $r.Valid = $null; $r.Reason = (Get-MspkiErrorInfo $_).Message }
    return $r
}

function Test-MspkiTrustedRoot {
    <#
    .SYNOPSIS
    Read-only: is the certificate in this computer's Trusted Root Certification Authorities store.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
        $found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Thumbprint, $false)
        return ($found.Count -gt 0)
    }
    finally { $store.Close() }
}
