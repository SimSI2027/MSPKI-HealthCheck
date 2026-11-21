# Certificate helpers: load public certificates from bytes or Base64 text and describe them as plain
# data (no private keys are ever loaded or exported).

$script:MspkiOid = @{
    BasicConstraints   = '2.5.29.19'
    KeyUsage           = '2.5.29.15'
    SubjectKeyId       = '2.5.29.14'
    CAVersion          = '1.3.6.1.4.1.311.21.1'
    PreviousCAHash     = '1.3.6.1.4.1.311.21.2'
}

function New-MspkiCertificate {
    <#
    .SYNOPSIS
    Creates a public X509Certificate2 from DER bytes, or from Base64/PEM text (as returned by the CA with
    CR_OUT_BASE64). The .NET constructor decodes Base64 itself, so no Base64 handling is needed here.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Bytes')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')][byte[]]$Bytes,
        [Parameter(Mandatory = $true, ParameterSetName = 'Text')][string]$Text
    )
    if ($PSCmdlet.ParameterSetName -eq 'Text') { $Bytes = [System.Text.Encoding]::ASCII.GetBytes($Text.Trim()) }
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $Bytes)
    return $c
}

function ConvertTo-MspkiHex {
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    return ([System.BitConverter]::ToString($Bytes) -replace '-', '')
}

function Get-MspkiSha256Hex {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (ConvertTo-MspkiHex $sha.ComputeHash($Bytes)) } finally { $sha.Dispose() }
}

function Get-MspkiCertificateExtension {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$Oid
    )
    foreach ($e in $Certificate.Extensions) { if ($e.Oid.Value -eq $Oid) { return $e } }
    return $null
}

function ConvertFrom-MspkiCAVersionExtension {
    <#
    .SYNOPSIS
    Decodes the Microsoft CA Version extension (a DER INTEGER: key index << 16 | certificate index).
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$RawData)
    if ($null -eq $RawData -or $RawData.Length -lt 3 -or $RawData[0] -ne 0x02) { return $null }
    $len = [int]$RawData[1]
    if ($len -lt 1 -or $len -gt 4 -or $RawData.Length -lt (2 + $len)) { return $null }
    [int64]$v = 0
    for ($i = 0; $i -lt $len; $i++) { $v = ($v * 256) + $RawData[2 + $i] }
    $certIndex = [int]($v % 65536)
    $keyIndex = [int][math]::Floor($v / 65536)
    return [pscustomobject]@{
        CertIndex = $certIndex
        KeyIndex  = $keyIndex
        Label     = ('V{0}.{1}' -f $certIndex, $keyIndex)
    }
}

function ConvertFrom-MspkiPreviousCAHashExtension {
    <#
    .SYNOPSIS
    Decodes the Microsoft Previous CA Certificate Hash extension (DER OCTET STRING) to a hex string.
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$RawData)
    if ($null -eq $RawData -or $RawData.Length -lt 3 -or $RawData[0] -ne 0x04) { return '' }
    $len = [int]$RawData[1]
    if ($len -lt 1 -or $len -gt 64 -or $RawData.Length -lt (2 + $len)) { return '' }
    $b = New-Object byte[] $len
    [Array]::Copy($RawData, 2, $b, 0, $len)
    return (ConvertTo-MspkiHex $b)
}

function Get-MspkiPublicKeyInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $alg = [string]$Certificate.PublicKey.Oid.FriendlyName
    $size = 0
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
        if ($null -ne $rsa) { $size = $rsa.KeySize; $alg = 'RSA'; $rsa.Dispose() }
    }
    catch { }
    if ($size -eq 0) {
        try {
            $ec = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Certificate)
            if ($null -ne $ec) { $size = $ec.KeySize; $alg = 'ECDSA'; $ec.Dispose() }
        }
        catch { }
    }
    return [pscustomobject]@{ Algorithm = $alg; KeySize = $size }
}

function Get-MspkiCertificateInfo {
    <#
    .SYNOPSIS
    Describes a certificate as plain data (strings and numbers only, dates in ISO 8601 UTC).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [DateTime]$Now = [DateTime]::UtcNow
    )
    $c = $Certificate
    $bc = Get-MspkiCertificateExtension -Certificate $c -Oid $script:MspkiOid.BasicConstraints
    $isCA = $null; $pathLen = $null
    if ($null -ne $bc) {
        $bce = New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($bc, $bc.Critical)
        $isCA = $bce.CertificateAuthority
        if ($bce.HasPathLengthConstraint) { $pathLen = $bce.PathLengthConstraint }
    }
    $ku = Get-MspkiCertificateExtension -Certificate $c -Oid $script:MspkiOid.KeyUsage
    $kuText = ''
    if ($null -ne $ku) {
        $kue = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension($ku, $ku.Critical)
        $kuText = [string]$kue.KeyUsages
    }
    $ski = Get-MspkiCertificateExtension -Certificate $c -Oid $script:MspkiOid.SubjectKeyId
    $skiText = ''
    if ($null -ne $ski) {
        $skie = New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($ski, $ski.Critical)
        $skiText = [string]$skie.SubjectKeyIdentifier
    }
    $ver = $null
    $verExt = Get-MspkiCertificateExtension -Certificate $c -Oid $script:MspkiOid.CAVersion
    if ($null -ne $verExt) { $ver = ConvertFrom-MspkiCAVersionExtension -RawData $verExt.RawData }
    $prev = ''
    $prevExt = Get-MspkiCertificateExtension -Certificate $c -Oid $script:MspkiOid.PreviousCAHash
    if ($null -ne $prevExt) { $prev = ConvertFrom-MspkiPreviousCAHashExtension -RawData $prevExt.RawData }
    $key = Get-MspkiPublicKeyInfo -Certificate $c
    $notAfterUtc = $c.NotAfter.ToUniversalTime()
    $daysLeft = [int][math]::Floor(($notAfterUtc - $Now.ToUniversalTime()).TotalDays)

    $verLabel = ''; $certIdx = $null; $keyIdx = $null
    if ($null -ne $ver) { $verLabel = $ver.Label; $certIdx = $ver.CertIndex; $keyIdx = $ver.KeyIndex }

    return [pscustomobject][ordered]@{
        Subject            = $c.Subject
        Issuer             = $c.Issuer
        Thumbprint         = $c.Thumbprint
        Sha256             = (Get-MspkiSha256Hex -Bytes $c.RawData)
        SerialNumber       = $c.SerialNumber
        NotBefore          = $c.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        NotAfter           = $notAfterUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        DaysLeft           = $daysLeft
        SelfIssued         = ($c.SubjectName.RawData.Length -gt 0 -and
                              (ConvertTo-MspkiHex $c.SubjectName.RawData) -eq (ConvertTo-MspkiHex $c.IssuerName.RawData))
        IsCA               = $isCA
        PathLength         = $pathLen
        KeyUsage           = $kuText
        KeyAlgorithm       = $key.Algorithm
        KeySize            = $key.KeySize
        SignatureAlgorithm = [string]$c.SignatureAlgorithm.FriendlyName
        SubjectKeyId       = $skiText
        CAVersion          = $verLabel
        CertIndex          = $certIdx
        KeyIndex           = $keyIdx
        PreviousCAHash     = $prev
    }
}
