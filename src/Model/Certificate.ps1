# Certificate helpers: load public certificates from bytes or Base64 data and describe them as plain
# data (no private keys are ever loaded or exported).

$script:MspkiOid = @{
    BasicConstraints   = '2.5.29.19'
    KeyUsage           = '2.5.29.15'
    SubjectKeyId       = '2.5.29.14'
    AuthorityKeyId     = '2.5.29.35'
    CAVersion          = '1.3.6.1.4.1.311.21.1'
    PreviousCAHash     = '1.3.6.1.4.1.311.21.2'
}

function New-MspkiCertificate {
    <#
    .SYNOPSIS
    Creates a public X509Certificate2 from DER bytes, or from Base64/PEM text (as returned by the CA with
    CR_OUT_BASE64). Text is decoded as data by ConvertFrom-MspkiBase64Data and only ever parsed as a certificate.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Bytes')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')][byte[]]$Bytes,
        [Parameter(Mandatory = $true, ParameterSetName = 'Text')][string]$Text
    )
    if ($PSCmdlet.ParameterSetName -eq 'Text') { $Bytes = ConvertFrom-MspkiBase64Data -Text $Text }
    # Only a single certificate is ever built (audit 2 M10). The content type is checked first: the byte[] constructor also
    # accepts a PKCS #12 / PFX and then writes its private key to a key container in the user profile.
    $type = Get-MspkiCertificateContentType -Bytes $Bytes
    if ($type -ne 'Cert') { throw (Get-MspkiRefusedContentText -ContentType $type) }
    $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Bytes, [string]$null, (Get-MspkiNoPersistKeyFlag))
    return $c
}

function Get-MspkiCertificateContentType {
    <#
    .SYNOPSIS
    Names what certificate-shaped bytes are, without building any certificate object: Cert (one DER/Base64 certificate), Pkcs7,
    Pkcs12 (PKCS #12 / PFX), another X509ContentType name (SerializedCert, SerializedStore, Authenticode), or Unknown.
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return 'Unknown' }
    try { $t = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Bytes) }
    catch { return 'Unknown' }
    # Pfx and Pkcs12 share one value, so the value is compared, not the name.
    switch ([int]$t) {
        1 { return 'Cert' }
        3 { return 'Pkcs12' }
        5 { return 'Pkcs7' }
        0 { return 'Unknown' }
        default { return [string]$t }
    }
}

function Get-MspkiRefusedContentText {
    [CmdletBinding()]
    param([string]$ContentType)
    if ($ContentType -eq 'Pkcs12') {
        return 'The data is a PKCS #12 / PFX file, not a certificate. It was refused before any certificate object was built: loading it could write a private key to this computer.'
    }
    return ('The data is not a single certificate (content type {0}); only a DER or Base64 certificate, or a PKCS #7 with certificates, is read.' -f $ContentType)
}

function Get-MspkiNoPersistKeyFlag {
    <#
    .SYNOPSIS
    Key storage flags for loading downloaded certificate data: EphemeralKeySet (.NET Framework 4.7.2 and later) so that no key can
    ever be written to disk, otherwise DefaultKeySet. Only Cert and Pkcs7 content, which never carries a key, is loaded anyway.
    #>
    [CmdletBinding()]
    param()
    $t = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]
    if ([Enum]::GetNames($t) -contains 'EphemeralKeySet') { return [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'EphemeralKeySet' }
    return [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
}

function ConvertFrom-MspkiCertificateBytes {
    <#
    .SYNOPSIS
    Reads downloaded certificate data (AIA file, NDES GetCACert answer): one certificate, or the certificates of a PKCS #7. The
    content type is checked before any object is built; PKCS #12 / PFX and every other type is refused, so downloaded bytes can
    never create a key on disk.

    .OUTPUTS
    { ContentType; Certificates (X509Certificate2[]); Error ('' when read) }
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Bytes)
    $out = [pscustomobject]@{ ContentType = (Get-MspkiCertificateContentType -Bytes $Bytes); Certificates = @(); Error = '' }
    try {
        if ($out.ContentType -eq 'Cert') { $out.Certificates = @(New-MspkiCertificate -Bytes $Bytes) }
        elseif ($out.ContentType -eq 'Pkcs7') {
            $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
            $col.Import($Bytes, [string]$null, (Get-MspkiNoPersistKeyFlag))
            $out.Certificates = @($col | ForEach-Object { $_ })
        }
        else { $out.Error = Get-MspkiRefusedContentText -ContentType $out.ContentType }
    }
    catch { $out.Error = (Get-MspkiErrorInfo $_).Message; $out.Certificates = @() }
    return $out
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

function Get-MspkiAuthorityKeyIdHex {
    <#
    .SYNOPSIS
    The keyIdentifier of an Authority Key Identifier extension value (DER SEQUENCE { [0] keyIdentifier, ... }) as upper-case
    hex; '' when the value has none.
    #>
    [CmdletBinding()]
    param([AllowNull()][byte[]]$Value)
    if ($null -eq $Value -or $Value.Length -lt 4 -or $Value[0] -ne 0x30) { return '' }
    try {
        $top = Read-MspkiDerElement -Bytes $Value -Offset 0
        foreach ($k in (Get-MspkiDerChild -Bytes $Value -Element $top)) {
            if ($k.Tag -eq 0x80) { return (ConvertTo-MspkiHex (Get-MspkiDerBytes -Bytes $Value -Element $k)) }
        }
    }
    catch { }
    return ''
}

function Get-MspkiCertificateSubjectKeyId {
    <#
    .SYNOPSIS
    The Subject Key Identifier of a certificate as upper-case hex ('' when the certificate has none).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $ski = Get-MspkiCertificateExtension -Certificate $Certificate -Oid $script:MspkiOid.SubjectKeyId
    if ($null -eq $ski) { return '' }
    try { return ([string](New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($ski, $ski.Critical)).SubjectKeyIdentifier).ToUpperInvariant() }
    catch { return '' }
}

function Get-MspkiCertificateAuthorityKeyId {
    <#
    .SYNOPSIS
    The Authority Key Identifier (keyIdentifier) of a certificate as upper-case hex ('' when absent): the key that signed it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $aki = Get-MspkiCertificateExtension -Certificate $Certificate -Oid $script:MspkiOid.AuthorityKeyId
    if ($null -eq $aki) { return '' }
    return (Get-MspkiAuthorityKeyIdHex -Value $aki.RawData)
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
        AuthorityKeyId     = (Get-MspkiCertificateAuthorityKeyId -Certificate $c)
        CAVersion          = $verLabel
        CertIndex          = $certIdx
        KeyIndex           = $keyIdx
        PreviousCAHash     = $prev
    }
}
