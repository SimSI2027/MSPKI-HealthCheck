# Shared helpers for the Pester tests. Test certificates are generated in memory with the .NET
# CertificateRequest class (.NET Framework 4.7.2+). They use example.test names only and are never
# written to a certificate store.

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:ModulePath = Join-Path $script:RepoRoot 'src\MspkiHealthCheck.psd1'
$script:FixturePath = Join-Path $PSScriptRoot 'fixtures'

function ConvertTo-TestDerInteger {
    param([int64]$Value)
    $bytes = New-Object System.Collections.Generic.List[byte]
    $v = $Value
    do { $bytes.Insert(0, [byte]($v % 256)); $v = [math]::Floor($v / 256) } while ($v -gt 0)
    if ($bytes[0] -ge 0x80) { $bytes.Insert(0, [byte]0) }
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add([byte]0x02); $out.Add([byte]$bytes.Count); $out.AddRange($bytes)
    return , $out.ToArray()
}

function New-TestCertificate {
    <#
    Returns @{ Full = certificate with private key (only for signing other test certificates);
               Public = public-only X509Certificate2 }.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        $Signer = $null,
        [int]$DaysBefore = 30,
        [int]$DaysValid = 365,
        [bool]$IsCA = $true,
        [int64]$CAVersion = -1,
        [string]$PreviousHashHex = ''
    )
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($Subject, $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($IsCA, $false, 0, $true)))
    $ku = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'KeyCertSign, CrlSign, DigitalSignature'
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension($ku, $true)))
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($req.PublicKey, $false)))
    if ($CAVersion -ge 0) {
        $der = ConvertTo-TestDerInteger -Value $CAVersion
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509Extension('1.3.6.1.4.1.311.21.1', $der, $false)))
    }
    if ($PreviousHashHex) {
        $h = New-Object byte[] ($PreviousHashHex.Length / 2)
        for ($i = 0; $i -lt $h.Length; $i++) { $h[$i] = [Convert]::ToByte($PreviousHashHex.Substring($i * 2, 2), 16) }
        $der = [byte[]](@([byte]0x04, [byte]$h.Length) + $h)
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509Extension('1.3.6.1.4.1.311.21.2', $der, $false)))
    }
    $nb = [DateTimeOffset]::UtcNow.AddDays(-$DaysBefore)
    $na = [DateTimeOffset]::UtcNow.AddDays($DaysValid)
    if ($null -eq $Signer) {
        $full = $req.CreateSelfSigned($nb, $na)
    }
    else {
        $serial = New-Object byte[] 16
        (New-Object System.Random).NextBytes($serial)
        $serial[0] = $serial[0] -band 0x7F
        $issued = $req.Create($Signer, $nb, $na, $serial)
        $full = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issued, $rsa)
    }
    $public = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $full.RawData)
    return [pscustomobject]@{ Full = $full; Public = $public }
}

function ConvertTo-TestBase64 {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes)
}

function Get-TestLdapRecord {
    <#
    Loads a JSON fixture as an LDAP record (lower-case attribute -> array of values).
    #>
    param([Parameter(Mandatory = $true)][string]$Name)
    $obj = Get-Content -LiteralPath (Join-Path $script:FixturePath $Name) -Raw | ConvertFrom-Json
    $rec = @{}
    foreach ($p in $obj.psobject.Properties) { $rec[$p.Name.ToLowerInvariant()] = @($p.Value) }
    return $rec
}
