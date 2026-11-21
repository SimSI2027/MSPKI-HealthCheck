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

function New-TestDer {
    # One DER element: tag byte + definite length + content.
    param([int]$Tag, [byte[]]$Content = @())
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add([byte]$Tag)
    $n = $Content.Length
    if ($n -lt 0x80) { $out.Add([byte]$n) }
    elseif ($n -lt 0x100) { $out.Add([byte]0x81); $out.Add([byte]$n) }
    else { $out.Add([byte]0x82); $out.Add([byte]($n -shr 8)); $out.Add([byte]($n -band 0xFF)) }
    if ($n -gt 0) { $out.AddRange($Content) }
    return , $out.ToArray()
}

function Join-TestBytes {
    param([object[]]$Parts)
    $out = New-Object System.Collections.Generic.List[byte]
    foreach ($p in $Parts) { $out.AddRange([byte[]]$p) }
    return , $out.ToArray()
}

function New-TestCdpExtensionValue {
    param([string[]]$Urls)
    $names = Join-TestBytes @($Urls | ForEach-Object { , (New-TestDer -Tag 0x86 -Content ([System.Text.Encoding]::ASCII.GetBytes($_))) })
    $dp = New-TestDer -Tag 0x30 -Content (New-TestDer -Tag 0xA0 -Content (New-TestDer -Tag 0xA0 -Content $names))
    return , (New-TestDer -Tag 0x30 -Content $dp)
}

function New-TestAiaExtensionValue {
    param([string[]]$CaIssuers = @(), [string[]]$Ocsp = @())
    $caOid = [byte[]](0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02)
    $ocspOid = [byte[]](0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01)
    $items = @()
    foreach ($u in $CaIssuers) { $items += , (New-TestDer -Tag 0x30 -Content (Join-TestBytes @($caOid, (New-TestDer -Tag 0x86 -Content ([System.Text.Encoding]::ASCII.GetBytes($u)))))) }
    foreach ($u in $Ocsp) { $items += , (New-TestDer -Tag 0x30 -Content (Join-TestBytes @($ocspOid, (New-TestDer -Tag 0x86 -Content ([System.Text.Encoding]::ASCII.GetBytes($u)))))) }
    return , (New-TestDer -Tag 0x30 -Content (Join-TestBytes $items))
}

function New-TestCertificate {
    <#
    Returns @{ Full = certificate with private key (only for signing other test certificates);
               Public = public-only X509Certificate2; Key = the key (to re-issue with the same key) }.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        $Signer = $null,
        [int]$DaysBefore = 30,
        [int]$DaysValid = 365,
        [bool]$IsCA = $true,
        [int64]$CAVersion = -1,
        [string]$PreviousHashHex = '',
        [string[]]$CdpUrls = @(),
        [string[]]$AiaUrls = @(),
        [string[]]$OcspUrls = @(),
        [switch]$Ecdsa,
        $Key = $null
    )
    if ($Ecdsa) {
        $rsa = $Key
        if ($null -eq $rsa) { $rsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256) }
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($Subject, $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    }
    else {
        $rsa = $Key
        if ($null -eq $rsa) { $rsa = [System.Security.Cryptography.RSA]::Create(2048) }
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($Subject, $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
    if ($CdpUrls.Count -gt 0) {
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509Extension('2.5.29.31', (New-TestCdpExtensionValue -Urls $CdpUrls), $false)))
    }
    if ($AiaUrls.Count -gt 0 -or $OcspUrls.Count -gt 0) {
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509Extension('1.3.6.1.5.5.7.1.1', (New-TestAiaExtensionValue -CaIssuers $AiaUrls -Ocsp $OcspUrls), $false)))
    }
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
        if ($Ecdsa) { $full = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($issued, $rsa) }
        else { $full = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issued, $rsa) }
    }
    $public = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $full.RawData)
    return [pscustomobject]@{ Full = $full; Public = $public; Key = $rsa }
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

function New-TestCrl {
    <#
    Builds a signed DER CRL (v2) for an issuer from New-TestCertificate (RSA). HoursValid is the lifetime
    from thisUpdate to nextUpdate; thisUpdate is HoursBefore hours ago.
    #>
    param(
        [Parameter(Mandatory = $true)]$Issuer,
        [double]$HoursBefore = 24,
        [double]$HoursValid = 240,
        [int]$Number = 1,
        [switch]$Delta,
        [int]$BaseNumber = 1,
        [string[]]$FreshestUrls = @(),
        [switch]$NoNextUpdate,
        [int64]$CAVersion = -1,
        $SigningKey = $null
    )
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $now = [DateTime]::UtcNow
    $thisUpd = $now.AddHours(-$HoursBefore)
    $next = $thisUpd.AddHours($HoursValid)
    $alg = New-TestDer 0x30 (Join-TestBytes @((New-TestDer 0x06 ([byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B))), (New-TestDer 0x05)))
    $exts = @()
    $exts += , (New-TestDer 0x30 (Join-TestBytes @((New-TestDer 0x06 ([byte[]](0x55, 0x1D, 0x14))), (New-TestDer 0x04 (ConvertTo-TestDerInteger $Number)))))
    if ($Delta) {
        $exts += , (New-TestDer 0x30 (Join-TestBytes @((New-TestDer 0x06 ([byte[]](0x55, 0x1D, 0x1B))), (New-TestDer 0x01 ([byte[]](0xFF))), (New-TestDer 0x04 (ConvertTo-TestDerInteger $BaseNumber)))))
    }
    if ($FreshestUrls.Count -gt 0) {
        $exts += , (New-TestDer 0x30 (Join-TestBytes @((New-TestDer 0x06 ([byte[]](0x55, 0x1D, 0x2E))), (New-TestDer 0x04 (New-TestCdpExtensionValue -Urls $FreshestUrls)))))
    }
    if ($CAVersion -ge 0) {
        $exts += , (New-TestDer 0x30 (Join-TestBytes @((New-TestDer 0x06 ([byte[]](0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x01))), (New-TestDer 0x04 (ConvertTo-TestDerInteger $CAVersion)))))
    }
    $parts = @()
    $parts += , (New-TestDer 0x02 ([byte[]](0x01)))
    $parts += , $alg
    $parts += , ([byte[]]$Issuer.Public.SubjectName.RawData)
    $parts += , (New-TestDer 0x17 ([System.Text.Encoding]::ASCII.GetBytes($thisUpd.ToString('yyMMddHHmmss', $inv) + 'Z')))
    if (-not $NoNextUpdate) { $parts += , (New-TestDer 0x17 ([System.Text.Encoding]::ASCII.GetBytes($next.ToString('yyMMddHHmmss', $inv) + 'Z'))) }
    $parts += , (New-TestDer 0xA0 (New-TestDer 0x30 (Join-TestBytes $exts)))
    $tbs = New-TestDer 0x30 (Join-TestBytes $parts)
    $key = $SigningKey
    if ($null -eq $key) { $key = $Issuer.Key }
    $sig = $key.SignData($tbs, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $bits = New-TestDer 0x03 (Join-TestBytes @(([byte[]](0x00)), $sig))
    return , (New-TestDer 0x30 (Join-TestBytes @($tbs, $alg, $bits)))
}

function Start-TestHttpServer {
    <#
    Minimal HTTP/1.1 server on 127.0.0.1 (random port) in a background runspace, for probe tests only.
    Routes: path -> @{ Status; Body = [byte[]]; Headers = @{} }. Requests are logged with their headers.
    #>
    param([hashtable]$Routes)
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $log = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $ps = [System.Management.Automation.PowerShell]::Create()
    [void]$ps.AddScript({
        param($listener, $routes, $log)
        while ($true) {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII, $false, 4096, $true)
                $line = $reader.ReadLine()
                $headers = @()
                while ($true) { $h = $reader.ReadLine(); if ($null -eq $h -or $h -eq '') { break }; $headers += $h }
                $path = ($line -split ' ')[1]
                [void]$log.Add([pscustomobject]@{ Path = $path; Headers = $headers })
                $route = $routes[$path]
                if ($null -eq $route) { $route = @{ Status = 404; Body = [System.Text.Encoding]::ASCII.GetBytes('not found'); Headers = @{} } }
                $body = [byte[]]$route.Body
                $hdr = "HTTP/1.1 {0} Test`r`nContent-Length: {1}`r`nConnection: close`r`n" -f $route.Status, $body.Length
                if ($route.Headers) { foreach ($k in $route.Headers.Keys) { $hdr += ("{0}: {1}`r`n" -f $k, $route.Headers[$k]) } }
                $hdr += "`r`n"
                $hb = [System.Text.Encoding]::ASCII.GetBytes($hdr)
                $stream.Write($hb, 0, $hb.Length)
                if ($body.Length -gt 0) { $stream.Write($body, 0, $body.Length) }
                $stream.Flush()
            }
            catch { }
            finally { $client.Close() }
        }
    }).AddArgument($listener).AddArgument($Routes).AddArgument($log)
    $handle = $ps.BeginInvoke()
    $port = $listener.LocalEndpoint.Port
    return [pscustomobject]@{ Listener = $listener; PowerShell = $ps; Handle = $handle; Port = $port; Base = ('http://127.0.0.1:{0}' -f $port); Log = $log }
}

function Stop-TestHttpServer {
    param($Server)
    try { $Server.Listener.Stop() } catch { }
    try { [void]$Server.PowerShell.BeginStop($null, $null) } catch { }
}
