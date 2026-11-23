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
        $Key = $null,
        [switch]$WithAki,
        [string[]]$Eku = @(),
        [object[]]$Extensions = @()
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
    if ($Eku.Count -gt 0) {
        $oc = New-Object System.Security.Cryptography.OidCollection
        foreach ($o in $Eku) { [void]$oc.Add((New-Object System.Security.Cryptography.Oid($o))) }
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oc, $false)))
    }
    foreach ($x in $Extensions) { $req.CertificateExtensions.Add($x) }
    if ($CAVersion -ge 0) {
        $der = ConvertTo-TestDerInteger -Value $CAVersion
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509Extension('1.3.6.1.4.1.311.21.1', $der, $false)))
    }
    if ($WithAki -and $null -ne $Signer) {
        # Authority Key Identifier = the signer's Subject Key Identifier (CertificateRequest.Create does not add it).
        $skiExt = @($Signer.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.14' })[0]
        $skiHex = (New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($skiExt, $false)).SubjectKeyIdentifier
        $skiBytes = New-Object byte[] ($skiHex.Length / 2)
        for ($i = 0; $i -lt $skiBytes.Length; $i++) { $skiBytes[$i] = [Convert]::ToByte($skiHex.Substring($i * 2, 2), 16) }
        $akiDer = New-TestDer -Tag 0x30 -Content (New-TestDer -Tag 0x80 -Content $skiBytes)
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509Extension('2.5.29.35', $akiDer, $false)))
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
        # A child made a second after its issuer with the same lifetime would end after it, which Create() refuses (this made
        # LocalEvidence.Tests fail about every second run). Clamp to the issuer's end, and the start to its start.
        $sNa = [DateTimeOffset]$Signer.NotAfter.ToUniversalTime()
        $sNb = [DateTimeOffset]$Signer.NotBefore.ToUniversalTime()
        if ($na -gt $sNa) { $na = $sNa }
        if ($nb -lt $sNb) { $nb = $sNb }
        $issued = $req.Create($Signer, $nb, $na, $serial)
        if ($Ecdsa) { $full = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey($issued, $rsa) }
        else { $full = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issued, $rsa) }
    }
    $public = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $full.RawData)
    return [pscustomobject]@{ Full = $full; Public = $public; Key = $rsa }
}

function New-TestForgedCertificate {
    <#
    A certificate that carries somebody else's PUBLIC key (from -PublicKeyOf) but is signed with another key (-SigningKey) under the
    issuer name -IssuerName: what anyone can build, because the public key of a CA is public (audit 2 verification N1). Returns the
    public-only X509Certificate2.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$PublicKeyOf,
        [Parameter(Mandatory = $true)][string]$IssuerName,
        [Parameter(Mandatory = $true)]$SigningKey,
        [string[]]$CdpUrls = @(),
        [string[]]$AiaUrls = @(),
        [int]$DaysValid = 365
    )
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        (New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($Subject)), $PublicKeyOf.PublicKey,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($CdpUrls.Count -gt 0) {
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509Extension('2.5.29.31', (New-TestCdpExtensionValue -Urls $CdpUrls), $false)))
    }
    if ($AiaUrls.Count -gt 0) {
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509Extension('1.3.6.1.5.5.7.1.1', (New-TestAiaExtensionValue -CaIssuers $AiaUrls), $false)))
    }
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($true, $false, 0, $true)))
    $gen = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($SigningKey, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $serial = New-Object byte[] 16
    (New-Object System.Random).NextBytes($serial)
    $serial[0] = $serial[0] -band 0x7F
    $issued = $req.Create((New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName($IssuerName)), $gen,
        [DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays($DaysValid), $serial)
    return (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $issued.RawData))
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
        $SigningKey = $null,
        [string]$AuthorityKeyIdHex = ''
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
    if ($AuthorityKeyIdHex) {
        $akiBytes = New-Object byte[] ($AuthorityKeyIdHex.Length / 2)
        for ($i = 0; $i -lt $akiBytes.Length; $i++) { $akiBytes[$i] = [Convert]::ToByte($AuthorityKeyIdHex.Substring($i * 2, 2), 16) }
        $akiVal = New-TestDer 0x30 (New-TestDer 0x80 $akiBytes)
        $exts += , (New-TestDer 0x30 (Join-TestBytes @((New-TestDer 0x06 ([byte[]](0x55, 0x1D, 0x23))), (New-TestDer 0x04 $akiVal))))
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
                if (-not $line) { continue }   # a bare TCP connect (port probe) sends no request
                $headers = @()
                while ($true) { $h = $reader.ReadLine(); if ($null -eq $h -or $h -eq '') { break }; $headers += $h }
                $path = ($line -split ' ')[1]
                [void]$log.Add([pscustomobject]@{ Method = ($line -split " ")[0]; Path = $path; Headers = $headers })
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

function New-TestSecurityDescriptor {
    <#
    Builds a binary security descriptor like the one on an AD object. Each ACE is a hashtable:
    Sid, Type (Allow or Deny), Mask (int), ObjectType (GUID text, optional), Flags (AceFlags value, optional).
    #>
    param([string]$OwnerSid = "S-1-5-21-1111-2222-3333-512", [object[]]$Aces = @())
    $acl = New-Object System.Security.AccessControl.RawAcl(2, [math]::Max(1, $Aces.Count))
    $i = 0
    foreach ($a in $Aces) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($a.Sid)
        $flags = [System.Security.AccessControl.AceFlags]::None
        if ($a.Flags) { $flags = [System.Security.AccessControl.AceFlags][int]$a.Flags }
        $qual = [System.Security.AccessControl.AceQualifier]::AccessAllowed
        if ($a.Type -eq "Deny") { $qual = [System.Security.AccessControl.AceQualifier]::AccessDenied }
        if ($a.ObjectType) {
            $ace = New-Object System.Security.AccessControl.ObjectAce($flags, $qual, [int]$a.Mask, $sid,
                [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent, [guid]$a.ObjectType, [guid]::Empty, $false, $null)
        }
        else {
            $ace = New-Object System.Security.AccessControl.CommonAce($flags, $qual, [int]$a.Mask, $sid, $false, $null)
        }
        $acl.InsertAce($i, $ace)
        $i++
    }
    $owner = New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)
    $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor([System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent, $owner, $null, $null, $acl)
    $bytes = New-Object byte[] $sd.BinaryLength
    $sd.GetBinaryForm($bytes, 0)
    return , $bytes
}

function Remove-TestCertificateKey {
    <#
    Deletes the persisted private key of a test certificate that was loaded with PersistKeySet (a key in this user's key store). Safe to
    call for any certificate, more than once, and for a certificate without a key. A test that creates such a key calls this in a
    finally block (or registers the certificate the moment it exists and calls this for every one in AfterAll), so a failure part-way
    cannot leave a key behind. tests/zzz-KeyStoreLeftovers.Tests.ps1 checks that no key remains after the suite.
    #>
    param($Certificate)
    if ($null -eq $Certificate) { return }
    $rsa = $null
    try { $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) } catch { $rsa = $null }
    if ($null -eq $rsa) { return }
    try {
        if ($rsa -is [System.Security.Cryptography.RSACng]) { $rsa.Key.Delete() }
        elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $rsa.PersistKeyInCsp = $false; $rsa.Clear() }
    }
    catch { }
    try { $rsa.Dispose() } catch { }
}

function Get-TestKeyStoreSnapshot {
    <#
    The names of the private-key containers in this user's key store (CNG and CryptoAPI files) and the thumbprints of the certificates in
    CurrentUser\My, as sorted text lines. Names only: no key material is read.
    #>
    $lines = New-Object System.Collections.ArrayList
    $roots = @(
        @{ Tag = 'cng'; Path = (Join-Path $env:APPDATA 'Microsoft\Crypto\Keys') }
        @{ Tag = 'capi'; Path = (Join-Path $env:APPDATA 'Microsoft\Crypto\RSA') }
    )
    foreach ($r in $roots) {
        if (-not (Test-Path -LiteralPath $r.Path)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $r.Path -Recurse -File -ErrorAction SilentlyContinue)) { [void]$lines.Add(('{0}:{1}' -f $r.Tag, $f.FullName.Substring($r.Path.Length))) }
    }
    foreach ($c in @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue)) { [void]$lines.Add(('cert:{0}' -f $c.Thumbprint)) }
    return @($lines | Sort-Object)
}
