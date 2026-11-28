<#
.SYNOPSIS
DEVELOPER-ONLY (tools\dev, never shipped, never referenced by the product). Creates the public PKI material of the demo world
(docs/DEMO-WORLD.md): CA certificates, end-entity certificates and CRLs of Alcyone Orbital Systems, as DER files under site\world\pki.

.DESCRIPTION
Owner decision 2026-11-23 (CLAUDE.md, "Developer-only tools"): this script may create throw-away signing keys IN MEMORY ONLY. Every key
is an ephemeral RSACng object that lives in this process and is never exported, written to disk or put in a key store; only the public
certificates and the CRLs (public DER) are written. Certificates are built with the in-box CertificateRequest class; CRLs are encoded here
(DER) and signed with the in-memory key. Everything is clearly fictional (the reserved .example TLD) and dated around the demo clock
(DemoClock in site\world\pki\pki.json) so nothing looks expired on the demo site unless a scenario wants it to.

Run it once (Windows PowerShell 5.1) when the world's PKI changes; commit the DER files and pki.json. Regenerating creates new keys,
so every thumbprint changes.
#>
[CmdletBinding()]
param([string]$Output = '')

$ErrorActionPreference = 'Stop'
if (-not $Output) { $Output = Join-Path (Split-Path (Split-Path (Split-Path (Split-Path $MyInvocation.MyCommand.Path)))) 'site\world\pki' }
Set-StrictMode -Version 2

$X = 'System.Security.Cryptography.X509Certificates'
$sha256 = [System.Security.Cryptography.HashAlgorithmName]::SHA256
$pkcs1 = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
$demoClock = [DateTime]::new(2026, 11, 20, 9, 0, 0, [DateTimeKind]::Utc)
$cfg = 'CN=Configuration,DC=alcyone-orbital,DC=example'
$pks = 'CN=Public Key Services,CN=Services,' + $cfg

# --- DER --------------------------------------------------------------------------------------------------------------------------
function Join-Bytes { param([object[]]$Parts) $l = New-Object System.Collections.Generic.List[byte]; foreach ($p in $Parts) { if ($null -ne $p) { $l.AddRange([byte[]]$p) } }; return , $l.ToArray() }
function New-Der {
    param([int]$Tag, [byte[]]$Content)
    $n = $Content.Length
    if ($n -lt 128) { $len = [byte[]]@($n) }
    else { $b = New-Object System.Collections.Generic.List[byte]; $v = $n; while ($v -gt 0) { $b.Insert(0, [byte]($v -band 0xFF)); $v = $v -shr 8 }; $len = Join-Bytes @([byte[]]@(0x80 + $b.Count), $b.ToArray()) }
    return , (Join-Bytes @([byte[]]@($Tag), $len, $Content))
}
function New-DerSeq { param([object[]]$Parts) return , (New-Der 0x30 (Join-Bytes $Parts)) }
function New-DerInt {
    param([byte[]]$Big)   # big-endian unsigned
    $i = 0; while ($i -lt $Big.Length - 1 -and $Big[$i] -eq 0) { $i++ }
    $b = $Big[$i..($Big.Length - 1)]
    if ($b[0] -band 0x80) { $b = Join-Bytes @([byte[]]@(0), [byte[]]$b) }
    return , (New-Der 0x02 ([byte[]]$b))
}
function New-DerIntValue { param([long]$Value) $b = New-Object System.Collections.Generic.List[byte]; $v = $Value; do { $b.Insert(0, [byte]($v -band 0xFF)); $v = $v -shr 8 } while ($v -gt 0); return , (New-DerInt $b.ToArray()) }
function New-DerOid { param([string]$Oid) return , ([System.Security.Cryptography.CryptoConfig]::EncodeOID($Oid)) }
function New-DerNull { return , ([byte[]]@(0x05, 0x00)) }
function New-DerOctets { param([byte[]]$B) return , (New-Der 0x04 $B) }
function New-DerBits { param([byte[]]$B) return , (New-Der 0x03 (Join-Bytes @([byte[]]@(0), $B))) }
function New-DerIa5 { param([string]$S) return , (New-Der 0x16 ([System.Text.Encoding]::ASCII.GetBytes($S))) }
function New-DerBmp { param([string]$S) return , (New-Der 0x1E ([System.Text.Encoding]::BigEndianUnicode.GetBytes($S))) }
function New-DerTime {
    param([DateTime]$T)
    $u = $T.ToUniversalTime()
    if ($u.Year -lt 2050) { return , (New-Der 0x17 ([System.Text.Encoding]::ASCII.GetBytes($u.ToString('yyMMddHHmmss') + 'Z'))) }
    return , (New-Der 0x18 ([System.Text.Encoding]::ASCII.GetBytes($u.ToString('yyyyMMddHHmmss') + 'Z')))
}
function New-DerCtx { param([int]$N, [byte[]]$Content, [switch]$Primitive) $tag = $(if ($Primitive) { 0x80 + $N } else { 0xA0 + $N }); return , (New-Der $tag $Content) }

# --- extensions -------------------------------------------------------------------------------------------------------------------
function New-Ext { param([string]$Oid, [byte[]]$Value, [bool]$Critical = $false) return (New-Object "$X.X509Extension" ($Oid, $Value, $Critical)) }
function New-UriNames { param([string[]]$Uris) $p = @(foreach ($u in $Uris) { , (New-Der 0x86 ([System.Text.Encoding]::ASCII.GetBytes($u))) }); return , (Join-Bytes $p) }
function New-CdpExt {
    param([string[]]$Uris)
    return New-Ext '2.5.29.31' (New-DerSeq @(, (New-DerSeq @(, (New-DerCtx 0 (New-DerCtx 0 (New-UriNames $Uris)))))))
}
function New-AiaExt {
    param([string[]]$CaIssuers = @(), [string[]]$Ocsp = @())
    $ads = @()
    foreach ($u in $Ocsp) { $ads += , (New-DerSeq @((New-DerOid '1.3.6.1.5.5.7.48.1'), (New-Der 0x86 ([System.Text.Encoding]::ASCII.GetBytes($u))))) }
    foreach ($u in $CaIssuers) { $ads += , (New-DerSeq @((New-DerOid '1.3.6.1.5.5.7.48.2'), (New-Der 0x86 ([System.Text.Encoding]::ASCII.GetBytes($u))))) }
    return New-Ext '1.3.6.1.5.5.7.1.1' (New-DerSeq $ads)
}
function New-AkiExt { param([byte[]]$KeyId) return New-Ext '2.5.29.35' (New-DerSeq @(, (New-DerCtx 0 $KeyId -Primitive))) }
function New-CaVersionExt { param([int]$CertIndex, [int]$KeyIndex) return New-Ext '1.3.6.1.4.1.311.21.1' (New-DerIntValue (($KeyIndex -shl 16) -bor $CertIndex)) }
function New-TemplateNameExt { param([string]$Name) return New-Ext '1.3.6.1.4.1.311.20.2' (New-DerBmp $Name) }
function New-TemplateInfoExt { param([string]$Oid, [int]$Major = 100, [int]$Minor = 4) return New-Ext '1.3.6.1.4.1.311.21.7' (New-DerSeq @((New-DerOid $Oid), (New-DerIntValue $Major), (New-DerIntValue $Minor))) }
function New-SanExt { param([string[]]$Dns) $p = @(foreach ($d in $Dns) { , (New-Der 0x82 ([System.Text.Encoding]::ASCII.GetBytes($d))) }); return New-Ext '2.5.29.17' (New-DerSeq $p) }
function New-EkuExt { param([string[]]$Oids) $c = New-Object System.Security.Cryptography.OidCollection; foreach ($o in $Oids) { [void]$c.Add((New-Object System.Security.Cryptography.Oid($o))) }; return (New-Object "$X.X509EnhancedKeyUsageExtension" ($c, $false)) }
function Get-KeyId { param($Rsa) $p = $Rsa.ExportParameters($false); $sha = [System.Security.Cryptography.SHA1]::Create(); $spki = New-DerSeq @((New-DerInt $p.Modulus), (New-DerInt $p.Exponent)); return , $sha.ComputeHash($spki) }

# --- issuing ------------------------------------------------------------------------------------------------------------------------
$script:keys = @{}
$script:certs = [ordered]@{}
$script:meta = New-Object System.Collections.ArrayList
$script:serialNo = 0x61A0

function New-Serial { $script:serialNo += 0x1F3; $b = [BitConverter]::GetBytes([long]$script:serialNo); [Array]::Reverse($b); return , ([byte[]](@(0x1B, 0x7E) + $b[4..7] + @(0x00, 0x00, 0x00, 0x0A))) }

function New-WorldCert {
    param([string]$Name, [string]$Subject, [string]$Issuer = '', [string]$KeyName = '', [DateTime]$NotBefore, [DateTime]$NotAfter,
        [switch]$Ca, [string[]]$Cdp = @(), [string[]]$AiaIssuers = @(), [string[]]$AiaOcsp = @(), [string]$TemplateName = '', [string]$TemplateOid = '',
        [string[]]$Eku = @(), [string[]]$Dns = @(), [int]$CertIndex = -1, [int]$KeyIndex = 0, [string]$Role = '', [string]$IssuerKeyName = '')
    if (-not $KeyName) { $KeyName = $Name }
    if (-not $script:keys.ContainsKey($KeyName)) { $script:keys[$KeyName] = [System.Security.Cryptography.RSA]::Create(2048) }
    $key = $script:keys[$KeyName]
    $req = New-Object "$X.CertificateRequest" ($Subject, $key, $sha256, $pkcs1)
    if ($Ca) {
        $req.CertificateExtensions.Add((New-Object "$X.X509KeyUsageExtension" ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyCertSign, CrlSign', $false)))
        $req.CertificateExtensions.Add((New-Object "$X.X509BasicConstraintsExtension" ($true, $false, 0, $true)))
    }
    else {
        $req.CertificateExtensions.Add((New-Object "$X.X509KeyUsageExtension" ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyEncipherment', $true)))
    }
    $ski = Get-KeyId $key
    $req.CertificateExtensions.Add((New-Ext '2.5.29.14' (New-DerOctets $ski)))
    if ($CertIndex -ge 0) { $req.CertificateExtensions.Add((New-CaVersionExt -CertIndex $CertIndex -KeyIndex $KeyIndex)) }
    if ($TemplateName) { $req.CertificateExtensions.Add((New-TemplateNameExt $TemplateName)) }
    if ($TemplateOid) { $req.CertificateExtensions.Add((New-TemplateInfoExt $TemplateOid)) }
    if ($Eku.Count -gt 0) { $req.CertificateExtensions.Add((New-EkuExt $Eku)) }
    if ($Dns.Count -gt 0) { $req.CertificateExtensions.Add((New-SanExt $Dns)) }
    if ($Issuer) {
        if (-not $IssuerKeyName) { $IssuerKeyName = $Issuer }
        $ik = $script:keys[$IssuerKeyName]
        $req.CertificateExtensions.Add((New-AkiExt (Get-KeyId $ik)))
        if ($Cdp.Count -gt 0) { $req.CertificateExtensions.Add((New-CdpExt $Cdp)) }
        if ($AiaIssuers.Count + $AiaOcsp.Count -gt 0) { $req.CertificateExtensions.Add((New-AiaExt -CaIssuers $AiaIssuers -Ocsp $AiaOcsp)) }
        $gen = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA($ik, $pkcs1)
        $issuerName = $script:certs[$Issuer].SubjectName
        $c = $req.Create($issuerName, $gen, [DateTimeOffset]$NotBefore, [DateTimeOffset]$NotAfter, (New-Serial))
    }
    else { $c = $req.CreateSelfSigned([DateTimeOffset]$NotBefore, [DateTimeOffset]$NotAfter) }
    $pub = New-Object "$X.X509Certificate2" (, $c.RawData)   # the public certificate only, from here on
    $c.Dispose()
    $script:certs[$Name] = $pub
    [void]$script:meta.Add([ordered]@{ File = ($Name + '.cer'); Kind = 'Certificate'; Role = $Role; Subject = $pub.Subject; Issuer = $pub.Issuer
        Thumbprint = $pub.Thumbprint; Serial = $pub.SerialNumber; NotBefore = $pub.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        NotAfter = $pub.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); KeyId = (($ski | ForEach-Object { $_.ToString('x2') }) -join '') })
    [System.IO.File]::WriteAllBytes((Join-Path $Output ($Name + '.cer')), $pub.RawData)
}

function New-WorldCrl {
    param([string]$Name, [string]$Issuer, [string]$KeyName = '', [DateTime]$ThisUpdate, [DateTime]$NextUpdate, [DateTime]$NextPublish, [long]$Number,
        [long]$DeltaOf = -1, [int]$CertIndex = 0, [int]$KeyIndex = 0, [object[]]$Revoked = @(), [string]$Role = '', [string[]]$FreshestDelta = @())
    if (-not $KeyName) { $KeyName = $Issuer }
    $key = $script:keys[$KeyName]
    $ic = $script:certs[$Issuer]
    $alg = New-DerSeq @((New-DerOid '1.2.840.113549.1.1.11'), (New-DerNull))
    $exts = @(
        (New-DerSeq @((New-DerOid '2.5.29.35'), (New-DerOctets (New-DerSeq @(, (New-DerCtx 0 (Get-KeyId $key) -Primitive)))))),
        (New-DerSeq @((New-DerOid '1.3.6.1.4.1.311.21.1'), (New-DerOctets (New-DerIntValue (($KeyIndex -shl 16) -bor $CertIndex))))),
        (New-DerSeq @((New-DerOid '2.5.29.20'), (New-DerOctets (New-DerIntValue $Number)))),
        (New-DerSeq @((New-DerOid '1.3.6.1.4.1.311.21.4'), (New-DerOctets (New-DerTime $NextPublish))))
    )
    if ($DeltaOf -ge 0) { $exts += , (New-DerSeq @((New-DerOid '2.5.29.27'), [byte[]]@(0x01, 0x01, 0xFF), (New-DerOctets (New-DerIntValue $DeltaOf)))) }
    if ($FreshestDelta.Count -gt 0) { $exts += , (New-DerSeq @((New-DerOid '2.5.29.46'), (New-DerOctets (New-DerSeq @(, (New-DerSeq @(, (New-DerCtx 0 (New-DerCtx 0 (New-UriNames $FreshestDelta)))))))))) }
    $parts = @((New-DerIntValue 1), $alg, $ic.SubjectName.RawData, (New-DerTime $ThisUpdate), (New-DerTime $NextUpdate))
    if ($Revoked.Count -gt 0) {
        $parts += , (New-DerSeq @(foreach ($r in $Revoked) { , (New-DerSeq @((New-DerInt ([byte[]]$r.Serial)), (New-DerTime $r.Date))) }))
    }
    $parts += , (New-DerCtx 0 (New-DerSeq $exts))
    $tbs = New-DerSeq $parts
    $sig = $key.SignData($tbs, $sha256, $pkcs1)
    $crl = New-DerSeq @($tbs, $alg, (New-DerBits $sig))
    [System.IO.File]::WriteAllBytes((Join-Path $Output ($Name + '.crl')), $crl)
    [void]$script:meta.Add([ordered]@{ File = ($Name + '.crl'); Kind = $(if ($DeltaOf -ge 0) { 'DeltaCrl' } else { 'BaseCrl' }); Role = $Role; Issuer = $ic.Subject
        Number = ('{0:X2}' -f $Number); ThisUpdate = $ThisUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ'); NextUpdate = $NextUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Sha256 = ((([System.Security.Cryptography.SHA256]::Create()).ComputeHash($crl) | ForEach-Object { $_.ToString('x2') }) -join '') })
}

# --- the world ----------------------------------------------------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Output)) { [void](New-Item -ItemType Directory -Path $Output) }
Get-ChildItem -LiteralPath $Output -File | Where-Object { $_.Extension -in @('.cer', '.crl', '.p7b') } | Remove-Item

$rootSub = 'CN=Alcyone Lodestar Root CA, DC=alcyone-orbital, DC=example'
$merSub = 'CN=Alcyone Meridian Issuing CA, DC=alcyone-orbital, DC=example'
$zenSub = 'CN=Alcyone Zenith Issuing CA, DC=flightops, DC=example'
$rootCdpLdap = 'ldap:///CN=Alcyone Lodestar Root CA,CN=root-ca,CN=CDP,{0}?certificateRevocationList?base?objectClass=cRLDistributionPoint' -f $pks
$rootAiaLdap = 'ldap:///CN=Alcyone Lodestar Root CA,CN=AIA,{0}?cACertificate?base?objectClass=certificationAuthority' -f $pks
$merCdpLdap = 'ldap:///CN=Alcyone Meridian Issuing CA,CN=issuing-ca,CN=CDP,{0}' -f $pks
$merAiaLdap = 'ldap:///CN=Alcyone Meridian Issuing CA,CN=AIA,{0}?cACertificate?base?objectClass=certificationAuthority' -f $pks
$pkiHttp = 'http://pki.alcyone-orbital.example/CertEnroll'
$rootCdpHttp = $pkiHttp + '/Alcyone%20Lodestar%20Root%20CA.crl'
$rootAiaHttp = $pkiHttp + '/Alcyone%20Lodestar%20Root%20CA.crt'
$merCdpHttp = $pkiHttp + '/Alcyone%20Meridian%20Issuing%20CA.crl'
$merAiaHttp = $pkiHttp + '/Alcyone%20Meridian%20Issuing%20CA.crt'
$merOcsp = 'http://ocsp.vault.alcyone-orbital.example/ocsp'

$d = { param([string]$s) [DateTime]::SpecifyKind([DateTime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Utc) }

# Root: 5 years, no CDP or AIA in its own certificate.
New-WorldCert -Name 'lodestar-root' -Subject $rootSub -NotBefore (& $d '2024-03-04 10:12:00') -NotAfter (& $d '2029-03-04 10:22:00') -Ca -CertIndex 0 -Role 'Root CA (Lodestar)'
# Meridian: two generations 11 days apart (new key each); LDAP-only URLs from the root's configuration.
New-WorldCert -Name 'meridian-g0' -KeyName 'meridian-k0' -Subject $merSub -Issuer 'lodestar-root' -NotBefore (& $d '2026-05-08 14:03:00') -NotAfter (& $d '2028-05-08 14:13:00') -Ca -CertIndex 0 -KeyIndex 0 -TemplateName 'SubCA' -Cdp @($rootCdpLdap) -AiaIssuers @($rootAiaLdap) -Role 'Meridian, older generation (V0.0)'
New-WorldCert -Name 'meridian-g1' -KeyName 'meridian-k1' -Subject $merSub -Issuer 'lodestar-root' -NotBefore (& $d '2026-05-19 09:41:00') -NotAfter (& $d '2028-05-19 09:51:00') -Ca -CertIndex 1 -KeyIndex 1 -TemplateName 'SubCA' -Cdp @($rootCdpLdap) -AiaIssuers @($rootAiaLdap) -Role 'Meridian, current generation (V1.1)'
# Healthy world: the current Meridian generation as it would be issued with HTTP first, LDAP second.
New-WorldCert -Name 'meridian-healthy' -KeyName 'meridian-k1' -Subject $merSub -Issuer 'lodestar-root' -NotBefore (& $d '2026-05-19 09:41:00') -NotAfter (& $d '2028-05-19 09:51:00') -Ca -CertIndex 1 -KeyIndex 1 -TemplateName 'SubCA' -Cdp @($rootCdpHttp, $rootCdpLdap) -AiaIssuers @($rootAiaHttp, $rootAiaLdap) -Role 'Meridian, current generation with HTTP publication (healthy)'
# Renewal leftovers: a third generation, and an expired earlier one.
New-WorldCert -Name 'meridian-g2' -KeyName 'meridian-k2' -Subject $merSub -Issuer 'lodestar-root' -NotBefore (& $d '2026-10-02 08:00:00') -NotAfter (& $d '2028-10-02 08:10:00') -Ca -CertIndex 2 -KeyIndex 2 -TemplateName 'SubCA' -Cdp @($rootCdpLdap) -AiaIssuers @($rootAiaLdap) -Role 'Meridian, third generation (V2.2, renewal-drift)'
New-WorldCert -Name 'meridian-expired' -KeyName 'meridian-kx' -Subject $merSub -Issuer 'lodestar-root' -NotBefore (& $d '2024-03-11 11:00:00') -NotAfter (& $d '2025-03-11 11:10:00') -Ca -CertIndex 0 -KeyIndex 0 -TemplateName 'SubCA' -Cdp @($rootCdpLdap) -AiaIssuers @($rootAiaLdap) -Role 'Meridian, expired generation still published (renewal-drift)'
# Zenith (mixed estate): the flight-operations issuing CA.
New-WorldCert -Name 'zenith' -Subject $zenSub -Issuer 'lodestar-root' -NotBefore (& $d '2025-09-01 07:30:00') -NotAfter (& $d '2027-09-01 07:40:00') -Ca -CertIndex 0 -TemplateName 'SubCA' -Cdp @($rootCdpHttp, $rootCdpLdap) -AiaIssuers @($rootAiaHttp) -Role 'Zenith issuing CA (mixed-sample)'
# A forged "root": the right name, a different key, self-signed (forged-aia).
New-WorldCert -Name 'lodestar-forged' -KeyName 'forged-k' -Subject $rootSub -NotBefore (& $d '2024-03-04 10:12:00') -NotAfter (& $d '2029-03-04 10:22:00') -Ca -CertIndex 0 -Role 'Forged certificate with the root''s name and another key (forged-aia)'

# End-entity certificates issued by Meridian (current key).
$leafCdp = @($merCdpLdap)   # no attribute part: valid, clients use the defaults (DEMO-WORLD)
$leafAia = @($merAiaLdap)
$leafCdpH = @($merCdpHttp) + $leafCdp
$leafAiaH = @($merAiaHttp) + $leafAia
$tplOid = { param([string]$n) '1.3.6.1.4.1.311.21.8.4718263.9937315.12810493.16219837.6011209.47.{0}' -f $n }
New-WorldCert -Name 'ground-web-rdp' -Subject 'CN=ground-web.alcyone-orbital.example' -Issuer 'meridian-g1' -IssuerKeyName 'meridian-k1' -NotBefore (& $d '2026-08-14 06:20:00') -NotAfter (& $d '2027-08-14 06:20:00') -TemplateOid (& $tplOid '101') -Eku @('1.3.6.1.5.5.7.3.1') -Dns @('ground-web.alcyone-orbital.example') -Cdp $leafCdp -AiaIssuers $leafAia -Role 'RDP certificate on ground-web (Alcyone-RDPServerAuth)'
New-WorldCert -Name 'ground-web-tls' -Subject 'CN=ground-web.alcyone-orbital.example' -Issuer 'meridian-g1' -IssuerKeyName 'meridian-k1' -NotBefore (& $d '2026-06-02 13:05:00') -NotAfter (& $d '2027-06-02 13:05:00') -TemplateOid (& $tplOid '102') -Eku @('1.3.6.1.5.5.7.3.1') -Dns @('ground-web.alcyone-orbital.example', 'telemetry.alcyone-orbital.example') -Cdp $leafCdp -AiaIssuers $leafAia -Role 'Web certificate on ground-web with a dead alias (Alcyone-WebServer)'
New-WorldCert -Name 'ground-web-rdp-healthy' -Subject 'CN=ground-web.alcyone-orbital.example' -Issuer 'meridian-healthy' -IssuerKeyName 'meridian-k1' -NotBefore (& $d '2026-08-14 06:20:00') -NotAfter (& $d '2027-08-14 06:20:00') -TemplateOid (& $tplOid '101') -Eku @('1.3.6.1.5.5.7.3.1') -Dns @('ground-web.alcyone-orbital.example') -Cdp $leafCdpH -AiaIssuers $leafAiaH -AiaOcsp @($merOcsp) -Role 'RDP certificate on ground-web (healthy)'
New-WorldCert -Name 'scep-gateway-tls' -Subject 'CN=scep-gateway.vault.alcyone-orbital.example' -Issuer 'meridian-g1' -IssuerKeyName 'meridian-k1' -NotBefore (& $d '2026-06-01 10:00:00') -NotAfter (& $d '2027-06-01 10:00:00') -TemplateOid (& $tplOid '106') -Eku @('1.3.6.1.5.5.7.3.1') -Dns @('scep-gateway.vault.alcyone-orbital.example') -Cdp $leafCdp -AiaIssuers $leafAia -Role 'HTTPS certificate of the NDES gateway (Alcyone-NDES-HTTPS)'
New-WorldCert -Name 'root-ca-tls-healthy' -Subject 'CN=root-ca.vault.alcyone-orbital.example' -Issuer 'meridian-healthy' -IssuerKeyName 'meridian-k1' -NotBefore (& $d '2026-07-01 09:00:00') -NotAfter (& $d '2027-07-01 09:00:00') -TemplateOid (& $tplOid '102') -Eku @('1.3.6.1.5.5.7.3.1') -Dns @('root-ca.vault.alcyone-orbital.example', 'pki.alcyone-orbital.example') -Cdp $leafCdpH -AiaIssuers $leafAiaH -Role 'HTTPS certificate of the PKI web host (healthy)'
New-WorldCert -Name 'ndes-ra-signing' -Subject 'CN=scep-gateway-mscep-ra, O=Alcyone Orbital Systems, C=US' -Issuer 'meridian-g1' -IssuerKeyName 'meridian-k1' -NotBefore (& $d '2026-06-01 10:05:00') -NotAfter (& $d '2028-05-18 10:05:00') -TemplateOid (& $tplOid '103') -Eku @('1.3.6.1.4.1.311.20.2.1') -Cdp $leafCdp -AiaIssuers $leafAia -Role 'NDES registration authority signing certificate (Alcyone-NDES-Agent)'
New-WorldCert -Name 'ndes-ra-encryption' -Subject 'CN=scep-gateway-mscep-ra, O=Alcyone Orbital Systems, C=US' -Issuer 'meridian-g1' -IssuerKeyName 'meridian-k1' -NotBefore (& $d '2026-06-01 10:05:00') -NotAfter (& $d '2028-05-18 10:05:00') -TemplateOid (& $tplOid '104') -Eku @('1.3.6.1.4.1.311.20.2.1') -Cdp $leafCdp -AiaIssuers $leafAia -Role 'NDES registration authority encryption certificate (Alcyone-NDES-Encryption)'

# What an NDES gateway answers to GetCACert: a certificates-only PKCS #7 (SignedData without signers) with the CA certificate and the RA
# certificates. Public data only.
$p7certs = Join-Bytes @(foreach ($n in 'meridian-g1', 'ndes-ra-signing', 'ndes-ra-encryption') { , $script:certs[$n].RawData })
$signedData = New-DerSeq @((New-DerIntValue 1), (New-Der 0x31 ([byte[]]@())), (New-DerSeq @(, (New-DerOid '1.2.840.113549.1.7.1'))), (New-Der 0xA0 $p7certs), (New-Der 0x31 ([byte[]]@())))
$p7 = New-DerSeq @((New-DerOid '1.2.840.113549.1.7.2'), (New-DerCtx 0 $signedData))
[System.IO.File]::WriteAllBytes((Join-Path $Output 'ndes-getcacert.p7b'), $p7)
[void]$script:meta.Add([ordered]@{ File = 'ndes-getcacert.p7b'; Kind = 'Pkcs7'; Role = 'GetCACert answer of the NDES gateway: the issuing CA and the two RA certificates'; Certificates = @('meridian-g1.cer', 'ndes-ra-signing.cer', 'ndes-ra-encryption.cer') })
# CRLs (CRL numbers in hex as the CA writes them).
$rootTU = & $d '2026-11-14 09:00:00'
New-WorldCrl -Name 'lodestar-root' -Issuer 'lodestar-root' -ThisUpdate $rootTU -NextUpdate (& $d '2026-12-14 21:00:00') -NextPublish (& $d '2026-12-13 09:00:00') -Number 0x12 -Role 'Root base CRL'
New-WorldCrl -Name 'meridian' -Issuer 'meridian-g1' -KeyName 'meridian-k1' -ThisUpdate (& $d '2026-11-17 08:00:00') -NextUpdate (& $d '2026-11-25 20:00:00') -NextPublish (& $d '2026-11-24 08:00:00') -Number 0x2B -CertIndex 1 -KeyIndex 1 -Role 'Meridian base CRL'
New-WorldCrl -Name 'meridian+' -Issuer 'meridian-g1' -KeyName 'meridian-k1' -ThisUpdate (& $d '2026-11-20 06:00:00') -NextUpdate (& $d '2026-11-21 18:00:00') -NextPublish (& $d '2026-11-21 06:00:00') -Number 0x2C -DeltaOf 0x2B -CertIndex 1 -KeyIndex 1 -Role 'Meridian delta CRL'
New-WorldCrl -Name 'meridian-expired-crl' -Issuer 'meridian-g1' -KeyName 'meridian-k1' -ThisUpdate (& $d '2026-11-09 08:00:00') -NextUpdate (& $d '2026-11-17 09:00:00') -NextPublish (& $d '2026-11-16 08:00:00') -Number 0x29 -CertIndex 1 -KeyIndex 1 -Role 'Meridian base CRL, 3 days past Next Update (expired-crl)'
New-WorldCrl -Name 'meridian-expired-delta' -Issuer 'meridian-g1' -KeyName 'meridian-k1' -ThisUpdate (& $d '2026-11-12 06:00:00') -NextUpdate (& $d '2026-11-13 18:00:00') -NextPublish (& $d '2026-11-13 06:00:00') -Number 0x2A -DeltaOf 0x29 -CertIndex 1 -KeyIndex 1 -Role 'Meridian delta CRL, expired (expired-crl)'
New-WorldCrl -Name 'meridian-g2' -Issuer 'meridian-g2' -KeyName 'meridian-k2' -ThisUpdate (& $d '2026-11-17 08:00:00') -NextUpdate (& $d '2026-11-25 20:00:00') -NextPublish (& $d '2026-11-24 08:00:00') -Number 0x2B -CertIndex 2 -KeyIndex 2 -Role 'Meridian base CRL signed by the third generation (renewal-drift)'
New-WorldCrl -Name 'zenith' -Issuer 'zenith' -ThisUpdate (& $d '2026-11-18 07:00:00') -NextUpdate (& $d '2026-11-26 19:00:00') -NextPublish (& $d '2026-11-25 07:00:00') -Number 0x0E -Role 'Zenith base CRL (mixed-sample)'

$doc = [ordered]@{
    Note      = 'Public demo-world PKI material (fictional, reserved .example names). Generated by tools/dev/demo-site/New-MspkiWorldPki.ps1 with throw-away in-memory keys that were never written anywhere.'
    DemoClock = $demoClock.ToString('yyyy-MM-ddTHH:mm:ssZ')
    Files     = @($script:meta)
}
[System.IO.File]::WriteAllText((Join-Path $Output 'pki.json'), ($doc | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
foreach ($k in @($script:keys.Keys)) { $script:keys[$k].Dispose() }
$script:keys.Clear()
Write-Host ('{0} files written to {1}' -f $script:meta.Count, $Output)
