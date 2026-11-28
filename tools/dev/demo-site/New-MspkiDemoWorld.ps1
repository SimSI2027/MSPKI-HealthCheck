<#
.SYNOPSIS
DEVELOPER-ONLY (tools\dev, never shipped, never referenced by the product). Writes site\world\world.json: the baseline simulated world of
Alcyone Orbital Systems (docs/DEMO-WORLD.md) as DATA: the directory objects the engine reads, what each CA answers, the network and this
computer. Scenario files (site\world\scenarios\<id>.json) change parts of it. Run it after changing the world; commit world.json.

.DESCRIPTION
Values that are bytes refer to the public PKI files: "pki:<file>" (DER) and "b64pki:<file>" (the Base64 text a CA COM property returns).
Security descriptors are SDDL ("sddl:..."), SIDs "sid:...", times "time:...". Everything is fictional: .example names (RFC 2606) and
192.0.2.0/24 addresses (RFC 5737).
#>
[CmdletBinding()]
param([string]$Output = '')
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path (Split-Path (Split-Path $MyInvocation.MyCommand.Path)))
if (-not $Output) { $Output = Join-Path $repo 'site\world\world.json' }

$dom = 'DC=alcyone-orbital,DC=example'
$cfg = 'CN=Configuration,' + $dom
$pks = 'CN=Public Key Services,CN=Services,' + $cfg
$sid = 'S-1-5-21-2718281828-3141592653-1618033988'
$fsid = 'S-1-5-21-1414213562-1732050807-2236067977'
$DA = "$sid-512"; $DU = "$sid-513"; $DC = "$sid-515"; $DCS = "$sid-516"; $EA = "$sid-519"
$GuidEnroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'; $GuidAutoEnroll = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$oidBase = '1.3.6.1.4.1.311.21.8.4718263.9937315.12810493.16219837.6011209.47'

function New-Acl {
    # Template security in SDDL: owner and group Domain Admins; Authenticated Users read; Domain and Enterprise Admins full control; the
    # given principals Enroll (and AutoEnroll).
    param([string[]]$Enroll = @(), [string[]]$AutoEnroll = @(), [string[]]$Write = @())
    $s = "O:${DA}G:${DA}D:PAI(A;;LCRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;$DA)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;$EA)"
    foreach ($p in $Enroll) { $s += "(OA;;CR;$GuidEnroll;;$p)" }
    foreach ($p in $AutoEnroll) { $s += "(OA;;CR;$GuidAutoEnroll;;$p)" }
    foreach ($p in $Write) { $s += "(A;;RPWPWD;;;$p)" }
    return 'sddl:' + $s
}

$objects = [ordered]@{}
function Add-Obj { param([string]$Dn, [hashtable]$Attrs) $o = [ordered]@{}; foreach ($k in ($Attrs.Keys | Sort-Object)) { $o[$k] = $Attrs[$k] }; $objects[$Dn] = $o }

# --- Configuration partition: Public Key Services --------------------------------------------------------------------------------------
$changed = 'time:2026-05-19T10:02:00Z'
Add-Obj "CN=Public Key Services,CN=Services,$cfg" @{ objectClass = @('top', 'container'); cn = 'Public Key Services'; whenChanged = $changed }
foreach ($c in 'Certification Authorities', 'AIA', 'CDP', 'Enrollment Services', 'Certificate Templates', 'OID', 'KRA') {
    Add-Obj "CN=$c,$pks" @{ objectClass = @('top', 'container'); cn = $c; whenChanged = $changed }
}
Add-Obj "CN=NTAuthCertificates,$pks" @{ objectClass = @('top', 'certificationAuthority'); cn = 'NTAuthCertificates'; whenChanged = $changed
    cACertificate = @('pki:lodestar-root.cer', 'pki:meridian-g0.cer', 'pki:meridian-g1.cer') }
Add-Obj "CN=Alcyone Lodestar Root CA,CN=Certification Authorities,$pks" @{ objectClass = @('top', 'certificationAuthority'); cn = 'Alcyone Lodestar Root CA'; cACertificate = @('pki:lodestar-root.cer'); whenChanged = 'time:2024-03-04T10:30:00Z' }
Add-Obj "CN=Alcyone Lodestar Root CA,CN=AIA,$pks" @{ objectClass = @('top', 'certificationAuthority'); cn = 'Alcyone Lodestar Root CA'; cACertificate = @('pki:lodestar-root.cer'); whenChanged = 'time:2024-03-04T10:30:00Z' }
Add-Obj "CN=Alcyone Meridian Issuing CA,CN=AIA,$pks" @{ objectClass = @('top', 'certificationAuthority'); cn = 'Alcyone Meridian Issuing CA'; cACertificate = @('pki:meridian-g1.cer'); whenChanged = 'time:2026-05-19T10:02:00Z' }
Add-Obj "CN=root-ca,CN=CDP,$pks" @{ objectClass = @('top', 'container'); cn = 'root-ca' }
Add-Obj "CN=issuing-ca,CN=CDP,$pks" @{ objectClass = @('top', 'container'); cn = 'issuing-ca' }
Add-Obj "CN=Alcyone Lodestar Root CA,CN=root-ca,CN=CDP,$pks" @{ objectClass = @('top', 'cRLDistributionPoint'); cn = 'Alcyone Lodestar Root CA'; certificateRevocationList = @('pki:lodestar-root.crl'); whenChanged = 'time:2026-11-14T09:00:00Z' }
Add-Obj "CN=Alcyone Meridian Issuing CA,CN=issuing-ca,CN=CDP,$pks" @{ objectClass = @('top', 'cRLDistributionPoint'); cn = 'Alcyone Meridian Issuing CA'
    certificateRevocationList = @('pki:meridian.crl'); deltaRevocationList = @('pki:meridian+.crl'); whenChanged = 'time:2026-11-20T06:00:00Z' }

# --- Certificate templates (33 Windows defaults and 8 of Alcyone's own) ------------------------------------------------------------------
# name, display name, schema version, OID suffix (defaults use their Windows OIDs' last arc as a label), EKUs, name flag, enrollment flag, RA
# signatures, enroll principals, auto-enroll principals.
$eku = @{ Server = '1.3.6.1.5.5.7.3.1'; Client = '1.3.6.1.5.5.7.3.2'; Code = '1.3.6.1.5.5.7.3.3'; Email = '1.3.6.1.5.5.7.3.4'; Efs = '1.3.6.1.4.1.311.10.3.4'
    EfsRec = '1.3.6.1.4.1.311.10.3.4.1'; Agent = '1.3.6.1.4.1.311.20.2.1'; SmartLogon = '1.3.6.1.4.1.311.20.2.2'; Kdc = '1.3.6.1.5.2.3.5'; Ocsp = '1.3.6.1.5.5.7.3.9'
    Ipsec = '1.3.6.1.5.5.8.2.2'; Ctl = '1.3.6.1.4.1.311.10.3.1'; Kra = '1.3.6.1.4.1.311.21.6'; CaEx = '1.3.6.1.4.1.311.21.5'; DirRep = '1.3.6.1.4.1.311.21.19' }
$U = $DU; $C = $DC
$templates = @(
    @('Administrator', 'Administrator', 1, 1, @($eku.Ctl, $eku.Efs, $eku.Email, $eku.Client), -1509949440, 41, 0, @($DA, $EA), @()),
    @('CA', 'Root Certification Authority', 1, 2, @(), 1, 0, 0, @(), @()),
    @('CAExchange', 'CA Exchange', 2, 3, @($eku.CaEx), 1, 0, 0, @(), @()),
    @('CEPEncryption', 'CEP Encryption', 1, 4, @('1.3.6.1.4.1.311.20.2.1'), 1, 0, 0, @($DA, $EA), @()),
    @('ClientAuth', 'Authenticated Session', 1, 5, @($eku.Client), -2113929216, 32, 0, @($DA, $EA, $DU), @()),
    @('CodeSigning', 'Code Signing', 1, 6, @($eku.Code), -2113929216, 32, 0, @($DA, $EA), @()),
    @('CrossCA', 'Cross Certification Authority', 2, 7, @(), 1, 0, 1, @($DA, $EA), @()),
    @('CTLSigning', 'Trust List Signing', 1, 8, @($eku.Ctl), -2113929216, 32, 0, @($DA, $EA), @()),
    @('DirectoryEmailReplication', 'Directory Email Replication', 2, 9, @($eku.DirRep), 152043520, 41, 0, @($DCS, $EA), @($DCS, $EA)),
    @('DomainController', 'Domain Controller', 1, 10, @($eku.Client, $eku.Server), 402653184, 32, 0, @($DCS, $EA), @()),
    @('DomainControllerAuthentication', 'Domain Controller Authentication', 2, 11, @($eku.Client, $eku.Server, $eku.SmartLogon), 134217728, 32, 0, @($DCS, $EA), @($DCS, $EA)),
    @('EFS', 'Basic EFS', 1, 12, @($eku.Efs), -1509949440, 41, 0, @($DA, $EA, $DU), @()),
    @('EFSRecovery', 'EFS Recovery Agent', 1, 13, @($eku.EfsRec), -1509949440, 32, 0, @($DA, $EA), @()),
    @('EnrollmentAgent', 'Enrollment Agent', 1, 14, @($eku.Agent), -2113929216, 32, 0, @($DA, $EA), @()),
    @('EnrollmentAgentOffline', 'Exchange Enrollment Agent (Offline request)', 1, 15, @($eku.Agent), 1, 0, 0, @($DA, $EA), @()),
    @('ExchangeUser', 'Exchange User', 1, 16, @($eku.Email), 1, 0, 0, @($DA, $EA), @()),
    @('ExchangeUserSignature', 'Exchange Signature Only', 1, 17, @($eku.Email), 1, 0, 0, @($DA, $EA), @()),
    @('IPSECIntermediateOffline', 'IPSec (Offline request)', 1, 18, @($eku.Ipsec), 1, 0, 0, @($DA, $EA), @()),
    @('IPSECIntermediateOnline', 'IPSec', 1, 19, @($eku.Ipsec), 402653184, 32, 0, @($DA, $EA, $DC), @()),
    @('KerberosAuthentication', 'Kerberos Authentication', 2, 20, @($eku.Client, $eku.Server, $eku.SmartLogon, $eku.Kdc), 134217728, 32, 0, @($DCS, $EA), @($DCS, $EA)),
    @('KeyRecoveryAgent', 'Key Recovery Agent', 2, 21, @($eku.Kra), -2113929216, 34, 0, @($DA, $EA), @()),
    @('Machine', 'Computer', 1, 22, @($eku.Client, $eku.Server), 402653184, 32, 0, @($DA, $EA, $DC), @()),
    @('MachineEnrollmentAgent', 'Enrollment Agent (Computer)', 1, 23, @($eku.Agent), 402653184, 32, 0, @($DA, $EA), @()),
    @('OCSPResponseSigning', 'OCSP Response Signing', 3, 24, @($eku.Ocsp), 402653184, 4128, 0, @($DA, $EA), @()),
    @('OfflineRouter', 'Router (Offline request)', 1, 25, @($eku.Client), 1, 0, 0, @($DA, $EA), @()),
    @('RASAndIASServer', 'RAS and IAS Server', 2, 26, @($eku.Client, $eku.Server), 1207959552, 32, 0, @($DA, $EA), @()),
    @('SmartcardLogon', 'Smartcard Logon', 1, 27, @($eku.Client, $eku.SmartLogon), -2113929216, 32, 0, @($DA, $EA), @()),
    @('SmartcardUser', 'Smartcard User', 1, 28, @($eku.Email, $eku.Client, $eku.SmartLogon), -1509949440, 41, 0, @($DA, $EA), @()),
    @('SubCA', 'Subordinate Certification Authority', 1, 29, @(), 1, 0, 0, @($DA, $EA), @()),
    @('User', 'User', 1, 30, @($eku.Efs, $eku.Email, $eku.Client), -1509949440, 41, 0, @($DA, $EA, $DU), @()),
    @('UserSignature', 'User Signature Only', 1, 31, @($eku.Email, $eku.Client), -2113929216, 32, 0, @($DA, $EA, $DU), @()),
    @('WebServer', 'Web Server', 1, 32, @($eku.Server), 1, 0, 0, @($DA, $EA), @()),
    @('Workstation', 'Workstation Authentication', 2, 33, @($eku.Client), 134217728, 32, 0, @($DA, $EA, $DC), @()),
    @('Alcyone-WebServer', 'Alcyone Web Server', 2, 102, @($eku.Server), 1, 0, 0, @($DA, $EA, "$sid-1108"), @()),
    @('Alcyone-RDPServerAuth', 'Alcyone RDP Server Authentication', 2, 101, @($eku.Server), 1207959552, 32, 0, @($DA, $EA, $DC), @($DC)),
    @('Alcyone-NDES-Agent', 'Alcyone NDES Agent', 2, 103, @($eku.Agent), 1, 0, 0, @($DA, $EA, "$sid-1104"), @()),
    @('Alcyone-NDES-Encryption', 'Alcyone NDES Encryption', 2, 104, @($eku.Agent), 1, 0, 0, @($DA, $EA, "$sid-1104"), @()),
    @('Alcyone-NDES-Device', 'Alcyone NDES Device', 2, 105, @($eku.Client), 1, 0, 0, @($DA, $EA, "$sid-1104"), @()),
    @('Alcyone-NDES-HTTPS', 'Alcyone NDES HTTPS', 2, 106, @($eku.Server), 1, 0, 0, @($DA, $EA, "$sid-1104"), @()),
    @('Alcyone-Telemetry', 'Alcyone Telemetry', 2, 107, @($eku.Client, $eku.Server), 402653184, 32, 0, @($DA, $EA, $DC), @()),
    @('Alcyone-Telemetry2', 'Alcyone Telemetry v2', 4, 108, @($eku.Client, $eku.Server), 402653184, 32, 0, @($DA, $EA, $DC), @())
)
foreach ($t in $templates) {
    $oid = $(if ($t[3] -ge 100) { '{0}.{1}' -f $oidBase, $t[3] } else { '1.3.6.1.4.1.311.21.8.4718263.9937315.12810493.16219837.6011209.1.{0}' -f $t[3] })
    $a = @{ objectClass = @('top', 'pKICertificateTemplate'); cn = $t[0]; displayName = $t[1]; 'msPKI-Template-Schema-Version' = $t[2]; 'msPKI-Cert-Template-OID' = $oid
        'msPKI-Certificate-Name-Flag' = $t[5]; 'msPKI-Enrollment-Flag' = $t[6]; 'msPKI-RA-Signature' = $t[7]; whenChanged = $(if ($t[3] -ge 100) { 'time:2026-04-21T09:30:00Z' } else { 'time:2024-03-04T10:40:00Z' })
        nTSecurityDescriptor = (New-Acl -Enroll $t[8] -AutoEnroll $t[9]) }
    if (@($t[4]).Count -gt 0) { $a['pKIExtendedKeyUsage'] = @($t[4]); if ($t[2] -ge 2) { $a['msPKI-Certificate-Application-Policy'] = @($t[4]) } }
    Add-Obj "CN=$($t[0]),CN=Certificate Templates,$pks" $a
    if ($t[3] -ge 100) {
        Add-Obj "CN=$($t[3]).4718263,CN=OID,$pks" @{ objectClass = @('top', 'msPKI-Enterprise-Oid'); cn = "$($t[3]).4718263"; displayName = $t[1]; flags = 1; 'msPKI-Cert-Template-OID' = $oid }
    }
}

# --- Enrollment Services ------------------------------------------------------------------------------------------------------------
$rootTemplates = @('CA', 'CrossCA', 'SubCA')
$merTemplates = @('User', 'Machine', 'DomainController', 'DomainControllerAuthentication', 'DirectoryEmailReplication', 'KerberosAuthentication', 'EFS', 'EFSRecovery',
    'Administrator', 'WebServer', 'Workstation', 'ClientAuth', 'CodeSigning', 'OCSPResponseSigning', 'Alcyone-WebServer', 'Alcyone-RDPServerAuth', 'Alcyone-NDES-Agent',
    'Alcyone-NDES-Encryption', 'Alcyone-NDES-Device', 'Alcyone-NDES-HTTPS', 'Alcyone-Telemetry', 'Alcyone-Telemetry2')
Add-Obj "CN=Alcyone Lodestar Root CA,CN=Enrollment Services,$pks" @{ objectClass = @('top', 'pKIEnrollmentService'); cn = 'Alcyone Lodestar Root CA'; displayName = 'Alcyone Lodestar Root CA'
    dNSHostName = 'root-ca.vault.alcyone-orbital.example'; cACertificate = @('pki:lodestar-root.cer'); certificateTemplates = $rootTemplates; flags = 10
    whenCreated = 'time:2024-03-04T10:25:00Z'; whenChanged = 'time:2024-03-04T10:45:00Z' }
Add-Obj "CN=Alcyone Meridian Issuing CA,CN=Enrollment Services,$pks" @{ objectClass = @('top', 'pKIEnrollmentService'); cn = 'Alcyone Meridian Issuing CA'; displayName = 'Alcyone Meridian Issuing CA'
    dNSHostName = 'issuing-ca.vault.alcyone-orbital.example'; cACertificate = @('pki:meridian-g1.cer'); certificateTemplates = $merTemplates; flags = 10
    whenCreated = 'time:2026-05-08T14:20:00Z'; whenChanged = 'time:2026-04-21T09:35:00Z' }

# --- Partitions and sites ------------------------------------------------------------------------------------------------------------
Add-Obj "CN=Partitions,$cfg" @{ objectClass = @('top', 'crossRefContainer'); cn = 'Partitions' }
Add-Obj "CN=ALCYONE,CN=Partitions,$cfg" @{ objectClass = @('top', 'crossRef'); cn = 'ALCYONE'; nETBIOSName = 'ALCYONE'; dnsRoot = 'alcyone-orbital.example' }
Add-Obj "CN=FLIGHTOPS,CN=Partitions,$cfg" @{ objectClass = @('top', 'crossRef'); cn = 'FLIGHTOPS'; nETBIOSName = 'FLIGHTOPS'; dnsRoot = 'flightops.example' }
$site = "CN=Default-First-Site-Name,CN=Sites,$cfg"
Add-Obj "CN=Sites,$cfg" @{ objectClass = @('top', 'sitesContainer'); cn = 'Sites' }
Add-Obj $site @{ objectClass = @('top', 'site'); cn = 'Default-First-Site-Name' }
Add-Obj "CN=Servers,$site" @{ objectClass = @('top', 'serversContainer'); cn = 'Servers' }
foreach ($s in @(@('DC-NORTH', 'dc-north.alcyone-orbital.example'), @('DC-FLIGHT', 'dc-flight.flightops.example'))) {
    Add-Obj "CN=$($s[0]),CN=Servers,$site" @{ objectClass = @('top', 'server'); cn = $s[0]; dNSHostName = $s[1] }
    Add-Obj "CN=NTDS Settings,CN=$($s[0]),CN=Servers,$site" @{ objectClass = @('top', 'applicationSettings', 'nTDSDSA'); cn = 'NTDS Settings' }
}

# --- Domain partition: the accounts that template permissions and SPNs name ---------------------------------------------------------
Add-Obj $dom @{ objectClass = @('top', 'domain', 'domainDNS'); dc = 'alcyone-orbital' }
Add-Obj "CN=Users,$dom" @{ objectClass = @('top', 'container'); cn = 'Users' }
Add-Obj "OU=Service Accounts,$dom" @{ objectClass = @('top', 'organizationalUnit'); ou = 'Service Accounts' }
Add-Obj "OU=Groups,$dom" @{ objectClass = @('top', 'organizationalUnit'); ou = 'Groups' }
Add-Obj "CN=svc-scep,OU=Service Accounts,$dom" @{ objectClass = @('top', 'person', 'organizationalPerson', 'user'); cn = 'svc-scep'; sAMAccountName = 'svc-scep'
    objectSid = "sid:$sid-1104"; userAccountControl = 66048; servicePrincipalName = @('HTTP/scep-gateway.vault.alcyone-orbital.example', 'HTTP/scep-gateway') }
Add-Obj "CN=svc-scep-ra,OU=Service Accounts,$dom" @{ objectClass = @('top', 'person', 'organizationalPerson', 'user'); cn = 'svc-scep-ra'; sAMAccountName = 'svc-scep-ra'; objectSid = "sid:$sid-1105"; userAccountControl = 66048 }
Add-Obj "CN=Web Admins,OU=Groups,$dom" @{ objectClass = @('top', 'group'); cn = 'Web Admins'; sAMAccountName = 'Web Admins'; objectSid = "sid:$sid-1108"; groupType = -2147483646 }
foreach ($g in @(@('Domain Admins', 512), @('Domain Users', 513), @('Domain Computers', 515), @('Domain Controllers', 516), @('Enterprise Admins', 519))) {
    Add-Obj "CN=$($g[0]),CN=Users,$dom" @{ objectClass = @('top', 'group'); cn = $g[0]; sAMAccountName = $g[0]; objectSid = "sid:$sid-$($g[1])"; groupType = -2147483646 }
}

# --- CAs: what GetCAProperty answers ---------------------------------------------------------------------------------------------------
$rootCdp = "ldap:///CN=Alcyone Lodestar Root CA,CN=root-ca,CN=CDP,${pks}?certificateRevocationList?base?objectClass=cRLDistributionPoint"
$rootAia = "ldap:///CN=Alcyone Lodestar Root CA,CN=AIA,${pks}?cACertificate?base?objectClass=certificationAuthority"
$merCdp = "ldap:///CN=Alcyone Meridian Issuing CA,CN=issuing-ca,CN=CDP,$pks"
$merAia = "ldap:///CN=Alcyone Meridian Issuing CA,CN=AIA,${pks}?cACertificate?base?objectClass=certificationAuthority"
function Get-TemplateList { param([string[]]$Names) (@(foreach ($n in $Names) { $t = @($templates | Where-Object { $_[0] -eq $n })[0]; $n; $(if ($t[3] -ge 100) { '{0}.{1}' -f $oidBase, $t[3] } else { '1.3.6.1.4.1.311.21.8.4718263.9937315.12810493.16219837.6011209.1.{0}' -f $t[3] }) }) -join "`n") + "`n" }
$cas = [ordered]@{
    'root-ca.vault.alcyone-orbital.example\Alcyone Lodestar Root CA' = [ordered]@{ values = [ordered]@{
        CAType = 0; CAName = 'Alcyone Lodestar Root CA'; SanitizedCAName = 'Alcyone Lodestar Root CA'; DnsName = 'root-ca.vault.alcyone-orbital.example'; ParentCA = ''
        FileVersion = '10.0.20348.1 (WinBuild.160101.0800)'; ProductVersion = '10.0.20348.1'; RoleSeparation = 0; AdvancedServer = 1; KraCertCount = 0; KraCertUsedCount = 0
        Templates = (Get-TemplateList $rootTemplates); CASigCertCount = 1
        'CASigCert[0]' = 'b64pki:lodestar-root.cer'; 'CACertState[0]' = 3; 'CACertVersion[0]' = 0; 'CrlState[0]' = 3; 'BaseCrlPublishStatus[0]' = 1; 'DeltaCrlPublishStatus[0]' = 0
        'CertCdpUrls[0]' = $rootCdp; 'CertAiaUrls[0]' = $rootAia; 'CertAiaOcspUrls[0]' = ''; 'BaseCrl[0]' = 'b64pki:lodestar-root.crl' }
        errors = [ordered]@{ 'DeltaCrl[0]' = [ordered]@{ hresult = '80070002'; message = 'The system cannot find the file specified.' } } }
    'issuing-ca.vault.alcyone-orbital.example\Alcyone Meridian Issuing CA' = [ordered]@{ values = [ordered]@{
        CAType = 1; CAName = 'Alcyone Meridian Issuing CA'; SanitizedCAName = 'Alcyone Meridian Issuing CA'; DnsName = 'issuing-ca.vault.alcyone-orbital.example'
        ParentCA = 'root-ca.vault.alcyone-orbital.example\Alcyone Lodestar Root CA'
        FileVersion = '10.0.20348.1 (WinBuild.160101.0800)'; ProductVersion = '10.0.20348.1'; RoleSeparation = 0; AdvancedServer = 1; KraCertCount = 0; KraCertUsedCount = 0
        Templates = (Get-TemplateList $merTemplates); CASigCertCount = 1
        'CASigCert[0]' = 'b64pki:meridian-g1.cer'; 'CACertState[0]' = 3; 'CACertVersion[0]' = 65537; 'CrlState[0]' = 3; 'BaseCrlPublishStatus[0]' = 1; 'DeltaCrlPublishStatus[0]' = 1
        'CertCdpUrls[0]' = $merCdp; 'CertAiaUrls[0]' = $merAia; 'CertAiaOcspUrls[0]' = ''; 'BaseCrl[0]' = 'b64pki:meridian.crl'; 'DeltaCrl[0]' = 'b64pki:meridian+.crl' }
        databaseFatal = [ordered]@{ hresult = '80070005'; message = 'Access is denied.' } }
}

# --- Network --------------------------------------------------------------------------------------------------------------------------
$network = [ordered]@{
    dns = [ordered]@{
        'dc-north.alcyone-orbital.example' = @{ a = @('192.0.2.10') }; 'dc-flight.flightops.example' = @{ a = @('192.0.2.11') }
        'root-ca.vault.alcyone-orbital.example' = @{ a = @('192.0.2.21') }; 'issuing-ca.vault.alcyone-orbital.example' = @{ a = @('192.0.2.22') }
        'scep-gateway.vault.alcyone-orbital.example' = @{ a = @('192.0.2.24') }; 'ground-web.alcyone-orbital.example' = @{ a = @('192.0.2.32') }
        'telemetry.alcyone-orbital.example' = 'nxdomain'; 'alcyone-orbital.example' = @{ a = @('192.0.2.10') }; 'flightops.example' = @{ a = @('192.0.2.11') }
    }
    ptr = [ordered]@{ '192.0.2.10' = @('dc-north.alcyone-orbital.example'); '192.0.2.11' = @('dc-flight.flightops.example'); '192.0.2.21' = @(); '192.0.2.22' = @()
        '192.0.2.24' = @('scep-gateway.vault.alcyone-orbital.example'); '192.0.2.32' = @('ground-web.alcyone-orbital.example') }
    srv = [ordered]@{ 'alcyone-orbital.example' = @('dc-north.alcyone-orbital.example'); 'flightops.example' = @('dc-flight.flightops.example') }
    tcp = [ordered]@{
        'root-ca.vault.alcyone-orbital.example:135' = 'open'; 'issuing-ca.vault.alcyone-orbital.example:135' = 'open'
        'root-ca.vault.alcyone-orbital.example:80' = 'open'; 'root-ca.vault.alcyone-orbital.example:443' = 'open'
        'issuing-ca.vault.alcyone-orbital.example:80' = 'filtered'; 'issuing-ca.vault.alcyone-orbital.example:443' = 'filtered'
        'scep-gateway.vault.alcyone-orbital.example:80' = 'open'; 'scep-gateway.vault.alcyone-orbital.example:443' = 'open'
        'dc-north.alcyone-orbital.example:389' = 'open'; 'dc-north.alcyone-orbital.example:636' = 'open'
    }
    tls = [ordered]@{
        'root-ca.vault.alcyone-orbital.example:443' = @{ reset = $true }
        'scep-gateway.vault.alcyone-orbital.example:443' = @{ code = 'OK'; nameMatch = $true; certificate = 'pki:scep-gateway-tls.cer'; dnsNames = @('scep-gateway.vault.alcyone-orbital.example') }
    }
    http = [ordered]@{
        'http://root-ca.vault.alcyone-orbital.example/certsrv/' = @{ status = 403; server = 'Microsoft-IIS/10.0'; contentType = 'text/html' }
        'http://root-ca.vault.alcyone-orbital.example/ocsp/' = @{ status = 500; server = 'Microsoft-IIS/10.0'; contentType = 'text/html' }
    }
}

# --- This computer (ground-web) -----------------------------------------------------------------------------------------------------
$local = [ordered]@{
    stores = [ordered]@{ 'LocalMachine\My' = @('pki:ground-web-rdp.cer', 'pki:ground-web-tls.cer'); 'LocalMachine\Root' = @('pki:lodestar-root.cer'); 'LocalMachine\CA' = @('pki:meridian-g1.cer')
        'LocalMachine\NTAuth' = @('pki:lodestar-root.cer', 'pki:meridian-g0.cer', 'pki:meridian-g1.cer') }
    enterprise = [ordered]@{ Root = @('pki:lodestar-root.cer'); CA = @('pki:meridian-g1.cer'); NTAuth = @('pki:lodestar-root.cer', 'pki:meridian-g0.cer', 'pki:meridian-g1.cer') }
    trustedRoots = @('pki:lodestar-root.cer')
    policy = [ordered]@{ templateCache = [ordered]@{ Computer = @{ timestamp = '2026-11-20T07:40:00Z'; templates = @($merTemplates + $rootTemplates | Sort-Object) } }
        aePolicy = [ordered]@{ Computer = 7 }; rdpTemplate = 'Alcyone-RDPServerAuth' }
    policyServers = [ordered]@{}
    lifecycleEvents = @(); enrollmentEvents = @()
    services = @(
        [ordered]@{ Name = 'W3SVC'; DisplayName = 'World Wide Web Publishing Service'; State = 'Running'; StartMode = 'Auto'; ExecutablePath = 'C:\Windows\system32\svchost.exe' },
        [ordered]@{ Name = 'TermService'; DisplayName = 'Remote Desktop Services'; State = 'Running'; StartMode = 'Manual'; ExecutablePath = 'C:\Windows\System32\svchost.exe' },
        [ordered]@{ Name = 'CertPropSvc'; DisplayName = 'Certificate Propagation'; State = 'Running'; StartMode = 'Manual'; ExecutablePath = 'C:\Windows\system32\svchost.exe' })
    products = @()
}

$world = [ordered]@{
    note = 'Simulated world of the demo site (docs/DEMO-WORLD.md, docs/DEMO-SITE.md). Fictional: .example names (RFC 2606), 192.0.2.0/24 addresses (RFC 5737). Generated by tools/dev/demo-site/New-MspkiDemoWorld.ps1.'
    clock = '2026-11-20T09:00:00Z'; runId = '7a1c0e5b-0d5e-4f0a-9a6e-a1c90e0b17a1'
    latency = [ordered]@{ Dns = 14; Tcp = 9; Tls = 48; Http = 36; Ldap = 22; Com = 64; Local = 6 }
    computer = [ordered]@{ name = 'GROUND-WEB'; user = 'ALCYONE\ops-analyst'; isAdmin = $false; partOfDomain = $true; domain = 'alcyone-orbital.example'; dnsDomain = 'alcyone-orbital.example'
        site = 'Default-First-Site-Name'; netbios = 'ALCYONE' }
    forest = [ordered]@{ name = 'alcyone-orbital.example'; rootDomain = 'alcyone-orbital.example'; forestMode = 'Windows2016Forest'; domains = @('alcyone-orbital.example', 'flightops.example')
        trusts = @([ordered]@{ source = 'Forest'; targetName = 'launchpartner.example'; trustType = 'Forest'; trustDirection = 'Inbound' }) }
    directory = [ordered]@{ servers = @('dc-north.alcyone-orbital.example'); unreachable = @()
        rootDse = [ordered]@{ configurationNamingContext = $cfg; rootDomainNamingContext = $dom; defaultNamingContext = $dom; schemaNamingContext = "CN=Schema,$cfg"
            dnsHostName = 'dc-north.alcyone-orbital.example'; serverName = "CN=DC-NORTH,CN=Servers,$site"; domainControllerFunctionality = '7' }
        accountNames = [ordered]@{}; denied = [ordered]@{}; absent = @(); objects = $objects }
    cas = $cas; network = $network; local = $local
}
[System.IO.File]::WriteAllText($Output, ($world | ConvertTo-Json -Depth 12), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ('Wrote {0} ({1} directory objects)' -f $Output, $objects.Count)
