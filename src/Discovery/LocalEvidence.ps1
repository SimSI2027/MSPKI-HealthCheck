# Local evidence (ROADMAP D3): how this computer's certificates got here, read from what a normal user can read on this computer.
#   - certificate stores, public parts only (X509Store opened read-only; keys are never touched): CurrentUser\My, LocalMachine\My,
#     LocalMachine\Root, \CA (intermediate) and \NTAuth, plus the names of the Enterprise physical stores that Windows fills from AD;
#   - the CertificateServicesClient Lifecycle logs (System and User) and the AutoEnrollment / CertEnroll events in the Application log;
#   - the enrollment policy on this computer: the template cache autoenrollment downloads from AD, the autoenrollment policy and the
#     Remote Desktop certificate template policy (the CEP servers are read by LocalPolicy.ps1).
# Read-only: stores opened ReadOnly/OpenExistingOnly, registry keys opened without write access, event logs read with Get-WinEvent.

$script:MspkiLifecycleLogs = @(
    @{ Name = 'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational'; Context = 'System' }
    @{ Name = 'Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational'; Context = 'User' }
)
$script:MspkiLifecycleAction = @{ 1001 = 'Replaced'; 1002 = 'Expired'; 1003 = 'AboutToExpire'; 1004 = 'Deleted'; 1006 = 'Installed'; 1007 = 'Exported' }
$script:MspkiEnrollmentEventProviders = @('Microsoft-Windows-CertificateServicesClient-AutoEnrollment', 'Microsoft-Windows-CertificateServicesClient-CertEnroll')

function Get-MspkiStoreReadError {
    # Classifies a store, registry or event log read failure by exception type (never by localised text).
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($null -ne $e.InnerException -and -not ($e -is [System.UnauthorizedAccessException] -or $e -is [System.Security.SecurityException])) { $e = $e.InnerException }
    $class = 'Error'
    if ($e -is [System.UnauthorizedAccessException] -or $e -is [System.Security.SecurityException]) { $class = 'PermissionDenied' }
    return (New-MspkiErrorInfo -Class $class -Message ([string]$ErrorRecord.Exception.Message).Trim())
}

function Read-MspkiLocalStore {
    <#
    .SYNOPSIS
    The public certificates of one store: { Store; Certificates; Error }. Each certificate is copied from its public bytes only.
    #>
    [CmdletBinding()]
    param([ValidateSet('CurrentUser', 'LocalMachine')][string]$Location, [Parameter(Mandatory = $true)][string]$Name)
    $path = 'Cert:\{0}\{1}' -f $Location, $Name
    $out = [pscustomobject]@{ Store = $path; Certificates = @(); Error = $null }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($Name, [System.Security.Cryptography.X509Certificates.StoreLocation]$Location)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
        $list = New-Object System.Collections.ArrayList
        foreach ($c in $store.Certificates) { [void]$list.Add((New-MspkiCertificate -Bytes $c.RawData)) }
        $out.Certificates = $list.ToArray()
    }
    catch { $out.Error = Get-MspkiStoreReadError $_ }
    finally { $store.Close() }
    return $out
}

function Get-MspkiEnterpriseStoreThumbprint {
    <#
    .SYNOPSIS
    The thumbprints in one Enterprise physical store (HKLM\SOFTWARE\Microsoft\EnterpriseCertificates\<store>\Certificates): the certificates
    Windows copied from AD (Certification Authorities -> Root, AIA -> CA, NTAuthCertificates -> NTAuth). Only key names are read.
    #>
    [CmdletBinding()]
    param([ValidateSet('Root', 'CA', 'NTAuth')][string]$Name)
    $out = [pscustomobject]@{ Store = $Name; Thumbprints = @(); Exists = $false; Error = $null }
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(('SOFTWARE\Microsoft\EnterpriseCertificates\{0}\Certificates' -f $Name), $false)
        if ($null -ne $k) {
            $out.Exists = $true
            $out.Thumbprints = @($k.GetSubKeyNames() | ForEach-Object { $_.ToUpperInvariant() })
            $k.Close()
        }
    }
    catch { $out.Error = Get-MspkiStoreReadError $_ }
    return $out
}

function ConvertTo-MspkiLocalCertificateInfo {
    <#
    .SYNOPSIS
    Public facts of one local certificate. Pure: { Store; Thumbprint; Subject; Issuer; NotBefore; NotAfter; Expired; IsCA; Ski; Aki; Eku;
    TemplateName; TemplateOid; TemplateMajorVersion; DnsNames; Urls }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$Store = '', [DateTime]$Now = [DateTime]::UtcNow)
    $c = $Certificate
    $isCA = $false
    $bc = Get-MspkiCertificateExtension -Certificate $c -Oid $script:MspkiOid.BasicConstraints
    if ($null -ne $bc) { $isCA = (New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension($bc, $bc.Critical)).CertificateAuthority }
    $ti = $null
    try { $ti = ConvertFrom-MspkiTemplateExtension -Certificate $c } catch { $ti = $null }
    $urls = @()
    # Get-MspkiCertificateUrl returns its list as ONE object ("return , array"): a pipeline would hand the whole list to Where-Object and
    # ForEach-Object as a single item and format it as "System.Object[]" (audit 3 N12). foreach enumerates the list itself.
    try {
        $urlList = New-Object System.Collections.ArrayList
        foreach ($u in (Get-MspkiCertificateUrl -Certificate $c)) { if ($u.Kind -ne 'Error') { [void]$urlList.Add(('{0}: {1}' -f $u.Kind, $u.Url)) } }
        $urls = @($urlList)
    }
    catch { $urls = @() }
    $names = @()
    try { $names = @(Get-MspkiCertificateDnsName -Certificate $c) } catch { $names = @() }
    $na = $c.NotAfter.ToUniversalTime()
    return [pscustomobject][ordered]@{
        Store = $Store; Thumbprint = $c.Thumbprint.ToUpperInvariant(); Subject = $c.Subject; Issuer = $c.Issuer
        NotBefore = $c.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); NotAfter = $na.ToString('yyyy-MM-ddTHH:mm:ssZ'); Expired = ($na -lt $Now.ToUniversalTime())
        IsCA = [bool]$isCA; Ski = (ConvertTo-MspkiKeyIdHex (Get-MspkiCertificateSubjectKeyId -Certificate $c)); Aki = (ConvertTo-MspkiKeyIdHex (Get-MspkiCertificateAuthorityKeyId -Certificate $c))
        Eku = @(Get-MspkiCertificateEku -Certificate $c)
        TemplateName = $(if ($null -ne $ti) { [string]$ti.Name } else { '' }); TemplateOid = $(if ($null -ne $ti) { [string]$ti.Oid } else { '' })
        TemplateMajorVersion = $(if ($null -ne $ti) { $ti.MajorVersion } else { $null })
        DnsNames = $names; Urls = $urls
    }
}

function ConvertFrom-MspkiLifecycleEventXml {
    <#
    .SYNOPSIS
    One CertificateServicesClient Lifecycle event (its XML) as data. Pure: { Log; Time; EventId; Action; Process; Account; Context; Thumbprint;
    TemplateName; TemplateOid; Subjects; NotAfter }. The action comes from the event (<Action>) or, when absent, from the event id.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Xml, [string]$Log = '')
    $x = [xml]$Xml
    $ev = $x.Event
    $id = [int]$ev.System.EventID
    $time = ''
    $tc = $ev.System.TimeCreated
    if ($null -ne $tc -and $tc.SystemTime) { $time = ([DateTime]::Parse([string]$tc.SystemTime, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')).ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $d = $null
    if ($null -ne $ev.UserData) { $d = $ev.UserData.CertNotificationData }
    $r = [pscustomobject][ordered]@{ Log = $Log; Time = $time; EventId = $id; Action = ''; Process = ''; Account = ''; Context = ''; Thumbprint = ''; TemplateName = ''; TemplateOid = ''; Subjects = @(); NotAfter = '' }
    if ($null -ne $d) {
        $r.Process = [string]$d.ProcessName; $r.Account = [string]$d.AccountName; $r.Context = [string]$d.Context
        if ($d.Action) { $r.Action = [string]$d.Action }
        $cd = $d.CertificateDetails
        if ($null -ne $cd) {
            $r.Thumbprint = ([string]$cd.Thumbprint).ToUpperInvariant() -replace '\s', ''
            if ($null -ne $cd.Template) { $r.TemplateName = [string]$cd.Template.Name; $r.TemplateOid = [string]$cd.Template.OID }
            if ($null -ne $cd.SubjectNames) { $r.Subjects = @($cd.SubjectNames.SubjectName | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
            if ($cd.NotValidAfter) { $r.NotAfter = [string]$cd.NotValidAfter }
        }
    }
    if (-not $r.Action -and $script:MspkiLifecycleAction.ContainsKey($id)) { $r.Action = $script:MspkiLifecycleAction[$id] }
    if (-not $r.Action) { $r.Action = ('event {0}' -f $id) }
    return $r
}

function Get-MspkiLifecycleEvent {
    <#
    .SYNOPSIS
    Reads both Lifecycle logs (newest first, at most -MaxEvents each). Returns { Events; Logs = @({ Name; Read; Count; Error }) }.
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 5000)][int]$MaxEvents = 500)
    $events = New-Object System.Collections.ArrayList
    $logs = New-Object System.Collections.ArrayList
    foreach ($l in $script:MspkiLifecycleLogs) {
        $st = [pscustomobject]@{ Name = $l.Name; Read = $false; Count = 0; Error = $null }
        try {
            $raw = @(Get-WinEvent -LogName $l.Name -MaxEvents $MaxEvents -ErrorAction Stop)
            foreach ($e in $raw) { try { [void]$events.Add((ConvertFrom-MspkiLifecycleEventXml -Xml $e.ToXml() -Log $l.Name)) } catch { } }
            $st.Read = $true; $st.Count = $raw.Count
        }
        catch {
            # An empty log throws "No events were found"; that is a successful read of nothing.
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $st.Read = $true }
            else { $st.Error = Get-MspkiStoreReadError $_ }
        }
        [void]$logs.Add($st)
    }
    return [pscustomobject]@{ Events = $events.ToArray(); Logs = $logs.ToArray() }
}

function Get-MspkiEnrollmentEvent {
    <#
    .SYNOPSIS
    AutoEnrollment and CertEnroll events from the Application log (newest first). Returns { Events; Read; Error }; each event is
    { Time; EventId; Provider; Level (Error / Warning / Information); Data (name -> text); Message (first 300 characters) }.
    #>
    [CmdletBinding()]
    param([ValidateRange(1, 5000)][int]$MaxEvents = 300)
    $out = [pscustomobject]@{ Events = @(); Read = $false; Error = $null }
    try {
        $raw = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $script:MspkiEnrollmentEventProviders } -MaxEvents $MaxEvents -ErrorAction Stop)
        $list = New-Object System.Collections.ArrayList
        foreach ($e in $raw) {
            $data = [ordered]@{}
            try { foreach ($d in @(([xml]$e.ToXml()).Event.EventData.Data)) { if ($null -ne $d -and $d.Name) { $data[[string]$d.Name] = [string]$d.InnerText } } } catch { }
            $lvl = $(switch ([int]$e.Level) { 1 { 'Error' } 2 { 'Error' } 3 { 'Warning' } default { 'Information' } })
            $msg = ''
            try { $msg = ([string]$e.Message -replace '\s+', ' ').Trim(); if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' } } catch { }
            [void]$list.Add([pscustomobject][ordered]@{ Time = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); EventId = [int]$e.Id; Provider = [string]$e.ProviderName; Level = $lvl; Data = $data; Message = $msg })
        }
        $out.Events = $list.ToArray(); $out.Read = $true
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $out.Read = $true }
        else { $out.Error = Get-MspkiStoreReadError $_ }
    }
    return $out
}

function ConvertFrom-MspkiFileTimeBytes {
    # An 8-byte little-endian FILETIME (as the template cache stores its Timestamp) to ISO 8601 UTC; '' when it is not one.
    param($Bytes)
    if ($null -eq $Bytes -or -not ($Bytes -is [byte[]]) -or $Bytes.Length -ne 8) { return '' }
    try { return ([DateTime]::FromFileTimeUtc([BitConverter]::ToInt64([byte[]]$Bytes, 0))).ToString('yyyy-MM-ddTHH:mm:ssZ') } catch { return '' }
}

function Get-MspkiEnrollmentPolicyState {
    <#
    .SYNOPSIS
    The enrollment policy this computer and user hold: the AD template cache (time and template names), the autoenrollment policy (AEPolicy)
    and the Remote Desktop certificate template policy. Returns { TemplateCache = @({ Scope; Path; Timestamp; Templates; Error }); AutoEnrollment =
    @({ Scope; Path; AEPolicy; Configured; Error }); RdpTemplate = { Path; Template; Error } }.
    #>
    [CmdletBinding()]
    param()
    $hives = @(@{ Scope = 'Computer'; Root = [Microsoft.Win32.Registry]::LocalMachine; Hive = 'HKLM' }, @{ Scope = 'User'; Root = [Microsoft.Win32.Registry]::CurrentUser; Hive = 'HKCU' })
    $cache = New-Object System.Collections.ArrayList
    $ae = New-Object System.Collections.ArrayList
    foreach ($h in $hives) {
        $p = 'SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache'
        $c = [pscustomobject]@{ Scope = $h.Scope; Path = ('{0}\{1}' -f $h.Hive, $p); Timestamp = ''; Templates = @(); Exists = $false; Error = $null }
        try {
            $k = $h.Root.OpenSubKey($p, $false)
            if ($null -ne $k) { $c.Exists = $true; $c.Timestamp = ConvertFrom-MspkiFileTimeBytes $k.GetValue('Timestamp'); $c.Templates = @($k.GetSubKeyNames()); $k.Close() }
        }
        catch { $c.Error = Get-MspkiStoreReadError $_ }
        [void]$cache.Add($c)
        $p2 = 'SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment'
        $a = [pscustomobject]@{ Scope = $h.Scope; Path = ('{0}\{1}' -f $h.Hive, $p2); AEPolicy = $null; Configured = $false; Error = $null }
        try {
            $k = $h.Root.OpenSubKey($p2, $false)
            if ($null -ne $k) { $v = $k.GetValue('AEPolicy'); if ($null -ne $v) { $a.AEPolicy = [int64]$v; $a.Configured = $true }; $k.Close() }
        }
        catch { $a.Error = Get-MspkiStoreReadError $_ }
        [void]$ae.Add($a)
    }
    $rdp = [pscustomobject]@{ Path = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Template = ''; Error = $null }
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services', $false)
        if ($null -ne $k) { $rdp.Template = [string]$k.GetValue('CertTemplateName'); $k.Close() }
    }
    catch { $rdp.Error = Get-MspkiStoreReadError $_ }
    return [pscustomobject]@{ TemplateCache = $cache.ToArray(); AutoEnrollment = $ae.ToArray(); RdpTemplate = $rdp }
}

function Get-MspkiAutoEnrollmentPolicyText {
    # AEPolicy bits in words: 1 = enroll / renew (Enabled), 2 = update certificates that use templates, 4 = remove revoked/expired, 0x8000 = disabled.
    param($Value)
    if ($null -eq $Value) { return 'not configured by policy (Windows default: autoenrollment runs, but only templates that grant Autoenroll are enrolled)' }
    $v = [int64]$Value
    if (($v -band 0x8000) -ne 0) { return ('disabled by policy (AEPolicy = 0x{0:X})' -f $v) }
    $parts = @()
    if (($v -band 1) -ne 0) { $parts += 'enroll and renew' }
    if (($v -band 2) -ne 0) { $parts += 'update certificates that use templates' }
    if (($v -band 4) -ne 0) { $parts += 'remove revoked and expired certificates' }
    if ($parts.Count -eq 0) { return ('configured, no action bits set (AEPolicy = 0x{0:X})' -f $v) }
    return ('enabled: {0} (AEPolicy = 0x{1:X})' -f ($parts -join ', '), $v)
}
