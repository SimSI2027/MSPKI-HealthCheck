# CA properties through the in-box COM object CertificateAuthority.Request (ICertRequest2::GetCAProperty),
# the same read-only call that "certutil -CAInfo" uses. Nothing is requested or changed on the CA.
# Property ids are the CR_PROP_* constants from certcli.h (Windows SDK).

$script:MspkiCAProp = @{
    FileVersion          = @{ Id = 1;  Type = 4 }
    ProductVersion       = @{ Id = 2;  Type = 4 }
    CAName               = @{ Id = 6;  Type = 4 }
    SanitizedCAName      = @{ Id = 7;  Type = 4 }
    ParentCA             = @{ Id = 9;  Type = 4 }
    CAType               = @{ Id = 10; Type = 1 }
    CASigCertCount       = @{ Id = 11; Type = 1 }
    CASigCert            = @{ Id = 12; Type = 3 }   # indexed, binary
    BaseCrl              = @{ Id = 17; Type = 3 }   # indexed, binary: the CA's own current base CRL
    DeltaCrl             = @{ Id = 18; Type = 3 }   # indexed, binary: the CA's own current delta CRL
    CACertState          = @{ Id = 19; Type = 1 }   # indexed
    CrlState             = @{ Id = 20; Type = 1 }   # indexed
    DnsName              = @{ Id = 22; Type = 4 }
    RoleSeparation       = @{ Id = 23; Type = 1 }
    KraCertUsedCount     = @{ Id = 24; Type = 1 }
    KraCertCount         = @{ Id = 25; Type = 1 }
    AdvancedServer       = @{ Id = 28; Type = 1 }
    Templates            = @{ Id = 29; Type = 4 }
    BaseCrlPublishStatus = @{ Id = 30; Type = 1 }   # indexed
    DeltaCrlPublishStatus= @{ Id = 31; Type = 1 }   # indexed
    CACertVersion        = @{ Id = 39; Type = 1 }   # indexed
    CertCdpUrls          = @{ Id = 41; Type = 4 }   # indexed
    CertAiaUrls          = @{ Id = 42; Type = 4 }   # indexed
    CertAiaOcspUrls      = @{ Id = 43; Type = 4 }   # indexed
}
$script:MspkiCAPlainProps = @('CAName', 'SanitizedCAName', 'DnsName', 'ParentCA', 'FileVersion', 'ProductVersion',
    'RoleSeparation', 'AdvancedServer', 'KraCertCount', 'KraCertUsedCount', 'Templates')
$script:MspkiCAIndexedProps = @('CASigCert', 'CACertState', 'CACertVersion', 'CrlState', 'BaseCrlPublishStatus',
    'DeltaCrlPublishStatus', 'CertCdpUrls', 'CertAiaUrls', 'CertAiaOcspUrls', 'BaseCrl', 'DeltaCrl')

# CA type (ENUM_CATYPES) and CA certificate / CRL state (CA_DISP_*).
$script:MspkiCATypeNames = @{ 0 = 'EnterpriseRoot'; 1 = 'EnterpriseSubordinate'; 3 = 'StandaloneRoot'; 4 = 'StandaloneSubordinate' }
$script:MspkiCADispNames = @{ 0 = 'Incomplete'; 1 = 'Error'; 2 = 'Revoked'; 3 = 'Valid'; 4 = 'Invalid'; 5 = 'UnderSubmission' }

# Runs inside a separate runspace (Invoke-MspkiTimeLimitedScript), so it must be self-contained.
# Binary values are requested as Base64 text (CR_OUT_BASE64 = 1).
$script:MspkiCAPropertyReader = {
    param([string]$Config, [hashtable]$Props, [string[]]$Plain, [string[]]$Indexed, [int]$MaxIndex)
    $result = @{ Values = @{}; Errors = @{}; Fatal = $null; Count = -1 }
    function Get-MspkiReaderError($err) {
        $e = $err.Exception
        while ($null -ne $e.InnerException) { $e = $e.InnerException }
        return @{ HResult = ('{0:X8}' -f $e.HResult); Message = ([string]$e.Message).Trim() }
    }
    try { $ca = New-Object -ComObject CertificateAuthority.Request }
    catch { $result.Fatal = Get-MspkiReaderError $_; return $result }
    try {
        $p = $Props['CAType']
        $result.Values['CAType'] = $ca.GetCAProperty($Config, $p.Id, 0, $p.Type, 1)
    }
    catch { $result.Fatal = Get-MspkiReaderError $_; return $result }
    foreach ($n in $Plain) {
        $p = $Props[$n]
        try { $result.Values[$n] = $ca.GetCAProperty($Config, $p.Id, 0, $p.Type, 1) }
        catch { $result.Errors[$n] = Get-MspkiReaderError $_ }
    }
    try {
        $p = $Props['CASigCertCount']
        $result.Count = [int]$ca.GetCAProperty($Config, $p.Id, 0, $p.Type, 1)
    }
    catch { $result.Errors['CASigCertCount'] = Get-MspkiReaderError $_ }
    $n = [math]::Min($result.Count, $MaxIndex)
    for ($i = 0; $i -lt $n; $i++) {
        foreach ($name in $Indexed) {
            $p = $Props[$name]
            $key = '{0}[{1}]' -f $name, $i
            try { $result.Values[$key] = $ca.GetCAProperty($Config, $p.Id, $i, $p.Type, 1) }
            catch { $result.Errors[$key] = Get-MspkiReaderError $_ }
        }
    }
    return $result
}

function Split-MspkiCAPropertyText {
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return , @() }
    return , @(([string]$Value) -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
}

function Read-MspkiCaCrlProperty {
    <#
    .SYNOPSIS
    Decodes the CA's own base or delta CRL from a GetCAProperty value (Base64 data -> DER -> CRL).
    State: Read | Empty (the CA has no such CRL, for example deltas are disabled) | Error | NotRead.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Raw, [Parameter(Mandatory = $true)][string]$Name)
    $o = @{ Crl = $null; State = 'NotRead'; Detail = '' }
    if ($Raw.Values.ContainsKey($Name) -and $null -ne $Raw.Values[$Name]) {
        try {
            $bytes = ConvertFrom-MspkiBase64Data -Text ([string]$Raw.Values[$Name])
            $o.Crl = ConvertFrom-MspkiCrl -Bytes $bytes
            $o.State = 'Read'
        }
        catch { $o.State = 'Error'; $o.Detail = (Get-MspkiErrorInfo $_).Message }
    }
    elseif ($Raw.Errors.ContainsKey($Name)) {
        $e = $Raw.Errors[$Name]
        $class = 'Error'
        if ($script:MspkiHResultClass.ContainsKey([string]$e.HResult)) { $class = $script:MspkiHResultClass[[string]$e.HResult] }
        if ($class -eq 'NotFound') { $o.State = 'Empty'; $o.Detail = 'The CA holds no such CRL (property empty).' }
        else { $o.State = 'Error'; $o.Detail = ('{0} 0x{1} {2}' -f $class, $e.HResult, $e.Message) }
    }
    return [pscustomobject]$o
}

function ConvertFrom-MspkiCAPropertyResult {
    <#
    .SYNOPSIS
    Converts the raw reader output (Values / Errors / Count) into a CA properties object.
    Pure function: no network access.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Raw)
    $v = $Raw.Values
    $caType = $null
    if ($v.ContainsKey('CAType')) { $caType = [int]$v['CAType'] }
    $typeName = 'Unknown'
    if ($null -ne $caType -and $script:MspkiCATypeNames.ContainsKey($caType)) { $typeName = $script:MspkiCATypeNames[$caType] }

    $templates = New-Object System.Collections.ArrayList
    if ($v.ContainsKey('Templates')) {
        $t = Split-MspkiCAPropertyText $v['Templates']
        for ($i = 0; $i -lt $t.Count; $i += 2) {
            $oid = ''
            if ($i + 1 -lt $t.Count) { $oid = $t[$i + 1] }
            [void]$templates.Add([pscustomobject]@{ Name = $t[$i]; Oid = $oid })
        }
    }

    $sig = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt [int]$Raw.Count; $i++) {
        $certKey = 'CASigCert[{0}]' -f $i
        if (-not $v.ContainsKey($certKey) -and -not $Raw.Errors.ContainsKey($certKey)) { continue }
        $cert = $null; $certError = ''
        if ($v.ContainsKey($certKey)) {
            try { $cert = New-MspkiCertificate -Text ([string]$v[$certKey]) }
            catch { $certError = (Get-MspkiErrorInfo $_).Message }
        }
        else { $certError = ('0x{0} {1}' -f $Raw.Errors[$certKey].HResult, $Raw.Errors[$certKey].Message) }
        $state = $null
        if ($v.ContainsKey(('CACertState[{0}]' -f $i))) { $state = [int]$v[('CACertState[{0}]' -f $i)] }
        $stateName = 'Unknown'
        if ($null -ne $state -and $script:MspkiCADispNames.ContainsKey($state)) { $stateName = $script:MspkiCADispNames[$state] }
        $crlState = $null
        if ($v.ContainsKey(('CrlState[{0}]' -f $i))) { $crlState = [int]$v[('CrlState[{0}]' -f $i)] }
        $crlStateName = 'Unknown'
        if ($null -ne $crlState -and $script:MspkiCADispNames.ContainsKey($crlState)) { $crlStateName = $script:MspkiCADispNames[$crlState] }
        $verLabel = ''
        if ($v.ContainsKey(('CACertVersion[{0}]' -f $i))) {
            $vv = [int64]$v[('CACertVersion[{0}]' -f $i)]
            $verLabel = 'V{0}.{1}' -f ($vv % 65536), [math]::Floor($vv / 65536)
        }
        $baseCrlStatus = $null; $deltaCrlStatus = $null
        if ($v.ContainsKey(('BaseCrlPublishStatus[{0}]' -f $i))) { $baseCrlStatus = [int]$v[('BaseCrlPublishStatus[{0}]' -f $i)] }
        if ($v.ContainsKey(('DeltaCrlPublishStatus[{0}]' -f $i))) { $deltaCrlStatus = [int]$v[('DeltaCrlPublishStatus[{0}]' -f $i)] }
        $baseCrl = Read-MspkiCaCrlProperty -Raw $Raw -Name ('BaseCrl[{0}]' -f $i)
        $deltaCrl = Read-MspkiCaCrlProperty -Raw $Raw -Name ('DeltaCrl[{0}]' -f $i)
        [void]$sig.Add([pscustomobject][ordered]@{
            Index                 = $i
            Certificate           = $cert
            CertificateError      = $certError
            State                 = $state
            StateName             = $stateName
            CAVersion             = $verLabel
            CrlState              = $crlState
            CrlStateName          = $crlStateName
            BaseCrlPublishStatus  = $baseCrlStatus
            DeltaCrlPublishStatus = $deltaCrlStatus
            BaseCrl               = $baseCrl.Crl
            BaseCrlState          = $baseCrl.State
            BaseCrlDetail         = $baseCrl.Detail
            DeltaCrl              = $deltaCrl.Crl
            DeltaCrlState         = $deltaCrl.State
            DeltaCrlDetail        = $deltaCrl.Detail
            CdpUrls               =(Split-MspkiCAPropertyText $v[('CertCdpUrls[{0}]' -f $i)])
            AiaUrls               = (Split-MspkiCAPropertyText $v[('CertAiaUrls[{0}]' -f $i)])
            OcspUrls              = (Split-MspkiCAPropertyText $v[('CertAiaOcspUrls[{0}]' -f $i)])
        })
    }

    $errs = New-Object System.Collections.ArrayList
    foreach ($k in ($Raw.Errors.Keys | Sort-Object)) {
        $e = $Raw.Errors[$k]
        $class = 'Error'
        if ($script:MspkiHResultClass.ContainsKey([string]$e.HResult)) { $class = $script:MspkiHResultClass[[string]$e.HResult] }
        if ($class -eq 'NotFound' -and $k -match '^(Base|Delta)Crl\[') { continue }   # no such CRL: shown as BaseCrlState/DeltaCrlState
        [void]$errs.Add([pscustomobject]@{ Property = $k; HResult = ('0x' + $e.HResult); Class = $class; Message = $e.Message })
    }

    $num = {
        param($name)
        if ($v.ContainsKey($name) -and $null -ne $v[$name]) { return [int]$v[$name] }
        return $null
    }
    return [pscustomobject][ordered]@{
        CAType              = $caType
        CATypeName          = $typeName
        CAName              = [string]$v['CAName']
        SanitizedCAName     = [string]$v['SanitizedCAName']
        DnsName             = ConvertTo-MspkiHostName ([string]$v['DnsName'])
        ParentCA            = [string]$v['ParentCA']
        FileVersion         = [string]$v['FileVersion']
        ProductVersion      = [string]$v['ProductVersion']
        RoleSeparation      = (& $num 'RoleSeparation')
        AdvancedServer      = (& $num 'AdvancedServer')
        KraCertCount        = (& $num 'KraCertCount')
        KraCertUsedCount    = (& $num 'KraCertUsedCount')
        Templates           = @($templates)
        SigningCertCount    = [int]$Raw.Count
        SigningCertificates = @($sig)
        PropertyErrors      = @($errs)
    }
}

function Get-MspkiCAProperty {
    <#
    .SYNOPSIS
    Reads an Enterprise CA's properties over DCOM, after DNS and TCP 135 pre-checks, with a hard time limit.

    .OUTPUTS
    Data: CA properties object (ConvertFrom-MspkiCAPropertyResult) or $null. Findings: one finding with
    the outcome (properties read, permission denied, unreachable, timed out or skipped).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$CA,
        $Context = $null,
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork,
        [int]$MaxCertIndex = 64
    )
    $findings = New-Object System.Collections.ArrayList
    $scope = 'Unknown'
    if ($null -ne $Context) {
        $scope = Get-MspkiHostScope -HostName $CA.DnsHostName -LocalDomains @($Context.ForestDomains) -TrustedDomains @($Context.TrustedDomains)
    }
    $method = 'CA:GetCAProperty'
    $src = @('AD:EnrollmentServices', $method)
    $common = @{ Category = 'CA'; Target = $CA.Name; Endpoint = $CA.Config; RelatedCA = $CA.Name; Scope = $scope; Sources = $src }

    if (-not $CA.Config) {
        [void]$findings.Add((New-MspkiFinding @common -Status 'Warning' -StatusCode 'NOT_CONFIGURED' -Confidence 'Referenced' `
            -Message 'The Enrollment Services object has no dNSHostName, so the CA cannot be contacted.' `
            -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = 'NotApplicable' }))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }
    if ($SkipNetwork) {
        Add-MspkiMethodOutcome -Method $method -Outcome 'Skipped' -Detail ('{0}: -SkipNetwork' -f $CA.Config)
        [void]$findings.Add((New-MspkiFinding @common -Status 'Skipped' -StatusCode 'NOT_APPLICABLE' -Confidence 'Referenced' `
            -Message 'CA properties were not read because -SkipNetwork was used.' -Layers @{ DiscoveryStatus = 'Skipped' }))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }

    $dns = Resolve-MspkiDnsName -HostName $CA.DnsHostName -TimeoutMs ($TimeoutSeconds * 1000)
    if ($dns.Status -ne 'Pass') {
        Add-MspkiMethodOutcome -Method $method -Outcome 'Unreachable' -Detail ('{0}: DNS {1}' -f $CA.Config, $dns.Status)
        [void]$findings.Add((New-MspkiFinding @common -Status 'Fail' -StatusCode $dns.StatusCode -Confidence 'Referenced' `
            -Message ('The CA host {0} does not resolve in DNS from this computer.' -f $CA.DnsHostName) `
            -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = $dns.Status } -Evidence @(('DNS: {0} after {1} ms. {2}' -f $dns.Status, $dns.ElapsedMs, $dns.Error))))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }
    $tcp = Test-MspkiTcpPort -HostName $CA.DnsHostName -Port 135 -TimeoutMs ($TimeoutSeconds * 1000)
    if ($tcp.Status -ne 'Pass') {
        Add-MspkiMethodOutcome -Method $method -Outcome 'Unreachable' -Detail ('{0}: TCP 135 {1}' -f $CA.Config, $tcp.Status)
        [void]$findings.Add((New-MspkiFinding @common -Status 'Fail' -StatusCode $tcp.StatusCode -Confidence 'Referenced' `
            -Message ('The CA host {0} does not accept RPC connections (TCP 135) from this computer.' -f $CA.DnsHostName) `
            -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = 'Pass'; TcpStatus = $tcp.Status } `
            -Evidence @(('DNS: {0}' -f ($dns.Addresses -join ', ')), ('TCP 135: {0} after {1} ms. {2}' -f $tcp.Status, $tcp.ElapsedMs, $tcp.Error))))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }

    $limit = [math]::Max(15, $TimeoutSeconds * 4)
    $run = Invoke-MspkiTimeLimitedScript -ScriptBlock $script:MspkiCAPropertyReader -TimeoutSeconds $limit -ArgumentList @(
        $CA.Config, $script:MspkiCAProp, $script:MspkiCAPlainProps, $script:MspkiCAIndexedProps, $MaxCertIndex)
    $layers = @{ DiscoveryStatus = 'Pass'; DnsStatus = 'Pass'; TcpStatus = 'Pass' }
    if ($run.TimedOut) {
        Add-MspkiMethodOutcome -Method $method -Outcome 'Timeout' -Detail $CA.Config -ElapsedMs $run.ElapsedMs
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Timeout' -Message ('No answer within {0} s.' -f $limit)) `
            -Category 'CA' -Target $CA.Name -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope $scope `
            -Action 'reading CA properties over DCOM' -UnreachableStatus 'Fail' `
            -Notes 'TCP 135 answered, so dynamic RPC ports may be blocked between this computer and the CA, or the CA service is hung.'))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }
    $raw = $null
    if ($run.Completed) { $raw = @($run.Output | Where-Object { $_ -is [hashtable] }) | Select-Object -First 1 }
    if ($null -eq $raw) {
        Add-MspkiMethodOutcome -Method $method -Outcome 'Error' -Detail (($run.Errors -join '; ')) -ElapsedMs $run.ElapsedMs
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Error' -Message ($run.Errors -join '; ')) `
            -Category 'CA' -Target $CA.Name -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope $scope `
            -Action 'reading CA properties over DCOM'))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }
    if ($null -ne $raw.Fatal) {
        $class = 'Error'
        if ($script:MspkiHResultClass.ContainsKey([string]$raw.Fatal.HResult)) { $class = $script:MspkiHResultClass[[string]$raw.Fatal.HResult] }
        Add-MspkiMethodOutcome -Method $method -Outcome $class -Detail ('{0}: 0x{1}' -f $CA.Config, $raw.Fatal.HResult) -ElapsedMs $run.ElapsedMs
        $notes = ''
        if ($class -eq 'PermissionDenied') { $notes = 'The account running the tool needs Read (or Request Certificates) permission on the CA.' }
        if ($class -eq 'Unreachable') { $notes = 'TCP 135 answered but the CA did not: the Certificate Services service may be stopped, or dynamic RPC ports are blocked.' }
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class $class -HResult ('0x' + $raw.Fatal.HResult) -Message $raw.Fatal.Message) `
            -Category 'CA' -Target $CA.Name -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope $scope `
            -Action 'reading CA properties over DCOM' -UnreachableStatus 'Fail' -Notes $notes))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }

    $props = ConvertFrom-MspkiCAPropertyResult -Raw $raw
    Add-MspkiMethodOutcome -Method $method -Outcome 'Success' `
        -Detail ('{0}: {1} signing certificate(s), {2} property error(s)' -f $CA.Config, $props.SigningCertCount, $props.PropertyErrors.Count) `
        -ElapsedMs $run.ElapsedMs
    $ev = @(
        ('CA type: {0} ({1})' -f $props.CATypeName, $props.CAType),
        ('CA name (CA): {0}' -f $props.CAName),
        ('DNS name (CA): {0}' -f $props.DnsName),
        ('CA signing certificates: {0}' -f $props.SigningCertCount)
    )
    foreach ($s in $props.SigningCertificates) {
        $tp = ''
        if ($null -ne $s.Certificate) { $tp = $s.Certificate.Thumbprint }
        $ev += ('Signing certificate [{0}] {1}: state {2}, CRL state {3}, thumbprint {4}' -f $s.Index, $s.CAVersion, $s.StateName, $s.CrlStateName, $tp)
    }
    if ($props.ProductVersion) { $ev += ('Product version: {0}' -f $props.ProductVersion) }
    $ev += ('Templates offered (CA): {0}' -f $props.Templates.Count)
    if ($null -ne $props.KraCertCount) { $ev += ('KRA certificates: {0} (used: {1})' -f $props.KraCertCount, $props.KraCertUsedCount) }
    if ($null -ne $props.RoleSeparation) { $ev += ('Role separation enabled: {0}' -f $props.RoleSeparation) }
    foreach ($e in $props.PropertyErrors) { $ev += ('Property {0} not read: {1} {2}' -f $e.Property, $e.Class, $e.HResult) }
    if ($props.DnsName -and $props.DnsName -ne $CA.DnsHostName) {
        $ev += ('Note: the CA reports DNS name {0}, AD has {1}.' -f $props.DnsName, $CA.DnsHostName)
    }
    $status = 'Information'; $code = 'OK'
    $msg = ('CA properties read from {0}: {1}, {2} signing certificate(s).' -f $CA.Config, $props.CATypeName, $props.SigningCertCount)
    $layers['ContentStatus'] = 'Pass'
    [void]$findings.Add((New-MspkiFinding @common -Status $status -StatusCode $code -Confidence 'Confirmed' `
        -Role (Get-MspkiCARoleFromType -CATypeName $props.CATypeName) -Message $msg -Layers $layers -Evidence $ev))
    return [pscustomobject]@{ Data = $props; Findings = @($findings) }
}

function Get-MspkiCARoleFromType {
    [CmdletBinding()]
    param([string]$CATypeName)
    if ($script:MspkiSchema.Role -contains $CATypeName) { return $CATypeName }
    return 'Unknown'
}
