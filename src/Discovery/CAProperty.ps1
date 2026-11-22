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
# Binary values are requested as Base64 text (CR_OUT_BASE64 = 1). Every call is traced for the log (property name and id,
# index, requested data type, the type of the raw result, its size, the time it took and the error code). The VALUES are
# never traced: the trace holds no certificate, CRL or other content.
$script:MspkiCAPropertyReader = {
    param([string]$Config, [hashtable]$Props, [string[]]$Plain, [string[]]$Indexed, [int]$MaxIndex)
    $result = @{ Values = @{}; Errors = @{}; Fatal = $null; Count = -1; Trace = (New-Object System.Collections.ArrayList); Config = $Config }
    function Get-MspkiReaderError($err) {
        $e = $err.Exception
        while ($null -ne $e.InnerException) { $e = $e.InnerException }
        return @{ HResult = ('{0:X8}' -f $e.HResult); Message = ([string]$e.Message).Trim() }
    }
    function Invoke-MspkiReaderCall($ca, $name, $index) {
        $p = $Props[$name]
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $v = $ca.GetCAProperty($Config, $p.Id, $index, $p.Type, 1)
            $rt = 'null'; $size = 0
            if ($null -ne $v) {
                $rt = $v.GetType().Name
                if ($v -is [string]) { $size = $v.Length } elseif ($v -is [byte[]]) { $size = $v.Length }
            }
            [void]$result.Trace.Add(@{ Name = $name; Id = $p.Id; Index = $index; DataType = $p.Type; ResultType = $rt; Size = $size; ElapsedMs = [int64]$sw.ElapsedMilliseconds; HResult = '' })
            return $v
        }
        catch {
            $er = Get-MspkiReaderError $_
            [void]$result.Trace.Add(@{ Name = $name; Id = $p.Id; Index = $index; DataType = $p.Type; ResultType = 'error'; Size = 0; ElapsedMs = [int64]$sw.ElapsedMilliseconds; HResult = $er.HResult })
            throw
        }
    }
    try { $ca = New-Object -ComObject CertificateAuthority.Request }
    catch { $result.Fatal = Get-MspkiReaderError $_; return $result }
    try { $result.Values['CAType'] = Invoke-MspkiReaderCall $ca 'CAType' 0 }
    catch { $result.Fatal = Get-MspkiReaderError $_; return $result }
    foreach ($n in $Plain) {
        try { $result.Values[$n] = Invoke-MspkiReaderCall $ca $n 0 }
        catch { $result.Errors[$n] = Get-MspkiReaderError $_ }
    }
    try { $result.Count = [int](Invoke-MspkiReaderCall $ca 'CASigCertCount' 0) }
    catch { $result.Errors['CASigCertCount'] = Get-MspkiReaderError $_ }
    $n = [math]::Min($result.Count, $MaxIndex)
    for ($i = 0; $i -lt $n; $i++) {
        foreach ($name in $Indexed) {
            $key = '{0}[{1}]' -f $name, $i
            try { $result.Values[$key] = Invoke-MspkiReaderCall $ca $name $i }
            catch { $result.Errors[$key] = Get-MspkiReaderError $_ }
        }
    }
    return $result
}
# HRESULTs that mean "no CA with this name on that host" when they are the answer to the first call of a CA connection:
# ERROR_FILE_NOT_FOUND and E_INVALIDARG. Only then is another connection string (the CA's common name instead of its
# display name) worth a try.
$script:MspkiCaNameMismatchHResult = @('80070002', '80070057')

function Get-MspkiCaConfigCandidate {
    <#
    .SYNOPSIS
    The CA connection strings to try, in order: the one built from the display name (host\name), then, when AD has a different
    common name, host\commonName. Each is tried only until one answers.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$CA)
    $list = New-Object System.Collections.ArrayList
    if ($CA.Config) { [void]$list.Add([string]$CA.Config) }
    $h = [string]$CA.DnsHostName
    if ($h -and $CA.PSObject.Properties['CommonName'] -and $CA.CommonName) {
        $alt = '{0}\{1}' -f $h, $CA.CommonName
        if (-not ($list | Where-Object { $_ -ieq $alt })) { [void]$list.Add($alt) }
    }
    return $list.ToArray()
}

function Write-MspkiCaPropertyTrace {
    <#
    .SYNOPSIS
    Writes the trace of one CA connection to the log: for every GetCAProperty call the property name and id, the index, the
    requested data type, the type and size of the raw result, the time it took and the error code. Never any value.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Trace = @(), [string]$Config = '')
    foreach ($t in $Trace) {
        if ($t.ResultType -eq 'error') {
            Write-MspkiLog -Message ('GetCAProperty {0} (property id {1}, index {2}, requested data type {3}) on {4}: error 0x{5} after {6} ms' -f $t.Name, $t.Id, $t.Index, $t.DataType, $Config, $t.HResult, $t.ElapsedMs)
        }
        else {
            Write-MspkiLog -Message ('GetCAProperty {0} (property id {1}, index {2}, requested data type {3}) on {4}: result type {5}, size {6} after {7} ms' -f $t.Name, $t.Id, $t.Index, $t.DataType, $Config, $t.ResultType, $t.Size, $t.ElapsedMs)
        }
    }
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

function Get-MspkiFirstCallElapsedMs {
    # The time of the first GetCAProperty call (the one that failed), or the whole attempt when no trace came back.
    param($Raw, $Run)
    if ($null -ne $Raw -and $null -ne $Raw.Trace) {
        $first = @($Raw.Trace | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if ($null -ne $first -and $null -ne $first.ElapsedMs) { return [int64]$first.ElapsedMs }
    }
    if ($null -ne $Run -and $null -ne $Run.ElapsedMs) { return [int64]$Run.ElapsedMs }
    return [int64]-1
}

function Get-MspkiCaRpcFailureDiagnosis {
    <#
    .SYNOPSIS
    Explains an RPC_S_SERVER_UNAVAILABLE (0x800706BA) from a CA after TCP 135 answered, using how fast it came back.

    .DESCRIPTION
    DCOM reports 0x800706BA for two very different situations, and the client API hides which one happened:
    - Quick (within FastLimitMs): the CA host's RPC endpoint mapper (TCP 135) took the activation request and answered it with an
      RPC fault, then closed the connection; no dynamic-port connection was even tried. In the lab this was RPC fault 5 (access
      denied) for one domain account while another account read the same CA: the host refused this account at the DCOM layer
      (machine-wide DCOM limits / the "Certificate Service DCOM Access" group, or DCOM hardening). The CA service itself is not
      the cause, and it is not a network failure. Reported as PERMISSION_DENIED with Inferred confidence, because the fault code
      itself is not visible to the tool.
    - Slow: no answer from the dynamic RPC port the endpoint mapper handed out: a firewall between this computer and the CA
      (49152-65535 or the CA's fixed port) is the usual cause. Reported as RPC_FAIL.
    Returns $null for other HRESULTs.
    #>
    [CmdletBinding()]
    param(
        [string]$HResult,
        [int64]$ElapsedMs = -1,
        [string]$HostName = '',
        [int]$FastLimitMs = 5000
    )
    if (([string]$HResult).TrimStart('0x').ToUpperInvariant() -ne '800706BA') { return $null }
    $timing = $(if ($ElapsedMs -ge 0) { ('The failing call came back after {0} ms.' -f $ElapsedMs) } else { 'The time of the failing call is unknown.' })
    if ($ElapsedMs -ge 0 -and $ElapsedMs -le $FastLimitMs) {
        return [pscustomobject]@{
            Kind = 'RejectedQuickly'; Status = 'Skipped'; StatusCode = 'PERMISSION_DENIED'; Confidence = 'Inferred'; Layer = 'PermissionDenied'
            Message = ('The CA host {0} turned down this account''s request to read the CA (DCOM reported "RPC server unavailable", error 0x800706BA, but it answered within {1} ms on TCP 135). The CA was not read; this is most likely a permission on the CA host for the account running the tool, not a network or CA outage.' -f $HostName, $ElapsedMs)
            Evidence = @($timing, ('Answered within {0} ms after TCP 135 was reachable: a blocked dynamic RPC port would have taken many seconds (connection time-out).' -f $FastLimitMs))
            Notes = 'Windows DCOM shows "RPC server unavailable" when the remote RPC endpoint mapper refuses the activation request itself. On a lab CA this was RPC fault 5 (access denied) for one ordinary domain account, while an administrator account read the same CA. Confidence is Inferred: the tool cannot see the fault code. Less likely causes with the same signature: the CA host''s DCOM hardening rejects the authentication level, or Certificate Services is being reinstalled.'
            Remediation = 'On the CA host (owner): check that the account (normally through Authenticated Users or Domain Users) is in the local group "Certificate Service DCOM Access" and that the machine-wide DCOM limits (dcomcnfg > My Computer > COM Security) grant it Remote Access and Remote Activation; look for DCOM events 10027/10028 or 10036 in the CA host''s System log at the time of this run. Also check the CA''s Security tab grants Read or Request Certificates. Then run the tool again.'
        }
    }
    return [pscustomobject]@{
        Kind = 'NoAnswer'; Status = 'Fail'; StatusCode = 'RPC_FAIL'; Confidence = 'Referenced'; Layer = 'Fail'
        Message = ('The CA host {0} answered on TCP 135 but the CA could not be reached over its dynamic RPC port (error 0x800706BA, RPC server unavailable).' -f $HostName)
        Evidence = @($timing)
        Notes = 'A slow "RPC server unavailable" after TCP 135 answered usually means a firewall blocks the dynamic RPC ports (49152-65535, or the port the CA is fixed to) between this computer and the CA, or the Certificate Services service is hung.'
        Remediation = 'Allow the CA''s RPC dynamic ports from client networks (or fix the CA to a known port and allow that), and check that Certificate Services is running on the CA host.'
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
        [void]$findings.Add((Set-MspkiScopeCap -Finding (New-MspkiFinding @common -Status 'Fail' -StatusCode $dns.StatusCode -Confidence 'Referenced' `
            -Message ('The CA host {0} does not resolve in DNS from this computer.' -f $CA.DnsHostName) `
            -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = $dns.Status } -Evidence @(('DNS: {0} after {1} ms. {2}' -f $dns.Status, $dns.ElapsedMs, $dns.Error)))))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }
    $tcp = Test-MspkiTcpPort -HostName $CA.DnsHostName -Port 135 -TimeoutMs ($TimeoutSeconds * 1000)
    if ($tcp.Status -ne 'Pass') {
        Add-MspkiMethodOutcome -Method $method -Outcome 'Unreachable' -Detail ('{0}: TCP 135 {1}' -f $CA.Config, $tcp.Status)
        [void]$findings.Add((Set-MspkiScopeCap -Finding (New-MspkiFinding @common -Status 'Fail' -StatusCode $tcp.StatusCode -Confidence 'Referenced' `
            -Message ('The CA host {0} does not accept RPC connections (TCP 135) from this computer.' -f $CA.DnsHostName) `
            -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = 'Pass'; TcpStatus = $tcp.Status } `
            -Evidence @(('DNS: {0}' -f ($dns.Addresses -join ', ')), ('TCP 135: {0} after {1} ms. {2}' -f $tcp.Status, $tcp.ElapsedMs, $tcp.Error)))))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }

    $limit = [math]::Max(15, $TimeoutSeconds * 4)
    $configs = @(Get-MspkiCaConfigCandidate -CA $CA)
    $tried = New-Object System.Collections.ArrayList
    $raw = $null
    $run = $null
    $usedConfig = ''
    foreach ($cfg in $configs) {
        Write-MspkiLog -Message ('CA connection string tried ({0} of {1}): {2} (time limit {3} s)' -f ($tried.Count + 1), $configs.Count, $cfg, $limit)
        $run = Invoke-MspkiTimeLimitedScript -ScriptBlock $script:MspkiCAPropertyReader -TimeoutSeconds $limit -ArgumentList @(
            $cfg, $script:MspkiCAProp, $script:MspkiCAPlainProps, $script:MspkiCAIndexedProps, $MaxCertIndex)
        $raw = $null
        if ($run.Completed) { $raw = @($run.Output | Where-Object { $_ -is [hashtable] }) | Select-Object -First 1 }
        $outcome = 'Error'; $detail = ''
        if ($run.TimedOut) { $outcome = 'Timeout'; $detail = ('no answer within {0} s' -f $limit) }
        elseif ($null -eq $raw) { $detail = ($run.Errors -join '; ') }
        elseif ($null -ne $raw.Fatal) { $outcome = ('Failed 0x{0}' -f $raw.Fatal.HResult); $detail = $raw.Fatal.Message }
        else { $outcome = 'Answered' }
        [void]$tried.Add(('{0} -> {1} in {2} ms{3}' -f $cfg, $outcome, $run.ElapsedMs, $(if ($detail) { ' (' + $detail + ')' } else { '' })))
        Write-MspkiLog -Message ('CA connection string {0}: {1} after {2} ms {3}' -f $cfg, $outcome, $run.ElapsedMs, $detail).Trim()
        if ($null -ne $raw -and $null -ne $raw.Trace) { Write-MspkiCaPropertyTrace -Trace @($raw.Trace) -Config $cfg }
        if ($outcome -eq 'Answered') { $usedConfig = $cfg; break }
        # Only an answer that says "no CA of that name here" is worth another connection string; anything else (timeout, access
        # denied, RPC unavailable) would give the same result with a different name.
        if ($null -eq $raw -or $null -eq $raw.Fatal -or $script:MspkiCaNameMismatchHResult -notcontains [string]$raw.Fatal.HResult) { break }
    }
    $layers = @{ DiscoveryStatus = 'Pass'; DnsStatus = 'Pass'; TcpStatus = 'Pass' }
    $triedEvidence = @(('Connection string(s) tried: {0}' -f ($configs -join ' | '))) + @($tried | ForEach-Object { 'Attempt: {0}' -f $_ })
    if ($run.TimedOut) {
        Add-MspkiMethodOutcome -Method $method -Outcome 'Timeout' -Detail ($tried -join '; ') -ElapsedMs $run.ElapsedMs
        $f = New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Timeout' -Message ('No answer within {0} s.' -f $limit)) `
            -Category 'CA' -Target $CA.Name -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope $scope -Evidence $triedEvidence `
            -Action 'reading CA properties over DCOM' -UnreachableStatus 'Fail' `
            -Notes 'TCP 135 answered, so dynamic RPC ports may be blocked between this computer and the CA, or the CA service is hung.'
        [void]$findings.Add((Set-MspkiScopeCap -Finding $f))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }
    if ($null -eq $raw) {
        Add-MspkiMethodOutcome -Method $method -Outcome 'Error' -Detail (($run.Errors -join '; ')) -ElapsedMs $run.ElapsedMs
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Error' -Message ($run.Errors -join '; ')) `
            -Category 'CA' -Target $CA.Name -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope $scope -Evidence $triedEvidence `
            -Action 'reading CA properties over DCOM'))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }
    if ($null -ne $raw.Fatal) {
        # The first call decides the CA-wide result, so it is classified here and not by the generic table: the codes for "file not
        # found", "invalid argument" and "class not registered" mean different things for different calls.
        $hr = [string]$raw.Fatal.HResult
        $class = 'Error'
        if ($script:MspkiHResultClass.ContainsKey($hr)) { $class = $script:MspkiHResultClass[$hr] }
        Add-MspkiMethodOutcome -Method $method -Outcome $class -Detail ('{0}: 0x{1}' -f ($tried -join '; '), $hr) -ElapsedMs $run.ElapsedMs
        if ($script:MspkiCaNameMismatchHResult -contains $hr) {
            $f = New-MspkiFinding @common -Status 'Fail' -StatusCode 'CONFIG_MISMATCH' -Confidence 'Referenced' -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = 'Pass'; TcpStatus = 'Pass'; ContentStatus = 'Fail' } `
                -Message ('The host {0} answered, but no Certification Authority named {1} was found there (HRESULT 0x{2}).' -f $CA.DnsHostName, $CA.Name, $hr) `
                -Evidence ($triedEvidence + @(('HResult: 0x{0}' -f $hr), ('Message: {0}' -f $raw.Fatal.Message))) `
                -Notes 'The Enrollment Services object in AD names a CA that this host does not answer for. The Certificate Services service may be stopped or uninstalled, the CA may have been renamed or moved, or the AD object may be left over. If other CAs on the same kind of host answer, compare the CA name with the one shown by the CA itself.'
        }
        elseif ($hr -eq '80040154') {
            $f = New-MspkiFinding @common -Status 'Skipped' -StatusCode 'NOT_APPLICABLE' -Confidence 'Referenced' -Layers @{ DiscoveryStatus = 'Skipped' } `
                -Message 'The Certification Authority client COM class (CertificateAuthority.Request) is not registered on this computer, so no CA can be asked for its properties from here.' `
                -Evidence ($triedEvidence + @('HResult: 0x80040154 (class not registered)', ('Message: {0}' -f $raw.Fatal.Message))) `
                -Notes 'This is a limit of the computer running the tool, not a finding about the CA.'
        }
        elseif ($null -ne ($diag = Get-MspkiCaRpcFailureDiagnosis -HResult $hr -ElapsedMs (Get-MspkiFirstCallElapsedMs -Raw $raw -Run $run) -HostName $CA.DnsHostName)) {
            $f = New-MspkiFinding @common -Status $diag.Status -StatusCode $diag.StatusCode -Confidence $diag.Confidence `
                -Layers @{ DiscoveryStatus = 'Pass'; DnsStatus = 'Pass'; TcpStatus = 'Pass'; ContentStatus = $diag.Layer } `
                -Message $diag.Message -Notes $diag.Notes -Remediation $diag.Remediation `
                -Evidence ($triedEvidence + $diag.Evidence + @(('HResult: 0x{0}' -f $hr), ('Message: {0}' -f $raw.Fatal.Message)))
        }
        else {
            $notes = ''
            if ($class -eq 'PermissionDenied') { $notes = 'The account running the tool needs Read (or Request Certificates) permission on the CA.' }
            if ($class -eq 'Unreachable') { $notes = 'TCP 135 answered but the CA did not: the Certificate Services service may be stopped, or dynamic RPC ports are blocked.' }
            $f = New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class $class -HResult ('0x' + $hr) -Message $raw.Fatal.Message) `
                -Category 'CA' -Target $CA.Name -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope $scope -Evidence $triedEvidence `
                -Action 'reading CA properties over DCOM' -UnreachableStatus 'Fail' -Notes $notes
        }
        [void]$findings.Add((Set-MspkiScopeCap -Finding $f))
        return [pscustomobject]@{ Data = $null; Findings = @($findings) }
    }
    $props = ConvertFrom-MspkiCAPropertyResult -Raw $raw
    $props | Add-Member -NotePropertyName 'ConfigUsed' -NotePropertyValue $usedConfig -Force
    Add-MspkiMethodOutcome -Method $method -Outcome 'Success' `
        -Detail ('{0}: {1} signing certificate(s), {2} property error(s); {3} call(s) traced in the log' -f $usedConfig, $props.SigningCertCount, $props.PropertyErrors.Count, @($raw.Trace | Where-Object { $_ }).Count) `
        -ElapsedMs $run.ElapsedMs
    $ev = @(
        ('Connection string that answered: {0}' -f $usedConfig),
        ('Connection string(s) tried: {0}' -f ($tried -join ' | ')),
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
