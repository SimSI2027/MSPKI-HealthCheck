# NDES evidence from the CA database (REQUIREMENTS 5.7, evidence 1): which computers were issued certificates from the
# "CEP Encryption" and "Exchange Enrollment Agent (Offline request)" templates. This uses the in-box COM object
# CertificateAuthority.View, which only reads the CA database (no request is submitted, nothing is changed).
# It needs read access to the CA database; a standard account usually sees only its own requests, so "no rows" is not
# proof that no NDES exists (reported as such). Access denied is PERMISSION_DENIED.

$script:MspkiNdesTemplateNames = @(
    @{ Name = 'CEPEncryption';          Display = 'CEP Encryption' }
    @{ Name = 'EnrollmentAgentOffline'; Display = 'Exchange Enrollment Agent (Offline request)' }
)

# Runs inside a separate runspace (Invoke-MspkiTimeLimitedScript), so it must be self-contained. One read-only view
# per template key: issued certificates (Disposition 20) of that template; columns are plain text and dates.
$script:MspkiNdesDbReader = {
    param([string]$Config, [string[]]$TemplateKeys, [int]$MaxRows)
    $result = @{ Rows = (New-Object System.Collections.ArrayList); Errors = (New-Object System.Collections.ArrayList); Fatal = $null }
    function Get-MspkiReaderError($err) {
        $e = $err.Exception
        while ($null -ne $e.InnerException) { $e = $e.InnerException }
        return @{ HResult = ('{0:X8}' -f $e.HResult); Message = ([string]$e.Message).Trim() }
    }
    $columns = @('Request.RequestID', 'Request.RequesterName', 'CommonName', 'CertificateTemplate', 'NotBefore', 'NotAfter')
    $first = $true
    foreach ($key in $TemplateKeys) {
        try {
            $view = New-Object -ComObject CertificateAuthority.View
            $view.OpenConnection($Config)
            $view.SetResultColumnCount($columns.Count)
            foreach ($c in $columns) { $view.SetResultColumn($view.GetColumnIndex($false, $c)) }
            # Restrictions are ANDed: issued certificates (20) of this template.
            $view.SetRestriction($view.GetColumnIndex($false, 'Request.Disposition'), 1, 0, 20)
            $view.SetRestriction($view.GetColumnIndex($false, 'CertificateTemplate'), 1, 0, $key)
            $rows = $view.OpenView()
            $n = 0
            while ($rows.Next() -ne -1 -and $n -lt $MaxRows) {
                $n++
                $rec = @{ TemplateKey = $key }
                $cols = $rows.EnumCertViewColumn()
                while ($cols.Next() -ne -1) {
                    $name = [string]$cols.GetName()
                    $val = $cols.GetValue(0)
                    if ($val -is [datetime]) { $val = $val.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
                    $rec[$name.ToLowerInvariant()] = [string]$val
                }
                [void]$result.Rows.Add($rec)
            }
            $first = $false
        }
        catch {
            $err = Get-MspkiReaderError $_
            # Access denied, an unreachable CA or a missing COM class applies to every key: stop at the first one.
            if ($first) { $result.Fatal = $err; return $result }
            [void]$result.Errors.Add(@{ Key = $key; HResult = $err.HResult; Message = $err.Message })
        }
    }
    return $result
}

function ConvertTo-MspkiNdesRow {
    <#
    .SYNOPSIS
    Normalises one row from the CA database reader (column names may carry a table prefix such as "Request.").
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Row)
    $get = {
        param($suffix)
        foreach ($k in $Row.Keys) { if ($k.ToLowerInvariant().EndsWith($suffix)) { return [string]$Row[$k] } }
        return ''
    }
    return [pscustomobject][ordered]@{
        RequestId = (& $get 'requestid'); Requester = (& $get 'requestername'); CommonName = (& $get 'commonname')
        Template = (& $get 'certificatetemplate'); NotBefore = (& $get 'notbefore'); NotAfter = (& $get 'notafter')
        TemplateKey = [string]$Row['TemplateKey']
    }
}

function Get-MspkiNdesHostCandidate {
    <#
    .SYNOPSIS
    Turns CA database rows into NDES host candidates. Pure function.

    .DESCRIPTION
    A NDES server asks the CA for its own RA certificates: the requester is normally the computer account
    (DOMAIN\HOST$) and the certificate name is "HOST-MSCEP-RA". Each signal that is present is listed. The DNS name
    is built from the NetBIOS-to-DNS domain map read from AD (or, when the forest has one domain, from that domain),
    so it is a constructed name: the caller checks it in DNS before anything is sent to it.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [string]$CaName = '',
        [hashtable]$DomainMap = @{},
        [string[]]$ForestDomains = @()
    )
    $by = @{}
    foreach ($row in @($Rows | Where-Object { $_ })) {
        $r = $row
        if ($row -is [hashtable]) { $r = ConvertTo-MspkiNdesRow -Row $row }
        $short = ''; $dom = ''; $signals = @()
        $m = [regex]::Match([string]$r.Requester, '^(?<d>[^\\]+)\\(?<a>[^\\]+)$')
        if ($m.Success) { $dom = $m.Groups['d'].Value }
        if ($m.Success -and $m.Groups['a'].Value.EndsWith('$')) {
            $short = $m.Groups['a'].Value.TrimEnd('$')
            $signals += ('requester is the computer account {0}' -f $r.Requester)
        }
        $ra = [regex]::Match([string]$r.CommonName, '^(?<h>.+)-MSCEP-RA(\s.*)?$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if ($ra.Success) {
            $h = $ra.Groups['h'].Value
            if (-not $short) { $short = $h }
            if ($h -ieq $short) { $signals += ('certificate name {0} follows the NDES RA naming ({1}-MSCEP-RA)' -f $r.CommonName, $h) }
        }
        if (-not $short) { continue }
        $key = $short.ToLowerInvariant()
        if (-not $by.ContainsKey($key)) {
            $by[$key] = [pscustomobject][ordered]@{ ShortName = $short; Domain = $dom; Fqdn = ''; DomainSource = 'none'; Signals = (New-Object System.Collections.ArrayList)
                Templates = (New-Object System.Collections.ArrayList); Requesters = (New-Object System.Collections.ArrayList); RequestIds = (New-Object System.Collections.ArrayList)
                Rows = 0; LatestNotAfter = ''; CAs = (New-Object System.Collections.ArrayList) }
        }
        $c = $by[$key]
        $c.Rows++
        foreach ($s in $signals) { if (-not $c.Signals.Contains($s)) { [void]$c.Signals.Add($s) } }
        $tn = [string]$r.Template; if ($r.TemplateKey) { $tn = [string]$r.TemplateKey }
        if ($tn -and -not $c.Templates.Contains($tn)) { [void]$c.Templates.Add($tn) }
        if ($r.Requester -and -not $c.Requesters.Contains([string]$r.Requester)) { [void]$c.Requesters.Add([string]$r.Requester) }
        if ($r.RequestId) { [void]$c.RequestIds.Add([string]$r.RequestId) }
        if ($r.NotAfter -and ($r.NotAfter -gt $c.LatestNotAfter)) { $c.LatestNotAfter = [string]$r.NotAfter }
        if ($CaName -and -not $c.CAs.Contains($CaName)) { [void]$c.CAs.Add($CaName) }
        if (-not $c.Domain -and $dom) { $c.Domain = $dom }
    }
    foreach ($c in $by.Values) {
        $root = ''
        if ($c.Domain -and $DomainMap.ContainsKey($c.Domain.ToUpperInvariant())) { $root = [string]$DomainMap[$c.Domain.ToUpperInvariant()]; $c.DomainSource = 'AD crossRef (NetBIOS name to DNS name)' }
        elseif (@($ForestDomains).Count -eq 1) { $root = [string]@($ForestDomains)[0]; $c.DomainSource = 'the only domain of the forest' }
        if ($root) { $c.Fqdn = ('{0}.{1}' -f $c.ShortName, $root).ToLowerInvariant() }
    }
    return , @($by.Values | Sort-Object ShortName)
}

function Get-MspkiNetBiosDomainMap {
    <#
    .SYNOPSIS
    NetBIOS domain name (upper case) to DNS name, from the crossRef objects in CN=Partitions (one level, two attributes).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context, [int]$TimeoutSeconds = 5)
    $map = @{}
    if (-not $Context.ConfigNC) { return $map }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $recs = @(Get-MspkiLdapObject -Server $Context.DomainController -BaseDN ('CN=Partitions,{0}' -f $Context.ConfigNC) -Scope OneLevel `
            -Filter '(&(objectClass=crossRef)(nETBIOSName=*))' -Properties @('nETBIOSName', 'dnsRoot') -TimeoutSeconds ([math]::Max(10, $TimeoutSeconds * 3)))
        foreach ($r in $recs) {
            $nb = [string](Get-MspkiLdapValue -Record $r -Name 'nETBIOSName')
            $dns = [string](Get-MspkiLdapValue -Record $r -Name 'dnsRoot')
            if ($nb -and $dns) { $map[$nb.ToUpperInvariant()] = $dns.ToLowerInvariant() }
        }
        Add-MspkiMethodOutcome -Method 'AD:Partitions:nETBIOSName' -Outcome 'Success' -Detail ('{0} domain(s)' -f $map.Count) -ElapsedMs $sw.ElapsedMilliseconds
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:Partitions:nETBIOSName' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
    }
    return $map
}

function Get-MspkiNdesTemplateKey {
    <#
    .SYNOPSIS
    The values that the CertificateTemplate column can hold for the two NDES templates: the template names (version 1
    templates) and the OIDs of the templates with these names or display names that AD has (version 2 and later).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Inventory)
    $keys = New-Object System.Collections.ArrayList
    foreach ($t in $script:MspkiNdesTemplateNames) { [void]$keys.Add($t.Name) }
    if ($null -ne $Inventory -and $Inventory.TemplatesRead -eq $true) {
        foreach ($tpl in @($Inventory.Templates)) {
            foreach ($t in $script:MspkiNdesTemplateNames) {
                if (($tpl.Name -ieq $t.Name -or $tpl.DisplayName -ieq $t.Display) -and $tpl.Oid -and -not $keys.Contains([string]$tpl.Oid)) { [void]$keys.Add([string]$tpl.Oid) }
            }
        }
    }
    return , $keys.ToArray()
}

function Get-MspkiNdesCaEvidence {
    <#
    .SYNOPSIS
    Reads, for one Enterprise CA, the issued certificates of the NDES templates (read-only, time-limited).

    .OUTPUTS
    { Rows, Read (bool), Findings }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$CA,
        [AllowNull()]$Inventory = $null,
        [int]$TimeoutSeconds = 5,
        [int]$MaxRows = 200,
        [switch]$SkipNetwork
    )
    $findings = New-Object System.Collections.ArrayList
    $out = [pscustomobject]@{ Rows = @(); Read = $false; Findings = @() }
    $src = @('CA:CertificateAuthority.View', 'AD:EnrollmentServices')
    $common = @{ Category = 'NDES'; Target = $CA.Name; Endpoint = $CA.Config; RelatedCA = $CA.Name; Scope = 'Local'; Sources = $src; Stage = 'Discovery' }
    if ($SkipNetwork) {
        Add-MspkiMethodOutcome -Method 'CA:CertificateAuthority.View' -Outcome 'Skipped' -Detail ('{0}: -SkipNetwork' -f $CA.Config)
        [void]$findings.Add((New-MspkiFinding @common -Status 'Skipped' -StatusCode 'NOT_APPLICABLE' -Confidence 'Unknown' -Layers @{ DiscoveryStatus = 'Skipped' } `
            -Message ('The CA database of {0} was not read for NDES evidence because -SkipNetwork was used.' -f $CA.Name)))
        $out.Findings = @($findings); return $out
    }
    if ($null -eq $CA.Properties) {
        [void]$findings.Add((New-MspkiFinding @common -Status 'Skipped' -StatusCode 'NOT_APPLICABLE' -Confidence 'Unknown' -Layers @{ DiscoveryStatus = 'Skipped' } `
            -Message ('The CA database of {0} was not read for NDES evidence because the CA did not answer earlier (see the CA findings).' -f $CA.Name)))
        $out.Findings = @($findings); return $out
    }
    $keys = Get-MspkiNdesTemplateKey -Inventory $Inventory
    $limit = [math]::Max(30, $TimeoutSeconds * 6)
    $run = Invoke-MspkiTimeLimitedScript -ScriptBlock $script:MspkiNdesDbReader -TimeoutSeconds $limit -ArgumentList @($CA.Config, [string[]]$keys, $MaxRows)
    if ($run.TimedOut) {
        Add-MspkiMethodOutcome -Method 'CA:CertificateAuthority.View' -Outcome 'Timeout' -Detail $CA.Config -ElapsedMs $run.ElapsedMs
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Timeout' -Message ('No answer within {0} s.' -f $limit)) -Category 'NDES' -Target $CA.Name `
            -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope 'Local' -Action 'reading the CA database for NDES evidence' -UnreachableStatus 'Warning'))
        $out.Findings = @($findings); return $out
    }
    $raw = $null
    if ($run.Completed) { $raw = @($run.Output | Where-Object { $_ -is [hashtable] }) | Select-Object -First 1 }
    if ($null -eq $raw) {
        Add-MspkiMethodOutcome -Method 'CA:CertificateAuthority.View' -Outcome 'Error' -Detail (($run.Errors -join '; ')) -ElapsedMs $run.ElapsedMs
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Error' -Message ($run.Errors -join '; ')) -Category 'NDES' -Target $CA.Name `
            -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope 'Local' -Action 'reading the CA database for NDES evidence'))
        $out.Findings = @($findings); return $out
    }
    if ($null -ne $raw.Fatal) {
        $class = 'Error'
        if ($script:MspkiHResultClass.ContainsKey([string]$raw.Fatal.HResult)) { $class = $script:MspkiHResultClass[[string]$raw.Fatal.HResult] }
        Add-MspkiMethodOutcome -Method 'CA:CertificateAuthority.View' -Outcome $class -Detail ('{0}: 0x{1}' -f $CA.Config, $raw.Fatal.HResult) -ElapsedMs $run.ElapsedMs
        $notes = ''
        if ($class -eq 'PermissionDenied') { $notes = 'Reading the CA database needs Read permission on the CA (certificate managers and CA administrators see all requests). Without it, NDES hosts can only be found from references.' }
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class $class -HResult ('0x' + $raw.Fatal.HResult) -Message $raw.Fatal.Message) -Category 'NDES' -Target $CA.Name `
            -Endpoint $CA.Config -RelatedCA $CA.Name -Sources $src -Scope 'Local' -Action 'reading the CA database for NDES evidence' -UnreachableStatus 'Warning' -Notes $notes))
        $out.Findings = @($findings); return $out
    }
    $rows = @($raw.Rows | ForEach-Object { ConvertTo-MspkiNdesRow -Row $_ })
    $out.Rows = $rows
    $out.Read = $true
    Add-MspkiMethodOutcome -Method 'CA:CertificateAuthority.View' -Outcome 'Success' -Detail ('{0}: {1} issued certificate(s) from NDES templates, {2} query error(s)' -f $CA.Config, $rows.Count, @($raw.Errors).Count) -ElapsedMs $run.ElapsedMs
    $ev = @(('Template values queried (names and OIDs): {0}' -f ($keys -join ', ')), ('Issued certificates found: {0}' -f $rows.Count))
    foreach ($e in @($raw.Errors)) { $ev += ('Query for {0} failed: 0x{1} {2}' -f $e.Key, $e.HResult, $e.Message) }
    [void]$findings.Add((New-MspkiFinding @common -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' -Layers @{ DiscoveryStatus = 'Pass' } -Evidence $ev `
        -Message ('CA database of {0} read: {1} issued certificate(s) from the NDES templates.' -f $CA.Name, $rows.Count) `
        -Notes 'A standard account usually sees only its own requests, so no rows does not prove that no NDES server exists.'))
    $out.Findings = @($findings)
    return $out
}
