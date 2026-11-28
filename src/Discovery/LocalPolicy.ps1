# Certificate Enrollment Policy (CEP) servers configured on this computer, read from the registry (read-only:
# keys are opened without write access and only string/number values are read).
#   Group Policy:   HKLM / HKCU \Software\Policies\Microsoft\Cryptography\PolicyServers\<id>
#   Local settings: HKLM / HKCU \Software\Microsoft\Cryptography\PolicyServers\<id>
# Each <id> key holds URL, PolicyID, FriendlyName, Flags, AuthFlags and Cost. A URL that is not http(s) (for example
# the Active Directory policy, whose URL is "ldap:") is not a CEP web service and is never probed.

$script:MspkiCepPolicyLocations = @(
    @{ Hive = 'LocalMachine'; Path = 'SOFTWARE\Policies\Microsoft\Cryptography\PolicyServers'; Source = 'Policy:CEP:HKLM'; Managed = 'Group Policy (computer)' }
    @{ Hive = 'CurrentUser';  Path = 'Software\Policies\Microsoft\Cryptography\PolicyServers';  Source = 'Policy:CEP:HKCU'; Managed = 'Group Policy (user)' }
    @{ Hive = 'LocalMachine'; Path = 'SOFTWARE\Microsoft\Cryptography\PolicyServers';           Source = 'Local:CEP:HKLM';  Managed = 'local configuration (computer)' }
    @{ Hive = 'CurrentUser';  Path = 'Software\Microsoft\Cryptography\PolicyServers';           Source = 'Local:CEP:HKCU';  Managed = 'local configuration (user)' }
)

function Get-MspkiAuthFlagText {
    <#
    .SYNOPSIS
    Names the X509EnrollmentAuthFlags bits (1 Anonymous, 2 Kerberos, 4 UserName/password, 8 Certificate).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Flags)
    if ($null -eq $Flags) { return 'Unknown' }
    $n = 0
    if (-not [int]::TryParse(([string]$Flags), [ref]$n)) { return 'Unknown' }
    if ($n -eq 0) { return 'None' }
    $names = @()
    if (($n -band 1) -ne 0) { $names += 'Anonymous' }
    if (($n -band 2) -ne 0) { $names += 'Kerberos' }
    if (($n -band 4) -ne 0) { $names += 'UserName' }
    if (($n -band 8) -ne 0) { $names += 'Certificate' }
    if ($names.Count -eq 0) { return ('Flags 0x{0:X}' -f $n) }
    return ($names -join ', ')
}

function ConvertFrom-MspkiCepPolicyEntry {
    <#
    .SYNOPSIS
    Converts the values of one policy-server key into a policy entry. Pure function.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Values,
        [Parameter(Mandatory = $true)][string]$KeyName,
        [Parameter(Mandatory = $true)][hashtable]$Location
    )
    $url = ([string]$Values['URL']).Trim()
    $auth = $Values['AuthFlags']
    $isWeb = ($url -match '^(?i)https?://')
    return [pscustomobject][ordered]@{
        Source       = $Location.Source
        Managed      = $Location.Managed
        KeyName      = $KeyName
        Url          = $url
        IsWebService = $isWeb
        IsAdPolicy   = ($url -match '^(?i)ldaps?:')
        FriendlyName = ([string]$Values['FriendlyName']).Trim()
        PolicyId     = ([string]$Values['PolicyID']).Trim()
        Flags        = $Values['Flags']
        AuthFlags    = $auth
        AuthName     = (Get-MspkiAuthFlagText -Flags $auth)
        Cost         = $Values['Cost']
    }
}

function Read-MspkiPolicyServerKey {
    <#
    .SYNOPSIS
    Reads every sub-key of one PolicyServers key into hashtables of values (read-only). Returns
    { Exists, Entries, Error, ErrorInfo }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Location)
    $out = [pscustomobject]@{ Exists = $false; Entries = @(); Error = ''; ErrorInfo = $null }
    $root = [Microsoft.Win32.Registry]::LocalMachine
    if ($Location.Hive -eq 'CurrentUser') { $root = [Microsoft.Win32.Registry]::CurrentUser }
    $entries = New-Object System.Collections.ArrayList
    $base = $null
    try {
        $base = $root.OpenSubKey($Location.Path, $false)
        if ($null -eq $base) { return $out }
        $out.Exists = $true
        $names = @('URL', 'PolicyID', 'FriendlyName', 'Flags', 'AuthFlags', 'Cost')
        $read = {
            param($key, $label)
            $v = @{}
            foreach ($n in $names) { $x = $key.GetValue($n, $null); if ($null -ne $x) { $v[$n] = $x } }
            if ($v.ContainsKey('URL')) { [void]$entries.Add(@{ KeyName = $label; Values = $v }) }
        }
        & $read $base '(key itself)'
        foreach ($sn in $base.GetSubKeyNames()) {
            $sub = $null
            try { $sub = $base.OpenSubKey($sn, $false); if ($null -ne $sub) { & $read $sub $sn } }
            finally { if ($null -ne $sub) { $sub.Close() } }
        }
    }
    catch { $out.ErrorInfo = Get-MspkiErrorInfo $_; $out.Error = $out.ErrorInfo.Message; $out.Exists = $true }
    finally { if ($null -ne $base) { $base.Close() } }
    $out.Entries = @($entries)
    return $out
}

function Get-MspkiLocalCepPolicy {
    <#
    .SYNOPSIS
    Lists the enrollment policy servers configured on this computer (Group Policy and local settings).

    .OUTPUTS
    Data: policy entries. Findings: a read problem for a key (permission and other failures kept apart). Absence of
    a key is normal and is not a finding; the analysis reports "none configured" once.
    #>
    [CmdletBinding()]
    param()
    $findings = New-Object System.Collections.ArrayList
    $list = New-Object System.Collections.ArrayList
    foreach ($loc in $script:MspkiCepPolicyLocations) {
        $sw = (New-MspkiStopwatch)
        $r = Read-MspkiPolicyServerKey -Location $loc
        if ($r.Error) {
            $ei = $r.ErrorInfo
            if ($null -eq $ei) { $ei = New-MspkiErrorInfo -Class 'Error' -Message $r.Error }
            Add-MspkiMethodOutcome -Method $loc.Source -Outcome $ei.Class -Detail $r.Error -ElapsedMs $sw.ElapsedMilliseconds
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'CEP' -Role 'Computer' -Target $loc.Source -Sources $loc.Source `
                -Action ('reading the enrollment policy servers ({0})' -f $loc.Managed) -Scope 'Local'))
            continue
        }
        foreach ($e in $r.Entries) { [void]$list.Add((ConvertFrom-MspkiCepPolicyEntry -Values $e.Values -KeyName $e.KeyName -Location $loc)) }
        $detail = 'key not present'
        if ($r.Exists) { $detail = '{0} entr(y/ies)' -f $r.Entries.Count }
        Add-MspkiMethodOutcome -Method $loc.Source -Outcome 'Success' -Detail $detail -ElapsedMs $sw.ElapsedMilliseconds
    }
    return [pscustomobject]@{ Data = @($list); Findings = @($findings) }
}
