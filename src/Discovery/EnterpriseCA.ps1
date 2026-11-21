# Enterprise CAs: the pKIEnrollmentService objects in CN=Enrollment Services.

$script:MspkiEnrollmentServiceProperties = @('cn', 'displayName', 'dNSHostName', 'cACertificate',
    'certificateTemplates', 'msPKI-Enrollment-Servers', 'flags', 'distinguishedName', 'whenCreated', 'whenChanged')

# X509EnrollmentAuthFlags values used in msPKI-Enrollment-Servers.
$script:MspkiEnrollmentAuthNames = @{ 0 = 'None'; 1 = 'Anonymous'; 2 = 'Kerberos'; 4 = 'UserName'; 8 = 'Certificate' }

function ConvertFrom-MspkiEnrollmentServerValue {
    <#
    .SYNOPSIS
    Parses one msPKI-Enrollment-Servers value ("priority`nauthType`nrenewalOnly`nURL") into fields.
    Unparseable values keep the URL (if any) and mark the other fields Unknown.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)
    $lines = @($Value -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $out = [ordered]@{ Priority = $null; AuthType = $null; AuthName = 'Unknown'; RenewalOnly = $null; Url = ''; Parsed = $false; Raw = $Value }
    if ($lines.Count -ge 4 -and $lines[3] -match '^(?i)https?://') {
        $p = 0; $a = 0
        if ([int]::TryParse($lines[0], [ref]$p)) { $out.Priority = $p }
        if ([int]::TryParse($lines[1], [ref]$a)) {
            $out.AuthType = $a
            if ($script:MspkiEnrollmentAuthNames.ContainsKey($a)) { $out.AuthName = $script:MspkiEnrollmentAuthNames[$a] }
            else { $out.AuthName = ('Flags 0x{0:X}' -f $a) }
        }
        $out.RenewalOnly = ($lines[2] -eq '1' -or $lines[2] -eq 'true')
        $out.Url = $lines[3]
        $out.Parsed = ($null -ne $out.Priority -and $null -ne $out.AuthType)
    }
    else {
        $m = [regex]::Match($Value, '(?i)https?://\S+')
        if ($m.Success) { $out.Url = $m.Value }
    }
    return [pscustomobject]$out
}

function ConvertFrom-MspkiEnrollmentServiceRecord {
    <#
    .SYNOPSIS
    Converts one pKIEnrollmentService LDAP record (hashtable from Get-MspkiLdapObject) into an
    Enterprise CA object. Pure function: no network access.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Record)
    $cn = [string](Get-MspkiLdapValue -Record $Record -Name 'cn')
    $display = [string](Get-MspkiLdapValue -Record $Record -Name 'displayName')
    $name = $display
    if (-not $name) { $name = $cn }
    $dns = ConvertTo-MspkiHostName ([string](Get-MspkiLdapValue -Record $Record -Name 'dNSHostName'))

    $certs = New-Object System.Collections.ArrayList
    $certErrors = New-Object System.Collections.ArrayList
    foreach ($raw in (Get-MspkiLdapValues -Record $Record -Name 'cACertificate')) {
        try { [void]$certs.Add((New-MspkiCertificate -Bytes ([byte[]]$raw))) }
        catch { [void]$certErrors.Add((Get-MspkiErrorInfo $_).Message) }
    }
    # Get-MspkiLdapValues returns the array as one object: assign it before piping.
    $tplValues = Get-MspkiLdapValues -Record $Record -Name 'certificateTemplates'
    $templates = @($tplValues | ForEach-Object { [string]$_ } | Sort-Object)
    $cesValues = Get-MspkiLdapValues -Record $Record -Name 'msPKI-Enrollment-Servers'
    $ces = @($cesValues | ForEach-Object { ConvertFrom-MspkiEnrollmentServerValue -Value ([string]$_) })
    $flags = Get-MspkiLdapValue -Record $Record -Name 'flags'
    $config = ''
    if ($dns -and $name) { $config = '{0}\{1}' -f $dns, $name }

    return [pscustomobject][ordered]@{
        Name              = $name
        CommonName        = $cn
        DisplayName       = $display
        DnsHostName       = $dns
        Config            = $config
        DistinguishedName = [string](Get-MspkiLdapValue -Record $Record -Name 'distinguishedName')
        Templates         = $templates
        EnrollmentServers = $ces
        Flags             = $flags
        WhenCreated       = ConvertTo-MspkiIsoTime (Get-MspkiLdapValue -Record $Record -Name 'whenCreated')
        WhenChanged       = ConvertTo-MspkiIsoTime (Get-MspkiLdapValue -Record $Record -Name 'whenChanged')
        Certificates      = @($certs)
        CertificateErrors = @($certErrors)
    }
}

function Get-MspkiEnterpriseCA {
    <#
    .SYNOPSIS
    Lists the Enterprise CAs (pKIEnrollmentService objects) of the forest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [int]$TimeoutSeconds = 5
    )
    $findings = New-Object System.Collections.ArrayList
    $cas = New-Object System.Collections.ArrayList
    $dn = 'CN=Enrollment Services,{0}' -f $Context.PksDN
    $t = [math]::Max(10, $TimeoutSeconds * 3)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $recs = @(Get-MspkiLdapObject -Server $Context.DomainController -BaseDN $dn -Scope OneLevel `
            -Filter '(objectClass=pKIEnrollmentService)' -Properties $script:MspkiEnrollmentServiceProperties -TimeoutSeconds $t)
        Add-MspkiMethodOutcome -Method 'AD:EnrollmentServices:pKIEnrollmentService' -Outcome 'Success' `
            -Detail ('{0} object(s)' -f $recs.Count) -ElapsedMs $sw.ElapsedMilliseconds
        foreach ($r in $recs) {
            try { [void]$cas.Add((ConvertFrom-MspkiEnrollmentServiceRecord -Record $r)) }
            catch {
                $obj = [string](Get-MspkiLdapValue -Record $r -Name 'distinguishedName')
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'CA' -Target $obj `
                    -Sources 'AD:EnrollmentServices' -Action 'decoding an Enrollment Services object' -Scope 'Local'))
            }
        }
        if ($recs.Count -eq 0) {
            [void]$findings.Add((New-MspkiFinding -Category 'CA' -Target 'Enrollment Services' -Endpoint $dn `
                -Status 'Information' -StatusCode 'NOT_DISCOVERED' -Confidence 'Confirmed' -Sources 'AD:EnrollmentServices' `
                -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass' } `
                -Message 'No Enterprise CA is registered in Enrollment Services.' `
                -Notes 'Standalone CAs are found only through the certificates they publish in AD.'))
        }
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:EnrollmentServices:pKIEnrollmentService' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'CA' -Target 'Enrollment Services' -Endpoint $dn `
            -Sources 'AD:EnrollmentServices' -Action 'listing Enterprise CAs' -NotFoundCode 'NOT_CONFIGURED' -Scope 'Local'))
    }
    return [pscustomobject]@{ Data = @($cas); Findings = @($findings) }
}
