# Certificate templates, key recovery agents (KRA) and OID objects from the PKI containers of the Configuration
# partition. Read-only, one-level searches with explicit attribute lists. Results are plain data (no raw security
# descriptors, no live directory objects).

$script:MspkiTemplateProperties = @('cn', 'displayName', 'distinguishedName', 'whenChanged', 'msPKI-Cert-Template-OID',
    'msPKI-Template-Schema-Version', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature',
    'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy', 'msPKI-RA-Application-Policies', 'msPKI-RA-Policies',
    'msPKI-Certificate-Policy', 'nTSecurityDescriptor')

function ConvertTo-MspkiStringList {
    [CmdletBinding()]
    param([AllowNull()]$Values)
    return , @(@($Values) | Where-Object { $null -ne $_ -and ([string]$_) -ne '' } | ForEach-Object { ([string]$_).Trim() })
}

function ConvertFrom-MspkiTemplateRecord {
    <#
    .SYNOPSIS
    Converts one pKICertificateTemplate LDAP record into a template object. Pure function: the security
    descriptor is parsed in memory and principals are named later by the caller.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Record)
    $g = { param($n) Get-MspkiLdapValue -Record $Record -Name $n }
    $m = { param($n) Get-MspkiLdapValues -Record $Record -Name $n }
    $cn = [string](& $g 'cn')
    $display = [string](& $g 'displayName')
    $schema = 0
    $sv = & $g 'msPKI-Template-Schema-Version'
    if ($null -ne $sv) { $schema = [int](ConvertTo-MspkiUInt32 $sv) }
    $raSig = 0
    $rv = & $g 'msPKI-RA-Signature'
    if ($null -ne $rv) { $raSig = [int](ConvertTo-MspkiUInt32 $rv) }
    $eku = ConvertTo-MspkiStringList (& $m 'pKIExtendedKeyUsage')
    $app = ConvertTo-MspkiStringList (& $m 'msPKI-Certificate-Application-Policy')
    $raApp = ConvertTo-MspkiStringList (& $m 'msPKI-RA-Application-Policies')
    $raPol = ConvertTo-MspkiStringList (& $m 'msPKI-RA-Policies')
    $pol = ConvertTo-MspkiStringList (& $m 'msPKI-Certificate-Policy')
    $ownerSid = ''
    $acl = @()
    $aclError = ''
    $aclErrorClass = ''
    $sdBytes = & $g 'nTSecurityDescriptor'
    if ($null -ne $sdBytes) {
        try {
            $sd = ConvertFrom-MspkiSecurityDescriptor -Bytes ([byte[]]$sdBytes)
            $ownerSid = $sd.OwnerSid
            $acl = @($sd.Aces)
        }
        catch { $aclError = (Get-MspkiErrorInfo $_).Message; $aclErrorClass = 'ParseError' }
    }
    else { $aclError = 'The security descriptor was not returned (the account may lack the right to read it).'; $aclErrorClass = 'NotReturned' }
    $name = $cn
    return [pscustomobject][ordered]@{
        Name                  = $name
        DisplayName           = $display
        DistinguishedName     = [string](& $g 'distinguishedName')
        Oid                   = [string](& $g 'msPKI-Cert-Template-OID')
        SchemaVersion         = $schema
        NameFlag              = (ConvertTo-MspkiUInt32 (& $g 'msPKI-Certificate-Name-Flag'))
        EnrollmentFlag        = (ConvertTo-MspkiUInt32 (& $g 'msPKI-Enrollment-Flag'))
        RaSignature           = $raSig
        Eku                   = $eku
        ApplicationPolicies   = $app
        RaApplicationPolicies = $raApp
        RaPolicies            = $raPol
        IssuancePolicies      = $pol
        OwnerSid              = $ownerSid
        Owner                 = ''
        Acl                   = $acl
        AclError              = $aclError
        AclErrorClass         = $aclErrorClass
        WhenChanged           = ConvertTo-MspkiIsoTime (& $g 'whenChanged')
    }
}

function Get-MspkiTemplateObject {
    <#
    .SYNOPSIS
    Reads the certificate template objects from CN=Certificate Templates (one level) with their security
    descriptors, and names each principal once per run.

    .OUTPUTS
    Data: template objects. Findings: the read outcome (read failures are PERMISSION_DENIED or unreachable, kept apart).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [int]$TimeoutSeconds = 5
    )
    $findings = New-Object System.Collections.ArrayList
    $list = New-Object System.Collections.ArrayList
    $dn = 'CN=Certificate Templates,{0}' -f $Context.PksDN
    $t = [math]::Max(20, $TimeoutSeconds * 6)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $read = $false
    $method = 'AD:CertificateTemplates:pKICertificateTemplate'
    try {
        $recs = @(Get-MspkiLdapObject -Server $Context.DomainController -BaseDN $dn -Scope OneLevel `
            -Filter '(objectClass=pKICertificateTemplate)' -Properties $script:MspkiTemplateProperties -TimeoutSeconds $t -IncludeDacl)
        $noAcl = 0
        foreach ($r in $recs) {
            try {
                $tpl = ConvertFrom-MspkiTemplateRecord -Record $r
                foreach ($a in $tpl.Acl) { $a.Principal = Resolve-MspkiSid -Sid $a.Sid }
                if ($tpl.OwnerSid) { $tpl.Owner = Resolve-MspkiSid -Sid $tpl.OwnerSid }
                if ($tpl.AclError) { $noAcl++ }
                [void]$list.Add($tpl)
            }
            catch {
                $obj = [string](Get-MspkiLdapValue -Record $r -Name 'distinguishedName')
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Template' -Role 'Template' -Target $obj `
                    -Sources 'AD:CertificateTemplates' -Action 'decoding a certificate template object' -Scope 'Local' -Stage 'Discovery'))
            }
        }
        $read = $true
        Add-MspkiMethodOutcome -Method $method -Outcome 'Success' -Detail ('{0} template(s), {1} without a readable security descriptor' -f $list.Count, $noAcl) -ElapsedMs $sw.ElapsedMilliseconds
        $stat = Get-MspkiSidStatistic
        [void]$findings.Add((New-MspkiFinding -Category 'Template' -Role 'Template' -Target 'Certificate Templates' -Endpoint $dn -Stage 'Discovery' `
            -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' -Sources 'AD:CertificateTemplates' -Scope 'Local' `
            -Layers @{ DiscoveryStatus = 'Pass' } -Message ('Read {0} certificate template object(s) from AD.' -f $list.Count) `
            -Evidence @(('Templates without a readable security descriptor: {0}' -f $noAcl),
                ('SID lookups: {0} ({1} failed), {2} distinct principal(s) cached' -f $stat.Lookups, $stat.Failures, $stat.Cached))))
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method $method -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        if ($ei.Class -ne 'NotFound') {
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'Template' -Role 'Template' -Target 'Certificate Templates' -Endpoint $dn `
                -Sources 'AD:CertificateTemplates' -Action 'reading certificate templates' -Scope 'Local' -Stage 'Discovery'))
        }
    }
    return [pscustomobject]@{ Data = @($list); Findings = @($findings); Read = $read }
}

function ConvertFrom-MspkiKraRecord {
    <#
    .SYNOPSIS
    Converts one object of the KRA container into { Name, DistinguishedName, Certificates, CertificateErrors }.
    The certificates are public userCertificate values; only validity and names are kept.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Record, [DateTime]$Now = [DateTime]::UtcNow)
    $certs = New-Object System.Collections.ArrayList
    $errs = New-Object System.Collections.ArrayList
    foreach ($raw in (Get-MspkiLdapValues -Record $Record -Name 'userCertificate')) {
        try {
            $c = New-MspkiCertificate -Bytes ([byte[]]$raw)
            $info = Get-MspkiCertificateInfo -Certificate $c -Now $Now
            [void]$certs.Add([pscustomobject][ordered]@{
                Thumbprint = $info.Thumbprint; Subject = $info.Subject; Issuer = $info.Issuer
                NotBefore = $info.NotBefore; NotAfter = $info.NotAfter; DaysLeft = $info.DaysLeft; Expired = ($info.DaysLeft -lt 0 -and $c.NotAfter.ToUniversalTime() -lt $Now.ToUniversalTime())
            })
        }
        catch { [void]$errs.Add((Get-MspkiErrorInfo $_).Message) }
    }
    return [pscustomobject][ordered]@{
        Name = [string](Get-MspkiLdapValue -Record $Record -Name 'cn')
        DistinguishedName = [string](Get-MspkiLdapValue -Record $Record -Name 'distinguishedName')
        Certificates = @($certs); CertificateErrors = @($errs)
    }
}

function Get-MspkiKraObject {
    <#
    .SYNOPSIS
    Reads the key recovery agent objects (CN=KRA, one level): names and certificate validity only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context, [int]$TimeoutSeconds = 5)
    $findings = New-Object System.Collections.ArrayList
    $list = New-Object System.Collections.ArrayList
    $dn = 'CN=KRA,{0}' -f $Context.PksDN
    $t = [math]::Max(10, $TimeoutSeconds * 3)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $read = $false
    try {
        $recs = @(Get-MspkiLdapObject -Server $Context.DomainController -BaseDN $dn -Scope OneLevel -Properties @('cn', 'userCertificate', 'distinguishedName') -TimeoutSeconds $t)
        foreach ($r in $recs) { [void]$list.Add((ConvertFrom-MspkiKraRecord -Record $r)) }
        $read = $true
        Add-MspkiMethodOutcome -Method 'AD:KRA:userCertificate' -Outcome 'Success' -Detail ('{0} object(s)' -f $list.Count) -ElapsedMs $sw.ElapsedMilliseconds
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:KRA:userCertificate' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        if ($ei.Class -ne 'NotFound') {
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADContainer' -Role 'ADContainer' -Target 'KRA' -Endpoint $dn `
                -Sources 'AD:KRA' -Action 'reading the KRA container' -Scope 'Local'))
        }
    }
    return [pscustomobject]@{ Data = @($list); Findings = @($findings); Read = $read }
}

function ConvertFrom-MspkiOidRecord {
    <#
    .SYNOPSIS
    Converts one msPKI-Enterprise-Oid object into { Name, DisplayName, Oid, Flags, GroupLink }. Flags:
    1 = template OID, 2 = issuance policy, 4 = application policy.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Record)
    $flags = Get-MspkiLdapValue -Record $Record -Name 'flags'
    $link = [string](Get-MspkiLdapValue -Record $Record -Name 'msDS-OIDToGroupLink')
    return [pscustomobject][ordered]@{
        Name = [string](Get-MspkiLdapValue -Record $Record -Name 'cn')
        DisplayName = [string](Get-MspkiLdapValue -Record $Record -Name 'displayName')
        DistinguishedName = [string](Get-MspkiLdapValue -Record $Record -Name 'distinguishedName')
        Oid = [string](Get-MspkiLdapValue -Record $Record -Name 'msPKI-Cert-Template-OID')
        Flags = [int](ConvertTo-MspkiUInt32 $flags)
        GroupLink = $link
        GroupName = ''
        GroupSid = ''
        GroupResolved = $null
        GroupError = ''
    }
}

function Get-MspkiOidObject {
    <#
    .SYNOPSIS
    Reads the OID objects (CN=OID, one level). For every object with an msDS-OIDToGroupLink value, the linked
    group is looked up once (base search) so that an unresolvable link can be reported.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context, [int]$TimeoutSeconds = 5)
    $findings = New-Object System.Collections.ArrayList
    $list = New-Object System.Collections.ArrayList
    $dn = 'CN=OID,{0}' -f $Context.PksDN
    $t = [math]::Max(10, $TimeoutSeconds * 3)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $read = $false
    try {
        $recs = @(Get-MspkiLdapObject -Server $Context.DomainController -BaseDN $dn -Scope OneLevel `
            -Properties @('cn', 'displayName', 'distinguishedName', 'flags', 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink') -TimeoutSeconds $t)
        foreach ($r in $recs) { [void]$list.Add((ConvertFrom-MspkiOidRecord -Record $r)) }
        $read = $true
        Add-MspkiMethodOutcome -Method 'AD:OID:msDS-OIDToGroupLink' -Outcome 'Success' `
            -Detail ('{0} OID object(s), {1} with a group link' -f $list.Count, @($list | Where-Object { $_.GroupLink }).Count) -ElapsedMs $sw.ElapsedMilliseconds
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:OID:msDS-OIDToGroupLink' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        if ($ei.Class -ne 'NotFound') {
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADContainer' -Role 'ADContainer' -Target 'OID' -Endpoint $dn `
                -Sources 'AD:OID' -Action 'reading the OID container' -Scope 'Local'))
        }
        return [pscustomobject]@{ Data = @(); Findings = @($findings); Read = $false }
    }
    foreach ($o in @($list | Where-Object { $_.GroupLink })) {
        # A group of another domain is looked up by a serverless bind (the DN names its domain); the selected DC
        # does not hold that naming context, so asking it would report a missing object that may well exist.
        $srv = $Context.DomainController
        if ($Context.DefaultNC -and -not $o.GroupLink.EndsWith(',' + $Context.DefaultNC, [System.StringComparison]::OrdinalIgnoreCase)) { $srv = '' }
        try {
            $g = @(Get-MspkiLdapObject -Server $srv -BaseDN $o.GroupLink -Scope Base -Properties @('cn', 'objectSid', 'groupType') -TimeoutSeconds $t)
            if ($g.Count -eq 0) { $o.GroupResolved = $false; $o.GroupError = 'The group object returned no data.'; continue }
            $o.GroupResolved = $true
            $o.GroupName = [string](Get-MspkiLdapValue -Record $g[0] -Name 'cn')
            $sidBytes = Get-MspkiLdapValue -Record $g[0] -Name 'objectSid'
            if ($null -ne $sidBytes) { $o.GroupSid = (New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$sidBytes), 0)).Value }
        }
        catch {
            $ei = Get-MspkiErrorInfo $_
            $o.GroupError = ('{0}: {1}' -f $ei.Class, $ei.Message)
            # Only a missing object means the link does not resolve; permission and network errors are kept apart.
            if ($ei.Class -eq 'NotFound') { $o.GroupResolved = $false } else { $o.GroupResolved = $null }
            Add-MspkiMethodOutcome -Method 'AD:OID:GroupLink' -Outcome $ei.Class -Detail $o.Name
        }
    }
    return [pscustomobject]@{ Data = @($list); Findings = @($findings); Read = $read }
}
