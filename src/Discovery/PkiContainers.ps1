# The PKI containers under CN=Public Key Services,CN=Services,<Configuration NC>, and the CA
# certificates published in Certification Authorities, AIA and NTAuthCertificates.

$script:MspkiPkiContainers = @(
    @{ Name = 'Enrollment Services';       Rdn = 'CN=Enrollment Services';       Kind = 'Container'; Source = 'AD:EnrollmentServices' }
    @{ Name = 'Certification Authorities'; Rdn = 'CN=Certification Authorities'; Kind = 'Container'; Source = 'AD:CertificationAuthorities' }
    @{ Name = 'AIA';                       Rdn = 'CN=AIA';                       Kind = 'Container'; Source = 'AD:AIA' }
    @{ Name = 'CDP';                       Rdn = 'CN=CDP';                       Kind = 'Container'; Source = 'AD:CDP' }
    @{ Name = 'Certificate Templates';     Rdn = 'CN=Certificate Templates';     Kind = 'Container'; Source = 'AD:CertificateTemplates' }
    @{ Name = 'OID';                       Rdn = 'CN=OID';                       Kind = 'Container'; Source = 'AD:OID' }
    @{ Name = 'KRA';                       Rdn = 'CN=KRA';                       Kind = 'Container'; Source = 'AD:KRA' }
    @{ Name = 'NTAuthCertificates';        Rdn = 'CN=NTAuthCertificates';        Kind = 'Object';    Source = 'AD:NTAuthCertificates' }
)

function Get-MspkiPkiContainer {
    <#
    .SYNOPSIS
    Checks that each PKI container exists and counts its child objects (one-level, names only).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [int]$TimeoutSeconds = 5
    )
    $findings = New-Object System.Collections.ArrayList
    $list = New-Object System.Collections.ArrayList
    $server = $Context.DomainController
    $t = [math]::Max(10, $TimeoutSeconds * 3)

    # Public Key Services itself: if it is missing, AD CS was never installed in this forest.
    $sw = (New-MspkiStopwatch)
    try {
        $null = @(Get-MspkiLdapObject -Server $server -BaseDN $Context.PksDN -Scope Base -Properties @('cn') -TimeoutSeconds $t)
        Add-MspkiMethodOutcome -Method 'AD:PublicKeyServices' -Outcome 'Success' -ElapsedMs $sw.ElapsedMilliseconds
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:PublicKeyServices' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        $f = New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADContainer' -Role 'ADContainer' -Target 'Public Key Services' `
            -Endpoint $Context.PksDN -Sources 'AD:Configuration' -Action 'reading the Public Key Services container' `
            -NotFoundCode 'NOT_CONFIGURED' -Scope 'Local' `
            -Notes 'Without this container there are no Enterprise CAs, templates or AD-published CA certificates in this forest.'
        [void]$findings.Add($f)
        return [pscustomobject]@{ Data = [pscustomobject]@{ PksExists = $false; Containers = @() }; Findings = @($findings) }
    }

    foreach ($c in $script:MspkiPkiContainers) {
        $dn = '{0},{1}' -f $c.Rdn, $Context.PksDN
        $item = [ordered]@{ Name = $c.Name; DistinguishedName = $dn; Kind = $c.Kind; Exists = $null; ChildCount = $null;
                            WhenChanged = ''; Outcome = '' }
        $sw = (New-MspkiStopwatch)
        try {
            $base = @(Get-MspkiLdapObject -Server $server -BaseDN $dn -Scope Base -Properties @('cn', 'whenChanged', 'cACertificate') -TimeoutSeconds $t)
            $item.Exists = $true
            if ($base.Count -gt 0) { $item.WhenChanged = ConvertTo-MspkiIsoTime (Get-MspkiLdapValue -Record $base[0] -Name 'whenChanged') }
            if ($c.Kind -eq 'Container') {
                $kids = @(Get-MspkiLdapObject -Server $server -BaseDN $dn -Scope OneLevel -Properties @('cn') -TimeoutSeconds $t)
                $item.ChildCount = $kids.Count
                $what = '{0} child object(s)' -f $kids.Count
            }
            else {
                $item.ChildCount = (Get-MspkiLdapValues -Record $base[0] -Name 'cACertificate').Count
                $what = '{0} certificate(s) in cACertificate' -f $item.ChildCount
            }
            $item.Outcome = 'Success'
            Add-MspkiMethodOutcome -Method $c.Source -Outcome 'Success' -Detail $what -ElapsedMs $sw.ElapsedMilliseconds
            [void]$findings.Add((New-MspkiFinding -Category 'ADContainer' -Role 'ADContainer' -Target $c.Name -Endpoint $dn `
                -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' -Sources $c.Source -Scope 'Local' `
                -Message ('{0}: present, {1}.' -f $c.Name, $what) -Layers @{ DiscoveryStatus = 'Pass' } `
                -Evidence @(('Distinguished name: {0}' -f $dn), ('whenChanged: {0}' -f $item.WhenChanged))))
        }
        catch {
            $ei = Get-MspkiErrorInfo $_
            $item.Outcome = $ei.Class
            if ($ei.Class -eq 'NotFound') { $item.Exists = $false }
            Add-MspkiMethodOutcome -Method $c.Source -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADContainer' -Role 'ADContainer' -Target $c.Name `
                -Endpoint $dn -Sources $c.Source -Action ('reading the {0} container' -f $c.Name) `
                -NotFoundCode 'NOT_CONFIGURED' -Scope 'Local'))
        }
        [void]$list.Add([pscustomobject]$item)
    }
    return [pscustomobject]@{ Data = [pscustomobject]@{ PksExists = $true; Containers = @($list) }; Findings = @($findings) }
}

function Get-MspkiAdCACertificate {
    <#
    .SYNOPSIS
    Reads the CA certificates published in Certification Authorities, AIA and NTAuthCertificates.

    .OUTPUTS
    Data: list of entries { Source, ObjectName, Certificate }. Findings: read failures and values that
    are not certificates.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [int]$TimeoutSeconds = 5
    )
    $findings = New-Object System.Collections.ArrayList
    $entries = New-Object System.Collections.ArrayList
    $server = $Context.DomainController
    $t = [math]::Max(10, $TimeoutSeconds * 3)
    $sources = @(
        @{ Name = 'Certification Authorities'; Rdn = 'CN=Certification Authorities'; Scope = 'OneLevel'
           Filter = '(objectClass=certificationAuthority)'; Source = 'AD:CertificationAuthorities' }
        @{ Name = 'AIA'; Rdn = 'CN=AIA'; Scope = 'OneLevel'
           Filter = '(objectClass=certificationAuthority)'; Source = 'AD:AIA' }
        @{ Name = 'NTAuthCertificates'; Rdn = 'CN=NTAuthCertificates'; Scope = 'Base'
           Filter = '(objectClass=*)'; Source = 'AD:NTAuthCertificates' }
    )
    foreach ($s in $sources) {
        $dn = '{0},{1}' -f $s.Rdn, $Context.PksDN
        $sw = (New-MspkiStopwatch)
        try {
            $recs = @(Get-MspkiLdapObject -Server $server -BaseDN $dn -Scope $s.Scope -Filter $s.Filter `
                -Properties @('cn', 'cACertificate', 'distinguishedName') -TimeoutSeconds $t)
            $n = 0
            foreach ($r in $recs) {
                $obj = [string](Get-MspkiLdapValue -Record $r -Name 'cn')
                foreach ($raw in (Get-MspkiLdapValues -Record $r -Name 'cACertificate')) {
                    try {
                        $cert = New-MspkiCertificate -Bytes ([byte[]]$raw)
                        [void]$entries.Add([pscustomobject]@{ Source = $s.Source; ObjectName = $obj; Certificate = $cert })
                        $n++
                    }
                    catch {
                        [void]$findings.Add((New-MspkiFinding -Category 'ADContainer' -Role 'ADContainer' -Target $obj `
                            -Endpoint $dn -Status 'Warning' -StatusCode 'CONTENT_WRONG_TYPE' -Confidence 'Referenced' `
                            -Sources $s.Source -Scope 'Local' -Layers @{ DiscoveryStatus = 'Pass'; ContentStatus = 'Fail' } `
                            -Message ('A cACertificate value on {0} in {1} is not a readable certificate.' -f $obj, $s.Name) `
                            -Evidence @(('Error: {0}' -f (Get-MspkiErrorInfo $_).Message))))
                    }
                }
            }
            Add-MspkiMethodOutcome -Method ($s.Source + ':cACertificate') -Outcome 'Success' `
                -Detail ('{0} certificate(s)' -f $n) -ElapsedMs $sw.ElapsedMilliseconds
        }
        catch {
            $ei = Get-MspkiErrorInfo $_
            Add-MspkiMethodOutcome -Method ($s.Source + ':cACertificate') -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
            # A missing container is already reported by Get-MspkiPkiContainer.
            if ($ei.Class -ne 'NotFound') {
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADContainer' -Role 'ADContainer' `
                    -Target $s.Name -Endpoint $dn -Sources $s.Source -Scope 'Local' `
                    -Action ('reading CA certificates from {0}' -f $s.Name)))
            }
        }
    }
    return [pscustomobject]@{ Data = @($entries); Findings = @($findings) }
}
