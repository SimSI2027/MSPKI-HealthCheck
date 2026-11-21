# AD PKI container consistency (REQUIREMENTS section 5.4). Review only: findings describe what AD and the CA
# say and where they disagree; nothing here recommends deleting an object. Pure functions over the inventory.

function Get-MspkiSchemaRole {
    [CmdletBinding()]
    param([string]$Role)
    if ($script:MspkiSchema.Role -contains $Role) { return $Role }
    return 'Unknown'
}

function Find-MspkiChainRootEntry {
    <#
    .SYNOPSIS
    Follows the issuer names of a CA certificate entry through the discovered CA certificates and returns the
    self-issued root entry it ends in, or $null when the chain is not complete among the discovered certificates.
    #>
    [CmdletBinding()]
    param($Entry, [AllowEmptyCollection()][object[]]$Entries = @())
    $cur = $Entry
    for ($i = 0; $i -lt 8; $i++) {
        if ($cur.Info.SelfIssued) { return $cur }
        $parents = @($Entries | Where-Object { $_.Info.Subject -eq $cur.Info.Issuer -and $_.Thumbprint -ne $cur.Thumbprint } |
            Sort-Object @{ Expression = { $_.Lifecycle -ne 'Current' } }, @{ Expression = { $_.Info.NotAfter }; Descending = $true })
        if ($parents.Count -eq 0) { return $null }
        $cur = $parents[0]
    }
    return $null
}

function Get-MspkiCaClientAuthTemplate {
    <#
    .SYNOPSIS
    The templates a CA publishes (the AD list and the CA's own list) that can be used to sign in (client authentication, smart card
    logon, any purpose, or no EKU). Known is $false when the template objects were not read, so nothing can be said.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$CA, [AllowNull()]$Inventory)
    $o = [pscustomobject]@{ Known = $false; Capable = @(); Published = 0 }
    if ($null -eq $Inventory -or $Inventory.TemplatesRead -ne $true) { return $o }
    $names = New-Object System.Collections.ArrayList
    foreach ($n in @($CA.Templates)) { if ($n -and -not ($names | Where-Object { $_ -ieq [string]$n })) { [void]$names.Add([string]$n) } }
    if ($null -ne $CA.Properties) {
        foreach ($n in @($CA.Properties.Templates)) { $x = [string]$n.Name; if ($x -and -not ($names | Where-Object { $_ -ieq $x })) { [void]$names.Add($x) } }
    }
    $capable = New-Object System.Collections.ArrayList
    foreach ($n in $names) {
        $tpl = @($Inventory.Templates | Where-Object { $_.Name -ieq $n }) | Select-Object -First 1
        if ($null -eq $tpl) { continue }
        if ((Get-MspkiTemplateFact -Template $tpl).ClientAuthCapable) { [void]$capable.Add($tpl.Name) }
    }
    $o.Known = $true; $o.Capable = @($capable); $o.Published = $names.Count
    return $o
}

function Test-MspkiAdContainerConsistency {
    <#
    .SYNOPSIS
    Compares what the AD PKI containers say about each Enterprise CA with what the CA itself reports.

    .DESCRIPTION
    Per Enterprise CA: (1) is the current CA certificate published in the AIA container, is the chain's root in the
    Certification Authorities container, is the CA in NTAuthCertificates; (2) is there a clear current/historical
    split among its certificates; (3) does the Enrollment Services object (certificates, templates) agree with the
    CA's own properties. Missing publication is "not discovered in the container", never a recommendation to delete.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Inventory)
    $findings = New-Object System.Collections.ArrayList
    if ($null -eq $Inventory) { return , $findings.ToArray() }
    $entries = @($Inventory.CACertificates)
    foreach ($ca in @($Inventory.EnterpriseCAs)) {
        $mine = @($entries | Where-Object { $_.CAName -eq $ca.Name })
        $current = @($mine | Where-Object { $_.Lifecycle -eq 'Current' })
        $props = $ca.Properties
        $common = @{ Category = 'ADContainer'; Stage = 'Analysis'; Target = $ca.Name; RelatedCA = $ca.Name; Scope = 'Local' }

        if ($mine.Count -eq 0) {
            [void]$findings.Add((New-MspkiFinding @common -Role 'Unknown' -Status 'Warning' -StatusCode 'NOT_DISCOVERED' -Confidence 'Referenced' `
                -Sources @('AD:EnrollmentServices', 'AD:AIA') -Message ('No CA certificate was found for the Enterprise CA {0} in AD or from the CA, so its AD publication cannot be reviewed.' -f $ca.Name) `
                -Evidence @('Enrollment Services object found; no cACertificate value that could be read, and no CA properties.') -Layers @{ DiscoveryStatus = 'Warning' }))
            continue
        }

        # (2) current / historical split
        if ($mine.Count -gt 1 -and ($current.Count -ne 1 -or @($mine | Where-Object { $_.Lifecycle -eq 'Unknown' }).Count -gt 0)) {
            $allConfirmed = (@($mine | Where-Object { $_.LifecycleConfidence -ne 'Confirmed' }).Count -eq 0)
            $conf = 'Inferred'
            if ($allConfirmed) { $conf = 'Confirmed' }
            [void]$findings.Add((New-MspkiFinding @common -Role (Get-MspkiSchemaRole $mine[0].Role) -Status 'Warning' -StatusCode 'NOT_DISCOVERED' -Confidence $conf `
                -Sources @('AD:EnrollmentServices', 'AD:AIA', 'CA:GetCAProperty') `
                -Message ('{0} has {1} CA certificates but {2} of them are current, so there is no clear current/historical split.' -f $ca.Name, $mine.Count, $current.Count) `
                -Evidence @($mine | ForEach-Object { '{0} [{1}] {2} ({3}, {4})' -f $_.Generation, $_.Thumbprint, $_.Lifecycle, $_.LifecycleConfidence, $_.LifecycleBasis }) `
                -Notes 'Review only. Only the CA itself can say which certificate is current; this needs read access to the CA.'))
        }
        if ($current.Count -eq 0) { continue }

        # (1) publication in the AD containers, for the newest current certificate
        $cur = @($current | Sort-Object @{ Expression = { $_.Info.NotAfter }; Descending = $true })[0]
        $root = Find-MspkiChainRootEntry -Entry $cur -Entries $entries
        $ev = New-Object System.Collections.ArrayList
        $missing = New-Object System.Collections.ArrayList
        [void]$ev.Add(('Current CA certificate: {0} [{1}]' -f $cur.Info.Subject, $cur.Thumbprint))
        if ($cur.InAIA) { [void]$ev.Add('AIA container: published') } else { [void]$ev.Add('AIA container: not found'); [void]$missing.Add('the AIA container') }
        $ntaInfo = $false
        if ($cur.InNTAuth) { [void]$ev.Add('NTAuthCertificates: published') }
        else {
            # Being in NTAuthCertificates matters for a CA that issues certificates used to sign in to AD. A CA that does not publish such a
            # template does not need to be there (taking it out is even a recommended hardening step), so that is not a warning.
            $auth = Get-MspkiCaClientAuthTemplate -CA $ca -Inventory $Inventory
            if ($auth.Known -and $auth.Capable.Count -gt 0) {
                [void]$ev.Add(('NTAuthCertificates: not found; this CA publishes {0} template(s) that can be used to sign in: {1}' -f $auth.Capable.Count, ($auth.Capable -join ', ')))
                [void]$missing.Add('NTAuthCertificates')
            }
            elseif ($auth.Known) { [void]$ev.Add(('NTAuthCertificates: not found; none of the {0} template(s) this CA publishes can be used to sign in, so it does not need to be there' -f $auth.Published)); $ntaInfo = $true }
            else { [void]$ev.Add('NTAuthCertificates: not found; whether this CA publishes a template that can be used to sign in could not be determined (the template objects were not read)'); $ntaInfo = $true }
        }
        if ($null -eq $root) { [void]$ev.Add('Chain root: not found among the discovered CA certificates') }
        elseif ($root.InCertificationAuthorities) { [void]$ev.Add(('Certification Authorities container: root {0} [{1}] published' -f $root.Info.Subject, $root.Thumbprint)) }
        else { [void]$ev.Add(('Certification Authorities container: root {0} [{1}] not found' -f $root.Info.Subject, $root.Thumbprint)); [void]$missing.Add('the Certification Authorities container (for the root)') }
        $conf = 'Referenced'
        if (@($cur.Sources) -contains 'CA:GetCAProperty') { $conf = 'Confirmed' }
        if ($missing.Count -eq 0 -and -not $ntaInfo) {
            [void]$findings.Add((New-MspkiFinding @common -Role (Get-MspkiSchemaRole $cur.Role) -Status 'Pass' -StatusCode 'OK' -Confidence $conf `
                -Sources @($cur.Sources) -Message ('The current CA certificate of {0} and its root are published in the AD PKI containers.' -f $ca.Name) -Evidence @($ev)))
        }
        elseif ($missing.Count -eq 0 -and $ntaInfo) {
            [void]$findings.Add((New-MspkiFinding @common -Role (Get-MspkiSchemaRole $cur.Role) -Status 'Information' -StatusCode 'NOT_DISCOVERED' -Confidence $conf `
                -Sources @($cur.Sources) -Message ('The current CA certificate of {0} is not in NTAuthCertificates; that matters only for a CA that issues certificates used to sign in to AD.' -f $ca.Name) -Evidence @($ev) `
                -Notes 'Review only. Not being in NTAuthCertificates is expected for a CA that does not issue sign-in certificates.'))
        }
        else {
            [void]$findings.Add((New-MspkiFinding @common -Role (Get-MspkiSchemaRole $cur.Role) -Status 'Warning' -StatusCode 'NOT_DISCOVERED' -Confidence $conf `
                -Sources @($cur.Sources) -Message ('The current CA certificate of {0} was not found in {1}.' -f $ca.Name, ($missing -join ' and ')) -Evidence @($ev) `
                -Notes 'Review only. Not being in NTAuthCertificates matters when this CA issues certificates used to sign in to AD (smart card, client authentication, domain controller). Missing AIA data affects chain building for clients that rely on AD.'))
        }

        # (3) AD publication versus the CA's own properties
        if ($null -ne $props) {
            $adNames = @($ca.Templates | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
            $caNames = @($props.Templates | Where-Object { $_ } | ForEach-Object { $_.Name.ToLowerInvariant() } | Sort-Object -Unique)
            if ($adNames.Count -gt 0 -or $caNames.Count -gt 0) {
                $adOnly = @($adNames | Where-Object { $caNames -notcontains $_ })
                $caOnly = @($caNames | Where-Object { $adNames -notcontains $_ })
                $tev = @(('Templates on the Enrollment Services object (AD): {0}' -f $adNames.Count), ('Templates the CA reports it can issue: {0}' -f $caNames.Count))
                if ($adOnly.Count -gt 0) { $tev += ('In AD only: {0}' -f ($adOnly -join ', ')) }
                if ($caOnly.Count -gt 0) { $tev += ('On the CA only: {0}' -f ($caOnly -join ', ')) }
                if ($adOnly.Count -eq 0 -and $caOnly.Count -eq 0) {
                    [void]$findings.Add((New-MspkiFinding @common -Role 'Unknown' -Status 'Pass' -StatusCode 'OK' -Confidence 'Confirmed' -Sources @('AD:EnrollmentServices:certificateTemplates', 'CA:GetCAProperty') `
                        -Message ('The template list in AD and the template list of {0} agree ({1} template(s)).' -f $ca.Name, $adNames.Count) -Evidence $tev))
                }
                else {
                    [void]$findings.Add((New-MspkiFinding @common -Role 'Unknown' -Status 'Warning' -StatusCode 'CONFIG_MISMATCH' -Confidence 'Confirmed' -Sources @('AD:EnrollmentServices:certificateTemplates', 'CA:GetCAProperty') `
                        -Message ('The templates published in AD for {0} differ from the templates the CA reports ({1} only in AD, {2} only on the CA).' -f $ca.Name, $adOnly.Count, $caOnly.Count) -Evidence $tev `
                        -Notes 'Review only. This can be AD replication delay or an update that did not complete. Clients use the AD list to find templates; the CA decides what it issues.'))
                }
            }
            $signing = @($props.SigningCertificates | Where-Object { $_.Thumbprint -and $_.State -eq 'Valid' })
            $adTps = @($ca.CertificateThumbprints)
            $absent = @($signing | Where-Object { $adTps -notcontains $_.Thumbprint })
            if ($signing.Count -gt 0) {
                $cev = @(('CA signing certificates in state Valid: {0}' -f $signing.Count), ('Certificates on the Enrollment Services object: {0}' -f $adTps.Count))
                foreach ($a in $absent) { $cev += ('Valid on the CA but not on the Enrollment Services object: {0} {1}' -f $a.CAVersion, $a.Thumbprint) }
                if ($absent.Count -gt 0) {
                    [void]$findings.Add((New-MspkiFinding @common -Role 'Unknown' -Status 'Warning' -StatusCode 'CONFIG_MISMATCH' -Confidence 'Confirmed' -Sources @('AD:EnrollmentServices', 'CA:GetCAProperty') `
                        -Message ('The Enrollment Services object of {0} does not carry {1} certificate(s) that the CA reports as valid.' -f $ca.Name, $absent.Count) -Evidence $cev `
                        -Notes 'Review only. The cACertificate attribute is refreshed when the CA certificate is renewed or published again.'))
                }
                else {
                    [void]$findings.Add((New-MspkiFinding @common -Role 'Unknown' -Status 'Pass' -StatusCode 'OK' -Confidence 'Confirmed' -Sources @('AD:EnrollmentServices', 'CA:GetCAProperty') `
                        -Message ('The Enrollment Services object of {0} carries every certificate the CA reports as valid.' -f $ca.Name) -Evidence $cev))
                }
            }
        }
    }
    return , $findings.ToArray()
}
