# AD PKI container objects (REQUIREMENTS 5.4, second half): template objects against the lists of published
# templates, the KRA container and OID group links. Review only; nothing here recommends deleting an object.
# Pure functions over the inventory.

function Get-MspkiPublishedTemplateMap {
    <#
    .SYNOPSIS
    Maps each published template name (lower case) to the CAs that publish it and where that was seen
    (AD = certificateTemplates on the Enrollment Services object, CA = the CA's own list).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Inventory)
    $map = @{}
    if ($null -eq $Inventory) { return $map }
    foreach ($ca in @($Inventory.EnterpriseCAs)) {
        $seen = @{}
        foreach ($n in @($ca.Templates | Where-Object { $_ })) { $seen[([string]$n).ToLowerInvariant()] = @{ Name = [string]$n; AD = $true; CA = $false } }
        if ($null -ne $ca.Properties) {
            foreach ($t in @($ca.Properties.Templates | Where-Object { $_ -and $_.Name })) {
                $k = ([string]$t.Name).ToLowerInvariant()
                if ($seen.ContainsKey($k)) { $seen[$k].CA = $true } else { $seen[$k] = @{ Name = [string]$t.Name; AD = $false; CA = $true } }
            }
        }
        foreach ($k in $seen.Keys) {
            if (-not $map.ContainsKey($k)) { $map[$k] = @{ Name = $seen[$k].Name; Cas = (New-Object System.Collections.ArrayList); AD = $false; CA = $false } }
            [void]$map[$k].Cas.Add([string]$ca.Name)
            if ($seen[$k].AD) { $map[$k].AD = $true }
            if ($seen[$k].CA) { $map[$k].CA = $true }
        }
    }
    return $map
}

function Test-MspkiAdContainerObject {
    <#
    .SYNOPSIS
    Reviews the template, KRA and OID containers against what the CAs publish and report.

    .DESCRIPTION
    (1) A template name published by a CA that has no template object. (2) Template objects that no CA publishes
    (one summary, information only: most forests keep unpublished default templates). (3) KRA certificates that
    are missing or expired, and CAs that report fewer usable KRA certificates than configured. (4) OID objects
    whose msDS-OIDToGroupLink does not resolve to a group. A failed read is never reported as "missing".
    #>
    [CmdletBinding()]
    param([AllowNull()]$Inventory, [DateTime]$Now = (Get-MspkiUtcNow))
    $findings = New-Object System.Collections.ArrayList
    if ($null -eq $Inventory) { return , $findings.ToArray() }
    $common = @{ Stage = 'Analysis'; Scope = 'Local' }

    # (1) and (2): templates
    if ($Inventory.TemplatesRead -eq $true) {
        $objects = @{}
        foreach ($t in @($Inventory.Templates)) { $objects[([string]$t.Name).ToLowerInvariant()] = $t }
        $published = Get-MspkiPublishedTemplateMap -Inventory $Inventory
        foreach ($ca in @($Inventory.EnterpriseCAs)) {
            $missing = @()
            foreach ($k in ($published.Keys | Sort-Object)) {
                if (@($published[$k].Cas) -contains $ca.Name -and -not $objects.ContainsKey($k)) { $missing += $published[$k] }
            }
            if ($missing.Count -gt 0) {
                $ev = @($missing | ForEach-Object {
                    $where = @(); if ($_.AD) { $where += 'AD (Enrollment Services)' }; if ($_.CA) { $where += 'CA (GetCAProperty)' }
                    'Published template with no template object: {0} (listed by {1})' -f $_.Name, ($where -join ' and ') })
                $ev += ('Template objects read from CN=Certificate Templates: {0}' -f $objects.Count)
                $conf = 'Referenced'
                if (@($missing | Where-Object { $_.CA }).Count -eq $missing.Count) { $conf = 'Confirmed' }
                [void]$findings.Add((New-MspkiFinding @common -Category 'Template' -Role 'Template' -Target $ca.Name -RelatedCA $ca.Name -Status 'Warning' `
                    -StatusCode 'NOT_DISCOVERED' -Confidence $conf -Sources @('AD:EnrollmentServices:certificateTemplates', 'AD:CertificateTemplates') `
                    -Layers @{ DiscoveryStatus = 'Warning' } `
                    -Message ('{0} publishes {1} template name(s) for which no template object exists in AD.' -f $ca.Name, $missing.Count) -Evidence $ev `
                    -Notes 'Review only. The CA cannot issue from a template whose object is missing. This can follow a template that was changed in AD while the CA list was not updated.'))
            }
        }
        if (@($Inventory.EnterpriseCAs).Count -gt 0) {
            $unpublished = @($Inventory.Templates | Where-Object { -not $published.ContainsKey(([string]$_.Name).ToLowerInvariant()) } | ForEach-Object { $_.Name } | Sort-Object)
            if ($unpublished.Count -gt 0) {
                $ev = @($unpublished | ForEach-Object { 'Template object published by no Enterprise CA: {0}' -f $_ })
                $ev += ('Enterprise CAs compared: {0}' -f @($Inventory.EnterpriseCAs).Count)
                [void]$findings.Add((New-MspkiFinding @common -Category 'Template' -Role 'Template' -Target 'Certificate Templates' -Status 'Information' `
                    -StatusCode 'NOT_CONFIGURED' -Confidence 'Referenced' -Sources @('AD:CertificateTemplates', 'AD:EnrollmentServices:certificateTemplates') `
                    -Layers @{ DiscoveryStatus = 'Pass' } `
                    -Message ('{0} of {1} template object(s) are published by no Enterprise CA.' -f $unpublished.Count, @($Inventory.Templates).Count) -Evidence $ev `
                    -Notes 'Review only. Unpublished templates are normal (the default templates are kept in AD). They are reviewed with a lower severity.'))
            }
        }
    }

    # (3) KRA
    if ($Inventory.KraRead -eq $true) {
        $validKra = 0
        foreach ($k in @($Inventory.Kra)) {
            $certs = @($k.Certificates)
            $live = @($certs | Where-Object { -not $_.Expired })
            $validKra += $live.Count
            $ev = @(('KRA object: {0}' -f $k.DistinguishedName), ('Certificates on the object: {0}' -f $certs.Count))
            foreach ($c in $certs) { $ev += ('Certificate {0} [{1}] valid until {2}{3}' -f $c.Subject, $c.Thumbprint, $c.NotAfter, $(if ($c.Expired) { ' (expired)' } else { '' })) }
            foreach ($e in @($k.CertificateErrors)) { $ev += ('Unreadable value: {0}' -f $e) }
            if ($certs.Count -eq 0) {
                # AD CS creates one KRA object per CA at install time; it holds a certificate only after a key recovery agent was added.
                # An empty object is the normal state when key archival is not used. The CA-side check below (KraCertCount from the CA)
                # is what shows a real problem.
                [void]$findings.Add((New-MspkiFinding @common -Category 'ADContainer' -Role 'ADContainer' -Target $k.Name -Endpoint $k.DistinguishedName -Status 'Information' `
                    -StatusCode 'NOT_CONFIGURED' -Confidence 'Confirmed' -Sources 'AD:KRA' -Layers @{ DiscoveryStatus = 'Pass' } `
                    -Message ('The KRA object {0} holds no key recovery agent certificate (normal when key archival is not used).' -f $k.Name) -Evidence $ev `
                    -Notes 'Information only. It matters only when the CA is configured to archive keys: the CA property KraCertCount is checked separately when the CA answers.'))
            }
            elseif ($live.Count -eq 0) {
                [void]$findings.Add((New-MspkiFinding @common -Category 'ADContainer' -Role 'ADContainer' -Target $k.Name -Endpoint $k.DistinguishedName -Status 'Warning' `
                    -StatusCode 'OBJECT_EXPIRED' -Confidence 'Confirmed' -Sources 'AD:KRA' -Layers @{ DiscoveryStatus = 'Pass'; ContentStatus = 'Fail' } `
                    -Message ('Every certificate of the KRA object {0} has expired.' -f $k.Name) -Evidence $ev `
                    -Notes 'Review only. A CA cannot encrypt archived keys to an expired key recovery agent certificate.'))
            }
            else {
                [void]$findings.Add((New-MspkiFinding @common -Category 'ADContainer' -Role 'ADContainer' -Target $k.Name -Endpoint $k.DistinguishedName -Status 'Pass' `
                    -StatusCode 'OK' -Confidence 'Confirmed' -Sources 'AD:KRA' -Layers @{ DiscoveryStatus = 'Pass'; ContentStatus = 'Pass' } `
                    -Message ('The KRA object {0} holds {1} certificate(s) that have not expired.' -f $k.Name, $live.Count) -Evidence $ev))
            }
        }
        foreach ($ca in @($Inventory.EnterpriseCAs)) {
            $p = $ca.Properties
            if ($null -eq $p -or $null -eq $p.KraCertCount -or [int]$p.KraCertCount -le 0) { continue }
            $used = 0
            if ($null -ne $p.KraCertUsedCount) { $used = [int]$p.KraCertUsedCount }
            if ($used -lt [int]$p.KraCertCount) {
                [void]$findings.Add((New-MspkiFinding @common -Category 'ADContainer' -Role 'ADContainer' -Target $ca.Name -RelatedCA $ca.Name -Status 'Warning' `
                    -StatusCode 'NOT_DISCOVERED' -Confidence 'Confirmed' -Sources @('CA:GetCAProperty', 'AD:KRA') -Layers @{ DiscoveryStatus = 'Warning' } `
                    -Message ('{0} is configured with {1} key recovery agent certificate(s) but can use only {2}.' -f $ca.Name, $p.KraCertCount, $used) `
                    -Evidence @(('CA reports KRA certificates configured: {0}' -f $p.KraCertCount), ('CA reports KRA certificates it can use: {0}' -f $used),
                        ('Non-expired certificates in the KRA container: {0}' -f $validKra)) `
                    -Notes 'Review only. A KRA certificate the CA cannot find or that has expired is not used when archiving keys.'))
            }
        }
    }

    # (4) OID group links
    if ($Inventory.OidRead -eq $true) {
        $linked = @($Inventory.OidObjects | Where-Object { $_.GroupLink })
        $ok = New-Object System.Collections.ArrayList
        foreach ($o in $linked) {
            $label = $o.DisplayName
            if (-not $label) { $label = $o.Name }
            $ev = @(('OID object: {0}' -f $o.DistinguishedName), ('OID: {0}' -f $o.Oid), ('msDS-OIDToGroupLink: {0}' -f $o.GroupLink))
            if ($o.GroupResolved -eq $true) { [void]$ok.Add(('{0} ({1}) -> {2}' -f $label, $o.Oid, $o.GroupName)); continue }
            if ($o.GroupResolved -eq $false) {
                $ev += ('Lookup of the group: {0}' -f $o.GroupError)
                [void]$findings.Add((New-MspkiFinding @common -Category 'ADContainer' -Role 'ADContainer' -Target $label -Endpoint $o.DistinguishedName -Status 'Warning' `
                    -StatusCode 'NOT_DISCOVERED' -Confidence 'Confirmed' -Sources 'AD:OID:msDS-OIDToGroupLink' -Layers @{ DiscoveryStatus = 'Pass'; ContentStatus = 'Fail' } `
                    -Message ('The OID {0} is linked to a group that does not resolve.' -f $label) -Evidence $ev `
                    -Notes 'Review only. Holders of a certificate with this issuance policy get no group membership from a link that does not resolve.'))
                continue
            }
            # Not looked up successfully: keep the permission problem apart from an infrastructure problem.
            $ev += ('Lookup of the group: {0}' -f $o.GroupError)
            if ($o.GroupError -like 'PermissionDenied*') { $st = 'Skipped'; $code = 'PERMISSION_DENIED' } else { $st = 'Error'; $code = 'RETRIEVAL_FAIL' }
            [void]$findings.Add((New-MspkiFinding @common -Category 'ADContainer' -Role 'ADContainer' -Target $label -Endpoint $o.DistinguishedName -Status $st `
                -StatusCode $code -Confidence 'Unknown' -Sources 'AD:OID:msDS-OIDToGroupLink' -Layers @{ DiscoveryStatus = 'Error' } `
                -Message ('The group linked to the OID {0} could not be looked up, so the link was not judged.' -f $label) -Evidence $ev))
        }
        if ($ok.Count -gt 0) {
            [void]$findings.Add((New-MspkiFinding @common -Category 'ADContainer' -Role 'ADContainer' -Target 'OID' -Status 'Pass' -StatusCode 'OK' -Confidence 'Confirmed' `
                -Sources 'AD:OID:msDS-OIDToGroupLink' -Layers @{ DiscoveryStatus = 'Pass' } `
                -Message ('{0} OID group link(s) resolve to a group.' -f $ok.Count) -Evidence @($ok | ForEach-Object { 'Link: {0}' -f $_ })))
        }
    }
    return , $findings.ToArray()
}
