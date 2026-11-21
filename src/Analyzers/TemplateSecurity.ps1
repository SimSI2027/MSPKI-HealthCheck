# Defensive review of certificate templates (REQUIREMENTS 5.5). Reads template data only; no enrollment code.
# A finding needs EVERY condition of a review pattern and lists each condition in Evidence. One flag on its own
# is never a finding. The pattern labels (ESC1, ESC2, ...) are the names used in public PKI security research.
# Effective permissions (group nesting, deny ACEs) are not computed: the evidence shows the ACEs that are in the
# template's own ACL.

$script:MspkiEkuName = @{
    '1.3.6.1.5.5.7.3.2'      = 'Client Authentication'
    '1.3.6.1.5.2.3.4'        = 'PKINIT Client Authentication'
    '1.3.6.1.4.1.311.20.2.2' = 'Smart Card Logon'
    '2.5.29.37.0'            = 'Any Purpose'
    '1.3.6.1.4.1.311.20.2.1' = 'Certificate Request Agent'
    '1.3.6.1.5.5.7.3.1'      = 'Server Authentication'
}
$script:MspkiClientAuthEku = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0')
$script:MspkiAnyPurposeEku = '2.5.29.37.0'
$script:MspkiAgentEku = '1.3.6.1.4.1.311.20.2.1'
$script:MspkiTemplateFlagBit = @{
    EnrolleeSuppliesSubject = 0x1; EnrolleeSuppliesSubjectAltName = 0x10000
    PendAllRequests = 0x2; NoSecurityExtension = 0x80000
}
$script:MspkiSeverityStep = @{ High = 'Medium'; Medium = 'Low'; Low = 'Information'; Information = 'Information'; ReviewRequired = 'ReviewRequired'; None = 'None' }
$script:MspkiSeverityStatus = @{ High = 'Fail'; Medium = 'Warning'; Low = 'Information'; Information = 'Information'; ReviewRequired = 'Warning' }

function Get-MspkiEkuLabel {
    [CmdletBinding()]
    param([string]$Oid)
    if ($script:MspkiEkuName.ContainsKey($Oid)) { return ('{0} ({1})' -f $script:MspkiEkuName[$Oid], $Oid) }
    return $Oid
}

function Test-MspkiAceGrant {
    <#
    .SYNOPSIS
    True when an ACE (from ConvertFrom-MspkiSecurityDescriptor) grants the Enroll right or a write-type right on
    the template object itself. Deny ACEs and inherit-only ACEs never count as a grant.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Ace, [Parameter(Mandatory = $true)][ValidateSet('Enroll', 'Write')][string]$Right)
    if ($Ace.Type -ne 'Allow' -or $Ace.InheritOnly) { return $false }
    $m = [int64]$Ace.Mask
    $full = (($m -band $script:MspkiAdRightBit.GenericAll) -ne 0) -or (($m -band 0xF01FF) -eq 0xF01FF)
    if ($full) { return $true }
    if ($Right -eq 'Enroll') {
        if (($m -band $script:MspkiAdRightBit.ExtendedRight) -eq 0) { return $false }
        return ($Ace.ObjectType -eq '' -or $Ace.ObjectType -eq $script:MspkiEnrollRightGuid)
    }
    $writeBits = $script:MspkiAdRightBit.GenericWrite -bor $script:MspkiAdRightBit.WriteOwner -bor $script:MspkiAdRightBit.WriteDacl -bor $script:MspkiAdRightBit.WriteProperty
    return (($m -band $writeBits) -ne 0)
}

function Get-MspkiBroadAce {
    <#
    .SYNOPSIS
    The ACEs of a template that grant Enroll or a write-type right to a broad group, as { Sid, Principal, Label, Rights, Denied }.
    "Denied" is true when a Deny ACE exists for the same principal (effective access is then not computed).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Template, [Parameter(Mandatory = $true)][ValidateSet('Enroll', 'Write')][string]$Right)
    $out = New-Object System.Collections.ArrayList
    $acl = @($Template.Acl)
    foreach ($a in $acl) {
        if (-not (Test-MspkiAceGrant -Ace $a -Right $Right)) { continue }
        $label = Get-MspkiBroadPrincipal -Sid ([string]$a.Sid)
        if (-not $label) { continue }
        $denied = (@($acl | Where-Object { $_.Type -eq 'Deny' -and -not $_.InheritOnly -and $_.Sid -eq $a.Sid }).Count -gt 0)
        $name = [string]$a.Principal
        if (-not $name) { $name = $label }
        [void]$out.Add([pscustomobject][ordered]@{ Sid = [string]$a.Sid; Principal = $name; Label = $label; Rights = @($a.Rights); Denied = $denied; Via = 'ACE' })
    }
    if ($Right -eq 'Write' -and $Template.OwnerSid) {
        $ol = Get-MspkiBroadPrincipal -Sid ([string]$Template.OwnerSid)
        if ($ol) {
            $name = [string]$Template.Owner
            if (-not $name) { $name = $ol }
            [void]$out.Add([pscustomobject][ordered]@{ Sid = [string]$Template.OwnerSid; Principal = $name; Label = $ol; Rights = @('Owner'); Denied = $false; Via = 'Owner' })
        }
    }
    return , $out.ToArray()
}

function Get-MspkiTemplateFact {
    <#
    .SYNOPSIS
    Reduces a template object to the facts the review patterns use.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Template)
    $eku = @($Template.ApplicationPolicies | Where-Object { $_ })
    if ($eku.Count -eq 0) { $eku = @($Template.Eku | Where-Object { $_ }) }
    $noEku = ($eku.Count -eq 0)
    $nf = [int64]$Template.NameFlag
    $ef = [int64]$Template.EnrollmentFlag
    $supplies = @()
    if (($nf -band $script:MspkiTemplateFlagBit.EnrolleeSuppliesSubject) -ne 0) { $supplies += 'subject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)' }
    if (($nf -band $script:MspkiTemplateFlagBit.EnrolleeSuppliesSubjectAltName) -ne 0) { $supplies += 'subject alternative name (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)' }
    $raApp = @($Template.RaApplicationPolicies | Where-Object { $_ })
    $clientAuth = ($noEku -or @($eku | Where-Object { $script:MspkiClientAuthEku -contains $_ }).Count -gt 0)
    return [pscustomobject][ordered]@{
        Eku               = $eku
        NoEku             = $noEku
        EkuText           = $(if ($noEku) { 'none (the template has no EKU, so the certificate is valid for any purpose)' } else { (@($eku | ForEach-Object { Get-MspkiEkuLabel $_ }) -join ', ') })
        ClientAuthCapable = $clientAuth
        AnyPurpose        = ($eku -contains $script:MspkiAnyPurposeEku)
        AgentEku          = ($eku -contains $script:MspkiAgentEku)
        Supplies          = $supplies
        ManagerApproval   = (($ef -band $script:MspkiTemplateFlagBit.PendAllRequests) -ne 0)
        RaSignatures      = [int]$Template.RaSignature
        AcceptsAgentSig   = ([int]$Template.RaSignature -ge 1 -and $raApp -contains $script:MspkiAgentEku)
        NoSecurityExt     = (($ef -band $script:MspkiTemplateFlagBit.NoSecurityExtension) -ne 0)
        BroadEnroll       = (Get-MspkiBroadAce -Template $Template -Right Enroll)
        BroadWrite        = (Get-MspkiBroadAce -Template $Template -Right Write)
    }
}

function Get-MspkiPrincipalText {
    [CmdletBinding()]
    param($Entries)
    return (@($Entries | ForEach-Object {
        $t = '{0} [{1}] ({2}; rights: {3})' -f $_.Principal, $_.Label, $_.Sid, (@($_.Rights) -join ', ')
        if ($_.Denied) { $t += ' - a Deny ACE exists for the same principal, effective access not computed' }
        $t }) -join '; ')
}

function Get-MspkiTemplatePatternMatch {
    <#
    .SYNOPSIS
    Evaluates one template against every review pattern. Returns one object per pattern whose conditions are
    ALL met: { Rule, Title, Severity, Conditions (one line per condition), Notes, Sources }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Template,
        [Parameter(Mandatory = $true)]$Facts,
        [Parameter(Mandatory = $true)][hashtable]$AllFacts,
        [Parameter(Mandatory = $true)][hashtable]$Published,
        [hashtable]$OidLinks = @{}
    )
    $found = New-Object System.Collections.ArrayList
    $f = $Facts
    $enrollText = { 'Broad group can enroll: {0}' -f (Get-MspkiPrincipalText $f.BroadEnroll) }
    $noApprovalText = 'No manager approval (CT_FLAG_PEND_ALL_REQUESTS is not set)'
    $noSigText = 'No authorised signatures required (msPKI-RA-Signature = {0})' -f $f.RaSignatures

    # Pattern ESC1: enrollee supplies the subject, certificate usable to sign in, broad enroll, no approval or signatures.
    if ($f.BroadEnroll.Count -gt 0 -and $f.Supplies.Count -gt 0 -and $f.ClientAuthCapable -and -not $f.ManagerApproval -and $f.RaSignatures -eq 0) {
        [void]$found.Add([pscustomobject]@{ Rule = 'ESC1'; Severity = 'High'
            Title = 'the enrollee supplies the subject of a certificate that can be used to sign in, and a broad group can enroll without approval'
            Conditions = @((& $enrollText), ('The enrollee supplies the {0}' -f ($f.Supplies -join ' and the ')),
                ('EKU allows client authentication: {0}' -f $f.EkuText), $noApprovalText, $noSigText)
            Notes = 'Review who needs to enroll, whether the subject must be supplied by the requester, and whether manager approval or authorised signatures fit this template.' })
    }
    # Pattern ESC2: any-purpose or no EKU, broad enroll, no approval or signatures.
    if ($f.BroadEnroll.Count -gt 0 -and ($f.AnyPurpose -or $f.NoEku) -and -not $f.ManagerApproval -and $f.RaSignatures -eq 0) {
        [void]$found.Add([pscustomobject]@{ Rule = 'ESC2'; Severity = 'High'
            Title = 'the certificate is valid for any purpose (Any Purpose or no EKU) and a broad group can enroll without approval'
            Conditions = @((& $enrollText), ('EKU is Any Purpose or absent: {0}' -f $f.EkuText), $noApprovalText, $noSigText)
            Notes = 'A certificate valid for any purpose can also act as a certificate request agent or a subordinate CA certificate, depending on its other settings.' })
    }
    # Pattern ESC3: broad enroll for the Certificate Request Agent EKU without approval, AND another published template that
    # accepts enrollment-agent signatures and is usable to sign in.
    if ($f.BroadEnroll.Count -gt 0 -and $f.AgentEku -and -not $f.ManagerApproval) {
        $others = New-Object System.Collections.ArrayList
        foreach ($k in ($AllFacts.Keys | Sort-Object)) {
            if ($k -eq $Template.Name.ToLowerInvariant()) { continue }
            if (-not $Published.ContainsKey($k)) { continue }
            $o = $AllFacts[$k]
            if ($o.Facts.AcceptsAgentSig -and $o.Facts.ClientAuthCapable) { [void]$others.Add($o) }
        }
        if ($others.Count -gt 0) {
            $oc = @($others | ForEach-Object {
                'Another published template accepts enrollment-agent signatures and allows client authentication: {0} (msPKI-RA-Signature = {1}; manager approval: {2}; broad enroll: {3})' -f `
                    $_.Template.Name, $_.Facts.RaSignatures, $(if ($_.Facts.ManagerApproval) { 'required' } else { 'not required' }), $(if ($_.Facts.BroadEnroll.Count -gt 0) { 'yes' } else { 'no' }) })
            [void]$found.Add([pscustomobject]@{ Rule = 'ESC3'; Severity = 'High'
                Title = 'a broad group can enroll for a Certificate Request Agent certificate without approval, and another published template accepts that agent''s signature'
                Conditions = @((& $enrollText), ('EKU includes Certificate Request Agent: {0}' -f $f.EkuText), $noApprovalText, ('Authorised signatures on this template: {0}' -f $f.RaSignatures)) + $oc
                Notes = 'Enrollment agent restrictions configured on the CA cannot be read from here and may limit this.' })
        }
    }
    # Pattern ESC4: a broad group has write, owner or full-control rights on the template object.
    if ($f.BroadWrite.Count -gt 0) {
        [void]$found.Add([pscustomobject]@{ Rule = 'ESC4'; Severity = 'High'
            Title = 'a broad group has write, owner or full-control rights on the template object'
            Conditions = @(('Broad group with write-type rights on the template: {0}' -f (Get-MspkiPrincipalText $f.BroadWrite)))
            Notes = 'Anyone who can change the template can change who may enroll and what the certificate is valid for.' })
    }
    # Pattern ESC9: no security extension, usable to sign in, broad enroll. Review only: strong certificate binding on the
    # domain controllers cannot be confirmed from here.
    if ($f.NoSecurityExt -and $f.ClientAuthCapable -and $f.BroadEnroll.Count -gt 0) {
        [void]$found.Add([pscustomobject]@{ Rule = 'ESC9'; Severity = 'ReviewRequired'
            Title = 'certificates from this template carry no security identifier extension, can be used to sign in, and a broad group can enroll'
            Conditions = @('The template sets CT_FLAG_NO_SECURITY_EXTENSION (msPKI-Enrollment-Flag)', ('EKU allows client authentication: {0}' -f $f.EkuText), (& $enrollText))
            Notes = 'Whether this matters depends on certificate-binding enforcement on the domain controllers (registry settings that are not read here), so it is marked for review.' })
    }
    # Pattern ESC13: an issuance policy of the template is linked to a group, and a broad group can enroll.
    if ($f.BroadEnroll.Count -gt 0) {
        $linked = @($Template.IssuancePolicies | Where-Object { $_ -and $OidLinks.ContainsKey([string]$_) })
        if ($linked.Count -gt 0) {
            $lc = @($linked | ForEach-Object {
                $o = $OidLinks[[string]$_]
                $gr = 'resolved'; if ($o.GroupResolved -ne $true) { $gr = 'not looked up' }
                'Issuance policy {0} ({1}) is linked by msDS-OIDToGroupLink to {2} (group {3})' -f $o.Oid, $o.DisplayName, $o.GroupLink, $gr })
            [void]$found.Add([pscustomobject]@{ Rule = 'ESC13'; Severity = 'Medium'
                Title = 'the template carries an issuance policy that is linked to a group, and a broad group can enroll'
                Conditions = @($lc) + @((& $enrollText), ('Other settings (for the reviewer): client authentication EKU {0}; manager approval {1}; authorised signatures {2}' -f $f.ClientAuthCapable, $f.ManagerApproval, $f.RaSignatures))
                Notes = 'A certificate with this issuance policy can add the linked group to a Kerberos ticket. Review the group''s members and rights.'; Extra = 'AD:OID:msDS-OIDToGroupLink' })
        }
    }
    return , $found.ToArray()
}

function Test-MspkiTemplateEnrollmentRisk {
    <#
    .SYNOPSIS
    Defensive review of the certificate templates in the inventory against the review patterns of REQUIREMENTS 5.5.

    .DESCRIPTION
    Pure function over the inventory (templates read from AD, the lists of published templates, OID group links).
    Every finding lists each condition that was met. Templates that no CA publishes are reported one severity step
    lower and marked Unpublished. Reading problems are reported as such, never as "no issue".
    #>
    [CmdletBinding()]
    param([AllowNull()]$Inventory)
    $findings = New-Object System.Collections.ArrayList
    if ($null -eq $Inventory) { return , $findings.ToArray() }
    $common = @{ Category = 'Template'; Role = 'Template'; Stage = 'Analysis'; Scope = 'Local' }
    if ($Inventory.TemplatesRead -ne $true) {
        [void]$findings.Add((New-MspkiFinding @common -Target 'Certificate Templates' -Status 'Skipped' -StatusCode 'NOT_APPLICABLE' -Confidence 'Unknown' `
            -Sources 'AD:CertificateTemplates' -Layers @{ DiscoveryStatus = 'Skipped' } `
            -Message 'The template review was not done because the template objects could not be read (see the discovery findings).'))
        return , $findings.ToArray()
    }
    $templates = @($Inventory.Templates | Sort-Object { $_.Name })
    $published = Get-MspkiPublishedTemplateMap -Inventory $Inventory
    $oidLinks = @{}
    foreach ($o in @($Inventory.OidObjects | Where-Object { $_.GroupLink -and $_.Oid -and $_.GroupResolved -ne $false })) { $oidLinks[[string]$o.Oid] = $o }

    $allFacts = @{}
    $noAcl = New-Object System.Collections.ArrayList
    foreach ($t in $templates) {
        $allFacts[([string]$t.Name).ToLowerInvariant()] = @{ Template = $t; Facts = (Get-MspkiTemplateFact -Template $t) }
        if ($t.AclError) { [void]$noAcl.Add($t) }
    }
    if ($noAcl.Count -gt 0) {
        [void]$findings.Add((New-MspkiFinding @common -Target 'Certificate Templates' -Status 'Warning' -StatusCode 'RETRIEVAL_FAIL' -Confidence 'Confirmed' `
            -Sources 'AD:CertificateTemplates' -Layers @{ DiscoveryStatus = 'Warning' } `
            -Message ('The permissions of {0} template(s) could not be read, so the enrollment and write patterns could not be evaluated for them.' -f $noAcl.Count) `
            -Evidence @($noAcl | ForEach-Object { 'Template {0}: {1}' -f $_.Name, $_.AclError })))
    }

    $matched = 0
    $lines = New-Object System.Collections.ArrayList
    foreach ($t in $templates) {
        $key = ([string]$t.Name).ToLowerInvariant()
        $facts = $allFacts[$key].Facts
        $isPub = $published.ContainsKey($key)
        $cas = @(); $viaCa = $false
        if ($isPub) { $cas = @($published[$key].Cas); $viaCa = [bool]$published[$key].CA }
        $hits = (Get-MspkiTemplatePatternMatch -Template $t -Facts $facts -AllFacts $allFacts -Published $published -OidLinks $oidLinks)
        if ($hits.Count -eq 0) { [void]$lines.Add(('{0}: no review pattern matched' -f $t.Name)); continue }
        [void]$lines.Add(('{0}: matched {1}' -f $t.Name, (($hits | ForEach-Object { $_.Rule }) -join ', ')))
        foreach ($h in $hits) {
            $matched++
            $sev = $h.Severity
            if (-not $isPub) { $sev = $script:MspkiSeverityStep[$sev] }
            $status = $script:MspkiSeverityStatus[$sev]
            $head = @(('Template: {0} (cn {1}), schema version {2}, OID {3}' -f $(if ($t.DisplayName) { $t.DisplayName } else { $t.Name }), $t.Name, $t.SchemaVersion, $t.Oid))
            if ($isPub) { $head += ('Published on: {0}{1}' -f ($cas -join ', '), $(if ($viaCa) { ' (also in the CA''s own list)' } else { ' (AD Enrollment Services list only)' })) }
            else { $head += 'Unpublished: no Enterprise CA publishes this template; the severity is one step lower than for a published template.' }
            $ev = @($head) + @($h.Conditions | ForEach-Object { 'Condition met: {0}' -f $_ })
            $ev += 'Effective permissions (group nesting, deny ACEs) are not computed; the ACEs above are in the template''s own ACL.'
            $src = @('AD:CertificateTemplates', 'AD:EnrollmentServices:certificateTemplates')
            if ($viaCa) { $src += 'CA:GetCAProperty' }
            if ($h.Extra) { $src += $h.Extra }
            $conf = 'Referenced'
            if ($isPub -and $viaCa) { $conf = 'Confirmed' }
            $prefix = ''
            if (-not $isPub) { $prefix = '[Unpublished] ' }
            $msg = '{0}Template {1} meets every condition of review pattern {2}: {3}.' -f $prefix, $t.Name, $h.Rule, $h.Title
            [void]$findings.Add((New-MspkiFinding @common -Target $t.Name -Endpoint $t.DistinguishedName -RelatedCA ($cas -join ', ') -Status $status `
                -StatusCode 'CONFIG_RISK' -Severity $sev -Confidence $conf -Sources $src -Layers @{ DiscoveryStatus = 'Pass' } -Message $msg -Evidence $ev `
                -Remediation 'Review only: no change is made or suggested automatically.' -Notes $h.Notes))
        }
    }
    $pubCount = @($templates | Where-Object { $published.ContainsKey(([string]$_.Name).ToLowerInvariant()) }).Count
    $st = 'Pass'; if ($matched -gt 0) { $st = 'Information' }
    $sum = New-MspkiFinding @common -Target 'Certificate Templates' -Status $st -StatusCode 'OK' -Confidence 'Referenced' `
        -Sources @('AD:CertificateTemplates', 'AD:EnrollmentServices:certificateTemplates') -Layers @{ DiscoveryStatus = 'Pass' } `
        -Message ('Reviewed {0} template(s) ({1} published): {2} review finding(s).' -f $templates.Count, $pubCount, $matched) `
        -Evidence (@(@($lines) | Select-Object -First 300) + @('Patterns evaluated: ESC1, ESC2, ESC3, ESC4, ESC9, ESC13. Each needs every one of its conditions.')) `
        -Notes 'CA-side settings (for example the CA''s own flags and permissions) are not read by this review.'
    [void]$findings.Add($sum)
    return , $findings.ToArray()
}
