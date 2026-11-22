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

# Schema IDs of the template attributes whose value decides what a certificate may be used for (name flags, enrollment flags, extended key
# usage and application policies, issuance and RA policies, RA signatures, private key flags, minimal key size). They are defined by
# Microsoft and are the same in every forest. A write to any other single attribute of a template is not a way to change what a
# certificate may be used for, so it does not count for ESC4 (audit 2 M11).
$script:MspkiTemplateSensitiveAttribute = [ordered]@{
    'msPKI-Certificate-Name-Flag'          = 'ea1dddc4-60ff-416e-8cc0-17cee534bce7'
    'msPKI-Enrollment-Flag'                = 'd15ef7d8-f226-46db-ae79-b34e560bd12c'
    'msPKI-RA-Signature'                   = 'fe17e04b-937d-4f7e-8e0e-9292c8d5683e'
    'msPKI-Private-Key-Flag'               = 'bab04ac2-0435-4709-9307-28380e7c7001'
    'pKIExtendedKeyUsage'                  = '18976af6-3b9e-11d2-90cc-00c04fd91ab1'
    'msPKI-Certificate-Application-Policy' = 'dbd90548-aa37-4202-9966-8c537ba5ce32'
    'msPKI-RA-Application-Policies'        = '3c91fbbf-4773-4ccd-a87b-85d53e7bcf6a'
    'msPKI-RA-Policies'                    = 'd546ae22-0951-4d47-817e-1c9f96faad46'
    'msPKI-Certificate-Policy'             = '38942346-cc5b-424b-a7d8-6ffd12029c5f'
    'msPKI-Minimal-Key-Size'               = 'e96a63f5-417f-46d3-be52-db7703c503df'
}

function Test-MspkiAceGrant {
    <#
    .SYNOPSIS
    True when an ACE (from ConvertFrom-MspkiSecurityDescriptor) grants the Enroll right or a write-type right on
    the template object itself. Deny ACEs and inherit-only ACEs never count as a grant. A write-type right is write-DACL, write-owner,
    generic write, a write to all properties, or a write to one of the attributes in $script:MspkiTemplateSensitiveAttribute; a write
    to any other single attribute is not one.
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
    # Rights that apply to the whole object, whatever object type the ACE names.
    $writeBits = $script:MspkiAdRightBit.GenericWrite -bor $script:MspkiAdRightBit.WriteOwner -bor $script:MspkiAdRightBit.WriteDacl
    # The Enroll and Autoenroll ACEs are written by the template console with the mask 0x130 (read, write, control access) and the
    # extended-right GUID as object type. Their write bit does not apply to a property of the template: it is not a write right.
    $ot = ([string]$Ace.ObjectType).ToLowerInvariant()
    $isEnrollAce = ($ot -eq $script:MspkiEnrollRightGuid -or $ot -eq $script:MspkiAutoEnrollRightGuid)
    if ($isEnrollAce) { $writeBits = $writeBits -band (-bnot $script:MspkiAdRightBit.GenericWrite) }
    if (($m -band $writeBits) -ne 0) { return $true }
    # A write to properties: all of them (no object type), or one that can change what a certificate may be used for.
    if (($m -band $script:MspkiAdRightBit.WriteProperty) -ne 0 -and -not $isEnrollAce) {
        return ($ot -eq '' -or @($script:MspkiTemplateSensitiveAttribute.Values) -contains $ot)
    }
    return $false
}

function Test-MspkiSidContains {
    <#
    .SYNOPSIS
    True when the well-known group Outer contains the principal Inner, or both are the same SID. Only the fixed containments of the
    broad groups are known without a directory lookup: Everyone contains every principal; Authenticated Users contains itself,
    Domain Users and Domain Computers (of any domain). Nothing else is assumed.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Outer, [AllowEmptyString()][string]$Inner)
    if (-not $Outer -or -not $Inner) { return $false }
    if ($Outer -eq $Inner) { return $true }
    if ($Outer -eq 'S-1-1-0') { return $true }
    if ($Outer -eq 'S-1-5-11') { return ($Inner -match '^S-1-5-21-\d+-\d+-\d+-(513|515)$') }
    return $false
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
        # A Deny ACE for the same principal, or for a well-known group that contains it (audit 2 M11: a Deny for Everyone also
        # applies to Authenticated Users), may cancel this grant. Effective access is not computed, so such a match is a review item.
        $denyAces = @($acl | Where-Object { $_.Type -eq 'Deny' -and -not $_.InheritOnly -and (Test-MspkiSidContains -Outer ([string]$_.Sid) -Inner ([string]$a.Sid)) })
        $denied = ($denyAces.Count -gt 0)
        $deniedBy = @($denyAces | ForEach-Object { $l = Get-MspkiBroadPrincipal -Sid ([string]$_.Sid); if ($l) { $l } elseif ($_.Principal) { [string]$_.Principal } else { [string]$_.Sid } } | Select-Object -Unique)
        $name = [string]$a.Principal
        if (-not $name) { $name = $label }
        [void]$out.Add([pscustomobject][ordered]@{ Sid = [string]$a.Sid; Principal = $name; Label = $label; Rights = @($a.Rights); Denied = $denied; DeniedBy = $deniedBy; Via = 'ACE' })
    }
    if ($Right -eq 'Write' -and $Template.OwnerSid) {
        $ol = Get-MspkiBroadPrincipal -Sid ([string]$Template.OwnerSid)
        if ($ol) {
            $name = [string]$Template.Owner
            if (-not $name) { $name = $ol }
            [void]$out.Add([pscustomobject][ordered]@{ Sid = [string]$Template.OwnerSid; Principal = $name; Label = $ol; Rights = @('Owner'); Denied = $false; DeniedBy = @(); Via = 'Owner' })
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
    # Which templates accept a request signed by an enrollment agent on behalf of another user (audit 2 H2): a schema version 1
    # template accepts it from any enrollment agent (it has no issuance requirements to check); a template of schema version 2 or
    # later accepts it when it requires an authorised signature with the Certificate Request Agent application policy.
    $schema = 0
    if ($null -ne $Template.PSObject.Properties['SchemaVersion']) { $schema = [int]$Template.SchemaVersion }
    $acceptsAgent = $false; $agentWhy = ''
    if ($schema -eq 1) { $acceptsAgent = $true; $agentWhy = 'a schema version 1 template accepts a request signed by any enrollment agent' }
    elseif ([int]$Template.RaSignature -ge 1 -and $raApp -contains $script:MspkiAgentEku) {
        $acceptsAgent = $true; $agentWhy = ('msPKI-RA-Signature = {0} with the Certificate Request Agent application policy' -f [int]$Template.RaSignature)
    }
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
        SchemaVersion     = $schema
        AcceptsAgentSig   = $acceptsAgent
        AgentSigWhy       = $agentWhy
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
        if ($_.Denied) { $t += (' - a Deny ACE for {0} may cancel this grant, effective access not computed' -f (@($_.DeniedBy) -join ', ')) }
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
        [void]$found.Add([pscustomobject]@{ Rule = 'ESC1'; Principals = $f.BroadEnroll; Severity = 'High'
            Title = 'the enrollee supplies the subject of a certificate that can be used to sign in, and a broad group can enroll without approval'
            Conditions = @((& $enrollText), ('The enrollee supplies the {0}' -f ($f.Supplies -join ' and the ')),
                ('EKU allows client authentication: {0}' -f $f.EkuText), $noApprovalText, $noSigText)
            Notes = 'Review who needs to enroll, whether the subject must be supplied by the requester, and whether manager approval or authorised signatures fit this template.' })
    }
    # Pattern ESC2: any-purpose or no EKU, broad enroll, no approval or signatures.
    if ($f.BroadEnroll.Count -gt 0 -and ($f.AnyPurpose -or $f.NoEku) -and -not $f.ManagerApproval -and $f.RaSignatures -eq 0) {
        [void]$found.Add([pscustomobject]@{ Rule = 'ESC2'; Principals = $f.BroadEnroll; Severity = 'High'
            Title = 'the certificate is valid for any purpose (Any Purpose or no EKU) and a broad group can enroll without approval'
            Conditions = @((& $enrollText), ('EKU is Any Purpose or absent: {0}' -f $f.EkuText), $noApprovalText, $noSigText)
            Notes = 'A certificate valid for any purpose can also act as a certificate request agent or a subordinate CA certificate, depending on its other settings.' })
    }
    # Pattern ESC3 (audit 2 H2: every condition on both templates).
    # Agent template: a broad group can enroll, Certificate Request Agent EKU, no manager approval, no authorised signatures.
    # Target template (another published one): accepts an enrollment agent's signature (schema version 1, or version 2+ with the
    # Certificate Request Agent signature policy), allows client authentication, no manager approval, and the agent's principals
    # may enroll for it (the same broad group, or Everyone / Authenticated Users, which contain every broad group).
    if ($f.BroadEnroll.Count -gt 0 -and $f.AgentEku -and -not $f.ManagerApproval -and $f.RaSignatures -eq 0) {
        $agentSids = @($f.BroadEnroll | Where-Object { -not $_.Denied } | ForEach-Object { $_.Sid })
        $others = New-Object System.Collections.ArrayList
        foreach ($k in ($AllFacts.Keys | Sort-Object)) {
            if ($k -eq $Template.Name.ToLowerInvariant()) { continue }
            if (-not $Published.ContainsKey($k)) { continue }
            $o = $AllFacts[$k]
            if (-not ($o.Facts.AcceptsAgentSig -and $o.Facts.ClientAuthCapable -and -not $o.Facts.ManagerApproval)) { continue }
            $shared = @($o.Facts.BroadEnroll | Where-Object { -not $_.Denied -and ($agentSids -contains $_.Sid -or $_.Sid -eq 'S-1-1-0' -or $_.Sid -eq 'S-1-5-11') })
            if ($shared.Count -eq 0) { continue }
            [void]$others.Add([pscustomobject]@{ Entry = $o; Shared = $shared })
        }
        if ($others.Count -gt 0) {
            $oc = @(('{0} published template(s) accept this agent''s signature on behalf of another user and allow client authentication' -f $others.Count))
            $oc += @($others | ForEach-Object {
                'Another published template accepts enrollment-agent signatures and allows client authentication: {0} (schema version {1}: {2}; manager approval: not required; the agent''s principals may enroll through: {3})' -f `
                    $_.Entry.Template.Name, $_.Entry.Facts.SchemaVersion, $_.Entry.Facts.AgentSigWhy, ((@($_.Shared) | ForEach-Object { '{0} [{1}]' -f $_.Principal, $_.Label }) -join ', ') })
            [void]$found.Add([pscustomobject]@{ Rule = 'ESC3'; Principals = $f.BroadEnroll; Severity = 'High'
                Title = 'a broad group can enroll for a Certificate Request Agent certificate without approval, and another published template accepts that agent''s signature'
                Conditions = @((& $enrollText), ('EKU includes Certificate Request Agent: {0}' -f $f.EkuText), $noApprovalText,
                    ('No authorised signatures required on the agent template (msPKI-RA-Signature = {0})' -f $f.RaSignatures)) + $oc
                Notes = 'Enrollment agent restrictions configured on the CA cannot be read from here and may limit this.' })
        }
    }
    # Pattern ESC4: a broad group has write, owner or full-control rights on the template object.
    if ($f.BroadWrite.Count -gt 0) {
        [void]$found.Add([pscustomobject]@{ Rule = 'ESC4'; Principals = $f.BroadWrite; Severity = 'High'
            Title = 'a broad group has write, owner or full-control rights on the template object'
            Conditions = @(('Broad group with write-type rights on the template: {0}' -f (Get-MspkiPrincipalText $f.BroadWrite)))
            Notes = 'Anyone who can change the template can change who may enroll and what the certificate is valid for.' })
    }
    # Pattern ESC9: no security extension, usable to sign in, broad enroll. Review only: strong certificate binding on the
    # domain controllers cannot be confirmed from here.
    if ($f.NoSecurityExt -and $f.ClientAuthCapable -and $f.BroadEnroll.Count -gt 0) {
        [void]$found.Add([pscustomobject]@{ Rule = 'ESC9'; Principals = $f.BroadEnroll; Severity = 'ReviewRequired'
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
            [void]$found.Add([pscustomobject]@{ Rule = 'ESC13'; Principals = $f.BroadEnroll; Severity = 'Medium'
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
    # Two different reasons, two different codes: the descriptor was not returned (the account lacks the right to read it) is a
    # permission matter; a descriptor that came back but could not be parsed is a limit of this tool.
    $noAclPerm = @($noAcl | Where-Object { $_.AclErrorClass -eq 'NotReturned' })
    $noAclParse = @($noAcl | Where-Object { $_.AclErrorClass -ne 'NotReturned' })
    if ($noAclPerm.Count -gt 0) {
        [void]$findings.Add((New-MspkiFinding @common -Target 'Certificate Templates' -Status 'Skipped' -StatusCode 'PERMISSION_DENIED' -Confidence 'Confirmed' `
            -Sources 'AD:CertificateTemplates' -Layers @{ DiscoveryStatus = 'PermissionDenied' } `
            -Message ('The permissions of {0} template(s) were not returned by the directory, so the enrollment and write patterns could not be evaluated for them.' -f $noAclPerm.Count) `
            -Evidence @($noAclPerm | ForEach-Object { 'Template {0}: {1}' -f $_.Name, $_.AclError }) `
            -Notes 'The account running the tool may lack the right to read the security descriptor of these template objects.'))
    }
    if ($noAclParse.Count -gt 0) {
        [void]$findings.Add((New-MspkiFinding @common -Target 'Certificate Templates' -Status 'Warning' -StatusCode 'INTERNAL_ERROR' -Confidence 'Confirmed' `
            -Sources 'AD:CertificateTemplates' -Layers @{ DiscoveryStatus = 'Warning' } `
            -Message ('The permissions of {0} template(s) could not be read by this tool, so the enrollment and write patterns could not be evaluated for them.' -f $noAclParse.Count) `
            -Evidence @($noAclParse | ForEach-Object { 'Template {0}: {1}' -f $_.Name, $_.AclError }) `
            -Notes 'The security descriptor was returned but could not be decoded. This is a limit or a fault of this tool, not a finding about the template.'))
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
            # Every pattern rests on who may enroll or write (audit 2 M11). This review reads the ACEs but does not compute effective
            # access, so a match is Referenced, never Confirmed; it could be Confirmed only once effective access is computed.
            $effectiveAccessComputed = $false
            $conf = 'Referenced'
            if ($effectiveAccessComputed -and $isPub -and $viaCa) { $conf = 'Confirmed' }
            $ev += 'Confidence Referenced, not Confirmed: the conditions were read from AD, but effective permissions are not computed (group nesting, Deny ACEs on groups that contain the principal, the order of the ACEs, the CA''s own Request Certificates permission and its enrollment agent restrictions are not evaluated).'
            # A Deny ACE for the same principal, or for a well-known group that contains it, may cancel the grant that matched: such
            # a match is a review item that is only inferred.
            $denied = @(@($h.Principals) | Where-Object { $_ -and $_.Denied })
            if ($denied.Count -gt 0) {
                $sev = 'ReviewRequired'; $status = $script:MspkiSeverityStatus[$sev]; $conf = 'Inferred'
                $ev += ('A Deny ACE for {0} may cancel the grant to {1}. Effective access (the order and combination of the ACEs, group nesting) is not computed, so this match may not apply and is only a review item.' -f `
                    ((@($denied | ForEach-Object { @($_.DeniedBy) }) | Select-Object -Unique) -join ', '), (($denied | ForEach-Object { $_.Principal }) -join ', '))
            }
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
