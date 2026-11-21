# Template review: every pattern has a template where it fires and templates where it must not. Fixtures are
# synthetic example.test data; ACLs are given as parsed ACE records (the parser itself is tested in Templates.Tests.ps1).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:enrollGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:du = 'S-1-5-21-1111-2222-3333-513'
    $script:dc = 'S-1-5-21-1111-2222-3333-515'
    $script:da = 'S-1-5-21-1111-2222-3333-512'
    $script:clientAuth = '1.3.6.1.5.5.7.3.2'
    $script:serverAuth = '1.3.6.1.5.5.7.3.1'
    $script:agentEku = '1.3.6.1.4.1.311.20.2.1'
    $script:anyPurpose = '2.5.29.37.0'
    $script:policyOid = '1.3.6.1.4.1.311.21.8.100.50'

    $script:ace = { param($sid, $mask, $objType = '', $type = 'Allow', $inheritOnly = $false)
        @{ Sid = $sid; Principal = ('CORP\' + $sid); Type = $type; Mask = [int64]$mask; ObjectType = $objType; InheritOnly = $inheritOnly; Inherited = $false; Rights = @('x') } }
    $script:enrollAce = { param($sid = $script:du) & $script:ace $sid 0x100 $script:enrollGuid }
    $script:adminAce = { & $script:ace $script:da 0x10000000 }

    # A template that matches no pattern: server authentication only, enrolled by Domain Users, administrators control it.
    $script:tpl = {
        param([string]$Name = 'SafeTemplate', [hashtable]$o = @{})
        $t = [ordered]@{
            Name = $Name; DisplayName = $Name; DistinguishedName = ('CN={0},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test' -f $Name)
            Oid = '1.3.6.1.4.1.311.21.8.100.1'; SchemaVersion = 2; NameFlag = [int64]0; EnrollmentFlag = [int64]0; RaSignature = 0
            Eku = @($script:serverAuth); ApplicationPolicies = @(); RaApplicationPolicies = @(); RaPolicies = @(); IssuancePolicies = @()
            OwnerSid = $script:da; Owner = 'CORP\Domain Admins'; Acl = @((& $script:adminAce), (& $script:enrollAce)); AclError = ''
        }
        foreach ($k in $o.Keys) { $t[$k] = $o[$k] }
        [pscustomobject]$t
    }
    # Inventory: every template is published by one CA unless -Published names a subset.
    $script:inv = {
        param([object[]]$Templates, $Published = $null, [object[]]$Oids = @())
        $names = $Published
        if ($null -eq $names) { $names = @($Templates | ForEach-Object { $_.Name }) }
        [pscustomobject]@{ TemplatesRead = $true; Templates = @($Templates); OidObjects = @($Oids)
            EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @($names); Properties = $null }) }
    }
    $script:run = { param($i) InModuleScope MspkiHealthCheck -Parameters @{ I = $i } { param($I) Test-MspkiTemplateEnrollmentRisk -Inventory $I } }
    $script:hits = { param($f, $rule) @($f | Where-Object { $_.StatusCode -eq 'CONFIG_RISK' -and $_.Message -like ('*pattern {0}:*' -f $rule) }) }
    $script:agentB = { param([hashtable]$o = @{}) $h = @{ Eku = @($script:clientAuth); RaSignature = 1; RaApplicationPolicies = @($script:agentEku) }
        foreach ($k in $o.Keys) { $h[$k] = $o[$k] }; & $script:tpl 'AgentSigned' $h }
    $script:agentA = { param([hashtable]$o = @{}) $h = @{ Eku = @($script:agentEku) }
        foreach ($k in $o.Keys) { $h[$k] = $o[$k] }; & $script:tpl 'AgentEnroll' $h }
}

Describe 'Template review: baseline' {
    It 'matches no pattern for a template with a server-authentication EKU enrolled by Domain Users' {
        $f = & $script:run (& $script:inv @((& $script:tpl)))
        @($f | Where-Object { $_.StatusCode -eq 'CONFIG_RISK' }).Count | Should -Be 0
        $s = @($f | Where-Object { $_.Message -like 'Reviewed *' })
        $s.Count | Should -Be 1
        $s[0].Status | Should -Be 'Pass'
        $s[0].StatusCode | Should -Be 'OK'
        ($s[0].Evidence -join "`n") | Should -Match 'SafeTemplate: no review pattern matched'
    }
}

Describe 'Pattern ESC1: enrollee supplies the subject' {
    It 'fires when every condition is met and lists each one' {
        $f = & $script:run (& $script:inv @((& $script:tpl 'SubjectTemplate' @{ NameFlag = [int64]1; Eku = @($script:clientAuth) })))
        $h = @(& $script:hits $f 'ESC1')
        $h.Count | Should -Be 1
        $h[0].Severity | Should -Be 'High'
        $h[0].Status | Should -Be 'Fail'
        $h[0].Category | Should -Be 'Template'
        $h[0].RelatedCA | Should -Be 'Example Issuing CA'
        $ev = $h[0].Evidence -join "`n"
        $ev | Should -Match 'Condition met: Broad group can enroll: .*Domain Users'
        $ev | Should -Match 'Condition met: The enrollee supplies the subject'
        $ev | Should -Match 'Condition met: EKU allows client authentication: Client Authentication'
        $ev | Should -Match 'Condition met: No manager approval'
        $ev | Should -Match 'Condition met: No authorised signatures required'
        $ev | Should -Match 'Published on: Example Issuing CA'
    }

    It 'fires for a supplied subject alternative name, a template without EKU and Smart Card Logon' {
        foreach ($case in @(@{ NameFlag = [int64]0x10000; Eku = @($script:clientAuth) }, @{ NameFlag = [int64]1; Eku = @() }, @{ NameFlag = [int64]1; Eku = @('1.3.6.1.4.1.311.20.2.2') })) {
            $f = & $script:run (& $script:inv @((& $script:tpl 'T' $case)))
            @(& $script:hits $f 'ESC1').Count | Should -Be 1
        }
    }

    It 'uses application policies instead of the EKU attribute when the template has them' {
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:serverAuth); ApplicationPolicies = @($script:clientAuth) })))
        @(& $script:hits $f 'ESC1').Count | Should -Be 1
    }

    It 'must not fire when <Why>' -ForEach @(
        @{ Why = 'no broad group can enroll'; O = @{ NameFlag = [int64]1; Eku = @('1.3.6.1.5.5.7.3.2'); Acl = @() } }
        @{ Why = 'the subject is not supplied by the enrollee'; O = @{ NameFlag = [int64]0; Eku = @('1.3.6.1.5.5.7.3.2') } }
        @{ Why = 'the EKU cannot be used to sign in'; O = @{ NameFlag = [int64]1; Eku = @('1.3.6.1.5.5.7.3.1') } }
        @{ Why = 'manager approval is required'; O = @{ NameFlag = [int64]1; Eku = @('1.3.6.1.5.5.7.3.2'); EnrollmentFlag = [int64]2 } }
        @{ Why = 'authorised signatures are required'; O = @{ NameFlag = [int64]1; Eku = @('1.3.6.1.5.5.7.3.2'); RaSignature = 1 } }
        @{ Why = 'only the Enroll right of a non-broad group exists'; O = @{ NameFlag = [int64]1; Eku = @('1.3.6.1.5.5.7.3.2'); Acl = @() } }
    ) {
        $o = $O
        if ($Why -like 'only the Enroll*') { $o.Acl = @((& $script:enrollAce $script:da)) }
        elseif ($Why -like 'no broad*') { $o.Acl = @((& $script:adminAce)) }
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' $o)))
        @(& $script:hits $f 'ESC1').Count | Should -Be 0
    }

    It 'must not fire when the only enroll ACE is a Deny ACE or inherit-only' {
        foreach ($acl in @(@((& $script:ace $script:du 0x100 $script:enrollGuid 'Deny')), @((& $script:ace $script:du 0x100 $script:enrollGuid 'Allow' $true)))) {
            $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = $acl })))
            @(& $script:hits $f 'ESC1').Count | Should -Be 0
        }
    }

    It 'must not fire when the extended right on the ACE is not Enroll' {
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = @((& $script:ace $script:du 0x100 'a05b8cc2-17bc-4802-a710-e7c15ab866a2')) })))
        @(& $script:hits $f 'ESC1').Count | Should -Be 0
    }

    It 'treats Everyone, Authenticated Users and Domain Computers as broad, and other groups as not broad' {
        foreach ($sid in @('S-1-1-0', 'S-1-5-11', $script:dc)) {
            $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = @((& $script:enrollAce $sid)) })))
            @(& $script:hits $f 'ESC1').Count | Should -Be 1 -Because $sid
        }
        foreach ($sid in @('S-1-5-21-1111-2222-3333-1105', 'S-1-5-21-1111-2222-3333-519')) {
            $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = @((& $script:enrollAce $sid)) })))
            @(& $script:hits $f 'ESC1').Count | Should -Be 0 -Because $sid
        }
    }

    It 'notes a Deny ACE for the same principal in the evidence' {
        $acl = @((& $script:enrollAce), (& $script:ace $script:du 0x100 $script:enrollGuid 'Deny'))
        # The Deny ACE leaves the Allow ACE in place, so the pattern still fires but says effective access is not computed.
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = $acl })))
        $h = @(& $script:hits $f 'ESC1')
        $h.Count | Should -Be 1
        ($h[0].Evidence -join "`n") | Should -Match 'Deny ACE exists for the same principal'
    }

    It 'turns the match into a review item that is only Inferred when a Deny ACE exists for the same principal (effective access is not computed)' {
        $plain = & $script:run (& $script:inv @((& $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = @((& $script:enrollAce)) })))
        $c = @(& $script:hits $plain 'ESC1')[0]
        $c.Severity | Should -Be 'High'
        $c.Status | Should -Be 'Fail'
        $c.Confidence | Should -Not -Be 'Inferred'
        $acl = @((& $script:enrollAce), (& $script:ace $script:du 0x100 $script:enrollGuid 'Deny'))
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = $acl })))
        $h = @(& $script:hits $f 'ESC1')
        $h.Count | Should -Be 1
        $h[0].Severity | Should -Be 'ReviewRequired'
        $h[0].Status | Should -Be 'Warning'
        $h[0].Confidence | Should -Be 'Inferred'
        ($h[0].Evidence -join "`n") | Should -Match 'may not apply and is only a review item'
    }
}

Describe 'Pattern ESC2: any purpose or no EKU' {
    It 'fires for Any Purpose and for a template without EKU, and lists the conditions' {
        foreach ($eku in @(@($script:anyPurpose), @())) {
            $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ Eku = $eku })))
            $h = @(& $script:hits $f 'ESC2')
            $h.Count | Should -Be 1
            $h[0].Severity | Should -Be 'High'
            ($h[0].Evidence -join "`n") | Should -Match 'Condition met: EKU is Any Purpose or absent'
            ($h[0].Evidence -join "`n") | Should -Match 'Condition met: No manager approval'
        }
    }

    It 'must not fire when <Why>' -ForEach @(
        @{ Why = 'the EKU is client authentication only'; O = @{ Eku = @('1.3.6.1.5.5.7.3.2') } }
        @{ Why = 'manager approval is required'; O = @{ Eku = @('2.5.29.37.0'); EnrollmentFlag = [int64]2 } }
        @{ Why = 'authorised signatures are required'; O = @{ Eku = @('2.5.29.37.0'); RaSignature = 2 } }
        @{ Why = 'no broad group can enroll'; O = @{ Eku = @('2.5.29.37.0'); Acl = @() } }
    ) {
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' $O)))
        @(& $script:hits $f 'ESC2').Count | Should -Be 0
    }
}

Describe 'Pattern ESC3: Certificate Request Agent' {
    It 'fires when a published template accepts agent signatures and allows client authentication' {
        $f = & $script:run (& $script:inv @((& $script:agentA), (& $script:agentB)))
        $h = @(& $script:hits $f 'ESC3')
        $h.Count | Should -Be 1
        $h[0].Target | Should -Be 'AgentEnroll'
        $h[0].Severity | Should -Be 'High'
        $ev = $h[0].Evidence -join "`n"
        $ev | Should -Match 'Condition met: EKU includes Certificate Request Agent'
        $ev | Should -Match 'Condition met: Another published template accepts enrollment-agent signatures .*: AgentSigned'
        $ev | Should -Match 'Condition met: No manager approval'
        $ev | Should -Match 'Condition met: Broad group can enroll'
    }

    It 'must not fire when <Why>' -ForEach @(
        @{ Why = 'the other template is not published'; Setup = 'unpublished' }
        @{ Why = 'the other template does not allow client authentication'; Setup = 'nologon' }
        @{ Why = 'the other template needs no agent signature'; Setup = 'nosig' }
        @{ Why = 'the other template''s signature policy is not Certificate Request Agent'; Setup = 'otherpolicy' }
        @{ Why = 'the agent template requires manager approval'; Setup = 'approval' }
        @{ Why = 'no broad group can enroll for the agent template'; Setup = 'noenroll' }
        @{ Why = 'there is no other template'; Setup = 'alone' }
    ) {
        $a = & $script:agentA; $b = & $script:agentB; $pub = $null; $tpls = @($a, $b)
        switch ($Setup) {
            'unpublished' { $pub = @('AgentEnroll') }
            'nologon' { $b = & $script:agentB @{ Eku = @($script:serverAuth) }; $tpls = @($a, $b) }
            'nosig' { $b = & $script:agentB @{ RaSignature = 0 }; $tpls = @($a, $b) }
            'otherpolicy' { $b = & $script:agentB @{ RaApplicationPolicies = @('1.3.6.1.5.5.7.3.3') }; $tpls = @($a, $b) }
            'approval' { $a = & $script:agentA @{ EnrollmentFlag = [int64]2 }; $tpls = @($a, $b) }
            'noenroll' { $a = & $script:agentA @{ Acl = @((& $script:adminAce)) }; $tpls = @($a, $b) }
            'alone' { $tpls = @($a) }
        }
        $f = & $script:run (& $script:inv $tpls $pub)
        @(& $script:hits $f 'ESC3').Count | Should -Be 0
    }
}

Describe 'Pattern ESC4: broad group controls the template object' {
    It 'fires for write, write-DACL, write-owner, generic-all and an owner that is a broad group' {
        foreach ($case in @(
            @{ Acl = @((& $script:ace $script:du 0x20)); What = 'WriteProperty' }
            @{ Acl = @((& $script:ace $script:du 0x20 'bf967a0a-0de6-11d0-a285-00aa003049e2')); What = 'WriteProperty on one property of the template' }
            @{ Acl = @((& $script:ace $script:du 0x40130 $script:enrollGuid)); What = 'WriteDacl in the same ACE as the Enroll right' }
            @{ Acl = @((& $script:ace $script:du 0x40000)); What = 'WriteDacl' }
            @{ Acl = @((& $script:ace 'S-1-5-11' 0x80000)); What = 'WriteOwner' }
            @{ Acl = @((& $script:ace $script:dc 0x10000000)); What = 'GenericAll' }
            @{ Acl = @((& $script:ace $script:du 0xF01FF)); What = 'FullControl' }
            @{ Acl = @((& $script:adminAce)); What = 'Owner'; Owner = 'S-1-1-0' })) {
            $o = @{ Acl = $case.Acl }
            if ($case.Owner) { $o.OwnerSid = $case.Owner }
            $f = & $script:run (& $script:inv @((& $script:tpl 'T' $o)))
            $h = @(& $script:hits $f 'ESC4')
            $h.Count | Should -Be 1 -Because $case.What
            $h[0].Severity | Should -Be 'High'
            ($h[0].Evidence -join "`n") | Should -Match 'Condition met: Broad group with write-type rights'
        }
    }

    It 'must not fire for <Why>' -ForEach @(
        @{ Why = 'a non-broad group with full control'; Acl = @(@{ Sid = 'S-1-5-21-1111-2222-3333-519'; Type = 'Allow'; Mask = 0x10000000; ObjectType = ''; InheritOnly = $false }) }
        @{ Why = 'a broad group with read rights only'; Acl = @(@{ Sid = 'S-1-5-11'; Type = 'Allow'; Mask = 0x20094; ObjectType = ''; InheritOnly = $false }) }
        @{ Why = 'a broad group that can only enroll'; Acl = @(@{ Sid = 'S-1-5-21-1111-2222-3333-513'; Type = 'Allow'; Mask = 0x100; ObjectType = '0e10c968-78fb-11d2-90d4-00c04f79dc55'; InheritOnly = $false }) }
        @{ Why = 'a broad group with the Enroll ACE the template console writes (mask 0x130, extended-right GUID)'; Acl = @(@{ Sid = 'S-1-5-21-1111-2222-3333-513'; Type = 'Allow'; Mask = 0x130; ObjectType = '0e10c968-78fb-11d2-90d4-00c04f79dc55'; InheritOnly = $false }) }
        @{ Why = 'a broad group with the Autoenroll ACE the template console writes (mask 0x130, extended-right GUID)'; Acl = @(@{ Sid = 'S-1-5-21-1111-2222-3333-515'; Type = 'Allow'; Mask = 0x130; ObjectType = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'; InheritOnly = $false }) }
        @{ Why = 'a Deny ACE'; Acl = @(@{ Sid = 'S-1-1-0'; Type = 'Deny'; Mask = 0x10000000; ObjectType = ''; InheritOnly = $false }) }
        @{ Why = 'an inherit-only ACE'; Acl = @(@{ Sid = 'S-1-1-0'; Type = 'Allow'; Mask = 0x10000000; ObjectType = ''; InheritOnly = $true }) }
    ) {
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ Acl = $Acl })))
        @(& $script:hits $f 'ESC4').Count | Should -Be 0
    }
}

Describe 'Pattern ESC9: no security extension (review required)' {
    It 'fires as ReviewRequired when the flag, a sign-in EKU and a broad enroll are present' {
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ EnrollmentFlag = [int64]0x80000; Eku = @($script:clientAuth) })))
        $h = @(& $script:hits $f 'ESC9')
        $h.Count | Should -Be 1
        $h[0].Severity | Should -Be 'ReviewRequired'
        $h[0].Status | Should -Be 'Warning'
        ($h[0].Evidence -join "`n") | Should -Match 'CT_FLAG_NO_SECURITY_EXTENSION'
        $h[0].Notes | Should -Match 'domain controllers'
    }

    It 'must not fire when <Why>' -ForEach @(
        @{ Why = 'the flag is not set'; O = @{ EnrollmentFlag = [int64]0; Eku = @('1.3.6.1.5.5.7.3.2') } }
        @{ Why = 'the EKU cannot be used to sign in'; O = @{ EnrollmentFlag = [int64]0x80000; Eku = @('1.3.6.1.5.5.7.3.1') } }
        @{ Why = 'no broad group can enroll'; O = @{ EnrollmentFlag = [int64]0x80000; Eku = @('1.3.6.1.5.5.7.3.2'); Acl = @() } }
    ) {
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' $O)))
        @(& $script:hits $f 'ESC9').Count | Should -Be 0
    }
}

Describe 'Pattern ESC13: issuance policy linked to a group' {
    BeforeAll {
        $script:oidObj = { param([hashtable]$o = @{}) $h = @{ Name = '1.50'; DisplayName = 'Example Policy'; DistinguishedName = 'CN=1.50,CN=OID'; Oid = $script:policyOid; Flags = 2
            GroupLink = 'CN=Example Group,CN=Users,DC=corp,DC=example,DC=test'; GroupName = 'Example Group'; GroupResolved = $true; GroupError = '' }
            foreach ($k in $o.Keys) { $h[$k] = $o[$k] }; [pscustomobject]$h }
    }

    It 'fires when a template carries a linked issuance policy and a broad group can enroll' {
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' @{ IssuancePolicies = @($script:policyOid) })) $null @((& $script:oidObj)))
        $h = @(& $script:hits $f 'ESC13')
        $h.Count | Should -Be 1
        $h[0].Severity | Should -Be 'Medium'
        $h[0].Status | Should -Be 'Warning'
        $ev = $h[0].Evidence -join "`n"
        $ev | Should -Match 'Condition met: Issuance policy 1\.3\.6\.1\.4\.1\.311\.21\.8\.100\.50 .* is linked by msDS-OIDToGroupLink to CN=Example Group'
        $ev | Should -Match 'Condition met: Broad group can enroll'
        $h[0].Sources | Should -Contain 'AD:OID:msDS-OIDToGroupLink'
    }

    It 'must not fire when <Why>' -ForEach @(
        @{ Why = 'the policy has no group link'; Oid = @{ GroupLink = '' }; Tpl = @{ IssuancePolicies = @('1.3.6.1.4.1.311.21.8.100.50') } }
        @{ Why = 'the linked group does not resolve'; Oid = @{ GroupResolved = $false }; Tpl = @{ IssuancePolicies = @('1.3.6.1.4.1.311.21.8.100.50') } }
        @{ Why = 'the template carries a different policy'; Oid = @{}; Tpl = @{ IssuancePolicies = @('1.3.6.1.4.1.311.21.8.100.51') } }
        @{ Why = 'the template carries no policy'; Oid = @{}; Tpl = @{} }
        @{ Why = 'no broad group can enroll'; Oid = @{}; Tpl = @{ IssuancePolicies = @('1.3.6.1.4.1.311.21.8.100.50'); Acl = @() } }
    ) {
        $f = & $script:run (& $script:inv @((& $script:tpl 'T' $Tpl)) $null @((& $script:oidObj $Oid)))
        @(& $script:hits $f 'ESC13').Count | Should -Be 0
    }
}

Describe 'Unpublished templates and reading problems' {
    It 'reports an unpublished template one step lower and marks it Unpublished' {
        $t = & $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth) }
        $pub = & $script:run (& $script:inv @($t))
        $unp = & $script:run (& $script:inv @($t) @('SomethingElse'))
        $p = (& $script:hits $pub 'ESC1')[0]
        $u = (& $script:hits $unp 'ESC1')[0]
        $p.Severity | Should -Be 'High'
        $u.Severity | Should -Be 'Medium'
        $u.Status | Should -Be 'Warning'
        $u.Message | Should -Match '^\[Unpublished\]'
        ($u.Evidence -join "`n") | Should -Match 'Unpublished: no Enterprise CA publishes this template'
        $u.Confidence | Should -Be 'Referenced'
        $u.RelatedCA | Should -Be ''
    }

    It 'steps ESC13 down to Low and keeps ESC9 at ReviewRequired when unpublished' {
        $oid = [pscustomobject]@{ Name = '1.50'; DisplayName = 'P'; DistinguishedName = 'CN=1.50'; Oid = $script:policyOid; Flags = 2; GroupLink = 'CN=G'; GroupName = 'G'; GroupResolved = $true; GroupError = '' }
        $t13 = & $script:tpl 'T13' @{ IssuancePolicies = @($script:policyOid) }
        $t9 = & $script:tpl 'T9' @{ EnrollmentFlag = [int64]0x80000; Eku = @($script:clientAuth) }
        $f = & $script:run (& $script:inv @($t13, $t9) @('Other') @($oid))
        (& $script:hits $f 'ESC13')[0].Severity | Should -Be 'Low'
        (& $script:hits $f 'ESC13')[0].Status | Should -Be 'Information'
        (& $script:hits $f 'ESC9')[0].Severity | Should -Be 'ReviewRequired'
    }

    It 'is Confirmed only when the CA''s own template list also names the template' {
        $t = & $script:tpl 'T' @{ NameFlag = [int64]1; Eku = @($script:clientAuth) }
        $props = [pscustomobject]@{ Templates = @([pscustomobject]@{ Name = 'T'; Oid = '1.2' }) }
        $i = & $script:inv @($t)
        $i.EnterpriseCAs[0].Properties = $props
        $h = (& $script:hits (& $script:run $i) 'ESC1')[0]
        $h.Confidence | Should -Be 'Confirmed'
        $h.Sources | Should -Contain 'CA:GetCAProperty'
    }

    It 'skips the review when the template objects could not be read, without claiming that nothing was found' {
        $f = & $script:run ([pscustomobject]@{ TemplatesRead = $false; Templates = @(); OidObjects = @(); EnterpriseCAs = @() })
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Skipped'
        $f[0].Message | Should -Match 'not done'
        @($f | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
    }

    It 'reports templates whose permissions were not returned as PERMISSION_DENIED (skipped), not as clean and not as a retrieval failure' {
        $f = & $script:run (& $script:inv @((& $script:tpl 'NoAcl' @{ Acl = @(); AclError = 'The security descriptor was not returned.'; AclErrorClass = 'NotReturned' })))
        $p = @($f | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' })
        $p.Count | Should -Be 1
        $p[0].Status | Should -Be 'Skipped'
        ($p[0].Evidence -join "`n") | Should -Match 'NoAcl'
        @($f | Where-Object { $_.Status -eq 'Pass' -and $_.Message -like '*No review*' }).Count | Should -Be 0
    }

    It 'reports a security descriptor that could not be decoded as a limit of the tool (INTERNAL_ERROR), apart from a permission problem' {
        $f = & $script:run (& $script:inv @((& $script:tpl 'BadAcl' @{ Acl = @(); AclError = 'Unexpected ACL revision.'; AclErrorClass = 'ParseError' })))
        $w = @($f | Where-Object { $_.Status -eq 'Warning' })
        $w.Count | Should -Be 1
        $w[0].StatusCode | Should -Be 'INTERNAL_ERROR'
        ($w[0].Evidence -join "`n") | Should -Match 'BadAcl'
        @($f | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' }).Count | Should -Be 0
    }

    It 'handles a missing inventory' {
        @(& $script:run $null | Where-Object { $_ }).Count | Should -Be 0
    }
}

Describe 'Template review: every finding is evidence-based and review-only' {
    It 'gives every CONFIG_RISK finding sources, a Condition met line per condition and no automatic change' {
        $oid = [pscustomobject]@{ Name = '1.50'; DisplayName = 'P'; DistinguishedName = 'CN=1.50'; Oid = $script:policyOid; Flags = 2; GroupLink = 'CN=G'; GroupName = 'G'; GroupResolved = $true; GroupError = '' }
        $tpls = @(
            (& $script:tpl 'A1' @{ NameFlag = [int64]1; Eku = @($script:clientAuth) }),
            (& $script:tpl 'A2' @{ Eku = @() }),
            (& $script:tpl 'A4' @{ Acl = @((& $script:ace $script:du 0x20)) }),
            (& $script:tpl 'A9' @{ EnrollmentFlag = [int64]0x80000; Eku = @($script:clientAuth) }),
            (& $script:tpl 'A13' @{ IssuancePolicies = @($script:policyOid) }),
            (& $script:agentA), (& $script:agentB))
        $f = & $script:run (& $script:inv $tpls $null @($oid))
        $risk = @($f | Where-Object { $_.StatusCode -eq 'CONFIG_RISK' })
        $risk.Count | Should -BeGreaterOrEqual 6
        foreach ($x in $risk) {
            @($x.Sources).Count | Should -BeGreaterThan 1
            @($x.Evidence | Where-Object { $_ -like 'Condition met:*' }).Count | Should -BeGreaterOrEqual 1
            $x.Remediation | Should -Match 'no change is made'
            $x.Severity | Should -BeIn @('High', 'Medium', 'Low', 'ReviewRequired')
            $x.Message | Should -Not -Match '(?i)vulnerable|exploit'
        }
    }
}
