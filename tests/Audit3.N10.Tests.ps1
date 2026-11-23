# Fix log 3, N10 (docs/AUDIT-3-VERIFY.md): a Deny ACE counts only when it removes the right that the pattern rests on. An unrelated Deny
# (for example Deny Everyone Delete, which "protect object from accidental deletion" writes) must not hide or downgrade a match, and a
# rule that is suppressed by a real Deny is named in the summary with the reason, never "no review pattern matched".
# Synthetic example.test data. Scenario numbers S11-S16 are the ones of docs/AUDIT-3-VERIFY.md part 3.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:enrollGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:autoEnrollGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
    $script:du = 'S-1-5-21-1111-2222-3333-513'
    $script:dc = 'S-1-5-21-1111-2222-3333-515'
    $script:da = 'S-1-5-21-1111-2222-3333-512'
    $script:au = 'S-1-5-11'; $script:everyone = 'S-1-1-0'
    $script:clientAuth = '1.3.6.1.5.5.7.3.2'; $script:serverAuth = '1.3.6.1.5.5.7.3.1'
    $script:agentEku = '1.3.6.1.4.1.311.20.2.1'
    $script:efs = '1.3.6.1.4.1.311.10.3.4'; $script:email = '1.3.6.1.5.5.7.3.4'
    $script:ace = { param($sid, $mask, $objType = '', $type = 'Allow')
        @{ Sid = $sid; Principal = ('CORP\' + $sid); Type = $type; Mask = [int64]$mask; ObjectType = $objType; InheritOnly = $false; Inherited = $false; Rights = @('x') } }
    $script:enrollAce = { param($sid = $script:du) & $script:ace $sid 0x100 $script:enrollGuid }
    $script:adminAce = { & $script:ace $script:da 0x10000000 }
    $script:denyDelete = { param($sid = $script:everyone) & $script:ace $sid 0x10000 '' 'Deny' }
    $script:denyEnroll = { param($sid) & $script:ace $sid 0x100 $script:enrollGuid 'Deny' }
    $script:denyAutoEnroll = { param($sid) & $script:ace $sid 0x100 $script:autoEnrollGuid 'Deny' }

    $script:tpl = {
        param([string]$Name, [hashtable]$o = @{})
        $t = [ordered]@{
            Name = $Name; DisplayName = $Name; DistinguishedName = ('CN={0},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test' -f $Name)
            Oid = '1.3.6.1.4.1.311.21.8.100.1'; SchemaVersion = 2; NameFlag = [int64]0; EnrollmentFlag = [int64]0; RaSignature = 0
            Eku = @($script:serverAuth); ApplicationPolicies = @(); RaApplicationPolicies = @(); RaPolicies = @(); IssuancePolicies = @()
            OwnerSid = $script:da; Owner = 'CORP\Domain Admins'; Acl = @((& $script:adminAce), (& $script:enrollAce)); AclError = ''
        }
        foreach ($k in $o.Keys) { $t[$k] = $o[$k] }
        [pscustomobject]$t
    }
    $script:inv = { param([object[]]$Templates)
        [pscustomobject]@{ TemplatesRead = $true; Templates = @($Templates); OidObjects = @()
            EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @($Templates | ForEach-Object { $_.Name }); Properties = $null }) } }
    $script:run = { param($i) InModuleScope MspkiHealthCheck -Parameters @{ I = $i } { param($I) Test-MspkiTemplateEnrollmentRisk -Inventory $I } }
    $script:hits = { param($f, $rule) @($f | Where-Object { $_.StatusCode -eq 'CONFIG_RISK' -and $_.Message -like ('*pattern {0}:*' -f $rule) }) }
    $script:summary = { param($f) (@($f | Where-Object { $_.Message -like 'Reviewed *' })[0].Evidence) -join "`n" }

    # The default templates of a new forest (schema version 1) and the misconfiguration: an agent template that a broad group can enroll for.
    $script:userTpl = { param([object[]]$Acl = @((& $script:adminAce), (& $script:enrollAce $script:du)))
        & $script:tpl 'User' @{ SchemaVersion = 1; Eku = @($script:efs, $script:email, $script:clientAuth); EnrollmentFlag = [int64]0x29; Oid = '1.3.6.1.4.1.311.21.8.100.11'; Acl = $Acl } }
    $script:machineTpl = { & $script:tpl 'Machine' @{ SchemaVersion = 1; Eku = @($script:clientAuth, $script:serverAuth); EnrollmentFlag = [int64]0x20; Oid = '1.3.6.1.4.1.311.21.8.100.12'
        Acl = @((& $script:adminAce), (& $script:enrollAce $script:dc)) } }
    $script:agentTpl = { param([string]$Sid, [object[]]$Extra = @())
        & $script:tpl 'BroadAgent' @{ SchemaVersion = 2; Eku = @($script:agentEku); ApplicationPolicies = @($script:agentEku); Oid = '1.3.6.1.4.1.311.21.8.100.14'
            Acl = @((& $script:adminAce), (& $script:enrollAce $Sid)) + @($Extra) } }
}

Describe 'N10: an unrelated Deny ACE does not hide or downgrade ESC3' {
    It 'S11: Deny Everyone Delete on the agent template (agent open to Authenticated Users) still gives a High ESC3 naming both targets' {
        $f = & $script:run (& $script:inv @((& $script:userTpl), (& $script:machineTpl), (& $script:agentTpl $script:au @((& $script:denyDelete)))))
        $h = @(& $script:hits $f 'ESC3')
        $h.Count | Should -Be 1
        $h[0].Status | Should -Be 'Fail'
        $h[0].Severity | Should -Be 'High'
        $h[0].Confidence | Should -Be 'Referenced'
        ($h[0].Evidence -join "`n") | Should -Match 'User \(schema version 1'
        ($h[0].Evidence -join "`n") | Should -Match 'Machine \(schema version 1'
    }

    It 'S12: Deny Everyone Delete on the User template keeps User as a target' {
        $f = & $script:run (& $script:inv @((& $script:userTpl @((& $script:adminAce), (& $script:enrollAce $script:du), (& $script:denyDelete))), (& $script:machineTpl), (& $script:agentTpl $script:au)))
        $h = @(& $script:hits $f 'ESC3')
        $h.Count | Should -Be 1
        ($h[0].Evidence -join "`n") | Should -Match 'User \(schema version 1'
        $h[0].Status | Should -Be 'Fail'
    }

    It 'S13: Deny Domain Users AutoEnroll on the User template keeps User as a target (Enroll is not denied)' {
        $f = & $script:run (& $script:inv @((& $script:userTpl @((& $script:adminAce), (& $script:enrollAce $script:du), (& $script:denyAutoEnroll $script:du))), (& $script:machineTpl), (& $script:agentTpl $script:au)))
        $h = @(& $script:hits $f 'ESC3')
        $h.Count | Should -Be 1
        ($h[0].Evidence -join "`n") | Should -Match 'User \(schema version 1'
    }

    It 'S15: agent open to Domain Users, Deny Everyone Delete on the User template: still a match' {
        $f = & $script:run (& $script:inv @((& $script:userTpl @((& $script:adminAce), (& $script:enrollAce $script:du), (& $script:denyDelete))), (& $script:agentTpl $script:du)))
        @(& $script:hits $f 'ESC3').Count | Should -Be 1
    }

    It 'S16: agent open to Domain Users, Deny Everyone Delete on the agent template: still a match' {
        $f = & $script:run (& $script:inv @((& $script:userTpl), (& $script:agentTpl $script:du @((& $script:denyDelete)))))
        $h = @(& $script:hits $f 'ESC3')
        $h.Count | Should -Be 1
        $h[0].Status | Should -Be 'Fail'
    }
}

Describe 'N10: a Deny ACE that really removes Enroll still suppresses, and the summary says why' {
    It 'S14: Deny Domain Users Enroll on the User template drops User but keeps Machine' {
        $f = & $script:run (& $script:inv @((& $script:userTpl @((& $script:adminAce), (& $script:enrollAce $script:du), (& $script:denyEnroll $script:du))), (& $script:machineTpl), (& $script:agentTpl $script:au)))
        $h = @(& $script:hits $f 'ESC3')
        $h.Count | Should -Be 1
        ($h[0].Evidence -join "`n") | Should -Match 'Machine \(schema version 1'
        ($h[0].Evidence -join "`n") | Should -Not -Match 'User \(schema version 1'
    }

    It 'when the only target is denied, no finding is raised and the summary names the rule and the Deny ACE, not "no review pattern matched"' {
        $f = & $script:run (& $script:inv @((& $script:userTpl @((& $script:adminAce), (& $script:enrollAce $script:du), (& $script:denyEnroll $script:du))), (& $script:agentTpl $script:du)))
        @(& $script:hits $f 'ESC3').Count | Should -Be 0
        $s = & $script:summary $f
        $s | Should -Match 'BroadAgent: ESC3 not reported'
        $s | Should -Match 'Deny'
        $s | Should -Not -Match 'BroadAgent: no review pattern matched'
    }

    It 'when every principal that can enroll for the agent template is denied Enroll, the summary says so' {
        $f = & $script:run (& $script:inv @((& $script:userTpl), (& $script:agentTpl $script:du @((& $script:denyEnroll $script:du)))))
        @(& $script:hits $f 'ESC3').Count | Should -Be 0
        $s = & $script:summary $f
        $s | Should -Match 'BroadAgent: ESC3 not reported'
        $s | Should -Not -Match 'BroadAgent: no review pattern matched'
    }

    It 'a template that really matches nothing still says "no review pattern matched"' {
        $f = & $script:run (& $script:inv @((& $script:userTpl), (& $script:machineTpl)))
        (& $script:summary $f) | Should -Match 'User: no review pattern matched'
    }
}

Describe 'N10: the other patterns use the same rule' {
    It 'ESC1 with an unrelated Deny Everyone Delete stays a Referenced High finding, not an Inferred review item' {
        $t = & $script:tpl 'SubjectTemplate' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = @((& $script:adminAce), (& $script:enrollAce $script:du), (& $script:denyDelete)) }
        $f = & $script:run (& $script:inv @($t))
        $h = @(& $script:hits $f 'ESC1')
        $h.Count | Should -Be 1
        $h[0].Severity | Should -Be 'High'
        $h[0].Confidence | Should -Be 'Referenced'
        ($h[0].Evidence -join "`n") | Should -Not -Match 'may cancel the grant'
    }

    It 'ESC1 with a Deny Enroll for the same group is still an Inferred review item (it may cancel the grant)' {
        $t = & $script:tpl 'SubjectTemplate' @{ NameFlag = [int64]1; Eku = @($script:clientAuth); Acl = @((& $script:adminAce), (& $script:enrollAce $script:du), (& $script:denyEnroll $script:du)) }
        $h = @(& $script:hits (& $script:run (& $script:inv @($t))) 'ESC1')
        $h.Count | Should -Be 1
        $h[0].Confidence | Should -Be 'Inferred'
    }

    It 'ESC4 with a Deny of read access only is not downgraded; a Deny of write is' {
        $grant = & $script:ace $script:au 0x20034
        $readDeny = & $script:ace $script:au 0x10 '' 'Deny'
        $writeDeny = & $script:ace $script:au 0x40000 '' 'Deny'
        $t1 = & $script:tpl 'Writable' @{ Acl = @((& $script:adminAce), $grant, $readDeny) }
        $t2 = & $script:tpl 'Writable' @{ Acl = @((& $script:adminAce), $grant, $writeDeny) }
        $h1 = @(& $script:hits (& $script:run (& $script:inv @($t1))) 'ESC4')
        $h2 = @(& $script:hits (& $script:run (& $script:inv @($t2))) 'ESC4')
        $h1.Count | Should -Be 1
        $h1[0].Confidence | Should -Be 'Referenced'
        $h2.Count | Should -Be 1
        $h2[0].Confidence | Should -Be 'Inferred'
    }
}
