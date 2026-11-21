BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:inv = {
        param([hashtable]$o = @{})
        $d = @{
            TemplatesRead = $true; KraRead = $true; OidRead = $true
            Templates = @([pscustomobject]@{ Name = 'User' }, [pscustomobject]@{ Name = 'Machine' })
            Kra = @(); OidObjects = @()
            EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('User', 'Machine'); Properties = $null })
        }
        foreach ($k in $o.Keys) { $d[$k] = $o[$k] }
        [pscustomobject]$d
    }
    $script:run = { param($i) InModuleScope MspkiHealthCheck -Parameters @{ I = $i } { param($I) Test-MspkiAdContainerObject -Inventory $I } }
    $script:cert = { param($tp, [bool]$expired) [pscustomobject]@{ Thumbprint = $tp; Subject = 'CN=Example KRA'; NotAfter = '2030-01-01T00:00:00Z'; Expired = $expired } }
    $script:oid = { param($resolved, $err = '') [pscustomobject]@{ Name = '1.5'; DisplayName = 'Example Policy'; DistinguishedName = 'CN=1.5,CN=OID'; Oid = '1.2.3'; Flags = 2
        GroupLink = 'CN=Example Group,CN=Users,DC=corp,DC=example,DC=test'; GroupName = 'Example Group'; GroupResolved = $resolved; GroupError = $err } }
}

Describe 'Test-MspkiAdContainerObject: templates' {
    It 'is silent when every published template has an object and every object is published' {
        $f = & $script:run (& $script:inv)
        @($f | Where-Object { $_.Status -ne 'Pass' -and $_.Status -ne 'Information' }).Count | Should -Be 0
        @($f | Where-Object { $_.Message -like '*published by no Enterprise CA*' }).Count | Should -Be 0
    }

    It 'warns about a published template name with no template object, with the source of the name' {
        $f = & $script:run (& $script:inv @{ EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('User', 'Machine', 'GoneTemplate'); Properties = $null }) })
        $w = @($f | Where-Object { $_.Status -eq 'Warning' })
        $w.Count | Should -Be 1
        $w[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        $w[0].Category | Should -Be 'Template'
        $w[0].Confidence | Should -Be 'Referenced'
        ($w[0].Evidence -join "`n") | Should -Match 'GoneTemplate .*AD \(Enrollment Services\)'
    }

    It 'is Confirmed when the CA itself lists the missing template' {
        $props = [pscustomobject]@{ Templates = @([pscustomobject]@{ Name = 'GoneTemplate'; Oid = '1.2' }) }
        $f = & $script:run (& $script:inv @{ EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('User'); Properties = $props }) })
        $w = @($f | Where-Object { $_.Status -eq 'Warning' })
        $w[0].Confidence | Should -Be 'Confirmed'
        ($w[0].Evidence -join "`n") | Should -Match 'CA \(GetCAProperty\)'
    }

    It 'compares names case-insensitively' {
        $f = & $script:run (& $script:inv @{ EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('USER', 'machine'); Properties = $null }) })
        @($f | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 0
    }

    It 'reports template objects that no CA publishes as one information finding' {
        $f = & $script:run (& $script:inv @{ Templates = @([pscustomobject]@{ Name = 'User' }, [pscustomobject]@{ Name = 'Machine' }, [pscustomobject]@{ Name = 'Spare' }) })
        $u = @($f | Where-Object { $_.Message -like '*published by no Enterprise CA*' })
        $u.Count | Should -Be 1
        $u[0].Status | Should -Be 'Information'
        $u[0].StatusCode | Should -Be 'NOT_CONFIGURED'
        $u[0].Evidence[0] | Should -Match 'Spare'
    }

    It 'does not judge templates when the template objects could not be read' {
        $f = & $script:run (& $script:inv @{ TemplatesRead = $false; Templates = @() })
        @($f | Where-Object { $_.Category -eq 'Template' }).Count | Should -Be 0
    }

    It 'does not call every template unpublished when there is no Enterprise CA' {
        $f = & $script:run (& $script:inv @{ EnterpriseCAs = @() })
        @($f | Where-Object { $_.Message -like '*published by no Enterprise CA*' }).Count | Should -Be 0
    }
}

Describe 'Test-MspkiAdContainerObject: KRA' {
    It 'passes a KRA object with a certificate that has not expired' {
        $f = & $script:run (& $script:inv @{ Kra = @([pscustomobject]@{ Name = 'Example Issuing CA'; DistinguishedName = 'CN=Example Issuing CA,CN=KRA'; Certificates = @(& $script:cert 'AA' $false); CertificateErrors = @() }) })
        $k = @($f | Where-Object { $_.Message -like '*KRA object*' })
        $k.Count | Should -Be 1
        $k[0].Status | Should -Be 'Pass'
    }

    It 'warns when the KRA certificate is missing' {
        $f = & $script:run (& $script:inv @{ Kra = @([pscustomobject]@{ Name = 'Example Issuing CA'; DistinguishedName = 'CN=Example Issuing CA,CN=KRA'; Certificates = @(); CertificateErrors = @() }) })
        $k = @($f | Where-Object { $_.Message -like '*KRA object*' })
        $k[0].Status | Should -Be 'Warning'
        $k[0].StatusCode | Should -Be 'NOT_DISCOVERED'
    }

    It 'warns when every KRA certificate has expired' {
        $f = & $script:run (& $script:inv @{ Kra = @([pscustomobject]@{ Name = 'Example Issuing CA'; DistinguishedName = 'CN=Example Issuing CA,CN=KRA'; Certificates = @(& $script:cert 'AA' $true); CertificateErrors = @() }) })
        $k = @($f | Where-Object { $_.Message -like '*KRA object*' })
        $k[0].Status | Should -Be 'Warning'
        $k[0].StatusCode | Should -Be 'OBJECT_EXPIRED'
    }

    It 'warns when the CA is configured with more KRA certificates than it can use' {
        $props = [pscustomobject]@{ Templates = @(); KraCertCount = 2; KraCertUsedCount = 1 }
        $f = & $script:run (& $script:inv @{ EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('User', 'Machine'); Properties = $props }) })
        $k = @($f | Where-Object { $_.Message -like '*key recovery agent certificate(s) but can use only*' })
        $k.Count | Should -Be 1
        $k[0].Confidence | Should -Be 'Confirmed'
    }

    It 'says nothing about KRA when the CA has none configured' {
        $props = [pscustomobject]@{ Templates = @(); KraCertCount = 0; KraCertUsedCount = 0 }
        $f = & $script:run (& $script:inv @{ EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('User', 'Machine'); Properties = $props }) })
        @($f | Where-Object { $_.Message -like '*key recovery*' }).Count | Should -Be 0
    }

    It 'does not judge KRA when the container could not be read' {
        $f = & $script:run (& $script:inv @{ KraRead = $false })
        @($f | Where-Object { $_.Message -like '*KRA*' }).Count | Should -Be 0
    }
}

Describe 'Test-MspkiAdContainerObject: OID group links' {
    It 'passes when every linked group resolves' {
        $f = & $script:run (& $script:inv @{ OidObjects = @(& $script:oid $true) })
        $o = @($f | Where-Object { $_.Message -like '*OID group link(s) resolve*' })
        $o.Count | Should -Be 1
        $o[0].Status | Should -Be 'Pass'
    }

    It 'warns when the linked group does not exist' {
        $f = & $script:run (& $script:inv @{ OidObjects = @(& $script:oid $false 'No such object') })
        $o = @($f | Where-Object { $_.Message -like '*does not resolve*' })
        $o.Count | Should -Be 1
        $o[0].Status | Should -Be 'Warning'
        $o[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        ($o[0].Evidence -join "`n") | Should -Match 'msDS-OIDToGroupLink'
    }

    It 'keeps a permission failure apart from a missing group' {
        $f = & $script:run (& $script:inv @{ OidObjects = @(& $script:oid $null 'PermissionDenied: Access is denied') })
        $o = @($f | Where-Object { $_.Message -like '*could not be looked up*' })
        $o[0].StatusCode | Should -Be 'PERMISSION_DENIED'
        $o[0].Status | Should -Be 'Skipped'
        @($f | Where-Object { $_.Message -like '*does not resolve*' }).Count | Should -Be 0
    }

    It 'reports an infrastructure failure as an error, not as a missing group' {
        $f = & $script:run (& $script:inv @{ OidObjects = @(& $script:oid $null 'Unreachable: server down') })
        $o = @($f | Where-Object { $_.Message -like '*could not be looked up*' })
        $o[0].StatusCode | Should -Be 'RETRIEVAL_FAIL'
        $o[0].Status | Should -Be 'Error'
    }

    It 'ignores OID objects without a group link' {
        $x = & $script:oid $true; $x.GroupLink = ''
        $f = & $script:run (& $script:inv @{ OidObjects = @($x) })
        @($f | Where-Object { $_.Target -like '*Example Policy*' -or $_.Message -like '*OID*' }).Count | Should -Be 0
    }
}

Describe 'Test-MspkiAdContainerObject: review only' {
    It 'never recommends deleting anything and gives every finding a source' {
        $props = [pscustomobject]@{ Templates = @(); KraCertCount = 2; KraCertUsedCount = 0 }
        $oid = [pscustomobject]@{ Name = '1.5'; DisplayName = 'P'; DistinguishedName = 'CN=1.5'; Oid = '1.2'; Flags = 2; GroupLink = 'CN=G'; GroupName = ''; GroupResolved = $false; GroupError = 'gone' }
        $f = & $script:run (& $script:inv @{
            EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('User', 'GoneTemplate'); Properties = $props })
            Kra = @([pscustomobject]@{ Name = 'K'; DistinguishedName = 'CN=K'; Certificates = @(); CertificateErrors = @() }); OidObjects = @($oid)
            Templates = @([pscustomobject]@{ Name = 'User' }, [pscustomobject]@{ Name = 'Spare' }) })
        $f.Count | Should -BeGreaterOrEqual 4
        foreach ($x in $f) {
            (@($x.Message, $x.Notes, $x.Remediation, ($x.Evidence -join ' ')) -join ' ') | Should -Not -Match '(?i)\b(delete|remove|purge|clean up)\b'
            @($x.Sources).Count | Should -BeGreaterThan 0
        }
    }

    It 'handles a missing inventory' {
        @(& $script:run $null | Where-Object { $_ }).Count | Should -Be 0
    }
}
