BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:du = 'S-1-5-21-1111-2222-3333-513'
}

Describe 'Security descriptor parsing (in memory only)' {
    It 'reads owner and ACEs: type, mask, object type and flags' {
        $bytes = New-TestSecurityDescriptor -OwnerSid 'S-1-5-21-1111-2222-3333-512' -Aces @(
            @{ Sid = $script:du; Type = 'Allow'; Mask = 0x100; ObjectType = $script:enroll },
            @{ Sid = 'S-1-1-0'; Type = 'Deny'; Mask = 0x20 },
            @{ Sid = 'S-1-5-11'; Type = 'Allow'; Mask = 0x10000000; Flags = 0x08 })
        $sd = InModuleScope MspkiHealthCheck -Parameters @{ B = $bytes } { param($B) ConvertFrom-MspkiSecurityDescriptor -Bytes $B }
        $sd.OwnerSid | Should -Be 'S-1-5-21-1111-2222-3333-512'
        @($sd.Aces).Count | Should -Be 3
        $sd.Aces[0].Sid | Should -Be $script:du
        $sd.Aces[0].Type | Should -Be 'Allow'
        $sd.Aces[0].ObjectType | Should -Be $script:enroll
        $sd.Aces[0].Rights | Should -Contain 'Enroll'
        $sd.Aces[1].Type | Should -Be 'Deny'
        $sd.Aces[1].Rights | Should -Contain 'WriteProperty'
        $sd.Aces[2].Rights | Should -Contain 'FullControl'
        $sd.Aces[2].InheritOnly | Should -BeTrue
        $sd.Aces[0].InheritOnly | Should -BeFalse
    }

    It 'names an all-extended-rights ACE and the AutoEnroll right' {
        $bytes = New-TestSecurityDescriptor -Aces @(
            @{ Sid = $script:du; Type = 'Allow'; Mask = 0x100 },
            @{ Sid = $script:du; Type = 'Allow'; Mask = 0x100; ObjectType = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2' })
        $sd = InModuleScope MspkiHealthCheck -Parameters @{ B = $bytes } { param($B) ConvertFrom-MspkiSecurityDescriptor -Bytes $B }
        $sd.Aces[0].Rights | Should -Contain 'AllExtendedRights'
        $sd.Aces[1].Rights | Should -Contain 'AutoEnroll'
    }

    It 'throws on bytes that are not a security descriptor (the caller turns that into a finding)' {
        { InModuleScope MspkiHealthCheck { ConvertFrom-MspkiSecurityDescriptor -Bytes ([byte[]](1, 2, 3)) } } | Should -Throw
    }
}

Describe 'Broad groups and SID names' {
    It 'recognises broad groups by SID, including Domain Users and Domain Computers of any domain' {
        InModuleScope MspkiHealthCheck {
            Get-MspkiBroadPrincipal -Sid 'S-1-1-0' | Should -Be 'Everyone'
            Get-MspkiBroadPrincipal -Sid 'S-1-5-11' | Should -Be 'Authenticated Users'
            Get-MspkiBroadPrincipal -Sid 'S-1-5-21-1111-2222-3333-513' | Should -Be 'Domain Users'
            Get-MspkiBroadPrincipal -Sid 'S-1-5-21-9-8-7-515' | Should -Be 'Domain Computers'
        }
    }

    It 'does not treat other groups as broad' {
        InModuleScope MspkiHealthCheck {
            foreach ($s in @('S-1-5-21-1111-2222-3333-512', 'S-1-5-21-1111-2222-3333-519', 'S-1-5-21-1111-2222-3333-1105', 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-21-1-2-3-5130', '')) {
                Get-MspkiBroadPrincipal -Sid $s | Should -Be '' -Because $s
            }
        }
    }

    It 'resolves each SID once per run and falls back to the RID name when the lookup fails' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiSidCache
            $sid = 'S-1-5-21-1111-2222-3333-513'
            $a = Resolve-MspkiSid -Sid $sid
            $n1 = (Get-MspkiSidStatistic).Lookups
            $b = Resolve-MspkiSid -Sid $sid
            $c = Resolve-MspkiSid -Sid $sid
            (Get-MspkiSidStatistic).Lookups | Should -Be $n1
            $n1 | Should -BeLessOrEqual 1
            $b | Should -Be $a
            $a | Should -Match 'Domain Users'
            Resolve-MspkiSid -Sid 'S-1-1-0' | Should -Be 'Everyone'
            (Get-MspkiSidStatistic).Lookups | Should -Be $n1
        }
    }

    It 'stops looking up SIDs after the failure budget and still names them' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiSidCache -FailureBudget 1
            $null = Resolve-MspkiSid -Sid 'S-1-5-21-5-5-5-1001'
            $null = Resolve-MspkiSid -Sid 'S-1-5-21-5-5-5-1002'
            $x = Resolve-MspkiSid -Sid 'S-1-5-21-5-5-5-513'
            (Get-MspkiSidStatistic).Lookups | Should -BeLessOrEqual 1
            $x | Should -Match 'Domain Users'
            Reset-MspkiSidCache
        }
    }

    It 'reads signed Int32 flag attributes as unsigned' {
        InModuleScope MspkiHealthCheck {
            ConvertTo-MspkiUInt32 -2147483648 | Should -Be 2147483648
            ConvertTo-MspkiUInt32 524288 | Should -Be 524288
            ConvertTo-MspkiUInt32 $null | Should -Be 0
            ConvertTo-MspkiUInt32 'x' | Should -Be 0
        }
    }
}

Describe 'Template, KRA and OID records' {
    It 'converts a template record: flags, policies and the ACL' {
        $sd = New-TestSecurityDescriptor -Aces @(@{ Sid = $script:du; Type = 'Allow'; Mask = 0x100; ObjectType = $script:enroll })
        $rec = @{
            cn = @('ExampleUser'); displayname = @('Example User'); distinguishedname = @('CN=ExampleUser,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test')
            'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.100.1'); 'mspki-template-schema-version' = @(2); 'mspki-certificate-name-flag' = @(-2147483647)
            'mspki-enrollment-flag' = @(524288); 'mspki-ra-signature' = @(1); pkiextendedkeyusage = @('1.3.6.1.5.5.7.3.2')
            'mspki-certificate-policy' = @('1.3.6.1.4.1.311.21.8.100.2'); ntsecuritydescriptor = @(, $sd)
        }
        $t = InModuleScope MspkiHealthCheck -Parameters @{ R = $rec } { param($R) ConvertFrom-MspkiTemplateRecord -Record $R }
        $t.Name | Should -Be 'ExampleUser'
        $t.SchemaVersion | Should -Be 2
        $t.NameFlag | Should -Be 2147483649
        $t.EnrollmentFlag | Should -Be 524288
        $t.RaSignature | Should -Be 1
        $t.Eku | Should -Be @('1.3.6.1.5.5.7.3.2')
        $t.IssuancePolicies | Should -Be @('1.3.6.1.4.1.311.21.8.100.2')
        @($t.Acl).Count | Should -Be 1
        $t.Acl[0].Rights | Should -Contain 'Enroll'
        $t.AclError | Should -Be ''
    }

    It 'keeps the template and records why when the security descriptor is missing or broken' {
        $rec = @{ cn = @('NoAcl'); 'mspki-enrollment-flag' = @(0) }
        $t = InModuleScope MspkiHealthCheck -Parameters @{ R = $rec } { param($R) ConvertFrom-MspkiTemplateRecord -Record $R }
        $t.Name | Should -Be 'NoAcl'
        @($t.Acl).Count | Should -Be 0
        $t.AclError | Should -Not -BeNullOrEmpty
        $rec2 = @{ cn = @('BadAcl'); ntsecuritydescriptor = @(, ([byte[]](1, 2, 3))) }
        $t2 = InModuleScope MspkiHealthCheck -Parameters @{ R = $rec2 } { param($R) ConvertFrom-MspkiTemplateRecord -Record $R }
        $t2.AclError | Should -Not -BeNullOrEmpty
    }

    It 'reads KRA certificates: valid and expired' {
        $ok = New-TestCertificate -Subject 'CN=Example KRA, DC=example, DC=test' -IsCA $false
        $old = New-TestCertificate -Subject 'CN=Old KRA, DC=example, DC=test' -IsCA $false -DaysBefore 400 -DaysValid -10
        $rec = @{ cn = @('Example Issuing CA'); distinguishedname = @('CN=Example Issuing CA,CN=KRA,CN=Public Key Services'); usercertificate = @($ok.Public.RawData, $old.Public.RawData, ([byte[]](1, 2))) }
        $k = InModuleScope MspkiHealthCheck -Parameters @{ R = $rec } { param($R) ConvertFrom-MspkiKraRecord -Record $R }
        @($k.Certificates).Count | Should -Be 2
        @($k.Certificates | Where-Object { $_.Expired }).Count | Should -Be 1
        @($k.CertificateErrors).Count | Should -Be 1
    }

    It 'reads an OID record with a group link and its flags' {
        $rec = @{ cn = @('1234.5'); displayname = @('Example Policy'); 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.2'); flags = @(2)
            'msds-oidtogrouplink' = @('CN=Example Group,CN=Users,DC=corp,DC=example,DC=test') }
        $o = InModuleScope MspkiHealthCheck -Parameters @{ R = $rec } { param($R) ConvertFrom-MspkiOidRecord -Record $R }
        $o.Oid | Should -Be '1.3.6.1.4.1.311.21.8.1.2'
        $o.Flags | Should -Be 2
        $o.GroupLink | Should -Match '^CN=Example Group'
        $o.GroupResolved | Should -BeNullOrEmpty
    }
}
