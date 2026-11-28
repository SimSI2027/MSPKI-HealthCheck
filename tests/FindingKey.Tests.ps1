# GX8: every finding carries a deterministic Key (category, status code, rule, target), so two runs can be compared.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'Finding keys' {
    It 'gives the same check of the same thing the same Key in two runs, whatever the order, case or Id' {
        $keys = InModuleScope MspkiHealthCheck {
            $mk = {
                @(
                    (New-MspkiFinding -Category CRL -Target 'Example Issuing CA' -Status Fail -StatusCode OBJECT_EXPIRED -Sources 'test' -Message 'The CRL expired 3 days ago.'),
                    (New-MspkiFinding -Category CA -Target 'ca01.corp.example.test\Example Issuing CA' -Status Pass -StatusCode OK -Sources 'test' -Message 'The CA answers.'),
                    (New-MspkiFinding -Category CDP -Target 'pki.example.test' -Endpoint 'http://pki.example.test/cdp/Example CA.crl' -Status Fail -StatusCode HTTP_404 -Sources 'test' -Message 'Not found.')
                )
            }
            $a = & $mk
            $b = & $mk
            # The second run: other Ids, the CA written in another case, another order and other message text.
            $b[0].Message = 'The CRL expired 4 days ago.'
            $b[1].Target = 'CA01.corp.example.test\Example Issuing CA'
            $b = @($b[2], $b[0], $b[1])
            [void](Set-MspkiFindingKey -Findings $a); [void](Set-MspkiFindingKey -Findings $b)
            [pscustomobject]@{ A = @($a | ForEach-Object { $_.Key }); B = @($b | ForEach-Object { $_.Key }); Ids = @($a[0].Id, $b[1].Id) }
        }
        $keys.Ids[0] | Should -Not -Be $keys.Ids[1]
        foreach ($k in $keys.A) { $k | Should -Match '^k1-[0-9a-f]{20}$' }
        @($keys.A | Select-Object -Unique).Count | Should -Be 3
        $keys.B[1] | Should -Be $keys.A[0]
        $keys.B[2] | Should -Be $keys.A[1]
        $keys.B[0] | Should -Be $keys.A[2]
    }
    It 'keeps the status out of the Key, and tells two findings with the same identity apart by their order' {
        $r = InModuleScope MspkiHealthCheck {
            $w = New-MspkiFinding -Category CA -Target 'Example Issuing CA' -Status Warning -StatusCode OBJECT_EXPIRING -Sources 'test' -Message 'Expires in 80 days.'
            $f = New-MspkiFinding -Category CA -Target 'Example Issuing CA' -Status Fail -StatusCode OBJECT_EXPIRING -Sources 'test' -Message 'Expires in 20 days.'
            [void](Set-MspkiFindingKey -Findings @($w)); [void](Set-MspkiFindingKey -Findings @($f))
            $d1 = New-MspkiFinding -Category Template -Target 'Web Server' -Status Warning -StatusCode CONFIG_RISK -Sources 'test' -Message 'One.'
            $d2 = New-MspkiFinding -Category Template -Target 'Web Server' -Status Warning -StatusCode CONFIG_RISK -Sources 'test' -Message 'Two.'
            [void](Set-MspkiFindingKey -Findings @($d1, $d2))
            [pscustomobject]@{ W = $w.Key; F = $f.Key; D1 = $d1.Key; D2 = $d2.Key }
        }
        $r.W | Should -Be $r.F
        $r.D1 | Should -Not -Be $r.D2
    }
    It 'gives results written before the Key existed the same keys (the rule is resolved the same way), and keeps a Key that is there' {
        $r = InModuleScope MspkiHealthCheck {
            $new = New-MspkiFinding -Category CRL -Target 'Example Issuing CA' -Status Fail -StatusCode OBJECT_EXPIRED -Sources 'test' -Message 'The CRL expired.'
            [void](Add-MspkiFindingDiagnosis -Findings @($new))
            [void](Set-MspkiFindingKey -Findings @($new))
            $old = New-MspkiFinding -Category CRL -Target 'Example Issuing CA' -Status Fail -StatusCode OBJECT_EXPIRED -Sources 'test' -Message 'The CRL expired.'
            [void](Set-MspkiFindingKey -Findings @($old))
            $kept = New-MspkiFinding -Category CA -Target 'x' -Status Pass -StatusCode OK -Sources 'test' -Message 'm'
            $kept | Add-Member -NotePropertyName Key -NotePropertyValue 'k1-given' -Force
            $n = Set-MspkiFindingKey -Findings @($kept)
            [pscustomobject]@{ HasDiag = ($null -ne $new.Diagnosis); New = $new.Key; Old = $old.Key; Kept = $kept.Key; N = $n }
        }
        $r.HasDiag | Should -BeTrue
        $r.Old | Should -Be $r.New
        $r.Kept | Should -Be 'k1-given'
        $r.N | Should -Be 0
    }
}
