# Fix log 3, N11 and N12 (docs/AUDIT-3-VERIFY.md). example.test names only.
#  N11: an AIA URL outside the forest that answers above the size cap is a failure of that URL, not a working one, even after the scope rule
#       has reduced the Fail to a Warning.
#  N12: a local certificate with several CDP/AIA URLs records each URL on its own, never "System.Object[]".

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'N11: an AIA answer above the size cap is not a working URL in the retrieval-order check, also outside the forest' {
    It 'an AIA lead on a host outside the forest: Fail SIZE_LIMIT is capped to Warning by the scope rule and still counts as Failed' {
        InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $lead = Add-MspkiLead -Url 'http://pki.other.example.test/ca.crt' -Kind AIA -Source 'AD:test' -Origin 'test fixture'
            $lead.Scope | Should -Be 'External'
            $f = New-MspkiEndpointFinding -Lead $lead -Url $lead.Url -Status 'Fail' -Code 'SIZE_LIMIT' -Message 'The answer is larger than 10 MB; not read.'
            $f.Status | Should -Be 'Warning'
            $f.StatusCode | Should -Be 'SIZE_LIMIT'
            $o = Get-MspkiRetrievalOutcome -Findings @($f)
            $o[(Get-MspkiRetrievalUrlKey -Url $lead.Url)] | Should -Be 'Failed'
        }
    }

    It 'the same answer inside the forest is Failed too' {
        InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $lead = Add-MspkiLead -Url 'http://pki.corp.example.test/ca.crt' -Kind AIA -Source 'AD:test' -Origin 'test fixture'
            $f = New-MspkiEndpointFinding -Lead $lead -Url $lead.Url -Status 'Fail' -Code 'SIZE_LIMIT' -Message 'The answer is larger than 10 MB; not read.'
            $f.Status | Should -Be 'Fail'
            (Get-MspkiRetrievalOutcome -Findings @($f))[(Get-MspkiRetrievalUrlKey -Url $lead.Url)] | Should -Be 'Failed'
        }
    }

    It 'a CRL above the CRL cap (not read) is NotTested, neither working nor failing' {
        InModuleScope MspkiHealthCheck {
            $u = 'http://pki.corp.example.test/big.crl'
            $f = New-MspkiFinding -Category 'CDP' -Role 'CDPEndpoint' -Target $u -Endpoint $u -Status 'Information' -StatusCode 'SIZE_LIMIT' -Sources 'AD:test' -Message 'not read' -Confidence 'Confirmed'
            (Get-MspkiRetrievalOutcome -Findings @($f))[(Get-MspkiRetrievalUrlKey -Url $u)] | Should -Be 'NotTested'
            $w = New-MspkiFinding -Category 'CDP' -Role 'CDPEndpoint' -Target $u -Endpoint $u -Status 'Warning' -StatusCode 'SIZE_LIMIT' -Sources 'AD:test' -Message 'not read' -Confidence 'Confirmed'
            (Get-MspkiRetrievalOutcome -Findings @($w))[(Get-MspkiRetrievalUrlKey -Url $u)] | Should -Be 'NotTested'
        }
    }

    It 'a Warning about the age of a retrieved AIA certificate still counts as Usable' {
        InModuleScope MspkiHealthCheck {
            $u = 'http://pki.corp.example.test/old.crt'
            $f = New-MspkiFinding -Category 'AIA' -Role 'AIAEndpoint' -Target $u -Endpoint $u -Status 'Warning' -StatusCode 'OBJECT_EXPIRING' -Sources 'AD:test' -Message 'expires soon' -Confidence 'Confirmed'
            (Get-MspkiRetrievalOutcome -Findings @($f))[(Get-MspkiRetrievalUrlKey -Url $u)] | Should -Be 'Usable'
        }
    }
}

Describe 'N12: local certificate URLs are recorded one by one' {
    It 'records every URL of a certificate with two CDP URLs and one AIA URL as its own text' {
        $root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
        $leaf = New-TestCertificate -Subject 'CN=ws01.corp.example.test' -Signer $root.Full -DaysValid 90 `
            -CdpUrls @('http://pki.example.test/one.crl', 'http://pki.example.test/two.crl') -AiaUrls @('http://pki.example.test/ca.crt')
        $info = InModuleScope MspkiHealthCheck -Parameters @{ C = $leaf.Public } { param($C) ConvertTo-MspkiLocalCertificateInfo -Certificate $C -Store 'My' }
        @($info.Urls).Count | Should -Be 3
        ($info.Urls -join "`n") | Should -Not -Match 'System\.Object'
        @($info.Urls | Where-Object { $_ -eq 'CDP: http://pki.example.test/one.crl' }).Count | Should -Be 1
        @($info.Urls | Where-Object { $_ -eq 'CDP: http://pki.example.test/two.crl' }).Count | Should -Be 1
        @($info.Urls | Where-Object { $_ -eq 'AIA: http://pki.example.test/ca.crt' }).Count | Should -Be 1
    }

    It 'records one URL of one kind (the case that worked before)' {
        $root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
        $leaf = New-TestCertificate -Subject 'CN=ws01.corp.example.test' -Signer $root.Full -DaysValid 90 -CdpUrls @('http://pki.example.test/one.crl')
        $info = InModuleScope MspkiHealthCheck -Parameters @{ C = $leaf.Public } { param($C) ConvertTo-MspkiLocalCertificateInfo -Certificate $C -Store 'My' }
        @($info.Urls) | Should -Be @('CDP: http://pki.example.test/one.crl')
    }
}
