# Tests for the Batch B fixes of audit 2 (docs/AUDIT-2.md): results that were more confident than the evidence (M1, M2, M7),
# the retrieval-order check (M4), redirects (M5), large CRLs (M3), status codes (M8) and the other Medium and Low items.
# Hosts are 127.0.0.1 and example.test names only; nothing leaves this computer.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root1 = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    # The same name with a new key: the renewed root.
    $script:root2 = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 100 -DaysValid 4000
    $script:subNew = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root2.Full -DaysValid 900 -WithAki
}

Describe 'Audit 2 M1: an AIA location that serves the old CA certificate after a renewal is not Verified' {
    It 'is a key mismatch when the old root is known too (the old generation is still in AD) and the subordinate needs the new key' {
        $tp = $script:subNew.Public.Thumbprint
        $known = @{ $tp = $script:subNew.Public; $script:root1.Public.Thumbprint = $script:root1.Public; $script:root2.Public.Thumbprint = $script:root2.Public }
        $m = InModuleScope MspkiHealthCheck -Parameters @{ D = $script:root1.Public; K = $known; Tp = $tp } {
            param($D, $K, $Tp)
            Test-MspkiAiaCertificateMatch -Downloaded $D -Lead ([pscustomobject]@{ Sources = @(('Cert:{0}:AIA' -f $Tp)) }) -KnownCertificates $K -ExpectedIssuer @('CN=Example Root CA, DC=example, DC=test') }
        $m.Result | Should -Be 'KeyMismatch'
    }
    It 'is still Verified when the downloaded certificate is the new root' {
        $tp = $script:subNew.Public.Thumbprint
        $known = @{ $tp = $script:subNew.Public; $script:root1.Public.Thumbprint = $script:root1.Public; $script:root2.Public.Thumbprint = $script:root2.Public }
        $m = InModuleScope MspkiHealthCheck -Parameters @{ D = $script:root2.Public; K = $known; Tp = $tp } {
            param($D, $K, $Tp)
            Test-MspkiAiaCertificateMatch -Downloaded $D -Lead ([pscustomobject]@{ Sources = @(('Cert:{0}:AIA' -f $Tp)) }) -KnownCertificates $K -ExpectedIssuer @('CN=Example Root CA, DC=example, DC=test') }
        $m.Result | Should -Be 'Verified'
    }
}

Describe 'Audit 2 M4: the retrieval-order check matches URLs after normalisation and counts only usable objects' {
    BeforeAll {
        # Findings for a URL, built the way the probes build them: the Endpoint is the normalised probe URL (spaces as %20).
        $script:probeFinding = {
            param([string]$Url, [string]$Status, [string]$Code = 'OK', [string]$Category = 'CDP')
            InModuleScope MspkiHealthCheck -Parameters @{ U = $Url; S = $Status; C = $Code; K = $Category } {
                param($U, $S, $C, $K)
                New-MspkiFinding -Stage 'Probe' -Category $K -Role 'CDPEndpoint' -Target 'pki.example.test' -Endpoint $U -Status $S -StatusCode $C -Sources @('test') -Message 'test' -Confidence 'Confirmed'
            }
        }
        $script:order = {
            param([string[]]$Urls, $Findings, [string]$Kind = 'CDP')
            InModuleScope MspkiHealthCheck -Parameters @{ U = $Urls; F = @($Findings); K = $Kind } {
                param($U, $F, $K)
                $o = Get-MspkiRetrievalOutcome -Findings $F
                Test-MspkiRetrievalOrder -IssuerName 'Example Issuing CA' -Kind $K -Urls $U -UrlOutcome $o
            }
        }
    }
    It 'finds a failing URL that contains a space (the certificate has the space, the probe the %20): Fail, not "not tested"' {
        $f = & $script:order @('http://pki.example.test/CertEnroll/Example Issuing CA.crl') @(& $script:probeFinding 'http://pki.example.test/CertEnroll/Example%20Issuing%20CA.crl' 'Fail' 'HTTP_404')
        $f.Status | Should -Be 'Fail'
        $f.StatusCode | Should -Be 'RETRIEVAL_FAIL'
    }
    It 'matches an explicit default port and a different host case' {
        $f = & $script:order @('http://PKI.example.test:80/CertEnroll/ca.crl') @(& $script:probeFinding 'http://pki.example.test/CertEnroll/ca.crl' 'Pass')
        $f.Status | Should -Be 'Pass'
    }
    It 'does not mix up the http and the https URL of the same path' {
        $f = & $script:order @('https://pki.example.test/ca.crl', 'http://pki.example.test/ca.crl') @(& $script:probeFinding 'http://pki.example.test/ca.crl' 'Pass')
        # The https URL was not tested; the http one works, and the first URL is unknown, not failing.
        $f.Status | Should -Not -Be 'Pass'
        $f.Status | Should -Not -Be 'Warning'
        $f.Confidence | Should -Be 'Referenced'
    }
    It 'does not count a Warning for the wrong content as a working URL: <Name>' -TestCases @(
        @{ Name = 'wrong CRL issuer'; Code = 'CONTENT_WRONG_TYPE' }
        @{ Name = 'a failure capped to a Warning by scope'; Code = 'DNS_FAIL' }
        @{ Name = 'a redirect that was not followed'; Code = 'HTTP_REDIRECT' }
    ) {
        param($Name, $Code)
        $only = & $script:order @('http://pki.example.test/a.crl') @(& $script:probeFinding 'http://pki.example.test/a.crl' 'Warning' $Code)
        $only.Status | Should -Be 'Fail' -Because 'the only URL did not deliver a usable object'
        $two = & $script:order @('http://pki.example.test/a.crl', 'http://pki.example.test/b.crl') @(
            (& $script:probeFinding 'http://pki.example.test/a.crl' 'Warning' $Code), (& $script:probeFinding 'http://pki.example.test/b.crl' 'Pass'))
        $two.Status | Should -Be 'Warning'
        $two.Message | Should -Match '1 failing CDP URL'
    }
    It 'still counts a Warning about the object''s age (it was retrieved) as working' {
        $f = & $script:order @('http://pki.example.test/a.crl') @(& $script:probeFinding 'http://pki.example.test/a.crl' 'Pass'; & $script:probeFinding 'http://pki.example.test/a.crl' 'Warning' 'OBJECT_EXPIRING' 'CRL')
        $f.Status | Should -Be 'Pass'
    }
    It 'an expired CRL (Fail from the freshness check) is not a working URL even though the download passed' {
        $f = & $script:order @('http://pki.example.test/a.crl') @(& $script:probeFinding 'http://pki.example.test/a.crl' 'Pass'; & $script:probeFinding 'http://pki.example.test/a.crl' 'Fail' 'OBJECT_EXPIRED' 'CRL')
        $f.Status | Should -Be 'Fail'
    }
    It 'says how many URLs were really tested, and is not Confirmed when some were not' {
        $urls = @('http://pki.example.test/a.crl', 'http://pki.example.test/b.crl', 'http://pki.example.test/c.crl')
        $f = & $script:order $urls @(& $script:probeFinding $urls[0] 'Fail' 'HTTP_404'; & $script:probeFinding $urls[1] 'Fail' 'TIMEOUT'; & $script:probeFinding $urls[2] 'Skipped' 'NOT_APPLICABLE')
        $f.Status | Should -Be 'Fail'
        $f.Message | Should -Match '2 of the 3 CDP URLs'
        $f.Message | Should -Not -Match '^None of the 3'
        $f.Confidence | Should -Be 'Referenced'
        $all = & $script:order $urls @(& $script:probeFinding $urls[0] 'Fail' 'HTTP_404'; & $script:probeFinding $urls[1] 'Fail' 'HTTP_404'; & $script:probeFinding $urls[2] 'Fail' 'TIMEOUT')
        $all.Confidence | Should -Be 'Confirmed'
    }
}

Describe 'Audit 2 M5: a redirect that is not followed is an answer (status and Location), never "no answer"' {
    BeforeAll {
        $script:routes5 = [hashtable]::Synchronized(@{})
        $script:server5 = Start-TestHttpServer -Routes $script:routes5
        $script:b5 = $script:server5.Base
        $script:routes5['/start'] = @{ Status = 302; Body = @(); Headers = @{ Location = '/next' } }
        $script:routes5['/next'] = @{ Status = 301; Body = @(); Headers = @{ Location = '/last' } }
        $script:routes5['/last'] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('ok') }
        $script:get5 = {
            param([string]$Path, [int]$Max = 0)
            InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:b5 + $Path); M = $Max } {
                param($U, $M) Reset-MspkiProbeCache; Invoke-MspkiHttpGet -Url $U -TimeoutMs 3000 -MaxRedirects $M -DiscardBody }
        }
    }
    AfterAll { Stop-TestHttpServer -Server $script:server5 }

    It 'takes HttpStatus and the Location from the redirect when redirects are turned off' {
        $r = & $script:get5 '/start' 0
        $r.HttpStatus | Should -Be 302
        $r.Code | Should -Be 'HTTP_REDIRECT'
        $r.Redirected | Should -BeTrue
        @($r.Hops)[-1].HttpStatus | Should -Be 302
        @($r.Hops)[-1].Location | Should -Be '/next'
        $r.Error | Should -Match 'redirect'
        $r.Error | Should -Match '/next'
    }
    It 'takes HttpStatus from the last hop when the hop limit is reached' {
        $r = & $script:get5 '/start' 1
        $r.HttpStatus | Should -Be 301
        $r.Code | Should -Be 'HTTP_REDIRECT'
        $r.Error | Should -Match 'More than 1 redirect'
    }
    It 'still follows redirects within the limit' {
        $r = & $script:get5 '/start' 5
        $r.HttpStatus | Should -Be 200
        $r.Code | Should -Be 'OK'
    }
    It 'is present Web Enrollment evidence: the state is not $null and says it redirects' {
        $r = & $script:get5 '/start' 0
        $s = InModuleScope MspkiHealthCheck -Parameters @{ R = $r } { param($R) Get-MspkiWebEnrollmentState -Http $R }
        $s | Should -Not -BeNullOrEmpty
        $s.HttpStatus | Should -Be 302
        $s.Meaning | Should -Match 'redirects \(HTTP 302\) to /next'
    }
    It 'gives a Web Enrollment finding (Inferred) with the redirect in its evidence when http redirects and https was not reachable' {
        $r = & $script:get5 '/start' 0
        $f = @(InModuleScope MspkiHealthCheck -Parameters @{ R = $r } { param($R) Test-MspkiWebEnrollment -HostName 'ca01.corp.example.test' -Http $R })
        $f.Count | Should -Be 1
        $f[0].StatusCode | Should -Be 'OK'
        $f[0].Confidence | Should -Be 'Inferred'
        ($f[0].Evidence -join "`n") | Should -Match 'HTTP 302, redirects \(HTTP 302\) to /next'
        ($f[0].Evidence -join "`n") | Should -Not -Match 'no answer'
    }
}
