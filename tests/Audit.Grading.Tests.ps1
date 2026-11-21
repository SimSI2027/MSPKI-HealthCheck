# Tests for the audit fixes (docs/AUDIT.md) that concern how results are graded: H3 (what carries a URL), M3 (could not check is not
# invalid; key generations), M4 (unconfirmed lifecycle), M5 (scope), M8 (Confirmed only when validated), M10 (CA connection and
# its classification, trace logging) and M11 (-SkipNetwork at every stage). Fixtures are synthetic example.test data.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root1 = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    # The same name with another key: a later key generation of the CA.
    $script:root2 = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 100 -DaysValid 4000
    $script:subAki = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root1.Full -DaysValid 900 -WithAki

    $script:info = { param($C) InModuleScope MspkiHealthCheck -Parameters @{ C = $C } { param($C) Get-MspkiCertificateInfo -Certificate $C } }
    $script:entry = {
        param($Cert, [string]$Role = 'EnterpriseRoot', [string]$Lifecycle = 'Current', [string]$Confidence = 'Confirmed', [string]$CAName = 'Example Root CA')
        [pscustomobject]@{ Thumbprint = $Cert.Thumbprint; CAName = $CAName; Role = $Role; Lifecycle = $Lifecycle; LifecycleConfidence = $Confidence; LifecycleBasis = 'test'
            Sources = @('AD:EnrollmentServices'); Info = (& $script:info $Cert); Certificate = $Cert }
    }
    $script:dnsFail = { [pscustomobject]@{ Status = 'Fail'; StatusCode = 'DNS_FAIL'; Error = 'mock: no such host'; Addresses = @(); ElapsedMs = 0; FromCache = $false } }
    $script:dnsPass = { [pscustomobject]@{ Status = 'Pass'; StatusCode = 'OK'; Error = ''; Addresses = @('192.0.2.10'); ElapsedMs = 0; FromCache = $false } }
}

Describe 'H3: a URL that only expired or historical certificates carry is a review item, not a failure' {
    It 'grades by what carries the URL: <Name>' -TestCases @(
        @{ Name = 'an expired certificate only'; Review = $true; Sources = @('Cert:AA01:CDP'); Carriers = @(); Certs = @(@{ Tp = 'AA01'; NotAfter = '2020-01-01T00:00:00Z'; Life = 'Current' }) }
        @{ Name = 'a historical certificate that has not expired'; Review = $true; Sources = @('Cert:AA01:CDP'); Carriers = @(); Certs = @(@{ Tp = 'AA01'; NotAfter = '2999-01-01T00:00:00Z'; Life = 'Historical' }) }
        @{ Name = 'an expired and a current certificate'; Review = $false; Sources = @('Cert:AA01:CDP', 'Cert:AA02:CDP'); Carriers = @(); Certs = @(@{ Tp = 'AA01'; NotAfter = '2020-01-01T00:00:00Z'; Life = 'Current' }, @{ Tp = 'AA02'; NotAfter = '2999-01-01T00:00:00Z'; Life = 'Current' }) }
        @{ Name = 'a certificate whose lifecycle is unknown and which has not expired'; Review = $false; Sources = @('Cert:AA01:CDP'); Carriers = @(); Certs = @(@{ Tp = 'AA01'; NotAfter = '2999-01-01T00:00:00Z'; Life = 'Unknown' }) }
        @{ Name = 'an older signing-certificate index of a CA only'; Review = $true; Sources = @('CA:Example CA:CertCdpUrls'); Carriers = @('CAIndex|Example CA|0|Historical'); Certs = @() }
        @{ Name = 'an older and the newest signing-certificate index'; Review = $false; Sources = @('CA:Example CA:CertCdpUrls'); Carriers = @('CAIndex|Example CA|0|Historical', 'CAIndex|Example CA|1|Current'); Certs = @() }
        @{ Name = 'the CA configuration without index information'; Review = $false; Sources = @('CA:Example CA:CertCdpUrls'); Carriers = @(); Certs = @() }
        @{ Name = 'Active Directory'; Review = $false; Sources = @('AD:EnrollmentServices:msPKI-Enrollment-Servers'); Carriers = @(); Certs = @() }
        @{ Name = 'an expired certificate and the current CA configuration'; Review = $false; Sources = @('Cert:AA01:CDP', 'CA:Example CA:CertCdpUrls'); Carriers = @('CAIndex|Example CA|1|Current'); Certs = @(@{ Tp = 'AA01'; NotAfter = '2020-01-01T00:00:00Z'; Life = 'Current' }) }
    ) {
        param($Name, $Review, $Sources, $Carriers, $Certs)
        $inv = [pscustomobject]@{ CACertificates = @($Certs | ForEach-Object { [pscustomobject]@{ Thumbprint = $_.Tp; Lifecycle = $_.Life; Info = [pscustomobject]@{ Subject = 'CN=Example Old CA'; NotAfter = $_.NotAfter } } }) }
        $lead = [pscustomobject]@{ Sources = $Sources; Carriers = $Carriers }
        $g = InModuleScope MspkiHealthCheck -Parameters @{ L = $lead; I = $inv } { param($L, $I) Get-MspkiLeadGrading -Lead $L -Inventory $I -Now ([DateTime]'2026-06-01T00:00:00Z') }
        $g.ReviewOnly | Should -Be $Review
        if ($Review) { $g.Reason | Should -Match 'historical or expired' } else { $g.Reason | Should -BeNullOrEmpty }
    }

    It 'turns Fail, Critical and Warning into a review item that keeps its code, and leaves everything else alone' {
        InModuleScope MspkiHealthCheck {
            foreach ($st in @('Fail', 'Critical', 'Warning')) {
                $f = New-MspkiFinding -Category CDP -Target t -Status $st -StatusCode DNS_FAIL -Sources s -Message m -Evidence @('e1')
                $r = ConvertTo-MspkiReviewFinding -Finding $f -Reason 'All carriers are expired.'
                $r.Status | Should -Be 'Information'
                $r.Severity | Should -Be 'ReviewRequired'
                $r.StatusCode | Should -Be 'DNS_FAIL'
                ($r.Evidence -join "`n") | Should -Match "Review only: All carriers are expired\. .*would have been $st"
            }
            $ok = New-MspkiFinding -Category CDP -Target t -Status Pass -StatusCode OK -Sources s -Message m
            (ConvertTo-MspkiReviewFinding -Finding $ok -Reason 'x').Status | Should -Be 'Pass'
        }
    }

    It 'end to end: a dead host on an expired certificate is Information/ReviewRequired and does not set exit code 4; the same dead host on a current certificate is a Fail' {
        $old = New-TestCertificate -Subject 'CN=Example Old CA, DC=corp, DC=example, DC=test' -DaysBefore 900 -DaysValid -30 -CdpUrls @('http://retired.corp.example.test/old.crl')
        $cur = New-TestCertificate -Subject 'CN=Example Current CA, DC=corp, DC=example, DC=test' -DaysBefore 30 -DaysValid 900 -CdpUrls @('http://dead.corp.example.test/cur.crl')
        $mk = { param($c, $life) [pscustomobject]@{ Thumbprint = $c.Public.Thumbprint; CAName = 'Example CA'; Lifecycle = $life; Info = (& $script:info $c.Public) } }
        $disc = [pscustomobject]@{
            Certificates = @{ $old.Public.Thumbprint = $old.Public; $cur.Public.Thumbprint = $cur.Public }
            Inventory = [pscustomobject]@{
                AdContext = [pscustomobject]@{ DomainController = ''; ForestDomains = @('corp.example.test'); TrustedDomains = @() }
                CACertificates = @((& $mk $old 'Historical'), (& $mk $cur 'Current')); EnterpriseCAs = @() }
        }
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName $script:dnsFail
        $f = InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } { param($D)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test'); Reset-MspkiProbeCache
            Register-MspkiDiscoveredLead -Discovery $D
            Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 3 }
        $retired = @($f | Where-Object { $_.Endpoint -like '*retired.corp.example.test*' })
        $dead = @($f | Where-Object { $_.Endpoint -like '*dead.corp.example.test*' })
        $retired.Count | Should -Be 1
        $retired[0].StatusCode | Should -Be 'DNS_FAIL'
        $retired[0].Status | Should -Be 'Information'
        $retired[0].Severity | Should -Be 'ReviewRequired'
        ($retired[0].Evidence -join "`n") | Should -Match 'Review only: Every reference to this URL is historical or expired'
        $dead.Count | Should -Be 1
        $dead[0].Status | Should -Be 'Fail'
        $dead[0].StatusCode | Should -Be 'DNS_FAIL'
        InModuleScope MspkiHealthCheck -Parameters @{ R = $retired; D = $dead } { param($R, $D)
            Get-MspkiExitCode -Findings $R | Should -Be 2
            Get-MspkiExitCode -Findings $D | Should -Be 4
            # The stale-reference review still sees the failure (it keeps its status code), so its classification does not change.
            $lead = @(Get-MspkiLead | Where-Object { $_.Host -eq 'retired.corp.example.test' })[0]
            (Get-MspkiLeadProbeOutcome -Lead $lead -Findings $R).State | Should -Be 'Unreachable'
        }
    }

    It 'registers the newest signing certificate of a CA as the current carrier and an older one as historical' {
        $ca = [pscustomobject]@{ Name = 'Example CA'; EnrollmentServers = @(); Properties = [pscustomobject]@{ SigningCertCount = 2; SigningCertificates = @(
            [pscustomobject]@{ Index = 0; CdpUrls = @('http://old.corp.example.test/a.crl', 'http://same.corp.example.test/c.crl'); AiaUrls = @(); OcspUrls = @() }
            [pscustomobject]@{ Index = 1; CdpUrls = @('http://new.corp.example.test/b.crl', 'http://same.corp.example.test/c.crl'); AiaUrls = @(); OcspUrls = @() }) } }
        $disc = [pscustomobject]@{ Certificates = @{}; Inventory = [pscustomobject]@{ CACertificates = @(); EnterpriseCAs = @($ca) } }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } { param($D)
            Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test'); Register-MspkiDiscoveredLead -Discovery $D
            @(Get-MspkiLead | ForEach-Object { [pscustomobject]@{ Host = $_.Host; Review = (Get-MspkiLeadGrading -Lead $_ -Inventory $D.Inventory).ReviewOnly } }) }
        ($r | Where-Object { $_.Host -eq 'old.corp.example.test' }).Review | Should -BeTrue
        ($r | Where-Object { $_.Host -eq 'new.corp.example.test' }).Review | Should -BeFalse
        ($r | Where-Object { $_.Host -eq 'same.corp.example.test' }).Review | Should -BeFalse
    }
}

Describe 'M3: a check that could not be done is never reported as an invalid signature' {
    BeforeEach { InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test') } }

    It 'CRL: a signature that could not be checked is not SIGNATURE_INVALID; the chain is Unknown and the note says so' {
        $crl = New-TestCrl -Issuer $script:root1
        Mock -ModuleName MspkiHealthCheck Test-MspkiSignature { [pscustomobject]@{ Valid = $null; Algorithm = '1.2.3'; Reason = 'Unsupported signature algorithm.' } }
        $f = InModuleScope MspkiHealthCheck -Parameters @{ B = $crl; R = $script:root1.Public } { param($B, $R)
            $lead = Add-MspkiLead -Url 'http://pki.corp.example.test/root.crl' -Kind CDP -Source 'test' -Origin 'test'
            Test-MspkiCrlHealth -Record ([pscustomobject]@{ Url = $lead.Url; Lead = $lead; Crl = (ConvertFrom-MspkiCrl -Bytes $B); ExpectedIssuer = @() }) -Certificates @($R) }
        $f.StatusCode | Should -Not -Be 'SIGNATURE_INVALID'
        $f.Status | Should -Be 'Pass'
        $f.ChainStatus | Should -Be 'Unknown'
        $f.Confidence | Should -Be 'Referenced'
        ($f.Evidence -join "`n") | Should -Match 'could not be checked with the certificate\(s\) named'
        $f.Notes | Should -Match 'not a bad signature'
    }

    It 'a computer whose .NET Framework lacks the signature APIs gets "could not be checked" with the reason, not an exception or a failure' {
        Mock -ModuleName MspkiHealthCheck Test-MspkiSignatureApiAvailable { $false }
        $v = InModuleScope MspkiHealthCheck -Parameters @{ B = $script:root1.Public.RawData; R = $script:root1.Public } { param($B, $R) Test-MspkiSignature -SignedBytes $B -Issuer $R }
        $v.Valid | Should -BeNullOrEmpty
        $v.Reason | Should -Match '4\.6\.2'
    }

    It 'the run records the .NET release and whether the signature APIs exist' {
        $run = InModuleScope MspkiHealthCheck { Initialize-MspkiRun }
        $run.Keys | Should -Contain 'DotNetRelease'
        $run.Keys | Should -Contain 'DotNetVersion'
        $run.Keys | Should -Contain 'SignatureApisAvailable'
        $run.Keys | Should -Contain 'TlsSecurityProtocol'
        $run.Keys | Should -Contain 'HttpProxy'
        [int]$run.DotNetRelease | Should -BeGreaterThan 0
    }

    It 'CRL: a certificate with the issuer name but another key is "issuer not found", not a bad signature' {
        $ski = InModuleScope MspkiHealthCheck -Parameters @{ C = $script:root1.Public } { param($C) Get-MspkiCertificateSubjectKeyId -Certificate $C }
        $ski | Should -Not -BeNullOrEmpty
        $crl = New-TestCrl -Issuer $script:root1 -AuthorityKeyIdHex $ski
        $run = { param($pool) InModuleScope MspkiHealthCheck -Parameters @{ B = $crl; P = $pool } { param($B, $P)
            $lead = Add-MspkiLead -Url 'http://pki.corp.example.test/root.crl' -Kind CDP -Source 'test' -Origin 'test'
            Test-MspkiCrlHealth -Record ([pscustomobject]@{ Url = $lead.Url; Lead = $lead; Crl = (ConvertFrom-MspkiCrl -Bytes $B); ExpectedIssuer = @() }) -Certificates @($P) } }
        $wrongGen = & $run @($script:root2.Public)
        $wrongGen.StatusCode | Should -Not -Be 'SIGNATURE_INVALID'
        $wrongGen.ChainStatus | Should -Be 'Unknown'
        ($wrongGen.Evidence -join "`n") | Should -Match 'another key generation of the CA'
        # With the right generation present (and the newer one listed first) the issuer is picked by key and the signature verifies.
        $both = & $run @($script:root2.Public, $script:root1.Public)
        $both.Status | Should -Be 'Pass'
        $both.Confidence | Should -Be 'Confirmed'
        ($both.Evidence -join "`n") | Should -Match 'verified with CN=Example Root CA'
    }

    It 'a chain with only another key generation of the issuer is CHAIN_PARTIAL (issuer not found), not SIGNATURE_INVALID' {
        $r = InModuleScope MspkiHealthCheck -Parameters @{ S = $script:subAki.Public; R2 = $script:root2.Public; R1 = $script:root1.Public } { param($S, $R2, $R1)
            [pscustomobject]@{
                Wrong = (Get-MspkiCertificateParent -Certificate $S -Candidates @($R2))
                Right = (Get-MspkiCertificateParent -Certificate $S -Candidates @($R2, $R1)) } }
        $r.Wrong.Status | Should -Be 'NotFound'
        $r.Wrong.Reason | Should -Match 'another key generation'
        $r.Right.Status | Should -Be 'Found'
        $r.Right.Parent.Thumbprint | Should -Be $script:root1.Public.Thumbprint
    }

    It 'a signature that cannot be checked in the CA chain is UNSUPPORTED (Information), not CHAIN_INVALID' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiCertificateParent { [pscustomobject]@{ Parent = $null; Status = 'Unverifiable'; Reason = 'Unsupported signature algorithm.' } }
        $e = & $script:entry $script:subAki.Public 'EnterpriseSubordinate' 'Current' 'Confirmed' 'Example Issuing CA'
        $f = InModuleScope MspkiHealthCheck -Parameters @{ E = $e } { param($E) Test-MspkiCACertificateHealth -Entries @($E) -TrustTest { param($tp) $true } }
        $h = @($f | Where-Object { $_.Category -eq 'Hierarchy' })
        $h.Count | Should -Be 1
        $h[0].StatusCode | Should -Be 'UNSUPPORTED'
        $h[0].Status | Should -Be 'Information'
        $h[0].ChainStatus | Should -Be 'Unknown'
    }
}

Describe 'M4: an expired certificate whose lifecycle is only inferred or unknown is a review item, not a Critical failure' {
    BeforeAll {
        $script:expired = New-TestCertificate -Subject 'CN=Example Old Root, DC=example, DC=test' -DaysBefore 900 -DaysValid -10
        $script:soon = New-TestCertificate -Subject 'CN=Example Soon Root, DC=example, DC=test' -DaysBefore 30 -DaysValid 100
    }
    It 'grades <Name> as <Status> (severity <Severity>)' -TestCases @(
        @{ Name = 'an expired certificate that is Current and Confirmed'; Cert = 'expired'; Life = 'Current'; Conf = 'Confirmed'; Status = 'Critical'; Severity = 'None' }
        @{ Name = 'an expired certificate that is Current and Referenced'; Cert = 'expired'; Life = 'Current'; Conf = 'Referenced'; Status = 'Critical'; Severity = 'None' }
        @{ Name = 'an expired certificate whose lifecycle is Current but only Inferred'; Cert = 'expired'; Life = 'Current'; Conf = 'Inferred'; Status = 'Information'; Severity = 'ReviewRequired' }
        @{ Name = 'an expired certificate whose lifecycle is Unknown'; Cert = 'expired'; Life = 'Unknown'; Conf = 'Unknown'; Status = 'Information'; Severity = 'ReviewRequired' }
        @{ Name = 'a certificate within the critical period that is Current and Confirmed'; Cert = 'soon'; Life = 'Current'; Conf = 'Confirmed'; Status = 'Critical'; Severity = 'None' }
        @{ Name = 'a certificate within the critical period whose lifecycle is only Inferred'; Cert = 'soon'; Life = 'Current'; Conf = 'Inferred'; Status = 'Warning'; Severity = 'None' }
    ) {
        param($Name, $Cert, $Life, $Conf, $Status, $Severity)
        $c = $script:expired; if ($Cert -eq 'soon') { $c = $script:soon }
        $e = & $script:entry $c.Public 'EnterpriseRoot' $Life $Conf
        $f = InModuleScope MspkiHealthCheck -Parameters @{ E = $e } { param($E) Test-MspkiCACertificateHealth -Entries @($E) -TrustTest { param($tp) $true } }
        $v = @($f | Where-Object { $_.Category -eq 'CA' })
        $v.Count | Should -Be 1
        $v[0].Status | Should -Be $Status
        $v[0].Severity | Should -Be $Severity
        if ($Cert -eq 'expired') { $v[0].StatusCode | Should -Be 'OBJECT_EXPIRED' }
    }
}

Describe 'M5: a reference to another environment goes to review and is never a failure' {
    It 'caps <Status> at Warning/ReviewRequired for scope <Scope>: <Capped>' -TestCases @(
        @{ Scope = 'Local'; Status = 'Fail'; Capped = $false; Result = 'Fail' }
        @{ Scope = 'Unknown'; Status = 'Critical'; Capped = $false; Result = 'Critical' }
        @{ Scope = 'External'; Status = 'Fail'; Capped = $true; Result = 'Warning' }
        @{ Scope = 'OtherForest'; Status = 'Critical'; Capped = $true; Result = 'Warning' }
        @{ Scope = 'External'; Status = 'Warning'; Capped = $false; Result = 'Warning' }
        @{ Scope = 'External'; Status = 'Pass'; Capped = $false; Result = 'Pass' }
    ) {
        param($Scope, $Status, $Capped, $Result)
        $r = InModuleScope MspkiHealthCheck -Parameters @{ S = $Scope; T = $Status } { param($S, $T) Resolve-MspkiScopeStatus -Status $T -Scope $S }
        $r.Capped | Should -Be $Capped
        $r.Status | Should -Be $Result
        if ($Capped) { $r.Severity | Should -Be 'ReviewRequired'; $r.Evidence | Should -Match 'would have been' } else { $r.Evidence | Should -BeNullOrEmpty }
    }

    It 'an endpoint on a host outside the forest is a review item; the same failure on a host inside the forest is a Fail' {
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName $script:dnsFail
        $r = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test') -TrustedDomains @('partner.example.test'); Reset-MspkiProbeCache
            foreach ($u in @('http://pki.corp.example.test/a.crl', 'http://pki.partner.example.test/a.crl', 'http://pki.elsewhere.example.test/a.crl')) {
                $lead = Add-MspkiLead -Url $u -Kind CDP -Source 'test' -Origin 'test'
                (Test-MspkiLeadEndpoint -Lead $lead -Url $lead.Url).Findings[0] } }
        $r[0].Status | Should -Be 'Fail'
        $r[0].Severity | Should -Be 'None'
        foreach ($i in 1, 2) {
            $r[$i].Status | Should -Be 'Warning'
            $r[$i].Severity | Should -Be 'ReviewRequired'
            $r[$i].StatusCode | Should -Be 'DNS_FAIL'
            ($r[$i].Evidence -join "`n") | Should -Match 'capped at Warning'
        }
        $r[1].Scope | Should -Be 'OtherForest'
        $r[2].Scope | Should -Be 'External'
    }

    It 'a CEP or CES endpoint on a host outside the forest that does not resolve is a review item' {
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName $script:dnsFail
        $r = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test'); Reset-MspkiProbeCache
            foreach ($u in @('https://ces.corp.example.test/ca_CES_Kerberos/service.svc', 'https://ces.elsewhere.example.test/ca_CES_Kerberos/service.svc')) {
                $lead = Add-MspkiLead -Url $u -Kind CES -Source 'AD:EnrollmentServices:msPKI-Enrollment-Servers' -Origin 'test'
                (Test-MspkiEnrollmentEndpoint -Lead $lead -Url $lead.Url -TimeoutSeconds 3).Findings[0] } }
        $r[0].Status | Should -Be 'Fail'
        $r[1].Status | Should -Be 'Warning'
        $r[1].Severity | Should -Be 'ReviewRequired'
    }

    It 'a CA host outside the forest that does not resolve is a review item; inside the forest it is a Fail' {
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName $script:dnsFail
        $r = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun)
            $ctx = [pscustomobject]@{ ForestDomains = @('corp.example.test'); TrustedDomains = @() }
            foreach ($h in @('ca01.corp.example.test', 'ca01.elsewhere.example.test')) {
                $ca = [pscustomobject]@{ Name = 'Example CA'; CommonName = 'ExampleCA'; DnsHostName = $h; Config = ('{0}\Example CA' -f $h) }
                (Get-MspkiCAProperty -CA $ca -Context $ctx -TimeoutSeconds 3).Findings[0] } }
        $r[0].Status | Should -Be 'Fail'
        $r[0].StatusCode | Should -Be 'DNS_FAIL'
        $r[1].Status | Should -Be 'Warning'
        $r[1].Severity | Should -Be 'ReviewRequired'
        $r[1].StatusCode | Should -Be 'DNS_FAIL'
    }
}

Describe 'M8: Confirmed only when the content was validated' {
    BeforeAll {
        $script:match = { param($Downloaded, $Lead, $Known = @{}, $Expected = @())
            InModuleScope MspkiHealthCheck -Parameters @{ D = $Downloaded; L = $Lead; K = $Known; E = $Expected } { param($D, $L, $K, $E) Test-MspkiAiaCertificateMatch -Downloaded $D -Lead $L -KnownCertificates $K -ExpectedIssuer $E } }
        $script:refTp = $script:subAki.Public.Thumbprint
        $script:refLead = [pscustomobject]@{ Sources = @(('Cert:{0}:AIA' -f $script:refTp)) }
    }
    It 'Verified: the referencing certificate verifies with the key of the downloaded one' {
        $m = & $script:match $script:root1.Public $script:refLead @{ $script:refTp = $script:subAki.Public } @('CN=Example Root CA, DC=example, DC=test')
        $m.Result | Should -Be 'Verified'
        ($m.Lines -join "`n") | Should -Match 'verifies with this certificate''s key'
    }
    It 'KeyMismatch: the expected name, but another key generation' {
        $m = & $script:match $script:root2.Public $script:refLead @{ $script:refTp = $script:subAki.Public } @('CN=Example Root CA, DC=example, DC=test')
        $m.Result | Should -Be 'KeyMismatch'
        ($m.Lines -join "`n") | Should -Match 'does NOT verify'
    }
    It 'NotVerifiable: the name matches but there is nothing to verify against' {
        $m = & $script:match $script:root1.Public ([pscustomobject]@{ Sources = @('CA:Example CA:CertAiaUrls') }) @{} @('CN=Example Root CA, DC=example, DC=test')
        $m.Result | Should -Be 'NotVerifiable'
        ($m.Lines -join "`n") | Should -Match 'only the subject name was compared'
    }
    It 'NameMismatch: a certificate for another subject' {
        (& $script:match $script:root2.Public $script:refLead @{} @('CN=Someone Else')).Result | Should -Be 'NameMismatch'
    }
    It 'Verified: byte-identical to a CA certificate that is already known from AD or the CA' {
        $m = & $script:match $script:root1.Public ([pscustomobject]@{ Sources = @('CA:Example CA:CertAiaUrls') }) @{ $script:root1.Public.Thumbprint = $script:root1.Public }
        $m.Result | Should -Be 'Verified'
    }
    It 'NotVerifiable when the signature cannot be checked, never KeyMismatch' {
        Mock -ModuleName MspkiHealthCheck Test-MspkiSignature { [pscustomobject]@{ Valid = $null; Algorithm = ''; Reason = 'no API' } }
        $m = & $script:match $script:root2.Public $script:refLead @{ $script:refTp = $script:subAki.Public } @('CN=Example Root CA, DC=example, DC=test')
        $m.Result | Should -Be 'NotVerifiable'
    }
}

Describe 'CA connection: connection strings, trace, and classification of the first call (M10, logging)' {
    BeforeAll {
        $script:caObj = [pscustomobject]@{ Name = 'Example Issuing CA'; CommonName = 'ExampleIssuingCA'; DisplayName = 'Example Issuing CA'; DnsHostName = 'ca01.corp.example.test'; Config = 'ca01.corp.example.test\Example Issuing CA' }
        $script:ctx = [pscustomobject]@{ ForestDomains = @('corp.example.test'); TrustedDomains = @() }
        $script:read = { param($Ca = $script:caObj) InModuleScope MspkiHealthCheck -Parameters @{ C = $Ca; X = $script:ctx } { param($C, $X) Get-MspkiCAProperty -CA $C -Context $X -TimeoutSeconds 3 } }
        $script:fatal = { param($hr, $msg) [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 7; Errors = @(); Output = @(@{ Values = @{}; Errors = @{}; Count = -1; Fatal = @{ HResult = $hr; Message = $msg }; Trace = @(@{ Name = 'CAType'; Id = 10; Index = 0; DataType = 1; ResultType = 'error'; Size = 0; ElapsedMs = 6; HResult = $hr }) }) } }
    }
    BeforeEach {
        InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun) }
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName $script:dnsPass
        Mock -ModuleName MspkiHealthCheck Test-MspkiTcpPort { [pscustomobject]@{ Status = 'Pass'; StatusCode = 'OK'; Error = ''; ElapsedMs = 1; FromCache = $false } }
    }

    It 'tries the common name after "file not found", keeps the string that answered, and lists every attempt' {
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 7; Errors = @(); Output = @(@{ Values = @{}; Errors = @{}; Count = -1; Fatal = @{ HResult = '80070002'; Message = 'The system cannot find the file specified.' }; Trace = @() }) } } -ParameterFilter { $ArgumentList[0] -like '*\Example Issuing CA' }
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 9; Errors = @(); Output = @(@{ Values = @{ CAType = 1; CAName = 'Example Issuing CA'; DnsName = 'ca01.corp.example.test' }; Errors = @{}; Count = 0; Fatal = $null; Trace = @(@{ Name = 'CAType'; Id = 10; Index = 0; DataType = 1; ResultType = 'Int32'; Size = 0; ElapsedMs = 3; HResult = '' }) }) } } -ParameterFilter { $ArgumentList[0] -like '*\ExampleIssuingCA' }
        $r = & $script:read
        $r.Data.ConfigUsed | Should -Be 'ca01.corp.example.test\ExampleIssuingCA'
        $ev = ($r.Findings[0].Evidence -join "`n")
        $ev | Should -Match 'Connection string that answered: ca01\.corp\.example\.test\\ExampleIssuingCA'
        $ev | Should -Match 'ca01\.corp\.example\.test\\Example Issuing CA -> Failed 0x80070002'
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript -Times 2 -Exactly
    }

    It 'reports "no CA of that name" (after every string) as Fail/RETRIEVAL_FAIL and names the strings tried, not as UNSUPPORTED or NOT_DISCOVERED' {
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 7; Errors = @(); Output = @(@{ Values = @{}; Errors = @{}; Count = -1; Fatal = @{ HResult = '80070057'; Message = 'The parameter is incorrect.' }; Trace = @() }) } }
        $r = & $script:read
        $f = $r.Findings[0]
        $f.Status | Should -Be 'Fail'
        $f.StatusCode | Should -Be 'RETRIEVAL_FAIL'
        $f.Message | Should -Match 'no Certification Authority named Example Issuing CA was found'
        ($f.Evidence -join "`n") | Should -Match 'Example Issuing CA -> Failed 0x80070057'
        ($f.Evidence -join "`n") | Should -Match 'ExampleIssuingCA -> Failed 0x80070057'
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript -Times 2 -Exactly
    }

    It 'does not try another string after <Name>' -TestCases @(
        @{ Name = 'a quick RPC failure'; Hr = '800706BA'; Code = 'PERMISSION_DENIED' }
        @{ Name = 'access denied'; Hr = '80070005'; Code = 'PERMISSION_DENIED' }
    ) {
        param($Name, $Hr, $Code)
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript ([scriptblock]::Create(("[pscustomobject]@{{ Completed = `$true; TimedOut = `$false; ElapsedMs = 7; Errors = @(); Output = @(@{{ Values = @{{}}; Errors = @{{}}; Count = -1; Fatal = @{{ HResult = '{0}'; Message = 'x' }}; Trace = @() }}) }}" -f $Hr)))
        $r = & $script:read
        $r.Findings[0].StatusCode | Should -Be $Code
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript -Times 1 -Exactly
    }

    It 'reports a COM class that is not registered on this computer as UNSUPPORTED (a limit of this computer, not of the CA)' {
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 7; Errors = @(); Output = @(@{ Values = @{}; Errors = @{}; Count = -1; Fatal = @{ HResult = '80040154'; Message = 'Class not registered' }; Trace = @() }) } }
        $f = (& $script:read).Findings[0]
        $f.Status | Should -Be 'Skipped'
        $f.StatusCode | Should -Be 'UNSUPPORTED'
        $f.Notes | Should -Match 'computer running the tool'
    }

    It 'logs every connection string, every property id with the type of the raw result and its time, and never a value' {
        Mock -ModuleName MspkiHealthCheck Write-MspkiLog { }
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 9; Errors = @(); Output = @(@{
            Values = @{ CAType = 1; CAName = 'SECRET-VALUE-MUST-NOT-BE-LOGGED'; DnsName = 'ca01.corp.example.test' }; Errors = @{}; Count = 0; Fatal = $null
            Trace = @(@{ Name = 'CAType'; Id = 10; Index = 0; DataType = 1; ResultType = 'Int32'; Size = 0; ElapsedMs = 3; HResult = '' }
                      @{ Name = 'CASigCert'; Id = 12; Index = 1; DataType = 3; ResultType = 'String'; Size = 1800; ElapsedMs = 11; HResult = '' }
                      @{ Name = 'BaseCrl'; Id = 17; Index = 1; DataType = 3; ResultType = 'error'; Size = 0; ElapsedMs = 2; HResult = '80094004' }) }) } }
        $null = & $script:read
        Should -Invoke -ModuleName MspkiHealthCheck Write-MspkiLog -ParameterFilter { $Message -like 'CA connection string tried (1 of 2): ca01.corp.example.test\Example Issuing CA*' }
        Should -Invoke -ModuleName MspkiHealthCheck Write-MspkiLog -ParameterFilter { $Message -like 'GetCAProperty CAType (property id 10, index 0, requested data type 1)*result type Int32, size 0 after 3 ms' }
        Should -Invoke -ModuleName MspkiHealthCheck Write-MspkiLog -ParameterFilter { $Message -like 'GetCAProperty CASigCert (property id 12, index 1, requested data type 3)*result type String, size 1800 after 11 ms' }
        Should -Invoke -ModuleName MspkiHealthCheck Write-MspkiLog -ParameterFilter { $Message -like 'GetCAProperty BaseCrl (property id 17*error 0x80094004 after 2 ms' }
        Should -Invoke -ModuleName MspkiHealthCheck Write-MspkiLog -Times 0 -Exactly -ParameterFilter { $Message -like '*SECRET-VALUE*' }
    }

    It 'the reader traces property id, index, data type, result type, size, time and error code, and no value' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Discovery\CAProperty.ps1') -Raw
        $src | Should -Match 'ResultType = \$rt; Size = \$size; ElapsedMs'
        $src | Should -Not -Match 'Value\s*=\s*\$v\b'
    }
}

Describe 'M10: a CRL dated in the future is clock skew, not stale data' {
    It 'labels a CRL whose thisUpdate is in the future as CLOCK_SKEW' {
        $crl = New-TestCrl -Issuer $script:root1 -HoursBefore -3 -HoursValid 48
        $f = InModuleScope MspkiHealthCheck -Parameters @{ B = $crl } { param($B) Get-MspkiCrlFreshness -Crl (ConvertFrom-MspkiCrl -Bytes $B) }
        $f.StatusCode | Should -Be 'CLOCK_SKEW'
        $f.Status | Should -Be 'Warning'
    }
}

Describe 'M11: -SkipNetwork reaches no host at any stage' {
    It 'the endpoint, CEP/CES and NDES stages send nothing, resolve nothing and bind to nothing' {
        $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root1.Full -DaysValid 900 `
            -CdpUrls @('http://pki.corp.example.test/ca.crl', 'ldap://dc02.corp.example.test/CN=ca,CN=CDP,DC=corp,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint') `
            -AiaUrls @('https://pki.corp.example.test/ca.crt') -OcspUrls @('http://ocsp.corp.example.test/ocsp')
        $disc = [pscustomobject]@{
            Certificates = @{ $sub.Public.Thumbprint = $sub.Public }
            Inventory = [pscustomobject]@{
                AdContext = [pscustomobject]@{ DomainController = 'dc01.corp.example.test'; ForestDomains = @('corp.example.test'); TrustedDomains = @(); Ready = $false }
                CACertificates = @([pscustomobject]@{ Thumbprint = $sub.Public.Thumbprint; CAName = 'Example Issuing CA'; Lifecycle = 'Current'; Info = [pscustomobject]@{ Subject = $sub.Public.Subject; NotAfter = '2999-01-01T00:00:00Z' } })
                EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Config = 'ca01.corp.example.test\Example Issuing CA'; DnsHostName = 'ca01.corp.example.test'; Templates = @(); Properties = $null
                    EnrollmentServers = @([pscustomobject]@{ Url = 'https://ces.corp.example.test/ca_CES_Kerberos/service.svc'; AuthName = 'Kerberos'; AuthType = 2; Priority = 1; RenewalOnly = $false }) })
                CepPolicies = @([pscustomobject]@{ IsWebService = $true; Url = 'https://cep.corp.example.test/ADPolicyProvider_CEP_Kerberos/service.svc'; Source = 'Policy:CEP:HKLM'; Managed = 'Group Policy (computer)'; KeyName = 'k1'; FriendlyName = '' })
                TemplatesRead = $false; Templates = @()
            }
        }
        foreach ($fn in @('Invoke-MspkiHttpGet', 'Resolve-MspkiDnsName', 'Resolve-MspkiDnsEntry', 'Test-MspkiTcpPort', 'Test-MspkiTlsEndpoint', 'Get-MspkiLdapObject', 'Invoke-MspkiTimeLimitedScript')) {
            Mock -ModuleName MspkiHealthCheck $fn { throw 'must not be called with -SkipNetwork' }
        }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } { param($D)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test'); Reset-MspkiProbeCache
            Register-MspkiDiscoveredLead -Discovery $D
            [pscustomobject]@{
                Endpoints = (Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 3 -SkipNetwork)
                Enrollment = (Invoke-MspkiEnrollmentServiceAnalysis -Discovery $D -TimeoutSeconds 3 -SkipNetwork)
                Ndes = (Invoke-MspkiNdesAnalysis -Discovery $D -TimeoutSeconds 3 -SkipNetwork -IncludeAdminProbe) } }
        foreach ($fn in @('Invoke-MspkiHttpGet', 'Resolve-MspkiDnsName', 'Resolve-MspkiDnsEntry', 'Test-MspkiTcpPort', 'Test-MspkiTlsEndpoint', 'Get-MspkiLdapObject', 'Invoke-MspkiTimeLimitedScript')) {
            Should -Invoke -ModuleName MspkiHealthCheck $fn -Times 0 -Exactly
        }
        @($r.Endpoints | Where-Object { $_.Status -eq 'Skipped' }).Count | Should -BeGreaterThan 2
        @($r.Endpoints | Where-Object { $_.Status -in @('Fail', 'Critical', 'Error') }).Count | Should -Be 0
        @($r.Enrollment | Where-Object { $_.Status -eq 'Skipped' }).Count | Should -BeGreaterThan 1
        @($r.Enrollment | Where-Object { $_.Status -in @('Fail', 'Critical', 'Error') }).Count | Should -Be 0
        @($r.Ndes.Findings | Where-Object { $_.Status -in @('Fail', 'Critical', 'Error') }).Count | Should -Be 0
        $ldap = @($r.Endpoints | Where-Object { $_.Endpoint -like 'ldap://dc02*' })
        $ldap.Count | Should -Be 1
        $ldap[0].Status | Should -Be 'Skipped'
    }
}
