BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    $script:sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900
    $script:impostor = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysValid 100

    $script:newLead = {
        param([string]$Url, [string]$Kind = 'CDP', [string]$Source = 'test:source')
        InModuleScope MspkiHealthCheck -Parameters @{ U = $Url; K = $Kind; S = $Source } {
            param($U, $K, $S)
            Add-MspkiLead -Url $U -Kind $K -Source $S -Origin 'test'
        }
    }
}

Describe 'CRL decoding and freshness' {
    It 'decodes a base CRL with Freshest CRL and a delta CRL' {
        $base = New-TestCrl -Issuer $script:root -Number 5 -FreshestUrls @('http://pki.corp.example.test/CertEnroll/Example Root CA+.crl')
        $delta = New-TestCrl -Issuer $script:root -Number 6 -Delta -BaseNumber 5 -HoursValid 48
        InModuleScope MspkiHealthCheck -Parameters @{ B = $base; D = $delta } {
            param($B, $D)
            $c = ConvertFrom-MspkiCrl -Bytes $B
            $c.Issuer | Should -Be 'CN=Example Root CA, DC=example, DC=test'
            $c.CrlNumber | Should -Be '05'
            $c.IsDelta | Should -BeFalse
            $c.FreshestCrlUrls | Should -Be @('http://pki.corp.example.test/CertEnroll/Example Root CA+.crl')
            $c.ThisUpdate.Kind | Should -Be 'Utc'
            $d = ConvertFrom-MspkiCrl -Bytes $D
            $d.IsDelta | Should -BeTrue
            $d.BaseCrlNumber | Should -Be '05'
            { ConvertFrom-MspkiCrl -Bytes ([System.Text.Encoding]::ASCII.GetBytes('-----BEGIN X509 CRL-----')) } | Should -Throw
        }
    }

    It 'grades <Before>h of <Valid>h as <Status>/<Code>' -TestCases @(
        @{ Before = 24; Valid = 240; Status = 'Pass'; Code = 'OK' }
        @{ Before = 192; Valid = 240; Status = 'Warning'; Code = 'OBJECT_EXPIRING' }
        @{ Before = 235; Valid = 240; Status = 'Critical'; Code = 'OBJECT_EXPIRING' }
        @{ Before = 250; Valid = 240; Status = 'Fail'; Code = 'OBJECT_EXPIRED' }
    ) {
        param($Before, $Valid, $Status, $Code)
        $b = New-TestCrl -Issuer $script:root -HoursBefore $Before -HoursValid $Valid
        InModuleScope MspkiHealthCheck -Parameters @{ B = $b; S = $Status; C = $Code } {
            param($B, $S, $C)
            $f = Get-MspkiCrlFreshness -Crl (ConvertFrom-MspkiCrl -Bytes $B)
            $f.Status | Should -Be $S
            $f.StatusCode | Should -Be $C
        }
    }

    It 'treats a CRL without nextUpdate as not applicable' {
        $b = New-TestCrl -Issuer $script:root -NoNextUpdate
        InModuleScope MspkiHealthCheck -Parameters @{ B = $b } {
            param($B)
            (Get-MspkiCrlFreshness -Crl (ConvertFrom-MspkiCrl -Bytes $B)).Status | Should -Be 'NotApplicable'
        }
    }
}

Describe 'Test-MspkiCrlHealth' {
    # The forest's own domain is registered, so pki.corp.example.test is Local and failures are graded in full (see Audit.Tests.ps1 for the scope rule).
    BeforeEach { InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test') } }

    It 'confirms a CRL whose signature verifies and uses root thresholds for a root issuer' {
        $b = New-TestCrl -Issuer $script:root
        $lead = & $script:newLead 'http://pki.corp.example.test/root.crl'
        InModuleScope MspkiHealthCheck -Parameters @{ B = $b; L = $lead; R = $script:root.Public; S = $script:sub.Public } {
            param($B, $L, $R, $S)
            $rec = [pscustomobject]@{ Url = $L.Url; Lead = $L; Crl = (ConvertFrom-MspkiCrl -Bytes $B); ExpectedIssuer = @($S.Issuer) }
            $f = Test-MspkiCrlHealth -Record $rec -Certificates @($R, $S)
            $f.Status | Should -Be 'Pass'
            $f.Confidence | Should -Be 'Confirmed'
            $f.ChainStatus | Should -Be 'Pass'
            ($f.Evidence -join ' ') | Should -Match 'root CA'
            ($f.Evidence -join ' ') | Should -Match 'Delta CRLs: not referenced'
        }
    }

    It 'separates bad signature, unknown issuer, wrong issuer and base-at-delta-location' {
        $b = New-TestCrl -Issuer $script:root
        $lead = & $script:newLead 'http://pki.corp.example.test/root.crl'
        $dLead = & $script:newLead 'http://pki.corp.example.test/root+.crl' 'FreshestCRL'
        InModuleScope MspkiHealthCheck -Parameters @{ B = $b; L = $lead; DL = $dLead; R = $script:root.Public; I = $script:impostor.Public } {
            param($B, $L, $DL, $R, $I)
            $crl = ConvertFrom-MspkiCrl -Bytes $B
            $rec = { param($lead, $exp) [pscustomobject]@{ Url = $lead.Url; Lead = $lead; Crl = $crl; ExpectedIssuer = $exp } }
            $bad = Test-MspkiCrlHealth -Record (& $rec $L @()) -Certificates @($I)
            $bad.StatusCode | Should -Be 'SIGNATURE_INVALID'
            $bad.Status | Should -Be 'Fail'
            $unknown = Test-MspkiCrlHealth -Record (& $rec $L @()) -Certificates @()
            $unknown.Confidence | Should -Be 'Referenced'
            $unknown.ChainStatus | Should -Be 'Unknown'
            $unknown.Notes | Should -Match 'could not be validated'
            $wrong = Test-MspkiCrlHealth -Record (& $rec $L @('CN=Other CA, DC=example, DC=test')) -Certificates @($R)
            $wrong.StatusCode | Should -Be 'CONTENT_MISMATCH'
            $notDelta = Test-MspkiCrlHealth -Record (& $rec $DL @()) -Certificates @($R)
            $notDelta.StatusCode | Should -Be 'CONTENT_MISMATCH'
            $notDelta.Message | Should -Match 'not a delta'
        }
    }

    It 'reports a location that serves an older CRL number as STALE_DATA' {
        $old = New-TestCrl -Issuer $script:root -Number 5
        $new = New-TestCrl -Issuer $script:root -Number 7
        $l1 = & $script:newLead 'http://pki.corp.example.test/a.crl'
        $l2 = & $script:newLead 'ldap:///CN=Example Root CA,CN=CDP,DC=corp,DC=example,DC=test?certificateRevocationList'
        InModuleScope MspkiHealthCheck -Parameters @{ O = $old; N = $new; L1 = $l1; L2 = $l2 } {
            param($O, $N, $L1, $L2)
            $r = @(
                [pscustomobject]@{ Url = $L1.Url; Lead = $L1; Crl = (ConvertFrom-MspkiCrl -Bytes $N); ExpectedIssuer = @() }
                [pscustomobject]@{ Url = $L2.Url; Lead = $L2; Crl = (ConvertFrom-MspkiCrl -Bytes $O); ExpectedIssuer = @() }
            )
            $f = Test-MspkiCrlConsistency -Records $r
            $f.Count | Should -Be 1
            $f[0].StatusCode | Should -Be 'STALE_DATA'
            $f[0].Endpoint | Should -Be $L2.Url
        }
    }
}

Describe 'LDAP URLs' {
    It 'parses a CDP LDAP URL' {
        InModuleScope MspkiHealthCheck {
            $p = ConvertFrom-MspkiLdapUrl -Url 'ldap:///CN=Example%20Root%20CA,CN=ca00,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint'
            $p.Host | Should -Be ''
            $p.DN | Should -Be 'CN=Example Root CA,CN=ca00,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test'
            $p.Attribute | Should -Be 'certificateRevocationList'
            $p.Scope | Should -Be 'base'
            $p.Filter | Should -Be '(objectClass=cRLDistributionPoint)'
            (ConvertFrom-MspkiLdapUrl -Url 'ldap://dc01.corp.example.test/CN=x?cACertificate;binary').Attribute | Should -Be 'cACertificate'
        }
    }

    It 'reads a CRL from LDAP and keeps missing values and permission problems apart' {
        $b = New-TestCrl -Issuer $script:root
        $script:ldapCrl = $b
        $url = 'ldap:///CN=Example Root CA,CN=ca00,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint'
        InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun) }
        $lead = & $script:newLead $url
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { @{ certificaterevocationlist = @(, $script:ldapCrl) } }
        $ok = InModuleScope MspkiHealthCheck -Parameters @{ L = $lead } { param($L) Test-MspkiLeadEndpoint -Lead $L -Url $L.Url -DomainController 'dc01.corp.example.test' -SkipNetwork }
        $ok.Findings[0].Status | Should -Be 'Pass'
        $ok.Findings[0].HttpStatus | Should -Be 'NotApplicable'
        $ok.Crl | Should -Not -BeNullOrEmpty

        InModuleScope MspkiHealthCheck { Reset-MspkiProbeCache }
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { @{ cn = @('x') } }
        $empty = InModuleScope MspkiHealthCheck -Parameters @{ L = $lead } { param($L) Test-MspkiLeadEndpoint -Lead $L -Url $L.Url }
        $empty.Findings[0].StatusCode | Should -Be 'PUBLICATION_FAIL'

        InModuleScope MspkiHealthCheck { Reset-MspkiProbeCache }
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw (New-Object System.Runtime.InteropServices.COMException('Access is denied.', [int]0x80070005)) }
        $denied = InModuleScope MspkiHealthCheck -Parameters @{ L = $lead } { param($L) Test-MspkiLeadEndpoint -Lead $L -Url $L.Url }
        $denied.Findings[0].StatusCode | Should -Be 'PERMISSION_DENIED'
        $denied.Findings[0].Status | Should -Be 'Skipped'
    }

    It 'reads the default attribute from a CDP LDAP URL that names no attribute (valid, as a CA writes it): Pass, not Fail' {
        $script:ldapCrl2 = New-TestCrl -Issuer $script:root
        $url = 'ldap:///CN=Example Issuing CA,CN=ca02,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test'
        InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun) }
        $lead = & $script:newLead $url
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { @{ certificaterevocationlist = @(, $script:ldapCrl2) } }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ L = $lead } { param($L) Test-MspkiLeadEndpoint -Lead $L -Url $L.Url -DomainController 'dc01.corp.example.test' -SkipNetwork }
        $r.Findings[0].Status | Should -Be 'Pass'
        $r.Crl | Should -Not -BeNullOrEmpty
        ($r.Findings[0].Evidence -join "`n") | Should -Match 'names no attribute; read certificateRevocationList'
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 1 -Exactly -ParameterFilter { @($Properties) -contains 'certificateRevocationList' }
    }

    It 'still fails an LDAP URL without an attribute when the object has no CRL (negative case)' {
        $url = 'ldap:///CN=Example Issuing CA,CN=ca02,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test'
        InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun) }
        $lead = & $script:newLead $url
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { @{ cn = @('x') } }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ L = $lead } { param($L) Test-MspkiLeadEndpoint -Lead $L -Url $L.Url -DomainController 'dc01.corp.example.test' -SkipNetwork }
        $r.Findings[0].StatusCode | Should -Be 'PUBLICATION_FAIL'
        InModuleScope MspkiHealthCheck { Get-MspkiLdapDefaultAttribute -Kind 'AIA' } | Should -Be 'cACertificate'
        InModuleScope MspkiHealthCheck { Get-MspkiLdapDefaultAttribute -Kind 'FreshestCRL' } | Should -Be 'deltaRevocationList'
    }
}

Describe 'HTTP probes against a loopback test server' {
    BeforeAll {
        $script:baseCrl = New-TestCrl -Issuer $script:root -Number 3 -FreshestUrls @('http://127.0.0.1:1/placeholder')
        $script:routes = [hashtable]::Synchronized(@{})
        $script:server = Start-TestHttpServer -Routes $script:routes
        $b = $script:server.Base
        $script:deltaCrl = New-TestCrl -Issuer $script:root -Number 4 -Delta -BaseNumber 3 -HoursValid 48
        $script:baseCrl = New-TestCrl -Issuer $script:root -Number 3 -FreshestUrls @("$b/root+.crl")
        $script:routes['/root.crl'] = @{ Status = 200; Body = $script:baseCrl; Headers = @{ 'Content-Type' = 'application/pkix-crl' } }
        $script:routes['/root+.crl'] = @{ Status = 200; Body = $script:deltaCrl }
        $script:routes['/old.crl'] = @{ Status = 302; Body = @(); Headers = @{ Location = '/root.crl' } }
        $script:routes['/root.crt'] = @{ Status = 200; Body = $script:root.Public.RawData }
        $script:routes['/garbage.crt'] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('hello') }
        $script:routes['/denied.crl'] = @{ Status = 401; Body = @() }
        $script:routes['/broken.crl'] = @{ Status = 500; Body = @() }
        $script:routes['/big.crl'] = @{ Status = 200; Body = (New-Object byte[] 5000) }
    }
    AfterAll { Stop-TestHttpServer -Server $script:server }
    BeforeEach { InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun) } }

    It 'gets 200, follows a redirect, separates 401/404/500 and caps the size, never sending credentials' {
        InModuleScope MspkiHealthCheck -Parameters @{ B = $script:server.Base } {
            param($B)
            $ok = Invoke-MspkiHttpGet -Url "$B/root.crl" -TimeoutMs 5000
            $ok.Code | Should -Be 'OK'
            $ok.HttpStatus | Should -Be 200
            $ok.Bytes.Length | Should -BeGreaterThan 100
            $ok.ContentType | Should -Be 'application/pkix-crl'
            $r = Invoke-MspkiHttpGet -Url "$B/old.crl" -TimeoutMs 5000
            $r.Redirected | Should -BeTrue
            $r.Hops.Count | Should -Be 2
            $r.Code | Should -Be 'OK'
            (Invoke-MspkiHttpGet -Url "$B/missing.crl").Code | Should -Be 'HTTP_404'
            (Invoke-MspkiHttpGet -Url "$B/denied.crl").Code | Should -Be 'HTTP_401_403'
            (Invoke-MspkiHttpGet -Url "$B/broken.crl").Code | Should -Be 'HTTP_500'
            $big = Invoke-MspkiHttpGet -Url "$B/big.crl" -MaxBytes 1024
            $big.Code | Should -Be 'SIZE_LIMIT'
            $big.Bytes | Should -BeNullOrEmpty
            (Invoke-MspkiHttpGet -Url "$B/root.crl").FromCache | Should -BeTrue
        }
        @($script:server.Log | Where-Object { ($_.Headers -join "`n") -match '(?im)^(Authorization|Proxy-Authorization):' }).Count | Should -Be 0
        @($script:server.Log | Where-Object { $_.Path -eq '/root.crl' }).Count | Should -Be 2
    }

    It 'checks AIA and CDP leads layer by layer and validates the content' {
        $b = $script:server.Base
        $aia = & $script:newLead "$b/root.crt" 'AIA'
        $bad = & $script:newLead "$b/garbage.crt" 'AIA'
        $cdp = & $script:newLead "$b/old.crl" 'CDP'
        $miss = & $script:newLead "$b/root+missing+.crl" 'CDP'
        $ocsp = & $script:newLead "$b/ocsp" 'OCSP'
        InModuleScope MspkiHealthCheck -Parameters @{ A = $aia; Bad = $bad; C = $cdp; M = $miss; O = $ocsp; Root = $script:root.Public } {
            param($A, $Bad, $C, $M, $O, $Root)
            # Same name alone is not proof: without a way to verify the key the result is Pass but only Referenced, and nothing is followed.
            $rn = Test-MspkiLeadEndpoint -Lead $A -Url $A.Url -ExpectedIssuer @($Root.Subject)
            $rn.Findings[0].Status | Should -Be 'Pass'
            $rn.Findings[0].Confidence | Should -Be 'Referenced'
            $rn.Validated | Should -BeFalse
            $ra = Test-MspkiLeadEndpoint -Lead $A -Url $A.Url -ExpectedIssuer @($Root.Subject) -KnownCertificate @{ $Root.Thumbprint = $Root }
            $ra.Findings[0].Status | Should -Be 'Pass'
            $ra.Findings[0].Confidence | Should -Be 'Confirmed'
            $ra.Validated | Should -BeTrue
            $ra.Findings[0].DnsStatus | Should -Be 'Pass'
            $ra.Findings[0].TcpStatus | Should -Be 'Pass'
            $ra.Findings[0].HttpStatus | Should -Be 'Pass'
            $ra.Findings[0].ContentStatus | Should -Be 'Pass'
            $ra.Certificate.Thumbprint | Should -Be $Root.Thumbprint
            (Test-MspkiLeadEndpoint -Lead $A -Url $A.Url -ExpectedIssuer @('CN=Someone Else')).Findings[0].StatusCode | Should -Be 'CONTENT_MISMATCH'
            (Test-MspkiLeadEndpoint -Lead $Bad -Url $Bad.Url).Findings[0].StatusCode | Should -Be 'CONTENT_WRONG_TYPE'
            $rc = Test-MspkiLeadEndpoint -Lead $C -Url $C.Url
            @($rc.Findings).Count | Should -Be 2
            ($rc.Findings | Where-Object StatusCode -eq 'HTTP_REDIRECT').Status | Should -Be 'Information'
            ($rc.Findings | Where-Object StatusCode -eq 'OK').RedirectStatus | Should -Be 'Warning'
            $rc.Crl.CrlNumber | Should -Be '03'
            $rm = Test-MspkiLeadEndpoint -Lead $M -Url $M.Url
            $rm.Findings[0].StatusCode | Should -Be 'HTTP_404'
            $rm.Findings[0].Notes | Should -Match 'double escaping'
            $ro = Test-MspkiLeadEndpoint -Lead $O -Url $O.Url
            $ro.Findings[0].Status | Should -Be 'Information'
            $ro.Findings[0].HttpStatus | Should -Be 'NotTested'
            (Test-MspkiLeadEndpoint -Lead $C -Url $C.Url -SkipNetwork).Findings[0].Status | Should -Be 'Skipped'
        }
        @($script:server.Log | Where-Object { $_.Path -eq '/ocsp' }).Count | Should -Be 0
    }

    It 'follows the Freshest CRL link of a downloaded CRL and checks every CRL' {
        $b = $script:server.Base
        $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900 `
            -CdpUrls @("$b/root.crl") -AiaUrls @("$b/root.crt")
        $disc = [pscustomobject]@{
            Certificates = @{ $sub.Public.Thumbprint = $sub.Public }
            Inventory = [pscustomobject]@{
                AdContext = [pscustomobject]@{ DomainController = ''; ForestDomains = @(); TrustedDomains = @() }
                CACertificates = @([pscustomobject]@{ Thumbprint = $sub.Public.Thumbprint; CAName = 'Example Issuing CA'; Info = [pscustomobject]@{ Subject = $sub.Public.Subject } })
                EnterpriseCAs = @()
            }
        }
        InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } {
            param($D)
            Register-MspkiDiscoveredLead -Discovery $D
            $f = Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 5
            $crl = @($f | Where-Object Category -eq 'CRL')
            $crl.Count | Should -Be 2
            @($crl | Where-Object { $_.Status -eq 'Pass' -and $_.Confidence -eq 'Confirmed' }).Count | Should -Be 2
            (Get-MspkiLead -Kind FreshestCRL).Depth | Should -Be 1
            ($f | Where-Object { $_.Category -eq 'AIA' }).Status | Should -Be 'Pass'
        }
    }
}
