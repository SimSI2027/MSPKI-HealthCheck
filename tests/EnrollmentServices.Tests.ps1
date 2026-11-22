# CEP / CES (REQUIREMENTS 5.6): policy entries, lead registration, layered probes against a loopback test server.
# No internet and no real names: the only hosts are 127.0.0.1 and example.test.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:reset = { InModuleScope MspkiHealthCheck { Reset-MspkiLeadRegistry; Reset-MspkiProbeCache } }
    $script:probe = {
        param([string]$Url, [string]$Kind = 'CEP', [string]$Source = 'Policy:CEP:HKLM', $Inventory = $null, [switch]$SkipNetwork, [string]$RelatedCA = '', [string]$Confidence = 'Referenced')
        InModuleScope MspkiHealthCheck -Parameters @{ U = $Url; K = $Kind; S = $Source; I = $Inventory; Skip = [bool]$SkipNetwork; R = $RelatedCA; C = $Confidence } {
            param($U, $K, $S, $I, $Skip, $R, $C)
            $lead = Add-MspkiLead -Url $U -Kind $K -Source $S -Origin 'test fixture' -RelatedCA $R -Confidence $C
            Test-MspkiEnrollmentEndpoint -Lead $lead -Url $lead.Url -Inventory $I -TimeoutSeconds 3 -SkipNetwork:$Skip
        }
    }
    $script:routes = [hashtable]::Synchronized(@{})
    $script:server = Start-TestHttpServer -Routes $script:routes
    $script:b = $script:server.Base
    $script:routes['/pol/service.svc'] = @{ Status = 401; Body = @(); Headers = @{ 'WWW-Authenticate' = 'Negotiate' } }
    $script:routes['/bad/service.svc'] = @{ Status = 400; Body = [System.Text.Encoding]::ASCII.GetBytes('Bad Request') }
    $script:routes['/post/service.svc'] = @{ Status = 405; Body = @() }
    $script:routes['/page/service.svc'] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('<?xml version="1.0"?><wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"><wsdl:types/></wsdl:definitions>'); Headers = @{ 'Content-Type' = 'text/xml' } }
    $script:routes['/mention/service.svc'] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('<html>Service - WSDL available</html>'); Headers = @{ 'Content-Type' = 'text/html' } }
    $script:routes['/junk/service.svc'] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('hello'); Headers = @{ 'Content-Type' = 'application/octet-stream' } }
    $script:routes['/boom/service.svc'] = @{ Status = 500; Body = @() }
    $script:routes['/forbidden/service.svc'] = @{ Status = 403; Body = [System.Text.Encoding]::ASCII.GetBytes('Forbidden: SSL required') }
    $script:routes['/moved/service.svc'] = @{ Status = 302; Body = @(); Headers = @{ Location = '/elsewhere/service.svc' } }
}

AfterAll { Stop-TestHttpServer -Server $script:server }

Describe 'Local CEP policy entries' {
    It 'names the authentication flags' {
        InModuleScope MspkiHealthCheck {
            Get-MspkiAuthFlagText -Flags 2 | Should -Be 'Kerberos'
            Get-MspkiAuthFlagText -Flags 10 | Should -Be 'Kerberos, Certificate'
            Get-MspkiAuthFlagText -Flags 1 | Should -Be 'Anonymous'
            Get-MspkiAuthFlagText -Flags 4 | Should -Be 'UserName'
            Get-MspkiAuthFlagText -Flags 0 | Should -Be 'None'
            Get-MspkiAuthFlagText -Flags $null | Should -Be 'Unknown'
        }
    }

    It 'converts a web policy server and recognises the Active Directory policy, which is never a web service' {
        InModuleScope MspkiHealthCheck {
            $loc = @{ Source = 'Policy:CEP:HKLM'; Managed = 'Group Policy (computer)' }
            $web = ConvertFrom-MspkiCepPolicyEntry -Values @{ URL = ' https://cep.corp.example.test/ADPolicyProvider_CEP_Kerberos/service.svc '; AuthFlags = 2; FriendlyName = 'Example policy'; PolicyID = '{x}'; Cost = 100 } -KeyName 'k1' -Location $loc
            $web.IsWebService | Should -BeTrue
            $web.Url | Should -Be 'https://cep.corp.example.test/ADPolicyProvider_CEP_Kerberos/service.svc'
            $web.AuthName | Should -Be 'Kerberos'
            $web.Source | Should -Be 'Policy:CEP:HKLM'
            $ad = ConvertFrom-MspkiCepPolicyEntry -Values @{ URL = 'ldap:'; AuthFlags = 2 } -KeyName 'k2' -Location $loc
            $ad.IsWebService | Should -BeFalse
            $ad.IsAdPolicy | Should -BeTrue
        }
    }

    It 'reads this computer''s policy keys without error (read-only)' {
        $r = InModuleScope MspkiHealthCheck { Get-MspkiLocalCepPolicy }
        $r.PSObject.Properties.Name | Should -Contain 'Data'
        @($r.Findings | Where-Object { $_.Status -eq 'Error' }).Count | Should -Be 0
    }

    It 'classifies a policy-key read failure by exception type, not by (localised) message text' {
        $r = InModuleScope MspkiHealthCheck {
            Mock Read-MspkiPolicyServerKey {
                [pscustomobject]@{ Exists = $true; Entries = @(); Error = 'Zugriff verweigert (not English)'
                    ErrorInfo = (Get-MspkiErrorInfo (New-Object System.Security.SecurityException('Zugriff verweigert (not English)'))) }
            }
            Get-MspkiLocalCepPolicy
        }
        $f = @($r.Findings)
        $f.Count | Should -BeGreaterThan 0
        @($f | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' }).Count | Should -Be $f.Count
    }
}

Describe 'Registering CEP and CES leads' {
    BeforeEach { & $script:reset }

    It 'registers web policy servers as Configured leads and ignores the Active Directory policy' {
        $inv = [pscustomobject]@{
            EnterpriseCAs = @()
            CepPolicies = @(
                [pscustomobject]@{ IsWebService = $true; Url = 'https://cep.corp.example.test/ADPolicyProvider_CEP_Kerberos/service.svc'; Source = 'Policy:CEP:HKLM'; Managed = 'Group Policy (computer)'; KeyName = 'k1'; FriendlyName = '' }
                [pscustomobject]@{ IsWebService = $false; Url = 'ldap:'; Source = 'Policy:CEP:HKLM'; Managed = 'Group Policy (computer)'; KeyName = 'k2'; FriendlyName = '' })
        }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ I = $inv } { param($I)
            $null = Register-MspkiEnrollmentLead -Inventory $I -SkipNetwork
            $l = @(Get-MspkiLead -Kind CEP)
            [pscustomobject]@{ Count = $l.Count; Origin = (Get-MspkiEnrollmentOrigin -Lead $l[0]); Confidence = $l[0].Confidence } }
        $r.Count | Should -Be 1
        $r.Origin | Should -Be 'Configured'
        $r.Confidence | Should -Be 'Referenced'
    }

    It 'builds constructed candidates only on Enterprise CA hosts, as Inferred leads, and none with -SkipNetwork' {
        $inv = [pscustomobject]@{ CepPolicies = @(); EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; DnsHostName = 'ca01.corp.example.test'; EnrollmentServers = @() }, [pscustomobject]@{ Name = 'No Host CA'; DnsHostName = ''; EnrollmentServers = @() }) }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ I = $inv } { param($I)
            $null = Register-MspkiEnrollmentLead -Inventory $I -SkipNetwork
            $skipped = @(Get-MspkiLead | Where-Object { $_.Kind -eq 'CES' -or $_.Kind -eq 'CEP' }).Count
            $null = Register-MspkiEnrollmentLead -Inventory $I
            $l = @(Get-MspkiLead | Where-Object { $_.Kind -eq 'CES' -or $_.Kind -eq 'CEP' })
            [pscustomobject]@{ Skipped = $skipped; Count = $l.Count; Ces = @($l | Where-Object { $_.Kind -eq 'CES' }).Count; All = $l } }
        $r.Skipped | Should -Be 0
        $r.Count | Should -Be 6
        $r.Ces | Should -Be 3
        foreach ($l in $r.All) {
            $l.Confidence | Should -Be 'Inferred'
            @($l.Sources) | Should -Be @('Constructed:CAHost')
            $l.Host | Should -Be 'ca01.corp.example.test'
            @($l.RelatedCAs) | Should -Be @('Example Issuing CA')
        }
        @($r.All | ForEach-Object { $_.Url }) | Should -Contain 'https://ca01.corp.example.test/Example%20Issuing%20CA_CES_Kerberos/service.svc'
        @($r.All | ForEach-Object { $_.Url }) | Should -Contain 'https://ca01.corp.example.test/ADPolicyProvider_CEP_Certificate/service.svc'
    }

    It 'does not register a constructed URL again when AD already references it (the referenced lead keeps its sources)' {
        $inv = [pscustomobject]@{ CepPolicies = @(); EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; DnsHostName = 'ca01.corp.example.test'; EnrollmentServers = @() }) }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ I = $inv } { param($I)
            $null = Add-MspkiLead -Url 'https://ca01.corp.example.test/Example Issuing CA_CES_Kerberos/service.svc' -Kind CES -Source 'AD:EnrollmentServices:msPKI-Enrollment-Servers' -Origin 'test'
            $null = Register-MspkiEnrollmentLead -Inventory $I
            $ces = @(Get-MspkiLead -Kind CES)
            $kerb = @($ces | Where-Object { $_.Sources -contains 'AD:EnrollmentServices:msPKI-Enrollment-Servers' })
            [pscustomobject]@{ Ces = $ces.Count; Kerb = $kerb.Count; Sources = @($kerb[0].Sources); Origin = (Get-MspkiEnrollmentOrigin -Lead $kerb[0]) } }
        $r.Ces | Should -Be 3
        $r.Kerb | Should -Be 1
        $r.Sources | Should -Be @('AD:EnrollmentServices:msPKI-Enrollment-Servers')
        $r.Origin | Should -Be 'Discovered'
    }
}

Describe 'Probing a CEP/CES endpoint: separate layers' {
    BeforeEach { & $script:reset; $script:server.Log.Clear() }

    It 'treats HTTP 401 as reachable, authentication required, NOT confirmed (audit 2 M2), with each layer as its own fact' {
        $r = & $script:probe ($script:b + '/pol/service.svc')
        $r.State | Should -Be 'AuthRequired'
        $r.Responding | Should -BeFalse
        $r.Origin | Should -Be 'Configured'
        $f = @($r.Findings | Where-Object { $_.StatusCode -eq 'HTTP_401_403' })
        $f.Count | Should -Be 1
        @($r.Findings | Where-Object { $_.Status -eq 'Pass' -or $_.Confidence -eq 'Confirmed' }).Count | Should -Be 0
        $f[0].Status | Should -Be 'Information'
        $f[0].Message | Should -Match 'authentication required'
        $f[0].Message | Should -Match 'not confirmed'
        $f[0].Category | Should -Be 'CEP'
        $f[0].Role | Should -Be 'CEPEndpoint'
        $f[0].Confidence | Should -Be 'Referenced'
        $f[0].DnsStatus | Should -Be 'Pass'
        $f[0].TcpStatus | Should -Be 'Pass'
        $f[0].HttpStatus | Should -Be 'Pass'
        $ev = $f[0].Evidence -join "`n"
        $ev | Should -Match 'Classification: Configured'
        $ev | Should -Match 'Reachability \(TCP \d+\): connects'
        $ev | Should -Match 'Reachability \(HTTP\): the host answered with HTTP 401'
        $ev | Should -Match 'Authentication required: yes \(HTTP 401\)'
        $ev | Should -Match 'TLS trust: not applicable \(http\)'
        $ev | Should -Match 'TLS name match: not applicable \(http\)'
        $ev | Should -Match 'Content: not checked'
    }

    It 'treats HTTP 400 and 405 (the web service itself answers a bare GET that way) as confirmed' {
        foreach ($p in @('/bad/service.svc', '/post/service.svc')) {
            & $script:reset
            $r = & $script:probe ($script:b + $p)
            $r.State | Should -Be 'ConfirmedResponding' -Because $p
            $r.Responding | Should -BeTrue
            (@($r.Findings | Where-Object { $_.StatusCode -eq 'OK' })[0].Evidence -join "`n") | Should -Match 'Authentication required: no authentication challenge'
        }
    }

    It 'treats HTTP 403 like 401: reachable, not confirmed (a WAF, an IP restriction or SSL-required answers 403 for every path)' {
        $r = & $script:probe ($script:b + '/forbidden/service.svc') 'CES' 'AD:EnrollmentServices:msPKI-Enrollment-Servers'
        $r.State | Should -Be 'AuthRequired'
        $r.Responding | Should -BeFalse
        $f = @($r.Findings | Where-Object { $_.StatusCode -eq 'HTTP_401_403' })
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Information'
        $f[0].Confidence | Should -Not -Be 'Confirmed'
        @($r.Findings | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 0
    }

    It 'reports a redirect that was not followed as redirected, never as responding (audit 2 M2 with M5)' {
        # 127.0.0.1 is a trusted host for its own redirect (same host), so the 302 is followed to /elsewhere, which is a 404 here; the
        # not-followed form is covered in Audit2.Results.Tests.ps1.
        $r = & $script:probe ($script:b + '/moved/service.svc') 'CES' 'AD:EnrollmentServices:msPKI-Enrollment-Servers'
        $r.Responding | Should -BeFalse
        @($r.Findings | Where-Object { $_.Status -eq 'Pass' -or $_.Confidence -eq 'Confirmed' }).Count | Should -Be 0
    }

    It 'checks the content of an HTTP 200 answer: a service response (WSDL) passes, other content, a page that only mentions the service included, is a warning' {
        $ok = & $script:probe ($script:b + '/page/service.svc')
        @($ok.Findings | Where-Object { $_.StatusCode -eq 'OK' })[0].ContentStatus | Should -Be 'Pass'
        & $script:reset
        $bad = & $script:probe ($script:b + '/junk/service.svc')
        $w = @($bad.Findings | Where-Object { $_.StatusCode -eq 'CONTENT_WRONG_TYPE' })
        $w.Count | Should -Be 1
        $w[0].Status | Should -Be 'Warning'
        $w[0].ContentStatus | Should -Be 'Warning'
        & $script:reset
        $m = & $script:probe ($script:b + '/mention/service.svc')
        $m.Responding | Should -BeFalse
        @($m.Findings | Where-Object { $_.StatusCode -eq 'CONTENT_WRONG_TYPE' -and $_.Confidence -eq 'Inferred' }).Count | Should -Be 1
    }

    It 'reports HTTP 404 on a referenced URL as a failure (Unreachable), not as a responding service' {
        $r = & $script:probe ($script:b + '/missing/service.svc')
        $r.State | Should -Be 'Unreachable'
        $r.Responding | Should -BeFalse
        $f = @($r.Findings | Where-Object { $_.Status -eq 'Fail' })
        $f.Count | Should -Be 1
        $f[0].StatusCode | Should -Be 'HTTP_404'
        $f[0].HttpStatus | Should -Be 'Fail'
    }

    It 'reports a TCP failure on its own layer' {
        $r = & $script:probe 'http://127.0.0.1:1/ces/service.svc' 'CES' 'AD:EnrollmentServices:msPKI-Enrollment-Servers'
        $r.State | Should -Be 'Unreachable'
        $f = @($r.Findings | Where-Object { $_.Status -eq 'Fail' })
        $f[0].StatusCode | Should -BeIn @('TCP_FAIL', 'TIMEOUT')
        $f[0].TcpStatus | Should -Be 'Fail'
        $f[0].DnsStatus | Should -Be 'Pass'
        $f[0].HttpStatus | Should -Be 'NotTested'
        $f[0].Category | Should -Be 'CES'
        ($f[0].Evidence -join "`n") | Should -Match 'Classification: Discovered'
    }

    It 'flags a service reachable over plain HTTP as a configuration risk, apart from the reachability result' {
        $r = & $script:probe ($script:b + '/pol/service.svc')
        $risk = @($r.Findings | Where-Object { $_.StatusCode -eq 'CONFIG_RISK' })
        $risk.Count | Should -Be 1
        $risk[0].Severity | Should -Be 'Medium'
        $risk[0].Status | Should -Be 'Warning'
        $risk[0].Message | Should -Match 'HTTP, not HTTPS'
        $risk[0].TlsStatus | Should -Be 'NotApplicable'
    }

    It 'makes a user-name authentication service over HTTP a High finding' {
        $inv = [pscustomobject]@{ CepPolicies = @(); EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; EnrollmentServers = @([pscustomobject]@{ Url = ($script:b + '/pol/service.svc'); AuthName = 'UserName'; AuthType = 4; Priority = 1; RenewalOnly = $false }) }) }
        $r = & $script:probe ($script:b + '/pol/service.svc') 'CES' 'AD:EnrollmentServices:msPKI-Enrollment-Servers' $inv
        $risk = @($r.Findings | Where-Object { $_.StatusCode -eq 'CONFIG_RISK' })
        $risk[0].Severity | Should -Be 'High'
        $risk[0].Status | Should -Be 'Fail'
        $ok = @($r.Findings | Where-Object { $_.StatusCode -eq 'HTTP_401_403' })[0]
        ($ok.Evidence -join "`n") | Should -Match 'Authentication type from AD \(msPKI-Enrollment-Servers\): UserName; priority/cost 1; renewal only: no'
    }

    It 'keeps a constructed candidate Inferred even when something answers, and says so' {
        $r = & $script:probe ($script:b + '/page/service.svc') 'CES' 'Constructed:CAHost' $null -RelatedCA 'Example Issuing CA' -Confidence 'Inferred'
        $r.Origin | Should -Be 'ConstructedCandidate'
        $r.State | Should -Be 'ConfirmedResponding'
        $f = @($r.Findings | Where-Object { $_.StatusCode -eq 'OK' })[0]
        $f.Confidence | Should -Be 'Inferred'
        $f.Message | Should -Match 'not confirmed'
        $f.Notes | Should -Match 'Constructed candidate'
        $f.RelatedCA | Should -Be 'Example Issuing CA'
    }

    It 'gives no finding for a constructed candidate that does not answer (the analysis reports them together)' {
        $r = & $script:probe ($script:b + '/nothing/service.svc') 'CES' 'Constructed:CAHost' $null -Confidence 'Inferred'
        $r.State | Should -Be 'Unreachable'
        @($r.Findings).Count | Should -Be 0
    }

    It 'sends nothing with -SkipNetwork' {
        $r = & $script:probe ($script:b + '/pol/service.svc') -SkipNetwork
        $r.State | Should -Be 'NotTested'
        @($r.Findings)[0].Status | Should -Be 'Skipped'
        $script:server.Log.Count | Should -Be 0
    }

    It 'sends only anonymous GET requests and never an Authorization header' {
        foreach ($p in @('/pol/service.svc', '/bad/service.svc', '/boom/service.svc')) { & $script:reset; $null = & $script:probe ($script:b + $p) }
        $script:server.Log.Count | Should -BeGreaterOrEqual 3
        foreach ($e in @($script:server.Log)) {
            $e.Method | Should -Be 'GET'
            ($e.Headers -join "`n") | Should -Not -Match '(?i)authorization|cookie'
        }
    }

    It 'reports HTTP 500 as reachable but failing (Fail, HTTP_500, never Pass or Confirmed), and keeps the answer in the evidence' {
        $r = & $script:probe ($script:b + '/boom/service.svc')
        $r.State | Should -Be 'Failing'
        $r.Responding | Should -BeFalse
        $f = @($r.Findings)[0]
        $f.Status | Should -Be 'Fail'
        $f.StatusCode | Should -Be 'HTTP_500'
        $f.Confidence | Should -Not -Be 'Confirmed'
        $f.HttpStatus | Should -Be 'Fail'
        ($f.Evidence -join "`n") | Should -Match 'the host answered with HTTP 500'
        $f.Message | Should -Match 'reachable but failing'
    }

    It 'reports HTTP <Code> the same way for a CEP and a CES (a stopped application pool answers 503)' -TestCases @(
        @{ Code = 501; Kind = 'CEP' }
        @{ Code = 503; Kind = 'CEP' }
        @{ Code = 503; Kind = 'CES' }
    ) {
        param($Code, $Kind)
        $script:routes['/e{0}/service.svc' -f $Code] = @{ Status = $Code; Body = @() }
        $r = & $script:probe ($script:b + ('/e{0}/service.svc' -f $Code)) $Kind 'AD:EnrollmentServices:msPKI-Enrollment-Servers'
        $r.State | Should -Be 'Failing'
        @($r.Findings)[0].Status | Should -Be 'Fail'
        @($r.Findings)[0].StatusCode | Should -Be 'HTTP_500'
    }

    It 'does not turn a failing constructed candidate into a finding of its own and does not count it as answering' {
        $r = & $script:probe ($script:b + '/boom/service.svc') 'CES' 'Constructed:CAHost' $null -Confidence 'Inferred'
        $r.State | Should -Be 'Failing'
        $r.Responding | Should -BeFalse
        @($r.Findings).Count | Should -Be 0
    }
}

Describe 'CEP/CES analysis' {
    BeforeEach { & $script:reset; $script:server.Log.Clear() }

    It 'probes every lead once, reports constructed candidates that stay silent in one finding, and notes that no CEP is configured' {
        $ces = [pscustomobject]@{ Url = ($script:b + '/pol/service.svc'); AuthName = 'Kerberos'; AuthType = 2; Priority = 1; RenewalOnly = $false }
        $inv = [pscustomobject]@{ CepPolicies = @(); EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; DnsHostName = 'ca01.corp.example.test'; EnrollmentServers = @($ces) }) }
        $disc = [pscustomobject]@{ Inventory = $inv }
        InModuleScope MspkiHealthCheck -Parameters @{ I = $inv } { param($I)
            $null = Add-MspkiLead -Url $I.EnterpriseCAs[0].EnrollmentServers[0].Url -Kind CES -Source 'AD:EnrollmentServices:msPKI-Enrollment-Servers' -Origin 'test' -RelatedCA 'Example Issuing CA' }
        # The constructed candidates are on a host that does not resolve (mocked), so they stay silent.
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName { [pscustomobject]@{ Status = 'Pass'; StatusCode = 'OK'; Error = ''; Addresses = @('127.0.0.1'); ElapsedMs = 0 } }
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName { [pscustomobject]@{ Status = 'Fail'; StatusCode = 'DNS_FAIL'; Error = 'mock: no such host'; Addresses = @(); ElapsedMs = 0 } } -ParameterFilter { $HostName -eq 'ca01.corp.example.test' }
        $f = InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } { param($D) Invoke-MspkiEnrollmentServiceAnalysis -Discovery $D -TimeoutSeconds 3 }
        $ok = @($f | Where-Object { $_.Category -eq 'CES' -and $_.StatusCode -eq 'HTTP_401_403' })
        $ok.Count | Should -Be 1
        $ok[0].Evidence -join "`n" | Should -Match 'Classification: Discovered'
        $sil = @($f | Where-Object { $_.Message -like '*constructed CEP/CES candidate URL(s)*' })
        $sil.Count | Should -Be 1
        $sil[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        $sil[0].Status | Should -Be 'NotApplicable'
        $sil[0].Confidence | Should -Be 'Inferred'
        $sil[0].Message | Should -Match '^6 constructed'
        @($f | Where-Object { $_.Category -eq 'CEP' -and $_.StatusCode -eq 'NOT_CONFIGURED' }).Count | Should -Be 1
        # No finding says "Confirmed" for anything constructed.
        @($f | Where-Object { $_.Sources -contains 'Constructed:CAHost' -and $_.Confidence -eq 'Confirmed' }).Count | Should -Be 0
        # Only the one referenced URL was requested from the server.
        @($script:server.Log).Count | Should -Be 1
    }

    It 'reports when AD publishes no CES URL and the CEP list is empty, as not applicable, never as a failure' {
        $inv = [pscustomobject]@{ CepPolicies = @(); EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; DnsHostName = ''; EnrollmentServers = @() }) }
        $f = InModuleScope MspkiHealthCheck -Parameters @{ D = ([pscustomobject]@{ Inventory = $inv }) } { param($D) Invoke-MspkiEnrollmentServiceAnalysis -Discovery $D -TimeoutSeconds 3 -SkipNetwork }
        @($f | Where-Object { $_.Status -eq 'Fail' -or $_.Status -eq 'Warning' -or $_.Status -eq 'Error' }).Count | Should -Be 0
        @($f | Where-Object { $_.StatusCode -eq 'NOT_CONFIGURED' -and $_.Category -eq 'CEP' }).Count | Should -Be 1
        @($f | Where-Object { $_.StatusCode -eq 'NOT_DISCOVERED' -and $_.Category -eq 'CES' }).Count | Should -Be 1
    }

    It 'probes a CEP from policy and attributes it to the policy (Configured)' {
        $inv = [pscustomobject]@{ EnterpriseCAs = @(); CepPolicies = @([pscustomobject]@{ IsWebService = $true; Url = ($script:b + '/pol/service.svc'); Source = 'Policy:CEP:HKCU'; Managed = 'Group Policy (user)'; KeyName = 'k1'; FriendlyName = 'Example'; AuthName = 'Kerberos'; AuthFlags = 2; Cost = 100 }) }
        $f = InModuleScope MspkiHealthCheck -Parameters @{ D = ([pscustomobject]@{ Inventory = $inv }) } { param($D) Invoke-MspkiEnrollmentServiceAnalysis -Discovery $D -TimeoutSeconds 3 }
        $ok = @($f | Where-Object { $_.Category -eq 'CEP' -and $_.StatusCode -eq 'HTTP_401_403' })
        $ok.Count | Should -Be 1
        $ok[0].Sources | Should -Contain 'Policy:CEP:HKCU'
        ($ok[0].Evidence -join "`n") | Should -Match 'Found in: Enrollment policy server on this computer \(Group Policy \(user\)'
        @($f | Where-Object { $_.StatusCode -eq 'NOT_CONFIGURED' }).Count | Should -Be 0
    }
}
