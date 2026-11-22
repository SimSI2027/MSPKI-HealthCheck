# Tests for the Batch E fixes N4 (CES/CEP 200 answers) of the audit 2 verification
# (docs/AUDIT-2-VERIFY.md, Fix log 2). Loopback server and example.test only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'Audit 2 N4: a 200 answer from a CES or CEP is Confirmed only for a valid service response' {
    BeforeAll {
        $enc = [System.Text.Encoding]::UTF8
        $script:routesN4 = [hashtable]::Synchronized(@{})
        $script:serverN4 = Start-TestHttpServer -Routes $script:routesN4
        $script:bN4 = $script:serverN4.Base
        $wsdl = '<?xml version="1.0"?><wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" targetNamespace="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"><wsdl:types/></wsdl:definitions>'
        $fault = '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text xml:lang="en">The message could not be processed.</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>'
        $fault11 = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>bad request</faultstring></s:Fault></s:Body></s:Envelope>'
        $words = '<html><body>Welcome to the service portal. Enrollment policy and web service (svc) information: WSDL, policy, enrollment.</body></html>'
        $xmlWords = '<?xml version="1.0"?><page>service wsdl svc policy enrollment</page>'
        $fakeWsdl = '<?xml version="1.0"?><definitions><service/></definitions>'
        $broken = '<?xml version="1.0"?><wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"><wsdl:types>'
        $dtd = '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">&x;</wsdl:definitions>'
        $r = $script:routesN4
        $r['/wsdl/service.svc'] = @{ Status = 200; Body = $enc.GetBytes($wsdl); Headers = @{ 'Content-Type' = 'text/xml; charset=utf-8' } }
        $r['/fault12/service.svc'] = @{ Status = 200; Body = $enc.GetBytes($fault); Headers = @{ 'Content-Type' = 'application/soap+xml' } }
        $r['/fault11/service.svc'] = @{ Status = 200; Body = $enc.GetBytes($fault11); Headers = @{ 'Content-Type' = 'text/xml' } }
        $r['/portal/service.svc'] = @{ Status = 200; Body = $enc.GetBytes($words); Headers = @{ 'Content-Type' = 'text/html' } }
        $r['/xmlwords/service.svc'] = @{ Status = 200; Body = $enc.GetBytes($xmlWords); Headers = @{ 'Content-Type' = 'text/xml' } }
        $r['/fakewsdl/service.svc'] = @{ Status = 200; Body = $enc.GetBytes($fakeWsdl); Headers = @{ 'Content-Type' = 'text/xml' } }
        $r['/broken/service.svc'] = @{ Status = 200; Body = $enc.GetBytes($broken); Headers = @{ 'Content-Type' = 'text/xml' } }
        $r['/dtd/service.svc'] = @{ Status = 200; Body = $enc.GetBytes($dtd); Headers = @{ 'Content-Type' = 'text/xml' } }
        $script:probeN4 = {
            param([string]$Path, [string]$Kind = 'CES')
            InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:bN4 + $Path); K = $Kind } {
                param($U, $K)
                [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry; Reset-MspkiProbeCache; Set-MspkiWebProbeOption
                $lead = Add-MspkiLead -Url $U -Kind $K -Source 'AD:EnrollmentServices:msPKI-Enrollment-Servers' -Origin 'test fixture' -Confidence 'Referenced'
                Test-MspkiEnrollmentEndpoint -Lead $lead -Url $lead.Url -Inventory $null -TimeoutSeconds 3
            }
        }
    }
    AfterAll { Stop-TestHttpServer -Server $script:serverN4 }

    It 'confirms <Name>' -TestCases @(
        @{ Name = 'a WSDL document'; Path = '/wsdl/service.svc' }
        @{ Name = 'a SOAP 1.2 fault'; Path = '/fault12/service.svc' }
        @{ Name = 'a SOAP 1.1 fault'; Path = '/fault11/service.svc' }
    ) {
        param($Name, $Path)
        $r = & $script:probeN4 $Path
        $r.State | Should -Be 'ConfirmedResponding'
        $r.Responding | Should -BeTrue
        $f = @($r.Findings | Where-Object { $_.StatusCode -eq 'OK' })
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Pass'
        $f[0].Confidence | Should -Be 'Confirmed'
    }

    It 'does not confirm <Name>: a word match is not a service response (Inferred, not responding)' -TestCases @(
        @{ Name = 'an HTML portal page that mentions service, WSDL, policy and enrollment'; Path = '/portal/service.svc' }
        @{ Name = 'well-formed XML that only contains those words'; Path = '/xmlwords/service.svc' }
        @{ Name = 'an element named definitions that is not in the WSDL namespace'; Path = '/fakewsdl/service.svc' }
        @{ Name = 'a WSDL that is cut off (not parsable)'; Path = '/broken/service.svc' }
        @{ Name = 'a document with a DTD (refused, never resolved)'; Path = '/dtd/service.svc' }
    ) {
        param($Name, $Path)
        $r = & $script:probeN4 $Path
        $r.Responding | Should -BeFalse
        $r.State | Should -Be 'NotConfirmed'
        @($r.Findings | Where-Object { $_.Confidence -eq 'Confirmed' -or $_.Status -eq 'Pass' }).Count | Should -Be 0
        @($r.Findings | Where-Object { $_.StatusCode -eq 'CONTENT_WRONG_TYPE' -and $_.Confidence -eq 'Inferred' }).Count | Should -Be 1
    }

    It 'says in the evidence why a 200 was not confirmed' {
        $r = & $script:probeN4 '/portal/service.svc'
        (@($r.Findings)[0].Evidence -join "`n") | Should -Match 'not a valid service response'
    }
}
