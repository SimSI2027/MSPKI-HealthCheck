# Fix log 3, N15 (docs/AUDIT-3-VERIFY.md): a new lead is UNtrusted unless a caller names a trusted source. A lead derived from another lead
# keeps that lead's trust. example.test names only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'N15: lead trust is fail-closed' {
    It 'a lead added without -Trust is Unverified and its host is not trusted' {
        InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $l = Add-MspkiLead -Url 'http://forgetful.corp.example.test/ca.crt' -Kind AIA -Source 'test:caller-forgot-trust' -Origin 'test fixture'
            $l.Trust | Should -Be 'Unverified'
            Test-MspkiTrustedLeadHost -HostName 'forgetful.corp.example.test' | Should -BeFalse
        }
    }

    It 'only an explicit Authoritative or Verified source makes the host trusted' -TestCases @(
        @{ Trust = 'Authoritative' }, @{ Trust = 'Verified' }
    ) {
        param($Trust)
        InModuleScope MspkiHealthCheck -Parameters @{ T = $Trust } { param($T)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $l = Add-MspkiLead -Url 'http://named.corp.example.test/ca.crt' -Kind AIA -Source 'test:explicit' -Origin 'test fixture' -Trust $T
            $l.Trust | Should -Be $T
            Test-MspkiTrustedLeadHost -HostName 'named.corp.example.test' | Should -BeTrue
        }
    }

    It 'the same URL named again by a trusted source raises the trust; a later untrusted mention never lowers it' {
        InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $null = Add-MspkiLead -Url 'http://both.corp.example.test/ca.crt' -Kind AIA -Source 'test:a' -Origin 'x'
            (Add-MspkiLead -Url 'http://both.corp.example.test/ca.crt' -Kind AIA -Source 'test:b' -Origin 'x' -Trust 'Verified').Trust | Should -Be 'Verified'
            (Add-MspkiLead -Url 'http://both.corp.example.test/ca.crt' -Kind AIA -Source 'test:c' -Origin 'x').Trust | Should -Be 'Verified'
        }
    }

    It 'a lead from discovery (a CA certificate read from AD) is Authoritative' {
        $root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650 -AiaUrls @('http://pki.corp.example.test/root.crt')
        InModuleScope MspkiHealthCheck -Parameters @{ Root = $root } { param($Root)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $root = $Root
            $d = [pscustomobject]@{
                Certificates = @{ $root.Public.Thumbprint = $root.Public }
                Inventory = [pscustomobject]@{
                    AdContext = [pscustomobject]@{ DomainController = 'dc01.corp.example.test'; ForestDomains = @('corp.example.test'); TrustedDomains = @(); DomainControllers = @('dc01.corp.example.test') }
                    CACertificates = @([pscustomobject]@{ Thumbprint = $root.Public.Thumbprint; CAName = 'Example Root CA'; Lifecycle = 'Current'; Info = [pscustomobject]@{ Subject = $root.Public.Subject; NotAfter = '2999-01-01T00:00:00Z' } })
                    EnterpriseCAs = @()
                }
            }
            Register-MspkiDiscoveredLead -Discovery $d
            $l = @(Get-MspkiLead | Where-Object { $_.Kind -eq 'AIA' })
            $l.Count | Should -BeGreaterThan 0
            foreach ($x in $l) { $x.Trust | Should -Be 'Authoritative' }
        }
    }

    It 'CES/CEP candidates built from a CA host path, and a CEP URL from local policy: constructed = Unverified, policy = Authoritative' {
        InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $inv = [pscustomobject]@{
                CepPolicies = @([pscustomobject]@{ IsWebService = $true; Url = 'https://cep.corp.example.test/ADPolicyProvider_CEP_Kerberos/service.svc'; Source = 'Local:CEP'; Managed = 'Group Policy'; KeyName = 'k'; FriendlyName = '' })
                EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; DnsHostName = 'sub-ca01.pki.example.test' })
            }
            $n = Register-MspkiEnrollmentLead -Inventory $inv
            $n | Should -BeGreaterThan 1
            $policy = @(Get-MspkiLead | Where-Object { $_.Host -eq 'cep.corp.example.test' })
            $policy.Count | Should -Be 1
            $policy[0].Trust | Should -Be 'Authoritative'
            $constructed = @(Get-MspkiLead | Where-Object { $_.Host -eq 'sub-ca01.pki.example.test' })
            $constructed.Count | Should -BeGreaterThan 0
            foreach ($x in $constructed) { $x.Trust | Should -Be 'Unverified' }
        }
    }
}

Describe 'N15: an NDES lead derived from another lead keeps that lead''s trust' {
    It 'a lead referenced by a Verified lead becomes a Verified NDES lead, not Authoritative' {
        InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $null = Add-MspkiLead -Url 'http://ndes01.corp.example.test/certsrv/mscep/mscep.dll' -Kind AIA -Source 'Cert:ABC:AIA' -Origin 'downloaded certificate' -Trust 'Verified'
            $d = [pscustomobject]@{ Inventory = [pscustomobject]@{ AdContext = [pscustomobject]@{ DomainController = 'dc01.corp.example.test'; ForestDomains = @('corp.example.test'); TrustedDomains = @(); DomainControllers = @('dc01.corp.example.test') }
                CACertificates = @(); EnterpriseCAs = @(); Templates = @(); TemplatesRead = $false } }
            $null = Invoke-MspkiNdesAnalysis -Discovery $d -TimeoutSeconds 1 -SkipNetwork -ErrorAction SilentlyContinue
            $nd = @(Get-MspkiLead | Where-Object { $_.Kind -eq 'NDES' -and $_.Host -eq 'ndes01.corp.example.test' })
            $nd.Count | Should -BeGreaterThan 0
            foreach ($x in $nd) { $x.Trust | Should -Be 'Verified' }
        }
    }
}
