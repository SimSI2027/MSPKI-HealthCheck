# Tests for the security fixes of audit 2 (docs/AUDIT-2.md, Batch A): H1 (links in unverified CRLs, LDAP binds only to
# proven hosts), M10 (no key from downloaded bytes), M9 (redirects and TLS to undiscovered hosts), H2 (ESC3) and M11 (template
# confidence). Hosts are 127.0.0.1 and example.test names only; nothing leaves this computer.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    # Same name as the root, another key: a CRL signed with this key must not verify.
    $script:impostor = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysValid 100
    $script:plantedLdap = 'ldap://planted.corp.example.test/CN=Example Root CA,CN=CDP,DC=corp,DC=example,DC=test?deltaRevocationList?base?objectClass=cRLDistributionPoint'

    # A discovery result with one issuing CA (signed by the root) whose CDP is the given URL; the root is discovered too.
    $script:newDiscovery = {
        param([string]$CdpUrl)
        $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900 -CdpUrls @($CdpUrl)
        [pscustomobject]@{
            Certificates = @{ $sub.Public.Thumbprint = $sub.Public; $script:root.Public.Thumbprint = $script:root.Public }
            Inventory = [pscustomobject]@{
                AdContext = [pscustomobject]@{ DomainController = 'dc01.corp.example.test'; ForestDomains = @('corp.example.test'); TrustedDomains = @(); DomainControllers = @('dc01.corp.example.test') }
                CACertificates = @(
                    [pscustomobject]@{ Thumbprint = $sub.Public.Thumbprint; CAName = 'Example Issuing CA'; Lifecycle = 'Current'; Info = [pscustomobject]@{ Subject = $sub.Public.Subject; NotAfter = '2999-01-01T00:00:00Z' } },
                    [pscustomobject]@{ Thumbprint = $script:root.Public.Thumbprint; CAName = 'Example Root CA'; Lifecycle = 'Current'; Info = [pscustomobject]@{ Subject = $script:root.Public.Subject; NotAfter = '2999-01-01T00:00:00Z' } })
                EnterpriseCAs = @()
            }
        }
    }
}

Describe 'Audit 2 H1: links in a downloaded CRL are followed only when its signature verified' {
    BeforeAll {
        $script:routes = [hashtable]::Synchronized(@{})
        $script:server = Start-TestHttpServer -Routes $script:routes
        $b = $script:server.Base
        $bad = New-TestCrl -Issuer $script:root -SigningKey $script:impostor.Key -Number 7 -FreshestUrls @("$b/planted+.crl", $script:plantedLdap)
        $good = New-TestCrl -Issuer $script:root -Number 8 -FreshestUrls @("$b/good+.crl")
        $unknown = New-TestCrl -Issuer $script:impostor -Number 2 -FreshestUrls @("$b/unknown+.crl")
        $script:routes['/bad.crl'] = @{ Status = 200; Body = $bad }
        $script:routes['/good.crl'] = @{ Status = 200; Body = $good }
        $script:routes['/good+.crl'] = @{ Status = 200; Body = (New-TestCrl -Issuer $script:root -Number 9 -Delta -BaseNumber 8 -HoursValid 48) }
        $script:routes['/unknown.crl'] = @{ Status = 200; Body = $unknown }
    }
    AfterAll { Stop-TestHttpServer -Server $script:server }

    It 'does not follow the Freshest CRL links (HTTP and LDAP) of a CRL whose signature does not verify' {
        $disc = & $script:newDiscovery "$($script:server.Base)/bad.crl"
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
        $f = InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } { param($D)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test') -DomainControllers @('dc01.corp.example.test')
            Register-MspkiDiscoveredLead -Discovery $D
            Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 5 }
        @(InModuleScope MspkiHealthCheck { Get-MspkiLead -Kind FreshestCRL }).Count | Should -Be 0
        @($script:server.Log | Where-Object { $_.Path -like '/planted*' }).Count | Should -Be 0
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
        $crl = @($f | Where-Object { $_.Category -eq 'CRL' -and $_.Endpoint -like '*/bad.crl' })
        $crl.Count | Should -Be 1
        $crl[0].StatusCode | Should -Be 'SIGNATURE_INVALID'
        ($crl[0].Evidence -join "`n") | Should -Match 'not followed'
    }

    It 'does not follow the links of a CRL whose issuer certificate was not discovered (signature not checked)' {
        $disc = & $script:newDiscovery "$($script:server.Base)/unknown.crl"
        $null = InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } { param($D)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            Register-MspkiDiscoveredLead -Discovery $D
            Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 5 }
        @(InModuleScope MspkiHealthCheck { Get-MspkiLead -Kind FreshestCRL }).Count | Should -Be 0
        @($script:server.Log | Where-Object { $_.Path -eq '/unknown+.crl' }).Count | Should -Be 0
    }

    It 'follows the Freshest CRL link of a CRL that verifies with a discovered CA certificate, and marks the lead Verified' {
        $disc = & $script:newDiscovery "$($script:server.Base)/good.crl"
        $f = InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } { param($D)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            Register-MspkiDiscoveredLead -Discovery $D
            Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 5 }
        $l = @(InModuleScope MspkiHealthCheck { Get-MspkiLead -Kind FreshestCRL })
        $l.Count | Should -Be 1
        $l[0].Trust | Should -Be 'Verified'
        @($script:server.Log | Where-Object { $_.Path -eq '/good+.crl' }).Count | Should -Be 1
        @($f | Where-Object { $_.Category -eq 'CRL' -and $_.Status -eq 'Pass' -and $_.Confidence -eq 'Confirmed' }).Count | Should -Be 2
    }
}

Describe 'Audit 2 H1: an LDAP bind goes only to hosts proven by authoritative discovery' {
    It 'decides for <Name>' -TestCases @(
        @{ Name = 'a serverless URL'; HostName = ''; Trust = ''; Dcs = @(); Allowed = $true }
        @{ Name = 'the selected domain controller'; HostName = 'DC01.corp.example.test'; Trust = ''; Dcs = @(); Allowed = $true }
        @{ Name = 'a forest domain controller from the Configuration partition'; HostName = 'dc02.corp.example.test'; Trust = ''; Dcs = @('dc02.corp.example.test'); Allowed = $true }
        @{ Name = 'a forest-zone name that nothing proved'; HostName = 'anyname.corp.example.test'; Trust = ''; Dcs = @('dc02.corp.example.test'); Allowed = $false }
        @{ Name = 'a forest-zone name from an unverified object'; HostName = 'anyname.corp.example.test'; Trust = 'Unverified'; Dcs = @(); Allowed = $false }
        @{ Name = 'a forest host named by an AD object'; HostName = 'dc03.corp.example.test'; Trust = 'Authoritative'; Dcs = @(); Allowed = $true }
        @{ Name = 'a forest host named by a verified CRL'; HostName = 'dc03.corp.example.test'; Trust = 'Verified'; Dcs = @(); Allowed = $true }
        @{ Name = 'an outside host named by an AD object'; HostName = 'ldap.example.test'; Trust = 'Authoritative'; Dcs = @(); Allowed = $false }
        @{ Name = 'a forest domain controller with a port'; HostName = 'dc02.corp.example.test:389'; Trust = ''; Dcs = @('dc02.corp.example.test'); Allowed = $true }
    ) {
        param($Name, $HostName, $Trust, $Dcs, $Allowed)
        $d = InModuleScope MspkiHealthCheck -Parameters @{ H = $HostName; T = $Trust; Dc = $Dcs } { param($H, $T, $Dc)
            Test-MspkiLdapHostAllowed -HostName $H -DefaultServer 'dc01.corp.example.test' -LocalDomains @('corp.example.test') -DomainControllers $Dc -Trust $T }
        $d.Allowed | Should -Be $Allowed
        $d.Reason | Should -Not -BeNullOrEmpty
    }

    It 'never binds to a forest-zone host for a lead that only an unverified object named' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
        $r = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test') -DomainControllers @('dc01.corp.example.test')
            $lead = Add-MspkiLead -Url 'ldap://anyname.corp.example.test/CN=x,DC=corp,DC=example,DC=test?deltaRevocationList?base' -Kind FreshestCRL -Source 'Crl:AA:FreshestCRL' -Origin 'test' -Trust Unverified
            Test-MspkiLeadEndpoint -Lead $lead -Url $lead.Url -DomainController 'dc01.corp.example.test' }
        @($r.Findings)[0].Status | Should -Be 'Skipped'
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
    }

    It 'keeps the strongest trust when the same lead comes from several sources' {
        $t = InModuleScope MspkiHealthCheck {
            Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $null = Add-MspkiLead -Url 'http://pki.corp.example.test/a.crl' -Kind CDP -Source 's1' -Trust Unverified
            $a = (Add-MspkiLead -Url 'http://pki.corp.example.test/a.crl' -Kind CDP -Source 's2' -Trust Verified).Trust
            $b = (Add-MspkiLead -Url 'http://pki.corp.example.test/a.crl' -Kind CDP -Source 's3' -Trust Unverified).Trust
            $c = (Add-MspkiLead -Url 'http://pki.corp.example.test/b.crl' -Kind CDP -Source 's4').Trust
            @($a, $b, $c) }
        $t | Should -Be @('Verified', 'Verified', 'Authoritative')
    }

    It 'reads the forest domain controllers from the server objects under CN=Sites of the Configuration partition' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject {
            @(@{ dnshostname = @('DC01.corp.example.test') }, @{ dnshostname = @('dc02.child.corp.example.test.') }, @{ cn = @('no-name') })
        }
        $dcs = InModuleScope MspkiHealthCheck { Get-MspkiForestDomainController -Server 'dc01.corp.example.test' -ConfigNC 'CN=Configuration,DC=corp,DC=example,DC=test' }
        $dcs | Should -Be @('dc01.corp.example.test', 'dc02.child.corp.example.test')
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 1 -Exactly -ParameterFilter {
            $BaseDN -eq 'CN=Sites,CN=Configuration,DC=corp,DC=example,DC=test' -and $Scope -eq 'Subtree' -and $Server -eq 'dc01.corp.example.test' }
    }
}
