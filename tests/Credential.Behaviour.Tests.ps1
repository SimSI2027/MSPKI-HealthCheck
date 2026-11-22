# End-to-end credential tests (audit 2 verification, Fix log 2 item 5). The credential harness (tests/CredentialHarness.ps1) records
# every directory bind, HTTP request and TLS handshake the tool attempts. Each test runs a real stage of the tool (endpoint analysis,
# AD context) against a loopback HTTP server and a fake directory, and proves that no bind goes to a host that only an unverified
# object named. The tests mock only functions and cmdlets that existed before the fixes, so on the old code they fail because of
# what the old code did, not because something is missing. Hosts are 127.0.0.1 and example.test names only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot 'CredentialHarness.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    $script:attacker = New-TestCertificate -Subject 'CN=Example Attacker CA' -DaysBefore 10 -DaysValid 3650
    $script:routes = [hashtable]::Synchronized(@{})
    $script:server = Start-TestHttpServer -Routes $script:routes
    $script:base = $script:server.Base

    # A discovery result: the root and one issuing CA (signed by the root) with the given AIA and CDP URLs, as AD and the CA give them.
    $script:newDiscovery = {
        param([string[]]$AiaUrls = @(), [string[]]$CdpUrls = @(), [string[]]$DomainControllers = @('dc01.corp.example.test'))
        $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900 -AiaUrls $AiaUrls -CdpUrls $CdpUrls
        [pscustomobject]@{
            Certificates = @{ $sub.Public.Thumbprint = $sub.Public; $script:root.Public.Thumbprint = $script:root.Public }
            Inventory = [pscustomobject]@{
                AdContext = [pscustomobject]@{ DomainController = 'dc01.corp.example.test'; ForestDomains = @('corp.example.test'); TrustedDomains = @(); DomainControllers = $DomainControllers }
                CACertificates = @(
                    [pscustomobject]@{ Thumbprint = $sub.Public.Thumbprint; CAName = 'Example Issuing CA'; Lifecycle = 'Current'; Info = [pscustomobject]@{ Subject = $sub.Public.Subject; NotAfter = '2999-01-01T00:00:00Z' } },
                    [pscustomobject]@{ Thumbprint = $script:root.Public.Thumbprint; CAName = 'Example Root CA'; Lifecycle = 'Current'; Info = [pscustomobject]@{ Subject = $script:root.Public.Subject; NotAfter = '2999-01-01T00:00:00Z' } })
                EnterpriseCAs = @()
            }
        }
    }
    # Runs the endpoint stage as the tool does: lead registry from the AD context, discovered leads, then analysis with link following.
    $script:analyse = {
        param($D)
        InModuleScope MspkiHealthCheck -Parameters @{ D = $D } { param($D)
            [void](Initialize-MspkiRun)
            Reset-MspkiLeadRegistry -LocalDomains @($D.Inventory.AdContext.ForestDomains) -DomainControllers @($D.Inventory.AdContext.DomainControllers)
            Register-MspkiDiscoveredLead -Discovery $D
            Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 5 }
    }
    $script:ldap = { param([string]$HostName, [string]$Cn) 'ldap://{0}/CN={1},CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint' -f $HostName, $Cn }
}

AfterAll { Stop-TestHttpServer -Server $script:server }

Describe 'Credential behaviour: no bind, no handshake and no credentials because of an unverified object' {
    It 'sends no bind to an ldap:// host planted in a forged certificate (the root''s public key, wrong signature)' {
        $planted = & $script:ldap 'planted.corp.example.test' 'Example Root CA'
        $forged = New-TestForgedCertificate -Subject $script:root.Public.Subject -PublicKeyOf $script:root.Public -IssuerName 'CN=Example Attacker CA' `
            -SigningKey $script:attacker.Key -CdpUrls @($planted) -AiaUrls @('https://planted-web.corp.example.test/x.crt')
        $script:routes['/e2e-forged.crt'] = @{ Status = 200; Body = $forged.RawData }
        Install-TestCredentialRecorder
        $null = & $script:analyse (& $script:newDiscovery -AiaUrls @("$($script:base)/e2e-forged.crt"))
        @(Get-TestCredentialEvent -Kind Bind -Server 'planted.corp.example.test').Count | Should -Be 0
        @(Get-TestCredentialEvent -Kind Tls -Server 'planted-web.corp.example.test').Count | Should -Be 0
        @(Get-TestCredentialEvent -Kind Http -Server '127.0.0.1').Count | Should -BeGreaterThan 0
        @(Get-TestCredentialedRequest -Server $script:server).Count | Should -Be 0
    }

    It 'sends no bind to an ldap:// host planted in a CRL whose signature no trusted CA certificate verifies' {
        # The CRL at the issuing CA's CDP is signed by an attacker key. The attacker also serves, at the issuing CA's AIA, a forged
        # certificate with the root's public key whose own AIA hands out the attacker's CA certificate: if the forged certificate
        # were trusted, the attacker's certificate would be too, and it would "verify" the CRL.
        $planted = & $script:ldap 'planted-crl.corp.example.test' 'Example Issuing CA'
        $forged = New-TestForgedCertificate -Subject $script:root.Public.Subject -PublicKeyOf $script:root.Public -IssuerName $script:attacker.Public.Subject `
            -SigningKey $script:attacker.Key -AiaUrls @("$($script:base)/e2e-attacker.crt")
        $script:routes['/e2e-chain.crt'] = @{ Status = 200; Body = $forged.RawData }
        $script:routes['/e2e-attacker.crt'] = @{ Status = 200; Body = $script:attacker.Public.RawData }
        $script:routes['/e2e-sub.crl'] = @{ Status = 200; Body = (New-TestCrl -Issuer $script:attacker -Number 5 -FreshestUrls @($planted)) }
        Install-TestCredentialRecorder
        $f = & $script:analyse (& $script:newDiscovery -AiaUrls @("$($script:base)/e2e-chain.crt") -CdpUrls @("$($script:base)/e2e-sub.crl"))
        @(Get-TestCredentialEvent -Kind Bind -Server 'planted-crl.corp.example.test').Count | Should -Be 0
        @(Get-TestCredentialEvent -Kind Bind).Count | Should -Be 0
        $crl = @($f | Where-Object { $_.Category -eq 'CRL' -and $_.Endpoint -like '*/e2e-sub.crl' -and $_.Stage -eq 'Analysis' })
        $crl.Count | Should -Be 1
        $crl[0].Confidence | Should -Not -Be 'Confirmed'
        @(Get-TestCredentialedRequest -Server $script:server).Count | Should -Be 0
    }

    It 'does not chase a referral: the bind stays on the selected domain controller' {
        $url = 'ldap://dc01.corp.example.test/CN=Example Issuing CA,CN=CDP,DC=other,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint'
        Install-TestCredentialRecorder -Handler {
            param($Query)
            if ($Query.BaseDN -like '*DC=other,DC=example,DC=test') { return @{ Referral = 'dc9.other.example.test'; ReferralRecords = @(@{ certificaterevocationlist = @(, [byte[]](1, 2, 3)) }) } }
            @{ Records = @() }
        }
        $f = & $script:analyse (& $script:newDiscovery -CdpUrls @($url))
        @(Get-TestCredentialEvent -Kind Bind -Server 'dc9.other.example.test').Count | Should -Be 0
        @(Get-TestCredentialEvent -Kind Bind -Server 'dc01.corp.example.test').Count | Should -Be 1
        $cdp = @($f | Where-Object { $_.Category -eq 'CDP' -and $_.Endpoint -like '*DC=other,DC=example,DC=test*' })
        $cdp.Count | Should -Be 1
        $cdp[0].Status | Should -Be 'Warning'
        ($cdp[0].Evidence -join "`n") | Should -Match 'referral'
    }

    It 'sends no bind to a host whose only claim is a stale domain controller object' {
        # CN=Sites holds the live DC (NTDS Settings, SRV record) and a server object that a removed DC left behind: no NTDS Settings,
        # no SRV record, and a name outside the forest's DNS domains. An LDAP URL from the CA names that host.
        $sites = 'CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=test'
        Install-TestCredentialRecorder -Handler {
            param($Query)
            $s = 'CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=example,DC=test'
            if ($Query.BaseDN -like 'CN=Sites,*' -and $Query.Filter -like '*objectClass=server*') {
                return @{ Records = @(@{ dnshostname = @('dc01.corp.example.test'); distinguishedname = @("CN=DC01,$s") },
                        @{ dnshostname = @('dc-old.example.test'); distinguishedname = @("CN=DC-OLD,$s") }) }
            }
            if ($Query.BaseDN -like 'CN=Sites,*' -and $Query.Filter -eq '(objectClass=nTDSDSA)') { return @{ Records = @(@{ distinguishedname = @("CN=NTDS Settings,CN=DC01,$s") }) } }
            @{ Records = @() }
        }
        # Live evidence: the DNS SRV answer at the runspace call (Invoke-MspkiTimeLimitedScript existed before the fix).
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript -ParameterFilter { $ProgressText -like 'Domain controllers*' } {
            [pscustomobject]@{ Completed = $true; TimedOut = $false; Errors = @(); ElapsedMs = 1
                Output = @(@{ Domain = 'corp.example.test'; Names = [string[]]@('dc01.corp.example.test'); Errors = [string[]]@() }) } }
        Mock -ModuleName MspkiHealthCheck Get-MspkiComputerSystemInfo { [pscustomobject]@{ PartOfDomain = $true; Domain = 'corp.example.test' } }
        Mock -ModuleName MspkiHealthCheck Find-MspkiRootDse { [pscustomobject]@{ Method = 'Serverless'; Constructed = $false; Attempts = @()
                Root = [pscustomobject]@{ configurationNamingContext = 'CN=Configuration,DC=corp,DC=example,DC=test'; rootDomainNamingContext = 'DC=corp,DC=example,DC=test'
                    defaultNamingContext = 'DC=corp,DC=example,DC=test'; schemaNamingContext = 'CN=Schema,CN=Configuration,DC=corp,DC=example,DC=test'
                    dnsHostName = 'dc01.corp.example.test'; serverName = ''; currentTime = ''; domainControllerFunctionality = '7' } } }
        Mock -ModuleName MspkiHealthCheck Get-MspkiForestInfo { [pscustomobject]@{ Name = 'corp.example.test'; RootDomain = 'corp.example.test'; ForestMode = 'x'; Domains = @('corp.example.test'); Trusts = @(); TrustErrors = @() } }
        Mock -ModuleName MspkiHealthCheck Get-MspkiComputerSiteName { 'Default-First-Site-Name' }
        $ctx = InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun); (Get-MspkiAdContext -TimeoutSeconds 5).Data }
        $url = & $script:ldap 'dc-old.example.test' 'Example Issuing CA'
        $null = & $script:analyse (& $script:newDiscovery -CdpUrls @($url) -DomainControllers @($ctx.DomainControllers))
        @(Get-TestCredentialEvent -Kind Bind -Server 'dc-old.example.test').Count | Should -Be 0
        @(Get-TestCredentialEvent -Kind Bind -Server 'dc01.corp.example.test').Count | Should -BeGreaterThan 0
        $null = $sites
    }
}
