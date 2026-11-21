BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650 -CAVersion 0
    $script:sub0 = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full `
        -DaysBefore 400 -DaysValid 30 -CAVersion 0
    $script:sub1 = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full `
        -DaysBefore 10 -DaysValid 900 -CAVersion 65537

    $script:pks = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test'
    $script:caRecord = Get-TestLdapRecord -Name 'enrollment-service.json'
    $script:caRecord['cacertificate'] = @(, $script:sub1.Public.RawData)
    $rd = Get-Content -LiteralPath (Join-Path $script:FixturePath 'rootdse.json') -Raw | ConvertFrom-Json
    $script:rootDse = $rd

    $script:rawCA = @{
        Values = @{
            CAType = 1; CAName = 'Example Issuing CA'; SanitizedCAName = 'Example Issuing CA'; DnsName = 'CA01.corp.example.test'
            ProductVersion = '10.0'; RoleSeparation = 0; KraCertCount = 0; KraCertUsedCount = 0
            Templates = "WebServer`n1.3.6.1.4.1.311.21.8.1.1`nUser`n1.3.6.1.4.1.311.21.8.1.2"
            'CASigCert[0]' = (ConvertTo-TestBase64 $script:sub0.Public.RawData)
            'CASigCert[1]' = (ConvertTo-TestBase64 $script:sub1.Public.RawData)
            'CACertState[0]' = 4; 'CACertState[1]' = 3
            'CACertVersion[0]' = 0; 'CACertVersion[1]' = 65537
            'CrlState[0]' = 3; 'CrlState[1]' = 3
            'CertCdpUrls[1]' = "http://pki.corp.example.test/cdp/Example%20Issuing%20CA.crl`nldap:///CN=Example Issuing CA,CN=ca01,CN=CDP,$($script:pks)?certificateRevocationList?base?objectClass=cRLDistributionPoint"
            'CertAiaUrls[1]' = 'http://pki.corp.example.test/aia/ca01_Example%20Issuing%20CA(1).crt'
        }
        Errors = @{ 'CertAiaOcspUrls[0]' = @{ HResult = '80070057'; Message = 'The parameter is incorrect.' } }
        Fatal  = $null
        Count  = 2
    }

    $script:mockAd = {
        Mock -ModuleName MspkiHealthCheck Get-MspkiComputerSystemInfo { [pscustomobject]@{ PartOfDomain = $true; Domain = 'corp.example.test' } }
        Mock -ModuleName MspkiHealthCheck Get-MspkiRootDse { $script:rootDse }
        Mock -ModuleName MspkiHealthCheck Get-MspkiForestInfo {
            [pscustomobject]@{ Name = 'corp.example.test'; RootDomain = 'corp.example.test'; ForestMode = 'Windows2016Forest'
                Domains = @('corp.example.test', 'child.corp.example.test')
                Trusts = @([pscustomobject]@{ Source = 'Forest'; TargetName = 'partner.example.test'; TrustType = 'Forest'; TrustDirection = 'Bidirectional' })
                TrustErrors = @() }
        }
        Mock -ModuleName MspkiHealthCheck Get-MspkiComputerSiteName { 'Default-First-Site-Name' }
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject {
            if ($Scope -eq 'Base') {
                if ($BaseDN -like 'CN=NTAuthCertificates,*') { return @{ cn = @('NTAuthCertificates'); cacertificate = @(, $script:sub1.Public.RawData) } }
                return @{ cn = @('container'); whenchanged = @([datetime]'2025-01-01') }
            }
            if ($BaseDN -like 'CN=Enrollment Services,*') { return $script:caRecord }
            if ($BaseDN -like 'CN=Certification Authorities,*') {
                return @{ cn = @('Example Root CA'); cacertificate = @(, $script:root.Public.RawData) }
            }
            if ($BaseDN -like 'CN=AIA,*') {
                @{ cn = @('Example Root CA'); cacertificate = @(, $script:root.Public.RawData) }
                @{ cn = @('Example Issuing CA'); cacertificate = @($script:sub0.Public.RawData, $script:sub1.Public.RawData) }
                return
            }
        }
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName { [pscustomobject]@{ Status = 'Pass'; StatusCode = 'OK'; Addresses = @('192.0.2.10'); Error = ''; ElapsedMs = 1 } }
        Mock -ModuleName MspkiHealthCheck Test-MspkiTcpPort { [pscustomobject]@{ Status = 'Pass'; StatusCode = 'OK'; Error = ''; ElapsedMs = 1 } }
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiHttpGet {
            [pscustomobject]@{ Url = $Url; FinalUrl = $Url; HttpStatus = 404; Code = 'HTTP_404'; Redirected = $false
                Hops = @([pscustomobject]@{ Url = $Url; HttpStatus = 404; Location = ''; Error = '' }); ContentType = ''; Bytes = $null; Error = ''; ElapsedMs = 1 }
        }
        Mock -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint { [pscustomobject]@{ Code = 'OK'; Protocol = 'Tls12'; Subject = ''; Issuer = ''; NotAfter = ''; NameMatch = $true; ChainErrors = @() } }
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript {
            [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 5; Errors = @(); Output = @($script:rawCA) }
        }
    }

    $script:discover = {
        param([switch]$SkipNetwork)
        InModuleScope MspkiHealthCheck -Parameters @{ Skip = [bool]$SkipNetwork } {
            param($Skip)
            [void](Initialize-MspkiRun)
            Invoke-MspkiDiscovery -TimeoutSeconds 1 -SkipNetwork:$Skip
        }
    }
}

Describe 'Pure converters' {
    It 'parses msPKI-Enrollment-Servers values' {
        InModuleScope MspkiHealthCheck {
            $a = ConvertFrom-MspkiEnrollmentServerValue -Value "1`n2`n0`nhttps://ces.corp.example.test/x/service.svc/CES"
            $a.Parsed | Should -BeTrue
            $a.Priority | Should -Be 1
            $a.AuthName | Should -Be 'Kerberos'
            $a.RenewalOnly | Should -BeFalse
            $a.Url | Should -Be 'https://ces.corp.example.test/x/service.svc/CES'
            $b = ConvertFrom-MspkiEnrollmentServerValue -Value 'garbage https://ces2.corp.example.test/y'
            $b.Parsed | Should -BeFalse
            $b.Url | Should -Be 'https://ces2.corp.example.test/y'
            $b.AuthName | Should -Be 'Unknown'
            (ConvertFrom-MspkiEnrollmentServerValue -Value '').Url | Should -Be ''
        }
    }

    It 'converts an Enrollment Services record (fixture)' {
        $rec = $script:caRecord.Clone()
        $rec['cacertificate'] = @($script:sub1.Public.RawData, [byte[]](1, 2, 3))
        InModuleScope MspkiHealthCheck -Parameters @{ Rec = $rec } {
            param($Rec)
            $ca = ConvertFrom-MspkiEnrollmentServiceRecord -Record $Rec
            $ca.Name | Should -Be 'Example Issuing CA'
            $ca.DnsHostName | Should -Be 'ca01.corp.example.test'
            $ca.Config | Should -Be 'ca01.corp.example.test\Example Issuing CA'
            @($ca.Templates) | Should -Be @('Machine', 'User', 'WebServer')
            $ca.EnrollmentServers.Count | Should -Be 2
            $ca.EnrollmentServers[0].AuthName | Should -Be 'Kerberos'
            $ca.Certificates.Count | Should -Be 1
            $ca.CertificateErrors.Count | Should -Be 1
        }
    }

    It 'converts raw CA properties and classifies property errors' {
        InModuleScope MspkiHealthCheck -Parameters @{ Raw = $script:rawCA; T1 = $script:sub1.Public.Thumbprint } {
            param($Raw, $T1)
            $p = ConvertFrom-MspkiCAPropertyResult -Raw $Raw
            $p.CATypeName | Should -Be 'EnterpriseSubordinate'
            $p.DnsName | Should -Be 'ca01.corp.example.test'
            $p.SigningCertCount | Should -Be 2
            $p.SigningCertificates[1].Certificate.Thumbprint | Should -Be $T1
            $p.SigningCertificates[1].StateName | Should -Be 'Valid'
            $p.SigningCertificates[0].StateName | Should -Be 'Invalid'
            $p.SigningCertificates[1].CAVersion | Should -Be 'V1.1'
            $p.SigningCertificates[1].CdpUrls.Count | Should -Be 2
            $p.Templates.Count | Should -Be 2
            $p.Templates[0].Name | Should -Be 'WebServer'
            $p.PropertyErrors[0].Class | Should -Be 'Unsupported'
            $p.PropertyErrors[0].HResult | Should -Be '0x80070057'
        }
    }

    It 'escapes LDAP filter values and converts DNs' {
        InModuleScope MspkiHealthCheck {
            ConvertTo-MspkiLdapFilterValue -Value 'a*(b)\c' | Should -Be 'a\2a\28b\29\5cc'
            ConvertFrom-MspkiDistinguishedName -DistinguishedName 'CN=x,DC=Corp,DC=Example,DC=Test' | Should -Be 'corp.example.test'
        }
    }
}

Describe 'Invoke-MspkiDiscovery' {
    It 'stops with UNSUPPORTED on a computer that is not domain-joined' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiComputerSystemInfo { [pscustomobject]@{ PartOfDomain = $false; Domain = 'WORKGROUP' } }
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
        $d = & $script:discover
        $d.Findings.Count | Should -Be 1
        $d.Findings[0].StatusCode | Should -Be 'UNSUPPORTED'
        $d.Findings[0].Status | Should -Be 'Skipped'
        $d.Inventory.AdContext.Ready | Should -BeFalse
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
    }

    It 'reports an unreachable domain controller as a failure, not a permission problem' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiComputerSystemInfo { [pscustomobject]@{ PartOfDomain = $true; Domain = 'corp.example.test' } }
        Mock -ModuleName MspkiHealthCheck Get-MspkiRootDse { throw (New-Object System.Runtime.InteropServices.COMException('The server is not operational.', [int]0x8007203A)) }
        $d = & $script:discover
        $f = $d.Findings | Where-Object { $_.Role -eq 'DomainController' }
        $f.Status | Should -Be 'Fail'
        $f.StatusCode | Should -Be 'RETRIEVAL_FAIL'
        $d.Inventory.AdContext.Ready | Should -BeFalse
    }

    It 'reports a missing Public Key Services container as NOT_CONFIGURED' {
        & $script:mockAd
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject -ParameterFilter { $BaseDN -like 'CN=Public Key Services,*' } {
            throw (New-Object System.Runtime.InteropServices.COMException('There is no such object on the server.', [int]0x80072030))
        }
        $d = & $script:discover
        ($d.Findings | Where-Object { $_.Target -eq 'Public Key Services' }).StatusCode | Should -Be 'NOT_CONFIGURED'
        $d.Inventory.PksExists | Should -BeFalse
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript -Times 0 -Exactly
    }

    Context 'with an Enterprise CA that answers' {
        BeforeAll {
            & $script:mockAd
            $script:d = & $script:discover
        }
        It 'discovers forest, DC, site, containers and trusts' {
            $f = $script:d.Findings
            ($f | Where-Object { $_.Role -eq 'Forest' }).Target | Should -Be 'corp.example.test'
            ($f | Where-Object { $_.Role -eq 'DomainController' }).Target | Should -Be 'dc01.corp.example.test'
            ($f | Where-Object { $_.Role -eq 'Site' }).Target | Should -Be 'Default-First-Site-Name'
            @($f | Where-Object { $_.Category -eq 'ADContainer' -and $_.StatusCode -eq 'OK' }).Count | Should -Be 8
            $script:d.Inventory.AdContext.TrustedDomains | Should -Contain 'partner.example.test'
        }
        It 'confirms the CA type from the CA and keeps every source' {
            $ca = $script:d.Findings | Where-Object { $_.Category -eq 'CA' -and $_.Message -like 'Enterprise CA*' }
            $ca.Role | Should -Be 'EnterpriseSubordinate'
            $ca.Confidence | Should -Be 'Confirmed'
            $ca.Scope | Should -Be 'Local'
            $ca.Sources | Should -Contain 'AD:EnrollmentServices'
            $ca.Sources | Should -Contain 'CA:GetCAProperty'
            $p = $script:d.Findings | Where-Object { $_.Message -like 'CA properties read*' }
            $p.TcpStatus | Should -Be 'Pass'
            ($p.Evidence -join "`n") | Should -Match 'CertAiaOcspUrls\[0\] not read: Unsupported'
        }
        It 'lists every CA certificate generation once with current and historical' {
            $certs = @($script:d.Inventory.CACertificates)
            $certs.Count | Should -Be 3
            @($certs | Where-Object { $_.CAName -eq 'Example Issuing CA' -and $_.Lifecycle -eq 'Current' }).Count | Should -Be 1
            @($certs | Where-Object { $_.CAName -eq 'Example Issuing CA' -and $_.Lifecycle -eq 'Historical' }).Count | Should -Be 1
            ($certs | Where-Object { $_.Role -eq 'StandaloneRoot' }).Lifecycle | Should -Be 'Current'
            $script:d.Certificates.Count | Should -Be 3
        }
        It 'produces a JSON-safe inventory without certificate objects' {
            $json = ConvertTo-Json -InputObject $script:d.Inventory -Depth 12
            $json | Should -Not -Match 'RawData'
            $json | Should -Not -Match 'PrivateKey'
            $null = $json | ConvertFrom-Json
        }
        It 'raises no exit code beyond informational' {
            InModuleScope MspkiHealthCheck -Parameters @{ F = $script:d.Findings } { param($F) Get-MspkiExitCode -Findings $F | Should -Be 0 }
        }
    }

    It 'keeps permission denied on the CA separate and never shows Confirmed without the CA' {
        & $script:mockAd
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript {
            [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 5; Errors = @()
                Output = @(@{ Values = @{}; Errors = @{}; Count = -1; Fatal = @{ HResult = '80070005'; Message = 'Access is denied.' } }) }
        }
        $d = & $script:discover
        $p = $d.Findings | Where-Object { $_.Category -eq 'CA' -and $_.Message -like 'Permission denied*' }
        $p.StatusCode | Should -Be 'PERMISSION_DENIED'
        $p.Status | Should -Be 'Skipped'
        $p.DiscoveryStatus | Should -Be 'PermissionDenied'
        ($d.Findings | Where-Object { $_.Message -like 'Enterprise CA*' }).Confidence | Should -Be 'Referenced'
        @($d.Findings | Where-Object { $_.Category -eq 'CA' -and $_.Confidence -eq 'Confirmed' }).Count | Should -Be 0
        InModuleScope MspkiHealthCheck -Parameters @{ F = $d.Findings } { param($F) Get-MspkiExitCode -Findings $F | Should -Be 6 }
    }

    It 'reports an RPC failure on the CA as RETRIEVAL_FAIL, not PERMISSION_DENIED' {
        & $script:mockAd
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript {
            [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 5; Errors = @()
                Output = @(@{ Values = @{}; Errors = @{}; Count = -1; Fatal = @{ HResult = '800706BA'; Message = 'The RPC server is unavailable.' } }) }
        }
        $d = & $script:discover
        $p = $d.Findings | Where-Object { $_.Category -eq 'CA' -and $_.Endpoint -like '*\Example Issuing CA' -and $_.Message -notlike 'Enterprise CA*' }
        $p.StatusCode | Should -Be 'RETRIEVAL_FAIL'
        $p.Status | Should -Be 'Fail'
    }

    It 'stops at TCP 135 when the CA host does not answer' {
        & $script:mockAd
        Mock -ModuleName MspkiHealthCheck Test-MspkiTcpPort { [pscustomobject]@{ Status = 'Fail'; StatusCode = 'TCP_FAIL'; Error = 'refused'; ElapsedMs = 1 } }
        $d = & $script:discover
        $p = $d.Findings | Where-Object { $_.StatusCode -eq 'TCP_FAIL' }
        $p.Status | Should -Be 'Fail'
        $p.TcpStatus | Should -Be 'Fail'
        $p.DnsStatus | Should -Be 'Pass'
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript -Times 0 -Exactly
    }

    It 'reports a CA that does not answer in time as TIMEOUT' {
        & $script:mockAd
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript {
            [pscustomobject]@{ Completed = $false; TimedOut = $true; ElapsedMs = 15000; Errors = @(); Output = @() }
        }
        $d = & $script:discover
        ($d.Findings | Where-Object { $_.StatusCode -eq 'TIMEOUT' }).Status | Should -Be 'Fail'
    }

    It 'runs discovery, lead registration and CA certificate health end to end' {
        & $script:mockAd
        $r = Start-MspkiHealthCheck -OutputPath (Join-Path $TestDrive 'e2e') -TimeoutSeconds 1
        $j = Get-Content -LiteralPath $r.ResultsPath -Raw | ConvertFrom-Json
        @($j.Inventory.Leads | Where-Object { $_.Kind -eq 'CDP' }).Count | Should -Be 2
        @($j.Inventory.Leads | Where-Object { $_.Kind -eq 'AIA' }).Count | Should -Be 1
        @($j.Inventory.Leads | Where-Object { $_.Kind -eq 'CES' -and $_.Confidence -eq 'Referenced' }).Count | Should -Be 2
        # Constructed candidates on the CA host are leads too, but always Inferred.
        @($j.Inventory.Leads | Where-Object { ($_.Kind -eq 'CES' -or $_.Kind -eq 'CEP') -and $_.Confidence -eq 'Inferred' -and @($_.Sources) -contains 'Constructed:CAHost' }).Count | Should -BeGreaterThan 0
        @($j.Findings | Where-Object { $_.Category -eq 'Hierarchy' }).Count | Should -Be 3
        @($j.Findings | Where-Object { $_.Stage -eq 'Analysis' -and $_.Category -eq 'CA' }).Count | Should -Be 3
        ($j.Findings | Where-Object { $_.Stage -eq 'Analysis' -and $_.Category -eq 'CA' -and $_.Message -like 'Historical*' }).Status | Should -Be 'Pass'
        @($j.Findings | Where-Object { $_.Category -eq 'CDP' -and $_.StatusCode -eq 'HTTP_404' }).Count | Should -Be 1
        @($j.Findings | Where-Object { $_.Category -eq 'CDP' -and $_.StatusCode -eq 'PUBLICATION_FAIL' }).Count | Should -Be 1
        $j.RunInfo.Completed | Should -BeTrue
        $j.ExitCode | Should -Be 4
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiHttpGet -Times 2 -Exactly -ParameterFilter { $Url -notmatch 'service.svc' }
        # CEP/CES: the 2 URLs from AD plus the 6 constructed candidates on the CA host.
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiHttpGet -Times 8 -Exactly -ParameterFilter { $Url -match 'service.svc' }
    }

    It 'contacts no host with -SkipNetwork' {
        & $script:mockAd
        $d = & $script:discover -SkipNetwork
        ($d.Findings | Where-Object { $_.Message -like '*-SkipNetwork*' }).Status | Should -Be 'Skipped'
        Should -Invoke -ModuleName MspkiHealthCheck Resolve-MspkiDnsName -Times 0 -Exactly
        Should -Invoke -ModuleName MspkiHealthCheck Test-MspkiTcpPort -Times 0 -Exactly
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript -Times 0 -Exactly
    }
}
