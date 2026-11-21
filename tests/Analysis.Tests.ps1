BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    $script:sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full `
        -DaysValid 900 -CdpUrls @('http://pki.corp.example.test/CertEnroll/Example Root CA.crl', 'ldap:///CN=Example Root CA,CN=ca00,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint') `
        -AiaUrls @('http://pki.corp.example.test/CertEnroll/ca00_Example%20Root%20CA.crt') -OcspUrls @('http://ocsp.corp.example.test/ocsp')

    function New-TestEntry {
        param($Cert, [string]$Role = 'EnterpriseSubordinate', [string]$Lifecycle = 'Current', [string]$LifecycleConfidence = 'Confirmed',
              [string]$CAName = 'Example Issuing CA', [string[]]$Sources = @('CA:GetCAProperty', 'AD:EnrollmentServices'))
        $info = InModuleScope MspkiHealthCheck -Parameters @{ C = $Cert } { param($C) Get-MspkiCertificateInfo -Certificate $C }
        return [pscustomobject]@{ Thumbprint = $Cert.Thumbprint; CAName = $CAName; Role = $Role; Lifecycle = $Lifecycle
            LifecycleConfidence = $LifecycleConfidence; LifecycleBasis = 'test'; Sources = $Sources; Info = $info; Certificate = $Cert }
    }
    $script:newEntry = ${function:New-TestEntry}
    $script:trusted = { param($tp) $true }
    $script:untrusted = { param($tp) $false }
}

Describe 'DER reader' {
    It 'decodes OIDs, integers and times' {
        InModuleScope MspkiHealthCheck {
            ConvertFrom-MspkiDerOid -Content ([byte[]](0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B)) | Should -Be '1.2.840.113549.1.1.11'
            ConvertFrom-MspkiDerOid -Content ([byte[]](0x55, 0x1D, 0x1F)) | Should -Be '2.5.29.31'
            ConvertFrom-MspkiDerInteger -Content ([byte[]](0x00, 0x8F, 0x01)) | Should -Be '8F01'
            $t = [System.Text.Encoding]::ASCII.GetBytes('491231235959Z')
            $b = [byte[]](@([byte]0x17, [byte]$t.Length) + $t)
            (ConvertFrom-MspkiDerTime -Bytes $b -Element (Read-MspkiDerElement -Bytes $b)).Year | Should -Be 2049
            $t = [System.Text.Encoding]::ASCII.GetBytes('500101000000Z')
            $b = [byte[]](@([byte]0x17, [byte]$t.Length) + $t)
            (ConvertFrom-MspkiDerTime -Bytes $b -Element (Read-MspkiDerElement -Bytes $b)).Year | Should -Be 1950
            $t = [System.Text.Encoding]::ASCII.GetBytes('20500101000000Z')
            $b = [byte[]](@([byte]0x18, [byte]$t.Length) + $t)
            $g = ConvertFrom-MspkiDerTime -Bytes $b -Element (Read-MspkiDerElement -Bytes $b)
            $g.Year | Should -Be 2050
            $g.Kind | Should -Be 'Utc'
        }
    }
    It 'rejects truncated data' {
        InModuleScope MspkiHealthCheck {
            { Read-MspkiDerElement -Bytes ([byte[]](0x30, 0x05, 0x01)) } | Should -Throw
            { Read-MspkiDerElement -Bytes ([byte[]](0x30)) } | Should -Throw
        }
    }
}

Describe 'Certificate URLs' {
    It 'extracts CDP, AIA and OCSP URLs from a certificate' {
        InModuleScope MspkiHealthCheck -Parameters @{ C = $script:sub.Public } {
            param($C)
            $u = Get-MspkiCertificateUrl -Certificate $C
            @($u | Where-Object Kind -eq 'CDP').Count | Should -Be 2
            ($u | Where-Object Kind -eq 'AIA').Url | Should -Be 'http://pki.corp.example.test/CertEnroll/ca00_Example%20Root%20CA.crt'
            ($u | Where-Object Kind -eq 'OCSP').Url | Should -Be 'http://ocsp.corp.example.test/ocsp'
            @($u | Where-Object Kind -eq 'Error').Count | Should -Be 0
        }
    }
}

Describe 'Lead registry' {
    BeforeEach { InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test') -TrustedDomains @('partner.example.test') } }

    It 'normalises <A> and <B> to the same key' -TestCases @(
        @{ A = 'HTTP://PKI.Corp.Example.Test/CertEnroll/Example CA.crl'; B = 'https://pki.corp.example.test/certenroll/Example%20CA.crl/' }
        @{ A = 'http://pki.corp.example.test:80/x/'; B = 'https://pki.corp.example.test:443/x' }
        @{ A = 'ldap:///CN=Example%20CA,CN=CDP,DC=corp,DC=example,DC=test?certificateRevocationList'; B = 'LDAP:///CN=Example CA,CN=CDP,DC=corp,DC=example,DC=test?certificateRevocationList' }
    ) {
        param($A, $B)
        InModuleScope MspkiHealthCheck -Parameters @{ A = $A; B = $B } {
            param($A, $B)
            (ConvertTo-MspkiNormalizedUrl $A).Key | Should -Be (ConvertTo-MspkiNormalizedUrl $B).Key
        }
    }

    It 'keeps different ports and paths apart and rejects unusable URLs' {
        InModuleScope MspkiHealthCheck {
            (ConvertTo-MspkiNormalizedUrl 'http://pki.corp.example.test:8080/x').Key | Should -Not -Be (ConvertTo-MspkiNormalizedUrl 'http://pki.corp.example.test/x').Key
            (ConvertTo-MspkiNormalizedUrl 'not a url').Valid | Should -BeFalse
            (ConvertTo-MspkiNormalizedUrl '\\files.corp.example.test\pki\ca.crl').UrlType | Should -Be 'File'
            Add-MspkiLead -Url 'not a url' -Kind CDP -Source 'test' | Should -BeNullOrEmpty
        }
    }

    It 'merges duplicates, keeps every source and both http and https variants' {
        InModuleScope MspkiHealthCheck {
            $a = Add-MspkiLead -Url 'http://pki.corp.example.test/CertEnroll/Example CA.crl' -Kind CDP -Source 'Cert:AAA:CDP' -Origin 'cert A' -RelatedCA 'Example CA'
            $b = Add-MspkiLead -Url 'https://PKI.corp.example.test/certenroll/Example%20CA.crl' -Kind CDP -Source 'CA:Example CA:CertCdpUrls' -Origin 'CA props'
            $c = Add-MspkiLead -Url 'http://pki.corp.example.test/CertEnroll/Example CA.crl' -Kind CDP -Source 'Cert:AAA:CDP'
            [object]::ReferenceEquals($a, $b) | Should -BeTrue
            @(Get-MspkiLead).Count | Should -Be 1
            $a.Sources.Count | Should -Be 2
            $a.Variants.Count | Should -Be 2
            $a.Origins.Count | Should -Be 2
            $a.Scope | Should -Be 'Local'
            $a.Url | Should -Be 'http://pki.corp.example.test/CertEnroll/Example%20CA.crl'
        }
    }

    It 'sets scope from the DNS suffix' {
        InModuleScope MspkiHealthCheck {
            (Add-MspkiLead -Url 'http://pki.partner.example.test/a.crl' -Kind CDP -Source s).Scope | Should -Be 'OtherForest'
            (Add-MspkiLead -Url 'http://crl.example.test/a.crl' -Kind CDP -Source s).Scope | Should -Be 'External'
            (Add-MspkiLead -Url 'ldap:///CN=x,DC=corp,DC=example,DC=test' -Kind CDP -Source s).Scope | Should -Be 'Local'
        }
    }

    It 'enforces the depth limit and the lead cap (logged once as a run limit)' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiLeadRegistry -MaxLeads 2 -MaxDepth 1
            Add-MspkiLead -Url 'http://a.corp.example.test/1.crl' -Kind CDP -Source s -Depth 2 | Should -BeNullOrEmpty
            $null = Add-MspkiLead -Url 'http://a.corp.example.test/1.crl' -Kind CDP -Source s
            $null = Add-MspkiLead -Url 'http://a.corp.example.test/2.crl' -Kind CDP -Source s
            Add-MspkiLead -Url 'http://a.corp.example.test/3.crl' -Kind CDP -Source s | Should -BeNullOrEmpty
            Add-MspkiLead -Url 'http://a.corp.example.test/4.crl' -Kind CDP -Source s | Should -BeNullOrEmpty
            (Get-MspkiLeadStatistic).Dropped | Should -Be 2
            @((Get-MspkiRunValue -Name 'Limits') | Where-Object { $_ -like 'Lead cap*' }).Count | Should -Be 1
        }
    }

    It 'registers leads from CA certificates, CA properties and Enrollment Services with merged sources' {
        $disc = [pscustomobject]@{
            Certificates = @{ $script:sub.Public.Thumbprint = $script:sub.Public }
            Inventory = [pscustomobject]@{
                CACertificates = @([pscustomobject]@{ Thumbprint = $script:sub.Public.Thumbprint; CAName = 'Example Issuing CA' })
                EnterpriseCAs = @([pscustomobject]@{
                    Name = 'Example Issuing CA'
                    EnrollmentServers = @([pscustomobject]@{ Url = 'https://ces.corp.example.test/x/service.svc/CES' })
                    Properties = [pscustomobject]@{ SigningCertificates = @([pscustomobject]@{ Index = 0
                        CdpUrls = @('http://pki.corp.example.test/CertEnroll/Example%20Root%20CA.crl'); AiaUrls = @(); OcspUrls = @() }) }
                })
            }
        }
        InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } {
            param($D)
            Register-MspkiDiscoveredLead -Discovery $D
            $cdp = @(Get-MspkiLead -Kind CDP | Where-Object { $_.UrlType -eq 'Http' })
            $cdp.Count | Should -Be 1
            $cdp[0].Sources.Count | Should -Be 2
            @(Get-MspkiLead -Kind CDP).Count | Should -Be 2
            @(Get-MspkiLead -Kind AIA).Count | Should -Be 1
            @(Get-MspkiLead -Kind OCSP).Count | Should -Be 1
            (Get-MspkiLead -Kind CES).Sources | Should -Contain 'AD:EnrollmentServices:msPKI-Enrollment-Servers'
        }
    }
}

Describe 'Signatures' {
    It 'verifies RSA and ECDSA signatures and rejects the wrong issuer' {
        $other = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
        $ecRoot = New-TestCertificate -Subject 'CN=Example EC Root, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650 -Ecdsa
        $ecSub = New-TestCertificate -Subject 'CN=Example EC Issuing, DC=example, DC=test' -Signer $ecRoot.Full -DaysValid 300 -Ecdsa
        InModuleScope MspkiHealthCheck -Parameters @{ R = $script:root.Public; S = $script:sub.Public; O = $other.Public; ER = $ecRoot.Public; ES = $ecSub.Public } {
            param($R, $S, $O, $ER, $ES)
            (Test-MspkiSignature -SignedBytes $R.RawData -Issuer $R).Valid | Should -BeTrue
            (Test-MspkiSignature -SignedBytes $S.RawData -Issuer $R).Valid | Should -BeTrue
            (Test-MspkiSignature -SignedBytes $S.RawData -Issuer $O).Valid | Should -BeFalse
            (Test-MspkiSignature -SignedBytes $ES.RawData -Issuer $ER).Valid | Should -BeTrue
            (Test-MspkiSignature -SignedBytes ([byte[]](1, 2, 3)) -Issuer $R).Valid | Should -BeNullOrEmpty
        }
    }
}

Describe 'CA certificate health' {
    It 'applies root thresholds: <Days> days -> <Status>/<Code>' -TestCases @(
        @{ Days = 3650; Status = 'Pass'; Code = 'OK' }
        @{ Days = 600; Status = 'Warning'; Code = 'OBJECT_EXPIRING' }
        @{ Days = 200; Status = 'Critical'; Code = 'OBJECT_EXPIRING' }
    ) {
        param($Days, $Status, $Code)
        $r = New-TestCertificate -Subject 'CN=Threshold Root, DC=example, DC=test' -DaysValid $Days
        $e = & $script:newEntry $r.Public 'StandaloneRoot' 'Current' 'Referenced' '' @('AD:CertificationAuthorities')
        InModuleScope MspkiHealthCheck -Parameters @{ E = $e; T = $script:trusted; S = $Status; C = $Code } {
            param($E, $T, $S, $C)
            $f = Test-MspkiCACertificateHealth -Entries @($E) -TrustTest $T
            $v = $f | Where-Object Category -eq 'CA'
            $v.Status | Should -Be $S
            $v.StatusCode | Should -Be $C
            $v.Confidence | Should -Be 'Referenced'
            ($f | Where-Object Category -eq 'Hierarchy').StatusCode | Should -Be 'OK'
        }
    }

    It 'applies subordinate thresholds and reports expiry: <Days> days -> <Status>/<Code>' -TestCases @(
        @{ Days = 400; Status = 'Pass'; Code = 'OK' }
        @{ Days = 150; Status = 'Warning'; Code = 'OBJECT_EXPIRING' }
        @{ Days = 60; Status = 'Critical'; Code = 'OBJECT_EXPIRING' }
        @{ Days = -5; Status = 'Critical'; Code = 'OBJECT_EXPIRED' }
    ) {
        param($Days, $Status, $Code)
        $s = New-TestCertificate -Subject 'CN=Threshold Sub, DC=example, DC=test' -Signer $script:root.Full -DaysBefore 500 -DaysValid $Days
        $entries = @((& $script:newEntry $s.Public), (& $script:newEntry $script:root.Public 'StandaloneRoot' 'Current' 'Referenced' '' @('AD:AIA')))
        InModuleScope MspkiHealthCheck -Parameters @{ E = $entries; T = $script:trusted; S = $Status; C = $Code; Tp = $s.Public.Thumbprint } {
            param($E, $T, $S, $C, $Tp)
            $f = Test-MspkiCACertificateHealth -Entries $E -TrustTest $T
            $v = $f | Where-Object { $_.Category -eq 'CA' -and $_.RelatedCA -like "*$Tp*" }
            $v.Status | Should -Be $S
            $v.StatusCode | Should -Be $C
            $v.Confidence | Should -Be 'Confirmed'
        }
    }

    It 'limits the effective expiry by the parent and treats expired historical certificates as not applicable' {
        $shortRoot = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 100 -Key $script:root.Key
        $old = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysBefore 700 -DaysValid -10
        $entries = @(
            (& $script:newEntry $script:sub.Public),
            (& $script:newEntry $shortRoot.Public 'StandaloneRoot' 'Current' 'Inferred' '' @('AD:CertificationAuthorities')),
            (& $script:newEntry $old.Public 'EnterpriseSubordinate' 'Historical')
        )
        InModuleScope MspkiHealthCheck -Parameters @{ E = $entries; T = $script:trusted; Sub = $script:sub.Public.Thumbprint; Old = $old.Public.Thumbprint; Root = $shortRoot.Public.Thumbprint } {
            param($E, $T, $Sub, $Old, $Root)
            $f = Test-MspkiCACertificateHealth -Entries $E -TrustTest $T
            $s = $f | Where-Object { $_.Category -eq 'CA' -and $_.RelatedCA -like "*$Sub*" }
            $s.Status | Should -Be 'Warning'
            ($s.Evidence -join ' ') | Should -Match 'limited by the parent'
            $o = $f | Where-Object { $_.Category -eq 'CA' -and $_.RelatedCA -like "*$Old*" }
            $o.Status | Should -Be 'NotApplicable'
            $o.StatusCode | Should -Be 'NOT_APPLICABLE'
            ($f | Where-Object { $_.Category -eq 'CA' -and $_.RelatedCA -like "*$Root*" }).Confidence | Should -Be 'Inferred'
        }
    }

    It 'separates partial chain, untrusted root and invalid signature' {
        $impostor = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
        InModuleScope MspkiHealthCheck -Parameters @{ Sub = (& $script:newEntry $script:sub.Public); Root = (& $script:newEntry $script:root.Public 'StandaloneRoot' 'Current' 'Referenced' '' @('AD:AIA'))
            Imp = (& $script:newEntry $impostor.Public 'StandaloneRoot' 'Current' 'Referenced' '' @('AD:AIA')); T = $script:trusted; U = $script:untrusted; Tp = $script:sub.Public.Thumbprint } {
            param($Sub, $Root, $Imp, $T, $U, $Tp)
            $pick = { param($fs) $fs | Where-Object { $_.Category -eq 'Hierarchy' -and $_.RelatedCA -like "*$Tp*" } }
            $partial = & $pick (Test-MspkiCACertificateHealth -Entries @($Sub) -TrustTest $T)
            $partial.StatusCode | Should -Be 'CHAIN_PARTIAL'
            $partial.Status | Should -Be 'Warning'
            $partial.ChainStatus | Should -Be 'Fail'
            $untrusted = & $pick (Test-MspkiCACertificateHealth -Entries @($Sub, $Root) -TrustTest $U)
            $untrusted.StatusCode | Should -Be 'CHAIN_UNTRUSTED_ROOT'
            $untrusted.Notes | Should -Match 'local trust'
            $bad = & $pick (Test-MspkiCACertificateHealth -Entries @($Sub, $Imp) -TrustTest $T)
            $bad.StatusCode | Should -Be 'SIGNATURE_INVALID'
            $bad.Status | Should -Be 'Fail'
            $ok = & $pick (Test-MspkiCACertificateHealth -Entries @($Sub, $Root) -TrustTest $T)
            $ok.StatusCode | Should -Be 'OK'
            ($ok.Evidence -join ' ') | Should -Match 'Example Issuing CA.*->.*Example Root CA'
        }
    }
}
