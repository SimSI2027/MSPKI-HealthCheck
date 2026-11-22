BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:ldapAia = 'ldap:///CN=Example Root CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=example,DC=test?cACertificate?base?objectClass=certificationAuthority'
    $script:ldapCdp = 'ldap:///CN=Example Root CA,CN=ca01,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint'
    $script:httpCdp = 'http://pki.example.test/CertEnroll/Example%20Root%20CA.crl'
}

Describe 'AIA/CDP published only over LDAP' {
    It 'is a Warning (design risk) with the reason and the owner fix when every URL is LDAP' {
        $f = InModuleScope MspkiHealthCheck -Parameters @{ U = $script:ldapCdp } { param($U) Test-MspkiPublicationProtocol -IssuerName 'Example Root CA' -Kind 'CDP' -Urls @($U) }
        $f.Status | Should -Be 'Warning'
        $f.StatusCode | Should -Be 'CONFIG_RISK'
        $f.Severity | Should -Be 'Medium'
        $f.Message | Should -Match 'only over LDAP'
        $f.Notes | Should -Match 'not domain members'
        $f.Remediation | Should -Match 'HTTP'
    }
    It 'is a Pass when at least one HTTP URL is published, and nothing when there are no URLs (a root)' {
        $f = InModuleScope MspkiHealthCheck -Parameters @{ A = $script:ldapCdp; B = $script:httpCdp } { param($A, $B) Test-MspkiPublicationProtocol -IssuerName 'Example Root CA' -Kind 'CDP' -Urls @($A, $B) }
        $f.Status | Should -Be 'Pass'
        InModuleScope MspkiHealthCheck { Test-MspkiPublicationProtocol -IssuerName 'Example Root CA' -Kind 'AIA' -Urls @() } | Should -BeNullOrEmpty
    }
}

Describe 'Retrieval order used by Windows clients' {
    It 'warns when the first URL fails and a later one works' {
        $f = InModuleScope MspkiHealthCheck -Parameters @{ A = $script:ldapCdp; B = $script:httpCdp } { param($A, $B)
            Test-MspkiRetrievalOrder -IssuerName 'Example Root CA' -Kind 'CDP' -Urls @($A, $B) -UrlOutcome @{ $A = 'Failed'; $B = 'Usable' } }
        $f.Status | Should -Be 'Warning'
        $f.Message | Should -Match '1 failing CDP URL'
        ($f.Evidence -join "`n") | Should -Match '1\. ldap.*Fail'
    }
    It 'passes when the first URL works, and fails when none does' {
        $ok = InModuleScope MspkiHealthCheck -Parameters @{ A = $script:ldapCdp; B = $script:httpCdp } { param($A, $B)
            Test-MspkiRetrievalOrder -IssuerName 'Example Root CA' -Kind 'CDP' -Urls @($A, $B) -UrlOutcome @{ $A = 'Usable'; $B = 'Failed' } }
        $ok.Status | Should -Be 'Pass'
        $bad = InModuleScope MspkiHealthCheck -Parameters @{ A = $script:ldapCdp } { param($A) Test-MspkiRetrievalOrder -IssuerName 'Example Root CA' -Kind 'CDP' -Urls @($A) -UrlOutcome @{ $A = 'Failed' } }
        $bad.Status | Should -Be 'Fail'
        $bad.Severity | Should -Be 'High'
    }
}

Describe 'CA certificate generations' {
    BeforeAll {
        $script:gen = {
            param([string]$Thumb, [int]$KeySize = 2048, [string]$Oid = '1.2.840.113549.1.1.11', [int]$AfterYears = 2, $Parents = @(), [bool]$Self = $false, [int]$StartDays = -100)
            [pscustomobject]@{ Thumbprint = $Thumb; Subject = 'CN=Example Issuing CA, DC=corp, DC=example, DC=test'; Issuer = 'CN=Example Root CA, DC=example, DC=test'
                NotBefore = [DateTime]::UtcNow.AddDays($StartDays); NotAfter = [DateTime]::UtcNow.AddYears($AfterYears); KeyAlgorithm = 'RSA'; KeySize = $KeySize
                SignatureAlgorithm = 'x'; SignatureOid = $Oid; SelfIssued = $Self; Lifecycle = 'Current'; CAName = 'Example Issuing CA'; Parents = $Parents }
        }
        $script:parent = [pscustomobject]@{ Subject = 'CN=Example Root CA, DC=example, DC=test'; Thumbprint = ('B' * 40); NotAfter = [DateTime]::UtcNow.AddYears(5) }
    }
    It 'passes a generation with RSA 2048, SHA-256 and validity inside its issuer, and describes the overlap with the next generation' {
        $a = & $script:gen ('A' * 40) -Parents @($script:parent) -StartDays -300
        $b = & $script:gen ('C' * 40) -Parents @($script:parent) -StartDays -10
        $fs = @(InModuleScope MspkiHealthCheck -Parameters @{ G = @($a, $b) } { param($G) Test-MspkiCaGeneration -Generations $G })
        $fs.Count | Should -Be 2
        $fs[0].Status | Should -Be 'Pass'
        ($fs[0].Evidence -join "`n") | Should -Match 'Overlap: the next generation starts'
        $fs[0].EntityIds | Should -Be @('cacert:' + ('a' * 40))
    }
    It 'fails a weak key or SHA-1 signature on an issuing CA, and warns when it outlives its issuer' {
        $weak = & $script:gen ('D' * 40) -KeySize 1024 -Oid '1.2.840.113549.1.1.5' -Parents @($script:parent)
        $f = @(InModuleScope MspkiHealthCheck -Parameters @{ G = @($weak) } { param($G) Test-MspkiCaGeneration -Generations $G })[0]
        $f.Status | Should -Be 'Fail'
        $f.Message | Should -Match '1024 bits'
        $f.Message | Should -Match 'sha1RSA'
        $long = & $script:gen ('E' * 40) -AfterYears 9 -Parents @($script:parent)
        $w = @(InModuleScope MspkiHealthCheck -Parameters @{ G = @($long) } { param($G) Test-MspkiCaGeneration -Generations $G })[0]
        $w.Status | Should -Be 'Warning'
        $w.Message | Should -Match 'after its issuer'
    }
}

Describe 'NTAuth versus AIA' {
    BeforeAll {
        $script:c = { param([string]$T, [bool]$Aia, [bool]$Nt) [pscustomobject]@{ Thumbprint = $T; Subject = 'CN=Example Issuing CA, DC=corp, DC=example, DC=test'; InAIA = $Aia; InNTAuth = $Nt
            NotBefore = [DateTime]::UtcNow.AddDays(-200); NotAfter = [DateTime]::UtcNow.AddYears(1); Lifecycle = 'Unknown' } }
    }
    It 'warns about an older generation that is in NTAuth but not in AIA' {
        $fs = @(InModuleScope MspkiHealthCheck -Parameters @{ L = @((& $script:c ('A' * 40) $true $true), (& $script:c ('B' * 40) $false $true)) } { param($L) Test-MspkiNtAuthAiaMatch -CACertificates $L })
        $fs.Count | Should -Be 1
        $fs[0].Status | Should -Be 'Warning'
        $fs[0].StatusCode | Should -Be 'CONFIG_MISMATCH'
        $fs[0].Message | Should -Match 'in NTAuth but not in the AIA container'
        $fs[0].Remediation | Should -Match 'dspublish'
    }
    It 'passes when every NTAuth generation is in AIA, and ignores an expired one' {
        $old = & $script:c ('C' * 40) $false $true
        $old.NotAfter = [DateTime]::UtcNow.AddDays(-1)
        $fs = @(InModuleScope MspkiHealthCheck -Parameters @{ L = @((& $script:c ('A' * 40) $true $true), $old) } { param($L) Test-MspkiNtAuthAiaMatch -CACertificates $L })
        $fs.Count | Should -Be 1
        $fs[0].Status | Should -Be 'Pass'
    }
}

Describe 'Offline root CRL lifetime' {
    It 'warns when the CRL of an offline root expires soon, and is Critical when it expired' {
        $f = InModuleScope MspkiHealthCheck { Test-MspkiOfflineRootCrl -RootName 'Example Offline Root' -ThisUpdate ([DateTime]::UtcNow.AddDays(-170)) -NextUpdate ([DateTime]::UtcNow.AddDays(10)) }
        $f.Status | Should -Be 'Warning'
        $f.StatusCode | Should -Be 'OBJECT_EXPIRING'
        $f.Notes | Should -Match 'every certificate under this root'
        $x = InModuleScope MspkiHealthCheck { Test-MspkiOfflineRootCrl -RootName 'Example Offline Root' -ThisUpdate ([DateTime]::UtcNow.AddDays(-200)) -NextUpdate ([DateTime]::UtcNow.AddDays(-2)) }
        $x.Status | Should -Be 'Critical'
    }
    It 'passes a long CRL with time left, warns about a very short lifetime, and warns when no CRL was read' {
        (InModuleScope MspkiHealthCheck { Test-MspkiOfflineRootCrl -RootName 'R' -ThisUpdate ([DateTime]::UtcNow.AddDays(-30)) -NextUpdate ([DateTime]::UtcNow.AddDays(150)) }).Status | Should -Be 'Pass'
        $s = InModuleScope MspkiHealthCheck { Test-MspkiOfflineRootCrl -RootName 'R' -ThisUpdate ([DateTime]::UtcNow.AddDays(-1)) -NextUpdate ([DateTime]::UtcNow.AddDays(6)) }
        $s.StatusCode | Should -Be 'CONFIG_RISK'
        $n = InModuleScope MspkiHealthCheck { Test-MspkiOfflineRootCrl -RootName 'R' }
        $n.StatusCode | Should -Be 'PUBLICATION_FAIL'
        $n.Confidence | Should -Be 'Referenced'
    }
}

Describe 'OCSP responder that no certificate names' {
    BeforeAll { $script:http = { param([int]$S) [pscustomobject]@{ Url = 'http://ca01.example.test/ocsp/'; HttpStatus = $S; ElapsedMs = 9 } } }
    It 'warns (Inferred) when /ocsp/ answers on a CA host and no OCSP URL names that host' {
        $f = InModuleScope MspkiHealthCheck -Parameters @{ H = (& $script:http 500) } { param($H) Test-MspkiOcspResponderUse -HostName 'ca01.example.test' -Http $H -OcspUrls @() }
        $f.Status | Should -Be 'Warning'
        $f.Confidence | Should -Be 'Inferred'
        $f.Message | Should -Match 'no client will ever ask it'
    }
    It 'passes when an OCSP URL names the host, and reports nothing for 404 or no answer' {
        $f = InModuleScope MspkiHealthCheck -Parameters @{ H = (& $script:http 200) } { param($H) Test-MspkiOcspResponderUse -HostName 'ca01.example.test' -Http $H -OcspUrls @('http://ca01.example.test/ocsp') }
        $f.Status | Should -Be 'Pass'
        InModuleScope MspkiHealthCheck -Parameters @{ H = (& $script:http 404) } { param($H) Test-MspkiOcspResponderUse -HostName 'ca01.example.test' -Http $H } | Should -BeNullOrEmpty
        InModuleScope MspkiHealthCheck -Parameters @{ H = (& $script:http 0) } { param($H) Test-MspkiOcspResponderUse -HostName 'ca01.example.test' -Http $H } | Should -BeNullOrEmpty
    }
}

Describe 'HTTPS that closes every TLS handshake' {
    It 'warns for an endpoint where the server closed the handshake, and says what it breaks' {
        $t = [pscustomobject]@{ Target = 'ca01.example.test:443'; ServerClosed = $true; OfferedProtocols = 'Tls12, Tls13'; Error = 'closed'; ElapsedMs = 4 }
        $fs = @(InModuleScope MspkiHealthCheck -Parameters @{ T = @($t) } { param($T) Test-MspkiTlsResetEndpoint -TlsResults $T -HostCategory @{ 'ca01.example.test' = 'CA' } })
        $fs.Count | Should -Be 1
        $fs[0].Category | Should -Be 'CA'
        $fs[0].TlsStatus | Should -Be 'Fail'
        $fs[0].TcpStatus | Should -Be 'Pass'
        $fs[0].Notes | Should -Match 'CES/CEP'
        $fs[0].EntityIds | Should -Be @('host:ca01.example.test')
    }
    It 'reports nothing for a normal handshake or a name mismatch' {
        $ok = [pscustomobject]@{ Target = 'pki.example.test:443'; ServerClosed = $false; Code = 'OK' }
        $mm = [pscustomobject]@{ Target = 'pki.example.test:8443'; ServerClosed = $false; Code = 'TLS_NAME_MISMATCH' }
        @(InModuleScope MspkiHealthCheck -Parameters @{ T = @($ok, $mm) } { param($T) Test-MspkiTlsResetEndpoint -TlsResults $T }).Count | Should -Be 0
    }
    It 'marks a reset handshake from a loopback listener that closes at once as ServerClosed' {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = $listener.LocalEndpoint.Port
        $ps = [powershell]::Create()
        [void]$ps.AddScript({ param($l) $c = $l.AcceptTcpClient(); $c.Client.LingerState = New-Object System.Net.Sockets.LingerOption($true, 0); $c.Close() }).AddArgument($listener)
        $h = $ps.BeginInvoke()
        try {
            $r = InModuleScope MspkiHealthCheck -Parameters @{ P = $port } { param($P) Reset-MspkiProbeCache; Test-MspkiTlsEndpoint -HostName '127.0.0.1' -Port $P -TimeoutMs 3000 }
            $r.ServerClosed | Should -BeTrue
            $r.Code | Should -Be 'TLS_HANDSHAKE_FAIL'
        }
        finally { [void]$ps.EndInvoke($h); $ps.Dispose(); $listener.Stop() }
    }
}

Describe 'Certificate SAN names without DNS' {
    It 'warns for an alias with no DNS record' {
        $fs = @(InModuleScope MspkiHealthCheck {
            Test-MspkiSanDnsName -Subject 'CN=web01.corp.example.test' -Thumbprint ('A' * 40) -Where 'LocalMachine\My on this computer' -Names @('web01.corp.example.test', 'app.corp.example.test') `
                -Dns @{ 'web01.corp.example.test' = [pscustomobject]@{ StatusCode = 'OK'; Error = '' }; 'app.corp.example.test' = [pscustomobject]@{ StatusCode = 'DNS_FAIL'; Error = 'No such host is known.' } } })
        $fs.Count | Should -Be 1
        $fs[0].Status | Should -Be 'Warning'
        $fs[0].Target | Should -Be 'app.corp.example.test'
        $fs[0].DnsStatus | Should -Be 'Fail'
    }
    It 'passes when every name resolves, and ignores wildcard names' {
        $fs = @(InModuleScope MspkiHealthCheck {
            Test-MspkiSanDnsName -Subject 'CN=web01' -Thumbprint ('A' * 40) -Where 'x' -Names @('web01.corp.example.test', '*.corp.example.test') -Dns @{ 'web01.corp.example.test' = [pscustomobject]@{ StatusCode = 'OK' } } })
        $fs.Count | Should -Be 1
        $fs[0].Status | Should -Be 'Pass'
    }
    It 'reads the dNSName entries of a certificate' {
        $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest('CN=web01', [System.Security.Cryptography.RSA]::Create(2048), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
        $san.AddDnsName('web01.corp.example.test'); $san.AddDnsName('App.Corp.Example.Test')
        $req.CertificateExtensions.Add($san.Build())
        $c = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(10))
        $names = @(InModuleScope MspkiHealthCheck -Parameters @{ C = $c } { param($C) Get-MspkiCertificateDnsName -Certificate $C })
        $names | Should -Be @('web01.corp.example.test', 'app.corp.example.test')
    }
}

Describe 'Hierarchy analysis on a discovery' {
    It 'groups the URLs an issuing CA writes by kind (AIA URLs are not mixed with CDP URLs)' {
        $root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
        $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $root.Full -DaysValid 700 -WithAki -CdpUrls @($script:ldapCdp) -AiaUrls @($script:ldapAia)
        $mk = { param($c, $n, $role, $self) [pscustomobject]@{ Thumbprint = $c.Thumbprint; CAName = $n; Role = $role; Lifecycle = 'Current'; InAIA = $true; InNTAuth = $true
            Info = [pscustomobject]@{ KeyAlgorithm = 'RSA'; KeySize = 2048; SelfIssued = $self } } }
        $d = [pscustomobject]@{
            Inventory = [pscustomobject]@{ CACertificates = @((& $mk $root.Public 'Example Root CA' 'EnterpriseRoot' $true), (& $mk $sub.Public 'Example Issuing CA' 'EnterpriseSubordinate' $false))
                EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Root CA'; CommonName = 'Example Root CA'; DnsHostName = 'ca01.example.test' }); Leads = @(); NdesHosts = @() }
            Certificates = @{ $root.Public.Thumbprint = $root.Public; $sub.Public.Thumbprint = $sub.Public }
        }
        Mock -ModuleName MspkiHealthCheck Get-MspkiLocalIssuedCertificate { @() }
        $fs = @(InModuleScope MspkiHealthCheck -Parameters @{ D = $d; A = $script:ldapCdp } { param($D, $A)
            Reset-MspkiEntityGraph; Reset-MspkiProbeCache
            Invoke-MspkiHierarchyAnalysis -Discovery $D -Findings @([pscustomobject]@{ Endpoint = $A; Category = 'CDP'; Status = 'Pass' }) -SkipNetwork })
        $aia = @($fs | Where-Object { $_.Category -eq 'AIA' -and $_.StatusCode -eq 'CONFIG_RISK' })
        $aia.Count | Should -Be 1
        $aia[0].Message | Should -Match '\(1 URL\(s\)'
        ($aia[0].Evidence -join "`n") | Should -Not -Match 'certificateRevocationList'
        (@($fs | Where-Object { $_.Category -eq 'CDP' -and $_.Sources -contains 'Analysis:RetrievalOrder' }))[0].Status | Should -Be 'Pass'
        @($fs | Where-Object { $_.Category -eq 'OCSP' }).Count | Should -Be 0
    }
}
