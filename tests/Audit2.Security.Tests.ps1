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

Describe 'Audit 2 M10: downloaded bytes never create a private key on disk' {
    BeforeAll {
        # A PFX with no password (what a changed AIA file could be). Export does not write a key; importing it would.
        $c = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysValid 100
        $script:pfx = $c.Full.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        [void]$col.Add($script:root.Public)
        $script:p7b = $col.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7)
        # Every place where Windows writes a user key container (CAPI RSA/DSS and CNG), and the machine key folders.
        $script:keyFiles = {
            $dirs = @((Join-Path $env:APPDATA 'Microsoft\Crypto'), (Join-Path $env:ProgramData 'Microsoft\Crypto\RSA\MachineKeys'), (Join-Path $env:ProgramData 'Microsoft\Crypto\Keys'))
            @(foreach ($d in $dirs) { if (Test-Path -LiteralPath $d) { Get-ChildItem -LiteralPath $d -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } } }) | Sort-Object
        }
        $script:routes = [hashtable]::Synchronized(@{})
        $script:server = Start-TestHttpServer -Routes $script:routes
        $script:routes['/planted.crt'] = @{ Status = 200; Body = $script:pfx }
        $script:routes['/root.p7b'] = @{ Status = 200; Body = $script:p7b }
        $script:keep = New-Object System.Collections.ArrayList
    }
    AfterAll {
        Stop-TestHttpServer -Server $script:server
        # If a key was created (red run), remove it again.
        foreach ($o in @($script:keep)) { try { if ($o -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) { $o.Reset() } } catch { } }
    }

    It 'names the content type of certificate bytes, and refuses PKCS #12 before any certificate object is built' {
        InModuleScope MspkiHealthCheck -Parameters @{ Pfx = $script:pfx; P7 = $script:p7b; Der = $script:root.Public.RawData } { param($Pfx, $P7, $Der)
            Get-MspkiCertificateContentType -Bytes $Der | Should -Be 'Cert'
            Get-MspkiCertificateContentType -Bytes $P7 | Should -Be 'Pkcs7'
            Get-MspkiCertificateContentType -Bytes $Pfx | Should -Be 'Pkcs12'
            Get-MspkiCertificateContentType -Bytes ([System.Text.Encoding]::ASCII.GetBytes('hello')) | Should -Be 'Unknown'
        }
    }

    It 'New-MspkiCertificate refuses a passwordless PFX and no key file or container is created' {
        $before = & $script:keyFiles
        $res = InModuleScope MspkiHealthCheck -Parameters @{ Pfx = $script:pfx } { param($Pfx)
            $out = [pscustomobject]@{ Cert = $null; Error = '' }
            try { $out.Cert = New-MspkiCertificate -Bytes $Pfx } catch { $out.Error = $_.Exception.Message }
            $out }
        if ($null -ne $res.Cert) { [void]$script:keep.Add($res.Cert) }
        $after = & $script:keyFiles
        $res.Cert | Should -BeNullOrEmpty
        $res.Error | Should -Match 'PKCS #12'
        @(Compare-Object -ReferenceObject @($before) -DifferenceObject @($after) | Where-Object SideIndicator -eq '=>').Count | Should -Be 0
    }

    It 'an AIA location that serves a PFX is CONTENT_WRONG_TYPE, nothing is loaded and no key file is created' {
        $before = & $script:keyFiles
        $r = InModuleScope MspkiHealthCheck -Parameters @{ U = "$($script:server.Base)/planted.crt" } { param($U)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry
            $lead = Add-MspkiLead -Url $U -Kind AIA -Source 'test' -Origin 'test'
            Test-MspkiLeadEndpoint -Lead $lead -Url $U }
        if ($null -ne $r.Certificate) { [void]$script:keep.Add($r.Certificate) }
        $after = & $script:keyFiles
        $r.Certificate | Should -BeNullOrEmpty
        @($r.Findings)[0].StatusCode | Should -Be 'CONTENT_WRONG_TYPE'
        (@($r.Findings)[0].Evidence -join "`n") | Should -Match 'PKCS #12'
        @(Compare-Object -ReferenceObject @($before) -DifferenceObject @($after) | Where-Object SideIndicator -eq '=>').Count | Should -Be 0
    }

    It 'the NDES GetCACert reader refuses a PFX and creates no key file' {
        $before = & $script:keyFiles
        # The reader returns its list with the unary comma; unroll it to count the entries.
        $certs = @(InModuleScope MspkiHealthCheck -Parameters @{ Pfx = $script:pfx } { param($Pfx) ConvertFrom-MspkiNdesCaCertificate -Bytes $Pfx | ForEach-Object { $_ } })
        foreach ($c in $certs) { [void]$script:keep.Add($c) }
        $after = & $script:keyFiles
        $certs.Count | Should -Be 0
        @(Compare-Object -ReferenceObject @($before) -DifferenceObject @($after) | Where-Object SideIndicator -eq '=>').Count | Should -Be 0
    }

    It 'still reads a PKCS #7 at an AIA location' {
        $r = InModuleScope MspkiHealthCheck -Parameters @{ U = "$($script:server.Base)/root.p7b" } { param($U)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry
            $lead = Add-MspkiLead -Url $U -Kind AIA -Source 'test' -Origin 'test'
            Test-MspkiLeadEndpoint -Lead $lead -Url $U }
        $r.Certificate | Should -Not -BeNullOrEmpty
        $r.Certificate.Thumbprint | Should -Be $script:root.Public.Thumbprint
        $r.Certificate.HasPrivateKey | Should -BeFalse
    }
}

Describe 'Audit 2 M9: a redirect or a TLS handshake never goes to a host that no trusted evidence named' {
    BeforeAll {
        # Both names reach the same loopback server, so a request that goes to "localhost" shows in the log; "localhost" is the
        # undiscovered host, 127.0.0.1 the host the lead named.
        $script:routes = [hashtable]::Synchronized(@{})
        $script:server = Start-TestHttpServer -Routes $script:routes
        $p = $script:server.Port
        $script:routes['/away.crl'] = @{ Status = 302; Body = @(); Headers = @{ Location = "http://localhost:$p/target.crl" } }
        $script:routes['/near.crl'] = @{ Status = 302; Body = @(); Headers = @{ Location = '/target.crl' } }
        $script:routes['/target.crl'] = @{ Status = 200; Body = (New-TestCrl -Issuer $script:root -Number 3) }
    }
    AfterAll { Stop-TestHttpServer -Server $script:server }
    BeforeEach { $script:server.Log.Clear() }

    It 'records a redirect to an undiscovered host and does not connect to it' {
        $r = InModuleScope MspkiHealthCheck -Parameters @{ B = $script:server.Base } { param($B)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry
            Invoke-MspkiHttpGet -Url "$B/away.crl" -TimeoutMs 5000 }
        $r.Code | Should -Be 'HTTP_REDIRECT'
        $r.HttpStatus | Should -Be 302
        $r.Redirected | Should -BeTrue
        $r.RedirectNotFollowed | Should -BeLike 'http://localhost:*/target.crl'
        $r.Error | Should -Match 'not followed'
        @($script:server.Log | Where-Object { $_.Path -eq '/target.crl' }).Count | Should -Be 0
    }

    It 'follows a redirect on the same host' {
        $r = InModuleScope MspkiHealthCheck -Parameters @{ B = $script:server.Base } { param($B)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry
            Invoke-MspkiHttpGet -Url "$B/near.crl" -TimeoutMs 5000 }
        $r.Code | Should -Be 'OK'
        @($script:server.Log | Where-Object { $_.Path -eq '/target.crl' }).Count | Should -Be 1
    }

    It 'follows a redirect to a host that an Authoritative lead names, but not to one that only an Unverified lead names' {
        $r = InModuleScope MspkiHealthCheck -Parameters @{ B = $script:server.Base; P = $script:server.Port } { param($B, $P)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry
            $null = Add-MspkiLead -Url "http://localhost:$P/other.crl" -Kind CDP -Source 'test' -Trust Unverified
            $u = Invoke-MspkiHttpGet -Url "$B/away.crl" -TimeoutMs 5000
            Reset-MspkiProbeCache
            $null = Add-MspkiLead -Url "http://localhost:$P/other.crl" -Kind CDP -Source 'AD:test' -Trust Authoritative
            $a = Invoke-MspkiHttpGet -Url "$B/away.crl" -TimeoutMs 5000
            @($u, $a) }
        $r[0].Code | Should -Be 'HTTP_REDIRECT'
        $r[1].Code | Should -Be 'OK'
        @($script:server.Log | Where-Object { $_.Path -eq '/target.crl' }).Count | Should -Be 1
    }

    It 'grades a CDP location that redirects to an undiscovered host as a Warning that names the target, not as a download failure' {
        $r = InModuleScope MspkiHealthCheck -Parameters @{ B = $script:server.Base } { param($B)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry
            $lead = Add-MspkiLead -Url "$B/away.crl" -Kind CDP -Source 'test' -Origin 'test'
            Test-MspkiLeadEndpoint -Lead $lead -Url $lead.Url }
        $f = @($r.Findings)
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Warning'
        $f[0].StatusCode | Should -Be 'HTTP_REDIRECT'
        $f[0].Message | Should -Match 'localhost'
        $f[0].Message | Should -Match 'not followed'
        @($script:server.Log | Where-Object { $_.Path -eq '/target.crl' }).Count | Should -Be 0
    }

    It 'makes no separate TLS handshake with a redirect host that no trusted evidence named' {
        Mock -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint { [pscustomobject]@{ Code = 'TLS_UNTRUSTED_ROOT' } }
        $c = InModuleScope MspkiHealthCheck {
            Reset-MspkiLeadRegistry
            @((Get-MspkiTrustFailureCode -Url 'https://elsewhere.example.test/x.crl' -RequestHost 'pki.corp.example.test'),
              (Get-MspkiTrustFailureCode -Url 'https://pki.corp.example.test/x.crl' -RequestHost 'pki.corp.example.test')) }
        $c | Should -Be @('TLS_HANDSHAKE_FAIL', 'TLS_UNTRUSTED_ROOT')
        Should -Invoke -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint -Times 1 -Exactly -ParameterFilter { $HostName -eq 'pki.corp.example.test' }
        Should -Invoke -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint -Times 0 -Exactly -ParameterFilter { $HostName -eq 'elsewhere.example.test' }
    }
}
