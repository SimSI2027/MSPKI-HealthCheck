# Tests for the audit fixes (docs/AUDIT.md) that concern what the probes send and to whom: H1 (LDAP bind), M1 (proxy), M6 (TLS
# protocols), M10 (distinct HTTP and TLS codes) and the TLS probe against a real TLS listener (M11). Hosts are 127.0.0.1,
# localhost and example.test only; nothing leaves this computer.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    # Same name as the root, another key, and links that must never be followed.
    $script:planted = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysValid 3000 `
        -CdpUrls @('ldap://ldap.example.test/CN=x,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint') -AiaUrls @('http://planted.example.test/x.crt')

    # A server certificate with a usable private key (a PFX round trip; the key container is removed again in AfterAll).
    $script:newServerCert = {
        param([string]$Subject, [int]$DaysBefore = 1, [int]$DaysValid = 30)
        $c = New-TestCertificate -Subject $Subject -IsCA $false -DaysBefore $DaysBefore -DaysValid $DaysValid
        $pfx = $c.Full.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'test-only')
        New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx, 'test-only', ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'Exportable,PersistKeySet,UserKeySet'))
    }
    # A TLS listener on 127.0.0.1 that completes the handshake and closes. Mode 'tls' speaks TLS, 'plain' accepts and closes at once.
    $script:startTls = {
        param($Certificate, [string]$Protocols = 'Tls12', [string]$Mode = 'tls')
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $ps = [System.Management.Automation.PowerShell]::Create()
        [void]$ps.AddScript({
            param($listener, $cert, $protocols, $mode)
            while ($true) {
                $client = $listener.AcceptTcpClient()
                try {
                    if ($mode -eq 'tls') {
                        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
                        $ssl.AuthenticateAsServer($cert, $false, [System.Security.Authentication.SslProtocols]$protocols, $false)
                    }
                }
                catch { }
                finally { $client.Close() }
            }
        }).AddArgument($listener).AddArgument($Certificate).AddArgument($Protocols).AddArgument($Mode)
        $h = $ps.BeginInvoke()
        [pscustomobject]@{ Listener = $listener; PowerShell = $ps; Handle = $h; Port = $listener.LocalEndpoint.Port }
    }
    $script:stopTls = { param($S) try { $S.Listener.Stop() } catch { }; try { [void]$S.PowerShell.BeginStop($null, $null) } catch { } }
    $script:cleanup = New-Object System.Collections.ArrayList
}

AfterAll {
    foreach ($c in @($script:cleanup)) {
        try { $k = $c.PrivateKey; if ($null -ne $k) { $k.PersistKeyInCsp = $false; $k.Clear() } } catch { }
        try { $k = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c); if ($null -ne $k -and $k.Key) { $k.Key.Delete() } } catch { }
    }
}

Describe 'H1: an LDAP URL never sends the credentials of the user running the tool to a host outside the forest' {
    It 'decides for <Name>' -TestCases @(
        @{ Name = 'a serverless URL'; HostName = ''; Skip = $false; Allowed = $true }
        @{ Name = 'the selected domain controller'; HostName = 'DC01.corp.example.test'; Skip = $false; Allowed = $true }
        @{ Name = 'another host of the forest'; HostName = 'dc02.corp.example.test'; Skip = $false; Allowed = $true }
        @{ Name = 'a host of a child domain'; HostName = 'dc3.child.corp.example.test'; Skip = $false; Allowed = $true }
        @{ Name = 'a host outside the forest'; HostName = 'ldap.example.test'; Skip = $false; Allowed = $false }
        @{ Name = 'a host of the forest named with a port'; HostName = 'dc02.corp.example.test:389'; Skip = $false; Allowed = $true }
        @{ Name = 'a host outside the forest named with a port'; HostName = 'ldap.example.test:636'; Skip = $false; Allowed = $false }
        @{ Name = 'a host of a trusted forest'; HostName = 'dc1.partner.example.test'; Skip = $false; Allowed = $false }
        @{ Name = 'a short name that is not the controller'; HostName = 'dc9'; Skip = $false; Allowed = $false }
        @{ Name = 'an IP address'; HostName = '192.0.2.10'; Skip = $false; Allowed = $false }
        @{ Name = 'another host of the forest with -SkipNetwork'; HostName = 'dc02.corp.example.test'; Skip = $true; Allowed = $false }
        @{ Name = 'the controller with -SkipNetwork'; HostName = 'dc01.corp.example.test'; Skip = $true; Allowed = $true }
        @{ Name = 'a serverless URL with -SkipNetwork'; HostName = ''; Skip = $true; Allowed = $true }
    ) {
        param($Name, $HostName, $Skip, $Allowed)
        $d = InModuleScope MspkiHealthCheck -Parameters @{ H = $HostName; S = $Skip } { param($H, $S)
            Test-MspkiLdapHostAllowed -HostName $H -DefaultServer 'dc01.corp.example.test' -LocalDomains @('corp.example.test') -SkipNetwork:$S }
        $d.Allowed | Should -Be $Allowed
        $d.Reason | Should -Not -BeNullOrEmpty
    }

    It 'makes no directory call for a host outside the forest' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
        $r = InModuleScope MspkiHealthCheck {
            Reset-MspkiProbeCache
            Get-MspkiLdapUrlContent -Url 'ldap://ldap.example.test/CN=x,DC=example,DC=test?cACertificate?base?objectClass=*' -DefaultServer 'dc01.corp.example.test' -LocalDomains @('corp.example.test') }
        $r.Contacted | Should -BeFalse
        $r.Code | Should -Be 'NOT_APPLICABLE'
        $r.Error | Should -Match 'Not contacted'
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
    }

    It 'binds to a host of the forest that the URL names, and uses that host as the server' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { @{ cacertificate = @(, [byte[]](1, 2, 3)) } }
        $r = InModuleScope MspkiHealthCheck {
            Reset-MspkiProbeCache
            Get-MspkiLdapUrlContent -Url 'ldap://dc02.corp.example.test/CN=x,DC=example,DC=test?cACertificate?base?objectClass=*' -DefaultServer 'dc01.corp.example.test' -LocalDomains @('corp.example.test') }
        $r.Contacted | Should -BeTrue
        $r.Code | Should -Be 'OK'
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 1 -Exactly -ParameterFilter { $Server -eq 'dc02.corp.example.test' }
    }

    It 'reports an LDAP location outside the forest as Skipped (NOT_APPLICABLE) with the reason, and sends nothing' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
        $r = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $lead = Add-MspkiLead -Url 'ldap://ldap.example.test/CN=Example Root CA,CN=CDP,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint' -Kind CDP -Source 'Cert:AA:CDP' -Origin 'test'
            Test-MspkiLeadEndpoint -Lead $lead -Url $lead.Url -DomainController 'dc01.corp.example.test' }
        $f = @($r.Findings)[0]
        $f.Status | Should -Be 'Skipped'
        $f.StatusCode | Should -Be 'NOT_APPLICABLE'
        $f.Message | Should -Match 'was not contacted'
        ($f.Evidence -join "`n") | Should -Match 'No bind and no request was sent'
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
    }

    It 'with -SkipNetwork does not bind to a host of the forest either, unless it is the selected domain controller' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
        $r = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
            $lead = Add-MspkiLead -Url 'ldap://dc02.corp.example.test/CN=Example Root CA,CN=CDP,DC=corp,DC=example,DC=test?certificateRevocationList?base?objectClass=cRLDistributionPoint' -Kind CDP -Source 'Cert:AA:CDP' -Origin 'test'
            Test-MspkiLeadEndpoint -Lead $lead -Url $lead.Url -DomainController 'dc01.corp.example.test' -SkipNetwork }
        @($r.Findings)[0].Status | Should -Be 'Skipped'
        @($r.Findings)[0].Message | Should -Match 'SkipNetwork'
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
    }

    It 'does not follow the links of a downloaded certificate that is not proven to be the expected issuer (a planted LDAP and HTTP link is never contacted)' {
        $routes = [hashtable]::Synchronized(@{})
        $server = Start-TestHttpServer -Routes $routes
        try {
            $b = $server.Base
            $routes['/root.crt'] = @{ Status = 200; Body = $script:planted.Public.RawData }
            $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900 -AiaUrls @("$b/root.crt")
            $disc = [pscustomobject]@{
                Certificates = @{ $sub.Public.Thumbprint = $sub.Public }
                Inventory = [pscustomobject]@{
                    AdContext = [pscustomobject]@{ DomainController = ''; ForestDomains = @('corp.example.test'); TrustedDomains = @() }
                    CACertificates = @([pscustomobject]@{ Thumbprint = $sub.Public.Thumbprint; CAName = 'Example Issuing CA'; Lifecycle = 'Current'; Info = [pscustomobject]@{ Subject = $sub.Public.Subject; NotAfter = '2999-01-01T00:00:00Z' } })
                    EnterpriseCAs = @()
                }
            }
            Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
            $f = InModuleScope MspkiHealthCheck -Parameters @{ D = $disc } { param($D)
                [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test')
                Register-MspkiDiscoveredLead -Discovery $D
                Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 5 }
            $aia = @($f | Where-Object { $_.Category -eq 'AIA' })
            $aia.Count | Should -Be 1
            $aia[0].Status | Should -Be 'Warning'
            $aia[0].StatusCode | Should -Be 'CONTENT_WRONG_TYPE'
            $aia[0].Confidence | Should -Be 'Confirmed'
            ($aia[0].Evidence -join "`n") | Should -Match 'does NOT verify'
            $hosts = @(InModuleScope MspkiHealthCheck { Get-MspkiLead | ForEach-Object { $_.Host } })
            $hosts | Should -Not -Contain 'ldap.example.test'
            $hosts | Should -Not -Contain 'planted.example.test'
            Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
            @($server.Log | ForEach-Object { $_.Path }) | Should -Be @('/root.crt')
        }
        finally { Stop-TestHttpServer -Server $server }
    }
}

Describe 'M1: HTTP probes connect directly' {
    BeforeAll {
        $script:routes = [hashtable]::Synchronized(@{})
        $script:origin = Start-TestHttpServer -Routes $script:routes
        $script:proxyRoutes = [hashtable]::Synchronized(@{})
        $script:proxy = Start-TestHttpServer -Routes $script:proxyRoutes
        $script:routes['/x'] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('ok') }
    }
    AfterAll { Stop-TestHttpServer -Server $script:origin; Stop-TestHttpServer -Server $script:proxy }
    BeforeEach { $script:origin.Log.Clear(); $script:proxy.Log.Clear() }

    It 'ignores a proxy that the session has configured and sends nothing to it (a plain request would have gone to the proxy)' {
        # The target name does not resolve. A request that uses the proxy never resolves it (the proxy does), so the proxy sees the
        # request; a direct request fails in DNS and the proxy sees nothing.
        $url = 'http://nonexistent.example.test:{0}/x' -f $script:origin.Port
        $prev = [System.Net.WebRequest]::DefaultWebProxy
        try {
            [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy(('http://127.0.0.1:{0}' -f $script:proxy.Port), $false)
            # Control: an ordinary request is sent to the proxy, so this test can tell the difference.
            try { $null = [System.Net.WebRequest]::Create($url).GetResponse() } catch { }
            @($script:proxy.Log).Count | Should -BeGreaterThan 0
            $script:proxy.Log.Clear(); $script:origin.Log.Clear()
            $r = InModuleScope MspkiHealthCheck -Parameters @{ U = $url } { param($U) Reset-MspkiProbeCache; Set-MspkiWebProbeOption; Invoke-MspkiHttpGet -Url $U -TimeoutMs 4000 }
            $r.Code | Should -Be 'DNS_FAIL'
            $r.ProxyMode | Should -Match 'none \(direct connection\)'
            @($script:proxy.Log).Count | Should -Be 0
            @($script:origin.Log).Count | Should -Be 0
            # And a reachable target still works directly while the session proxy is set.
            $ok = InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:origin.Base + '/x') } { param($U) Reset-MspkiProbeCache; Invoke-MspkiHttpGet -Url $U -TimeoutMs 4000 }
            $ok.Code | Should -Be 'OK'
            @($script:proxy.Log).Count | Should -Be 0
        }
        finally { [System.Net.WebRequest]::DefaultWebProxy = $prev }
    }

    It 'takes the system proxy only with the opt-in switch, records it, and never gives the proxy credentials' {
        InModuleScope MspkiHealthCheck {
            (Get-MspkiWebProbeOption).UseSystemProxy | Should -BeFalse
            Set-MspkiWebProbeOption -UseSystemProxy
            (Get-MspkiWebProbeOption).UseSystemProxy | Should -BeTrue
            (Get-MspkiWebProbeOption).ProxyMode | Should -Match 'system proxy settings, without credentials'
            Set-MspkiWebProbeOption
            (Get-MspkiWebProbeOption).UseSystemProxy | Should -BeFalse
        }
        foreach ($p in @((Get-Command Start-MspkiHealthCheck), (Get-Command (Join-Path $script:RepoRoot 'Invoke-MspkiHealthCheck.ps1')))) {
            $p.Parameters.ContainsKey('UseSystemProxy') | Should -BeTrue
            $p.Parameters['UseSystemProxy'].SwitchParameter | Should -BeTrue
        }
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Probes\WebProbes.ps1') -Raw
        $src | Should -Match 'GetSystemWebProxy\(\)'
        $src | Should -Not -Match '\.Credentials\s*=(?!\s*\$null)'
        $src | Should -Not -Match 'DefaultWebProxy|DefaultCredentials\s*=\s*\$true|NetworkCredential'
    }

    It 'records the proxy mode in the Evidence of an endpoint finding' {
        $r = InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:origin.Base + '/missing.crl') } { param($U)
            [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry; Reset-MspkiProbeCache; Set-MspkiWebProbeOption
            $lead = Add-MspkiLead -Url $U -Kind CDP -Source 'test' -Origin 'test'
            Test-MspkiLeadEndpoint -Lead $lead -Url $lead.Url }
        $f = @($r.Findings)[0]
        $f.StatusCode | Should -Be 'HTTP_404'
        ($f.Evidence -join "`n") | Should -Match 'HTTP proxy: none \(direct connection\)'
    }
}

Describe 'M10: HTTP answers and TLS trust problems keep their own codes' {
    BeforeAll {
        $script:routes2 = [hashtable]::Synchronized(@{})
        $script:server2 = Start-TestHttpServer -Routes $script:routes2
        foreach ($s in @(204, 405, 407, 410, 301)) { $script:routes2["/s$s"] = @{ Status = $s; Body = @() } }   # 301 without a Location header
        $script:routes2['/s400'] = @{ Status = 400; Body = @() }
        $script:routes2['/s403'] = @{ Status = 403; Body = @() }
        $script:routes2['/s503'] = @{ Status = 503; Body = @() }
    }
    AfterAll { Stop-TestHttpServer -Server $script:server2 }

    It 'gives HTTP <Status> the code <Code>' -TestCases @(
        @{ Status = 204; Code = 'HTTP_OTHER' }
        @{ Status = 405; Code = 'HTTP_OTHER' }
        @{ Status = 407; Code = 'HTTP_OTHER' }
        @{ Status = 410; Code = 'HTTP_OTHER' }
        @{ Status = 301; Code = 'HTTP_OTHER' }
        @{ Status = 400; Code = 'HTTP_400' }
        @{ Status = 403; Code = 'HTTP_401_403' }
        @{ Status = 503; Code = 'HTTP_500' }
    ) {
        param($Status, $Code)
        $r = InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:server2.Base + ('/s{0}' -f $Status)) } { param($U) Reset-MspkiProbeCache; Invoke-MspkiHttpGet -Url $U -TimeoutMs 4000 }
        $r.HttpStatus | Should -Be $Status
        $r.Code | Should -Be $Code
    }
}

Describe 'M6 and M11: the TLS probe against a real TLS listener' {
    BeforeAll {
        $script:cLocal = & $script:newServerCert 'CN=localhost'
        $script:cOther = & $script:newServerCert 'CN=other.example.test'
        $script:cExpired = & $script:newServerCert 'CN=localhost' 60 -30
        foreach ($c in @($script:cLocal, $script:cOther, $script:cExpired)) { [void]$script:cleanup.Add($c) }
        $script:probe = { param([int]$Port, [string]$HostName = 'localhost') InModuleScope MspkiHealthCheck -Parameters @{ P = $Port; H = $HostName } { param($P, $H) Reset-MspkiProbeCache; Test-MspkiTlsEndpoint -HostName $H -Port $P -TimeoutMs 8000 } }
    }

    It 'offers TLS 1.2, 1.1 and 1.0 explicitly (and 1.3 where the framework has it), never only the framework default' {
        InModuleScope MspkiHealthCheck {
            $legacy = Get-MspkiTlsClientProtocol -WithoutTls13
            ($legacy -band [System.Security.Authentication.SslProtocols]::Tls12) | Should -Not -Be 0
            ($legacy -band [System.Security.Authentication.SslProtocols]::Tls11) | Should -Not -Be 0
            ($legacy -band [System.Security.Authentication.SslProtocols]::Tls) | Should -Not -Be 0
            [string]$legacy | Should -Be 'Tls, Tls11, Tls12'
            ((Get-MspkiTlsClientProtocol) -band $legacy) | Should -Be $legacy
        }
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Probes\WebProbes.ps1') -Raw
        $src | Should -Match 'AuthenticateAsClient\(\$h, \$null, \$protocols, \$false\)'
        $src | Should -Not -Match 'AuthenticateAsClient\(\$h\)'
    }

    It 'reads the certificate of a TLS 1.2-only server and keeps trust, name and protocol apart' {
        $s = & $script:startTls $script:cLocal 'Tls12'
        try {
            $r = & $script:probe $s.Port
            $r.Code | Should -Be 'TLS_UNTRUSTED_ROOT'
            $r.ChainErrors | Should -Contain 'UntrustedRoot'
            $r.NameMatch | Should -BeTrue
            $r.Subject | Should -Be 'CN=localhost'
            $r.Protocol | Should -Be 'Tls12'
            $r.OfferedProtocols | Should -Match 'Tls12'
        }
        finally { & $script:stopTls $s }
    }

    It 'records a name that does not match as its own fact' {
        $s = & $script:startTls $script:cOther 'Tls12'
        try {
            $r = & $script:probe $s.Port
            $r.NameMatch | Should -BeFalse
            $r.Subject | Should -Be 'CN=other.example.test'
            $r.ChainErrors | Should -Contain 'UntrustedRoot'
        }
        finally { & $script:stopTls $s }
    }

    It 'records an expired certificate as its own chain fact' {
        $s = & $script:startTls $script:cExpired 'Tls12'
        try {
            $r = & $script:probe $s.Port
            $r.ChainErrors | Should -Contain 'NotTimeValid'
            $r.NameMatch | Should -BeTrue
        }
        finally { & $script:stopTls $s }
    }

    It 'reports a server that accepts the connection but does not speak TLS as TLS_HANDSHAKE_FAIL' {
        $s = & $script:startTls $null 'Tls12' 'plain'
        try { (& $script:probe $s.Port).Code | Should -Be 'TLS_HANDSHAKE_FAIL' }
        finally { & $script:stopTls $s }
    }

    It 'reports a closed port as TCP_FAIL, not as a TLS problem' {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
        (& $script:probe $port).Code | Should -BeIn @('TCP_FAIL', 'TIMEOUT')
    }

    It 'names the real TLS problem when an HTTPS request fails with a trust failure (and not always TLS_UNTRUSTED_ROOT)' -TestCases @(
        @{ Mocked = 'TLS_NAME_MISMATCH'; Expect = 'TLS_NAME_MISMATCH' }
        @{ Mocked = 'OBJECT_EXPIRED'; Expect = 'OBJECT_EXPIRED' }
        @{ Mocked = 'OK'; Expect = 'TLS_HANDSHAKE_FAIL' }
    ) {
        param($Mocked, $Expect)
        $s = & $script:startTls $script:cLocal 'Tls12'
        try {
            Mock -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint ([scriptblock]::Create(("[pscustomobject]@{{ Code = '{0}' }}" -f $Mocked)))
            $r = InModuleScope MspkiHealthCheck -Parameters @{ U = ('https://localhost:{0}/x' -f $s.Port) } { param($U) Reset-MspkiProbeCache; Invoke-MspkiHttpGet -Url $U -TimeoutMs 8000 }
            $r.HttpStatus | Should -Be 0
            $r.Code | Should -Be $Expect
        }
        finally { & $script:stopTls $s }
    }

    It 'looks at the host of the failing hop when a redirect leads to another HTTPS host' {
        $s = & $script:startTls $script:cLocal 'Tls12'
        $routes = [hashtable]::Synchronized(@{})
        $origin = Start-TestHttpServer -Routes $routes
        try {
            $routes['/go'] = @{ Status = 302; Body = @(); Headers = @{ Location = ('https://localhost:{0}/x' -f $s.Port) } }
            Mock -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint { [pscustomobject]@{ Code = 'TLS_NAME_MISMATCH' } }
            $r = InModuleScope MspkiHealthCheck -Parameters @{ U = ($origin.Base + '/go') } { param($U) Reset-MspkiProbeCache; Invoke-MspkiHttpGet -Url $U -TimeoutMs 8000 }
            $r.Redirected | Should -BeTrue
            $r.Code | Should -Be 'TLS_NAME_MISMATCH'
            # The handshake was made to the host and port of the hop that failed (the HTTPS host), not to the first host.
            Should -Invoke -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint -Times 1 -Exactly -ParameterFilter ([scriptblock]::Create(('$Port -eq {0}' -f $s.Port)))
            Should -Invoke -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint -Times 0 -Exactly -ParameterFilter ([scriptblock]::Create(('$Port -eq {0}' -f $origin.Port)))
        }
        finally { & $script:stopTls $s; Stop-TestHttpServer -Server $origin }
    }
}
