# Fix log 3, N9 (docs/AUDIT-3-VERIFY.md): a redirect to a non-HTTP scheme (file:, ftp:, ldap:, ...) must never throw out of the HTTP probe.
# It is recorded as evidence with its own status code, and every other result of the run is kept. Loopback server and example.test only.
# The tests call only functions that existed before the fix, so on the old code they fail because of what the old code did.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . (Join-Path $PSScriptRoot 'CredentialHarness.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    $script:routes = [hashtable]::Synchronized(@{})
    $script:server = Start-TestHttpServer -Routes $script:routes
    $script:base = $script:server.Base
    foreach ($s in @('file://127.0.0.1/share/ca.crt', 'ftp://127.0.0.1/ca.crt', 'ldap://127.0.0.1/CN=x,DC=example,DC=test', 'gopher://127.0.0.1/x', 'javascript:alert(1)', 'http://[bad/x')) {
        $name = '/redir-' + ([Math]::Abs($s.GetHashCode()))
        $script:routes[$name] = @{ Status = 302; Body = [byte[]]@(); Headers = @{ Location = $s } }
    }
    $script:routes['/ok.crt'] = @{ Status = 200; Body = $script:root.Public.RawData }

    $script:newDiscovery = {
        param([string[]]$AiaUrls = @())
        $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900 -AiaUrls $AiaUrls
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
    $script:analyse = {
        param($D)
        InModuleScope MspkiHealthCheck -Parameters @{ D = $D } { param($D)
            [void](Initialize-MspkiRun)
            Reset-MspkiLeadRegistry -LocalDomains @($D.Inventory.AdContext.ForestDomains) -DomainControllers @($D.Inventory.AdContext.DomainControllers)
            Register-MspkiDiscoveredLead -Discovery $D
            Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 5 }
    }
}

AfterAll { Stop-TestHttpServer -Server $script:server }

Describe 'N9: a redirect to a scheme other than http/https is recorded, never thrown' {
    It 'Invoke-MspkiHttpGet records a redirect to <Location> as HTTP_REDIRECT with the redirect''s own status code' -TestCases @(
        @{ Location = 'file://127.0.0.1/share/ca.crt' }
        @{ Location = 'ftp://127.0.0.1/ca.crt' }
        @{ Location = 'ldap://127.0.0.1/CN=x,DC=example,DC=test' }
        @{ Location = 'gopher://127.0.0.1/x' }
        @{ Location = 'javascript:alert(1)' }
        @{ Location = 'http://[bad/x' }
    ) {
        param($Location)
        $path = '/redir-' + ([Math]::Abs($Location.GetHashCode()))
        $before = @($script:server.Log).Count
        $r = InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:base + $path) } { param($U)
            [void](Initialize-MspkiRun); Reset-MspkiProbeCache; Set-MspkiWebProbeOption
            Invoke-MspkiHttpGet -Url $U -TimeoutMs 3000 -MaxRedirects 5 }
        $r.Code | Should -Be 'HTTP_REDIRECT'
        $r.HttpStatus | Should -Be 302
        $r.Redirected | Should -BeTrue
        $r.RedirectNotFollowed | Should -Not -BeNullOrEmpty
        $r.Error | Should -Match 'not followed'
        # Exactly one request reached the loopback server: nothing was followed.
        (@($script:server.Log).Count - $before) | Should -Be 1
        @($r.Hops).Count | Should -Be 1
    }

    It 'the endpoint stage keeps every other result when one AIA answer redirects to file:, ftp: or ldap:' -TestCases @(
        @{ Location = 'file://127.0.0.1/share/ca.crt' }
        @{ Location = 'ftp://127.0.0.1/ca.crt' }
        @{ Location = 'ldap://127.0.0.1/CN=x,DC=example,DC=test' }
    ) {
        param($Location)
        $path = '/redir-' + ([Math]::Abs($Location.GetHashCode()))
        $d = & $script:newDiscovery -AiaUrls @(($script:base + $path), ($script:base + '/ok.crt'))
        $f = & $script:analyse $d
        $redir = @($f | Where-Object { $_.Endpoint -like "*$path" -and $_.Stage -eq 'Probe' })
        $redir.Count | Should -BeGreaterThan 0
        @($redir | Where-Object { $_.StatusCode -eq 'HTTP_REDIRECT' }).Count | Should -BeGreaterThan 0
        # The second URL of the same certificate was still probed, and the run has no stage failure.
        @($f | Where-Object { $_.Endpoint -like '*/ok.crt' -and $_.Stage -eq 'Probe' }).Count | Should -BeGreaterThan 0
        @($f | Where-Object { $_.Category -eq 'Run' -and $_.Status -eq 'Error' }).Count | Should -Be 0
    }
}
