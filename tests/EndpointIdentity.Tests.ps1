# Tests for endpoint identity (D2): DNS identity records, reverse DNS / alias / TLS name checks, Web Enrollment classification,
# the Host entity in the graph, and the Server header / sign-in schemes captured by the HTTP probe. example.test names only;
# the only network traffic is to a loopback test server.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'DNS identity record' {
    It 'follows the CNAME chain in order even when the answers come out of order, and splits A and AAAA' {
        InModuleScope MspkiHealthCheck {
            $raw = @{ Name = 'pki.example.test'; QueryName = 'pki.example.test'; ErrorCode = 0; Records = @(
                    @{ Type = 'CNAME'; Name = 'web.corp.example.test'; Target = 'ca01.corp.example.test.' }
                    @{ Type = 'CNAME'; Name = 'PKI.example.test'; Target = 'web.corp.example.test' }
                    @{ Type = 'A'; Name = 'ca01.corp.example.test'; Address = '192.0.2.10' }
                    @{ Type = 'AAAA'; Name = 'ca01.corp.example.test'; Address = '2001:db8::10' })
                Ptr = @(@{ Address = '192.0.2.10'; ErrorCode = 0; Names = @('CA01.corp.example.test.') }, @{ Address = '2001:db8::10'; ErrorCode = 9003; Names = @() }) }
            $r = ConvertTo-MspkiDnsIdentity -Raw $raw
            $r.Chain | Should -Be @('pki.example.test', 'web.corp.example.test', 'ca01.corp.example.test')
            $r.CanonicalName | Should -Be 'ca01.corp.example.test'
            $r.A | Should -Be @('192.0.2.10')
            $r.AAAA | Should -Be @('2001:db8::10')
            $r.Lookup | Should -Be 'Found'
            $r.Ptr[0].Names | Should -Be @('ca01.corp.example.test')
            $r.Ptr[1].Lookup | Should -Be 'NoRecord'
        }
    }

    It 'tells a missing name from a timeout and from a server failure' {
        InModuleScope MspkiHealthCheck {
            (ConvertTo-MspkiDnsIdentity -Raw @{ Name = 'gone.example.test'; QueryName = 'gone.example.test'; ErrorCode = 9003 }).Lookup | Should -Be 'NoRecord'
            (ConvertTo-MspkiDnsIdentity -Raw @{ Name = 'slow.example.test'; QueryName = 'slow.example.test'; ErrorCode = 1460 }).Status | Should -Be 'Timeout'
            (ConvertTo-MspkiDnsIdentity -Raw @{ Name = 'bad.example.test'; QueryName = 'bad.example.test'; ErrorCode = 9002 }).Lookup | Should -Be 'Error'
        }
    }

    It 'is cached per name: a second call does not run a lookup' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiProbeCache
            Set-MspkiProbeCacheEntry -Key 'dnsid|ca01.corp.example.test' -Value (ConvertTo-MspkiDnsIdentity -Raw @{ Name = 'ca01.corp.example.test'; QueryName = 'ca01.corp.example.test'; ErrorCode = 0; Records = @(@{ Type = 'A'; Address = '192.0.2.10' }) })
            Mock Invoke-MspkiTimeLimitedScript { throw 'must not be called' }
            $r = @(Resolve-MspkiDnsIdentity -HostName @('CA01.corp.example.test.'))
            $r[0].FromCache | Should -BeTrue
            $r[0].A | Should -Be @('192.0.2.10')
            Should -Invoke Invoke-MspkiTimeLimitedScript -Times 0
        }
    }
}

Describe 'Certificate name coverage' {
    It 'covers exact names and one-label wildcards only' {
        InModuleScope MspkiHealthCheck {
            Test-MspkiDnsNameCovered -Name 'pki.example.test' -Patterns @('PKI.example.test') | Should -BeTrue
            Test-MspkiDnsNameCovered -Name 'pki.example.test' -Patterns @('*.example.test') | Should -BeTrue
            Test-MspkiDnsNameCovered -Name 'a.pki.example.test' -Patterns @('*.example.test') | Should -BeFalse
            Test-MspkiDnsNameCovered -Name 'example.test' -Patterns @('*.example.test') | Should -BeFalse
            Test-MspkiDnsNameCovered -Name 'example.test' -Patterns @('*.test') | Should -BeFalse
            Test-MspkiDnsNameCovered -Name 'other.example.test' -Patterns @('pki.example.test') | Should -BeFalse
        }
    }
}

Describe 'Host identity checks' {
    BeforeAll {
        $script:mkId = {
            param([string]$Name, [string[]]$Chain, [string[]]$A, [object[]]$Ptr, [string]$Lookup = 'Found', [string]$Method = 'DnsClient')
            [pscustomobject]@{ Target = $Name; QueryName = $Chain[0]; Chain = $Chain; A = $A; AAAA = @(); Ptr = $Ptr; Lookup = $Lookup; Method = $Method; Error = '' }
        }
    }

    It 'reports a missing PTR as Information (not a fault) and a matching PTR as nothing' {
        $id = & $script:mkId 'ca01.corp.example.test' @('ca01.corp.example.test') @('192.0.2.10') @([pscustomobject]@{ Address = '192.0.2.10'; Lookup = 'NoRecord'; Names = @() })
        $f = InModuleScope MspkiHealthCheck -Parameters @{ Id = $id } { param($Id) Test-MspkiHostIdentity -HostName 'ca01.corp.example.test' -Identity $Id }
        $m = @($f | Where-Object { $_.StatusCode -eq 'NOT_CONFIGURED' })
        $m.Count | Should -Be 1
        $m[0].Status | Should -Be 'Information'
        $m[0].Confidence | Should -Be 'Confirmed'
        $m[0].Category | Should -Be 'Identity'
        $ok = & $script:mkId 'ca01.corp.example.test' @('ca01.corp.example.test') @('192.0.2.10') @([pscustomobject]@{ Address = '192.0.2.10'; Lookup = 'Found'; Names = @('ca01.corp.example.test') })
        $g = InModuleScope MspkiHealthCheck -Parameters @{ Id = $ok } { param($Id) Test-MspkiHostIdentity -HostName 'ca01.corp.example.test' -Identity $Id }
        @($g | Where-Object { $_.Status -ne 'Information' -or $_.StatusCode -ne 'OK' }).Count | Should -Be 0
        @($g | Where-Object { $_.Message -like 'Identity of*' -and $_.Message -like '*reverse DNS ca01.corp.example.test*' }).Count | Should -Be 1
    }

    It 'warns when reverse DNS gives only the short name, or another host' {
        $short = & $script:mkId 'ca01.corp.example.test' @('ca01.corp.example.test') @('192.0.2.10') @([pscustomobject]@{ Address = '192.0.2.10'; Lookup = 'Found'; Names = @('ca01') })
        $f = InModuleScope MspkiHealthCheck -Parameters @{ Id = $short } { param($Id) Test-MspkiHostIdentity -HostName 'ca01.corp.example.test' -Identity $Id }
        $w = @($f | Where-Object { $_.Status -eq 'Warning' })
        $w.Count | Should -Be 1
        $w[0].Message | Should -Match 'only the short name'
        $other = & $script:mkId 'ca01.corp.example.test' @('ca01.corp.example.test') @('192.0.2.10') @([pscustomobject]@{ Address = '192.0.2.10'; Lookup = 'Found'; Names = @('old-web.corp.example.test') })
        $g = InModuleScope MspkiHealthCheck -Parameters @{ Id = $other } { param($Id) Test-MspkiHostIdentity -HostName 'ca01.corp.example.test' -Identity $Id }
        $w = @($g | Where-Object { $_.Status -eq 'Warning' })
        $w.Count | Should -Be 1
        $w[0].StatusCode | Should -Be 'CONFIG_MISMATCH'
        $w[0].Message | Should -Match 'names another host \(old-web\.corp\.example\.test\)'
    }

    It 'accepts a PTR that names the real host at the end of the alias chain' {
        $id = & $script:mkId 'pki.example.test' @('pki.example.test', 'ca01.corp.example.test') @('192.0.2.10') @([pscustomobject]@{ Address = '192.0.2.10'; Lookup = 'Found'; Names = @('ca01.corp.example.test') })
        $f = InModuleScope MspkiHealthCheck -Parameters @{ Id = $id } { param($Id) Test-MspkiHostIdentity -HostName 'pki.example.test' -Identity $Id }
        @($f | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 0
        @($f | Where-Object { $_.Message -like '*alias of ca01.corp.example.test*' }).Count | Should -Be 1
    }

    It 'warns about an alias that leads to no address, and not about a plain missing name' {
        $id = & $script:mkId 'pki.example.test' @('pki.example.test', 'gone.corp.example.test') @() @() 'NoRecord'
        $f = InModuleScope MspkiHealthCheck -Parameters @{ Id = $id } { param($Id) Test-MspkiHostIdentity -HostName 'pki.example.test' -Identity $Id }
        $w = @($f | Where-Object { $_.Status -eq 'Warning' -and $_.StatusCode -eq 'DNS_FAIL' })
        $w.Count | Should -Be 1
        $w[0].Message | Should -Match 'leads nowhere'
        $plain = & $script:mkId 'gone.example.test' @('gone.example.test') @() @() 'NoRecord'
        $g = InModuleScope MspkiHealthCheck -Parameters @{ Id = $plain } { param($Id) Test-MspkiHostIdentity -HostName 'gone.example.test' -Identity $Id }
        @($g | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 0
    }

    It 'flags an alias the TLS certificate does not cover: Warning when an https URL uses it, Information otherwise' {
        $id = & $script:mkId 'pki.example.test' @('pki.example.test', 'ca01.corp.example.test') @('192.0.2.10') @([pscustomobject]@{ Address = '192.0.2.10'; Lookup = 'Found'; Names = @('ca01.corp.example.test') })
        $tls = @([pscustomobject]@{ Target = 'ca01.corp.example.test:443'; Thumbprint = 'AB'; Subject = 'CN=ca01.corp.example.test'; Issuer = 'CN=Example Issuing CA'; DnsNames = @('ca01.corp.example.test'); Code = 'OK' })
        $used = InModuleScope MspkiHealthCheck -Parameters @{ Id = $id; T = $tls } { param($Id, $T) Test-MspkiHostIdentity -HostName 'pki.example.test' -Identity $Id -Tls $T -HttpsNames @('pki.example.test') }
        $w = @($used | Where-Object { $_.StatusCode -eq 'TLS_NAME_MISMATCH' })
        $w.Count | Should -Be 1
        $w[0].Status | Should -Be 'Warning'
        $w[0].Confidence | Should -Be 'Confirmed'
        $unused = InModuleScope MspkiHealthCheck -Parameters @{ Id = $id; T = $tls } { param($Id, $T) Test-MspkiHostIdentity -HostName 'pki.example.test' -Identity $Id -Tls $T }
        $i = @($unused | Where-Object { $_.StatusCode -eq 'TLS_NAME_MISMATCH' })
        $i[0].Status | Should -Be 'Information'
        $i[0].Confidence | Should -Be 'Inferred'
    }

    It 'does not flag an alias the certificate covers (wildcard), nor one that was itself handshaken' {
        $id = & $script:mkId 'pki.example.test' @('pki.example.test', 'ca01.corp.example.test') @('192.0.2.10') @([pscustomobject]@{ Address = '192.0.2.10'; Lookup = 'Found'; Names = @('ca01.corp.example.test') })
        $wild = @([pscustomobject]@{ Target = 'ca01.corp.example.test:443'; Thumbprint = 'AB'; Subject = 'CN=ca01'; DnsNames = @('ca01.corp.example.test', '*.example.test'); Code = 'OK' })
        $f = InModuleScope MspkiHealthCheck -Parameters @{ Id = $id; T = $wild } { param($Id, $T) Test-MspkiHostIdentity -HostName 'pki.example.test' -Identity $Id -Tls $T -HttpsNames @('pki.example.test') }
        @($f | Where-Object { $_.StatusCode -eq 'TLS_NAME_MISMATCH' }).Count | Should -Be 0
        $direct = @([pscustomobject]@{ Target = 'pki.example.test:443'; Thumbprint = 'AB'; Subject = 'CN=ca01'; DnsNames = @('ca01.corp.example.test'); Code = 'TLS_NAME_MISMATCH' })
        $g = InModuleScope MspkiHealthCheck -Parameters @{ Id = $id; T = $direct } { param($Id, $T) Test-MspkiHostIdentity -HostName 'pki.example.test' -Identity $Id -Tls $T -HttpsNames @('pki.example.test') }
        @($g | Where-Object { $_.StatusCode -eq 'TLS_NAME_MISMATCH' }).Count | Should -Be 0
    }

    It 'gives Inferred results when only .NET name resolution was available' {
        $id = & $script:mkId 'ca01.corp.example.test' @('ca01.corp.example.test') @('192.0.2.10') @([pscustomobject]@{ Address = '192.0.2.10'; Lookup = 'NoRecord'; Names = @() }) 'Found' 'DotNet'
        $f = InModuleScope MspkiHealthCheck -Parameters @{ Id = $id } { param($Id) Test-MspkiHostIdentity -HostName 'ca01.corp.example.test' -Identity $Id }
        foreach ($x in $f) { $x.Confidence | Should -Be 'Inferred' }
    }
}

Describe 'Web Enrollment (/certsrv/)' {
    It 'treats 404 and no answer as absent, every other answer as present' {
        InModuleScope MspkiHealthCheck {
            Get-MspkiWebEnrollmentState -Http ([pscustomobject]@{ HttpStatus = 404 }) | Should -BeNullOrEmpty
            Get-MspkiWebEnrollmentState -Http ([pscustomobject]@{ HttpStatus = 0; Code = 'TIMEOUT' }) | Should -BeNullOrEmpty
            (Get-MspkiWebEnrollmentState -Http ([pscustomobject]@{ HttpStatus = 403 })).Meaning | Should -Match 'refuses anonymous'
            $s = Get-MspkiWebEnrollmentState -Http ([pscustomobject]@{ HttpStatus = 401; AuthSchemes = @('Negotiate', 'NTLM') })
            $s.WindowsSignIn | Should -BeTrue
            $s.Meaning | Should -Match 'Windows sign-in \(Negotiate, NTLM\)'
        }
    }

    It 'warns (ESC8) when plain HTTP offers Windows sign-in, and only informs for HTTPS or a 403' {
        InModuleScope MspkiHealthCheck {
            $http401 = [pscustomobject]@{ Url = 'http://ca01.corp.example.test/certsrv/'; HttpStatus = 401; AuthSchemes = @('NTLM'); Code = 'HTTP_401_403'; Server = 'Microsoft-IIS/10.0' }
            $f = @(Test-MspkiWebEnrollment -HostName 'ca01.corp.example.test' -Http $http401)
            @($f | Where-Object { $_.Status -eq 'Warning' -and $_.StatusCode -eq 'CONFIG_RISK' }).Count | Should -Be 1
            ($f | Where-Object { $_.Status -eq 'Warning' }).Message | Should -Match 'ESC8'
            ($f | Where-Object { $_.Status -eq 'Information' }).Confidence | Should -Be 'Inferred'
            $https401 = [pscustomobject]@{ Url = 'https://ca01.corp.example.test/certsrv/'; HttpStatus = 401; AuthSchemes = @('Negotiate'); Code = 'HTTP_401_403' }
            $http403 = [pscustomobject]@{ Url = 'http://ca01.corp.example.test/certsrv/'; HttpStatus = 403; AuthSchemes = @(); Code = 'HTTP_401_403' }
            $g = @(Test-MspkiWebEnrollment -HostName 'ca01.corp.example.test' -Http $http403 -Https $https401)
            @($g | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 0
            $g.Count | Should -Be 1
            $none = @(Test-MspkiWebEnrollment -HostName 'ca01.corp.example.test' -Http ([pscustomobject]@{ HttpStatus = 404 }))
            $none.Count | Should -Be 0
        }
    }
}

Describe 'Host identity in the entity graph' {
    It 'records addresses, PTR, alias chain, TLS names and Server header, with resolvesTo and ExpectedMissing' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiEntityGraph
            $hid = Add-MspkiHostEntity -HostName 'pki.example.test'
            $id = ConvertTo-MspkiDnsIdentity -Raw @{ Name = 'pki.example.test'; QueryName = 'pki.example.test'; ErrorCode = 0; Records = @(
                    @{ Type = 'CNAME'; Name = 'pki.example.test'; Target = 'ca01.corp.example.test' }, @{ Type = 'A'; Address = '192.0.2.10' })
                Ptr = @(@{ Address = '192.0.2.10'; ErrorCode = 9003; Names = @() }) }
            $tls = @([pscustomobject]@{ Target = 'pki.example.test:443'; Thumbprint = 'AB'; Subject = 'CN=ca01.corp.example.test'; Issuer = 'CN=Example Issuing CA'; DnsNames = @('ca01.corp.example.test'); NotAfter = '2030-01-01T00:00:00Z'; Code = 'TLS_NAME_MISMATCH' })
            $http = @([pscustomobject]@{ Url = 'http://pki.example.test/certenroll/x.crl'; HttpStatus = 200; Server = 'Microsoft-IIS/10.0' })
            Add-MspkiHostIdentityToGraph -HostId $hid -Identity $id -Tls $tls -Http $http
            $e = Get-MspkiEntity -Id $hid
            $e.Properties['AliasChain'] | Should -Be @('pki.example.test', 'ca01.corp.example.test')
            $e.Properties['A'] | Should -Be @('192.0.2.10')
            $e.Properties['HttpServer'] | Should -Be @('Microsoft-IIS/10.0')
            $e.Properties['TlsCertificates'][0].DnsNames | Should -Be @('ca01.corp.example.test')
            $e.Properties['Ptr'][0].Lookup | Should -Be 'NoRecord'
            @(Get-MspkiRelation | Where-Object { $_.Type -eq 'resolvesTo' -and $_.From -eq 'host:pki.example.test' -and $_.To -eq 'host:ca01.corp.example.test' }).Count | Should -Be 1
            @(Get-MspkiObservation | Where-Object { $_.EntityId -eq $hid -and $_.Kind -eq 'ExpectedMissing' -and $_.Location -eq '10.2.0.192.in-addr.arpa' }).Count | Should -Be 1
            @(Get-MspkiObservation | Where-Object { $_.EntityId -eq $hid -and $_.Source -eq 'Certificate' }).Count | Should -Be 1
            (Get-MspkiEntity -Id 'host:ca01.corp.example.test').Properties['A'] | Should -Be @('192.0.2.10')
        }
    }

    It 'does not invent an alias chain or PTR when DNS was not queried' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiEntityGraph
            $hid = Add-MspkiHostEntity -HostName 'ca01.corp.example.test'
            Add-MspkiHostIdentityToGraph -HostId $hid -Identity $null
            $e = Get-MspkiEntity -Id $hid
            $e.Properties.Contains('AliasChain') | Should -BeFalse
            $e.Properties.Contains('Ptr') | Should -BeFalse
            @(Get-MspkiRelation | Where-Object { $_.Type -eq 'resolvesTo' }).Count | Should -Be 0
            @(Get-MspkiObservation | Where-Object { $_.Kind -eq 'ExpectedMissing' }).Count | Should -Be 0
        }
    }
}

Describe 'HTTP probe identity headers' {
    BeforeAll {
        $script:srv = Start-TestHttpServer -Routes @{
            '/certsrv/' = @{ Status = 401; Body = @(); Headers = @{ 'Server' = 'Microsoft-IIS/10.0'; 'WWW-Authenticate' = 'Negotiate' } }
            '/plain' = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('ok'); Headers = @{} }
        }
    }
    AfterAll { Stop-TestHttpServer -Server $script:srv }

    It 'records the Server header and the names of the offered sign-in schemes, never sending credentials' {
        $base = $script:srv.Base
        $r = InModuleScope MspkiHealthCheck -Parameters @{ U = ('{0}/certsrv/' -f $base) } { param($U) Reset-MspkiProbeCache; Invoke-MspkiHttpGet -Url $U -TimeoutMs 3000 -MaxRedirects 0 -DiscardBody }
        $r.HttpStatus | Should -Be 401
        $r.Server | Should -Be 'Microsoft-IIS/10.0'
        $r.AuthSchemes | Should -Be @('Negotiate')
        $r.Hops[0].Server | Should -Be 'Microsoft-IIS/10.0'
        $req = @($script:srv.Log | Where-Object { $_.Path -eq '/certsrv/' })
        $req.Count | Should -Be 1
        @($req[0].Headers | Where-Object { $_ -like 'Authorization:*' }).Count | Should -Be 0
    }

    It 'leaves Server empty when the header is not sent' {
        $base = $script:srv.Base
        $r = InModuleScope MspkiHealthCheck -Parameters @{ U = ('{0}/plain' -f $base) } { param($U) Invoke-MspkiHttpGet -Url $U -TimeoutMs 3000 }
        $r.HttpStatus | Should -Be 200
        $r.Server | Should -Be ''
        @($r.AuthSchemes).Count | Should -Be 0
    }
}
