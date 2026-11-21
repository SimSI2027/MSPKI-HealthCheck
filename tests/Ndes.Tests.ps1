# NDES / SCEP (REQUIREMENTS 5.7). The central test: the tool can only ever send the three allowed anonymous GET
# requests. Proven three ways: (1) the request table and its gate, (2) static checks of the source (nothing else can
# build a NDES URL, send credentials, POST or follow a redirect), (3) a loopback server that records every request.
# Hosts are 127.0.0.1 and example.test only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:srcRoot = Join-Path $script:RepoRoot 'src'
    $script:codeText = {
        param([string]$Path)
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        (@($tokens | Where-Object { $_.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment } | ForEach-Object { $_.Text }) -join ' ')
    }
    $script:srcFiles = @(Get-ChildItem -LiteralPath $script:srcRoot -Recurse -Filter '*.ps1' -File)

    $script:capsPath = '/certsrv/mscep/mscep.dll?operation=GetCACaps'
    $script:certPath = '/certsrv/mscep/mscep.dll?operation=GetCACert'
    $script:adminPath = '/certsrv/mscep_admin/'
    $script:allowedPaths = @($script:capsPath, $script:certPath, $script:adminPath)

    $script:ca = New-TestCertificate -Subject 'CN=Example NDES RA, DC=example, DC=test' -IsCA $false
    $script:oldCa = New-TestCertificate -Subject 'CN=Old NDES RA, DC=example, DC=test' -IsCA $false -DaysBefore 400 -DaysValid -10
    $script:routes = [hashtable]::Synchronized(@{})
    $script:server = Start-TestHttpServer -Routes $script:routes
    $script:b = $script:server.Base
    $script:setOk = {
        $script:routes.Clear()
        $script:routes[$script:capsPath] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes("POSTPKIOperation`nSHA-256`nRenewal`n"); Headers = @{ 'Content-Type' = 'text/plain' } }
        $script:routes[$script:certPath] = @{ Status = 200; Body = $script:ca.Public.RawData; Headers = @{ 'Content-Type' = 'application/x-x509-ca-cert' } }
        $script:routes[$script:adminPath] = @{ Status = 401; Body = @(); Headers = @{ 'WWW-Authenticate' = 'Negotiate' } }
    }
    $script:probe = {
        param([string]$Origin = 'Referenced', [string]$Url = ($script:b + '/certsrv/mscep/mscep.dll'), [switch]$SkipNetwork, [switch]$IncludeAdmin)
        InModuleScope MspkiHealthCheck -Parameters @{ U = $Url; O = $Origin; Skip = [bool]$SkipNetwork; Adm = [bool]$IncludeAdmin } {
            param($U, $O, $Skip, $Adm)
            Reset-MspkiLeadRegistry; Reset-MspkiProbeCache
            $lead = Add-MspkiLead -Url $U -Kind NDES -Source 'test:ndes' -Origin 'test fixture'
            $info = [pscustomobject]@{ Origin = $O; Lines = @('Test evidence line'); Sources = @('test:ndes'); RelatedCAs = @('Example Issuing CA') }
            Test-MspkiNdesHost -Lead $lead -Info $info -TimeoutSeconds 3 -SkipNetwork:$Skip -IncludeAdminProbe:$Adm
        }
    }
}

AfterAll { Stop-TestHttpServer -Server $script:server }

Describe 'NDES requests: the table and its gate' {
    It 'allows exactly three requests, all anonymous GETs' {
        $t = @(InModuleScope MspkiHealthCheck { Get-MspkiNdesAllowedRequest })
        $t.Count | Should -Be 3
        @($t | ForEach-Object { $_.Name }) | Should -Be @('GetCACaps', 'GetCACert', 'AdminAnonymous')
        @($t | ForEach-Object { $_.Path + $_.Query }) | Should -Be $script:allowedPaths
        foreach ($e in $t) { $e.Method | Should -Be 'GET'; $e.Authentication | Should -Be 'None' }
        ($t | Where-Object { $_.Name -eq 'AdminAnonymous' }).BodyRead | Should -BeFalse
    }

    It 'builds the URLs itself from a validated host, scheme and port' {
        InModuleScope MspkiHealthCheck {
            New-MspkiNdesRequestUrl -Name GetCACaps -HostName 'NDES01.Corp.Example.Test' -Scheme https | Should -Be 'https://ndes01.corp.example.test/certsrv/mscep/mscep.dll?operation=GetCACaps'
            New-MspkiNdesRequestUrl -Name GetCACert -HostName 'ndes01.corp.example.test' -Scheme http -Port 8080 | Should -Be 'http://ndes01.corp.example.test:8080/certsrv/mscep/mscep.dll?operation=GetCACert'
            New-MspkiNdesRequestUrl -Name AdminAnonymous -HostName 'ndes01.corp.example.test' -Scheme https -Port 443 | Should -Be 'https://ndes01.corp.example.test/certsrv/mscep_admin/'
        }
    }

    It 'refuses every request name that is not in the table (the enrolling operation and all others)' {
        foreach ($name in @('PKIOperation', 'GetNextCACert', 'GetCert', 'GetCRL', 'GetCACaps/../x', 'getcacaps ', '', 'admin')) {
            { InModuleScope MspkiHealthCheck -Parameters @{ N = $name } { param($N) New-MspkiNdesRequestUrl -Name $N -HostName 'ndes01.corp.example.test' } } | Should -Throw -Because ("'{0}'" -f $name)
            { InModuleScope MspkiHealthCheck -Parameters @{ N = $name } { param($N) Send-MspkiNdesRequest -Name $N -HostName 'ndes01.corp.example.test' } } | Should -Throw -Because ("'{0}'" -f $name)
        }
    }

    It 'refuses host names that could smuggle a path, query, user or second host' {
        foreach ($h in @('host/evil', 'host?x=1', 'user@host.example.test', 'host name', 'host#frag', 'a.example.test:8080', '', '-host.example.test', 'host\x')) {
            { InModuleScope MspkiHealthCheck -Parameters @{ H = $h } { param($H) New-MspkiNdesRequestUrl -Name GetCACaps -HostName $H } } | Should -Throw -Because ("'{0}'" -f $h)
        }
    }

    It 'has a request-name parameter that accepts only the three names' {
        $vs = (Get-Command -Module MspkiHealthCheck -All -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Send-MspkiNdesRequest' })
        $vs = InModuleScope MspkiHealthCheck { (Get-Command Send-MspkiNdesRequest).Parameters['Name'].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues } }
        @($vs) | Should -Be @('GetCACaps', 'GetCACert', 'AdminAnonymous')
    }

    It 'recognises URLs that point at a SCEP path' {
        InModuleScope MspkiHealthCheck {
            Test-MspkiNdesUrl 'http://ndes01.corp.example.test/certsrv/mscep/mscep.dll' | Should -BeTrue
            Test-MspkiNdesUrl 'https://ndes01.corp.example.test/CertSrv/mscep_admin/' | Should -BeTrue
            Test-MspkiNdesUrl 'http://pki.corp.example.test/CertEnroll/ca.crl' | Should -BeFalse
        }
    }
}

Describe 'NDES requests: nothing else in the source can send anything to a NDES host' {
    It 'names the SCEP paths in one file only (the request table)' {
        $offenders = @()
        foreach ($f in $script:srcFiles) {
            if ($f.Name -eq 'NdesProbe.ps1') { continue }
            $t = & $script:codeText $f.FullName
            if ($t -match '(?i)certsrv|mscep_admin|mscep\.dll|operation=') { $offenders += $f.Name }
        }
        $offenders | Should -BeNullOrEmpty
    }

    It 'never mentions the enrolling SCEP operation anywhere in code' {
        foreach ($f in $script:srcFiles) { (& $script:codeText $f.FullName) | Should -Not -Match '(?i)(?<!POST)PKIOperation|operation=GetNextCACert' -Because $f.Name }
    }

    It 'names the admin path once in the table, and the NDES probe file has no credentials, headers, POST or raw web request' {
        $t = & $script:codeText (Join-Path $script:srcRoot 'Probes\NdesProbe.ps1')
        ([regex]::Matches($t, '(?i)mscep_admin')).Count | Should -Be 1
        $t | Should -Not -Match '(?i)Credential|Authorization|Headers|\bPOST\b|\bPUT\b|WebRequest|HttpClient|WebClient|Invoke-WebRequest|Invoke-RestMethod|\.Method\b|UseDefault'
    }

    It 'lets the NDES probe file call only the shared probes (DNS, TCP, TLS handshake) and the one anonymous GET' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:srcRoot 'Probes\NdesProbe.ps1'), [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
        $network = @($cmds | Where-Object { $_ -match '(?i)Invoke-Mspki|Test-Mspki|Resolve-Mspki|Send-Mspki|Get-MspkiNdesTransport' })
        $allowed = @('Invoke-MspkiHttpGet', 'Resolve-MspkiDnsName', 'Test-MspkiTcpPort', 'Test-MspkiTlsEndpoint', 'Invoke-MspkiNdesProbe', 'Send-MspkiNdesRequest', 'New-MspkiNdesRequestUrl', 'Test-MspkiNdesUrl')
        foreach ($c in $network) { $allowed | Should -Contain $c -Because $c }
    }

    It 'sends every NDES request through Send-MspkiNdesRequest and no analyzer calls the HTTP probe directly' {
        $t = & $script:codeText (Join-Path $script:srcRoot 'Analyzers\Ndes.ps1')
        $t | Should -Not -Match 'Invoke-MspkiHttpGet'
        $t | Should -Not -Match 'Send-MspkiNdesRequest'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:srcRoot 'Probes\NdesProbe.ps1'), [ref]$null, [ref]$null)
        $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-MspkiHttpGet' }, $true))
        $calls.Count | Should -Be 2
        $inSend = @($calls | Where-Object { $p = $_.Parent; while ($null -ne $p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $p = $p.Parent }; $p.Name -eq 'Send-MspkiNdesRequest' })
        $inSend.Count | Should -Be 2
        foreach ($c in $calls) { $c.Extent.Text | Should -Match '-MaxRedirects 0' }
    }

    It 'has exactly one place that creates a web request, and it is an anonymous GET' {
        $creators = @($script:srcFiles | Where-Object { (& $script:codeText $_.FullName) -match '(?i)WebRequest\]::Create|HttpWebRequest|Net\.Http|WebClient' })
        @($creators | ForEach-Object { $_.Name }) | Should -Be @('WebProbes.ps1')
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:srcRoot 'Probes\WebProbes.ps1'), [ref]$null, [ref]$null)
        $assign = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true))
        foreach ($a in $assign) {
            $left = $a.Left.Extent.Text
            if ($left -match '\.Method$') { $a.Right.Extent.Text | Should -Be "'GET'" }
            if ($left -match '\.(Credentials|ClientCertificates)$') { $a.Right.Extent.Text | Should -Be '$null' }
            # The proxy is $null (a direct connection) unless -UseSystemProxy was given; then it is the system proxy WITHOUT credentials.
            if ($left -match '\.Proxy$') { $a.Right.Extent.Text | Should -BeIn @('$null', '$sysProxy') }
            if ($left -match '\.(UseDefaultCredentials|PreAuthenticate|AllowAutoRedirect)$') { $a.Right.Extent.Text | Should -Be '$false' }
        }
        $text = & $script:codeText (Join-Path $script:srcRoot 'Probes\WebProbes.ps1')
        $text | Should -Not -Match '(?i)GetRequestStream|ContentLength\s*=|Authorization|Headers\.Add|Headers\.Set'
    }

    It 'has no credential or token handling anywhere in src' {
        foreach ($f in $script:srcFiles) { (& $script:codeText $f.FullName) | Should -Not -Match '(?i)NetworkCredential|CredentialCache|Get-Credential|PSCredential|DefaultNetworkCredentials' -Because $f.Name }
    }
}

Describe 'NDES requests: what a server really receives' {
    BeforeEach { & $script:setOk; $script:server.Log.Clear() }

    It 'by default sends only GetCACaps and GetCACert: the admin request is opt-in because it can make an open admin page create a challenge password' {
        $r = & $script:probe
        $r.Classification | Should -Be 'ConfirmedEndpoint'
        $log = @($script:server.Log)
        $log.Count | Should -Be 2
        @($log | ForEach-Object { $_.Path } | Sort-Object) | Should -Be @($script:capsPath, $script:certPath | Sort-Object)
        @($log | Where-Object { $_.Path -like '*mscep_admin*' }).Count | Should -Be 0
        ((@($r.Findings)[0].Evidence) -join "`n") | Should -Match 'Admin page: not requested'
        ((@($r.Findings)[0].Evidence) -join "`n") | Should -Match 'HTTP proxy: none \(direct connection\)'
        $direct = InModuleScope MspkiHealthCheck -Parameters @{ B = $script:b } { param($B) Reset-MspkiProbeCache; Invoke-MspkiNdesProbe -HostName '127.0.0.1' -Scheme http -Port ([uri]$B).Port -TimeoutMs 3000 }
        $direct.AdminAnonymous | Should -BeNullOrEmpty
    }

    It 'with -IncludeNdesAdminProbe receives exactly the three allowed anonymous GET requests: no credentials, no body, no other path' {
        $r = & $script:probe -IncludeAdmin
        $r.Classification | Should -Be 'ConfirmedEndpoint'
        $log = @($script:server.Log)
        $log.Count | Should -Be 3
        @($log | ForEach-Object { $_.Path } | Sort-Object) | Should -Be @($script:allowedPaths | Sort-Object)
        foreach ($e in $log) {
            $e.Method | Should -Be 'GET'
            $h = $e.Headers -join "`n"
            $h | Should -Not -Match '(?i)^authorization:|^cookie:|^proxy-authorization:'
            $h | Should -Not -Match '(?i)content-length: *[1-9]|transfer-encoding'
        }
    }

    It 'does not follow a redirect to any other path (no request outside the table is ever sent)' {
        $script:routes[$script:capsPath] = @{ Status = 302; Body = @(); Headers = @{ Location = '/certsrv/mscep/mscep.dll?operation=PKIOperation&message=x' } }
        $script:routes[$script:certPath] = @{ Status = 301; Body = @(); Headers = @{ Location = '/elsewhere' } }
        $script:routes[$script:adminPath] = @{ Status = 302; Body = @(); Headers = @{ Location = '/certsrv/mscep_admin/login' } }
        $r = & $script:probe -IncludeAdmin
        $log = @($script:server.Log)
        $log.Count | Should -Be 3
        @($log | ForEach-Object { $_.Path } | Where-Object { $script:allowedPaths -notcontains $_ }) | Should -BeNullOrEmpty
        $r.Confirmed | Should -BeFalse
        (@($r.Findings)[0].Evidence -join "`n") | Should -Match 'redirect not followed'
    }

    It 'sends nothing at all with -SkipNetwork' {
        $r = & $script:probe -SkipNetwork
        @($script:server.Log).Count | Should -Be 0
        @($r.Findings)[0].Status | Should -Be 'Skipped'
    }

    It 'sends nothing when the TCP port is closed' {
        $r = & $script:probe 'Referenced' 'http://127.0.0.1:1/certsrv/mscep/mscep.dll'
        @($script:server.Log).Count | Should -Be 0
        @($r.Findings)[0].Status | Should -Be 'Fail'
        @($r.Findings)[0].StatusCode | Should -BeIn @('TCP_FAIL', 'TIMEOUT')
        @($r.Findings)[0].TcpStatus | Should -Be 'Fail'
    }

    It 'never reads the body of the admin page, and reports an anonymous HTTP 200 as a High finding without echoing it' {
        $script:routes[$script:adminPath] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('Enrollment challenge password: SECRET-CHALLENGE-123'); Headers = @{ 'Content-Type' = 'text/html' } }
        $r = & $script:probe -IncludeAdmin
        $risk = @($r.Findings | Where-Object { $_.StatusCode -eq 'CONFIG_RISK' })
        $risk.Count | Should -Be 1
        $risk[0].Severity | Should -Be 'High'
        $risk[0].Status | Should -Be 'Fail'
        $risk[0].Evidence -join ' ' | Should -Match 'body was not read'
        (@($r.Findings | ForEach-Object { $_.Message, $_.Notes, ($_.Evidence -join ' ') }) -join ' ') | Should -Not -Match 'SECRET-CHALLENGE'
        $direct = InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:b + $script:adminPath) } { param($U) Reset-MspkiProbeCache; Invoke-MspkiHttpGet -Url $U -TimeoutMs 3000 -DiscardBody }
        $direct.HttpStatus | Should -Be 200
        $direct.Bytes | Should -BeNullOrEmpty
    }

    It 'does not confirm a NDES endpoint from an anonymous HTTP 401 on the admin path alone (IIS answers 401 for any path below a protected site)' {
        $script:routes.Remove($script:capsPath); $script:routes.Remove($script:certPath)
        $r = & $script:probe -IncludeAdmin
        $r.Confirmed | Should -BeFalse
        $r.Classification | Should -Be 'ReferencedEndpoint'
        $f = @($r.Findings)[0]
        $f.Confidence | Should -Not -Be 'Confirmed'
        $f.Status | Should -Not -Be 'Pass'
        ($f.Evidence -join "`n") | Should -Match 'Admin page \(anonymous request\): HTTP 401: something on this host asks for authentication'
        ($f.Evidence -join "`n") | Should -Match 'does not confirm NDES'
        ($f.Evidence -join "`n") | Should -Match 'No credentials were sent and the body was not read'
        ($f.Evidence -join "`n") | Should -Match 'GetCACaps: HTTP 404'
        $f.Notes | Should -Match 'every path below a protected site'
    }

    It 'reports a 200 answer that is not a SCEP capability list as CONTENT_WRONG_TYPE, not as a retrieval failure' {
        $script:routes[$script:capsPath] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('<html>welcome</html>'); Headers = @{ 'Content-Type' = 'text/html' } }
        $script:routes.Remove($script:certPath)
        $r = & $script:probe 'Probable'
        $r.Confirmed | Should -BeFalse
        @($r.Findings)[0].StatusCode | Should -Be 'CONTENT_WRONG_TYPE'
        @($r.Findings)[0].Status | Should -Be 'Information'
    }

    It 'reads the SCEP capabilities and the returned certificates (public data) and warns about an expired one' {
        $script:routes[$script:certPath] = @{ Status = 200; Body = $script:oldCa.Public.RawData; Headers = @{ 'Content-Type' = 'application/x-x509-ca-cert' } }
        $r = & $script:probe
        $ok = @($r.Findings | Where-Object { $_.StatusCode -eq 'OK' })[0]
        ($ok.Evidence -join "`n") | Should -Match 'SCEP capabilities: POSTPKIOperation, SHA-256, Renewal'
        ($ok.Evidence -join "`n") | Should -Match 'certificate CN=Old NDES RA'
        $w = @($r.Findings | Where-Object { $_.StatusCode -eq 'OBJECT_EXPIRED' })
        $w.Count | Should -Be 1
        $w[0].Status | Should -Be 'Warning'
    }

    It 'does not call a host a NDES endpoint when it answers 404 to everything: Referenced fails, Probable only informs' {
        $script:routes.Clear()
        $ref = & $script:probe 'Referenced'
        $ref.Confirmed | Should -BeFalse
        $ref.Classification | Should -Be 'ReferencedEndpoint'
        @($ref.Findings)[0].Status | Should -Be 'Fail'
        $prob = & $script:probe 'Probable'
        $prob.Classification | Should -Be 'ProbableCandidate'
        @($prob.Findings)[0].Status | Should -Be 'Information'
        @($prob.Findings)[0].Confidence | Should -Be 'Inferred'
        @($script:server.Log | ForEach-Object { $_.Path } | Where-Object { $script:allowedPaths -notcontains $_ }) | Should -BeNullOrEmpty
    }
}

Describe 'NDES evidence from the CA database' {
    It 'derives host candidates from computer accounts and RA certificate names, and builds the DNS name from AD' {
        $rows = @(
            @{ RequestID = '11'; RequesterName = 'CORP\NDES01$'; CommonName = 'NDES01-MSCEP-RA'; CertificateTemplate = 'EnrollmentAgentOffline'; NotAfter = '2027-01-01T00:00:00Z'; TemplateKey = 'EnrollmentAgentOffline' },
            @{ RequestID = '12'; RequesterName = 'CORP\NDES01$'; CommonName = 'NDES01-MSCEP-RA'; CertificateTemplate = 'CEPEncryption'; NotAfter = '2027-02-01T00:00:00Z'; TemplateKey = 'CEPEncryption' },
            @{ RequestID = '13'; RequesterName = 'CORP\svc-ndes'; CommonName = 'NDES02-MSCEP-RA (2)'; CertificateTemplate = 'CEPEncryption'; NotAfter = '2026-12-01T00:00:00Z'; TemplateKey = 'CEPEncryption' },
            @{ RequestID = '14'; RequesterName = 'CORP\alice'; CommonName = 'alice'; CertificateTemplate = 'CEPEncryption'; NotAfter = '2026-12-01T00:00:00Z'; TemplateKey = 'CEPEncryption' })
        $c = InModuleScope MspkiHealthCheck -Parameters @{ R = $rows } { param($R) $x = Get-MspkiNdesHostCandidate -Rows $R -CaName 'Example Issuing CA' -DomainMap @{ CORP = 'corp.example.test' } -ForestDomains @('corp.example.test', 'child.corp.example.test'); $x }
        @($c).Count | Should -Be 2
        $n1 = @($c | Where-Object { $_.ShortName -eq 'NDES01' })[0]
        $n1.Fqdn | Should -Be 'ndes01.corp.example.test'
        $n1.DomainSource | Should -Match 'crossRef'
        $n1.Rows | Should -Be 2
        @($n1.Signals).Count | Should -Be 2
        @($n1.Templates) | Should -Contain 'CEPEncryption'
        @($n1.Templates) | Should -Contain 'EnrollmentAgentOffline'
        $n1.LatestNotAfter | Should -Be '2027-02-01T00:00:00Z'
        $n2 = @($c | Where-Object { $_.ShortName -eq 'NDES02' })[0]
        @($n2.Signals).Count | Should -Be 1
        $n2.Fqdn | Should -Be 'ndes02.corp.example.test'
    }

    It 'builds no DNS name when the domain cannot be determined (several domains, no crossRef match)' {
        $rows = @(@{ RequestID = '1'; RequesterName = 'OTHER\NDES03$'; CommonName = 'NDES03-MSCEP-RA'; TemplateKey = 'CEPEncryption' })
        $c = InModuleScope MspkiHealthCheck -Parameters @{ R = $rows } { param($R) $x = Get-MspkiNdesHostCandidate -Rows $R -DomainMap @{ CORP = 'corp.example.test' } -ForestDomains @('corp.example.test', 'child.corp.example.test'); $x }
        @($c)[0].Fqdn | Should -Be ''
        $one = InModuleScope MspkiHealthCheck -Parameters @{ R = $rows } { param($R) $x = Get-MspkiNdesHostCandidate -Rows $R -DomainMap @{} -ForestDomains @('corp.example.test'); $x }
        @($one)[0].Fqdn | Should -Be 'ndes03.corp.example.test'
    }

    It 'returns no candidate for rows that show no NDES signal' {
        $c = InModuleScope MspkiHealthCheck { $x = Get-MspkiNdesHostCandidate -Rows @(@{ RequestID = '1'; RequesterName = 'CORP\bob'; CommonName = 'bob' }) -ForestDomains @('corp.example.test'); $x }
        @($c).Count | Should -Be 0
    }

    It 'queries the template names and the OIDs of the templates AD has under those names' {
        $inv = [pscustomobject]@{ TemplatesRead = $true; Templates = @(
            [pscustomobject]@{ Name = 'CEPEncryption'; DisplayName = 'CEP Encryption'; Oid = '1.3.6.1.4.1.311.21.8.100.7' }
            [pscustomobject]@{ Name = 'CopyOfOffline'; DisplayName = 'Exchange Enrollment Agent (Offline request)'; Oid = '1.3.6.1.4.1.311.21.8.100.8' }
            [pscustomobject]@{ Name = 'User'; DisplayName = 'User'; Oid = '1.3.6.1.4.1.311.21.8.100.9' }) }
        $k = InModuleScope MspkiHealthCheck -Parameters @{ I = $inv } { param($I) $x = Get-MspkiNdesTemplateKey -Inventory $I; $x }
        @($k) | Should -Contain 'CEPEncryption'
        @($k) | Should -Contain 'EnrollmentAgentOffline'
        @($k) | Should -Contain '1.3.6.1.4.1.311.21.8.100.7'
        @($k) | Should -Contain '1.3.6.1.4.1.311.21.8.100.8'
        @($k) | Should -Not -Contain '1.3.6.1.4.1.311.21.8.100.9'
    }

    It 'keeps the CA-database reader read-only (view only, no submit, no admin interface)' {
        $t = & $script:codeText (Join-Path $script:srcRoot 'Discovery\NdesEvidence.ps1')
        $t | Should -Match 'CertificateAuthority\.View'
        $t | Should -Not -Match '(?i)Submit|CertificateAuthority\.Admin|CertificateAuthority\.Request|Revoke|Resubmit|DenyRequest|IssueCertificate|SetRequestAttributes'
    }
}

Describe 'NDES evidence: outcomes of reading the CA database' {
    BeforeAll {
        $script:caObj = [pscustomobject]@{ Name = 'Example Issuing CA'; Config = 'ca01.corp.example.test\Example Issuing CA'; DnsHostName = 'ca01.corp.example.test'; Properties = [pscustomobject]@{ Templates = @() } }
        $script:ev = { param($Ca = $script:caObj, [switch]$SkipNetwork) InModuleScope MspkiHealthCheck -Parameters @{ C = $Ca; Skip = [bool]$SkipNetwork } { param($C, $Skip) Get-MspkiNdesCaEvidence -CA $C -TimeoutSeconds 3 -SkipNetwork:$Skip } }
    }

    It 'returns the rows and an information finding when the database could be read' {
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 5; Errors = @(); Output = @(@{ Rows = (New-Object System.Collections.ArrayList (, @(@{ 'request.requestername' = 'CORP\NDES01$'; commonname = 'NDES01-MSCEP-RA'; TemplateKey = 'CEPEncryption' }))); Errors = @(); Fatal = $null }) } }
        $r = & $script:ev
        $r.Read | Should -BeTrue
        @($r.Rows).Count | Should -Be 1
        $r.Rows[0].Requester | Should -Be 'CORP\NDES01$'
        $r.Findings[0].Status | Should -Be 'Information'
        $r.Findings[0].Notes | Should -Match 'only its own requests'
    }

    It 'reports access denied as PERMISSION_DENIED (skipped), apart from infrastructure failures' {
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 5; Errors = @(); Output = @(@{ Rows = @(); Errors = @(); Fatal = @{ HResult = '80070005'; Message = 'Access is denied.' } }) } }
        $r = & $script:ev
        $r.Read | Should -BeFalse
        $r.Findings[0].StatusCode | Should -Be 'PERMISSION_DENIED'
        $r.Findings[0].Status | Should -Be 'Skipped'
        $r.Findings[0].Notes | Should -Match 'Read permission'
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 5; Errors = @(); Output = @(@{ Rows = @(); Errors = @(); Fatal = @{ HResult = '800706BA'; Message = 'The RPC server is unavailable.' } }) } }
        $u = & $script:ev
        $u.Findings[0].StatusCode | Should -Be 'RETRIEVAL_FAIL'
        $u.Findings[0].Status | Should -Be 'Warning'
    }

    It 'reports a timeout as TIMEOUT' {
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $false; TimedOut = $true; ElapsedMs = 30000; Errors = @(); Output = @() } }
        (& $script:ev).Findings[0].StatusCode | Should -Be 'TIMEOUT'
    }

    It 'does not touch the CA when -SkipNetwork is used or when the CA did not answer earlier' {
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript { throw 'must not be called' }
        $s = & $script:ev -SkipNetwork
        $s.Findings[0].Status | Should -Be 'Skipped'
        $noProps = [pscustomobject]@{ Name = 'Example Issuing CA'; Config = 'ca01.corp.example.test\Example Issuing CA'; Properties = $null }
        $n = & $script:ev $noProps
        $n.Findings[0].Status | Should -Be 'Skipped'
        Should -Invoke -ModuleName MspkiHealthCheck Invoke-MspkiTimeLimitedScript -Times 0 -Exactly
    }
}

Describe 'NDES analysis' {
    BeforeEach { & $script:setOk; $script:server.Log.Clear(); InModuleScope MspkiHealthCheck { Reset-MspkiLeadRegistry; Reset-MspkiProbeCache } }

    BeforeAll {
        $script:disc = { param($Cas = @(), $Domains = @('corp.example.test'))
            [pscustomobject]@{ Inventory = [pscustomobject]@{ AdContext = [pscustomobject]@{ ForestDomains = $Domains; Ready = $false; DomainController = '' }; TemplatesRead = $false; Templates = @(); EnterpriseCAs = @($Cas) } } }
        $script:run = { param($d, [switch]$SkipNetwork) InModuleScope MspkiHealthCheck -Parameters @{ D = $d; Skip = [bool]$SkipNetwork } { param($D, $Skip) Invoke-MspkiNdesAnalysis -Discovery $D -TimeoutSeconds 3 -SkipNetwork:$Skip } }
    }

    It 'reports NotDiscovered, as not applicable and with the limits, when there is no evidence and no reference' {
        $r = & $script:run (& $script:disc @($script:caObj))
        # The CA database is not reachable in this test (no COM): the CA read is skipped or fails; nothing is found.
        $nd = @($r.Findings | Where-Object { $_.Message -like 'Classification NotDiscovered*' })
        $nd.Count | Should -Be 1
        $nd[0].Status | Should -Be 'NotApplicable'
        $nd[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        $nd[0].Notes | Should -Match 'does not prove'
        @($r.Hosts).Count | Should -Be 0
        # No CA database could be read here, so the negative has no basis: it is Unknown, never Confirmed.
        $nd[0].Confidence | Should -Be 'Unknown'
    }

    It 'calls NotDiscovered only Inferred (never Confirmed) even when a CA database was read and showed no NDES template rows' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiNdesCaEvidence { [pscustomobject]@{ Rows = @(); Read = $true; Findings = @() } }
        $r = & $script:run (& $script:disc @($script:caObj))
        $nd = @($r.Findings | Where-Object { $_.Message -like 'Classification NotDiscovered*' })
        $nd.Count | Should -Be 1
        $nd[0].Confidence | Should -Be 'Inferred'
    }

    It 'probes a SCEP URL that another lead references (ReferencedEndpoint) and nothing else' {
        InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:b + '/certsrv/mscep/mscep.dll') } { param($U) $null = Add-MspkiLead -Url $U -Kind CEP -Source 'Policy:CEP:HKLM' -Origin 'test policy' }
        $r = & $script:run (& $script:disc @())
        @($r.Hosts).Count | Should -Be 1
        $r.Hosts[0].Classification | Should -Be 'ConfirmedEndpoint'
        $r.Hosts[0].Confirmed | Should -BeTrue
        $f = @($r.Findings | Where-Object { $_.Category -eq 'NDES' -and $_.StatusCode -eq 'OK' })[0]
        ($f.Evidence -join "`n") | Should -Match 'Referenced URL: .*/certsrv/mscep/mscep.dll'
        $f.Sources | Should -Contain 'Policy:CEP:HKLM'
        $log = @($script:server.Log)
        $log.Count | Should -Be 2
        @($log | ForEach-Object { $_.Path } | Where-Object { $script:allowedPaths -notcontains $_ }) | Should -BeNullOrEmpty
    }

    It 'classifies a CA-database candidate whose name resolves as ProbableCandidate and probes it only through its lead' {
        $rows = @([pscustomobject]@{ RequestId = '1'; Requester = 'CORP\NDES01$'; CommonName = 'NDES01-MSCEP-RA'; Template = 'CEPEncryption'; NotBefore = ''; NotAfter = '2027-01-01T00:00:00Z'; TemplateKey = 'CEPEncryption' })
        Mock -ModuleName MspkiHealthCheck Get-MspkiNdesCaEvidence { [pscustomobject]@{ Rows = $rows; Read = $true; Findings = @() } }
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName { [pscustomobject]@{ Status = 'Pass'; StatusCode = 'OK'; Error = ''; Addresses = @('192.0.2.50'); ElapsedMs = 0 } }
        Mock -ModuleName MspkiHealthCheck Test-MspkiTcpPort { [pscustomobject]@{ Status = 'Fail'; StatusCode = 'TCP_FAIL'; Error = 'refused'; ElapsedMs = 0 } }
        $r = & $script:run (& $script:disc @($script:caObj))
        $r.Hosts[0].Host | Should -Be 'ndes01.corp.example.test'
        $r.Hosts[0].Classification | Should -Be 'ProbableCandidate'
        $f = @($r.Findings | Where-Object { $_.Target -eq 'ndes01.corp.example.test' })[0]
        $f.Status | Should -Be 'Information'
        $f.Confidence | Should -Be 'Inferred'
        $f.TcpStatus | Should -Be 'Fail'
        ($f.Evidence -join "`n") | Should -Match 'CA database: 1 issued certificate\(s\) from CEPEncryption'
        ($f.Evidence -join "`n") | Should -Match 'Signal: requester is the computer account CORP\\NDES01\$'
        ($f.Evidence -join "`n") | Should -Match 'a constructed name'
        $leads = @(InModuleScope MspkiHealthCheck { Get-MspkiLead -Kind NDES })
        $leads.Count | Should -Be 1
        @($leads[0].Variants).Count | Should -Be 2
        @($script:server.Log).Count | Should -Be 0
    }

    It 'sends nothing to a candidate whose constructed name does not resolve (UnconfirmedCandidate)' {
        $rows = @([pscustomobject]@{ RequestId = '1'; Requester = 'CORP\NDES01$'; CommonName = 'NDES01-MSCEP-RA'; Template = 'CEPEncryption'; NotBefore = ''; NotAfter = ''; TemplateKey = 'CEPEncryption' })
        Mock -ModuleName MspkiHealthCheck Get-MspkiNdesCaEvidence { [pscustomobject]@{ Rows = $rows; Read = $true; Findings = @() } }
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName { [pscustomobject]@{ Status = 'Fail'; StatusCode = 'DNS_FAIL'; Error = 'no such host'; Addresses = @(); ElapsedMs = 0 } }
        Mock -ModuleName MspkiHealthCheck Test-MspkiTcpPort { throw 'must not be called' }
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiHttpGet { throw 'must not be called' }
        $r = & $script:run (& $script:disc @($script:caObj))
        $r.Hosts[0].Classification | Should -Be 'UnconfirmedCandidate'
        $f = @($r.Findings | Where-Object { $_.Target -eq 'ndes01.corp.example.test' })[0]
        $f.StatusCode | Should -Be 'DNS_FAIL'
        $f.Status | Should -Be 'Information'
        $f.Message | Should -Match 'Nothing was sent'
        @(InModuleScope MspkiHealthCheck { Get-MspkiLead -Kind NDES }).Count | Should -Be 0
    }

    It 'sends nothing to a candidate for which no DNS name can be built' {
        $rows = @([pscustomobject]@{ RequestId = '1'; Requester = 'OTHER\NDES09$'; CommonName = 'NDES09-MSCEP-RA'; Template = 'CEPEncryption'; NotBefore = ''; NotAfter = ''; TemplateKey = 'CEPEncryption' })
        Mock -ModuleName MspkiHealthCheck Get-MspkiNdesCaEvidence { [pscustomobject]@{ Rows = $rows; Read = $true; Findings = @() } }
        Mock -ModuleName MspkiHealthCheck Invoke-MspkiHttpGet { throw 'must not be called' }
        $r = & $script:run (& $script:disc @($script:caObj) @('corp.example.test', 'child.corp.example.test'))
        $r.Hosts[0].Classification | Should -Be 'UnconfirmedCandidate'
        $f = @($r.Findings | Where-Object { $_.Target -eq 'NDES09' })[0]
        $f.StatusCode | Should -Be 'NOT_DISCOVERED'
        $f.Confidence | Should -Be 'Inferred'
    }

    It 'never presents a candidate as Confirmed' {
        $rows = @([pscustomobject]@{ RequestId = '1'; Requester = 'CORP\NDES01$'; CommonName = 'NDES01-MSCEP-RA'; Template = 'CEPEncryption'; NotBefore = ''; NotAfter = ''; TemplateKey = 'CEPEncryption' })
        Mock -ModuleName MspkiHealthCheck Get-MspkiNdesCaEvidence { [pscustomobject]@{ Rows = $rows; Read = $true; Findings = @() } }
        Mock -ModuleName MspkiHealthCheck Resolve-MspkiDnsName { [pscustomobject]@{ Status = 'Fail'; StatusCode = 'DNS_FAIL'; Error = 'no such host'; Addresses = @(); ElapsedMs = 0 } }
        $r = & $script:run (& $script:disc @($script:caObj))
        @($r.Findings | Where-Object { $_.Category -eq 'NDES' -and $_.Confidence -eq 'Confirmed' -and $_.Message -like '*candidate*' }).Count | Should -Be 0
    }
}
