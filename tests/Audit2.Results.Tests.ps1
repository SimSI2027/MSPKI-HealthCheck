# Tests for the Batch B fixes of audit 2 (docs/AUDIT-2.md): results that were more confident than the evidence (M1, M2, M7),
# the retrieval-order check (M4), redirects (M5), large CRLs (M3), status codes (M8) and the other Medium and Low items.
# Hosts are 127.0.0.1 and example.test names only; nothing leaves this computer.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root1 = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    # The same name with a new key: the renewed root.
    $script:root2 = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 100 -DaysValid 4000
    $script:subNew = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root2.Full -DaysValid 900 -WithAki
}

Describe 'Audit 2 M1: an AIA location that serves the old CA certificate after a renewal is not Verified' {
    It 'is a key mismatch when the old root is known too (the old generation is still in AD) and the subordinate needs the new key' {
        $tp = $script:subNew.Public.Thumbprint
        $known = @{ $tp = $script:subNew.Public; $script:root1.Public.Thumbprint = $script:root1.Public; $script:root2.Public.Thumbprint = $script:root2.Public }
        $m = InModuleScope MspkiHealthCheck -Parameters @{ D = $script:root1.Public; K = $known; Tp = $tp } {
            param($D, $K, $Tp)
            Test-MspkiAiaCertificateMatch -Downloaded $D -Lead ([pscustomobject]@{ Sources = @(('Cert:{0}:AIA' -f $Tp)) }) -KnownCertificates $K -ExpectedIssuer @('CN=Example Root CA, DC=example, DC=test') }
        $m.Result | Should -Be 'KeyMismatch'
    }
    It 'is still Verified when the downloaded certificate is the new root' {
        $tp = $script:subNew.Public.Thumbprint
        $known = @{ $tp = $script:subNew.Public; $script:root1.Public.Thumbprint = $script:root1.Public; $script:root2.Public.Thumbprint = $script:root2.Public }
        $m = InModuleScope MspkiHealthCheck -Parameters @{ D = $script:root2.Public; K = $known; Tp = $tp } {
            param($D, $K, $Tp)
            Test-MspkiAiaCertificateMatch -Downloaded $D -Lead ([pscustomobject]@{ Sources = @(('Cert:{0}:AIA' -f $Tp)) }) -KnownCertificates $K -ExpectedIssuer @('CN=Example Root CA, DC=example, DC=test') }
        $m.Result | Should -Be 'Verified'
    }
}

Describe 'Audit 2 M4: the retrieval-order check matches URLs after normalisation and counts only usable objects' {
    BeforeAll {
        # Findings for a URL, built the way the probes build them: the Endpoint is the normalised probe URL (spaces as %20).
        $script:probeFinding = {
            param([string]$Url, [string]$Status, [string]$Code = 'OK', [string]$Category = 'CDP')
            InModuleScope MspkiHealthCheck -Parameters @{ U = $Url; S = $Status; C = $Code; K = $Category } {
                param($U, $S, $C, $K)
                New-MspkiFinding -Stage 'Probe' -Category $K -Role 'CDPEndpoint' -Target 'pki.example.test' -Endpoint $U -Status $S -StatusCode $C -Sources @('test') -Message 'test' -Confidence 'Confirmed'
            }
        }
        $script:order = {
            param([string[]]$Urls, $Findings, [string]$Kind = 'CDP')
            InModuleScope MspkiHealthCheck -Parameters @{ U = $Urls; F = @($Findings); K = $Kind } {
                param($U, $F, $K)
                $o = Get-MspkiRetrievalOutcome -Findings $F
                Test-MspkiRetrievalOrder -IssuerName 'Example Issuing CA' -Kind $K -Urls $U -UrlOutcome $o
            }
        }
    }
    It 'finds a failing URL that contains a space (the certificate has the space, the probe the %20): Fail, not "not tested"' {
        $f = & $script:order @('http://pki.example.test/CertEnroll/Example Issuing CA.crl') @(& $script:probeFinding 'http://pki.example.test/CertEnroll/Example%20Issuing%20CA.crl' 'Fail' 'HTTP_404')
        $f.Status | Should -Be 'Fail'
        $f.StatusCode | Should -Be 'RETRIEVAL_ORDER'
    }
    It 'matches an explicit default port and a different host case' {
        $f = & $script:order @('http://PKI.example.test:80/CertEnroll/ca.crl') @(& $script:probeFinding 'http://pki.example.test/CertEnroll/ca.crl' 'Pass')
        $f.Status | Should -Be 'Pass'
    }
    It 'does not mix up the http and the https URL of the same path' {
        $f = & $script:order @('https://pki.example.test/ca.crl', 'http://pki.example.test/ca.crl') @(& $script:probeFinding 'http://pki.example.test/ca.crl' 'Pass')
        # The https URL was not tested; the http one works, and the first URL is unknown, not failing.
        $f.Status | Should -Not -Be 'Pass'
        $f.Status | Should -Not -Be 'Warning'
        $f.Confidence | Should -Be 'Referenced'
    }
    It 'does not count a Warning for the wrong content as a working URL: <Name>' -TestCases @(
        @{ Name = 'wrong CRL issuer'; Code = 'CONTENT_WRONG_TYPE' }
        @{ Name = 'a failure capped to a Warning by scope'; Code = 'DNS_FAIL' }
        @{ Name = 'a redirect that was not followed'; Code = 'HTTP_REDIRECT' }
    ) {
        param($Name, $Code)
        $only = & $script:order @('http://pki.example.test/a.crl') @(& $script:probeFinding 'http://pki.example.test/a.crl' 'Warning' $Code)
        $only.Status | Should -Be 'Fail' -Because 'the only URL did not deliver a usable object'
        $two = & $script:order @('http://pki.example.test/a.crl', 'http://pki.example.test/b.crl') @(
            (& $script:probeFinding 'http://pki.example.test/a.crl' 'Warning' $Code), (& $script:probeFinding 'http://pki.example.test/b.crl' 'Pass'))
        $two.Status | Should -Be 'Warning'
        $two.Message | Should -Match '1 failing CDP URL'
    }
    It 'still counts a Warning about the object''s age (it was retrieved) as working' {
        $f = & $script:order @('http://pki.example.test/a.crl') @(& $script:probeFinding 'http://pki.example.test/a.crl' 'Pass'; & $script:probeFinding 'http://pki.example.test/a.crl' 'Warning' 'OBJECT_EXPIRING' 'CRL')
        $f.Status | Should -Be 'Pass'
    }
    It 'an expired CRL (Fail from the freshness check) is not a working URL even though the download passed' {
        $f = & $script:order @('http://pki.example.test/a.crl') @(& $script:probeFinding 'http://pki.example.test/a.crl' 'Pass'; & $script:probeFinding 'http://pki.example.test/a.crl' 'Fail' 'OBJECT_EXPIRED' 'CRL')
        $f.Status | Should -Be 'Fail'
    }
    It 'says how many URLs were really tested, and is not Confirmed when some were not' {
        $urls = @('http://pki.example.test/a.crl', 'http://pki.example.test/b.crl', 'http://pki.example.test/c.crl')
        $f = & $script:order $urls @(& $script:probeFinding $urls[0] 'Fail' 'HTTP_404'; & $script:probeFinding $urls[1] 'Fail' 'TIMEOUT'; & $script:probeFinding $urls[2] 'Skipped' 'NOT_APPLICABLE')
        $f.Status | Should -Be 'Fail'
        $f.Message | Should -Match '2 of the 3 CDP URLs'
        $f.Message | Should -Not -Match '^None of the 3'
        $f.Confidence | Should -Be 'Referenced'
        $all = & $script:order $urls @(& $script:probeFinding $urls[0] 'Fail' 'HTTP_404'; & $script:probeFinding $urls[1] 'Fail' 'HTTP_404'; & $script:probeFinding $urls[2] 'Fail' 'TIMEOUT')
        $all.Confidence | Should -Be 'Confirmed'
    }
}

Describe 'Audit 2 M5: a redirect that is not followed is an answer (status and Location), never "no answer"' {
    BeforeAll {
        $script:routes5 = [hashtable]::Synchronized(@{})
        $script:server5 = Start-TestHttpServer -Routes $script:routes5
        $script:b5 = $script:server5.Base
        $script:routes5['/start'] = @{ Status = 302; Body = @(); Headers = @{ Location = '/next' } }
        $script:routes5['/next'] = @{ Status = 301; Body = @(); Headers = @{ Location = '/last' } }
        $script:routes5['/last'] = @{ Status = 200; Body = [System.Text.Encoding]::ASCII.GetBytes('ok') }
        $script:get5 = {
            param([string]$Path, [int]$Max = 0)
            InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:b5 + $Path); M = $Max } {
                param($U, $M) Reset-MspkiProbeCache; Invoke-MspkiHttpGet -Url $U -TimeoutMs 3000 -MaxRedirects $M -DiscardBody }
        }
    }
    AfterAll { Stop-TestHttpServer -Server $script:server5 }

    It 'takes HttpStatus and the Location from the redirect when redirects are turned off' {
        $r = & $script:get5 '/start' 0
        $r.HttpStatus | Should -Be 302
        $r.Code | Should -Be 'HTTP_REDIRECT'
        $r.Redirected | Should -BeTrue
        @($r.Hops)[-1].HttpStatus | Should -Be 302
        @($r.Hops)[-1].Location | Should -Be '/next'
        $r.Error | Should -Match 'redirect'
        $r.Error | Should -Match '/next'
    }
    It 'takes HttpStatus from the last hop when the hop limit is reached' {
        $r = & $script:get5 '/start' 1
        $r.HttpStatus | Should -Be 301
        $r.Code | Should -Be 'HTTP_REDIRECT'
        $r.Error | Should -Match 'More than 1 redirect'
    }
    It 'still follows redirects within the limit' {
        $r = & $script:get5 '/start' 5
        $r.HttpStatus | Should -Be 200
        $r.Code | Should -Be 'OK'
    }
    It 'is present Web Enrollment evidence: the state is not $null and says it redirects' {
        $r = & $script:get5 '/start' 0
        $s = InModuleScope MspkiHealthCheck -Parameters @{ R = $r } { param($R) Get-MspkiWebEnrollmentState -Http $R }
        $s | Should -Not -BeNullOrEmpty
        $s.HttpStatus | Should -Be 302
        $s.Meaning | Should -Match 'redirects \(HTTP 302\) to /next'
    }
    It 'gives a Web Enrollment finding (Inferred) with the redirect in its evidence when http redirects and https was not reachable' {
        $r = & $script:get5 '/start' 0
        $f = @(InModuleScope MspkiHealthCheck -Parameters @{ R = $r } { param($R) Test-MspkiWebEnrollment -HostName 'ca01.corp.example.test' -Http $R })
        $f.Count | Should -Be 1
        $f[0].StatusCode | Should -Be 'OK'
        $f[0].Confidence | Should -Be 'Inferred'
        ($f[0].Evidence -join "`n") | Should -Match 'HTTP 302, redirects \(HTTP 302\) to /next'
        ($f[0].Evidence -join "`n") | Should -Not -Match 'no answer'
    }
}

Describe 'Audit 2 M3: a valid CRL larger than the general download cap is not a failure' {
    BeforeAll {
        $script:routes3 = [hashtable]::Synchronized(@{})
        $script:server3 = Start-TestHttpServer -Routes $script:routes3
        $script:b3 = $script:server3.Base
        # Bigger than the 1 KiB cap used below; the first byte is a DER SEQUENCE tag, as for a real CRL.
        $big = New-Object byte[] 5000; $big[0] = 0x30
        $script:routes3['/big.crl'] = @{ Status = 200; Body = $big }
        $script:crlProbe = {
            param([long]$Cap)
            InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:b3 + '/big.crl'); Cap = $Cap } {
                param($U, $Cap)
                [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry; Reset-MspkiProbeCache; Set-MspkiWebProbeOption
                $old = $script:MspkiCrlMaxBytes
                if ($Cap -gt 0) { $script:MspkiCrlMaxBytes = [int]$Cap }
                try {
                    $lead = Add-MspkiLead -Url $U -Kind CDP -Source 'AD:test' -Origin 'test'
                    Test-MspkiLeadEndpoint -Lead $lead -Url $lead.Url
                }
                finally { $script:MspkiCrlMaxBytes = $old }
            }
        }
    }
    AfterAll { Stop-TestHttpServer -Server $script:server3 }

    It 'allows a CRL of at least 32 MB for CDP downloads (the general cap is 10 MB)' {
        $cap = InModuleScope MspkiHealthCheck { $script:MspkiCrlMaxBytes }
        $cap | Should -BeGreaterOrEqual 33554432
    }
    It 'reports a CRL above the CRL cap as its own result: Information, SIZE_LIMIT, never Fail or CONTENT_WRONG_TYPE' {
        $r = & $script:crlProbe 1024
        $f = @($r.Findings)[0]
        $f.StatusCode | Should -Be 'SIZE_LIMIT'
        $f.Status | Should -Be 'Information'
        $f.Message | Should -Match 'larger than'
        $f.Message | Should -Match 'not (read|checked)'
        $f.HttpStatus | Should -Be 'Pass'
        @($r.Findings | Where-Object { $_.Status -eq 'Fail' }).Count | Should -Be 0
    }
    It 'does not turn that result into exit code 4' {
        $r = & $script:crlProbe 1024
        $code = InModuleScope MspkiHealthCheck -Parameters @{ F = @($r.Findings) } { param($F) Get-MspkiExitCode -Findings $F }
        $code | Should -Not -Be 4
    }
    It 'counts revoked entries without building an object per entry' {
        InModuleScope MspkiHealthCheck {
            $one = [byte[]](0x02, 0x01, 0x05)
            $list = New-Object System.Collections.Generic.List[byte]
            for ($i = 0; $i -lt 3000; $i++) { $list.AddRange($one) }
            $content = $list.ToArray()
            $hdr = [byte[]](0x30, 0x82, [byte](($content.Length -shr 8) -band 0xFF), [byte]($content.Length -band 0xFF))
            $seq = [byte[]]($hdr + $content)
            $el = Read-MspkiDerElement -Bytes $seq -Offset 0
            Measure-MspkiDerChild -Bytes $seq -Element $el | Should -Be 3000
            (Get-MspkiDerChild -Bytes $seq -Element $el).Count | Should -Be 3000
            { Measure-MspkiDerChild -Bytes ([byte[]]($hdr + $content[0..($content.Length - 2)])) -Element ([pscustomobject]@{ ContentOffset = 4; End = ($seq.Length - 1) }) } | Should -Throw
        }
    }
}

Describe 'Audit 2 M8: different failures have different status codes' {
    It 'names the TLS result from the chain errors: <Name>' -TestCases @(
        @{ Name = 'untrusted root'; Errors = @('UntrustedRoot'); Name2 = $true; Code = 'TLS_UNTRUSTED_ROOT' }
        @{ Name = 'partial chain'; Errors = @('PartialChain'); Name2 = $true; Code = 'TLS_PARTIAL_CHAIN' }
        @{ Name = 'expired'; Errors = @('NotTimeValid'); Name2 = $true; Code = 'OBJECT_EXPIRED' }
        @{ Name = 'a completed handshake whose chain has a signature error is a chain problem, not a failed handshake'; Errors = @('NotSignatureValid'); Name2 = $true; Code = 'CHAIN_INVALID' }
        @{ Name = 'a completed handshake with an unsuitable key usage'; Errors = @('NotValidForUsage', 'Revoked'); Name2 = $true; Code = 'CHAIN_INVALID' }
        @{ Name = 'a name mismatch when the chain is fine'; Errors = @(); Name2 = $false; Code = 'TLS_NAME_MISMATCH' }
        @{ Name = 'everything fine'; Errors = @(); Name2 = $true; Code = 'OK' }
    ) {
        param($Name, $Errors, $Name2, $Code)
        $c = InModuleScope MspkiHealthCheck -Parameters @{ E = @($Errors); N = $Name2 } { param($E, $N) Get-MspkiTlsChainCode -ChainErrors $E -NameMatch $N }
        $c | Should -Be $Code
    }

    It 'does not give a host identity summary the code OK when its DNS lookup failed or timed out' -TestCases @(
        @{ Lookup = 'Timeout'; Code = 'TIMEOUT' }
        @{ Lookup = 'ServerFailure'; Code = 'DNS_FAIL' }
        @{ Lookup = 'NoRecord'; Code = 'DNS_FAIL' }
    ) {
        param($Lookup, $Code)
        $id = [pscustomobject]@{ Target = 'ca01.corp.example.test'; QueryName = 'ca01.corp.example.test'; Chain = @('ca01.corp.example.test'); A = @(); AAAA = @(); Ptr = @(); Lookup = $Lookup; Method = 'DnsClient'; Error = '' }
        $f = @(InModuleScope MspkiHealthCheck -Parameters @{ Id = $id } { param($Id) Test-MspkiHostIdentity -HostName 'ca01.corp.example.test' -Identity $Id })
        $s = @($f | Where-Object { $_.Message -like 'Identity of*' })
        $s.Count | Should -Be 1
        $s[0].StatusCode | Should -Be $Code
        $s[0].StatusCode | Should -Not -Be 'OK'
    }

    It 'keeps one code for one cause: a missing CertificateAuthority.View class is NOT_APPLICABLE like a missing CertificateAuthority.Request class' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Discovery\NdesEvidence.ps1') -Raw
        $src | Should -Match "(?s)80040154.*?-StatusCode 'NOT_APPLICABLE'"
        $cp = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Discovery\CAProperty.ps1') -Raw
        $cp | Should -Match "(?s)80040154'\) \{.*?-StatusCode 'NOT_APPLICABLE'"
    }

    It 'has a code of its own for each of these (schema): RPC_FAIL, RETRIEVAL_ORDER, CONTENT_MISMATCH, ENROLLMENT_FAIL, SIZE_LIMIT' {
        $codes = InModuleScope MspkiHealthCheck { (Get-MspkiSchema).StatusCode }
        foreach ($c in @('RPC_FAIL', 'RETRIEVAL_ORDER', 'CONTENT_MISMATCH', 'ENROLLMENT_FAIL', 'SIZE_LIMIT')) { $codes | Should -Contain $c }
    }

    It 'documents every status code of the schema in REQUIREMENTS.md' {
        $codes = InModuleScope MspkiHealthCheck { (Get-MspkiSchema).StatusCode }
        $doc = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'docs\REQUIREMENTS.md') -Raw
        foreach ($c in $codes) { $doc | Should -Match ([regex]::Escape($c)) -Because "$c is a status code" }
    }
}

Describe 'Audit 2 M13: Constrained Language Mode is detected at the start and reported in plain words' {
    BeforeAll {
        # A child powershell.exe that switches its own session to Constrained Language Mode and then runs the script, so every script
        # it runs is restricted like under AppLocker or WDAC. Only the child is affected. The child is killed after 90 seconds.
        $script:runClm = {
            param([string]$Script, [string[]]$Arguments = @(), [switch]$Sta, [string]$Probe = '')
            $argText = (@($Arguments | ForEach-Object { if ($_ -match '^-[A-Za-z]+$') { $_ } else { "'" + ($_ -replace "'", "''") + "'" } }) -join ' ')
            $cmd = "`$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'; "
            if ($Probe) { $cmd += $Probe }
            else { $cmd += "& '" + ($Script -replace "'", "''") + "' $argText; exit `$LASTEXITCODE" }
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = ('-NoProfile {0} -ExecutionPolicy Bypass -Command "& {{ {1} }}"' -f $(if ($Sta) { '-STA' } else { '-MTA' }), ($cmd -replace '"', '\"'))
            $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $so = $proc.StandardOutput.ReadToEndAsync(); $se = $proc.StandardError.ReadToEndAsync()
            if (-not $proc.WaitForExit(90000)) { try { $proc.Kill() } catch { }; return [pscustomobject]@{ Code = -1; Text = 'TIMED OUT' } }
            $proc.WaitForExit()
            return [pscustomobject]@{ Code = $proc.ExitCode; Text = ($so.Result + "`n" + $se.Result) }
        }
        $script:clmOk = ((& $script:runClm '' @() -Probe 'Write-Output $ExecutionContext.SessionState.LanguageMode').Text -match 'ConstrainedLanguage')
    }

    It 'knows which language modes the tool can run in: <Mode>' -TestCases @(
        @{ Mode = 'FullLanguage'; Full = $true }
        @{ Mode = 'ConstrainedLanguage'; Full = $false }
        @{ Mode = 'RestrictedLanguage'; Full = $false }
        @{ Mode = 'NoLanguage'; Full = $false }
    ) {
        param($Mode, $Full)
        $s = InModuleScope MspkiHealthCheck -Parameters @{ M = $Mode } { param($M) Get-MspkiLanguageModeStatus -Mode $M }
        $s.IsFull | Should -Be $Full
        $s.Mode | Should -Be $Mode
        if (-not $Full) {
            $s.Message | Should -Match 'Constrained Language Mode'
            $s.Message | Should -Match 'AppLocker'
            $s.Message | Should -Match 'Nothing was changed'
        }
    }

    It 'reads the real mode of this session (Full on the test machine)' {
        $s = InModuleScope MspkiHealthCheck { Get-MspkiLanguageModeStatus }
        $s.Mode | Should -Be ([string]$ExecutionContext.SessionState.LanguageMode)
    }

    It 'the test child process really is in Constrained Language Mode (so the tests below mean something)' {
        $script:clmOk | Should -BeTrue
    }

    It 'the command-line script stops with exit code 5 and a plain explanation, before it loads or writes anything' {
        $script:clmOk | Should -BeTrue -Because 'the child must be restricted, otherwise this test would run a real check'
        $out = Join-Path $TestDrive 'clm-out'
        $r = & $script:runClm (Join-Path $script:RepoRoot 'Invoke-MspkiHealthCheck.ps1') @('-OutputPath', $out, '-SkipNetwork', '-NoOpen')
        $r.Code | Should -Be 5
        $r.Text | Should -Match 'Constrained Language Mode'
        $r.Text | Should -Match 'AppLocker'
        $r.Text | Should -Match 'Nothing was changed'
        Test-Path -LiteralPath $out | Should -BeFalse
    }

    It 'the window launcher does the same (and opens no window)' {
        $script:clmOk | Should -BeTrue -Because 'the child must be restricted, otherwise this test would open a real window'
        $out = Join-Path $TestDrive 'clm-out-gui'
        $r = & $script:runClm (Join-Path $script:RepoRoot 'Start-MspkiHealthCheckGui.ps1') @('-OutputPath', $out) -Sta
        $r.Code | Should -Be 5
        $r.Text | Should -Match 'Constrained Language Mode'
        Test-Path -LiteralPath $out | Should -BeFalse
    }

    It 'Start-MspkiHealthCheck refuses to start in another language mode, with the same words, and writes nothing' {
        $out = Join-Path $TestDrive 'clm-out-engine'
        $msg = $null
        try {
            InModuleScope MspkiHealthCheck -Parameters @{ O = $out } {
                param($O)
                Mock Get-MspkiLanguageModeStatus { [pscustomobject]@{ Mode = 'ConstrainedLanguage'; IsFull = $false; Message = 'MSPKI Health Check cannot run: Constrained Language Mode (test).' } }
                Start-MspkiHealthCheck -OutputPath $O -SkipNetwork
            }
        }
        catch { $msg = $_.Exception.Message }
        $msg | Should -Match 'Constrained Language Mode'
        Test-Path -LiteralPath $out | Should -BeFalse
    }
}
