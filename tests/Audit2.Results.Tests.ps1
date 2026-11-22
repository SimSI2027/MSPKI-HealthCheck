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

Describe 'Audit 2 L13: a cancel during discovery keeps what discovery had found' {
    It 'returns the partial inventory and findings, marked Cancelled, instead of throwing them away' {
        $d = InModuleScope MspkiHealthCheck {
            $ctl = New-MspkiRunControl
            Set-MspkiRunControl -Control $ctl
            try {
                Mock Get-MspkiAdContext { $ctl.Cancel = $true; [pscustomobject]@{ Findings = @(); Data = [pscustomobject]@{ Ready = $true; Forest = 'corp.example.test'; Domain = 'corp.example.test'; DomainController = 'dc01.corp.example.test' } } }
                Invoke-MspkiDiscovery -TimeoutSeconds 1
            }
            finally { Set-MspkiRunControl -Control $null }
        }
        $d.Cancelled | Should -BeTrue
        $d.Inventory.AdContext.Forest | Should -Be 'corp.example.test'
        @($d.Findings | Where-Object { $_.StatusCode -eq 'NOT_APPLICABLE' -and $_.Status -eq 'Skipped' -and $_.Message -match 'cancel' }).Count | Should -Be 1
    }
    It 'has no Cancelled flag on a normal run' {
        $d = InModuleScope MspkiHealthCheck {
            Set-MspkiRunControl -Control $null
            Mock Get-MspkiAdContext { [pscustomobject]@{ Findings = @(); Data = [pscustomobject]@{ Ready = $false } } }
            Invoke-MspkiDiscovery -TimeoutSeconds 1
        }
        $d.Cancelled | Should -BeFalse
    }
}

Describe 'Audit 2 L14 and L1: limits of a run are recorded, not silent' {
    It 'L14: when run.log cannot be written, the run records it as a limit and keeps the log in memory' {
        $lim = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun)
            $script:MspkiLogPath = Join-Path ([System.IO.Path]::GetTempPath()) 'mspki-not-the-output-folder\run.log'
            Write-MspkiLog -Message 'first line after the log became unwritable'
            [pscustomobject]@{ Limits = @($script:MspkiRun.Limits); InMemory = @(Get-MspkiLogLine | Where-Object { $_ -like '*first line after*' }).Count; Path = $script:MspkiLogPath }
        }
        $lim.Path | Should -Be ''
        $lim.InMemory | Should -Be 1
        @($lim.Limits | Where-Object { $_ -match 'run\.log' -and $_ -match 'could not be written' }).Count | Should -Be 1
    }
    It 'L1: a run with network checks says that Windows may fetch certificates on its own during TLS validation; -SkipNetwork does not' {
        $r = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun -Parameters @{ SkipNetwork = $false }); $a = @($script:MspkiRun.Limits)
            [void](Initialize-MspkiRun -Parameters @{ SkipNetwork = $true }); $b = @($script:MspkiRun.Limits)
            [pscustomobject]@{ With = $a; Without = $b }
        }
        @($r.With | Where-Object { $_ -match 'chain' -and $_ -match 'not bounded' }).Count | Should -Be 1
        @($r.Without | Where-Object { $_ -match 'chain' -and $_ -match 'not bounded' }).Count | Should -Be 0
    }
}

Describe 'Audit 2 L15: the report is opened in the browser only in an interactive session' {
    It 'checks [Environment]::UserInteractive (and -NoOpen) before it starts the default browser, and says so in the help' {
        $t = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-MspkiHealthCheck.ps1') -Raw
        $t | Should -Match '\$result\.ReportPath -and -not \$NoOpen -and \[Environment\]::UserInteractive'
        $t | Should -Match '(?is)\.PARAMETER NoOpen.{0,400}interactive'
    }
}

Describe 'Audit 2 L12: a probe runspace that timed out is disposed once its call has ended' {
    It 'keeps the abandoned runspace in a list, and Remove-MspkiAbandonedProbe closes and removes it after the call stopped' {
        $r = InModuleScope MspkiHealthCheck {
            [void](Initialize-MspkiRun)
            $res = Invoke-MspkiTimeLimitedScript -ScriptBlock { Start-Sleep -Seconds 20 } -TimeoutSeconds 1
            $before = @($script:MspkiAbandonedProbe).Count
            $rs = @($script:MspkiAbandonedProbe)[0].Runspace
            # BeginStop was asked for; give the sleeping call a moment to end.
            $n = 0
            for ($i = 0; $i -lt 40 -and $n -eq 0; $i++) { Start-Sleep -Milliseconds 250; $n = Remove-MspkiAbandonedProbe }
            [pscustomobject]@{ TimedOut = $res.TimedOut; Before = $before; Removed = $n; After = @($script:MspkiAbandonedProbe).Count; State = [string]$rs.RunspaceStateInfo.State }
        }
        $r.TimedOut | Should -BeTrue
        $r.Before | Should -Be 1
        $r.Removed | Should -Be 1
        $r.After | Should -Be 0
        $r.State | Should -Be 'Closed'
    }
}

Describe 'Audit 2 L8: the cross-location CRL comparison trusts only CRLs whose signature verified' {
    BeforeAll {
        $script:l8root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
        $script:l8other = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysValid 100
        $script:l8lead = { param($u) [pscustomobject]@{ Url = $u; Sources = @('AD:test'); Scope = 'Local'; RelatedCAs = @('Example Root CA'); Kind = 'CDP' } }
        $script:l8run = {
            param($Crls, [bool]$WithCerts = $true)
            InModuleScope MspkiHealthCheck -Parameters @{ C = $Crls; K = @($script:l8root.Public); W = $WithCerts; Lead = $script:l8lead } {
                param($C, $K, $W, $Lead)
                $recs = @(foreach ($c in $C) { $l = & $Lead $c.Url; [pscustomobject]@{ Url = $c.Url; Lead = $l; Crl = (ConvertFrom-MspkiCrl -Bytes $c.Bytes); ExpectedIssuer = @() } })
                if ($W) { @(Test-MspkiCrlConsistency -Records $recs -Certificates $K) } else { @(Test-MspkiCrlConsistency -Records $recs) }
            }
        }
    }
    It 'does not let a CRL with an invalid signature and a higher number mark the good locations as stale' {
        $forged = New-TestCrl -Issuer $script:l8root -SigningKey $script:l8other.Key -Number 9
        $good1 = New-TestCrl -Issuer $script:l8root -Number 8
        $good2 = New-TestCrl -Issuer $script:l8root -Number 8
        $f = & $script:l8run @(@{ Url = 'http://pki.example.test/forged.crl'; Bytes = $forged }, @{ Url = 'http://pki.example.test/a.crl'; Bytes = $good1 }, @{ Url = 'http://pki.example.test/b.crl'; Bytes = $good2 })
        @($f | Where-Object { $_.Endpoint -like '*/a.crl' -or $_.Endpoint -like '*/b.crl' }).Count | Should -Be 0
    }
    It 'still reports a verified older CRL as stale, Confirmed' {
        $old = New-TestCrl -Issuer $script:l8root -Number 5
        $new = New-TestCrl -Issuer $script:l8root -Number 7
        $f = & $script:l8run @(@{ Url = 'http://pki.example.test/old.crl'; Bytes = $old }, @{ Url = 'http://pki.example.test/new.crl'; Bytes = $new })
        $f.Count | Should -Be 1
        $f[0].StatusCode | Should -Be 'STALE_DATA'
        $f[0].Confidence | Should -Be 'Confirmed'
    }
    It 'is only Referenced when no signature could be verified at all (no issuer certificate known)' {
        $old = New-TestCrl -Issuer $script:l8root -Number 5
        $new = New-TestCrl -Issuer $script:l8root -Number 7
        $f = & $script:l8run @(@{ Url = 'http://pki.example.test/old.crl'; Bytes = $old }, @{ Url = 'http://pki.example.test/new.crl'; Bytes = $new }) -WithCerts $false
        $f.Count | Should -Be 1
        $f[0].Confidence | Should -Be 'Referenced'
        ($f[0].Evidence -join "`n") | Should -Match 'not verified'
    }
}

Describe 'Audit 2 L7: an ldaps:// location is read over LDAPS, not plain LDAP' {
    It 'keeps the scheme and the port of an LDAP URL' {
        $r = InModuleScope MspkiHealthCheck {
            [pscustomobject]@{
                S = ConvertFrom-MspkiLdapUrl -Url 'ldaps://dc01.corp.example.test/CN=Example%20CA,CN=CDP,DC=corp,DC=example,DC=test?certificateRevocationList?base'
                P = ConvertFrom-MspkiLdapUrl -Url 'ldap://dc01.corp.example.test:3268/CN=x,DC=corp,DC=example,DC=test?cACertificate'
                N = ConvertFrom-MspkiLdapUrl -Url 'ldap:///CN=x,DC=corp,DC=example,DC=test?cACertificate'
            }
        }
        $r.S.Scheme | Should -Be 'ldaps'
        $r.S.Port | Should -Be 636
        $r.S.Host | Should -Be 'dc01.corp.example.test'
        $r.P.Scheme | Should -Be 'ldap'
        $r.P.Port | Should -Be 3268
        $r.P.Host | Should -Be 'dc01.corp.example.test'
        $r.N.Scheme | Should -Be 'ldap'
        $r.N.Port | Should -Be 0
    }
    It 'builds an LDAPS connection (port 636, secure sockets layer) for ldaps and a plain one otherwise' {
        $r = InModuleScope MspkiHealthCheck {
            [pscustomobject]@{
                Ssl = Get-MspkiLdapConnectionSpec -Server 'dc01.corp.example.test' -BaseDN 'DC=corp,DC=example,DC=test' -Ssl -Port 636
                Plain = Get-MspkiLdapConnectionSpec -Server 'dc01.corp.example.test' -BaseDN 'DC=corp,DC=example,DC=test'
                Less = Get-MspkiLdapConnectionSpec -Server '' -BaseDN 'DC=corp,DC=example,DC=test'
            }
        }
        $r.Ssl.Path | Should -Be 'LDAP://dc01.corp.example.test:636/DC=corp,DC=example,DC=test'
        $r.Ssl.AuthenticationTypes | Should -Match 'SecureSocketsLayer'
        $r.Plain.Path | Should -Be 'LDAP://dc01.corp.example.test/DC=corp,DC=example,DC=test'
        $r.Plain.AuthenticationTypes | Should -Not -Match 'SecureSocketsLayer'
        $r.Less.Path | Should -Be 'LDAP://DC=corp,DC=example,DC=test'
    }
    It 'Get-MspkiLdapUrlContent asks for LDAPS when the URL says ldaps, and for plain LDAP when it says ldap' {
        $r = InModuleScope MspkiHealthCheck {
            Reset-MspkiProbeCache
            $script:l7calls = New-Object System.Collections.ArrayList
            Mock Get-MspkiLdapObject { [void]$script:l7calls.Add(@{ Ssl = [bool]$Ssl; Port = $Port }); @(@{ 'cacertificate' = @(, [byte[]](1, 2, 3)) }) }
            [void](Get-MspkiLdapUrlContent -Url 'ldaps:///CN=a,DC=corp,DC=example,DC=test?cACertificate?base' -DefaultServer 'dc01.corp.example.test')
            [void](Get-MspkiLdapUrlContent -Url 'ldap:///CN=b,DC=corp,DC=example,DC=test?cACertificate?base' -DefaultServer 'dc01.corp.example.test')
            @($script:l7calls)
        }
        $r.Count | Should -Be 2
        $r[0].Ssl | Should -BeTrue
        $r[0].Port | Should -Be 636
        $r[1].Ssl | Should -BeFalse
    }
}

Describe 'Audit 2 L6: a missing AD object is recognised by its error code, never by message text' {
    It 'a COMException with the NO_SUCH_OBJECT code is NotFound whatever its (localised) message says' {
        $r = InModuleScope MspkiHealthCheck {
            Mock Get-MspkiLdapObject { throw (New-Object System.Runtime.InteropServices.COMException('Es gibt kein solches Objekt auf dem Server.', -2147016656)) }
            Read-MspkiNdesAccount -Sid 'S-1-5-21-1-2-3-1001' -Server 'dc01.corp.example.test'
        }
        $r.Status | Should -Be 'NotFound'
    }
    It 'an exception without that code is an error even when its message contains the English words' {
        $r = InModuleScope MspkiHealthCheck {
            Mock Get-MspkiLdapObject { throw (New-Object System.InvalidOperationException('there is no such object in the cache')) }
            Read-MspkiNdesAccount -Sid 'S-1-5-21-1-2-3-1001' -Server 'dc01.corp.example.test'
        }
        $r.Status | Should -Be 'Error'
    }
}

Describe 'Audit 2 L5 (audit 1 L8b): BUILTIN\Users and Anonymous Logon are broad principals' {
    It 'labels them by SID' {
        $r = InModuleScope MspkiHealthCheck { [pscustomobject]@{ U = Get-MspkiBroadPrincipal -Sid 'S-1-5-32-545'; A = Get-MspkiBroadPrincipal -Sid 'S-1-5-7'; N = Get-MspkiBroadPrincipal -Sid 'S-1-5-32-544'; D = Get-MspkiBroadPrincipal -Sid 'S-1-5-21-1-2-3-512' } }
        $r.U | Should -Be 'BUILTIN\Users'
        $r.A | Should -Be 'Anonymous Logon'
        $r.N | Should -Be ''
        $r.D | Should -Be ''
    }
    It 'a template that BUILTIN\Users may enroll for is a broad enroll (ESC1-style review), and one it may write is ESC4' {
        $tpl = {
            param($Sid, [int64]$Mask, $Obj = '')
            [pscustomobject]@{ Name = 'T'; DisplayName = 'T'; Oid = '1.3.6.1.4.1.311.21.8.1.1'; SchemaVersion = 2; Eku = @('1.3.6.1.5.5.7.3.2'); EnrollmentFlag = [int64]0; NameFlag = [int64]1; RaSignature = 0; Acl = @([pscustomobject]@{ Sid = $Sid; Principal = ''; Type = 'Allow'; Mask = $Mask; ObjectType = $Obj; InheritOnly = $false; Rights = @() }); OwnerSid = ''; Owner = '' }
        }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ T = (& $tpl 'S-1-5-32-545' 0x40000); E = (& $tpl 'S-1-5-32-545' 0x130 '0e10c968-78fb-11d2-90d4-00c04f79dc55') } {
            param($T, $E)
            [pscustomobject]@{ Write = @(Get-MspkiBroadAce -Template $T -Right Write).Count; Enroll = @(Get-MspkiBroadAce -Template $E -Right Enroll).Count }
        }
        $r.Write | Should -Be 1
        $r.Enroll | Should -Be 1
    }
    It 'the NDES account list counts them as broad (they name no host), not as candidates' {
        $acl = @([pscustomobject]@{ Sid = 'S-1-5-32-545'; Principal = ''; Type = 'Allow'; Mask = 0x130; ObjectType = '0e10c968-78fb-11d2-90d4-00c04f79dc55'; InheritOnly = $false; Rights = @('Enroll') },
            [pscustomobject]@{ Sid = 'S-1-5-7'; Principal = ''; Type = 'Allow'; Mask = 0x130; ObjectType = '0e10c968-78fb-11d2-90d4-00c04f79dc55'; InheritOnly = $false; Rights = @('Enroll') })
        $tpl = [pscustomobject]@{ Name = 'CEPEncryption'; DisplayName = 'CEP Encryption'; Oid = '1.3.6.1.4.1.311.21.8.1'; Eku = @('1.3.6.1.4.1.311.20.2.1'); ApplicationPolicies = @(); NameFlag = [int64]1; Acl = $acl; AclError = '' }
        $p = InModuleScope MspkiHealthCheck -Parameters @{ T = $tpl } { param($T) Get-MspkiNdesTemplatePrincipal -Templates @($T) -PublishedNames @('CEPEncryption') }
        @($p.Principals | Where-Object { $_.Class -eq 'Candidate' }).Count | Should -Be 0
        @($p.Principals | Where-Object { $_.Class -eq 'Broad' }).Count | Should -Be 2
    }
}

Describe 'Audit 2 L4: a permission verdict from timing says that timing is all it rests on' {
    It 'names a network device that resets the dynamic RPC port at once as another cause with the same timing, and keeps the result Inferred' {
        $d = InModuleScope MspkiHealthCheck { Get-MspkiCaRpcFailureDiagnosis -HResult '800706BA' -ElapsedMs 1200 -HostName 'ca01.corp.example.test' }
        $d.Kind | Should -Be 'RejectedQuickly'
        $d.Confidence | Should -Be 'Inferred'
        $d.Notes | Should -Match 'network device|firewall'
        $d.Notes | Should -Match 'timing'
        ($d.Evidence -join "`n") | Should -Match 'timing alone|rests on the timing'
        $d.Message | Should -Match 'most likely'
    }
}

Describe 'Audit 2 L3: results.json does not export every template''s parsed ACL and owner SID' {
    BeforeAll {
        $script:l3inv = [pscustomobject]@{
            TemplatesRead = $true
            Templates = @([pscustomobject]@{
                Name = 'ExampleWebServer'; DisplayName = 'Example Web Server'; SchemaVersion = 2; Eku = @('1.3.6.1.5.5.7.3.1'); NameFlag = [int64]1; EnrollmentFlag = [int64]0
                OwnerSid = 'S-1-5-21-1111-2222-3333-1119'; Owner = ''
                AclError = ''; AclErrorClass = ''
                Acl = @(
                    [pscustomobject]@{ Sid = 'S-1-5-21-1111-2222-3333-513'; Principal = 'Domain Users'; Type = 'Allow'; Mask = 0x130; ObjectType = '0e10c968-78fb-11d2-90d4-00c04f79dc55'; InheritOnly = $false; Rights = @('Enroll') }
                    [pscustomobject]@{ Sid = 'S-1-5-21-1111-2222-3333-4242'; Principal = 'Example Web Admins'; Type = 'Allow'; Mask = 0xF01FF; ObjectType = ''; InheritOnly = $false; Rights = @('FullControl') })
            })
        }
    }
    It 'writes no SID of a named principal, no owner SID and no ACE list; keeps the broad-group rights and the facts the views use' {
        $text = InModuleScope MspkiHealthCheck -Parameters @{ I = $script:l3inv; D = $TestDrive } {
            param($I, $D)
            Set-MspkiOutputFolder -Path $D
            $p = Join-Path $D 'l3-results.json'
            [void](Export-MspkiJson -Path $p -RunInfo ([pscustomobject]@{ Tool = 'test' }) -Inventory $I -Findings @() -ExitCode 0)
            [System.IO.File]::ReadAllText($p)
        }
        $text | Should -Not -Match '1119' -Because 'the owner SID is not exported'
        $text | Should -Not -Match '4242' -Because 'the SID of a named (non-broad) principal is not exported'
        $text | Should -Not -Match 'Example Web Admins'
        $text | Should -Not -Match '"Acl"'
        $text | Should -Match 'ExampleWebServer'
        $text | Should -Match 'BroadAcl'
        $text | Should -Match 'Domain Users'
        $text | Should -Match '"AclRead":\s*true'
    }
    It 'does not change the live inventory (the analysers that run before the export still see the ACL)' {
        $n = InModuleScope MspkiHealthCheck -Parameters @{ I = $script:l3inv; D = $TestDrive } {
            param($I, $D)
            Set-MspkiOutputFolder -Path $D
            [void](Export-MspkiJson -Path (Join-Path $D 'l3b.json') -RunInfo ([pscustomobject]@{ Tool = 'test' }) -Inventory $I -Findings @() -ExitCode 0)
            @($I.Templates[0].Acl).Count
        }
        $n | Should -Be 2
    }
}

Describe 'Audit 2 L9: a finding is linked to a host by its short name only when that name is unambiguous' {
    BeforeAll {
        $script:l9 = {
            param([string[]]$Hosts, [string]$Target)
            InModuleScope MspkiHealthCheck -Parameters @{ Names = $Hosts; T = $Target } {
                param($Names, $T)
                Reset-MspkiEntityGraph
                foreach ($n in $Names) { [void](Add-MspkiHostEntity -HostName $n) }
                $f = [pscustomobject]@{ Id = 'F1'; Category = 'Hierarchy'; Target = $T; Endpoint = ''; RelatedCA = ''; Message = 'm'; EntityIds = @() }
                Add-MspkiFindingEntityLink -Findings @($f)
                [pscustomobject]@{ Ids = @($f.EntityIds); HostIds = @($Names | ForEach-Object { Get-MspkiEntityId -Type 'Host' -Key $_ }) }
            }
        }
    }
    It 'links the short name when exactly one host has that first label' {
        $r = & $script:l9 @('pki.corp.example.test', 'ca01.corp.example.test') 'pki'
        $r.Ids | Should -Contain $r.HostIds[0]
        $r.Ids | Should -Not -Contain $r.HostIds[1]
    }
    It 'links to no host when two hosts share the first label (it is ambiguous), instead of the first one found' {
        $r = & $script:l9 @('pki.a.example.test', 'pki.b.example.test') 'pki'
        $r.Ids | Should -Not -Contain $r.HostIds[0]
        $r.Ids | Should -Not -Contain $r.HostIds[1]
    }
    It 'links the full name exactly, even when the first label is shared' {
        $r = & $script:l9 @('pki.a.example.test', 'pki.b.example.test') 'pki.b.example.test'
        $r.Ids | Should -Contain $r.HostIds[1]
        $r.Ids | Should -Not -Contain $r.HostIds[0]
    }
}

Describe 'Audit 2 L11: every button of the window has an accessible name, and a count tile names its count' {
    It 'every Button in MainWindow.xaml has AutomationProperties.Name' {
        [xml]$x = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'src\Gui\MainWindow.xaml'), [System.Text.Encoding]::UTF8)
        $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
        $ns.AddNamespace('p', 'http://schemas.microsoft.com/winfx/2006/xaml/presentation')
        $missing = @($x.SelectNodes('//p:Button', $ns) | Where-Object { -not $_.GetAttribute('AutomationProperties.Name') } |
            ForEach-Object { $n = $_.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml'); if ($n) { $n } else { 'unnamed: ' + $_.GetAttribute('ToolTip') } })
        $missing.Count | Should -Be 0 -Because ($missing -join '; ')
    }
    It 'the status and severity tiles carry an accessible name that includes the number' {
        $xaml = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Gui\MainWindow.xaml') -Raw
        $xaml | Should -Match 'AutomationProperties\.Name="\{Binding AccessibleName\}"'
        $view = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Gui\GuiView.ps1') -Raw
        $view | Should -Match "AccessibleName = \('\{0\}: \{1\}'"
    }
}

Describe 'Audit 2 L2: the calls that have no timeout of their own are named as a limit of every run' {
    It 'lists the Active Directory calls without a timeout and says that Cancel acts only between calls' {
        $l = InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun -Parameters @{ SkipNetwork = $true }); @($script:MspkiRun.Limits) }
        $m = @($l | Where-Object { $_ -match 'no timeout of their own' })
        $m.Count | Should -Be 1
        $m[0] | Should -Match 'Cancel'
        $m[0] | Should -Match 'SID'
    }
}
