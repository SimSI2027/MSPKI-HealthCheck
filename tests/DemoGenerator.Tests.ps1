# The demo site's generator (docs/DEMO-SITE.md, ROADMAP DS1-DS3): the world's public PKI material, the simulation boundary and the
# scenarios. The world uses the fictional demo names of docs/DEMO-WORLD.md (read from site\world by path; tests themselves name only
# example.test). Developer-only tools live in tools\dev and are never referenced by the product (Hygiene.Tests.ps1).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:World = Join-Path $script:RepoRoot 'site\world'
    $script:Pki = Join-Path $script:World 'pki'
    $script:DevTools = Join-Path $script:RepoRoot 'tools\dev\demo-site'
    $script:PkiDoc = Get-Content -Raw -LiteralPath (Join-Path $script:Pki 'pki.json') | ConvertFrom-Json
    $script:DemoClock = [DateTime]::Parse($script:PkiDoc.DemoClock, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
}

Describe 'DS1: the simulation boundary covers every I/O call of the engine' {
    BeforeAll {
        $script:Boundary = Import-PowerShellDataFile -LiteralPath (Join-Path $script:DevTools 'Boundary.psd1')
        $script:IoFunctions = @{}
        $rx = '(' + (@($script:Boundary.Patterns) -join ')|(') + ')'
        $quiet = @('Comment', 'StringLiteral', 'StringExpandable', 'HereStringLiteral', 'HereStringExpandable')
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notlike '*\src\Gui\*' }) {
            $tokens = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$null)
            # Comments and string literals are blanked (a message that names a cmdlet is not a call), keeping every other offset.
            $chars = $ast.Extent.Text.ToCharArray()
            foreach ($t in @($tokens | Where-Object { $quiet -contains [string]$_.Kind })) { for ($i = $t.Extent.StartOffset; $i -lt $t.Extent.EndOffset; $i++) { if ($chars[$i] -ne "`n") { $chars[$i] = ' ' } } }
            $code = New-Object string (, $chars)
            foreach ($fn in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                # The function's own body: nested functions (the runspace readers' helpers) are left out.
                $b = $fn.Body.Extent
                $body = $code.Substring($b.StartOffset, $b.EndOffset - $b.StartOffset)
                foreach ($inner in $fn.Body.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                    $body = $body.Replace($code.Substring($inner.Extent.StartOffset, $inner.Extent.EndOffset - $inner.Extent.StartOffset), '')
                }
                $hits = @([regex]::Matches($body, $rx) | ForEach-Object { $_.Value } | Select-Object -Unique)
                if ($hits.Count -gt 0) { $script:IoFunctions[$fn.Name] = '{0}: {1}' -f $f.Name, ($hits -join ', ') }
            }
        }
    }

    It 'lists every engine function that uses an I/O API, the clock or a random id as replaced or exempt (with a reason)' {
        $known = @($script:Boundary.Replaced) + @($script:Boundary.Exempt.Keys)
        $missing = @($script:IoFunctions.Keys | Where-Object { $known -notcontains $_ } | Sort-Object | ForEach-Object { '{0} ({1})' -f $_, $script:IoFunctions[$_] })
        $missing | Should -BeNullOrEmpty
        $script:IoFunctions.Count | Should -BeGreaterThan 30
    }

    It 'names only functions that exist in the engine, each once' {
        $all = @($script:Boundary.Replaced) + @($script:Boundary.Exempt.Keys | Where-Object { $script:Boundary.Exempt[$_] -ne 'Replaced.' })
        @($all | Select-Object -Unique).Count | Should -Be $all.Count
        $defined = @(foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notlike '*\src\Gui\*' }) {
            [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null).FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name } })
        foreach ($n in $all) { $defined | Should -Contain $n -Because $n }
    }

    It 'replaces each listed function in the simulated boundary file, and the simulation answers nothing it was not given' {
        $sim = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:DevTools 'SimBoundary.ps1'), [ref]$null, [ref]$null)
        $defined = @($sim.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Name })
        foreach ($n in @($script:Boundary.Replaced) + @($script:Boundary.Shadowed)) { $defined | Should -Contain $n }
        # Each simulated function accepts every parameter of the engine function it replaces.
        $engine = @{}
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -Filter '*.ps1' -File | Where-Object { $_.FullName -notlike '*\src\Gui\*' }) {
            foreach ($fn in [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null).FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) { $engine[$fn.Name] = $fn }
        }
        $simFns = @{}; foreach ($fn in $sim.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) { $simFns[$fn.Name] = $fn }
        $paramsOf = { param($fn) $pb = $fn.Body.ParamBlock; $(if ($null -ne $pb) { @($pb.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath.ToLowerInvariant() }) } else { @($fn.Parameters | Where-Object { $_ } | ForEach-Object { $_.Name.VariablePath.UserPath.ToLowerInvariant() }) }) }
        foreach ($n in @($script:Boundary.Replaced)) {
            if (-not $engine.ContainsKey($n)) { continue }
            $want = @(& $paramsOf $engine[$n]); $have = @(& $paramsOf $simFns[$n])
            foreach ($p in $want) { $have | Should -Contain $p -Because ('{0} -{1}' -f $n, $p) }
        }
        $code = Get-Content -Raw -LiteralPath (Join-Path $script:DevTools 'SimBoundary.ps1')
        $code | Should -Not -Match '(?i)System\.DirectoryServices|-ComObject|HttpWebRequest|WebRequest\]|TcpClient|SslStream|\[System\.Net\.Dns\]|Get-WinEvent|X509Store|Microsoft\.Win32\.Registry|Get-CimInstance|\.Translate\(|Start-Process|Invoke-WebRequest'
        $code | Should -Match 'Assert-MspkiSimKnown'
    }
}

Describe 'DS1: the baseline world runs end to end through the real engine, and nothing outside the world is answered' {
    BeforeAll {
        # Every scenario, once, for this file (DS1 and DS3 tests); written under out\ only.
        $script:GenRoot = Join-Path $script:RepoRoot 'out\test-site-data'
        if (Test-Path -LiteralPath $script:GenRoot) { Remove-Item -LiteralPath $script:GenRoot -Recurse -Force }
        $gen = Join-Path $script:DevTools 'Invoke-MspkiScenario.ps1'
        $script:GenLog = @(& powershell -NoProfile -File $gen -Scenario all -Output $script:GenRoot -Commit 'test' 2>&1 | ForEach-Object { "$_" })
        $script:GenOut = Join-Path $script:GenRoot 'baseline'
        $script:Doc = Read-MspkiResultsJson -Path (Join-Path $script:GenOut 'results.json')
    }

    It 'writes results, events and a manifest, with findings and no error caused by a gap in the world' {
        foreach ($f in 'results.json', 'events.json', 'manifest.json') { Test-Path -LiteralPath (Join-Path $script:GenOut $f) | Should -BeTrue -Because $f }
        @($script:Doc.Findings).Count | Should -BeGreaterThan 40
        @($script:Doc.Findings | Where-Object { $_.Status -eq 'Error' }) | Should -BeNullOrEmpty
        (Get-Content -Raw -LiteralPath (Join-Path $script:GenOut 'results.json')) | Should -Not -Match 'SIMULATION'
        $m = Get-Content -Raw -LiteralPath (Join-Path $script:GenOut 'manifest.json') | ConvertFrom-Json
        $m.Scenario | Should -Be 'baseline'
        $m.Commit | Should -Be 'test'
        $m.DemoClock | Should -Be '2026-11-20T09:00:00Z'
        $m.Note | Should -Match 'Nothing here touched a real network'
        $ev = Get-Content -Raw -LiteralPath (Join-Path $script:GenOut 'events.json') | ConvertFrom-Json
        @($ev).Count | Should -BeGreaterThan 100
        @($ev | Where-Object { $_.Kind -eq 'Entity' }).Count | Should -BeGreaterThan 10
        @($ev | Where-Object { $_.Kind -eq 'Probe' }).Count | Should -BeGreaterThan 10
        $prev = -1; foreach ($e in $ev) { [int64]$e.T | Should -BeGreaterOrEqual $prev; $prev = [int64]$e.T }
    }

    It 'runs on the demo clock and the world''s computer, not this machine' {
        $script:Doc.RunInfo.StartedUtc | Should -Be '2026-11-20T09:00:00Z'
        $script:Doc.RunInfo.ComputerName | Should -Be 'GROUND-WEB'
        $script:Doc.RunInfo.ComputerName | Should -Not -Be ([Environment]::MachineName)
        $script:Doc.RunInfo.Forest | Should -Be 'alcyone-orbital.example'
    }

    It 'DS3: generates every scenario of the world (results, events, manifest), each with no gap, no Error and only the refusals it expects' {
        $ids = @(Get-ChildItem -LiteralPath (Join-Path $script:World 'scenarios') -Filter '*.json' | ForEach-Object { $_.BaseName })
        $ids.Count | Should -Be 10
        ($script:GenLog -join ' ') | Should -Not -Match 'SIMULATION|unexpected'
        foreach ($id in $ids) {
            foreach ($f in 'results.json', 'events.json', 'manifest.json') { Test-Path -LiteralPath (Join-Path $script:GenRoot "$id\$f") | Should -BeTrue -Because "$id $f" }
            $m = Get-Content -Raw -LiteralPath (Join-Path $script:GenRoot "$id\manifest.json") | ConvertFrom-Json
            $m.Scenario | Should -Be $id
            $m.Title | Should -Not -BeNullOrEmpty
        }
    }

    It 'DS3: each scenario shows what it is meant to teach (docs/DEMO-WORLD.md, Scenarios)' {
        $docs = @{}
        foreach ($d in Get-ChildItem -LiteralPath $script:GenRoot -Directory) { $docs[$d.Name] = Read-MspkiResultsJson -Path (Join-Path $d.FullName 'results.json') }
        $has = { param($id, [scriptblock]$Where) @($docs[$id].Findings | Where-Object $Where).Count -gt 0 }
        & $has 'healthy' { $_.Status -in @('Critical', 'Fail', 'Warning', 'Error') } | Should -BeFalse
        & $has 'baseline' { $_.StatusCode -eq 'CONFIG_RISK' -and $_.Category -eq 'CDP' } | Should -BeTrue
        & $has 'expired-crl' { $_.StatusCode -eq 'OBJECT_EXPIRED' -and $_.Category -eq 'CRL' } | Should -BeTrue
        & $has 'rpc-denied' { $_.StatusCode -eq 'PERMISSION_DENIED' -and $_.Category -eq 'CA' } | Should -BeTrue
        & $has 'rpc-denied' { $_.StatusCode -in @('RPC_FAIL', 'TIMEOUT', 'TCP_FAIL') -and $_.Category -eq 'CA' } | Should -BeFalse
        & $has 'esc8' { $_.Category -eq 'WebEnrollment' -and $_.Message -match 'ESC8' } | Should -BeTrue
        & $has 'forged-aia' { $_.StatusCode -eq 'CONTENT_MISMATCH' -and $_.Category -eq 'AIA' } | Should -BeTrue
        & $has 'ndes-found' { $_.Category -eq 'NDES' -and (@($_.Evidence) -join ' ') -match 'GetCACaps: HTTP 200' } | Should -BeTrue
        & $has 'renewal-drift' { $_.StatusCode -eq 'CONFIG_MISMATCH' -and $_.Category -eq 'ADContainer' } | Should -BeTrue
        & $has 'ldap-only' { $_.Category -eq 'ADDependency' -and $_.StatusCode -eq 'UNSUPPORTED' } | Should -BeTrue
        & $has 'mixed-sample' { $_.StatusCode -eq 'DNS_FAIL' -and $_.Message -match 'legacy-pki' } | Should -BeTrue
        & $has 'mixed-sample' { $_.StatusCode -eq 'PUBLICATION_FAIL' -and $_.Message -match 'pki-dr' } | Should -BeTrue
    }

    It 'DS3: the output names only the demo world (hosts, addresses, e-mail) and nothing of the machine that built it' {
        $hostRx = '(?i)(?<![\w$.\\-])((?:[a-z0-9-]+\.)+(?:com|net|org|local|lan|corp|internal|intra|gov|edu|io|uk|de|nl|ie|eu|fr|ch|be|au|info|biz|cloud|online|tech|test|lab|example))\b(?!\.exa)'
        $allowed = '(?i)^((?:[a-z0-9-]+\.)*(?:alcyone-orbital|flightops|launchpartner)\.example|learn\.microsoft\.com|docs\.microsoft\.com|support\.microsoft\.com|technet\.microsoft\.com|techcommunity\.microsoft\.com|github\.com|(?:[a-z0-9-]+\.)?specterops\.io|www\.w3\.org|system\.(?:[a-z]+\.)*(?:io|net))$'
        $me = @([Environment]::MachineName, [Environment]::UserName) | Where-Object { $_ -and $_.Length -ge 4 }
        foreach ($f in Get-ChildItem -LiteralPath $script:GenRoot -Recurse -File -Filter '*.json') {
            $t = [System.IO.File]::ReadAllText($f.FullName)
            $bad = @([regex]::Matches($t, $hostRx) | ForEach-Object { $_.Groups[1].Value } | Where-Object { $_ -notmatch $allowed } | Select-Object -Unique)
            $bad | Should -BeNullOrEmpty -Because $f.FullName
            $ips = @([regex]::Matches($t, '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])') | ForEach-Object { $_.Value } | Where-Object { $_ -notmatch '^(192\.0\.2\.|0\.0\.0\.0$|127\.0\.0\.1$|2\.5\.29\.|2\.5\.4\.|1\.3\.6\.|10\.0\.\d+\.\d+$)' } | Select-Object -Unique)
            $ips | Should -BeNullOrEmpty -Because $f.FullName
            foreach ($n in $me) { $t | Should -Not -Match ('(?i)\b' + [regex]::Escape($n) + '\b') -Because $f.FullName }
            $t | Should -Not -Match ([regex]::Escape($script:RepoRoot.Replace('\', '\\'))) -Because $f.FullName
        }
    }

    It 'DS3: the same commit and world give byte-identical output' {
        $again = Join-Path $script:RepoRoot 'out\test-site-data-again'
        & powershell -NoProfile -File (Join-Path $script:DevTools 'Invoke-MspkiScenario.ps1') -Scenario 'baseline,mixed-sample' -Output $again -Commit 'test' | Out-Null
        foreach ($id in 'baseline', 'mixed-sample') {
            foreach ($f in 'results.json', 'events.json', 'manifest.json') {
                (Get-FileHash -LiteralPath (Join-Path $again "$id\$f")).Hash | Should -Be (Get-FileHash -LiteralPath (Join-Path $script:GenRoot "$id\$f")).Hash -Because "$id $f"
            }
        }
        Remove-Item -LiteralPath $again -Recurse -Force
    }

    It 'throws for a question the world has no answer for, instead of asking the real network' {
        $out = & powershell -NoProfile -Command ("Import-Module '{0}' -Force; . '{1}'; `$w = Read-MspkiSimWorld -Root '{2}' -Scenario baseline; Enable-MspkiSimulation -World `$w; `$m = Get-Module MspkiHealthCheck; try {{ & `$m {{ Resolve-MspkiDnsName -HostName 'unknown-host.example.test' }} | Out-Null; 'answered' }} catch {{ `$_.Exception.Message }}" -f $script:ModulePath, (Join-Path $script:DevTools 'MspkiSimulation.ps1'), $script:World)
        ($out -join ' ') | Should -Match 'SIMULATION: the simulated world has no answer for the DNS name unknown-host\.example\.test'
    }
}

Describe 'DS2: the world PKI (public material only, verified with the engine''s own code)' {
    It 'holds only public certificates and CRLs, each listed once in pki.json' {
        $files = @(Get-ChildItem -LiteralPath $script:Pki -File)
        @($files | Where-Object { $_.Extension -notin @('.cer', '.crl', '.p7b', '.json') }).Count | Should -Be 0
        @($files | Where-Object { $_.Extension -eq '.json' }).Count | Should -Be 1
        $listed = @($script:PkiDoc.Files | ForEach-Object { $_.File })
        @($listed | Select-Object -Unique).Count | Should -Be $listed.Count
        foreach ($f in @($files | Where-Object { $_.Extension -ne '.json' })) { $listed | Should -Contain $f.Name }
        foreach ($f in @($files | Where-Object { $_.Extension -eq '.cer' })) {
            $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [System.IO.File]::ReadAllBytes($f.FullName))
            $c.HasPrivateKey | Should -BeFalse -Because $f.Name
            $c.Subject | Should -Match '(?i)DC=(alcyone-orbital|flightops), DC=example$|\.(alcyone-orbital)\.example$|alcyone-orbital\.example$|O=Alcyone Orbital Systems' -Because $f.Name
        }
    }

    It 'verifies every certificate and CRL with the key of its issuer (found by key id), and the forged root verifies nothing' {
        $certs = @{}
        foreach ($f in @($script:PkiDoc.Files | Where-Object Kind -eq 'Certificate')) { $certs[$f.File] = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [System.IO.File]::ReadAllBytes((Join-Path $script:Pki $f.File))) }
        $out = InModuleScope MspkiHealthCheck -Parameters @{ Pki = $script:Pki; Doc = $script:PkiDoc; Certs = $certs } {
            param($Pki, $Doc, $Certs)
            $bySki = @{}
            foreach ($k in $Certs.Keys) { $ski = Get-MspkiCertificateSubjectKeyId -Certificate (New-MspkiCertificate -Bytes $Certs[$k].RawData); if (-not $bySki.ContainsKey($ski)) { $bySki[$ski] = $Certs[$k] } }
            $res = @()
            foreach ($f in @($Doc.Files | Where-Object { $_.Kind -ne 'Pkcs7' })) {
                $bytes = [System.IO.File]::ReadAllBytes((Join-Path $Pki $f.File))
                if ($f.Kind -eq 'Certificate') {
                    $aki = Get-MspkiCertificateAuthorityKeyId -Certificate (New-MspkiCertificate -Bytes $bytes)
                    $issuer = $(if ($aki) { $bySki[$aki] } else { $Certs[$f.File] })
                }
                else { $issuer = $bySki[(ConvertFrom-MspkiCrl -Bytes $bytes).AuthorityKeyId] }
                $v = $(if ($null -ne $issuer) { (Test-MspkiSignature -SignedBytes $bytes -Issuer $issuer).Valid } else { $null })
                $res += [pscustomobject]@{ File = $f.File; Valid = $v }
            }
            $forged = $Certs['lodestar-forged.cer']
            $res += [pscustomobject]@{ File = 'issuing CA checked with the forged root'; Valid = (Test-MspkiSignature -SignedBytes $Certs['meridian-g1.cer'].RawData -Issuer $forged).Valid }
            $res
        }
        foreach ($r in @($out | Where-Object { $_.File -notlike '*forged root' })) { $r.Valid | Should -BeTrue -Because $r.File }
        @($out | Where-Object { $_.File -like '*forged root' })[0].Valid | Should -BeFalse
        $certs['lodestar-forged.cer'].Subject | Should -Be $certs['lodestar-root.cer'].Subject
        $certs['lodestar-forged.cer'].GetPublicKeyString() | Should -Not -Be $certs['lodestar-root.cer'].GetPublicKeyString()
    }

    It 'is dated around the demo clock: only the scenario material meant to be expired is expired' {
        $expiredOk = @('meridian-expired.cer', 'meridian-expired-crl.crl', 'meridian-expired-delta.crl')
        foreach ($f in @($script:PkiDoc.Files | Where-Object { $_.Kind -ne 'Pkcs7' })) {
            $end = [DateTime]::Parse($(if ($f.Kind -eq 'Certificate') { $f.NotAfter } else { $f.NextUpdate }), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
            if ($expiredOk -contains $f.File) { $end | Should -BeLessThan $script:DemoClock -Because $f.File } else { $end | Should -BeGreaterThan $script:DemoClock -Because $f.File }
        }
    }

    It 'creates keys in memory only: the generator never exports, persists or stores a private key' {
        $code = Get-Content -Raw -LiteralPath (Join-Path $script:DevTools 'New-MspkiWorldPki.ps1')
        $code | Should -Not -Match '(?i)ExportParameters\(\s*\$true|ExportPkcs8|ExportRSAPrivateKey|ExportEncrypted|ExportCspBlob|\.Export\(|PersistKeyInCsp|CngKeyCreationParameters|CspParameters|X509Store|CopyWithPrivateKey|\.pfx|\.p12|\.key\b'
        $code | Should -Match 'ExportParameters\(\$false\)'
        @([regex]::Matches($code, 'WriteAll(Bytes|Text)\(\(Join-Path \$Output')).Count | Should -Be 4
        @([regex]::Matches($code, 'WriteAll(Bytes|Text)\(')).Count | Should -Be 4
    }
}
