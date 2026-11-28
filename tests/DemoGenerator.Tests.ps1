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
        $code = Get-Content -Raw -LiteralPath (Join-Path $script:DevTools 'SimBoundary.ps1')
        $code | Should -Not -Match '(?i)System\.DirectoryServices|-ComObject|HttpWebRequest|WebRequest\]|TcpClient|SslStream|\[System\.Net\.Dns\]|Get-WinEvent|X509Store|Microsoft\.Win32\.Registry|Get-CimInstance|\.Translate\(|Start-Process|Invoke-WebRequest'
        $code | Should -Match 'Assert-MspkiSimKnown'
    }
}

Describe 'DS1: the baseline world runs end to end through the real engine, and nothing outside the world is answered' {
    BeforeAll {
        $script:GenOut = Join-Path $script:RepoRoot 'out\test-site-data\baseline'
        $gen = Join-Path $script:DevTools 'Invoke-MspkiScenario.ps1'
        $script:Gen = & powershell -NoProfile -File $gen -Scenario baseline -Output $script:GenOut -Commit 'test'
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

    It 'throws for a question the world has no answer for, instead of asking the real network' {
        $out = & powershell -NoProfile -Command ("Import-Module '{0}' -Force; . '{1}'; `$w = Read-MspkiSimWorld -Root '{2}' -Scenario baseline; Enable-MspkiSimulation -World `$w; `$m = Get-Module MspkiHealthCheck; try {{ & `$m {{ Resolve-MspkiDnsName -HostName 'unknown-host.example.test' }} | Out-Null; 'answered' }} catch {{ `$_.Exception.Message }}" -f $script:ModulePath, (Join-Path $script:DevTools 'MspkiSimulation.ps1'), $script:World)
        ($out -join ' ') | Should -Match 'SIMULATION: the simulated world has no answer for the DNS name unknown-host\.example\.test'
    }
}

Describe 'DS2: the world PKI (public material only, verified with the engine''s own code)' {
    It 'holds only public certificates and CRLs, each listed once in pki.json' {
        $files = @(Get-ChildItem -LiteralPath $script:Pki -File)
        @($files | Where-Object { $_.Extension -notin @('.cer', '.crl', '.json') }).Count | Should -Be 0
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
            foreach ($f in $Doc.Files) {
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
        foreach ($f in $script:PkiDoc.Files) {
            $end = [DateTime]::Parse($(if ($f.Kind -eq 'Certificate') { $f.NotAfter } else { $f.NextUpdate }), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
            if ($expiredOk -contains $f.File) { $end | Should -BeLessThan $script:DemoClock -Because $f.File } else { $end | Should -BeGreaterThan $script:DemoClock -Because $f.File }
        }
    }

    It 'creates keys in memory only: the generator never exports, persists or stores a private key' {
        $code = Get-Content -Raw -LiteralPath (Join-Path $script:DevTools 'New-MspkiWorldPki.ps1')
        $code | Should -Not -Match '(?i)ExportParameters\(\s*\$true|ExportPkcs8|ExportRSAPrivateKey|ExportEncrypted|ExportCspBlob|\.Export\(|PersistKeyInCsp|CngKeyCreationParameters|CspParameters|X509Store|CopyWithPrivateKey|\.pfx|\.p12|\.key\b'
        $code | Should -Match 'ExportParameters\(\$false\)'
        @([regex]::Matches($code, 'WriteAll(Bytes|Text)\(\(Join-Path \$Output')).Count | Should -Be 3
        @([regex]::Matches($code, 'WriteAll(Bytes|Text)\(')).Count | Should -Be 3
    }
}
