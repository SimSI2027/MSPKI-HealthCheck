BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:demoResults = Join-Path $script:FixturePath 'demo-results.json'
    $script:demoJson = [System.IO.File]::ReadAllText($script:demoResults, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
}

Describe 'Exit codes' {
    BeforeAll {
        $script:mk = {
            param($Status, $Code = 'OK')
            InModuleScope MspkiHealthCheck -Parameters @{ S = $Status; C = $Code } {
                param($S, $C)
                New-MspkiFinding -Category CA -Target 'Example CA' -Status $S -StatusCode $C -Sources @('test') -Message 'x'
            }
        }
    }

    It 'returns <Code> for <Name>' -TestCases @(
        @{ Name = 'no findings'; Code = 0; Set = @() }
        @{ Name = 'Pass and an OK inventory fact'; Code = 0; Set = @(@('Pass', 'OK'), @('Information', 'OK'), @('NotApplicable', 'NOT_APPLICABLE')) }
        @{ Name = 'information that is not an inventory fact'; Code = 2; Set = @(@('Information', 'HTTP_REDIRECT'), @('Pass', 'OK')) }
        @{ Name = 'a warning'; Code = 3; Set = @(@('Warning', 'OBJECT_EXPIRING'), @('Information', 'HTTP_REDIRECT'), @('Pass', 'OK')) }
        @{ Name = 'a failure'; Code = 4; Set = @(@('Fail', 'DNS_FAIL'), @('Warning', 'OBJECT_EXPIRING')) }
        @{ Name = 'a critical finding'; Code = 4; Set = @(, @('Critical', 'OBJECT_EXPIRING')) }
        @{ Name = 'an unsupported check'; Code = 5; Set = @(@('Skipped', 'UNSUPPORTED'), @('Warning', 'OBJECT_EXPIRING')) }
        @{ Name = 'an errored check'; Code = 5; Set = @(@('Error', 'RETRIEVAL_FAIL'), @('Warning', 'OBJECT_EXPIRING')) }
        @{ Name = 'a permission problem'; Code = 6; Set = @(@('Skipped', 'PERMISSION_DENIED'), @('Warning', 'OBJECT_EXPIRING')) }
        @{ Name = 'a failure together with a permission problem'; Code = 4; Set = @(@('Skipped', 'PERMISSION_DENIED'), @('Fail', 'DNS_FAIL')) }
        @{ Name = 'a permission problem together with an error'; Code = 6; Set = @(@('Skipped', 'PERMISSION_DENIED'), @('Error', 'RETRIEVAL_FAIL')) }
    ) {
        param($Name, $Code, $Set)
        $f = @($Set | ForEach-Object { & $script:mk $_[0] $_[1] })
        InModuleScope MspkiHealthCheck -Parameters @{ F = $f; C = $Code } {
            param($F, $C)
            Get-MspkiExitCode -Findings $F | Should -Be $C
        }
    }

    It 'makes an interrupted run at least 5, unless a failure (4) or a permission problem (6) decides' {
        $ok = & $script:mk 'Pass' 'OK'
        $warn = & $script:mk 'Warning' 'OBJECT_EXPIRING'
        $fail = & $script:mk 'Fail' 'DNS_FAIL'
        $perm = & $script:mk 'Skipped' 'PERMISSION_DENIED'
        InModuleScope MspkiHealthCheck -Parameters @{ Ok = $ok; Warn = $warn; Fail = $fail; Perm = $perm } {
            param($Ok, $Warn, $Fail, $Perm)
            Get-MspkiExitCode -Findings @($Ok) -Incomplete | Should -Be 5
            Get-MspkiExitCode -Findings @() -Incomplete | Should -Be 5
            Get-MspkiExitCode -Findings @($Warn) -Incomplete | Should -Be 5
            Get-MspkiExitCode -Findings @($Fail) -Incomplete | Should -Be 4
            Get-MspkiExitCode -Findings @($Perm) -Incomplete | Should -Be 6
        }
    }

    It 'explains every exit code and names the findings that decide it' {
        $fail = & $script:mk 'Fail' 'DNS_FAIL'
        InModuleScope MspkiHealthCheck -Parameters @{ Fail = $fail } {
            param($Fail)
            $names = @{ 0 = 'Passed'; 2 = 'Informational'; 3 = 'Warnings'; 4 = 'Failures'; 5 = 'Incomplete (unsupported or error)'; 6 = 'Incomplete (permissions)' }
            foreach ($c in @(0, 2, 3, 4, 5, 6)) {
                $i = Get-MspkiExitCodeInfo -Code $c -Findings @($Fail)
                $i.Name | Should -Be $names[$c]
                $i.Meaning | Should -Not -BeNullOrEmpty
            }
            $i4 = Get-MspkiExitCodeInfo -Code 4 -Findings @($Fail)
            $i4.DriverCount | Should -Be 1
            @($i4.DriverIds) | Should -Be @($Fail.Id)
            (Get-MspkiExitCodeInfo -Code 5 -Findings @() -Completed $false).Note | Should -Match 'did not finish'
            (Get-MspkiExitCodeInfo -Code 7 -Findings @()).Name | Should -Be 'Unknown'
        }
    }

    Context 'Start-MspkiHealthCheck end to end with a mocked discovery' {
        BeforeEach {
            Mock -ModuleName MspkiHealthCheck Invoke-MspkiDiscovery {
                $fs = @($script:mockSet | ForEach-Object {
                    New-MspkiFinding -Category CA -Target 'Example CA' -Status $_[0] -StatusCode $_[1] -Sources @('test') -Message 'mocked' -Confidence Referenced
                })
                [pscustomobject]@{
                    Findings = $fs; Certificates = @{}
                    Inventory = [pscustomobject]@{ AdContext = [pscustomobject]@{ ForestDomains = @('corp.example.test'); TrustedDomains = @(); DomainController = ''; Forest = 'corp.example.test' }
                        EnterpriseCAs = @(); CACertificates = @(); Containers = @() }
                }
            }
        }

        It 'exits with <Code> and writes results.json, findings.csv and report.html (<Name>)' -TestCases @(
            @{ Name = 'passed'; Code = 0; Set = @(, @('Pass', 'OK')) }
            @{ Name = 'informational'; Code = 2; Set = @(, @('Information', 'HTTP_REDIRECT')) }
            @{ Name = 'warnings'; Code = 3; Set = @(, @('Warning', 'OBJECT_EXPIRING')) }
            @{ Name = 'failures'; Code = 4; Set = @(, @('Fail', 'DNS_FAIL')) }
            @{ Name = 'unsupported'; Code = 5; Set = @(, @('Skipped', 'UNSUPPORTED')) }
            @{ Name = 'permissions'; Code = 6; Set = @(, @('Skipped', 'PERMISSION_DENIED')) }
        ) {
            param($Name, $Code, $Set)
            $script:mockSet = $Set
            $out = Join-Path $TestDrive ('run-' + $Name)
            $r = Start-MspkiHealthCheck -OutputPath $out -TimeoutSeconds 1 -SkipNetwork
            $r.ExitCode | Should -Be $Code
            $j = Get-Content -LiteralPath $r.ResultsPath -Raw | ConvertFrom-Json
            $j.ExitCode | Should -Be $Code
            Test-Path -LiteralPath $r.CsvPath | Should -BeTrue
            Test-Path -LiteralPath $r.ReportPath | Should -BeTrue
            $html = [System.IO.File]::ReadAllText($r.ReportPath)
            $html | Should -Match ('<div class="code">{0}</div>' -f $Code)
        }

        It 'records a reporter failure as a finding, still writes results.json and recomputes the exit code' {
            $script:mockSet = @(, @('Pass', 'OK'))
            Mock -ModuleName MspkiHealthCheck Export-MspkiHtml { throw 'simulated report failure' }
            $out = Join-Path $TestDrive 'run-reportfail'
            $r = Start-MspkiHealthCheck -OutputPath $out -TimeoutSeconds 1 -SkipNetwork
            $r.ExitCode | Should -Be 5
            Test-Path -LiteralPath $r.ResultsPath | Should -BeTrue
            Test-Path -LiteralPath $r.CsvPath | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $r.OutputFolder 'report.html') | Should -BeFalse
            $j = Get-Content -LiteralPath $r.ResultsPath -Raw | ConvertFrom-Json
            $j.ExitCode | Should -Be 5
            @($j.Findings | Where-Object { $_.Stage -eq 'Report' -and $_.Status -eq 'Error' }).Count | Should -Be 1
        }
    }
}

Describe 'findings.csv' {
    It 'writes a UTF-8 BOM, CRLF rows, quotes every field and round-trips through Import-Csv' {
        $dir = Join-Path $TestDrive 'csv'
        $null = New-Item -ItemType Directory -Path $dir
        InModuleScope MspkiHealthCheck -Parameters @{ Dir = $dir } {
            param($Dir)
            Set-MspkiOutputFolder -Path $Dir
            $f = New-MspkiFinding -Category CRL -Target 'CN=Example CA, DC=example, DC=test' -Status Warning -StatusCode STALE_DATA -Sources @('Cert:AA:CDP', 'CA:x:GetCAProperty') `
                -Confidence Confirmed -Message "line one`r`nline two, with ""quotes""" -Evidence @('first', 'second; with semicolon') -Endpoint 'http://pki.corp.example.test/a.crl' -Layers @{ HttpStatus = 'Pass' }
            $p = Join-Path $Dir 'findings.csv'
            Export-MspkiCsv -Path $p -Findings @($f, $f) | Out-Null
            $bytes = [System.IO.File]::ReadAllBytes($p)
            ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeTrue
            $text = [System.IO.File]::ReadAllText($p, [System.Text.Encoding]::UTF8)
            ($text -split "`r`n" | Where-Object { $_ }).Count | Should -Be 3
            $rows = @(Import-Csv -LiteralPath $p -Encoding UTF8)
            $rows.Count | Should -Be 2
            $rows[0].Id | Should -Be $f.Id
            $rows[0].Status | Should -Be 'Warning'
            $rows[0].StatusCode | Should -Be 'STALE_DATA'
            $rows[0].Confidence | Should -Be 'Confirmed'
            $rows[0].Sources | Should -Be 'Cert:AA:CDP | CA:x:GetCAProperty'
            $rows[0].Evidence | Should -Be 'first | second; with semicolon'
            $rows[0].Message | Should -Be 'line one line two, with "quotes"'
            $rows[0].HttpStatus | Should -Be 'Pass'
            $rows[0].DnsStatus | Should -Be 'NotTested'
            @($rows[0].psobject.Properties.Name) | Should -Contain 'RelatedCA'
        }
    }

    It 'neutralises spreadsheet formulas that come from the environment' {
        InModuleScope MspkiHealthCheck {
            ConvertTo-MspkiCsvField '=HYPERLINK("http://x","y")' | Should -Be '"''=HYPERLINK(""http://x"",""y"")"'
            ConvertTo-MspkiCsvField '+1+1' | Should -Be '"''+1+1"'
            ConvertTo-MspkiCsvField '-2' | Should -Be '"''-2"'
            ConvertTo-MspkiCsvField '@SUM(A1)' | Should -Be '"''@SUM(A1)"'
            ConvertTo-MspkiCsvField 'plain' | Should -Be '"plain"'
            ConvertTo-MspkiCsvField $null | Should -Be '""'
        }
    }

    It 'refuses to write outside the run output folder' {
        $dir = Join-Path $TestDrive 'csvguard'
        $null = New-Item -ItemType Directory -Path $dir
        InModuleScope MspkiHealthCheck -Parameters @{ Dir = $dir; Outside = (Join-Path $TestDrive 'elsewhere.csv') } {
            param($Dir, $Outside)
            Set-MspkiOutputFolder -Path $Dir
            { Export-MspkiCsv -Path $Outside -Findings @() } | Should -Throw '*outside the run output folder*'
        }
    }
}

Describe 'report.html from the example.test demo data' {
    BeforeAll {
        $script:demoOut = Join-Path $TestDrive 'demo'
        $script:demo = Export-MspkiReportFromResults -ResultsPath $script:demoResults -OutputFolder $script:demoOut
        $script:html = [System.IO.File]::ReadAllText($script:demo.HtmlPath, [System.Text.Encoding]::UTF8)
    }

    It 'writes report.html and findings.csv only into the chosen folder' {
        $script:demo.HtmlPath | Should -Be (Join-Path ([System.IO.Path]::GetFullPath($script:demoOut)) 'report.html')
        @(Get-ChildItem -LiteralPath $script:demoOut -File | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('findings.csv', 'report.html')
        $script:demo.Findings | Should -Be 30
        $script:demo.ExitCode | Should -Be 4
    }

    It 'is a single offline file: no external script, style, font, image or link' {
        $script:html | Should -Not -Match '(?i)<link\b'
        $script:html | Should -Not -Match '(?i)<script[^>]*\ssrc\s*='
        $script:html | Should -Not -Match '(?i)@import'
        $script:html | Should -Not -Match '(?i)\burl\s*\('
        $script:html | Should -Not -Match '(?i)@font-face'
        $script:html | Should -Not -Match '(?i)\b(src|href|action)\s*=\s*["'']?\s*(https?:)?//'
        $script:html | Should -Not -Match '(?i)<(img|iframe|object|embed|form)\b'
        $script:html | Should -Match "Content-Security-Policy"
        $script:html | Should -Match "default-src 'none'"
        # exactly one inline style block and one inline script block
        ([regex]::Matches($script:html, '<style>')).Count | Should -Be 1
        ([regex]::Matches($script:html, '<script>')).Count | Should -Be 1
    }

    It 'has the sections: summary, discovery map, findings with filters, evidence and run details' {
        foreach ($id in @('summary', 'map', 'findings', 'run')) { $script:html | Should -Match ('<section id="{0}">' -f $id) }
        foreach ($id in @('fsearch', 'fcat', 'fconf', 'fscope', 'fcode', 'freset', 'fexpand')) { $script:html | Should -Match ('id="{0}"' -f $id) }
        $script:html | Should -Match 'data-status="Warning"'
        $script:html | Should -Match 'data-confidence="Confirmed"'
        $script:html | Should -Match '<h4>Evidence</h4>'
        $script:html | Should -Match '<h4>Sources</h4>'
        $script:html | Should -Match 'Discovery methods and outcome'
        $script:html | Should -Match 'Known limits of this tool'
    }

    It 'lists every finding once, with its source and confidence' {
        $ids = @($script:demoJson.Findings | ForEach-Object { $_.Id })
        ([regex]::Matches($script:html, '<details class="f"')).Count | Should -Be $ids.Count
        foreach ($id in $ids) { ([regex]::Matches($script:html, ('id="{0}"' -f $id))).Count | Should -Be 1 }
        $script:html | Should -Match 'Cert:4D5E6F708192A3B4C5D6E7F80910111213141516:CDP'
    }

    It 'shows the exit code with its meaning and the deciding finding' {
        $script:html | Should -Match '<div class="card exit exit-4"><div class="code">4</div><div><b>Failures</b>'
        $script:html | Should -Match 'Decided by 1 finding'
    }

    It 'contains only example.test data' {
        $names = [regex]::Matches($script:html, '(?i)\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(test|com|net|org|local|lan)\b') | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique
        foreach ($n in $names) { $n | Should -Match 'example\.test$' }
    }
}

Describe 'report.html safety and edge cases' {
    It 'HTML-encodes everything that comes from the environment' {
        InModuleScope MspkiHealthCheck {
            $evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
            $f = New-MspkiFinding -Category CDP -Target $evil -Endpoint ('http://x.example.test/?a=' + $evil) -Status Warning -StatusCode STALE_DATA `
                -Sources @($evil) -Message $evil -Evidence @($evil) -Remediation $evil -Notes $evil -RelatedCA $evil -Confidence Referenced
            $run = [pscustomobject]@{ Tool = $evil; ToolVersion = '1'; StartedUtc = '2026-01-01T00:00:00Z'; Completed = $true; Forest = $evil; Domain = $evil
                Parameters = [ordered]@{ $evil = $evil }; Methods = @([pscustomobject]@{ Method = $evil; Outcome = $evil; Detail = $evil; ElapsedMs = 1 })
                StageTimings = @(); Limits = @($evil) }
            $html = Get-MspkiReportHtml -RunInfo $run -Inventory $null -Findings @($f) -ExitCode 3
            $html | Should -Not -Match '<script>alert'
            $html | Should -Not -Match '<img src=x'
            $html | Should -Not -Match 'onerror=alert\(2\)>'
            $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
            ([regex]::Matches($html, '<script>')).Count | Should -Be 1
        }
    }

    It 'renders an empty run (nothing discovered) without errors' {
        InModuleScope MspkiHealthCheck {
            $run = [pscustomobject]@{ Tool = 'MSPKI Health Check'; ToolVersion = '0.1.0'; StartedUtc = '2026-01-01T00:00:00Z'; Completed = $false; Parameters = [ordered]@{}
                Methods = @(); StageTimings = @(); Limits = @() }
            $html = Get-MspkiReportHtml -RunInfo $run -Inventory $null -Findings @() -ExitCode 5
            $html | Should -Match 'This run did not finish'
            $html | Should -Match 'No warnings, failures or errors were found'
            $html | Should -Match 'forest not discovered'
            $html | Should -Match 'Showing|fcount'
        }
    }

    It 'shows limits that were reached (depth, cap) under Run details' {
        InModuleScope MspkiHealthCheck {
            $run = [pscustomobject]@{ Tool = 't'; ToolVersion = '1'; StartedUtc = '2026-01-01T00:00:00Z'; Completed = $true; Parameters = [ordered]@{}
                Methods = @(); StageTimings = @(); Limits = @('Lead cap of 1000 reached: some URLs were not probed.', 'Link depth limit of 5 reached: some links found in downloaded certificates or CRLs were not followed.') }
            $html = Get-MspkiReportHtml -RunInfo $run -Inventory $null -Findings @() -ExitCode 0
            $html | Should -Match 'Lead cap of 1000 reached'
            $html | Should -Match 'Link depth limit of 5 reached'
        }
    }
}

Describe 'Discovery Map tree' {
    BeforeAll {
        $script:tree = InModuleScope MspkiHealthCheck -Parameters @{ J = $script:demoJson } {
            param($J)
            Get-MspkiDiscoveryTree -Inventory $J.Inventory -Findings @($J.Findings) -RunInfo $J.RunInfo
        }
        $script:flat = InModuleScope MspkiHealthCheck -Parameters @{ T = $script:tree } {
            param($T)
            $out = New-Object System.Collections.ArrayList
            $walk = { param($n, $path) $p = @($path) + $n.Label; [void]$out.Add([pscustomobject]@{ Node = $n; Path = ($p -join ' > ') }); foreach ($c in $n.Children) { & $walk $c $p } }
            & $walk $T @()
            , $out.ToArray()
        }
    }

    It 'is organised forest > CAs > certificates > endpoints, with templates and CES under the CA' {
        $script:tree.Type | Should -Be 'Forest'
        $script:tree.Label | Should -Be 'Forest corp.example.test'
        $ca = @($script:tree.Children | Where-Object { $_.Label -eq 'Example Issuing CA 01' })
        $ca.Count | Should -Be 1
        @($ca[0].Children | Where-Object { $_.Type -eq 'Certificate' }).Count | Should -Be 2
        $current = @($ca[0].Children | Where-Object { $_.Label -like 'CA certificate V1.0*' })[0]
        $current.Confidence | Should -Be 'Confirmed'
        @($current.Children | Where-Object { $_.Type -eq 'Endpoint' }).Count | Should -BeGreaterThan 3
        @($ca[0].Children | Where-Object { $_.Label -like 'Published certificate templates*' }).Count | Should -Be 1
        @($ca[0].Children | Where-Object { $_.Label -like 'Certificate Enrollment Web Services*' }).Count | Should -Be 1
        ($script:flat | Where-Object { $_.Path -like '*Example Root CA*' }).Count | Should -BeGreaterThan 0
    }

    It 'puts a link under the endpoint finding that belongs to it and rolls the worst status up' {
        $n = @($script:flat | Where-Object { $_.Node.Label -like 'CDP: http://pki2.corp.example.test/*' })[0].Node
        $n.Status | Should -Be 'Warning'
        @($n.FindingIds) | Should -Contain 'F0022'
        $script:tree.WorstBelow | Should -Be 'Fail'
        $ca = @($script:tree.Children | Where-Object { $_.Label -eq 'Example Issuing CA 01' })[0]
        $ca.WorstBelow | Should -Be 'Fail'
    }

    It 'places every finding in the map exactly once' {
        $ids = @($script:flat | ForEach-Object { $_.Node.FindingIds } | ForEach-Object { $_ })
        @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        foreach ($f in $script:demoJson.Findings) { $ids | Should -Contain $f.Id }
    }

    It 'gives every node its sources' {
        foreach ($x in @($script:flat | Where-Object { $_.Node.Type -in @('Certificate', 'Endpoint', 'CA') })) {
            @($x.Node.Sources).Count | Should -BeGreaterThan 0 -Because $x.Path
        }
    }
}

Describe 'Discovery Map: Phase D review results' {
    It 'groups template, CEP/CES, NDES, Intune connector and stale-reference findings, each exactly once' {
        $r = InModuleScope MspkiHealthCheck {
            Reset-MspkiFindingSequence
            $f = @(
                (New-MspkiFinding -Category Template -Target 'ExampleUser' -Status Fail -StatusCode CONFIG_RISK -Severity High -Sources 'AD:CertificateTemplates' -Message 'm1')
                (New-MspkiFinding -Category CES -Target 'ces.corp.example.test' -Status Pass -StatusCode OK -Sources 'AD:EnrollmentServices:msPKI-Enrollment-Servers' -Message 'm2')
                (New-MspkiFinding -Category NDES -Target 'ndes.corp.example.test' -Status Information -StatusCode NOT_DISCOVERED -Sources 'CA:CertificateAuthority.View' -Message 'm3')
                (New-MspkiFinding -Category IntuneConnector -Target 'EXAMPLEHOST01' -Status NotApplicable -StatusCode NOT_DISCOVERED -Sources 'Local:Win32_Service' -Message 'm4')
                (New-MspkiFinding -Category StaleRef -Target 'References' -Status Information -StatusCode OK -Sources 'Probe results' -Message 'm5'))
            $tree = Get-MspkiDiscoveryTree -Inventory $null -Findings $f -RunInfo $null
            $labels = @($tree.Children | ForEach-Object { $_.Label })
            $ids = @(); $walk = { param($n) $script:__ids += @($n.FindingIds); foreach ($c in $n.Children) { & $walk $c } }
            $script:__ids = @(); & $walk $tree
            [pscustomobject]@{ Labels = $labels; Ids = @($script:__ids) } }
        ($r.Labels -join '|') | Should -Match 'Certificate template review \(1\)'
        ($r.Labels -join '|') | Should -Match 'Enrollment policy and web services \(CEP/CES\) \(1\)'
        ($r.Labels -join '|') | Should -Match 'NDES / SCEP \(1\)'
        ($r.Labels -join '|') | Should -Match 'Intune Certificate Connector \(this computer only\) \(1\)'
        ($r.Labels -join '|') | Should -Match 'Historical and stale reference review \(1\)'
        @($r.Ids | Select-Object -Unique).Count | Should -Be 5
        @($r.Ids).Count | Should -Be 5
    }
}
