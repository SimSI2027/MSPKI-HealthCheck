# Tests for the GUI: the engine's cancel flag and progress queue, the pure GUI helpers (rows, filters, tree, summary,
# details) and, in a single-threaded runspace, that the XAML loads and the window shows the example.test fixture.
# No real environment data: everything uses tests\fixtures\demo-results.json (example.test only).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:GuiFolder = Join-Path $script:RepoRoot 'src\Gui'
    . (Join-Path $script:GuiFolder 'GuiModel.ps1')
    . (Join-Path $script:GuiFolder 'GuiView.ps1')
    . (Join-Path $script:GuiFolder 'GuiEntity.ps1')
    $script:DemoResults = Join-Path $script:FixturePath 'demo-results.json'

    function Invoke-InStaRunspace {
        # Runs a script in a new single-threaded runspace (WPF needs one) and returns its output; errors are thrown.
        param([string]$Script, [object[]]$Arguments = @())
        $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $rs.ApartmentState = [System.Threading.ApartmentState]::STA
        $rs.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
        $rs.Open()
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.Runspace = $rs
        [void]$ps.AddScript($Script)
        foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
        try {
            $out = @($ps.Invoke())
            if ($ps.Streams.Error.Count -gt 0) { throw ($ps.Streams.Error | ForEach-Object { $_.ToString() }) -join '; ' }
            return $out
        }
        finally { $ps.Dispose(); $rs.Dispose() }
    }
}

Describe 'Run control (cancel flag and progress queue)' {
    It 'does nothing without a control object' {
        InModuleScope MspkiHealthCheck {
            Set-MspkiRunControl -Control $null
            Test-MspkiCancelled | Should -BeFalse
            { Assert-MspkiNotCancelled } | Should -Not -Throw
            { Send-MspkiProgress -Kind Target -Text 'x' } | Should -Not -Throw
        }
    }

    It 'queues messages and honours the cancel flag' {
        InModuleScope MspkiHealthCheck {
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try {
                Send-MspkiProgress -Kind Target -Text 'DNS host.example.test'
                Write-MspkiLog -Level Warning -Message 'a warning'
                $items = @()
                $i = $null
                while ($c.Queue.TryDequeue([ref]$i)) { $items += $i }
                @($items | Where-Object { $_.Kind -eq 'Target' -and $_.Text -eq 'DNS host.example.test' }).Count | Should -Be 1
                $log = @($items | Where-Object { $_.Kind -eq 'Log' })
                $log.Count | Should -Be 1
                $log[0].Level | Should -Be 'Warning'
                Test-MspkiCancelled | Should -BeFalse
                $c.Cancel = $true
                Test-MspkiCancelled | Should -BeTrue
                { Assert-MspkiNotCancelled } | Should -Throw '*cancelled*'
            }
            finally { Set-MspkiRunControl -Control $null }
        }
    }

    It 'stops a probe and a stage start once cancelled, without contacting anything' {
        InModuleScope MspkiHealthCheck {
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try {
                $sw = Start-MspkiStageTimer -Stage 'Discovery:ADContext'
                $i = $null; $kinds = @()
                while ($c.Queue.TryDequeue([ref]$i)) { $kinds += $i.Kind }
                $kinds | Should -Contain 'StageStart'
                Add-MspkiStageTiming -Stage 'Discovery:ADContext' -Stopwatch $sw
                $c.Cancel = $true
                { Start-MspkiStageTimer -Stage 'Analysis:Templates' } | Should -Throw
                { Resolve-MspkiDnsName -HostName 'never.example.test' } | Should -Throw
                { Test-MspkiTcpPort -HostName 'never.example.test' -Port 443 } | Should -Throw
                { Invoke-MspkiHttpGet -Url 'http://never.example.test/x' } | Should -Throw
                { Test-MspkiTlsEndpoint -HostName 'never.example.test' } | Should -Throw
            }
            finally { Set-MspkiRunControl -Control $null }
        }
    }

    It 'classifies a cancellation on its own, not as an error or a timeout' {
        InModuleScope MspkiHealthCheck {
            $e = New-Object System.OperationCanceledException('stop')
            (Get-MspkiErrorInfo $e).Class | Should -Be 'Cancelled'
            $f = New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $e) -Category 'Run' -Target 'x' -Sources 'Run' -Action 'testing'
            $f.Status | Should -Be 'Skipped'
            $f.Message | Should -BeLike '*cancelled*'
        }
    }

    It 'a DNS/TCP/TLS wait ends within a fraction of a second of the cancel request, not after the probe timeout' {
        InModuleScope MspkiHealthCheck {
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            $never = New-Object System.Threading.ManualResetEvent($false)
            $fake = [pscustomobject]@{ AsyncWaitHandle = $never; IsCompleted = $false }
            try {
                # Not cancelled: a short wait times out and reports "not finished".
                (Wait-MspkiAsyncResult -AsyncResult $fake -TimeoutMs 300) | Should -BeFalse
                $c.Cancel = $true
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                { Wait-MspkiAsyncResult -AsyncResult $fake -TimeoutMs 30000 } | Should -Throw
                $sw.Elapsed.TotalSeconds | Should -BeLessThan 2
            }
            finally { Set-MspkiRunControl -Control $null; $never.Dispose() }
        }
    }

    It 'ends a long time-limited call within a second of the cancel request' {
        InModuleScope MspkiHealthCheck {
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            $t = New-Object System.Timers.Timer 600
            $t.AutoReset = $false
            $null = Register-ObjectEvent -InputObject $t -EventName Elapsed -MessageData $c -Action { $Event.MessageData.Cancel = $true }
            $t.Start()
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                { Invoke-MspkiTimeLimitedScript -ScriptBlock { Start-Sleep -Seconds 20 } -TimeoutSeconds 30 } | Should -Throw
                $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
            }
            finally { Set-MspkiRunControl -Control $null; $t.Dispose(); Get-EventSubscriber | Unregister-Event -ErrorAction SilentlyContinue }
        }
    }

    It 'a run that is cancelled before it starts still writes partial results and says so' {
        $out = Join-Path $TestDrive 'cancelled-run'
        InModuleScope MspkiHealthCheck -Parameters @{ Out = $out } {
            param($Out)
            $c = New-MspkiRunControl
            $c.Cancel = $true
            $r = Start-MspkiHealthCheck -OutputPath $Out -Control $c -SkipNetwork
            $r.RunInfo.Completed | Should -BeFalse
            $r.ExitCode | Should -Be 5
            @($r.Findings | Where-Object { $_.Message -like '*cancelled*' }).Count | Should -BeGreaterThan 0
            Test-Path -LiteralPath $r.ResultsPath | Should -BeTrue
            Test-Path -LiteralPath $r.ReportPath | Should -BeTrue
            Test-MspkiCancelled | Should -BeFalse
            $j = Read-MspkiResultsJson -Path $r.ResultsPath
            $j.RunInfo.Completed | Should -BeFalse
        }
    }
}

Describe 'GUI model helpers' {
    BeforeAll {
        $script:data = Read-MspkiGuiResults -Path $script:DemoResults
        $script:rows = ConvertTo-MspkiGuiRowList -Findings $script:data.Findings
    }

    It 'reads results.json into the same shape as a live run' {
        $script:data.Findings.Count | Should -Be 30
        $script:data.ExitCode | Should -Not -BeNullOrEmpty
        $script:data.OutputFolder | Should -Be (Split-Path -Parent $script:DemoResults)
        $script:data.ReportPath | Should -Be ''
    }

    It 'says what is wrong with a bad file' {
        { Read-MspkiGuiResults -Path (Join-Path $TestDrive 'missing.json') } | Should -Throw '*not found*'
        $bad = Join-Path $TestDrive 'bad.json'
        [System.IO.File]::WriteAllText($bad, '{ not json')
        { Read-MspkiGuiResults -Path $bad } | Should -Throw '*not valid JSON*'
        $other = Join-Path $TestDrive 'other.json'
        [System.IO.File]::WriteAllText($other, '{"Schema":"something-else/1"}')
        { Read-MspkiGuiResults -Path $other } | Should -Throw '*not a results.json*'
    }

    It 'builds one flat row per finding with the grid columns' {
        $script:rows.Count | Should -Be 30
        $r = $script:rows[0]
        foreach ($p in @('Status', 'Severity', 'Category', 'Target', 'Endpoint', 'Confidence', 'Source', 'Message', 'StatusRank', 'Finding')) {
            $r.psobject.Properties.Name | Should -Contain $p
        }
        $r.Message | Should -Not -Match '[\r\n]'
        (Get-MspkiGuiRank -Kind Status -Value 'Critical') | Should -BeGreaterThan (Get-MspkiGuiRank -Kind Status -Value 'Fail')
        (Get-MspkiGuiRank -Kind Status -Value 'Fail') | Should -BeGreaterThan (Get-MspkiGuiRank -Kind Status -Value 'Warning')
        (Get-MspkiGuiRank -Kind Status -Value 'nonsense') | Should -Be -1
    }

    It 'filters by status, category, confidence and free text (every word must match)' {
        $all = $script:rows.ToArray()
        (Get-MspkiGuiFilteredRow -Rows $all).Count | Should -Be 30
        (Get-MspkiGuiFilteredRow -Rows $all -Status 'All' -Category 'All' -Confidence 'All').Count | Should -Be 30
        $warn = @(Get-MspkiGuiFilteredRow -Rows $all -Status 'Warning')
        $warn.Count | Should -Be 6
        @($warn | Where-Object { $_.Status -ne 'Warning' }).Count | Should -Be 0
        $cat = $all[0].Category
        @(Get-MspkiGuiFilteredRow -Rows $all -Category $cat | Where-Object { $_.Category -ne $cat }).Count | Should -Be 0
        $word = ($all[0].Target -split '\s+')[0]
        $hits = @(Get-MspkiGuiFilteredRow -Rows $all -Text $word.ToUpperInvariant())
        $hits.Count | Should -BeGreaterThan 0
        @(Get-MspkiGuiFilteredRow -Rows $all -Text 'zzzz-no-such-word').Count | Should -Be 0
        # Two words narrow the result; an unmatched second word empties it.
        @(Get-MspkiGuiFilteredRow -Rows $all -Text ('{0} zzzz-no-such-word' -f $word)).Count | Should -Be 0
        # Filters combine.
        @(Get-MspkiGuiFilteredRow -Rows $all -Status 'Warning' -Text 'zzzz-no-such-word').Count | Should -Be 0
    }

    It 'offers "(all)" and only the values present, statuses in severity order' {
        $s = @(Get-MspkiGuiFilterChoice -Rows $script:rows -Field Status)
        $s[0] | Should -Be 'All'
        $s | Should -Contain 'Fail'
        $s | Should -Not -Contain 'Critical'
        $s.IndexOf('Fail') | Should -BeLessThan $s.IndexOf('Pass')
        $cats = @(Get-MspkiGuiFilterChoice -Rows $script:rows -Field Category)
        $cats[0] | Should -Be 'All'
        @($cats[1..($cats.Count - 1)]) | Should -Be @(@($cats[1..($cats.Count - 1)]) | Sort-Object)
    }

    It 'builds the summary: facts, a tile per status that adds up, and the CAs' {
        $s = Get-MspkiGuiSummary -RunInfo $script:data.RunInfo -Inventory $script:data.Inventory -Findings $script:data.Findings -ExitCode $script:data.ExitCode
        $s.Forest | Should -Be 'corp.example.test'
        $s.User | Should -Be 'CORP\demo.user'
        $s.IsAdmin | Should -BeLike 'No*'
        $s.Total | Should -Be 30
        $s.Tiles.Count | Should -Be 9
        (($s.Tiles | Measure-Object -Property Count -Sum).Sum) | Should -Be 30
        @($s.Tiles | Where-Object { $_.Status -eq 'Fail' })[0].Count | Should -Be 1
        $s.CAs.Count | Should -Be 2
        $s.CAs[0].Name | Should -Not -BeNullOrEmpty
        $s.ExitCode | Should -Match '^\d'
    }

    It 'builds the Discovery Map as plain tree items with confidence and status' {
        $tree = Get-MspkiDiscoveryTree -Inventory $script:data.Inventory -Findings $script:data.Findings -RunInfo $script:data.RunInfo
        $vm = ConvertTo-MspkiGuiTreeNode -Node $tree
        $vm.Label | Should -BeLike 'Forest*'
        $vm.Expanded | Should -BeTrue
        @($vm.Children).Count | Should -BeGreaterThan 0
        function Get-AllNode($n) { $n; foreach ($c in @($n.Children)) { Get-AllNode $c } }
        $nodes = @(Get-AllNode $vm)
        @($nodes | Where-Object { $_.Type -eq 'CA' }).Count | Should -BeGreaterThan 0
        @($nodes | Where-Object { $_.Confidence }).Count | Should -BeGreaterThan 0
        @($nodes | Where-Object { $_.ConfidenceText -like '(*)' }).Count | Should -BeGreaterThan 0
        # Every finding id on a node belongs to a real finding.
        $ids = @($script:data.Findings | ForEach-Object { $_.Id })
        foreach ($n in $nodes) { foreach ($id in @($n.FindingIds)) { $ids | Should -Contain $id } }
        # A node whose descendants are worse than itself says so.
        @($nodes | Where-Object { $_.BelowText -like 'contains *' }).Count | Should -BeGreaterThan 0
        (Get-MspkiGuiNodeSummary -Node $vm) | Should -BeLike 'Forest*'
        (Get-MspkiGuiNodeSummary -Node $null) | Should -Be ''
    }

    It 'shows every field of a finding that has a value, with readable names (D-23)' {
        $f = @($script:data.Findings | Where-Object { @($_.Evidence).Count -gt 0 -and $_.Remediation })[0]
        $d = Get-MspkiGuiFindingDetail -Finding $f
        $d.Fields.Count | Should -BeGreaterThan 4
        @($d.Fields | Where-Object { $_.Name -eq 'Finding id' })[0].Value | Should -Be $f.Id
        @($d.Fields | Where-Object { -not $_.Value -or $_.Value -eq [string][char]0x2014 }).Count | Should -Be 0
        @($d.Fields | Where-Object { $_.Name -in @('RelatedCA', 'StatusCode') }).Count | Should -Be 0
        @($d.Layers | ForEach-Object { $_.Name }) | Should -Be @('DNS', 'TCP', 'TLS', 'HTTP', 'Redirect', 'Content', 'Chain', 'Discovery')
        $d.Sources.Count | Should -BeGreaterThan 0
        $d.Evidence | Should -Not -BeNullOrEmpty
        $d.Remediation | Should -Be $f.Remediation
    }

    It 'maps engine stages to labels and a progress percentage' {
        (Get-MspkiGuiProgressPercent -FinishedStages @()) | Should -Be 0
        $names = @(Get-MspkiGuiStageList | ForEach-Object { $_.Name })
        (Get-MspkiGuiProgressPercent -FinishedStages $names) | Should -Be 100
        (Get-MspkiGuiProgressPercent -FinishedStages @($names[0], $names[0], 'Discovery', 'unknown')) | Should -Be ([int][math]::Floor(100 / $names.Count))
        (Get-MspkiGuiStageLabel -Stage 'Probe:NDES') | Should -BeLike '*NDES*'
        (Get-MspkiGuiStageLabel -Stage 'Something:Else') | Should -Be 'Something:Else'
        # Every stage the engine times is known to the progress bar (no stage is silently missing).
        $src = Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -Filter '*.ps1' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }
        $engine = @([regex]::Matches(($src -join "`n"), "Start-MspkiStageTimer -Stage '([^']+)'") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
        foreach ($e in $engine) { if ($e -ne 'Discovery') { $names | Should -Contain $e } }
    }

    It 'turns log messages and run.log lines into rows with a level' {
        (ConvertTo-MspkiGuiLogRow -Message ([pscustomobject]@{ Text = 't'; Level = 'Error' })).Level | Should -Be 'Error'
        (ConvertTo-MspkiGuiLogRowFromLine -Line '2026-01-01T00:00:00.000Z [ERROR] boom').Level | Should -Be 'Error'
        (ConvertTo-MspkiGuiLogRowFromLine -Line '2026-01-01T00:00:00.000Z [WARNING] hmm').Level | Should -Be 'Warning'
        (ConvertTo-MspkiGuiLogRowFromLine -Line 'plain line').Level | Should -Be 'Info'
        (ConvertTo-MspkiGuiLogRowFromLine -Line '2026-01-01T00:00:00.000Z [ERROR] boom').Tag | Should -Be 'ERROR'
    }

    It 'filters by several statuses at once and by severity' {
        $all = $script:rows.ToArray()
        $two = @(Get-MspkiGuiFilteredRow -Rows $all -Status @('Warning', 'Fail'))
        $two.Count | Should -Be 7
        @($two | Where-Object { $_.Status -notin @('Warning', 'Fail') }).Count | Should -Be 0
        @(Get-MspkiGuiFilteredRow -Rows $all -Severity 'High').Count | Should -Be @($all | Where-Object { $_.Severity -eq 'High' }).Count
        (Get-MspkiGuiFilterChoice -Rows $all -Field Severity)[0] | Should -Be 'All'
    }

    It 'gives every status, severity and confidence an icon, a tone and text (never colour alone)' {
        foreach ($s in @('Critical', 'Fail', 'Error', 'Warning', 'Skipped', 'Information', 'Pass', 'NotApplicable', 'PermissionDenied', 'Timeout')) {
            $p = Get-MspkiGuiStatusPill -Value $s
            $p.Glyph.Length | Should -Be 1
            $p.Text | Should -Not -BeNullOrEmpty
            $p.Tone | Should -BeIn @('Good', 'Warn', 'Bad', 'Info', 'Admin', 'Neutral')
        }
        (Get-MspkiGuiStatusPill -Value 'NotApplicable').Text | Should -Be 'Not Applicable'
        (Get-MspkiGuiStatusPill -Value 'Pass').Tone | Should -Be 'Good'
        (Get-MspkiGuiStatusPill -Value 'Fail').Tone | Should -Be 'Bad'
        (Get-MspkiGuiStatusPill -Value 'Warning').Tone | Should -Be 'Warn'
        (Get-MspkiGuiStatusPill -Value 'High' -Kind Severity).Tone | Should -Be 'Bad'
        (Get-MspkiGuiStatusPill -Value 'Confirmed' -Kind Confidence).Tone | Should -Be 'Good'
        (Get-MspkiGuiStatusPill -Value '').Text | Should -Be ''
        $script:rows[0].StatusPill.Glyph | Should -Not -BeNullOrEmpty
    }

    It 'builds the health banner: red for a failure, amber for warnings or a partial run, green when clean' {
        $s = Get-MspkiGuiSummary -RunInfo $script:data.RunInfo -Inventory $script:data.Inventory -Findings $script:data.Findings -ExitCode $script:data.ExitCode
        $s.Health.Level | Should -Be 'Red'
        $s.Health.Tone | Should -Be 'Bad'
        $s.Health.Title | Should -Be 'Action needed'
        $s.Health.Text | Should -BeLike '*1 failed*6 warning*'
        $warnOnly = @($script:data.Findings | Where-Object { $_.Status -notin @('Fail', 'Critical') })
        (Get-MspkiGuiHealth -Findings $warnOnly).Level | Should -Be 'Amber'
        $clean = @($script:data.Findings | Where-Object { $_.Status -in @('Pass', 'Information') -and $_.Severity -in @('None', 'Information') })
        (Get-MspkiGuiHealth -Findings $clean).Level | Should -Be 'Green'
        (Get-MspkiGuiHealth -Findings $clean -RunInfo ([pscustomobject]@{ Completed = $false })).Level | Should -Be 'Amber'
        (Get-MspkiGuiHealth -Findings $clean -CoverageProblems 2).Level | Should -Be 'Amber'
        (Get-MspkiGuiHealth -Findings @()).Text | Should -BeLike 'No findings*'
    }

    It 'fills the KPI tiles, CA cards, top issues and coverage so that nothing is blank' {
        $s = Get-MspkiGuiSummary -RunInfo $script:data.RunInfo -Inventory $script:data.Inventory -Findings $script:data.Findings -ExitCode $script:data.ExitCode
        $s.Kpis.Count | Should -Be 4
        @($s.Kpis | ForEach-Object { $_.Label }) | Should -Be @('Certification authorities', 'CA certificates', 'Published addresses', 'Certificate templates')
        $s.Kpis[0].Value | Should -Be 2
        $s.Kpis[1].Value | Should -Be 3
        $s.Kpis[3].Sub | Should -BeLike '*in Active Directory*'
        foreach ($k in $s.Kpis) { $k.Sub | Should -Not -BeNullOrEmpty; $k.Glyph | Should -Not -BeNullOrEmpty }
        $s.SeverityTiles.Count | Should -Be 5
        foreach ($c in $s.CAs) {
            foreach ($f in @('Name', 'Host', 'Role', 'Certificate', 'Facts')) { $c.$f | Should -Not -BeNullOrEmpty }
            foreach ($f in @('ExpiryPill', 'CrlPill', 'StatusPill')) { $c.$f.Text | Should -Not -BeNullOrEmpty }
        }
        $c1 = @($s.CAs | Where-Object { $_.Name -eq 'Example Issuing CA 01' })[0]
        $c1.Role | Should -Be 'Enterprise subordinate CA'
        $c1.Certificate | Should -Be 'Certificate expires 2029-05-02'
        $c1.ExpiryPill.Text | Should -Be '912 days left'
        $c1.ExpiryPill.Tone | Should -Be 'Good'
        $c1.CrlPill.Text | Should -BeLike 'CRL*'
        # The CA that did not answer still gets an honest card, not empty fields.
        $c2 = @($s.CAs | Where-Object { $_.Name -eq 'Example Issuing CA 02' })[0]
        $c2.Certificate | Should -Not -BeNullOrEmpty
        $c2.CrlPill.Text | Should -BeLike 'CRL not read*'
        # Top issues: worst first, never more than ten, never a pass or information.
        $s.TopIssues.Count | Should -BeLessOrEqual 10
        $s.TopIssues[0].StatusPill.Text | Should -Be 'Failing'
        @($s.TopIssues | Where-Object { $_.StatusPill.Text -in @('Pass', 'Information') }).Count | Should -Be 0
        # Coverage: every method with an outcome pill and a reason, problems first.
        $s.Coverage.Total | Should -Be 4
        $s.Coverage.Items[0].Bucket | Should -Be 'Could not check'
        $s.Coverage.Items[-1].Bucket | Should -Be 'Succeeded'
        foreach ($i in $s.Coverage.Items) { $i.Reason | Should -Not -BeNullOrEmpty; $i.Pill.Glyph | Should -Not -BeNullOrEmpty }
        $s.Coverage.Text | Should -BeLike '*4 methods tried*'
        $s.Coverage.Attention.Count | Should -Be 1
        $s.Coverage.Succeeded.Count | Should -Be 3
        $s.Coverage.SucceededText | Should -Be 'Show the 3 methods that succeeded'
        (Get-MspkiGuiCoverage -RunInfo ([pscustomobject]@{ Methods = @([pscustomobject]@{ Method = 'a'; Outcome = 'Success'; Detail = 'x'; ElapsedMs = 1 }) })).Text | Should -BeLike '*every one succeeded*'
        $s.Duration | Should -Be '1:26'
    }

    It 'says plainly when there is no discovery detail, and classifies every outcome' {
        (Get-MspkiGuiCoverage -RunInfo $null).Text | Should -BeLike 'No discovery method details*'
        $ri = [pscustomobject]@{ Methods = @(
            [pscustomobject]@{ Method = 'a'; Outcome = 'Timeout'; Detail = ''; ElapsedMs = 1 },
            [pscustomobject]@{ Method = 'b'; Outcome = 'Skipped'; Detail = 'switch'; ElapsedMs = 1 },
            [pscustomobject]@{ Method = 'c'; Outcome = 'SomethingNew'; Detail = 'x'; ElapsedMs = 1 }) }
        $c = Get-MspkiGuiCoverage -RunInfo $ri
        $c.Failed | Should -Be 1
        $c.Skipped | Should -Be 1
        $c.Items[0].Reason | Should -Not -BeNullOrEmpty
        @($c.Items | Where-Object { $_.Method -eq 'c' })[0].Pill.Text | Should -Be 'SomethingNew'
    }

    It 'builds the details and map panes with every field filled (a dash for an empty one)' {
        $f = @($script:data.Findings | Where-Object { -not $_.Notes })[0]
        $d = Get-MspkiGuiFindingDetail -Finding $f
        $d.Kind | Should -Be 'Finding'
        @($d.Fields | Where-Object { -not $_.Value }).Count | Should -Be 0
        $d.StatusPill.Text | Should -Not -BeNullOrEmpty
        $d.CopyText | Should -BeLike "$($f.Id) *"
        $d.HasNotes | Should -BeFalse
        @($d.Layers | Where-Object { -not $_.Pill.Text }).Count | Should -Be 0
        (Get-MspkiGuiEmptyPane).Kind | Should -Be 'None'
        $tree = Get-MspkiDiscoveryTree -Inventory $script:data.Inventory -Findings $script:data.Findings -RunInfo $script:data.RunInfo
        $vm = ConvertTo-MspkiGuiTreeNode -Node $tree
        $vm.TypeGlyph | Should -Not -BeNullOrEmpty
        (Get-MspkiGuiNodeCount -Node $vm) | Should -BeGreaterThan 10
        $byId = @{}
        foreach ($r in $script:rows) { $byId[$r.Id] = $r }
        $pane = Get-MspkiGuiNodePane -Node $vm -RowById $byId
        $pane.Kind | Should -Be 'Node'
        $pane.Title | Should -BeLike 'Forest*'
        $pane.CopyText | Should -BeLike 'Forest*'
        (Get-MspkiGuiNodePane -Node $null -RowById $byId).Kind | Should -Be 'None'
    }

    It 'formats role names, durations and dates' {
        Get-MspkiGuiRoleText -Role 'EnterpriseSubordinate' | Should -Be 'Enterprise subordinate CA'
        Get-MspkiGuiRoleText -Role 'StandaloneRoot' | Should -Be 'Standalone root CA'
        Get-MspkiGuiDurationText -Seconds 86 | Should -Be '1:26'
        Get-MspkiGuiDurationText -Seconds 3725 | Should -Be '1:02:05'
        (ConvertTo-MspkiGuiDateTime -Value '2026-11-20T09:29:00Z').Hour | Should -Be 9
        ConvertTo-MspkiGuiDateTime -Value '' | Should -BeNullOrEmpty
    }

    It 'only accepts a snapshot folder inside the allowed root' {
        . (Join-Path $script:GuiFolder 'GuiSnapshot.ps1')
        Test-MspkiGuiSnapshotFolder -Folder (Join-Path $TestDrive 'out\snap') -AllowedRoot (Join-Path $TestDrive 'out') | Should -BeTrue
        Test-MspkiGuiSnapshotFolder -Folder (Join-Path $TestDrive 'out') -AllowedRoot (Join-Path $TestDrive 'out') | Should -BeFalse
        Test-MspkiGuiSnapshotFolder -Folder (Join-Path $TestDrive 'elsewhere') -AllowedRoot (Join-Path $TestDrive 'out') | Should -BeFalse
        Test-MspkiGuiSnapshotFolder -Folder (Join-Path $TestDrive 'out\..\elsewhere') -AllowedRoot (Join-Path $TestDrive 'out') | Should -BeFalse
        Test-MspkiGuiSnapshotFolder -Folder (Join-Path $TestDrive 'out2') -AllowedRoot (Join-Path $TestDrive 'out') | Should -BeFalse
        # The snapshot function itself refuses a folder outside the root, before it creates or writes anything.
        { Invoke-MspkiGuiSnapshot -Window ([pscustomobject]@{}) -Folder (Join-Path $TestDrive 'elsewhere') -AllowedRoot (Join-Path $TestDrive 'out') } | Should -Throw '*inside*'
        Test-Path -LiteralPath (Join-Path $TestDrive 'elsewhere') | Should -BeFalse
    }

    It 'validates the timeout box' {
        Test-MspkiGuiTimeout -Text '5' | Should -Be 5
        Test-MspkiGuiTimeout -Text ' 120 ' | Should -Be 120
        Test-MspkiGuiTimeout -Text '0' | Should -BeNullOrEmpty
        Test-MspkiGuiTimeout -Text '121' | Should -BeNullOrEmpty
        Test-MspkiGuiTimeout -Text 'abc' | Should -BeNullOrEmpty
        Test-MspkiGuiTimeout -Text '' | Should -BeNullOrEmpty
    }

    It 'writes counts with the right word form, never "(s)"' {
        Format-MspkiGuiCount -Count 1 -Singular 'finding' | Should -Be '1 finding'
        Format-MspkiGuiCount -Count 0 -Singular 'finding' | Should -Be '0 findings'
        Format-MspkiGuiCount -Count 3 -Singular 'entry' -Plural 'entries' | Should -Be '3 entries'
        $h = Get-MspkiGuiHealth -Findings @() -CoverageProblems 1
        $h.Title | Should -Be 'Needs review'
        $h.Text | Should -Be '1 discovery method could not read its source (see Discovery coverage).'
        $h.Text | Should -Not -BeLike '*(s)*'
    }
}

Describe 'GUI window (single-threaded runspace)' {
    It 'loads Theme.xaml as a resource dictionary with the styles the window relies on' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder) -Script {
            param($folder)
            Add-Type -AssemblyName PresentationFramework
            Add-Type -AssemblyName PresentationCore
            Add-Type -AssemblyName WindowsBase
            $xaml = [System.IO.File]::ReadAllText((Join-Path $folder 'Theme.xaml'), [System.Text.Encoding]::UTF8)
            $d = [System.Windows.Markup.XamlReader]::Parse($xaml)
            # The colours live in the palette files (GX5); the window merges one of them next to the theme.
            $d.MergedDictionaries.Add([System.Windows.Markup.XamlReader]::Parse([System.IO.File]::ReadAllText((Join-Path $folder 'Palette.Light.xaml'), [System.Text.Encoding]::UTF8)))
            $keys = @('B.Accent', 'B.Header', 'PrimaryButton', 'PillTemplate', 'ChipToggle', 'Card', 'AppWindow', 'RowButton', 'TileButton', 'ReadBox', 'F.Icons',
                'SubtleButton', 'CaptionButton', 'CloseButton', 'SearchBox', 'FilterCombo', 'Switch', 'NavItem', 'NavList', 'ToneGlyph', 'ToneStripe', 'FocusRing')
            [pscustomobject]@{ Type = $d.GetType().Name; Missing = (@($keys | Where-Object { -not $d.Contains($_) }) -join ','); Count = $d.Count }
        }
        $out[0].Type | Should -Be 'ResourceDictionary'
        $out[0].Missing | Should -Be ''
        $out[0].Count | Should -BeGreaterThan 60
    }

    It 'loads MainWindow.xaml (with the theme merged in) and finds every named control the code uses' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder) -Script {
            param($folder)
            . (Join-Path $folder 'GuiModel.ps1')
            . (Join-Path $folder 'GuiView.ps1')
            . (Join-Path $folder 'GuiEntity.ps1')
            . (Join-Path $folder 'GuiApp.ps1')
            . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            $w = New-MspkiGuiWindow -XamlPath (Join-Path $folder 'MainWindow.xaml')
            # Every $ui.Name used in the app code must exist in the window.
            $code = (Get-Content -LiteralPath (Join-Path $folder 'GuiApp.ps1') -Raw) + (Get-Content -LiteralPath (Join-Path $folder 'GuiSnapshot.ps1') -Raw) + (Get-Content -LiteralPath (Join-Path $folder 'GuiMapView.ps1') -Raw)
            $used = [regex]::Matches($code, '\$(?:ui|u|s\.Ui|g\.Ui|script:MspkiGui\.Ui|st\.Ui)\.(\w+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
            $missing = @($used | Where-Object { -not $w.Ui.ContainsKey($_) -and $_ -notin @('ContainsKey', 'Keys', 'Count') })
            [pscustomobject]@{
                Title = $w.Window.Title; Controls = $w.Ui.Count; Missing = ($missing -join ',')
                ThemeLoaded = [bool]$w.Window.FindResource('B.Accent'); MinWidth = $w.Window.MinWidth; MinHeight = $w.Window.MinHeight
                FontFamily = $w.Window.FontFamily.Source
                Chrome = ($null -ne [System.Windows.Shell.WindowChrome]::GetWindowChrome($w.Window))
                Icons = $w.Window.FindResource('F.Icons').Source
                NavItems = $w.Ui.NavList.Items.Count; Pages = $w.Ui.Tabs.Items.Count
            }
        }
        $out[0].Title | Should -Be 'MSPKI Health Check'
        $out[0].Controls | Should -BeGreaterThan 80
        $out[0].Missing | Should -Be ''
        $out[0].ThemeLoaded | Should -BeTrue
        $out[0].MinWidth | Should -BeGreaterOrEqual 900
        $out[0].MinHeight | Should -BeGreaterOrEqual 560
        $out[0].FontFamily | Should -Be 'Segoe UI'
        # Custom title bar through the in-box WindowChrome; Fluent icons with the MDL2 font as the fallback; one nav item per page.
        $out[0].Chrome | Should -BeTrue
        $out[0].Icons | Should -Be 'Segoe Fluent Icons, Segoe MDL2 Assets'
        $out[0].NavItems | Should -Be $out[0].Pages
    }

    It 'starts on the welcome state, not on blank labels' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $TestDrive) -Script {
            param($folder, $module, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot
            $ui = $script:MspkiGui.Ui
            [pscustomobject]@{
                Welcome = [string]$ui.PanelWelcome.Visibility; Results = [string]$ui.PanelResults.Visibility
                Context = $ui.TxtWelcomeContext.Text; Header = @($ui.HdrContext.ItemsSource).Count; Badge = $ui.HdrBadge.Content.Text
                Version = $ui.HdrVersion.Text; Stage = $ui.TxtStage.Text; Options = $ui.TxtOptionsSummary.Text; Output = $ui.TxtOutputPath.Text
                RunEnabled = [bool]$ui.BtnRun.IsEnabled; CancelEnabled = [bool]$ui.BtnCancel.IsEnabled; Count = $ui.TxtCount.Text
                Forest = @($ui.HdrContext.ItemsSource)[0].Value; Error = [string]$ui.WelcomeError.Visibility
                Running = [string]$ui.RunStrip.Visibility
                BusyRunning = $(Set-MspkiGuiBusy -Busy $true; [string]$ui.RunStrip.Visibility); BusyWelcome = [string]$ui.PanelWelcome.Visibility; BusyResults = [string]$ui.PanelResults.Visibility; BusyRest = [string]$ui.PanelSummaryRest.Visibility; BusyTitle = $ui.BannerTitle.Text; BusyActions = [string]$ui.ActionBlock.Visibility
                IdleRunning = $(Clear-MspkiGuiResult; [string]$ui.RunStrip.Visibility)
            }
        }
        $r = $out[0]
        # Before the first run: no dash for facts that are not known yet, no error notice, no running panel.
        $r.Forest | Should -Be 'Known after a run'
        $r.Error | Should -Be 'Collapsed'
        $r.Running | Should -Be 'Collapsed'
        # While busy the Overview is the live mission control (the same hero and map, no separate running panel); a finished or failed run restores the rest.
        $r.BusyRunning | Should -Be 'Visible'
        $r.BusyWelcome | Should -Be 'Collapsed'
        $r.BusyResults | Should -Be 'Visible'
        $r.BusyRest | Should -Be 'Collapsed'
        $r.BusyActions | Should -Be 'Collapsed'
        $r.BusyTitle | Should -Be 'Checking your PKI'
        $r.IdleRunning | Should -Be 'Collapsed'
        $r.Welcome | Should -Be 'Visible'
        $r.Results | Should -Be 'Collapsed'
        $r.Context | Should -BeLike '*Administrator rights are not required*'
        $r.Header | Should -Be 4
        $r.Badge | Should -BeIn @('Administrator', 'Standard user')
        $r.Version | Should -BeLike 'v*'
        $r.Stage | Should -BeLike 'Ready*'
        $r.Options | Should -BeLike 'timeout 5 s*'
        $r.Output | Should -Be $TestDrive
        $r.RunEnabled | Should -BeTrue
        $r.CancelEnabled | Should -BeFalse
        $r.Count | Should -Be '' -Because 'D-35: no count before the first result'
    }

    It 'shows the fixture: summary, tiles, chips, grid, panes, tree, filters, export' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $script:DemoResults, $TestDrive) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            # The export confirmation would block the test with a message box, so record it instead.
            $script:messages = New-Object System.Collections.ArrayList
            function Show-MspkiGuiMessage { param([string]$Text, [string]$Title, [string]$Icon) [void]$script:messages.Add($Text) }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $ui = $script:MspkiGui.Ui
            $click = { param($c) $c.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))) }
            $r = [ordered]@{}
            $r.Apartment = [string][System.Threading.Thread]::CurrentThread.GetApartmentState()
            $r.Welcome = [string]$ui.PanelWelcome.Visibility; $r.Results = [string]$ui.PanelResults.Visibility
            $r.GridCount = @($ui.FindingsGrid.Items).Count
            $r.Kpis = @($ui.KpiList.ItemsSource).Count; $r.Tiles = @($ui.TileList.ItemsSource).Count; $r.SevTiles = @($ui.SevTileList.ItemsSource).Count
            $r.Cas = @($ui.CaList.ItemsSource).Count; $r.Top = @($ui.ActionList.ItemsSource).Count; $r.Coverage = @($ui.CoverageList.ItemsSource).Count; $r.CoverageOk = @($ui.CoverageOkList.ItemsSource).Count; $r.SevNote = [string]$ui.TxtNoSeverity.Visibility; $r.Mapsel = ($null -ne $ui.MapHost.Content)
            $r.Banner = $ui.BannerTitle.Text; $r.BannerText = $ui.BannerText.Text; $r.BannerTone = $ui.Banner.DataContext.Tone
            $r.Forest = @($ui.HdrContext.ItemsSource)[0].Value
            $r.Note = $ui.TxtNote.Text
            $r.Chips = @($script:MspkiGui.Chips).Count
            $r.TabCount = $ui.TxtTabFindings.Text; $r.StatusCount = $ui.TxtCount.Text; $r.MapCount = $ui.TxtMapCount.Text
            $r.RunEnabled = [bool]$ui.BtnRun.IsEnabled; $r.CancelEnabled = [bool]$ui.BtnCancel.IsEnabled
            # Free-text filter
            $ui.FltText.Text = 'zzzz-no-such-word'
            $r.AfterTextFilter = @($ui.FindingsGrid.Items).Count
            $r.EmptyShown = [string]$ui.TxtGridEmpty.Visibility
            & $click $ui.BtnClearFilters
            $r.AfterClear = @($ui.FindingsGrid.Items).Count
            # A status chip filters; two chips combine
            $warn = @($script:MspkiGui.Chips | Where-Object { $_.Tag -eq 'Warning' })[0]
            $warn.IsChecked = $true; & $click $warn
            $r.AfterChip = @($ui.FindingsGrid.Items).Count
            $r.ShowingText = $ui.TxtShowing.Text
            $fail = @($script:MspkiGui.Chips | Where-Object { $_.Tag -eq 'Fail' })[0]
            $fail.IsChecked = $true; & $click $fail
            $r.AfterTwoChips = @($ui.FindingsGrid.Items).Count
            & $click $ui.BtnClearFilters
            # Default order: most serious first. Grouping adds groups.
            $view = $script:MspkiGui.View
            $r.SortFirst = $view.GetItemAt(0).Status; $r.SortLast = $view.GetItemAt($view.Count - 1).Status
            $ui.ChkGroup.IsChecked = $true; & $click $ui.ChkGroup
            $r.Groups = $view.Groups.Count
            $ui.ChkGroup.IsChecked = $false; & $click $ui.ChkGroup
            $r.GroupsOff = $view.Groups.Count
            # Selecting a finding fills the details pane
            $ui.FindingsGrid.SelectedIndex = 0
            $sel = $ui.FindingsGrid.SelectedItem
            $r.PaneKind = $ui.FindingHost.Content.Kind; $r.PaneId = $ui.FindingHost.Content.Id; $r.SelectedId = $sel.Id
            # A tile opens the Findings tab filtered; a top issue opens its finding
            $script:MspkiGui.Ui.Tabs.SelectedItem = $ui.TabSummary
            Show-MspkiGuiFilteredStatus -Value 'Warning'
            $r.TileFiltered = @($ui.FindingsGrid.Items).Count; $r.TileTab = ($ui.Tabs.SelectedItem -eq $ui.TabFindings)
            $topId = @($ui.ActionList.ItemsSource)[0].Tag
            Show-MspkiGuiFinding -Id $topId
            $r.TopSelected = $ui.FindingsGrid.SelectedItem.Id; $r.TopId = $topId
            Clear-MspkiGuiFilter
            # Copy text of the selected rows
            $r.CopyText = Get-MspkiGuiSelectedRowsText
            # Discovery Map: select a CA node, then drill into one of its findings and back
            $root = $ui.MapTree.Items[0]
            $r.RootLabel = $root.Label
            $ca = $null; $stack = New-Object System.Collections.Stack; $stack.Push($root)
            while ($stack.Count -gt 0 -and $null -eq $ca) { $n = $stack.Pop(); if ($n.Type -eq 'CA' -and @($n.FindingIds).Count -gt 0) { $ca = $n } else { foreach ($c in @($n.Children)) { $stack.Push($c) } } }
            $script:MspkiGui.MapPane = Get-MspkiGuiNodePane -Node $ca -RowById $script:MspkiGui.RowById
            $ui.MapHost.Content = $script:MspkiGui.MapPane
            $r.MapKind = $ui.MapHost.Content.Kind; $r.MapFindings = $ui.MapHost.Content.FindingCount
            $ui.MapHost.Content = Get-MspkiGuiFindingDetail -Finding $script:MspkiGui.RowById[@($ca.FindingIds)[0]].Finding -CanGoBack $true
            $r.MapDrill = $ui.MapHost.Content.Kind; $r.MapBack = $ui.MapHost.Content.CanGoBack
            Set-MspkiGuiTreeExpansion -Parent $ui.MapTree -Expand $true
            Set-MspkiGuiTreeExpansion -Parent $ui.MapTree -Expand $false
            # Export of the filtered view lands in the output root and holds only the matching rows
            $ui.FltText.Text = 'Fail'
            Update-MspkiGuiFilter
            $r.ExportRows = @($ui.FindingsGrid.Items).Count
            Export-MspkiGuiFilteredView
            $r.ExportPath = $script:MspkiGui.LastExport
            $r.Messages = ($script:messages -join '|')
            $r.Log = $script:MspkiGui.LogRows.Count
            [pscustomobject]$r
        }
        $r = $out[0]
        $r.Apartment | Should -Be 'STA'
        $r.Welcome | Should -Be 'Collapsed'
        $r.Results | Should -Be 'Visible'
        $r.GridCount | Should -Be 30
        $r.Kpis | Should -Be 4
        $r.Tiles | Should -Be 9
        $r.SevTiles | Should -Be 5
        $r.Cas | Should -Be 2
        $r.Top | Should -BeGreaterThan 0
        $r.Coverage | Should -Be 1
        $r.CoverageOk | Should -Be 3
        $r.SevNote | Should -Be 'Visible'
        $r.Banner | Should -BeLike '* need* attention. Most urgent: *'
        $r.BannerTone | Should -Be 'Bad'
        $r.Forest | Should -Be 'corp.example.test'
        $r.Note | Should -BeLike '*earlier run*Nothing was scanned*'
        $r.Chips | Should -Be 5
        $r.TabCount | Should -Be '30'
        $r.StatusCount | Should -Be '30 findings'
        $r.MapCount | Should -BeLike '* items'
        $r.RunEnabled | Should -BeTrue
        $r.CancelEnabled | Should -BeFalse
        $r.AfterTextFilter | Should -Be 0
        $r.EmptyShown | Should -Be 'Visible'
        $r.AfterClear | Should -Be 30
        $r.AfterChip | Should -Be 6
        $r.ShowingText | Should -Be 'Showing 6 of 30 findings'
        $r.AfterTwoChips | Should -Be 7
        $r.SortFirst | Should -Be 'Fail'
        $r.SortLast | Should -Be 'Pass'
        $r.Groups | Should -BeGreaterThan 3
        $r.GroupsOff | Should -Be 0
        $r.PaneKind | Should -Be 'Finding'
        $r.PaneId | Should -Be $r.SelectedId
        $r.TileFiltered | Should -Be 6
        $r.TileTab | Should -BeTrue
        $r.TopSelected | Should -Be $r.TopId
        $r.CopyText | Should -BeLike "$($r.TopId)*"
        $r.RootLabel | Should -BeLike 'Forest*'
        $r.MapKind | Should -Be 'Node'
        $r.MapFindings | Should -BeGreaterThan 0
        $r.MapDrill | Should -Be 'Finding'
        $r.MapBack | Should -BeTrue
        $r.ExportRows | Should -BeGreaterThan 0
        $r.ExportPath | Should -BeLike "$TestDrive*findings-filtered-*.csv"
        Test-Path -LiteralPath $r.ExportPath | Should -BeTrue
        $csv = @(Get-Content -LiteralPath $r.ExportPath -Encoding UTF8)
        $csv.Count | Should -Be ($r.ExportRows + 1)
        $csv[0] | Should -BeLike '"Id","Timestamp"*'
        $r.Messages | Should -BeLike '*Exported*'
    }

    It 'drills into objects (format-2 fixture): Objects page, Overview tiles and cards, finding and map panes, related links, breadcrumbs, Back' {
        $v2 = Join-Path $script:FixturePath 'demo-results-v2.json'
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $v2, $TestDrive) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            function Show-MspkiGuiMessage { param([string]$Text, [string]$Title, [string]$Icon) }
            $null = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $g = $script:MspkiGui; $ui = $g.Ui
            $r = [ordered]@{}
            $r.Objects = @($g.ObjRows).Count; $r.Listed = $ui.ObjList.Items.Count; $r.Showing = $ui.TxtObjShowing.Text; $r.Types = @($ui.FltObjType.ItemsSource).Count
            $r.FirstPane = $ui.ObjHost.Content.Kind
            # Overview: a KPI tile lists one type; a CA card opens its CA
            Show-MspkiGuiObjectsOfType -Type 'CA'
            $r.KpiTab = ($ui.Tabs.SelectedItem -eq $ui.TabObjects); $r.KpiType = [string]$ui.FltObjType.SelectedItem; $r.KpiCount = $ui.ObjList.Items.Count
            $card = @($ui.CaList.ItemsSource)[0]
            $r.CardTag = [string]$card.Tag
            Show-MspkiGuiObject -Id $card.Tag.Substring(4)
            $r.CardPane = $ui.ObjHost.Content.Kind; $r.CardTitle = $ui.ObjHost.Content.Title; $r.CardName = $card.Name
            # Related link, breadcrumbs, crumb jump and Back on the Objects page
            $rel = @($ui.ObjHost.Content.Related | Where-Object { $_.Known })[0]
            Invoke-MspkiGuiPaneCommand -HostName 'ObjHost' -Tag $rel.Tag
            $r.Trail2 = @($g.Nav.ObjHost.Trail).Count; $r.Crumbs = $ui.ObjHost.Content.ShowCrumbs; $r.Back2 = $ui.ObjHost.Content.BackText
            Invoke-MspkiGuiPaneCommand -HostName 'ObjHost' -Tag 'crumb:0'
            $r.AfterCrumb = $ui.ObjHost.Content.Title
            Invoke-MspkiGuiPaneCommand -HostName 'ObjHost' -Tag 'Back'
            $r.BackAtStart = $ui.ObjHost.Content.Title
            # Attention filter and a search with no match
            Clear-MspkiGuiObjectFilter
            $ui.ChkObjAttention.IsChecked = $true; Update-MspkiGuiObjectFilter
            $r.Attention = $ui.ObjList.Items.Count
            $ui.FltObj.Text = 'zzzz-no-such-object'
            $r.NoMatch = $ui.ObjList.Items.Count; $r.NoMatchText = [string]$ui.TxtObjEmpty.Visibility
            Clear-MspkiGuiObjectFilter
            # Findings pane: objects of a finding, open one, Back to the finding
            $row = @($g.Rows | Where-Object { @($_.Finding.EntityIds).Count -gt 0 })[0]
            $ui.Tabs.SelectedItem = $ui.TabFindings
            $ui.FindingsGrid.SelectedItem = $row
            $r.FindObjects = $ui.FindingHost.Content.HasObjects
            Invoke-MspkiGuiPaneCommand -HostName 'FindingHost' -Tag @($ui.FindingHost.Content.Objects)[0].Tag
            $r.FindEntity = $ui.FindingHost.Content.Kind; $r.FindBack = $ui.FindingHost.Content.BackText
            Invoke-MspkiGuiPaneCommand -HostName 'FindingHost' -Tag 'Back'
            $r.FindReturn = $ui.FindingHost.Content.Kind
            # Discovery map: the CA item links its object; a finding opened from the object returns to it
            $root = $ui.MapTree.Items[0]
            $ca = $null; $stack = New-Object System.Collections.Stack; $stack.Push($root)
            while ($stack.Count -gt 0 -and $null -eq $ca) { $n = $stack.Pop(); if ($n.Type -eq 'CA') { $ca = $n } else { foreach ($c in @($n.Children)) { $stack.Push($c) } } }
            Show-MspkiGuiNodePane -Node $ca
            $r.MapObjects = $ui.MapHost.Content.ObjectCount
            Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag @($ui.MapHost.Content.Objects)[0].Tag
            $r.MapEntity = $ui.MapHost.Content.Kind; $r.MapBack = $ui.MapHost.Content.BackText
            $fid = @($ui.MapHost.Content.Findings)[0].Id
            if ($fid) {
                Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag $fid
                $r.MapFinding = $ui.MapHost.Content.Kind; $r.MapFindingBack = $ui.MapHost.Content.BackText
                Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag 'Back'
                $r.MapFindingReturn = $ui.MapHost.Content.Kind
            }
            Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag 'Back'
            $r.MapReturn = $ui.MapHost.Content.Kind
            Select-MspkiGuiTab -Index 4
            $r.Tab5 = ($ui.Tabs.SelectedItem -eq $ui.TabObjects)
            Select-MspkiGuiTab -Index 5
            $r.Tab6 = ($ui.Tabs.SelectedItem -eq $ui.TabServices)
            $r.Services = @($ui.SvcList.ItemsSource).Count; $r.SvcSummary = $ui.TxtSvcSummary.Text
            $inst = @(@($ui.SvcList.ItemsSource) | ForEach-Object { @($_.Instances) } | Where-Object { $_ })[0]
            Open-MspkiGuiServiceItem -Tag $inst.Tag; $r.SvcEntity = $ui.SvcHost.Content.Kind
            $sf = @(@($ui.SvcList.ItemsSource) | ForEach-Object { @($_.Findings) } | Where-Object { $_ })[0]
            Open-MspkiGuiServiceItem -Tag $sf.Id; $r.SvcFinding = $ui.SvcHost.Content.Kind
            Select-MspkiGuiTab -Index 4
            $r.Tab5 = ($ui.Tabs.SelectedItem -eq $ui.TabObjects)
            [pscustomobject]$r
        }
        $r = $out[0]
        $r.Objects | Should -BeGreaterThan 20
        $r.Listed | Should -Be $r.Objects
        $r.Showing | Should -Be ('Showing {0} of {0} objects' -f $r.Objects)
        $r.Types | Should -BeGreaterThan 5
        $r.FirstPane | Should -Be 'Entity'
        $r.KpiTab | Should -BeTrue
        $r.KpiType | Should -Be 'Certification authority'
        $r.KpiCount | Should -Be 2
        $r.CardTag | Should -BeLike 'ent:ca:*'
        $r.CardPane | Should -Be 'Entity'
        $r.CardTitle | Should -Be $r.CardName
        $r.Trail2 | Should -Be 2
        $r.Crumbs | Should -BeFalse
        $r.Back2 | Should -BeLike ('Back to {0} (*)' -f $r.CardName)
        $r.AfterCrumb | Should -Be $r.CardName
        $r.BackAtStart | Should -Be $r.CardName
        $r.Attention | Should -BeGreaterThan 0
        $r.Attention | Should -BeLessThan $r.Objects
        $r.NoMatch | Should -Be 0
        $r.NoMatchText | Should -Be 'Visible'
        $r.FindObjects | Should -BeTrue
        $r.FindEntity | Should -Be 'Entity'
        $r.FindBack | Should -Be 'Back to the finding'
        $r.FindReturn | Should -Be 'Finding'
        $r.MapObjects | Should -BeGreaterThan 0
        $r.MapEntity | Should -Be 'Entity'
        $r.MapBack | Should -Be 'Back to the map item'
        if ($null -ne $r.PSObject.Properties['MapFinding']) { $r.MapFinding | Should -Be 'Finding'; $r.MapFindingBack | Should -BeLike 'Back to *'; $r.MapFindingReturn | Should -Be 'Entity' }
        $r.MapReturn | Should -Be 'Node'
        $r.Tab5 | Should -BeTrue
        $r.Services | Should -Be 6
        $r.Tab6 | Should -BeTrue
        $r.SvcSummary | Should -BeLike "* of 6 service types confirmed*"
        $r.SvcEntity | Should -Be "Entity"
        $r.SvcFinding | Should -Be "Finding"
    }

    It 'a bad file is reported in a message, not a crash (window stays usable)' {
        $bad = Join-Path $TestDrive 'bad-results.json'
        [System.IO.File]::WriteAllText($bad, 'nope')
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $bad, $TestDrive) -Script {
            param($folder, $module, $bad, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            # A message box would block the test, so replace it with a recorder.
            $script:messages = New-Object System.Collections.ArrayList
            function Show-MspkiGuiMessage { param([string]$Text, [string]$Title, [string]$Icon) [void]$script:messages.Add($Text) }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $bad
            [pscustomobject]@{ Messages = ($script:messages -join '|'); Rows = $script:MspkiGui.Rows.Count; RunEnabled = [bool]$script:MspkiGui.Ui.BtnRun.IsEnabled; Welcome = [string]$script:MspkiGui.Ui.PanelWelcome.Visibility }
        }
        $out[0].Messages | Should -BeLike '*not valid JSON*'
        $out[0].Rows | Should -Be 0
        $out[0].RunEnabled | Should -BeTrue
        $out[0].Welcome | Should -Be 'Visible'
    }

    It 'D-34: the map tree follows the details pane''s trail (object links, Back) without losing the trail' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, (Join-Path $script:FixturePath 'demo-results-v2.json'), $TestDrive) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            function Show-MspkiGuiMessage { param([string]$Text, [string]$Title, [string]$Icon) }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $g = $script:MspkiGui; $ui = $g.Ui
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show()
            Wait-MspkiGuiIdle -Rounds 4
            $ui.Tabs.SelectedItem = $ui.TabMap; $ui.RbMapTree.IsChecked = $true
            Wait-MspkiGuiIdle -Rounds 2
            $r = [ordered]@{}
            $root = $ui.MapTree.Items[0]
            $cas = New-Object System.Collections.Generic.List[object]; $stack = New-Object System.Collections.Stack; $stack.Push($root)
            while ($stack.Count -gt 0) { $n = $stack.Pop(); if ($n.Type -eq 'CA') { $cas.Add($n) }; foreach ($c in @($n.Children)) { $stack.Push($c) } }
            # Start on the forest item, open a CA from its pane: the tree selects that CA (two levels in) and the pane keeps the object
            $ui.MapTree.ItemContainerGenerator.ContainerFromIndex(0).IsSelected = $true
            $target = $cas[$cas.Count - 1]
            $caId = @(Get-MspkiGuiNodeEntityId -Index $g.Index -Node $target)[0]
            $r.HasLink = [bool]$caId
            Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag ('ent:' + $caId)
            $r.Pane = $ui.MapHost.Content.Kind
            $r.Selected = [object]::ReferenceEquals($ui.MapTree.SelectedItem, $target)
            $r.Dbg = 'sel={0} target={1} cas={2}' -f $ui.MapTree.SelectedItem.Label, $target.Label, $cas.Count
            $r.Trail = @($g.Nav.MapHost.Trail).Count
            Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag 'Back'
            $r.Back = $ui.MapHost.Content.Kind
            $win.Close()
            [pscustomobject]$r
        }
        $out[0].HasLink | Should -BeTrue
        $out[0].Pane | Should -Be 'Entity'
        $out[0].Selected | Should -BeTrue -Because $out[0].Dbg
        $out[0].Trail | Should -Be 1
        $out[0].Back | Should -Be 'Node'
    }

    It 'is one live mission control while a run is in progress: the same hero, a map that fills as items arrive, no separate running panel; the results then restore the hero' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, (Join-Path $script:FixturePath 'demo-results-v2.json'), $TestDrive) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot
            $g = $script:MspkiGui; $ui = $g.Ui
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show()
            Wait-MspkiGuiIdle -Rounds 4
            $r = [ordered]@{}
            Set-MspkiGuiBusy -Busy $true
            $g.ForceMotion = $true   # motion on: the animations are real WPF animations, so they can be asked about
            Wait-MspkiGuiIdle -Rounds 4
            $r.StartTitle = $ui.BannerTitle.Text; $r.StartEmpty = [string]$ui.TxtMapEmpty.Visibility; $r.StartCanvas = $ui.MapCanvas.Children.Count
            $r.AreasDisabled = (@($ui.AreaPanel.Children | Where-Object { $_.IsEnabled }).Count -eq 0)
            $graph = (Read-MspkiGuiResults -Path $results).Graph
            $items = Get-MspkiGuiSnapshotLiveItems -Graph $graph
            foreach ($i in @($items.Phases[1])) { [void](Add-MspkiGuiLiveItem -State $g.Live -Item $i) }
            $ui.Progress.Value = 37
            Update-MspkiGuiRunningHero; Update-MspkiGuiLiveMap
            $r.FadingIn = @($g.MapDrawn.Nodes | Where-Object { $_.Body.HasAnimatedProperties }).Count
            Wait-MspkiGuiIdle -Rounds 3
            $r.Percent = $ui.TxtScore.Text; $r.Found1 = $ui.TxtRunFound.Text; $r.Nodes1 = $g.MapDrawn.Nodes.Count; $r.Canvas1 = $ui.MapCanvas.Children.Count
            foreach ($i in @($items.Phases[2])) { [void](Add-MspkiGuiLiveItem -State $g.Live -Item $i) }
            Update-MspkiGuiLiveMap
            $r.Pulsing = @($g.MapDrawn.Nodes | Where-Object { $null -ne $_.Pulse -and $_.Pulse.HasAnimatedProperties }).Count; $r.Pending = $g.Live.Probes.Count
            foreach ($i in @($items.Phases[3])) { [void](Add-MspkiGuiLiveItem -State $g.Live -Item $i) }
            Update-MspkiGuiLiveMap
            $r.PulsingEnd = @($g.MapDrawn.Nodes | Where-Object { $null -ne $_.Pulse -and $_.Pulse.HasAnimatedProperties }).Count
            Wait-MspkiGuiIdle -Rounds 3
            $r.Nodes2 = $g.MapDrawn.Nodes.Count; $r.Shown = $g.Live.Shown.Count
            $r.RunStrip = [string]$ui.RunStrip.Visibility; $r.Rest = [string]$ui.PanelSummaryRest.Visibility
            $final = Get-MspkiGuiMapModel -Index (New-MspkiGuiGraphIndex -Graph $graph -Findings @()) -FindingStatus @{}
            $r.FinalNodes = @($final.Nodes).Count
            $r.SameNodes = ((@($g.MapDrawn.Nodes | ForEach-Object { $_.Node.Id } | Sort-Object) -join '|') -eq (@($final.Nodes | ForEach-Object { $_.Id } | Sort-Object) -join '|'))
            # The run ends with results: the hero is restored, the live map is not built a second time, "All actions" lists every action.
            $g.LiveWasShown = ($null -ne $g.Live -and $g.Live.Shown.Count -gt 0)
            Set-MspkiGuiBusy -Busy $false
            Open-MspkiGuiResultsFile -Path $results
            Wait-MspkiGuiIdle -Rounds 4
            $r.EndStrip = [string]$ui.RunStrip.Visibility; $r.EndActions = [string]$ui.ActionBlock.Visibility; $r.EndRest = [string]$ui.PanelSummaryRest.Visibility
            $r.Shown5 = @($ui.ActionList.ItemsSource).Count; $r.Total = $g.Actions.Total
            $r.Headline = $ui.BannerTitle.Text; $r.LiveCleared = ($null -eq $g.Live)
            Switch-MspkiGuiActionList
            $r.ShownAll = @($ui.ActionList.ItemsSource).Count; $r.AllLabel = [string]$ui.BtnAllActions.Content
            Switch-MspkiGuiActionList
            $r.Back = @($ui.ActionList.ItemsSource).Count
            # The ring opens the Findings page filtered to what lowers the score.
            $ui.BtnScoreRing.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            $r.RingTab = ($ui.Tabs.SelectedItem -eq $ui.TabFindings); $r.RingCount = @($ui.FindingsGrid.Items).Count
            $r.NeedsAttention = @($g.Rows | Where-Object { $_.Status -in @('Critical', 'Fail', 'Error', 'Warning') }).Count; $r.AllRows = $g.Rows.Count
            # "How is this scored?" opens a themed popup in the window (no Windows message box).
            $ui.BtnScoreHow.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            $r.HowOpen = [bool]$ui.PopScore.IsOpen; $r.HowText = $ui.TxtScoreHow.Text
            $ui.PopScore.IsOpen = $false
            $win.Close()
            [pscustomobject]$r
        }
        $r = $out[0]
        $r.StartTitle | Should -Be 'Checking your PKI'
        $r.StartEmpty | Should -Be 'Visible'
        $r.StartCanvas | Should -Be 0
        $r.AreasDisabled | Should -BeTrue
        $r.Percent | Should -Be '37%'
        $r.Found1 | Should -BeLike '*found so far'
        $r.Nodes1 | Should -BeGreaterThan 0
        $r.FadingIn | Should -Be $r.Nodes1 -Because 'every node of the first batch fades in'
        $r.Pending | Should -Be 3
        $r.Pulsing | Should -Be 3 -Because 'a node pulses while its probe runs'
        $r.PulsingEnd | Should -Be 0 -Because 'and stops when the probe ended'
        $r.Canvas1 | Should -BeGreaterThan 0
        $r.Nodes2 | Should -BeGreaterThan $r.Nodes1
        $r.SameNodes | Should -BeTrue -Because ('live {0} vs finished {1} nodes' -f $r.Nodes2, $r.FinalNodes)
        $r.RunStrip | Should -Be 'Visible'
        $r.Rest | Should -Be 'Collapsed'
        $r.EndStrip | Should -Be 'Collapsed'
        $r.EndActions | Should -Be 'Visible'
        $r.EndRest | Should -Be 'Visible'
        $r.Shown5 | Should -BeLessOrEqual 5
        $r.Total | Should -BeGreaterThan $r.Shown5
        $r.Headline | Should -BeLike '* need* attention. Most urgent: *'
        $r.ShownAll | Should -Be $r.Total
        $r.AllLabel | Should -Be 'Show fewer'
        $r.Back | Should -Be $r.Shown5
        $r.RingTab | Should -BeTrue
        $r.HowOpen | Should -BeTrue
        $r.HowText | Should -BeLike '*not a certification*'
        $r.RingCount | Should -Be $r.NeedsAttention
        $r.RingCount | Should -BeLessThan $r.AllRows
    }

    It 'renders every tab to a PNG snapshot with RenderTargetBitmap' {
        $snap = Join-Path $TestDrive 'out\snap'
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $script:DemoResults, (Join-Path $TestDrive 'out'), $snap) -Script {
            param($folder, $module, $results, $outRoot, $snap)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot
            Invoke-MspkiGuiSnapshot -Window $win -Folder $snap -AllowedRoot $outRoot -ResultsFile $results -Width 1100 -Height 700
        }
        $files = @($out)
        $files.Count | Should -BeGreaterOrEqual 8
        foreach ($f in $files) { (Get-Item -LiteralPath $f).Length | Should -BeGreaterThan 8000 }
        @($files | ForEach-Object { Split-Path -Leaf $_ }) | Should -Contain '10-summary.png'
        @($files | ForEach-Object { Split-Path -Leaf $_ }) | Should -Contain '30-map.png'
        # The PNG header and the size we asked for.
        $bytes = [System.IO.File]::ReadAllBytes($files[0])
        [System.Text.Encoding]::ASCII.GetString($bytes, 1, 3) | Should -Be 'PNG'
        # Fixed-size off-window render: every frame is exactly the size asked for (IHDR width and height), whatever the screen is.
        foreach ($f in $files) {
            $b = [System.IO.File]::ReadAllBytes($f)
            $pw = ([int]$b[16] -shl 24) + ([int]$b[17] -shl 16) + ([int]$b[18] -shl 8) + [int]$b[19]
            $ph = ([int]$b[20] -shl 24) + ([int]$b[21] -shl 16) + ([int]$b[22] -shl 8) + [int]$b[23]
            ('{0}x{1}' -f $pw, $ph) | Should -Be '1100x700' -Because (Split-Path -Leaf $f)
        }
        # D-07: every frame shows the page its name claims, and the finished, partial and no-CA Overview frames have a score in the ring.
        $frames = @(Import-Csv -LiteralPath (Join-Path $snap 'frames.csv'))
        $frames.Count | Should -Be $files.Count
        foreach ($fr in $frames) { if ($fr.Expected) { $fr.Page | Should -Be $fr.Expected -Because $fr.Name } }
        foreach ($nm in @('10-summary', '50-partial', '60-no-ca')) {
            $fr = @($frames | Where-Object { $_.Name -eq $nm })[0]
            $fr | Should -Not -BeNullOrEmpty -Because $nm
            $fr.Score | Should -Not -BeNullOrEmpty -Because $nm
        }
        @($frames | Where-Object { $_.Name -like '3[1-4]-*' }).Count | Should -BeGreaterOrEqual 2
    }
    It 'D-07: maps every snapshot frame name to the page it must show' {
        . (Join-Path $script:GuiFolder 'GuiSnapshot.ps1')
        Get-MspkiGuiSnapshotExpectedPage -Name '34-map-tree' | Should -Be 'TabMap'
        Get-MspkiGuiSnapshotExpectedPage -Name '36b-history-bottom' | Should -Be 'TabHistory'
        Get-MspkiGuiSnapshotExpectedPage -Name '60-no-ca' | Should -Be 'TabSummary'
        Get-MspkiGuiSnapshotExpectedPage -Name '02-running-log' | Should -Be 'TabLog'
        Get-MspkiGuiSnapshotExpectedPage -Name '27-palette-search' | Should -Be ''
    }

    It 'renders at the window minimum size when asked, and at a size larger than the screen' {
        $snap = Join-Path $TestDrive 'out\snapmin'
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, (Join-Path $TestDrive 'out'), $snap) -Script {
            param($folder, $module, $outRoot, $snap)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot
            [void][System.IO.Directory]::CreateDirectory($snap)
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Show()
            Wait-MspkiGuiIdle -Rounds 4
            $min =Get-MspkiGuiSnapshotMinimumSize -Window $win
            $a = Save-MspkiGuiSnapshotImage -Window $win -Path (Join-Path $snap 'min.png') -Width $min.Width -Height $min.Height
            $b = Save-MspkiGuiSnapshotImage -Window $win -Path (Join-Path $snap 'huge.png') -Width 3000 -Height 2000
            $win.Close()
            [pscustomobject]@{ MinW = $min.Width; MinH = $min.Height; Files = @($a, $b) }
        }
        $out[0].MinW | Should -BeGreaterThan 900
        $out[0].MinW | Should -BeLessOrEqual 1080
        $out[0].MinH | Should -BeLessOrEqual 700
        $sizes = foreach ($f in $out[0].Files) {
            $b = [System.IO.File]::ReadAllBytes($f)
            '{0}x{1}' -f (([int]$b[18] -shl 8) + [int]$b[19] + ([int]$b[17] -shl 16)), (([int]$b[22] -shl 8) + [int]$b[23] + ([int]$b[21] -shl 16))
        }
        $sizes[1] | Should -Be '3000x2000'
    }
}

Describe 'Audit 2 M6: an unexpected error in the window never closes it' {

    It 'turns an exception and its inner exceptions into one line without a stack trace' {
        $inner = New-Object System.InvalidOperationException('inner problem')
        $outer = New-Object System.Exception('outer problem', $inner)
        $t = Format-MspkiGuiErrorText -Exception $outer
        $t | Should -Be 'outer problem | inner problem'
        Format-MspkiGuiErrorText -Exception $null | Should -Be 'An unknown error.'
    }

    It 'logs the error, shows it once, cancels a run in progress and handles it (the window stays alive)' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $TestDrive) -Script {
            param($folder, $module, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot
            $g = $script:MspkiGui
            $script:notified = New-Object System.Collections.ArrayList
            $script:MspkiGuiErrorNotifier = { param($t) [void]$script:notified.Add($t) }
            $ctl = [hashtable]::Synchronized(@{ Cancel = $false })
            $g.Run = [pscustomobject]@{ Control = $ctl; Handle = [pscustomobject]@{ IsCompleted = $false }; CancelRequested = $null; Started = [DateTime]::Now }
            $ex = New-Object System.InvalidOperationException('boom in a handler')
            $r1 = Invoke-MspkiGuiUnhandledError -Exception $ex -Source 'test'
            $r2 = Invoke-MspkiGuiUnhandledError -Exception $ex -Source 'test'
            [pscustomobject]@{
                Handled = [bool]$r1 -and [bool]$r2; Cancel = [bool]$ctl['Cancel']; Notified = $script:notified.Count; Msg = [string]$script:notified[0]
                ErrorRows = @($g.LogRows | Where-Object { $_.Level -eq 'Error' -and $_.Text -match 'boom in a handler' }).Count
                File = (Test-Path -LiteralPath (Join-Path $outRoot 'gui-error.log'))
                Alive = ($null -ne $g.Window)
            }
        }
        $r = $out[0]
        $r.Handled | Should -BeTrue
        $r.Cancel | Should -BeTrue
        $r.Notified | Should -Be 1 -Because 'the same error is shown once'
        $r.Msg | Should -Match 'boom in a handler'
        $r.Msg | Should -Match 'still open'
        $r.Msg | Should -Match 'cancelled'
        $r.ErrorRows | Should -Be 2
        $r.File | Should -BeTrue
        $r.Alive | Should -BeTrue
    }

    It 'survives a throwing handler and a throwing timer tick inside the real dispatcher loop, and the timer keeps ticking' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $TestDrive) -Script {
            param($folder, $module, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot
            $g = $script:MspkiGui
            $script:notified = New-Object System.Collections.ArrayList
            $script:MspkiGuiErrorNotifier = { param($t) [void]$script:notified.Add($t) }
            $script:ticks = 0
            # The progress timer's tick calls this function: make it throw every time.
            function Receive-MspkiGuiProgress { $script:ticks++; throw ('tick failure {0}' -f $script:ticks) }
            # A second timer stands in for any event handler: a delegate raised by WPF that throws.
            $script:h = 0
            $handlerTimer = New-Object System.Windows.Threading.DispatcherTimer
            $handlerTimer.Interval = [TimeSpan]::FromMilliseconds(30)
            $handlerTimer.Add_Tick({ $script:h++; $script:handlerTimer.Stop(); throw 'handler failure' })
            $script:handlerTimer = $handlerTimer
            $g.Timer.Interval = [TimeSpan]::FromMilliseconds(40)
            $g.Timer.Start(); $handlerTimer.Start()
            $disp = $win.Dispatcher
            $stop = New-Object System.Windows.Threading.DispatcherTimer
            $stop.Interval = [TimeSpan]::FromMilliseconds(900)
            $stop.Add_Tick({ $script:g2 = $true; $script:disp2.InvokeShutdown() })
            $script:disp2 = $disp
            $stop.Start()
            [System.Windows.Threading.Dispatcher]::Run()
            $g.Timer.Stop()
            [pscustomobject]@{ Ticks = $script:ticks; H = $script:h; Rows = @($g.LogRows | Where-Object { $_.Level -eq 'Error' }).Count
                HandlerLogged = @($g.LogRows | Where-Object { $_.Text -match 'handler failure' }).Count; Notified = $script:notified.Count }
        }
        $r = $out[0]
        $r.Ticks | Should -BeGreaterOrEqual 3 -Because 'a tick that throws must not stop the timer'
        $r.H | Should -Be 1
        $r.HandlerLogged | Should -Be 1 -Because 'an exception in a WPF-raised handler reaches the dispatcher hook'
        $r.Rows | Should -BeGreaterOrEqual 4
        $r.Notified | Should -BeGreaterOrEqual 2
        $r.Notified | Should -BeLessOrEqual 3
    }
}
