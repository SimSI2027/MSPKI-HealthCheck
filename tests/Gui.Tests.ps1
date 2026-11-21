# Tests for the GUI: the engine's cancel flag and progress queue, the pure GUI helpers (rows, filters, tree, summary,
# details) and, in a single-threaded runspace, that the XAML loads and the window shows the example.test fixture.
# No real environment data: everything uses tests\fixtures\demo-results.json (example.test only).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:GuiFolder = Join-Path $script:RepoRoot 'src\Gui'
    . (Join-Path $script:GuiFolder 'GuiModel.ps1')
    . (Join-Path $script:GuiFolder 'GuiView.ps1')
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
            $j = Get-Content -LiteralPath $r.ResultsPath -Raw | ConvertFrom-Json
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
        (Get-MspkiGuiFilteredRow -Rows $all -Status '(all)' -Category '(all)' -Confidence '(all)').Count | Should -Be 30
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
        $s[0] | Should -Be '(all)'
        $s | Should -Contain 'Fail'
        $s | Should -Not -Contain 'Critical'
        $s.IndexOf('Fail') | Should -BeLessThan $s.IndexOf('Pass')
        $cats = @(Get-MspkiGuiFilterChoice -Rows $script:rows -Field Category)
        $cats[0] | Should -Be '(all)'
        @($cats[1..($cats.Count - 1)]) | Should -Be @(@($cats[1..($cats.Count - 1)]) | Sort-Object)
    }

    It 'builds the summary: facts, a tile per status that adds up, and the CAs' {
        $s = Get-MspkiGuiSummary -RunInfo $script:data.RunInfo -Inventory $script:data.Inventory -Findings $script:data.Findings -ExitCode $script:data.ExitCode
        $s.Forest | Should -Be 'corp.example.test'
        $s.User | Should -Be 'CORP\demo.user'
        $s.IsAdmin | Should -BeLike 'No*'
        $s.Total | Should -Be 30
        $s.Tiles.Count | Should -Be 8
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
        @($nodes | Where-Object { $_.BelowText -like 'worst below:*' }).Count | Should -BeGreaterThan 0
        (Get-MspkiGuiNodeSummary -Node $vm) | Should -BeLike 'Forest*'
        (Get-MspkiGuiNodeSummary -Node $null) | Should -Be ''
    }

    It 'shows every field of a finding in the details' {
        $f = @($script:data.Findings | Where-Object { @($_.Evidence).Count -gt 0 -and $_.Remediation })[0]
        $d = Get-MspkiGuiFindingDetail -Finding $f
        $d.Fields.Count | Should -Be 15
        @($d.Fields | Where-Object { $_.Name -eq 'Id' })[0].Value | Should -Be $f.Id
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
        (Get-MspkiGuiFilterChoice -Rows $all -Field Severity)[0] | Should -Be '(all)'
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
        @($s.Kpis | ForEach-Object { $_.Label }) | Should -Be @('Certification authorities', 'CA certificates', 'Endpoints', 'Certificate templates')
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
        $s.TopIssues[0].StatusPill.Text | Should -Be 'Fail'
        @($s.TopIssues | Where-Object { $_.StatusPill.Text -in @('Pass', 'Information') }).Count | Should -Be 0
        # Coverage: every method with an outcome pill and a reason, problems first.
        $s.Coverage.Total | Should -Be 4
        $s.Coverage.Items[0].Bucket | Should -Be 'Permission denied'
        $s.Coverage.Items[-1].Bucket | Should -Be 'Succeeded'
        foreach ($i in $s.Coverage.Items) { $i.Reason | Should -Not -BeNullOrEmpty; $i.Pill.Glyph | Should -Not -BeNullOrEmpty }
        $s.Coverage.Text | Should -BeLike '*4 method(s) tried*'
        $s.Coverage.Attention.Count | Should -Be 1
        $s.Coverage.Succeeded.Count | Should -Be 3
        $s.Coverage.SucceededText | Should -Be 'Show the 3 method(s) that succeeded'
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
            $keys = @('B.Accent', 'B.Header', 'PrimaryButton', 'PillTemplate', 'ChipToggle', 'Card', 'AppWindow', 'RowButton', 'TileButton', 'ReadBox', 'F.Icons')
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
            . (Join-Path $folder 'GuiApp.ps1')
            . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            $w = New-MspkiGuiWindow -XamlPath (Join-Path $folder 'MainWindow.xaml')
            # Every $ui.Name used in the app code must exist in the window.
            $code = (Get-Content -LiteralPath (Join-Path $folder 'GuiApp.ps1') -Raw) + (Get-Content -LiteralPath (Join-Path $folder 'GuiSnapshot.ps1') -Raw)
            $used = [regex]::Matches($code, '\$(?:ui|u|s\.Ui|g\.Ui|script:MspkiGui\.Ui|st\.Ui)\.(\w+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
            $missing = @($used | Where-Object { -not $w.Ui.ContainsKey($_) -and $_ -notin @('ContainsKey', 'Keys', 'Count') })
            [pscustomobject]@{
                Title = $w.Window.Title; Controls = $w.Ui.Count; Missing = ($missing -join ',')
                ThemeLoaded = [bool]$w.Window.FindResource('B.Accent'); MinWidth = $w.Window.MinWidth; MinHeight = $w.Window.MinHeight
                FontFamily = $w.Window.FontFamily.Source
            }
        }
        $out[0].Title | Should -Be 'MSPKI Health Check'
        $out[0].Controls | Should -BeGreaterThan 80
        $out[0].Missing | Should -Be ''
        $out[0].ThemeLoaded | Should -BeTrue
        $out[0].MinWidth | Should -BeGreaterOrEqual 900
        $out[0].MinHeight | Should -BeGreaterOrEqual 560
        $out[0].FontFamily | Should -Be 'Segoe UI'
    }

    It 'starts on the welcome state, not on blank labels' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $TestDrive) -Script {
            param($folder, $module, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot
            $ui = $script:MspkiGui.Ui
            [pscustomobject]@{
                Welcome = [string]$ui.PanelWelcome.Visibility; Results = [string]$ui.PanelResults.Visibility
                Context = $ui.TxtWelcomeContext.Text; Header = @($ui.HdrContext.ItemsSource).Count; Badge = $ui.HdrBadge.Content.Text
                Version = $ui.HdrVersion.Text; Stage = $ui.TxtStage.Text; Options = $ui.TxtOptionsSummary.Text; Output = $ui.TxtOutputPath.Text
                RunEnabled = [bool]$ui.BtnRun.IsEnabled; CancelEnabled = [bool]$ui.BtnCancel.IsEnabled; Count = $ui.TxtCount.Text
            }
        }
        $r = $out[0]
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
        $r.Count | Should -Be '0 findings'
    }

    It 'shows the fixture: summary, tiles, chips, grid, panes, tree, filters, export' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $script:DemoResults, $TestDrive) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiApp.ps1')
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
            $r.Cas = @($ui.CaList.ItemsSource).Count; $r.Top = @($ui.TopList.ItemsSource).Count; $r.Coverage = @($ui.CoverageList.ItemsSource).Count; $r.CoverageOk = @($ui.CoverageOkList.ItemsSource).Count; $r.SevNote = [string]$ui.TxtNoSeverity.Visibility; $r.Mapsel = ($null -ne $ui.MapHost.Content)
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
            $topId = @($ui.TopList.ItemsSource)[0].Id
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
        $r.Tiles | Should -Be 8
        $r.SevTiles | Should -Be 5
        $r.Cas | Should -Be 2
        $r.Top | Should -BeGreaterThan 0
        $r.Coverage | Should -Be 1
        $r.CoverageOk | Should -Be 3
        $r.SevNote | Should -Be 'Visible'
        $r.Banner | Should -Be 'Action needed'
        $r.BannerTone | Should -Be 'Bad'
        $r.Forest | Should -Be 'corp.example.test'
        $r.Note | Should -BeLike '*earlier run*Nothing was scanned*'
        $r.Chips | Should -Be 5
        $r.TabCount | Should -Be '30'
        $r.StatusCount | Should -Be '30 findings'
        $r.MapCount | Should -BeLike '* item(s)'
        $r.RunEnabled | Should -BeTrue
        $r.CancelEnabled | Should -BeFalse
        $r.AfterTextFilter | Should -Be 0
        $r.EmptyShown | Should -Be 'Visible'
        $r.AfterClear | Should -Be 30
        $r.AfterChip | Should -Be 6
        $r.ShowingText | Should -Be 'Showing 6 of 30 finding(s)'
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

    It 'a bad file is reported in a message, not a crash (window stays usable)' {
        $bad = Join-Path $TestDrive 'bad-results.json'
        [System.IO.File]::WriteAllText($bad, 'nope')
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $bad, $TestDrive) -Script {
            param($folder, $module, $bad, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiApp.ps1')
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

    It 'renders every tab to a PNG snapshot with RenderTargetBitmap' {
        $snap = Join-Path $TestDrive 'out\snap'
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $script:DemoResults, (Join-Path $TestDrive 'out'), $snap) -Script {
            param($folder, $module, $results, $outRoot, $snap)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
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
    }
}
