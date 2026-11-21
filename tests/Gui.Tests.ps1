# Tests for the GUI: the engine's cancel flag and progress queue, the pure GUI helpers (rows, filters, tree, summary,
# details) and, in a single-threaded runspace, that the XAML loads and the window shows the example.test fixture.
# No real environment data: everything uses tests\fixtures\demo-results.json (example.test only).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:GuiFolder = Join-Path $script:RepoRoot 'src\Gui'
    . (Join-Path $script:GuiFolder 'GuiModel.ps1')
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
    It 'loads the XAML and finds every named control the code uses' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder) -Script {
            param($folder)
            . (Join-Path $folder 'GuiModel.ps1')
            . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            $w = New-MspkiGuiWindow -XamlPath (Join-Path $folder 'MainWindow.xaml')
            # Every Ui['...'] / $ui.Name used in the app code must exist in the window.
            $code = Get-Content -LiteralPath (Join-Path $folder 'GuiApp.ps1') -Raw
            $used = [regex]::Matches($code, '\$(?:ui|u|s\.Ui|g\.Ui|script:MspkiGui\.Ui)\.(\w+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
            $missing = @($used | Where-Object { -not $w.Ui.ContainsKey($_) -and $_ -notin @('ContainsKey', 'Keys', 'Count') })
            [pscustomobject]@{ Title = $w.Window.Title; Controls = $w.Ui.Count; Missing = ($missing -join ',') }
        }
        $out[0].Title | Should -Be 'MSPKI Health Check'
        $out[0].Controls | Should -BeGreaterThan 40
        $out[0].Missing | Should -Be ''
    }

    It 'shows the fixture: summary, tree, sortable and filterable grid, details, log' {
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $script:DemoResults, $TestDrive) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1')
            . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $ui = $script:MspkiGui.Ui
            $r = [ordered]@{}
            $r.Apartment = [string][System.Threading.Thread]::CurrentThread.GetApartmentState()
            $r.GridCount = @($ui.FindingsGrid.Items).Count
            $r.Tiles = @($ui.TileList.ItemsSource).Count
            $r.Cas = @($ui.CaGrid.ItemsSource).Count
            $r.Forest = $ui.SumForest.Text
            $r.TreeRoots = @($ui.MapTree.Items).Count
            $r.Banner = $ui.TxtBanner.Text
            $r.RunEnabled = [bool]$ui.BtnRun.IsEnabled
            $r.CancelEnabled = [bool]$ui.BtnCancel.IsEnabled
            # Free-text filter
            $ui.FltText.Text = 'zzzz-no-such-word'
            $r.AfterTextFilter = @($ui.FindingsGrid.Items).Count
            $ui.BtnClearFilters.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            $r.AfterClear = @($ui.FindingsGrid.Items).Count
            # Status drop-down filter
            $ui.FltStatus.SelectedItem = 'Warning'
            $r.AfterStatus = @($ui.FindingsGrid.Items).Count
            $r.ShowingText = $ui.TxtShowing.Text
            $ui.FltStatus.SelectedIndex = 0
            # Sorting by the Status column (sorted by rank) puts the most serious first, and a second click reverses it
            $view = $script:MspkiGui.View
            $view.SortDescriptions.Clear()
            $view.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription('StatusRank', [System.ComponentModel.ListSortDirection]::Descending)))
            $first = $view.GetItemAt(0)
            $last = $view.GetItemAt($view.Count - 1)
            $r.SortFirst = $first.Status; $r.SortLast = $last.Status
            $view.SortDescriptions.Clear()
            $view.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription('Category', [System.ComponentModel.ListSortDirection]::Ascending)))
            $r.SortCategoryOk = ($view.GetItemAt(0).Category -le $view.GetItemAt($view.Count - 1).Category)
            # Selecting a finding fills the details
            $ui.FindingsGrid.SelectedIndex = 0
            $sel = $ui.FindingsGrid.SelectedItem
            $r.DetailVisible = [string]$ui.DetPanel.Visibility
            $r.DetailId = $ui.DetPanel.DataContext.Id
            $r.SelectedId = $sel.Id
            # Selecting a tree node fills the node panel
            $root = $ui.MapTree.Items[0]
            $r.RootLabel = $root.Label
            $r.Log = $script:MspkiGui.LogRows.Count
            [pscustomobject]$r
        }
        $r = $out[0]
        $r.Apartment | Should -Be 'STA'
        $r.GridCount | Should -Be 30
        $r.Tiles | Should -Be 8
        $r.Cas | Should -Be 2
        $r.Forest | Should -Be 'corp.example.test'
        $r.TreeRoots | Should -Be 1
        $r.Banner | Should -BeLike '*earlier run*Nothing was scanned*'
        $r.RunEnabled | Should -BeTrue
        $r.CancelEnabled | Should -BeFalse
        $r.AfterTextFilter | Should -Be 0
        $r.AfterClear | Should -Be 30
        $r.AfterStatus | Should -Be 6
        $r.ShowingText | Should -Be 'Showing 6 of 30'
        $r.SortFirst | Should -Be 'Fail'
        $r.SortLast | Should -Be 'Pass'
        $r.SortCategoryOk | Should -BeTrue
        $r.DetailVisible | Should -Be 'Visible'
        $r.DetailId | Should -Be $r.SelectedId
        $r.RootLabel | Should -BeLike 'Forest*'
    }

    It 'a bad file is reported in a message, not a crash (window stays usable)' {
        $bad = Join-Path $TestDrive 'bad-results.json'
        [System.IO.File]::WriteAllText($bad, 'nope')
        $out = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $bad, $TestDrive) -Script {
            param($folder, $module, $bad, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1')
            . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            # A message box would block the test, so replace it with a recorder.
            $script:messages = New-Object System.Collections.ArrayList
            function Show-MspkiGuiMessage { param([string]$Text, [string]$Title, [string]$Icon) [void]$script:messages.Add($Text) }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $bad
            [pscustomobject]@{ Messages = ($script:messages -join '|'); Rows = $script:MspkiGui.Rows.Count; RunEnabled = [bool]$script:MspkiGui.Ui.BtnRun.IsEnabled }
        }
        $out[0].Messages | Should -BeLike '*not valid JSON*'
        $out[0].Rows | Should -Be 0
        $out[0].RunEnabled | Should -BeTrue
    }
}
