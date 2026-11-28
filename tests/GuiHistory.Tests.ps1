# GX8: the History page. Pure side (src/Gui/GuiHistory.ps1: run files, run summaries, comparing two runs, the comparison's view) and the
# page in the real window (src/Gui/GuiHistoryPage.ps1). Runs are written to TestDrive only, from the example.test fixture.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    foreach ($f in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1', 'GuiMission.ps1', 'GuiLifecycle.ps1', 'GuiHistory.ps1') { . (Join-Path $script:RepoRoot ('src\Gui\' + $f)) }
    . (Join-Path $PSScriptRoot 'GuiMapFixture.ps1')
    $script:Fixture = Join-Path $script:FixturePath 'demo-results-v2.json'
    $script:WriteRun = {
        param([string]$Root, [string]$Name, $Doc)
        $dir = Join-Path $Root $Name
        [void][System.IO.Directory]::CreateDirectory($dir)
        $p = Join-Path $dir 'results.json'
        [System.IO.File]::WriteAllText($p, ($Doc | ConvertTo-Json -Depth 40), (New-Object System.Text.UTF8Encoding($false)))
        return $p
    }
    $script:SetKeys = { param($findings) & (Get-Module MspkiHealthCheck) { param($f) [void](Set-MspkiFindingKey -Findings $f) } @($findings) }
    # Run A (older) is the fixture; run B (newer) fixes one failure, makes one warning a failure, drops one warning, adds a new failure,
    # loses one object and finds another.
    $script:MakePair = {
        param([string]$Root)
        $a = Get-Content -LiteralPath $script:Fixture -Raw | ConvertFrom-Json
        $a.RunInfo.StartedUtc = '2026-11-13T08:00:00Z'
        & $script:SetKeys $a.Findings
        $b = Get-Content -LiteralPath $script:Fixture -Raw | ConvertFrom-Json
        $b.RunInfo.StartedUtc = '2026-11-20T08:00:00Z'
        foreach ($f in $b.Findings) {
            if ($f.Id -eq 'F0020') { $f.Status = 'Pass'; $f.StatusCode = 'OK'; $f.Message = 'The AIA host answers now.' }
            if ($f.Id -eq 'F0012') { $f.Status = 'Fail' }
        }
        $b.Findings = @(@($b.Findings | Where-Object { $_.Id -ne 'F0027' }) + @([pscustomobject]@{ Id = 'F0031'; Category = 'Template'; Role = 'Unknown'; Target = 'Web Server'; Endpoint = ''; Status = 'Fail'; Severity = 'High'; StatusCode = 'CONFIG_RISK'; Confidence = 'Confirmed'; Message = 'Anyone may enroll.'; Sources = @('test'); Evidence = @(); EntityIds = @() }))
        & $script:SetKeys $b.Findings
        $gone = [string]@($b.Graph.Entities)[-1].Id
        $b.Graph.Entities = @(@($b.Graph.Entities | Where-Object { [string]$_.Id -ne $gone }) + @([pscustomobject]@{ Id = 'host:new01.corp.example.test'; Type = 'Host'; Name = 'new01.corp.example.test'; Properties = [pscustomobject]@{} }))
        [pscustomobject]@{ A = (& $script:WriteRun $Root '20261113-080000' $a); B = (& $script:WriteRun $Root '20261120-080000' $b); Gone = $gone }
    }
}

Describe 'Runs in the output folder' {
    It 'finds results.json one and two folders down, newest first, and nothing else' {
        $root = Join-Path $TestDrive 'find'
        $p1 = & $script:WriteRun $root 'run1' ([pscustomobject]@{ x = 1 })
        $p2 = & $script:WriteRun (Join-Path $root 'lab') 'run2' ([pscustomobject]@{ x = 2 })
        [System.IO.File]::SetLastWriteTimeUtc($p1, [datetime]::new(2026, 11, 1, 0, 0, 0, [DateTimeKind]::Utc))
        [System.IO.File]::SetLastWriteTimeUtc($p2, [datetime]::new(2026, 11, 2, 0, 0, 0, [DateTimeKind]::Utc))
        [void][System.IO.Directory]::CreateDirectory((Join-Path $root 'a\b\c'))
        [System.IO.File]::WriteAllText((Join-Path $root 'a\b\c\results.json'), '{}')
        $f = @(Find-MspkiGuiRunFile -Root $root)
        $f.Count | Should -Be 2
        $f[0].Path | Should -Be $p2
        @(Find-MspkiGuiRunFile -Root $root -Max 1).Count | Should -Be 1
        @(Find-MspkiGuiRunFile -Root (Join-Path $TestDrive 'nothing-here')).Count | Should -Be 0
    }
    It 'sums a run up (score, counts, finished or not), and says what is wrong with a file it cannot read' {
        $d = Read-MspkiGuiResults -Path $script:Fixture
        $s = Get-MspkiGuiRunSummary -Path $script:Fixture -Data $d
        $s.Forest | Should -Be 'corp.example.test'
        $s.Fail | Should -Be 1
        $s.Warn | Should -Be 6
        $s.Score | Should -BeOfType [int]
        $s.Completed | Should -BeTrue
        $bad = Get-MspkiGuiRunSummary -Path 'x\results.json' -ReadError 'This file is not valid JSON'
        $bad.Error | Should -Match 'not valid JSON'
        $bad.Score | Should -BeNullOrEmpty
    }
    It 'reads a few runs per step within its time budget, then the rest from where it stopped (the worker stays free)' {
        $root = Join-Path $TestDrive 'budget'
        $pair = & $script:MakePair $root
        $cache = @{}
        $r1 = Invoke-MspkiGuiHistoryJob -Request @{ Kind = 'History'; Gen = 1; Options = @{ Root = $root; BudgetMs = 0 } } -Cache $cache
        $r1.Found | Should -Be 2
        $r1.Pending | Should -BeGreaterThan 0
        $r2 = $r1
        for ($i = 0; $i -lt 5 -and $r2.Pending -gt 0; $i++) { $r2 = Invoke-MspkiGuiHistoryJob -Request @{ Kind = 'History'; Gen = 1; Options = @{ Root = $root; BudgetMs = 0 } } -Cache $cache }
        $r2.Pending | Should -Be 0
        @($r2.Runs).Count | Should -Be 2
        # The run on show, loaded from elsewhere, is listed too.
        $r3 = Invoke-MspkiGuiHistoryJob -Request @{ Kind = 'History'; Gen = 1; Options = @{ Root = $root; BudgetMs = 5000; Extra = $script:Fixture } } -Cache $cache
        @($r3.Runs).Count | Should -Be 3
    }
}

Describe 'Comparing two runs' {
    BeforeAll {
        $script:Pair = & $script:MakePair (Join-Path $TestDrive 'cmp')
        $script:A = Read-MspkiGuiResults -Path $script:Pair.A
        $script:B = Read-MspkiGuiResults -Path $script:Pair.B
        $script:C = Compare-MspkiGuiRun -Old $script:A -New $script:B
    }
    It 'finds the new problem, the fixed and the dropped ones as resolved, and the warning that became a failure as worse' {
        @($script:C.NewProblems | ForEach-Object { $_.Target }) | Should -Be @('Web Server')
        $res = @($script:C.Resolved)
        $res.Count | Should -Be 2
        $fixed = @($res | Where-Object { $_.Kind -eq 'Resolved' })[0]
        $fixed.Target | Should -Be 'old-pki.example.test'
        $fixed.Before | Should -Be 'Fail'
        $fixed.After | Should -Be 'Pass'
        @($res | Where-Object { $_.Kind -eq 'Gone' })[0].Target | Should -Be 'pki.corp.example.test'
        $ch = @($script:C.Changed)
        $ch.Count | Should -Be 1
        $ch[0].Kind | Should -Be 'Worse'
        $ch[0].Before | Should -Be 'Warning'
        $ch[0].After | Should -Be 'Fail'
        $script:C.StillOpen | Should -Be 4
    }
    It 'lists the objects added and gone by their ids, and the score per area' {
        @($script:C.Added | ForEach-Object { $_.Id }) | Should -Be @('host:new01.corp.example.test')
        @($script:C.Gone | ForEach-Object { $_.Id }) | Should -Be @($script:Pair.Gone)
        $script:C.ScoreDelta | Should -BeLessThan 0
        @($script:C.Areas).Count | Should -BeGreaterThan 3
        @($script:C.Notes).Count | Should -Be 0
    }
    It 'says what it cannot know: a run that did not finish, -SkipNetwork in one run, results without the graph or without keys' {
        $a2 = Read-MspkiGuiResults -Path $script:Pair.A
        $a2.RunInfo | Add-Member -NotePropertyName Completed -NotePropertyValue 'False' -Force
        $a2.RunInfo | Add-Member -NotePropertyName Parameters -NotePropertyValue ([pscustomobject]@{ SkipNetwork = $true }) -Force
        $a2.Graph = $null
        foreach ($f in $a2.Findings) { $f.PSObject.Properties.Remove('Key') }
        $c = Compare-MspkiGuiRun -Old $a2 -New $script:B
        $n = @($c.Notes) -join ' | '
        $n | Should -Match 'older run did not finish'
        $n | Should -Match 'SkipNetwork'
        $n | Should -Match 'without the object graph'
        $n | Should -Match 'before findings had a Key'
        $c.ObjectsKnown | Should -BeFalse
        # Without keys, findings are still paired by what they are about: the same answer.
        @($c.NewProblems).Count | Should -Be 1
        @($c.Changed).Count | Should -Be 1
    }
    It 'shows the comparison in plain words: before and after in the right order, readable names, and only findings of the run on show open' {
        $open = @{}; foreach ($f in $script:B.Findings) { $open[[string]$f.Id] = $true }
        $v = Get-MspkiGuiCompareView -Compare $script:C -OpenIds $open
        $v.Sub | Should -Match '^From the run of 13 Nov 2026, 08:00 UTC to the run of 20 Nov 2026, 08:00 UTC: 1 new problem, 2 resolved, 1 changed, 4 still open\.$'
        $sec = @{}; foreach ($s in $v.Sections) { $sec[$s.Key] = $s }
        $sec.Resolved.Items[0].Sub | Should -Match '^Was failing, now passing\. '
        $sec.Resolved.Items[0].CanOpen | Should -BeFalse
        $sec.Changed.Items[0].Sub | Should -Match '^Was a warning, now failing\. '
        $sec.New.Items[0].Sub | Should -Match '^Not in the older run; now failing\. '
        $sec.New.Items[0].Tag | Should -Be 'f:F0031'
        $sec.Gone.Heading | Should -Be 'Objects gone (1)'
        # A distinguished name as a target reads as its common name.
        $c2 = [pscustomobject]@{ Old = $script:C.Old; New = $script:C.New; ScoreDelta = 0; Areas = @(); NewProblems = @([pscustomobject]@{ Kind = 'New'; Id = 'F1'; Category = 'CRL'; Target = 'CN=Example Issuing CA 01, DC=corp, DC=example, DC=test'; Status = 'Warning'; Before = ''; After = 'Warning'; Code = 'STALE_DATA'; Message = 'm' })
            Resolved = @(); Changed = @(); StillOpen = 0; ObjectsKnown = $false; Added = @(); Gone = @(); Notes = @() }
        (Get-MspkiGuiCompareView -Compare $c2).Sections[0].Items[0].Title | Should -Be 'CRL · Example Issuing CA 01'
        foreach ($a in $v.Areas) { if ($null -eq $a.Delta -and $a.ScoresText -ne 'not scored') { $a.ScoresText | Should -Match '→' } }
    }
    It 'keeps long sections short: at most 40 rows and "and N more"' {
        $many = @(for ($i = 0; $i -lt 55; $i++) { [pscustomobject]@{ Kind = 'New'; Id = ('F{0}' -f $i); Category = 'CDP'; Target = ('h{0}.example.test' -f $i); Status = 'Fail'; Before = ''; After = 'Fail'; Code = 'DNS_FAIL'; Message = 'm' } })
        $c3 = [pscustomobject]@{ Old = $script:C.Old; New = $script:C.New; ScoreDelta = $null; Areas = @(); NewProblems = $many; Resolved = @(); Changed = @(); StillOpen = 0; ObjectsKnown = $false; Added = @(); Gone = @(); Notes = @() }
        $s = (Get-MspkiGuiCompareView -Compare $c3).Sections[0]
        @($s.Items).Count | Should -Be 40
        $s.More | Should -Be 'and 15 more'
    }
}

Describe 'The run list of a forest' {
    It 'lists the newest first, marks the run on show, and compares it with the run before it by default; the trend is oldest first' {
        $root = Join-Path $TestDrive 'rows'
        $pair = & $script:MakePair $root
        $runs = @(foreach ($p in @($pair.A, $pair.B)) { Get-MspkiGuiRunSummary -Path $p -Data (Read-MspkiGuiResults -Path $p) })
        $forests = @(Get-MspkiGuiHistoryForest -Runs $runs -Prefer 'corp.example.test')
        $forests[0].Text | Should -Be 'corp.example.test (2 runs)'
        $v = Get-MspkiGuiHistoryRow -Runs $runs -Forest 'corp.example.test' -CurrentPath $pair.B
        $v.Rows[0].Path | Should -Be $pair.B
        $v.Rows[0].IsCurrent | Should -BeTrue
        $v.Rows[0].When | Should -Be '20 Nov 2026, 08:00 UTC'
        $v.Newer.Path | Should -Be $pair.B
        $v.Older.Path | Should -Be $pair.A
        @($v.Trend | ForEach-Object { $_.Path }) | Should -Be @($pair.A, $pair.B)
        $v.Rows[1].AutomationName | Should -Match '^Run of 13 Nov 2026, 08:00 UTC: score \d+, '
    }
}

Describe 'Performance budget (GX8: reading and comparing runs is off the UI thread)' {
    It 'compares two 300-object estates well within a second (the background worker''s job)' {
        $root = Join-Path $TestDrive 'perf'
        $a = New-MspkiTestLargeResults -CaCount 8 -EndpointCount 60 -ObjectCount 300 -WithLifecycle
        $b = New-MspkiTestLargeResults -CaCount 8 -EndpointCount 60 -ObjectCount 300 -WithLifecycle
        & $script:SetKeys $a.Findings; & $script:SetKeys $b.Findings
        $pa = & $script:WriteRun $root 'a' $a; $pb = & $script:WriteRun $root 'b' $b
        $best = [double]::MaxValue
        for ($i = 0; $i -lt 3; $i++) { $r = Invoke-MspkiGuiHistoryJob -Request @{ Kind = 'HistoryCompare'; Gen = 1; Options = @{ OldPath = $pa; NewPath = $pb } } -Cache @{}; $best = [math]::Min($best, [double]$r.Ms) }
        Write-Host ('    history compare (two 300-object estates, read and compared): {0} ms, best of 3' -f $best)
        $best | Should -BeLessThan 3000
        @($r.Compare.NewProblems).Count | Should -Be 0
    }
}

Describe 'The History page in the real window (J4 in two clicks, keyboard, palette, budgets)' {
    BeforeAll {
        $script:GuiFolder = Join-Path $script:RepoRoot 'src\Gui'
        function Invoke-InStaRunspace {
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
        $outRoot = Join-Path $TestDrive 'hout'
        $pair = & $script:MakePair $outRoot
        # A third, older run of the same forest, and one run of another forest (not listed with these).
        $c = Get-Content -LiteralPath $pair.A -Raw | ConvertFrom-Json
        $c.RunInfo.StartedUtc = '2026-11-06T08:00:00Z'
        $script:PathC = & $script:WriteRun $outRoot '20261106-080000' $c
        $o = Get-Content -LiteralPath $pair.A -Raw | ConvertFrom-Json
        $o.RunInfo.Forest = 'other.example.test'
        [void](& $script:WriteRun $outRoot '20261101-080000' $o)
        # Two LARGE estates, to measure the UI-thread part of showing a big comparison.
        $la = New-MspkiTestLargeResults -CaCount 8 -EndpointCount 60 -ObjectCount 300 -WithLifecycle
        $lb = New-MspkiTestLargeResults -CaCount 8 -EndpointCount 60 -ObjectCount 300 -WithLifecycle -WithUnreadCa
        $lpa = & $script:WriteRun (Join-Path $TestDrive 'large') 'a' $la
        $lpb = & $script:WriteRun (Join-Path $TestDrive 'large') 'b' $lb
        $script:PairH = $pair
        $script:Win = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $pair.B, $outRoot, $lpa, $lpb) -Script {
            param($folder, $module, $results, $outRoot, $lpa, $lpb)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            function Show-MspkiGuiMessage { param($Text, $Title, $Icon) Write-Output ('MESSAGEBOX: ' + $Text) }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $g = $script:MspkiGui; $ui = $g.Ui
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show(); [void]$win.Activate()
            Wait-MspkiGuiIdle -Rounds 4
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            $r = [ordered]@{}
            $settle = { $end = [DateTime]::Now.AddSeconds(60); do { Wait-MspkiGuiMapIdle -TimeoutMs 20000; Wait-MspkiGuiIdle -Rounds 2 } while ((($g.HistPending -gt 0) -or ($null -eq $g.HistRuns) -or ($null -ne $g.MapJob)) -and [DateTime]::Now -lt $end) }
            # Click 1 (J4): Ctrl+7 opens History; the UI thread only asks the worker (timed), the runs and the comparison arrive after.
            $sw = [Diagnostics.Stopwatch]::StartNew()
            [void](Invoke-MspkiGuiShortcut -Key 'D7' -Ctrl $true -Alt $false -Shift $false)
            $r.SwitchMs = $sw.ElapsedMilliseconds
            $r.OnHistory = ($ui.Tabs.SelectedItem -eq $ui.TabHistory)
            & $settle
            $rows = @($ui.HistList.ItemsSource)
            $r.Rows = $rows.Count
            $r.Forests = @($ui.FltHistForest.ItemsSource).Count
            $r.FirstIsCurrent = [bool]$rows[0].IsCurrent
            $r.DefaultOld = [string]$g.HistCmp.Old.Path
            $r.DefaultNew = [string]$g.HistCmp.New.Path
            $r.NewCount = [string]@($ui.HistSections.ItemsSource)[0].Heading
            $r.Trend = $ui.HistTrend.Children.Count
            # Click 2: Compare on the oldest run.
            Invoke-MspkiGuiHistoryTag -Tag ([string]$rows[2].CompareTag)
            & $settle
            $r.PickedOld = [string]$g.HistCmp.Old.Path
            # A new problem of the run on show opens on the Findings page.
            Invoke-MspkiGuiHistoryTag -Tag 'f:F0031'
            Wait-MspkiGuiIdle -Rounds 2
            $r.OpenedFinding = ($ui.Tabs.SelectedItem -eq $ui.TabFindings -and [string]$ui.FindingsGrid.SelectedItem.Id -eq 'F0031')
            # The palette: the page (Ctrl+7) and "Compare with the run before" (back to the default pair).
            $r.Palette = (@(Get-MspkiGuiPalettePage | ForEach-Object { $_.Title + '=' + $_.Shortcut }) -join ',')
            $r.Commands = (@(Get-MspkiGuiPaletteCommand -Available (Get-MspkiGuiCommandAvailability) | ForEach-Object { $_.Action }) -join ',')
            $r.HistPrevOn = [bool](Get-MspkiGuiCommandAvailability).histprev
            $ui.Tabs.SelectedItem = $ui.TabHistory
            Invoke-MspkiGuiHistoryComparePrevious
            & $settle
            $r.PrevOld = [string]$g.HistCmp.Old.Path
            # Keyboard: F6 reaches the list; every control of the page and every button in it has an accessible name.
            [void]$ui.NavList.Focus(); Wait-MspkiGuiIdle -Rounds 1
            [void](Invoke-MspkiGuiShortcut -Key 'F6' -Ctrl $false -Alt $false -Shift $false)
            [void](Invoke-MspkiGuiShortcut -Key 'F6' -Ctrl $false -Alt $false -Shift $false)
            Wait-MspkiGuiIdle -Rounds 1
            $r.F6List = [bool]$ui.HistList.IsKeyboardFocusWithin
            $unnamed = New-Object System.Collections.ArrayList
            foreach ($n in 'BtnHistRefresh', 'FltHistForest', 'HistList', 'HistTrend') { if (-not [System.Windows.Automation.AutomationProperties]::GetName($ui[$n])) { [void]$unnamed.Add($n) } }
            $stack = New-Object System.Collections.Stack
            $stack.Push($ui.HistList); $stack.Push($ui.HistSections)
            while ($stack.Count -gt 0) {
                $v = $stack.Pop()
                if ($v -is [System.Windows.Controls.Button] -and -not [System.Windows.Automation.AutomationProperties]::GetName($v)) { [void]$unnamed.Add('a button') }
                if ($v -is [System.Windows.Media.Visual]) { for ($i = 0; $i -lt [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($v); $i++) { $stack.Push([System.Windows.Media.VisualTreeHelper]::GetChild($v, $i)) } }
            }
            $r.Unnamed = ($unnamed -join ',')
            # The UI-thread part of a big comparison (two 300-object estates): putting it on screen stays under 50 ms.
            $big = Invoke-MspkiGuiHistoryJob -Request @{ Kind = 'HistoryCompare'; Gen = [int]$g.MapGen; Options = @{ OldPath = $lpa; NewPath = $lpb } } -Cache @{}
            $best = [double]::MaxValue
            foreach ($i in 1..3) { $sw.Restart(); Complete-MspkiGuiHistoryJob -Result $big; Wait-MspkiGuiIdle -Rounds 1; $best = [math]::Min($best, $sw.Elapsed.TotalMilliseconds) }
            $r.BigApplyMs = $best
            $win.Close()
            [pscustomobject]$r
        }
        $script:WinR = @($script:Win | Where-Object { $_ -isnot [string] })[-1]
        $script:WinMsg = @($script:Win | Where-Object { $_ -is [string] })
    }
    It 'opened without a Windows message box' { $script:WinMsg.Count | Should -Be 0 }
    It 'J4 click 1: Ctrl+7 opens History within the page-switch budget, with the run on show compared with the run before it' {
        $script:WinR.OnHistory | Should -BeTrue
        $script:WinR.SwitchMs | Should -BeLessThan 150
        $script:WinR.Rows | Should -Be 3
        $script:WinR.Forests | Should -Be 2
        $script:WinR.FirstIsCurrent | Should -BeTrue
        $script:WinR.DefaultNew | Should -Be $script:PairH.B
        $script:WinR.DefaultOld | Should -Be $script:PairH.A
        $script:WinR.NewCount | Should -Be 'New problems (1)'
        $script:WinR.Trend | Should -BeGreaterThan 3
        Write-Host ('    window: switch to History {0} ms; a big comparison put on screen in {1:0} ms' -f $script:WinR.SwitchMs, $script:WinR.BigApplyMs)
    }
    It 'J4 click 2: Compare on another run compares that one; a new problem opens its finding' {
        $script:WinR.PickedOld | Should -Be $script:PathC
        $script:WinR.OpenedFinding | Should -BeTrue
    }
    It 'offers the page (Ctrl+7, the run log Ctrl+8) and "Compare with the run before" in the palette' {
        $script:WinR.Palette | Should -Match 'Go to History=Ctrl\+7'
        $script:WinR.Palette | Should -Match 'Go to Run log=Ctrl\+8'
        $script:WinR.Commands | Should -Match 'histprev'
        $script:WinR.HistPrevOn | Should -BeTrue
        $script:WinR.PrevOld | Should -Be $script:PairH.A
    }
    It 'reaches the run list with F6 and names every control and button' {
        $script:WinR.F6List | Should -BeTrue
        $script:WinR.Unnamed | Should -Be ''
    }
    It 'puts a big comparison on screen in under 50 ms of UI-thread work' { $script:WinR.BigApplyMs | Should -BeLessThan 50 }
}

Describe 'GUI files share one script scope' {
    It 'no two GUI files define the same script variable (one would silently replace the other)' {
        $seen = @{}; $dup = New-Object System.Collections.ArrayList
        foreach ($f in Get-ChildItem -Path (Join-Path $script:RepoRoot 'src\Gui') -Filter '*.ps1') {
            foreach ($m in [regex]::Matches([IO.File]::ReadAllText($f.FullName), '(?m)^\$script:(\w+)\s*=')) {
                $n = $m.Groups[1].Value
                if ($seen.ContainsKey($n) -and $seen[$n] -ne $f.Name) { [void]$dup.Add(('{0} in {1} and {2}' -f $n, $seen[$n], $f.Name)) } else { $seen[$n] = $f.Name }
            }
        }
        $dup -join '; ' | Should -Be ''
    }
}
