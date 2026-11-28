# GX4: keyboard-first paths through the real window (off-screen, single-threaded runspace): the Ctrl+K command palette, toasts in place
# of Windows message boxes, F6 regions, Alt+Left back, and a keyboard-only replay of the journeys that exist so far.
# Fixture: tests\fixtures\demo-results-v2.json (example.test only).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
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

    $script:Replay = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, (Join-Path $script:FixturePath 'demo-results-v2.json'), $TestDrive) -Script {
        param($folder, $module, $results, $outRoot)
        Import-Module $module -Force
        . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
        Import-MspkiGuiAssembly
        $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
        $g = $script:MspkiGui; $ui = $g.Ui
        $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show(); [void]$win.Activate()
        Wait-MspkiGuiIdle -Rounds 4
        $key = { param([string]$k, [bool]$c = $false, [bool]$a = $false, [bool]$s = $false) $h = Invoke-MspkiGuiShortcut -Key $k -Ctrl $c -Alt $a -Shift $s; Wait-MspkiGuiIdle -Rounds 2; $h }
        $type = { param([string]$t) $ui.PaletteText.Text = $t; Wait-MspkiGuiIdle -Rounds 2 }
        $focus = { $f = [System.Windows.Input.Keyboard]::FocusedElement; if ($null -eq $f) { '' } elseif ($f.Name) { $f.Name } else { $f.GetType().Name } }
        $r = [ordered]@{}

        # Ctrl+K opens (timed), Esc closes and returns the focus.
        $ui.Tabs.SelectedItem = $ui.TabFindings; Wait-MspkiGuiIdle -Rounds 2
        [void][System.Windows.Input.Keyboard]::Focus($ui.FltText); Wait-MspkiGuiIdle -Rounds 1
        $r.FocusBefore = & $focus
        [void](& $key 'K' $true)
        $r.OpenFirstMs = $g.PaletteOpenMs
        $r.Open = [string]$ui.PaletteLayer.Visibility
        $r.FocusInPalette = & $focus
        $r.EmptyKinds = (@(@($ui.PaletteList.ItemsSource) | ForEach-Object { $_.Kind } | Select-Object -Unique) -join ',')
        $r.CmdActions = (@(@($ui.PaletteList.ItemsSource) | Where-Object { $_.Kind -eq 'Command' } | ForEach-Object { $_.Action }) -join ',')
        $r.Virtualized = [System.Windows.Controls.VirtualizingStackPanel]::GetIsVirtualizing($ui.PaletteList)
        [void](& $key 'Escape')
        $r.Closed = [string]$ui.PaletteLayer.Visibility
        $r.FocusAfter = & $focus
        $times = @(foreach ($i in 1..5) { [void](& $key 'K' $true); $g.PaletteOpenMs; [void](& $key 'Escape') })
        $r.OpenMaxMs = ($times | Measure-Object -Maximum).Maximum

        # J1 (first run): Ctrl+K "run" offers the run command first; F5 is the direct key (not pressed: it would start a real run).
        [void](& $key 'K' $true); & $type 'run'
        $r.J1Top = [string]$ui.PaletteList.SelectedItem.Action
        [void](& $key 'Escape')

        # J2 (is my PKI healthy?): Ctrl+1 shows the Overview.
        [void](& $key 'D1' $true)
        $r.J2Overview = ($ui.Tabs.SelectedItem -eq $ui.TabSummary)

        # J3 (why is this failing?): Ctrl+K, type part of the first action's finding, Down/Up, Enter: the finding opens with its walkthrough; F6 reaches the details pane.
        $act = @($ui.ActionList.ItemsSource)[0]
        $row = $g.RowById[[string]$act.Tag]
        [void](& $key 'K' $true); & $type ([string]$row.Id)
        [void](& $key 'Down'); [void](& $key 'Up')
        $r.J3Selected = [string]$ui.PaletteList.SelectedItem.Action
        [void](& $key 'Return')
        $r.J3Closed = [string]$ui.PaletteLayer.Visibility
        $r.J3Tab = ($ui.Tabs.SelectedItem -eq $ui.TabFindings)
        $r.J3Pane = [string]$ui.FindingHost.Content.Id
        $r.J3Want = [string]$row.Id
        $r.J3HasWalk = [bool]$ui.FindingHost.Content.HasDiagnosis
        $where = { if ($ui.NavList.IsKeyboardFocusWithin) { "nav" } elseif ($ui.FindingsGrid.IsKeyboardFocusWithin) { "grid" } elseif ($ui.FindingHost.IsKeyboardFocusWithin) { "details" } elseif ($ui.BtnRun.IsKeyboardFocusWithin -or $ui.BtnOpenResults.IsKeyboardFocusWithin) { "bar" } else { & $focus } }
        $regions = @()
        foreach ($i in 1..4) { [void](& $key "F6"); $regions += (& $where) }
        $r.F6 = $regions -join ','
        [void](& $key 'F6' $false $false $true)
        $r.ShiftF6 = (& $where)

        # An object by name: Ctrl+K, its name, Enter: the Objects page with it selected; Alt+Left steps back after a drill-down.
        $obj = @($g.ObjRows | Where-Object { $_.Type -eq 'CA' })[0]
        [void](& $key 'K' $true); & $type ([string]$obj.Name)
        $r.ObjTop = [string]$ui.PaletteList.SelectedItem.Action
        $r.ObjWant = 'ent:' + [string]$obj.Id
        [void](& $key 'Return')
        $r.ObjTab = ($ui.Tabs.SelectedItem -eq $ui.TabObjects)
        $rel = @($ui.ObjHost.Content.Related | Where-Object { $_.Known }) | Select-Object -First 1
        if ($null -ne $rel) {
            Invoke-MspkiGuiPaneCommand -HostName 'ObjHost' -Tag ([string]$rel.Tag); Wait-MspkiGuiIdle -Rounds 2
            $r.Drilled = @($g.Nav['ObjHost'].Trail).Count
            [void](& $key 'Left' $false $true)
            $r.AfterBack = @($g.Nav['ObjHost'].Trail).Count
        }

        # J4 (what changed?) is History (GX8, tests/GuiHistory.Tests.ps1); the palette's "Open results..." still loads an earlier run (the dialog is not opened here).
        [void](& $key 'K' $true); & $type 'open results'
        $r.J4Top = [string]$ui.PaletteList.SelectedItem.Action
        # A page by name.
        & $type 'services'
        $r.PageTop = [string]$ui.PaletteList.SelectedItem.Action
        [void](& $key 'Return')
        $r.PageTab = ($ui.Tabs.SelectedItem -eq $ui.TabServices)
        # Nothing matches: the empty note shows.
        [void](& $key 'K' $true); & $type 'zzzz-no-such-thing'
        $r.EmptyNote = [string]$ui.PaletteEmpty.Visibility
        [void](& $key 'Escape')

        # Toasts replace message boxes once the window is on screen.
        Show-MspkiGuiMessage -Text 'The clipboard is in use by another program. Try again.' -Icon 'Warning'
        Show-MspkiGuiMessage -Text 'Two' ; Show-MspkiGuiMessage -Text 'Three'; Show-MspkiGuiMessage -Text 'Four' -Icon 'Error'
        Wait-MspkiGuiIdle -Rounds 2
        $r.Toasts = $ui.ToastHost.Children.Count
        $r.LastToast = $g.LastToast
        $r.ToastName = [System.Windows.Automation.AutomationProperties]::GetName($ui.ToastHost.Children[$ui.ToastHost.Children.Count - 1])
        $closeBtn = Find-MspkiGuiSnapshotVisual -Root $ui.ToastHost.Children[0] -Test { param($v) $v -is [System.Windows.Controls.Button] }
        $r.CloseName = [System.Windows.Automation.AutomationProperties]::GetName($closeBtn)
        $closeBtn.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
        $r.AfterDismiss = $ui.ToastHost.Children.Count
        $win.Close()
        [pscustomobject]$r
    }
}

Describe 'Command palette (Ctrl+K)' {
    It 'opens with the focus in its search box in under 100 ms and closes on Esc, returning the focus' {
        $r = $script:Replay[0]
        $r.FocusBefore | Should -Be 'FltText'
        $r.Open | Should -Be 'Visible'
        $r.FocusInPalette | Should -Be 'PaletteText'
        $r.OpenMaxMs | Should -BeLessThan 100
        $r.Closed | Should -Be 'Collapsed'
        $r.FocusAfter | Should -Be 'FltText'
    }
    It 'shows commands and pages before anything is typed, in a virtualised list' {
        $r = $script:Replay[0]
        $r.EmptyKinds | Should -Be 'Command,Page'
        $r.CmdActions | Should -Match 'cmd:run'
        $r.CmdActions | Should -Not -Match 'cmd:cancel'
        $r.Virtualized | Should -BeTrue
    }
    It 'opens a page, an object and a finding by name, and says when nothing matches' {
        $r = $script:Replay[0]
        $r.PageTop | Should -Be 'page:5'
        $r.PageTab | Should -BeTrue
        $r.ObjTop | Should -Be $r.ObjWant
        $r.ObjTab | Should -BeTrue
        $r.EmptyNote | Should -Be 'Visible'
    }
}

Describe 'Keyboard-only journeys' {
    It 'J1: Ctrl+K "run" offers the run first' { $script:Replay[0].J1Top | Should -Be 'cmd:run' }
    It 'J2: Ctrl+1 shows the Overview' { $script:Replay[0].J2Overview | Should -BeTrue }
    It 'J3: Ctrl+K, the finding, Enter opens it with its walkthrough; F6 walks nav, command bar, list, details' {
        $r = $script:Replay[0]
        $r.J3Selected | Should -Be ('finding:' + $r.J3Want)
        $r.J3Closed | Should -Be 'Collapsed'
        $r.J3Tab | Should -BeTrue
        $r.J3Pane | Should -Be $r.J3Want
        $r.J3HasWalk | Should -BeTrue
        $r.F6 | Should -Be 'details,nav,bar,grid'
        $r.ShiftF6 | Should -Be "bar"
    }
    It 'Alt+Left steps back after a drill-down in the details pane' {
        $r = $script:Replay[0]
        if ($null -ne $r.Drilled) { $r.AfterBack | Should -BeLessThan $r.Drilled }
    }
    It 'J4: the palette reaches "Open results..." (history and compare arrive in GX8)' { $script:Replay[0].J4Top | Should -Be 'cmd:open' }
}

Describe 'Toasts' {
    It 'replace the Windows message boxes once the window is shown: at most three, named for screen readers, dismissable' {
        $r = $script:Replay[0]
        $r.Toasts | Should -Be 3
        $r.LastToast | Should -Be 'Four'
        $r.ToastName | Should -Be 'Four'
        $r.CloseName | Should -Be 'Dismiss this notice'
        $r.AfterDismiss | Should -Be 2
    }
}
