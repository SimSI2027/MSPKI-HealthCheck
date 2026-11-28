# GX5 themes: the light and dark palettes (data files), WCAG AA contrast of the pairs the window uses, high contrast from SystemColors,
# the theme choice (follow Windows, light, dark), a live switch in the real window, and reduced motion (no Storyboard runs).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:GuiFolder = Join-Path $script:RepoRoot 'src\Gui'
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    . (Join-Path $script:GuiFolder 'GuiTheme.ps1')
    $script:Light = Read-MspkiGuiPaletteColor -Path (Join-Path $script:GuiFolder 'Palette.Light.xaml')
    $script:Dark = Read-MspkiGuiPaletteColor -Path (Join-Path $script:GuiFolder 'Palette.Dark.xaml')

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
}

Describe 'Palettes (data files)' {
    It 'light and dark define exactly the same keys' {
        $script:Light.Count | Should -BeGreaterThan 60
        @(Compare-Object @($script:Light.Keys) @($script:Dark.Keys)).Count | Should -Be 0
    }
    It 'every key used in the XAML and the GUI code exists in the palettes' {
        $text = (Get-ChildItem -LiteralPath $script:GuiFolder -Include *.xaml, *.ps1 -Recurse | Where-Object { $_.Name -notlike 'Palette.*' } | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        $used = @([regex]::Matches($text, '[''"{ ](B\.[A-Z][A-Za-z]+)[''"}]') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $used.Count | Should -BeGreaterThan 40
        foreach ($k in $used) { $script:Light.ContainsKey($k) | Should -BeTrue -Because $k }
    }
    It 'the theme and the window define no colour of their own and refer to the palette only dynamically' {
        foreach ($f in 'Theme.xaml', 'MainWindow.xaml') {
            $t = Get-Content -LiteralPath (Join-Path $script:GuiFolder $f) -Raw
            $t | Should -Not -Match 'StaticResource B\.' -Because $f
            $t | Should -Not -Match 'x:Key="B\.' -Because $f
            # Left on purpose: the header (dark in every theme) role badge, the palette backdrop and shadows.
            $hex = @([regex]::Matches($t, '"#[0-9A-Fa-f]{6,8}"') | ForEach-Object { $_.Value.Trim('"').ToUpperInvariant() } | Sort-Object -Unique)
            foreach ($h in $hex) { $h | Should -BeIn @('#000000', '#8F6CC9', '#3A2D57', '#D9C8F5', '#59101828', '#101828') -Because "$f has $h" }
        }
    }
}

Describe 'WCAG contrast' {
    It 'computes the reference ratios (black on white 21, equal colours 1)' {
        [math]::Round((Get-MspkiGuiContrastRatio -Foreground '#000000' -Background '#FFFFFF'), 1) | Should -Be 21
        Get-MspkiGuiContrastRatio -Foreground '#777777' -Background '#777777' | Should -Be 1
        [math]::Round((Get-MspkiGuiContrastRatio -Foreground '#767676' -Background '#FFFFFF'), 2) | Should -Be 4.54
    }
    It 'every pair meets its minimum in the <Name> palette' -ForEach @(@{ Name = 'light' }, @{ Name = 'dark' }) {
        $p = $(if ($Name -eq 'light') { $script:Light } else { $script:Dark })
        $fails = @(foreach ($pair in $script:MspkiGuiContrastPairs) {
            $r = Get-MspkiGuiContrastRatio -Foreground $p[$pair[0]] -Background $p[$pair[1]]
            if ($r -lt [double]$pair[2]) { '{0} on {1}: {2:N2} < {3}' -f $pair[0], $pair[1], $r, $pair[2] }
        })
        $fails -join '; ' | Should -Be ''
    }
}

Describe 'Theme choice' {
    It 'follows Windows for Auto, keeps an explicit choice, and high contrast always wins' {
        Resolve-MspkiGuiTheme -Mode Auto -WindowsDark $false | Should -Be 'Light'
        Resolve-MspkiGuiTheme -Mode Auto -WindowsDark $true | Should -Be 'Dark'
        Resolve-MspkiGuiTheme -Mode Light -WindowsDark $true | Should -Be 'Light'
        Resolve-MspkiGuiTheme -Mode Dark -WindowsDark $false | Should -Be 'Dark'
        Resolve-MspkiGuiTheme -Mode Dark -HighContrast $true | Should -Be 'HighContrast'
        Resolve-MspkiGuiTheme -Mode Auto -HighContrast $true | Should -Be 'HighContrast'
    }
    It 'reads the Windows setting without failing (a read, never a write)' {
        { Test-MspkiGuiWindowsDarkMode } | Should -Not -Throw
        (Get-Content -LiteralPath (Join-Path $script:GuiFolder 'GuiTheme.ps1') -Raw) | Should -Not -Match '(?i)SetValue|CreateSubKey|DeleteValue|Set-ItemProperty|New-ItemProperty'
    }
    It 'builds high contrast from SystemColors for every key' {
        $hc = New-MspkiGuiHighContrastPalette -Keys @($script:Light.Keys)
        $hc.Count | Should -Be $script:Light.Count
        $hc['B.Card'] | Should -Be ([System.Windows.SystemColors]::WindowBrush)
        $hc['B.Text'] | Should -Be ([System.Windows.SystemColors]::WindowTextBrush)
        $hc['B.Accent'] | Should -Be ([System.Windows.SystemColors]::HighlightBrush)
        $hc['B.OnAccent'] | Should -Be ([System.Windows.SystemColors]::HighlightTextBrush)
        $hc['B.Disabled'] | Should -Be ([System.Windows.SystemColors]::GrayTextBrush)
    }
}

Describe 'Theme in the window' {
    BeforeAll {
        $script:Win = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, (Join-Path $script:FixturePath 'demo-results-v2.json'), $TestDrive) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results -Theme Light
            $g = $script:MspkiGui; $ui = $g.Ui
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show()
            Wait-MspkiGuiIdle -Rounds 4
            $r = [ordered]@{}
            $r.LightEff = $g.ThemeEffective
            $r.LightCard = [string]$win.FindResource('B.Card').Color
            $ui.Tabs.SelectedItem = $ui.TabFindings; $ui.FindingsGrid.SelectedIndex = 0; Wait-MspkiGuiIdle -Rounds 3
            $title = Find-MspkiGuiSnapshotVisual -Root $ui.FindingHost -Test { param($v) $v -is [System.Windows.Controls.TextBlock] -and $v.FontSize -eq 16 }
            $r.LightTitle = [string]$title.Foreground.Color
            Set-MspkiGuiTheme -Mode Dark; Wait-MspkiGuiIdle -Rounds 3
            $r.DarkEff = $g.ThemeEffective
            $r.DarkCard = [string]$win.FindResource('B.Card').Color
            $r.DarkTitle = [string]$title.Foreground.Color
            $r.DarkGrid = [string]$ui.FindingsGrid.Foreground.Color
            $r.ThemeName = [System.Windows.Automation.AutomationProperties]::GetName($ui.BtnTheme)
            $r.Mode = $g.ThemeMode
            Switch-MspkiGuiTheme; Wait-MspkiGuiIdle -Rounds 2
            $r.AfterSwitch = $g.ThemeMode
            $r.Cmds = (@(Get-MspkiGuiPaletteCommand) | ForEach-Object { $_.Action }) -join ','
            # Reduced motion: no Storyboard and no animation anywhere.
            $g.ForceReducedMotion = $true
            Set-MspkiGuiTheme -Mode Light; $ui.Tabs.SelectedItem = $ui.TabSummary; Wait-MspkiGuiIdle -Rounds 3
            Start-MspkiGuiMissionAnimation
            $r.Storyboard = ($null -ne $g.Storyboard)
            $r.PopupAnim = [string]$ui.PopScore.PopupAnimation
            [void](Show-MspkiGuiToast -Text 'Still' -Tone Info)
            $toast = $ui.ToastHost.Children[$ui.ToastHost.Children.Count - 1]
            $r.ToastAnimated = $toast.HasAnimatedProperties
            $r.ToastOpacity = $toast.Opacity
            $animated = 0
            foreach ($d in @($g.MapDrawn.Nodes)) { if ($d.Body.HasAnimatedProperties -or $d.Label.HasAnimatedProperties) { $animated++ } }
            $r.MapAnimated = $animated
            $win.Close()
            [pscustomobject]$r
        }
    }
    It 'switches the palette live: the card and the text change at once, also where WPF would fall back to system black' {
        $r = $script:Win[0]
        $r.LightEff | Should -Be 'Light'
        $r.LightCard | Should -Be '#FFFFFFFF'
        $r.DarkEff | Should -Be 'Dark'
        $r.DarkCard | Should -Be '#FF25282D'
        $r.LightTitle | Should -Not -Be $r.DarkTitle
        $r.DarkTitle | Should -Be '#FFECEDEF'
        $r.DarkGrid | Should -Be '#FFECEDEF'
    }
    It 'names the theme button for screen readers and cycles follow Windows, light, dark' {
        $r = $script:Win[0]
        $r.Mode | Should -Be 'Dark'
        $r.ThemeName | Should -Match '^Theme: dark'
        $r.AfterSwitch | Should -Be 'Auto'
        $r.Cmds | Should -Match 'cmd:themeauto,cmd:themelight,cmd:themedark'
    }
    It 'runs no Storyboard and no animation with reduced motion' {
        $r = $script:Win[0]
        $r.Storyboard | Should -BeFalse
        $r.PopupAnim | Should -Be 'None'
        $r.ToastAnimated | Should -BeFalse
        $r.ToastOpacity | Should -Be 1
        $r.MapAnimated | Should -Be 0
    }
}
