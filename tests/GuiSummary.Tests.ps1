# GX10 executive summary (journey J6): one printable page from the Overview's own helpers; HTML-encoded, no script, no external resource;
# written inside the output folder only. example.test data only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:GuiFolder = Join-Path $script:RepoRoot 'src\Gui'
    foreach ($n in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1', 'GuiMission.ps1', 'GuiState.ps1', 'GuiSummary.ps1') { . (Join-Path $script:GuiFolder $n) }
    $script:Findings = @(
        [pscustomobject]@{ Id = 'F1'; Status = 'Critical'; Severity = 'High'; Category = 'CRL'; StatusCode = 'EXPIRED'; Target = 'CN=Example Issuing CA'; Endpoint = 'http://pki.example.test/x.crl'; Message = 'Base CRL expired.'; Evidence = @(); Sources = @('HTTP') }
        [pscustomobject]@{ Id = 'F2'; Status = 'Pass'; Severity = 'None'; Category = 'CA'; StatusCode = 'OK'; Target = 'Example Issuing CA'; Endpoint = ''; Message = 'ok'; Evidence = @(); Sources = @('AD') }
        [pscustomobject]@{ Id = 'F3'; Status = 'Pass'; Severity = 'None'; Category = 'ADContainer'; StatusCode = 'OK'; Target = 'AIA'; Endpoint = ''; Message = 'ok'; Evidence = @(); Sources = @('AD') }
    )
    $script:Score = Get-MspkiGuiHealthScore -Findings $script:Findings
    $script:Actions = Get-MspkiGuiNextAction -Findings $script:Findings -Max 1000
}

Describe 'ConvertTo-MspkiGuiExecutiveSummaryHtml' {
    It 'says when, the score with what holds it down, the areas, at most three actions and what was not checked' {
        $cov = [pscustomobject]@{ Attention = @([pscustomobject]@{ MethodText = 'Reading the CA''s properties'; Reason = 'was refused (access denied, 0x80070005).' }) }
        $h = ConvertTo-MspkiGuiExecutiveSummaryHtml -Score $script:Score -Actions $script:Actions -Coverage $cov -Forest 'corp.example.test' -AsOf '20 Nov 2026, 09:29 UTC' -ToolVersion 'v0.1.0' -Generated '28 Nov 2026, 10:00 UTC'
        $h | Should -Match '<h1>PKI health summary: corp\.example\.test</h1>'
        $h | Should -Match 'As of 20 Nov 2026, 09:29 UTC'
        $h | Should -Match 'out of 100'
        $h | Should -Match 'By area'
        $h | Should -Match 'What to do first'
        $h | Should -Match 'Reading the CA&#39;s properties'
        $h | Should -Match 'not a certification'
        ([regex]::Matches($h, '<li><b>')).Count | Should -BeLessOrEqual 3
        $h | Should -Not -Match 'This summary is of an earlier run'
    }
    It 'puts the earlier-run notice first when the run on show was opened from disk' {
        $h = ConvertTo-MspkiGuiExecutiveSummaryHtml -Score $script:Score -Actions $script:Actions -AsOf '6 Nov 2026, 09:30 UTC' -IsEarlierRun $true
        $h.IndexOf('This summary is of an earlier run') | Should -BeLessThan $h.IndexOf('class="hero"')
    }
    It 'encodes every value and loads nothing: no script, no external resource' {
        $h = ConvertTo-MspkiGuiExecutiveSummaryHtml -Score $script:Score -Actions $script:Actions -Forest '<script>alert(1)</script>' -AsOf 'x'
        $h | Should -Not -Match '<script'
        $h | Should -Match '&lt;script&gt;'
        $h | Should -Not -Match '(?i)\b(src|href)\s*='
        $h | Should -Not -Match '(?i)https?://'
        $h | Should -Not -Match '(?i)@import|url\('
    }
    It 'draws the score over time only with two scored runs or more' {
        Get-MspkiGuiTrendSvg -Trend @([pscustomobject]@{ Score = 50 }) | Should -Be ''
        $svg = Get-MspkiGuiTrendSvg -Trend @([pscustomobject]@{ Score = 50 }, [pscustomobject]@{ Score = 80 })
        $svg | Should -Match '^<svg class="trend"'
        $svg | Should -Match 'from 50 to 80'
    }
    It 'says when no score can be given, and that a partial score is partial' {
        $none = Get-MspkiGuiHealthScore -Findings @() -HasCa $false
        (ConvertTo-MspkiGuiExecutiveSummaryHtml -Score $none) | Should -Match 'Not scored\.'
        $p = Get-MspkiGuiHealthScore -Findings $script:Findings -Completed $false
        (ConvertTo-MspkiGuiExecutiveSummaryHtml -Score $p) | Should -Match 'Partial score\.'
    }
}

Describe 'Save-MspkiGuiExecutiveSummary' {
    It 'writes an .html file inside the output folder only' {
        $root = Join-Path $TestDrive 'out'
        [void](New-Item -ItemType Directory -Path $root -Force)
        Save-MspkiGuiExecutiveSummary -Html '<p>x</p>' -Path (Join-Path $root 'run1\executive-summary.html') -AllowedRoot $root | Should -BeFalse -Because 'the folder does not exist and is not created'
        Save-MspkiGuiExecutiveSummary -Html '<p>x</p>' -Path (Join-Path $root 'executive-summary.html') -AllowedRoot $root | Should -BeTrue
        Save-MspkiGuiExecutiveSummary -Html '<p>x</p>' -Path (Join-Path $root 'executive-summary.ps1') -AllowedRoot $root | Should -BeFalse
        Save-MspkiGuiExecutiveSummary -Html '<p>x</p>' -Path (Join-Path $TestDrive 'elsewhere.html') -AllowedRoot $root | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $TestDrive 'elsewhere.html') | Should -BeFalse
    }
}

Describe 'J6 in the real window: Executive summary from the Overview' {
    It 'writes the page of the run on show inside the output folder with one click, and the palette offers it' {
        $outRoot = Join-Path $TestDrive 'sout'
        [void](New-Item -ItemType Directory -Path $outRoot -Force)
        $results = Join-Path $script:FixturePath 'demo-results-v2.json'
        $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
        $rs.ApartmentState = [System.Threading.ApartmentState]::STA
        $rs.Open()
        $ps = [System.Management.Automation.PowerShell]::Create(); $ps.Runspace = $rs
        [void]$ps.AddScript({
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1')
            Import-MspkiGuiAssembly
            function Show-MspkiGuiMessage { param($Text, $Title, $Icon) }
            function Open-MspkiGuiPath { param($Path, $What) $script:Opened = $Path }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show()
            Wait-MspkiGuiIdle -Rounds 4; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            $ui = $script:MspkiGui.Ui
            $ui.BtnExecSummary.RaiseEvent((New-Object System.Windows.RoutedEventArgs([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)))
            Wait-MspkiGuiIdle -Rounds 2
            $cmds = (@(Get-MspkiGuiPaletteCommand -Available (Get-MspkiGuiCommandAvailability) | ForEach-Object { $_.Action }) -join ',')
            $win.Close()
            [pscustomobject]@{ Opened = [string]$script:Opened; Commands = $cmds }
        }).AddArgument($script:GuiFolder).AddArgument($script:ModulePath).AddArgument($results).AddArgument($outRoot)
        try { $r = @($ps.Invoke() | Where-Object { $_ -isnot [string] })[0] } finally { $ps.Dispose(); $rs.Dispose() }
        $r.Opened | Should -Not -BeNullOrEmpty
        $r.Opened | Should -BeLike ((Join-Path $outRoot '*') )
        Test-Path -LiteralPath $r.Opened | Should -BeTrue
        (Get-Content -Raw -LiteralPath $r.Opened) | Should -Match 'As of '
        $r.Commands | Should -Match 'cmd:execsummary'
    }
}
