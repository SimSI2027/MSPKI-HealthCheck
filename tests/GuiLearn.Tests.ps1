# GX9 "Explain it to me": the glossary (data only), the J5 check (no term on the Overview unexplained), the Learn page's items, the tour,
# the window settings (out\gui-settings.json only) and the healthy celebration rule; then the real window. example.test data only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:GuiFolder = Join-Path $script:RepoRoot 'src\Gui'
    foreach ($n in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1', 'GuiState.ps1', 'GuiLearn.ps1') { . (Join-Path $script:GuiFolder $n) }
    $script:GlossaryPath = Join-Path $script:RepoRoot 'src\Knowledge\Glossary.psd1'
    $script:Glossary = @(Get-MspkiGuiGlossary)
}

Describe 'Glossary (src\Knowledge\Glossary.psd1)' {
    It 'is data only: literals, plain ASCII, read with Import-PowerShellDataFile' {
        $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:GlossaryPath, [ref]$null, [ref]$errs)
        @($errs).Count | Should -Be 0
        $bad = @($ast.FindAll({ param($n)
            $n -is [System.Management.Automation.Language.VariableExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -or
            $n -is [System.Management.Automation.Language.SubExpressionAst] -or $n -is [System.Management.Automation.Language.CommandAst] -or
            $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
            $n -is [System.Management.Automation.Language.BinaryExpressionAst] }, $true))
        $bad.Count | Should -Be 0
        [regex]::Matches([System.IO.File]::ReadAllText($script:GlossaryPath), '[^\x00-\x7F]').Count | Should -Be 0
        (Get-Content -Raw -LiteralPath (Join-Path $script:GuiFolder 'GuiLearn.ps1')) | Should -Match 'Import-PowerShellDataFile'
    }
    It 'has a meaning for every term, unique names, and related terms that exist' {
        $script:Glossary.Count | Should -BeGreaterOrEqual 30
        $names = @{}
        foreach ($t in $script:Glossary) {
            $t.Short | Should -Not -BeNullOrEmpty -Because $t.Term
            $t.Short.Length | Should -BeLessOrEqual 200 -Because $t.Term
            foreach ($n in @(@($t.Term) + @($t.Also))) { $names.ContainsKey($n.ToLowerInvariant()) | Should -BeFalse -Because ('{0} is listed twice' -f $n); $names[$n.ToLowerInvariant()] = $true }
        }
        $terms = @($script:Glossary | ForEach-Object { $_.Term })
        foreach ($t in $script:Glossary) { foreach ($r in @($t.Related)) { $terms | Should -Contain $r -Because ('{0} relates to {1}' -f $t.Term, $r) } }
    }
    It 'uses the GUI-DESIGN section 9 words as its keys' {
        $terms = @($script:Glossary | ForEach-Object { $_.Term })
        foreach ($k in 'finding', 'could not check', 'published address', 'host', 'issuer not confirmed', 'group', 'earlier run', 'chain', 'copy', 'next update', 'next publish', 'as of the run', 'History') {
            $terms | Should -Contain $k
        }
    }
}

Describe 'J5: no term on the Overview unexplained' {
    It 'explains the acronyms, the score words and the status words the Overview and the map show' {
        $labels = @('AIA over LDAP', 'CDP over HTTP', 'OCSP over HTTP', 'CES over HTTPS', 'Partial score', 'Held down by Revocation (4)', 'Published addresses',
            'Could not check', 'Issuer not confirmed', 'Revocation', 'Enrollment security', 'Root CAs', 'Issuing CAs', 'Certificate templates', 'NTAuth')
        foreach ($l in $labels) { Find-MspkiGuiGlossaryTerm -Text $l -Glossary $script:Glossary | Should -Not -BeNullOrEmpty -Because $l }
        (Find-MspkiGuiGlossaryTerm -Text 'AIA over LDAP' -Glossary $script:Glossary).Term | Should -Be 'AIA'
        (Find-MspkiGuiGlossaryTerm -Text 'Partial score' -Glossary $script:Glossary).Term | Should -Be 'partial score'
    }
    It 'never matches inside a word or a sentence' {
        foreach ($l in 'Cancel', 'Discovery coverage', 'Local', 'Scan') { Find-MspkiGuiGlossaryTerm -Text $l -Glossary $script:Glossary | Should -BeNullOrEmpty -Because $l }
        Find-MspkiGuiGlossaryTerm -Text ('A sentence that mentions the CDP but is far too long to underline as a label in the window' ) -Glossary $script:Glossary | Should -BeNullOrEmpty
    }
}

Describe 'Learn items, tour, settings and celebration' {
    It 'lists a concept card per object type (the existing notes) and every term' {
        $items = @(Get-MspkiGuiLearnItem -Glossary $script:Glossary -Concepts $script:MspkiGuiEntityType)
        $concepts = @($script:MspkiGuiEntityType.Keys | Where-Object { $script:MspkiGuiEntityType[$_].About }).Count
        @($items | Where-Object Kind -eq 'Concept').Count | Should -Be $concepts
        @($items | Where-Object Kind -eq 'Term').Count | Should -Be $script:Glossary.Count
        (@($items | Where-Object Kind -eq 'Concept')[0].Short) | Should -Be ($script:MspkiGuiEntityType[@($script:MspkiGuiEntityType.Keys)[0]].About)
    }
    It 'has four tour stops whose targets exist in the window' {
        $xaml = Get-Content -Raw -LiteralPath (Join-Path $script:GuiFolder 'MainWindow.xaml')
        $stops = @(Get-MspkiGuiTourStop)
        $stops.Count | Should -Be 4
        foreach ($s in $stops) { $xaml | Should -Match ('x:Name="{0}"' -f $s.Target) }
        $stops[0].Text | Should -Match 'Held down by'
        $stops[3].Text | Should -Match 'Ctrl\+K'
    }
    It 'keeps the settings in gui-settings.json inside the output folder only' {
        $root = Join-Path $TestDrive 'out'
        $s = Read-MspkiGuiSettings -OutputRoot $root
        $s.TourDone | Should -BeFalse
        $s.TourDone = $true; $s.Celebrated = @('run1')
        Save-MspkiGuiSettings -Settings $s -AllowedRoot $root | Should -BeTrue
        $back = Read-MspkiGuiSettings -OutputRoot $root
        $back.TourDone | Should -BeTrue
        @($back.Celebrated) | Should -Contain 'run1'
        $s.Path = Join-Path $TestDrive 'elsewhere\gui-settings.json'
        Save-MspkiGuiSettings -Settings $s -AllowedRoot $root | Should -BeFalse
        Test-Path -LiteralPath $s.Path | Should -BeFalse
    }
    It 'celebrates a healthy live run once, never a partial score, a weak score or an earlier run' {
        $sc = [pscustomobject]@{ HasScore = $true; Overall = 95; Partial = $false }
        $h = [pscustomobject]@{ Level = 'Green' }
        $set = [pscustomobject]@{ Celebrated = @() }
        Test-MspkiGuiCelebrate -Score $sc -Health $h -RunKey 'r1' -Settings $set | Should -BeTrue
        Test-MspkiGuiCelebrate -Score $sc -Health $h -RunKey 'r1' -Settings ([pscustomobject]@{ Celebrated = @('r1') }) | Should -BeFalse
        Test-MspkiGuiCelebrate -Score $sc -Health $h -RunKey 'r1' -Settings $set -IsEarlierRun $true | Should -BeFalse
        Test-MspkiGuiCelebrate -Score ([pscustomobject]@{ HasScore = $true; Overall = 95; Partial = $true }) -Health $h -RunKey 'r1' -Settings $set | Should -BeFalse
        Test-MspkiGuiCelebrate -Score ([pscustomobject]@{ HasScore = $true; Overall = 89; Partial = $false }) -Health $h -RunKey 'r1' -Settings $set | Should -BeFalse
        Test-MspkiGuiCelebrate -Score $sc -Health ([pscustomobject]@{ Level = 'Amber' }) -RunKey 'r1' -Settings $set | Should -BeFalse
    }
}

Describe 'GX9 in the real window: Explain mode, Learn page, tour' {
    BeforeAll {
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
        $outRoot = Join-Path $TestDrive 'lout'
        [void](New-Item -ItemType Directory -Path $outRoot -Force)
        $results = Join-Path $script:FixturePath 'demo-results-v2.json'
        $script:Win = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $results, $outRoot) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            function Show-MspkiGuiMessage { param($Text, $Title, $Icon) Write-Output ('MESSAGEBOX: ' + $Text) }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $g = $script:MspkiGui; $ui = $g.Ui
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show(); [void]$win.Activate()
            Wait-MspkiGuiIdle -Rounds 4
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 3
            $r = [ordered]@{}
            # The tour was offered once (a notice, never started by itself) and that is remembered.
            $r.OfferedOnce = [bool]$g.Settings.TourDone
            $r.TourAutoStarted = ($ui.TourLayer.Visibility -eq 'Visible')
            # Explain mode: labels underlined with a tooltip, timed; off restores them.
            $ui.TglExplain.IsChecked = $true
            $sw = [Diagnostics.Stopwatch]::StartNew(); $r.Explained = Update-MspkiGuiExplain; $r.ExplainMs = $sw.ElapsedMilliseconds
            $tb = @($g.ExplainSaved.Keys)[0]
            $r.Tip = [string]$tb.ToolTip
            $ui.TglExplain.IsChecked = $false; $r.After = Update-MspkiGuiExplain
            $r.Restored = ($null -eq $tb.TextDecorations -or $tb.TextDecorations.Count -eq 0)
            # Ctrl+9 opens Learn; a term opens; the search narrows; Ctrl+F goes to the search.
            [void](Invoke-MspkiGuiShortcut -Key 'D9' -Ctrl $true -Alt $false -Shift $false)
            $r.OnLearn = ($ui.Tabs.SelectedItem -eq $ui.TabLearn)
            Show-MspkiGuiLearnItem -Name 'CDP'; Wait-MspkiGuiIdle -Rounds 2
            $r.Detail = [string]$ui.LearnDetail.DataContext.Title
            $ui.FltLearn.Text = 'zzzz-no-term'; Wait-MspkiGuiIdle -Rounds 2
            $r.Empty = ($ui.LearnEmpty.Visibility -eq 'Visible')
            $ui.FltLearn.Text = ''
            # The tour: four stops, Right steps, Esc closes, focus returns.
            Start-MspkiGuiTour; Wait-MspkiGuiIdle -Rounds 2
            $r.TourOn = ($ui.TourLayer.Visibility -eq 'Visible'); $r.Step1 = [string]$ui.TxtTourStep.Text
            Step-MspkiGuiTour -By 1; Step-MspkiGuiTour -By 1; Step-MspkiGuiTour -By 1; Wait-MspkiGuiIdle -Rounds 2
            $r.Step4 = [string]$ui.TxtTourStep.Text; $r.Done = [string]$ui.TxtTourNext.Text
            Step-MspkiGuiTour -By 1
            $r.TourOff = ($ui.TourLayer.Visibility -ne 'Visible')
            $r.SettingsFile = Test-Path -LiteralPath (Join-Path $outRoot 'gui-settings.json')
            $r.Pages = (@(Get-MspkiGuiPalettePage | ForEach-Object { $_.Shortcut }) -join ',')
            $r.Messages = $(foreach ($o in @($script:MspkiGuiMessages)) { $o })
            $win.Close()
            [pscustomobject]$r
        }
        $script:Win = @($script:Win | Where-Object { $_ -isnot [string] })[0]
    }
    It 'offers the tour once in a notice, never starting it by itself' {
        $script:Win.OfferedOnce | Should -BeTrue
        $script:Win.TourAutoStarted | Should -BeFalse
    }
    It 'underlines the terms of the page with their meaning, within budget, and restores them' {
        $script:Win.Explained | Should -BeGreaterThan 5
        $script:Win.ExplainMs | Should -BeLessThan 400
        $script:Win.Tip | Should -Match 'Learn page \(Ctrl\+9\)'
        $script:Win.After | Should -Be 0
        $script:Win.Restored | Should -BeTrue
    }
    It 'opens Learn with Ctrl+9, shows a term, and has a designed no-match state' {
        $script:Win.OnLearn | Should -BeTrue
        $script:Win.Detail | Should -Be 'CDP'
        $script:Win.Empty | Should -BeTrue
        $script:Win.Pages | Should -Match 'Ctrl\+9$'
    }
    It 'walks the four tour stops and closes, remembering it in out\gui-settings.json' {
        $script:Win.TourOn | Should -BeTrue
        $script:Win.Step1 | Should -Be 'Tour 1 of 4'
        $script:Win.Step4 | Should -Be 'Tour 4 of 4'
        $script:Win.Done | Should -Be 'Done'
        $script:Win.TourOff | Should -BeTrue
        $script:Win.SettingsFile | Should -BeTrue
    }
}
