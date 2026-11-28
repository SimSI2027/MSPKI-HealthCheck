# Guided troubleshooting walkthrough (GX3): the view model of the details pane (src/Gui/GuiView.ps1), the "mark as checked" state kept
# with the run (src/Gui/GuiState.ps1), and a static proof that the pane never runs a check: its buttons only copy text.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\MspkiHealthCheck.psd1') -Force
    foreach ($f in 'GuiModel.ps1', 'GuiView.ps1', 'GuiState.ps1') { . (Join-Path $script:RepoRoot ('src\Gui\' + $f)) }
    $script:Diag = [pscustomobject]@{
        Topic = 'crl-expired'; Title = 'The CRL has expired'; Summary = 'Clients cannot check revocation.'; Basis = 'Observed'; BasisNote = 'Something this run observed separates the causes.'
        Causes = @(
            [pscustomobject]@{ Rank = 1; Cause = 'The CA stopped publishing'; Likelihood = 'Most likely'; Because = @('The CRL NextUpdate is in the past.'); Confirm = @('certutil -URL <crl url>', 'Look at the CA''s CRL publication schedule in the CA console.'); Fix = @('Publish a new CRL on the CA.'); FixOwner = 'PKI owner' }
            [pscustomobject]@{ Rank = 2; Cause = 'The copy job to the web server fails'; Likelihood = 'Possible'; Because = @(); Confirm = @('Compare the file date on the web server with the CA''s CRL.'); Fix = @(); FixOwner = 'web server owner' }
        )
        Sources = @([pscustomobject]@{ Title = 'CRL publication'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/example' })
    }
    $script:Root = Join-Path $TestDrive 'out'
    [void](New-Item -ItemType Directory -Path (Join-Path $script:Root 'run1') -Force)
    $script:Results = Join-Path $script:Root 'run1\results.json'
    Set-Content -LiteralPath $script:Results -Value '{}' -Encoding UTF8
}

Describe 'ConvertTo-MspkiGuiDiagnosisView (walkthrough)' {
    It 'gives each check its own row with copy and mark tags and an accessible name' {
        $v = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $script:Diag
        $v.HasDiagnosis | Should -BeTrue
        @($v.Causes).Count | Should -Be 2
        $c1 = $v.Causes[0]
        @($c1.Checks).Count | Should -Be 2
        $c1.Checks[0].Key | Should -Be '1:0'
        $c1.Checks[1].CopyTag | Should -Be 'copycheck:1:1'
        $c1.Checks[0].ToggleTag | Should -Be 'toggle:1:0'
        $c1.Checks[0].CopyName | Should -Match '^Copy this check: certutil'
        $c1.Checks[1].ToggleName.Length | Should -BeLessOrEqual 80
        $c1.CopyChecksTag | Should -Be 'copychecks:1'
        $c1.ChecksCopyText | Should -Match '^1\. certutil -URL <crl url>\r\n2\. Look at'
    }
    It 'marks the causes this run observed and counts them' {
        $v = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $script:Diag
        $v.Causes[0].Observed | Should -BeTrue
        $v.Causes[1].Observed | Should -BeFalse
        $v.ObservedCount | Should -Be 1
        $v.Causes[0].IsTop | Should -BeTrue
    }
    It 'D-01: a weak hint is a muted hint, never "Observed in this run" (one rule with the engine)' {
        $d = [pscustomobject]@{ Topic = 't'; Title = 'T'; Summary = 'S'; Basis = 'Typical'; BasisNote = 'Nothing this run observed separates these causes.'
            Causes = @([pscustomobject]@{ Rank = 1; Cause = 'C1'; Likelihood = 'Most common'; Because = @('the finding is about a CRL'); Confirm = @(); Fix = @(); FixOwner = 'PKI owner' }
                       [pscustomobject]@{ Rank = 2; Cause = 'C2'; Likelihood = 'Common'; Supported = $false; Because = @('a hint'); Confirm = @(); Fix = @(); FixOwner = 'PKI owner' })
            Sources = @() }
        $v = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $d
        foreach ($c in $v.Causes) { $c.Observed | Should -BeFalse; $c.HasBecause | Should -BeFalse; $c.HasHint | Should -BeTrue; $c.HintText | Should -Match '^Hint: ' }
        $v.ObservedCount | Should -Be 0
        $v.CopyText | Should -Not -Match 'Observed in this run'
        $v.CopyText | Should -Match 'Hint \(not enough'
    }
    It 'D-01: the engine flag wins over the wording, and the pill never goes with "Most common" or "Common"' {
        Test-MspkiGuiCauseSupported -Cause ([pscustomobject]@{ Likelihood = 'Possible'; Supported = $true }) | Should -BeTrue
        Test-MspkiGuiCauseSupported -Cause ([pscustomobject]@{ Likelihood = 'Most likely'; Supported = $false }) | Should -BeFalse
        Test-MspkiGuiCauseSupported -Cause ([pscustomobject]@{ Likelihood = 'Most common' }) | Should -BeFalse
        $fx = Join-Path $script:RepoRoot 'tests\fixtures\demo-results.json'
        $doc = Read-MspkiResultsJson -Path $fx
        $n = 0
        foreach ($f in @($doc.Findings)) {
            $dg = Get-MspkiFindingDiagnosis -Finding $f -Recompute
            if ($null -eq $dg) { continue }
            foreach ($c in @($dg.Causes)) {
                $n++
                $c.PSObject.Properties['Supported'] | Should -Not -BeNullOrEmpty
                if (@('Most common', 'Common') -contains $c.Likelihood) { $c.Supported | Should -BeFalse }
                if (@('Most likely', 'Likely') -contains $c.Likelihood) { $c.Supported | Should -BeTrue }
            }
            $view = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $dg
            foreach ($vc in @($view.Causes)) { if (@('Most common', 'Common') -contains $vc.Likelihood) { $vc.Observed | Should -BeFalse } }
        }
        $n | Should -BeGreaterThan 0
    }
    It 'names the owner of the fix and says the tool changes nothing' {
        $v = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $script:Diag
        $v.Causes[0].FixLabel | Should -Match 'PKI owner'
        $v.Causes[0].FixLabel | Should -Match 'changes nothing'
        $v.Causes[0].HasFix | Should -BeTrue
        $v.Causes[1].HasFix | Should -BeFalse
        $v.Causes[0].CopyFixTag | Should -Be 'copyfix:1'
    }
    It 'lists the sources with a copy tag each' {
        $v = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $script:Diag
        @($v.SourceItems).Count | Should -Be 1
        $v.SourceItems[0].CopyTag | Should -Be 'copysource:0'
        $v.SourceItems[0].Url | Should -Be 'https://learn.microsoft.com/example'
    }
    It 'shows the checks already marked' {
        $v = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $script:Diag -CheckedKeys @('1:1', '2:0')
        $v.Causes[0].Checks[0].Checked | Should -BeFalse
        $v.Causes[0].Checks[1].Checked | Should -BeTrue
        $v.Causes[1].Checks[0].Checked | Should -BeTrue
    }
    It 'gives an empty view for a passing finding' {
        $v = ConvertTo-MspkiGuiDiagnosisView -Diagnosis $null
        $v.HasDiagnosis | Should -BeFalse
        @($v.SourceItems).Count | Should -Be 0
        $v.ObservedCount | Should -Be 0
    }
}

Describe 'Mark as checked (gui-state.json)' {
    It 'keeps the marks next to a results file inside the output folder' {
        $st = New-MspkiGuiCheckState -ResultsPath $script:Results -AllowedRoot $script:Root
        $st.Path | Should -Be (Join-Path $script:Root 'run1\gui-state.json')
        $st.Note | Should -Match 'kept with this run'
        Switch-MspkiGuiCheckedKey -State $st -FindingId 'F-1' -Key '1:0' -AllowedRoot $script:Root | Should -BeTrue
        Switch-MspkiGuiCheckedKey -State $st -FindingId 'F-1' -Key '2:0' -AllowedRoot $script:Root | Should -BeTrue
        Test-Path -LiteralPath $st.Path | Should -BeTrue
        $again = New-MspkiGuiCheckState -ResultsPath $script:Results -AllowedRoot $script:Root
        @(Get-MspkiGuiCheckedKey -State $again -FindingId 'F-1') | Should -Be @('1:0', '2:0')
    }
    It 'takes a mark back and saves that too' {
        $st = New-MspkiGuiCheckState -ResultsPath $script:Results -AllowedRoot $script:Root
        Switch-MspkiGuiCheckedKey -State $st -FindingId 'F-1' -Key '1:0' -AllowedRoot $script:Root | Should -BeFalse
        $again = New-MspkiGuiCheckState -ResultsPath $script:Results -AllowedRoot $script:Root
        @(Get-MspkiGuiCheckedKey -State $again -FindingId 'F-1') | Should -Be @('2:0')
    }
    It 'keeps the marks in memory only for a results file outside the output folder' {
        $elsewhere = Join-Path $TestDrive 'elsewhere\results.json'
        [void](New-Item -ItemType Directory -Path (Split-Path -Parent $elsewhere) -Force)
        $st = New-MspkiGuiCheckState -ResultsPath $elsewhere -AllowedRoot $script:Root
        $st.Path | Should -Be ''
        $st.Note | Should -Match 'nothing is saved'
        Switch-MspkiGuiCheckedKey -State $st -FindingId 'F-2' -Key '1:0' -AllowedRoot $script:Root | Should -BeTrue
        @(Get-MspkiGuiCheckedKey -State $st -FindingId 'F-2') | Should -Be @('1:0')
        Test-Path -LiteralPath (Join-Path (Split-Path -Parent $elsewhere) 'gui-state.json') | Should -BeFalse
    }
    It 'refuses a path that climbs out of the output folder' {
        Test-MspkiGuiPathInside -Path (Join-Path $script:Root '..\x') -Root $script:Root | Should -BeFalse
        Test-MspkiGuiPathInside -Path $script:Root -Root $script:Root | Should -BeFalse
        Test-MspkiGuiPathInside -Path (Join-Path $script:Root 'run1') -Root $script:Root | Should -BeTrue
        $st = [pscustomobject]@{ Path = (Join-Path $TestDrive 'gui-state.json'); Checked = @{ 'F' = @('1:0') }; Note = ''; SaveError = '' }
        Save-MspkiGuiCheckState -State $st -AllowedRoot $script:Root | Should -BeFalse
        Test-Path -LiteralPath $st.Path | Should -BeFalse
    }
    It 'starts empty and says so when the saved marks cannot be read' {
        $bad = Join-Path $script:Root 'run2\results.json'
        [void](New-Item -ItemType Directory -Path (Split-Path -Parent $bad) -Force)
        Set-Content -LiteralPath (Join-Path $script:Root 'run2\gui-state.json') -Value '{ not json' -Encoding UTF8
        $st = New-MspkiGuiCheckState -ResultsPath $bad -AllowedRoot $script:Root
        $st.Checked.Count | Should -Be 0
        $st.SaveError | Should -Match 'could not be read'
    }
    It 'works with no results file at all (memory only)' {
        $st = New-MspkiGuiCheckState -ResultsPath '' -AllowedRoot $script:Root
        $st.Path | Should -Be ''
        @(Get-MspkiGuiCheckedKey -State $st -FindingId 'X').Count | Should -Be 0
    }
}

Describe 'The walkthrough never runs a check (static)' {
    BeforeAll {
        $p = Join-Path $script:RepoRoot 'src\Gui\GuiApp.ps1'
        $script:Ast = [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$null)
        $script:FnAst = {
            param([string]$Name)
            $script:Ast.Find({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $a.Name -eq $Name }, $true)
        }
    }
    It 'the pane command handler calls only known window helpers (the clipboard, never a process)' {
        $allowed = @('Add-MspkiGuiPaneObject', 'Get-MspkiGuiFindingDetail', 'Reset-MspkiGuiPaneNav', 'Set-MspkiGuiClipboard', 'Show-MspkiGuiCopiedMark',
            'Show-MspkiGuiEntityPane', 'Step-MspkiGuiTrail', 'Switch-MspkiGuiCheckedKey', 'Where-Object',
            # GX6: after Back or a breadcrumb in the map's pane, the map selects the object shown (selection only).
            'Sync-MspkiGuiMapSelection', 'Sync-MspkiGuiTimelineSelection',
            # D-34: the map tree selects the object shown (selection only).
            'Sync-MspkiGuiTreeSelection')
        foreach ($n in 'Invoke-MspkiGuiPaneCommand', 'Show-MspkiGuiCopiedMark') {
            $fn = & $script:FnAst $n
            $fn | Should -Not -BeNullOrEmpty
            $cmds = @($fn.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true))
            foreach ($c in $cmds) {
                $name = $c.GetCommandName()
                $name | Should -Not -BeNullOrEmpty -Because 'a dynamic command (& $x) could run text'
                if ($n -eq 'Show-MspkiGuiCopiedMark') { $name | Should -BeIn @('New-Object') }
                else { $name | Should -BeIn $allowed }
            }
            $fn.Extent.Text | Should -Not -Match '(?i)Process\]?::Start|Start-Process|Invoke-Command|Invoke-Item|ScriptBlock\]::Create|NewScriptBlock|AddScript|\.Invoke\('
        }
    }
    It 'the clipboard helper only sets text' {
        $fn = & $script:FnAst 'Set-MspkiGuiClipboard'
        $fn.Extent.Text | Should -Match 'Clipboard\]::SetText'
        $fn.Extent.Text | Should -Not -Match '(?i)Start-Process|Process\]::Start|Invoke-'
    }
    It 'GuiState.ps1 writes only through the inside-the-output-folder check' {
        $t = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Gui\GuiState.ps1') -Raw
        # Three writes (walkthrough marks, window settings GX9, executive summary GX10), each behind its own inside-the-output-folder check.
        ([regex]::Matches($t, 'WriteAllText')).Count | Should -Be 3
        $t | Should -Match 'Test-MspkiGuiPathInside -Path \$Settings\.Path'
        $t | Should -Match 'Test-MspkiGuiPathInside -Path \$State\.Path'
    }
    It 'every walkthrough button in the window has a tag and an accessible name' {
        $x = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'src\Gui\MainWindow.xaml') -Raw
        foreach ($tag in 'CopyChecksTag', 'CopyTag', 'CopyFixTag', 'ToggleTag') {
            $m = [regex]::Matches($x, '<(Button|CheckBox)\b[^>]*Tag="\{Binding ' + $tag + '\}"[^>]*>')
            $m.Count | Should -BeGreaterThan 0 -Because $tag
            foreach ($e in $m) { $e.Value | Should -Match 'AutomationProperties\.Name=' }
        }
    }
}
