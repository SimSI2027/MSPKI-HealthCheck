# History page (GX8), window side: the runs saved under the output folder (read in the background map worker, a few at a time, so the
# list fills in step by step), the score over time, and the comparison of two runs. Nothing is written: the files are only read.
# Pure helpers are in GuiHistory.ps1. Loaded by GuiApp.ps1.

function Reset-MspkiGuiHistoryPage {
    # Forgets what the page showed (a new run or another results file is about to be shown); the runs are read again when the page opens.
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -eq $ui -or $null -eq $ui.HistList) { return }
    $g.HistStale = $true
    $g.HistCmp = $null; $g.HistCmpKey = ''; $g.HistUserPick = ''
    Show-MspkiGuiHistoryCompareEmpty -Text 'What changed between two runs shows here once the runs are read.'
}

function Set-MspkiGuiHistoryStale {
    # The run on show changed: read the list again (a run just written appears) and compare it with the run before it. When the page is
    # on show, at once.
    $g = $script:MspkiGui
    $g.HistStale = $true; $g.HistUserPick = ''
    if ($null -ne $g.Ui -and $g.Ui.Tabs.SelectedItem -eq $g.Ui.TabHistory) { Update-MspkiGuiHistoryPage }
}

function Get-MspkiGuiHistoryCurrentPath {
    $g = $script:MspkiGui
    if ($null -ne $g.Data -and $null -ne $g.Data.PSObject.Properties['ResultsPath'] -and $g.Data.ResultsPath) { return [string]$g.Data.ResultsPath }
    return ''
}

function Update-MspkiGuiHistoryPage {
    <#
    .SYNOPSIS
    Shows the History page: reads the list of runs again when it is stale (or -Force), otherwise draws what is known.
    #>
    [CmdletBinding()]
    param([switch]$Force)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($Force -or $g.HistStale -or $null -eq $g.HistRuns) {
        $g.HistStale = $false
        if ($null -eq $g.HistRuns) { Show-MspkiGuiHistoryEmpty -Text 'Reading the runs in the output folder...' }
        $ui.TxtHistCount.Text = 'Reading the runs...'
        Request-MspkiGuiMapJob -Kind History -Options @{ Root = [string]$g.OutputRoot; BudgetMs = 250; Extra = (Get-MspkiGuiHistoryCurrentPath) }
        return
    }
    Show-MspkiGuiHistoryList
}

function Show-MspkiGuiHistoryEmpty {
    param([string]$Text)
    $ui = $script:MspkiGui.Ui
    $ui.TxtHistEmpty.Text = $Text
    $ui.HistEmptyPanel.Visibility = 'Visible'
    $ui.HistList.Visibility = 'Collapsed'
    $ui.HistTrendBar.Visibility = 'Collapsed'
}

function Complete-MspkiGuiHistoryJob {
    # A history job came back from the worker: the list of runs (step by step) or a comparison.
    param([Parameter(Mandatory = $true)]$Result)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -ne $Result.PSObject.Properties['Error'] -and $Result.Error) {
        if ($Result.Kind -eq 'HistoryCompare') { Show-MspkiGuiHistoryCompareEmpty -Text ('The two runs could not be compared: {0}' -f $Result.Error) }
        else { Show-MspkiGuiHistoryEmpty -Text ('The runs in the output folder could not be read: {0}' -f $Result.Error); Show-MspkiGuiHistoryCompareEmpty -Text 'There is nothing to compare.'; $ui.TxtHistCount.Text = '' }
        return
    }
    if ($Result.Kind -eq 'HistoryCompare') {
        $g.HistCmp = $Result.Compare
        $g.HistCmpKey = '{0}|{1}' -f $Result.OldPath, $Result.NewPath
        $g.HistPerf = @{ CompareMs = [int]$Result.Ms }
        Show-MspkiGuiHistoryCompare
        return
    }
    $g.HistRuns = @($Result.Runs)
    $g.HistPending = [int]$Result.Pending
    Show-MspkiGuiHistoryList
    # More runs to read: the next few, in the background (the worker stays free for the map in between).
    if ($Result.Pending -gt 0) { Request-MspkiGuiMapJob -Kind History -Options @{ Root = [string]$g.OutputRoot; BudgetMs = 250; Extra = (Get-MspkiGuiHistoryCurrentPath) } }
}

function Show-MspkiGuiHistoryList {
    <#
    .SYNOPSIS
    Draws the forest choice, the runs of the chosen forest, the score over time and, once the runs are read, the comparison of the run on
    show with the run before it (or the pair the user picked).
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $runs = @($g.HistRuns)
    $cur = Get-MspkiGuiHistoryCurrentPath
    $curForest = ''
    if ($null -ne $g.Data -and $null -ne $g.Data.RunInfo) { $curForest = [string]$g.Data.RunInfo.Forest }
    $forests = @(Get-MspkiGuiHistoryForest -Runs $runs -Prefer $curForest)
    $bad = @($runs | Where-Object { $_.Error }).Count
    if ($forests.Count -eq 0) {
        $why = $(if ($runs.Count -eq 0 -and $g.HistPending -eq 0) { 'No earlier run was found in {0}. Each run saves its results there; after two runs, this page shows what changed between them.' -f $g.OutputRoot }
            elseif ($g.HistPending -gt 0) { 'Reading the runs in the output folder...' } else { 'The runs in {0} could not be read ({1} files). They may come from a newer version of this tool.' -f $g.OutputRoot, $bad })
        Show-MspkiGuiHistoryEmpty -Text $why
        Show-MspkiGuiHistoryCompareEmpty -Text 'There is nothing to compare yet.'
        $ui.TxtHistCount.Text = ''
        return
    }
    # The forest choice: keep the user's, else the forest of the run on show.
    $want = [string]$g.HistForest
    if (-not $want -or -not @($forests | Where-Object { $_.Forest -eq $want })) { $want = [string]$forests[0].Forest }
    $g.HistSilent = $true
    $ui.FltHistForest.ItemsSource = @($forests | ForEach-Object { $_.Text })
    $ui.FltHistForest.SelectedIndex = [array]::IndexOf([string[]]@($forests | ForEach-Object { $_.Forest }), $want)
    $g.HistSilent = $false
    $g.HistForest = $want
    $view = Get-MspkiGuiHistoryRow -Runs $runs -Forest $want -CurrentPath $cur
    $g.HistView = $view
    $rows = @($view.Rows)
    foreach ($r in $rows) {
        $r | Add-Member -NotePropertyName CompareTag -NotePropertyValue ('cmp:' + $r.Path) -Force
        $r | Add-Member -NotePropertyName OpenTag -NotePropertyValue ('open:' + $r.Path) -Force
        $r | Add-Member -NotePropertyName CanCompare -NotePropertyValue ($null -ne $view.Newer -and $r.Path -ne $view.Newer.Path) -Force
        $r | Add-Member -NotePropertyName CompareName -NotePropertyValue ('Compare the run of {0} with the run of {1}' -f $r.When, $(if ($null -ne $view.Newer) { $view.Newer.When } else { '' })) -Force
        $r | Add-Member -NotePropertyName CompareTip -NotePropertyValue $(if ($null -ne $view.Newer -and $r.Path -ne $view.Newer.Path) { 'Compare this run with the run of {0} (Enter)' -f $view.Newer.When } else { 'This is the newer run of the comparison' }) -Force
        $r | Add-Member -NotePropertyName OpenName -NotePropertyValue ('Open the run of {0}' -f $r.When) -Force
        # The marks carry their own tone (a pill takes the tone of what it is bound to; the row's tone is its score's).
        $r | Add-Member -NotePropertyName MarkPill -NotePropertyValue ([pscustomobject]@{ Show = [bool]$r.IsCurrent; Tone = 'Info'; Text = 'On show' }) -Force
        $r | Add-Member -NotePropertyName PartialPill -NotePropertyValue ([pscustomobject]@{ Show = [bool]$r.Partial; Tone = 'Info'; Text = 'Did not finish' }) -Force
    }
    $keep = $ui.HistList.SelectedIndex
    $ui.HistList.ItemsSource = $rows
    if ($keep -ge 0 -and $keep -lt $rows.Count) { $ui.HistList.SelectedIndex = $keep }
    $ui.HistList.Visibility = 'Visible'; $ui.HistEmptyPanel.Visibility = 'Collapsed'
    $more = $(if ($g.HistPending -gt 0) { ' {0} reading {1} more...' -f [char]0x00B7, $g.HistPending } else { '' })
    $other = @($forests).Count - 1
    # The count is in the forest box; here only what it does not say: other forests, and runs still being read.
    $ui.TxtHistCount.Text = ('{0}{1}' -f $(if ($other -gt 0) { 'and {0}' -f (Format-MspkiGuiCount -Count $other -Singular 'other forest') } else { '' }), $more).Trim().TrimStart([char]0x00B7).Trim()
    Show-MspkiGuiHistoryTrend
    # The comparison: the user's pick, else the run on show and the run before it. Only once the list is read (no half-known "previous").
    if ($g.HistPending -gt 0 -and -not $g.HistUserPick) { return }
    $older = $null
    if ($g.HistUserPick) { $older = @($rows | Where-Object { $_.Path -eq $g.HistUserPick })[0] }
    if ($null -eq $older) { $older = $view.Older }
    if ($null -eq $view.Newer -or $null -eq $older) {
        Show-MspkiGuiHistoryCompareEmpty -Text $(if ($rows.Count -le 1) { 'Only one run of this forest is saved. Run the health check again later: this page then shows what changed.' } else { 'Choose Compare on an earlier run to see what changed.' })
        return
    }
    Request-MspkiGuiHistoryCompare -OldPath $older.Path -NewPath $view.Newer.Path
}

function Request-MspkiGuiHistoryCompare {
    param([Parameter(Mandatory = $true)][string]$OldPath, [Parameter(Mandatory = $true)][string]$NewPath)
    $g = $script:MspkiGui
    $key = '{0}|{1}' -f $OldPath, $NewPath
    if ($g.HistCmpKey -eq $key -and $null -ne $g.HistCmp) { Show-MspkiGuiHistoryCompare; return }
    $ui = $g.Ui
    $ui.TxtHistCmpTitle.Text = 'What changed'
    $ui.TxtHistCmpSub.Text = 'Comparing the two runs...'
    Request-MspkiGuiMapJob -Kind HistoryCompare -Options @{ OldPath = $OldPath; NewPath = $NewPath }
}

function Show-MspkiGuiHistoryCompareEmpty {
    param([string]$Text)
    $ui = $script:MspkiGui.Ui
    $ui.TxtHistCmpEmpty.Text = $Text
    $ui.HistCmpEmpty.Visibility = 'Visible'
    $ui.HistCmpScroll.Visibility = 'Collapsed'
    # D-27: with only one saved run, the next step is a new run, so the button is here.
    $ui.BtnHistRun.Visibility = $(if ($Text -like 'Only one run*') { 'Visible' } else { 'Collapsed' })
}

function Show-MspkiGuiHistoryCompare {
    # Draws the comparison (computed in the worker) on the right.
    $g = $script:MspkiGui
    $ui = $g.Ui
    $c = $g.HistCmp
    if ($null -eq $c) { return }
    # A finding of the run on show can be opened on the Findings page.
    $open = @{}
    $cur = Get-MspkiGuiHistoryCurrentPath
    if ($cur -and [string]::Equals([System.IO.Path]::GetFullPath($cur), [System.IO.Path]::GetFullPath([string]$c.New.Path), [System.StringComparison]::OrdinalIgnoreCase)) { foreach ($k in $g.RowById.Keys) { $open[[string]$k] = $true } }
    $v = Get-MspkiGuiCompareView -Compare $c -OpenIds $open
    $ui.TxtHistCmpTitle.Text = $v.Title
    $ui.TxtHistCmpSub.Text = $v.Sub
    $ui.HistScoreCard.DataContext = $v
    $ui.TxtHistScores.Text = $v.Scores
    $ui.TxtHistDelta.Text = $v.DeltaText
    [System.Windows.Automation.AutomationProperties]::SetName($ui.HistScoreCard, $v.AutomationName)
    $ui.HistAreas.ItemsSource = @($v.Areas)
    $ui.HistNotes.ItemsSource = @($v.Notes)
    $ui.HistSections.ItemsSource = @($v.Sections)
    $ui.HistCmpEmpty.Visibility = 'Collapsed'
    $ui.HistCmpScroll.Visibility = 'Visible'
    $ui.HistCmpScroll.ScrollToTop()
    Show-MspkiGuiHistoryTrend
}

function Show-MspkiGuiHistoryTrend {
    <#
    .SYNOPSIS
    The score over time: one point per run of the forest (oldest left), the band lines at 60 and 90, the two compared runs ringed. A few
    dozen elements, drawn again when the strip changes width.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $cv = $ui.HistTrend
    $cv.Children.Clear()
    $v = $g.HistView
    $pts = @(); if ($null -ne $v) { $pts = @($v.Trend) }
    # D-27: a chart needs at least two scored runs; one lone dot says nothing.
    if (@($pts | Where-Object { $null -ne $_.Score }).Count -lt 2) { $ui.HistTrendBar.Visibility = 'Collapsed'; return }
    $ui.HistTrendBar.Visibility = 'Visible'
    $first = $pts[0].Score; $last = $pts[$pts.Count - 1].Score
    # Runs without a score (no CA found) are not points; the text says "scored runs" when that leaves some out.
    $scoredWord = $(if ($pts.Count -lt @($v.Rows).Count) { 'scored run' } else { 'run' })
    $ui.TxtHistTrend.Text = $(if ($pts.Count -eq 1) { 'One scored run: {0}' -f $last } else { '{0} {1} {2} over {3}' -f $first, [char]0x2192, $last, (Format-MspkiGuiCount -Count $pts.Count -Singular $scoredWord) })
    $w = [double]$cv.ActualWidth; $h = 64.0
    if ($w -le 0) { return }
    $y = { param([double]$s) 4.0 + ($h - 8.0) * (1.0 - [math]::Max(0.0, [math]::Min(100.0, $s)) / 100.0) }
    foreach ($band in 60, 90) {
        $ln = New-Object System.Windows.Shapes.Line
        $ln.X1 = 0; $ln.X2 = $w; $ln.Y1 = (& $y $band); $ln.Y2 = $ln.Y1; $ln.StrokeThickness = 1
        $dash = New-Object System.Windows.Media.DoubleCollection; $dash.Add(3.0); $dash.Add(3.0); $ln.StrokeDashArray = $dash
        $ln.SetResourceReference([System.Windows.Shapes.Shape]::StrokeProperty, 'B.Divider')
        [void]$cv.Children.Add($ln)
    }
    $step = $(if ($pts.Count -gt 1) { ($w - 12.0) / ($pts.Count - 1) } else { 0.0 })
    $xOf = { param([int]$i) if ($pts.Count -eq 1) { $w / 2.0 } else { 6.0 + $i * $step } }
    if ($pts.Count -gt 1) {
        $pl = New-Object System.Windows.Shapes.Polyline
        $pc = New-Object System.Windows.Media.PointCollection
        for ($i = 0; $i -lt $pts.Count; $i++) { $pc.Add((New-Object System.Windows.Point((& $xOf $i), (& $y $pts[$i].Score)))) }
        $pl.Points = $pc; $pl.StrokeThickness = 2
        $pl.SetResourceReference([System.Windows.Shapes.Shape]::StrokeProperty, 'B.Accent')
        [void]$cv.Children.Add($pl)
    }
    $cmp = @(); if ($null -ne $g.HistCmp) { $cmp = @([string]$g.HistCmp.Old.Path, [string]$g.HistCmp.New.Path) }
    $toneBrush = @{ Good = 'B.GoodFore'; Warn = 'B.WarnFore'; Bad = 'B.BadFore'; Neutral = 'B.NeutralFore' }
    for ($i = 0; $i -lt $pts.Count; $i++) {
        $p = $pts[$i]
        $ring = ($cmp -contains [string]$p.Path)
        # Many runs: smaller dots (the compared two stay ringed).
        $d = $(if ($ring) { 12.0 } elseif ($pts.Count -gt 20) { 5.0 } else { 8.0 })
        $e = New-Object System.Windows.Shapes.Ellipse
        $e.Width = $d; $e.Height = $d
        $b = $toneBrush[[string]$p.Tone]; if (-not $b) { $b = 'B.NeutralFore' }
        $e.SetResourceReference([System.Windows.Shapes.Shape]::FillProperty, $b)
        $e.SetResourceReference([System.Windows.Shapes.Shape]::StrokeProperty, 'B.Card')
        $e.StrokeThickness = $(if ($ring) { 2.5 } elseif ($pts.Count -gt 20) { 0.0 } else { 1.5 })
        $e.ToolTip = '{0}: score {1}{2}' -f $p.When, $p.Score, $(if ($ring) { ' (compared)' } else { '' })
        [System.Windows.Controls.Canvas]::SetLeft($e, (& $xOf $i) - $d / 2.0)
        [System.Windows.Controls.Canvas]::SetTop($e, (& $y $p.Score) - $d / 2.0)
        [void]$cv.Children.Add($e)
    }
}

function Test-MspkiGuiHistoryCanComparePrevious {
    # The palette's "Compare with the run before": there is a run on show (or any run) and History knows of a run before it, or has not read the list yet.
    $g = $script:MspkiGui
    if ($null -eq $g.HistView) { return ($null -ne $g.Data) }
    return ($null -ne $g.HistView.Older)
}

function Invoke-MspkiGuiHistoryComparePrevious {
    # Compares the run on show with the run before it (the page's default).
    $g = $script:MspkiGui
    $g.HistUserPick = ''
    Update-MspkiGuiHistoryPage
}

function Invoke-MspkiGuiHistoryTag {
    # A click on Compare (cmp:<path>), Open (open:<path>) or a finding of the comparison (f:<id>).
    param([AllowEmptyString()][string]$Tag)
    $g = $script:MspkiGui
    if (-not $Tag) { return }
    if ($Tag.StartsWith('cmp:')) {
        $p = $Tag.Substring(4)
        $g.HistUserPick = $p
        if ($null -ne $g.HistView -and $null -ne $g.HistView.Newer -and $p -ne $g.HistView.Newer.Path) { Request-MspkiGuiHistoryCompare -OldPath $p -NewPath $g.HistView.Newer.Path }
        return
    }
    if ($Tag.StartsWith('open:')) { Open-MspkiGuiResultsFile -Path $Tag.Substring(5); return }
    if ($Tag.StartsWith('f:')) { Show-MspkiGuiFinding -Id $Tag.Substring(2) }
}

function Initialize-MspkiGuiHistoryPage {
    <#
    .SYNOPSIS
    Wires the History page: refresh, the forest choice, Compare and Open on each run (Enter compares the selected run), the findings of
    the comparison, and the trend strip's width.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.HistRuns = $null; $g.HistView = $null; $g.HistPending = 0; $g.HistForest = ''; $g.HistSilent = $false
    Reset-MspkiGuiHistoryPage
    $ui.BtnHistRefresh.Add_Click({ Update-MspkiGuiHistoryPage -Force })
    $ui.FltHistForest.Add_SelectionChanged({
            $s = $script:MspkiGui
            if ($s.HistSilent -or $null -eq $s.HistRuns) { return }
            $i = $s.Ui.FltHistForest.SelectedIndex
            $fs = @(Get-MspkiGuiHistoryForest -Runs @($s.HistRuns) -Prefer $s.HistForest)
            if ($i -ge 0 -and $i -lt $fs.Count) { $s.HistForest = [string]$fs[$i].Forest; $s.HistUserPick = ''; $s.HistCmp = $null; $s.HistCmpKey = ''; Show-MspkiGuiHistoryList }
        })
    $btnClick = [System.Windows.Controls.Primitives.ButtonBase]::ClickEvent
    $ui.HistList.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Invoke-MspkiGuiHistoryTag -Tag ([string]$e.OriginalSource.Tag) })
    $ui.HistSections.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Invoke-MspkiGuiHistoryTag -Tag ([string]$e.OriginalSource.Tag) })
    $ui.HistList.Add_PreviewKeyDown({
            param($s, $e)
            if ($e.Key -eq [System.Windows.Input.Key]::Return) {
                $it = $script:MspkiGui.Ui.HistList.SelectedItem
                if ($null -ne $it -and $it.CanCompare) { Invoke-MspkiGuiHistoryTag -Tag ([string]$it.CompareTag); $e.Handled = $true }
            }
        })
    $ui.HistTrend.Add_SizeChanged({ param($s, $e) if ($e.WidthChanged) { Show-MspkiGuiHistoryTrend } })
}
