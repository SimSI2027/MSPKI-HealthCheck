# GX9 in the window: the Learn page (Ctrl+9), Explain mode (dotted underline + plain-words tooltip on the terms a page shows), the
# first-run tour (four stops, offered once) and the small celebration of a healthy run. Data and rules come from GuiLearn.ps1.

$script:MspkiGuiExplainIndex = $null

function Get-MspkiGuiExplainIndex {
    # One case-sensitive pattern for the acronyms and one case-insensitive pattern for the other names, longest first, so a page of a few
    # hundred labels is looked up in a few milliseconds.
    if ($null -ne $script:MspkiGuiExplainIndex) { return $script:MspkiGuiExplainIndex }
    $map = @{}; $cs = New-Object System.Collections.ArrayList; $ci = New-Object System.Collections.ArrayList
    foreach ($t in @(Get-MspkiGuiGlossary)) {
        foreach ($name in @(@($t.Term) + @($t.Also))) {
            if (-not $name) { continue }
            $map[$name.ToLowerInvariant()] = $t
            if ($name -cmatch '^[A-Z]{2,6}s?$') { [void]$cs.Add($name) } else { [void]$ci.Add($name) }
        }
    }
    $alt = { param($list) (@($list | Sort-Object -Property Length -Descending | ForEach-Object { [regex]::Escape($_) }) -join '|') }
    $o = [System.Text.RegularExpressions.RegexOptions]::Compiled
    $script:MspkiGuiExplainIndex = @{
        Map = $map; Cache = @{}
        Cs = $(if ($cs.Count -gt 0) { New-Object System.Text.RegularExpressions.Regex(('(?<![\w-])(' + (& $alt $cs) + ')(?![\w-])'), $o) } else { $null })
        Ci = $(if ($ci.Count -gt 0) { New-Object System.Text.RegularExpressions.Regex(('(?<![\w-])(' + (& $alt $ci) + ')(?![\w-])'), ($o -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) } else { $null })
    }
    return $script:MspkiGuiExplainIndex
}

function Find-MspkiGuiExplainEntry {
    # The glossary entry of a short label (at most 48 characters), from the fast index; $null when none.
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if (-not $Text -or $Text.Length -gt 48) { return $null }
    $ix = Get-MspkiGuiExplainIndex
    if ($ix.Cache.ContainsKey($Text)) { return $ix.Cache[$Text] }
    # The first term in the label wins ("AIA over LDAP" is about AIA), as in Find-MspkiGuiGlossaryTerm. Everyday words ("3 findings",
    # "out of 100", "web host") are explained only when they are the whole label, so Explain mode underlines terms, not every line.
    $hit = $null; $at = [int]::MaxValue
    $quiet = @('finding', 'findings', 'score', 'out of 100', 'address', 'addresses', 'host', 'hosts', 'web host', 'copy', 'copies', 'group', 'groups', 'template', 'templates', 'compare', 'partial', 'overlap', 'valid until', 'as of')
    foreach ($rx in @($ix.Ci, $ix.Cs)) {
        if ($null -eq $rx) { continue }
        $m = $rx.Match($Text)
        if (-not $m.Success) { continue }
        $w = $m.Value.ToLowerInvariant()
        if ($quiet -contains $w -and $Text.Trim().ToLowerInvariant() -ne $w) { continue }
        if ($m.Index -lt $at) { $hit = $ix.Map[$w]; $at = $m.Index }
    }
    $ix.Cache[$Text] = $hit
    return $hit
}

function Initialize-MspkiGuiLearn {
    <#
    .SYNOPSIS
    Fills the Learn page, reads the window settings (out\gui-settings.json) and wires Explain mode, the tour and their keys.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.Settings = Read-MspkiGuiSettings -OutputRoot ([string]$g.OutputRoot)
    $g.ExplainSaved = New-Object 'System.Collections.Generic.Dictionary[object,object]'
    $g.LearnItems = @(Get-MspkiGuiLearnItem -Concepts $script:MspkiGuiEntityType)
    $g.LearnList = New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'
    foreach ($it in $g.LearnItems) { $g.LearnList.Add($it) }
    $ui.LearnList.ItemsSource = $g.LearnList
    $g.LearnView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($g.LearnList)
    $g.LearnView.Filter = [System.Predicate[object]]{
        param($it)
        $q = [string]$script:MspkiGui.LearnQuery
        if (-not $q) { return $true }
        foreach ($w in @($q -split '\s+' | Where-Object { $_ })) { if ([string]$it.Search -notlike ('*' + $w + '*')) { return $false } }
        return $true
    }
    $ui.LearnList.Add_SelectionChanged({ $u = $script:MspkiGui.Ui; if ($null -ne $u.LearnList.SelectedItem) { $u.LearnDetail.DataContext = $u.LearnList.SelectedItem; $u.LearnDetailScroll.ScrollToTop() } })
    $ui.FltLearn.Add_TextChanged({ Update-MspkiGuiLearnFilter })
    $ui.BtnLearnClear.Add_Click({ $script:MspkiGui.Ui.FltLearn.Text = '' })
    Update-MspkiGuiLearnFilter
    $ui.TglExplain.IsChecked = [bool]$g.Settings.ExplainMode
    $ui.TglExplain.Add_Click({ Set-MspkiGuiExplainMode -On ([bool]$script:MspkiGui.Ui.TglExplain.IsChecked) })
    $ui.BtnTourNext.Add_Click({ Step-MspkiGuiTour -By 1 })
    $ui.BtnTourBack.Add_Click({ Step-MspkiGuiTour -By -1 })
    $ui.BtnTourSkip.Add_Click({ Stop-MspkiGuiTour })
    $ui.TourLayer.Add_PreviewKeyDown({
        param($s, $e)
        switch ([string]$e.Key) {
            'Escape' { Stop-MspkiGuiTour; $e.Handled = $true }
            'Right' { Step-MspkiGuiTour -By 1; $e.Handled = $true }
            'Left' { Step-MspkiGuiTour -By -1; $e.Handled = $true }
        }
    })
}

function Update-MspkiGuiLearnFilter {
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.LearnQuery = ([string]$ui.FltLearn.Text).Trim().ToLowerInvariant()
    $g.LearnView.Refresh()
    $n = @($ui.LearnList.Items).Count
    $ui.TxtLearnCount.Text = $(if ($g.LearnQuery) { '{0} of {1}' -f $n, (Format-MspkiGuiCount -Count @($g.LearnItems).Count -Singular 'item') } else { '{0} concept cards and {1} terms' -f @($g.LearnItems | Where-Object { $_.Kind -eq 'Concept' }).Count, @($g.LearnItems | Where-Object { $_.Kind -eq 'Term' }).Count })
    $ui.LearnEmpty.Visibility = $(if ($n -eq 0) { 'Visible' } else { 'Collapsed' })
    if ($n -gt 0 -and ($null -eq $ui.LearnList.SelectedItem -or -not $ui.LearnList.Items.Contains($ui.LearnList.SelectedItem))) { $ui.LearnList.SelectedIndex = 0 }
}

function Show-MspkiGuiLearnItem {
    <#
    .SYNOPSIS
    Opens the Learn page on one term or concept (by its title or key).
    #>
    [CmdletBinding()]
    param([string]$Name)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $ui.FltLearn.Text = ''
    Select-MspkiGuiTab -Index 8
    $it = @($g.LearnItems | Where-Object { $_.Title -eq $Name -or $_.Key -eq $Name }) | Select-Object -First 1
    if ($null -ne $it) { $ui.LearnList.SelectedItem = $it; $ui.LearnList.ScrollIntoView($it) }
}

function Set-MspkiGuiExplainMode {
    <#
    .SYNOPSIS
    Turns Explain mode on or off (kept in gui-settings.json) and decorates or restores the page on show.
    #>
    [CmdletBinding()]
    param([bool]$On)
    $g = $script:MspkiGui
    $g.Ui.TglExplain.IsChecked = $On
    $g.Settings.ExplainMode = $On
    [void](Save-MspkiGuiSettings -Settings $g.Settings -AllowedRoot ([string]$g.OutputRoot))
    Update-MspkiGuiExplain
    if ($On) { [void](Show-MspkiGuiToast -Title 'Explain mode is on' -Text 'Terms with a dotted underline say what they mean when you point at them. The Learn page (Ctrl+9) has them all.' -Tone Info) }
}

function Update-MspkiGuiExplain {
    <#
    .SYNOPSIS
    Explain mode: every short label of the page on show that names a glossary term gets a dotted underline and a plain-words tooltip; off,
    the labels get their own tooltips back. Returns how many labels are explained.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -eq $g.ExplainSaved) { return 0 }
    foreach ($k in @($g.ExplainSaved.Keys)) { try { $k.TextDecorations = $null; $k.ToolTip = $g.ExplainSaved[$k]; $k.Uid = '' } catch { $null = $_ } }
    $g.ExplainSaved.Clear()
    if (-not [bool]$ui.TglExplain.IsChecked) { return 0 }
    $pen = New-Object System.Windows.Media.Pen($g.Window.FindResource('B.Accent'), 1)
    $pen.DashStyle = [System.Windows.Media.DashStyles]::Dot
    $dec = New-Object System.Windows.TextDecoration([System.Windows.TextDecorationLocation]::Underline, $pen, 1, [System.Windows.TextDecorationUnit]::FontRecommended, [System.Windows.TextDecorationUnit]::FontRecommended)
    $decs = New-Object System.Windows.TextDecorationCollection
    $decs.Add($dec)
    $roots = @($ui.Tabs, $ui.HdrContext) | Where-Object { $null -ne $_ }
    $stack = New-Object System.Collections.Stack
    foreach ($r in $roots) { $stack.Push($r) }
    $n = 0
    while ($stack.Count -gt 0) {
        $v = $stack.Pop()
        if ($v -is [System.Windows.Controls.TextBox] -or $v -is [System.Windows.Controls.Primitives.TextBoxBase]) { continue }
        if ($v -is [System.Windows.Controls.TextBlock] -and $v.IsVisible -and $v.Text -and $v.Inlines.Count -le 1) {
            $e = Find-MspkiGuiExplainEntry -Text ([string]$v.Text)
            if ($null -ne $e) {
                $g.ExplainSaved[$v] = $v.ToolTip
                $v.TextDecorations = $decs
                $v.ToolTip = Get-MspkiGuiExplainTip -Entry $e
                $v.Uid = 'explain'
                $n++
            }
            continue
        }
        $c = 0
        try { $c = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($v) } catch { $c = 0 }
        for ($i = 0; $i -lt $c; $i++) { $stack.Push([System.Windows.Media.VisualTreeHelper]::GetChild($v, $i)) }
    }
    $g.ExplainCount = $n
    return $n
}

function Request-MspkiGuiExplainUpdate {
    # After a page change or new results: decorate once the page has its layout (background priority, never in the way of input).
    $g = $script:MspkiGui
    if ($null -eq $g -or $null -eq $g.Ui -or -not [bool]$g.Ui.TglExplain.IsChecked) { return }
    [void]$g.Window.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [System.Action]{ try { [void](Update-MspkiGuiExplain) } catch { $null = $_ } })
}

function Start-MspkiGuiTour {
    <#
    .SYNOPSIS
    Shows the first-run tour on the Overview (four stops). It needs results on the Overview; otherwise it says so in a toast.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($ui.PanelResults.Visibility -ne 'Visible') { [void](Show-MspkiGuiToast -Title 'The tour needs results' -Text 'Run the health check or open an earlier run, then take the tour from Ctrl+K.' -Tone Info); return }
    Select-MspkiGuiTab -Index 0
    $g.TourStops = @(Get-MspkiGuiTourStop)
    $g.TourIndex = 0
    $ui.TourLayer.Visibility = 'Visible'
    Show-MspkiGuiTourStop
}

function Show-MspkiGuiTourStop {
    $g = $script:MspkiGui
    $ui = $g.Ui
    $stop = $g.TourStops[$g.TourIndex]
    $n = @($g.TourStops).Count
    $ui.TxtTourStep.Text = 'Tour {0} of {1}' -f ($g.TourIndex + 1), $n
    $ui.TxtTourTitle.Text = $stop.Title
    $ui.TxtTourText.Text = $stop.Text
    $ui.TxtTourNext.Text = $(if ($g.TourIndex -eq $n - 1) { 'Done' } else { 'Next' })
    $ui.BtnTourBack.Visibility = $(if ($g.TourIndex -eq 0) { 'Collapsed' } else { 'Visible' })
    $t = $ui[$stop.Target]
    if ($null -ne $t) { try { $t.BringIntoView() } catch { $null = $_ } }
    $g.Window.UpdateLayout()
    $lw = $ui.TourLayer.ActualWidth; $lh = $ui.TourLayer.ActualHeight
    if ($lw -le 0) { $lw = $g.Window.ActualWidth; $lh = $g.Window.ActualHeight }
    $x = 0.0; $y = 0.0; $w = 0.0; $h = 0.0
    if ($null -ne $t -and $t.IsVisible) {
        $p = $t.TranslatePoint((New-Object System.Windows.Point(0, 0)), $ui.TourLayer)
        $x = $p.X; $y = $p.Y; $w = [math]::Min($t.ActualWidth, $lw - $x - 8); $h = [math]::Min($t.ActualHeight, [math]::Max(40.0, $lh - $y - 8))
    }
    if ($w -gt 0) {
        $ui.TourRing.Visibility = 'Visible'
        [System.Windows.Controls.Canvas]::SetLeft($ui.TourRing, $x - 6); [System.Windows.Controls.Canvas]::SetTop($ui.TourRing, $y - 6)
        $ui.TourRing.Width = $w + 12; $ui.TourRing.Height = $h + 12
    }
    else { $ui.TourRing.Visibility = 'Collapsed' }
    # The card goes beside the target where there is room (right, then below, then above), always inside the window.
    $cw = 360.0; $ui.TourCard.UpdateLayout(); $ch = [math]::Max(160.0, $ui.TourCard.ActualHeight)
    $cx = $x + $w + 20; $cy = $y
    if ($cx + $cw -gt $lw - 16) { $cx = [math]::Max(16.0, [math]::Min($x, $lw - $cw - 16)); $cy = $y + $h + 20; if ($cy + $ch -gt $lh - 16) { $cy = $y - $ch - 20 } }
    $cy = [math]::Max(16.0, [math]::Min($cy, $lh - $ch - 16))
    [System.Windows.Controls.Canvas]::SetLeft($ui.TourCard, $cx); [System.Windows.Controls.Canvas]::SetTop($ui.TourCard, $cy)
    [void]$ui.BtnTourNext.Focus()
}

function Step-MspkiGuiTour {
    param([int]$By = 1)
    $g = $script:MspkiGui
    if ($null -eq $g.TourStops) { return }
    $i = [int]$g.TourIndex + $By
    if ($i -ge @($g.TourStops).Count) { Stop-MspkiGuiTour; return }
    if ($i -lt 0) { $i = 0 }
    $g.TourIndex = $i
    Show-MspkiGuiTourStop
}

function Stop-MspkiGuiTour {
    # Closing or finishing the tour marks it as done (it is offered once); Ctrl+K "Take the tour" shows it again.
    $g = $script:MspkiGui
    $g.Ui.TourLayer.Visibility = 'Collapsed'
    $g.TourStops = $null
    if (-not $g.Settings.TourDone) { $g.Settings.TourDone = $true; [void](Save-MspkiGuiSettings -Settings $g.Settings -AllowedRoot ([string]$g.OutputRoot)) }
    [void]$g.Ui.NavList.Focus()
}

function Request-MspkiGuiTourOffer {
    # The first time results are on the Overview, the tour is offered once, in a notice with "Take the tour" (it never starts by itself).
    # Offered means done: Ctrl+K "Take the tour" shows it again at any time. Never during a snapshot.
    $g = $script:MspkiGui
    if ($null -eq $g.Settings -or $g.Settings.TourDone -or [bool]$g.SnapshotMode) { return }
    if (-not $g.Window.IsVisible) {
        # Results opened at start-up arrive before the window is on screen: offer once it is.
        if (-not $g.TourOfferPending) { $g.TourOfferPending = $true; $g.Window.Add_ContentRendered({ $script:MspkiGui.TourOfferPending = $false; Request-MspkiGuiTourOffer }) }
        return
    }
    $shown = Show-MspkiGuiToast -Title 'New here?' -Text 'A four-stop tour shows the score, what to do next, the map and Ctrl+K.' -Tone Info -Seconds 15 -ActionText 'Take the tour' -Action { Start-MspkiGuiTour }
    if ($shown) { $g.Settings.TourDone = $true; [void](Save-MspkiGuiSettings -Settings $g.Settings -AllowedRoot ([string]$g.OutputRoot)) }
}

function Invoke-MspkiGuiCelebration {
    <#
    .SYNOPSIS
    Once per healthy live run: a short pulse of the score ring (nothing moves with reduced motion) and a toast that says what it means and
    what it does not mean. Returns whether it ran.
    #>
    [CmdletBinding()]
    param([string]$RunKey)
    $g = $script:MspkiGui
    if (-not (Test-MspkiGuiCelebrate -Score $g.Score -Health $(if ($null -ne $g.Summary) { $g.Summary.Health } else { $null }) -RunKey $RunKey -Settings $g.Settings)) { return $false }
    $g.Settings.Celebrated = @(@($g.Settings.Celebrated) + $RunKey)
    [void](Save-MspkiGuiSettings -Settings $g.Settings -AllowedRoot ([string]$g.OutputRoot))
    $ring = $g.Ui.ScoreRing
    if ($null -ne $ring -and -not (Test-MspkiGuiReducedMotion)) {
        $st = New-Object System.Windows.Media.ScaleTransform(1, 1)
        $ring.RenderTransformOrigin = New-Object System.Windows.Point(0.5, 0.5)
        $ring.RenderTransform = $st
        $a = New-Object System.Windows.Media.Animation.DoubleAnimation(1.0, 1.08, (New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds(260))))
        $a.AutoReverse = $true; $a.RepeatBehavior = New-Object System.Windows.Media.Animation.RepeatBehavior(2)
        $a.EasingFunction = New-Object System.Windows.Media.Animation.SineEase
        $st.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleXProperty, $a)
        $st.BeginAnimation([System.Windows.Media.ScaleTransform]::ScaleYProperty, $a)
    }
    [void](Show-MspkiGuiToast -Title 'Everything checked is healthy' -Text ('Score {0}. Nothing this run could check needs attention; what it could not check is listed under Discovery coverage.' -f $g.Score.Overall) -Tone Good)
    return $true
}
