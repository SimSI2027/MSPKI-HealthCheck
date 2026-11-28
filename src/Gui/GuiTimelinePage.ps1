# Timeline page (GX7), window side: draws what GuiLifecycle.ps1 computes. Three views share one panel and the details pane on the right:
# Certificates (every CA certificate generation on a time axis), CRLs (the heartbeat: published, next one due, runs out, and the copy at
# every address) and Chain (from a certificate up to its root, with the result of every AIA and CDP address).
# Rows are a virtualised ListBox with a data template: the bars are star-sized grid columns, so a resize costs nothing in PowerShell.
# Every countdown is counted from the time of the run (GuiLifecycle.ps1). Loaded by GuiApp.ps1.

function Update-MspkiGuiTimelineAxis {
    <#
    .SYNOPSIS
    Draws the axis above the rows: a tick and a date per step, and the run's time as an accent marker.
    #>
    [CmdletBinding()]
    param($Range, [datetime]$Now)
    $ui = $script:MspkiGui.Ui
    $host_ = $ui.TlAxisHost
    $host_.Children.Clear()
    if ($null -eq $Range) { return }
    $total = ($Range.End - $Range.Start).TotalDays
    $mk = {
        param([double]$f, $content, [bool]$isNow)
        $gr = New-Object System.Windows.Controls.Grid
        $gr.IsHitTestVisible = $false
        $c0 = New-Object System.Windows.Controls.ColumnDefinition; $c0.Width = New-Object System.Windows.GridLength([math]::Max(0.0, $f * 1000), [System.Windows.GridUnitType]::Star)
        $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = New-Object System.Windows.GridLength([math]::Max(0.0, (1 - $f) * 1000), [System.Windows.GridUnitType]::Star)
        [void]$gr.ColumnDefinitions.Add($c0); [void]$gr.ColumnDefinitions.Add($c1)
        [System.Windows.Controls.Grid]::SetColumn($content, 1)
        [void]$gr.Children.Add($content)
        [void]$host_.Children.Add($gr)
    }
    $g = $script:MspkiGui
    $g.TlAxisRange = $Range; $g.TlAxisNow = $Now
    # A date label needs about 48 px: a label that would be cut at the right edge, or would run into the label before it, is left out
    # (the tick stays). The width is the lane's own; the axis is drawn again when the lane's width changes (see Initialize).
    $laneW = [double]$host_.ActualWidth
    $lastPx = -1000.0
    # The run's line is drawn through the axis: a date label it would cross is left out too.
    $nowPx = -1000.0; if ($laneW -gt 0 -and $total -gt 0) { $nowPx = [math]::Min([math]::Max(($Now - $Range.Start).TotalDays / $total, 0), 1) * $laneW }
    foreach ($t in (Get-MspkiGuiTimelineTick -Start $Range.Start -End $Range.End)) {
        if ([double]$t.Fraction -gt 0.93) { continue }
        $showText = $true
        if ($laneW -gt 0) {
            $px = [double]$t.Fraction * $laneW
            if (($laneW - $px) -lt 48 -or ($px - $lastPx) -lt 52 -or ($nowPx -ge ($px - 2) -and $nowPx -le ($px + 48))) { $showText = $false } else { $lastPx = $px }
        }
        $sp = New-Object System.Windows.Controls.Grid
        $ln = New-Object System.Windows.Shapes.Rectangle
        $ln.Width = 1; $ln.Height = 8; $ln.HorizontalAlignment = 'Left'; $ln.VerticalAlignment = 'Bottom'
        $ln.SetResourceReference([System.Windows.Shapes.Shape]::FillProperty, 'B.ControlStrong')
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text = $(if ($showText) { [string]$t.Text } else { '' }); $tb.FontSize = 11; $tb.Margin = '4,0,0,10'; $tb.VerticalAlignment = 'Bottom'; $tb.HorizontalAlignment = 'Left'
        $tb.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'B.Muted')
        [void]$sp.Children.Add($ln); [void]$sp.Children.Add($tb)
        & $mk ([double]$t.Fraction) $sp $false
    }
    # The run's time: a short accent stem and "Run" on a small label, centred on the line the rows draw.
    $f = [math]::Min([math]::Max(($Now - $Range.Start).TotalDays / $total, 0), 1)
    $b = New-Object System.Windows.Controls.Border
    $b.CornerRadius = 3; $b.Padding = '5,0,5,0'; $b.Height = 16; $b.VerticalAlignment = 'Top'; $b.HorizontalAlignment = 'Left'; $b.Margin = '-17,3,0,0'
    $b.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'B.Accent')
    $tx = New-Object System.Windows.Controls.TextBlock
    $tx.Text = 'Run'; $tx.FontSize = 11; $tx.FontWeight = 'SemiBold'; $tx.VerticalAlignment = 'Center'
    $tx.SetResourceReference([System.Windows.Controls.TextBlock]::ForegroundProperty, 'B.OnAccent')
    $b.Child = $tx
    $stem = New-Object System.Windows.Shapes.Rectangle
    $stem.Width = 2; $stem.Height = 14; $stem.HorizontalAlignment = 'Left'; $stem.VerticalAlignment = 'Bottom'; $stem.Margin = '-1,0,0,0'
    $stem.SetResourceReference([System.Windows.Shapes.Shape]::FillProperty, 'B.Accent')
    $sp2 = New-Object System.Windows.Controls.Grid
    [void]$sp2.Children.Add($stem); [void]$sp2.Children.Add($b)
    & $mk $f $sp2 $true
}

function Update-MspkiGuiTimelineAxisMargin {
    # Lines the axis up with the lanes of the rows: the label column on the left; the lane margin and the list's scroll bar (when shown) on the right.
    $ui = $script:MspkiGui.Ui
    $sb = 0.0
    $sv = $script:MspkiGui.TlScroll
    if ($null -ne $sv -and $sv.ComputedVerticalScrollBarVisibility -eq 'Visible') { $sb = [math]::Max(0.0, $ui.TlList.ActualWidth - $sv.ViewportWidth) }
    $ui.TlAxisHost.Margin = New-Object System.Windows.Thickness($script:MspkiGuiTlLabelWidth, 0, (16 + $sb), 0)
}

function Reset-MspkiGuiTimelinePage {
    <#
    .SYNOPSIS
    Empties the Timeline page (before a run or when results are cleared).
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -eq $ui -or $null -eq $ui.TlList) { return }
    $g.TlModel = $null; $g.TlItems = $null; $g.TlChainIds = @(); $g.TlNow = $null; $g.TlChainOpened = ''; $g.TlHasGraph = $false; $g.TlFirst = $false; $g.TlOpenFirst = $false; $g.TlSilent = $true
    $ui.TlList.ItemsSource = $null
    $ui.TlChain.ItemsSource = $null
    $ui.TlNext.ItemsSource = $null
    $ui.TlAxisHost.Children.Clear(); $g.TlAxisRange = $null
    $ui.FltTlChain.ItemsSource = $null
    $ui.TxtTlAsOf.Text = 'No run yet'
    $ui.TxtTlStats.Text = ''
    $g.TlSilent = $false
    Reset-MspkiGuiPaneNav -HostName 'TimelineHost'
    $ui.TimelineHost.Content = Get-MspkiGuiEmptyPane -Text 'Select a CA, a certificate or a CRL to see where it was found, what was checked and what it is linked to.'
    Show-MspkiGuiTimelineEmpty -Text 'There is nothing to show yet. Run a health check, or open an earlier results.json.'
}

function Show-MspkiGuiTimelineEmpty {
    # The empty state of the panel (no results, an older results file without the object graph, or nothing of this kind was found).
    param([string]$Text)
    $ui = $script:MspkiGui.Ui
    $ui.TxtTlEmpty.Text = $Text
    $ui.TlEmptyPanel.Visibility = 'Visible'
    $ui.TlTimelinePanel.Visibility = 'Collapsed'
    $ui.TlChainScroll.Visibility = 'Collapsed'
    $ui.TlNextBar.Visibility = 'Collapsed'
    $ui.TlLegendBar.Visibility = 'Collapsed'
}

function Update-MspkiGuiTimelineData {
    <#
    .SYNOPSIS
    Takes the results on show: the run's time (every countdown is counted from it), the chain choices, and a request to the background map
    worker for the lifecycle model and the rows of the view (GuiLifecycle.ps1). Called after the Overview has asked for its map (a new
    results generation drops older requests).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Data)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $now = $null
    if ($null -ne $Data.RunInfo) { $now = ConvertTo-MspkiGuiDateTime -Value $Data.RunInfo.StartedUtc }
    $exact = ($null -ne $now)
    if ($null -eq $now) { $now = [DateTime]::UtcNow }
    $g.TlNow = $now
    $g.TlRunInfo = $Data.RunInfo
    $st = @{}; foreach ($r in $g.Rows) { $st[[string]$r.Id] = [string]$r.Status }
    $g.TlStatus = $st
    $g.TlModel = $null; $g.TlItems = $null; $g.TlFirst = $true; $g.TlHasGraph = ($null -ne $g.Index)
    $choices = @(Get-MspkiGuiChainChoice -Index $g.Index)
    $g.TlChainIds = @($choices | ForEach-Object { [string]$_.Id })
    $g.TlSilent = $true
    $ui.FltTlChain.ItemsSource = @($choices | ForEach-Object { [string]$_.Text })
    if ($choices.Count -gt 0) { $ui.FltTlChain.SelectedIndex = 0 }
    $g.TlSilent = $false
    $ui.TxtTlAsOf.Text = $(if ($exact) { 'As of the run: ' + (Format-MspkiGuiTimelineDate -Date $now -WithTime) } else { 'Run time unknown: counted from now' })
    if (-not $g.TlHasGraph) { Update-MspkiGuiTimelineView; return }
    $ui.TxtTlStats.Text = 'Preparing the timeline...'
    Request-MspkiGuiTimelineRow -View $(if ($ui.RbTlCrls.IsChecked) { 'Crls' } else { 'Certificates' })
}

function Request-MspkiGuiTimelineRow {
    # Asks the background map worker for the rows of one view (the model is computed once per results and kept there).
    param([string]$View)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $span = 0.0
    $key = [string]$ui.FltTlSpan.SelectedItem
    if ($key -and $script:MspkiGuiTimelineSpans.Contains($key)) { $span = [double]$script:MspkiGuiTimelineSpans[$key] }
    $g.TlPending = $View
    Request-MspkiGuiMapJob -Kind Timeline -Options @{ Now = $g.TlNow; RunInfo = $g.TlRunInfo; View = $View; SpanDays = $span; Copies = [bool]$ui.ChkTlCopies.IsChecked }
}

function Complete-MspkiGuiTimelineJob {
    <#
    .SYNOPSIS
    The worker's rows arrive: the first time for new results, the page opens on the view with the item that runs out first, with that item
    open in the details pane; afterwards the rows of the view the user chose replace the old ones.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Result)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.TlModel = $Result.Model
    $g.TlPerf = @{ ModelMs = [int]$Result.ModelMs; ItemsMs = [int]$Result.ItemsMs }
    $m = $g.TlModel
    if ($g.TlFirst) {
        $g.TlFirst = $false
        $want = 'Certificates'
        if ($null -ne $m -and @($m.NextToLapse).Count -gt 0 -and [string]$m.NextToLapse[0].Kind -eq 'Crl') { $want = 'Crls' }
        if (-not $ui.RbTlChain.IsChecked) {
            $g.TlSilent = $true
            if ($want -eq 'Crls') { $ui.RbTlCrls.IsChecked = $true } else { $ui.RbTlCerts.IsChecked = $true }
            $g.TlSilent = $false
            if ($want -ne [string]$Result.View) { $g.TlOpenFirst = $true; Request-MspkiGuiTimelineRow -View $want; return }
        }
        $g.TlOpenFirst = $true
    }
    if ([string]$Result.View -ne (Get-MspkiGuiTimelineMode)) { Update-MspkiGuiTimelineView; return }
    $g.TlRange = $Result.Range
    $g.TlItems = $Result.Items
    Show-MspkiGuiTimelineRow
    if ($g.TlOpenFirst) {
        $g.TlOpenFirst = $false
        # The item that runs out first, selected and open in the details pane: the page answers "what runs out first, and why" at once.
        if ($null -ne $m -and @($m.NextToLapse).Count -gt 0) { Select-MspkiGuiTimelineRow -Id ([string]$m.NextToLapse[0].Id) }
    }
}

function Get-MspkiGuiTimelineMode {
    $ui = $script:MspkiGui.Ui
    if ($ui.RbTlChain.IsChecked) { return 'Chain' }
    if ($ui.RbTlCrls.IsChecked) { return 'Crls' }
    return 'Certificates'
}

function Update-MspkiGuiTimelineView {
    <#
    .SYNOPSIS
    Shows the selected view (Certificates, CRLs or Chain) of the results on show: the chain is computed here (a few milliseconds); the rows
    of the two timeline views come from the background map worker.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $mode = Get-MspkiGuiTimelineMode
    $ui.FltTlSpan.Visibility = $(if ($mode -eq 'Chain') { 'Collapsed' } else { 'Visible' })
    $ui.FltTlChain.Visibility = $(if ($mode -eq 'Chain') { 'Visible' } else { 'Collapsed' })
    $ui.ChkTlCopies.Visibility = $(if ($mode -eq 'Crls') { 'Visible' } else { 'Collapsed' })
    $ui.TlLegendOverlap.Visibility = $(if ($mode -eq 'Crls') { 'Visible' } else { 'Collapsed' })
    if ($null -eq $g.Data) { Show-MspkiGuiTimelineEmpty -Text 'There is nothing to show yet. Run a health check, or open an earlier results.json.'; return }
    if (-not $g.TlHasGraph) { Show-MspkiGuiTimelineEmpty -Text 'These results were written by an older version of the tool, without the object graph. Run the health check again to see the timeline and the chains.'; return }
    if ($mode -eq 'Chain') { Update-MspkiGuiChainView; return }
    if ($null -eq $g.TlModel) { return }
    Request-MspkiGuiTimelineRow -View $mode
}

function Show-MspkiGuiTimelineRow {
    # Puts the worker's rows of the current view on screen with their axis, the "runs out first" strip and the counts (or the empty state).
    $g = $script:MspkiGui
    $ui = $g.Ui
    $m = $g.TlModel
    $mode = Get-MspkiGuiTimelineMode
    if ($null -eq $m) { return }
    $real = 0
    foreach ($gp in $m.Groups) { foreach ($r in $(if ($mode -eq 'Certificates') { $gp.Certs } else { $gp.Crls })) { if ([string]$r.Kind -ne 'Missing') { $real++ } } }
    if (@($m.Groups).Count -eq 0) { Show-MspkiGuiTimelineEmpty -Text 'This run found no CA, so there is no certificate or CRL to show. The Overview says why.'; return }
    if ($mode -eq 'Crls' -and $real -eq 0) { Show-MspkiGuiTimelineEmpty -Text 'This run read no CRL: none of the CRL addresses answered, or the run could not reach them (for example with -SkipNetwork). The Findings page lists what was tried.'; return }
    $ui.TlEmptyPanel.Visibility = 'Collapsed'
    $ui.TlChainScroll.Visibility = 'Collapsed'
    $ui.TlTimelinePanel.Visibility = 'Visible'
    $ui.TlLegendBar.Visibility = 'Visible'
    $keep = ''
    if ($g.Nav.ContainsKey('TimelineHost') -and @($g.Nav.TimelineHost.Trail).Count -gt 0) { $keep = [string]@($g.Nav.TimelineHost.Trail)[0] }
    $g.TlSilent = $true
    $ui.TlList.ItemsSource = $g.TlItems
    $g.TlSilent = $false
    Update-MspkiGuiTimelineAxis -Range $g.TlRange -Now $m.Now
    Update-MspkiGuiTimelineAxisMargin
    # Runs out first: the three current items with the nearest end; a click selects the row (switching view when needed).
    $next = @(foreach ($n in $(if ($mode -eq 'Certificates') { $m.NextCerts } else { $m.NextCrls })) {
            [pscustomobject]@{ Title = ('{0} {1} {2}' -f $n.Label, [char]0x00B7, $n.Short); Text = [string]$n.Due; Tone = [string]$n.Tone; Glyph = $script:MspkiGuiToneGlyph[[string]$n.Tone]; Tag = ('tl:{0}:{1}' -f $n.Kind, $n.Id)
                Tip = ('{0} ({1}). Select to show it.' -f $n.Text, (Format-MspkiGuiTimelineDate -Date $n.End -WithTime)) } })
    $ui.TlNext.ItemsSource = $next
    $ui.TlNextBar.Visibility = $(if ($next.Count -gt 0) { 'Visible' } else { 'Collapsed' })
    $nCa = @($m.Groups).Count
    $ui.TxtTlStats.Text = $(if ($mode -eq 'Certificates') { '{0} {1} {2}' -f (Format-MspkiGuiCount -Count $real -Singular 'certificate generation'), [char]0x00B7, (Format-MspkiGuiCount -Count $nCa -Singular 'CA') }
        else { '{0} {1} {2}' -f (Format-MspkiGuiCount -Count $real -Singular 'CRL'), [char]0x00B7, (Format-MspkiGuiCount -Count $nCa -Singular 'CA') })
    if ($keep) { Select-MspkiGuiTimelineRow -Id $keep -Silent }
}
function Update-MspkiGuiChainView {
    <#
    .SYNOPSIS
    Shows the chain of the selected certificate: cards from the certificate up to its root, the "issued by" links between them and the
    result of each AIA, CDP and OCSP address.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $ids = @($g.TlChainIds)
    $i = $ui.FltTlChain.SelectedIndex
    if ($ids.Count -eq 0 -or $i -lt 0) { Show-MspkiGuiTimelineEmpty -Text 'There is no chain to show: this run found no CA certificate with a known issuer (a root alone has no chain), or could not read the CA certificates.'; $ui.FltTlChain.Visibility = 'Collapsed'; return }
    $c = Get-MspkiGuiChainModel -Index $g.Index -FindingStatus $g.TlStatus -StartId $ids[$i] -Now $g.TlNow
    if ($null -eq $c) { Show-MspkiGuiTimelineEmpty -Text 'This certificate is not in the results.'; return }
    $ui.TlEmptyPanel.Visibility = 'Collapsed'
    $ui.TlTimelinePanel.Visibility = 'Collapsed'
    $ui.TlNextBar.Visibility = 'Collapsed'
    $ui.TlLegendBar.Visibility = 'Collapsed'
    $ui.TlChainScroll.Visibility = 'Visible'
    $ui.TlChainHead.DataContext = [pscustomobject]@{ Tone = $c.HeadlineTone; Glyph = $script:MspkiGuiToneGlyph[[string]$c.HeadlineTone]; Text = $c.Headline }
    $dash = New-Object System.Windows.Media.DoubleCollection; $dash.Add(2.0); $dash.Add(2.0)
    $items = New-Object 'System.Collections.Generic.List[object]'
    $sec = {
        param($list, [string]$head, [string]$tip)
        if (@($list).Count -eq 0) { return }
        $its = @(foreach ($a in $list) {
                [pscustomobject]@{ Tag = ('ent:' + $a.Id); Tone = $a.Tone; Glyph = $script:MspkiGuiToneGlyph[[string]$a.Tone]; Label = $a.Url; Result = $a.Text; Scheme = $a.Scheme; HasScheme = [bool]$a.Scheme
                    Tip = ('{0}{1}{2}' -f $a.Url, [Environment]::NewLine, $a.Text); AutomationName = ('{0} address {1}: {2}' -f $a.Kind, $a.Label, $a.Text) } })
        [pscustomobject]@{ Heading = $head; HeadingTip = $tip; Items = $its }
    }
    for ($k = 0; $k -lt @($c.Cards).Count; $k++) {
        $card = $c.Cards[$k]
        $sections = @(@(
            (& $sec $card.Aia ('Where clients fetch the issuer''s certificate (AIA, {0})' -f @($card.Aia).Count) 'Authority Information Access: the addresses in this certificate where a client downloads the certificate of the CA that issued it')
            (& $sec $card.Cdp ('Where clients check revocation (CDP, {0})' -f @($card.Cdp).Count) 'CRL Distribution Points: the addresses in this certificate where a client downloads the CRL that says whether it was revoked')
            (& $sec $card.Ocsp ('Online responder (OCSP, {0})' -f @($card.Ocsp).Count) 'An OCSP responder answers whether a certificate was revoked, instead of a client downloading the whole CRL')
        ) | Where-Object { $null -ne $_ })
        $glyph = $(if ($card.Placeholder) { [string][char]0xE9CE } elseif ($card.Sub -like 'Certificate on this computer*') { [string][char]0xE977 } else { [string][char]0xEB95 })
        $pillTone = [string]$card.ValidityTone; if (-not $pillTone) { $pillTone = 'Neutral' }
        $items.Add([pscustomobject]@{ Kind = 'Card'; Tag = $(if ($card.Id) { 'ent:' + $card.Id } else { '' }); CanOpen = [bool]$card.Id; Tone = $card.Tone; Glyph = $glyph; Title = $card.Title; Sub = $card.Sub
                Pill = [pscustomobject]@{ Text = [string]$card.Validity; Tone = $pillTone; Glyph = $(if ($pillTone -eq 'Bad') { [string][char]0xE711 } elseif ($card.Validity) { [string][char]0xE823 } else { '' }) }
                Note = $card.Note; HasNote = [bool]$card.Note; Sections = $sections
                OpenTip = $(if ($card.Id) { 'Open this certificate: where it was found, what was checked, what it is linked to' } else { [string]$card.Note })
                AutomationName = ('{0}, {1}. {2}' -f $card.Title, $card.Sub, $card.Validity) })
        if ($k -lt @($c.Links).Count) {
            $l = $c.Links[$k]
            $lg = switch ([string]$l.Tone) { 'Good' { [string][char]0xE73E } 'Warn' { [string][char]0xE7BA } 'Bad' { [string][char]0xE711 } default { [string][char]0xE9CE } }
            $head = Get-MspkiGuiChainLinkHeading -Link $l
            if ($l.Inferred -and -not ($c.Cards[$k + 1]).Placeholder) { $head += ' ' + [char]0x00B7 + ' matched by name (Inferred)' }
            if (($c.Cards[$k + 1]).Placeholder) { $head = 'Issuer not confirmed' }
            $items.Add([pscustomobject]@{ Kind = 'Link'; Tone = $l.Tone; Glyph = $lg; Heading = $head; Text = $l.Text; Dash = $(if ($l.Tone -eq 'Bad' -or $l.Inferred) { $dash } else { $null }) })
        }
    }
    $ui.TlChain.ItemsSource = $items
    $ui.TlChainScroll.ScrollToTop()
    # The pane shows the certificate the chain starts from (unless the user already opened something from this chain).
    if ($g.TlChainOpened -ne $ids[$i]) { $g.TlChainOpened = $ids[$i]; Open-MspkiGuiTimelineItem -Id $ids[$i] }
}

function Select-MspkiGuiTimelineRow {
    <#
    .SYNOPSIS
    Selects the row of an object (the first row with that id) and scrolls it into view. -Silent leaves the details pane as it is.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id, [switch]$Silent)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -eq $g.TlItems) { return }
    foreach ($it in $g.TlItems) {
        if ([string]$it.Id -eq $Id -and $it.Kind -ne 'Copy') {
            $g.TlSilent = [bool]$Silent
            $ui.TlList.SelectedItem = $it
            $g.TlSilent = $false
            $ui.TlList.ScrollIntoView($it)
            return
        }
    }
}

function Open-MspkiGuiTimelineItem {
    <#
    .SYNOPSIS
    Opens an object of the Timeline page in its details pane (a fresh trail, so that Back returns along what the user opens from there).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Id)
    $g = $script:MspkiGui
    if (-not $Id -or $null -eq $g.Index -or -not $g.Index.Entities.ContainsKey($Id)) { return }
    Reset-MspkiGuiPaneNav -HostName 'TimelineHost'
    $g.Nav.TimelineHost.Trail = [string[]]@($Id)
    Show-MspkiGuiEntityPane -HostName 'TimelineHost'
}

function Sync-MspkiGuiTimelineSelection {
    # After Back or a breadcrumb in the pane: the row of the object now on show is selected (without opening it again).
    $g = $script:MspkiGui
    if (-not $g.Nav.ContainsKey('TimelineHost')) { return }
    $t = @($g.Nav.TimelineHost.Trail)
    if ($t.Count -gt 0) { Select-MspkiGuiTimelineRow -Id ([string]$t[$t.Count - 1]) -Silent }
}

function Invoke-MspkiGuiTimelineTag {
    # A click on a "runs out first" chip (tl:<kind>:<id>) or on a chain card or address (ent:<id>).
    param([AllowEmptyString()][string]$Tag)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if (-not $Tag) { return }
    if ($Tag -match '^tl:(Certificate|Crl):(.+)$') {
        $id = $Matches[2]
        if ($Matches[1] -eq 'Crl') { $ui.RbTlCrls.IsChecked = $true } else { $ui.RbTlCerts.IsChecked = $true }
        Select-MspkiGuiTimelineRow -Id $id
        Set-MspkiGuiFocusLater -Element $ui.TlList
        return
    }
    if ($Tag.StartsWith('ent:')) { Open-MspkiGuiTimelineItem -Id $Tag.Substring(4) }
}

function Initialize-MspkiGuiTimelinePage {
    <#
    .SYNOPSIS
    Wires the Timeline page: the three views, the range, the chain's start, the copies switch, the list (selection opens the pane; Enter
    opens it too), the "runs out first" chips and the chain's cards and addresses.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.TlSilent = $true
    $ui.FltTlSpan.ItemsSource = @($script:MspkiGuiTimelineSpans.Keys)
    $ui.FltTlSpan.SelectedIndex = 0
    $g.TlSilent = $false
    $g.TlChainIds = @()
    foreach ($rb in @($ui.RbTlCerts, $ui.RbTlCrls, $ui.RbTlChain)) {
        $rb.Add_Checked({ if (-not $script:MspkiGui.TlSilent) { Update-MspkiGuiTimelineView } })
    }
    $ui.FltTlSpan.Add_SelectionChanged({ if (-not $script:MspkiGui.TlSilent -and $null -ne $script:MspkiGui.TlModel) { Update-MspkiGuiTimelineView } })
    $ui.FltTlChain.Add_SelectionChanged({
            $s = $script:MspkiGui
            # The full name in the tooltip: a long certificate name can be cut in the box.
            $sel = [string]$s.Ui.FltTlChain.SelectedItem
            $s.Ui.FltTlChain.ToolTip = $(if ($sel) { $sel + [Environment]::NewLine + 'The certificate the chain starts from (the leaf); the chain goes up to its root.' } else { 'The certificate the chain starts from (the leaf); the chain goes up to its root.' })
            if (-not $s.TlSilent -and $null -ne $s.TlModel -and $s.Ui.RbTlChain.IsChecked) { Update-MspkiGuiChainView }
        })
    $ui.ChkTlCopies.Add_Click({ if ($null -ne $script:MspkiGui.TlModel) { Update-MspkiGuiTimelineView } })
    $ui.TlList.Add_SelectionChanged({
            $s = $script:MspkiGui
            if ($s.TlSilent) { return }
            $it = $s.Ui.TlList.SelectedItem
            if ($null -ne $it) { Open-MspkiGuiTimelineItem -Id ([string]$it.Id) }
        })
    $ui.TlList.Add_PreviewKeyDown({
            param($s, $e)
            if ($e.Key -eq [System.Windows.Input.Key]::Return) {
                $it = $script:MspkiGui.Ui.TlList.SelectedItem
                if ($null -ne $it) { Open-MspkiGuiTimelineItem -Id ([string]$it.Id); $e.Handled = $true }
            }
        })
    $ui.TlList.Add_Loaded({
            $s = $script:MspkiGui
            if ($null -eq $s.TlScroll) {
                $s.TlScroll = Find-MspkiGuiTimelineScroll -Root $s.Ui.TlList
                if ($null -ne $s.TlScroll) { $s.TlScroll.Add_ScrollChanged({ param($x, $e) if ($e.ViewportWidthChange -ne 0 -or $e.ExtentHeightChange -ne 0) { Update-MspkiGuiTimelineAxisMargin } }) }
            }
            Update-MspkiGuiTimelineAxisMargin
        })
    # The axis leaves out date labels that do not fit: when the lane's width changes, it is drawn again (a few elements).
    $ui.TlAxisHost.Add_SizeChanged({
            param($s, $e)
            $x = $script:MspkiGui
            if ($e.WidthChanged -and [math]::Abs($e.NewSize.Width - $e.PreviousSize.Width) -ge 8 -and $null -ne $x.TlAxisRange) { Update-MspkiGuiTimelineAxis -Range $x.TlAxisRange -Now $x.TlAxisNow }
        })
    $btnClick = [System.Windows.Controls.Primitives.ButtonBase]::ClickEvent
    $ui.TlNext.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Invoke-MspkiGuiTimelineTag -Tag ([string]$e.OriginalSource.Tag) })
    $ui.TlChain.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Invoke-MspkiGuiTimelineTag -Tag ([string]$e.OriginalSource.Tag) })
    Reset-MspkiGuiTimelinePage
}

function Find-MspkiGuiTimelineScroll {
    # The ScrollViewer inside the list's template (to line the axis up with the lanes when the scroll bar appears).
    param($Root)
    $q = New-Object System.Collections.Queue
    $q.Enqueue($Root)
    while ($q.Count -gt 0) {
        $v = $q.Dequeue()
        if ($v -is [System.Windows.Controls.ScrollViewer]) { return $v }
        if ($v -is [System.Windows.Media.Visual]) { $n = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($v); for ($i = 0; $i -lt $n; $i++) { $q.Enqueue([System.Windows.Media.VisualTreeHelper]::GetChild($v, $i)) } }
    }
    return $null
}
