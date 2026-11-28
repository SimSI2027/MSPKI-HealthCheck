# Discovery map, window side (GX6): the background map worker, the time-sliced drawer shared by the Overview and the full-page map, and
# the full-page map itself (zoom, pan, minimap, groups, filters, search, keyboard, selection in the details pane, replay, PNG export).
# Budget: the UI thread never works more than about 30 ms at a time on the map. The model, the view and the layout are computed in a
# background runspace (Invoke-MspkiGuiMapJob, pure, in GuiMap.ps1); the elements are created in slices of at most 30 ms on a new canvas,
# which replaces the old one when it is complete (no flicker). Panning and zooming only change two transforms.

$script:MspkiGuiFolder = $PSScriptRoot
$script:MspkiGuiMapSliceMs = 15
$script:MspkiGuiMapStatusChoices = @(
    [pscustomobject]@{ Text = 'All statuses'; Value = 'All' }, [pscustomobject]@{ Text = 'Failing'; Value = 'Bad' }, [pscustomobject]@{ Text = 'Warning'; Value = 'Warn' }
    [pscustomobject]@{ Text = 'Could not check'; Value = 'Admin' }, [pscustomobject]@{ Text = 'Healthy'; Value = 'Good' }, [pscustomobject]@{ Text = 'No finding'; Value = 'Neutral' }
)
$script:MspkiGuiMapTypeChoices = @(
    [pscustomobject]@{ Text = 'All objects'; Value = 'All' }, [pscustomobject]@{ Text = 'CAs'; Value = 'CA' }, [pscustomobject]@{ Text = 'Published addresses'; Value = 'Endpoint' }, [pscustomobject]@{ Text = 'Hosts'; Value = 'Host' }
)

function Start-MspkiGuiMapWorker {
    <#
    .SYNOPSIS
    Opens the background runspace that computes map models and layouts, and the timeline's rows (GuiModel, GuiView, GuiMap and GuiLifecycle:
    pure functions, no I/O).
    Returns $false when it cannot be started; the window then computes the map inline.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -ne $g.MapWorker) { return $true }
    try {
        $rs = [runspacefactory]::CreateRunspace()
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        [void]$ps.AddScript('param($Folder, $ModulePath) foreach ($f in @(''GuiModel.ps1'', ''GuiView.ps1'', ''GuiMap.ps1'', ''GuiLifecycle.ps1'', ''GuiMission.ps1'', ''GuiHistory.ps1'')) { . (Join-Path $Folder $f) }; $global:MspkiMapCache = @{}; $global:MspkiModulePath = $ModulePath').AddArgument($script:MspkiGuiFolder).AddArgument([string]$g.ModulePath)
        $g.MapWorker = $rs
        $g.MapJob = @{ PS = $ps; Async = $ps.BeginInvoke(); Request = @{ Kind = 'Init'; Gen = -1 }; Started = [DateTime]::Now }
        $g.MapTimer.Start()
        return $true
    }
    catch { $g.MapWorker = $null; $g.MapJob = $null; return $false }
}

function Stop-MspkiGuiMapWorker {
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -ne $g.MapTimer) { $g.MapTimer.Stop() }
    if ($null -ne $g.MapJob) { try { $g.MapJob.PS.Stop(); $g.MapJob.PS.Dispose() } catch { $null = $_ } ; $g.MapJob = $null }
    if ($null -ne $g.MapWorker) { try { $g.MapWorker.Close(); $g.MapWorker.Dispose() } catch { $null = $_ }; $g.MapWorker = $null }
}

function Request-MspkiGuiMapJob {
    <#
    .SYNOPSIS
    Asks for a map of the loaded results: -Kind Overview (fitted to -Width) or Page (the full-page map with the page's filters). The latest
    request of each kind wins; the result is drawn when it arrives (results of an older generation are dropped).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][ValidateSet('Overview', 'Page', 'Timeline', 'History', 'HistoryCompare')][string]$Kind, [double]$Width = 0, [hashtable]$Options = @{})
    $g = $script:MspkiGui
    $req = @{ Kind = $Kind; Gen = [int]$g.MapGen; Width = $Width; Options = $Options; Asked = [DateTime]::Now }
    $g.MapQueue[$Kind] = $req
    if ($Kind -eq 'Page') { Set-MspkiGuiMapBusy -Busy $true }
    if ($g.MapSync -or -not (Start-MspkiGuiMapWorker)) {
        # Inline (developer tests and a window whose worker could not start): the same function, on this thread.
        $g.MapQueue.Remove($Kind)
        $r = Invoke-MspkiGuiMapJob -Request $req -Index $g.Index -Status $g.MapStatus -Cache $g.MapCache
        Complete-MspkiGuiMapJob -Result $r -Request $req
        return
    }
    Start-MspkiGuiMapNextJob
}

function Start-MspkiGuiMapNextJob {
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -ne $g.MapJob) { return }
    $req = $null
    foreach ($k in @('Overview', 'Page', 'Timeline', 'HistoryCompare', 'History')) { if ($g.MapQueue.ContainsKey($k)) { $req = $g.MapQueue[$k]; $g.MapQueue.Remove($k); break } }
    if ($null -eq $req) { return }
    $ps = [powershell]::Create()
    $ps.Runspace = $g.MapWorker
    [void]$ps.AddScript('param($Req, $Index, $Status) Invoke-MspkiGuiMapJob -Request $Req -Index $Index -Status $Status -Cache $global:MspkiMapCache').AddArgument($req).AddArgument($g.Index).AddArgument($g.MapStatus)
    $g.MapJob = @{ PS = $ps; Async = $ps.BeginInvoke(); Request = $req; Started = [DateTime]::Now }
    $g.MapTimer.Start()
}

function Receive-MspkiGuiMapJob {
    <#
    .SYNOPSIS
    The map timer's tick (every 15 ms while there is map work): collects a finished background job, starts the next one, and draws the next
    slice of a pending drawing. Each call does at most one slice of work.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $j = $g.MapJob
    if ($null -ne $j -and $j.Async.IsCompleted) {
        $g.MapJob = $null
        $out = $null; $err = $null
        try { $out = @($j.PS.EndInvoke($j.Async)); if ($j.PS.Streams.Error.Count -gt 0) { $err = $j.PS.Streams.Error[0] } } catch { $err = $_ }
        try { $j.PS.Dispose() } catch { $null = $_ }
        if ($j.Request.Kind -ne 'Init') {
            if (($null -ne $err -or $null -eq $out -or $out.Count -eq 0) -and $j.Request.Kind -in @('History', 'HistoryCompare')) {
                # Reading earlier runs is never done on the window's thread: the page says what went wrong instead.
                $why = $(if ($null -ne $err) { [string]$err } else { 'The background reader returned nothing.' })
                Complete-MspkiGuiMapJob -Result ([pscustomobject]@{ Kind = $j.Request.Kind; Gen = $j.Request.Gen; Error = $why }) -Request $j.Request
            }
            elseif ($null -ne $err -or $null -eq $out -or $out.Count -eq 0) {
                # The worker failed: compute this one inline, so the user still gets a map.
                $r = Invoke-MspkiGuiMapJob -Request $j.Request -Index $g.Index -Status $g.MapStatus -Cache $g.MapCache
                Complete-MspkiGuiMapJob -Result $r -Request $j.Request
            }
            else { Complete-MspkiGuiMapJob -Result $out[-1] -Request $j.Request }
        }
        Start-MspkiGuiMapNextJob
    }
    if ($g.MapDraws.Count -gt 0 -or $g.MapAnims.Count -gt 0) { Step-MspkiGuiMapDraw }
    if ($null -eq $g.MapJob -and $g.MapQueue.Count -eq 0 -and $g.MapDraws.Count -eq 0 -and $g.MapAnims.Count -eq 0) { $g.MapTimer.Stop() }
}

function Complete-MspkiGuiMapJob {
    # A computed map arrives: start drawing it (results of an older generation are dropped).
    param([Parameter(Mandatory = $true)]$Result, [Parameter(Mandatory = $true)][hashtable]$Request)
    $g = $script:MspkiGui
    if ([int]$Result.Gen -ne [int]$g.MapGen) { return }
    if ($Request.Kind -eq 'Timeline') { Complete-MspkiGuiTimelineJob -Result $Result; return }
    if ($Request.Kind -in @('History', 'HistoryCompare')) { Complete-MspkiGuiHistoryJob -Result $Result; return }
    $g.MapPerf.LastLayoutMs = [int]$Result.LayoutMs; $g.MapPerf.LastModelMs = [int]$Result.ModelMs
    if ($Request.Kind -eq 'Overview') {
        $g.MapBase = $Result.Base
        if ($Result.Empty) { return }
        $g.MapModel = $Result.View
        $g.MapTotalMs = [double]$Result.View.TotalMs
        Start-MspkiGuiMapDraw -Kind Overview -Model $Result.View -Width ([double]$Request.Width)
        return
    }
    $g.MapBase = $Result.Base
    $g.MapPageModel = $Result.View
    Update-MspkiGuiMapFocusChoice
    if ($Result.Empty -or $null -eq $Result.View -or @($Result.View.Nodes).Count -eq 0) { Show-MspkiGuiMapPageEmpty; Set-MspkiGuiMapBusy -Busy $false; return }
    Start-MspkiGuiMapDraw -Kind Page -Model $Result.View -Width ([double]$Result.View.Width)
}

function Start-MspkiGuiMapDraw {
    <#
    .SYNOPSIS
    Starts drawing a laid-out map on a new canvas, in slices (Step-MspkiGuiMapDraw): nodes first, then links. A newer drawing of the same
    kind replaces one still in progress.
    #>
    param([Parameter(Mandatory = $true)][ValidateSet('Overview', 'Page')][string]$Kind, [Parameter(Mandatory = $true)]$Model, [double]$Width)
    $g = $script:MspkiGui
    $cv = New-Object System.Windows.Controls.Canvas
    $cv.HorizontalAlignment = 'Left'; $cv.VerticalAlignment = 'Top'; $cv.ClipToBounds = $true
    $top = $(if ($Kind -eq 'Overview') { $script:MspkiGuiMapHeaderHeight } else { 36.0 })
    $cv.Width = [math]::Max(200.0, $Width); $cv.Height = [double]$Model.Height + $top
    $cv.SetResourceReference([System.Windows.Controls.Panel]::BackgroundProperty, 'B.Card')
    foreach ($cap in (Get-MspkiGuiMapCaption -Model $Model)) {
        $t = New-Object System.Windows.Controls.TextBlock
        $t.Text = $cap.Text; $t.Style = $g.Window.FindResource('Label')
        [System.Windows.Controls.Canvas]::SetLeft($t, [double]$cap.X); [System.Windows.Controls.Canvas]::SetTop($t, $(if ($Kind -eq 'Page') { 8 } else { 0 }))
        [void]$cv.Children.Add($t)
    }
    $byId = @{}; foreach ($n in $Model.Nodes) { $byId[[string]$n.Id] = $n }
    if ($Kind -eq 'Page') {
        # Attached now, collapsed: each slice then attaches its own elements (attaching 700 at once took about 40 ms).
        if ($g.MapDraws.ContainsKey('Page')) { $g.MapLayer.Children.Remove($g.MapDraws.Page.Canvas) }
        $cv.Visibility = 'Collapsed'
        [void]$g.MapLayer.Children.Add($cv)
    }
    $g.MapDraws[$Kind] = @{
        Kind = $Kind; Model = $Model; Canvas = $cv; Top = $top; Width = $Width; ById = $byId; NodeAt = 0; LinkAt = 0; Marked = @{}
        Drawn = [pscustomobject]@{ Nodes = (New-Object System.Collections.ArrayList); Links = (New-Object System.Collections.ArrayList); ById = @{}; Canvas = $cv; Top = $top; Model = $Model }
        Started = [DateTime]::Now; Slices = 0; MaxSliceMs = 0
    }
    if ($g.MapSync) { while ($g.MapDraws.ContainsKey($Kind)) { Step-MspkiGuiMapDraw } ; return }
    $g.MapTimer.Start()
}

function Step-MspkiGuiMapDraw {
    <#
    .SYNOPSIS
    Draws the next slice (at most about 30 ms) of every pending map drawing; a finished drawing replaces the canvas on screen.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    # One budget for the whole tick, shared by the drawings in progress (the Overview's and the page's).
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $gc2 = [System.GC]::CollectionCount(2)
    foreach ($kind in @('Overview', 'Page')) {
        if (-not $g.MapDraws.ContainsKey($kind)) { continue }
        if ($sw.ElapsedMilliseconds -ge $script:MspkiGuiMapSliceMs) { break }
        $d = $g.MapDraws[$kind]
        $nodes = @($d.Model.Nodes); $links = @($d.Model.Links)
        $gap = $(if ($null -ne $d.Model.PSObject.Properties['Gap'] -and $d.Model.Gap) { [double]$d.Model.Gap } else { 38.0 })
        while ($d.NodeAt -lt $nodes.Count -and $sw.ElapsedMilliseconds -lt $script:MspkiGuiMapSliceMs) {
            $n = $nodes[$d.NodeAt]; $d.NodeAt++
            $v = New-MspkiGuiMapNodeVisual -Node $n -Canvas $d.Canvas -Top $d.Top -Gap $gap
            [void]$d.Drawn.Nodes.Add($v); $d.Drawn.ById[[string]$n.Id] = $v
        }
        while ($d.NodeAt -ge $nodes.Count -and $d.LinkAt -lt $links.Count -and $sw.ElapsedMilliseconds -lt $script:MspkiGuiMapSliceMs) {
            $l = $links[$d.LinkAt]; $d.LinkAt++
            if (-not $d.Drawn.ById.ContainsKey([string]$l.From) -or -not $d.Drawn.ById.ContainsKey([string]$l.To)) { continue }
            $from = $d.ById[[string]$l.From]; $to = $d.ById[[string]$l.To]
            $lv = New-MspkiGuiMapLinkVisual -Link $l -From $from -To $to -Canvas $d.Canvas -Top $d.Top -StartX $d.Drawn.ById[[string]$l.From].LabelEnd -Marked $d.Marked
            $lv | Add-Member -NotePropertyName From -NotePropertyValue $from
            $lv | Add-Member -NotePropertyName To -NotePropertyValue $to
            if (-not ($from.Match -and $to.Match)) { $lv.Path.Opacity = 0.2; if ($null -ne $lv.Marker) { $lv.Marker.Opacity = 0.3 } }
            [void]$d.Drawn.Links.Add($lv)
        }
        $d.Slices++
        # A finished drawing goes on screen at the start of a tick of its own (swapping the canvas also costs time).
        if ($d.NodeAt -ge $nodes.Count -and $d.LinkAt -ge $links.Count -and ($d.Slices -gt 1 -and $sw.ElapsedMilliseconds -lt 2 -or $g.MapSync)) {
            $g.MapDraws.Remove($kind)
            $g.MapPerf.LastDrawMs = [int]([DateTime]::Now - $d.Started).TotalMilliseconds
            $g.MapPerf.LastSlices = $d.Slices
            if ($kind -eq 'Overview') { Complete-MspkiGuiOverviewDraw -Draw $d } else { Complete-MspkiGuiMapPageDraw -Draw $d }
        }
    }
    foreach ($kind in @('Overview', 'Page')) {
        if (-not $g.MapAnims.ContainsKey($kind)) { continue }
        if ($sw.ElapsedMilliseconds -ge $script:MspkiGuiMapSliceMs) { break }
        $a = $g.MapAnims[$kind]
        while ($a.NodeAt -lt $a.Nodes.Count -and $sw.ElapsedMilliseconds -lt $script:MspkiGuiMapSliceMs) {
            Add-MspkiGuiNodeBuild -Storyboard $a.Storyboard -D $a.Nodes[$a.NodeAt] -P $a.Paths -SettleIndex $(if ($a.Settle) { $a.NodeAt } else { -1 })
            $a.NodeAt++
        }
        while ($a.NodeAt -ge $a.Nodes.Count -and $a.LinkAt -lt $a.Links.Count -and $sw.ElapsedMilliseconds -lt $script:MspkiGuiMapSliceMs) {
            Add-MspkiGuiLinkBuild -Storyboard $a.Storyboard -L $a.Links[$a.LinkAt] -P $a.Paths
            $a.LinkAt++
        }
        if ($a.NodeAt -ge $a.Nodes.Count -and $a.LinkAt -ge $a.Links.Count -and ($sw.ElapsedMilliseconds -lt 4 -or $g.MapSync)) { $g.MapAnims.Remove($kind); Complete-MspkiGuiAnimBuild -Build $a }
    }
    # The whole tick, putting the finished canvas on screen included, is what the UI thread spent.
    $ms = [int]$sw.ElapsedMilliseconds
    # A tick during which .NET ran a full garbage collection is counted apart (that pause is not the map's work).
    if ([System.GC]::CollectionCount(2) -ne $gc2) { $g.MapPerf.GcTicks.Add($ms); return }
    if ($ms -gt $g.MapPerf.MaxSliceMs) { $g.MapPerf.MaxSliceMs = $ms }
    $g.MapPerf.Ticks.Add($ms)
}

function Complete-MspkiGuiOverviewDraw {
    # The Overview's map is complete: put it on screen and play the build when one is pending.
    param([Parameter(Mandatory = $true)][hashtable]$Draw)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($g.MapAnimatePending -and -not (Test-MspkiGuiReducedMotion)) {
        # With a build to play, the new canvas waits until its animation is ready (no flash of the finished map first).
        $g.MapAnimatePending = $false
        $noMap = [bool]$g.MapNoMapOnce
        $g.MapNoMapOnce = $false
        $sb = New-MspkiGuiMissionStoryboard -Drawn $Draw.Drawn -TotalMs ([double]$g.MapTotalMs) -NoMap:$noMap -HeroOnly
        Start-MspkiGuiAnimBuild -Kind Overview -Storyboard $sb -Drawn $Draw.Drawn -Settle:$noMap -Draw $Draw
        return
    }
    $g.MapAnimatePending = $false
    Set-MspkiGuiOverviewCanvas -Draw $Draw
}

function Set-MspkiGuiOverviewCanvas {
    # Puts a finished Overview map on screen.
    param([Parameter(Mandatory = $true)][hashtable]$Draw)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -ne $g.Storyboard) { try { $g.Storyboard.Stop($ui.PanelResults); $g.Storyboard.Remove($ui.PanelResults) } catch { $null = $_ }; $g.Storyboard = $null }
    $ui.MapCanvasHost.Child = $Draw.Canvas
    $ui.MapCanvas = $Draw.Canvas
    # A map taller than the card (560 px) fades out at the bottom, with the way to the full-page map.
    $more = ([double]$Draw.Canvas.Height -gt 560)
    $ui.MapMoreStrip.Visibility = $(if ($more) { 'Visible' } else { 'Collapsed' })
    $ui.BtnMapMore.Visibility = $(if ($more) { 'Visible' } else { 'Collapsed' })
    $ui.TxtMapMore.Text = 'Open the whole map ({0})' -f (Format-MspkiGuiCount -Count ([int]$Draw.Model.Total) -Singular 'object')
    $g.MapDrawn = $Draw.Drawn
    $g.MapDrawnWidth = $Draw.Width
    $m = $Draw.Model
    $ui.TxtMapStats.Text = '{0}{1}{2}{3}' -f (Format-MspkiGuiCount -Count ([int]$m.Total) -Singular 'object'), $script:MspkiGuiDot, (Format-MspkiGuiCount -Count @($m.Links).Count -Singular 'link'), $(if ($m.Groups -gt 0) { '{0}{1} grouped: open the Discovery map to expand them' -f $script:MspkiGuiDot, (Format-MspkiGuiCount -Count ([int]$m.Groups) -Singular 'group') } else { '' })
}

function Start-MspkiGuiAnimBuild {
    <#
    .SYNOPSIS
    Builds a map's build animation in slices (with the map timer, inside the same per-tick budget as the drawing) and starts it when it is
    complete: -Kind Overview (with the score ring and bars already in the storyboard; -Draw: the new canvas goes on screen at the same
    moment) or Page (the replay). -Settle: only the health colours settle (a map that was built live during the run).
    #>
    param([Parameter(Mandatory = $true)][ValidateSet('Overview', 'Page')][string]$Kind, [Parameter(Mandatory = $true)]$Storyboard, [Parameter(Mandatory = $true)]$Drawn, [switch]$Settle, $Draw = $null)
    $g = $script:MspkiGui
    $nodes = $(if ($Settle) { Get-MspkiGuiSettleOrder -Drawn $Drawn } else { [object[]]@($Drawn.Nodes) })
    $g.MapAnims[$Kind] = @{ Kind = $Kind; Storyboard = $Storyboard; Drawn = $Drawn; Settle = [bool]$Settle; Draw = $Draw; Paths = (New-MspkiGuiBuildPaths)
        Nodes = [object[]]@($nodes); Links = $(if ($Settle) { [object[]]@() } else { [object[]]@($Drawn.Links) }); NodeAt = 0; LinkAt = 0 }
    if ($g.MapSync) { while ($g.MapAnims.ContainsKey($Kind)) { Step-MspkiGuiMapDraw }; return }
    $g.MapTimer.Start()
}

function Complete-MspkiGuiAnimBuild {
    # A build animation is ready: (put the new Overview canvas on screen and) start it.
    param([Parameter(Mandatory = $true)][hashtable]$Build)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($Build.Kind -eq 'Overview') {
        if ($null -ne $Build.Draw) { Set-MspkiGuiOverviewCanvas -Draw $Build.Draw }
        if ($null -ne $g.Storyboard) { try { $g.Storyboard.Stop($ui.PanelResults); $g.Storyboard.Remove($ui.PanelResults) } catch { $null = $_ } }
        $g.Storyboard = $Build.Storyboard
        $g.Storyboard.Begin($ui.PanelResults, $true)
        return
    }
    if ($null -ne $g.MapPageStoryboard) { try { $g.MapPageStoryboard.Stop($ui.MapWorld) } catch { $null = $_ } }
    $g.MapPageStoryboard = $Build.Storyboard
    $g.MapPageStoryboard.Begin($ui.MapWorld, $true)
}

function Wait-MspkiGuiMapIdle {
    <#
    .SYNOPSIS
    Developer snapshots and tests: lets the window process its map work (worker jobs and drawing slices) until none is left, or -TimeoutMs.
    #>
    [CmdletBinding()]
    param([int]$TimeoutMs = 15000)
    $g = $script:MspkiGui
    $end = [DateTime]::Now.AddMilliseconds($TimeoutMs)
    while ([DateTime]::Now -lt $end) {
        if ($null -eq $g.MapJob -and $g.MapQueue.Count -eq 0 -and $g.MapDraws.Count -eq 0 -and $g.MapAnims.Count -eq 0) { break }
        $frame = New-Object System.Windows.Threading.DispatcherFrame
        $cb = [System.Action]{ $frame.Continue = $false }
        [void][System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, $cb)
        [System.Windows.Threading.Dispatcher]::PushFrame($frame)
        if ($null -ne $g.MapJob -and $g.MapJob.Async.IsCompleted) { Receive-MspkiGuiMapJob }
        elseif ($g.MapDraws.Count -gt 0 -or $g.MapAnims.Count -gt 0) { Receive-MspkiGuiMapJob }
        else { Start-Sleep -Milliseconds 5 }
    }
}

# ---------------------------------------------------------------- the full-page map

function Get-MspkiGuiMapOptions {
    # The page's filters as a job's options.
    $g = $script:MspkiGui
    $ui = $g.Ui
    $st = 'All'; if ($ui.FltMapStatus.SelectedIndex -gt 0) { $st = [string]$script:MspkiGuiMapStatusChoices[$ui.FltMapStatus.SelectedIndex].Value }
    $ty = 'All'; if ($ui.FltMapType.SelectedIndex -gt 0) { $ty = [string]$script:MspkiGuiMapTypeChoices[$ui.FltMapType.SelectedIndex].Value }
    $fo = ''; if ($ui.FltMapFocus.SelectedIndex -gt 0 -and $null -ne $g.MapFocusValues -and $ui.FltMapFocus.SelectedIndex -lt @($g.MapFocusValues).Count) { $fo = [string]@($g.MapFocusValues)[$ui.FltMapFocus.SelectedIndex] }
    return @{ Status = $st; Type = $ty; FocusId = $fo; OnlyProblems = [bool]$ui.ChkMapProblems.IsChecked; Expanded = $g.MapExpanded.Clone(); Search = [string]$ui.FltMap.Text; Threshold = $script:MspkiGuiMapClusterThreshold }
}

function Update-MspkiGuiMapPage {
    <#
    .SYNOPSIS
    Asks for the full-page map with the current filters (after results load, a filter change, a group expanded). -Fit fits it to the window.
    #>
    [CmdletBinding()]
    param([switch]$Fit)
    $g = $script:MspkiGui
    if ($null -eq $g.Data) { return }
    if ($Fit) { $g.MapFitPending = $true }
    if ($null -eq $g.Index) { Show-MspkiGuiMapPageEmpty; return }
    Request-MspkiGuiMapJob -Kind Page -Options (Get-MspkiGuiMapOptions)
}

function Set-MspkiGuiMapBusy {
    param([bool]$Busy)
    $ui = $script:MspkiGui.Ui
    if ($null -eq $ui.MapBusy) { return }
    $ui.MapBusy.Visibility = $(if ($Busy) { 'Visible' } else { 'Collapsed' })
}

function Show-MspkiGuiMapPageEmpty {
    # The page without a map: older results, nothing found, or filters that match nothing (with the way out).
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.MapLayer.Children.Clear(); $g.MapPageCanvas = $null
    $g.MapPageDrawn = $null
    $ui.MiniMap.Visibility = 'Collapsed'
    $ui.MapZoomBar.Visibility = 'Collapsed'
    $filtered = ($null -ne $g.MapPageModel -and $g.MapPageModel.Filtered)
    $ui.TxtMapPageEmpty.Text = $(if ($null -ne $g.Run) { 'The map appears here when the run finishes. Until then the Overview shows it building live.' }
        elseif ($null -eq $g.Data) { 'Run the health check, or open an earlier run, to see the map.' }
        elseif ($null -eq $g.Index) { 'These results were written by an older version of the tool, without the object graph, so there is no map. The tree view still lists everything; run the health check again to see the map.' }
        elseif ($filtered) { 'Nothing on the map matches these filters.' }
        else { 'This run found no CA certificate or published address to draw.' })
    $ui.BtnMapClearEmpty.Visibility = $(if ($filtered) { 'Visible' } else { 'Collapsed' })
    $ui.MapEmptyPanel.Visibility = 'Visible'
    $ui.TxtMapPageStats.Text = ''
}

function Complete-MspkiGuiMapPageDraw {
    # The full-page map is complete: swap it in, keep (or fit) the zoom, restore the selection, update the counts and the minimap.
    param([Parameter(Mandatory = $true)][hashtable]$Draw)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -ne $g.MapPageStoryboard) { try { $g.MapPageStoryboard.Stop($ui.MapWorld) } catch { $null = $_ }; $g.MapPageStoryboard = $null }
    foreach ($c in @($g.MapLayer.Children)) { if ($c -ne $Draw.Canvas) { $g.MapLayer.Children.Remove($c) } }
    $Draw.Canvas.Visibility = 'Visible'
    $g.MapPageCanvas = $Draw.Canvas
    $g.MapPageDrawn = $Draw.Drawn
    $ui.MapEmptyPanel.Visibility = 'Collapsed'
    $ui.MapZoomBar.Visibility = 'Visible'
    $m = $Draw.Model
    $ring = New-Object System.Windows.Shapes.Ellipse
    $ring.Width = 36; $ring.Height = 36; $ring.StrokeThickness = 2; $ring.IsHitTestVisible = $false; $ring.Visibility = 'Collapsed'
    $ring.SetResourceReference([System.Windows.Shapes.Shape]::StrokeProperty, 'B.FocusRing')
    $ring.StrokeDashArray = [System.Windows.Media.DoubleCollection]::Parse('2.0 1.5')
    [System.Windows.Controls.Panel]::SetZIndex($ring, 5)
    [void]$Draw.Canvas.Children.Add($ring)
    $g.MapFocusRing = $ring
    $parts = @('{0} of {1}' -f ([int]$m.Shown), (Format-MspkiGuiCount -Count ([int]$m.Total) -Singular 'object'))
    if ($m.Groups -gt 0) { $parts += ('{0} (select one to expand it)' -f (Format-MspkiGuiCount -Count ([int]$m.Groups) -Singular 'group')) }
    if ($ui.FltMap.Text.Trim()) { $parts += $(if ($m.Matches -eq 0) { 'nothing matches the search' } else { '{0} the search' -f $(if ($m.Matches -eq 1) { '1 matches' } else { '{0} match' -f $m.Matches }) }) }
    $ui.TxtMapPageStats.Text = $parts -join $script:MspkiGuiDot
    $ui.BtnMapCollapse.Visibility = $(if ($g.MapExpanded.Count -gt 0) { 'Visible' } else { 'Collapsed' })
    $ui.MiniMapImage.Fill = $(if ($null -ne $Draw.Canvas) { $vb = New-Object System.Windows.Media.VisualBrush($Draw.Canvas); $vb.Stretch = 'Uniform'; $vb.AlignmentX = 'Left'; $vb.AlignmentY = 'Top'; $vb } else { $null })
    if ($g.MapFitPending -or $g.MapZoom -le 0) { $g.MapFitPending = $false; Set-MspkiGuiMapFit -Readable }
    else { Set-MspkiGuiMapTransform -Scale $g.MapZoom -X $g.MapOffX -Y $g.MapOffY }
    if ($g.MapFocusId -and -not $Draw.Drawn.ById.ContainsKey($g.MapFocusId)) { $g.MapFocusId = '' }
    if ($g.MapPendingSelect) { $id = $g.MapPendingSelect; $g.MapPendingSelect = ''; Select-MspkiGuiMapNode -Id $id -Open -Reveal }
    else { Update-MspkiGuiMapSelectionLook }
    Set-MspkiGuiMapBusy -Busy $false
    $ui.BtnMapReplay.IsEnabled = $ui.RbMapCanvas.IsChecked; $ui.BtnMapExport.IsEnabled = $ui.RbMapCanvas.IsChecked
    if ($g.MapReplayPending) { $g.MapReplayPending = $false; Start-MspkiGuiMapReplay }
}

function Set-MspkiGuiMapTransform {
    <#
    .SYNOPSIS
    Applies a zoom and an offset to the full-page map (kept so that some of the map always stays in view), and updates the zoom controls
    and the minimap. Cheap: two transforms.
    #>
    param([double]$Scale, [double]$X, [double]$Y)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $stops = $script:MspkiGuiMapZoomStops
    $Scale = [math]::Max($stops[0], [math]::Min($stops[-1], $Scale))
    $cv = $g.MapPageCanvas
    $vw = $ui.MapViewport.ActualWidth; $vh = $ui.MapViewport.ActualHeight
    if ($null -ne $cv -and $vw -gt 0) {
        $cw = $cv.Width * $Scale; $ch = $cv.Height * $Scale
        $keep = 80.0
        $X = [math]::Min($vw - $keep, [math]::Max($keep - $cw, $X))
        $Y = [math]::Min($vh - $keep, [math]::Max($keep - $ch, $Y))
    }
    $g.MapZoom = $Scale; $g.MapOffX = [math]::Round($X); $g.MapOffY = [math]::Round($Y)
    $ui.MapScale.ScaleX = $Scale; $ui.MapScale.ScaleY = $Scale
    $ui.MapPan.X = $g.MapOffX; $ui.MapPan.Y = $g.MapOffY
    $g.MapSliderSilent = $true
    $ui.SldZoom.Value = $Scale
    $g.MapSliderSilent = $false
    $ui.TxtZoom.Text = '{0:0} %' -f ($Scale * 100)
    [System.Windows.Automation.AutomationProperties]::SetName($ui.SldZoom, ('Zoom, {0:0} percent' -f ($Scale * 100)))
    Update-MspkiGuiMiniMap
}

function Set-MspkiGuiMapFit {
    <#
    .SYNOPSIS
    Fits the whole map into the window (Ctrl+0, the Fit button), above the zoom bar. -Readable (a new run): never below 84 % (map labels at 10 px or more, D-06), so a large
    estate opens readable, centred, with the minimap showing the whole.
    #>
    param([switch]$Readable)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $cv = $g.MapPageCanvas
    if ($null -eq $cv) { return }
    $vw = $ui.MapViewport.ActualWidth; $vh = [math]::Max(120.0, $ui.MapViewport.ActualHeight - 52)
    $f = Get-MspkiGuiMapFit -ContentWidth $cv.Width -ContentHeight $cv.Height -ViewWidth $vw -ViewHeight $vh
    if ($Readable -and $f.Scale -lt 0.84) {
        $s = 0.84
        Set-MspkiGuiMapTransform -Scale $s -X ([math]::Max(16.0, ($vw - $cv.Width * $s) / 2.0)) -Y (($vh - $cv.Height * $s) / 2.0)
        return
    }
    Set-MspkiGuiMapTransform -Scale $f.Scale -X $f.X -Y $f.Y
}

function Step-MspkiGuiMapZoomBy {
    <#
    .SYNOPSIS
    Zooms the full-page map in or out to the next stop (Ctrl+plus, Ctrl+minus, the buttons) or by a factor (Ctrl+wheel), around a point
    of the view (the middle by default).
    #>
    param([ValidateSet('In', 'Out')][string]$Direction = 'In', [double]$Factor = 0, [double]$AtX = -1, [double]$AtY = -1)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -eq $g.MapPageCanvas) { return }
    $s = [double]$g.MapZoom
    $new = $(if ($Factor -gt 0) { $s * $Factor } else { Step-MspkiGuiMapZoom -Scale $s -Direction $Direction })
    if ($AtX -lt 0) { $AtX = $ui.MapViewport.ActualWidth / 2.0; $AtY = $ui.MapViewport.ActualHeight / 2.0 }
    $new = [math]::Max($script:MspkiGuiMapZoomStops[0], [math]::Min($script:MspkiGuiMapZoomStops[-1], $new))
    $o = Get-MspkiGuiMapZoomAt -Scale $s -NewScale $new -OffsetX $g.MapOffX -OffsetY $g.MapOffY -PointX $AtX -PointY $AtY
    Set-MspkiGuiMapTransform -Scale $new -X $o.X -Y $o.Y
}

function Move-MspkiGuiMapPan {
    param([double]$DX, [double]$DY)
    $g = $script:MspkiGui
    Set-MspkiGuiMapTransform -Scale $g.MapZoom -X ($g.MapOffX + $DX) -Y ($g.MapOffY + $DY)
}

function Update-MspkiGuiMiniMap {
    <#
    .SYNOPSIS
    The minimap (bottom right): shown for a large estate (300 objects or more) or whenever the map does not fit the window; the accent
    frame is the part in view.
    #>
    $g = $script:MspkiGui
    $ui = $g.Ui
    $cv = $g.MapPageCanvas
    if ($null -eq $cv -or $ui.MapViewport.ActualWidth -le 0) { $ui.MiniMap.Visibility = 'Collapsed'; return }
    $vw = $ui.MapViewport.ActualWidth; $vh = $ui.MapViewport.ActualHeight
    $s = [double]$g.MapZoom
    $fits = ($g.MapOffX -ge 0 -and $g.MapOffY -ge 0 -and $g.MapOffX + $cv.Width * $s -le $vw + 1 -and $g.MapOffY + $cv.Height * $s -le $vh + 1)
    $large = ($null -ne $g.Index -and $g.Index.Entities.Count -ge 300)
    $show = (($large -or -not $fits) -and $vw -ge 520 -and $vh -ge 300)
    $ui.MiniMap.Visibility = $(if ($show) { 'Visible' } else { 'Collapsed' })
    if (-not $show) { return }
    $mw = 176.0; $mh = 116.0
    $m = [math]::Min($mw / $cv.Width, $mh / $cv.Height)
    $g.MiniMapScale = $m
    $rx = [math]::Max(0.0, -$g.MapOffX / $s * $m); $ry = [math]::Max(0.0, -$g.MapOffY / $s * $m)
    $rw = [math]::Min($cv.Width * $m - $rx, $vw / $s * $m); $rh = [math]::Min($cv.Height * $m - $ry, $vh / $s * $m)
    $ui.MiniMapView.Width = [math]::Max(4.0, $rw); $ui.MiniMapView.Height = [math]::Max(4.0, $rh)
    [System.Windows.Controls.Canvas]::SetLeft($ui.MiniMapView, $rx); [System.Windows.Controls.Canvas]::SetTop($ui.MiniMapView, $ry)
}

function Move-MspkiGuiMapToMiniPoint {
    # A click or drag on the minimap centres the view there.
    param([double]$X, [double]$Y)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if (-not $g.MiniMapScale) { return }
    $cx = $X / $g.MiniMapScale; $cy = $Y / $g.MiniMapScale
    $s = $g.MapZoom
    Set-MspkiGuiMapTransform -Scale $s -X ($ui.MapViewport.ActualWidth / 2.0 - $cx * $s) -Y ($ui.MapViewport.ActualHeight / 2.0 - $cy * $s)
}

function Show-MspkiGuiMapNodeInView {
    # Pans (never zooms) so that a node is inside the view with a margin.
    param([Parameter(Mandatory = $true)]$Drawn)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $s = $g.MapZoom
    $top = [double]$g.MapPageDrawn.Top
    $x = [double]$Drawn.Node.X * $s + $g.MapOffX; $y = ([double]$Drawn.Node.Y + $top) * $s + $g.MapOffY
    $right = ([double]$Drawn.LabelEnd) * $s + $g.MapOffX
    $vw = $ui.MapViewport.ActualWidth; $vh = $ui.MapViewport.ActualHeight
    $dx = 0.0; $dy = 0.0
    if ($x -lt 40) { $dx = 40 - $x } elseif ($right -gt $vw - 24) { $dx = [math]::Max(40 - $x, ($vw - 24) - $right) }
    if ($y -lt 48) { $dy = 48 - $y } elseif ($y -gt $vh - 140) { $dy = ($vh - 140) - $y }
    if ($dx -ne 0 -or $dy -ne 0) { Move-MspkiGuiMapPan -DX $dx -DY $dy }
}

function Update-MspkiGuiMapSelectionLook {
    # The opened node's label is tinted (selected); the keyboard focus node has a dashed ring while the map has the keyboard focus.
    $g = $script:MspkiGui
    $ui = $g.Ui
    $dr = $g.MapPageDrawn
    if ($null -eq $dr) { return }
    foreach ($d in $dr.Nodes) {
        $sel = ([string]$d.Node.EntityId -and [string]$d.Node.EntityId -eq [string]$g.MapSelectedEntity) -or ([string]$d.Node.Id -eq [string]$g.MapSelectedId)
        if ($sel) { $d.Label.Uid = 'selected'; $d.Label.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'B.Select') }
        elseif ([string]$d.Label.Uid -eq 'selected') { $d.Label.Uid = ''; $d.Label.SetResourceReference([System.Windows.Controls.Border]::BackgroundProperty, 'B.Card') }
    }
    $ring = $g.MapFocusRing
    if ($null -eq $ring) { return }
    if ($g.MapFocusId -and $dr.ById.ContainsKey($g.MapFocusId) -and $ui.MapViewport.IsKeyboardFocusWithin) {
        $d = $dr.ById[$g.MapFocusId]
        [System.Windows.Controls.Canvas]::SetLeft($ring, [double]$d.Node.X - 5); [System.Windows.Controls.Canvas]::SetTop($ring, [double]$d.Node.Y + $dr.Top - 18)
        $ring.Visibility = 'Visible'
        [System.Windows.Automation.AutomationProperties]::SetName($ui.MapViewport, ('Discovery map. {0}. Arrow keys move between objects, Enter opens one.' -f [System.Windows.Automation.AutomationProperties]::GetName($d.Label)))
    }
    else { $ring.Visibility = 'Collapsed' }
}

function Select-MspkiGuiMapNode {
    <#
    .SYNOPSIS
    Selects a node of the full-page map. -Open shows it in the details pane (an object: its pane, pushed on the pane's trail so that Back
    and Alt+Left return to the previous one; a group: expands it; the "Unknown issuer" placeholder: what it stands for). -Reveal pans to it.
    #>
    param([Parameter(Mandatory = $true)][string]$Id, [switch]$Open, [switch]$Reveal)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $dr = $g.MapPageDrawn
    if ($null -eq $dr) { return }
    if (-not $dr.ById.ContainsKey($Id)) {
        # An object inside a group: expand the group first, then select it when the map is drawn again.
        foreach ($d in $dr.Nodes) {
            if ($d.Node.Kind -eq 'Cluster' -and @($d.Node.Members) -contains $Id) { $g.MapExpanded[[string]$d.Node.HostId] = $true; $g.MapPendingSelect = $Id; Update-MspkiGuiMapPage; return }
        }
        return
    }
    $d = $dr.ById[$Id]
    $g.MapFocusId = $Id
    if ($Reveal) { Show-MspkiGuiMapNodeInView -Drawn $d }
    if ($Open) {
        $n = $d.Node
        switch ([string]$n.Kind) {
            'Cluster' { $g.MapExpanded[[string]$n.HostId] = $true; $g.MapFocusId = [string]@($n.Members)[0]; Update-MspkiGuiMapPage; return }
            'Unknown' { $g.MapSelectedId = $Id; $g.MapSelectedEntity = ''; $ui.MapHost.Content = Get-MspkiGuiEmptyPane -Text ([string]$n.Explain) }
            default {
                $g.MapSelectedId = $Id; $g.MapSelectedEntity = [string]$n.EntityId
                if (-not $g.Nav.ContainsKey('MapHost')) { Reset-MspkiGuiPaneNav -HostName 'MapHost' }
                $nav = $g.Nav.MapHost
                $t = @($nav.Trail)
                if ($t.Count -eq 0 -or $t[$t.Count - 1] -ne [string]$n.EntityId) { $nav.Return = $null; $nav.Origin = $null; $nav.Trail = Step-MspkiGuiTrail -Trail $nav.Trail -Action Push -Id ([string]$n.EntityId) }
                Show-MspkiGuiEntityPane -HostName 'MapHost'
            }
        }
    }
    Update-MspkiGuiMapSelectionLook
}

function Sync-MspkiGuiMapSelection {
    # After Back or a breadcrumb in the map's details pane, the map selects the object the pane now shows.
    $g = $script:MspkiGui
    if ($null -eq $g.MapPageDrawn -or -not $g.Nav.ContainsKey('MapHost')) { return }
    $t = @($g.Nav.MapHost.Trail)
    $g.MapSelectedEntity = $(if ($t.Count -gt 0) { [string]$t[$t.Count - 1] } else { '' })
    $g.MapSelectedId = ''
    foreach ($d in $g.MapPageDrawn.Nodes) { if ([string]$d.Node.EntityId -eq $g.MapSelectedEntity -and $g.MapSelectedEntity) { $g.MapSelectedId = [string]$d.Node.Id; $g.MapFocusId = [string]$d.Node.Id; Show-MspkiGuiMapNodeInView -Drawn $d; break } }
    Update-MspkiGuiMapSelectionLook
}

function Invoke-MspkiGuiMapNodeClick {
    <#
    .SYNOPSIS
    A node was clicked. On the full-page map it is selected and opened (unless the mouse was dragging the map); on the Overview the full-page
    map opens with that node selected.
    #>
    param([Parameter(Mandatory = $true)][string]$Tag, $Source = $null)
    $g = $script:MspkiGui
    if (-not $Tag.StartsWith('node:')) { return }
    $id = $Tag.Substring(5)
    $onPage = ($null -ne $g.MapPageDrawn -and $null -ne $Source -and [System.Windows.Media.VisualTreeHelper]::GetParent($Source) -eq $g.MapPageCanvas)
    if ($onPage) {
        if ($null -ne $g.MapDrag -and $g.MapDrag.Moved) { return }
        Select-MspkiGuiMapNode -Id $id -Open
        [void]$g.Ui.MapViewport.Focus()
        return
    }
    Open-MspkiGuiMapPageAt -Id $id
}

function Open-MspkiGuiMapPageAt {
    # Opens the full-page map (map view) with one node selected; groups on the Overview open expanded.
    param([Parameter(Mandatory = $true)][string]$Id)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $ui.RbMapCanvas.IsChecked = $true
    $ui.Tabs.SelectedItem = $ui.TabMap
    if ($Id.StartsWith('cluster:')) { $g.MapExpanded[$Id.Substring(8)] = $true; $g.MapPendingSelect = ''; Update-MspkiGuiMapPage; return }
    if ($null -ne $g.MapPageDrawn -and $g.MapPageDrawn.ById.ContainsKey($Id)) { Select-MspkiGuiMapNode -Id $Id -Open -Reveal; return }
    $g.MapPendingSelect = $Id
    if ($null -ne $g.MapPageDrawn) { Select-MspkiGuiMapNode -Id $Id -Open -Reveal } else { Update-MspkiGuiMapPage -Fit }
}

function Invoke-MspkiGuiMapKey {
    <#
    .SYNOPSIS
    Keys on the full-page map (the map has the keyboard focus): arrows move between nodes (the view follows), Enter opens the node,
    Shift+arrows pan, plus and minus zoom, 0 fits, Home and End go to the top and bottom of the column. Returns $true when handled.
    #>
    param([Parameter(Mandatory = $true)][System.Windows.Input.Key]$Key, [System.Windows.Input.ModifierKeys]$Modifiers = [System.Windows.Input.ModifierKeys]::None)
    $g = $script:MspkiGui
    $m = $g.MapPageModel
    if ($null -eq $m -or $null -eq $g.MapPageDrawn) { return $false }
    $shift = (($Modifiers -band [System.Windows.Input.ModifierKeys]::Shift) -ne 0)
    $dir = switch ($Key) { 'Up' { 'Up' } 'Down' { 'Down' } 'Left' { 'Left' } 'Right' { 'Right' } 'Home' { 'Home' } 'End' { 'End' } default { '' } }
    if ($dir -and $shift -and $dir -in @('Up', 'Down', 'Left', 'Right')) {
        $step = 80.0
        switch ($dir) { 'Up' { Move-MspkiGuiMapPan -DX 0 -DY $step } 'Down' { Move-MspkiGuiMapPan -DX 0 -DY (-$step) } 'Left' { Move-MspkiGuiMapPan -DX $step -DY 0 } 'Right' { Move-MspkiGuiMapPan -DX (-$step) -DY 0 } }
        return $true
    }
    if ($dir) {
        $next = Find-MspkiGuiMapNeighbor -Model $m -Id $g.MapFocusId -Direction $dir
        if ($next) { Select-MspkiGuiMapNode -Id $next -Reveal }
        return $true
    }
    # Enum comparisons: Key.Enter and Key.Return are the same value, whose name is "Return" (a string comparison would miss Enter).
    $K = [System.Windows.Input.Key]
    if ($Key -eq $K::Return -or $Key -eq $K::Space) { if ($g.MapFocusId) { Select-MspkiGuiMapNode -Id $g.MapFocusId -Open }; return $true }
    if ($Key -eq $K::OemPlus -or $Key -eq $K::Add) { Step-MspkiGuiMapZoomBy -Direction In; return $true }
    if ($Key -eq $K::OemMinus -or $Key -eq $K::Subtract) { Step-MspkiGuiMapZoomBy -Direction Out; return $true }
    if ($Key -eq $K::D0 -or $Key -eq $K::NumPad0) { Set-MspkiGuiMapFit; return $true }
    return $false
}

function Set-MspkiGuiMapViewMode {
    # Map (the canvas) or Tree (the accessible text alternative); both share the details pane.
    param([ValidateSet('Map', 'Tree')][string]$Mode)
    $ui = $script:MspkiGui.Ui
    $ui.MapCanvasPanel.Visibility = $(if ($Mode -eq 'Map') { 'Visible' } else { 'Collapsed' })
    $ui.MapTreePanel.Visibility = $(if ($Mode -eq 'Tree') { 'Visible' } else { 'Collapsed' })
    $g = $script:MspkiGui
    $ui.BtnMapReplay.IsEnabled = ($Mode -eq 'Map' -and $null -ne $g.MapPageDrawn)
    $ui.BtnMapExport.IsEnabled = ($Mode -eq 'Map' -and $null -ne $g.MapPageDrawn)
    if ($null -eq $g.Data) { return }
    # The details pane belongs to the view on show: the tree's selected item, or the map's opened object (or a hint).
    if ($Mode -eq 'Tree') {
        if ($null -eq $ui.MapTree.SelectedItem) {
            # The tree was hidden while the results loaded, so its first item could not be selected then.
            $ui.MapTree.UpdateLayout()
            $rc = $ui.MapTree.ItemContainerGenerator.ContainerFromIndex(0)
            if ($null -ne $rc) { $rc.IsSelected = $true }
        }
        if ($null -ne $ui.MapTree.SelectedItem) { Show-MspkiGuiNodePane -Node $ui.MapTree.SelectedItem }
        else { Reset-MspkiGuiPaneNav -HostName 'MapHost'; $ui.MapHost.Content = Get-MspkiGuiEmptyPane -Text 'Select an item in the tree to see what was found and why.' }
    }
    elseif ($g.MapSelectedEntity) { Reset-MspkiGuiPaneNav -HostName 'MapHost'; $g.Nav.MapHost.Trail = [string[]]@($g.MapSelectedEntity); Show-MspkiGuiEntityPane -HostName 'MapHost' }
    else { Reset-MspkiGuiPaneNav -HostName 'MapHost'; $ui.MapHost.Content = Get-MspkiGuiEmptyPane -Text 'Select an object on the map to see what was found and why. Arrow keys move between objects when the map has the focus.' }
}

function Update-MspkiGuiMapFocusChoice {
    # The "CA" filter lists the CAs of the loaded run (once per run).
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($g.MapFocusGen -eq $g.MapGen -or $null -eq $g.MapBase) { return }
    $g.MapFocusGen = $g.MapGen
    $items = @('All CAs'); $values = @('')
    $cas = @($g.MapBase.Nodes | Where-Object { $_.Kind -eq 'CA' } | Sort-Object Layer, Label)
    foreach ($n in $cas) { $items += [string]$n.Label; $values += [string]$n.Id }
    $g.MapFocusValues = $values
    $g.MapFilterSilent = $true
    $ui.FltMapFocus.ItemsSource = $items
    $ui.FltMapFocus.SelectedIndex = 0
    $g.MapFilterSilent = $false
}

function Reset-MspkiGuiMapPage {
    <#
    .SYNOPSIS
    Forgets the full-page map of the previous results (filters back to all, groups collapsed, zoom to fit on the next draw).
    #>
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.MapGen = [int]$g.MapGen + 1
    $g.MapCache = @{}
    $g.MapQueue.Clear(); $g.MapDraws.Clear(); $g.MapAnims.Clear()
    $g.MapExpanded = @{}; $g.MapFocusId = ''; $g.MapSelectedId = ''; $g.MapSelectedEntity = ''; $g.MapPendingSelect = ''
    $g.MapPageModel = $null; $g.MapPageDrawn = $null; $g.MapBase = $null; $g.MapZoom = 0; $g.MapFitPending = $true
    $g.MapFilterSilent = $true
    $ui.FltMap.Text = ''
    $ui.FltMapStatus.SelectedIndex = 0; $ui.FltMapType.SelectedIndex = 0
    $ui.FltMapFocus.ItemsSource = @('All CAs'); $ui.FltMapFocus.SelectedIndex = 0; $g.MapFocusValues = @('')
    $ui.ChkMapProblems.IsChecked = $false
    $g.MapFilterSilent = $false
    $g.MapLayer.Children.Clear(); $g.MapPageCanvas = $null
    $ui.MiniMap.Visibility = 'Collapsed'
    $ui.TxtMapPageStats.Text = ''
    Set-MspkiGuiMapBusy -Busy $false
    Show-MspkiGuiMapPageEmpty
    Set-MspkiGuiMapViewMode -Mode $(if ($ui.RbMapTree.IsChecked) { 'Tree' } else { 'Map' })
}

function Clear-MspkiGuiMapFilter {
    # Back to the whole map: no search, all statuses and types, all CAs, groups collapsed again.
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.MapFilterSilent = $true
    $ui.FltMap.Text = ''; $ui.FltMapStatus.SelectedIndex = 0; $ui.FltMapType.SelectedIndex = 0; $ui.FltMapFocus.SelectedIndex = 0; $ui.ChkMapProblems.IsChecked = $false
    $g.MapFilterSilent = $false
    Update-MspkiGuiMapPage
}

function Start-MspkiGuiMapReplay {
    <#
    .SYNOPSIS
    Plays the discovery of this run again on the full-page map. With reduced motion nothing moves: a toast says the map is already complete.
    #>
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -eq $g.MapPageDrawn) { return }
    if (Test-MspkiGuiReducedMotion) { Show-MspkiGuiToast -Text 'Animations are off in Windows, so the map is shown complete.' -Tone Info; return }
    if ($null -ne $g.MapPageStoryboard) { try { $g.MapPageStoryboard.Stop($ui.MapWorld) } catch { $null = $_ } }
    if ($null -ne $g.MapFocusRing) { $g.MapFocusRing.Visibility = 'Collapsed' }
    $sb = New-Object System.Windows.Media.Animation.Storyboard
    $sb.Duration = New-Object System.Windows.Duration([TimeSpan]::FromMilliseconds([double]$g.MapPageModel.TotalMs))
    Start-MspkiGuiAnimBuild -Kind Page -Storyboard $sb -Drawn $g.MapPageDrawn
}

function Initialize-MspkiGuiMapPage {
    <#
    .SYNOPSIS
    Wires the full-page map: filters, view switch, zoom controls, mouse (drag, wheel, Ctrl+wheel), keyboard, minimap, replay and export.
    #>
    $g = $script:MspkiGui
    $ui = $g.Ui
    foreach ($k in @{ MapWorker = $null; MapJob = $null; MapGen = 0; MapZoom = 0; MapOffX = 0; MapOffY = 0; MapFocusId = ''; MapSelectedId = ''; MapSelectedEntity = ''; MapPendingSelect = ''; MapFitPending = $true; MapPageModel = $null; MapPageDrawn = $null; MapBase = $null; MapDrag = $null; MapFocusGen = -1; MapSync = $false; MapFilterSilent = $false; MapSliderSilent = $false; MapReplayPending = $false; MapPageStoryboard = $null; MapFocusRing = $null; MiniMapScale = 0; MapStatus = @{} }.GetEnumerator()) { if (-not $g.ContainsKey($k.Key)) { $g[$k.Key] = $k.Value } }
    $g.MapLayer = New-Object System.Windows.Controls.Grid
    $ui.MapWorld.Child = $g.MapLayer
    $g.MapPageCanvas = $null
    $g.MapQueue = @{}; $g.MapDraws = @{}; $g.MapAnims = @{}; $g.MapCache = @{}; $g.MapExpanded = @{}
    $g.MapPerf = @{ MaxSliceMs = 0; LastLayoutMs = 0; LastModelMs = 0; LastDrawMs = 0; LastSlices = 0; Ticks = (New-Object 'System.Collections.Generic.List[int]'); GcTicks = (New-Object 'System.Collections.Generic.List[int]') }
    $g.MapTimer = New-Object System.Windows.Threading.DispatcherTimer([System.Windows.Threading.DispatcherPriority]::Background)
    $g.MapTimer.Interval = [TimeSpan]::FromMilliseconds(15)
    $g.MapTimer.Add_Tick({ try { Receive-MspkiGuiMapJob } catch { $script:MspkiGui.MapTimer.Stop(); [void](Invoke-MspkiGuiUnhandledError -Exception $_.Exception -Source 'map') } })
    $ui.FltMapStatus.ItemsSource = @($script:MspkiGuiMapStatusChoices | ForEach-Object { $_.Text }); $ui.FltMapStatus.SelectedIndex = 0
    $ui.FltMapType.ItemsSource = @($script:MspkiGuiMapTypeChoices | ForEach-Object { $_.Text }); $ui.FltMapType.SelectedIndex = 0
    $ui.FltMapFocus.ItemsSource = @('All CAs'); $ui.FltMapFocus.SelectedIndex = 0; $g.MapFocusValues = @('')
    $changed = { $s = $script:MspkiGui; if (-not $s.MapFilterSilent -and $null -ne $s.Data) { $s.MapExpanded = @{}; Update-MspkiGuiMapPage } }
    foreach ($c in @($ui.FltMapStatus, $ui.FltMapType, $ui.FltMapFocus)) { $c.Add_SelectionChanged($changed) }
    $ui.ChkMapProblems.Add_Click($changed)
    # Search only dims: a short pause after typing, then one redraw.
    $g.MapSearchTimer = New-Object System.Windows.Threading.DispatcherTimer
    $g.MapSearchTimer.Interval = [TimeSpan]::FromMilliseconds(250)
    $g.MapSearchTimer.Add_Tick({ $script:MspkiGui.MapSearchTimer.Stop(); Update-MspkiGuiMapPage })
    $ui.FltMap.Add_TextChanged({ $s = $script:MspkiGui; if (-not $s.MapFilterSilent -and $null -ne $s.Data) { $s.MapSearchTimer.Stop(); $s.MapSearchTimer.Start() } })
    $ui.BtnMapCollapse.Add_Click({ $script:MspkiGui.MapExpanded = @{}; Update-MspkiGuiMapPage })
    $ui.BtnMapClearEmpty.Add_Click({ Clear-MspkiGuiMapFilter })
    $ui.RbMapCanvas.Add_Checked({ Set-MspkiGuiMapViewMode -Mode Map })
    $ui.RbMapTree.Add_Checked({ Set-MspkiGuiMapViewMode -Mode Tree })
    $ui.BtnZoomIn.Add_Click({ Step-MspkiGuiMapZoomBy -Direction In })
    $ui.BtnZoomOut.Add_Click({ Step-MspkiGuiMapZoomBy -Direction Out })
    $ui.BtnZoomFit.Add_Click({ Set-MspkiGuiMapFit })
    $ui.SldZoom.Add_ValueChanged({ param($s, $e) $x = $script:MspkiGui; if (-not $x.MapSliderSilent -and $null -ne $x.MapPageCanvas) { Step-MspkiGuiMapZoomBy -Factor ([double]$e.NewValue / [math]::Max(0.01, [double]$x.MapZoom)) } })
    $ui.BtnMapReplay.Add_Click({ Start-MspkiGuiMapReplay })
    $ui.BtnMapMore.Add_Click({ $u = $script:MspkiGui.Ui; $u.RbMapCanvas.IsChecked = $true; $u.Tabs.SelectedItem = $u.TabMap })
    $ui.BtnMapExport.Add_Click({ Export-MspkiGuiMapPng })
    $vp = $ui.MapViewport
    $vp.Add_SizeChanged({ $s = $script:MspkiGui; if ($null -ne $s.MapPageCanvas) { if ($s.MapFitPending) { $s.MapFitPending = $false; Set-MspkiGuiMapFit -Readable } else { Update-MspkiGuiMiniMap } } })
    $vp.Add_PreviewMouseWheel({
        param($s, $e)
        $x = $script:MspkiGui
        if ($null -eq $x.MapPageCanvas) { return }
        $p = $e.GetPosition($x.Ui.MapViewport)
        $mods = [System.Windows.Input.Keyboard]::Modifiers
        if (($mods -band [System.Windows.Input.ModifierKeys]::Control) -ne 0) { Step-MspkiGuiMapZoomBy -Factor $(if ($e.Delta -gt 0) { 1.12 } else { 1 / 1.12 }) -AtX $p.X -AtY $p.Y }
        elseif (($mods -band [System.Windows.Input.ModifierKeys]::Shift) -ne 0) { Move-MspkiGuiMapPan -DX ($e.Delta / 2.0) -DY 0 }
        else { Move-MspkiGuiMapPan -DX 0 -DY ($e.Delta / 2.0) }
        $e.Handled = $true
    })
    $vp.Add_PreviewMouseLeftButtonDown({
        param($s, $e)
        $x = $script:MspkiGui
        if ($null -eq $x.MapPageCanvas) { return }
        $src = $e.OriginalSource
        $inMini = $false; $o = $src -as [System.Windows.DependencyObject]
        while ($null -ne $o) { if ($o -eq $x.Ui.MiniMap -or $o -eq $x.Ui.MapZoomBar) { $inMini = $true; break }; $o = [System.Windows.Media.VisualTreeHelper]::GetParent($o) }
        if ($inMini) { return }
        $x.MapDrag = @{ Start = $e.GetPosition($x.Ui.MapViewport); X = $x.MapOffX; Y = $x.MapOffY; Moved = $false; Space = [System.Windows.Input.Keyboard]::IsKeyDown([System.Windows.Input.Key]::Space) }
        [void]$x.Ui.MapViewport.Focus()
    })
    $vp.Add_PreviewMouseMove({
        param($s, $e)
        $x = $script:MspkiGui
        $d = $x.MapDrag
        if ($null -eq $d -or $e.LeftButton -ne 'Pressed') { return }
        $p = $e.GetPosition($x.Ui.MapViewport)
        $dx = $p.X - $d.Start.X; $dy = $p.Y - $d.Start.Y
        if (-not $d.Moved -and [math]::Abs($dx) + [math]::Abs($dy) -lt 4) { return }
        if (-not $d.Moved) { $d.Moved = $true; [void]$x.Ui.MapViewport.CaptureMouse(); $x.Ui.MapViewport.Cursor = [System.Windows.Input.Cursors]::SizeAll }
        Set-MspkiGuiMapTransform -Scale $x.MapZoom -X ($d.X + $dx) -Y ($d.Y + $dy)
    })
    $vp.Add_PreviewMouseLeftButtonUp({
        param($s, $e)
        $x = $script:MspkiGui
        $d = $x.MapDrag
        if ($null -eq $d) { return }
        if ($d.Moved) { $x.Ui.MapViewport.ReleaseMouseCapture(); $x.Ui.MapViewport.Cursor = $null; $e.Handled = $true }
        # The flag survives this event so that a node under the mouse does not treat the end of a drag as a click.
        $x.MapDrag = $(if ($d.Moved) { @{ Moved = $true } } else { $null })
        if ($d.Moved) { $null = $x.Window.Dispatcher.BeginInvoke([Action]{ $script:MspkiGui.MapDrag = $null }, [System.Windows.Threading.DispatcherPriority]::Background) }
    })
    $vp.Add_KeyDown({ param($s, $e) if (Invoke-MspkiGuiMapKey -Key $e.Key -Modifiers ([System.Windows.Input.Keyboard]::Modifiers)) { $e.Handled = $true } })
    $vp.Add_GotKeyboardFocus({ $x = $script:MspkiGui; if (-not $x.MapFocusId -and $null -ne $x.MapPageModel) { $x.MapFocusId = Find-MspkiGuiMapNeighbor -Model $x.MapPageModel -Id '' -Direction Home }; Update-MspkiGuiMapSelectionLook })
    $vp.Add_LostKeyboardFocus({ Update-MspkiGuiMapSelectionLook })
    $mini = $ui.MiniMap
    $mini.Add_MouseLeftButtonDown({ param($s, $e) $p = $e.GetPosition($script:MspkiGui.Ui.MiniMapCanvas); Move-MspkiGuiMapToMiniPoint -X $p.X -Y $p.Y; [void]$s.CaptureMouse(); $e.Handled = $true })
    $mini.Add_MouseMove({ param($s, $e) if ($e.LeftButton -eq 'Pressed' -and $s.IsMouseCaptured) { $p = $e.GetPosition($script:MspkiGui.Ui.MiniMapCanvas); Move-MspkiGuiMapToMiniPoint -X $p.X -Y $p.Y } })
    $mini.Add_MouseLeftButtonUp({ param($s, $e) $s.ReleaseMouseCapture() })
    Set-MspkiGuiMapViewMode -Mode Map
    Show-MspkiGuiMapPageEmpty
    # Warm-up: the first node and link drawn in a session compile their script code (about 40 ms); doing it once here, on a throw-away
    # canvas before the window is shown, keeps every drawing slice later within its budget.
    try {
        $wn = [pscustomobject]@{ Id = 'w'; EntityId = ''; Kind = 'Endpoint'; Label = 'w'; Sub = 'w'; Glyph = [string][char]0xE774; Tone = 'Bad'; FullName = 'w'; X = 10; Y = 10; LabelWidth = 60; Context = $false; Match = $true; Count = 0; Explain = ''; Members = @() }
        # Windows PowerShell interprets a function for its first calls and compiles it after about 16; running the drawing and animation
        # functions past that point here keeps the compile out of the slices.
        $wc = New-Object System.Windows.Controls.Canvas
        $wsb = New-Object System.Windows.Media.Animation.Storyboard
        $wp = New-MspkiGuiBuildPaths
        $wl = [pscustomobject]@{ Kind = 'publishes'; Tone = 'Bad'; Text = 'w'; Id = 'w2' }
        $wt = [pscustomobject]@{ Id = 'w2'; X = 200; Y = 40; AppearMs = 0; ResultMs = 0 }
        foreach ($i in 1..20) {
            $wd = New-MspkiGuiMapNodeVisual -Node $wn -Canvas $wc -Top 0 -Gap 38
            $wv = New-MspkiGuiMapLinkVisual -Link $wl -From $wn -To $wt -Canvas $wc -Top 0 -StartX $wd.LabelEnd -Marked @{}
            $wv | Add-Member -NotePropertyName From -NotePropertyValue $wn -Force; $wv | Add-Member -NotePropertyName To -NotePropertyValue $wt -Force
            Add-MspkiGuiNodeBuild -Storyboard $wsb -D $wd -P $wp
            Add-MspkiGuiNodeBuild -Storyboard $wsb -D $wd -P $wp -SettleIndex 1
            Add-MspkiGuiLinkBuild -Storyboard $wsb -L $wv -P $wp
        }
        $wc.Children.Clear(); $wsb.Children.Clear()
        # The zoom slider's change handler compiles on its first run.
        $g.MapSliderSilent = $false; $ui.SldZoom.Value = 0.9; $ui.SldZoom.Value = 1.0
        # The functions that run when a map goes on screen (with nothing to show they change nothing).
        Set-MspkiGuiMapTransform -Scale 1 -X 0 -Y 0
        Set-MspkiGuiMapFit; Update-MspkiGuiMiniMap; Update-MspkiGuiMapSelectionLook; Step-MspkiGuiMapDraw
        [void](Get-MspkiGuiMapCaption -Model ([pscustomobject]@{ Nodes = @($wn); Layers = 1 }))
        [void](New-MspkiGuiBuildPaths)
    }
    catch { $null = $_ }
}

function Update-MspkiGuiMapPaneSpace {
    <#
    .SYNOPSIS
    D-06: the Discovery map page gives the map the whole width until something is selected; the details pane opens beside it when the map
    or the tree shows an object, and closes again when nothing is selected.
    #>
    [CmdletBinding()]
    param()
    $ui = $script:MspkiGui.Ui
    if ($null -eq $ui.MapPaneCol) { return }
    $c = $ui.MapHost.Content
    $empty = ($null -eq $c -or [string]$c.Kind -eq 'None')
    if ($empty) {
        $ui.MapPaneCol.MinWidth = 0; $ui.MapPaneCol.Width = New-Object System.Windows.GridLength(0)
        $ui.MapGapCol.Width = New-Object System.Windows.GridLength(0)
        $ui.MapPanePanel.Visibility = 'Collapsed'; $ui.MapSplitter.Visibility = 'Collapsed'
    }
    elseif ($ui.MapPanePanel.Visibility -ne 'Visible') {
        $ui.MapPaneCol.Width = New-Object System.Windows.GridLength(3, [System.Windows.GridUnitType]::Star); $ui.MapPaneCol.MinWidth = 300
        $ui.MapGapCol.Width = New-Object System.Windows.GridLength(16)
        $ui.MapPanePanel.Visibility = 'Visible'; $ui.MapSplitter.Visibility = 'Visible'
    }
}
