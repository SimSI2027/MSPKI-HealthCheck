# Developer snapshots: render each page and state of the window to a PNG with RenderTargetBitmap (no screen capture).
# Used with: Start-MspkiHealthCheckGui.ps1 -Snapshot <folder under out\> [-ResultsFile <results.json>] [-SnapshotMaximized]
# Snapshots contain real names from a real run, so they are only ever written under out\ (git-ignored).

function Test-MspkiGuiSnapshotFolder {
    <#
    .SYNOPSIS
    True when the folder is inside the allowed root (out\). A snapshot folder anywhere else is refused.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Folder, [Parameter(Mandatory = $true)][string]$AllowedRoot)
    $f = [System.IO.Path]::GetFullPath($Folder).TrimEnd('\') + '\'
    $r = [System.IO.Path]::GetFullPath($AllowedRoot).TrimEnd('\') + '\'
    return ($f.Length -gt $r.Length -and $f.StartsWith($r, [System.StringComparison]::OrdinalIgnoreCase))
}

function Find-MspkiGuiSnapshotVisual {
    <#
    .SYNOPSIS
    The first element below Root (visual tree, breadth first) for which Test returns true, or $null.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Root, [Parameter(Mandatory = $true)][scriptblock]$Test)
    $q = New-Object System.Collections.Queue
    $q.Enqueue($Root)
    while ($q.Count -gt 0) {
        $v = $q.Dequeue()
        if ($v -ne $Root -and (& $Test $v)) { return $v }
        if ($v -is [System.Windows.Media.Visual]) {
            $n = [System.Windows.Media.VisualTreeHelper]::GetChildrenCount($v)
            for ($i = 0; $i -lt $n; $i++) { $q.Enqueue([System.Windows.Media.VisualTreeHelper]::GetChild($v, $i)) }
        }
    }
    return $null
}

function Wait-MspkiGuiIdle {
    <#
    .SYNOPSIS
    Lets the window finish layout and rendering (runs queued dispatcher work down to idle priority).
    #>
    [CmdletBinding()]
    param([int]$Rounds = 3)
    for ($i = 0; $i -lt $Rounds; $i++) {
        $frame = New-Object System.Windows.Threading.DispatcherFrame
        $cb = [System.Action]{ $frame.Continue = $false }
        [void][System.Windows.Threading.Dispatcher]::CurrentDispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::ApplicationIdle, $cb)
        [System.Windows.Threading.Dispatcher]::PushFrame($frame)
    }
}

function Get-MspkiGuiSnapshotMinimumSize {
    <#
    .SYNOPSIS
    The smallest client size the window allows (its MinWidth and MinHeight minus the non-client frame), for a fixed-size render
    at the minimum size. Returns a Size.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Window)
    $root = $Window.Content
    $frameW = 0.0; $frameH = 0.0
    if ($null -ne $root -and $Window.ActualWidth -gt 0 -and $root.ActualWidth -gt 0) {
        $frameW = [math]::Max(0.0, $Window.ActualWidth - $root.ActualWidth)
        $frameH = [math]::Max(0.0, $Window.ActualHeight - $root.ActualHeight)
    }
    return (New-Object System.Windows.Size(([double]$Window.MinWidth - $frameW), ([double]$Window.MinHeight - $frameH)))
}

function Set-MspkiGuiSnapshotLayout {
    <#
    .SYNOPSIS
    Lays the window's content out at a fixed size, off the window: the content gets exactly Width x Height as its own size, whatever the
    screen or the window's real size is (WPF clamps a window to the screen of this computer, so frames would differ from machine to machine).
    An explicit size survives every later layout pass (the map redraws, the navigation changes); Clear-MspkiGuiSnapshotLayout removes it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Window, [Parameter(Mandatory = $true)][double]$Width, [Parameter(Mandatory = $true)][double]$Height)
    $root = $Window.Content
    if ($null -eq $root) { return }
    $root.HorizontalAlignment = [System.Windows.HorizontalAlignment]::Left
    $root.VerticalAlignment = [System.Windows.VerticalAlignment]::Top
    $root.Width = $Width
    $root.Height = $Height
    # Width-dependent layout (compact navigation, tile columns) follows the fixed width, as it would in a real window of that size.
    if ($null -ne $script:MspkiGui) { $script:MspkiGui.ViewWidth = $Width; Update-MspkiGuiNavMode }
    $Window.UpdateLayout()
    $root.UpdateLayout()
}

function Clear-MspkiGuiSnapshotLayout {
    <#
    .SYNOPSIS
    Puts the content back to the window's size after Set-MspkiGuiSnapshotLayout.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Window)
    $root = $Window.Content
    if ($null -eq $root) { return }
    $root.ClearValue([System.Windows.FrameworkElement]::WidthProperty)
    $root.ClearValue([System.Windows.FrameworkElement]::HeightProperty)
    $root.ClearValue([System.Windows.FrameworkElement]::HorizontalAlignmentProperty)
    $root.ClearValue([System.Windows.FrameworkElement]::VerticalAlignmentProperty)
    if ($null -ne $script:MspkiGui) { $script:MspkiGui.ViewWidth = 0; Update-MspkiGuiNavMode }
    $Window.UpdateLayout()
}
function Save-MspkiGuiSnapshotImage {
    <#
    .SYNOPSIS
    Renders the window (as it is now) to a PNG file with RenderTargetBitmap. Returns the file path.
    With -Width and -Height the content is laid out at exactly that size first (an off-window render: the frame size does not depend on the
    screen) and put back afterwards. The window's own background is drawn behind it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Window, [Parameter(Mandatory = $true)][string]$Path, [double]$Scale = 1.0, [double]$Width = 0, [double]$Height = 0, [switch]$KeepLayout)
    Wait-MspkiGuiIdle
    $fixed = ($Width -gt 0 -and $Height -gt 0 -and $null -ne $Window.Content)
    $dpi = 96.0 * $Scale
    if ($fixed) {
        Set-MspkiGuiSnapshotLayout -Window $Window -Width $Width -Height $Height
        Wait-MspkiGuiIdle -Rounds 2
        $w = [int][math]::Ceiling($Width * $Scale)
        $h = [int][math]::Ceiling($Height * $Scale)
        $rect = New-Object System.Windows.Rect(0, 0, $Width, $Height)
        $brush = New-Object System.Windows.Media.VisualBrush($Window.Content)
        $brush.Stretch = [System.Windows.Media.Stretch]::None
        $brush.AlignmentX = [System.Windows.Media.AlignmentX]::Left
        $brush.AlignmentY = [System.Windows.Media.AlignmentY]::Top
        $brush.ViewboxUnits = [System.Windows.Media.BrushMappingMode]::Absolute
        $brush.Viewbox = $rect
        $brush.ViewportUnits = [System.Windows.Media.BrushMappingMode]::Absolute
        $brush.Viewport = $rect
        $dv = New-Object System.Windows.Media.DrawingVisual
        $dc = $dv.RenderOpen()
        $dc.DrawRectangle($Window.Background, $null, $rect)
        $dc.DrawRectangle($brush, $null, $rect)
        $dc.Close()
        $visual = $dv
    }
    else {
        $w = [int][math]::Ceiling($Window.ActualWidth * $Scale)
        $h = [int][math]::Ceiling($Window.ActualHeight * $Scale)
        $visual = $Window
    }
    $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($w, $h, $dpi, $dpi, [System.Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($visual)
    if ($fixed -and -not $KeepLayout) { Clear-MspkiGuiSnapshotLayout -Window $Window }
    $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))
    $fs = [System.IO.File]::Create($Path)
    try { $enc.Save($fs) } finally { $fs.Dispose() }
    return $Path
}

function Get-MspkiGuiSnapshotLiveItems {
    <#
    .SYNOPSIS
    Turns a results graph into the queue items the engine would have sent during a run (Entity, Relation, Probe), in four phases, for the
    live-map snapshots: 0 nothing yet, 1 the forest, CAs and their certificates, 2 half of the published addresses (the last three still
    being probed), 3 everything (every probe finished). Developer tool; only the names in the results file are used.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Graph)
    $keep = @('Url', 'UrlType', 'Kinds', 'Kind', 'CAType', 'PropertiesRead', 'Role', 'Scope')
    $item = {
        param($e)
        $props = @{}
        if ($null -ne $e.Properties) { foreach ($k in $keep) { if ($null -ne $e.Properties.PSObject.Properties[$k] -and $null -ne $e.Properties.$k -and [string]$e.Properties.$k -ne '') { $props[$k] = $e.Properties.$k } } }
        [pscustomobject]@{ Kind = 'Entity'; Id = [string]$e.Id; Type = [string]$e.Type; Name = [string]$e.Name; Parents = @(); Props = $props; Time = [DateTime]::Now }
    }
    $rel = { param($r) [pscustomobject]@{ Kind = 'Relation'; From = [string]$r.From; Type = [string]$r.Type; To = [string]$r.To; Time = [DateTime]::Now } }
    $ents = @($Graph.Entities | Where-Object { $_ })
    $rels = @($Graph.Relations | Where-Object { $_ })
    $early = @($ents | Where-Object { $_.Type -in @('Forest', 'CA', 'CACertificate') })
    $earlyIds = @{}; foreach ($e in $early) { $earlyIds[[string]$e.Id] = $true }
    $phase1 = @(foreach ($e in $early) { & $item $e })
    $phase1 += @($rels | Where-Object { $earlyIds.ContainsKey([string]$_.From) -and $earlyIds.ContainsKey([string]$_.To) } | ForEach-Object { & $rel $_ })
    $eps = @($ents | Where-Object { $_.Type -eq 'Endpoint' } | Sort-Object { [string]$_.Id })
    $hostOf = @{}
    foreach ($r in $rels) { if ([string]$r.Type -eq 'hostedOn') { $hostOf[[string]$r.From] = [string]$r.To } }
    $missing = @{}
    foreach ($o in @($Graph.Observations | Where-Object { $_ -and [string]$_.Kind -eq 'ExpectedMissing' })) { $missing[[string]$o.EntityId] = $true }
    $made = @{}
    $stepFor = {
        param($list, [bool]$finish)
        $out = @()
        foreach ($e in $list) {
            $id = [string]$e.Id
            $hid = $hostOf[$id]
            if ($hid -and -not $made.ContainsKey($hid)) { $made[$hid] = $true; $h = $ents | Where-Object { [string]$_.Id -eq $hid } | Select-Object -First 1; if ($h) { $out += (& $item $h) } }
            $out += (& $item $e)
            foreach ($r in @($rels | Where-Object { [string]$_.To -eq $id -and [string]$_.Type -eq 'references' })) { $out += (& $rel $r) }
            if ($hid) { $out += [pscustomobject]@{ Kind = 'Relation'; From = $id; Type = 'hostedOn'; To = $hid; Time = [DateTime]::Now } }
            $out += [pscustomobject]@{ Kind = 'Probe'; Phase = 'Start'; Probe = 'HTTP'; Id = $id; Outcome = ''; Time = [DateTime]::Now }
            if ($finish) { $out += [pscustomobject]@{ Kind = 'Probe'; Phase = 'End'; Probe = 'HTTP'; Id = $id; Outcome = $(if ($missing.ContainsKey($id)) { 'HTTP_404' } else { 'OK' }); Time = [DateTime]::Now } }
        }
        , $out
    }
    $half = [math]::Floor($eps.Count / 2)
    $p2 = @(); $p3 = @()
    $head = @($eps | Select-Object -First $half)
    $p2 += (& $stepFor ($head | Select-Object -SkipLast ([math]::Min(3, $head.Count))) $true)
    $p2 += (& $stepFor ($head | Select-Object -Last ([math]::Min(3, $head.Count))) $false)
    # Phase 3: the rest of the addresses, and every probe that was still running finishes.
    $p3 += @($head | Select-Object -Last ([math]::Min(3, $head.Count)) | ForEach-Object { [pscustomobject]@{ Kind = 'Probe'; Phase = 'End'; Probe = 'HTTP'; Id = [string]$_.Id; Outcome = $(if ($missing.ContainsKey([string]$_.Id)) { 'HTTP_404' } else { 'OK' }); Time = [DateTime]::Now } })
    $p3 += (& $stepFor @($eps | Select-Object -Skip $half) $true)
    return [pscustomobject]@{ Phases = @(, @(), $phase1, $p2, $p3) }
}

function Invoke-MspkiGuiSnapshot {
    <#
    .SYNOPSIS
    Shows the window, renders every page and state to a PNG, closes the window. Returns the files written.
    States: welcome, options open, running (fed like the progress queue feeds it; nothing is scanned), run ended without
    results, finished (Overview, Findings, grouped, no match, Discovery map, drill-in, Run log), partial (cancelled) and
    no CA found. The folder must be inside -AllowedRoot (the out folder); anything else is refused before anything is written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Window,
        [Parameter(Mandatory = $true)][string]$Folder,
        [Parameter(Mandatory = $true)][string]$AllowedRoot,
        [AllowEmptyString()][string]$ResultsFile = '',
        [int]$Width = 1360,
        [int]$Height = 860,
        [double]$Scale = 1.0,
        [switch]$Maximized,
        [switch]$Minimum
    )
    if (-not (Test-MspkiGuiSnapshotFolder -Folder $Folder -AllowedRoot $AllowedRoot)) { throw ('Snapshots can only be written inside {0} (they can contain real names).' -f $AllowedRoot) }
    $g = $script:MspkiGui
    $ui = $g.Ui
    [void][System.IO.Directory]::CreateDirectory($Folder)
    $Window.WindowStartupLocation = 'Manual'
    $Window.ShowInTaskbar = $false
    if ($Maximized) {
        # A maximised window has to be on a screen; it is shown there for the few seconds the snapshots take.
        $Window.Left = 0; $Window.Top = 0
        $Window.Show()
        $Window.WindowState = [System.Windows.WindowState]::Maximized
    }
    else {
        $Window.Left = -32000; $Window.Top = 0
        $Window.Width = $Width; $Window.Height = $Height
        $Window.Show()
    }
    Wait-MspkiGuiIdle -Rounds 4
    # Frame size: fixed (an off-window Measure/Arrange at Width x Height, or at the window's minimum size with -Minimum), so it does not
    # depend on this computer's screen. Only -Maximized renders the real window.
    $renderW = 0.0; $renderH = 0.0
    if (-not $Maximized) {
        if ($Minimum) { $sz = Get-MspkiGuiSnapshotMinimumSize -Window $Window; $renderW = $sz.Width; $renderH = $sz.Height }
        else { $renderW = [double]$Width; $renderH = [double]$Height }
    }
    $files = New-Object 'System.Collections.Generic.List[string]'
    $shot = {
        param([string]$Name)
        $p = Join-Path $Folder ($Name + '.png')
        [void](Save-MspkiGuiSnapshotImage -Window $Window -Path $p -Scale $Scale -Width $renderW -Height $renderH -KeepLayout)
        $files.Add($p)
    }
    # Scroll targets are computed in the same fixed layout the frame is rendered in.
    $scrollTo = {
        param($Viewer, $Target, $Parent, [double]$Pad)
        if ($renderW -gt 0) { Set-MspkiGuiSnapshotLayout -Window $Window -Width $renderW -Height $renderH }
        $top = $Target.TransformToAncestor($Parent).Transform((New-Object System.Windows.Point(0, 0))).Y
        $Viewer.ScrollToVerticalOffset([math]::Max(0, $top - $Pad))
        Wait-MspkiGuiIdle -Rounds 2
    }
    $page = {
        param($Tab)
        $ui.Tabs.SelectedItem = $Tab
        Wait-MspkiGuiIdle -Rounds 3
    }
    try {
        # Before the first run: the welcome state, and the options panel open.
        & $page $ui.TabSummary
        & $shot '00-welcome'
        $ui.ExpOptions.IsExpanded = $true
        & $shot '01-welcome-options'
        $ui.ExpOptions.IsExpanded = $false

        # Running: fed the way the progress queue feeds it (example.test names only; nothing is contacted).
        Set-MspkiGuiBusy -Busy $true
        $ui.Progress.Visibility = 'Visible'
        $ui.Progress.Value = 45
        Set-MspkiGuiState -Text ('Running: {0}' -f (Get-MspkiGuiStageLabel -Stage 'Probe:Endpoints')) -State Running
        $ui.TxtTarget.Text = 'http://pki.example.test/CertEnroll/Example-Issuing-CA.crl'
        $ui.TxtElapsed.Text = 'Elapsed 0:21'
        $ui.TxtWelcomeContext.Text = 'A run is in progress. Findings appear here when it finishes; the Run log page shows the run live.'
        $demo = @(
            @('Info', 'Run started on a domain-joined computer (read-only).'),
            @('Info', 'Forest corp.example.test, domain controller dc01.corp.example.test, site Default-First-Site-Name.'),
            @('Info', 'Public Key Services: 8 of 8 containers read.'),
            @('Info', 'Enterprise CAs: 2 found (Example Root CA, Example Issuing CA).'),
            @('Info', 'CA properties read from ca01.corp.example.test over DCOM.'),
            @('Warning', 'CA certificate of Example Issuing CA expires in 180 days.'),
            @('Info', 'Templates: 24 published, 43 in Active Directory.'),
            @('Debug', 'Lead http://pki.example.test/CertEnroll/Example-Root-CA.crt (AIA, depth 1).'),
            @('Info', 'GET http://pki.example.test/CertEnroll/Example-Root-CA.crl returned 200 OK (1.2 KB).'),
            @('Error', 'GET http://pki.example.test/ocsp: TCP 80 timed out after 5 s.'),
            @('Info', 'Checking AIA, CDP and OCSP endpoints (6 of 15).')
        )
        $i = 0
        foreach ($d in $demo) {
            $i++
            $text = '2026-01-01 09:00:{0:00}  {1,-7}  {2}' -f $i, $d[0].ToUpperInvariant(), $d[1]
            Add-MspkiGuiLogRow -Row (New-MspkiGuiLogRow -Text $text -Level $d[0])
        }
        & $page $ui.TabLog
        Update-MspkiGuiLogView -Scroll
        & $shot '02-running-log'
        & $page $ui.TabSummary
        & $shot '03-running-overview'
        # The live mission control: the engine's Entity, Relation and Probe items, replayed from the results graph (nothing is scanned).
        # Frames are rendered with reduced motion so that they are deterministic: nodes appear at once and a probed node shows a still ring.
        $liveGraph = $null
        if ($ResultsFile) { $liveGraph = (Read-MspkiGuiResults -Path $ResultsFile).Graph }
        if ($null -ne $liveGraph) {
            $live = Get-MspkiGuiSnapshotLiveItems -Graph $liveGraph
            $steps = @(
                @{ Name = '03a-live-start'; Phase = 0; Pct = 6; Stage = 'Running: Reading Active Directory'; Target = 'LDAP CN=Enrollment Services' }
                @{ Name = '03b-live-cas'; Phase = 1; Pct = 28; Stage = 'Running: Reading the CAs'; Target = 'COM CA properties' }
                @{ Name = '03c-live-probing'; Phase = 2; Pct = 55; Stage = 'Running: Checking the published addresses'; Target = 'HTTP pki-dr/CertEnroll/Meridian Issuing CA.crl' }
                @{ Name = '03d-live-late'; Phase = 3; Pct = 86; Stage = 'Running: Reviewing the hierarchy'; Target = '' }
            )
            $g.ForceMotion = $false
            foreach ($s in $steps) {
                foreach ($i in @($live.Phases[$s.Phase])) { [void](Add-MspkiGuiLiveItem -State $g.Live -Item $i) }
                $ui.Progress.Value = $s.Pct
                Set-MspkiGuiState -Text $s.Stage -State Running
                $ui.TxtTarget.Text = $s.Target
                Update-MspkiGuiRunningHero
                Update-MspkiGuiLiveMap
                Wait-MspkiGuiIdle -Rounds 3
                & $shot $s.Name
                $osv = $ui.PanelResults.Parent
                while ($null -ne $osv -and $osv -isnot [System.Windows.Controls.ScrollViewer]) { $osv = [System.Windows.LogicalTreeHelper]::GetParent($osv) }
                if ($null -ne $osv -and $s.Phase -eq 2) {
                    & $scrollTo $osv $ui.MapCanvasHost $ui.PanelResults 120
                    & $shot ($s.Name + '-map')
                    $osv.ScrollToTop(); Wait-MspkiGuiIdle -Rounds 2
                }
            }
        }
        if ($null -ne $liveGraph) {
            # One frame with motion on: the nodes of a batch fade in and grow, and the probed addresses pulse. It is captured 150 ms after
            # the redraw, so it shows what a user sees in the middle of the animation.
            $g.ForceMotion = $true
            $g.Live = New-MspkiGuiLiveState
            foreach ($i in (@($live.Phases[1]) + @($live.Phases[2]))) { [void](Add-MspkiGuiLiveItem -State $g.Live -Item $i) }
            $ui.Progress.Value = 55
            Update-MspkiGuiRunningHero
            $osv = $ui.PanelResults.Parent
            while ($null -ne $osv -and $osv -isnot [System.Windows.Controls.ScrollViewer]) { $osv = [System.Windows.LogicalTreeHelper]::GetParent($osv) }
            Update-MspkiGuiLiveMap
            if ($null -ne $osv) { & $scrollTo $osv $ui.MapCanvasHost $ui.PanelResults 120 }
            Update-MspkiGuiLiveMap
            $clock = [System.Diagnostics.Stopwatch]::StartNew()
            while ($clock.ElapsedMilliseconds -lt 150) { Wait-MspkiGuiIdle -Rounds 1 }
            & $shot '03e-live-motion'
            if ($null -ne $osv) { $osv.ScrollToTop() }
            $g.ForceMotion = $false
        }
        Set-MspkiGuiBusy -Busy $false
        $ui.Progress.Visibility = 'Hidden'
        $ui.TxtTarget.Text = ''

        # A run that ended without results.
        Clear-MspkiGuiResult
        $ui.TxtWelcomeError.Text = 'The domain controller could not be reached (LDAP bind timed out after 5 s). See the Run log page for details, then try again.'
        $ui.WelcomeError.Visibility = 'Visible'
        Set-MspkiGuiState -Text 'The run ended without results. See the Run log page.' -State Bad
        & $shot '04-error'
        Clear-MspkiGuiResult
        $g.LogRows.Clear()
        Update-MspkiGuiLogView

        if ($ResultsFile) {
            # Motion is forced on so that the Overview build can be held at chosen times (mid-animation frames); every later
            # frame is held at the end of the build, which is the state a user sees once it has played.
            $g.ForceMotion = $true
            $settle = {
                Wait-MspkiGuiIdle -Rounds 3
                Set-MspkiGuiMissionFrame -Ms ([double]$g.MapTotalMs + 500)
                Wait-MspkiGuiIdle -Rounds 2
            }
            & $page $ui.TabSummary
            Open-MspkiGuiResultsFile -Path $ResultsFile
            if ($null -eq $g.Data) { throw 'The results file could not be opened.' }
            $data = $g.Data
            Wait-MspkiGuiIdle -Rounds 4
            $osv = $ui.PanelResults.Parent
            while ($null -ne $osv -and $osv -isnot [System.Windows.Controls.ScrollViewer]) { $osv = [System.Windows.LogicalTreeHelper]::GetParent($osv) }
            foreach ($ms in @(300, 1250, 2100)) {
                Set-MspkiGuiMissionFrame -Ms $ms
                Wait-MspkiGuiIdle -Rounds 2
                & $shot ('05-build-{0:0000}ms' -f $ms)
                if ($null -ne $osv) {
                    & $scrollTo $osv $ui.MapCanvasHost $ui.PanelResults 120
                    & $shot ('06-build-map-{0:0000}ms' -f $ms)
                    $osv.ScrollToTop(); Wait-MspkiGuiIdle -Rounds 2
                }
            }
            & $settle
            if ($null -ne $osv) {
                & $scrollTo $osv $ui.MapCanvasHost $ui.PanelResults 120
                & $shot '12-summary-map'
                $osv.ScrollToTop(); Wait-MspkiGuiIdle -Rounds 2
            }
            & $shot '10-summary'
            # Scrolled to the bottom of the overview (CAs, top issues, coverage).
            $sv = $ui.PanelResults.Parent
            while ($null -ne $sv -and $sv -isnot [System.Windows.Controls.ScrollViewer]) { $sv = [System.Windows.LogicalTreeHelper]::GetParent($sv) }
            if ($null -ne $sv) { $sv.ScrollToEnd(); & $shot '11-summary-bottom'; $sv.ScrollToTop() }
            # Findings: first row selected, then grouped, then a filter that matches nothing.
            & $page $ui.TabFindings
            if ($g.Rows.Count -gt 0) { $ui.FindingsGrid.SelectedIndex = 0 }
            & $shot '20-findings'
            $ui.ChkGroup.IsChecked = $true
            $g.View.GroupDescriptions.Add((New-Object System.Windows.Data.PropertyGroupDescription('Category')))
            & $shot '21-findings-grouped'
            $g.View.GroupDescriptions.Clear(); $ui.ChkGroup.IsChecked = $false
            $ui.FltText.Text = 'no-such-finding-text'
            Update-MspkiGuiFilter
            & $shot '22-findings-nomatch'
            Clear-MspkiGuiFilter
            # Guided walkthrough (GX3, journey J3): the first "What to do next" action opened as a click would, the causes in view, one check
            # marked as checked and a copy button answering "Copied". The copy frame shows the mark only: the snapshot never touches the clipboard.
            $act = @(@($ui.ActionList.ItemsSource) | Where-Object { $_ -and $_.Tag }) | Select-Object -First 1
            if ($null -ne $act -and $g.RowById.ContainsKey([string]$act.Tag)) {
                Show-MspkiGuiFinding -Id ([string]$act.Tag)
                Wait-MspkiGuiIdle -Rounds 3
                & $shot '23-walkthrough'
                $walk = {
                    $sv = Find-MspkiGuiSnapshotVisual -Root $ui.FindingHost -Test { param($v) $v -is [System.Windows.Controls.ScrollViewer] }
                    $lbl = Find-MspkiGuiSnapshotVisual -Root $ui.FindingHost -Test { param($v) $v -is [System.Windows.Controls.TextBlock] -and $v.Text -eq 'What to do about it' }
                    if ($null -ne $sv -and $null -ne $lbl -and $null -ne $sv.Content) { & $scrollTo $sv $lbl $sv.Content 8 }
                }
                & $walk
                & $shot '24-walkthrough-causes'
                $c1 = @($ui.FindingHost.Content.DiagCauses | Where-Object { $_.HasChecks }) | Select-Object -First 1
                if ($null -ne $c1) {
                    Invoke-MspkiGuiPaneCommand -HostName 'FindingHost' -Tag ([string]@($c1.Checks)[0].ToggleTag)
                    Show-MspkiGuiFindingPane -Finding $g.RowById[[string]$act.Tag].Finding
                    Wait-MspkiGuiIdle -Rounds 3
                    $sv = Find-MspkiGuiSnapshotVisual -Root $ui.FindingHost -Test { param($v) $v -is [System.Windows.Controls.ScrollViewer] }
                    $chk = Find-MspkiGuiSnapshotVisual -Root $ui.FindingHost -Test { param($v) $v -is [System.Windows.Controls.CheckBox] }
                    if ($null -ne $sv -and $null -ne $chk -and $null -ne $sv.Content) { & $scrollTo $sv $chk $sv.Content 140 }
                    $copyBtn = Find-MspkiGuiSnapshotVisual -Root $ui.FindingHost -Test { param($v) $v -is [System.Windows.Controls.Button] -and [string]$v.Tag -eq [string]@($c1.Checks)[0].CopyTag }
                    if ($null -ne $copyBtn) { $g.LastClicked = $copyBtn; Show-MspkiGuiCopiedMark; Wait-MspkiGuiIdle -Rounds 2 }
                    & $shot '25-walkthrough-checked'
                    [void](Switch-MspkiGuiCheckedKey -State $g.CheckState -FindingId ([string]$act.Tag) -Key ([string]@($c1.Checks)[0].Key) -AllowedRoot $g.OutputRoot)
                }
            }
            if ($g.Rows.Count -gt 0) { $ui.FindingsGrid.SelectedIndex = 0 }
            # Command palette (GX4): as it opens (commands and pages), then a search that finds objects and findings; and two toasts.
            & $page $ui.TabSummary
            Open-MspkiGuiPalette; Wait-MspkiGuiIdle -Rounds 3
            & $shot '26-palette'
            $ui.PaletteText.Text = 'crl'; Update-MspkiGuiPalette; Wait-MspkiGuiIdle -Rounds 3
            & $shot '27-palette-search'
            $ui.PaletteText.Text = 'zzzz-no-such-thing'; Update-MspkiGuiPalette; Wait-MspkiGuiIdle -Rounds 3
            & $shot '28-palette-nomatch'
            Close-MspkiGuiPalette -NoReturn
            $toastsShown = (Show-MspkiGuiToast -Title 'Export finished' -Text ('12 findings written to {0}' -f (Join-Path $g.OutputRoot 'findings-filtered.csv')) -Tone Good)
            [void](Show-MspkiGuiToast -Text 'The clipboard is in use by another program. Try again.' -Tone Warn)
            Wait-MspkiGuiIdle -Rounds 3
            foreach ($tc in @($ui.ToastHost.Children)) { $tc.BeginAnimation([System.Windows.UIElement]::OpacityProperty, $null); $tc.Opacity = 1 }
            if ($toastsShown) { & $shot '29-toasts'; $ui.ToastHost.Children.Clear() }
            # Discovery map: expand everything, select the first CA node, then drill into its first finding.
            & $page $ui.TabMap
            Set-MspkiGuiTreeExpansion -Parent $ui.MapTree -Expand $true
            Wait-MspkiGuiIdle -Rounds 3
            $pick = $null
            $stack = New-Object System.Collections.Stack
            foreach ($n in @($ui.MapTree.ItemsSource)) { $stack.Push($n) }
            while ($stack.Count -gt 0 -and $null -eq $pick) {
                $n = $stack.Pop()
                if ($n.Type -eq 'CA') { $pick = $n }
                else { foreach ($c in @($n.Children)) { $stack.Push($c) } }
            }
            if ($null -ne $pick) { Show-MspkiGuiNodePane -Node $pick }
            & $shot '30-map'
            $first = $null
            if ($null -ne $g.MapPane) { $first = @($g.MapPane.Findings | Where-Object { $_ }) | Select-Object -First 1 }
            if ($null -ne $first -and $g.RowById.ContainsKey([string]$first.Id)) {
                Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag ([string]$first.Id)
                & $shot '31-map-finding'
                Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag 'Back'
            }
            # Drill-down from the map item: its object, then two related objects (breadcrumbs and Back), then back to the item.
            $obj = $null
            if ($null -ne $g.MapPane -and $g.MapPane.HasObjects) { $obj = @($g.MapPane.Objects)[0] }
            if ($null -ne $obj) {
                Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag ([string]$obj.Tag)
                & $shot '32-map-object'
                foreach ($k in 1..2) {
                    $next = @($ui.MapHost.Content.Related | Where-Object { $_.Known }) | Select-Object -First 1
                    if ($null -eq $next) { break }
                    Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag ([string]$next.Tag)
                }
                & $shot '33-map-object-trail'
                Show-MspkiGuiNodePane -Node $pick
            }
            # Objects page: the full list, a host (identity), an object that is expected but missing somewhere, and a filter with no match.
            & $page $ui.TabObjects
            & $shot '70-objects'
            $hostRow = @($g.ObjRows | Where-Object { $_.Type -eq 'Host' }) | Select-Object -First 1
            if ($null -ne $hostRow) { Show-MspkiGuiObject -Id $hostRow.Id; Wait-MspkiGuiIdle -Rounds 3; & $shot '71-objects-host' }
            $missRow = @($g.ObjRows | Where-Object { $_.HasMissing }) | Select-Object -First 1
            if ($null -ne $missRow) { Show-MspkiGuiObject -Id $missRow.Id; Wait-MspkiGuiIdle -Rounds 3; & $shot '72-objects-missing' }
            $ui.ChkObjAttention.IsChecked = $true; Update-MspkiGuiObjectFilter
            & $shot '73-objects-attention'
            $ui.FltObj.Text = 'no-such-object-text'
            Update-MspkiGuiObjectFilter
            & $shot '74-objects-nomatch'
            Clear-MspkiGuiObjectFilter
            # PKI services: the cards, a service opened on the right, and the bottom of the list.
            & $page $ui.TabServices
            & $shot '80-services'
            $svcItem = @(@($ui.SvcList.ItemsSource) | ForEach-Object { @($_.Instances) } | Where-Object { $_ }) | Select-Object -First 1
            if ($null -ne $svcItem) { Open-MspkiGuiServiceItem -Tag $svcItem.Tag; Wait-MspkiGuiIdle -Rounds 3; & $shot '81-services-detail' }
            $ui.SvcScroll.ScrollToEnd(); Wait-MspkiGuiIdle -Rounds 3
            & $shot '82-services-bottom'
            $ui.SvcScroll.ScrollToTop()
            & $page $ui.TabLog
            & $shot '40-log'

            # Partial: the same run marked as not finished (cancelled).
            $ri = $data.RunInfo | Select-Object -Property *
            $ri | Add-Member -NotePropertyName Completed -NotePropertyValue $false -Force
            $partial = $data | Select-Object -Property *
            $partial.RunInfo = $ri
            Show-MspkiGuiResult -Data $partial
            Set-MspkiGuiState -Text 'Cancelled. Partial results are shown and were saved.' -State Warn
            & $page $ui.TabSummary
            & $settle
            & $shot '50-partial'

            # No CA found: the same run without Enterprise CAs (and without the CA findings).
            $inv = $data.Inventory | Select-Object -Property *
            $inv | Add-Member -NotePropertyName EnterpriseCAs -NotePropertyValue @() -Force
            $none = $data | Select-Object -Property *
            $none.Inventory = $inv
            $none.Findings = @($data.Findings | Where-Object { $_ -and [string]$_.Category -ne 'CA' })
            Show-MspkiGuiResult -Data $none
            Set-MspkiGuiState -Text ('Loaded {0} from an earlier run' -f (Format-MspkiGuiCount -Count @($none.Findings).Count -Singular 'finding')) -State Warn
            & $page $ui.TabSummary
            & $settle
            & $shot '60-no-ca'
            $ui.TxtNoCa.BringIntoView()
            Wait-MspkiGuiIdle -Rounds 3
            & $shot '61-no-ca-section'
        }
        else {
            & $page $ui.TabLog
            & $shot '40-log'
        }
    }
    finally { if ($renderW -gt 0) { try { Clear-MspkiGuiSnapshotLayout -Window $Window } catch { $null = $_ } }; $Window.Close() }
    return $files.ToArray()
}
