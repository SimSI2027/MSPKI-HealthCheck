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

function Get-MspkiGuiSnapshotExpectedPage {
    <#
    .SYNOPSIS
    The page (tab name) a snapshot frame must show, from the number at the start of its name; '' for frames that may show any page
    (palette and toasts float over the page). D-07: a test compares it with the page the window really showed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    $n = 0
    if (-not [int]::TryParse(($Name -replace '^(\d+).*$', '$1'), [ref]$n)) { return '' }
    if ($n -eq 2 -or $n -eq 40) { return 'TabLog' }
    if ($n -le 19 -or $n -eq 50 -or $n -eq 60 -or $n -eq 61) { return 'TabSummary' }
    if ($n -ge 20 -and $n -le 25) { return 'TabFindings' }
    if ($n -ge 26 -and $n -le 29) { return '' }
    if ($n -ge 30 -and $n -le 34) { return 'TabMap' }
    if ($n -eq 35) { return 'TabTimeline' }
    if ($n -eq 36) { return 'TabHistory' }
    if ($n -eq 37) { return 'TabLearn' }
    if ($n -ge 70 -and $n -le 79) { return 'TabObjects' }
    if ($n -ge 80 -and $n -le 89) { return 'TabServices' }
    if ($n -ge 90) { return 'TabFindings' }
    return ''
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
        [switch]$Minimum,
        # Developer motion frames (docs/DEMO-SITE.md): the Overview map's discovery build every ReplayStepMs, as 07-replay-NNNN.png. 0 = off.
        [ValidateRange(0, 2000)][int]$ReplayFrames = 0,
        [ValidateRange(20, 1000)][int]$ReplayStepMs = 60
    )
    if (-not (Test-MspkiGuiSnapshotFolder -Folder $Folder -AllowedRoot $AllowedRoot)) { throw ('Snapshots can only be written inside {0} (they can contain real names).' -f $AllowedRoot) }
    $g = $script:MspkiGui
    $g.SnapshotMode = $true
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
    $frames = New-Object 'System.Collections.Generic.List[object]'
    $shot = {
        param([string]$Name)
        $p = Join-Path $Folder ($Name + '.png')
        # The map is computed in the background and drawn in slices: every frame waits until it is complete.
        if ($null -ne $script:MspkiGui.MapQueue -and ($null -ne $script:MspkiGui.MapJob -or $script:MspkiGui.MapQueue.Count -gt 0 -or $script:MspkiGui.MapDraws.Count -gt 0 -or $script:MspkiGui.MapAnims.Count -gt 0)) { Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2 }
        [void](Save-MspkiGuiSnapshotImage -Window $Window -Path $p -Scale $Scale -Width $renderW -Height $renderH -KeepLayout)
        $files.Add($p)
        # D-07: every frame records the page it really shows and the score text, so a test can prove each frame shows what its name claims.
        $tabName = ''; if ($null -ne $ui.Tabs.SelectedItem) { $tabName = [string]$ui.Tabs.SelectedItem.Name }
        $frames.Add([pscustomobject][ordered]@{ Name = $Name; Page = $tabName; Expected = (Get-MspkiGuiSnapshotExpectedPage -Name $Name); Score = [string]$ui.TxtScore.Text })
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
        Show-MspkiGuiRunError -Problem 'The domain controller could not be reached (LDAP bind timed out after 5 s).'
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
                # D-07: a new result restarts the map in the worker; seeking the build before the map arrived froze an empty ring.
                Wait-MspkiGuiIdle -Rounds 3
                Wait-MspkiGuiMapIdle
                Wait-MspkiGuiIdle -Rounds 2
                Set-MspkiGuiMissionFrame -Ms ([double]$g.MapTotalMs + 500)
                Wait-MspkiGuiIdle -Rounds 2
            }
            & $page $ui.TabSummary
            Open-MspkiGuiResultsFile -Path $ResultsFile
            if ($null -eq $g.Data) { throw 'The results file could not be opened.' }
            $data = $g.Data
            Wait-MspkiGuiIdle -Rounds 4
            Wait-MspkiGuiMapIdle
            Wait-MspkiGuiIdle -Rounds 2
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
            if ($ReplayFrames -gt 0 -and $null -ne $osv) {
                # The build seeked frame by frame (the same storyboard as the window's replay), the map card in view.
                & $scrollTo $osv $ui.MapCanvasHost $ui.PanelResults 120
                for ($i = 0; $i -lt $ReplayFrames; $i++) {
                    Set-MspkiGuiMissionFrame -Ms ($i * $ReplayStepMs)
                    Wait-MspkiGuiIdle -Rounds 1
                    & $shot ('07-replay-{0:0000}' -f $i)
                }
                $osv.ScrollToTop(); Wait-MspkiGuiIdle -Rounds 2
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
                Show-MspkiGuiFinding -Id ([string]$act.Tag) -ToCauses
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
            # Discovery map (GX6): the full-page map fitted, a node opened, the keyboard focus, filters, search, zoomed with the minimap,
            # a filter with no match, and the replay held mid-build.
            & $page $ui.TabMap
            $ui.RbMapCanvas.IsChecked = $true
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 3
            Set-MspkiGuiMapFit -Readable; Wait-MspkiGuiIdle -Rounds 2
            & $shot '30-map'
            Set-MspkiGuiMapFit; Wait-MspkiGuiIdle -Rounds 2
            & $shot '30h-map-fit-all'
            Set-MspkiGuiMapFit -Readable; Wait-MspkiGuiIdle -Rounds 2
            $pm = $g.MapPageModel
            if ($null -ne $pm) {
                $pickNode = @($pm.Nodes | Where-Object { $_.Kind -eq 'CA' -and $_.Tone -eq 'Admin' }) + @($pm.Nodes | Where-Object { $_.Kind -eq 'CA' }) | Select-Object -First 1
                if ($null -ne $pickNode) { Select-MspkiGuiMapNode -Id ([string]$pickNode.Id) -Open; Wait-MspkiGuiIdle -Rounds 3; & $shot '30a-map-selected' }
                [void]$ui.MapViewport.Focus(); [void][System.Windows.Input.Keyboard]::Focus($ui.MapViewport)
                foreach ($k in 'Right', 'Down', 'Down') { [void](Invoke-MspkiGuiMapKey -Key $k) }
                Wait-MspkiGuiIdle -Rounds 2
                & $shot '30b-map-keyboard'
                $ui.ChkMapProblems.IsChecked = $true; Update-MspkiGuiMapPage; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
                & $shot '30c-map-problems'
                $ui.ChkMapProblems.IsChecked = $false
                $g.MapFilterSilent = $true; $ui.FltMap.Text = 'lodestar'; $g.MapFilterSilent = $false
                Update-MspkiGuiMapPage; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
                & $shot '30d-map-search'
                $g.MapFilterSilent = $true; $ui.FltMap.Text = ''; $g.MapFilterSilent = $false
                Update-MspkiGuiMapPage; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
                Step-MspkiGuiMapZoomBy -Direction In; Step-MspkiGuiMapZoomBy -Direction In; Step-MspkiGuiMapZoomBy -Direction In
                Wait-MspkiGuiIdle -Rounds 2
                & $shot '30e-map-zoomed'
                Set-MspkiGuiMapFit
                $g.MapFilterSilent = $true; $ui.FltMapStatus.SelectedIndex = 4; $ui.FltMapType.SelectedIndex = 1; $g.MapFilterSilent = $false
                Update-MspkiGuiMapPage; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
                & $shot '30f-map-nomatch'
                Clear-MspkiGuiMapFilter; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
                Start-MspkiGuiMapReplay; Wait-MspkiGuiMapIdle
                if ($null -ne $g.MapPageStoryboard) {
                    $g.MapPageStoryboard.Pause($ui.MapWorld)
                    $g.MapPageStoryboard.SeekAlignedToLastTick($ui.MapWorld, [TimeSpan]::FromMilliseconds(1400), [System.Windows.Media.Animation.TimeSeekOrigin]::BeginTime)
                    Wait-MspkiGuiIdle -Rounds 2
                    & $shot '30g-map-replay-1400ms'
                    $g.MapPageStoryboard.SeekAlignedToLastTick($ui.MapWorld, [TimeSpan]::FromMilliseconds([double]$g.MapPageModel.TotalMs + 300), [System.Windows.Media.Animation.TimeSeekOrigin]::BeginTime)
                    Wait-MspkiGuiIdle -Rounds 2
                }
            }
            # Timeline (GX7): CRLs (opens on what runs out first), the certificates, a range, a row opened and Back, the chain, and the
            # chain with one address opened in the pane.
            & $page $ui.TabTimeline
            $ui.RbTlCrls.IsChecked = $true
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 3
            & $shot '35-timeline-crls'
            $ui.RbTlCerts.IsChecked = $true
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 3
            & $shot '35a-timeline-certificates'
            if ($ui.FltTlSpan.Items.Count -gt 2) {
                $ui.FltTlSpan.SelectedIndex = 2
                Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 3
                & $shot '35b-timeline-range'
                $ui.FltTlSpan.SelectedIndex = 0
                Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 3
            }
            $tlRow = @(@($g.TlItems) | Where-Object { $_ -and $_.Kind -eq 'Row' -and $_.Tone -in @('Bad', 'Warn', 'Admin') }) + @(@($g.TlItems) | Where-Object { $_ -and $_.Kind -eq 'Row' }) | Select-Object -First 1
            if ($null -ne $tlRow) {
                Select-MspkiGuiTimelineRow -Id ([string]$tlRow.Id); Wait-MspkiGuiIdle -Rounds 3
                & $shot '35c-timeline-row-open'
                $paneObj = $null
                if ($null -ne $ui.TimelineHost.Content -and $ui.TimelineHost.Content.PSObject.Properties['Related']) { $paneObj = @($ui.TimelineHost.Content.Related | Where-Object { $_.Known }) | Select-Object -First 1 }
                if ($null -ne $paneObj) {
                    Invoke-MspkiGuiPaneCommand -HostName 'TimelineHost' -Tag ([string]$paneObj.Tag); Wait-MspkiGuiIdle -Rounds 3
                    Invoke-MspkiGuiPaneCommand -HostName 'TimelineHost' -Tag 'Back'; Wait-MspkiGuiIdle -Rounds 3
                    & $shot '35d-timeline-back'
                }
            }
            $ui.RbTlChain.IsChecked = $true
            Wait-MspkiGuiIdle -Rounds 4
            & $shot '35e-timeline-chain'
            $chainAddr = $null
            foreach ($ci in @($ui.TlChain.ItemsSource)) { if ($null -eq $chainAddr -and $ci.Kind -eq 'Card') { foreach ($sx in @($ci.Sections)) { if ($null -eq $chainAddr) { $chainAddr = @($sx.Items | Where-Object { $_.Tone -in @('Bad', 'Warn') }) + @($sx.Items) | Select-Object -First 1 } } } }
            if ($null -ne $chainAddr) { Invoke-MspkiGuiTimelineTag -Tag ([string]$chainAddr.Tag); Wait-MspkiGuiIdle -Rounds 3; & $shot '35f-timeline-chain-address' }
            $ui.RbTlCrls.IsChecked = $true
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            # History (GX8): the runs of this forest in the output folder (read a few at a time in the background), the run on show
            # compared with the run before it, then with the oldest run, and the bottom of the comparison (objects added and gone).
            & $page $ui.TabHistory
            $histEnd = [DateTime]::Now.AddSeconds(120)
            do { Wait-MspkiGuiMapIdle -TimeoutMs 20000; Wait-MspkiGuiIdle -Rounds 2 } while (($g.HistPending -gt 0 -or $null -eq $g.HistRuns) -and [DateTime]::Now -lt $histEnd)
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 3
            & $shot '36-history'
            $histRows = @($ui.HistList.ItemsSource)
            if ($histRows.Count -gt 2) {
                Invoke-MspkiGuiHistoryTag -Tag ([string]$histRows[$histRows.Count - 1].CompareTag)
                Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 3
                & $shot '36a-history-oldest'
            }
            if ($ui.HistCmpScroll.IsVisible) { $ui.HistCmpScroll.ScrollToEnd(); Wait-MspkiGuiIdle -Rounds 3; & $shot '36b-history-bottom'; $ui.HistCmpScroll.ScrollToTop() }
            Invoke-MspkiGuiHistoryComparePrevious; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            # The tree (the text alternative): expand everything, select the first CA node, then drill into its first finding.
            # D-07: back to the map page first (the History frames left the window on History).
            & $page $ui.TabMap
            $ui.RbMapTree.IsChecked = $true
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
            & $shot '34-map-tree'
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
            $ui.RbMapCanvas.IsChecked = $true
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
            # GX9: Explain mode on the Overview, the four tour stops, and the Learn page (a term, a search, no match). Settings are not saved
            # by the snapshot (SnapshotMode keeps gui-settings.json as it is).
            & $page $ui.TabSummary
            $osv2 = $ui.PanelResults.Parent
            while ($null -ne $osv2 -and $osv2 -isnot [System.Windows.Controls.ScrollViewer]) { $osv2 = [System.Windows.LogicalTreeHelper]::GetParent($osv2) }
            if ($null -ne $osv2) { $osv2.ScrollToTop() }
            $ui.TglExplain.IsChecked = $true; [void](Update-MspkiGuiExplain); Wait-MspkiGuiIdle -Rounds 2
            & $shot '15-explain'
            $ui.TglExplain.IsChecked = $false; [void](Update-MspkiGuiExplain)
            Start-MspkiGuiTour
            foreach ($ti in 0..3) {
                $g.TourIndex = $ti; Show-MspkiGuiTourStop; Wait-MspkiGuiIdle -Rounds 3
                if ($renderW -gt 0) { Set-MspkiGuiSnapshotLayout -Window $Window -Width $renderW -Height $renderH; Show-MspkiGuiTourStop; Wait-MspkiGuiIdle -Rounds 2 }
                & $shot ('16-tour-{0}' -f ($ti + 1))
            }
            $ui.TourLayer.Visibility = 'Collapsed'; $g.TourStops = $null
            if ($null -ne $osv2) { $osv2.ScrollToTop() }
            & $page $ui.TabLearn
            Show-MspkiGuiLearnItem -Name 'CDP'; Wait-MspkiGuiIdle -Rounds 2
            & $shot '37-learn'
            $ui.FltLearn.Text = 'revoked'; Wait-MspkiGuiIdle -Rounds 2
            & $shot '37a-learn-search'
            $ui.FltLearn.Text = 'no-such-term-text'; Wait-MspkiGuiIdle -Rounds 2
            & $shot '37b-learn-nomatch'
            $ui.FltLearn.Text = ''
            # High contrast (GX5): the window with the SystemColors palette as this computer has it now (a real high-contrast theme
            # changes those colours); the findings page shows the most kinds of element.
            $Window.Resources.MergedDictionaries[0] = (Import-MspkiGuiPalette -Theme HighContrast)
            & $page $ui.TabFindings
            & $shot '90-high-contrast-mapping'
            Set-MspkiGuiTheme -Mode ([string]$g.ThemeMode) -Force

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
    finally {
        if ($renderW -gt 0) { try { Clear-MspkiGuiSnapshotLayout -Window $Window } catch { $null = $_ } }
        $Window.Close()
        try { $frames | Export-Csv -LiteralPath (Join-Path $Folder 'frames.csv') -NoTypeInformation -Encoding UTF8 } catch { $null = $_ }
    }
    return $files.ToArray()
}
