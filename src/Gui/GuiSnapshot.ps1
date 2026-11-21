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

function Save-MspkiGuiSnapshotImage {
    <#
    .SYNOPSIS
    Renders the window (as it is now) to a PNG file with RenderTargetBitmap. Returns the file path.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Window, [Parameter(Mandatory = $true)][string]$Path, [double]$Scale = 1.0)
    Wait-MspkiGuiIdle
    $w = [int][math]::Ceiling($Window.ActualWidth * $Scale)
    $h = [int][math]::Ceiling($Window.ActualHeight * $Scale)
    $dpi = 96.0 * $Scale
    $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap($w, $h, $dpi, $dpi, [System.Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($Window)
    $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))
    $fs = [System.IO.File]::Create($Path)
    try { $enc.Save($fs) } finally { $fs.Dispose() }
    return $Path
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
        [switch]$Maximized
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
    $files = New-Object 'System.Collections.Generic.List[string]'
    $shot = {
        param([string]$Name)
        $p = Join-Path $Folder ($Name + '.png')
        [void](Save-MspkiGuiSnapshotImage -Window $Window -Path $p -Scale $Scale)
        $files.Add($p)
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
            Open-MspkiGuiResultsFile -Path $ResultsFile
            if ($null -eq $g.Data) { throw 'The results file could not be opened.' }
            $data = $g.Data
            Wait-MspkiGuiIdle -Rounds 4
            & $page $ui.TabSummary
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
            if ($g.Rows.Count -gt 0) { $ui.FindingsGrid.SelectedIndex = 0 }
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
            if ($null -ne $pick) { $g.MapPane = Get-MspkiGuiNodePane -Node $pick -RowById $g.RowById; $ui.MapHost.Content = $g.MapPane }
            & $shot '30-map'
            $first = $null
            if ($null -ne $g.MapPane) { $first = @($g.MapPane.Findings | Where-Object { $_ }) | Select-Object -First 1 }
            if ($null -ne $first -and $g.RowById.ContainsKey([string]$first.Id)) {
                $ui.MapHost.Content = Get-MspkiGuiFindingDetail -Finding $g.RowById[[string]$first.Id].Finding -CanGoBack $true
                & $shot '31-map-finding'
                $ui.MapHost.Content = $g.MapPane
            }
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
    finally { $Window.Close() }
    return $files.ToArray()
}
