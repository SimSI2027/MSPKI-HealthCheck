# Developer snapshots: render each tab of the window to a PNG with RenderTargetBitmap (no screen capture).
# Used with: Start-MspkiHealthCheckGui.ps1 -Snapshot <folder under out\> [-ResultsFile <results.json>]
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
    Shows the window off-screen, takes one PNG per tab (and a few states of them), closes the window. Returns the files written.
    The folder must be inside -AllowedRoot (the out folder); anything else is refused before anything is written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Window,
        [Parameter(Mandatory = $true)][string]$Folder,
        [Parameter(Mandatory = $true)][string]$AllowedRoot,
        [AllowEmptyString()][string]$ResultsFile = '',
        [int]$Width = 1360,
        [int]$Height = 860,
        [double]$Scale = 1.0
    )
    if (-not (Test-MspkiGuiSnapshotFolder -Folder $Folder -AllowedRoot $AllowedRoot)) { throw ('Snapshots can only be written inside {0} (they can contain real names).' -f $AllowedRoot) }
    $g = $script:MspkiGui
    $ui = $g.Ui
    [void][System.IO.Directory]::CreateDirectory($Folder)
    $Window.WindowStartupLocation = 'Manual'
    $Window.Left = -32000; $Window.Top = 0
    $Window.ShowInTaskbar = $false
    $Window.Width = $Width; $Window.Height = $Height
    $Window.Show()
    Wait-MspkiGuiIdle -Rounds 4
    $files = New-Object 'System.Collections.Generic.List[string]'
    $shot = {
        param([string]$Name)
        $p = Join-Path $Folder ($Name + '.png')
        [void](Save-MspkiGuiSnapshotImage -Window $Window -Path $p -Scale $Scale)
        $files.Add($p)
    }
    try {
        # Before the first run: the welcome state, and the options panel open.
        $ui.Tabs.SelectedItem = $ui.TabSummary
        & $shot '00-welcome'
        $ui.ExpOptions.IsExpanded = $true
        & $shot '01-welcome-options'
        $ui.ExpOptions.IsExpanded = $false
        if ($ResultsFile) {
            Open-MspkiGuiResultsFile -Path $ResultsFile
            if ($null -eq $g.Data) { throw 'The results file could not be opened.' }
            Wait-MspkiGuiIdle -Rounds 4
            $ui.Tabs.SelectedItem = $ui.TabSummary
            & $shot '10-summary'
            # Scrolled to the bottom of the summary (top issues, coverage).
            $sv = $ui.PanelResults.Parent
            while ($null -ne $sv -and $sv -isnot [System.Windows.Controls.ScrollViewer]) { $sv = [System.Windows.LogicalTreeHelper]::GetParent($sv) }
            if ($null -ne $sv) { $sv.ScrollToEnd(); & $shot '11-summary-bottom'; $sv.ScrollToTop() }
            # Findings: first row selected, then grouped and filtered.
            $ui.Tabs.SelectedItem = $ui.TabFindings
            Wait-MspkiGuiIdle -Rounds 3
            if ($g.Rows.Count -gt 0) { $ui.FindingsGrid.SelectedIndex = 0 }
            & $shot '20-findings'
            $ui.ChkGroup.IsChecked = $true
            $g.View.GroupDescriptions.Add((New-Object System.Windows.Data.PropertyGroupDescription('Category')))
            & $shot '21-findings-grouped'
            $g.View.GroupDescriptions.Clear(); $ui.ChkGroup.IsChecked = $false
            # Discovery map: expand everything, select the first CA node.
            $ui.Tabs.SelectedItem = $ui.TabMap
            Wait-MspkiGuiIdle -Rounds 3
            Set-MspkiGuiTreeExpansion -Parent $ui.MapTree -Expand $true
            Wait-MspkiGuiIdle -Rounds 3
            $pick = $null
            $stack = New-Object System.Collections.Stack
            foreach ($i in @($ui.MapTree.ItemsSource)) { $stack.Push($i) }
            while ($stack.Count -gt 0 -and $null -eq $pick) {
                $n = $stack.Pop()
                if ($n.Type -eq 'CA') { $pick = $n }
                else { foreach ($c in @($n.Children)) { $stack.Push($c) } }
            }
            if ($null -ne $pick) { $g.MapPane = Get-MspkiGuiNodePane -Node $pick -RowById $g.RowById; $ui.MapHost.Content = $g.MapPane }
            & $shot '30-map'
        }
        $ui.Tabs.SelectedItem = $ui.TabLog
        Wait-MspkiGuiIdle -Rounds 3
        & $shot '40-log'
    }
    finally { $Window.Close() }
    return $files.ToArray()
}
