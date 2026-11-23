# GUI application: loads the window, runs the engine in a background runspace and shows the results.
# The window only displays and filters. Every check stays in the engine (src\Model, Probes, Discovery, Analyzers).
# State lives in $script:MspkiGui because event handlers run after the function that wired them has returned.

$script:MspkiGui = $null

# The mission-control Overview (score, actions, discovery map) lives in two files next to this one; they are loaded with it, so
# every caller of this file (the start script, the tests) gets them.
. (Join-Path $PSScriptRoot 'GuiMission.ps1')
. (Join-Path $PSScriptRoot 'GuiMapView.ps1')

function Import-MspkiGuiAssembly {
    <#
    .SYNOPSIS
    Loads the in-box WPF assemblies the window needs. Only these three; nothing is compiled or downloaded.
    #>
    [CmdletBinding()]
    param()
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
}

function Test-MspkiGuiApartment {
    <#
    .SYNOPSIS
    True when the current thread is single-threaded (STA), which WPF windows need.
    #>
    [CmdletBinding()]
    param()
    return ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq [System.Threading.ApartmentState]::STA)
}

function New-MspkiGuiWindow {
    <#
    .SYNOPSIS
    Loads the window from its XAML file (the theme file next to it is merged by the XAML itself) and returns the window
    and a table of its named controls.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$XamlPath)
    $full = [System.IO.Path]::GetFullPath($XamlPath)
    $xaml = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
    $ctx = New-Object System.Windows.Markup.ParserContext
    $ctx.BaseUri = New-Object System.Uri($full)
    $stream = New-Object System.IO.MemoryStream(, [System.Text.Encoding]::UTF8.GetBytes($xaml))
    $window = $null
    try { $window = [System.Windows.Markup.XamlReader]::Load($stream, $ctx) }
    finally { $stream.Dispose() }
    $ui = @{}
    foreach ($m in [regex]::Matches($xaml, 'x:Name="(\w+)"')) {
        $n = $m.Groups[1].Value
        $c = $window.FindName($n)
        if ($null -ne $c) { $ui[$n] = $c }
    }
    return [pscustomobject]@{ Window = $window; Ui = $ui }
}

function Show-MspkiGuiMessage {
    [CmdletBinding()]
    param([string]$Text, [string]$Title = 'MSPKI Health Check', [string]$Icon = 'Information')
    $owner = $null
    if ($null -ne $script:MspkiGui) { $owner = $script:MspkiGui.Window }
    if ($null -ne $owner -and $owner.IsVisible) { [void][System.Windows.MessageBox]::Show($owner, $Text, $Title, 'OK', $Icon) }
    else { [void][System.Windows.MessageBox]::Show($Text, $Title, 'OK', $Icon) }
}

function Write-MspkiGuiErrorFile {
    <#
    .SYNOPSIS
    Appends one line to gui-error.log in the output folder (only if that folder exists and the file is inside it). Never throws.
    #>
    [CmdletBinding()]
    param([string]$Line)
    try {
        $g = $script:MspkiGui
        if ($null -eq $g -or -not $g.OutputRoot -or -not (Test-Path -LiteralPath $g.OutputRoot -PathType Container)) { return }
        $root = [System.IO.Path]::GetFullPath([string]$g.OutputRoot).TrimEnd('\') + '\'
        $file = [System.IO.Path]::GetFullPath((Join-Path $g.OutputRoot 'gui-error.log'))
        if (-not $file.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { return }
        # Through the output-folder guard like every other write of this tool.
        $mod = Get-Module -Name MspkiHealthCheck
        & $mod {
            param($f, $text)
            [void](Use-MspkiOutputFolder -Path (Split-Path -Parent $f))
            Write-MspkiOutputFile -Path $f -Content $text -Append
        } $file (('{0} {1}{2}' -f [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'), $Line, [Environment]::NewLine))
    }
    catch { }
}

function Invoke-MspkiGuiUnhandledError {
    <#
    .SYNOPSIS
    The one place where an unexpected error in the window ends up (audit 2 M6): it is written to the Run log (and gui-error.log), shown
    once in a message, and the window stays alive. A run in progress is cancelled cleanly (partial results are still written). Never throws.
    .OUTPUTS
    $true (the error is handled), so a Dispatcher handler can set Handled.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Exception, [string]$Source = 'window', [switch]$Fatal)
    try {
        $text = Format-MspkiGuiErrorText -Exception $Exception
        $g = $script:MspkiGui
        $line = 'Unexpected error in the window ({0}): {1}' -f $Source, $text
        if ($null -ne $Exception) { $line += ' [{0}]' -f $Exception.GetType().FullName }
        try { if ($null -ne $g) { Add-MspkiGuiLogRow -Row (New-MspkiGuiLogRow -Text $line -Level 'Error'); Update-MspkiGuiLogView } } catch { }
        Write-MspkiGuiErrorFile -Line $line
        $runNote = ''
        if ($null -ne $g -and $null -ne $g.Run) {
            $run = $g.Run
            $engineDone = $false
            try { $engineDone = [bool]$run.Handle.IsCompleted } catch { }
            if (-not $engineDone) {
                # Cancel through the same flag the Cancel button sets: the engine stops at the next probe and writes partial results.
                try { $run.Control['Cancel'] = $true; if ($null -eq $run.CancelRequested) { $run.CancelRequested = [DateTime]::Now } } catch { }
                try { $g.Ui.BtnCancel.IsEnabled = $false } catch { }
                try { Set-MspkiGuiState -Text 'An error occurred in the window; the run is being cancelled (partial results are still written).' -State Warn } catch { }
                $runNote = ' The run in progress is being cancelled; partial results are still written.'
            }
            else {
                # The engine already finished, so the error is in showing the results. After repeated errors give the run up, so the
                # timer does not raise the same error forever; results.json and the report are already on disk.
                $g.CrashRepeats = 1 + [int]$g.CrashRepeats
                if ($g.CrashRepeats -ge 3) {
                    try { $g.Timer.Stop() } catch { }
                    try { Stop-MspkiGuiRunspace -Run $run } catch { }
                    $g.Run = $null
                    try { Set-MspkiGuiBusy -Busy $false } catch { }
                    try { Set-MspkiGuiState -Text ('The results could not be shown (see the Run log). The run finished; its files are in {0}. Use Open results to try again.' -f $g.OutputRoot) -State Warn } catch { }
                    $runNote = ' The run had finished; its files are in the output folder.'
                }
            }
            # A handled exception can leave a DispatcherTimer silent: arm it again.
            try { if ($null -ne $g.Run -and $null -ne $g.Timer) { $g.Timer.Stop(); $g.Timer.Start() } } catch { }
        }
        # One message per distinct error and at most three per session, so a repeating error cannot bury the window in dialogs.
        if ($null -ne $g) {
            if ($null -eq $g.CrashShown) { $g.CrashShown = @{} }
            $first = -not $g.CrashShown.ContainsKey($text)
            if ($first) { $g.CrashShown[$text] = $true }
            if ($first -and $g.CrashShown.Count -le 3) {
                $msg = 'Something unexpected went wrong in this window, but it is still open.{0}{0}{1}{0}{0}Details are in the Run log page.{2}' -f [Environment]::NewLine, $text, $runNote
                if ($Fatal) { $msg += ' This error could not be recovered; please save anything you need and restart the program.' }
                if ($null -ne $script:MspkiGuiErrorNotifier) { & $script:MspkiGuiErrorNotifier $msg }
                else { Show-MspkiGuiMessage -Text $msg -Title 'MSPKI Health Check' -Icon 'Warning' }
            }
        }
    }
    catch { }
    return $true
}

function Register-MspkiGuiCrashGuard {
    <#
    .SYNOPSIS
    Installs the catch-all handlers (audit 2 M6): the window's Dispatcher (an exception in any event handler or timer tick is handled
    instead of ending ShowDialog) and the AppDomain (an error on another thread is logged). Call once per window.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Window)
    $Window.Dispatcher.add_UnhandledException({
        param($sender, $e)
        $e.Handled = [bool](Invoke-MspkiGuiUnhandledError -Exception $e.Exception -Source 'Dispatcher')
    })
    # Only a log entry is possible here: the runtime ends the process after this event for an error on a non-UI thread.
    [System.AppDomain]::CurrentDomain.add_UnhandledException({
        param($sender, $e)
        [void](Invoke-MspkiGuiUnhandledError -Exception ([System.Exception]$e.ExceptionObject) -Source 'AppDomain' -Fatal:([bool]$e.IsTerminating))
    })
}

function Get-MspkiGuiBrush {
    <#
    .SYNOPSIS
    A brush from the theme (for example 'B.GoodFore').
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Key)
    return $script:MspkiGui.Window.FindResource($Key)
}

function Get-MspkiGuiToneBrush {
    [CmdletBinding()]
    param([string]$Tone)
    $k = @{ Good = 'B.GoodFore'; Warn = 'B.WarnFore'; Bad = 'B.BadFore'; Info = 'B.InfoFore'; Admin = 'B.AdminFore'; Neutral = 'B.NeutralFore' }[$Tone]
    if (-not $k) { $k = 'B.NeutralFore' }
    return (Get-MspkiGuiBrush -Key $k)
}

function Set-MspkiGuiState {
    <#
    .SYNOPSIS
    The run state in the status bar: an icon and a short sentence. Icon and text always go together.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [ValidateSet('Ready', 'Running', 'Done', 'Warn', 'Bad')][string]$State = 'Ready'
    )
    $ui = $script:MspkiGui.Ui
    $spec = @{
        Ready = @(0xE946, 'Info'); Running = @(0xE895, 'Info'); Done = @(0xE73E, 'Good'); Warn = @(0xE7BA, 'Warn'); Bad = @(0xE711, 'Bad')
    }[$State]
    $ui.StatusIcon.Text = [string][char]$spec[0]
    $ui.StatusIcon.Foreground = Get-MspkiGuiToneBrush -Tone $spec[1]
    $ui.TxtStage.Text = $Text
}

function Set-MspkiGuiClipboard {
    <#
    .SYNOPSIS
    Puts text on the clipboard (another program can hold it for a moment, so it retries a few times).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    for ($i = 0; $i -lt 5; $i++) {
        try { [System.Windows.Clipboard]::SetText($Text); return $true }
        catch { Start-Sleep -Milliseconds 80 }
    }
    Show-MspkiGuiMessage -Text 'The clipboard is in use by another program. Try again.' -Icon 'Warning'
    return $false
}

function Set-MspkiGuiBusy {
    <#
    .SYNOPSIS
    Enables and disables the buttons and options for a running or idle window.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][bool]$Busy)
    $ui = $script:MspkiGui.Ui
    $ui.BtnRun.IsEnabled = -not $Busy
    $ui.BtnWelcomeRun.IsEnabled = -not $Busy
    $ui.BtnWelcomeOpen.IsEnabled = -not $Busy
    $ui.BtnCancel.IsEnabled = $Busy
    $ui.BtnOpenResults.IsEnabled = -not $Busy
    foreach ($n in @('TxtTimeout', 'ChkSkipNetwork', 'ChkProxy', 'ChkNdesAdmin')) { $ui[$n].IsEnabled = -not $Busy }
    # While busy the Overview is the live mission control (same hero, live map); when the run ends, the results or the welcome state take over.
    if ($Busy) { Enter-MspkiGuiRunningMode }
}

function Update-MspkiGuiNavMode {
    <#
    .SYNOPSIS
    Compact navigation (icons only) when the window is narrower than 1280 px, so the pages keep their room.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -eq $g) { return }
    $ui = $g.Ui
    # A developer snapshot lays the window out at a fixed size off the window (GuiSnapshot.ps1): its width stands in for the window's.
    $viewWidth = $g.Window.ActualWidth
    if ($g.ContainsKey('ViewWidth') -and [double]$g.ViewWidth -gt 0) { $viewWidth = [double]$g.ViewWidth }
    $compact = ($viewWidth -gt 0 -and $viewWidth -lt 1280)
    if ($compact) {
        $ui.NavColumn.Width = New-Object System.Windows.GridLength(56)
        $ui.NavList.Tag = 'Compact'; $ui.NavEnv.Visibility = 'Collapsed'; $ui.NavEnvCompact.Visibility = 'Visible'
    }
    else {
        $ui.NavColumn.Width = New-Object System.Windows.GridLength(232)
        $ui.NavList.Tag = ''; $ui.NavEnv.Visibility = 'Visible'; $ui.NavEnvCompact.Visibility = 'Collapsed'
    }
    # Status tiles: one row of eight on a wide window, two rows of four otherwise.
    $cols = 4
    if ($viewWidth -ge 1600) { $cols = 8 }
    $ui.TileList.Tag = $cols
}

function Update-MspkiGuiOptionsSummary {
    <#
    .SYNOPSIS
    The one-line summary next to the Options header, so a collapsed panel still shows what will run.
    #>
    [CmdletBinding()]
    param()
    $ui = $script:MspkiGui.Ui
    $t = Test-MspkiGuiTimeout -Text ([string]$ui.TxtTimeout.Text)
    $parts = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $t) { $parts.Add('timeout is not valid') } else { $parts.Add(('timeout {0} s' -f $t)) }
    if ([bool]$ui.ChkSkipNetwork.IsChecked) { $parts.Add('Active Directory only') } else { $parts.Add('network checks on') }
    if ([bool]$ui.ChkProxy.IsChecked) { $parts.Add('system proxy') } else { $parts.Add('direct web access') }
    if ([bool]$ui.ChkNdesAdmin.IsChecked) { $parts.Add('NDES admin probe on') } else { $parts.Add('NDES admin probe off') }
    $ui.TxtOptionsSummary.Text = ($parts -join $script:MspkiGuiDot)
}

function Update-MspkiGuiHeader {
    <#
    .SYNOPSIS
    The header strip (forest, domain, domain controller, user, Administrator badge) from a summary, or from this Windows session.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Summary = $null)
    $ui = $script:MspkiGui.Ui
    $c = Get-MspkiGuiContext -Summary $Summary
    $ui.HdrContext.ItemsSource = @($c.Items)
    $ui.HdrBadge.Content = $c.Badge
    $ui.NavEnvCompact.ToolTip = (@('Environment') + @($c.Items | ForEach-Object { '{0}: {1}' -f $_.Label, $_.Value })) -join [Environment]::NewLine
    return $c
}

function Add-MspkiGuiLogRow {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row)
    $log = $script:MspkiGui.LogRows
    $log.Add($Row)
    if ($log.Count -gt 40000) { for ($i = 0; $i -lt 5000; $i++) { $log.RemoveAt(0) } }
}

function Update-MspkiGuiLogView {
    <#
    .SYNOPSIS
    Applies the log filter box and level drop-down, updates the count and (when asked) scrolls to the newest line.
    #>
    [CmdletBinding()]
    param([switch]$Scroll)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.LogFilter.Text = ([string]$ui.FltLog.Text).Trim().ToLowerInvariant()
    $g.LogFilter.Level = [string]$ui.FltLogLevel.SelectedItem
    $g.LogView.Refresh()
    $shown = @($ui.LogList.Items).Count
    $ui.TxtLogCount.Text = '{0} of {1} shown' -f $shown, (Format-MspkiGuiCount -Count $g.LogRows.Count -Singular 'line')
    $ui.TxtLogEmpty.Visibility = 'Collapsed'
    if ($g.LogRows.Count -eq 0) { $ui.TxtLogEmpty.Text = 'The log fills in while a run is in progress.'; $ui.TxtLogEmpty.Visibility = 'Visible' }
    elseif ($shown -eq 0) { $ui.TxtLogEmpty.Text = 'No log line matches the filter.'; $ui.TxtLogEmpty.Visibility = 'Visible' }
    if ($Scroll -and [bool]$ui.ChkFollow.IsChecked -and $shown -gt 0) { $ui.LogList.ScrollIntoView($ui.LogList.Items[$shown - 1]) }
}

function Update-MspkiGuiFilter {
    <#
    .SYNOPSIS
    Reads the filter controls, refreshes the Findings grid and shows how many findings match.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -eq $g.View) { return }
    $ui = $g.Ui
    $g.Filter.Text = [string]$ui.FltText.Text
    $g.Filter.Status = [string[]]@($g.Chips | Where-Object { $_.IsChecked } | ForEach-Object { [string]$_.Tag })
    $g.Filter.Category = [string]$ui.FltCategory.SelectedItem
    $g.Filter.Confidence = [string]$ui.FltConfidence.SelectedItem
    $g.Filter.Severity = [string]$ui.FltSeverity.SelectedItem
    $g.View.Refresh()
    $shown = @($ui.FindingsGrid.Items).Count
    $ui.TxtShowing.Text = 'Showing {0} of {1}' -f $shown, (Format-MspkiGuiCount -Count $g.Rows.Count -Singular 'finding')
    if ($null -ne $g.Filter.Area) { $ui.TxtShowing.Text += ('{0}area: {1}' -f $script:MspkiGuiDot, $g.Filter.Area.Name) }
    $ui.TxtGridEmpty.Visibility = 'Collapsed'
    if ($g.Rows.Count -gt 0 -and $shown -eq 0) {
        $ui.TxtGridEmpty.Text = 'No finding matches the current filters. Use "Clear filters" to see all of them.'
        $ui.TxtGridEmpty.Visibility = 'Visible'
    }
    elseif ($g.Rows.Count -eq 0) {
        $ui.TxtGridEmpty.Text = 'There are no findings yet. Run a health check, or open an earlier results.json.'
        $ui.TxtGridEmpty.Visibility = 'Visible'
    }
}

function Clear-MspkiGuiFilter {
    <#
    .SYNOPSIS
    Resets every filter control on the Findings tab (and refreshes the grid).
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $ui.FltText.Text = ''
    $g.Filter.Area = $null
    foreach ($c in $g.Chips) { $c.IsChecked = $false }
    foreach ($n in @('FltSeverity', 'FltCategory', 'FltConfidence')) { if ($null -ne $ui[$n].Items -and $ui[$n].Items.Count -gt 0) { $ui[$n].SelectedIndex = 0 } }
    Update-MspkiGuiFilter
}

function Show-MspkiGuiArea {
    <#
    .SYNOPSIS
    From an area bar on the Overview: opens the Findings page filtered to that area's categories ("Clear filters" removes it).
    #>
    [CmdletBinding()]
    param([string]$Tag)
    $g = $script:MspkiGui
    if (-not $Tag -or -not $Tag.StartsWith('area:') -or $null -eq $g.View) { return }
    $area = @(Get-MspkiGuiScoreAreaList | Where-Object { $_.Key -eq $Tag.Substring(5) })[0]
    if ($null -eq $area) { return }
    Clear-MspkiGuiFilter
    $g.Filter.Area = $area
    Update-MspkiGuiFilter
    $g.Ui.Tabs.SelectedItem = $g.Ui.TabFindings
}

function Show-MspkiGuiAllActions {
    <#
    .SYNOPSIS
    "All actions": the Findings page filtered to every finding that needs attention (critical, failing, error, warning).
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -eq $g.View) { return }
    Clear-MspkiGuiFilter
    foreach ($c in $g.Chips) { if ([string]$c.Tag -in @('Critical', 'Fail', 'Error', 'Warning')) { $c.IsChecked = $true } }
    Update-MspkiGuiFilter
    $g.Ui.Tabs.SelectedItem = $g.Ui.TabFindings
}

function New-MspkiGuiChip {
    <#
    .SYNOPSIS
    A status filter chip (toggle button with the status icon, name and count).
    #>
    [CmdletBinding()]
    param([string]$Status, [int]$Count)
    $w = $script:MspkiGui.Window
    $pill = Get-MspkiGuiStatusPill -Value $Status
    $chip = New-Object System.Windows.Controls.Primitives.ToggleButton
    $chip.Style = $w.FindResource('ChipToggle')
    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.Orientation = 'Horizontal'
    $ic = New-Object System.Windows.Controls.TextBlock
    $ic.FontFamily = $w.FindResource('F.Icons'); $ic.Text = $pill.Glyph; $ic.FontSize = 12
    $ic.Margin = New-Object System.Windows.Thickness(0, 0, 6, 0); $ic.VerticalAlignment = 'Center'
    $ic.Foreground = Get-MspkiGuiToneBrush -Tone $pill.Tone
    $tx = New-Object System.Windows.Controls.TextBlock
    $tx.Text = '{0}  {1}' -f $pill.Text, $Count
    $tx.VerticalAlignment = 'Center'
    [void]$sp.Children.Add($ic); [void]$sp.Children.Add($tx)
    $chip.Content = $sp
    $chip.Tag = $Status
    $chip.ToolTip = 'Show only {0} findings. Select several to combine them.' -f $pill.Text
    [System.Windows.Automation.AutomationProperties]::SetName($chip, ('{0} findings: {1}' -f $pill.Text, $Count))
    $chip.Add_Click({ Update-MspkiGuiFilter })
    return $chip
}

function Show-MspkiGuiFindingPane {
    <#
    .SYNOPSIS
    Fills the details pane of the Findings tab (null clears it).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Finding)
    $g = $script:MspkiGui
    $ui = $g.Ui
    Reset-MspkiGuiPaneNav -HostName 'FindingHost'
    if ($null -eq $Finding) { $ui.FindingHost.Content = Get-MspkiGuiEmptyPane; return }
    $ui.FindingHost.Content = Add-MspkiGuiPaneObject -Pane (Get-MspkiGuiFindingDetail -Finding $Finding) -Index $g.Index -Ids @($Finding.EntityIds | Where-Object { $_ })
}

function Show-MspkiGuiNodePane {
    <#
    .SYNOPSIS
    Fills the details pane of the Discovery map for one tree item, with links to the objects behind it.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Node)
    $g = $script:MspkiGui
    Reset-MspkiGuiPaneNav -HostName 'MapHost'
    $p = Get-MspkiGuiNodePane -Node $Node -RowById $g.RowById
    if ($null -ne $Node) { $p = Add-MspkiGuiPaneObject -Pane $p -Index $g.Index -Ids (Get-MspkiGuiNodeEntityId -Index $g.Index -Node $Node -RowById $g.RowById) }
    $g.MapPane = $p
    $g.Ui.MapHost.Content = $p
}

function Reset-MspkiGuiPaneNav {
    <#
    .SYNOPSIS
    Forgets the object trail of one details pane (FindingHost, MapHost, ObjHost): called when the list or tree next to it changes selection.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$HostName)
    $script:MspkiGui.Nav[$HostName] = @{ Trail = [string[]]@(); Origin = $null; Return = $null }
}

function Show-MspkiGuiEntityPane {
    <#
    .SYNOPSIS
    Shows the object at the end of a pane's trail, with breadcrumbs and a Back link (to the previous object, or to the finding or map item
    the user came from).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$HostName)
    $g = $script:MspkiGui
    $nav = $g.Nav[$HostName]
    $t = @($nav.Trail)
    if ($t.Count -eq 0) { return }
    $origin = ''
    if ($null -ne $nav.Origin) {
        $origin = 'Back'
        if ($nav.Origin.Kind -eq 'Finding') { $origin = 'Back to the finding' }
        elseif ($nav.Origin.Kind -eq 'Node') { $origin = 'Back to the map item' }
    }
    $g.Ui[$HostName].Content = Get-MspkiGuiEntityPane -Index $g.Index -Id $t[$t.Count - 1] -RowById $g.RowById -Trail ([string[]]$t) -OriginText $origin
}

function Invoke-MspkiGuiPaneCommand {
    <#
    .SYNOPSIS
    Handles a click inside a details pane by the button's Tag: Copy, Back, "ent:<id>" (open a related object), "crumb:<n>" (jump back
    along the trail) or a finding id (open the finding in the same pane, with Back to where the user was).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$HostName, [AllowEmptyString()][string]$Tag)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $c = $ui[$HostName].Content
    if (-not $Tag -or $null -eq $c) { return }
    if (-not $g.Nav.ContainsKey($HostName)) { Reset-MspkiGuiPaneNav -HostName $HostName }
    $nav = $g.Nav[$HostName]
    if ($Tag -eq 'Copy') { if ($c.CopyText) { [void](Set-MspkiGuiClipboard -Text $c.CopyText) }; return }
    if ($Tag -eq 'Back') {
        if ($null -ne $nav.Return) { $ui[$HostName].Content = $nav.Return; $nav.Return = $null; return }
        if (@($nav.Trail).Count -gt 1) { $nav.Trail = Step-MspkiGuiTrail -Trail $nav.Trail -Action Back; Show-MspkiGuiEntityPane -HostName $HostName; return }
        if ($null -ne $nav.Origin) { $ui[$HostName].Content = $nav.Origin; $nav.Origin = $null; $nav.Trail = [string[]]@() }
        return
    }
    if ($Tag.StartsWith('ent:')) {
        if (@($nav.Trail).Count -eq 0 -and $c.Kind -ne 'Entity') { $nav.Origin = $c }
        $nav.Return = $null
        $nav.Trail = Step-MspkiGuiTrail -Trail $nav.Trail -Action Push -Id $Tag.Substring(4)
        Show-MspkiGuiEntityPane -HostName $HostName
        return
    }
    if ($Tag.StartsWith('crumb:')) {
        $nav.Return = $null
        $nav.Trail = Step-MspkiGuiTrail -Trail $nav.Trail -Action Crumb -Index ([int]$Tag.Substring(6))
        Show-MspkiGuiEntityPane -HostName $HostName
        return
    }
    if ($g.RowById.ContainsKey($Tag)) {
        $back = 'Back'
        if ($c.Kind -eq 'Entity') { $back = 'Back to {0}' -f $c.Title }
        elseif ($c.Kind -eq 'Node') { $back = 'Back to the map item' }
        $nav.Return = $c
        $f = $g.RowById[$Tag].Finding
        $ui[$HostName].Content = Add-MspkiGuiPaneObject -Pane (Get-MspkiGuiFindingDetail -Finding $f -CanGoBack $true -BackText $back) -Index $g.Index -Ids @($f.EntityIds | Where-Object { $_ })
    }
}

function Update-MspkiGuiObjectFilter {
    <#
    .SYNOPSIS
    Applies the search box, type filter and "needs attention" switch of the Objects page and updates its count and empty text.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -eq $g.ObjView) { $ui.TxtObjShowing.Text = ''; return }
    $g.ObjFilter.Text = [string]$ui.FltObj.Text
    $g.ObjFilter.Type = [string]$ui.FltObjType.SelectedItem
    $g.ObjFilter.Attention = [bool]$ui.ChkObjAttention.IsChecked
    $g.ObjView.Refresh()
    $shown = $ui.ObjList.Items.Count
    $total = @($g.ObjRows).Count
    $ui.TxtObjShowing.Text = 'Showing {0} of {1}' -f $shown, (Format-MspkiGuiCount -Count $total -Singular 'object')
    if ($shown -eq 0 -and $total -gt 0) { $ui.TxtObjEmpty.Text = 'No object matches the search and filters. Clear the filters to see every object.'; $ui.TxtObjEmpty.Visibility = 'Visible' }
    elseif ($total -gt 0) { $ui.TxtObjEmpty.Visibility = 'Collapsed' }
}

function Clear-MspkiGuiObjectFilter {
    [CmdletBinding()]
    param()
    $ui = $script:MspkiGui.Ui
    $ui.FltObj.Text = ''
    if ($null -ne $ui.FltObjType.Items -and $ui.FltObjType.Items.Count -gt 0) { $ui.FltObjType.SelectedIndex = 0 }
    $ui.ChkObjAttention.IsChecked = $false
    Update-MspkiGuiObjectFilter
}

function Show-MspkiGuiObject {
    <#
    .SYNOPSIS
    Opens one object on the Objects page: selects it in the list (clearing the filters when they hide it) and shows its details.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $g = $script:MspkiGui
    $ui = $g.Ui
    $ui.Tabs.SelectedItem = $ui.TabObjects
    $row = @($g.ObjRows | Where-Object { $_.Id -eq $Id }) | Select-Object -First 1
    if ($null -ne $row) {
        $f = $g.ObjFilter
        if (-not (Test-MspkiGuiObjectFilter -Row $row -Text $f.Text -Type $f.Type -AttentionOnly:([bool]$f.Attention))) { Clear-MspkiGuiObjectFilter }
        $ui.ObjList.SelectedItem = $row
        $ui.ObjList.ScrollIntoView($row)
        return
    }
    Reset-MspkiGuiPaneNav -HostName 'ObjHost'
    $g.Nav.ObjHost.Trail = [string[]]@($Id)
    Show-MspkiGuiEntityPane -HostName 'ObjHost'
}

function Open-MspkiGuiServiceItem {
    <#
    .SYNOPSIS
    From the PKI services page: opens a service (Tag "ent:<id>") or a finding (its id) in the details pane next to the list.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Tag)
    $g = $script:MspkiGui
    if (-not $Tag) { return }
    Reset-MspkiGuiPaneNav -HostName 'SvcHost'
    if ($Tag.StartsWith('ent:')) { $g.Nav.SvcHost.Trail = [string[]]@($Tag.Substring(4)); Show-MspkiGuiEntityPane -HostName 'SvcHost'; return }
    if ($g.RowById.ContainsKey($Tag)) {
        $f = $g.RowById[$Tag].Finding
        $g.Ui.SvcHost.Content = Add-MspkiGuiPaneObject -Pane (Get-MspkiGuiFindingDetail -Finding $f) -Index $g.Index -Ids @($f.EntityIds | Where-Object { $_ })
    }
}

function Show-MspkiGuiObjectsOfType {
    <#
    .SYNOPSIS
    From an Overview tile: the Objects page filtered to one object type (an entity type name such as CA or Template).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Type)
    $ui = $script:MspkiGui.Ui
    Clear-MspkiGuiObjectFilter
    $label = (Get-MspkiGuiEntityTypeInfo -Type $Type).Label
    $idx = @($ui.FltObjType.Items).IndexOf($label)
    if ($idx -ge 0) { $ui.FltObjType.SelectedIndex = $idx }
    Update-MspkiGuiObjectFilter
    $ui.Tabs.SelectedItem = $ui.TabObjects
    if ($ui.ObjList.Items.Count -gt 0) { $ui.ObjList.SelectedIndex = 0 }
}

function Clear-MspkiGuiResult {
    <#
    .SYNOPSIS
    Empties every results view (used when a new run starts and before results are loaded) and shows the welcome state.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.Data = $null; $g.Summary = $null; $g.Rows = (New-Object 'System.Collections.Generic.List[object]'); $g.View = $null; $g.RowById = @{}; $g.MapPane = $null
    $g.Chips = @()
    $ui.FindingsGrid.ItemsSource = $null
    $ui.ChipList.ItemsSource = $null
    $ui.MapTree.ItemsSource = $null
    $ui.MapHost.Content = Get-MspkiGuiEmptyPane -Text 'Select an item in the tree to see what was found and why.'
    $ui.FindingHost.Content = Get-MspkiGuiEmptyPane
    foreach ($h in @('FindingHost', 'MapHost', 'ObjHost', 'SvcHost')) { Reset-MspkiGuiPaneNav -HostName $h }
    $ui.SvcList.ItemsSource = $null
    $ui.SvcHost.Content = Get-MspkiGuiEmptyPane -Text 'Select a service or a finding to see its details.'
    $ui.TxtSvcSummary.Text = ''
    $ui.TxtSvcEmpty.Visibility = 'Visible'
    $g.Index = $null; $g.ObjRows = @(); $g.ObjView = $null
    $ui.ObjList.ItemsSource = $null
    $ui.ObjHost.Content = Get-MspkiGuiEmptyPane -Text 'Select an object to see where it exists, where it is missing and what it is linked to.'
    $ui.FltObj.Text = ''
    $ui.FltObjType.ItemsSource = @('All'); $ui.FltObjType.SelectedIndex = 0
    $ui.ChkObjAttention.IsChecked = $false
    $ui.TxtObjShowing.Text = ''
    $ui.TxtObjEmpty.Text = 'There are no objects yet. Run a health check, or open an earlier results.json.'
    $ui.TxtObjEmpty.Visibility = 'Visible'
    foreach ($n in @('KpiList', 'TileList', 'SevTileList', 'CaList', 'CoverageList', 'CoverageOkList', 'ActionList')) { $ui[$n].ItemsSource = $null }
    if ($null -ne $g.Storyboard) { try { $g.Storyboard.Stop($ui.PanelResults); $g.Storyboard.Remove($ui.PanelResults) } catch { $null = $_ } }
    $g.Storyboard = $null; $g.MapModel = $null; $g.MapDrawn = $null; $g.MapDrawnWidth = 0; $g.MapAnimatePending = $false; $g.Score = $null; $g.Actions = $null
    $g.Live = $null; $g.ActionsExpanded = $false
    $ui.MapCanvas.Children.Clear()
    $ui.AreaPanel.Children.Clear()
    $ui.TxtNoSeverity.Visibility = 'Collapsed'
    $ui.ExpCoverageOk.Visibility = 'Collapsed'
    $ui.PanelResults.Visibility = 'Collapsed'
    $ui.PanelWelcome.Visibility = 'Visible'
    Set-MspkiGuiHeroMode -Mode Results
    $ui.WelcomeError.Visibility = 'Collapsed'
    $ui.TxtNote.Visibility = 'Collapsed'
    $ui.TxtShowing.Text = ''
    $ui.TxtTabFindings.Text = ''
    $ui.TxtMapCount.Text = ''
    $ui.TxtGridEmpty.Text = 'There are no findings yet. Run a health check, or open an earlier results.json.'
    $ui.TxtGridEmpty.Visibility = 'Visible'
    $ui.FltText.Text = ''
    foreach ($n in @('FltSeverity', 'FltCategory', 'FltConfidence')) { $ui[$n].ItemsSource = @('All'); $ui[$n].SelectedIndex = 0 }
    $ui.ChkGroup.IsChecked = $false
    $g.Filter.Text = ''; $g.Filter.Status = @(); $g.Filter.Category = ''; $g.Filter.Confidence = ''; $g.Filter.Severity = ''; $g.Filter.Area = $null
    $ui.BtnOpenReport.IsEnabled = $false
    $ui.TxtCount.Text = '0 findings'
    $ui.TxtOutputPath.Text = $g.OutputRoot
    $ui.TxtOutputPath.ToolTip = $g.OutputRoot
    [void](Update-MspkiGuiHeader -Summary $null)
    $c = Get-MspkiGuiContext -Summary $null
    $ui.TxtWelcomeContext.Text = 'This window runs as {0} ({1}). Administrator rights are not required; some local checks on a CA server need them. Output goes to: {2}' -f `
        $c.Items[3].Value, $c.Badge.Text.ToLowerInvariant(), $g.OutputRoot
}

function Show-MspkiGuiResult {
    <#
    .SYNOPSIS
    Shows a run (live or loaded from results.json) in the Summary, Findings and Discovery Map tabs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Data,
        [string]$Banner = ''
    )
    $g = $script:MspkiGui
    $ui = $g.Ui
    Clear-MspkiGuiResult
    $g.Data = $Data
    $findings = @($Data.Findings | Where-Object { $null -ne $_ })
    $graph = $null
    if ($null -ne $Data.PSObject.Properties['Graph']) { $graph = $Data.Graph }
    $g.Index = New-MspkiGuiGraphIndex -Graph $graph -Findings $findings

    # Summary
    $s = Get-MspkiGuiSummary -RunInfo $Data.RunInfo -Inventory $Data.Inventory -Findings $findings -ExitCode $Data.ExitCode
    $g.Summary = $s
    [void](Update-MspkiGuiHeader -Summary $s)
    $h = $s.Health
    $ui.Banner.DataContext = $h
    $ui.BannerGlyph.Text = $h.Glyph
    $ui.BannerTitle.Text = $h.Title
    $ui.BannerText.Text = $h.Text
    $ui.BannerMeta1.Text = 'Exit code: {0}' -f $(if ($s.ExitCode) { $s.ExitCode } else { [string][char]0x2014 })
    $ui.BannerMeta2.Text = '{0}{1}' -f $(if ($s.RunState) { $s.RunState } else { 'State unknown' }), $(if ($s.Duration) { ' in ' + $s.Duration } else { '' })
    $sd = ConvertTo-MspkiGuiDateTime -Value $s.Started
    $ui.BannerMeta3.Text = 'Started: {0}' -f $(if ($null -ne $sd) { $sd.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { [string][char]0x2014 })
    $ui.TxtTotal.Text = 'Findings ({0} in total)' -f $s.Total
    $ui.KpiList.ItemsSource = @($s.Kpis)
    $ui.TileList.ItemsSource = @($s.Tiles)
    $ui.SevTileList.ItemsSource = @($s.SeverityTiles)
    $hasSeverity = (@($s.SeverityTiles | Where-Object { $_.Status -ne 'Information' -and $_.Count -gt 0 }).Count -gt 0)
    $ui.SevTileList.Visibility = $(if ($hasSeverity) { 'Visible' } else { 'Collapsed' })
    $ui.TxtNoSeverity.Visibility = $(if ($hasSeverity) { 'Collapsed' } else { 'Visible' })
    foreach ($card in @($s.CAs)) {
        $cid = @(Find-MspkiGuiEntityId -Index $g.Index -Name ([string]$card.Name) -Type 'CA') | Select-Object -First 1
        $card | Add-Member -NotePropertyName Tag -NotePropertyValue $(if ($cid) { 'ent:' + $cid } else { '' }) -Force
    }
    $ui.CaList.ItemsSource = @($s.CAs)
    $ui.TxtNoCa.Visibility = $(if (@($s.CAs).Count -eq 0) { 'Visible' } else { 'Collapsed' })
    $ui.TxtCoverage.Text = $s.Coverage.Text
    $ui.CoverageList.ItemsSource = @($s.Coverage.Attention)
    $ui.CoverageOkList.ItemsSource = @($s.Coverage.Succeeded)
    $ui.TxtCoverageOk.Text = $s.Coverage.SucceededText
    $ui.ExpCoverageOk.Visibility = $(if (@($s.Coverage.Succeeded).Count -gt 0) { 'Visible' } else { 'Collapsed' })
    if (@($s.Limits).Count -gt 0) { $ui.TxtLimits.Text = 'Limits of this run: ' + (@($s.Limits) -join ' '); $ui.TxtLimits.Visibility = 'Visible' }
    else { $ui.TxtLimits.Visibility = 'Collapsed' }
    $ui.PanelWelcome.Visibility = 'Collapsed'
    $ui.PanelResults.Visibility = 'Visible'

    # Findings grid with filters, chips, sorting and grouping
    $g.Rows = (ConvertTo-MspkiGuiRowList -Findings $findings)
    $g.RowById = @{}
    foreach ($r in $g.Rows) { $g.RowById[$r.Id] = $r }
    $ui.FindingsGrid.ItemsSource = $g.Rows
    $g.View = [System.Windows.Data.CollectionViewSource]::GetDefaultView($g.Rows)
    $g.View.Filter = [System.Predicate[object]]{
        param($row)
        $f = $script:MspkiGui.Filter
        if ($null -ne $f.Area -and $f.Area.Categories -notcontains [string]$row.Category) { return $false }
        return (Test-MspkiGuiRowFilter -Row $row -Text $f.Text -Status $f.Status -Category $f.Category -Confidence $f.Confidence -Severity $f.Severity)
    }
    [void]$g.View.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription('StatusRank', [System.ComponentModel.ListSortDirection]::Descending)))
    [void]$g.View.SortDescriptions.Add((New-Object System.ComponentModel.SortDescription('Id', [System.ComponentModel.ListSortDirection]::Ascending)))
    $ui.FltSeverity.ItemsSource = @(Get-MspkiGuiFilterChoice -Rows $g.Rows -Field Severity)
    $ui.FltCategory.ItemsSource = @(Get-MspkiGuiFilterChoice -Rows $g.Rows -Field Category)
    $ui.FltConfidence.ItemsSource = @(Get-MspkiGuiFilterChoice -Rows $g.Rows -Field Confidence)
    foreach ($n in @('FltSeverity', 'FltCategory', 'FltConfidence')) { $ui[$n].SelectedIndex = 0 }
    $chips = New-Object 'System.Collections.Generic.List[object]'
    foreach ($st in (Get-MspkiGuiStatusOrder)) {
        $n = @($g.Rows | Where-Object { $_.Status -eq $st }).Count
        if ($n -gt 0) { $chips.Add((New-MspkiGuiChip -Status $st -Count $n)) }
    }
    $g.Chips = $chips.ToArray()
    $ui.ChipList.ItemsSource = $g.Chips
    $ui.TxtTabFindings.Text = '{0}' -f $g.Rows.Count
    $ui.TxtCount.Text = '{0} finding{1}' -f $g.Rows.Count, $(if ($g.Rows.Count -eq 1) { '' } else { 's' })
    Update-MspkiGuiFilter
    if ($g.Rows.Count -gt 0) { $ui.FindingsGrid.SelectedIndex = 0 }

    # Discovery Map
    $tree = Get-MspkiDiscoveryTree -Inventory $Data.Inventory -Findings $findings -RunInfo $Data.RunInfo
    $root = ConvertTo-MspkiGuiTreeNode -Node $tree
    $ui.MapTree.ItemsSource = @($root)
    $ui.TxtMapCount.Text = Format-MspkiGuiCount -Count (Get-MspkiGuiNodeCount -Node $root) -Singular 'item'
    Show-MspkiGuiNodePane -Node $root
    $ui.MapTree.UpdateLayout()
    $rc = $ui.MapTree.ItemContainerGenerator.ContainerFromIndex(0)
    if ($null -ne $rc) { $rc.IsSelected = $true }

    # Objects (the entity graph; results written before format 2 have none)
    $g.ObjRows = @(Get-MspkiGuiObjectList -Index $g.Index -RowById $g.RowById)
    $ui.ObjList.ItemsSource = $g.ObjRows
    $g.ObjView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($ui.ObjList.ItemsSource)
    if ($null -ne $g.ObjView) {
        $g.ObjView.Filter = [System.Predicate[object]]{
            param($row)
            $f = $script:MspkiGui.ObjFilter
            return (Test-MspkiGuiObjectFilter -Row $row -Text $f.Text -Type $f.Type -AttentionOnly:([bool]$f.Attention))
        }
        $g.ObjView.GroupDescriptions.Clear()
        [void]$g.ObjView.GroupDescriptions.Add((New-Object System.Windows.Data.PropertyGroupDescription('TypeText')))
    }
    $ui.FltObjType.ItemsSource = @(Get-MspkiGuiObjectTypeChoice -Rows $g.ObjRows)
    $ui.FltObjType.SelectedIndex = 0
    if ($g.ObjRows.Count -eq 0) {
        $ui.TxtObjEmpty.Text = $(if ($null -eq $g.Index) { 'These results were written by an older version of the tool, without the object graph. Run the health check again to see every object.' } else { 'This run recorded no objects.' })
        $ui.TxtObjEmpty.Visibility = 'Visible'
    }
    else { $ui.TxtObjEmpty.Visibility = 'Collapsed' }
    Update-MspkiGuiObjectFilter
    if ($g.ObjRows.Count -gt 0) { $ui.ObjList.SelectedIndex = 0 }

    # PKI services (one card per service kind; without a graph they are built from the findings alone)
    # @($g.Rows) on the generic list throws "Argument types do not match" in Windows PowerShell 5.1; the pipeline does not.
    $svc = @(Get-MspkiGuiServiceSection -Index $g.Index -Rows @($g.Rows | Where-Object { $null -ne $_ }))
    $ui.SvcList.ItemsSource = $svc
    $found = @($svc | Where-Object { $_.Found }).Count
    $notes = @($svc | Where-Object { $_.RiskCount -gt 0 }).Count
    $ui.TxtSvcSummary.Text = '{0} of {1} service types confirmed in this run{2}{3}.' -f $found, $svc.Count, $script:MspkiGuiDot, $(if ($notes -gt 0) { '{0} with findings that need attention' -f $notes } else { 'no service has a finding that needs attention' })
    if ($null -eq $g.Index) { $ui.TxtSvcSummary.Text += ' These results have no object graph (older version), so only the findings are shown.' }
    $ui.TxtSvcEmpty.Visibility = 'Collapsed'

    # Buttons, folder and notes
    $ui.BtnOpenReport.IsEnabled = [bool]$Data.ReportPath
    $where = [string]$Data.OutputFolder
    if (-not $where) { $where = $g.OutputRoot }
    $ui.TxtOutputPath.Text = $where
    $ui.TxtOutputPath.ToolTip = $where
    $notes = New-Object 'System.Collections.Generic.List[string]'
    if ($Banner) { $notes.Add($Banner) }
    # A partial run is already called out in the health banner (text and state), so it gets no second note here.
    if ($notes.Count -gt 0) { $ui.TxtNote.Text = ($notes -join ' '); $ui.TxtNote.Visibility = 'Visible' }
    if ($s.Duration) { $ui.TxtElapsed.Text = 'Took {0}' -f $s.Duration } else { $ui.TxtElapsed.Text = '' }

    # Mission control: score, areas, what to do next, and the discovery map (built on screen once the Overview has a size).
    Update-MspkiGuiMission -Data $Data -Animate
}

function Show-MspkiGuiLogFile {
    <#
    .SYNOPSIS
    Fills the Run Log tab from the run.log of an earlier run (read only).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path)
    $g = $script:MspkiGui
    $g.LogRows.Clear()
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Add-MspkiGuiLogRow -Row (New-MspkiGuiLogRow -Text '(no run.log was found next to this results.json)' -Level 'Info')
    }
    else {
        foreach ($line in [System.IO.File]::ReadLines($Path)) { Add-MspkiGuiLogRow -Row (ConvertTo-MspkiGuiLogRowFromLine -Line $line) }
    }
    Update-MspkiGuiLogView -Scroll
}

function Open-MspkiGuiResultsFile {
    <#
    .SYNOPSIS
    Loads an earlier results.json into the window without scanning anything.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $g = $script:MspkiGui
    try {
        $data = Read-MspkiGuiResults -Path $Path
        $banner = 'Showing an earlier run loaded from {0}. Nothing was scanned.' -f $data.ResultsPath
        if ($data.Notice) { $banner = '{0} {1}' -f $banner, $data.Notice }
        Show-MspkiGuiResult -Data $data -Banner $banner
        Show-MspkiGuiLogFile -Path $data.LogPath
        $g.Ui.Progress.Value = 0
        $g.Ui.TxtTarget.Text = ''
        $state = 'Done'
        if ($g.Summary.Health.Level -ne 'Green') { $state = 'Warn' }
        Set-MspkiGuiState -Text ('Loaded {0} from an earlier run' -f (Format-MspkiGuiCount -Count @($data.Findings).Count -Singular 'finding')) -State $state
        $g.Ui.Tabs.SelectedItem = $g.Ui.TabSummary
    }
    catch {
        Show-MspkiGuiMessage -Text $_.Exception.Message -Title 'Could not open the results' -Icon 'Warning'
    }
}

function Start-MspkiGuiRunspace {
    <#
    .SYNOPSIS
    Starts the engine in a background runspace so that the window never freezes. Returns the handle object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ModulePath,
        [Parameter(Mandatory = $true)][hashtable]$Parameters,
        [Parameter(Mandatory = $true)]$Control
    )
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $rs.ApartmentState = [System.Threading.ApartmentState]::STA
    $rs.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $rs.Open()
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs
    $script = {
        param($modulePath, $runParameters, $control)
        Import-Module -Name $modulePath -Force -ErrorAction Stop
        Start-MspkiHealthCheck @runParameters -Control $control
    }
    [void]$ps.AddScript($script.ToString(), $true)
    [void]$ps.AddArgument($ModulePath)
    [void]$ps.AddArgument($Parameters)
    [void]$ps.AddArgument($Control)
    $handle = $ps.BeginInvoke()
    return [pscustomobject]@{ PowerShell = $ps; Runspace = $rs; Handle = $handle; Control = $Control; Started = [DateTime]::Now; CancelRequested = $null }
}

function Stop-MspkiGuiRunspace {
    <#
    .SYNOPSIS
    Ends a background run for good (used when the window closes and the engine does not stop in time).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Run)
    if ($null -eq $Run) { return }
    try { [void]$Run.PowerShell.BeginStop($null, $null) } catch { }
}

function Request-MspkiGuiCancel {
    <#
    .SYNOPSIS
    Asks the running engine to stop at the next stage or probe (partial results are still written).
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -eq $g.Run) { return }
    $g.Run.Control['Cancel'] = $true
    if ($null -eq $g.Run.CancelRequested) { $g.Run.CancelRequested = [DateTime]::Now }
    $g.Ui.BtnCancel.IsEnabled = $false
    Set-MspkiGuiState -Text 'Cancelling... waiting for the current step to finish (a few seconds at most).' -State Warn
}

function Start-MspkiGuiRun {
    <#
    .SYNOPSIS
    Reads the options, clears the window and starts a new health check in the background.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -ne $g.Run) { return }
    $timeout = Test-MspkiGuiTimeout -Text ([string]$ui.TxtTimeout.Text)
    if ($null -eq $timeout) {
        $ui.ExpOptions.IsExpanded = $true
        Show-MspkiGuiMessage -Text 'The timeout must be a whole number of seconds from 1 to 120.' -Title 'Check the options' -Icon 'Warning'
        $ui.TxtTimeout.Focus() | Out-Null
        return
    }
    $params = @{
        OutputPath            = $g.OutputRoot
        TimeoutSeconds        = $timeout
        SkipNetwork           = [bool]$ui.ChkSkipNetwork.IsChecked
        UseSystemProxy        = [bool]$ui.ChkProxy.IsChecked
        IncludeNdesAdminProbe = [bool]$ui.ChkNdesAdmin.IsChecked
    }
    Clear-MspkiGuiResult
    $g.LogRows.Clear()
    Update-MspkiGuiLogView
    $g.FinishedStages = New-Object 'System.Collections.Generic.List[string]'
    $ui.Progress.Value = 0
    Set-MspkiGuiState -Text 'Starting...' -State Running
    $ui.TxtTarget.Text = ''
    $ui.TxtElapsed.Text = 'Elapsed 0:00'
    $ui.TxtWelcomeContext.Text = 'A run is in progress. Findings appear here when it finishes; the Run log page shows the run live.'
    $ui.Tabs.SelectedItem = $ui.TabSummary
    $control = New-MspkiRunControl
    try {
        $g.Run = Start-MspkiGuiRunspace -ModulePath $g.ModulePath -Parameters $params -Control $control
    }
    catch {
        $g.Run = $null
        Show-MspkiGuiMessage -Text ('The run could not be started: {0}' -f $_.Exception.Message) -Title 'MSPKI Health Check' -Icon 'Error'
        return
    }
    Set-MspkiGuiBusy -Busy $true
    $ui.Progress.Visibility = 'Visible'
    $g.Timer.Start()
}

function Receive-MspkiGuiProgress {
    <#
    .SYNOPSIS
    Timer tick: reads the engine's progress queue, updates the window, and finishes the run when the engine is done.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $run = $g.Run
    if ($null -eq $run) { $g.Timer.Stop(); return }
    $ui = $g.Ui
    $q = $run.Control['Queue']
    $item = $null
    $n = 0
    $added = $false
    while ($n -lt 400 -and $q.TryDequeue([ref]$item)) {
        $n++
        switch ($item.Kind) {
            'StageStart' {
                $g.CurrentStage = [string]$item.Text
                if ($item.Text -ne 'Discovery' -and $null -eq $run.CancelRequested) { Set-MspkiGuiState -Text ('Running: {0}' -f (Get-MspkiGuiStageLabel -Stage ([string]$item.Text))) -State Running }
            }
            'StageEnd' {
                if (-not $g.FinishedStages.Contains([string]$item.Text)) { $g.FinishedStages.Add([string]$item.Text) }
                $ui.Progress.Value = Get-MspkiGuiProgressPercent -FinishedStages $g.FinishedStages.ToArray()
            }
            'Target' { $ui.TxtTarget.Text = [string]$item.Text }
            'Log' { Add-MspkiGuiLogRow -Row (ConvertTo-MspkiGuiLogRow -Message $item); $added = $true }
            { $_ -in @('Entity', 'Relation', 'Probe') } { if ($null -ne $g.Live) { [void](Add-MspkiGuiLiveItem -State $g.Live -Item $item) } }
        }
    }
    if ($null -ne $g.Live) {
        Update-MspkiGuiRunningHero
        # The map is redrawn at most twice a second, and only when something changed.
        if ($g.Live.Version -ne $g.Live.DrawnVersion -and ([DateTime]::Now - $g.Live.LastDraw).TotalMilliseconds -ge 500) { Update-MspkiGuiLiveMap }
    }
    if ($added) { Update-MspkiGuiLogView -Scroll }
    $el = [DateTime]::Now - $run.Started
    $ui.TxtElapsed.Text = 'Elapsed {0}' -f (Get-MspkiGuiDurationText -Seconds $el.TotalSeconds)

    # The window was closed during the run: wait a little for the engine to stop, then end it.
    if ($g.CloseRequested -and $null -ne $run.CancelRequested -and ([DateTime]::Now - $run.CancelRequested).TotalSeconds -gt 45 -and -not $run.Handle.IsCompleted) {
        Stop-MspkiGuiRunspace -Run $run
        $g.Run = $null
        $g.Timer.Stop()
        $g.Window.Close()
        return
    }
    if ($run.Handle.IsCompleted -and $q.IsEmpty) { Complete-MspkiGuiRun }
}

function Complete-MspkiGuiRun {
    <#
    .SYNOPSIS
    Collects the finished run, shows its results and returns the window to the idle state.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $run = $g.Run
    $g.Timer.Stop()
    # A map that was built live is not built a second time when the results arrive (only its health colours settle).
    $g.LiveWasShown = ($null -ne $g.Live -and $g.Live.Shown.Count -gt 0)
    $result = $null
    $problem = ''
    try {
        $out = @($run.PowerShell.EndInvoke($run.Handle))
        if ($out.Count -gt 0) { $result = $out[$out.Count - 1] }
    }
    catch { $problem = $_.Exception.Message }
    foreach ($e in @($run.PowerShell.Streams.Error)) {
        Add-MspkiGuiLogRow -Row (New-MspkiGuiLogRow -Text ('ERROR {0}' -f $e.ToString()) -Level 'Error')
        if (-not $problem) { $problem = $e.ToString() }
    }
    $cancelled = ($null -ne $run.CancelRequested)
    try { $run.PowerShell.Dispose(); $run.Runspace.Dispose() } catch { }
    $g.Run = $null
    $g.CurrentStage = ''
    Set-MspkiGuiBusy -Busy $false
    $ui.Progress.Visibility = 'Hidden'
    $ui.TxtTarget.Text = ''
    if ($null -ne $result -and $null -ne $result.Findings) {
        $log = ''
        if ($result.OutputFolder) { $log = Join-Path $result.OutputFolder 'run.log' }
        # The object graph is read back from results.json, so a live run and an opened file show exactly the same objects.
        $graph = $null
        if ($result.ResultsPath -and (Test-Path -LiteralPath ([string]$result.ResultsPath) -PathType Leaf)) {
            try { $graph = (Read-MspkiGuiResults -Path ([string]$result.ResultsPath)).Graph }
            catch { Add-MspkiGuiLogRow -Row (New-MspkiGuiLogRow -Text ('WARNING The object graph could not be read back from results.json: {0}' -f $_.Exception.Message) -Level 'Warning') }
        }
        $data = [pscustomobject][ordered]@{
            RunInfo = $result.RunInfo; Inventory = $result.Inventory; Findings = @($result.Findings); ExitCode = $result.ExitCode; Graph = $graph
            OutputFolder = [string]$result.OutputFolder; ResultsPath = [string]$result.ResultsPath; ReportPath = [string]$result.ReportPath; LogPath = $log
        }
        Show-MspkiGuiResult -Data $data
        Update-MspkiGuiLogView -Scroll
        $g.LastFolder = [string]$result.OutputFolder
        $state = 'Done'
        if ($g.Summary.Health.Level -ne 'Green') { $state = 'Warn' }
        if ($cancelled) { Set-MspkiGuiState -Text 'Cancelled. Partial results are shown and were saved.' -State Warn }
        else { $ui.Progress.Value = 100; Set-MspkiGuiState -Text ('Finished: {0}' -f $g.Summary.Health.Title) -State $state }
        if (-not $g.CloseRequested) { $ui.Tabs.SelectedItem = $ui.TabSummary }
    }
    else {
        Clear-MspkiGuiResult
        Set-MspkiGuiState -Text 'The run ended without results. See the Run log page.' -State Bad
        $why = 'See the Run log page for the reason, then try again.'
        if ($problem) { $why = '{0} See the Run log page for details, then try again.' -f $problem }
        if ($cancelled) { $why = 'The run was cancelled before it produced results. Start it again when you are ready.' }
        $ui.TxtWelcomeError.Text = $why
        $ui.WelcomeError.Visibility = 'Visible'
        if ($problem -and -not $g.CloseRequested) { Show-MspkiGuiMessage -Text ('The run stopped with an error: {0}' -f $problem) -Icon 'Error' }
    }
    if ($g.CloseRequested) { $g.Window.Close() }
}

function Open-MspkiGuiPath {
    <#
    .SYNOPSIS
    Hands one existing file or folder to the Windows shell (the report in the browser, the folder in Explorer).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Path, [string]$What = 'item')
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        Show-MspkiGuiMessage -Text ('The {0} does not exist yet.' -f $What) -Icon 'Information'
        return
    }
    try { Invoke-Item -LiteralPath $Path -ErrorAction Stop }
    catch { Show-MspkiGuiMessage -Text ('Could not open the {0}: {1}' -f $What, $_.Exception.Message) -Icon 'Warning' }
}

function Show-MspkiGuiFinding {
    <#
    .SYNOPSIS
    Opens one finding in the Findings tab (clears the filters first so that the row is visible) and selects it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Id)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if (-not $g.RowById.ContainsKey($Id)) { return }
    $row = $g.RowById[$Id]
    $ui.Tabs.SelectedItem = $ui.TabFindings
    $visible = Test-MspkiGuiRowFilter -Row $row -Text $g.Filter.Text -Status $g.Filter.Status -Category $g.Filter.Category -Confidence $g.Filter.Confidence -Severity $g.Filter.Severity
    if (-not $visible) { Clear-MspkiGuiFilter }
    $ui.FindingsGrid.SelectedItem = $row
    $ui.FindingsGrid.ScrollIntoView($row)
    $ui.FindingsGrid.Focus() | Out-Null
}

function Show-MspkiGuiFilteredStatus {
    <#
    .SYNOPSIS
    From a Summary tile: opens the Findings tab filtered to one status or one severity.
    #>
    [CmdletBinding()]
    param([string]$Value)
    $g = $script:MspkiGui
    $ui = $g.Ui
    if (-not $Value -or $null -eq $g.View) { return }
    Clear-MspkiGuiFilter
    if ($script:MspkiGuiStatusOrder -contains $Value) {
        foreach ($c in $g.Chips) { if ([string]$c.Tag -eq $Value) { $c.IsChecked = $true } }
    }
    else {
        $idx = @($ui.FltSeverity.Items).IndexOf($Value)
        if ($idx -ge 0) { $ui.FltSeverity.SelectedIndex = $idx }
    }
    Update-MspkiGuiFilter
    $ui.Tabs.SelectedItem = $ui.TabFindings
}

function Get-MspkiGuiSelectedRowsText {
    <#
    .SYNOPSIS
    The selected rows of the Findings grid as tab-separated text (what "Copy selected rows" puts on the clipboard).
    #>
    [CmdletBinding()]
    param()
    $grid = $script:MspkiGui.Ui.FindingsGrid
    $lines = foreach ($r in @($grid.SelectedItems)) {
        (@($r.Id, $r.Status, $r.Severity, $r.Category, $r.Target, $r.Endpoint, $r.Confidence, $r.Message) | ForEach-Object { ([string]$_) -replace '[\t\r\n]+', ' ' }) -join "`t"
    }
    return ($lines -join "`r`n")
}

function Export-MspkiGuiFilteredView {
    <#
    .SYNOPSIS
    Writes the findings that match the current filters to a CSV file in the run's output folder (never anywhere else).
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    if ($null -eq $g.View -or $g.Rows.Count -eq 0) { Show-MspkiGuiMessage -Text 'There are no findings to export yet.' -Icon 'Information'; return }
    $items = @($g.View | ForEach-Object { $_.Finding })
    if ($items.Count -eq 0) { Show-MspkiGuiMessage -Text 'No finding matches the current filters, so there is nothing to export.' -Icon 'Information'; return }
    $folder = ''
    if ($null -ne $g.Data -and $g.Data.OutputFolder) { $folder = [string]$g.Data.OutputFolder }
    $rootFull = [System.IO.Path]::GetFullPath($g.OutputRoot).TrimEnd('\') + '\'
    if (-not $folder -or -not ([System.IO.Path]::GetFullPath($folder).TrimEnd('\') + '\').StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) { $folder = $g.OutputRoot }
    $path = Join-Path $folder ('findings-filtered-{0}.csv' -f [DateTime]::Now.ToString('yyyyMMdd-HHmmss'))
    try {
        $mod = Get-Module -Name MspkiHealthCheck
        & $mod {
            param($p, $f)
            $text = ConvertTo-MspkiCsvText -Findings $f
            [void](Use-MspkiOutputFolder -Path (Split-Path -Parent $p))
            Write-MspkiOutputFile -Path $p -Content $text -Bom
        } $path $items
        $g.LastExport = $path
        Set-MspkiGuiState -Text ('Exported {0} to {1}' -f (Format-MspkiGuiCount -Count $items.Count -Singular 'finding'), (Split-Path -Leaf $path)) -State Done
        Show-MspkiGuiMessage -Text ('Exported {0} to:{1}{2}' -f (Format-MspkiGuiCount -Count $items.Count -Singular 'finding'), [Environment]::NewLine, $path) -Title 'Export finished'
    }
    catch { Show-MspkiGuiMessage -Text ('The export failed: {0}' -f $_.Exception.Message) -Title 'Export' -Icon 'Warning' }
}

function Set-MspkiGuiTreeExpansion {
    <#
    .SYNOPSIS
    Expands or collapses every branch of the Discovery Map tree (the first level stays open when collapsing).
    #>
    [CmdletBinding()]
    param($Parent, [bool]$Expand, [int]$Depth = 0)
    foreach ($item in @($Parent.Items)) {
        $c = $Parent.ItemContainerGenerator.ContainerFromItem($item)
        if ($null -eq $c) { continue }
        if ($Expand) { $c.IsExpanded = $true } else { $c.IsExpanded = ($Depth -lt 1) }
        if ($c.IsExpanded) { $c.UpdateLayout() }
        Set-MspkiGuiTreeExpansion -Parent $c -Expand $Expand -Depth ($Depth + 1)
    }
}

function Invoke-MspkiGuiOpenDialog {
    <#
    .SYNOPSIS
    Asks for an earlier results.json and shows it (nothing is scanned).
    #>
    [CmdletBinding()]
    param()
    $dlg = New-Object Microsoft.Win32.OpenFileDialog
    $dlg.Title = 'Open an earlier results.json'
    $dlg.Filter = 'results.json|results.json|JSON files (*.json)|*.json'
    $root = $script:MspkiGui.OutputRoot
    if (Test-Path -LiteralPath $root -PathType Container) { $dlg.InitialDirectory = $root }
    if ($dlg.ShowDialog($script:MspkiGui.Window)) { Open-MspkiGuiResultsFile -Path $dlg.FileName }
}

function Select-MspkiGuiTab {
    [CmdletBinding()]
    param([int]$Index)
    $ui = $script:MspkiGui.Ui
    $tabs = @($ui.TabSummary, $ui.TabFindings, $ui.TabMap, $ui.TabLog, $ui.TabObjects, $ui.TabServices)
    if ($Index -ge 0 -and $Index -lt $tabs.Count) { $ui.Tabs.SelectedItem = $tabs[$Index] }
}

function Initialize-MspkiGuiApplication {
    <#
    .SYNOPSIS
    Builds the window, wires every control and returns the window (not yet shown). The caller shows it with ShowDialog().
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ModulePath,
        [Parameter(Mandatory = $true)][string]$XamlPath,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [string]$OpenResults = ''
    )
    $w = New-MspkiGuiWindow -XamlPath $XamlPath
    $script:MspkiGui = @{
        Window = $w.Window; Ui = $w.Ui; ModulePath = $ModulePath; OutputRoot = $OutputPath
        Run = $null; Timer = $null; Data = $null; Summary = $null; Rows = (New-Object 'System.Collections.Generic.List[object]'); View = $null; RowById = @{}
        Chips = @(); MapPane = $null; LastExport = ''
        Index = $null; ObjRows = @(); ObjView = $null; ObjFilter = @{ Text = ''; Type = ''; Attention = $false }; Nav = @{}
        Filter = @{ Text = ''; Status = @(); Category = ''; Confidence = ''; Severity = ''; Area = $null }
        Score = $null; Actions = $null; MapModel = $null; MapDrawn = $null; MapDrawnWidth = 0; MapAnimatePending = $false; MapTotalMs = 0
        Storyboard = $null; AreaFills = $null; ForceMotion = $false
        LogFilter = @{ Text = ''; Level = '' }
        LogRows = (New-Object 'System.Collections.ObjectModel.ObservableCollection[object]'); LogView = $null
        FinishedStages = (New-Object 'System.Collections.Generic.List[string]')
        CurrentStage = ''; CloseRequested = $false; LastFolder = ''
    }
    $g = $script:MspkiGui
    $ui = $g.Ui
    Register-MspkiGuiCrashGuard -Window $g.Window

    # Run Log list with its filter
    $ui.LogList.ItemsSource = $g.LogRows
    $g.LogView = [System.Windows.Data.CollectionViewSource]::GetDefaultView($g.LogRows)
    $g.LogView.Filter = [System.Predicate[object]]{
        param($row)
        $f = $script:MspkiGui.LogFilter
        if ($f.Text -and $row.Search.IndexOf($f.Text, [System.StringComparison]::Ordinal) -lt 0) { return $false }
        if ($f.Level -eq 'Warnings and errors' -and $row.Level -notin @('Warning', 'Error')) { return $false }
        if ($f.Level -eq 'Errors only' -and $row.Level -ne 'Error') { return $false }
        return $true
    }
    $ui.FltLogLevel.ItemsSource = @('All levels', 'Warnings and errors', 'Errors only')
    $ui.FltLogLevel.SelectedIndex = 0

    $m = Get-Module -Name MspkiHealthCheck
    if ($null -ne $m) { $ui.HdrVersion.Text = 'v{0}' -f $m.Version }
    $ui.TxtOutput.Text = $OutputPath
    $ui.TxtElapsed.Text = ''
    Clear-MspkiGuiResult
    Update-MspkiGuiLogView
    Update-MspkiGuiOptionsSummary
    Set-MspkiGuiState -Text 'Ready. Press Run to start a health check, or open an earlier results.json.' -State Ready

    $g.Timer = New-Object System.Windows.Threading.DispatcherTimer
    $g.Timer.Interval = [TimeSpan]::FromMilliseconds(200)
    # An exception in a tick stops a DispatcherTimer for good, so the tick catches its own errors (audit 2 M6).
    $g.Timer.Add_Tick({ try { Receive-MspkiGuiProgress } catch { [void](Invoke-MspkiGuiUnhandledError -Exception $_.Exception -Source 'timer') } })

    # Title bar caption buttons (in-box SystemCommands; the title bar itself is the WindowChrome caption area)
    $ui.BtnMin.Add_Click({ [System.Windows.SystemCommands]::MinimizeWindow($script:MspkiGui.Window) })
    $ui.BtnMax.Add_Click({
        $w = $script:MspkiGui.Window
        if ($w.WindowState -eq [System.Windows.WindowState]::Maximized) { [System.Windows.SystemCommands]::RestoreWindow($w) } else { [System.Windows.SystemCommands]::MaximizeWindow($w) }
    })
    $ui.BtnClose.Add_Click({ $script:MspkiGui.Window.Close() })
    $g.Window.Add_SizeChanged({ Update-MspkiGuiNavMode })

    # Running panel on the Overview
    $ui.BtnRunningLog.Add_Click({ Select-MspkiGuiTab -Index 3 })
    $ui.BtnRunningCancel.Add_Click({ Request-MspkiGuiCancel })

    # Toolbar and welcome buttons

    $ui.BtnRun.Add_Click({ Start-MspkiGuiRun })
    $ui.BtnWelcomeRun.Add_Click({ Start-MspkiGuiRun })
    $ui.BtnCancel.Add_Click({ Request-MspkiGuiCancel })
    $ui.BtnOpenResults.Add_Click({ Invoke-MspkiGuiOpenDialog })
    $ui.BtnWelcomeOpen.Add_Click({ Invoke-MspkiGuiOpenDialog })
    $ui.BtnOpenReport.Add_Click({
        $d = $script:MspkiGui.Data
        if ($null -ne $d) { Open-MspkiGuiPath -Path ([string]$d.ReportPath) -What 'HTML report' }
    })
    $ui.BtnOpenFolder.Add_Click({
        $s = $script:MspkiGui
        $p = $s.OutputRoot
        if ($null -ne $s.Data -and $s.Data.OutputFolder) { $p = [string]$s.Data.OutputFolder }
        elseif ($s.LastFolder) { $p = $s.LastFolder }
        Open-MspkiGuiPath -Path $p -What 'output folder'
    })

    # Options summary
    $ui.TxtTimeout.Add_TextChanged({ Update-MspkiGuiOptionsSummary })
    foreach ($n in @('ChkSkipNetwork', 'ChkProxy', 'ChkNdesAdmin')) { $ui[$n].Add_Click({ Update-MspkiGuiOptionsSummary }) }

    # Findings: filters, grouping, selection, copy, export
    $ui.FltText.Add_TextChanged({ Update-MspkiGuiFilter })
    foreach ($n in @('FltSeverity', 'FltCategory', 'FltConfidence')) { $ui[$n].Add_SelectionChanged({ Update-MspkiGuiFilter }) }
    $ui.BtnClearFilters.Add_Click({ Clear-MspkiGuiFilter })
    $ui.BtnExport.Add_Click({ Export-MspkiGuiFilteredView })
    $groupOn = {
        $s = $script:MspkiGui
        if ($null -eq $s.View) { return }
        $s.View.GroupDescriptions.Clear()
        if ([bool]$s.Ui.ChkGroup.IsChecked) { $s.View.GroupDescriptions.Add((New-Object System.Windows.Data.PropertyGroupDescription('Category'))) }
    }
    $ui.ChkGroup.Add_Click($groupOn)
    $ui.FindingsGrid.Add_SelectionChanged({
        $row = $script:MspkiGui.Ui.FindingsGrid.SelectedItem
        if ($null -ne $row) { Show-MspkiGuiFindingPane -Finding $row.Finding } else { Show-MspkiGuiFindingPane -Finding $null }
    })
    $ui.FindingsGrid.Add_PreviewKeyDown({
        param($sender, $e)
        if ($e.Key -eq 'C' -and ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
            $t = Get-MspkiGuiSelectedRowsText
            if ($t) { [void](Set-MspkiGuiClipboard -Text $t) }
            $e.Handled = $true
        }
    })
    $ui.MenuCopyRows.Add_Click({ $t = Get-MspkiGuiSelectedRowsText; if ($t) { [void](Set-MspkiGuiClipboard -Text $t) } })
    $ui.MenuCopyMessage.Add_Click({ $r = $script:MspkiGui.Ui.FindingsGrid.SelectedItem; if ($null -ne $r) { [void](Set-MspkiGuiClipboard -Text ([string]$r.Finding.Message)) } })
    $ui.MenuCopyTarget.Add_Click({ $r = $script:MspkiGui.Ui.FindingsGrid.SelectedItem; if ($null -ne $r) { [void](Set-MspkiGuiClipboard -Text ([string]$r.Finding.Target)) } })
    $ui.MenuCopyDetails.Add_Click({ $r = $script:MspkiGui.Ui.FindingsGrid.SelectedItem; if ($null -ne $r) { [void](Set-MspkiGuiClipboard -Text (Get-MspkiGuiFindingDetail -Finding $r.Finding).CopyText) } })
    # A right-click selects the row under the pointer first, so that "Copy" acts on what the user pointed at.
    $ui.FindingsGrid.Add_PreviewMouseRightButtonDown({
        param($sender, $e)
        $d = $e.OriginalSource -as [System.Windows.DependencyObject]
        while ($null -ne $d -and $d -isnot [System.Windows.Controls.DataGridRow]) { $d = [System.Windows.Media.VisualTreeHelper]::GetParent($d) }
        if ($null -ne $d -and -not $d.IsSelected) { $sender.SelectedItems.Clear(); $d.IsSelected = $true }
    })

    # Summary: tiles and top issues are buttons; one handler per list
    $btnClick = [System.Windows.Controls.Primitives.ButtonBase]::ClickEvent
    $tagOf = {
        param($e)
        $b = $e.OriginalSource -as [System.Windows.Controls.Button]
        if ($null -eq $b) { $b = $e.Source -as [System.Windows.Controls.Button] }
        if ($null -eq $b) { return '' }
        return [string]$b.Tag
    }
    $tileHandler = [System.Windows.RoutedEventHandler]{ param($s, $e) $t = (& $script:MspkiGuiTagOf $e); if ($t) { Show-MspkiGuiFilteredStatus -Value $t } }
    $script:MspkiGuiTagOf = $tagOf
    $ui.TileList.AddHandler($btnClick, $tileHandler)
    $ui.SevTileList.AddHandler($btnClick, $tileHandler)

    # Overview: KPI tiles open the Objects page for their type, CA cards open the CA object
    $ui.KpiList.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) $t = (& $script:MspkiGuiTagOf $e); if ($t -and $t.StartsWith('type:')) { Show-MspkiGuiObjectsOfType -Type $t.Substring(5) } })
    $ui.CaList.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) $t = (& $script:MspkiGuiTagOf $e); if ($t -and $t.StartsWith('ent:')) { Show-MspkiGuiObject -Id $t.Substring(4) } })
    # Mission control: actions open their finding (causes and checks), area bars filter the Findings page, the map redraws on resize.
    $ui.ActionList.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) $t = (& $script:MspkiGuiTagOf $e); if ($t) { Show-MspkiGuiFinding -Id $t } })
    $ui.AreaPanel.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Show-MspkiGuiArea -Tag (& $script:MspkiGuiTagOf $e) })
    $ui.BtnAllActions.Add_Click({ Switch-MspkiGuiActionList })
    $ui.BtnScoreRing.Add_Click({ Show-MspkiGuiAllActions })
    $ui.BtnScoreHow.Add_Click({ $sc = $script:MspkiGui.Score; if ($null -ne $sc) { $script:MspkiGui.Ui.TxtScoreHow.Text = $sc.HowText; $script:MspkiGui.Ui.PopScore.IsOpen = $true } })
    $ui.BtnReplay.Add_Click({ Start-MspkiGuiMissionAnimation })
    $ui.MapCanvasHost.Add_SizeChanged({ try { Invoke-MspkiGuiMapDraw } catch { [void](Invoke-MspkiGuiUnhandledError -Exception $_.Exception -Source 'map') } })

    # Details panes (Findings, Discovery map, Objects): Copy, Back, related objects, breadcrumbs, findings. One handler each.
    $ui.FindingHost.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Invoke-MspkiGuiPaneCommand -HostName 'FindingHost' -Tag (& $script:MspkiGuiTagOf $e) })
    $ui.MapHost.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Invoke-MspkiGuiPaneCommand -HostName 'MapHost' -Tag (& $script:MspkiGuiTagOf $e) })
    $ui.ObjHost.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Invoke-MspkiGuiPaneCommand -HostName 'ObjHost' -Tag (& $script:MspkiGuiTagOf $e) })
    $ui.SvcHost.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Invoke-MspkiGuiPaneCommand -HostName 'SvcHost' -Tag (& $script:MspkiGuiTagOf $e) })
    # PKI services page: a service opens its object, a finding opens the finding (both in the pane on the right)
    $ui.SvcList.AddHandler($btnClick, [System.Windows.RoutedEventHandler]{ param($s, $e) Open-MspkiGuiServiceItem -Tag (& $script:MspkiGuiTagOf $e) })

    # Discovery Map: selection, expand/collapse
    $ui.MapTree.Add_SelectedItemChanged({ Show-MspkiGuiNodePane -Node $script:MspkiGui.Ui.MapTree.SelectedItem })

    # Objects page: search, type filter, needs-attention switch, selection
    $ui.FltObj.Add_TextChanged({ Update-MspkiGuiObjectFilter })
    $ui.FltObjType.Add_SelectionChanged({ Update-MspkiGuiObjectFilter })
    $ui.ChkObjAttention.Add_Click({ Update-MspkiGuiObjectFilter })
    $ui.BtnObjClear.Add_Click({ Clear-MspkiGuiObjectFilter })
    $ui.ObjList.Add_SelectionChanged({
        $s = $script:MspkiGui
        $row = $s.Ui.ObjList.SelectedItem
        if ($null -eq $row) { return }
        Reset-MspkiGuiPaneNav -HostName 'ObjHost'
        $s.Nav.ObjHost.Trail = [string[]]@([string]$row.Id)
        Show-MspkiGuiEntityPane -HostName 'ObjHost'
    })
    $ui.BtnExpandAll.Add_Click({ $t = $script:MspkiGui.Ui.MapTree; Set-MspkiGuiTreeExpansion -Parent $t -Expand $true })
    $ui.BtnCollapseAll.Add_Click({ $t = $script:MspkiGui.Ui.MapTree; Set-MspkiGuiTreeExpansion -Parent $t -Expand $false })

    # Run Log (opening the tab scrolls to the newest line when auto-scroll is on)
    $ui.Tabs.Add_SelectionChanged({
        param($sender, $e)
        if ($e.OriginalSource -ne $sender) { return }
        $u = $script:MspkiGui.Ui
        if ($u.Tabs.SelectedItem -eq $u.TabLog) {
            [void]$u.LogList.Dispatcher.BeginInvoke([System.Windows.Threading.DispatcherPriority]::Background, [System.Action]{ Update-MspkiGuiLogView -Scroll })
        }
    })
    $ui.FltLog.Add_TextChanged({ Update-MspkiGuiLogView })
    $ui.FltLogLevel.Add_SelectionChanged({ Update-MspkiGuiLogView })
    $ui.ChkFollow.Add_Click({ if ([bool]$script:MspkiGui.Ui.ChkFollow.IsChecked) { Update-MspkiGuiLogView -Scroll } })
    $ui.BtnCopyLog.Add_Click({
        $lines = @($script:MspkiGui.Ui.LogList.Items | ForEach-Object { $_.Text })
        if ($lines.Count -gt 0) { [void](Set-MspkiGuiClipboard -Text ($lines -join "`r`n")) }
    })

    # Keyboard: F5 run, Esc clear the focused filter or cancel, Ctrl+1..4 tabs, Ctrl+F search, Ctrl+O open
    $g.Window.Add_PreviewKeyDown({
        param($sender, $e)
        $s = $script:MspkiGui
        $u = $s.Ui
        $ctrl = ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) -ne 0
        if ($e.Key -eq 'F5' -and $u.BtnRun.IsEnabled) { Start-MspkiGuiRun; $e.Handled = $true; return }
        if ($e.Key -eq 'Escape') {
            $f = [System.Windows.Input.Keyboard]::FocusedElement
            if (($f -eq $u.FltText -and $u.FltText.Text) -or ($f -eq $u.FltLog -and $u.FltLog.Text) -or ($f -eq $u.FltObj -and $u.FltObj.Text)) { $f.Text = ''; $e.Handled = $true; return }
            if ($null -ne $s.Run) { Request-MspkiGuiCancel; $e.Handled = $true }
            return
        }
        if ($ctrl) {
            switch ($e.Key) {
                'D1' { Select-MspkiGuiTab -Index 0; $e.Handled = $true }
                'D2' { Select-MspkiGuiTab -Index 1; $e.Handled = $true }
                'D3' { Select-MspkiGuiTab -Index 2; $e.Handled = $true }
                'D4' { Select-MspkiGuiTab -Index 3; $e.Handled = $true }
                'D5' { Select-MspkiGuiTab -Index 4; $e.Handled = $true }
                'D6' { Select-MspkiGuiTab -Index 5; $e.Handled = $true }
                'O' { if ($u.BtnOpenResults.IsEnabled) { Invoke-MspkiGuiOpenDialog }; $e.Handled = $true }
                'F' {
                    if ($u.Tabs.SelectedItem -eq $u.TabFindings) { [void]$u.FltText.Focus(); $e.Handled = $true }
                    elseif ($u.Tabs.SelectedItem -eq $u.TabLog) { [void]$u.FltLog.Focus(); $e.Handled = $true }
                    elseif ($u.Tabs.SelectedItem -eq $u.TabObjects) { [void]$u.FltObj.Focus(); $e.Handled = $true }
                }
            }
        }
    })

    $g.Window.Add_Closing({
        param($sender, $e)
        $s = $script:MspkiGui
        if ($null -eq $s.Run) { return }
        if ($s.CloseRequested) {
            # Second attempt while waiting: stop the engine now and let the window close.
            Stop-MspkiGuiRunspace -Run $s.Run
            $s.Run = $null
            $s.Timer.Stop()
            return
        }
        $e.Cancel = $true
        $s.CloseRequested = $true
        Request-MspkiGuiCancel
        Set-MspkiGuiState -Text 'Cancelling the run before closing... the window closes by itself in a few seconds.' -State Warn
    })
    $g.Window.Add_Closed({
        $s = $script:MspkiGui
        if ($null -ne $s.Timer) { $s.Timer.Stop() }
    })

    if ($OpenResults) { Open-MspkiGuiResultsFile -Path $OpenResults }
    return $g.Window
}
