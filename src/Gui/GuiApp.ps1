# GUI application: loads the window, runs the engine in a background runspace and shows the results.
# The window only displays and filters. Every check stays in the engine (src\Model, Probes, Discovery, Analyzers).
# State lives in $script:MspkiGui because event handlers run after the function that wired them has returned.

$script:MspkiGui = $null

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
    Loads the window from its XAML file and returns the window and a table of its named controls.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$XamlPath)
    $xaml = [System.IO.File]::ReadAllText($XamlPath, [System.Text.Encoding]::UTF8)
    $sr = New-Object System.IO.StringReader($xaml)
    $xr = [System.Xml.XmlReader]::Create($sr)
    $window = $null
    try { $window = [System.Windows.Markup.XamlReader]::Load($xr) }
    finally { $xr.Close(); $sr.Close() }
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

function Set-MspkiGuiBusy {
    <#
    .SYNOPSIS
    Enables and disables the buttons and options for a running or idle window.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][bool]$Busy)
    $ui = $script:MspkiGui.Ui
    $ui.BtnRun.IsEnabled = -not $Busy
    $ui.BtnCancel.IsEnabled = $Busy
    $ui.BtnOpenResults.IsEnabled = -not $Busy
    foreach ($n in @('TxtTimeout', 'ChkSkipNetwork', 'ChkProxy', 'ChkNdesAdmin')) { $ui[$n].IsEnabled = -not $Busy }
}

function Add-MspkiGuiLogRow {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Row)
    $log = $script:MspkiGui.LogRows
    $log.Add($Row)
    if ($log.Count -gt 40000) { for ($i = 0; $i -lt 5000; $i++) { $log.RemoveAt(0) } }
}

function Update-MspkiGuiFilter {
    <#
    .SYNOPSIS
    Reads the filter boxes, refreshes the Findings grid and shows how many findings match.
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    if ($null -eq $g.View) { return }
    $ui = $g.Ui
    $g.Filter.Text = [string]$ui.FltText.Text
    $g.Filter.Status = [string]$ui.FltStatus.SelectedItem
    $g.Filter.Category = [string]$ui.FltCategory.SelectedItem
    $g.Filter.Confidence = [string]$ui.FltConfidence.SelectedItem
    $g.View.Refresh()
    $ui.TxtShowing.Text = 'Showing {0} of {1}' -f $g.View.Count, $g.Rows.Count
}

function Show-MspkiGuiDetail {
    <#
    .SYNOPSIS
    Fills the Details tab with every field of one finding (null clears it).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Finding)
    $ui = $script:MspkiGui.Ui
    if ($null -eq $Finding) {
        $ui.DetPanel.Visibility = 'Collapsed'; $ui.DetNone.Visibility = 'Visible'
        return
    }
    $ui.DetPanel.DataContext = (Get-MspkiGuiFindingDetail -Finding $Finding)
    $ui.DetNone.Visibility = 'Collapsed'; $ui.DetPanel.Visibility = 'Visible'
}

function Clear-MspkiGuiResult {
    <#
    .SYNOPSIS
    Empties every results view (used when a new run starts and before results are loaded).
    #>
    [CmdletBinding()]
    param()
    $g = $script:MspkiGui
    $ui = $g.Ui
    $g.Data = $null; $g.Rows = (New-Object 'System.Collections.Generic.List[object]'); $g.View = $null; $g.RowById = @{}
    $ui.FindingsGrid.ItemsSource = $null
    $ui.MapTree.ItemsSource = $null
    $ui.MapFindings.ItemsSource = $null
    $ui.MapDetail.Text = 'Select an item in the tree.'
    $ui.TileList.ItemsSource = $null
    $ui.CaGrid.ItemsSource = $null
    $ui.SumNoCa.Visibility = 'Collapsed'
    foreach ($n in @('SumForest', 'SumDomain', 'SumDc', 'SumUser', 'SumAdmin', 'SumState', 'SumExit')) { $ui[$n].Text = '' }
    $ui.SumTotal.Text = 'Findings by status'
    $ui.TxtBanner.Visibility = 'Collapsed'; $ui.TxtBanner.Text = ''
    $ui.TxtShowing.Text = ''
    foreach ($n in @('FltStatus', 'FltCategory', 'FltConfidence')) { $ui[$n].ItemsSource = @('(all)'); $ui[$n].SelectedIndex = 0 }
    $ui.FltText.Text = ''
    $g.Filter.Text = ''; $g.Filter.Status = ''; $g.Filter.Category = ''; $g.Filter.Confidence = ''
    Show-MspkiGuiDetail -Finding $null
    $ui.BtnOpenReport.IsEnabled = $false
}

function Show-MspkiGuiResult {
    <#
    .SYNOPSIS
    Shows a run (live or loaded from results.json) in the Summary, Discovery Map, Findings and Details tabs.
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

    # Summary
    $s = Get-MspkiGuiSummary -RunInfo $Data.RunInfo -Inventory $Data.Inventory -Findings $findings -ExitCode $Data.ExitCode
    $ui.SumForest.Text = $s.Forest; $ui.SumDomain.Text = $s.Domain; $ui.SumDc.Text = $s.DomainController
    $ui.SumUser.Text = $s.User; $ui.SumAdmin.Text = $s.IsAdmin; $ui.SumState.Text = $s.RunState; $ui.SumExit.Text = $s.ExitCode
    $ui.SumTotal.Text = 'Findings by status ({0} in total)' -f $s.Total
    $ui.TileList.ItemsSource = @($s.Tiles)
    $ui.CaGrid.ItemsSource = @($s.CAs)
    if (@($s.CAs).Count -eq 0) { $ui.SumNoCa.Visibility = 'Visible' }

    # Findings grid with filters and sorting
    $g.Rows = (ConvertTo-MspkiGuiRowList -Findings $findings)
    $g.RowById = @{}
    foreach ($r in $g.Rows) { $g.RowById[$r.Id] = $r }
    $ui.FindingsGrid.ItemsSource = $g.Rows
    $g.View = [System.Windows.Data.CollectionViewSource]::GetDefaultView($g.Rows)
    $g.View.Filter = [System.Predicate[object]]{
        param($row)
        $f = $script:MspkiGui.Filter
        return (Test-MspkiGuiRowFilter -Row $row -Text $f.Text -Status $f.Status -Category $f.Category -Confidence $f.Confidence)
    }
    $ui.FltStatus.ItemsSource = @(Get-MspkiGuiFilterChoice -Rows $g.Rows -Field Status)
    $ui.FltCategory.ItemsSource = @(Get-MspkiGuiFilterChoice -Rows $g.Rows -Field Category)
    $ui.FltConfidence.ItemsSource = @(Get-MspkiGuiFilterChoice -Rows $g.Rows -Field Confidence)
    foreach ($n in @('FltStatus', 'FltCategory', 'FltConfidence')) { $ui[$n].SelectedIndex = 0 }
    $ui.TxtShowing.Text = 'Showing {0} of {1}' -f $g.Rows.Count, $g.Rows.Count

    # Discovery Map
    $tree = Get-MspkiDiscoveryTree -Inventory $Data.Inventory -Findings $findings -RunInfo $Data.RunInfo
    $ui.MapTree.ItemsSource = @(ConvertTo-MspkiGuiTreeNode -Node $tree)

    # Buttons and banner
    $ui.BtnOpenReport.IsEnabled = [bool]($Data.ReportPath)
    $notes = New-Object 'System.Collections.Generic.List[string]'
    if ($Banner) { $notes.Add($Banner) }
    if ($null -ne $Data.RunInfo -and $null -ne $Data.RunInfo.Completed -and -not [bool]$Data.RunInfo.Completed) {
        $notes.Add('This run did not finish (it was cancelled or stopped by an error), so the results are partial.')
    }
    if ($notes.Count -gt 0) { $ui.TxtBanner.Text = ($notes -join ' '); $ui.TxtBanner.Visibility = 'Visible' }
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
        Add-MspkiGuiLogRow -Row ([pscustomobject]@{ Text = '(no run.log was found next to this results.json)'; Level = 'Info' })
        return
    }
    foreach ($line in [System.IO.File]::ReadLines($Path)) { Add-MspkiGuiLogRow -Row (ConvertTo-MspkiGuiLogRowFromLine -Line $line) }
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
        Show-MspkiGuiResult -Data $data -Banner ('Showing an earlier run loaded from {0}. Nothing was scanned.' -f $data.ResultsPath)
        Show-MspkiGuiLogFile -Path $data.LogPath
        $g.Ui.TxtStage.Text = 'Loaded {0} finding(s) from {1}' -f @($data.Findings).Count, $data.ResultsPath
        $g.Ui.Progress.Value = 0
        $g.Ui.TxtTarget.Text = ''
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
    $g.Ui.TxtStage.Text = 'Cancelling... waiting for the current step to finish (a few seconds at most).'
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
    $g.FinishedStages = New-Object 'System.Collections.Generic.List[string]'
    $ui.Progress.IsIndeterminate = $false
    $ui.Progress.Value = 0
    $ui.TxtStage.Text = 'Starting...'
    $ui.TxtTarget.Text = ''
    $ui.TxtBanner.Text = 'A run is in progress. Findings appear here when it finishes; the Run Log tab shows the run live.'
    $ui.TxtBanner.Visibility = 'Visible'
    $ui.Tabs.SelectedItem = $ui.TabLog
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
                if ($item.Text -ne 'Discovery') { $ui.TxtStage.Text = 'Stage: {0}' -f (Get-MspkiGuiStageLabel -Stage ([string]$item.Text)) }
            }
            'StageEnd' {
                if (-not $g.FinishedStages.Contains([string]$item.Text)) { $g.FinishedStages.Add([string]$item.Text) }
                $ui.Progress.Value = Get-MspkiGuiProgressPercent -FinishedStages $g.FinishedStages.ToArray()
            }
            'Target' { $ui.TxtTarget.Text = [string]$item.Text }
            'Log' { Add-MspkiGuiLogRow -Row (ConvertTo-MspkiGuiLogRow -Message $item); $added = $true }
        }
    }
    if ($added) {
        $ui.TxtLogCount.Text = '{0} line(s)' -f $g.LogRows.Count
        if ([bool]$ui.ChkFollow.IsChecked -and $g.LogRows.Count -gt 0) { $ui.LogList.ScrollIntoView($g.LogRows[$g.LogRows.Count - 1]) }
    }
    $el = [DateTime]::Now - $run.Started
    $ui.TxtElapsed.Text = 'Elapsed {0:00}:{1:00}' -f [int][math]::Floor($el.TotalMinutes), $el.Seconds

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
    $result = $null
    $problem = ''
    try {
        $out = @($run.PowerShell.EndInvoke($run.Handle))
        if ($out.Count -gt 0) { $result = $out[$out.Count - 1] }
    }
    catch { $problem = $_.Exception.Message }
    foreach ($e in @($run.PowerShell.Streams.Error)) {
        Add-MspkiGuiLogRow -Row ([pscustomobject]@{ Text = ('ERROR {0}' -f $e.ToString()); Level = 'Error' })
        if (-not $problem) { $problem = $e.ToString() }
    }
    $cancelled = ($null -ne $run.CancelRequested)
    try { $run.PowerShell.Dispose(); $run.Runspace.Dispose() } catch { }
    $g.Run = $null
    $g.CurrentStage = ''
    Set-MspkiGuiBusy -Busy $false
    $ui.TxtTarget.Text = ''
    if ($null -ne $result -and $null -ne $result.Findings) {
        $log = ''
        if ($result.OutputFolder) { $log = Join-Path $result.OutputFolder 'run.log' }
        $data = [pscustomobject][ordered]@{
            RunInfo = $result.RunInfo; Inventory = $result.Inventory; Findings = @($result.Findings); ExitCode = $result.ExitCode
            OutputFolder = [string]$result.OutputFolder; ResultsPath = [string]$result.ResultsPath; ReportPath = [string]$result.ReportPath; LogPath = $log
        }
        Show-MspkiGuiResult -Data $data
        $g.LastFolder = [string]$result.OutputFolder
        if ($cancelled) { $ui.TxtStage.Text = 'Cancelled. Partial results are shown and were saved to {0}' -f $result.OutputFolder }
        else { $ui.Progress.Value = 100; $ui.TxtStage.Text = 'Finished. Results were saved to {0}' -f $result.OutputFolder }
        if (-not $g.CloseRequested) { $ui.Tabs.SelectedItem = $ui.TabSummary }
    }
    else {
        $ui.TxtBanner.Text = 'The run ended without results. See the Run Log tab.'
        $ui.TxtBanner.Visibility = 'Visible'
        $ui.TxtStage.Text = 'The run ended without results.'
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
        Run = $null; Timer = $null; Data = $null; Rows = (New-Object 'System.Collections.Generic.List[object]'); View = $null; RowById = @{}
        Filter = @{ Text = ''; Status = ''; Category = ''; Confidence = '' }
        LogRows = (New-Object 'System.Collections.ObjectModel.ObservableCollection[object]')
        FinishedStages = (New-Object 'System.Collections.Generic.List[string]')
        CurrentStage = ''; CloseRequested = $false; LastFolder = ''
    }
    $g = $script:MspkiGui
    $ui = $g.Ui
    $ui.LogList.ItemsSource = $g.LogRows
    $ui.TxtOutput.Text = 'Output folder: {0}' -f $OutputPath
    $ui.TxtElapsed.Text = ''
    Clear-MspkiGuiResult

    $g.Timer = New-Object System.Windows.Threading.DispatcherTimer
    $g.Timer.Interval = [TimeSpan]::FromMilliseconds(200)
    $g.Timer.Add_Tick({ Receive-MspkiGuiProgress })

    $ui.BtnRun.Add_Click({ Start-MspkiGuiRun })
    $ui.BtnCancel.Add_Click({ Request-MspkiGuiCancel })
    $ui.BtnOpenResults.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Title = 'Open an earlier results.json'
        $dlg.Filter = 'results.json|results.json|JSON files (*.json)|*.json'
        $root = $script:MspkiGui.OutputRoot
        if (Test-Path -LiteralPath $root -PathType Container) { $dlg.InitialDirectory = $root }
        if ($dlg.ShowDialog($script:MspkiGui.Window)) { Open-MspkiGuiResultsFile -Path $dlg.FileName }
    })
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

    $ui.FltText.Add_TextChanged({ Update-MspkiGuiFilter })
    foreach ($n in @('FltStatus', 'FltCategory', 'FltConfidence')) { $ui[$n].Add_SelectionChanged({ Update-MspkiGuiFilter }) }
    $ui.BtnClearFilters.Add_Click({
        $u = $script:MspkiGui.Ui
        $u.FltText.Text = ''
        foreach ($n in @('FltStatus', 'FltCategory', 'FltConfidence')) { $u[$n].SelectedIndex = 0 }
        Update-MspkiGuiFilter
    })
    $ui.FindingsGrid.Add_SelectionChanged({
        $row = $script:MspkiGui.Ui.FindingsGrid.SelectedItem
        if ($null -ne $row) { Show-MspkiGuiDetail -Finding $row.Finding }
    })
    $ui.FindingsGrid.Add_MouseDoubleClick({
        $u = $script:MspkiGui.Ui
        if ($null -ne $u.FindingsGrid.SelectedItem) { $u.Tabs.SelectedItem = $u.TabDetails }
    })
    $ui.MapTree.Add_SelectedItemChanged({
        $s = $script:MspkiGui
        $node = $s.Ui.MapTree.SelectedItem
        $s.Ui.MapDetail.Text = Get-MspkiGuiNodeSummary -Node $node
        $rows = @()
        if ($null -ne $node) { $rows = @($node.FindingIds | Where-Object { $_ -and $s.RowById.ContainsKey($_) } | ForEach-Object { $s.RowById[$_] }) }
        $s.Ui.MapFindings.ItemsSource = $rows
    })
    $ui.MapFindings.Add_MouseDoubleClick({
        $u = $script:MspkiGui.Ui
        $row = $u.MapFindings.SelectedItem
        if ($null -ne $row) { Show-MspkiGuiDetail -Finding $row.Finding; $u.Tabs.SelectedItem = $u.TabDetails }
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
        $s.Ui.TxtStage.Text = 'Cancelling the run before closing... the window closes by itself in a few seconds.'
    })
    $g.Window.Add_Closed({
        $s = $script:MspkiGui
        if ($null -ne $s.Timer) { $s.Timer.Stop() }
    })

    if ($OpenResults) { Open-MspkiGuiResultsFile -Path $OpenResults }
    return $g.Window
}
