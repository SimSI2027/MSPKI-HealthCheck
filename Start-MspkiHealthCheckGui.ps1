<#
.SYNOPSIS
MSPKI Health Check: Windows GUI. Runs the same read-only health check as Invoke-MspkiHealthCheck.ps1 and shows the results.

.DESCRIPTION
Start it from a Windows PowerShell 5.1 window. WPF needs a single-threaded apartment (STA); powershell.exe is STA by default, and
if a session is not, the script says so and stops (it never relaunches itself). To be explicit:

    powershell.exe -STA -File .\Start-MspkiHealthCheckGui.ps1

The check runs in a background runspace, so the window never freezes. Run starts a check, Cancel stops it at the next step
(partial results are still saved), and "Open results.json" shows an earlier run without scanning anything. The window only
displays and filters; every check stays in the engine, and the output files are the same as the command-line run.

.PARAMETER OutputPath
Root folder for run output. Default: the out folder next to this script.

.PARAMETER OpenResults
Path of an earlier results.json to show when the window opens (no scan is started).

.PARAMETER Snapshot
Developer switch. A folder under out\ (anything else is refused). The window is shown off-screen, each tab is rendered to a PNG
with RenderTargetBitmap (never a screen capture), and the script exits. Snapshots can contain real names, so they stay under out\.

.PARAMETER ResultsFile
With -Snapshot: the results.json to load before the tabs are rendered. Without it, only the welcome state and the empty tabs are rendered.

.PARAMETER SnapshotWidth
With -Snapshot: window width in pixels (default 1360).

.PARAMETER SnapshotHeight
With -Snapshot: window height in pixels (default 860).

.PARAMETER SnapshotMaximized
With -Snapshot: render the window maximised on the primary screen (it is visible there for a few seconds) instead of off-screen.

.PARAMETER SnapshotScale
With -Snapshot: output scale (default 1; 2 renders at 192 DPI to check how it looks on a high-DPI screen).

.EXAMPLE
powershell.exe -STA -File .\Start-MspkiHealthCheckGui.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$OpenResults = '',
    [string]$Snapshot = '',
    [string]$ResultsFile = '',
    [ValidateRange(900, 4000)][int]$SnapshotWidth = 1360,
    [ValidateRange(560, 3000)][int]$SnapshotHeight = 860,
    [ValidateRange(1, 4)][double]$SnapshotScale = 1,
    [switch]$SnapshotMaximized
)

if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot 'out' }

if ($PSVersionTable.PSEdition -ne 'Desktop') {
    Write-Host 'The MSPKI Health Check window needs Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.'
    exit 5
}
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
    Write-Host 'The MSPKI Health Check window needs a single-threaded PowerShell session (STA).'
    Write-Host 'Close this window and start it like this, from a normal Windows PowerShell prompt:'
    Write-Host ''
    Write-Host '    powershell.exe -STA -File .\Start-MspkiHealthCheckGui.ps1'
    Write-Host ''
    Write-Host '(The PowerShell ISE is already single-threaded, so you can also run the script from there.)'
    exit 5
}

$modulePath = Join-Path $PSScriptRoot 'src\MspkiHealthCheck.psd1'
$guiFolder = Join-Path $PSScriptRoot 'src\Gui'
try {
    Import-Module $modulePath -Force -ErrorAction Stop
    . (Join-Path $guiFolder 'GuiModel.ps1')
    . (Join-Path $guiFolder 'GuiView.ps1')
    . (Join-Path $guiFolder 'GuiEntity.ps1')
    . (Join-Path $guiFolder 'GuiApp.ps1')
    . (Join-Path $guiFolder 'GuiSnapshot.ps1')
    Import-MspkiGuiAssembly
}
catch {
    Write-Host ('The MSPKI Health Check window could not start: {0}' -f $_.Exception.Message)
    exit 5
}

if ($Snapshot) {
    if (-not (Test-MspkiGuiSnapshotFolder -Folder $Snapshot -AllowedRoot (Join-Path $PSScriptRoot 'out'))) {
        Write-Host 'Snapshots can only be written under the out folder next to this script (they can contain real names).'
        exit 5
    }
    try {
        $window = Initialize-MspkiGuiApplication -ModulePath $modulePath -XamlPath (Join-Path $guiFolder 'MainWindow.xaml') -OutputPath $OutputPath
        $files = Invoke-MspkiGuiSnapshot -Window $window -Folder $Snapshot -AllowedRoot (Join-Path $PSScriptRoot 'out') -ResultsFile $ResultsFile -Width $SnapshotWidth -Height $SnapshotHeight -Scale $SnapshotScale -Maximized:$SnapshotMaximized
        foreach ($f in $files) { Write-Host $f }
    }
    catch {
        Write-Host ('The snapshot stopped with an error: {0}' -f $_.Exception.Message)
        Write-Host $_.ScriptStackTrace
        exit 5
    }
    exit 0
}

try {
    $window = Initialize-MspkiGuiApplication -ModulePath $modulePath -XamlPath (Join-Path $guiFolder 'MainWindow.xaml') `
        -OutputPath $OutputPath -OpenResults $OpenResults
    [void]$window.ShowDialog()
}
catch {
    Write-Host ('The MSPKI Health Check window stopped with an error: {0}' -f $_.Exception.Message)
    exit 5
}
exit 0
