<#
.SYNOPSIS
DEVELOPER-ONLY (tools\dev, never shipped, never referenced by the product). Runs the real MSPKI Health Check engine against one simulated
scenario of the demo world and writes results.json, events.json and manifest.json for the demo site (docs/DEMO-SITE.md section 3).

.DESCRIPTION
The module in src is imported unchanged. Only the I/O boundary listed in Boundary.psd1 is replaced, inside the module scope, by functions
that answer from site\world (MspkiSimulation.ps1, SimBoundary.ps1); a question the world has no answer for stops the run with an error
instead of reaching a real network, directory, CA or store. The clock is the world's demo clock and advances only by the simulated
latencies, so the same commit and world give the same bytes. The run is written under -Output (default out\site-data\<scenario>).

.EXAMPLE
powershell -NoProfile -File tools\dev\demo-site\Invoke-MspkiScenario.ps1 -Scenario baseline
#>
[CmdletBinding()]
param(
    [string]$Scenario = 'baseline',
    [string]$Output = '',
    [string]$Commit = ''
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path (Split-Path (Split-Path $here))
if (-not $Output) { $Output = Join-Path $repo ('out\site-data\{0}' -f $Scenario) }
$outFull = [System.IO.Path]::GetFullPath($Output)
$outRoot = [System.IO.Path]::GetFullPath((Join-Path $repo 'out')) + '\'
if (-not $outFull.StartsWith($outRoot, [StringComparison]::OrdinalIgnoreCase)) { throw ('The generator writes only under {0}' -f $outRoot) }
if (-not $Commit) { try { $Commit = (& git -C $repo rev-parse --short HEAD 2>$null) } catch { $Commit = '' } }

Import-Module (Join-Path $repo 'src\MspkiHealthCheck.psd1') -Force
. (Join-Path $here 'MspkiSimulation.ps1')
$world = Read-MspkiSimWorld -Root (Join-Path $repo 'site\world') -Scenario $Scenario
Enable-MspkiSimulation -World $world

# The run writes into a fixed relative folder of a scratch directory under the output, so its paths are the same on every machine.
$work = Join-Path $outFull 'run'
if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
[void](New-Item -ItemType Directory -Path $work -Force)
$control = New-MspkiRunControl
Push-Location $work
$cwd = [Environment]::CurrentDirectory
[Environment]::CurrentDirectory = $work   # the engine resolves its output folder against the process directory
try { $run = Start-MspkiHealthCheck -OutputPath 'demo' -Control $control -TimeoutSeconds 5 }
finally { [Environment]::CurrentDirectory = $cwd; Pop-Location }
$results = Join-Path $work ('demo\' + (Split-Path -Leaf (Split-Path -Parent $run.ResultsPath)) + '\results.json')
if (-not (Test-Path -LiteralPath $results)) { $results = [string]$run.ResultsPath; if (-not [System.IO.Path]::IsPathRooted($results)) { $results = Join-Path $work $results } }

# The recorded stream (the replay): each queue item with its offset from the start of the run on the simulated clock.
$start = $world.StartClock
$events = New-Object System.Collections.ArrayList
$item = $null
while ($control.Queue.TryDequeue([ref]$item)) {
    $e = [ordered]@{ T = [int64](([DateTime]$item.Time).ToUniversalTime() - $start).TotalMilliseconds }
    foreach ($p in @($item.PSObject.Properties | Where-Object { $_.Name -ne 'Time' } | Sort-Object Name)) { $e[$p.Name] = $p.Value }
    [void]$events.Add([pscustomobject]$e)
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
Copy-Item -LiteralPath $results -Destination (Join-Path $outFull 'results.json') -Force
[System.IO.File]::WriteAllText((Join-Path $outFull 'events.json'), (ConvertTo-Json -InputObject @($events) -Depth 6 -Compress), $utf8)
$boundary = Import-PowerShellDataFile -LiteralPath (Join-Path $here 'Boundary.psd1')
$manifest = [ordered]@{
    Scenario = $Scenario; Title = $world.Title
    Tool = 'MSPKI Health Check'; ToolVersion = [string](Get-Module MspkiHealthCheck).Version; Commit = [string]$Commit
    DemoClock = $start.ToString('yyyy-MM-ddTHH:mm:ssZ'); SimulatedSeconds = [math]::Round(($world.Clock - $start).TotalSeconds, 1)
    Events = $events.Count; ExitCode = [int]$run.ExitCode
    Replaced = @($boundary.Replaced); Shadowed = @($boundary.Shadowed)
    Note = 'Simulated environment. Alcyone Orbital Systems is fictional. These results were produced by the real analysers of MSPKI Health Check running against a simulated directory, CAs and network. Nothing here touched a real network.'
}
[System.IO.File]::WriteAllText((Join-Path $outFull 'manifest.json'), ($manifest | ConvertTo-Json -Depth 4), $utf8)
Remove-Item -LiteralPath $work -Recurse -Force
[pscustomobject]@{ Scenario = $Scenario; Output = $outFull; ExitCode = $run.ExitCode; Events = $events.Count; SimulatedSeconds = $manifest.SimulatedSeconds }
