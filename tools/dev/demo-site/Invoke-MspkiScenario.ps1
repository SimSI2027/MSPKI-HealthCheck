<#
.SYNOPSIS
DEVELOPER-ONLY (tools\dev, never shipped, never referenced by the product). Runs the real MSPKI Health Check engine against simulated
scenarios of the demo world and writes results.json, events.json and manifest.json per scenario for the demo site (docs/DEMO-SITE.md
section 3).

.DESCRIPTION
The module in src is imported unchanged (once per scenario, so no state carries over). Only the I/O boundary listed in Boundary.psd1 is
replaced, inside the module scope, by functions that answer from site\world (MspkiSimulation.ps1, SimBoundary.ps1). A question the world
has no answer for invalidates the scenario, even when the engine turned it into an ordinary result. The clock is the world's demo clock
and advances only by the simulated latencies, so the same commit and world give the same bytes.
A scenario also fails when it has an Error finding, or a permission refusal in a category its "expect.permissionDenied" does not list.
Each scenario is written to <Output>\<id> (default out\site-data); nothing is written outside out\.

.EXAMPLE
powershell -NoProfile -File tools\dev\demo-site\Invoke-MspkiScenario.ps1 -Scenario all
#>
[CmdletBinding()]
param(
    [string[]]$Scenario = @('baseline'),
    [string]$Output = '',
    [string]$Commit = ''
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = Split-Path (Split-Path (Split-Path $here))
$worldRoot = Join-Path $repo 'site\world'
if (-not $Output) { $Output = Join-Path $repo 'out\site-data' }
$outFull = [System.IO.Path]::GetFullPath($Output)
$outRoot = [System.IO.Path]::GetFullPath((Join-Path $repo 'out')) + '\'
if (-not $outFull.StartsWith($outRoot, [StringComparison]::OrdinalIgnoreCase)) { throw ('The generator writes only under {0}' -f $outRoot) }
if (-not $Commit) { try { $Commit = [string](& git -C $repo rev-parse --short HEAD 2>$null) } catch { $Commit = '' } }
$ids = @(($Scenario -join ',') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($ids -contains 'all') { $ids = @(Get-ChildItem -LiteralPath (Join-Path $worldRoot 'scenarios') -Filter '*.json' | Sort-Object Name | ForEach-Object { $_.BaseName }) }
$boundary = Import-PowerShellDataFile -LiteralPath (Join-Path $here 'Boundary.psd1')
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Invoke-MspkiOneScenario {
    param([string]$Id, [string]$Folder)
    Import-Module (Join-Path $repo 'src\MspkiHealthCheck.psd1') -Force
    . (Join-Path $here 'MspkiSimulation.ps1')
    $world = Read-MspkiSimWorld -Root $worldRoot -Scenario $Id
    Enable-MspkiSimulation -World $world

    # The run writes into a fixed relative folder of a scratch directory, so its paths are the same on every machine.
    $work = Join-Path $Folder 'run'
    if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    [void](New-Item -ItemType Directory -Path $work -Force)
    $control = New-MspkiRunControl
    Push-Location $work
    $cwd = [Environment]::CurrentDirectory
    [Environment]::CurrentDirectory = $work   # the engine resolves its output folder against the process directory
    try { $run = Start-MspkiHealthCheck -OutputPath 'demo' -Control $control -TimeoutSeconds 5 }
    finally { [Environment]::CurrentDirectory = $cwd; Pop-Location }
    $results = Join-Path $work ('demo\' + (Split-Path -Leaf (Split-Path -Parent ([string]$run.ResultsPath))) + '\results.json')

    # Any question the world could not answer makes the scenario invalid, even when the engine turned it into an ordinary result.
    if ($world.Gaps.Count -gt 0) { throw ('SIMULATION: scenario {0} asked {1} question(s) the world has no answer for: {2}' -f $Id, $world.Gaps.Count, ((@($world.Gaps) | Select-Object -Unique) -join '; ')) }
    $doc = Read-MspkiResultsJson -Path $results
    $err = @($doc.Findings | Where-Object { $_.Status -eq 'Error' })
    if ($err.Count -gt 0) { throw ('Scenario {0}: unexpected Error finding(s): {1}' -f $Id, ((@($err) | ForEach-Object { '{0} {1}' -f $_.Category, $_.StatusCode }) -join '; ')) }
    $okDenied = @($world.Expect.permissionDenied | Where-Object { $_ })
    $denied = @($doc.Findings | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' -and $okDenied -notcontains [string]$_.Category })
    if ($denied.Count -gt 0) { throw ('Scenario {0}: unexpected permission refusal(s) in {1}' -f $Id, ((@($denied) | ForEach-Object { $_.Category } | Select-Object -Unique) -join ', ')) }

    # The recorded stream (the replay): each queue item with its offset from the start of the run on the simulated clock.
    # The run's own output folder (on the build machine, named after the local time) appears in a few log lines; it becomes a neutral
    # "<output folder>", so the replay shows no path of the machine that built the site and the bytes do not depend on it.
    $runFolder = Split-Path -Parent $results
    $start = $world.StartClock
    $events = New-Object System.Collections.ArrayList
    $item = $null
    while ($control.Queue.TryDequeue([ref]$item)) {
        $e = [ordered]@{ T = [int64](([DateTime]$item.Time).ToUniversalTime() - $start).TotalMilliseconds }
        foreach ($p in @($item.PSObject.Properties | Where-Object { $_.Name -ne 'Time' } | Sort-Object Name)) {
            $v = $p.Value
            if ($v -is [string] -and $v.IndexOf($runFolder, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $v = [regex]::Replace($v, [regex]::Escape($runFolder), '<output folder>', 'IgnoreCase') }
            $e[$p.Name] = $v
        }
        [void]$events.Add([pscustomobject]$e)
    }
    Copy-Item -LiteralPath $results -Destination (Join-Path $Folder 'results.json') -Force
    [System.IO.File]::WriteAllText((Join-Path $Folder 'events.json'), (ConvertTo-Json -InputObject @($events) -Depth 6 -Compress), $utf8)
    $manifest = [ordered]@{
        Scenario = $Id; Title = $world.Title; Summary = [string]$world.Summary
        Tool = 'MSPKI Health Check'; ToolVersion = [string](Get-Module MspkiHealthCheck).Version; Commit = [string]$Commit
        DemoClock = $start.ToString('yyyy-MM-ddTHH:mm:ssZ'); SimulatedSeconds = [math]::Round(($world.Clock - $start).TotalSeconds, 1)
        Events = $events.Count; Findings = @($doc.Findings).Count; ExitCode = [int]$run.ExitCode
        Replaced = @($boundary.Replaced); Shadowed = @($boundary.Shadowed)
        Note = 'Simulated environment. Alcyone Orbital Systems is fictional. These results were produced by the real analysers of MSPKI Health Check running against a simulated directory, CAs and network. Nothing here touched a real network.'
    }
    [System.IO.File]::WriteAllText((Join-Path $Folder 'manifest.json'), ($manifest | ConvertTo-Json -Depth 4), $utf8)
    Remove-Item -LiteralPath $work -Recurse -Force
    return [pscustomobject]@{ Scenario = $Id; Findings = $manifest.Findings; ExitCode = $manifest.ExitCode; Events = $events.Count; SimulatedSeconds = $manifest.SimulatedSeconds }
}

foreach ($id in $ids) {
    $folder = Join-Path $outFull $id
    [void](New-Item -ItemType Directory -Path $folder -Force)
    Invoke-MspkiOneScenario -Id $id -Folder $folder
}
