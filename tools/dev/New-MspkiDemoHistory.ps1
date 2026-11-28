# Developer-only (never shipped, never referenced by the product): writes a small run history of the demo world for the History page's
# snapshots (GX8): three runs of the fictional forest, a week apart, under out\demo-history\ (out\ only; nothing in the repository changes):
#   <date>-mixed         the hand-made `mixed-sample` results
#   <date>-renewal-drift the `renewal-drift` sample
#   <date>-expired-crl   the `expired-crl` sample (the newest)
# The samples are hand-made (docs\DEMO-WORLD.md); their run times are moved so they read as a series, and each finding gets the Key a run
# of this version writes. Windows PowerShell 5.1. Idempotent.
[CmdletBinding()]
param([string]$OutFolder = '')
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))
if (-not $OutFolder) { $OutFolder = Join-Path $repo 'out\demo-history' }
$outRoot = [System.IO.Path]::GetFullPath((Join-Path $repo 'out'))
$full = [System.IO.Path]::GetFullPath($OutFolder)
if (-not $full.StartsWith($outRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) { throw 'The demo history is written under out\ only.' }
$mod = Import-Module (Join-Path $repo 'src\MspkiHealthCheck.psd1') -Force -PassThru
$series = @(
    @{ Name = 'mixed'; Started = [datetime]::new(2026, 11, 6, 9, 30, 0, [DateTimeKind]::Utc) },
    @{ Name = 'renewal-drift'; Started = [datetime]::new(2026, 11, 13, 9, 29, 0, [DateTimeKind]::Utc) },
    @{ Name = 'expired-crl'; Started = [datetime]::new(2026, 11, 20, 9, 29, 41, [DateTimeKind]::Utc) }
)
foreach ($s in $series) {
    $src = Join-Path $repo ('demo\world\alcyone-{0}-results.json' -f $s.Name)
    $doc = Get-Content -LiteralPath $src -Raw | ConvertFrom-Json
    if ($s.Name -ne 'expired-crl') {
        # Only the run time moves (the expired-crl sample keeps its own, as the newest run); the PKI dates stay as each sample has them.
        $doc.RunInfo.StartedUtc = $s.Started.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $doc.RunInfo.FinishedUtc = $s.Started.AddSeconds(86).ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    & $mod { param($f) [void](Set-MspkiFindingKey -Findings $f) } @($doc.Findings)
    $dir = Join-Path $full ('{0}-{1}' -f $s.Started.ToString('yyyyMMdd-HHmmss'), $s.Name)
    [void][System.IO.Directory]::CreateDirectory($dir)
    $json = $doc | ConvertTo-Json -Depth 40
    [System.IO.File]::WriteAllText((Join-Path $dir 'results.json'), $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ('wrote {0}' -f (Join-Path $dir 'results.json'))
}
