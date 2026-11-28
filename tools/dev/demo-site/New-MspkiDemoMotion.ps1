<#
.SYNOPSIS
DEVELOPER-ONLY (tools\dev, never shipped, never referenced by the product). Makes the demo site's short motion version: the window's
"replay discovery" frames (Start-MspkiHealthCheckGui.ps1 -Snapshot ... -SnapshotReplayFrames N, on a results file the real engine produced
for a demo-world scenario) stitched into an MP4 and an optimised GIF with ffmpeg (a developer tool, used for these outputs only).

.DESCRIPTION
The frames are cropped above the status bar (which shows a local folder), the last frame is held so the finished map can be read, and the
outputs go to -Output (default site\assets\media: discovery.mp4, discovery.gif, discovery-poster.png). Nothing else is written.

.EXAMPLE
powershell -NoProfile -STA -File Start-MspkiHealthCheckGui.ps1 -Snapshot out\motion-frames -ResultsFile out\site-data\baseline\results.json -SnapshotReplayFrames 60
powershell -NoProfile -File tools\dev\demo-site\New-MspkiDemoMotion.ps1 -Frames out\motion-frames
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Frames,
    [string]$Output = '',
    [string]$FFmpeg = '',
    [int]$StepMs = 60,
    [int]$CropHeight = 826,
    [double]$HoldSeconds = 2.5
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path (Split-Path (Split-Path $MyInvocation.MyCommand.Path)))
if (-not $Output) { $Output = Join-Path $repo 'site\assets\media' }
if (-not $FFmpeg) {
    $FFmpeg = @(Get-Command ffmpeg -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }) + @(Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Gyan.FFmpeg*\*\bin\ffmpeg.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) | Select-Object -First 1
}
if (-not $FFmpeg -or -not (Test-Path -LiteralPath $FFmpeg)) { throw 'ffmpeg was not found: install it for this user or pass -FFmpeg.' }
$framesFull = (Resolve-Path -LiteralPath $Frames).Path
if (@(Get-ChildItem -LiteralPath $framesFull -Filter '07-replay-*.png').Count -lt 2) { throw 'No replay frames (07-replay-NNNN.png) in that folder.' }
[void](New-Item -ItemType Directory -Path $Output -Force)
$fps = [math]::Round(1000.0 / $StepMs, 3).ToString([Globalization.CultureInfo]::InvariantCulture)
$hold = $HoldSeconds.ToString([Globalization.CultureInfo]::InvariantCulture)
$in = Join-Path $framesFull '07-replay-%04d.png'
$crop = 'crop=iw:{0}:0:0' -f $CropHeight
$mp4 = Join-Path $Output 'discovery.mp4'
$gif = Join-Path $Output 'discovery.gif'
$poster = Join-Path $Output 'discovery-poster.png'
& $FFmpeg -hide_banner -loglevel error -y -framerate $fps -i $in -vf "$crop,tpad=stop_mode=clone:stop_duration=$hold,scale=1280:-2:flags=lanczos,format=yuv420p" -c:v libx264 -preset slow -crf 24 -bsf:v filter_units=remove_types=6 -map_metadata -1 -fflags +bitexact -movflags +faststart -an $mp4
if ($LASTEXITCODE -ne 0) { throw 'ffmpeg could not write the MP4.' }
& $FFmpeg -hide_banner -loglevel error -y -framerate $fps -i $in -vf "$crop,tpad=stop_mode=clone:stop_duration=$hold,fps=12,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle" -loop 0 $gif
if ($LASTEXITCODE -ne 0) { throw 'ffmpeg could not write the GIF.' }
$last = @(Get-ChildItem -LiteralPath $framesFull -Filter '07-replay-*.png' | Sort-Object Name)[-1].FullName
& $FFmpeg -hide_banner -loglevel error -y -i $last -vf "$crop,scale=960:-1:flags=lanczos" -frames:v 1 $poster
foreach ($f in $mp4, $gif, $poster) { '{0} {1:n0} KB' -f (Split-Path -Leaf $f), ((Get-Item -LiteralPath $f).Length / 1KB) }
