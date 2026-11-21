# MSPKI Health Check module: loads the engine files in a fixed order. Read-only by design (see CLAUDE.md).

foreach ($folder in @('Model', 'Probes', 'Discovery', 'Analyzers', 'Reporters')) {
    $dir = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter '*.ps1' -File | Sort-Object Name)) {
        . $file.FullName
    }
}
. (Join-Path $PSScriptRoot 'Start-MspkiHealthCheck.ps1')

Export-ModuleMember -Function @('Start-MspkiHealthCheck', 'New-MspkiFinding', 'Get-MspkiSchema')
