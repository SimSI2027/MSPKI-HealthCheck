<#
.SYNOPSIS
MSPKI Health Check: read-only, self-discovering health check for Microsoft AD CS.

.DESCRIPTION
Run on any domain-joined Windows computer with Windows PowerShell 5.1. No configuration file, no
installation, no external modules. Output goes to <OutputPath>\<yyyyMMdd-HHmmss>\.

Exit codes: 0 passed, 2 informational, 3 warnings, 4 failures, 5 incomplete (unsupported or error),
6 incomplete (permissions).

.PARAMETER OutputPath
Root folder for run output. Default: the out folder next to this script.

.PARAMETER TimeoutSeconds
Base timeout for each network probe. Default 5.

.PARAMETER SkipNetwork
Read AD only; do not contact CAs or other hosts.

.PARAMETER RootCaWarningDays
Days before a root CA certificate expires when a warning is raised (default 730; critical default 365).

.PARAMETER IssuingCaWarningDays
Days before a subordinate CA certificate expires when a warning is raised (default 180; critical default 90).

.EXAMPLE
.\Invoke-MspkiHealthCheck.ps1

.EXAMPLE
.\Invoke-MspkiHealthCheck.ps1 -OutputPath D:\Reports -TimeoutSeconds 10
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'out'),
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 5,
    [switch]$SkipNetwork,
    [ValidateRange(1, 36500)][int]$RootCaWarningDays = 730,
    [ValidateRange(1, 36500)][int]$RootCaCriticalDays = 365,
    [ValidateRange(1, 36500)][int]$IssuingCaWarningDays = 180,
    [ValidateRange(1, 36500)][int]$IssuingCaCriticalDays = 90
)

$module = Join-Path $PSScriptRoot 'src\MspkiHealthCheck.psd1'
Import-Module $module -Force -ErrorAction Stop

$run = @{
    OutputPath = $OutputPath; TimeoutSeconds = $TimeoutSeconds; SkipNetwork = $SkipNetwork
    RootCaWarningDays = $RootCaWarningDays; RootCaCriticalDays = $RootCaCriticalDays
    IssuingCaWarningDays = $IssuingCaWarningDays; IssuingCaCriticalDays = $IssuingCaCriticalDays
}
$result = Start-MspkiHealthCheck @run

$counts = $result.Findings | Group-Object Status | Sort-Object Name | ForEach-Object { '{0}={1}' -f $_.Name, $_.Count }
Write-Host ('MSPKI Health Check finished: {0} finding(s) [{1}]' -f @($result.Findings).Count, ($counts -join ', '))
foreach ($f in @($result.Findings | Where-Object { $_.Status -notin @('Pass', 'Information') -or $_.StatusCode -ne 'OK' })) {
    Write-Host ('  {0,-11} {1,-18} {2}' -f $f.Status, $f.StatusCode, $f.Message)
}
Write-Host ('Results: {0}' -f $result.ResultsPath)
Write-Host ('Exit code: {0}' -f $result.ExitCode)
exit $result.ExitCode
