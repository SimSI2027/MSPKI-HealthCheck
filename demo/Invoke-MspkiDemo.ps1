<#
.SYNOPSIS
Builds findings.csv and report.html from the sanitised example.test demo data, so the report can be seen
without a domain, a CA or a network. Nothing is discovered or contacted.

.DESCRIPTION
Reads tests\fixtures\demo-results.json (a results.json with example.test names only), runs the CSV and HTML
reporters on it and writes the files to out\demo (the only place this script writes to).

.PARAMETER OutputPath
Folder for the demo files. Default: out\demo next to the repository root.

.PARAMETER Open
Open report.html in the default browser when it has been written.

.EXAMPLE
.\demo\Invoke-MspkiDemo.ps1 -Open
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [switch]$Open
)

$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) { $OutputPath = Join-Path $repo 'out\demo' }
Import-Module (Join-Path $repo 'src\MspkiHealthCheck.psd1') -Force -ErrorAction Stop
$r = Export-MspkiReportFromResults -ResultsPath (Join-Path $repo 'tests\fixtures\demo-results.json') -OutputFolder $OutputPath
Write-Host ('Demo report written from {0} example finding(s) (exit code in the data: {1}).' -f $r.Findings, $r.ExitCode)
Write-Host ('Report: {0}' -f $r.HtmlPath)
Write-Host ('CSV:    {0}' -f $r.CsvPath)
if ($Open) { Invoke-Item -LiteralPath $r.HtmlPath }
