# Writes the report files of a run (findings.csv, report.html) and regenerates them from a results.json.

function Write-MspkiRunReport {
    <#
    .SYNOPSIS
    Writes findings.csv and report.html into the run output folder. Each reporter runs in its own try/catch;
    a failure is logged and returned as an Error finding so that it is never silent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Folder,
        [Parameter(Mandatory = $true)]$RunInfo,
        [AllowNull()]$Inventory = $null,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [int]$ExitCode = 0
    )
    $result = [pscustomobject]@{ CsvPath = ''; HtmlPath = ''; Errors = (New-Object System.Collections.ArrayList) }
    $csv = Join-Path $Folder 'findings.csv'
    $html = Join-Path $Folder 'report.html'
    try {
        $result.CsvPath = Export-MspkiCsv -Path $csv -Findings $Findings
        Write-MspkiLog -Message ('Wrote {0}' -f $csv)
    }
    catch {
        Write-MspkiLog -Level Error -Message ('Could not write findings.csv: {0}' -f $_.Exception.Message)
        [void]$result.Errors.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' -Target 'findings.csv' `
            -Sources 'Run' -Action 'writing findings.csv' -Stage 'Report'))
    }
    try {
        $result.HtmlPath = Export-MspkiHtml -Path $html -RunInfo $RunInfo -Inventory $Inventory -Findings $Findings -ExitCode $ExitCode
        Write-MspkiLog -Message ('Wrote {0}' -f $html)
    }
    catch {
        Write-MspkiLog -Level Error -Message ('Could not write report.html: {0}' -f $_.Exception.Message)
        [void]$result.Errors.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' -Target 'report.html' `
            -Sources 'Run' -Action 'writing report.html' -Stage 'Report'))
    }
    return $result
}

function Export-MspkiReportFromResults {
    <#
    .SYNOPSIS
    Builds findings.csv and report.html from an existing results.json (for example the sanitised demo data in
    tests\fixtures) without contacting anything.

    .PARAMETER ResultsPath
    A results.json written by this tool.

    .PARAMETER OutputFolder
    Folder for findings.csv and report.html. It is created if needed and is the only place written to.

    .EXAMPLE
    Export-MspkiReportFromResults -ResultsPath .\tests\fixtures\demo-results.json -OutputFolder .\out\demo
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ResultsPath,
        [Parameter(Mandatory = $true)][string]$OutputFolder
    )
    $text = [System.IO.File]::ReadAllText([System.IO.Path]::GetFullPath($ResultsPath), [System.Text.Encoding]::UTF8)
    $j = ConvertFrom-MspkiResultsDocument -Document ($text | ConvertFrom-Json)
    $folder = Use-MspkiOutputFolder -Path $OutputFolder
    $findings = @($j.Findings)
    $r = Write-MspkiRunReport -Folder $folder -RunInfo $j.RunInfo -Inventory $j.Inventory -Findings $findings -ExitCode ([int]$j.ExitCode)
    if ($r.Errors.Count -gt 0) { throw ('Report writing failed: {0}' -f (@($r.Errors | ForEach-Object { $_.Message }) -join '; ')) }
    return [pscustomobject][ordered]@{ OutputFolder = $folder; HtmlPath = $r.HtmlPath; CsvPath = $r.CsvPath; ExitCode = [int]$j.ExitCode; Findings = $findings.Count }
}
