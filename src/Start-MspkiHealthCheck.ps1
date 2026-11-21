function Start-MspkiHealthCheck {
    <#
    .SYNOPSIS
    Runs the MSPKI Health Check and writes results.json and run.log to <OutputPath>\<yyyyMMdd-HHmmss>\.

    .DESCRIPTION
    Read-only. Discovers the forest, domain controller, PKI containers, Enterprise CAs, every CA
    certificate generation and the CA properties (or records why they could not be read).
    Returns an object with OutputFolder, ResultsPath, ExitCode, Findings, Inventory and RunInfo.

    .PARAMETER OutputPath
    Root folder for run output. A new timestamped sub-folder is created for each run.

    .PARAMETER TimeoutSeconds
    Base timeout for each network probe (DNS, TCP). LDAP and CA calls use a multiple of it.

    .PARAMETER SkipNetwork
    Reads AD only; does not contact CAs or other hosts.

    .EXAMPLE
    Start-MspkiHealthCheck -OutputPath .\out
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork
    )
    $runInfo = Initialize-MspkiRun -Parameters @{
        OutputPath = $OutputPath; TimeoutSeconds = $TimeoutSeconds; SkipNetwork = [bool]$SkipNetwork
    }
    $folder = New-MspkiOutputFolder -Root $OutputPath
    Start-MspkiLogFile -Path (Join-Path $folder 'run.log')
    Write-MspkiLog -Message ('{0} {1} started. Run id {2}.' -f $script:MspkiToolName, $script:MspkiToolVersion, $runInfo.RunId)
    Write-MspkiLog -Message ('PowerShell {0} ({1}), CLR {2}, admin: {3}' -f $runInfo.PSVersion, $runInfo.PSEdition, $runInfo.ClrVersion, $runInfo.IsAdmin)

    $findings = New-Object System.Collections.ArrayList
    $inventory = $null
    $completed = $false
    $resultsPath = Join-Path $folder 'results.json'
    $exitCode = 5
    try {
        if ($PSVersionTable.PSEdition -ne 'Desktop') {
            [void]$findings.Add((New-MspkiFinding -Category 'Run' -Role 'Run' -Target 'PowerShell' -Status 'Warning' `
                -StatusCode 'UNSUPPORTED' -Confidence 'Confirmed' -Sources 'Local:PSVersionTable' -Stage 'Run' -Scope 'Local' `
                -Message ('This tool targets Windows PowerShell 5.1; running on {0} {1} is not supported.' -f $PSVersionTable.PSEdition, $runInfo.PSVersion)))
        }
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $d = Invoke-MspkiDiscovery -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork
            foreach ($f in $d.Findings) { [void]$findings.Add($f) }
            $inventory = $d.Inventory
        }
        catch {
            Write-MspkiLog -Level Error -Message ('Discovery stopped: {0}' -f $_.Exception.Message)
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                -Target 'Discovery' -Sources 'Run' -Action 'running discovery' -Stage 'Run'))
        }
        Add-MspkiStageTiming -Stage 'Discovery' -Stopwatch $sw
        $completed = $true
    }
    finally {
        # Also runs on Ctrl+C, so a partial results.json is still written.
        Complete-MspkiRun -Completed $completed
        $exitCode = Get-MspkiExitCode -Findings @($findings)
        try {
            [void](Export-MspkiJson -Path $resultsPath -RunInfo ([pscustomobject]$runInfo) -Inventory $inventory `
                -Findings @($findings) -ExitCode $exitCode)
            Write-MspkiLog -Message ('Wrote {0} ({1} findings), exit code {2}.' -f $resultsPath, $findings.Count, $exitCode)
        }
        catch { Write-MspkiLog -Level Error -Message ('Could not write results.json: {0}' -f $_.Exception.Message) }
    }
    return [pscustomobject][ordered]@{
        OutputFolder = $folder
        ResultsPath  = $resultsPath
        ExitCode     = $exitCode
        Findings     = @($findings)
        Inventory    = $inventory
        RunInfo      = [pscustomobject]$runInfo
    }
}
