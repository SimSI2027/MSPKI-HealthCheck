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
        [switch]$SkipNetwork,
        [ValidateRange(1, 36500)][int]$RootCaWarningDays = 730,
        [ValidateRange(1, 36500)][int]$RootCaCriticalDays = 365,
        [ValidateRange(1, 36500)][int]$IssuingCaWarningDays = 180,
        [ValidateRange(1, 36500)][int]$IssuingCaCriticalDays = 90,
        [ValidateRange(1, 100)][int]$RootCrlWarningPercent = 75,
        [ValidateRange(1, 100)][int]$RootCrlCriticalPercent = 95,
        [ValidateRange(1, 100)][int]$IssuingCrlWarningPercent = 75,
        [ValidateRange(1, 100)][int]$IssuingCrlCriticalPercent = 95,
        [ValidateRange(1, 1440)][int]$CrlPublicationGraceMinutes = 60
    )
    $thresholds = Get-MspkiThreshold -Override @{
        RootCaWarningDays = $RootCaWarningDays; RootCaCriticalDays = $RootCaCriticalDays
        IssuingCaWarningDays = $IssuingCaWarningDays; IssuingCaCriticalDays = $IssuingCaCriticalDays
        RootCrlWarningPercent = $RootCrlWarningPercent; RootCrlCriticalPercent = $RootCrlCriticalPercent
        IssuingCrlWarningPercent = $IssuingCrlWarningPercent; IssuingCrlCriticalPercent = $IssuingCrlCriticalPercent
        CrlPublicationGraceMinutes = $CrlPublicationGraceMinutes
    }
    $runInfo = Initialize-MspkiRun -Parameters @{
        OutputPath = $OutputPath; TimeoutSeconds = $TimeoutSeconds; SkipNetwork = [bool]$SkipNetwork
        RootCaWarningDays = $RootCaWarningDays; RootCaCriticalDays = $RootCaCriticalDays
        IssuingCaWarningDays = $IssuingCaWarningDays; IssuingCaCriticalDays = $IssuingCaCriticalDays
        RootCrlWarningPercent = $RootCrlWarningPercent; RootCrlCriticalPercent = $RootCrlCriticalPercent
        IssuingCrlWarningPercent = $IssuingCrlWarningPercent; IssuingCrlCriticalPercent = $IssuingCrlCriticalPercent
        CrlPublicationGraceMinutes = $CrlPublicationGraceMinutes
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
        $d = $null
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

        if ($null -ne $d) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $ctx = $d.Inventory.AdContext
                Reset-MspkiLeadRegistry -LocalDomains @($ctx.ForestDomains) -TrustedDomains @($ctx.TrustedDomains)
                Register-MspkiDiscoveredLead -Discovery $d
                $entries = @(Get-MspkiDiscoveredCertificateEntry -Discovery $d)
                foreach ($f in (Test-MspkiCACertificateHealth -Entries $entries -Thresholds $thresholds)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Analysis stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'Analysis' -Sources 'Run' -Action 'analysing CA certificates' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:CACertificates' -Stopwatch $sw
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                foreach ($f in (Invoke-MspkiEndpointAnalysis -Discovery $d -Thresholds $thresholds -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork)) {
                    [void]$findings.Add($f)
                }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Endpoint checks stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'Endpoints' -Sources 'Run' -Action 'checking AIA/CDP/OCSP endpoints' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Probe:Endpoints' -Stopwatch $sw
            $inventory | Add-Member -NotePropertyName 'Leads' -NotePropertyValue @(Get-MspkiLead | ForEach-Object { ConvertTo-MspkiLeadExport -Lead $_ }) -Force
            $inventory | Add-Member -NotePropertyName 'LeadStatistics' -NotePropertyValue (Get-MspkiLeadStatistic) -Force
        }
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
