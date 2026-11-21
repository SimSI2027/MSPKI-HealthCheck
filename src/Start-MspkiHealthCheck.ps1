function Start-MspkiHealthCheck {
    <#
    .SYNOPSIS
    Runs the MSPKI Health Check and writes results.json, findings.csv, report.html and run.log to <OutputPath>\<yyyyMMdd-HHmmss>\.

    .DESCRIPTION
    Read-only. Discovers the forest, domain controller, PKI containers, Enterprise CAs, every CA
    certificate generation and the CA properties (or records why they could not be read).
    Returns an object with OutputFolder, ResultsPath, CsvPath, ReportPath, ExitCode, Findings, Inventory and RunInfo.

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
    $csvPath = ''
    $reportPath = ''
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
                foreach ($f in (Test-MspkiAdContainerConsistency -Inventory $d.Inventory)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('AD container review stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'ADContainers' -Sources 'Run' -Action 'reviewing the AD PKI containers' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:ADContainers' -Stopwatch $sw
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                foreach ($f in (Test-MspkiAdContainerObject -Inventory $d.Inventory)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Template/KRA/OID container review stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'ADContainerObjects' -Sources 'Run' -Action 'reviewing the template, KRA and OID containers' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:ADContainerObjects' -Stopwatch $sw
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                foreach ($f in (Test-MspkiTemplateEnrollmentRisk -Inventory $d.Inventory)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Template review stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'Templates' -Sources 'Run' -Action 'reviewing certificate templates' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:Templates' -Stopwatch $sw
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
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $cep = Get-MspkiLocalCepPolicy
                foreach ($f in $cep.Findings) { [void]$findings.Add($f) }
                $inventory | Add-Member -NotePropertyName 'CepPolicies' -NotePropertyValue @($cep.Data) -Force
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Local policy read stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'CEP' -Role 'Computer' `
                    -Target 'Enrollment policy servers' -Sources 'Policy:CEP:HKLM' -Action 'reading the enrollment policy servers' -Scope 'Local'))
            }
            Add-MspkiStageTiming -Stage 'Discovery:LocalPolicy' -Stopwatch $sw
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                foreach ($f in (Invoke-MspkiEnrollmentServiceAnalysis -Discovery $d -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('CEP/CES checks stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'EnrollmentServices' -Sources 'Run' -Action 'checking CEP and CES endpoints' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Probe:EnrollmentServices' -Stopwatch $sw
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $ndesHosts = @()
            try {
                $ndes = Invoke-MspkiNdesAnalysis -Discovery $d -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork
                foreach ($f in $ndes.Findings) { [void]$findings.Add($f) }
                $ndesHosts = @($ndes.Hosts)
            }
            catch {
                Write-MspkiLog -Level Error -Message ('NDES checks stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'NDES' -Role 'NDESEndpoint' `
                    -Target 'NDES' -Sources 'Run' -Action 'checking NDES / SCEP' -Stage 'Run'))
            }
            $inventory | Add-Member -NotePropertyName 'NdesHosts' -NotePropertyValue $ndesHosts -Force
            Add-MspkiStageTiming -Stage 'Probe:NDES' -Stopwatch $sw
            $inventory | Add-Member -NotePropertyName 'Leads'-NotePropertyValue @(Get-MspkiLead | ForEach-Object { ConvertTo-MspkiLeadExport -Lead $_ }) -Force
            $inventory | Add-Member -NotePropertyName 'LeadStatistics' -NotePropertyValue (Get-MspkiLeadStatistic) -Force
        }
        $completed = $true
    }
    finally {
        # Also runs on Ctrl+C, so a partial results.json is still written.
        Complete-MspkiRun -Completed $completed
        $exitCode = Get-MspkiExitCode -Findings @($findings) -Incomplete:(-not $completed)
        $writeJson = {
            try {
                [void](Export-MspkiJson -Path $resultsPath -RunInfo ([pscustomobject]$runInfo) -Inventory $inventory `
                    -Findings @($findings) -ExitCode $exitCode)
                Write-MspkiLog -Message ('Wrote {0} ({1} findings), exit code {2}.' -f $resultsPath, $findings.Count, $exitCode)
            }
            catch { Write-MspkiLog -Level Error -Message ('Could not write results.json: {0}' -f $_.Exception.Message) }
        }
        & $writeJson
        # Reports are written after results.json so the data is safe even if a reporter fails; a reporter failure
        # becomes a finding, which can change the exit code, so results.json is then written again.
        $rep = $null
        try { $rep = Write-MspkiRunReport -Folder $folder -RunInfo ([pscustomobject]$runInfo) -Inventory $inventory -Findings @($findings) -ExitCode $exitCode }
        catch { Write-MspkiLog -Level Error -Message ('Reports stopped: {0}' -f $_.Exception.Message) }
        if ($null -ne $rep) {
            $csvPath = $rep.CsvPath; $reportPath = $rep.HtmlPath
            if ($rep.Errors.Count -gt 0) {
                foreach ($f in $rep.Errors) { [void]$findings.Add($f) }
                $exitCode = Get-MspkiExitCode -Findings @($findings) -Incomplete:(-not $completed)
                & $writeJson
            }
        }
    }
    return [pscustomobject][ordered]@{
        OutputFolder = $folder
        ResultsPath  = $resultsPath
        CsvPath      = $csvPath
        ReportPath   = $reportPath
        ExitCode     = $exitCode
        Findings     = @($findings)
        Inventory    = $inventory
        RunInfo      = [pscustomobject]$runInfo
    }
}
