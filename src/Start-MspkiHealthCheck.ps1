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

    .PARAMETER UseSystemProxy
    Lets the HTTP probes use the system proxy settings (without credentials). By default they connect directly, so that no
    proxy and no automatic proxy detection is involved.

    .PARAMETER IncludeNdesAdminProbe
    Also sends the one anonymous request to the NDES admin page. Off by default: an admin page that is wrongly open to
    anonymous users creates a challenge password on the server when it is requested.

    .PARAMETER Control
    Optional object from New-MspkiRunControl, for a caller that runs this function in another runspace (the GUI). Setting
    $Control.Cancel to $true stops the run at the next stage or probe (partial results are still written); progress messages
    are added to $Control.Queue. Without it nothing changes.

    .EXAMPLE
    Start-MspkiHealthCheck -OutputPath .\out
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork,
        [switch]$UseSystemProxy,
        [switch]$IncludeNdesAdminProbe,
        [ValidateRange(1, 36500)][int]$RootCaWarningDays = 730,
        [ValidateRange(1, 36500)][int]$RootCaCriticalDays = 365,
        [ValidateRange(1, 36500)][int]$IssuingCaWarningDays = 180,
        [ValidateRange(1, 36500)][int]$IssuingCaCriticalDays = 90,
        [ValidateRange(1, 100)][int]$RootCrlWarningPercent = 75,
        [ValidateRange(1, 100)][int]$RootCrlCriticalPercent = 95,
        [ValidateRange(1, 100)][int]$IssuingCrlWarningPercent = 75,
        [ValidateRange(1, 100)][int]$IssuingCrlCriticalPercent = 95,
        [ValidateRange(1, 1440)][int]$CrlPublicationGraceMinutes = 60,
        [hashtable]$Control = $null
    )
    # The tool needs Full Language mode (audit 2 M13); stop before anything is written.
    $languageMode = Get-MspkiLanguageModeStatus
    if (-not $languageMode.IsFull) { throw $languageMode.Message }
    Set-MspkiRunControl -Control $Control
    $thresholds = Get-MspkiThreshold -Override @{
        RootCaWarningDays = $RootCaWarningDays; RootCaCriticalDays = $RootCaCriticalDays
        IssuingCaWarningDays = $IssuingCaWarningDays; IssuingCaCriticalDays = $IssuingCaCriticalDays
        RootCrlWarningPercent = $RootCrlWarningPercent; RootCrlCriticalPercent = $RootCrlCriticalPercent
        IssuingCrlWarningPercent = $IssuingCrlWarningPercent; IssuingCrlCriticalPercent = $IssuingCrlCriticalPercent
        CrlPublicationGraceMinutes = $CrlPublicationGraceMinutes
    }
    Set-MspkiWebProbeOption -UseSystemProxy:$UseSystemProxy
    $runInfo = Initialize-MspkiRun -Parameters @{
        OutputPath = $OutputPath; TimeoutSeconds = $TimeoutSeconds; SkipNetwork = [bool]$SkipNetwork
        UseSystemProxy = [bool]$UseSystemProxy; IncludeNdesAdminProbe = [bool]$IncludeNdesAdminProbe
        RootCaWarningDays = $RootCaWarningDays; RootCaCriticalDays = $RootCaCriticalDays
        IssuingCaWarningDays = $IssuingCaWarningDays; IssuingCaCriticalDays = $IssuingCaCriticalDays
        RootCrlWarningPercent = $RootCrlWarningPercent; RootCrlCriticalPercent = $RootCrlCriticalPercent
        IssuingCrlWarningPercent = $IssuingCrlWarningPercent; IssuingCrlCriticalPercent = $IssuingCrlCriticalPercent
        CrlPublicationGraceMinutes = $CrlPublicationGraceMinutes
    }
    $folder = New-MspkiOutputFolder -Root $OutputPath
    Start-MspkiLogFile -Path (Join-Path $folder 'run.log')
    Write-MspkiLog -Message ('{0} {1} started. Run id {2}.' -f $script:MspkiToolName, $script:MspkiToolVersion, $runInfo.RunId)
    Write-MspkiLog -Message ('PowerShell {0} ({1}), CLR {2}, .NET Framework {3} (release {4}), OS {5}, admin: {6}' -f $runInfo.PSVersion, $runInfo.PSEdition, $runInfo.ClrVersion, $runInfo.DotNetVersion, $runInfo.DotNetRelease, $runInfo.OSVersion, $runInfo.IsAdmin)
    Write-MspkiLog -Message ('Options: timeout {0} s, SkipNetwork {1}, HTTP proxy: {2}, NDES admin request: {3}; signature APIs available: {4}; TLS setting of this process: {5}' -f `
        $TimeoutSeconds, [bool]$SkipNetwork, $runInfo.HttpProxy, $(if ($IncludeNdesAdminProbe) { 'sent (opt-in)' } else { 'not sent (default)' }), $runInfo.SignatureApisAvailable, $runInfo.TlsSecurityProtocol)
    $tlsState = Enable-MspkiClientTlsProtocol
    if ($tlsState.Changed) { Write-MspkiLog -Message ('TLS setting of this process raised for the run: {0} -> {1} (restored at the end)' -f $tlsState.Previous, $tlsState.Current) }

    $findings = New-Object System.Collections.ArrayList
    $inventory = $null
    $completed = $false
    $resultsPath = Join-Path $folder 'results.json'
    $exitCode = 5
    $csvPath = ''
    $reportPath = ''
    try {
        if (-not $runInfo.SignatureApisAvailable) {
            [void]$findings.Add((New-MspkiFinding -Category 'Run' -Role 'Run' -Target '.NET Framework' -Status 'Warning' `
                -StatusCode 'UNSUPPORTED' -Confidence 'Confirmed' -Sources 'Local:DotNetFramework' -Stage 'Run' -Scope 'Local' `
                -Message ('Signatures of certificates and CRLs cannot be checked on this computer: .NET Framework {0} (release {1}) lacks the public-key signature APIs (4.6.2 or later is needed).' -f $runInfo.DotNetVersion, $runInfo.DotNetRelease) `
                -Notes 'Every signature check is reported as "could not be checked", never as an invalid signature.'))
        }
        if ($PSVersionTable.PSEdition -ne 'Desktop') {
            [void]$findings.Add((New-MspkiFinding -Category 'Run' -Role 'Run' -Target 'PowerShell' -Status 'Warning' `
                -StatusCode 'UNSUPPORTED' -Confidence 'Confirmed' -Sources 'Local:PSVersionTable' -Stage 'Run' -Scope 'Local' `
                -Message ('This tool targets Windows PowerShell 5.1; running on {0} {1} is not supported.' -f $PSVersionTable.PSEdition, $runInfo.PSVersion)))
        }
        $sw = Start-MspkiStageTimer -Stage 'Discovery'
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
            # The CA certificate entities must exist before the probes record where each one was seen.
            try { Add-MspkiInventoryToEntityGraph -Inventory $d.Inventory }
            catch { Write-MspkiLog -Level Warning -Message ('Entity graph (discovery part) stopped: {0}' -f $_.Exception.Message) }
            $sw = Start-MspkiStageTimer -Stage 'Analysis:CACertificates'
            try {
                $ctx = $d.Inventory.AdContext
                $dcs = @()
                if ($null -ne $ctx.PSObject.Properties['DomainControllers']) { $dcs = @($ctx.DomainControllers) }
                Reset-MspkiLeadRegistry -LocalDomains @($ctx.ForestDomains) -TrustedDomains @($ctx.TrustedDomains) -DomainControllers $dcs
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
            $sw = Start-MspkiStageTimer -Stage 'Analysis:ADContainers'
            try {
                foreach ($f in (Test-MspkiAdContainerConsistency -Inventory $d.Inventory)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('AD container review stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'ADContainers' -Sources 'Run' -Action 'reviewing the AD PKI containers' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:ADContainers' -Stopwatch $sw
            $sw = Start-MspkiStageTimer -Stage 'Analysis:ADContainerObjects'
            try {
                foreach ($f in (Test-MspkiAdContainerObject -Inventory $d.Inventory)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Template/KRA/OID container review stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'ADContainerObjects' -Sources 'Run' -Action 'reviewing the template, KRA and OID containers' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:ADContainerObjects' -Stopwatch $sw
            $sw = Start-MspkiStageTimer -Stage 'Analysis:Templates'
            try {
                foreach ($f in (Test-MspkiTemplateEnrollmentRisk -Inventory $d.Inventory)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Template review stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'Templates' -Sources 'Run' -Action 'reviewing certificate templates' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:Templates' -Stopwatch $sw
            $sw = Start-MspkiStageTimer -Stage 'Probe:Endpoints'
            try {
                foreach ($f in (Invoke-MspkiEndpointAnalysis -Discovery $d -Thresholds $thresholds -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork)) {
                    [void]$findings.Add($f)
                }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Endpoint checks stopped: {0} | {1}' -f $_.Exception.Message, (($_.ScriptStackTrace -split "`r?`n" | Select-Object -First 6) -join ' <- '))
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'Endpoints' -Sources 'Run' -Action 'checking AIA/CDP/OCSP endpoints' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Probe:Endpoints' -Stopwatch $sw
            Send-MspkiLeadEntityEvent
            $sw = Start-MspkiStageTimer -Stage 'Discovery:LocalPolicy'
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
            $sw = Start-MspkiStageTimer -Stage 'Probe:EnrollmentServices'
            try {
                foreach ($f in (Invoke-MspkiEnrollmentServiceAnalysis -Discovery $d -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('CEP/CES checks stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'EnrollmentServices' -Sources 'Run' -Action 'checking CEP and CES endpoints' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Probe:EnrollmentServices' -Stopwatch $sw
            Send-MspkiLeadEntityEvent
            $sw = Start-MspkiStageTimer -Stage 'Probe:NDES'
            $ndesHosts = @()
            try {
                $ndes = Invoke-MspkiNdesAnalysis -Discovery $d -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork -IncludeAdminProbe:$IncludeNdesAdminProbe
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
            $sw = Start-MspkiStageTimer -Stage 'Discovery:IntuneConnector'
            try {
                $intune = Invoke-MspkiIntuneConnectorAnalysis -NdesHosts $ndesHosts
                foreach ($f in $intune.Findings) { [void]$findings.Add($f) }
                $inventory | Add-Member -NotePropertyName 'IntuneConnector' -NotePropertyValue $intune.Data -Force
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Intune connector check stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'IntuneConnector' -Role 'IntuneConnector' `
                    -Target 'Intune Certificate Connector' -Sources 'Local:Win32_Service' -Action 'checking this computer for the Intune Certificate Connector' -Scope 'Local'))
            }
            Add-MspkiStageTiming -Stage 'Discovery:IntuneConnector' -Stopwatch $sw
            $sw = Start-MspkiStageTimer -Stage 'Analysis:StaleReferences'
            try {
                foreach ($f in (Invoke-MspkiStaleReferenceAnalysis -Discovery $d -Findings @($findings))) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Stale-reference review stopped: {0}' -f $_.Exception.Message)
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'StaleReferences' -Sources 'Run' -Action 'reviewing historical and stale references' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:StaleReferences' -Stopwatch $sw
            $sw = Start-MspkiStageTimer -Stage 'Analysis:Hierarchy'
            try {
                foreach ($f in (Invoke-MspkiHierarchyAnalysis -Discovery $d -Findings @($findings) -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Hierarchy review stopped: {0} | {1}' -f $_.Exception.Message, (($_.ScriptStackTrace -split "`r?`n" | Select-Object -First 6) -join ' <- '))
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Run' -Role 'Run' `
                    -Target 'Hierarchy' -Sources 'Run' -Action 'reviewing the CA hierarchy (generations, AIA/CDP design, OCSP, TLS, certificate names)' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:Hierarchy' -Stopwatch $sw
            $sw = Start-MspkiStageTimer -Stage 'Analysis:LocalEvidence'
            try {
                foreach ($f in (Invoke-MspkiLocalEvidenceAnalysis -Inventory $inventory)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Local evidence review stopped: {0} | {1}' -f $_.Exception.Message, (($_.ScriptStackTrace -split "`r?`n" | Select-Object -First 6) -join ' <- '))
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'LocalEvidence' -Role 'Computer' `
                    -Target 'LocalEvidence' -Sources 'Run' -Action 'reading this computer''s certificates, enrollment events and policy' -Stage 'Run' -Scope 'Local'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:LocalEvidence' -Stopwatch $sw
            $sw = Start-MspkiStageTimer -Stage 'Analysis:Identity'
            try {
                foreach ($f in (Invoke-MspkiEndpointIdentityAnalysis -Inventory $inventory -TimeoutSeconds $TimeoutSeconds -SkipNetwork:$SkipNetwork)) { [void]$findings.Add($f) }
            }
            catch {
                Write-MspkiLog -Level Error -Message ('Endpoint identity review stopped: {0} | {1}' -f $_.Exception.Message, (($_.ScriptStackTrace -split "`r?`n" | Select-Object -First 6) -join ' <- '))
                [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $_) -Category 'Identity' -Role 'Computer' `
                    -Target 'Identity' -Sources 'Run' -Action 'recording endpoint identity (DNS, reverse DNS, aliases, TLS names, Server header) and Web Enrollment' -Stage 'Run'))
            }
            Add-MspkiStageTiming -Stage 'Analysis:Identity' -Stopwatch $sw
            $inventory | Add-Member -NotePropertyName 'Leads'-NotePropertyValue @(Get-MspkiLead | ForEach-Object { ConvertTo-MspkiLeadExport -Lead $_ }) -Force
            $inventory | Add-Member -NotePropertyName 'LeadStatistics' -NotePropertyValue (Get-MspkiLeadStatistic) -Force
        }
        if (Test-MspkiCancelled) { throw (New-Object System.OperationCanceledException('The run was cancelled.')) }
        $completed = $true
    }
    catch [System.OperationCanceledException] {
        Write-MspkiLog -Level Warning -Message 'The run was cancelled by the user; the results are incomplete.'
        [void]$findings.Add((New-MspkiFinding -Category 'Run' -Role 'Run' -Target 'Run' -Status 'Information' -StatusCode 'NOT_APPLICABLE' `
            -Confidence 'Confirmed' -Sources 'Run' -Stage 'Run' -Scope 'Local' `
            -Message 'The run was cancelled before it finished. Stages that had not run are missing and the stage that was running is incomplete, so these results are partial.'))
    }
    finally {
        # Also runs on Ctrl+C, so a partial results.json is still written.
        Restore-MspkiClientTlsProtocol -State $tlsState
        Complete-MspkiRun -Completed $completed
        $exitCode = Get-MspkiExitCode -Findings @($findings) -Incomplete:(-not $completed)
        # "Probable causes and next steps" for every non-passing finding (docs/KNOWLEDGE-SOURCES.md). A failure here never stops the run.
        $nDiag = Add-MspkiFindingDiagnosis -Findings @($findings)
        Write-MspkiLog -Message ('Probable causes and next steps added to {0} finding(s).' -f $nDiag)
        $graph = $null
        try {
            if ($null -ne $inventory) { Add-MspkiInventoryToEntityGraph -Inventory $inventory }
            Add-MspkiFindingEntityLink -Findings @($findings)
            $graph = Get-MspkiEntityGraphExport
            Write-MspkiLog -Message ('Entity graph: {0} entities, {1} observations ({2} expected but missing), {3} relations.' -f $graph.Counts.Entities, $graph.Counts.Observations, $graph.Counts.ExpectedMissing, $graph.Counts.Relations)
        }
        catch { Write-MspkiLog -Level Error -Message ('Entity graph stopped: {0} | {1}' -f $_.Exception.Message, (($_.ScriptStackTrace -split "`r?`n" | Select-Object -First 4) -join ' <- ')) }
        $writeJson = {
            try {
                [void](Export-MspkiJson -Path $resultsPath -RunInfo ([pscustomobject]$runInfo) -Inventory $inventory `
                    -Findings @($findings) -ExitCode $exitCode -Graph $graph)
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
                [void](Add-MspkiFindingDiagnosis -Findings @($findings))
                $exitCode = Get-MspkiExitCode -Findings @($findings) -Incomplete:(-not $completed)
                & $writeJson
            }
        }
    }
    Set-MspkiRunControl -Control $null
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
