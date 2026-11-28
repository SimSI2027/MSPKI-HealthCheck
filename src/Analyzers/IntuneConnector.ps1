# Intune Certificate Connector review (REQUIREMENTS 5.8): LOCAL ONLY. What this computer shows is reported with its
# evidence. Other computers are not checked: remote connector discovery is not reliable without Microsoft Graph,
# and an NDES host is never assumed to be a connector host.

function Test-MspkiIntuneConnector {
    <#
    .SYNOPSIS
    Turns the local evidence and the NDES hosts into findings. Pure function.

    .DESCRIPTION
    Local: documented service or product name = detected (Confirmed: the local read is authoritative; the identification
    rests on a documented name). Only pattern matches = possible components (Inferred). Nothing = not discovered on this
    computer. For every NDES host other than this computer: UNSUPPORTED with the Microsoft Graph note.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Local,
        [AllowEmptyCollection()][object[]]$NdesHosts = @(),
        [string]$ComputerName = (Get-MspkiLocalComputerName),
        [string]$DnsDomain = ''
    )
    $findings = New-Object System.Collections.ArrayList
    $common = @{ Category = 'IntuneConnector'; Role = 'IntuneConnector'; Stage = 'Analysis'; Scope = 'Local' }
    $sources = @('Local:Win32_Service', 'Local:Uninstall', 'Local:CertStore:My')
    if ($null -ne $Local) {
        $ev = @($Local.Evidence)
        $strong = @($ev | Where-Object { $_.Strength -eq 'Documented' })
        $checked = @(('Computer checked: {0} (this computer only)' -f $Local.ComputerName), ('Windows services read: {0}' -f $Local.ServicesChecked),
            ('Installed products that match a connector signature: {0}' -f $Local.ProductsMatched), ('Certificates in the Personal store that match a connector pattern: {0}' -f $Local.CertificatesMatched))
        $localNdes = @($NdesHosts | Where-Object { $_ -and (Test-MspkiIsLocalHost -HostName $_.Host -ComputerName $ComputerName -DnsDomain $DnsDomain) })
        $cross = @()
        foreach ($n in $localNdes) { $cross += ('This computer is also an NDES host ({0}); that is reported separately and is not taken as evidence of the connector.' -f $n.Classification) }
        if ($strong.Count -gt 0) {
            $lines = @($ev | ForEach-Object { '{0} [{1}]: {2}. {3}.' -f $_.Kind, $_.Strength, $_.Text, $_.Basis })
            [void]$findings.Add((New-MspkiFinding @common -Target $Local.ComputerName -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' -Sources $sources `
                -Layers @{ DiscoveryStatus = 'Pass' } -Message ('The Certificate Connector for Microsoft Intune was detected on this computer ({0} documented component(s)).' -f $strong.Count) `
                -Evidence (@($checked) + $lines + $cross) `
                -Notes 'Local detection only. The state of the connector in the Intune service is not visible without Microsoft Graph.'))
        }
        elseif ($ev.Count -gt 0) {
            $lines = @($ev | ForEach-Object { '{0} [{1}]: {2}. {3}.' -f $_.Kind, $_.Strength, $_.Text, $_.Basis })
            [void]$findings.Add((New-MspkiFinding @common -Target $Local.ComputerName -Status 'Information' -StatusCode 'OK' -Confidence 'Inferred' -Sources $sources `
                -Layers @{ DiscoveryStatus = 'Pass' } -Message ('Possible Intune Certificate Connector components were found on this computer ({0} weak match(es)); no documented service or product name matched.' -f $ev.Count) `
                -Evidence (@($checked) + $lines + $cross) `
                -Notes 'Weak evidence only: other software can have similar names. Not reported as a detected connector.'))
        }
        elseif (@($Local.Methods | Where-Object { $_.Outcome -ne 'Success' }).Count -gt 0) {
            $failed = @($Local.Methods | Where-Object { $_.Outcome -ne 'Success' } | ForEach-Object { 'Not read: {0} ({1})' -f $_.Method, $_.Outcome })
            [void]$findings.Add((New-MspkiFinding @common -Target $Local.ComputerName -Status 'Skipped' -StatusCode 'NOT_DISCOVERED' -Confidence 'Unknown' -Sources $sources `
                -Layers @{ DiscoveryStatus = 'Error' } -Message 'No Intune Certificate Connector was found in the parts of this computer that could be read; some parts could not be read.' `
                -Evidence (@($checked) + $failed + $cross) `
                -Notes 'Not discovered is not the same as not present: see the findings about what could not be read.'))
        }
        else {
            [void]$findings.Add((New-MspkiFinding @common -Target $Local.ComputerName -Status 'NotApplicable' -StatusCode 'NOT_DISCOVERED' -Confidence 'Confirmed' -Sources $sources `
                -Layers @{ DiscoveryStatus = 'Pass' } -Message 'No Intune Certificate Connector was found on this computer.' `
                -Evidence (@($checked) + $cross + 'No documented service name, installed product name, install folder or connector-style certificate was found.') `
                -Notes 'Only this computer is checked. The connector may run on another server; remote detection is not reliable without Microsoft Graph.'))
        }
    }
    foreach ($n in @($NdesHosts | Where-Object { $_ -and @('ConfirmedEndpoint', 'ReferencedEndpoint', 'ProbableCandidate') -contains $_.Classification })) {
        if (Test-MspkiIsLocalHost -HostName $n.Host -ComputerName $ComputerName -DnsDomain $DnsDomain) { continue }
        [void]$findings.Add((New-MspkiFinding @common -Target $n.Host -Status 'Skipped' -StatusCode 'UNSUPPORTED' -Confidence 'Unknown' -Sources @('Local:Win32_Service') `
            -Layers @{ DiscoveryStatus = 'Skipped' } `
            -Message ('Whether the NDES host {0} runs the Intune Certificate Connector was not checked: remote connector discovery is not reliable without Microsoft Graph.' -f $n.Host) `
            -Evidence @(('NDES host: {0} ({1})' -f $n.Host, $n.Classification), ('This computer: {0}' -f $ComputerName), 'The connector is detected on the local computer only.') `
            -Notes 'An NDES host is not assumed to be a connector host.'))
    }
    return , $findings.ToArray()
}

function Invoke-MspkiIntuneConnectorAnalysis {
    <#
    .SYNOPSIS
    Reads the local evidence (services, products, certificate metadata) and reviews it together with the NDES hosts.

    .OUTPUTS
    { Findings, Data } (Data goes into the inventory).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$NdesHosts = @())
    $findings = New-Object System.Collections.ArrayList
    $local = Get-MspkiIntuneConnectorLocal
    foreach ($f in $local.Findings) { [void]$findings.Add($f) }
    $me = Get-MspkiLocalComputerIdentity
    foreach ($f in (Test-MspkiIntuneConnector -Local $local.Data -NdesHosts $NdesHosts -ComputerName $me.ComputerName -DnsDomain $me.DnsDomain)) { [void]$findings.Add($f) }
    return [pscustomobject]@{ Findings = @($findings); Data = $local.Data }
}
