# Historical and stale references (REQUIREMENTS 5.9). Review only: every result carries its evidence, and nothing here
# recommends removing anything. Classifications:
#   ActiveConfirmed          referenced by current configuration AND confirmed to answer correctly now
#   CurrentReference         referenced by current configuration, not (fully) confirmed
#   HistoricalReference      found only in historical or expired CA certificates
#   UnreachableReference     the host does not answer (DNS, TCP or timeout), whatever references it
#   StaleReferenceCandidate  ALL of: only expired CA certificates carry it, no current reference, and its host does not
#                            answer. Never decided by host name, OS, age or reachability alone.
# An old URL may still be needed by certificates that have not expired. This tool cannot see issued certificates, so
# the Evidence always says so.

$script:MspkiHostFailureCode = @('DNS_FAIL', 'TCP_FAIL', 'TIMEOUT')
$script:MspkiStaleCaveat = 'An old URL may still be needed by certificates that have not expired. This tool cannot see the certificates a CA issued, so it cannot rule that out.'
$script:MspkiStaleLeadRole = @{ AIA = 'AIAEndpoint'; CDP = 'CDPEndpoint'; FreshestCRL = 'CDPEndpoint'; OCSP = 'OCSPEndpoint'; CES = 'CESEndpoint'; CEP = 'CEPEndpoint'; NDES = 'NDESEndpoint' }
$script:MspkiStaleLeadCategory = @{ AIA = 'AIA'; CDP = 'CDP'; FreshestCRL = 'CDP'; OCSP = 'OCSP'; CES = 'CES'; CEP = 'CEP'; NDES = 'NDES' }

function ConvertTo-MspkiUtcDate {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $d = [DateTime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([DateTime]::TryParse($Text, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function Get-MspkiLeadReferenceFact {
    <#
    .SYNOPSIS
    Works out what references a lead: current configuration (the CA's own URL lists, AD Enrollment Services, policy on
    this computer) and CA certificates (current, historical or expired). Pure function.

    .OUTPUTS
    { Current, CurrentBy, HistoricalOnly, AllCertsExpired, CertSources, Lines, Inferred, Neutral, Classifiable }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lead,
        [AllowNull()]$Inventory,
        [DateTime]$Now = (Get-MspkiUtcNow)
    )
    $currentBy = New-Object System.Collections.ArrayList
    $certs = New-Object System.Collections.ArrayList
    $lines = New-Object System.Collections.ArrayList
    $neutral = 0
    $inferred = $false
    $entries = @()
    if ($null -ne $Inventory) { $entries = @($Inventory.CACertificates) }
    foreach ($s in @($Lead.Sources)) {
        if ($s -match '^CA:(?<n>.+):Cert(Cdp|Aia|AiaOcsp)Urls$') {
            $by = 'the current configuration of Enterprise CA {0} (CA properties, GetCAProperty)' -f $Matches['n']
            if (-not $currentBy.Contains($by)) { [void]$currentBy.Add($by) }
            [void]$lines.Add(('Referenced by {0} [Current, Confirmed]' -f $by))
        }
        elseif ($s -like 'AD:EnrollmentServices:msPKI-Enrollment-Servers') {
            $by = 'the Enrollment Services object in AD (msPKI-Enrollment-Servers)'
            if (-not $currentBy.Contains($by)) { [void]$currentBy.Add($by) }
            [void]$lines.Add(('Referenced by {0} [Current]' -f $by))
        }
        elseif ($s -like 'Policy:CEP:*' -or $s -like 'Local:CEP:*') {
            $by = 'enrollment policy on this computer ({0})' -f $s
            if (-not $currentBy.Contains($by)) { [void]$currentBy.Add($by) }
            [void]$lines.Add(('Referenced by {0} [Current]' -f $by))
        }
        elseif ($s -match '^Cert:(?<tp>[0-9A-Fa-f]+):') {
            $tp = $Matches['tp']
            $e = @($entries | Where-Object { $_.Thumbprint -eq $tp }) | Select-Object -First 1
            if ($null -eq $e) { $neutral++; [void]$lines.Add(('Referenced by certificate {0}, which was downloaded during this run (lifecycle not known)' -f $tp)); continue }
            $na = ConvertTo-MspkiUtcDate -Text ([string]$e.Info.NotAfter)
            $expired = ($null -ne $na -and $na -lt $Now.ToUniversalTime())
            $life = [string]$e.Lifecycle
            if ($e.LifecycleConfidence -ne 'Confirmed') { $inferred = $true }
            $state = 'valid until {0}' -f $e.Info.NotAfter
            if ($expired) { $state = 'EXPIRED {0}' -f $e.Info.NotAfter }
            [void]$lines.Add(('Referenced by CA certificate {0} [{1}]: {2}; lifecycle {3} ({4}{5})' -f $e.Info.Subject, $tp, $state, $life, $e.LifecycleConfidence, $(if ($e.LifecycleBasis) { ', ' + $e.LifecycleBasis } else { '' })))
            if ($life -eq 'Current' -and -not $expired) {
                $by = 'the current CA certificate {0} [{1}]' -f $e.Info.Subject, $tp
                if (-not $currentBy.Contains($by)) { [void]$currentBy.Add($by) }
            }
            else { [void]$certs.Add([pscustomobject]@{ Thumbprint = $tp; Expired = $expired; Lifecycle = $life }) }
        }
        else { $neutral++ }
    }
    $hasCurrent = ($currentBy.Count -gt 0)
    $classifiable = ($hasCurrent -or $certs.Count -gt 0)
    return [pscustomobject][ordered]@{
        Current         = $hasCurrent
        CurrentBy       = @($currentBy)
        HistoricalOnly  = (-not $hasCurrent -and $certs.Count -gt 0)
        AllCertsExpired = ($certs.Count -gt 0 -and @($certs | Where-Object { -not $_.Expired }).Count -eq 0)
        CertSources     = $certs.Count
        Lines           = @($lines)
        Inferred        = $inferred
        Neutral         = $neutral
        Classifiable    = $classifiable
    }
}

function Get-MspkiLeadProbeOutcome {
    <#
    .SYNOPSIS
    Summarises what the probes found for the URL variants of a lead: Responding, Partial (answers with a problem),
    Failing (answers, but not as expected), Unreachable (DNS, TCP or timeout) or NotTested. Pure function over findings.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Lead, [AllowEmptyCollection()][object[]]$Findings = @())
    $variants = @($Lead.Variants)
    if ($variants.Count -eq 0) { $variants = @($Lead.Url) }
    $mine = @($Findings | Where-Object { $_ -and $_.Endpoint -and $variants -contains $_.Endpoint -and $script:MspkiStaleLeadCategory.Values -contains $_.Category })
    $out = [pscustomobject][ordered]@{ State = 'NotTested'; Layer = ''; Code = ''; Lines = @(); Findings = $mine.Count }
    if ($mine.Count -eq 0) { $out.Lines = @('Probe: no probe result (not probed, for example because of -SkipNetwork, or the URL type is not probed)'); return $out }
    $lines = New-Object System.Collections.ArrayList
    foreach ($f in $mine) { [void]$lines.Add(('Probe result {0}: {1}/{2} (DNS {3}, TCP {4}, TLS {5}, HTTP {6}, content {7}) - {8}' -f $f.Id, $f.Status, $f.StatusCode, $f.DnsStatus, $f.TcpStatus, $f.TlsStatus, $f.HttpStatus, $f.ContentStatus, $f.Message)) }
    $out.Lines = @($lines)
    $real = @($mine | Where-Object { $_.Status -ne 'Skipped' -and $_.Status -ne 'NotApplicable' })
    if ($real.Count -eq 0) { return $out }
    $pass = @($real | Where-Object { $_.Status -eq 'Pass' -or ($_.Status -eq 'Information' -and $_.StatusCode -eq 'OK') })
    # A result that was turned into a review item (a lead carried only by historical or expired certificates) keeps its status code.
    $bad = @($real | Where-Object { @('Fail', 'Warning', 'Critical', 'Error') -contains $_.Status -or ($_.Severity -eq 'ReviewRequired' -and @('OK', 'NOT_APPLICABLE') -notcontains $_.StatusCode) })
    $nonHost = @($bad | Where-Object { $script:MspkiHostFailureCode -notcontains $_.StatusCode })
    if ($pass.Count -gt 0 -and $nonHost.Count -eq 0) { $out.State = 'Responding'; return $out }
    if ($pass.Count -gt 0) { $out.State = 'Partial'; $out.Code = $nonHost[0].StatusCode; return $out }
    $hostFail = @($bad | Where-Object { $script:MspkiHostFailureCode -contains $_.StatusCode })
    if ($hostFail.Count -gt 0 -and $nonHost.Count -eq 0) {
        $out.State = 'Unreachable'; $out.Code = $hostFail[0].StatusCode
        $out.Layer = switch ($hostFail[0].StatusCode) { 'DNS_FAIL' { 'DNS' } 'TCP_FAIL' { 'TCP' } default { 'timeout' } }
        return $out
    }
    if ($nonHost.Count -gt 0) { $out.State = 'Failing'; $out.Code = $nonHost[0].StatusCode; return $out }
    return $out
}

function Get-MspkiStaleClassification {
    <#
    .SYNOPSIS
    The decision table. Returns { Class, Rule } from the reference facts and the probe outcome.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Reference, [Parameter(Mandatory = $true)]$Outcome)
    if ($Reference.Current) {
        if ($Outcome.State -eq 'Responding') { return [pscustomobject]@{ Class = 'ActiveConfirmed'; Rule = 'current reference and the probe confirmed it' } }
        if ($Outcome.State -eq 'Unreachable') { return [pscustomobject]@{ Class = 'UnreachableReference'; Rule = 'current reference whose host does not answer' } }
        return [pscustomobject]@{ Class = 'CurrentReference'; Rule = 'current reference, not fully confirmed' }
    }
    if ($Outcome.State -eq 'Unreachable') {
        if ($Reference.AllCertsExpired) { return [pscustomobject]@{ Class = 'StaleReferenceCandidate'; Rule = 'only expired CA certificates carry it, no current reference, and the host does not answer' } }
        return [pscustomobject]@{ Class = 'UnreachableReference'; Rule = 'only historical CA certificates carry it (at least one has not expired) and the host does not answer' }
    }
    return [pscustomobject]@{ Class = 'HistoricalReference'; Rule = 'carried only by historical or expired CA certificates' }
}

function Test-MspkiStaleReference {
    <#
    .SYNOPSIS
    Classifies every reference (lead) and every Enterprise CA object, with evidence on every result. Review only.

    .PARAMETER Leads
    Lead objects from the lead registry. Findings: every finding of the run so far (probe results).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$Inventory,
        [AllowEmptyCollection()][object[]]$Leads = @(),
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [DateTime]$Now = (Get-MspkiUtcNow)
    )
    $out = New-Object System.Collections.ArrayList
    $common = @{ Category = 'StaleRef'; Stage = 'Analysis' }
    $active = New-Object System.Collections.ArrayList
    $counts = [ordered]@{ ActiveConfirmed = 0; CurrentReference = 0; HistoricalReference = 0; UnreachableReference = 0; StaleReferenceCandidate = 0 }
    $unclassified = 0
    foreach ($lead in @($Leads | Where-Object { $_ -and $script:MspkiStaleLeadCategory.ContainsKey([string]$_.Kind) } | Sort-Object { $_.Id })) {
        $ref = Get-MspkiLeadReferenceFact -Lead $lead -Inventory $Inventory -Now $Now
        if (-not $ref.Classifiable) { $unclassified++; continue }
        $probe = Get-MspkiLeadProbeOutcome -Lead $lead -Findings $Findings
        $c = Get-MspkiStaleClassification -Reference $ref -Outcome $probe
        $counts[$c.Class]++
        $variants = @($lead.Variants); if ($variants.Count -eq 0) { $variants = @($lead.Url) }
        $head = @(('Classification: {0}' -f $c.Class), ('Rule: {0}' -f $c.Rule), ('Reference: {0} (kind {1}, lead {2}, depth {3}); URL variants: {4}' -f $lead.Url, $lead.Kind, $lead.Id, $lead.Depth, ($variants -join ' | ')))
        $head += @($lead.Origins | ForEach-Object { 'Found in: {0}' -f $_ })
        $facts = @($ref.Lines)
        $facts += ('Current reference: {0}' -f $(if ($ref.Current) { 'yes (' + ($ref.CurrentBy -join '; ') + ')' } else { 'no' }))
        if (-not $ref.Current) { $facts += ('CA certificates that carry it: {0}; all of them expired: {1}' -f $ref.CertSources, $ref.AllCertsExpired) }
        $facts += ('Probe outcome: {0}{1}' -f $probe.State, $(if ($probe.Layer) { ' at ' + $probe.Layer } else { '' }))
        $ev = @($head) + $facts + @($probe.Lines)
        $conf = 'Referenced'
        if ($ref.Inferred) { $conf = 'Inferred' }
        $target = $lead.Host; if (-not $target) { $target = $lead.Url }
        $role = $script:MspkiStaleLeadRole[[string]$lead.Kind]
        $lcommon = @{ Role = $role; Target = $target; Endpoint = $lead.Url; RelatedCA = (@($lead.RelatedCAs) -join ', '); Scope = $lead.Scope; Sources = @($lead.Sources) }
        if ($c.Class -eq 'ActiveConfirmed') { [void]$active.Add(('{0} - {1}' -f $lead.Url, ($ref.CurrentBy -join '; '))); continue }
        switch ($c.Class) {
            'CurrentReference' {
                $st = 'Information'; $code = 'OK'; $msg = ('{0} is referenced by current configuration but not confirmed to answer correctly (CurrentReference).' -f $lead.Url)
                if ($probe.State -eq 'Partial' -or $probe.State -eq 'Failing') { $st = 'Warning'; $code = $probe.Code; $msg = ('{0} is referenced by current configuration but the probe found a problem: {1} (CurrentReference).' -f $lead.Url, $probe.Code) }
                if ($probe.State -eq 'NotTested') { $code = 'NOT_APPLICABLE' }
                [void]$out.Add((New-MspkiFinding @common @lcommon -Status $st -StatusCode $code -Confidence $conf -Message $msg -Evidence $ev -Layers @{ DiscoveryStatus = 'Pass' }))
            }
            'HistoricalReference' {
                [void]$out.Add((New-MspkiFinding @common @lcommon -Status 'Information' -StatusCode 'OK' -Confidence $conf -Layers @{ DiscoveryStatus = 'Pass' } `
                    -Message ('{0} is found only in historical or expired CA certificates (HistoricalReference); probe outcome: {1}.' -f $lead.Url, $probe.State) `
                    -Evidence (@($ev) + $script:MspkiStaleCaveat) -Notes 'Review only. A historical reference is normal while certificates issued under an older CA certificate are still valid.'))
            }
            'UnreachableReference' {
                $st = 'Information'; $why = 'carried only by historical CA certificates'
                if ($ref.Current) { $st = 'Warning'; $why = 'referenced by current configuration' }
                [void]$out.Add((New-MspkiFinding @common @lcommon -Status $st -StatusCode $probe.Code -Confidence $conf -Layers @{ DiscoveryStatus = 'Pass' } `
                    -Message ('{0} does not answer ({1}; UnreachableReference); it is {2}.' -f $lead.Url, $probe.Layer, $why) `
                    -Evidence (@($ev) + $script:MspkiStaleCaveat) `
                    -Notes 'Review only. Unreachable is a fact about now; whether the reference is still needed depends on the certificates that carry it.'))
            }
            'StaleReferenceCandidate' {
                [void]$out.Add((New-MspkiFinding @common @lcommon -Status 'Information' -StatusCode 'STALE_REFERENCE' -Severity 'ReviewRequired' -Confidence 'Inferred' -Layers @{ DiscoveryStatus = 'Pass' } `
                    -Message ('{0} is a stale-reference candidate: only expired CA certificates carry it and its host does not answer ({1}).' -f $lead.Url, $probe.Layer) `
                    -Evidence (@($ev) + $script:MspkiStaleCaveat + 'A candidate is not a conclusion: it combines three facts (expired carriers only, no current reference, host does not answer), none of which is enough alone.') `
                    -Notes 'Review only. Nothing here is a recommendation to change anything.'))
            }
        }
    }

    # Enterprise CA objects
    foreach ($ca in @($Inventory.EnterpriseCAs)) {
        if ($null -eq $ca) { continue }
        $mine = @($Inventory.CACertificates | Where-Object { $_.CAName -eq $ca.Name })
        $expiredAll = ($mine.Count -gt 0)
        $lines = @(('Enterprise CA object: {0} (host {1}, whenChanged {2})' -f $ca.Name, $ca.DnsHostName, $ca.WhenChanged))
        foreach ($m in $mine) {
            $na = ConvertTo-MspkiUtcDate -Text ([string]$m.Info.NotAfter)
            $exp = ($null -ne $na -and $na -lt $Now.ToUniversalTime())
            if (-not $exp) { $expiredAll = $false }
            $lines += ('CA certificate {0} [{1}]: lifecycle {2}, valid until {3}{4}' -f $m.Info.Subject, $m.Thumbprint, $m.Lifecycle, $m.Info.NotAfter, $(if ($exp) { ' (EXPIRED)' } else { '' }))
        }
        if ($mine.Count -eq 0) { $lines += 'CA certificates for this CA: none found' }
        $cf = @($Findings | Where-Object { $_ -and $_.Category -eq 'CA' -and $_.Target -eq $ca.Name -and $script:MspkiHostFailureCode -contains $_.StatusCode })
        $perm = @($Findings | Where-Object { $_ -and $_.Category -eq 'CA' -and $_.Target -eq $ca.Name -and $_.StatusCode -eq 'PERMISSION_DENIED' })
        foreach ($f in $cf) { $lines += ('CA probe {0}: {1}/{2} (DNS {3}, TCP {4}) - {5}' -f $f.Id, $f.Status, $f.StatusCode, $f.DnsStatus, $f.TcpStatus, $f.Message) }
        foreach ($f in $perm) { $lines += ('CA probe {0}: {1}/{2} - {3}' -f $f.Id, $f.Status, $f.StatusCode, $f.Message) }
        $answered = ($null -ne $ca.Properties)
        $hostGone = ($cf.Count -gt 0 -and -not $answered)
        $layer = ''; if ($hostGone) { $layer = switch ($cf[0].StatusCode) { 'DNS_FAIL' { 'DNS' } 'TCP_FAIL' { 'TCP 135' } default { 'timeout' } } }
        $lines += ('The CA answered with its properties: {0}' -f $(if ($answered) { 'yes' } else { 'no' }))
        $tgt = @{ Role = 'Unknown'; Target = $ca.Name; Endpoint = $ca.Config; RelatedCA = $ca.Name; Scope = 'Local'; Sources = @('AD:EnrollmentServices', 'CA:GetCAProperty') }
        if ($hostGone -and $expiredAll) {
            $counts['StaleReferenceCandidate']++
            [void]$out.Add((New-MspkiFinding @common @tgt -Status 'Information' -StatusCode 'STALE_REFERENCE' -Severity 'ReviewRequired' -Confidence 'Inferred' -Layers @{ DiscoveryStatus = 'Pass' } `
                -Message ('The Enterprise CA object {0} is a stale-reference candidate: every CA certificate for it has expired and its host does not answer ({1}).' -f $ca.Name, $layer) `
                -Evidence (@('Classification: StaleReferenceCandidate', 'Rule: every CA certificate for the object has expired, and the CA host does not answer; neither fact alone is enough') + $lines + 'The object is still registered in Active Directory; this tool does not change it.') `
                -Notes 'Review only. A CA that is offline on purpose can look like this; confirm with the owners of the PKI.'))
        }
        elseif ($hostGone) {
            $counts['UnreachableReference']++
            [void]$out.Add((New-MspkiFinding @common @tgt -Status 'Warning' -StatusCode $cf[0].StatusCode -Confidence 'Referenced' -Layers @{ DiscoveryStatus = 'Pass' } `
                -Message ('The Enterprise CA object {0} is registered in AD, but its host does not answer ({1}; UnreachableReference).' -f $ca.Name, $layer) `
                -Evidence (@('Classification: UnreachableReference', 'Rule: registered Enterprise CA object whose host does not answer; at least one CA certificate has not expired') + $lines) `
                -Notes 'Review only. A permission problem is a different finding and is not treated as unreachable.'))
        }
        elseif ($answered) {
            $counts['ActiveConfirmed']++
            [void]$active.Add(('Enterprise CA {0} - the CA answered with its properties' -f $ca.Name))
        }
        else {
            $counts['CurrentReference']++
            $why = 'its properties were not read'
            [void]$out.Add((New-MspkiFinding @common @tgt -Status 'Information' -StatusCode 'OK' -Confidence 'Referenced' -Layers @{ DiscoveryStatus = 'Pass' } `
                -Message ('The Enterprise CA object {0} is registered in AD ({1}); not confirmed (CurrentReference).' -f $ca.Name, $why) `
                -Evidence (@('Classification: CurrentReference', 'Rule: registered Enterprise CA object that was not confirmed by the CA itself') + $lines)))
        }
    }

    # Summary: every classification with its count; ActiveConfirmed references are listed here, as evidence.
    $sumEv = @($counts.Keys | ForEach-Object { '{0}: {1}' -f $_, $counts[$_] })
    $sumEv += ('References not classified (only found in certificates downloaded during the run, CRLs or constructed candidates): {0}' -f $unclassified)
    $sumEv += @($active | Select-Object -First 300 | ForEach-Object { 'ActiveConfirmed: {0}' -f $_ })
    $sumEv += $script:MspkiStaleCaveat
    [void]$out.Add((New-MspkiFinding @common -Role 'Run' -Target 'References' -Status 'Information' -StatusCode 'OK' -Confidence 'Referenced' -Scope 'Local' `
        -Sources @('AD:EnrollmentServices', 'CA:GetCAProperty', 'Probe results') -Layers @{ DiscoveryStatus = 'Pass' } `
        -Message ('Reference review: {0} active and confirmed, {1} current, {2} historical, {3} unreachable, {4} stale candidate(s).' -f $counts.ActiveConfirmed, $counts.CurrentReference, $counts.HistoricalReference, $counts.UnreachableReference, $counts.StaleReferenceCandidate) `
        -Evidence $sumEv -Notes 'Review only. A classification is not a recommendation to change anything.'))
    return , $out.ToArray()
}

function Invoke-MspkiStaleReferenceAnalysis {
    <#
    .SYNOPSIS
    Runs the stale-reference review over the discovery inventory, the lead registry and the findings of the run.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Discovery, [AllowEmptyCollection()][object[]]$Findings = @())
    return (Test-MspkiStaleReference -Inventory $Discovery.Inventory -Leads @(Get-MspkiLead) -Findings $Findings)
}
