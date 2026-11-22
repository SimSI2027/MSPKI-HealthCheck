# Local evidence analysis (ROADMAP D3, stage Analysis:LocalEvidence): how this computer's certificates got here (template, issuing CA,
# the Lifecycle event that installed them and the policy behind it), whether the AD trust containers reached this computer's stores, what
# autoenrollment reported, and the enrollment policy cache. Everything is linked into the entity graph. Reads only (see LocalEvidence.ps1).

function Get-MspkiCertificateOrigin {
    <#
    .SYNOPSIS
    How one certificate got onto this computer, from its Lifecycle events and the local policy. Pure: { How; Confidence; Installed; By }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Info,
        [AllowEmptyCollection()][object[]]$Events = @(),
        [string]$RdpTemplate = '',
        [bool]$AutoEnrollmentEnabled = $false
    )
    $inst = @($Events | Where-Object { $_.Action -in @('Enroll', 'Installed', 'Replaced', 'Renew', 'Import') } | Sort-Object Time -Descending) | Select-Object -First 1
    $tname = $(if ($Info.TemplateName) { $Info.TemplateName } else { $Info.TemplateDisplay })
    if ($null -eq $inst) {
        $how = $(if ($tname) { 'issued from the template {0} by {1}; no Lifecycle event on this computer says how it was installed (the log may have been cleared, or the certificate was imported)' -f $tname, $Info.Issuer } else { 'no template extension and no Lifecycle event: imported or requested outside the Windows enrollment client' })
        return [pscustomobject][ordered]@{ How = $how; Confidence = 'Inferred'; Installed = ''; By = '' }
    }
    $p = ([string]$inst.Process).ToLowerInvariant()
    $by = ('{0} as {1} ({2} context)' -f $inst.Process, $inst.Account, $inst.Context).Trim()
    $how = ''; $conf = 'Confirmed'
    if ($p -in @('svchost.exe', 'taskhostw.exe', 'taskhost.exe')) {
        if ($RdpTemplate -and $tname -and $RdpTemplate -ieq $tname) { $how = ('enrolled by Windows in the background for the Remote Desktop certificate policy (Group Policy names the template {0})' -f $RdpTemplate) }
        elseif ($AutoEnrollmentEnabled) { $how = 'enrolled by Windows in the background: autoenrollment (the policy is enabled on this computer)' }
        else { $how = 'enrolled by Windows in the background (autoenrollment or another policy-driven enrollment)'; $conf = 'Inferred' }
    }
    elseif ($p -eq 'mmc.exe') { $how = ('requested by {0} in the Certificates console (a manual request)' -f $inst.Account) }
    elseif ($p -eq 'certreq.exe') { $how = ('requested by {0} with certreq (a manual or scripted request)' -f $inst.Account) }
    elseif ($p) { $how = ('installed by {0} as {1}' -f $inst.Process, $inst.Account) }
    else { $how = ('installed ({0} event, no process recorded)' -f $inst.Action); $conf = 'Inferred' }
    if ($tname) { $how += ('; template {0}' -f $tname) }
    return [pscustomobject][ordered]@{ How = $how; Confidence = $conf; Installed = $inst.Time; By = $by }
}

function Test-MspkiTrustStoreCoverage {
    <#
    .SYNOPSIS
    Whether the CA certificates that AD publishes for clients reached this computer's store. Pure. Returns one finding.
    .PARAMETER Expected
    { Thumbprint; Subject } of the certificates that should be there (not expired).
    .PARAMETER Present
    Thumbprints in the local store (logical view: local, Group Policy and Enterprise physical stores).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Container,
        [Parameter(Mandatory = $true)][string]$Store,
        [AllowEmptyCollection()][object[]]$Expected = @(),
        [AllowEmptyCollection()][string[]]$Present = @(),
        [AllowEmptyCollection()][string[]]$Enterprise = @(),
        [string]$Why = '',
        [string[]]$EntityIds = @()
    )
    $missing = @($Expected | Where-Object { @($Present) -notcontains ([string]$_.Thumbprint).ToUpperInvariant() })
    $ev = @($Expected | ForEach-Object {
        $t = ([string]$_.Thumbprint).ToUpperInvariant()
        '{0} [{1}]: {2}' -f $_.Subject, $t, $(if (@($Present) -notcontains $t) { 'MISSING' } elseif (@($Enterprise) -contains $t) { 'present (Enterprise store, copied from AD)' } else { 'present (local or Group Policy store)' }) })
    $common = @{ Category = 'LocalEvidence'; Role = 'Computer'; Target = $Store; Sources = @(('Local:CertStore:{0}' -f $Store), ('AD:{0}' -f $Container)); Confidence = 'Confirmed'; Stage = 'Analysis'; Scope = 'Local'; EntityIds = $EntityIds }
    if ($missing.Count -gt 0) {
        return (New-MspkiFinding @common -Status 'Warning' -StatusCode 'PUBLICATION_FAIL' -Severity 'Medium' `
            -Message ('{0} of {1} certificate(s) that AD publishes in {2} are not in this computer''s {3} store: {4}.' -f $missing.Count, @($Expected).Count, $Container, $Store, (($missing | ForEach-Object { $_.Subject }) -join '; ')) `
            -Evidence @($ev) -Notes $Why `
            -Remediation 'Windows copies these certificates from AD during the Group Policy / autoenrollment refresh (about every 8 hours). Check that this computer applies Group Policy and can read the Public Key Services container; an administrator can run "gpupdate /force". Nothing is changed by this tool.')
    }
    return (New-MspkiFinding @common -Status 'Pass' -StatusCode 'OK' -Message ('All {0} certificate(s) that AD publishes in {1} are in this computer''s {2} store.' -f @($Expected).Count, $Container, $Store) -Evidence @($ev))
}

function Invoke-MspkiLocalEvidenceAnalysis {
    <#
    .SYNOPSIS
    Stage Analysis:LocalEvidence: reads this computer's stores, Lifecycle and autoenrollment events and enrollment policy, links them to the
    discovered CAs and templates in the graph, and returns the findings.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Inventory, [DateTime]$Now = [DateTime]::UtcNow)
    $out = New-Object System.Collections.ArrayList
    $mk = { param([hashtable]$P) $P['Category'] = 'LocalEvidence'; $P['Role'] = 'Computer'; $P['Stage'] = 'Analysis'; $P['Scope'] = 'Local'; New-MspkiFinding @P }
    $templates = @($Inventory.Templates | Where-Object { $null -ne $_ })
    $tByOid = @{}; $tByName = @{}
    foreach ($t in $templates) { if ($t.Oid) { $tByOid[[string]$t.Oid] = $t }; $tByName[([string]$t.Name).ToLowerInvariant()] = $t }

    # Known CA keys: SKI of every CA certificate generation in the graph.
    $skiToCert = @{}
    foreach ($e in @(Get-MspkiEntityList -Type 'CACertificate')) { $k = ConvertTo-MspkiKeyIdHex ([string]$e.Properties['SubjectKeyId']); if ($k) { $skiToCert[$k] = $e.Id } }

    # Reads (each one recorded as a method outcome, failures as findings with permission and other errors kept apart).
    $stores = [ordered]@{}
    foreach ($s in @(@('CurrentUser', 'My'), @('LocalMachine', 'My'), @('LocalMachine', 'Root'), @('LocalMachine', 'CA'), @('LocalMachine', 'NTAuth'))) {
        $r = Read-MspkiLocalStore -Location $s[0] -Name $s[1]
        $stores[$r.Store] = $r
        if ($null -ne $r.Error) {
            Add-MspkiMethodOutcome -Method ('Local:CertStore:{0}' -f $r.Store) -Outcome $r.Error.Class -Detail $r.Error.Message
            [void]$out.Add((New-MspkiErrorFinding -ErrorInfo $r.Error -Category 'LocalEvidence' -Role 'Computer' -Target $r.Store -Sources ('Local:CertStore:{0}' -f $r.Store) -Action ('reading the certificate store {0}' -f $r.Store) -Scope 'Local'))
        }
        else { Add-MspkiMethodOutcome -Method ('Local:CertStore:{0}' -f $r.Store) -Outcome 'Success' -Detail ('{0} certificate(s)' -f @($r.Certificates).Count) }
    }
    $ent = @{}
    foreach ($n in @('Root', 'CA', 'NTAuth')) { $x = Get-MspkiEnterpriseStoreThumbprint -Name $n; $ent[$n] = @($x.Thumbprints) }
    $lc = Get-MspkiLifecycleEvent
    foreach ($l in @($lc.Logs)) {
        if ($l.Read) { Add-MspkiMethodOutcome -Method ('Local:EventLog:{0}' -f $l.Name) -Outcome 'Success' -Detail ('{0} event(s)' -f $l.Count) }
        else {
            Add-MspkiMethodOutcome -Method ('Local:EventLog:{0}' -f $l.Name) -Outcome $l.Error.Class -Detail $l.Error.Message
            [void]$out.Add((New-MspkiErrorFinding -ErrorInfo $l.Error -Category 'LocalEvidence' -Role 'Computer' -Target $l.Name -Sources ('Local:EventLog:{0}' -f $l.Name) -Action ('reading the event log {0}' -f $l.Name) -Scope 'Local'))
        }
    }
    $ae = Get-MspkiEnrollmentEvent
    if ($null -ne $ae.Error) {
        Add-MspkiMethodOutcome -Method 'Local:EventLog:Application:CertificateServicesClient' -Outcome $ae.Error.Class -Detail $ae.Error.Message
        [void]$out.Add((New-MspkiErrorFinding -ErrorInfo $ae.Error -Category 'LocalEvidence' -Role 'Computer' -Target 'Application log' -Sources 'Local:EventLog:Application' -Action 'reading the autoenrollment events in the Application log' -Scope 'Local'))
    }
    else { Add-MspkiMethodOutcome -Method 'Local:EventLog:Application:CertificateServicesClient' -Outcome 'Success' -Detail ('{0} event(s)' -f @($ae.Events).Count) }
    $pol = Get-MspkiEnrollmentPolicyState
    $aeOn = @($pol.AutoEnrollment | Where-Object { $_.Configured -and (([int64]$_.AEPolicy -band 1) -ne 0) -and (([int64]$_.AEPolicy -band 0x8000) -eq 0) }).Count -gt 0
    $rdpT = [string]$pol.RdpTemplate.Template
    $lcByThumb = @{}
    foreach ($e in @($lc.Events | Where-Object { $_.Thumbprint })) { if (-not $lcByThumb.ContainsKey($e.Thumbprint)) { $lcByThumb[$e.Thumbprint] = New-Object System.Collections.ArrayList }; [void]$lcByThumb[$e.Thumbprint].Add($e) }

    # 1. Personal stores: certificates from this forest's PKI (issued by a discovered CA, or from a template that exists in AD).
    foreach ($sp in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
        $st = $stores[$sp]
        if ($null -ne $st.Error) { continue }
        $other = 0
        foreach ($c in @($st.Certificates)) {
            $i = ConvertTo-MspkiLocalCertificateInfo -Certificate $c -Store $sp -Now $Now
            $tpl = $null
            if ($i.TemplateOid -and $tByOid.ContainsKey($i.TemplateOid)) { $tpl = $tByOid[$i.TemplateOid] }
            elseif ($i.TemplateName -and $tByName.ContainsKey($i.TemplateName.ToLowerInvariant())) { $tpl = $tByName[$i.TemplateName.ToLowerInvariant()] }
            $issuerId = $(if ($i.Aki -and $skiToCert.ContainsKey($i.Aki)) { $skiToCert[$i.Aki] } else { '' })
            if (-not $issuerId -and $null -eq $tpl) { $other++; continue }
            $i | Add-Member -NotePropertyName 'TemplateDisplay' -NotePropertyValue $(if ($null -ne $tpl) { [string]$tpl.Name } elseif ($i.TemplateOid) { $i.TemplateOid } else { '' }) -Force
            $evs = @(); if ($lcByThumb.ContainsKey($i.Thumbprint)) { $evs = @($lcByThumb[$i.Thumbprint]) }
            $o = Get-MspkiCertificateOrigin -Info $i -Events $evs -RdpTemplate $rdpT -AutoEnrollmentEnabled $aeOn
            $id = Add-MspkiEntity -Type 'LocalCertificate' -Key $i.Thumbprint -Name $i.Subject -Properties @{ Subject = $i.Subject; Issuer = $i.Issuer; NotBefore = $i.NotBefore; NotAfter = $i.NotAfter; Expired = $i.Expired
                Template = [string]$i.TemplateDisplay; TemplateOid = $i.TemplateOid; Eku = @($i.Eku); DnsNames = @($i.DnsNames); Origin = $o.How; Installed = $o.Installed; InstalledBy = $o.By }
            $e = Get-MspkiEntity -Id $id
            $e.Properties['Origin'] = $o.How
            if (@($e.Properties['Stores']) -notcontains $sp) { $e.Properties['Stores'] = @(@($e.Properties['Stores']) + $sp | Where-Object { $_ }) }
            Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'LocalStore' -Location $sp -Confidence 'Confirmed' -Detail ('valid until {0}{1}' -f $i.NotAfter, $(if ($i.Expired) { ' (expired)' } else { '' }))
            foreach ($ev in $evs) { Add-MspkiObservation -EntityId $id -Kind 'Seen' -Source 'EventLog' -Location ('{0} event {1}' -f $ev.Log, $ev.EventId) -Confidence 'Confirmed' -Detail ('{0} by {1} as {2} at {3}' -f $ev.Action, $ev.Process, $ev.Account, $ev.Time) -Timestamp $ev.Time }
            if ($issuerId) { Add-MspkiRelation -From $id -Type 'issuedBy' -To $issuerId -Source 'Certificate:AuthorityKeyIdentifier' -Confidence 'Confirmed' }
            if ($null -ne $tpl) { Add-MspkiRelation -From $id -Type 'references' -To (Get-MspkiEntityId -Type 'Template' -Key $tpl.Name) -Source 'Certificate:TemplateExtension' -Confidence 'Confirmed' }
            $evd = @(('Store: {0}' -f $sp), ('Issuer: {0}{1}' -f $i.Issuer, $(if ($issuerId) { ' (a CA certificate found in this run)' } else { ' (not a CA certificate found in this run)' })),
                ('Template: {0}' -f $(if ($i.TemplateDisplay) { '{0}{1}' -f $i.TemplateDisplay, $(if ($i.TemplateOid) { ' (' + $i.TemplateOid + ')' } else { '' }) } else { 'none in the certificate' })),
                ('Valid: {0} to {1}{2}' -f $i.NotBefore, $i.NotAfter, $(if ($i.Expired) { ' (EXPIRED)' } else { '' })))
            if (@($i.DnsNames).Count) { $evd += ('DNS names: {0}' -f (@($i.DnsNames) -join ', ')) }
            foreach ($ev in $evs) { $evd += ('Lifecycle event {0} ({1}) at {2}: {3} by {4} as {5}, {6} context' -f $ev.EventId, $ev.Action, $ev.Time, $(if ($ev.TemplateName) { 'template ' + $ev.TemplateName } else { 'no template' }), $ev.Process, $ev.Account, $ev.Context) }
            if ($rdpT) { $evd += ('Remote Desktop certificate template policy: {0}' -f $rdpT) }
            [void]$out.Add((& $mk @{ Target = ('{0} [{1}]' -f $i.Subject, $i.Thumbprint); Status = 'Information'; StatusCode = 'OK'; Confidence = $o.Confidence
                Sources = @(('Local:CertStore:{0}' -f $sp), 'Local:EventLog:Lifecycle', 'Certificate:TemplateExtension')
                Message = ('How {0} ({1}) got here: {2}.' -f $i.Subject, $sp, $o.How); Evidence = $evd; EntityIds = @(@($id, $issuerId) | Where-Object { $_ }) }))
        }
        if ($other -gt 0) { Write-MspkiLog -Message ('{0}: {1} certificate(s) from issuers outside this forest''s PKI (not analysed)' -f $sp, $other) }
    }

    # 2. Trust stores: did what AD publishes reach this computer? (Logical store view: local, Group Policy and Enterprise physical stores.)
    $caCerts = @($Inventory.CACertificates | Where-Object { $null -ne $_ -and $_.Thumbprint })
    $notExpired = { param($c) $na = $null; try { $na = [DateTime]::Parse([string]$c.Info.NotAfter, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') } catch { }; ($null -eq $na -or $na -gt $Now) }
    $checks = @(
        @{ Container = 'Certification Authorities'; Store = 'Cert:\LocalMachine\Root'; Ent = 'Root'; Pick = { param($c) $c.InCertificationAuthorities }; Why = 'Clients trust an Enterprise root only once it is in their Root store; certificates that chain to a missing root fail on this computer.' }
        @{ Container = 'AIA'; Store = 'Cert:\LocalMachine\CA'; Ent = 'CA'; Pick = { param($c) $c.InAIA -and -not $c.Info.SelfIssued }; Why = 'Windows preloads the intermediate certificates from the AIA container so chains build without a download.' }
        @{ Container = 'NTAuthCertificates'; Store = 'Cert:\LocalMachine\NTAuth'; Ent = 'NTAuth'; Pick = { param($c) $c.InNTAuth }; Why = 'Smart card, certificate and Windows Hello logon (and some other authentications) accept only certificates whose issuing CA is in the NTAuth store of the computer that checks them.' }
    )
    foreach ($ch in $checks) {
        $st = $stores[$ch.Store]
        if ($null -ne $st.Error) { continue }
        $exp = @($caCerts | Where-Object { (& $ch.Pick $_) -and (& $notExpired $_) } | ForEach-Object { [pscustomobject]@{ Thumbprint = $_.Thumbprint; Subject = $(if ($_.Info.Subject) { $_.Info.Subject } else { $_.CAName }) } })
        if ($exp.Count -eq 0) { continue }
        $present = @($st.Certificates | ForEach-Object { $_.Thumbprint.ToUpperInvariant() })
        $ids = New-Object System.Collections.ArrayList
        foreach ($x in $exp) {
            $cid = Get-MspkiEntityId -Type 'CACertificate' -Key $x.Thumbprint
            if (-not (Test-MspkiEntity -Id $cid)) { continue }
            [void]$ids.Add($cid)
            $t = ([string]$x.Thumbprint).ToUpperInvariant()
            if ($present -contains $t) { Add-MspkiObservation -EntityId $cid -Kind 'Seen' -Source 'LocalStore' -Location $ch.Store -Confidence 'Confirmed' -Detail $(if (@($ent[$ch.Ent]) -contains $t) { 'Enterprise store (copied from AD)' } else { 'local or Group Policy store' }) }
            else { Add-MspkiObservation -EntityId $cid -Kind 'ExpectedMissing' -Source 'LocalStore' -Location $ch.Store -Confidence 'Confirmed' -Detail ('Published in AD {0}; not in this computer''s store' -f $ch.Container) }
        }
        [void]$out.Add((Test-MspkiTrustStoreCoverage -Container $ch.Container -Store $ch.Store -Expected $exp -Present $present -Enterprise @($ent[$ch.Ent]) -Why $ch.Why -EntityIds @($ids)))
    }

    # 3. Lifecycle history and autoenrollment events.
    $readLogs = @($lc.Logs | Where-Object { $_.Read })
    if ($readLogs.Count -gt 0) {
        $byAction = @($lc.Events | Group-Object Action | Sort-Object Name | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name })
        $times = @($lc.Events | Where-Object { $_.Time } | ForEach-Object { $_.Time } | Sort-Object)
        $ev = @($readLogs | ForEach-Object { '{0}: {1} event(s) read' -f $_.Name, $_.Count })
        if ($byAction.Count) { $ev += ('By action: {0}' -f ($byAction -join ', ')) }
        if ($times.Count) { $ev += ('Oldest {0}, newest {1}' -f $times[0], $times[-1]) }
        foreach ($e in @($lc.Events | Sort-Object Time -Descending | Select-Object -First 25)) { $ev += ('{0} {1}: {2} [{3}] template {4}, by {5} as {6}' -f $e.Time, $e.Action, (@($e.Subjects) | Select-Object -First 1), $e.Thumbprint, $(if ($e.TemplateName) { $e.TemplateName } else { '-' }), $e.Process, $e.Account) }
        [void]$out.Add((& $mk @{ Target = 'Certificate lifecycle events'; Status = 'Information'; StatusCode = 'OK'; Confidence = 'Confirmed'; Sources = @('Local:EventLog:Lifecycle')
            Message = ('Certificate lifecycle on this computer: {0} event(s) in the Lifecycle logs ({1}).' -f @($lc.Events).Count, $(if ($byAction.Count) { $byAction -join ', ' } else { 'none' })); Evidence = $ev
            Notes = 'Windows writes one event when a certificate is enrolled, renewed, replaced, exported or deleted in a store, with the template, the process and the account. This is how the tool tells an autoenrolled certificate from a manual request.' }))
    }
    if ($ae.Read) {
        $all = @($ae.Events)
        $exp64 = @($all | Where-Object { $_.EventId -eq 64 })
        $fail = @($all | Where-Object { $_.Level -in @('Error', 'Warning') -and $_.EventId -ne 64 })
        foreach ($g in @($fail | Group-Object Provider, EventId)) {
            $last = @($g.Group | Sort-Object Time -Descending)[0]
            [void]$out.Add((& $mk @{ Target = ('{0} event {1}' -f $last.Provider, $last.EventId); Status = 'Warning'; StatusCode = 'RETRIEVAL_FAIL'; Severity = 'Low'; Confidence = 'Confirmed'; Sources = @('Local:EventLog:Application')
                Message = ('Certificate enrollment on this computer reported a problem {0} time(s), last at {1}: {2}' -f $g.Count, $last.Time, $last.Message)
                Evidence = @(@(('Provider {0}, event {1}, level {2}' -f $last.Provider, $last.EventId, $last.Level)) + @($last.Data.Keys | ForEach-Object { '{0} = {1}' -f $_, $last.Data[$_] }))
                Notes = 'Read from the Application log of this computer. The event text names the template and the CA when Windows knows them.' }))
        }
        $mine = @($stores['Cert:\CurrentUser\My'].Certificates) + @($stores['Cert:\LocalMachine\My'].Certificates) | Where-Object { $null -ne $_ } | ForEach-Object { $_.Thumbprint.ToUpperInvariant() }
        foreach ($g in @($exp64 | Group-Object { ([string]$_.Data['ObjId']).ToUpperInvariant() -replace '\s', '' })) {
            $tp = $g.Name
            $last = @($g.Group | Sort-Object Time -Descending)[0]
            $still = @($mine) -contains $tp
            [void]$out.Add((& $mk @{ Target = ('Certificate [{0}]' -f $tp); Status = $(if ($still) { 'Warning' } else { 'Information' }); StatusCode = $(if ($still) { 'OBJECT_EXPIRING' } else { 'OK' }); Severity = $(if ($still) { 'Low' } else { 'None' })
                Confidence = 'Confirmed'; Sources = @('Local:EventLog:Application', 'Local:CertStore')
                Message = $(if ($still) { 'Autoenrollment warned {0} time(s) (last {1}) that the certificate [{2}] is about to expire or has expired, and it is still in the store.' -f $g.Count, $last.Time, $tp } else { 'Autoenrollment warned {0} time(s) (last {1}) that the certificate [{2}] was about to expire; it is no longer in the store (renewed or removed).' -f $g.Count, $last.Time, $tp })
                Evidence = @(('Context: {0}' -f $last.Data['Context']), ('Event text: {0}' -f $last.Message)) }))
        }
    }

    # 4. Enrollment policy on this computer: template cache, autoenrollment policy, Remote Desktop template policy.
    $ev = @()
    foreach ($c in @($pol.TemplateCache)) {
        if ($null -ne $c.Error) { $ev += ('{0}: not readable ({1})' -f $c.Path, $c.Error.Message); continue }
        if (-not $c.Exists) { $ev += ('{0}: not present (no template downloaded for the {1} yet)' -f $c.Path, $c.Scope.ToLowerInvariant()); continue }
        $ev += ('{0}: {1} template(s), downloaded from AD at {2}' -f $c.Path, @($c.Templates).Count, $(if ($c.Timestamp) { $c.Timestamp } else { 'an unknown time' }))
        foreach ($tn in @($c.Templates)) {
            $tid = Get-MspkiEntityId -Type 'Template' -Key $tn
            if (Test-MspkiEntity -Id $tid) { Add-MspkiObservation -EntityId $tid -Kind 'Seen' -Source 'LocalPolicy' -Location $c.Path -Confidence 'Confirmed' -Detail ('{0} template cache (downloaded at {1})' -f $c.Scope, $c.Timestamp) }
        }
    }
    foreach ($a in @($pol.AutoEnrollment)) { $ev += ('Autoenrollment policy ({0}, {1}): {2}' -f $a.Scope.ToLowerInvariant(), $a.Path, $(if ($null -ne $a.Error) { 'not readable: ' + $a.Error.Message } else { Get-MspkiAutoEnrollmentPolicyText -Value $a.AEPolicy })) }
    $ev += ('Remote Desktop certificate template policy ({0}): {1}' -f $pol.RdpTemplate.Path, $(if ($rdpT) { $rdpT } else { 'not configured' }))
    if ($rdpT) {
        $tid = Get-MspkiEntityId -Type 'Template' -Key $rdpT
        if (Test-MspkiEntity -Id $tid) { Add-MspkiObservation -EntityId $tid -Kind 'Referenced' -Source 'LocalPolicy' -Location ($pol.RdpTemplate.Path + '\CertTemplateName') -Confidence 'Confirmed' -Detail 'Group Policy: Remote Desktop server certificate template' }
    }
    $hk = @($pol.TemplateCache | Where-Object { $_.Scope -eq 'Computer' }) | Select-Object -First 1
    [void]$out.Add((& $mk @{ Target = 'Enrollment policy on this computer'; Status = 'Information'; StatusCode = 'OK'; Confidence = 'Confirmed'; Sources = @('Local:Registry:CertificateTemplateCache', 'Local:Registry:AutoEnrollment', 'Local:Registry:TerminalServices')
        Message = ('Enrollment policy on this computer: template cache {0}; autoenrollment {1}; Remote Desktop template {2}.' -f $(if ($null -ne $hk -and $hk.Exists) { 'updated ' + $hk.Timestamp } else { 'not present' }), $(if ($aeOn) { 'enabled by policy' } else { 'not enabled by policy' }), $(if ($rdpT) { $rdpT } else { 'not set' }))
        Evidence = $ev; Notes = 'The template cache is what Windows downloaded from AD the last time autoenrollment ran; if its time is old, the autoenrollment refresh is not running on this computer. The CEP policy servers are reported in the CEP results.' }))
    return $out.ToArray()
}
