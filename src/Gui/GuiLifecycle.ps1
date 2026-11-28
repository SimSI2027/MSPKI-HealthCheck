# Timeline and chain (GX7), pure side: the lifecycle of every CA certificate generation and CRL from the results graph (rows with their
# windows, countdowns and health), the time axis (range and ticks) and the certificate chain from a leaf to its root with the result of
# every AIA and CDP address. No WPF here: GuiTimelinePage.ps1 draws what these functions return. Loaded by GuiApp.ps1.
#
# Honesty rules (GUI-EXPERIENCE section 1):
# - every countdown is measured from the time of the run (the run's StartedUtc), never from "now": an earlier run says what it saw then;
# - a date is never invented: a row without dates has no bar and says why;
# - an address that this run did not check is "not checked", never healthy;
# - a CA whose certificate could not be read gets a row that says so ("could not check"), never an empty group.

$script:MspkiGuiTimelineSpans = [ordered]@{ Auto = 0; '2 weeks' = 14; '3 months' = 91; '1 year' = 365; '5 years' = 1826 }

function Get-MspkiGuiSpanText {
    <#
    .SYNOPSIS
    A length of time in plain words: "2 years 5 months", "7 months", "4 days 3 hours", "11 hours", "35 minutes". (A plain function: it is called for every row.)
    #>
    param([double]$Days, [switch]$Coarse)
    # -Coarse: the largest unit only ("6 days", "2 years"), where room is tight.
    $d = [math]::Abs($Days)
    $plural = { param([int]$n, [string]$w) if ($n -eq 1) { '1 ' + $w } else { '{0} {1}s' -f $n, $w } }
    if ($d -ge 365) {
        $y = [int][math]::Floor($d / 365.25)
        $m = [int][math]::Floor(($d - $y * 365.25) / 30.44)
        if ($m -ge 12) { $y++; $m = 0 }
        if ($m -gt 0 -and -not $Coarse) { return ('{0} {1}' -f (& $plural $y 'year'), (& $plural $m 'month')) }
        return (& $plural $y 'year')
    }
    if ($d -ge 61) { return (& $plural ([int][math]::Floor($d / 30.44)) 'month') }
    if ($d -ge 14) { return (& $plural ([int][math]::Floor($d)) 'day') }
    if ($d -ge 2) {
        $whole = [int][math]::Floor($d)
        $h = [int][math]::Floor(($d - $whole) * 24)
        if ($h -gt 0 -and -not $Coarse) { return ('{0} {1}' -f (& $plural $whole 'day'), (& $plural $h 'hour')) }
        return (& $plural $whole 'day')
    }
    if ($d -ge (1.0 / 24)) { return (& $plural ([int][math]::Floor($d * 24)) 'hour') }
    return (& $plural ([int][math]::Max(1, [math]::Floor($d * 1440))) 'minute')
}

function Format-MspkiGuiTimelineDate {
    <#
    .SYNOPSIS
    A UTC date for people: "27 Nov 2026" for long spans, "27 Nov 2026, 14:05 UTC" when the hour matters (CRLs); -Short: "27 Nov 14:05" (UTC) where room is tight.
    #>
    param([AllowNull()]$Date, [switch]$WithTime, [switch]$Short)
    if ($null -eq $Date) { return '' }
    $c = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Short) { return ([datetime]$Date).ToString('d MMM HH:mm', $c) }
    if ($WithTime) { return ([datetime]$Date).ToString('d MMM yyyy, HH:mm', $c) + ' UTC' }
    return ([datetime]$Date).ToString('d MMM yyyy', $c)
}

function Read-MspkiGuiCrlCopy {
    <#
    .SYNOPSIS
    The CRL number, this update and next update of one copy, read from the engine's observation detail ("CRL number 42, this update ...,
    next update ..." at an address; "The CA's own current CRL: number ..." at the CA). Returns $null for any other text.
    #>
    param([AllowEmptyString()][string]$Detail)
    if ($Detail -notmatch 'number (\S+), this update (\S*), next update (\S*)\s*$') { return $null }
    $st = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $a = [DateTime]::MinValue; $b = [DateTime]::MinValue
    $tu = $null; if ($Matches[2] -and [DateTime]::TryParse($Matches[2], $inv, $st, [ref]$a)) { $tu = $a }
    $nu = $null; if ($Matches[3] -and [DateTime]::TryParse($Matches[3], $inv, $st, [ref]$b)) { $nu = $b }
    return [pscustomobject]@{ Number = $Matches[1]; ThisUpdate = $tu; NextUpdate = $nu }
}

function Compare-MspkiGuiHexNumber {
    # -1, 0 or 1 for two CRL numbers written in hex (as the engine writes them); unreadable numbers compare as equal.
    param([string]$A, [string]$B)
    $a = ($A -replace '^0+', ''); $b = ($B -replace '^0+', '')
    if ($a -notmatch '^[0-9A-Fa-f]*$' -or $b -notmatch '^[0-9A-Fa-f]*$') { return 0 }
    if ($a.Length -ne $b.Length) { return $(if ($a.Length -lt $b.Length) { -1 } else { 1 }) }
    $c = [string]::Compare($a.ToUpperInvariant(), $b.ToUpperInvariant(), [StringComparison]::Ordinal)
    if ($c -lt 0) { return -1 }
    if ($c -gt 0) { return 1 }
    return 0
}

function Get-MspkiGuiCnOf {
    # The CN of a distinguished name ("Alcyone Meridian Issuing CA"), or the text itself.
    param([string]$Dn)
    if ($Dn -match '(?i)(?:^|,)\s*CN=([^,]+)') { return $Matches[1].Trim() }
    return $Dn
}

function Get-MspkiGuiLifecycleModel {
    <#
    .SYNOPSIS
    The lifecycle of the PKI as rows grouped by CA: every CA certificate generation (validity window, countdown, current or replaced) and
    every CRL (this update to next update, the overlap from Next CRL Publish, the copy at each address). Returns $null without a graph.

    .DESCRIPTION
    Now is the time of the run. Tones: a current certificate is failing when expired or inside the critical days, a warning inside the
    warning days (the run's own thresholds, as the CA cards use them); a replaced generation that expired is no finding by itself. A CRL
    is failing after its next update and a warning once Next CRL Publish has passed with no newer CRL seen. Findings about the object
    itself can only make a row worse. A copy at an address is failing when it expired or was not found there, a warning when it is older
    than the newest CRL this run saw.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Index, [hashtable]$FindingStatus = @{}, [Parameter(Mandatory = $true)][datetime]$Now, [AllowNull()]$RunInfo = $null)
    if ($null -eq $Index) { return $null }
    if ($Now.Kind -eq [DateTimeKind]::Local) { $Now = $Now.ToUniversalTime() }
    $ent = $Index.Entities
    $outOf = { param($id, $type) $r = New-Object System.Collections.ArrayList; if ($Index.Out.ContainsKey($id)) { foreach ($x in $Index.Out[$id]) { if ($null -ne $x -and [string]$x.Type -eq $type) { [void]$r.Add($x) } } }; , $r }
    $prop = { param($e, $n) if ($null -ne $e -and $null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties[$n]) { $e.Properties.$n } else { $null } }
    $findTone = {
        param($id)
        $st = New-Object System.Collections.Generic.List[string]
        if ($Index.Findings.ContainsKey($id)) { foreach ($fid in $Index.Findings[$id]) { $st.Add([string]$FindingStatus[[string]$fid]) } }
        Get-MspkiGuiNodeHealth -Statuses $st.ToArray()
    }
    $findIds = { param($id) if ($Index.Findings.ContainsKey($id)) { [string[]]@(foreach ($x in $Index.Findings[$id]) { [string]$x }) } else { [string[]]@() } }
    $thr = @{ RootWarn = 730; RootCrit = 365; IssWarn = 180; IssCrit = 90 }
    if ($null -ne $RunInfo -and $null -ne $RunInfo.Parameters) {
        $p = $RunInfo.Parameters
        foreach ($pair in @(@('RootWarn', 'RootCaWarningDays'), @('RootCrit', 'RootCaCriticalDays'), @('IssWarn', 'IssuingCaWarningDays'), @('IssCrit', 'IssuingCaCriticalDays'))) {
            $v = $null; if ($null -ne $p.PSObject.Properties[$pair[1]]) { $v = $p.($pair[1]) }
            $n = 0; if ($null -ne $v -and [int]::TryParse([string]$v, [ref]$n) -and $n -gt 0) { $thr[$pair[0]] = $n }
        }
    }

    # Groups: one per CA entity; a CA certificate without a CA (an offline root) is grouped by its subject.
    $groups = [ordered]@{}
    $newGroup = {
        param($key, $name, $caId)
        if (-not $groups.Contains($key)) { $groups[$key] = [pscustomobject]@{ Key = $key; Name = $name; CaId = $caId; Depth = 0; Root = $false; Unread = $false; Certs = (New-Object System.Collections.ArrayList); Crls = (New-Object System.Collections.ArrayList); Tone = 'Neutral'; Summary = '' } }
        $groups[$key]
    }
    # One pass over the entities (hot loops use foreach and array sorts, no pipelines: a 300-object estate stays well under 50 ms).
    $byType = @{ CA = (New-Object System.Collections.ArrayList); CACertificate = (New-Object System.Collections.ArrayList); CRL = (New-Object System.Collections.ArrayList) }
    foreach ($e in $ent.Values) { $ty = [string]$e.Type; if ($byType.ContainsKey($ty)) { [void]$byType[$ty].Add($e) } }
    $caList = [object[]]$byType.CA.ToArray()
    $caKeys = [string[]]@(foreach ($e in $caList) { [string]$e.Name + '|' + [string]$e.Id })
    [Array]::Sort([Array]$caKeys, [Array]$caList, [System.Collections.IComparer][StringComparer]::Ordinal)
    foreach ($e in $caList) {
        $gp = & $newGroup ([string]$e.Id) ([string]$e.Name) ([string]$e.Id)
        $read = & $prop $e 'PropertiesRead'
        $gp.Unread = ($null -ne $read -and -not [bool]$read)
    }
    $certGroup = @{}
    $certs = $byType.CACertificate.ToArray()
    foreach ($c in $certs) {
        $id = [string]$c.Id
        $ca = @(foreach ($r in (& $outOf $id 'certificateOf')) { if ($ent.ContainsKey([string]$r.To)) { $r } })
        if ($ca.Count -gt 0) { $key = [string]$ca[0].To; $gp = & $newGroup $key ([string]$ent[$key].Name) $key }
        else { $subj = [string](& $prop $c 'Subject'); if (-not $subj) { $subj = [string]$c.Name }; $key = 'cagroup:' + $subj.ToLowerInvariant(); $gp = & $newGroup $key (Get-MspkiGuiCnOf $subj) '' }
        $certGroup[$id] = $key
    }
    # Depth in the chain (roots first): from issuedBy between certificates of different groups.
    $parentGroup = @{}
    foreach ($c in $certs) {
        foreach ($r in (& $outOf ([string]$c.Id) 'issuedBy')) {
            $to = [string]$r.To
            if ($certGroup.ContainsKey($to) -and $certGroup[$to] -ne $certGroup[[string]$c.Id]) { $parentGroup[$certGroup[[string]$c.Id]] = $certGroup[$to] }
        }
    }
    foreach ($gp in $groups.Values) {
        $d = 0; $cur = $gp.Key; $guard = 0
        while ($parentGroup.ContainsKey($cur) -and $guard -lt 8) { $cur = $parentGroup[$cur]; $d++; $guard++ }
        # A CA with no certificate in the results (its properties could not be read) sits with the issuing CAs unless AD calls it a root.
        if ($d -eq 0 -and -not ($certGroup.Values -contains $gp.Key)) { $ct = ''; if ($gp.CaId -and $ent.ContainsKey($gp.CaId)) { $ct = [string](& $prop $ent[$gp.CaId] 'CAType') }; if ($ct -notmatch 'Root') { $d = 1 } }
        $gp.Depth = $d
    }

    foreach ($c in $certs) {
        $id = [string]$c.Id
        $gp = $groups[$certGroup[$id]]
        $nb = ConvertTo-MspkiGuiDateTime -Value (& $prop $c 'NotBefore')
        $na = ConvertTo-MspkiGuiDateTime -Value (& $prop $c 'NotAfter')
        $life = [string](& $prop $c 'Lifecycle')
        $role = [string](& $prop $c 'Role')
        $gen = [string](& $prop $c 'Generation')
        $isRoot = ($role -match 'Root') -or ([string](& $prop $c 'Subject') -and [string](& $prop $c 'Subject') -eq [string](& $prop $c 'Issuer'))
        if ($isRoot) { $gp.Root = $true }
        $historical = ($life -eq 'Historical')
        $tone = 'Neutral'; $state = ''; $count = ''; $countTone = 'Neutral'
        if ($null -eq $na) { $state = 'Validity not read'; $count = 'End date unknown' }
        else {
            $left = ($na - $Now).TotalDays
            if ($left -lt 0) {
                $count = 'Expired {0} ago' -f $(if ($historical) { Get-MspkiGuiSpanText -Days $left -Coarse } else { Get-MspkiGuiSpanText -Days $left })
                if ($historical) { $state = 'Replaced'; $countTone = 'Neutral' } else { $state = 'Expired'; $tone = 'Bad'; $countTone = 'Bad' }
            }
            else {
                $count = 'Expires in {0}' -f (Get-MspkiGuiSpanText -Days $left)
                $warnD = $(if ($isRoot) { $thr.RootWarn } else { $thr.IssWarn }); $critD = $(if ($isRoot) { $thr.RootCrit } else { $thr.IssCrit })
                if ($historical) { $state = 'Replaced'; $tone = 'Good' }
                elseif ($left -le $critD) { $state = 'Expires soon'; $tone = 'Bad'; $countTone = 'Bad' }
                elseif ($left -le $warnD) { $state = 'Renew soon'; $tone = 'Warn'; $countTone = 'Warn' }
                else { $state = 'Valid'; $tone = 'Good'; $countTone = 'Good' }
            }
            if ($null -ne $nb -and $nb -gt $Now) { $state = 'Not yet valid'; $count = 'Valid from {0}' -f (Format-MspkiGuiTimelineDate -Date $nb); $tone = 'Warn'; $countTone = 'Warn' }
        }
        $tone = Get-MspkiGuiWorseTone $tone (& $findTone $id)
        $genText = $(if ($gen) { 'generation ' + $gen } else { '' })
        $lifeText = switch ($life) { 'Current' { 'current' } 'Historical' { 'replaced' } default { 'role in the hierarchy not confirmed' } }
        $label = $(if ($isRoot) { 'Root certificate' } else { 'CA certificate' })
        $sub = $(if ($genText) { $genText + ' ' + [char]0x00B7 + ' ' + $lifeText } else { $lifeText })
        $tip = '{0} of {1}: valid from {2} to {3}. {4}.' -f $label, $gp.Name, $(if ($nb) { Format-MspkiGuiTimelineDate -Date $nb } else { 'an unknown date' }), $(if ($na) { Format-MspkiGuiTimelineDate -Date $na } else { 'an unknown date' }), $count
        if ($historical) { $tip += ' A newer generation of this CA exists; this one stays valid for what it signed until it expires.' }
        [void]$gp.Certs.Add([pscustomobject]@{ Id = $id; Kind = 'Certificate'; Group = $gp.Key; Label = $label; Sub = $sub; Start = $nb; End = $na; Mark = $null; Tone = $tone; State = $state
                Countdown = $count; CountdownTone = $countTone; Current = (-not $historical); Tip = $tip; Findings = @(& $findIds $id); Copies = @(); SortKey = $(if ($nb) { $nb.Ticks } else { 0 }) })
    }

    # CRLs: by the CA key that signs them (signedBy), else by the issuer name.
    foreach ($e in $byType.CRL) {
        $id = [string]$e.Id
        $sig = [string[]]@(foreach ($r in (& $outOf $id 'signedBy')) { if ($certGroup.ContainsKey([string]$r.To)) { [string]$r.To } })
        $key = ''
        if ($sig.Count -gt 0) { $key = $certGroup[$sig[0]] }
        else {
            $iss = [string](& $prop $e 'Issuer')
            $cn = Get-MspkiGuiCnOf $iss
            foreach ($gp in $groups.Values) { if ($gp.Name -eq $cn) { $key = $gp.Key; break } }
            if (-not $key) { $key = 'cagroup:' + $(if ($iss) { $iss.ToLowerInvariant() } else { $id }); [void](& $newGroup $key $(if ($cn) { $cn } else { 'Unknown CA' }) '') }
        }
        $gp = $groups[$key]
        $delta = [bool](& $prop $e 'IsDelta')
        $tu = ConvertTo-MspkiGuiDateTime -Value (& $prop $e 'ThisUpdate')
        $nu = ConvertTo-MspkiGuiDateTime -Value (& $prop $e 'NextUpdate')
        $np = ConvertTo-MspkiGuiDateTime -Value (& $prop $e 'NextPublish')
        $num = [string](& $prop $e 'CrlNumber')
        $genText = ''
        if ($sig.Count -gt 0 -and $ent.ContainsKey($sig[0])) { $gv = [string](& $prop $ent[$sig[0]] 'Generation'); if ($gv) { $genText = 'signed by generation ' + $gv } }
        $tone = 'Neutral'; $state = ''; $count = ''; $countTone = 'Neutral'
        if ($null -eq $nu) { $state = 'Not read'; $count = $(if ($null -eq $tu) { 'No copy was read' } else { 'No next update' }) }
        else {
            $left = ($nu - $Now).TotalDays
            if ($left -lt 0) { $state = 'Expired'; $count = 'Expired {0} ago' -f (Get-MspkiGuiSpanText -Days $left); $tone = 'Bad'; $countTone = 'Bad' }
            elseif ($null -ne $np -and $np -le $Now) { $state = 'New CRL overdue'; $count = 'Next update in {0}' -f (Get-MspkiGuiSpanText -Days $left); $tone = 'Warn'; $countTone = 'Warn' }
            else { $state = 'Valid'; $count = 'Next update in {0}' -f (Get-MspkiGuiSpanText -Days $left); $tone = 'Good'; $countTone = 'Good' }
        }
        # The copy at each address (and at the CA): the newest number this run saw is the reference.
        $copies = New-Object System.Collections.ArrayList
        if ($Index.Obs.ContainsKey($id)) {
            foreach ($o in $Index.Obs[$id]) {
                if ($null -eq $o) { continue }
                $loc = [string]$o.Location
                $where = $(if ([string]$o.Source -eq 'CA') { 'At the CA (its own current CRL)' } else { $u = $loc; try { $u = [System.Uri]::UnescapeDataString($loc) } catch { $u = $loc }; $u })
                if ([string]$o.Kind -eq 'ExpectedMissing') {
                    [void]$copies.Add([pscustomobject]@{ Where = $where; Location = $loc; Source = [string]$o.Source; Number = ''; ThisUpdate = $null; NextUpdate = $null; Tone = 'Bad'; Text = 'Not found at this address'; Missing = $true })
                    continue
                }
                if ([string]$o.Kind -ne 'Seen') { continue }
                $cp = Read-MspkiGuiCrlCopy -Detail ([string]$o.Detail)
                if ($null -eq $cp) { continue }
                $ct = 'Good'; $tx = 'Number {0} {1} until {2}' -f $cp.Number, [char]0x00B7, (Format-MspkiGuiTimelineDate -Date $cp.NextUpdate -Short)
                if ($null -ne $cp.NextUpdate -and $cp.NextUpdate -lt $Now) { $ct = 'Bad'; $tx = 'Number {0} {1} expired {2} ago' -f $cp.Number, [char]0x00B7, (Get-MspkiGuiSpanText -Days ($cp.NextUpdate - $Now).TotalDays -Coarse) }
                elseif ($num -and (Compare-MspkiGuiHexNumber $cp.Number $num) -lt 0) { $ct = 'Warn'; $tx = 'Number {0} {1} older than number {2}' -f $cp.Number, [char]0x00B7, $num }
                [void]$copies.Add([pscustomobject]@{ Where = $where; Location = $loc; Source = [string]$o.Source; Number = $cp.Number; ThisUpdate = $cp.ThisUpdate; NextUpdate = $cp.NextUpdate; Tone = $ct; Text = $tx; Missing = $false })
            }
        }
        $copyTone = 'Neutral'
        foreach ($cp in $copies) { $copyTone = Get-MspkiGuiWorseTone $copyTone $cp.Tone }
        if ($copyTone -in @('Bad', 'Warn') -and $tone -eq 'Good') { $tone = 'Warn' }
        $tone = Get-MspkiGuiWorseTone $tone (& $findTone $id)
        $label = $(if ($delta) { 'Delta CRL' } else { 'Base CRL' })
        $sub = $genText; if ($num) { $sub = 'number ' + $num + $(if ($genText) { ' ' + [char]0x00B7 + ' ' + $genText } else { '' }) }
        $tip = '{0} of {1}.' -f $label, $gp.Name
        if ($tu -and $nu) { $tip += ' Published {0}; valid until {1}.' -f (Format-MspkiGuiTimelineDate -Date $tu -WithTime), (Format-MspkiGuiTimelineDate -Date $nu -WithTime) }
        if ($np) { $tip += ' The CA plans the next one for {0} (Next CRL Publish): from then until the next update, the old and the new CRL overlap.' -f (Format-MspkiGuiTimelineDate -Date $np -WithTime) }
        if ($state -eq 'New CRL overdue') { $tip += ' That time has passed and this run saw no newer CRL.' }
        $bad = 0; foreach ($cp in $copies) { if ($cp.Tone -eq 'Bad' -or $cp.Tone -eq 'Warn') { $bad++ } }
        if ($copies.Count -gt 0) { $tip += ' Copies: {0} read, {1} with a problem.' -f $copies.Count, $bad }
        [void]$gp.Crls.Add([pscustomobject]@{ Id = $id; Kind = 'Crl'; Group = $gp.Key; Label = $label; Sub = $sub; Start = $tu; End = $nu; Mark = $np; Tone = $tone; State = $state
                Countdown = $count; CountdownTone = $countTone; Current = $true; Tip = $tip; Findings = @(& $findIds $id); Copies = @($copies); Delta = $delta; SortKey = $(if ($delta) { 1 } else { 0 }) })
    }

    $ordered = [object[]]@($groups.Values)
    $oKeys = [string[]]@(foreach ($gp in $ordered) { '{0:00}|{1}|{2}' -f [int]$gp.Depth, [string]$gp.Name, [string]$gp.Key })
    [Array]::Sort([Array]$oKeys, [Array]$ordered, [System.Collections.IComparer][StringComparer]::Ordinal)
    # Short names for tight places: the first word every CA name shares (usually the organisation) is left out, as on the map.
    $prefix = ''
    $names = [string[]]@(foreach ($gp in $ordered) { [string]$gp.Name })
    if ($names.Count -ge 2) {
        $w = ($names[0] -split ' ')[0]
        $all = $true
        foreach ($n in $names) { if (-not ($n.StartsWith($w + ' ') -and ($n -split ' ').Count -ge 3)) { $all = $false; break } }
        if ($w -and $all) { $prefix = $w + ' ' }
    }
    foreach ($gp in $ordered) { $gp | Add-Member -NotePropertyName Short -NotePropertyValue $(if ($prefix) { ([string]$gp.Name).Substring($prefix.Length) } else { [string]$gp.Name }) -Force }
    $lapse = New-Object System.Collections.ArrayList
    foreach ($gp in $ordered) {
        # Never an empty group: a CA whose certificate this run could not read says so in a row of its own.
        if ($gp.Certs.Count -eq 0) {
            $why = $(if ($gp.Unread) { 'This run could not read the CA''s properties (permission denied or the CA did not answer), so its certificate and dates are unknown. Run as a user who may read the CA to see them.' } else { 'No certificate of this CA is in the results.' })
            [void]$gp.Certs.Add([pscustomobject]@{ Id = $gp.CaId; Kind = 'Missing'; Group = $gp.Key; Label = 'CA certificate'; Sub = 'not read'; Start = $null; End = $null; Mark = $null; Tone = $(if ($gp.Unread) { 'Admin' } else { 'Neutral' }); State = 'Could not check'
                    Countdown = 'Dates unknown'; CountdownTone = 'Neutral'; Current = $false; Tip = $why; Findings = @(& $findIds $gp.CaId); Copies = @(); SortKey = 0 })
        }
        foreach ($list in @($gp.Certs, $gp.Crls)) {
            if ($list.Count -lt 2) { continue }
            $arr = [object[]]$list.ToArray()
            $keys = [string[]]@(foreach ($r in $arr) { '{0:D20}|{1}' -f [long]$r.SortKey, [string]$r.Sub })
            [Array]::Sort([Array]$keys, [Array]$arr, [System.Collections.IComparer][StringComparer]::Ordinal)
            $list.Clear(); foreach ($r in $arr) { [void]$list.Add($r) }
        }
        $t = 'Neutral'
        foreach ($r in @($gp.Certs) + @($gp.Crls)) { $t = Get-MspkiGuiWorseTone $t $r.Tone }
        if ($gp.Unread) { $t = Get-MspkiGuiWorseTone $t 'Admin' }
        $gp.Tone = $t
        $ct = 'Neutral'; foreach ($r in $gp.Certs) { $ct = Get-MspkiGuiWorseTone $ct $r.Tone }
        $rt = 'Neutral'; foreach ($r in $gp.Crls) { $rt = Get-MspkiGuiWorseTone $rt $r.Tone }
        # Per view, "could not check" only where this run has nothing to show: a CA it could not read whose CRLs it read elsewhere (AD, a web
        # address) shows those CRLs' status in the CRLs view. The certificates view gets it from the "not read" row when the certificate is missing.
        if ($gp.Unread -and $gp.Crls.Count -eq 0) { $rt = Get-MspkiGuiWorseTone $rt 'Admin' }
        $gp | Add-Member -NotePropertyName CertTone -NotePropertyValue $ct -Force
        $gp | Add-Member -NotePropertyName CrlTone -NotePropertyValue $rt -Force
        $cur = @(); foreach ($r in $gp.Certs) { if ($r.Current -and $null -ne $r.End -and ($cur.Count -eq 0 -or $r.End -gt $cur[0].End)) { $cur = @($r) } }
        $base = @(); foreach ($r in $gp.Crls) { if (-not $r.Delta -and $null -ne $r.End) { $base = @($r); break } }
        $parts = @()
        $certPart = ''; $crlPart = ''
        if ($cur.Count -gt 0) { $certPart = 'Certificate: ' + $cur[0].Countdown.Substring(0, 1).ToLowerInvariant() + $cur[0].Countdown.Substring(1) }
        elseif ($gp.Unread) { $certPart = 'Certificate not read' }
        if ($base.Count -gt 0) { $crlPart = 'Base CRL: ' + $base[0].Countdown.Substring(0, 1).ToLowerInvariant() + $base[0].Countdown.Substring(1) }
        elseif ($gp.Unread) { $crlPart = 'CRLs not read' }
        $gp.Summary = $(if ($certPart -and $crlPart) { $certPart + '  ' + [char]0x00B7 + '  ' + $crlPart } elseif ($certPart) { $certPart } else { $crlPart })
        $gp | Add-Member -NotePropertyName CertSummary -NotePropertyValue $(if ($certPart) { $certPart } else { $gp.Summary }) -Force
        $gp | Add-Member -NotePropertyName CrlSummary -NotePropertyValue $(if ($crlPart) { $crlPart } else { 'No CRL read' }) -Force
        foreach ($r in @($gp.Certs) + @($gp.Crls)) {
            if ($r.Current -and $null -ne $r.End) { $gen = ''; $same = 0; if ($r.Kind -eq 'Crl') { foreach ($x in $gp.Crls) { if ($x.Label -eq $r.Label) { $same++ } } }; if ($same -gt 1 -and [string]$r.Sub -match 'generation (\S+)') { $gen = ' (' + $Matches[1] + ')' }
                $low = $r.Countdown.Substring(0, 1).ToLowerInvariant() + $r.Countdown.Substring(1)
                [void]$lapse.Add([pscustomobject]@{ Id = $r.Id; Kind = $r.Kind; Group = $gp.Name; Short = $gp.Short; Label = ($r.Label + $gen); Due = $r.Countdown; End = $r.End; Tone = $r.Tone; Text = ('{0}{1} of {2}: {3}' -f $r.Label, $gen, $gp.Name, $low) }) }
        }
    }
    $la = [object[]]$lapse.ToArray()
    $lk = [string[]]@(foreach ($x in $la) { '{0:D20}|{1}' -f ([datetime]$x.End).Ticks, [string]$x.Id })
    [Array]::Sort([Array]$lk, [Array]$la, [System.Collections.IComparer][StringComparer]::Ordinal)
    $next = @($la | Select-Object -First 3)
    # Per view: the Certificates view lists the certificates that run out first, the CRLs view the CRLs.
    $nextCerts = @($la | Where-Object { [string]$_.Kind -ne 'Crl' } | Select-Object -First 3)
    $nextCrls = @($la | Where-Object { [string]$_.Kind -eq 'Crl' } | Select-Object -First 3)
    $nCert = 0; $nCrl = 0; foreach ($gp in $ordered) { $nCert += $gp.Certs.Count; $nCrl += $gp.Crls.Count }
    return [pscustomobject]@{ Now = $Now; Groups = $ordered; NextToLapse = $next; NextCerts = $nextCerts; NextCrls = $nextCrls
        CertCount = $nCert; CrlCount = $nCrl }
}

function Get-MspkiGuiTimelineRange {
    <#
    .SYNOPSIS
    The time axis of one view: Start and End (UTC). Auto covers every bar of the view and the run's time with a small margin; a fixed
    span (in days) puts the run's time a third of the way in, so what comes next has the most room.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory = $true)][datetime]$Now, [double]$SpanDays = 0, [double]$MinDays = 2, [double]$FocusDays = 0)
    # FocusDays: Auto leaves out rows whose window is longer (an offline root's CRL lasts months, an issuing CA's days): those bars run off
    # the axis with an arrow, and the short heartbeats stay readable. When every row is longer, all of them count.
    if ($SpanDays -le 0 -and $FocusDays -gt 0) {
        $short = @($Rows | Where-Object { $null -ne $_ -and $null -ne $_.Start -and $null -ne $_.End -and ($_.End - $_.Start).TotalDays -le $FocusDays })
        if ($short.Count -gt 0) { $Rows = $short }
    }
    if ($SpanDays -gt 0) { return [pscustomobject]@{ Start = $Now.AddDays(-$SpanDays / 3); End = $Now.AddDays($SpanDays * 2 / 3) } }
    $lo = $Now; $hi = $Now
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        foreach ($d in @($r.Start, $r.End, $r.Mark)) { if ($null -ne $d) { if ($d -lt $lo) { $lo = $d }; if ($d -gt $hi) { $hi = $d } } }
        foreach ($cp in @($r.Copies)) { if ($null -ne $cp -and $null -ne $cp.NextUpdate) { if ($cp.NextUpdate -lt $lo) { $lo = $cp.NextUpdate }; if ($cp.NextUpdate -gt $hi) { $hi = $cp.NextUpdate } } }
    }
    $span = ($hi - $lo).TotalDays
    if ($span -lt $MinDays) { $mid = $lo.AddDays($span / 2); $lo = $mid.AddDays(-$MinDays / 2); $hi = $mid.AddDays($MinDays / 2); $span = $MinDays }
    $pad = $span * 0.04
    return [pscustomobject]@{ Start = $lo.AddDays(-$pad); End = $hi.AddDays($pad) }
}

function Get-MspkiGuiTimelineTick {
    <#
    .SYNOPSIS
    Axis ticks for a range: hours, days, weeks, months or years, at most about MaxLabels labels. Each tick: Date, Text, Fraction (0..1).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][datetime]$Start, [Parameter(Mandatory = $true)][datetime]$End, [int]$MaxLabels = 9)
    $c = [System.Globalization.CultureInfo]::InvariantCulture
    $span = ($End - $Start).TotalDays
    if ($span -le 0) { return @() }
    $ticks = New-Object System.Collections.ArrayList
    $add = { param([datetime]$d, [string]$t) if ($d -ge $Start -and $d -le $End) { [void]$ticks.Add([pscustomobject]@{ Date = $d; Text = $t; Fraction = (($d - $Start).TotalDays / $span) }) } }
    if ($span -le 3) {
        $step = 6; if ($span / 0.25 -le $MaxLabels) { $step = 6 } elseif ($span * 2 -le $MaxLabels) { $step = 12 } else { $step = 24 }
        $d = New-Object DateTime($Start.Year, $Start.Month, $Start.Day, 0, 0, 0, [DateTimeKind]::Utc)
        while ($d -le $End) { & $add $d $(if ($d.Hour -eq 0) { $d.ToString('d MMM', $c) } else { $d.ToString('HH:mm', $c) }); $d = $d.AddHours($step) }
    }
    elseif ($span -le 45) {
        $step = [math]::Max(1, [int][math]::Ceiling($span / $MaxLabels))
        if ($step -gt 2 -and $step -lt 7) { $step = 7 }
        $d = New-Object DateTime($Start.Year, $Start.Month, $Start.Day, 0, 0, 0, [DateTimeKind]::Utc)
        if ($step -ge 7) { while ($d.DayOfWeek -ne [DayOfWeek]::Monday) { $d = $d.AddDays(1) } }
        while ($d -le $End) { & $add $d $d.ToString('d MMM', $c); $d = $d.AddDays($step) }
    }
    elseif ($span -le 1100) {
        $months = [math]::Max(1, [int][math]::Ceiling(($span / 30.44) / $MaxLabels))
        foreach ($s in @(1, 2, 3, 6, 12)) { if ($s -ge $months) { $months = $s; break } }
        $d = New-Object DateTime($Start.Year, $Start.Month, 1, 0, 0, 0, [DateTimeKind]::Utc)
        while ((($d.Month - 1) % $months) -ne 0) { $d = $d.AddMonths(1) }
        while ($d -le $End) { & $add $d $(if ($months -ge 12) { $d.ToString('yyyy', $c) } else { $d.ToString('MMM yyyy', $c) }); $d = $d.AddMonths($months) }
    }
    else {
        $years = [math]::Max(1, [int][math]::Ceiling(($span / 365.25) / $MaxLabels))
        foreach ($s in @(1, 2, 5, 10, 20)) { if ($s -ge $years) { $years = $s; break } }
        $y = $Start.Year; while ($y % $years -ne 0) { $y++ }
        $d = New-Object DateTime($y, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
        while ($d -le $End) { & $add $d $d.ToString('yyyy', $c); $d = $d.AddYears($years) }
    }
    return @($ticks)
}

function Get-MspkiGuiTimelineBar {
    <#
    .SYNOPSIS
    Where a row's window sits on the axis, as four proportional lengths (in days) for a star-sized grid: Before, Main (start to the mark or
    the end), Tail (mark to end: the CRL overlap) and After; ClipStart / ClipEnd say the bar continues beyond the axis; NowBefore and
    NowAfter place the run's time. HasBar is false for a row without both dates. (A plain function: it runs once per row.)
    #>
    param([Parameter(Mandatory = $true)]$Row, [Parameter(Mandatory = $true)]$Range, [Parameter(Mandatory = $true)][datetime]$Now)
    $s = $Range.Start; $e = $Range.End
    $total = ($e - $s).TotalDays
    $nb = [math]::Min([math]::Max(($Now - $s).TotalDays, 0), $total)
    $res = [pscustomobject]@{ HasBar = $false; Before = $total; Main = 0.0; Tail = 0.0; After = 0.0; ClipStart = $false; ClipEnd = $false; NowBefore = $nb; NowAfter = ($total - $nb); Outside = '' }
    if ($null -eq $Row.Start -or $null -eq $Row.End -or $Row.End -le $Row.Start) { return $res }
    if ($Row.End -le $s) { $res.Outside = 'Before'; return $res }
    if ($Row.Start -ge $e) { $res.Outside = 'After'; return $res }
    $a = $Row.Start; $b = $Row.End
    if ($a -lt $s) { $a = $s; $res.ClipStart = $true }
    if ($b -gt $e) { $b = $e; $res.ClipEnd = $true }
    $m = $b
    if ($null -ne $Row.Mark -and $Row.Mark -gt $a -and $Row.Mark -lt $b) { $m = $Row.Mark }
    $res.HasBar = $true
    $res.Before = ($a - $s).TotalDays
    $res.Main = ($m - $a).TotalDays
    $res.Tail = ($b - $m).TotalDays
    $res.After = ($e - $b).TotalDays
    return $res
}

function Get-MspkiGuiChainChoice {
    <#
    .SYNOPSIS
    The certificates a chain can start from, most useful first: certificates on this computer that a CA of this run issued (leaves), then the
    current certificate of every CA that is not a root, then replaced generations. Each: Id, Text.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Index)
    if ($null -eq $Index) { return @() }
    $ent = $Index.Entities
    $items = New-Object System.Collections.ArrayList
    $prop = { param($e, $n) if ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties[$n]) { $e.Properties.$n } else { $null } }
    $hasIssuer = { param($id) if (-not $Index.Out.ContainsKey($id)) { return $false }; foreach ($r in $Index.Out[$id]) { if ($null -ne $r -and [string]$r.Type -eq 'issuedBy' -and $ent.ContainsKey([string]$r.To)) { return $true } }; return $false }
    $caName = {
        param($id)
        if ($Index.Out.ContainsKey($id)) { foreach ($r in $Index.Out[$id]) { if ($null -ne $r -and [string]$r.Type -eq 'certificateOf' -and $ent.ContainsKey([string]$r.To)) { return [string]$ent[[string]$r.To].Name } } }
        Get-MspkiGuiCnOf ([string]$ent[$id].Name)
    }
    $certs = @($ent.Values | Where-Object { [string]$_.Type -eq 'CACertificate' } | Sort-Object { [string]$_.Name }, { [string]$_.Id })
    # Certificates on this computer first: a leaf-to-root chain is what a client builds.
    foreach ($c in @($ent.Values | Where-Object { [string]$_.Type -eq 'LocalCertificate' } | Sort-Object { [string]$_.Name })) {
        if (-not (& $hasIssuer ([string]$c.Id))) { continue }
        [void]$items.Add([pscustomobject]@{ Id = [string]$c.Id; Text = ('{0} {1} on this computer' -f (Get-MspkiGuiCnOf ([string]$c.Name)), [char]0x00B7); Kind = 'Local' })
    }
    foreach ($pass in 1, 3) {
        foreach ($c in $certs) {
            $id = [string]$c.Id
            if (-not (& $hasIssuer $id)) { continue }
            $hist = ([string](& $prop $c 'Lifecycle') -eq 'Historical')
            if (($pass -eq 1 -and $hist) -or ($pass -eq 3 -and -not $hist)) { continue }
            $gen = [string](& $prop $c 'Generation')
            $t = '{0} {1} {2}{3}' -f (& $caName $id), [char]0x00B7, $(if ($gen) { $gen + ', ' } else { '' }), $(if ($hist) { 'replaced' } else { 'current' })
            [void]$items.Add([pscustomobject]@{ Id = $id; Text = $t; Kind = 'CA' })
        }
    }
    return @($items)
}

function Get-MspkiGuiChainAddress {
    # The result of one address of a certificate (AIA, CDP or OCSP): Tone and Text from this run's evidence (what it served, the CRL copy it
    # served, or that it served nothing) and the findings about the address.
    param($Index, [hashtable]$FindingStatus, [string]$EndpointId, [string]$Kind, [string[]]$IssuerIds = @(), [string[]]$CrlIds = @(), [datetime]$Now = [DateTime]::UtcNow)
    $ent = $Index.Entities
    $e = $ent[$EndpointId]
    $url = ''; if ($null -ne $e -and $null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties['Url']) { $url = [string]$e.Properties.Url }
    if (-not $url -and $null -ne $e) { $url = [string]$e.Name }
    $shown = $url; try { $shown = [System.Uri]::UnescapeDataString($url) } catch { $shown = $url }
    $tone = 'Neutral'; $text = 'Not checked in this run'
    $served = $false; $wrong = $false; $missing = $false; $copy = $null; $newest = ''
    $targets = @($(if ($Kind -eq 'AIA') { $IssuerIds } else { $CrlIds }))
    foreach ($t in $targets) {
        if ($Index.Out.ContainsKey($t)) {
            foreach ($r in $Index.Out[$t]) {
                if ($null -ne $r -and [string]$r.Type -eq 'publishedAt' -and [string]$r.To -eq $EndpointId) { if ([string]$r.Confidence -eq 'Referenced') { $wrong = $true } else { $served = $true } }
            }
        }
        if ($Index.Obs.ContainsKey($t)) {
            foreach ($o in $Index.Obs[$t]) {
                if ($null -eq $o -or ([string]$o.Location -ne $url -and [string]$o.Location -ne $shown)) { continue }
                if ([string]$o.Kind -eq 'ExpectedMissing') { $missing = $true }
                elseif ($Kind -ne 'AIA' -and [string]$o.Kind -eq 'Seen' -and $null -eq $copy) {
                    $copy = Read-MspkiGuiCrlCopy -Detail ([string]$o.Detail)
                    if ($null -ne $ent[$t] -and $null -ne $ent[$t].Properties -and $null -ne $ent[$t].Properties.PSObject.Properties['CrlNumber']) { $newest = [string]$ent[$t].Properties.CrlNumber }
                }
            }
        }
    }
    $dot = [string][char]0x00B7
    if ($null -ne $copy) {
        $served = $true
        if ($null -ne $copy.NextUpdate -and $copy.NextUpdate -lt $Now) { $tone = 'Bad'; $text = 'Served CRL number {0} {1} expired {2} ago' -f $copy.Number, $dot, (Get-MspkiGuiSpanText -Days ($copy.NextUpdate - $Now).TotalDays) }
        elseif ($newest -and (Compare-MspkiGuiHexNumber $copy.Number $newest) -lt 0) { $tone = 'Warn'; $text = 'Served CRL number {0} {1} older than number {2}' -f $copy.Number, $dot, $newest }
        else { $tone = 'Good'; $text = 'Served CRL number {0} {1} valid until {2}' -f $copy.Number, $dot, (Format-MspkiGuiTimelineDate -Date $copy.NextUpdate -Short) }
    }
    elseif ($served) { $tone = 'Good'; $text = $(if ($Kind -eq 'AIA') { 'Served the issuer''s certificate (key proven)' } else { 'Served the CRL' }) }
    elseif ($wrong) { $tone = 'Bad'; $text = 'Served a certificate that is not the issuer' }
    elseif ($missing) { $tone = 'Bad'; $text = $(if ($Kind -eq 'AIA') { 'Did not serve the issuer''s certificate' } else { 'Did not serve the CRL' }) }
    $st = New-Object System.Collections.Generic.List[string]
    if ($Index.Findings.ContainsKey($EndpointId)) { foreach ($fid in $Index.Findings[$EndpointId]) { $st.Add([string]$FindingStatus[[string]$fid]) } }
    $ft = Get-MspkiGuiNodeHealth -Statuses $st.ToArray()
    $worse = Get-MspkiGuiWorseTone -A $tone -B $ft
    if ($tone -eq 'Neutral' -and $ft -eq 'Good') { $tone = 'Good'; $text = 'Answered correctly when this run checked it' }
    elseif ($worse -ne $tone -and $ft -ne 'Good') {
        $text = switch ($ft) {
            'Bad' { $(if ($served) { $text + '; a check on this address failed' } else { 'Failed when this run checked it' }) }
            'Warn' { $(if ($served) { $text + '; with a warning' } else { 'Answered with a warning' }) }
            'Admin' { 'This run could not check it' }
            default { $text }
        }
        $tone = $worse
    }
    return [pscustomobject]@{ Id = $EndpointId; Url = $shown; Label = (Get-MspkiGuiEndpointLabel -Url $url); Kind = $Kind; Tone = $tone; Text = $text; Scheme = $(if ($url -match '^([a-zA-Z]+):') { $Matches[1].ToUpperInvariant() } else { '' }) }
}
function Get-MspkiGuiChainModel {
    <#
    .SYNOPSIS
    The certificate chain from one certificate up to its root: one card per certificate (validity, its AIA, CDP and OCSP addresses with
    this run's result for each) and one link per "issued by" step that says whether clients can fetch the issuer, in plain words.
    The chain ends with a root (trust comes from the trusted root store) or with an "issuer not found" card that says why.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Index, [hashtable]$FindingStatus = @{}, [Parameter(Mandatory = $true)][string]$StartId, [Parameter(Mandatory = $true)][datetime]$Now)
    if ($null -eq $Index -or -not $Index.Entities.ContainsKey($StartId)) { return $null }
    if ($Now.Kind -eq [DateTimeKind]::Local) { $Now = $Now.ToUniversalTime() }
    $ent = $Index.Entities
    $prop = { param($e, $n) if ($null -ne $e.Properties -and $null -ne $e.Properties.PSObject.Properties[$n]) { $e.Properties.$n } else { $null } }
    $cards = New-Object System.Collections.ArrayList
    $links = New-Object System.Collections.ArrayList
    $cur = $StartId; $guard = 0; $seen = @{}
    while ($cur -and -not $seen.ContainsKey($cur) -and $guard -lt 8) {
        $seen[$cur] = $true; $guard++
        $e = $ent[$cur]
        $issuer = $null; $conf = ''
        if ($Index.Out.ContainsKey($cur)) { foreach ($r in $Index.Out[$cur]) { if ($null -ne $r -and [string]$r.Type -eq 'issuedBy' -and $ent.ContainsKey([string]$r.To) -and [string]$r.To -ne $cur) { $issuer = [string]$r.To; $conf = [string]$r.Confidence; break } } }
        $caName = ''
        if ($Index.Out.ContainsKey($cur)) { foreach ($r in $Index.Out[$cur]) { if ($null -ne $r -and [string]$r.Type -eq 'certificateOf' -and $ent.ContainsKey([string]$r.To)) { $caName = [string]$ent[[string]$r.To].Name } } }
        if (-not $caName) { $caName = Get-MspkiGuiCnOf ([string](& $prop $e 'Subject')); if (-not $caName) { $caName = Get-MspkiGuiCnOf ([string]$e.Name) } }
        $role = [string](& $prop $e 'Role')
        $self = ([string](& $prop $e 'Subject') -and [string](& $prop $e 'Subject') -eq [string](& $prop $e 'Issuer'))
        $isRoot = ($null -eq $issuer) -and ($self -or $role -match 'Root')
        $na = ConvertTo-MspkiGuiDateTime -Value (& $prop $e 'NotAfter')
        $valid = 'Validity not read'; $vt = 'Neutral'
        if ($null -ne $na) {
            $left = ($na - $Now).TotalDays
            if ($left -lt 0) { $valid = 'Expired {0} ago' -f (Get-MspkiGuiSpanText -Days $left); $vt = 'Bad' } else { $valid = 'Valid until {0} ({1} left)' -f (Format-MspkiGuiTimelineDate -Date $na), (Get-MspkiGuiSpanText -Days $left); $vt = 'Good' }
        }
        # The issuer's generations (all certificates with the issuer's key) and the CRLs it signs: what the AIA and CDP addresses should serve.
        $issuerIds = @(); $crlIds = @()
        if ($issuer) {
            $issuerIds = @($issuer)
            # Every certificate with the issuer's key serves the AIA reference (a renewal with the same key is a new certificate).
            $ski = [string](& $prop $ent[$issuer] 'SubjectKeyId')
            if ($ski) { foreach ($o in $ent.Values) { if ([string]$o.Type -eq 'CACertificate' -and [string]$o.Id -ne $issuer -and [string](& $prop $o 'SubjectKeyId') -eq $ski) { $issuerIds += [string]$o.Id } } }
            if ($Index.In.ContainsKey($issuer)) { foreach ($r in $Index.In[$issuer]) { if ($null -ne $r -and [string]$r.Type -eq 'signedBy') { $crlIds += [string]$r.From } } }
        }
        $addr = @{ AIA = (New-Object System.Collections.ArrayList); CDP = (New-Object System.Collections.ArrayList); OCSP = (New-Object System.Collections.ArrayList) }
        # A certificate on this computer: the run did not read the addresses inside it, so the chain shows the addresses its CA writes into
        # the certificates it issues (the CA's CertAiaUrls / CertCdpUrls / CertAiaOcspUrls settings), marked as Inferred.
        $refFrom = $cur; $fromCa = $false
        if ([string]$e.Type -eq 'LocalCertificate' -and $issuer -and $Index.Out.ContainsKey($issuer)) {
            foreach ($r in $Index.Out[$issuer]) { if ($null -ne $r -and [string]$r.Type -eq 'certificateOf' -and $ent.ContainsKey([string]$r.To)) { $refFrom = [string]$r.To; $fromCa = $true } }
        }
        $settingKind = @{ CertAiaUrls = 'AIA'; CertCdpUrls = 'CDP'; CertAiaOcspUrls = 'OCSP' }
        if ($Index.Out.ContainsKey($refFrom)) {
            foreach ($r in $Index.Out[$refFrom]) {
                if ($null -eq $r -or [string]$r.Type -ne 'references') { continue }
                $to = [string]$r.To
                if (-not $ent.ContainsKey($to) -or [string]$ent[$to].Type -ne 'Endpoint') { continue }
                $k = ''
                if ($fromCa) {
                    foreach ($s in @($r.Sources)) { if ([string]$s -match ':(CertAiaUrls|CertCdpUrls|CertAiaOcspUrls)$') { $k = $settingKind[$Matches[1]] } }
                    if (-not $k) { continue }
                }
                else { foreach ($s in @($r.Sources)) { if ([string]$s -match ':(AIA|CDP|OCSP)$') { $k = $Matches[1] } } }
                if (-not $k -and -not $fromCa) { foreach ($kk in @($ent[$to].Properties.Kinds)) { if ([string]$kk -in @('AIA', 'CDP', 'OCSP')) { $k = [string]$kk } } }
                if ($k -eq 'FreshestCRL') { $k = 'CDP' }
                if (-not $addr.ContainsKey($k)) { continue }
                [void]$addr[$k].Add((Get-MspkiGuiChainAddress -Index $Index -FindingStatus $FindingStatus -EndpointId $to -Kind $k -IssuerIds $issuerIds -CrlIds $crlIds -Now $Now))
            }
        }
        $st = New-Object System.Collections.Generic.List[string]
        if ($Index.Findings.ContainsKey($cur)) { foreach ($fid in $Index.Findings[$cur]) { $st.Add([string]$FindingStatus[[string]$fid]) } }
        $tone = Get-MspkiGuiWorseTone -A $vt -B (Get-MspkiGuiNodeHealth -Statuses $st.ToArray())
        # Revocation is part of this certificate's health: no CDP address serving a valid CRL fails it, some failing is a warning.
        # (The AIA addresses are shown on the link to the issuer.)
        if ($addr.CDP.Count -gt 0) {
            $cdpGood = 0; $cdpBad = 0; $cdpWarn = 0
            foreach ($a in $addr.CDP) { if ($a.Tone -eq 'Good') { $cdpGood++ } elseif ($a.Tone -eq 'Bad') { $cdpBad++ } elseif ($a.Tone -eq 'Warn') { $cdpWarn++ } }
            if ($cdpGood -eq 0 -and $cdpWarn -eq 0 -and $cdpBad -gt 0) { $tone = Get-MspkiGuiWorseTone -A $tone -B 'Bad' }
            elseif ($cdpBad -gt 0 -or $cdpWarn -gt 0) { $tone = Get-MspkiGuiWorseTone -A $tone -B 'Warn' }
        }
        $kindText = $(if ([string]$e.Type -eq 'LocalCertificate') { 'Certificate on this computer' } elseif ($isRoot) { 'Root CA certificate' } else { 'CA certificate' })
        $gen = [string](& $prop $e 'Generation'); $life = [string](& $prop $e 'Lifecycle')
        $sub = (@($kindText, $(if ($gen) { 'generation ' + $gen } else { '' }), $(if ($life -eq 'Historical') { 'replaced' } elseif ($life -eq 'Current') { 'current' } else { '' })) | Where-Object { $_ }) -join (' ' + [char]0x00B7 + ' ')
        $note = ''
        if ([string]$e.Type -eq 'LocalCertificate') { $note = $(if ($fromCa -and ($addr.AIA.Count + $addr.CDP.Count + $addr.OCSP.Count) -gt 0) { 'This run did not read the addresses inside this certificate. Shown are the addresses its CA writes into the certificates it issues (from the CA''s settings): Inferred, not read from the certificate.' } else { 'This run did not read the addresses inside this certificate; its issuer is shown below.' }) }
        elseif ($addr.AIA.Count -eq 0 -and $addr.CDP.Count -eq 0 -and -not $isRoot) { $note = 'This certificate names no AIA or CDP address that this run read.' }
        elseif ($isRoot) { $note = 'A root signs itself. Computers trust it because it is in their trusted root store (domain members get it from Active Directory''s Certification Authorities container).' }
        [void]$cards.Add([pscustomobject]@{ Id = $cur; Title = $(if ([string]$e.Type -eq 'LocalCertificate') { Get-MspkiGuiCnOf ([string]$e.Name) } else { $caName }); Sub = $sub; Validity = $valid; ValidityTone = $vt; Tone = $tone
                Root = $isRoot; Aia = @($addr.AIA); Cdp = @($addr.CDP); Ocsp = @($addr.OCSP); Note = $note; Placeholder = $false })
        if (-not $issuer) { break }
        # The link to the issuer: can a client that does not have the issuer yet fetch it from the addresses in this certificate?
        $iname = ''
        if ($Index.Out.ContainsKey($issuer)) { foreach ($r in $Index.Out[$issuer]) { if ($null -ne $r -and [string]$r.Type -eq 'certificateOf' -and $ent.ContainsKey([string]$r.To)) { $iname = [string]$ent[[string]$r.To].Name } } }
        if (-not $iname) { $iname = Get-MspkiGuiCnOf ([string]$ent[$issuer].Name) }
        $child = $cards[$cards.Count - 1].Title
        $aia = @($addr.AIA)
        $ok = @($aia | Where-Object { $_.Tone -eq 'Good' }).Count
        $badN = @($aia | Where-Object { $_.Tone -eq 'Bad' }).Count
        $warnN = @($aia | Where-Object { $_.Tone -eq 'Warn' }).Count
        # An address that answered with a warning still served the issuer: it counts as served (the warning is on the address).
        $served = $ok + $warnN
        $lt = 'Neutral'; $lx = ''
        $allText = $(if ($aia.Count -eq 1) { 'the one address in the certificate' } elseif ($aia.Count -eq 2) { 'both addresses in the certificate' } else { 'all {0} addresses in the certificate' -f $aia.Count })
        if ([string]$e.Type -eq 'LocalCertificate' -and $aia.Count -eq 0) { $lx = '{0} issued this certificate (matched by key identifier).' -f $iname; $lt = 'Good' }
        elseif ($aia.Count -eq 0) { $lx = '{0} issued {1}. The certificate names no address to fetch {0} from: clients must already have it (for example from Active Directory).' -f $iname, $child }
        elseif ($ok -eq $aia.Count) { $lt = 'Good'; $lx = '{0} issued {1}. Clients can fetch {0} from {2}.' -f $iname, $child, $allText }
        elseif ($served -eq $aia.Count) { $lt = 'Warn'; $lx = '{0} issued {1}. Clients can fetch {0} from {2}, but with a warning (see the address above).' -f $iname, $child, $allText }
        elseif ($served -gt 0) { $lt = 'Warn'; $lx = '{0} issued {1}. Clients can fetch {0} from {2} of {3} addresses; they try the addresses in order, so a failing one first slows every chain check.' -f $iname, $child, $served, $aia.Count }
        elseif ($badN -gt 0) { $lt = 'Bad'; $lx = '{0} issued {1}, but no address in the certificate served {0} in this run: a client that does not already have {0} cannot build this chain. This is where the chain breaks.' -f $iname, $child }
        else { $lx = '{0} issued {1}. This run did not check the addresses in the certificate.' -f $iname, $child }
        if ($conf -eq 'Inferred') { $lx += ' The link is matched by name only (the certificate has no key identifier), so it is Inferred.' }
        [void]$links.Add([pscustomobject]@{ Tone = $lt; Text = $lx; Inferred = ($conf -eq 'Inferred'); Ok = $served; Warn = $warnN; Total = $aia.Count })
        $cur = $issuer
    }
    $last = $cards[$cards.Count - 1]
    if (-not $last.Root) {
        $why = 'This run did not find the certificate of the CA that issued {0}.' -f $last.Title
        [void]$links.Add([pscustomobject]@{ Tone = 'Neutral'; Text = ('Issuer not confirmed. ' + $why); Inferred = $true; Ok = 0; Warn = 0; Total = 0 })
        [void]$cards.Add([pscustomobject]@{ Id = ''; Title = 'Issuer not found'; Sub = 'Not confirmed'; Validity = ''; ValidityTone = 'Neutral'; Tone = 'Neutral'; Root = $false; Aia = @(); Cdp = @(); Ocsp = @()
                Note = $why + ' Check the AIA addresses above, or run as a user who can read every CA.'; Placeholder = $true })
    }
    $broken = @($links | Where-Object { $_.Tone -eq 'Bad' }).Count
    $warnL = @($links | Where-Object { $_.Tone -eq 'Warn' }).Count
    # Revocation: a certificate whose every CDP address failed cannot be checked; one that failed somewhere is a warning.
    $noRev = @($cards | Where-Object { @($_.Cdp).Count -gt 0 -and @($_.Cdp | Where-Object { $_.Tone -eq 'Bad' }).Count -eq @($_.Cdp).Count })
    $warnRev = @($cards | Where-Object { @($_.Cdp | Where-Object { $_.Tone -in @('Bad', 'Warn') }).Count -gt 0 })
    $head = ''; $headTone = 'Good'
    if ($broken -gt 0) { $head = 'The chain breaks: a client that does not already have every CA certificate cannot fetch one of them.'; $headTone = 'Bad' }
    elseif ($noRev.Count -gt 0) { $head = 'The chain builds, but clients cannot check whether {0} was revoked: none of its CDP addresses served a valid CRL. Clients that require a revocation check reject it.' -f $noRev[0].Title; $headTone = 'Bad' }
    elseif ($warnL -gt 0 -or $warnRev.Count -gt 0) { $head = 'The chain builds, but some addresses fail or serve an older CRL: clients may wait on them first.'; $headTone = 'Warn' }
    elseif ($cards[$cards.Count - 1].Placeholder) { $head = 'The chain could not be followed to a root.'; $headTone = 'Neutral' }
    else { $head = 'The chain can be built and checked from the addresses in the certificates.' }
    return [pscustomobject]@{ Cards = @($cards); Links = @($links); Headline = $head; HeadlineTone = $headTone }
}

# ===== Timeline rows (pure: text and numbers only, so the background map worker can build them; the window binds them as they are) =====

$script:MspkiGuiTlLabelWidth = 264
$script:MspkiGuiTlLabelText = '264'
$script:MspkiGuiToneGlyph = @{ Good = [string][char]0xE73E; Warn = [string][char]0xE7BA; Bad = [string][char]0xE711; Admin = [string][char]0xE72E; Neutral = [string][char]0xE738; Info = [string][char]0xE946 }
$script:MspkiGuiToneTitle = @{ Good = 'Healthy'; Warn = 'Warning'; Bad = 'Failing'; Admin = 'Could not check'; Neutral = 'No finding'; Info = 'Information' }

function New-MspkiGuiStarLength {
    # A proportional grid length for a number of days, as the text WPF converts itself ("12.5*"; 0 stays 0: the column takes no room).
    # Text, not a GridLength object: building a hundred rows stays cheap, and the rows can be built without WPF.
    param([double]$Value)
    return ([math]::Max(0.0, $Value)).ToString('0.######', [System.Globalization.CultureInfo]::InvariantCulture) + '*'
}

function ConvertTo-MspkiGuiTimelineItem {
    <#
    .SYNOPSIS
    One row of the timeline list from a lifecycle row, a CA group or a CRL copy: label, status, countdown and the bar on the axis. Kind is Group,
    Row, Copy or Note. A plain function (no [CmdletBinding()]): it runs once per row and advanced functions cost several times more to call.
    #>
    param([string]$Kind, $Source, $Range, [datetime]$Now, [bool]$First = $false, [string]$GroupName = '', [string]$Summary = '', [string]$GroupTone = '')
    $tone = $(if ($GroupTone) { $GroupTone } else { [string]$Source.Tone }); if (-not $tone) { $tone = 'Neutral' }
    $word = $script:MspkiGuiToneTitle[$tone]
    $item = [ordered]@{ Kind = $Kind; Id = ''; Tone = $tone; Glyph = $script:MspkiGuiToneGlyph[$tone]; GlyphSize = 14; ToneWord = $word; Title = ''; TitleWeight = 'Normal'; TitleSize = 14; TitleWrap = 'NoWrap'; Sub = ''; HasSub = $false
        Due = $null; HasDue = $false; Pill = [pscustomobject]@{ Text = ''; Tone = 'Neutral'; Glyph = '' }; Tip = ''; AutomationName = ''; RowHeight = 48.0; LabelWidth = $script:MspkiGuiTlLabelText
        LabelMargin = '20,6,12,6'; HasBar = $false; BarHeight = 14.0; WBefore = (New-MspkiGuiStarLength 1); WMain = (New-MspkiGuiStarLength 0); WTail = (New-MspkiGuiStarLength 0); WAfter = (New-MspkiGuiStarLength 0)
        HasTail = $false; MainCorner = '3'; ClipStart = $false; ClipEnd = $false; EndColumn = 1; Outside = ''; HasOutside = $false; OutsideAlign = 'Left'; NowL = (New-MspkiGuiStarLength 1); NowR = (New-MspkiGuiStarLength 1)
        RuleThickness = '0'; Group = ''; Entity = '' }
    $bar = $null
    switch ($Kind) {
        'Group' {
            $item.Id = [string]$Source.CaId; $item.Group = [string]$Source.Key
            if (-not $item.Id) { $first = @(@($Source.Certs) + @($Source.Crls) | Where-Object { $_.Id }) | Select-Object -First 1; if ($null -ne $first) { $item.Id = [string]$first.Id } }
            $item.Tone = 'Neutral'; $item.Glyph = [string][char]0xEB95; $item.GlyphSize = 16
            $item.Title = [string]$Source.Name; $item.TitleWeight = 'SemiBold'; $item.TitleSize = 15; $item.TitleWrap = 'Wrap'
            $item.Sub = $(if ($Summary) { $Summary } else { [string]$Source.Summary }); $item.HasSub = [bool]$item.Sub
            $item.Pill = [pscustomobject]@{ Text = $word; Tone = $tone; Glyph = $script:MspkiGuiToneGlyph[$tone] }
            $item.RowHeight = 56.0; $item.LabelMargin = '12,8,12,8'
            if (-not $First) { $item.RuleThickness = '0,1,0,0' }
            $item.Tip = '{0}: {1}. {2}' -f $item.Title, $word, $item.Sub
            if ($Source.Unread) { $item.Tip += ' This run could not read the CA itself; what is shown was read elsewhere (Active Directory or a published address).' }
            $item.AutomationName = '{0}, {1}. {2}' -f $item.Title, $word, $item.Sub
        }
        'Row' {
            $item.Id = [string]$Source.Id; $item.Entity = [string]$Source.Id; $item.Group = [string]$Source.Group
            $item.Title = [string]$Source.Label; $item.TitleWeight = 'SemiBold'
            $item.Sub = [string]$Source.Sub; $item.HasSub = [bool]$item.Sub
            $ct = [string]$Source.CountdownTone; if (-not $ct) { $ct = 'Neutral' }
            # The state word only where it adds something the countdown does not say (Valid and Expired do not).
            $dueText = [string]$Source.Countdown
            if ($Source.State -and [string]$Source.State -notin @('Valid', 'Expired')) { $cd = [string]$Source.Countdown; if ($cd -match '^(Expires|Expired|Next update|Valid from)') { $cd = $cd.Substring(0, 1).ToLowerInvariant() + $cd.Substring(1) }; $dueText = '{0} {1} {2}' -f $Source.State, [char]0x00B7, $cd }
            $item.Due = [pscustomobject]@{ Text = $dueText; Tone = $ct; Glyph = $(if ($ct -in @('Bad', 'Warn')) { [string][char]0xE823 } else { '' }) }
            $item.HasDue = $true
            $item.RowHeight = 60.0
            $item.Tip = [string]$Source.Tip
            $item.AutomationName = '{0} of {1}, {2}. {3}. {4}' -f $item.Title, $GroupName, $word, $item.Sub, $item.Due.Text
            if ([string]$Source.Kind -eq 'Missing') { $item.Outside = 'Dates unknown: this run could not read this certificate'; $item.HasOutside = $true }
            else { $bar = $Source }
        }
        'Copy' {
            $item.Entity = ''; $item.Id = [string]$Source.ParentId; $item.Group = [string]$Source.Group
            $item.Glyph = $script:MspkiGuiToneGlyph[$tone]; $item.GlyphSize = 11
            $item.Title = [string]$Source.Title; $item.TitleSize = 13
            $item.Due = [pscustomobject]@{ Text = [string]$Source.Text; Tone = $tone; Glyph = '' }; $item.HasDue = $true
            $item.RowHeight = 42.0; $item.LabelMargin = '36,4,12,4'; $item.BarHeight = 8.0
            $item.Tip = '{0}: {1}' -f $Source.Where, $Source.Text
            $item.AutomationName = 'Copy {0}: {1}' -f $Source.Title, $Source.Text
            if ($Source.Missing) { $item.Outside = 'Not found at this address'; $item.HasOutside = $true }
            else { $bar = [pscustomobject]@{ Start = $Source.ThisUpdate; End = $Source.NextUpdate; Mark = $null } }
        }
        'Note' {
            $item.Id = [string]$Source.Id; $item.Group = [string]$Source.Group
            $item.Title = [string]$Source.Title; $item.TitleSize = 13
            $item.Glyph = $script:MspkiGuiToneGlyph[$tone]; $item.GlyphSize = 12
            $item.RowHeight = 44.0
            $item.Tip = [string]$Source.Tip; $item.AutomationName = [string]$Source.Title
            $item.Outside = [string]$Source.Lane; $item.HasOutside = [bool]$item.Outside
        }
    }
    if ($null -ne $Range) {
        $total = ($Range.End - $Range.Start).TotalDays
        $nl = [math]::Min([math]::Max(($Now - $Range.Start).TotalDays, 0), $total)
        $item.NowL = New-MspkiGuiStarLength $nl; $item.NowR = New-MspkiGuiStarLength ($total - $nl)
        if ($null -ne $bar) {
            $b = Get-MspkiGuiTimelineBar -Row $bar -Range $Range -Now $Now
            if ($b.HasBar) {
                $item.HasBar = $true
                $item.WBefore = New-MspkiGuiStarLength $b.Before; $item.WMain = New-MspkiGuiStarLength $b.Main; $item.WTail = New-MspkiGuiStarLength $b.Tail; $item.WAfter = New-MspkiGuiStarLength $b.After
                $item.HasTail = ($b.Tail -gt 0); $item.ClipStart = $b.ClipStart; $item.ClipEnd = $b.ClipEnd
                $item.MainCorner = $(if ($b.Tail -gt 0) { '3,0,0,3' } else { '3' })
                $item.EndColumn = $(if ($b.Tail -gt 0) { 2 } else { 1 })
            }
            elseif ($b.Outside) {
                $item.HasOutside = $true
                if ($b.Outside -eq 'Before') { $item.Outside = 'Ended before this range'; $item.OutsideAlign = 'Left' } else { $item.Outside = 'Starts after this range'; $item.OutsideAlign = 'Right' }
            }
            elseif (-not $item.HasOutside) { $item.Outside = 'No dates in the results'; $item.HasOutside = $true }
        }
    }
    return [pscustomobject]$item
}

function Get-MspkiGuiTimelineItemList {
    <#
    .SYNOPSIS
    The rows of one view (Certificates or Crls): a CA row, then its certificates or its CRLs (and the copy of each CRL at every address).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Model, [Parameter(Mandatory = $true)][ValidateSet('Certificates', 'Crls')][string]$View, $Range, [bool]$Copies = $true)
    $items = New-Object 'System.Collections.Generic.List[object]'
    $first = $true
    foreach ($gp in $Model.Groups) {
        $items.Add((ConvertTo-MspkiGuiTimelineItem -Kind Group -Source $gp -Range $Range -Now $Model.Now -First $first -Summary $(if ($View -eq 'Certificates') { [string]$gp.CertSummary } else { [string]$gp.CrlSummary }) -GroupTone $(if ($View -eq 'Certificates') { [string]$gp.CertTone } else { [string]$gp.CrlTone })))
        $first = $false
        if ($View -eq 'Certificates') {
            foreach ($r in $gp.Certs) { $items.Add((ConvertTo-MspkiGuiTimelineItem -Kind Row -Source $r -Range $Range -Now $Model.Now -GroupName $gp.Name)) }
            continue
        }
        if (@($gp.Crls).Count -eq 0) {
            $why = $(if ($gp.Unread) { 'This run could not read the CA, so its CRLs are unknown.' } else { 'This run read no CRL signed by this CA: none was published where the run looked, or the run did not reach it.' })
            $items.Add((ConvertTo-MspkiGuiTimelineItem -Kind Note -Source ([pscustomobject]@{ Id = $gp.CaId; Group = $gp.Key; Tone = $(if ($gp.Unread) { 'Admin' } else { 'Neutral' }); Title = 'No CRL read'; Tip = $why; Lane = $why }) -Range $Range -Now $Model.Now))
            continue
        }
        foreach ($r in $gp.Crls) {
            $items.Add((ConvertTo-MspkiGuiTimelineItem -Kind Row -Source $r -Range $Range -Now $Model.Now -GroupName $gp.Name))
            if (-not $Copies) { continue }
            foreach ($c in $r.Copies) {
                $title = [string]$c.Where
                if ($c.Source -ne 'CA') {
                    $u = [string]$c.Where
                    if ($u -match '^(?i)ldap:') { $title = 'Active Directory (LDAP) ' + [char]0x00B7 + ' ' + (Get-MspkiGuiEndpointLabel -Url $u) }
                    elseif ($u -match '^[a-zA-Z]+://([^/:]+)') { $title = '{0} {1} {2}' -f (Get-MspkiGuiShortHost -Name $Matches[1]), [char]0x00B7, (Get-MspkiGuiEndpointLabel -Url $u) }
                }
                else { $title = 'At the CA' }
                $src = [pscustomobject]@{ ParentId = $r.Id; Group = $gp.Key; Tone = $c.Tone; Title = $title; Where = $c.Where; Text = $c.Text; Missing = $c.Missing; ThisUpdate = $c.ThisUpdate; NextUpdate = $c.NextUpdate }
                $items.Add((ConvertTo-MspkiGuiTimelineItem -Kind Copy -Source $src -Range $Range -Now $Model.Now))
            }
        }
    }
    return , $items.ToArray()
}

function Invoke-MspkiGuiTimelineJob {
    <#
    .SYNOPSIS
    One timeline computation, the same in the window's background map worker and inline: the lifecycle model once per results generation
    (kept in -Cache), then the rows of the requested view (Certificates or Crls) on its time axis. Options: Now, RunInfo, View, SpanDays, Copies.
    Returns the model, the range, the rows and the time each step took.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Request, [AllowNull()]$Index, [hashtable]$Status = @{}, [Parameter(Mandatory = $true)][hashtable]$Cache)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $o = $Request.Options
    if (-not $Cache.ContainsKey('TlGen') -or $Cache.TlGen -ne $Request.Gen) {
        $Cache.TlModel = Get-MspkiGuiLifecycleModel -Index $Index -FindingStatus $Status -Now ([datetime]$o.Now) -RunInfo $o.RunInfo
        $Cache.TlGen = $Request.Gen
    }
    $modelMs = $sw.ElapsedMilliseconds
    $m = $Cache.TlModel
    $range = $null; $items = $null
    $view = [string]$o.View
    if ($null -ne $m -and $view -in @('Certificates', 'Crls')) {
        $sw.Restart()
        $copies = ($view -eq 'Crls' -and [bool]$o.Copies)
        $rows = New-Object System.Collections.ArrayList
        foreach ($gp in $m.Groups) { foreach ($r in $(if ($view -eq 'Certificates') { $gp.Certs } else { $gp.Crls })) { if ([string]$r.Kind -ne 'Missing') { [void]$rows.Add($r) } } }
        $forRange = $rows
        if (-not $copies) { $forRange = @(foreach ($r in $rows) { [pscustomobject]@{ Start = $r.Start; End = $r.End; Mark = $r.Mark; Copies = @() } }) }
        $range = Get-MspkiGuiTimelineRange -Rows $(if ($forRange -is [System.Collections.ArrayList]) { $forRange.ToArray() } else { @($forRange) }) -Now $m.Now -SpanDays ([double]$o.SpanDays) -MinDays $(if ($view -eq 'Crls') { 2 } else { 60 }) -FocusDays $(if ($view -eq 'Crls') { 31 } else { 0 })
        $items = Get-MspkiGuiTimelineItemList -Model $m -View $view -Range $range -Copies $copies
    }
    return [pscustomobject]@{ Kind = 'Timeline'; Gen = $Request.Gen; View = $view; Model = $m; Range = $range; Items = $items; ModelMs = $modelMs; ItemsMs = $sw.ElapsedMilliseconds }
}

function Get-MspkiGuiChainLinkHeading {
    # The heading of an "issued by" link in the chain: how many AIA addresses served the issuer ("1 of 2 AIA addresses served it, 1 with a
    # warning"; "its AIA address served it"). An address that answered with a warning served it.
    param([Parameter(Mandatory = $true)]$Link)
    $dot = [char]0x00B7
    $total = [int]$Link.Total; $ok = [int]$Link.Ok; $warn = 0
    if ($null -ne $Link.PSObject.Properties['Warn']) { $warn = [int]$Link.Warn }
    if ($total -le 0) { return 'Issued by' }
    $tail = $(if ($warn -eq 1 -and $total -eq 1) { ', with a warning' } elseif ($warn -gt 0) { ', {0} with a warning' -f $warn } else { '' })
    if ($total -eq 1) { return $(if ($ok -ge 1) { 'Issued by {0} its AIA address served it{1}' -f $dot, $tail } else { 'Issued by {0} its AIA address did not serve it' -f $dot }) }
    return ('Issued by {0} {1} of {2} AIA addresses served it{3}' -f $dot, $ok, $total, $tail)
}
