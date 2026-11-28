# History page (GX8), pure side: finds the runs saved under the output folder, sums each one up (score, counts) and compares two runs
# (new, resolved and changed findings; objects added or gone; the score per area). Read-only: files are only read, never written.
# Runs in the window's background map worker (Invoke-MspkiGuiHistoryJob) and inline in tests. Needs GuiModel.ps1, GuiView.ps1 and
# GuiMission.ps1 (the score).

$script:MspkiGuiHistoryMaxRuns = 60
$script:MspkiGuiHistoryProblem = @('Critical', 'Fail', 'Warning')
$script:MspkiGuiHistoryRank = @{ Critical = 5; Fail = 4; Warning = 3; Error = 2; Skipped = 1; Information = 0; Pass = 0; NotApplicable = 0 }

function Find-MspkiGuiRunFile {
    <#
    .SYNOPSIS
    The results.json files of earlier runs under -Root: one and two folders down (a run folder, or a run folder inside a folder given as
    -OutputPath), newest first, at most -Max. Each: Path, Folder, Written (UTC), Size. Nothing is opened.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root, [int]$Max = $script:MspkiGuiHistoryMaxRuns)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { return @() }
    $files = New-Object System.Collections.ArrayList
    $top = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($Root))
    foreach ($d1 in $top.GetDirectories()) {
        $f = [System.IO.FileInfo]::new((Join-Path $d1.FullName 'results.json'))
        if ($f.Exists) { [void]$files.Add($f) }
        try { foreach ($d2 in $d1.GetDirectories()) { $f2 = [System.IO.FileInfo]::new((Join-Path $d2.FullName 'results.json')); if ($f2.Exists) { [void]$files.Add($f2) } } } catch { $null = $_ }
    }
    $arr = [object[]]$files.ToArray()
    $keys = [long[]]@(foreach ($f in $arr) { - $f.LastWriteTimeUtc.Ticks })
    [Array]::Sort([Array]$keys, [Array]$arr)
    return @($arr | Select-Object -First $Max | ForEach-Object { [pscustomobject]@{ Path = $_.FullName; Folder = $_.Directory.Name; Written = $_.LastWriteTimeUtc; Size = $_.Length } })
}

function Get-MspkiGuiRunSummary {
    <#
    .SYNOPSIS
    One run in a line: when it started, the forest, who ran it, whether it finished, the score (overall and per area), the number of
    findings per status. -Data is a document from Read-MspkiGuiResults. Error is set (and nothing else) when the file could not be read.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, $Data = $null, [string]$ReadError = '')
    $s = [ordered]@{ Path = $Path; Folder = (Split-Path -Leaf (Split-Path -Parent $Path)); Error = $ReadError; Started = $null; Forest = ''; Domain = ''; User = ''; Computer = ''
        Completed = $true; SkipNetwork = $false; Score = $null; Band = ''; Tone = 'Neutral'; Areas = @(); Total = 0; Fail = 0; Warn = 0; NotChecked = 0; HasGraph = $false; HasKeys = $false; ToolVersion = '' }
    if ($null -eq $Data) { return [pscustomobject]$s }
    $ri = $Data.RunInfo
    if ($null -ne $ri) {
        $s.Started = ConvertTo-MspkiGuiDateTime -Value $ri.StartedUtc
        $s.Forest = [string]$ri.Forest; $s.Domain = [string]$ri.Domain; $s.User = [string]$ri.UserContext; $s.Computer = [string]$ri.ComputerName; $s.ToolVersion = [string]$ri.ToolVersion
        if ($null -ne $ri.PSObject.Properties['Completed'] -and $null -ne $ri.Completed) { $s.Completed = ConvertTo-MspkiGuiFlag -Value $ri.Completed }
        if ($null -ne $ri.PSObject.Properties['Parameters'] -and $null -ne $ri.Parameters) {
            $prm = $ri.Parameters
            # A switch can be stored as true/false or as the text "True"/"False" (and [bool]'False' is true in PowerShell).
            $sv = $null
            if ($prm -is [System.Collections.IDictionary]) { if ($prm.Contains('SkipNetwork')) { $sv = $prm['SkipNetwork'] } }
            elseif ($null -ne $prm.PSObject.Properties['SkipNetwork']) { $sv = $prm.SkipNetwork }
            if ($null -ne $sv) { $s.SkipNetwork = ConvertTo-MspkiGuiFlag -Value $sv }
        }
    }
    $findings = @($Data.Findings | Where-Object { $null -ne $_ })
    $hasCa = $false
    if ($null -ne $Data.Inventory -and $null -ne $Data.Inventory.PSObject.Properties['EnterpriseCAs']) { $hasCa = (@($Data.Inventory.EnterpriseCAs | Where-Object { $null -ne $_ }).Count -gt 0) }
    $sc = Get-MspkiGuiHealthScore -Findings $findings -Completed $s.Completed -HasCa $hasCa
    if ($sc.HasScore) { $s.Score = [int]$sc.Overall; $s.Band = [string]$sc.Band; $s.Tone = [string]$sc.Tone }
    $s.Areas = @(foreach ($a in $sc.Areas) { [pscustomobject]@{ Key = $a.Key; Name = $a.Name; Score = $a.Score } })
    $s.Total = $findings.Count
    foreach ($f in $findings) {
        switch ([string]$f.Status) { 'Critical' { $s.Fail++ } 'Fail' { $s.Fail++ } 'Warning' { $s.Warn++ } 'Error' { $s.NotChecked++ } 'Skipped' { $s.NotChecked++ } }
        if (-not $s.HasKeys -and $null -ne $f.PSObject.Properties['Key'] -and $f.Key) { $s.HasKeys = $true }
    }
    $s.HasGraph = ($null -ne $Data.Graph)
    return [pscustomobject]$s
}

function Get-MspkiGuiFindingSubject {
    # What a finding is about, without the outcome: category, role, target and endpoint (used to pair findings whose Key changed because
    # their status code changed, for example from OBJECT_EXPIRING to OBJECT_EXPIRED).
    param($Finding)
    $ep = ''; if ($null -ne $Finding.PSObject.Properties['Endpoint']) { $ep = [string]$Finding.Endpoint }
    return ('{0}|{1}|{2}|{3}' -f [string]$Finding.Category, [string]$Finding.Role, ([string]$Finding.Target).Trim().ToLowerInvariant(), $ep.Trim().ToLowerInvariant())
}

function Compare-MspkiGuiRun {
    <#
    .SYNOPSIS
    Compares an older and a newer run (documents from Read-MspkiGuiResults). Findings are paired by Key first, then by subject (category,
    role, target, endpoint) in the order the runs produced them. Returns New (a problem the newer run has and the older did not),
    Resolved (a problem of the older run the newer one no longer has: passing now, or not reported), Changed (a problem in both whose
    status, code or severity changed, Worse or Better), StillOpen (count), objects Added and Gone (by entity id, when both runs have a
    graph), the score of each run per area, and Notes that say what the comparison cannot know.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Old, [Parameter(Mandatory = $true)]$New, $OldSummary = $null, $NewSummary = $null)
    $isProblem = { param($f) $script:MspkiGuiHistoryProblem -contains [string]$f.Status }
    $oldF = @($Old.Findings | Where-Object { $null -ne $_ })
    $newF = @($New.Findings | Where-Object { $null -ne $_ })
    $keyOf = { param($f) if ($null -ne $f.PSObject.Properties['Key'] -and $f.Key) { [string]$f.Key } else { '' } }
    # Pair by Key.
    $oldByKey = @{}
    for ($i = 0; $i -lt $oldF.Count; $i++) { $k = & $keyOf $oldF[$i]; if ($k -and -not $oldByKey.ContainsKey($k)) { $oldByKey[$k] = $i } }
    $oldUsed = New-Object 'bool[]' $oldF.Count
    $pairs = New-Object System.Collections.ArrayList
    $newLeft = New-Object System.Collections.ArrayList
    foreach ($f in $newF) {
        $k = & $keyOf $f
        if ($k -and $oldByKey.ContainsKey($k) -and -not $oldUsed[$oldByKey[$k]]) { $oldUsed[$oldByKey[$k]] = $true; [void]$pairs.Add(@($oldF[$oldByKey[$k]], $f)) }
        else { [void]$newLeft.Add($f) }
    }
    # Then by subject, in order.
    $oldBySubject = @{}
    for ($i = 0; $i -lt $oldF.Count; $i++) {
        if ($oldUsed[$i]) { continue }
        $sj = Get-MspkiGuiFindingSubject -Finding $oldF[$i]
        if (-not $oldBySubject.ContainsKey($sj)) { $oldBySubject[$sj] = New-Object System.Collections.Queue }
        $oldBySubject[$sj].Enqueue($i)
    }
    $unpairedNew = New-Object System.Collections.ArrayList
    foreach ($f in $newLeft) {
        $sj = Get-MspkiGuiFindingSubject -Finding $f
        if ($oldBySubject.ContainsKey($sj) -and $oldBySubject[$sj].Count -gt 0) { $i = [int]$oldBySubject[$sj].Dequeue(); $oldUsed[$i] = $true; [void]$pairs.Add(@($oldF[$i], $f)) }
        else { [void]$unpairedNew.Add($f) }
    }
    $item = {
        param($f, [string]$kind, [string]$before, [string]$after)
        # The finding shown (its message), and its status in the older run (Before) and in the newer run (After); empty when it is not in that run.
        $st = [string]$f.Status
        [pscustomobject]@{ Kind = $kind; Id = [string]$f.Id; Key = (& $keyOf $f); Category = [string]$f.Category; Target = [string]$f.Target; Status = $st; Before = $before; After = $after
            Severity = [string]$f.Severity; Code = [string]$f.StatusCode; Message = [string]$f.Message; Rank = [int]$script:MspkiGuiHistoryRank[$st] }
    }
    $listNew = New-Object System.Collections.ArrayList; $listResolved = New-Object System.Collections.ArrayList; $listChanged = New-Object System.Collections.ArrayList
    $stillOpen = 0; $newPassing = 0
    foreach ($p in $pairs) {
        $o = $p[0]; $n = $p[1]
        $op = & $isProblem $o; $np = & $isProblem $n
        if ($op -and -not $np) { [void]$listResolved.Add((& $item $o 'Resolved' ([string]$o.Status) ([string]$n.Status))); continue }
        if ($np -and -not $op) { [void]$listNew.Add((& $item $n 'New' ([string]$o.Status) ([string]$n.Status))); continue }
        if (-not $np) { continue }
        $diff = ([string]$o.Status -ne [string]$n.Status) -or ([string]$o.StatusCode -ne [string]$n.StatusCode) -or ([string]$o.Severity -ne [string]$n.Severity)
        if ($diff) {
            $ro = [int]$script:MspkiGuiHistoryRank[[string]$o.Status]; $rn = [int]$script:MspkiGuiHistoryRank[[string]$n.Status]
            $dir = $(if ($rn -gt $ro) { 'Worse' } elseif ($rn -lt $ro) { 'Better' } else { 'Changed' })
            [void]$listChanged.Add((& $item $n $dir ([string]$o.Status) ([string]$n.Status)))
        }
        else { $stillOpen++ }
    }
    foreach ($f in $unpairedNew) { if (& $isProblem $f) { [void]$listNew.Add((& $item $f 'New' '' ([string]$f.Status))) } else { $newPassing++ } }
    for ($i = 0; $i -lt $oldF.Count; $i++) { if (-not $oldUsed[$i] -and (& $isProblem $oldF[$i])) { [void]$listResolved.Add((& $item $oldF[$i] 'Gone' ([string]$oldF[$i].Status) '')) } }
    $byRank = { param($list) @($list | Sort-Object -Property @{ Expression = 'Rank'; Descending = $true }, @{ Expression = 'Category'; Descending = $false }, @{ Expression = 'Target'; Descending = $false }) }
    # Objects: entity ids are deterministic, so an id in one graph and not the other was added or is gone.
    $added = @(); $gone = @(); $objectsKnown = ($null -ne $Old.Graph -and $null -ne $New.Graph)
    if ($objectsKnown) {
        $oldIds = @{}; foreach ($e in @($Old.Graph.Entities)) { if ($null -ne $e) { $oldIds[[string]$e.Id] = $e } }
        $newIds = @{}; foreach ($e in @($New.Graph.Entities)) { if ($null -ne $e) { $newIds[[string]$e.Id] = $e } }
        $obj = { param($e, [string]$kind) [pscustomobject]@{ Kind = $kind; Id = [string]$e.Id; Type = [string]$e.Type; Name = $(if ($e.Name) { [string]$e.Name } else { [string]$e.Id }) } }
        $added = @(foreach ($k in $newIds.Keys) { if (-not $oldIds.ContainsKey($k)) { & $obj $newIds[$k] 'Added' } }) | Sort-Object Type, Name
        $gone = @(foreach ($k in $oldIds.Keys) { if (-not $newIds.ContainsKey($k)) { & $obj $oldIds[$k] 'Gone' } }) | Sort-Object Type, Name
    }
    if ($null -eq $OldSummary) { $OldSummary = Get-MspkiGuiRunSummary -Path ([string]$Old.ResultsPath) -Data $Old }
    if ($null -eq $NewSummary) { $NewSummary = Get-MspkiGuiRunSummary -Path ([string]$New.ResultsPath) -Data $New }
    $areas = @(foreach ($a in $NewSummary.Areas) {
            $o = @($OldSummary.Areas | Where-Object { $_.Key -eq $a.Key })[0]
            $os = $(if ($null -ne $o) { $o.Score } else { $null })
            $delta = $(if ($null -ne $a.Score -and $null -ne $os) { [int]$a.Score - [int]$os } else { $null })
            [pscustomobject]@{ Key = $a.Key; Name = $a.Name; Old = $os; New = $a.Score; Delta = $delta }
        })
    # What the comparison cannot know, said plainly (data honesty: a finding missing from a partial run was not checked, not resolved).
    $notes = New-Object System.Collections.ArrayList
    if (-not $OldSummary.Completed) { [void]$notes.Add('The older run did not finish: a problem it does not list may simply not have been checked then.') }
    if (-not $NewSummary.Completed) { [void]$notes.Add('The newer run did not finish: a problem it no longer lists may simply not have been checked, so "resolved" is not proven.') }
    if ($OldSummary.SkipNetwork -ne $NewSummary.SkipNetwork) { [void]$notes.Add('One of the runs did not check the network (-SkipNetwork): differences in web, LDAP and TLS checks come from that, not from the PKI.') }
    if ($OldSummary.Forest -and $NewSummary.Forest -and $OldSummary.Forest -ne $NewSummary.Forest) { [void]$notes.Add(('The runs are of different forests ({0} and {1}): the comparison means little.' -f $OldSummary.Forest, $NewSummary.Forest)) }
    if (-not $objectsKnown) { [void]$notes.Add('One of the runs was written without the object graph (an older version of the tool), so objects added or gone are not shown.') }
    if (-not $OldSummary.HasKeys -or -not $NewSummary.HasKeys) { [void]$notes.Add('One of the runs was written before findings had a Key: its findings are matched by what they are about, which is less exact.') }
    $delta = $(if ($null -ne $OldSummary.Score -and $null -ne $NewSummary.Score) { [int]$NewSummary.Score - [int]$OldSummary.Score } else { $null })
    return [pscustomobject]@{
        Old = $OldSummary; New = $NewSummary; ScoreDelta = $delta; Areas = $areas
        NewProblems = @(& $byRank $listNew); Resolved = @(& $byRank $listResolved); Changed = @(& $byRank $listChanged)
        StillOpen = $stillOpen; NewPassing = $newPassing; ObjectsKnown = $objectsKnown; Added = @($added); Gone = @($gone); Notes = @($notes)
    }
}

function Invoke-MspkiGuiHistoryJob {
    <#
    .SYNOPSIS
    One history computation, in the window's background worker or inline. Kind History: lists the runs under Options.Root and sums up as
    many as fit in Options.BudgetMs (default 300 ms; summaries are kept in -Cache by path, size and time), returning Pending when more
    are left, so the list fills in step by step and the worker stays free for the map. Kind HistoryCompare: compares Options.OldPath with
    Options.NewPath. Files are only read.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Request, [Parameter(Mandatory = $true)][hashtable]$Cache)
    $o = $Request.Options
    if (-not $Cache.ContainsKey('HistSum')) { $Cache.HistSum = @{} }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $read = {
        param([string]$p, $info)
        $ck = '{0}|{1}|{2}' -f $p, $info.Size, $info.Written.Ticks
        if ($Cache.HistSum.ContainsKey($ck)) { return $Cache.HistSum[$ck] }
        $d = $null; $err = ''
        try { $d = Read-MspkiGuiResults -Path $p } catch { $err = $_.Exception.Message }
        $s = Get-MspkiGuiRunSummary -Path $p -Data $d -ReadError $err
        $Cache.HistSum[$ck] = $s
        return $s
    }
    if ($Request.Kind -eq 'HistoryCompare') {
        $fi = { param($p) $x = [System.IO.FileInfo]::new($p); [pscustomobject]@{ Size = $x.Length; Written = $x.LastWriteTimeUtc } }
        $old = Read-MspkiGuiResults -Path ([string]$o.OldPath)
        $new = Read-MspkiGuiResults -Path ([string]$o.NewPath)
        $c = Compare-MspkiGuiRun -Old $old -New $new -OldSummary (& $read ([string]$o.OldPath) (& $fi ([string]$o.OldPath))) -NewSummary (& $read ([string]$o.NewPath) (& $fi ([string]$o.NewPath)))
        return [pscustomobject]@{ Kind = 'HistoryCompare'; Gen = $Request.Gen; Compare = $c; OldPath = [string]$o.OldPath; NewPath = [string]$o.NewPath; Ms = $sw.ElapsedMilliseconds }
    }
    $budget = 300; if ($o.ContainsKey('BudgetMs')) { $budget = [int]$o.BudgetMs }
    $files = @(Find-MspkiGuiRunFile -Root ([string]$o.Root))
    # The run on show, when it was loaded from somewhere else, is listed too (it is the newer run of the default comparison).
    if ($o.ContainsKey('Extra') -and [string]$o.Extra -and (Test-Path -LiteralPath ([string]$o.Extra) -PathType Leaf)) {
        $xp = [System.IO.Path]::GetFullPath([string]$o.Extra)
        if (-not @($files | Where-Object { [string]::Equals($_.Path, $xp, [System.StringComparison]::OrdinalIgnoreCase) })) {
            $xi = [System.IO.FileInfo]::new($xp)
            $files = @($files) + @([pscustomobject]@{ Path = $xi.FullName; Folder = $xi.Directory.Name; Written = $xi.LastWriteTimeUtc; Size = $xi.Length })
        }
    }
    $runs = New-Object System.Collections.ArrayList
    $pending = 0; $readNow = 0
    foreach ($f in $files) {
        $ck = '{0}|{1}|{2}' -f $f.Path, $f.Size, $f.Written.Ticks
        if ($Cache.HistSum.ContainsKey($ck)) { [void]$runs.Add($Cache.HistSum[$ck]); continue }
        # At least one file per step, so the list always moves on.
        if ($readNow -gt 0 -and $sw.ElapsedMilliseconds -ge $budget) { $pending++; continue }
        $readNow++
        [void]$runs.Add((& $read $f.Path $f))
    }
    return [pscustomobject]@{ Kind = 'History'; Gen = $Request.Gen; Root = [string]$o.Root; Runs = $runs.ToArray(); Pending = $pending; Found = $files.Count; Ms = $sw.ElapsedMilliseconds }
}

function Get-MspkiGuiHistoryForest {
    <#
    .SYNOPSIS
    The forests the listed runs are of, with how many runs each, the one of the run on show (or the one with the newest run) first.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Runs = @(), [string]$Prefer = '')
    $count = [ordered]@{}
    foreach ($r in $Runs) { if ($null -eq $r -or $r.Error) { continue }; $f = $(if ($r.Forest) { [string]$r.Forest } else { '(forest unknown)' }); if ($count.Contains($f)) { $count[$f]++ } else { $count[$f] = 1 } }
    $list = @(foreach ($k in $count.Keys) { [pscustomobject]@{ Forest = $k; Count = $count[$k]; Text = ('{0} ({1})' -f $k, (Format-MspkiGuiCount -Count $count[$k] -Singular 'run')) } })
    if ($Prefer) { $list = @(@($list | Where-Object { $_.Forest -eq $Prefer }) + @($list | Where-Object { $_.Forest -ne $Prefer })) }
    return $list
}

function Get-MspkiGuiHistoryRow {
    <#
    .SYNOPSIS
    The run list of one forest, newest first, as rows the window binds: date, score pill, counts, partial and "on show" marks, the trend
    points (oldest first, 0..1 of the score) and the default pair to compare (the run on show and the run before it).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Runs = @(), [string]$Forest = '', [string]$CurrentPath = '')
    $mine = @($Runs | Where-Object { $null -ne $_ -and -not $_.Error -and (($_.Forest -eq $Forest) -or (-not $_.Forest -and $Forest -eq '(forest unknown)')) })
    $arr = [object[]]$mine
    $keys = [long[]]@(foreach ($r in $arr) { if ($null -ne $r.Started) { - ([datetime]$r.Started).Ticks } else { 0 } })
    if ($arr.Count -gt 1) { [Array]::Sort([Array]$keys, [Array]$arr) }
    $cur = $(if ($CurrentPath) { [System.IO.Path]::GetFullPath($CurrentPath) } else { '' })
    $rows = @(for ($i = 0; $i -lt $arr.Count; $i++) {
            $r = $arr[$i]
            $isCur = ($cur -and [string]::Equals([System.IO.Path]::GetFullPath([string]$r.Path), $cur, [System.StringComparison]::OrdinalIgnoreCase))
            $when = $(if ($null -ne $r.Started) { Format-MspkiGuiTimelineDate -Date $r.Started -WithTime } else { 'Start time unknown' })
            $parts = @()
            if ($r.Fail -gt 0) { $parts += (Format-MspkiGuiCount -Count $r.Fail -Singular 'failure') }
            if ($r.Warn -gt 0) { $parts += (Format-MspkiGuiCount -Count $r.Warn -Singular 'warning') }
            if ($r.NotChecked -gt 0) { $parts += ('{0} not checked' -f $r.NotChecked) }
            if ($parts.Count -eq 0) { $parts += 'No problem found' }
            $scoreText = $(if ($null -ne $r.Score) { [string]$r.Score } else { [string][char]0x2014 })
            $tone = $(if ($null -ne $r.Score) { [string]$r.Tone } else { 'Neutral' })
            [pscustomobject]@{ Path = [string]$r.Path; Index = $i; When = $when; Started = $r.Started; Score = $r.Score; ScoreText = $scoreText; Tone = $tone
                Band = $(if ($r.Band) { [string]$r.Band } else { 'Not scored' }); Counts = ($parts -join ' ' + [char]0x00B7 + ' '); Partial = (-not $r.Completed); IsCurrent = [bool]$isCur
                Folder = [string]$r.Folder; Who = $(if ($r.User) { 'by {0} on {1}' -f $r.User, $r.Computer } else { '' })
                AutomationName = ('Run of {0}: score {1}, {2}{3}{4}' -f $when, $scoreText, ($parts -join ', '), $(if (-not $r.Completed) { ', did not finish' } else { '' }), $(if ($isCur) { ', on show' } else { '' }))
                Tip = ('{0}{1}{2}' -f [string]$r.Path, [Environment]::NewLine, $(if ($r.User) { 'Run by {0} on {1}, tool {2}' -f $r.User, $r.Computer, $r.ToolVersion } else { '' })) }
        })
    $newer = $null; $older = $null
    $ci = -1; for ($i = 0; $i -lt $rows.Count; $i++) { if ($rows[$i].IsCurrent) { $ci = $i; break } }
    if ($ci -lt 0 -and $rows.Count -gt 0) { $ci = 0 }
    if ($ci -ge 0) { $newer = $rows[$ci]; if ($ci + 1 -lt $rows.Count) { $older = $rows[$ci + 1] } }
    $trend = @(for ($i = $rows.Count - 1; $i -ge 0; $i--) { if ($null -ne $rows[$i].Score) { [pscustomobject]@{ Path = $rows[$i].Path; Score = [int]$rows[$i].Score; Tone = $rows[$i].Tone; When = $rows[$i].When } } })
    return [pscustomobject]@{ Rows = $rows; Newer = $newer; Older = $older; Trend = $trend }
}

function Get-MspkiGuiCompareView {
    <#
    .SYNOPSIS
    What the window shows for a comparison (pure): the title, the two runs, the score change, one line per area, the notes and the
    sections (new problems, changed, resolved, objects added, objects gone), each with at most -MaxItems rows and an "and N more" line.
    A finding of the run on show can be opened (Tag f:<Id>, when -OpenIds has it); a finding only in the older run cannot.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Compare, [hashtable]$OpenIds = @{}, [int]$MaxItems = 40)
    $c = $Compare
    $dot = [char]0x00B7
    $minus = [string][char]0x2212
    $when = { param($s) if ($null -ne $s.Started) { Format-MspkiGuiTimelineDate -Date $s.Started -WithTime } else { 'start time unknown' } }
    $scoreOf = { param($s) if ($null -ne $s.Score) { [string]$s.Score } else { [string][char]0x2014 } }
    $glyphOf = @{ Bad = [string][char]0xE711; Warn = [string][char]0xE7BA; Good = [string][char]0xE73E; Admin = [string][char]0xE72E; Neutral = [string][char]0xE738; Info = [string][char]0xE946 }
    $toneOfStatus = { param([string]$st) switch ($st) { 'Critical' { 'Bad' } 'Fail' { 'Bad' } 'Warning' { 'Warn' } 'Error' { 'Admin' } 'Pass' { 'Good' } default { 'Neutral' } } }
    $signed = { param($d) if ($null -eq $d) { '' } elseif ($d -gt 0) { '+' + $d } elseif ($d -lt 0) { $minus + [math]::Abs($d) } else { '0' } }
    $delta = $c.ScoreDelta
    $deltaText = $(if ($null -eq $delta) { [string][char]0x2014 } else { & $signed $delta })
    $deltaTone = $(if ($null -eq $delta -or $delta -eq 0) { 'Neutral' } elseif ($delta -gt 0) { 'Good' } else { 'Bad' })
    $areas = @(foreach ($a in $c.Areas) {
            $d = $a.Delta
            $t = $(if ($null -eq $d -or $d -eq 0) { 'Neutral' } elseif ($d -gt 0) { 'Good' } else { 'Bad' })
            $o = $(if ($null -ne $a.Old) { [string]$a.Old } else { [string][char]0x2014 })
            $n = $(if ($null -ne $a.New) { [string]$a.New } else { [string][char]0x2014 })
            $dt = $(if ($null -ne $d -and $d -eq 0) { 'same' } else { & $signed $d })
            $gl = $(if ($null -eq $d -or $d -eq 0) { '' } elseif ($d -gt 0) { [string][char]0xE70E } else { [string][char]0xE70D })
            $word = $(if ($null -eq $d) { 'not scored in one of the runs' } elseif ($d -eq 0) { 'no change' } elseif ($d -gt 0) { 'better' } else { 'worse' })
            [pscustomobject]@{ Name = $a.Name; ScoresText = $(if ($null -eq $a.Old -and $null -eq $a.New) { 'not scored' } else { '{0} {1} {2}' -f $o, [char]0x2192, $n }); DeltaText = $dt; Tone = $t; Glyph = $gl
                Tip = ('{0}: {1} then, {2} now ({3})' -f $a.Name, $o, $n, $word) }
        })
    $fItem = {
        param($x, [string]$section)
        $tone = & $toneOfStatus $x.Status
        $glyph = $glyphOf[$tone]
        $msg = [string]$x.Message
        $before = Get-MspkiGuiStatusWord -Status ([string]$x.Before); $after = Get-MspkiGuiStatusWord -Status ([string]$x.After)
        $sub = $msg
        $title = '{0} {1} {2}' -f $x.Category, $dot, (Get-MspkiGuiReadableName -Name ([string]$x.Target))
        switch ([string]$x.Kind) {
            'Resolved' { $tone = 'Good'; $glyph = $glyphOf.Good; $sub = 'Was {0}, now {1}. {2}' -f $before, $after, $msg }
            'Gone' { $tone = 'Good'; $glyph = $glyphOf.Good; $sub = 'Was {0}; the newer run does not report it. {1}' -f $before, $msg }
            'Worse' { $glyph = [string][char]0xE70D; $sub = 'Was {0}, now {1}. {2}' -f $before, $after, $msg }
            'Better' { $glyph = [string][char]0xE70E; $tone = 'Good'; $sub = 'Was {0}, now {1}. {2}' -f $before, $after, $msg }
            'Changed' { $sub = 'Was {0}, now {1} ({2}). {3}' -f $before, $after, $x.Code, $msg }
            'New' { if ($x.Before) { $sub = 'Was {0}, now {1}. {2}' -f $before, $after, $msg } else { $sub = 'Not in the older run; now {0}. {1}' -f $after, $msg } }
        }
        $can = ($section -ne 'Resolved' -and [string]$x.Id -and $OpenIds.ContainsKey([string]$x.Id))
        [pscustomobject]@{ Tag = $(if ($can) { 'f:' + $x.Id } else { '' }); CanOpen = [bool]$can; Tone = $tone; Glyph = $glyph; Title = $title; Sub = $sub
            Tip = $(if ($can) { 'Open this finding' } else { $sub }); AutomationName = ('{0}: {1}' -f $title, $sub) }
    }
    $oItem = {
        param($x, [string]$section)
        $added = ([string]$x.Kind -eq 'Added')
        $where = $(if ($added) { 'found by the newer run only' } else { 'found by the older run only' })
        [pscustomobject]@{ Tag = ''; CanOpen = $false; Tone = $(if ($added) { 'Info' } else { 'Neutral' }); Glyph = $(if ($added) { [string][char]0xE710 } else { [string][char]0xE738 }); Title = [string]$x.Name
            Sub = (Get-MspkiGuiEntityTypeLabel -Type ([string]$x.Type)); Tip = ('{0}: {1}' -f $x.Name, $where); AutomationName = ('{0}, {1}: {2}' -f $x.Name, (Get-MspkiGuiEntityTypeLabel -Type ([string]$x.Type)), $where) }
    }
    $section = {
        param([string]$key, [string]$head, [string]$tone, [string]$glyph, [string]$tip, $list, [string]$empty, $mk)
        $all = @($list)
        $items = @(for ($i = 0; $i -lt [math]::Min($all.Count, $MaxItems); $i++) { & $mk $all[$i] $key })
        [pscustomobject]@{ Key = $key; Heading = ('{0} ({1})' -f $head, $all.Count); Tone = $tone; Glyph = $glyph; HeadTip = $tip; Items = $items; IsEmpty = ($all.Count -eq 0); Empty = $empty
            HasMore = ($all.Count -gt $MaxItems); More = $(if ($all.Count -gt $MaxItems) { 'and {0} more' -f ($all.Count - $MaxItems) } else { '' }) }
    }
    $sections = New-Object System.Collections.ArrayList
    [void]$sections.Add((& $section 'New' 'New problems' 'Bad' $glyphOf.Bad 'Failures and warnings the newer run has and the older one did not' $c.NewProblems 'None: no problem appeared.' $fItem))
    [void]$sections.Add((& $section 'Changed' 'Changed' 'Warn' ([string][char]0xE8AB) 'Problems in both runs whose status, code or severity changed' $c.Changed 'None.' $fItem))
    [void]$sections.Add((& $section 'Resolved' 'Resolved' 'Good' $glyphOf.Good 'Problems of the older run that the newer run no longer has' $c.Resolved 'None.' $fItem))
    if ($c.ObjectsKnown) {
        [void]$sections.Add((& $section 'Added' 'Objects added' 'Info' ([string][char]0xE710) 'Objects the newer run found and the older one did not (by their ids, which are the same in every run)' $c.Added 'None.' $oItem))
        [void]$sections.Add((& $section 'Gone' 'Objects gone' 'Neutral' ([string][char]0xE738) 'Objects the older run found and the newer one did not' $c.Gone 'None.' $oItem))
    }
    $notes = @(foreach ($n in $c.Notes) { [pscustomobject]@{ Text = [string]$n; Tone = 'Info' } })
    $summary = @((Format-MspkiGuiCount -Count @($c.NewProblems).Count -Singular 'new problem'), ('{0} resolved' -f @($c.Resolved).Count), ('{0} changed' -f @($c.Changed).Count), ('{0} still open' -f $c.StillOpen))
    return [pscustomobject]@{
        Title = 'What changed'
        Sub = ('From the run of {0} to the run of {1}: {2}.' -f (& $when $c.Old), (& $when $c.New), ($summary -join ', '))
        Scores = ('{0} {1} {2}' -f (& $scoreOf $c.Old), [char]0x2192, (& $scoreOf $c.New)); DeltaText = $deltaText; Tone = $deltaTone; Text = 'score'
        Areas = $areas; Notes = $notes; Sections = $sections.ToArray()
        AutomationName = ('Health score {0} then, {1} now; {2}' -f (& $scoreOf $c.Old), (& $scoreOf $c.New), ($summary -join ', '))
    }
}

function Get-MspkiGuiEntityTypeLabel {
    # The plain-word name of an object type (as the details pane says it), or the type itself.
    param([string]$Type)
    try { $ti = Get-MspkiGuiEntityTypeInfo -Type $Type; if ($ti.Label) { return [string]$ti.Label } } catch { $null = $_ }
    return $Type
}

function Get-MspkiGuiStatusWord {
    # A finding's status as a word in a sentence ("Was passing, now failing").
    param([AllowEmptyString()][string]$Status)
    switch ($Status) {
        'Pass' { return 'passing' } 'Fail' { return 'failing' } 'Critical' { return 'critical' } 'Warning' { return 'a warning' }
        'Error' { return 'not checked (the check failed)' } 'Skipped' { return 'skipped' } 'Information' { return 'information only' } 'NotApplicable' { return 'not applicable' }
        '' { return 'not reported' }
    }
    return $Status.ToLowerInvariant()
}

function ConvertTo-MspkiGuiFlag {
    # A yes/no value from a results file: true/false, or the text "True"/"False" ([bool]'False' would be true in PowerShell).
    param($Value)
    if ($Value -is [bool]) { return $Value }
    if ($null -eq $Value) { return $false }
    return [string]::Equals(([string]$Value).Trim(), 'True', [System.StringComparison]::OrdinalIgnoreCase)
}
