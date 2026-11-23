# "Probable causes and next steps" for every non-passing finding (Batch H).
# The knowledge is DATA (src/Knowledge/Diagnosis*.psd1, read with Import-PowerShellDataFile, never run). This file only loads it,
# picks the topic that fits a finding, and ranks the causes of that topic with what the tool observed. Nothing here changes anything.

$script:MspkiKnowledgeRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'Knowledge'
$script:MspkiDiagnosisKb = $null

function Get-MspkiDiagnosisKnowledge {
    <#
    .SYNOPSIS
    Loads the diagnosis knowledge base (sources, status-code defaults, rules and topics) from src/Knowledge, once per session.

    .PARAMETER Path
    A folder to read instead of the product's own (tests use this).

    .PARAMETER Reload
    Read the files again even when they were read before.
    #>
    [CmdletBinding()]
    param([string]$Path = '', [switch]$Reload)
    $useDefault = [string]::IsNullOrEmpty($Path)
    if ($useDefault -and -not $Reload -and $null -ne $script:MspkiDiagnosisKb) { return $script:MspkiDiagnosisKb }
    $root = $(if ($useDefault) { $script:MspkiKnowledgeRoot } else { $Path })
    $main = Import-PowerShellDataFile -LiteralPath (Join-Path $root 'Diagnosis.psd1')
    $topics = @{}
    $topicFile = @{}
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Filter 'Diagnosis.Topics.*.psd1' -File | Sort-Object Name)) {
        $part = Import-PowerShellDataFile -LiteralPath $file.FullName
        foreach ($k in $part.Keys) {
            if ($topics.ContainsKey($k)) { throw ('Diagnosis knowledge: topic "{0}" is defined in {1} and in {2}.' -f $k, $topicFile[$k], $file.Name) }
            $topics[$k] = $part[$k]; $topicFile[$k] = $file.Name
        }
    }
    $kb = [pscustomobject]@{
        Version   = [string]$main.Updated
        Schema    = [int]$main.SchemaVersion
        Sources   = $main.Sources
        Codes     = $main.Codes
        Rules     = @($main.Rules)
        Topics    = $topics
        TopicFile = $topicFile
    }
    if ($useDefault) { $script:MspkiDiagnosisKb = $kb }
    return $kb
}

function Test-MspkiFindingNeedsDiagnosis {
    <#
    .SYNOPSIS
    True for a finding that is not passing: Warning, Fail, Critical, Error, Skipped, an Information finding that is more than an
    all-clear note, or a "not applicable" finding that says something was not found, not set up or not supported.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $s = [string]$Finding.Status
    $c = [string]$Finding.StatusCode
    switch ($s) {
        { $_ -in @('Warning', 'Fail', 'Critical', 'Error', 'Skipped') } { return $true }
        'Information' { return ($c -ne 'OK' -and $c -ne 'NOT_APPLICABLE') }
        'NotApplicable' { return ($c -in @('NOT_DISCOVERED', 'NOT_CONFIGURED', 'UNSUPPORTED')) }
        default { return $false }
    }
}

function Get-MspkiDiagnosisSearchText {
    <#
    .SYNOPSIS
    The text the signals of a cause are matched against: the finding's fields, evidence and layer results as plain lines.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $f = $Finding
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($n in @('Category', 'Status', 'StatusCode', 'Confidence', 'Role', 'Scope', 'Severity')) { $lines.Add(('{0}={1}' -f $n, [string]$f.$n)) }
    # Notes and Remediation are explanations the analyzers write for every finding of a kind (possible causes, standing advice). They are not
    # observations of this run, so a signal never sees them: otherwise boilerplate would be shown as something that was observed.
    foreach ($n in @('Target', 'Endpoint', 'RelatedCA', 'Message')) {
        $v = [string]$f.$n
        if ($v) { $lines.Add(('{0}: {1}' -f $n, $v)) }
    }
    foreach ($e in @($f.Evidence)) { if ($null -ne $e -and [string]$e) { $lines.Add(('Evidence: {0}' -f [string]$e)) } }
    foreach ($l in @('DiscoveryStatus', 'DnsStatus', 'TcpStatus', 'HttpStatus', 'RedirectStatus', 'TlsStatus', 'ContentStatus', 'ChainStatus')) {
        $v = [string]$f.$l
        if ($v -and $v -ne 'NotTested') { $lines.Add(('{0}={1}' -f $l, $v)) }
    }
    return ($lines -join "`n")
}

function Resolve-MspkiDiagnosisTopic {
    <#
    .SYNOPSIS
    Picks the knowledge topic for a finding: the first matching rule, else the default topic of its status code.

    .OUTPUTS
    An object with Topic (the id) and Match ('Rule' or 'Code'), or $null when the knowledge base knows neither.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, $Knowledge = $null)
    if ($null -eq $Knowledge) { $Knowledge = Get-MspkiDiagnosisKnowledge }
    $cat = [string]$Finding.Category
    $code = [string]$Finding.StatusCode
    $text = ((@([string]$Finding.Message, [string]$Finding.Target, [string]$Finding.Notes) | Where-Object { $_ }) -join "`n")
    foreach ($r in @($Knowledge.Rules)) {
        if ($r.ContainsKey('Category') -and -not (@($r.Category) | Where-Object { [string]::Equals([string]$_, $cat, [System.StringComparison]::OrdinalIgnoreCase) })) { continue }
        if ($r.ContainsKey('StatusCode') -and -not (@($r.StatusCode) | Where-Object { [string]::Equals([string]$_, $code, [System.StringComparison]::OrdinalIgnoreCase) })) { continue }
        if ($r.ContainsKey('Match')) {
            $hit = $false
            try { $hit = [regex]::IsMatch($text, [string]$r.Match, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) } catch { $hit = $false }
            if (-not $hit) { continue }
        }
        if ($Knowledge.Topics.ContainsKey([string]$r.Topic)) { return [pscustomobject]@{ Topic = [string]$r.Topic; Match = 'Rule' } }
    }
    if ($Knowledge.Codes.ContainsKey($code) -and $Knowledge.Topics.ContainsKey([string]$Knowledge.Codes[$code])) {
        return [pscustomobject]@{ Topic = [string]$Knowledge.Codes[$code]; Match = 'Code' }
    }
    return $null
}

function Get-MspkiRankedCause {
    <#
    .SYNOPSIS
    Ranks the causes of a topic for one finding. The order in the knowledge file is the prior (the first cause is the most common one);
    every signal that matches the finding's own text moves a cause up or down. Returns the causes best first.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Topic, [Parameter(Mandatory = $true)][string]$SearchText)
    $causes = @($Topic.Causes)
    $n = $causes.Count
    $ranked = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $n; $i++) {
        $c = $causes[$i]
        $score = ($n - $i) * 10
        $because = New-Object System.Collections.Generic.List[string]
        $matched = 0
        $support = 0
        if ($c.ContainsKey('Signals')) {
            foreach ($s in @($c.Signals)) {
                $hit = $false
                try { $hit = [regex]::IsMatch($SearchText, [string]$s.When, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) } catch { $hit = $false }
                if ($hit) {
                    $score += [int]$s.Weight; $matched++; if ([int]$s.Weight -gt 0) { $support += [int]$s.Weight }
                    if ($s.ContainsKey('Because') -and $s.Because) { $because.Add([string]$s.Because) }
                }
            }
        }
        [void]$ranked.Add([pscustomobject]@{ Index = $i; Score = $score; Matched = $matched; Support = $support; Cause = $c; Because = @($because) })
    }
    return @($ranked | Sort-Object -Property @{ Expression = 'Score'; Descending = $true }, @{ Expression = 'Index'; Descending = $false })
}

function Get-MspkiFindingDiagnosis {
    <#
    .SYNOPSIS
    The "Probable causes and next steps" of a finding: what it means, the causes ranked by what the tool observed, how to confirm each
    one (read-only checks), how to fix it (an action for the PKI owner) and the sources.

    .DESCRIPTION
    Returns $null for a finding that is passing. A finding that already carries a Diagnosis (results.json written by this version)
    gets that one back; -Recompute builds it again from the knowledge base. Causes are probable, never proven: Basis says whether an
    observation of the tool separated them ("Observed") or the order only reflects how common each cause is ("Typical").
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, [switch]$Recompute, $Knowledge = $null)
    if (-not $Recompute -and $null -ne $Finding.PSObject.Properties['Diagnosis'] -and $null -ne $Finding.Diagnosis) { return $Finding.Diagnosis }
    if (-not (Test-MspkiFindingNeedsDiagnosis -Finding $Finding)) { return $null }
    if ($null -eq $Knowledge) { $Knowledge = Get-MspkiDiagnosisKnowledge }
    $res = Resolve-MspkiDiagnosisTopic -Finding $Finding -Knowledge $Knowledge
    if ($null -eq $res) { return $null }
    $topic = $Knowledge.Topics[$res.Topic]
    $text = Get-MspkiDiagnosisSearchText -Finding $Finding
    $ranked = @(Get-MspkiRankedCause -Topic $topic -SearchText $text)
    # A cause is "supported" when what this run observed adds at least 10 points for it; weaker hints are listed but do not change the wording.
    $observed = (@($ranked | Where-Object { $_.Support -ge 10 }).Count -gt 0)
    $out = New-Object System.Collections.ArrayList
    $rank = 0
    foreach ($r in $ranked) {
        $rank++
        $c = $r.Cause
        # The wording follows the support of THIS cause: "most likely" / "likely" only when something observed backs it; otherwise the order is
        # only how common the cause is, and it says so.
        $supported = ($r.Support -ge 10)
        $like = $(if ($rank -eq 1) { if ($supported) { 'Most likely' } else { 'Most common' } }
                  elseif ($rank -le 3) { if ($supported) { 'Likely' } else { 'Common' } }
                  else { 'Possible' })
        [void]$out.Add([pscustomobject][ordered]@{
            Rank       = $rank
            Id         = [string]$c.Id
            Cause      = [string]$c.Cause
            Likelihood = $like
            Because    = [string[]]@($r.Because)
            Confirm    = [string[]]@($c.Confirm)
            Fix        = [string[]]@($c.Fix)
            FixOwner   = 'PKI owner'
        })
    }
    $srcIds = @($topic.Sources)
    foreach ($c in $topic.Causes) { if ($c.ContainsKey('Sources')) { $srcIds += @($c.Sources) } }
    $srcs = @($srcIds | Where-Object { $_ } | Select-Object -Unique | ForEach-Object {
        $s = $Knowledge.Sources[[string]$_]
        if ($null -ne $s) { [pscustomobject][ordered]@{ Id = [string]$_; Title = [string]$s.Title; Publisher = [string]$s.Publisher; Url = [string]$s.Url } }
    })
    $basisNote = $(if ($observed) { 'The order uses what this run observed (the facts listed under each cause) on top of how common each cause is.' }
                   else { 'Nothing this run observed separates these causes, so the order only reflects how common each one is in Microsoft and community guidance. Use the checks to find out which applies.' })
    return [pscustomobject][ordered]@{
        Topic     = [string]$res.Topic
        Title     = [string]$topic.Title
        Summary   = [string]$topic.What
        Basis     = $(if ($observed) { 'Observed' } else { 'Typical' })
        BasisNote = $basisNote
        Causes    = @($out)
        Sources   = $srcs
        Match     = [string]$res.Match
        Knowledge = [string]$Knowledge.Version
    }
}

function Add-MspkiFindingDiagnosis {
    <#
    .SYNOPSIS
    Adds a Diagnosis property ("Probable causes and next steps") to every non-passing finding that has none. Returns how many were added.

    .DESCRIPTION
    A failure inside the knowledge code never stops a run: the finding stays without a Diagnosis and the error goes to the run log.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $added = 0
    $kb = $null
    try { $kb = Get-MspkiDiagnosisKnowledge } catch {
        Write-MspkiLog -Level Warning -Message ('Diagnosis knowledge not loaded: {0}' -f $_.Exception.Message)
        return 0
    }
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        try {
            if ($null -ne $f.PSObject.Properties['Diagnosis'] -and $null -ne $f.Diagnosis) { continue }
            $d = Get-MspkiFindingDiagnosis -Finding $f -Knowledge $kb
            if ($null -ne $d) { $f | Add-Member -NotePropertyName 'Diagnosis' -NotePropertyValue $d -Force; $added++ }
        }
        catch { Write-MspkiLog -Level Warning -Message ('Diagnosis for {0} not built: {1}' -f [string]$f.Id, $_.Exception.Message) }
    }
    return $added
}
