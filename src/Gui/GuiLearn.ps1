# GX9 "Explain it to me": the glossary (src/Knowledge/Glossary.psd1, data only), the Learn page's items (concept cards from the object
# notes plus the glossary), the first-run tour's stops, the window settings kept in out\gui-settings.json, and the rule for the healthy
# celebration. Pure functions: no WPF types and no writes (Save-MspkiGuiSettings, in GuiState.ps1, writes inside the output folder only).

$script:MspkiGuiGlossaryCache = $null
$script:MspkiGuiSettingsFileName = 'gui-settings.json'

function Get-MspkiGuiGlossary {
    <#
    .SYNOPSIS
    The glossary terms (Term, Also, Short, More, Related), read once from src\Knowledge\Glossary.psd1 with Import-PowerShellDataFile (data,
    never run). Returns an empty list when the file cannot be read, so the window still works.
    #>
    [CmdletBinding()]
    param([string]$Path = '')
    if (-not $Path -and $null -ne $script:MspkiGuiGlossaryCache) { return $script:MspkiGuiGlossaryCache }
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Knowledge\Glossary.psd1' }
    $terms = @()
    try {
        $d = Import-PowerShellDataFile -LiteralPath $Path
        $terms = @(foreach ($t in @($d.Terms)) {
            [pscustomobject][ordered]@{ Term = [string]$t.Term; Also = [string[]]@($t.Also); Short = [string]$t.Short; More = [string]$t.More; Related = [string[]]@($t.Related) }
        })
    }
    catch { $terms = @() }
    if (-not $PSBoundParameters.ContainsKey('Path') -or -not $PSBoundParameters['Path']) { $script:MspkiGuiGlossaryCache = $terms }
    return $terms
}

function Find-MspkiGuiGlossaryTerm {
    <#
    .SYNOPSIS
    The glossary entry a short label is about ("AIA over HTTP" -> AIA, "Partial score" -> partial score), or $null. Only labels of at most
    -MaxLength characters are looked at (sentences are not underlined). Upper-case acronyms match case-sensitively as whole words, so "ca"
    inside a word never matches; other terms match whole words in any case. The longest name wins.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Text, $Glossary = $null, [int]$MaxLength = 48)
    if (-not $Text -or $Text.Length -gt $MaxLength) { return $null }
    if ($null -eq $Glossary) { $Glossary = Get-MspkiGuiGlossary }
    # The first term in the label wins ("AIA over LDAP" is about AIA); at the same place, the longest name.
    $best = $null; $bestAt = [int]::MaxValue; $bestLen = 0
    foreach ($t in @($Glossary)) {
        foreach ($name in @(@($t.Term) + @($t.Also))) {
            if (-not $name) { continue }
            $pat = '(?<![\w-])' + [regex]::Escape($name) + '(?![\w-])'
            $caseSensitive = ($name -cmatch '^[A-Z]{2,6}s?$')
            $m = $(if ($caseSensitive) { [regex]::Match($Text, $pat) } else { [regex]::Match($Text, $pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) })
            if ($m.Success -and ($m.Index -lt $bestAt -or ($m.Index -eq $bestAt -and $name.Length -gt $bestLen))) { $best = $t; $bestAt = $m.Index; $bestLen = $name.Length }
        }
    }
    return $best
}

function Get-MspkiGuiExplainTip {
    <#
    .SYNOPSIS
    The Explain-mode tooltip of a glossary entry: the term, its one-sentence meaning, and where to read more.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Entry)
    return ('{0}: {1}{2}More on the Learn page (Ctrl+9).' -f $Entry.Term, $Entry.Short, [Environment]::NewLine)
}

function Get-MspkiGuiLearnItem {
    <#
    .SYNOPSIS
    The Learn page's list: a concept card per object type (the "What it is" notes the details pane already shows, not a second set), then the
    glossary terms A to Z. Each item: Kind, Key, Title, Short, More, Related, Glyph, Search.
    #>
    [CmdletBinding()]
    param($Glossary = $null, $Concepts = $null)
    if ($null -eq $Glossary) { $Glossary = Get-MspkiGuiGlossary }
    $items = New-Object System.Collections.ArrayList
    if ($null -ne $Concepts) {
        foreach ($entry in @($Concepts.GetEnumerator())) {
            $k = [string]$entry.Key; $c = $entry.Value
            if (-not $c.About) { continue }
            [void]$items.Add([pscustomobject][ordered]@{ Kind = 'Concept'; Key = ('concept:' + $k); Title = [string]$c.Label; Short = [string]$c.About; More = ''; Related = @(); RelatedText = ''
                Glyph = [string]$c.Glyph; KindText = 'Concept card'; Search = ('{0} {1}' -f $c.Label, $c.About).ToLowerInvariant() })
        }
    }
    foreach ($t in @($Glossary | Sort-Object Term)) {
        [void]$items.Add([pscustomobject][ordered]@{ Kind = 'Term'; Key = ('term:' + $t.Term); Title = [string]$t.Term; Short = [string]$t.Short; More = [string]$t.More; Related = [string[]]@($t.Related)
            RelatedText = $(if (@($t.Related).Count -gt 0) { 'Related: ' + (@($t.Related) -join ', ') } else { '' })
            Glyph = [string][char]0xE736; KindText = $(if (@($t.Also).Count -gt 0) { 'Also: ' + (@($t.Also) -join ', ') } else { 'Term' })
            Search = ('{0} {1} {2} {3}' -f $t.Term, (@($t.Also) -join ' '), $t.Short, $t.More).ToLowerInvariant() })
    }
    return $items.ToArray()
}

function Get-MspkiGuiTourStop {
    <#
    .SYNOPSIS
    The four stops of the first-run tour (GX9): the score line, What to do next, the map, the command palette. Target is the name of the
    element the stop points at.
    #>
    [CmdletBinding()]
    param()
    return @(
        [pscustomobject]@{ Key = 'score'; Target = 'ScoreRing'; Title = 'The health score'; Text = 'A summary of the findings, from 0 to 100. "Held down by" names the area that limits it: fix that one first. Select the ring for how it is scored.' }
        [pscustomobject]@{ Key = 'actions'; Target = 'ActionList'; Title = 'What to do next'; Text = 'The problems, grouped and most urgent first. Each one opens its probable causes, read-only checks to copy, and the fix with its owner.' }
        [pscustomobject]@{ Key = 'map'; Target = 'MapCanvasHost'; Title = 'The Discovery map'; Text = 'How the run found your PKI: each CA, the addresses it publishes and what serves them. Red dashed links fail; select any object to open it.' }
        [pscustomobject]@{ Key = 'palette'; Target = 'TglExplain'; Title = 'Everything is one key away'; Text = 'Press Ctrl+K to find any page, command, object or finding by name. Explain mode (the book button) underlines the terms and says what they mean.' }
    )
}

function Read-MspkiGuiSettings {
    <#
    .SYNOPSIS
    The window settings from out\gui-settings.json: TourDone, ExplainMode, Celebrated (the runs already celebrated). Missing or unreadable
    file: the defaults.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$OutputRoot)
    $s = [pscustomobject][ordered]@{ Path = ''; TourDone = $false; ExplainMode = $false; Celebrated = @(); SaveError = '' }
    if (-not $OutputRoot) { return $s }
    $s.Path = Join-Path $OutputRoot $script:MspkiGuiSettingsFileName
    try {
        if (Test-Path -LiteralPath $s.Path -PathType Leaf) {
            $d = [System.IO.File]::ReadAllText($s.Path) | ConvertFrom-Json
            if ($null -ne $d.TourDone) { $s.TourDone = ([string]$d.TourDone -eq 'True') }
            if ($null -ne $d.ExplainMode) { $s.ExplainMode = ([string]$d.ExplainMode -eq 'True') }
            if ($null -ne $d.Celebrated) { $s.Celebrated = [string[]]@($d.Celebrated | Where-Object { $_ }) }
        }
    }
    catch { $s.SaveError = $_.Exception.Message }
    return $s
}

function Test-MspkiGuiCelebrate {
    <#
    .SYNOPSIS
    True once per healthy run: a finished live run (not an earlier run opened from disk) with a score of 90 or more, the Green level and no
    partial score, not celebrated before (RunKey = the run's results path or start time).
    #>
    [CmdletBinding()]
    param($Score, $Health, [string]$RunKey, $Settings, [bool]$IsEarlierRun = $false)
    if ($IsEarlierRun -or -not $RunKey -or $null -eq $Score -or -not $Score.HasScore) { return $false }
    if ([int]$Score.Overall -lt 90 -or [bool]$Score.Partial) { return $false }
    if ($null -eq $Health -or [string]$Health.Level -ne 'Green') { return $false }
    if ($null -ne $Settings -and @($Settings.Celebrated) -contains $RunKey) { return $false }
    return $true
}
