# Command palette (Ctrl+K, GX4): one search box that reaches every page, every command of the command bar, every object by name and every
# finding by text. Pure data helpers: the window (GuiApp.ps1) builds the index when results arrive and asks Find-MspkiGuiPaletteItem on
# every key press. An item's Action is a plain key ("page:<n>", "cmd:<name>", "ent:<id>", "finding:<id>") that the window maps to one
# of its own functions; nothing typed into the box is ever run.

$script:MspkiGuiPaletteKindOrder = @{ Command = 0; Page = 1; Object = 2; Finding = 3 }

function New-MspkiGuiPaletteEntry {
    <#
    .SYNOPSIS
    One palette item. Search is the lower-case text that is matched; Title is matched first.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Kind, [Parameter(Mandatory = $true)][string]$Title, [string]$Detail = '', [string]$Glyph = '',
        [Parameter(Mandatory = $true)][string]$Action, [string]$Shortcut = '', [string]$Extra = '', $Pill = $null, [int]$Seq = 0)
    $kindText = @{ Command = 'Command'; Page = 'Page'; Finding = 'Finding'; Object = 'Object' }[$Kind]
    return [pscustomobject][ordered]@{
        Kind = $Kind; KindText = $kindText; Title = $Title; Detail = $Detail; Glyph = $Glyph; Action = $Action; Shortcut = $Shortcut
        HasShortcut = [bool]$Shortcut; Pill = $Pill; HasPill = ($null -ne $Pill)
        TitleLower = $Title.ToLowerInvariant(); Search = (@($Title, $Detail, $Extra) -join ' ').ToLowerInvariant()
        KindOrder = [int]$script:MspkiGuiPaletteKindOrder[$Kind]; Seq = $Seq
        AutomationName = ('{0}: {1}' -f $kindText, $Title)
    }
}

function Get-MspkiGuiPalettePage {
    <#
    .SYNOPSIS
    The pages of the window as palette items, in navigation order (Ctrl+1..8).
    #>
    [CmdletBinding()]
    param()
    $pages = @(
        @('Overview', 'Score, what to do next and the discovery map', [char]0xE80F),
        @('Findings', 'Every check result with its sources and evidence', [char]0xE8FD),
        @('Discovery map', 'What the run found, as a map or a tree', [char]0xE81E),
        @('Timeline', 'When CA certificates and CRLs run out, and the certificate chains', [char]0xE787),
        @('Objects', 'Everything the run found, by type', [char]0xE8A9),
        @('PKI services', 'CAs, web enrollment, OCSP, NDES, CEP/CES', [char]0xE968),
        @('History', 'Earlier runs, the score over time, and what changed between two runs', [char]0xE81C),
        @('Run log', 'What the run did, step by step', [char]0xE9D5)
    )
    $i = 0
    return @(foreach ($p in $pages) {
        New-MspkiGuiPaletteEntry -Kind Page -Title ('Go to ' + $p[0]) -Detail $p[1] -Glyph ([string]$p[2]) -Action ('page:{0}' -f $i) -Shortcut ('Ctrl+{0}' -f ($i + 1)) -Extra $p[0] -Seq $i
        $i++
    })
}

function Get-MspkiGuiPaletteCommand {
    <#
    .SYNOPSIS
    The commands of the window as palette items. Available says which ones can run now (a hashtable name -> bool, from the window's
    buttons); a command that is not available is left out, so the palette never offers something that does nothing.
    #>
    [CmdletBinding()]
    param([hashtable]$Available = @{})
    $all = @(
        @('run', 'Run health check', 'Start a new read-only run with the current options', [char]0xE768, 'F5', 'start scan check'),
        @('cancel', 'Cancel the run', 'Stop the run that is going on; what was found so far is kept', [char]0xE711, 'Esc', 'stop abort'),
        @('open', 'Open results...', 'Show an earlier run from its results.json', [char]0xE8E5, 'Ctrl+O', 'load file earlier'),
        @('report', 'Open the HTML report', 'The report of the run on show, in the browser', [char]0xE774, '', 'html browser'),
        @('folder', 'Open the output folder', 'The folder with the run''s files', [char]0xE838, '', 'explorer files'),
        @('export', 'Export the filtered findings', 'Write the findings that match the filters to a CSV file under the output folder', [char]0xE896, '', 'csv save'),
        @('actions', 'Show all actions', 'Every "What to do next" action, most urgent first', [char]0xE762, '', 'what to do next todo'),
        @('score', 'How is this scored?', 'The health score in plain words', [char]0xE9CE, '', 'score explain help'),
        @('options', 'Show the run options', 'Timeout, network checks, proxy, NDES admin probe', [char]0xE713, '', 'settings timeout proxy'),
        @('mapfit', 'Fit the map to the window', 'Show the whole Discovery map', [char]0xE9A6, 'Ctrl+0', 'zoom discovery map whole'),
        @('mapproblems', 'Show only problems on the map', 'Failing, warning and could-not-check objects with the path to them', [char]0xE7BA, '', 'discovery map filter failing broken'),
        @('mapreplay', 'Replay discovery', 'Play the discovery of this run again on the map', [char]0xE768, '', 'animation discovery map build'),
        @('tlcerts', 'Show when the CA certificates expire', 'The Timeline page: every CA certificate generation on a time axis', [char]0xEB95, '', 'timeline expiry renew lifetime generation'),
        @('tlcrls', 'Show the CRL heartbeat', 'The Timeline page: when each CRL was published, is due and runs out, and the copy at every address', [char]0xEA41, '', 'timeline crl next update overlap expired revocation'),
        @('tlchain', 'Show the certificate chain', 'From a CA certificate up to its root, with the result of every AIA and CDP address', [char]0xE71B, '', 'chain path aia cdp issuer trust'),
        @('mapexport', 'Export the map as an image', 'Save the whole Discovery map as a PNG in the run''s output folder', [char]0xEB9F, '', 'png picture save discovery map'),
        @('histprev', 'Compare with the run before', 'The History page: what changed since the run before the one on show', [char]0xE81C, '', 'history compare changed difference previous last time trend'),
        @('histrefresh', 'Read the list of earlier runs again', 'The History page: every run saved in the output folder', [char]0xE72C, '', 'history refresh runs reload'),
        @('copylog', 'Copy the run log', 'Every line of the run log, to the clipboard', [char]0xE8C8, '', 'clipboard'),
        @('themeauto', 'Theme: follow Windows', 'Light or dark as Windows is set; high contrast always wins', [char]0xE7F4, '', 'appearance colour color mode system'),
        @('themelight', 'Theme: light', 'Light background', [char]0xE706, '', 'appearance colour color mode'),
        @('themedark', 'Theme: dark', 'Dark background', [char]0xE708, '', 'appearance colour color mode night')
    )
    $i = 0
    return @(foreach ($c in $all) {
        $i++
        if ($Available.ContainsKey($c[0]) -and -not $Available[$c[0]]) { continue }
        New-MspkiGuiPaletteEntry -Kind Command -Title $c[1] -Detail $c[2] -Glyph ([string]$c[3]) -Action ('cmd:' + $c[0]) -Shortcut $c[4] -Extra $c[5] -Seq $i
    })
}

function Get-MspkiGuiPaletteIndex {
    <#
    .SYNOPSIS
    The searchable items of a run: one per finding (by id, status, category, target and message) and one per object (by name and type).
    Built once when results arrive.
    #>
    [CmdletBinding()]
    param($Rows = @(), $ObjRows = @())
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        # D-11 / D-12 / D-42: the shared finding title (readable name and where the copy was read) tells findings apart; the message and id
        # go underneath, joined with a middle dot. The glyph is the finding's status glyph (D-16), never a command's.
        $title = [string]$r.Title
        if (-not $title) { $title = [string]$r.Message }
        if (-not $title) { $title = [string]$r.Id }
        $detail = (@([string]$r.Message, [string]$r.Id) | Where-Object { $_ }) -join (' ' + [string][char]0x00B7 + ' ')
        $fg = [string][char]0xE8FD; if ($null -ne $r.StatusPill -and $r.StatusPill.Glyph) { $fg = [string]$r.StatusPill.Glyph }
        $list.Add((New-MspkiGuiPaletteEntry -Kind Finding -Title $title -Detail $detail -Glyph $fg -Action ('finding:' + [string]$r.Id) -Extra ([string]$r.SearchText) -Pill $r.StatusPill -Seq (100000 - [int]$r.StatusRank)))
    }
    foreach ($o in @($ObjRows)) {
        if ($null -eq $o) { continue }
        $list.Add((New-MspkiGuiPaletteEntry -Kind Object -Title (Get-MspkiGuiReadableName -Name ([string]$o.Name)) -Detail ([string]$o.TypeText) -Glyph ([string]$o.Glyph) -Action ('ent:' + [string]$o.Id) -Extra ([string]$o.SearchText) -Seq ([int]$o.TypeOrder)))
    }
    return , $list.ToArray()
}

function Find-MspkiGuiPaletteItem {
    <#
    .SYNOPSIS
    The items that match a query, best first, at most Max. Every word of the query must appear; a title that starts with the query ranks
    first, then a word of the title that starts with it, then a match anywhere. An empty query gives the commands and the pages.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Query = "", $Fixed = @(), $Items = @(), [int]$Max = 200)
    $q = ($Query.Trim() -replace '\s+', ' ').ToLowerInvariant()
    if (-not $q) { return @($Fixed | Sort-Object KindOrder, Seq | Select-Object -First $Max) }
    $words = $q.Split(' ')
    $hits = New-Object 'System.Collections.Generic.List[object]'
    foreach ($set in @($Fixed, $Items)) {
        foreach ($it in @($set)) {
            if ($null -eq $it) { continue }
            $s = [string]$it.Search
            $ok = $true
            foreach ($w in $words) { if ($s.IndexOf($w, [System.StringComparison]::Ordinal) -lt 0) { $ok = $false; break } }
            if (-not $ok) { continue }
            $t = [string]$it.TitleLower
            $score = 3
            if ($t.StartsWith($q, [System.StringComparison]::Ordinal) -or $t.StartsWith('go to ' + $q, [System.StringComparison]::Ordinal)) { $score = 0 }
            # A page whose name holds the query as a whole word comes first ("map" means the map page, before the map commands).
            elseif ([string]$it.Kind -eq 'Page' -and (' ' + $t + ' ').Contains(' ' + $q + ' ')) { $score = 0 }
            elseif ($t.IndexOf(' ' + $words[0], [System.StringComparison]::Ordinal) -ge 0) { $score = 1 }
            elseif ($t.IndexOf($words[0], [System.StringComparison]::Ordinal) -ge 0) { $score = 2 }
            $hits.Add([pscustomobject]@{ Score = $score; KindOrder = [int]$it.KindOrder; Seq = [int]$it.Seq; Len = $t.Length; Item = $it })
        }
    }
    return @($hits | Sort-Object Score, KindOrder, Seq, Len | Select-Object -First $Max | ForEach-Object { $_.Item })
}
