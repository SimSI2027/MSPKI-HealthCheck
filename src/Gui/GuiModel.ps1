# GUI data model: pure functions that turn run results (live or from results.json) into plain objects for the window.
# No WPF types here, so they can be tested without a window. The GUI only displays and filters; every check stays in the engine.

$script:MspkiGuiStatusOrder = @('Critical', 'Fail', 'Error', 'Warning', 'CouldNotCheck', 'Skipped', 'Information', 'Pass', 'NotApplicable')
$script:MspkiGuiStatusRank = @{ Critical = 7; Fail = 6; Error = 5; Warning = 4; CouldNotCheck = 3; Skipped = 3; Information = 2; Pass = 1; NotApplicable = 0 }
$script:MspkiGuiSeverityRank = @{ High = 5; Medium = 4; Low = 3; ReviewRequired = 2; Information = 1; None = 0 }
$script:MspkiGuiConfidenceRank = @{ Confirmed = 3; Referenced = 2; Inferred = 1; Unknown = 0 }
$script:MspkiGuiAllChoice = 'All'

# Engine stages in the order they run, with the label shown in the window. Used for the progress bar.
$script:MspkiGuiStages = @(
    @('Discovery:ADContext', 'Reading the forest and domain controller'),
    @('Discovery:PKIContainers', 'Reading the Public Key Services containers'),
    @('Discovery:EnterpriseCAs', 'Finding Enterprise CAs'),
    @('Discovery:TemplatesKraOid', 'Reading templates, KRA and OID objects'),
    @('Discovery:CAProperties', 'Reading CA properties'),
    @('Discovery:CACertificates', 'Merging CA certificates'),
    @('Analysis:CACertificates', 'Checking CA certificates'),
    @('Analysis:ADContainers', 'Reviewing the AD PKI containers'),
    @('Analysis:ADContainerObjects', 'Reviewing template, KRA and OID containers'),
    @('Analysis:Templates', 'Reviewing certificate templates'),
    @('Probe:Endpoints', 'Checking AIA, CDP and OCSP endpoints'),
    @('Discovery:LocalPolicy', 'Reading local enrollment policy'),
    @('Probe:EnrollmentServices', 'Checking CEP and CES endpoints'),
    @('Probe:NDES', 'Checking NDES / SCEP'),
    @('Discovery:IntuneConnector', 'Looking for the Intune Certificate Connector'),
    @('Analysis:StaleReferences', 'Reviewing stale references'),
    @('Analysis:Hierarchy', 'Reviewing the CA hierarchy'),
    @('Analysis:LocalEvidence', 'Reading this computer''s certificates, events and policy'),
    @('Analysis:Identity', 'Recording endpoint identity and Web Enrollment')
)

# Icon (Segoe MDL2 Assets code point) and tone for every status word the window shows. Icon + text, never colour alone.
$script:MspkiGuiStatusStyle = @{
    Critical = @('Bad', 0xEA39); Fail = @('Bad', 0xE711); Error = @('Admin', 0xE783); PermissionDenied = @('Admin', 0xE72E)
    Warning = @('Warn', 0xE7BA); Timeout = @('Warn', 0xE916); Skipped = @('Neutral', 0xE893); Information = @('Info', 0xE946); CouldNotCheck = @('Admin', 0xE72E)
    Pass = @('Good', 0xE73E); NotApplicable = @('Neutral', 0xE738); NotTested = @('Neutral', 0xE738); Unknown = @('Neutral', 0xE897)
}
$script:MspkiGuiConfidenceStyle = @{
    Confirmed = @('Good', 0xE73E); Referenced = @('Info', 0xE71B); Inferred = @('Warn', 0xE897); Unknown = @('Neutral', 0xE897)
}
$script:MspkiGuiSeverityStyle = @{
    High = @('Bad', 0xE7BA); Medium = @('Warn', 0xE7BA); Low = @('Info', 0xE946); ReviewRequired = @('Admin', 0xE7B3); Information = @('Neutral', 0xE946); None = @('Neutral', 0xE738)
}

# The words the window uses for each status, severity and confidence value (GUI-DESIGN §9, sentence case). Values not listed show as
# their own name with spaces between the words.
$script:MspkiGuiStatusWord = @{
    Fail = 'Failing'; Error = 'Check failed'; CouldNotCheck = 'Could not check'; PermissionDenied = 'Could not check'; NotApplicable = 'Not applicable'
    NotTested = 'Not tested'; Timeout = 'Timed out'; ReviewRequired = 'Review required'
}

function Get-MspkiGuiStatusKey {
    <#
    .SYNOPSIS
    The status the window shows for a finding. The engine reports "could not check" (permission denied, not supported here) as Skipped
    with a PERMISSION_DENIED or UNSUPPORTED code; the window calls that "Could not check" (lock) everywhere and keeps "Skipped" for a
    check that was skipped on purpose (D-03).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Status, [AllowEmptyString()][AllowNull()][string]$StatusCode = '')
    if ($Status -eq 'Skipped' -and @('PERMISSION_DENIED', 'UNSUPPORTED') -contains [string]$StatusCode) { return 'CouldNotCheck' }
    return [string]$Status
}

function Get-MspkiGuiFindingStatusKey {
    <#
    .SYNOPSIS
    Get-MspkiGuiStatusKey for one finding (its Status and StatusCode).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Finding)
    if ($null -eq $Finding) { return '' }
    return (Get-MspkiGuiStatusKey -Status ([string]$Finding.Status) -StatusCode ([string]$Finding.StatusCode))
}

function Get-MspkiGuiStatusLabel {
    <#
    .SYNOPSIS
    The word the window shows for a status, severity or confidence value ("Fail" -> "Failing", "ReviewRequired" -> "Review required").
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Value)
    if (-not $Value) { return '' }
    if ($script:MspkiGuiStatusWord.ContainsKey($Value)) { return [string]$script:MspkiGuiStatusWord[$Value] }
    $w = ($Value -creplace '([a-z])([A-Z])', '$1 $2')
    if ($w.Length -gt 1) { $w = $w.Substring(0, 1) + $w.Substring(1).ToLowerInvariant() }
    return $w
}

function Get-MspkiGuiReadableName {
    # A heading for people: a distinguished name inside an object's name becomes its common name ("Base CRL of CN=Example CA, DC=corp" ->
    # "Base CRL of Example CA"; "CN=web01.example.test" -> "web01.example.test"). The full name stays in the properties and in the copy text.
    param([AllowEmptyString()][AllowNull()][string]$Name)
    if (-not $Name) { return '' }
    # The parts after the common name end at the next comma (CN, OU, O, L, S, ST, C) or at the first space (DC, never spaced), so a DN
    # inside a sentence ("... DC=example at http://...") keeps the rest of the sentence.
    return [regex]::Replace($Name, '(?i)\bCN=((?:[^,\\]|\\.)+?)(?=\s*,|\s*$|\s+(?:at|in|on|from|has|is|was|for|and|with)\b)(?:\s*,\s*(?:(?:CN|OU|O|L|ST|S|C)=(?:[^,=\\]|\\.)+?(?=\s*,|\s*$)|DC=[^,\s]+))*', '$1')
}

$script:MspkiGuiCategoryWord = @{ ADContainer = 'AD container'; ADContainerObjects = 'AD objects'; EnrollmentServices = 'Enrollment services'; LocalEvidence = 'This computer'; StaleReference = 'Stale reference' }

function Get-MspkiGuiShortTarget {
    <#
    .SYNOPSIS
    A finding's target for people: a URL becomes "host · file" ("pki28 · Example CA.crt", the first label of the host and the decoded file
    name); anything else is its readable name (Get-MspkiGuiReadableName). The full target stays in the tooltip and the properties.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Target)
    if (-not $Target) { return '' }
    $m = [regex]::Match($Target, '^(?i)(?:https?|ldaps?|file)://([^/?#:]*)(?::\d+)?(/[^?#]*)?')
    if ($m.Success) {
        $h = ($m.Groups[1].Value -split '\.')[0]
        $file = ''
        try { $file = [System.Uri]::UnescapeDataString(($m.Groups[2].Value -replace '^.*/', '')) } catch { $file = '' }
        $parts = @($h, $file) | Where-Object { $_ }
        if (@($parts).Count -gt 0) { return (@($parts) -join (' ' + [string][char]0x00B7 + ' ')) }
    }
    return (Get-MspkiGuiReadableName -Name $Target)
}

function Get-MspkiGuiFindingQualifier {
    <#
    .SYNOPSIS
    The part of a finding's title that tells it apart from others about the same object (D-11): where the copy was read
    ("at pki (HTTP)", "in AD (LDAP)", "at the CA (base CRL)") or, when the subject is the host itself, the file at that address.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Finding)
    if ($null -eq $Finding) { return '' }
    $ep = [string]$Finding.Endpoint
    if (-not $ep) { return '' }
    $m = [regex]::Match($ep, '^(?i)CA property (Base|Delta)CRL')
    if ($m.Success) { return ('at the CA ({0} CRL)' -f $m.Groups[1].Value.ToLowerInvariant()) }
    $m = [regex]::Match($ep, '^(?i)(https?|ldaps?|file)://([^/?#]*)(/[^?#]*)?')
    # The target is this very address ("host · file" already says where): only the protocol is added.
    if ($ep -and [string]$Finding.Target -eq $ep -and $m.Success) { return ('({0})' -f $m.Groups[1].Value.ToUpperInvariant()) }
    if (-not $m.Success) { return '' }
    $scheme = $m.Groups[1].Value.ToUpperInvariant()
    $h = $m.Groups[2].Value
    if ($scheme -like 'LDAP*') { if (-not $h) { return ('in AD ({0})' -f $scheme) } }
    $target = [string]$Finding.Target
    if ($h -and $target -and $h.ToLowerInvariant() -eq $target.ToLowerInvariant()) {
        $file = ''
        try { $file = [System.Uri]::UnescapeDataString(($m.Groups[3].Value -replace '^.*/', '')) } catch { $file = '' }
        if ($file) { return ('{0} ({1})' -f $file, $scheme) }
        return ('({0})' -f $scheme)
    }
    $short = ($h -split '\.')[0]
    if (-not $short) { $short = $h }
    return ('at {0} ({1})' -f $short, $scheme)
}

function Get-MspkiGuiFindingTitle {
    <#
    .SYNOPSIS
    The one title of a finding for the grid, the details pane, the palette and History (D-12): the category in words, the readable name
    of what it is about (common name, never a distinguished name) and the part that tells it apart (Get-MspkiGuiFindingQualifier).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Finding)
    if ($null -eq $Finding) { return '' }
    $dot = ' ' + [string][char]0x00B7 + ' '
    $cat = [string]$Finding.Category
    if ($script:MspkiGuiCategoryWord.ContainsKey($cat)) { $cat = $script:MspkiGuiCategoryWord[$cat] }
    $subject = Get-MspkiGuiShortTarget -Target ([string]$Finding.Target)
    $q = Get-MspkiGuiFindingQualifier -Finding $Finding
    $parts = @($cat, $subject, $(if ($q -notlike '(*') { $q } else { '' })) | Where-Object { $_ }
    $t = (@($parts) -join $dot)
    if ($q -like '(*' -and $t) { $t += ' ' + $q }
    if (-not $t) { $t = [string]$Finding.Id }
    return $t
}

function Format-MspkiGuiTime {
    <#
    .SYNOPSIS
    The one time format of the window (D-30): "17 Nov 2026, 08:00 UTC". Accepts a DateTime or a text date; '' when there is none.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value -or '' -eq [string]$Value) { return '' }
    $c = [System.Globalization.CultureInfo]::InvariantCulture
    $d = [datetime]::MinValue
    if ($Value -is [datetime]) { $d = $Value.ToUniversalTime() }
    elseif (-not [datetime]::TryParse([string]$Value, $c, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return [string]$Value }
    return ($d.ToString('d MMM yyyy, HH:mm', $c) + ' UTC')
}

function Format-MspkiGuiTextTimes {
    <#
    .SYNOPSIS
    Engine text with its ISO times ("2026-11-17T08:00:00Z") written the window's way ("17 Nov 2026, 08:00 UTC"). Only for display;
    the finding itself and the copied text keep the original.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][AllowNull()][string]$Text)
    if (-not $Text) { return '' }
    # D-39: an older engine's developer words, as people would say them.
    $Text = $Text.Replace('(not probed in this phase)', '(not contacted in this run)')
    return [regex]::Replace($Text, '\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})\b', { param($m) Format-MspkiGuiTime -Value $m.Value })
}

function Get-MspkiGuiGridColumnPlan {
    <#
    .SYNOPSIS
    The Findings grid's column widths for the width it has (D-05): no horizontal scroll, the message always the widest column, and the
    least useful columns become an icon or step aside on narrow grids (their values stay in the details pane). 0 = hidden.
    #>
    [CmdletBinding()]
    param([double]$Width)
    $avail = [math]::Max(0, $Width - 22)
    if ($avail -ge 880) {
        $t = [math]::Round([math]::Min(320, [math]::Max(170, $avail * 0.22)))
        return [pscustomobject]@{ Status = 136; Target = $t; Category = 100; Severity = 84; Confidence = 124; ConfidenceIcon = 0 }
    }
    if ($avail -ge 680) { return [pscustomobject]@{ Status = 136; Target = 170; Category = 90; Severity = 80; Confidence = 0; ConfidenceIcon = 36 } }
    if ($avail -ge 540) { return [pscustomobject]@{ Status = 136; Target = 150; Category = 0; Severity = 76; Confidence = 0; ConfidenceIcon = 36 } }
    return [pscustomobject]@{ Status = 136; Target = 128; Category = 0; Severity = 0; Confidence = 0; ConfidenceIcon = 36 }
}

function New-MspkiGuiPill {
    <#
    .SYNOPSIS
    A badge for the window: Text, Tone (Good, Warn, Bad, Info, Admin, Neutral) and Glyph (an icon character).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Text = '',
        [ValidateSet('Good', 'Warn', 'Bad', 'Info', 'Admin', 'Neutral')][string]$Tone = 'Neutral',
        [int]$Code = 0
    )
    $g = ''
    if ($Code -gt 0) { $g = [string][char]$Code }
    return [pscustomobject][ordered]@{ Text = $Text; Tone = $Tone; Glyph = $g }
}

function Get-MspkiGuiStatusPill {
    <#
    .SYNOPSIS
    The pill (icon, tone, text) for a finding status, a severity or a confidence value.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Value,
        [ValidateSet('Status', 'Severity', 'Confidence')][string]$Kind = 'Status',
        [string]$Text = ''
    )
    $t = $script:MspkiGuiStatusStyle
    if ($Kind -eq 'Severity') { $t = $script:MspkiGuiSeverityStyle }
    if ($Kind -eq 'Confidence') { $t = $script:MspkiGuiConfidenceStyle }
    if (-not $Value) { return (New-MspkiGuiPill -Text '' -Tone Neutral) }
    # D-29: a severity of None is no severity: no pill.
    if ($Kind -eq 'Severity' -and $Value -eq 'None' -and -not $Text) { return (New-MspkiGuiPill -Text '' -Tone Neutral) }
    if (-not $Text) { $Text = Get-MspkiGuiStatusLabel -Value $Value }
    if ($t.ContainsKey($Value)) { return (New-MspkiGuiPill -Text $Text -Tone $t[$Value][0] -Code $t[$Value][1]) }
    return (New-MspkiGuiPill -Text $Text -Tone Neutral -Code 0xE897)
}

function Get-MspkiGuiStatusOrder {
    <#
    .SYNOPSIS
    The finding statuses from most to least serious (the order of the summary tiles).
    #>
    [CmdletBinding()]
    param()
    return @($script:MspkiGuiStatusOrder)
}

function Get-MspkiGuiRank {
    <#
    .SYNOPSIS
    Sort rank of a Status, Severity or Confidence value (higher = more serious or more certain; -1 when unknown).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Status', 'Severity', 'Confidence')][string]$Kind,
        [AllowNull()][AllowEmptyString()][string]$Value
    )
    $t = $script:MspkiGuiStatusRank
    if ($Kind -eq 'Severity') { $t = $script:MspkiGuiSeverityRank }
    if ($Kind -eq 'Confidence') { $t = $script:MspkiGuiConfidenceRank }
    if ($Value -and $t.ContainsKey($Value)) { return [int]$t[$Value] }
    return -1
}

function Get-MspkiGuiStageList {
    <#
    .SYNOPSIS
    The engine stages in run order (Name, Label), used for the progress bar.
    #>
    [CmdletBinding()]
    param()
    return @($script:MspkiGuiStages | ForEach-Object { [pscustomobject]@{ Name = $_[0]; Label = $_[1] } })
}

function Get-MspkiGuiStageLabel {
    <#
    .SYNOPSIS
    The plain-language label of an engine stage name (the name itself when it is not a known stage).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Stage)
    foreach ($s in $script:MspkiGuiStages) { if ($s[0] -eq $Stage) { return $s[1] } }
    return $Stage
}

function Get-MspkiGuiProgressPercent {
    <#
    .SYNOPSIS
    Progress bar value (0 to 100) from the stages that have finished.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$FinishedStages = @())
    $names = @($script:MspkiGuiStages | ForEach-Object { $_[0] })
    $known = @($FinishedStages | Where-Object { $_ -and ($names -contains $_) } | Select-Object -Unique)
    return [int][math]::Min(100, [math]::Floor(100 * $known.Count / $names.Count))
}

function New-MspkiGuiLogRow {
    <#
    .SYNOPSIS
    One Run Log row: the text, the level (Info, Warning, Error, Debug) and a short level tag shown as text next to the colour.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text, [string]$Level = 'Info')
    $tag = @{ Info = 'INFO '; Warning = 'WARN '; Error = 'ERROR'; Debug = 'DEBUG' }[$Level]
    if (-not $tag) { $tag = 'INFO ' }
    return [pscustomobject][ordered]@{ Text = $Text; Level = $Level; Tag = $tag; Search = $Text.ToLowerInvariant() }
}

function Format-MspkiGuiErrorText {
    <#
    .SYNOPSIS
    One readable line for an exception: its message and the messages of its inner exceptions (no stack trace, no file paths).
    #>
    [CmdletBinding()]
    param([AllowNull()]$Exception)
    if ($null -eq $Exception) { return 'An unknown error.' }
    $parts = New-Object System.Collections.ArrayList
    $e = $Exception
    $depth = 0
    while ($null -ne $e -and $depth -lt 5) {
        $m = ([string]$e.Message).Trim()
        if ($m -and -not $parts.Contains($m)) { [void]$parts.Add($m) }
        $e = $e.InnerException
        $depth++
    }
    if ($parts.Count -eq 0) { return ('An error of type {0}.' -f $Exception.GetType().Name) }
    return ($parts -join ' | ')
}

function ConvertTo-MspkiGuiLogRow {
    <#
    .SYNOPSIS
    Turns one progress-queue message of kind Log into a row (Text, Level) for the Run Log list.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Message)
    $level = [string]$Message.Level
    if (-not $level) { $level = 'Info' }
    return (New-MspkiGuiLogRow -Text ([string]$Message.Text) -Level $level)
}

function ConvertTo-MspkiGuiLogRowFromLine {
    <#
    .SYNOPSIS
    Turns one line of a run.log file into a row (Text, Level); the level is read from the "[LEVEL]" marker.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Line)
    $level = 'Info'
    if ($Line -match '^\S+\s+\[(INFO|WARNING|ERROR|DEBUG)\]') {
        $level = (Get-Culture).TextInfo.ToTitleCase($Matches[1].ToLowerInvariant())
    }
    return (New-MspkiGuiLogRow -Text $Line -Level $level)
}

function ConvertTo-MspkiGuiRow {
    <#
    .SYNOPSIS
    One finding as a flat row for the Findings grid. Keeps the original finding in the Finding property.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $f = $Finding
    $msg = Get-MspkiGuiReadableName -Name (Format-MspkiGuiTextTimes -Text (([string]$f.Message) -replace '\s*[\r\n]+\s*', ' '))
    $source = (@($f.Sources) | Where-Object { $_ }) -join '; '
    $search = (@([string]$f.Id, [string]$f.Status, (Get-MspkiGuiStatusLabel -Value (Get-MspkiGuiFindingStatusKey -Finding $f)), [string]$f.Severity, [string]$f.Category, [string]$f.Role, [string]$f.Target, [string]$f.Endpoint,
        [string]$f.RelatedCA, [string]$f.Confidence, [string]$f.StatusCode, $source, $msg, [string]$f.Message, ((@($f.Evidence) | Where-Object { $_ }) -join ' ')) -join ' ').ToLowerInvariant()
    $key = Get-MspkiGuiFindingStatusKey -Finding $f
    $sevText = Get-MspkiGuiStatusLabel -Value ([string]$f.Severity)
    if ([string]$f.Severity -eq 'None') { $sevText = '' }
    $readable = Get-MspkiGuiShortTarget -Target ([string]$f.Target)
    $qual = Get-MspkiGuiFindingQualifier -Finding $f
    return [pscustomobject][ordered]@{
        Id             = [string]$f.Id
        Status         = [string]$f.Status
        StatusKey      = $key
        StatusWord     = (Get-MspkiGuiStatusLabel -Value $key)
        StatusRank     = (Get-MspkiGuiRank -Kind Status -Value ([string]$f.Status))
        Severity       = [string]$f.Severity
        SeverityText   = $sevText
        SeverityRank   = (Get-MspkiGuiRank -Kind Severity -Value ([string]$f.Severity))
        Category       = [string]$f.Category
        Target         = [string]$f.Target
        TargetText     = $(if ($qual -like '(*') { '{0} {1}' -f $readable, $qual } elseif ($qual) { '{0} {1} {2}' -f $readable, [char]0x00B7, $qual } else { $readable })
        TargetTip      = $(if ($f.Endpoint) { '{0}{1}{2}' -f [string]$f.Target, "`r`n", [string]$f.Endpoint } else { [string]$f.Target })
        Title          = (Get-MspkiGuiFindingTitle -Finding $f)
        Endpoint       = [string]$f.Endpoint
        Confidence     = [string]$f.Confidence
        ConfidenceRank = (Get-MspkiGuiRank -Kind Confidence -Value ([string]$f.Confidence))
        StatusPill     = (Get-MspkiGuiStatusPill -Value $key)
        ConfidencePill = (Get-MspkiGuiStatusPill -Value ([string]$f.Confidence) -Kind Confidence)
        SeverityPill   = (Get-MspkiGuiStatusPill -Value ([string]$f.Severity) -Kind Severity)
        StatusCode     = [string]$f.StatusCode
        Source         = $source
        Message        = $msg
        SearchText     = $search
        Finding        = $f
    }
}

function ConvertTo-MspkiGuiRowList {
    <#
    .SYNOPSIS
    All findings as grid rows in a typed list (the grid's items source).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) { $rows.Add((ConvertTo-MspkiGuiRow -Finding $f)) }
    return , $rows
}

function Test-MspkiGuiRowFilter {
    <#
    .SYNOPSIS
    True when a grid row passes the filters. Text: every word must appear somewhere in the row (case-insensitive).
    Status: one or several values (a row passes when it matches any of them). Severity, Category and Confidence: an exact
    match. An empty value or "All" means no filter.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Row,
        [AllowEmptyString()][string]$Text = '',
        [AllowNull()][string[]]$Status = @(),
        [AllowEmptyString()][string]$Category = '',
        [AllowEmptyString()][string]$Confidence = '',
        [AllowEmptyString()][string]$Severity = ''
    )
    $all = $script:MspkiGuiAllChoice
    $wanted = @($Status | Where-Object { $_ -and $_ -ne $all })
    $rs = [string]$Row.Status; if ($null -ne $Row.PSObject.Properties['StatusKey']) { $rs = [string]$Row.StatusKey }
    if ($wanted.Count -gt 0 -and $wanted -notcontains $rs) { return $false }
    if ($Category -and $Category -ne $all -and $Row.Category -ne $Category) { return $false }
    if ($Confidence -and $Confidence -ne $all -and $Row.Confidence -ne $Confidence) { return $false }
    if ($Severity -and $Severity -ne $all -and $Row.Severity -ne $Severity) { return $false }
    if ($Text) {
        foreach ($w in @($Text.ToLowerInvariant() -split '\s+' | Where-Object { $_ })) {
            if ($Row.SearchText.IndexOf($w, [System.StringComparison]::Ordinal) -lt 0) { return $false }
        }
    }
    return $true
}

function Get-MspkiGuiFilteredRow {
    <#
    .SYNOPSIS
    The rows that pass the filters (same rules as Test-MspkiGuiRowFilter).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [string]$Text = '', [AllowNull()][string[]]$Status = @(), [string]$Category = '', [string]$Confidence = '', [string]$Severity = ''
    )
    return @($Rows | Where-Object { Test-MspkiGuiRowFilter -Row $_ -Text $Text -Status $Status -Category $Category -Confidence $Confidence -Severity $Severity })
}

function Get-MspkiGuiFilterChoice {
    <#
    .SYNOPSIS
    The values for a filter drop-down: "All" and then the distinct values present in the rows
    (statuses, severity and confidence by rank, categories alphabetically).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [Parameter(Mandatory = $true)][ValidateSet('Status', 'Category', 'Confidence', 'Severity')][string]$Field
    )
    $values = @($Rows | ForEach-Object { [string]$_.$Field } | Where-Object { $_ } | Select-Object -Unique)
    if ($Field -in @('Status', 'Confidence', 'Severity')) { $values = @($values | Sort-Object { -1 * (Get-MspkiGuiRank -Kind $Field -Value $_) }) }
    else { $values = @($values | Sort-Object) }
    return @($script:MspkiGuiAllChoice) + $values
}

function Read-MspkiGuiResults {
    <#
    .SYNOPSIS
    Reads a results.json written by this tool (an earlier run, no scanning) into the same shape a live run gives.
    Throws a message that says what is wrong in plain language.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw ('The file was not found: {0}' -f $full) }
    $text = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
    $j = $null
    # In-box JavaScriptSerializer with no size limit (ConvertFrom-Json in Windows PowerShell 5.1 stops at about 2 MB).
    try { $j = ConvertFrom-MspkiJson -Text $text }
    catch { throw ('This file is not valid JSON: {0}' -f $_.Exception.Message) }
    if ($null -eq $j -or -not $j.Schema -or ([string]$j.Schema) -notlike 'mspki-healthcheck/*') {
        throw 'This is not a results.json written by the MSPKI Health Check.'
    }
    # Adapter for every format version this tool has written (format 1 has no graph); a newer format throws a plain message.
    $j = ConvertFrom-MspkiResultsDocument -Document $j
    $folder = Split-Path -Parent $full
    $html = Join-Path $folder 'report.html'
    $log = Join-Path $folder 'run.log'
    $htmlPath = Find-MspkiGuiReportPath -ResultsPath $full
    $logPath = ''
    if (Test-Path -LiteralPath $log -PathType Leaf) { $logPath = $log }
    return [pscustomobject][ordered]@{
        RunInfo      = $j.RunInfo
        Inventory    = $j.Inventory
        Findings     = @($j.Findings)
        ExitCode     = $j.ExitCode
        Graph        = $j.Graph
        SchemaVersion = $j.SchemaVersion
        Notice       = $j.Notice
        OutputFolder = $folder
        ResultsPath  = $full
        ReportPath   = $htmlPath
        LogPath      = $logPath
    }
}

function Find-MspkiGuiReportPath {
    <#
    .SYNOPSIS
    The HTML report of a results file: report.html in the same folder, or <name>-report.html for <name>-results.json. '' when there is none.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$ResultsPath, [AllowEmptyString()][string]$Known = '')
    if ($Known -and (Test-Path -LiteralPath $Known -PathType Leaf)) { return $Known }
    if (-not $ResultsPath) { return '' }
    $folder = Split-Path -Parent $ResultsPath
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($ResultsPath)
    $names = @('report.html')
    if ($stem -match '(?i)results$') { $names += ($stem -replace '(?i)results$', 'report') + '.html' }
    foreach ($n in $names) { $p = Join-Path $folder $n; if (Test-Path -LiteralPath $p -PathType Leaf) { return $p } }
    return ''
}

function Test-MspkiGuiTimeout {
    <#
    .SYNOPSIS
    Validates the timeout box: a whole number from 1 to 120. Returns the number, or $null when the text is not valid.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Text)
    $n = 0
    if ([int]::TryParse($Text.Trim(), [ref]$n) -and $n -ge 1 -and $n -le 120) { return $n }
    return $null
}

function Format-MspkiGuiCount {
    <#
    .SYNOPSIS
    A count with the right word form: "1 finding", "2 findings" (the plural is the singular plus "s" unless given).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Count, [Parameter(Mandatory = $true)][string]$Singular, [string]$Plural = '')
    if (-not $Plural) { $Plural = $Singular + 's' }
    if ($Count -eq 1) { return ('1 {0}' -f $Singular) }
    return ('{0} {1}' -f $Count, $Plural)
}

# Separator between facts on one line (a middle dot with spaces).
$script:MspkiGuiDot = ' ' + [string][char]0x00B7 + ' '
