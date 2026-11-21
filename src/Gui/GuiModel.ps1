# GUI data model: pure functions that turn run results (live or from results.json) into plain objects for the window.
# No WPF types here, so they can be tested without a window. The GUI only displays and filters; every check stays in the engine.

$script:MspkiGuiStatusOrder = @('Critical', 'Fail', 'Error', 'Warning', 'Skipped', 'Information', 'Pass', 'NotApplicable')
$script:MspkiGuiStatusRank = @{ Critical = 7; Fail = 6; Error = 5; Warning = 4; Skipped = 3; Information = 2; Pass = 1; NotApplicable = 0 }
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
    @('Analysis:StaleReferences', 'Reviewing stale references')
)

# Icon (Segoe MDL2 Assets code point) and tone for every status word the window shows. Icon + text, never colour alone.
$script:MspkiGuiStatusStyle = @{
    Critical = @('Bad', 0xEA39); Fail = @('Bad', 0xE711); Error = @('Admin', 0xE783); PermissionDenied = @('Admin', 0xE72E)
    Warning = @('Warn', 0xE7BA); Timeout = @('Warn', 0xE916); Skipped = @('Neutral', 0xE7E8); Information = @('Info', 0xE946)
    Pass = @('Good', 0xE73E); NotApplicable = @('Neutral', 0xE738); NotTested = @('Neutral', 0xE738); Unknown = @('Neutral', 0xE897)
}
$script:MspkiGuiConfidenceStyle = @{
    Confirmed = @('Good', 0xE73E); Referenced = @('Info', 0xE71B); Inferred = @('Warn', 0xE897); Unknown = @('Neutral', 0xE897)
}
$script:MspkiGuiSeverityStyle = @{
    High = @('Bad', 0xE7BA); Medium = @('Warn', 0xE7BA); Low = @('Info', 0xE946); ReviewRequired = @('Admin', 0xE7B3); Information = @('Neutral', 0xE946); None = @('Neutral', 0xE738)
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
    if (-not $Text) { $Text = ($Value -creplace '([a-z])([A-Z])', '$1 $2') }
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
    $msg = ([string]$f.Message) -replace '\s*[\r\n]+\s*', ' '
    $source = (@($f.Sources) | Where-Object { $_ }) -join '; '
    $search = (@([string]$f.Id, [string]$f.Status, [string]$f.Severity, [string]$f.Category, [string]$f.Role, [string]$f.Target, [string]$f.Endpoint,
        [string]$f.RelatedCA, [string]$f.Confidence, [string]$f.StatusCode, $source, $msg, ((@($f.Evidence) | Where-Object { $_ }) -join ' ')) -join ' ').ToLowerInvariant()
    return [pscustomobject][ordered]@{
        Id             = [string]$f.Id
        Status         = [string]$f.Status
        StatusRank     = (Get-MspkiGuiRank -Kind Status -Value ([string]$f.Status))
        Severity       = [string]$f.Severity
        SeverityRank   = (Get-MspkiGuiRank -Kind Severity -Value ([string]$f.Severity))
        Category       = [string]$f.Category
        Target         = [string]$f.Target
        Endpoint       = [string]$f.Endpoint
        Confidence     = [string]$f.Confidence
        ConfidenceRank = (Get-MspkiGuiRank -Kind Confidence -Value ([string]$f.Confidence))
        StatusPill     = (Get-MspkiGuiStatusPill -Value ([string]$f.Status))
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
    if ($wanted.Count -gt 0 -and $wanted -notcontains $Row.Status) { return $false }
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
    try { $j = $text | ConvertFrom-Json }
    catch {
        if ($text.Length -gt 2000000) {
            throw 'This results file is larger than Windows PowerShell 5.1 can read (about 2 MB of JSON). Open report.html from the same folder instead.'
        }
        throw ('This file is not valid JSON: {0}' -f $_.Exception.Message)
    }
    if ($null -eq $j -or -not $j.Schema -or ([string]$j.Schema) -notlike 'mspki-healthcheck/*') {
        throw 'This is not a results.json written by the MSPKI Health Check.'
    }
    $folder = Split-Path -Parent $full
    $html = Join-Path $folder 'report.html'
    $log = Join-Path $folder 'run.log'
    $htmlPath = ''; $logPath = ''
    if (Test-Path -LiteralPath $html -PathType Leaf) { $htmlPath = $html }
    if (Test-Path -LiteralPath $log -PathType Leaf) { $logPath = $log }
    return [pscustomobject][ordered]@{
        RunInfo      = $j.RunInfo
        Inventory    = $j.Inventory
        Findings     = @($j.Findings)
        ExitCode     = $j.ExitCode
        OutputFolder = $folder
        ResultsPath  = $full
        ReportPath   = $htmlPath
        LogPath      = $logPath
    }
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
