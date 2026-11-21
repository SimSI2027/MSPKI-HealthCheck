# GUI data model: pure functions that turn run results (live or from results.json) into plain objects for the window.
# No WPF types here, so they can be tested without a window. The GUI only displays and filters; every check stays in the engine.

$script:MspkiGuiStatusOrder = @('Critical', 'Fail', 'Error', 'Warning', 'Skipped', 'Information', 'Pass', 'NotApplicable')
$script:MspkiGuiStatusRank = @{ Critical = 7; Fail = 6; Error = 5; Warning = 4; Skipped = 3; Information = 2; Pass = 1; NotApplicable = 0 }
$script:MspkiGuiSeverityRank = @{ High = 5; Medium = 4; Low = 3; ReviewRequired = 2; Information = 1; None = 0 }
$script:MspkiGuiConfidenceRank = @{ Confirmed = 3; Referenced = 2; Inferred = 1; Unknown = 0 }
$script:MspkiGuiAllChoice = '(all)'

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

function ConvertTo-MspkiGuiLogRow {
    <#
    .SYNOPSIS
    Turns one progress-queue message of kind Log into a row (Text, Level) for the Run Log list.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Message)
    $level = [string]$Message.Level
    if (-not $level) { $level = 'Info' }
    return [pscustomobject][ordered]@{ Text = [string]$Message.Text; Level = $level }
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
    return [pscustomobject][ordered]@{ Text = $Line; Level = $level }
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
    Status, Category and Confidence: an exact match, or no filter when empty or "(all)".
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Row,
        [AllowEmptyString()][string]$Text = '',
        [AllowEmptyString()][string]$Status = '',
        [AllowEmptyString()][string]$Category = '',
        [AllowEmptyString()][string]$Confidence = ''
    )
    $all = $script:MspkiGuiAllChoice
    if ($Status -and $Status -ne $all -and $Row.Status -ne $Status) { return $false }
    if ($Category -and $Category -ne $all -and $Row.Category -ne $Category) { return $false }
    if ($Confidence -and $Confidence -ne $all -and $Row.Confidence -ne $Confidence) { return $false }
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
        [string]$Text = '', [string]$Status = '', [string]$Category = '', [string]$Confidence = ''
    )
    return @($Rows | Where-Object { Test-MspkiGuiRowFilter -Row $_ -Text $Text -Status $Status -Category $Category -Confidence $Confidence })
}

function Get-MspkiGuiFilterChoice {
    <#
    .SYNOPSIS
    The values for a filter drop-down: "(all)" and then the distinct values present in the rows
    (statuses and confidence by rank, categories alphabetically).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [Parameter(Mandatory = $true)][ValidateSet('Status', 'Category', 'Confidence')][string]$Field
    )
    $values = @($Rows | ForEach-Object { [string]$_.$Field } | Where-Object { $_ } | Select-Object -Unique)
    if ($Field -eq 'Status') { $values = @($values | Sort-Object { -1 * (Get-MspkiGuiRank -Kind Status -Value $_) }) }
    elseif ($Field -eq 'Confidence') { $values = @($values | Sort-Object { -1 * (Get-MspkiGuiRank -Kind Confidence -Value $_) }) }
    else { $values = @($values | Sort-Object) }
    return @($script:MspkiGuiAllChoice) + $values
}

function ConvertTo-MspkiGuiTreeNode {
    <#
    .SYNOPSIS
    Turns a Discovery Map node (Get-MspkiDiscoveryTree) into a plain tree item for the TreeView: label, status,
    confidence, a hint when something worse is below it, and the child items.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Node,
        [int]$Depth = 0
    )
    $kids = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in @($Node.Children)) { if ($null -ne $c) { $kids.Add((ConvertTo-MspkiGuiTreeNode -Node $c -Depth ($Depth + 1))) } }
    $status = [string]$Node.Status
    $below = [string]$Node.WorstBelow
    $belowText = ''
    $belowRank = Get-MspkiGuiRank -Kind Status -Value $below
    if ($below -and $belowRank -gt (Get-MspkiGuiRank -Kind Status -Value $status) -and $belowRank -ge (Get-MspkiGuiRank -Kind Status -Value 'Warning')) {
        $belowText = 'worst below: {0}' -f $below
    }
    $conf = [string]$Node.Confidence
    $confText = ''
    if ($conf) { $confText = '({0})' -f $conf }
    return [pscustomobject][ordered]@{
        Type           = [string]$Node.Type
        Label          = [string]$Node.Label
        Status         = $status
        Confidence     = $conf
        ConfidenceText = $confText
        BelowText      = $belowText
        Expanded       = ($Depth -lt 2)
        Detail         = [string[]]@($Node.Detail)
        Sources        = [string[]]@($Node.Sources)
        FindingIds     = [string[]]@($Node.FindingIds)
        Children       = [object[]]$kids.ToArray()
    }
}

function Get-MspkiGuiNodeSummary {
    <#
    .SYNOPSIS
    Text for the panel next to the tree: the node's type, status, confidence, details and sources.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Node)
    if ($null -eq $Node) { return '' }
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add([string]$Node.Label)
    $lines.Add(('Type: {0}' -f $Node.Type))
    if ($Node.Status) { $lines.Add(('Status: {0}' -f $Node.Status)) }
    if ($Node.Confidence) { $lines.Add(('Confidence: {0}' -f $Node.Confidence)) }
    if ($Node.BelowText) { $lines.Add([string]$Node.BelowText) }
    foreach ($d in @($Node.Detail)) { $lines.Add([string]$d) }
    if (@($Node.Sources).Count -gt 0) { $lines.Add(('Sources: {0}' -f (@($Node.Sources) -join ', '))) }
    return ($lines -join "`r`n")
}

function Get-MspkiGuiSummary {
    <#
    .SYNOPSIS
    The data for the Summary tab: forest, domain, DC, user, admin, exit code, counts by status and the CAs found.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]$RunInfo = $null,
        [AllowNull()]$Inventory = $null,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [AllowNull()]$ExitCode = $null
    )
    $all = @($Findings | Where-Object { $null -ne $_ })
    $ctx = $null
    if ($null -ne $Inventory) { $ctx = $Inventory.AdContext }
    $pick = {
        param([string]$Name)
        $v = ''
        if ($null -ne $RunInfo -and $RunInfo.$Name) { $v = [string]$RunInfo.$Name }
        if (-not $v -and $null -ne $ctx -and $ctx.$Name) { $v = [string]$ctx.$Name }
        return $v
    }
    $exitText = ''
    if ($null -ne $ExitCode -and '' -ne [string]$ExitCode) {
        $exitText = [string]$ExitCode
        if (Get-Command -Name 'Get-MspkiExitCodeInfo' -ErrorAction SilentlyContinue) {
            try { $exitText = '{0} - {1}' -f $ExitCode, (Get-MspkiExitCodeInfo -Code ([int]$ExitCode)).Name } catch { $exitText = [string]$ExitCode }
        }
    }
    $tiles = @(foreach ($s in $script:MspkiGuiStatusOrder) {
        [pscustomobject][ordered]@{ Status = $s; Count = @($all | Where-Object { $_.Status -eq $s }).Count }
    })
    $cas = @()
    if ($null -ne $Inventory) {
        $cas = @(foreach ($ca in @($Inventory.EnterpriseCAs | Where-Object { $_ })) {
            $mine = @($all | Where-Object { $_.RelatedCA -eq $ca.Name -or ($_.Category -eq 'CA' -and $_.Target -eq $ca.Name) })
            $worst = ''; $rank = -2
            foreach ($f in $mine) { $r = Get-MspkiGuiRank -Kind Status -Value ([string]$f.Status); if ($r -gt $rank) { $rank = $r; $worst = [string]$f.Status } }
            [pscustomobject][ordered]@{
                Name         = [string]$ca.Name
                Host         = [string]$ca.DnsHostName
                Config       = [string]$ca.Config
                Certificates = @($ca.CertificateThumbprints).Count
                Templates    = @($ca.Templates).Count
                Findings     = $mine.Count
                Status       = $worst
            }
        })
    }
    $isAdmin = ''
    if ($null -ne $RunInfo -and $null -ne $RunInfo.IsAdmin) {
        if ([bool]$RunInfo.IsAdmin) { $isAdmin = 'Yes (elevated)' } else { $isAdmin = 'No (standard user)' }
    }
    $runState = ''
    if ($null -ne $RunInfo -and $null -ne $RunInfo.Completed) {
        if ([bool]$RunInfo.Completed) { $runState = 'Finished' } else { $runState = 'Did not finish (partial results)' }
    }
    $user = ''; $computer = ''; $started = ''
    if ($null -ne $RunInfo) { $user = [string]$RunInfo.UserContext; $computer = [string]$RunInfo.ComputerName; $started = [string]$RunInfo.StartedUtc }
    return [pscustomobject][ordered]@{
        Forest           = (& $pick 'Forest')
        Domain           = (& $pick 'Domain')
        DomainController = (& $pick 'DomainController')
        Site             = (& $pick 'Site')
        User             = $user
        Computer         = $computer
        IsAdmin          = $isAdmin
        ExitCode         = $exitText
        RunState         = $runState
        Started          = $started
        Total            = $all.Count
        Tiles            = $tiles
        CAs              = $cas
    }
}

function Get-MspkiGuiFindingDetail {
    <#
    .SYNOPSIS
    Every field of a finding, grouped for the Details tab: header fields, sources, layer statuses, evidence, remediation, notes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $f = $Finding
    $fieldNames = @('Id', 'Timestamp', 'Stage', 'Category', 'Role', 'Target', 'Endpoint', 'RelatedCA', 'Confidence', 'Status', 'Severity', 'StatusCode', 'Scope', 'Forest', 'Domain')
    $fields = @(foreach ($n in $fieldNames) { [pscustomobject][ordered]@{ Name = $n; Value = [string]$f.$n } })
    $layerMap = @(@('DNS', 'DnsStatus'), @('TCP', 'TcpStatus'), @('TLS', 'TlsStatus'), @('HTTP', 'HttpStatus'), @('Redirect', 'RedirectStatus'),
        @('Content', 'ContentStatus'), @('Chain', 'ChainStatus'), @('Discovery', 'DiscoveryStatus'))
    $layers = @(foreach ($l in $layerMap) {
        $v = [string]$f.($l[1])
        if (-not $v) { $v = 'NotTested' }
        [pscustomobject][ordered]@{ Name = $l[0]; Status = $v }
    })
    return [pscustomobject][ordered]@{
        Id          = [string]$f.Id
        Status      = [string]$f.Status
        Title       = ('{0}  {1}  {2}' -f $f.Id, $f.Category, $f.Target).Trim()
        Message     = [string]$f.Message
        Fields      = $fields
        Sources     = [string[]]@($f.Sources | Where-Object { $_ })
        Layers      = $layers
        Evidence    = ((@($f.Evidence) | Where-Object { $null -ne $_ }) -join "`r`n")
        Remediation = [string]$f.Remediation
        Notes       = [string]$f.Notes
    }
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
