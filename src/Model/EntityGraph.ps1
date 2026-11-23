# Entity graph: every object the run found (forest, CA, CA certificate generation, CRL, endpoint, host, service, template, AD object,
# local certificate), every place it was seen or was expected but missing (observations), and how objects relate (relations).
# Design and vocabulary: docs/DATA-MODEL.md. Ids are deterministic (type prefix + normalised natural key), so the same object gets the
# same id in every run on every computer, and two runs can be compared by id.

$script:MspkiGraphSchemaVersion = 2

$script:MspkiEntityTypes = [ordered]@{
    Forest = 'forest'; Domain = 'domain'; CA = 'ca'; CACertificate = 'cacert'; CRL = 'crl'; Endpoint = 'endpoint'; Host = 'host'
    Service = 'service'; Template = 'template'; LocalCertificate = 'localcert'; ADObject = 'adobject'; Account = 'account'; RACertificate = 'racert'
}
$script:MspkiServiceKinds = @('WebEnrollment', 'CES', 'CEP', 'NDES', 'OCSP', 'IntuneConnector')
$script:MspkiRelationTypes = @('issuedBy', 'signedBy', 'publishedAt', 'references', 'hostedOn', 'servedBy', 'resolvesTo', 'aliasOf',
    'enrollsVia', 'supersedes', 'certificateOf', 'partOf', 'mayEnroll', 'identifies', 'memberOf', 'mayUse')
$script:MspkiObservationKinds = @('Seen', 'Referenced', 'ExpectedMissing')

$script:MspkiGraph = $null

function Reset-MspkiEntityGraph {
    <#
    .SYNOPSIS
    Starts an empty entity graph for a run.
    #>
    [CmdletBinding()]
    param()
    $script:MspkiGraph = @{
        Entities     = [ordered]@{}
        Observations = New-Object System.Collections.ArrayList
        ObsKeys      = @{}
        Relations    = New-Object System.Collections.ArrayList
        RelKeys      = @{}
        UrlCrl       = @{}
        Announced    = @{}
        CrlKey       = @{}
    }
}

function Get-MspkiEntityGraphState {
    # The live graph; started on first use so that analysers can record into it in tests without a full run.
    if ($null -eq $script:MspkiGraph) { Reset-MspkiEntityGraph }
    return $script:MspkiGraph
}

function Get-MspkiEntityId {
    <#
    .SYNOPSIS
    The stable id of an entity: "<prefix>:<normalised key>". Keys are lower-cased and trimmed; thumbprints and key ids lose spaces.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Key
    )
    if (-not $script:MspkiEntityTypes.Contains($Type)) { throw ('Unknown entity type: {0}' -f $Type) }
    $k = ([string]$Key).Trim().ToLowerInvariant()
    if ($Type -in @('CACertificate', 'LocalCertificate', 'RACertificate')) { $k = $k -replace '\s', '' }
    if ($Type -eq 'Host') { $k = $k.TrimEnd('.') }
    return ('{0}:{1}' -f $script:MspkiEntityTypes[$Type], $k)
}

function Get-MspkiEndpointEntityId {
    <#
    .SYNOPSIS
    The entity id of an AIA/CDP/OCSP/service URL: the lead registry's normalised key, so http and https of one path, case, default
    ports and %20 do not create two endpoints.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Url)
    $n = ConvertTo-MspkiNormalizedUrl -Url $Url
    $key = $n.Key
    if (-not $key) { $key = ([string]$Url).Trim() }
    return (Get-MspkiEntityId -Type 'Endpoint' -Key $key)
}

function Get-MspkiCrlEntityId {
    <#
    .SYNOPSIS
    The entity id of a CRL: one per CA key and kind (base or delta). The key is the CRL's Authority Key Identifier (= the Subject
    Key Identifier of the CA certificate that signs it); without one, the issuer name and the CA version.
    #>
    [CmdletBinding()]
    param(
        [string]$AuthorityKeyId = '',
        [string]$Issuer = '',
        [string]$CAVersion = '',
        [bool]$IsDelta = $false
    )
    $kind = $(if ($IsDelta) { 'delta' } else { 'base' })
    $k = ([string]$AuthorityKeyId -replace '[\s:]', '')
    if (-not $k) { $k = 'name=' + ([string]$Issuer).Trim() + $(if ($CAVersion) { ';v=' + $CAVersion } else { '' }) }
    return (Get-MspkiEntityId -Type 'CRL' -Key ('{0}:{1}' -f $k, $kind))
}

function Add-MspkiEntity {
    <#
    .SYNOPSIS
    Adds an entity or merges properties into an existing one (a value already set is kept unless -Overwrite). Returns the id.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Type,
        [string]$Key = '',
        [string]$Id = '',
        [string]$Name = '',
        [hashtable]$Properties = @{},
        [switch]$Overwrite,
        [string[]]$Parents = @()
    )
    $g = Get-MspkiEntityGraphState
    if (-not $Id) { $Id = Get-MspkiEntityId -Type $Type -Key $Key }
    if (-not $g.Entities.Contains($Id)) {
        $g.Entities[$Id] = [ordered]@{ Id = $Id; Type = $Type; Name = $(if ($Name) { $Name } else { $Key }); Properties = [ordered]@{} }
        # The window's live map hears about a new entity once (GX1); -Parents are the ids it sits under, known when it is created.
        # (An entity the lead announcer already named early is not announced a second time.)
        if (-not $g.Announced.ContainsKey($Id)) {
            Send-MspkiGraphEvent -Kind 'Entity' -Data @{ Id = $Id; Type = $Type; Name = [string]$g.Entities[$Id].Name; Parents = @($Parents | Where-Object { $_ -and $_ -ne $Id }) }
        }
    }
    $e = $g.Entities[$Id]
    if ($Name -and ($Overwrite -or -not $e.Name -or $e.Name -eq $Key)) { $e.Name = $Name }
    foreach ($p in @($Properties.Keys | Sort-Object)) {
        $v = $Properties[$p]
        if ($null -eq $v -or ($v -is [string] -and $v -eq '')) { continue }
        if ($Overwrite -or -not $e.Properties.Contains($p)) { $e.Properties[$p] = $v }
    }
    return $Id
}

function Test-MspkiEntity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Id)
    return ((Get-MspkiEntityGraphState).Entities.Contains($Id))
}

function Get-MspkiEntity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Id)
    $g = Get-MspkiEntityGraphState
    if ($g.Entities.Contains($Id)) { return $g.Entities[$Id] }
    return $null
}

function Add-MspkiObservation {
    <#
    .SYNOPSIS
    Records one place an entity was seen (Seen), named (Referenced) or expected but not found (ExpectedMissing).
    .DESCRIPTION
    Source is the kind of place (AD, CA, HTTP, LDAP, Certificate, LocalStore, EventLog, DNS, File). Location is the exact place: a DN,
    a URI, a store path, a CA config string or an event log name. Duplicates (same entity, kind, source and location) are merged.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$EntityId,
        [Parameter(Mandatory = $true)][ValidateSet('Seen', 'Referenced', 'ExpectedMissing')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Location,
        [ValidateSet('Confirmed', 'Referenced', 'Inferred', 'Unknown')][string]$Confidence = 'Referenced',
        [string]$Detail = '',
        [string]$Timestamp = ''
    )
    $g = Get-MspkiEntityGraphState
    $k = ('{0}|{1}|{2}|{3}' -f $EntityId, $Kind, $Source, $Location).ToLowerInvariant()
    if ($g.ObsKeys.ContainsKey($k)) {
        $o = $g.ObsKeys[$k]
        if ($Detail -and $o.Detail -notlike ('*' + $Detail + '*')) { $o.Detail = (@($o.Detail, $Detail) | Where-Object { $_ }) -join '; ' }
        return
    }
    if (-not $Timestamp) { $Timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $o = [ordered]@{ EntityId = $EntityId; Kind = $Kind; Source = $Source; Location = $Location; Confidence = $Confidence; Detail = $Detail; Timestamp = $Timestamp }
    $g.ObsKeys[$k] = $o
    [void]$g.Observations.Add($o)
}

function Add-MspkiRelation {
    <#
    .SYNOPSIS
    Records a directed relation between two entities (see $script:MspkiRelationTypes). Duplicates merge their sources.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$From,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][string]$To,
        [string]$Source = '',
        [ValidateSet('Confirmed', 'Referenced', 'Inferred', 'Unknown')][string]$Confidence = 'Referenced'
    )
    if ($script:MspkiRelationTypes -notcontains $Type) { throw ('Unknown relation type: {0}' -f $Type) }
    if (-not $From -or -not $To -or $From -eq $To) { return }
    $g = Get-MspkiEntityGraphState
    $k = ('{0}|{1}|{2}' -f $From, $Type, $To).ToLowerInvariant()
    if ($g.RelKeys.ContainsKey($k)) {
        $r = $g.RelKeys[$k]
        if ($Source -and @($r.Sources) -notcontains $Source) { $r.Sources = @($r.Sources) + $Source }
        return
    }
    $r = [ordered]@{ From = $From; Type = $Type; To = $To; Sources = @($(if ($Source) { $Source })); Confidence = $Confidence }
    $g.RelKeys[$k] = $r
    [void]$g.Relations.Add($r)
    Send-MspkiGraphEvent -Kind 'Relation' -Data @{ From = $From; Type = $Type; To = $To }
}

function Get-MspkiObservation {
    [CmdletBinding()]
    param([string]$EntityId = '', [string]$Kind = '')
    $all = @((Get-MspkiEntityGraphState).Observations)
    if ($EntityId) { $all = @($all | Where-Object { $_.EntityId -eq $EntityId }) }
    if ($Kind) { $all = @($all | Where-Object { $_.Kind -eq $Kind }) }
    return $all
}

function Get-MspkiRelation {
    [CmdletBinding()]
    param([string]$From = '', [string]$Type = '', [string]$To = '')
    $all = @((Get-MspkiEntityGraphState).Relations)
    if ($From) { $all = @($all | Where-Object { $_.From -eq $From }) }
    if ($Type) { $all = @($all | Where-Object { $_.Type -eq $Type }) }
    if ($To) { $all = @($all | Where-Object { $_.To -eq $To }) }
    return $all
}

function Get-MspkiEntityList {
    [CmdletBinding()]
    param([string]$Type = '')
    $all = @((Get-MspkiEntityGraphState).Entities.Values)
    if ($Type) { $all = @($all | Where-Object { $_.Type -eq $Type }) }
    return $all
}

function Register-MspkiUrlCrl {
    # Remembers which CRL entity a URL served, so CRL findings about that URL can link to it.
    param([string]$Url, [string]$CrlId)
    $g = Get-MspkiEntityGraphState
    $k = (Get-MspkiEndpointEntityId -Url $Url)
    if (-not $g.UrlCrl.ContainsKey($k)) { $g.UrlCrl[$k] = @() }
    if (@($g.UrlCrl[$k]) -notcontains $CrlId) { $g.UrlCrl[$k] = @($g.UrlCrl[$k]) + $CrlId }
}

function Get-MspkiEntityGraphExport {
    <#
    .SYNOPSIS
    The graph in the results.json form: { SchemaVersion; Counts; Entities; Observations; Relations } (JSON-safe, sorted by id).
    #>
    [CmdletBinding()]
    param()
    $g = Get-MspkiEntityGraphState
    $entities = @($g.Entities.Values | Sort-Object { $_.Id } | ForEach-Object {
        [pscustomobject][ordered]@{ Id = $_.Id; Type = $_.Type; Name = $_.Name; Properties = [pscustomobject]$_.Properties }
    })
    $obs = @($g.Observations | Sort-Object { $_.EntityId }, { $_.Kind }, { $_.Source }, { $_.Location } | ForEach-Object { [pscustomobject]$_ })
    $rels = @($g.Relations | Sort-Object { $_.From }, { $_.Type }, { $_.To } | ForEach-Object { [pscustomobject]$_ })
    $byType = [ordered]@{}
    foreach ($t in $script:MspkiEntityTypes.Keys) { $byType[$t] = @($entities | Where-Object { $_.Type -eq $t }).Count }
    return [pscustomobject][ordered]@{
        SchemaVersion = $script:MspkiGraphSchemaVersion
        Counts        = [pscustomobject][ordered]@{
            Entities = $entities.Count; Observations = $obs.Count; Relations = $rels.Count
            ExpectedMissing = @($obs | Where-Object { $_.Kind -eq 'ExpectedMissing' }).Count; ByType = [pscustomobject]$byType
        }
        Entities      = $entities
        Observations  = $obs
        Relations     = $rels
    }
}

function ConvertFrom-MspkiResultsDocument {
    <#
    .SYNOPSIS
    Adapter for every results.json this tool has written: returns { SchemaVersion; RunInfo; Inventory; Findings; ExitCode; Graph; Notice }.
    .DESCRIPTION
    Version 1 (no graph, findings without EntityIds) is accepted: Graph is $null, every finding gets an empty EntityIds list and Notice
    says the drill-down data is missing. Version 2 is read as is. A newer version throws a plain-language message.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Document)
    $schema = [string]$Document.Schema
    if (-not $schema -or $schema -notmatch '^mspki-healthcheck/(\d+)$') { throw 'This is not a results.json written by the MSPKI Health Check.' }
    $ver = [int]$Matches[1]
    if ($ver -gt $script:MspkiGraphSchemaVersion) {
        throw ('This results file uses format version {0}; this copy of the tool reads versions 1 to {1}. Open it with a newer version of the tool, or open report.html from the same folder.' -f $ver, $script:MspkiGraphSchemaVersion)
    }
    $findings = @($Document.Findings | Where-Object { $null -ne $_ })
    foreach ($f in $findings) {
        if ($null -eq $f.PSObject.Properties['EntityIds']) { $f | Add-Member -NotePropertyName 'EntityIds' -NotePropertyValue @() -Force }
    }
    $graph = $null
    $notice = ''
    if ($ver -ge 2 -and $null -ne $Document.PSObject.Properties['Graph']) { $graph = $Document.Graph }
    else { $notice = 'This results file was written by an older version of the tool (format 1). Findings and inventory are shown; the object graph (where each object was seen and how objects relate) is not in it.' }
    return [pscustomobject][ordered]@{
        SchemaVersion = $ver
        RunInfo       = $Document.RunInfo
        Inventory     = $Document.Inventory
        Findings      = $findings
        ExitCode      = $Document.ExitCode
        Graph         = $graph
        Notice        = $notice
    }
}
