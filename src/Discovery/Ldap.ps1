# Read-only LDAP access through System.DirectoryServices. Targeted base / one-level searches with
# explicit attribute lists and time limits. Results are plain hashtables (lower-case attribute name ->
# array of values) so that the rest of the tool never holds live directory objects.

function Get-MspkiLdapObject {
    <#
    .SYNOPSIS
    Runs one read-only LDAP search and returns each result as a hashtable of attribute -> values.
    #>
    [CmdletBinding()]
    param(
        [string]$Server = '',
        [Parameter(Mandatory = $true)][string]$BaseDN,
        [string]$Filter = '(objectClass=*)',
        [ValidateSet('Base', 'OneLevel')][string]$Scope = 'OneLevel',
        [string[]]$Properties = @('distinguishedName'),
        [ValidateRange(1, 600)][int]$TimeoutSeconds = 30,
        [switch]$IncludeDacl
    )
    if ($Server) { $path = 'LDAP://{0}/{1}' -f $Server, $BaseDN } else { $path = 'LDAP://{0}' -f $BaseDN }
    $entry = New-Object System.DirectoryServices.DirectoryEntry($path)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $results = $null
    try {
        $searcher.Filter = $Filter
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]$Scope
        if ($Scope -ne 'Base') { $searcher.PageSize = 500 }
        $searcher.ClientTimeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
        if ($IncludeDacl) { $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Owner, Dacl' }
        $searcher.PropertiesToLoad.Clear()
        foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
        $results = $searcher.FindAll()
        foreach ($r in $results) {
            $rec = @{}
            foreach ($name in $r.Properties.PropertyNames) {
                $rec[([string]$name).ToLowerInvariant()] = @($r.Properties[[string]$name])
            }
            $rec
        }
    }
    finally {
        if ($null -ne $results) { $results.Dispose() }
        $searcher.Dispose()
        $entry.Dispose()
    }
}

function Get-MspkiLdapValue {
    <#
    .SYNOPSIS
    First value of an attribute in a record from Get-MspkiLdapObject ('' or $null when absent).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Record,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $k = $Name.ToLowerInvariant()
    if (-not $Record.ContainsKey($k)) { return $null }
    $v = @($Record[$k])
    if ($v.Count -eq 0) { return $null }
    return , $v[0]
}

function Get-MspkiLdapValues {
    <#
    .SYNOPSIS
    All values of an attribute in a record from Get-MspkiLdapObject (empty array when absent).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Record,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $k = $Name.ToLowerInvariant()
    if (-not $Record.ContainsKey($k)) { return , @() }
    return , @($Record[$k])
}

function ConvertTo-MspkiLdapFilterValue {
    <#
    .SYNOPSIS
    Escapes a value for use inside an LDAP filter (RFC 4515).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Value)
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\' { [void]$sb.Append('\5c') }
            '*' { [void]$sb.Append('\2a') }
            '(' { [void]$sb.Append('\28') }
            ')' { [void]$sb.Append('\29') }
            ([char]0) { [void]$sb.Append('\00') }
            default { [void]$sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function ConvertFrom-MspkiDistinguishedName {
    <#
    .SYNOPSIS
    Converts DC=corp,DC=example,DC=test to corp.example.test.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$DistinguishedName)
    if (-not $DistinguishedName) { return '' }
    $parts = @($DistinguishedName -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^(?i)DC=' } |
        ForEach-Object { $_.Substring(3) })
    return ($parts -join '.').ToLowerInvariant()
}

function ConvertTo-MspkiIsoTime {
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    return [string]$Value
}
