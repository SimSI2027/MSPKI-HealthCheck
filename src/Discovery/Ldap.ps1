# Read-only LDAP access through System.DirectoryServices. Targeted base / one-level searches with
# explicit attribute lists and time limits. Results are plain hashtables (lower-case attribute name ->
# array of values) so that the rest of the tool never holds live directory objects.

function Get-MspkiLdapConnectionSpec {
    <#
    .SYNOPSIS
    The DirectoryEntry path and authentication types for one read: LDAP://host[:port]/DN, with secure sockets layer when -Ssl is given
    (an ldaps:// location is read over LDAPS, audit 2 L7). AuthenticationTypes is '' for a plain read: the caller then uses the default
    DirectoryEntry constructor. Passing an explicit authentication type, even Secure with no credentials, makes a serverless bind fail with
    "an operations error occurred" (0x80072020) on a domain-joined computer, which a lab run showed; only LDAPS needs the explicit form.
    #>
    [CmdletBinding()]
    param([string]$Server = '', [Parameter(Mandatory = $true)][string]$BaseDN, [switch]$Ssl, [int]$Port = 0)
    $hostPart = $Server
    if ($Server -and $Port -gt 0) { $hostPart = '{0}:{1}' -f $Server, $Port }
    if ($hostPart) { $path = 'LDAP://{0}/{1}' -f $hostPart, $BaseDN } else { $path = 'LDAP://{0}' -f $BaseDN }
    $auth = ''
    if ($Ssl) { $auth = 'Secure, SecureSocketsLayer' }
    return [pscustomobject]@{ Path = $path; AuthenticationTypes = $auth }
}

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
        [ValidateSet('Base', 'OneLevel', 'Subtree')][string]$Scope = 'OneLevel',
        [string[]]$Properties = @('distinguishedName'),
        [ValidateRange(1, 600)][int]$TimeoutSeconds = 30,
        [switch]$IncludeDacl,
        # LDAPS (an ldaps:// location) and an explicit port; the default is plain LDAP on the default port.
        [switch]$Ssl,
        [int]$Port = 0
    )
    $spec = Get-MspkiLdapConnectionSpec -Server $Server -BaseDN $BaseDN -Ssl:$Ssl -Port $Port
    if ($spec.AuthenticationTypes) { $entry = New-Object System.DirectoryServices.DirectoryEntry($spec.Path, $null, $null, [System.DirectoryServices.AuthenticationTypes]$spec.AuthenticationTypes) }
    else { $entry = New-Object System.DirectoryServices.DirectoryEntry($spec.Path) }
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $results = $null
    try {
        $searcher.Filter = $Filter
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]$Scope
        if ($Scope -ne 'Base') { $searcher.PageSize = 500 }
        $searcher.ClientTimeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($TimeoutSeconds)
        if ($IncludeDacl) { $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Owner, Dacl' }
        # Never chase a referral (audit 2 verification N6). The .NET default (External) lets the directory client follow a referral to
        # another server with the same Windows credentials, outside the host check of this tool. With None a referral comes back as
        # an error (0x8007202B), which the caller reports as evidence (Test-MspkiLdapReferralError).
        $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::None
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
        # After a failed bind (a referral, for example) Dispose can throw the bind error again, which would hide the first error.
        if ($null -ne $results) { try { $results.Dispose() } catch { } }
        try { $searcher.Dispose() } catch { }
        try { $entry.Dispose() } catch { }
    }
}

function Test-MspkiLdapReferralError {
    <#
    .SYNOPSIS
    True when an error is an LDAP referral (0x8007202B, "a referral was returned from the server"): the server named another server for
    the object. Referrals are never chased (Get-MspkiLdapObject sets ReferralChasing = None), so the referral is reported, not followed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$InputError)
    $e = $InputError
    if ($e -is [System.Management.Automation.ErrorRecord]) { $e = $e.Exception }
    while ($null -ne $e) {
        if ($e.HResult -eq -2147016661) { return $true }
        $e = $e.InnerException
    }
    return $false
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
