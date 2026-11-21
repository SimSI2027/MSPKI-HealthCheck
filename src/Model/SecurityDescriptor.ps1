# Reads a binary security descriptor (as stored on AD objects) into plain data, and resolves SIDs to names
# once per run. Parsing is in memory only (RawSecurityDescriptor); nothing is ever written back to AD.

$script:MspkiEnrollRightGuid     = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:MspkiAutoEnrollRightGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

# Access mask bits of AD objects (ADS_RIGHTS_ENUM and the standard rights).
$script:MspkiAdRightBit = [ordered]@{
    GenericAll    = 0x10000000
    GenericWrite  = 0x40000000
    WriteOwner    = 0x00080000
    WriteDacl     = 0x00040000
    ExtendedRight = 0x00000100
    WriteProperty = 0x00000020
    Self          = 0x00000008
    CreateChild   = 0x00000001
    DeleteChild   = 0x00000002
}

# SIDs that need no lookup. Domain-relative groups are named by their RID.
$script:MspkiWellKnownSid = @{
    'S-1-1-0'      = 'Everyone'
    'S-1-3-0'      = 'CREATOR OWNER'
    'S-1-5-9'      = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'
    'S-1-5-10'     = 'NT AUTHORITY\SELF'
    'S-1-5-11'     = 'NT AUTHORITY\Authenticated Users'
    'S-1-5-18'     = 'NT AUTHORITY\SYSTEM'
    'S-1-5-32-544' = 'BUILTIN\Administrators'
    'S-1-5-32-545' = 'BUILTIN\Users'
}
$script:MspkiDomainRidName = @{
    498 = 'Enterprise Read-only Domain Controllers'; 500 = 'Administrator'; 502 = 'krbtgt'; 512 = 'Domain Admins'
    513 = 'Domain Users'; 514 = 'Domain Guests'; 515 = 'Domain Computers'; 516 = 'Domain Controllers'
    517 = 'Cert Publishers'; 518 = 'Schema Admins'; 519 = 'Enterprise Admins'; 520 = 'Group Policy Creator Owners'
    526 = 'Key Admins'; 527 = 'Enterprise Key Admins'
}

$script:MspkiSidCache = @{}
$script:MspkiSidStats = @{ Lookups = 0; Failures = 0; Budget = 8; BudgetLogged = $false }

function Reset-MspkiSidCache {
    <#
    .SYNOPSIS
    Empties the SID-to-name cache (one cache per run).
    #>
    [CmdletBinding()]
    param([int]$FailureBudget = 8)
    $script:MspkiSidCache = @{}
    $script:MspkiSidStats = @{ Lookups = 0; Failures = 0; Budget = $FailureBudget; BudgetLogged = $false }
}

function Get-MspkiSidStatistic {
    [CmdletBinding()]
    param()
    return [pscustomobject]@{ Cached = $script:MspkiSidCache.Count; Lookups = $script:MspkiSidStats.Lookups; Failures = $script:MspkiSidStats.Failures }
}

function ConvertTo-MspkiUInt32 {
    <#
    .SYNOPSIS
    Reads an AD integer attribute as an unsigned 32-bit value (AD stores flag attributes as signed Int32).
    Returns 0 for $null or an unparseable value.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return [int64]0 }
    $n = 0L
    if (-not [int64]::TryParse(([string]$Value), [ref]$n)) { return [int64]0 }
    if ($n -lt 0) { $n += 4294967296 }
    return [int64]($n -band 0xFFFFFFFFL)
}

function Get-MspkiSidFallbackName {
    [CmdletBinding()]
    param([string]$Sid)
    if ($script:MspkiWellKnownSid.ContainsKey($Sid)) { return $script:MspkiWellKnownSid[$Sid] }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(\d+)$') {
        $rid = [int]$Matches[1]
        if ($script:MspkiDomainRidName.ContainsKey($rid)) { return ('{0} (domain {1})' -f $script:MspkiDomainRidName[$rid], ($Sid -replace '-\d+$', '')) }
    }
    return $Sid
}

function Resolve-MspkiSid {
    <#
    .SYNOPSIS
    Translates a SID to an account name. Each SID is looked up at most once per run (cached, also when the
    lookup fails). After a few failed lookups no further lookups are tried; the SID is then described by
    its well-known name or RID, or shown as the SID itself.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Sid)
    if ($script:MspkiSidCache.ContainsKey($Sid)) { return $script:MspkiSidCache[$Sid] }
    $name = ''
    if ($script:MspkiWellKnownSid.ContainsKey($Sid)) { $name = $script:MspkiWellKnownSid[$Sid] }
    elseif ($script:MspkiSidStats.Failures -lt $script:MspkiSidStats.Budget) {
        $script:MspkiSidStats.Lookups++
        try {
            $obj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $name = [string]$obj.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            $script:MspkiSidStats.Failures++
            $name = ''
        }
    }
    elseif (-not $script:MspkiSidStats.BudgetLogged) {
        $script:MspkiSidStats.BudgetLogged = $true
        Write-MspkiLog -Level Warning -Message ('SID lookups stopped after {0} failures; remaining SIDs are shown by well-known name, RID or SID.' -f $script:MspkiSidStats.Budget)
        Add-MspkiRunLimit -Text 'SID-to-name lookups failed repeatedly, so some principals in template permissions are shown as SIDs. Broad-group checks use SID patterns and are not affected.'
    }
    if (-not $name) { $name = Get-MspkiSidFallbackName -Sid $Sid }
    $script:MspkiSidCache[$Sid] = $name
    return $name
}

function Get-MspkiBroadPrincipal {
    <#
    .SYNOPSIS
    Returns the broad-group label for a SID, or '' when the SID is not a broad group.

    .DESCRIPTION
    Broad groups (REQUIREMENTS 5.5): Everyone, Authenticated Users, Domain Users and Domain Computers. The
    last two are recognised by their RID (513, 515) under any domain SID, so the Domain Users and Domain
    Computers groups of every domain in the forest (and of trusted domains) count. Decided by SID, never by name.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Sid)
    if ($Sid -eq 'S-1-1-0') { return 'Everyone' }
    if ($Sid -eq 'S-1-5-11') { return 'Authenticated Users' }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-513$') { return 'Domain Users' }
    if ($Sid -match '^S-1-5-21-\d+-\d+-\d+-515$') { return 'Domain Computers' }
    return ''
}

function Get-MspkiAceRightName {
    <#
    .SYNOPSIS
    Names the rights of one ACE that matter for template review.
    #>
    [CmdletBinding()]
    param([int64]$Mask, [AllowEmptyString()][string]$ObjectType = '')
    $names = New-Object System.Collections.ArrayList
    if (($Mask -band $script:MspkiAdRightBit.GenericAll) -ne 0 -or ($Mask -band 0xF01FF) -eq 0xF01FF) { [void]$names.Add('FullControl') }
    else {
        if (($Mask -band $script:MspkiAdRightBit.GenericWrite) -ne 0) { [void]$names.Add('GenericWrite') }
        if (($Mask -band $script:MspkiAdRightBit.WriteOwner) -ne 0) { [void]$names.Add('WriteOwner') }
        if (($Mask -band $script:MspkiAdRightBit.WriteDacl) -ne 0) { [void]$names.Add('WriteDacl') }
        if (($Mask -band $script:MspkiAdRightBit.WriteProperty) -ne 0) {
            if ($ObjectType) { [void]$names.Add(('WriteProperty({0})' -f $ObjectType)) } else { [void]$names.Add('WriteProperty') }
        }
        if (($Mask -band $script:MspkiAdRightBit.ExtendedRight) -ne 0) {
            if ($ObjectType -eq $script:MspkiEnrollRightGuid) { [void]$names.Add('Enroll') }
            elseif ($ObjectType -eq $script:MspkiAutoEnrollRightGuid) { [void]$names.Add('AutoEnroll') }
            elseif ($ObjectType) { [void]$names.Add(('ExtendedRight({0})' -f $ObjectType)) }
            else { [void]$names.Add('AllExtendedRights') }
        }
    }
    return , $names.ToArray()
}

function ConvertFrom-MspkiSecurityDescriptor {
    <#
    .SYNOPSIS
    Parses a binary security descriptor into { OwnerSid, Aces }. Each ACE: Sid, Type (Allow or Deny), Mask,
    ObjectType (GUID text or ''), InheritOnly, Inherited, Rights (names). Parsed in memory; nothing is written.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new($Bytes, 0)
    $owner = ''
    if ($null -ne $sd.Owner) { $owner = $sd.Owner.Value }
    $aces = New-Object System.Collections.ArrayList
    if ($null -ne $sd.DiscretionaryAcl) {
        foreach ($ace in $sd.DiscretionaryAcl) {
            $t = [string]$ace.AceType
            $type = ''
            if ($t -match 'Allowed') { $type = 'Allow' } elseif ($t -match 'Denied') { $type = 'Deny' } else { continue }
            $mask = [int64]$ace.AccessMask
            if ($mask -lt 0) { $mask += 4294967296 }
            $objType = ''
            if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                if (([int]$ace.ObjectAceFlags -band [int][System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) -ne 0) {
                    $objType = $ace.ObjectAceType.ToString()
                }
            }
            $flags = $ace.AceFlags
            [void]$aces.Add([pscustomobject][ordered]@{
                Sid         = $ace.SecurityIdentifier.Value
                Principal   = ''
                Type        = $type
                Mask        = $mask
                ObjectType  = $objType
                InheritOnly = (([int]$flags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0)
                Inherited   = (([int]$flags -band [int][System.Security.AccessControl.AceFlags]::Inherited) -ne 0)
                Rights      = [string[]](Get-MspkiAceRightName -Mask $mask -ObjectType $objType)
            })
        }
    }
    return [pscustomobject][ordered]@{ OwnerSid = $owner; Aces = @($aces) }
}
