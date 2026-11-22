# Host name normalisation and scope (Local / OtherForest / External), REQUIREMENTS section 4.2.

function ConvertTo-MspkiHostName {
    <#
    .SYNOPSIS
    Normalises a host name: trims, lower-cases and removes a trailing dot. Returns '' for empty input.
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return '' }
    return $HostName.Trim().TrimEnd('.').ToLowerInvariant()
}

function Test-MspkiDnsSuffix {
    <#
    .SYNOPSIS
    True when HostName equals Suffix or ends with "." + Suffix (case-insensitive).
    #>
    [CmdletBinding()]
    param([string]$HostName, [string]$Suffix)
    $h = ConvertTo-MspkiHostName $HostName
    $s = ConvertTo-MspkiHostName $Suffix
    if (-not $h -or -not $s) { return $false }
    return ($h -eq $s -or $h.EndsWith('.' + $s))
}

function Get-MspkiHostScope {
    <#
    .SYNOPSIS
    Compares the DNS suffix of a host with the current forest's domains and trusted domains.

    .OUTPUTS
    'Local', 'OtherForest', 'External' or 'Unknown' (empty name, single-label name or IP address).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$HostName,
        [string[]]$LocalDomains = @(),
        [string[]]$TrustedDomains = @()
    )
    $h = ConvertTo-MspkiHostName $HostName
    if (-not $h) { return 'Unknown' }
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($h, [ref]$ip)) { return 'Unknown' }
    if ($h.IndexOf('.') -lt 0) { return 'Unknown' }
    foreach ($d in $LocalDomains) { if (Test-MspkiDnsSuffix -HostName $h -Suffix $d) { return 'Local' } }
    foreach ($d in $TrustedDomains) { if (Test-MspkiDnsSuffix -HostName $h -Suffix $d) { return 'OtherForest' } }
    return 'External'
}


function Resolve-MspkiScopeStatus {
    <#
    .SYNOPSIS
    Applies the scope rule of REQUIREMENTS 4.2: a reference to another environment (scope External or OtherForest)
    goes to review and is never graded as a failure. Fail and Critical become Warning with severity ReviewRequired
    and an Evidence line that says so; every other status, and every Local or Unknown scope, is returned unchanged.

    .OUTPUTS
    { Status; Severity ('None' or 'ReviewRequired'); Capped (bool); Evidence (text, empty when not capped) }
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Status, [AllowEmptyString()][string]$Scope = 'Unknown')
    $o = [pscustomobject]@{ Status = $Status; Severity = 'None'; Capped = $false; Evidence = '' }
    if (($Scope -eq 'External' -or $Scope -eq 'OtherForest') -and ($Status -eq 'Fail' -or $Status -eq 'Critical')) {
        $o.Status = 'Warning'; $o.Severity = 'ReviewRequired'; $o.Capped = $true
        $o.Evidence = ('Scope: {0}. The host is outside this forest''s own domains, so the result is capped at Warning and goes to review; a reference to another environment is not graded as a failure (REQUIREMENTS 4.2). The uncapped result would have been {1}.' -f $Scope, $Status)
    }
    return $o
}

function Test-MspkiLdapHostAllowed {
    <#
    .SYNOPSIS
    Decides whether an LDAP URL that names a host may be contacted. Pure function (no network access).

    .DESCRIPTION
    An LDAP bind sends the running user's Windows credentials to the server, so a host is contacted only when authoritative
    discovery proved it (audit 2 H1). A name in one of this forest's DNS zones is not proof on its own: in a default
    AD-integrated zone any authenticated user can create a record. Allowed are:
    - a serverless URL (the selected domain controller is used);
    - the selected domain controller;
    - a domain controller of the forest (-DomainControllers, server objects in the Configuration partition);
    - a host in one of this forest's own DNS domains named by an Authoritative or Verified lead (-Trust): an AD object, a CA
      property, or a downloaded object whose signature was verified with a discovered CA certificate.
    With -SkipNetwork only the serverless URL and the selected domain controller are allowed. Everything else is reported
    as "not contacted" with the reason.

    .OUTPUTS
    { Allowed (bool); Reason (text) }
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$HostName,
        [AllowEmptyString()][string]$DefaultServer = '',
        [string[]]$LocalDomains = @(),
        [AllowEmptyCollection()][string[]]$DomainControllers = @(),
        # Trust of the lead that carries the URL; '' (not known) counts as Unverified.
        [AllowEmptyString()][string]$Trust = '',
        [switch]$SkipNetwork
    )
    # A port in the URL (host:389) is not part of the name that is checked.
    $h = (ConvertTo-MspkiHostName $HostName) -replace ':\d+$', ''
    $dc = ConvertTo-MspkiHostName $DefaultServer
    if (-not $h) { return [pscustomobject]@{ Allowed = $true; Reason = 'serverless LDAP URL: the domain controller selected for this run is used' } }
    if ($dc -and $h -eq $dc) { return [pscustomobject]@{ Allowed = $true; Reason = 'the host is the domain controller selected for this run' } }
    if ($SkipNetwork) {
        return [pscustomobject]@{ Allowed = $false; Reason = 'the URL names a host other than the selected domain controller and -SkipNetwork was used' }
    }
    $dcs = @($DomainControllers | ForEach-Object { ConvertTo-MspkiHostName $_ } | Where-Object { $_ })
    if ($dcs -contains $h) { return [pscustomobject]@{ Allowed = $true; Reason = 'the host is a domain controller of this forest (server object in the Configuration partition)' } }
    $scope = Get-MspkiHostScope -HostName $h -LocalDomains $LocalDomains
    if ($scope -ne 'Local') {
        return [pscustomobject]@{ Allowed = $false; Reason = ('the URL names host {0}, which is not in one of this forest''s own DNS domains (scope {1}); a directory bind would send the Windows credentials of the user running this tool to it' -f $h, $scope) }
    }
    if ($Trust -eq 'Authoritative' -or $Trust -eq 'Verified') {
        return [pscustomobject]@{ Allowed = $true; Reason = ('the host is in one of this forest''s own DNS domains and the URL comes from {0} evidence' -f $Trust.ToLowerInvariant()) }
    }
    $t = $Trust
    if (-not $t) { $t = 'not known' }
    return [pscustomobject]@{ Allowed = $false; Reason = ('the URL names host {0}, which is not a domain controller of this forest, and the object that named it was not verified (trust: {1}); a name in the forest''s DNS zone is not proof, and a directory bind would send the Windows credentials of the user running this tool to it' -f $h, $t) }
}

function Set-MspkiScopeCap {
    <#
    .SYNOPSIS
    Applies Resolve-MspkiScopeStatus to a finished finding in place (its Scope field decides): a Fail or Critical result for a
    host outside this forest becomes a Warning with severity ReviewRequired, and the Evidence says so. Returns the finding.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding)
    $sc = Resolve-MspkiScopeStatus -Status $Finding.Status -Scope $Finding.Scope
    if ($sc.Capped) {
        $Finding.Status = $sc.Status
        $Finding.Severity = $sc.Severity
        $Finding.Evidence = [string[]](@($Finding.Evidence) + $sc.Evidence)
    }
    return $Finding
}
