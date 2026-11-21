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
