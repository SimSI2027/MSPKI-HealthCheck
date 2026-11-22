# Shared probe cache for the run. Every network probe stores its result here by a normalised key, so a
# host or URL is probed at most once per run.

$script:MspkiProbeCache = @{}

function Reset-MspkiProbeCache {
    [CmdletBinding()]
    param()
    $script:MspkiProbeCache = @{}
}

function Get-MspkiProbeCacheEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Key)
    $k = $Key.ToLowerInvariant()
    if ($script:MspkiProbeCache.ContainsKey($k)) { return $script:MspkiProbeCache[$k] }
    return $null
}

function Set-MspkiProbeCacheEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)]$Value
    )
    $script:MspkiProbeCache[$Key.ToLowerInvariant()] = $Value
}

function Get-MspkiProbeCacheCount {
    [CmdletBinding()]
    param()
    return $script:MspkiProbeCache.Count
}

function Get-MspkiProbeCacheEntryList {
    <#
    .SYNOPSIS
    Every cached probe result whose key starts with Prefix (for example 'tls|'), for analysers that summarise what was already probed.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Prefix)
    $p = $Prefix.ToLowerInvariant()
    return @($script:MspkiProbeCache.Keys | Where-Object { $_.StartsWith($p) } | Sort-Object | ForEach-Object { $script:MspkiProbeCache[$_] })
}
