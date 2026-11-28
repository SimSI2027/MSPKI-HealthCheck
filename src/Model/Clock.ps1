# The run's clock: every "now" and every elapsed time the engine records comes from these two functions, so a run is reproducible
# when they are replaced (the demo site's simulated environment fixes the clock; docs/DEMO-SITE.md). In a normal run they are the
# system clock and a real stopwatch. Calls that wait for a real deadline (probe timeouts) keep using the system clock directly.

function Get-MspkiUtcNow {
    <#
    .SYNOPSIS
    The current time in UTC, as the engine sees it.
    #>
    [CmdletBinding()]
    [OutputType([DateTime])]
    param()
    return [DateTime]::UtcNow
}

function New-MspkiStopwatch {
    <#
    .SYNOPSIS
    A started stopwatch for an elapsed time the engine records (ElapsedMilliseconds is the only member the engine reads).
    #>
    [CmdletBinding()]
    param()
    return [System.Diagnostics.Stopwatch]::StartNew()
}
