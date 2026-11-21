# Exit codes (REQUIREMENTS section 2):
#   0 passed or not applicable, 2 informational, 3 warnings, 4 failures or critical,
#   5 incomplete because something is unsupported (or a check errored), 6 incomplete because of permissions.
# Precedence: 4 > 6 > 5 > 3 > 2 > 0. Information findings with StatusCode OK are plain inventory facts
# and do not raise the exit code.

function Get-MspkiExitCode {
    <#
    .SYNOPSIS
    Computes the process exit code from a set of findings.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $all = @($Findings | Where-Object { $null -ne $_ })
    if (@($all | Where-Object { $_.Status -eq 'Fail' -or $_.Status -eq 'Critical' }).Count -gt 0) { return 4 }
    if (@($all | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' }).Count -gt 0) { return 6 }
    if (@($all | Where-Object { $_.StatusCode -eq 'UNSUPPORTED' -or $_.Status -eq 'Error' }).Count -gt 0) { return 5 }
    if (@($all | Where-Object { $_.Status -eq 'Warning' }).Count -gt 0) { return 3 }
    if (@($all | Where-Object { $_.Status -eq 'Information' -and $_.StatusCode -ne 'OK' }).Count -gt 0) { return 2 }
    return 0
}
