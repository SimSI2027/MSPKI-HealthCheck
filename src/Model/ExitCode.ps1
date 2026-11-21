# Exit codes (REQUIREMENTS section 2):
#   0 passed or not applicable, 2 informational, 3 warnings, 4 failures or critical,
#   5 incomplete because something is unsupported (or a check errored, or the run was interrupted),
#   6 incomplete because of permissions.
# Precedence: 4 > 6 > 5 > 3 > 2 > 0. Information findings with StatusCode OK are plain inventory facts
# and do not raise the exit code.

$script:MspkiExitCodeTable = @{
    0 = @{ Name = 'Passed'; Meaning = 'Every check passed or was not applicable.' }
    2 = @{ Name = 'Informational'; Meaning = 'No warnings or failures, but some findings need a look (information that is not a plain inventory fact).' }
    3 = @{ Name = 'Warnings'; Meaning = 'At least one warning and no failures.' }
    4 = @{ Name = 'Failures'; Meaning = 'At least one failure or critical finding.' }
    5 = @{ Name = 'Incomplete (unsupported or error)'; Meaning = 'A check is unsupported on this computer, errored, or the run was interrupted, so the result is incomplete.' }
    6 = @{ Name = 'Incomplete (permissions)'; Meaning = 'A check was skipped because the account running the tool lacks permission, so the result is incomplete.' }
}

function Get-MspkiExitCode {
    <#
    .SYNOPSIS
    Computes the process exit code from a set of findings.

    .PARAMETER Incomplete
    The run did not finish (for example Ctrl+C). The result is at least 5, unless a failure (4) or a
    permission problem (6) already decides the code.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @(), [switch]$Incomplete)
    $all = @($Findings | Where-Object { $null -ne $_ })
    if (@($all | Where-Object { $_.Status -eq 'Fail' -or $_.Status -eq 'Critical' }).Count -gt 0) { return 4 }
    if (@($all | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' }).Count -gt 0) { return 6 }
    if ($Incomplete) { return 5 }
    if (@($all | Where-Object { $_.StatusCode -eq 'UNSUPPORTED' -or $_.Status -eq 'Error' }).Count -gt 0) { return 5 }
    if (@($all | Where-Object { $_.Status -eq 'Warning' }).Count -gt 0) { return 3 }
    if (@($all | Where-Object { $_.Status -eq 'Information' -and $_.StatusCode -ne 'OK' }).Count -gt 0) { return 2 }
    return 0
}

function Get-MspkiExitCodeInfo {
    <#
    .SYNOPSIS
    Explains an exit code: name, meaning and the findings that decide it.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Code, [AllowEmptyCollection()][object[]]$Findings = @(), [bool]$Completed = $true)
    $all = @($Findings | Where-Object { $null -ne $_ })
    $t = $script:MspkiExitCodeTable[$Code]
    if ($null -eq $t) { $t = @{ Name = 'Unknown'; Meaning = 'Not a defined exit code.' } }
    $drivers = @()
    switch ($Code) {
        4 { $drivers = @($all | Where-Object { $_.Status -eq 'Fail' -or $_.Status -eq 'Critical' }) }
        6 { $drivers = @($all | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' }) }
        5 { $drivers = @($all | Where-Object { $_.StatusCode -eq 'UNSUPPORTED' -or $_.Status -eq 'Error' }) }
        3 { $drivers = @($all | Where-Object { $_.Status -eq 'Warning' }) }
        2 { $drivers = @($all | Where-Object { $_.Status -eq 'Information' -and $_.StatusCode -ne 'OK' }) }
    }
    $note = ''
    if (-not $Completed) { $note = 'The run did not finish; the exit code is at least 5.' }
    return [pscustomobject][ordered]@{
        Code = $Code; Name = $t.Name; Meaning = $t.Meaning; Note = $note
        DriverCount = $drivers.Count; DriverIds = [string[]]@($drivers | Select-Object -First 25 | ForEach-Object { $_.Id })
    }
}
