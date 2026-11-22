# Run log. Lines are kept in memory until the output folder exists, then written to run.log.
# Never log secrets: only names, URLs, outcomes and timings.

$script:MspkiLogLines = New-Object System.Collections.ArrayList
$script:MspkiLogPath = ''

function Reset-MspkiLog {
    [CmdletBinding()]
    param()
    $script:MspkiLogLines = New-Object System.Collections.ArrayList
    $script:MspkiLogPath = ''
}

function Write-MspkiLog {
    <#
    .SYNOPSIS
    Adds one line to the run log (and to the verbose stream).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')][string]$Level = 'Info'
    )
    $line = '{0} [{1}] {2}' -f [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ'), $Level.ToUpperInvariant(), $Message
    [void]$script:MspkiLogLines.Add($line)
    Write-Verbose $line
    Send-MspkiProgress -Kind 'Log' -Text $line -Level $Level
    if ($script:MspkiLogPath) {
        try { Write-MspkiOutputFile -Path $script:MspkiLogPath -Content ($line + "`r`n") -Append }
        catch {
            # The log goes on in memory (and to the window), but the file stops: say so as a limit of this run instead of going quiet (audit 2 L14).
            $script:MspkiLogPath = ''
            Add-MspkiRunLimit -Text ('run.log could not be written and stopped at this point ({0}); the log of the rest of the run is only in memory and in the window.' -f (Get-MspkiErrorInfo $_).Message)
        }
    }
}

function Start-MspkiLogFile {
    <#
    .SYNOPSIS
    Starts writing the log to a file inside the run output folder, including the lines logged so far.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $text = ''
    if ($script:MspkiLogLines.Count -gt 0) { $text = (($script:MspkiLogLines -join "`r`n") + "`r`n") }
    Write-MspkiOutputFile -Path $Path -Content $text
    $script:MspkiLogPath = $Path
}

function Get-MspkiLogLine {
    [CmdletBinding()]
    param()
    return @($script:MspkiLogLines)
}
