# The language mode of this PowerShell session (audit 2 M13). On a computer where AppLocker or Windows Defender Application Control restricts
# unsigned scripts, PowerShell runs them in Constrained Language Mode. There COM objects, System.DirectoryServices, sockets, runspaces and
# WPF are blocked, so the tool would fail part-way with generic errors. It is better to say so at the start and stop.

function Get-MspkiLanguageModeStatus {
    <#
    .SYNOPSIS
    Is this session in Full Language mode? Returns { Mode; IsFull; Message } (Message is the plain explanation shown when it is not).
    .PARAMETER Mode
    A language mode name instead of the real one of this session (for tests).
    #>
    [CmdletBinding()]
    param([string]$Mode = '')
    if (-not $Mode) { $Mode = [string]$ExecutionContext.SessionState.LanguageMode }
    $full = ($Mode -eq 'FullLanguage')
    $text = ''
    if (-not $full) {
        $text = ('MSPKI Health Check cannot run in this PowerShell session: it is in {0} mode instead of FullLanguage. The usual cause is Constrained Language Mode, which Windows applies to unsigned scripts when AppLocker or Windows Defender Application Control (WDAC) restricts them. ' -f $Mode) +
            'The tool needs Full Language mode because it uses COM objects, System.DirectoryServices, network sockets and, for the window, WPF, which Constrained Language Mode blocks. ' +
            'Ask the administrator who manages the application control policy to allow or sign these scripts, or run them on a computer where they are allowed. Nothing was changed on this computer.'
    }
    return [pscustomobject][ordered]@{ Mode = $Mode; IsFull = $full; Message = $text }
}
