# Small per-run state of the window: which read-only checks the user has marked as checked. It is kept in gui-state.json next to the run's
# results.json, and only when that run folder is inside the output folder (out\). A results file anywhere else keeps the marks in memory
# for as long as the window is open. This file is the only place of the window that writes such a file; every write goes through
# Test-MspkiGuiPathInside (tests\GuiState.Tests.ps1, tests\Hygiene.Tests.ps1).

$script:MspkiGuiStateFileName = 'gui-state.json'

function Test-MspkiGuiPathInside {
    <#
    .SYNOPSIS
    True when Path is strictly inside Root (both made absolute first, so ".." cannot climb out).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Root)
    $p = [System.IO.Path]::GetFullPath($Path).TrimEnd('\') + '\'
    $r = [System.IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    return ($p.Length -gt $r.Length -and $p.StartsWith($r, [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-MspkiGuiStatePath {
    <#
    .SYNOPSIS
    Where the marks of a results file are kept: gui-state.json in the folder of results.json, or '' when that folder is not inside the output folder.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$ResultsPath, [Parameter(Mandatory = $true)][string]$AllowedRoot)
    if (-not $ResultsPath) { return '' }
    $folder = Split-Path -Parent ([System.IO.Path]::GetFullPath($ResultsPath))
    if (-not (Test-MspkiGuiPathInside -Path $folder -Root $AllowedRoot)) { return '' }
    return (Join-Path $folder $script:MspkiGuiStateFileName)
}

function New-MspkiGuiCheckState {
    <#
    .SYNOPSIS
    The marks of one run, read from its gui-state.json when there is one. Note says where they are kept, in words.
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$ResultsPath = '', [Parameter(Mandatory = $true)][string]$AllowedRoot)
    $path = Get-MspkiGuiStatePath -ResultsPath $ResultsPath -AllowedRoot $AllowedRoot
    $st = [pscustomobject]@{ Path = $path; Checked = @{}; Note = ''; SaveError = '' }
    if ($path) {
        $st.Note = 'Your checked marks are kept with this run (gui-state.json in its folder).'
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            try {
                $j = ConvertFrom-MspkiJson -Text ([System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8))
                if ($null -ne $j -and $null -ne $j.Checked) {
                    foreach ($pr in @($j.Checked.PSObject.Properties)) { $st.Checked[[string]$pr.Name] = @(@($pr.Value) | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
                }
            }
            catch { $st.SaveError = 'The saved marks could not be read; they start empty.' }
        }
    }
    else { $st.Note = 'Checked marks last until the window closes: this results file is outside the output folder, so nothing is saved next to it.' }
    return $st
}

function Get-MspkiGuiCheckedKey {
    <#
    .SYNOPSIS
    The keys ("<cause>:<check>") of the checks marked as done for a finding.
    #>
    [CmdletBinding()]
    param([AllowNull()]$State, [Parameter(Mandatory = $true)][string]$FindingId)
    if ($null -eq $State -or -not $State.Checked.ContainsKey($FindingId)) { return @() }
    return @($State.Checked[$FindingId])
}

function Save-MspkiGuiCheckState {
    <#
    .SYNOPSIS
    Writes the marks next to the run's results.json (gui-state.json). Refuses any path that is not inside -AllowedRoot; returns whether
    it was written. A write failure is kept in SaveError and never stops the window.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$AllowedRoot)
    if (-not $State.Path) { return $false }
    if (-not (Test-MspkiGuiPathInside -Path $State.Path -Root $AllowedRoot)) { return $false }
    try {
        $o = [ordered]@{}
        foreach ($k in @($State.Checked.Keys | Sort-Object)) { if (@($State.Checked[$k]).Count -gt 0) { $o[$k] = @($State.Checked[$k] | Sort-Object) } }
        $doc = [ordered]@{ Format = 1; Checked = $o }
        [System.IO.File]::WriteAllText($State.Path, ($doc | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
        $State.SaveError = ''
        return $true
    }
    catch { $State.SaveError = $_.Exception.Message; return $false }
}

function Switch-MspkiGuiCheckedKey {
    <#
    .SYNOPSIS
    Marks a check as done, or takes the mark back, and saves the marks when they are kept on disk. Returns the new state of the mark.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$State, [Parameter(Mandatory = $true)][string]$FindingId, [Parameter(Mandatory = $true)][string]$Key, [Parameter(Mandatory = $true)][string]$AllowedRoot)
    $cur = @(Get-MspkiGuiCheckedKey -State $State -FindingId $FindingId)
    $on = ($cur -notcontains $Key)
    if ($on) { $State.Checked[$FindingId] = @($cur + $Key) }
    else { $State.Checked[$FindingId] = @($cur | Where-Object { $_ -ne $Key }) }
    [void](Save-MspkiGuiCheckState -State $State -AllowedRoot $AllowedRoot)
    return $on
}
