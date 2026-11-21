# findings.csv: one row per finding, readable in Excel. UTF-8 with BOM, CRLF, every field quoted.
# Text that starts with = + - @ (or a control character) is prefixed with an apostrophe so that Excel never
# treats data from the environment (names, URLs) as a formula.

$script:MspkiCsvColumns = @('Id', 'Timestamp', 'Stage', 'Category', 'Role', 'Status', 'StatusCode', 'Severity', 'Confidence',
    'Scope', 'Target', 'Endpoint', 'RelatedCA', 'Sources', 'DiscoveryStatus', 'DnsStatus', 'TcpStatus', 'HttpStatus',
    'RedirectStatus', 'TlsStatus', 'ContentStatus', 'ChainStatus', 'Forest', 'Domain', 'Message', 'Evidence',
    'Remediation', 'Notes')

function ConvertTo-MspkiCsvField {
    <#
    .SYNOPSIS
    Quotes one CSV field: line breaks become spaces, formula starters are neutralised, quotes are doubled.
    #>
    [CmdletBinding()]
    param([AllowNull()]$Value)
    $s = ''
    if ($null -ne $Value) {
        if ($Value -is [System.Array] -or $Value -is [System.Collections.IList]) { $s = (@($Value) | ForEach-Object { [string]$_ }) -join ' | ' }
        else { $s = [string]$Value }
    }
    $s = $s -replace '[\r\n]+', ' '
    $s = $s -replace '[\x00-\x08\x0B\x0C\x0E-\x1F]', ''
    if ($s -match '^[=+\-@\t]') { $s = "'" + $s }
    return '"' + ($s -replace '"', '""') + '"'
}

function ConvertTo-MspkiCsvText {
    <#
    .SYNOPSIS
    Builds the CSV text for a list of findings (also usable on findings loaded from results.json).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append((($script:MspkiCsvColumns | ForEach-Object { ConvertTo-MspkiCsvField $_ }) -join ',')).Append("`r`n")
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $cells = foreach ($c in $script:MspkiCsvColumns) { ConvertTo-MspkiCsvField $f.$c }
        [void]$sb.Append(($cells -join ',')).Append("`r`n")
    }
    return $sb.ToString()
}

function Export-MspkiCsv {
    <#
    .SYNOPSIS
    Writes findings.csv (UTF-8 with BOM) inside the run output folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowEmptyCollection()][object[]]$Findings = @()
    )
    Write-MspkiOutputFile -Path $Path -Content (ConvertTo-MspkiCsvText -Findings $Findings) -Bom
    return $Path
}
