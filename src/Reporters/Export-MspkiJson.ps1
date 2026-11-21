# results.json: run metadata, summary counts, the discovered inventory and every finding.

function Get-MspkiFindingSummary {
    <#
    .SYNOPSIS
    Counts findings by Status, Confidence and Category.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $byStatus = [ordered]@{}
    foreach ($s in $script:MspkiSchema.Status) { $byStatus[$s] = 0 }
    $byConfidence = [ordered]@{}
    foreach ($c in $script:MspkiSchema.Confidence) { $byConfidence[$c] = 0 }
    $byCategory = [ordered]@{}
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        $byStatus[$f.Status]++
        $byConfidence[$f.Confidence]++
        if (-not $byCategory.Contains($f.Category)) { $byCategory[$f.Category] = 0 }
        $byCategory[$f.Category]++
    }
    return [pscustomobject][ordered]@{
        Total        = @($Findings | Where-Object { $null -ne $_ }).Count
        ByStatus     = [pscustomobject]$byStatus
        ByConfidence = [pscustomobject]$byConfidence
        ByCategory   = [pscustomobject]$byCategory
    }
}

function Export-MspkiJson {
    <#
    .SYNOPSIS
    Writes results.json (UTF-8, no BOM) inside the run output folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$RunInfo,
        [AllowNull()]$Inventory = $null,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [int]$ExitCode = 0,
        [AllowNull()]$Graph = $null
    )
    $doc = [ordered]@{
        Schema        = $script:MspkiJsonSchema
        SchemaVersion = $script:MspkiGraphSchemaVersion
        RunInfo       = $RunInfo
        ExitCode      = $ExitCode
        Summary       = (Get-MspkiFindingSummary -Findings $Findings)
        Inventory     = $Inventory
        Graph         = $Graph
        Findings      = @($Findings)
    }
    $json = ConvertTo-Json -InputObject $doc -Depth 12
    Write-MspkiOutputFile -Path $Path -Content $json
    return $Path
}
