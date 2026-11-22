# Reads JSON written by this tool (results.json) without the ~2 MB limit of Windows PowerShell 5.1's ConvertFrom-Json.
# Uses the in-box System.Web.Extensions JavaScriptSerializer (.NET Framework 4.x) with MaxJsonLength = [int]::MaxValue and turns
# its dictionaries into PSCustomObjects, so callers see the same shape ConvertFrom-Json gives. Data only: nothing is run or loaded.

function ConvertTo-MspkiJsonObject {
    # Dictionary -> PSCustomObject (key order kept). Arrays are converted in place and stored as the same object[] (never returned
    # through the pipeline: a pipeline-wrapped array would serialise as { value, Count } in Windows PowerShell 5.1).
    param([System.Collections.Generic.IDictionary[string, object]]$Node)
    $h = [ordered]@{}
    foreach ($k in $Node.Keys) {
        $v = $Node[$k]
        if ($v -is [System.Collections.Generic.IDictionary[string, object]]) { $h[$k] = ConvertTo-MspkiJsonObject $v }
        elseif ($v -is [object[]]) { Convert-MspkiJsonArray $v; $h[$k] = $v }
        else { $h[$k] = $v }
    }
    return [pscustomobject]$h
}

function Convert-MspkiJsonArray {
    # Replaces every dictionary in the array (and in nested arrays) with a PSCustomObject, in place. Returns nothing.
    param([object[]]$Node)
    for ($i = 0; $i -lt $Node.Length; $i++) {
        $v = $Node[$i]
        if ($v -is [System.Collections.Generic.IDictionary[string, object]]) { $Node[$i] = ConvertTo-MspkiJsonObject $v }
        elseif ($v -is [object[]]) { Convert-MspkiJsonArray $v }
    }
}

function ConvertFrom-MspkiJson {
    <#
    .SYNOPSIS
    Parses JSON text of any size (up to the .NET string limit) into PSCustomObjects, like ConvertFrom-Json but without its ~2 MB limit.
    .DESCRIPTION
    Windows PowerShell 5.1's ConvertFrom-Json refuses JSON above about 2 MB. This uses the in-box JavaScriptSerializer
    (System.Web.Extensions) with MaxJsonLength = [int]::MaxValue. Objects become PSCustomObjects (property order kept), arrays become
    object[]. Throws on invalid JSON.
    .EXAMPLE
    ConvertFrom-MspkiJson -Text ([System.IO.File]::ReadAllText('.\out\run\results.json'))
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    Add-Type -AssemblyName System.Web.Extensions
    $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $serializer.MaxJsonLength = [int]::MaxValue
    $serializer.RecursionLimit = 256
    $raw = $serializer.DeserializeObject($Text)
    if ($raw -is [System.Collections.Generic.IDictionary[string, object]]) { return (ConvertTo-MspkiJsonObject $raw) }
    if ($raw -is [object[]]) { Convert-MspkiJsonArray $raw; return , $raw }
    return $raw
}

function Read-MspkiResultsJson {
    <#
    .SYNOPSIS
    Reads a results.json file (UTF-8) of any size into PSCustomObjects. Does not check the schema; use ConvertFrom-MspkiResultsDocument for that.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $text = [System.IO.File]::ReadAllText($full, [System.Text.Encoding]::UTF8)
    return (ConvertFrom-MspkiJson -Text $text)
}
