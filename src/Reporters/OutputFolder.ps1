# The only place in the tool that writes to disk. Every write goes through Write-MspkiOutputFile,
# which refuses any path outside the current run output folder (hard rule 1: read-only).

$script:MspkiOutputFolder = ''

function New-MspkiOutputFolder {
    <#
    .SYNOPSIS
    Creates <Root>\<yyyyMMdd-HHmmss> (with a numeric suffix if it already exists) and makes it the
    only folder the tool may write to.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [DateTime]$Now = (Get-Date)
    )
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $name = $Now.ToString('yyyyMMdd-HHmmss')
    $path = Join-Path $rootFull $name
    $i = 1
    while (Test-Path -LiteralPath $path) {
        $i++
        $path = Join-Path $rootFull ('{0}-{1}' -f $name, $i)
    }
    [void][System.IO.Directory]::CreateDirectory($path)
    $script:MspkiOutputFolder = $path
    return $path
}

function Set-MspkiOutputFolder {
    <#
    .SYNOPSIS
    Sets the folder writes are allowed in (used by tests). The folder must already exist.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not [System.IO.Directory]::Exists($full)) { throw ('Output folder does not exist: {0}' -f $full) }
    $script:MspkiOutputFolder = $full
}

function Get-MspkiOutputFolder {
    [CmdletBinding()]
    param()
    return $script:MspkiOutputFolder
}

function Assert-MspkiOutputPath {
    <#
    .SYNOPSIS
    Throws unless Path is a file inside the current run output folder.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not $script:MspkiOutputFolder) { throw 'No output folder is set; refusing to write.' }
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = $script:MspkiOutputFolder.TrimEnd('\') + '\'
    if (-not $full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ('Refusing to write outside the run output folder: {0}' -f $full)
    }
    return $full
}

function Write-MspkiOutputFile {
    <#
    .SYNOPSIS
    Writes (or appends) UTF-8 text without BOM to a file inside the run output folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content,
        [switch]$Append
    )
    $full = Assert-MspkiOutputPath -Path $Path
    $enc = New-Object System.Text.UTF8Encoding($false)
    if ($Append) { [System.IO.File]::AppendAllText($full, $Content, $enc) }
    else { [System.IO.File]::WriteAllText($full, $Content, $enc) }
    return
}
