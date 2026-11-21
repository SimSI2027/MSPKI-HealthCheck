# A small read-only DER (ASN.1) reader for certificate extensions and CRLs. Pure PowerShell, no
# external code. Every function validates lengths and throws on malformed input.

function Read-MspkiDerElement {
    <#
    .SYNOPSIS
    Reads the DER element header at Offset. Returns Tag, Constructed, Offset, ContentOffset, Length, End.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [int]$Offset = 0,
        [int]$Limit = -1
    )
    if ($Limit -lt 0) { $Limit = $Bytes.Length }
    if ($Offset + 2 -gt $Limit) { throw 'DER: truncated header.' }
    $tag = [int]$Bytes[$Offset]
    if (($tag -band 0x1F) -eq 0x1F) { throw 'DER: multi-byte tags are not supported.' }
    $first = [int]$Bytes[$Offset + 1]
    $pos = $Offset + 2
    if ($first -lt 0x80) { $len = $first }
    else {
        $n = $first -band 0x7F
        if ($n -lt 1 -or $n -gt 4) { throw 'DER: unsupported length encoding.' }
        if ($pos + $n -gt $Limit) { throw 'DER: truncated length.' }
        [int64]$len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = ($len * 256) + $Bytes[$pos + $i] }
        $pos += $n
    }
    if ($pos + $len -gt $Limit) { throw 'DER: element extends past the end of the data.' }
    return [pscustomobject]@{
        Tag           = $tag
        Constructed   = (($tag -band 0x20) -ne 0)
        Offset        = $Offset
        ContentOffset = $pos
        Length        = [int]$len
        End           = [int]($pos + $len)
    }
}

function Get-MspkiDerChild {
    <#
    .SYNOPSIS
    Lists the direct children of a constructed DER element.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$Element
    )
    $list = New-Object System.Collections.ArrayList
    $pos = $Element.ContentOffset
    while ($pos -lt $Element.End) {
        $c = Read-MspkiDerElement -Bytes $Bytes -Offset $pos -Limit $Element.End
        [void]$list.Add($c)
        $pos = $c.End
    }
    return , $list.ToArray()
}

function Get-MspkiDerBytes {
    <#
    .SYNOPSIS
    Copies the content (or, with -WithHeader, the whole encoding) of a DER element.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$Element,
        [switch]$WithHeader
    )
    $start = $Element.ContentOffset
    if ($WithHeader) { $start = $Element.Offset }
    $n = $Element.End - $start
    $out = New-Object byte[] $n
    if ($n -gt 0) { [Array]::Copy($Bytes, $start, $out, 0, $n) }
    return , $out
}

function ConvertFrom-MspkiDerOid {
    <#
    .SYNOPSIS
    Decodes the content bytes of an OBJECT IDENTIFIER to dotted notation.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Content)
    if ($Content.Length -lt 1) { throw 'DER: empty OID.' }
    $parts = New-Object System.Collections.ArrayList
    [int64]$v = 0
    $firstDone = $false
    foreach ($b in $Content) {
        $v = ($v * 128) + ($b -band 0x7F)
        if (($b -band 0x80) -eq 0) {
            if (-not $firstDone) {
                if ($v -lt 40) { [void]$parts.Add(0); [void]$parts.Add($v) }
                elseif ($v -lt 80) { [void]$parts.Add(1); [void]$parts.Add($v - 40) }
                else { [void]$parts.Add(2); [void]$parts.Add($v - 80) }
                $firstDone = $true
            }
            else { [void]$parts.Add($v) }
            $v = 0
        }
    }
    return ($parts -join '.')
}

function ConvertFrom-MspkiDerTime {
    <#
    .SYNOPSIS
    Decodes UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) to a UTC DateTime.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)]$Element
    )
    $s = [System.Text.Encoding]::ASCII.GetString((Get-MspkiDerBytes -Bytes $Bytes -Element $Element))
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ($Element.Tag -eq 0x17) {
        $fmt = @("yyMMddHHmmss'Z'", "yyMMddHHmm'Z'")
        $dt = [DateTime]::ParseExact($s, [string[]]$fmt, $inv, $styles)
        # RFC 5280: YY >= 50 means 19YY, otherwise 20YY.
        $yy = [int]$s.Substring(0, 2)
        $year = 2000 + $yy
        if ($yy -ge 50) { $year = 1900 + $yy }
        return $dt.AddYears($year - $dt.Year)
    }
    if ($Element.Tag -eq 0x18) {
        $fmt = @("yyyyMMddHHmmss'Z'", "yyyyMMddHHmmss.f'Z'", "yyyyMMddHHmmss.ff'Z'", "yyyyMMddHHmmss.fff'Z'")
        return [DateTime]::ParseExact($s, [string[]]$fmt, $inv, $styles)
    }
    throw ('DER: tag 0x{0:X2} is not a time.' -f $Element.Tag)
}

function ConvertFrom-MspkiDerInteger {
    <#
    .SYNOPSIS
    Returns the content of a DER INTEGER as an upper-case hex string (leading zero byte removed).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Content)
    $start = 0
    while ($start -lt ($Content.Length - 1) -and $Content[$start] -eq 0) { $start++ }
    $b = New-Object byte[] ($Content.Length - $start)
    [Array]::Copy($Content, $start, $b, 0, $b.Length)
    return (ConvertTo-MspkiHex $b)
}

function Find-MspkiDerElement {
    <#
    .SYNOPSIS
    Walks a DER structure depth-first and returns every element with the given tag.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Tag,
        $Element = $null,
        [int]$MaxDepth = 12
    )
    $found = New-Object System.Collections.ArrayList
    if ($null -eq $Element) { $Element = Read-MspkiDerElement -Bytes $Bytes -Offset 0 }
    $stack = New-Object System.Collections.Stack
    $stack.Push(@($Element, 0))
    while ($stack.Count -gt 0) {
        $item = $stack.Pop()
        $e = $item[0]; $d = $item[1]
        if ($e.Tag -eq $Tag) { [void]$found.Add($e) }
        if ($e.Constructed -and $d -lt $MaxDepth) {
            $kids = Get-MspkiDerChild -Bytes $Bytes -Element $e
            for ($i = $kids.Count - 1; $i -ge 0; $i--) { $stack.Push(@($kids[$i], ($d + 1))) }
        }
    }
    return , $found.ToArray()
}
