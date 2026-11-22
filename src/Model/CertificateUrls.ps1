# URLs embedded in certificates (and CRLs): CRL Distribution Points, Freshest CRL (delta) and Authority
# Information Access (CA issuers and OCSP). Decoded from DER, never from localised text.

$script:MspkiUrlOid = @{
    CDP          = '2.5.29.31'
    FreshestCRL  = '2.5.29.46'
    AIA          = '1.3.6.1.5.5.7.1.1'
    CAIssuers    = '1.3.6.1.5.5.7.48.2'
    OCSP         = '1.3.6.1.5.5.7.48.1'
}

function Get-MspkiGeneralNameUri {
    <#
    .SYNOPSIS
    All uniformResourceIdentifier GeneralNames ([6] IA5String, tag 0x86) inside a DER structure.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $out = New-Object System.Collections.ArrayList
    foreach ($e in (Find-MspkiDerElement -Bytes $Bytes -Tag 0x86)) {
        [void]$out.Add([System.Text.Encoding]::ASCII.GetString((Get-MspkiDerBytes -Bytes $Bytes -Element $e)))
    }
    return , $out.ToArray()
}

function ConvertFrom-MspkiAiaExtension {
    <#
    .SYNOPSIS
    Decodes an Authority Information Access extension value into { Kind = AIA|OCSP|Other; Url }.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][byte[]]$RawData)
    $out = New-Object System.Collections.ArrayList
    $root = Read-MspkiDerElement -Bytes $RawData -Offset 0
    foreach ($ad in (Get-MspkiDerChild -Bytes $RawData -Element $root)) {
        $kids = Get-MspkiDerChild -Bytes $RawData -Element $ad
        if ($kids.Count -lt 2 -or $kids[0].Tag -ne 0x06) { continue }
        $oid = ConvertFrom-MspkiDerOid -Content (Get-MspkiDerBytes -Bytes $RawData -Element $kids[0])
        if ($kids[1].Tag -ne 0x86) { continue }
        $url = [System.Text.Encoding]::ASCII.GetString((Get-MspkiDerBytes -Bytes $RawData -Element $kids[1]))
        $kind = 'Other'
        if ($oid -eq $script:MspkiUrlOid.CAIssuers) { $kind = 'AIA' }
        elseif ($oid -eq $script:MspkiUrlOid.OCSP) { $kind = 'OCSP' }
        [void]$out.Add([pscustomobject]@{ Kind = $kind; Url = $url })
    }
    return , $out.ToArray()
}

function Get-MspkiCertificateUrl {
    <#
    .SYNOPSIS
    Lists the CDP, Freshest CRL, AIA and OCSP URLs in a certificate, in extension order.

    .OUTPUTS
    Objects { Kind = CDP | FreshestCRL | AIA | OCSP; Url }. Malformed extensions are skipped and
    reported in the Error property of a Kind = 'Error' item.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $out = New-Object System.Collections.ArrayList
    foreach ($ext in $Certificate.Extensions) {
        $oid = $ext.Oid.Value
        try {
            if ($oid -eq $script:MspkiUrlOid.CDP -or $oid -eq $script:MspkiUrlOid.FreshestCRL) {
                $kind = 'CDP'
                if ($oid -eq $script:MspkiUrlOid.FreshestCRL) { $kind = 'FreshestCRL' }
                foreach ($u in (Get-MspkiGeneralNameUri -Bytes $ext.RawData)) { [void]$out.Add([pscustomobject]@{ Kind = $kind; Url = $u; Error = '' }) }
            }
            elseif ($oid -eq $script:MspkiUrlOid.AIA) {
                foreach ($a in (ConvertFrom-MspkiAiaExtension -RawData $ext.RawData)) {
                    if ($a.Kind -ne 'Other') { [void]$out.Add([pscustomobject]@{ Kind = $a.Kind; Url = $a.Url; Error = '' }) }
                }
            }
        }
        catch {
            [void]$out.Add([pscustomobject]@{ Kind = 'Error'; Url = ''; Error = ('{0}: {1}' -f $oid, (Get-MspkiErrorInfo $_).Message) })
        }
    }
    return , $out.ToArray()
}

function Get-MspkiCertificateDnsName {
    <#
    .SYNOPSIS
    The dNSName entries ([2] IA5String, tag 0x82) of a certificate's Subject Alternative Name extension (2.5.29.17), lower-case.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $ext = Get-MspkiCertificateExtension -Certificate $Certificate -Oid '2.5.29.17'
    if ($null -eq $ext) { return @() }
    $b = [byte[]]$ext.RawData
    $out = New-Object System.Collections.ArrayList
    try {
        $top = Read-MspkiDerElement -Bytes $b -Offset 0
        foreach ($c in (Get-MspkiDerChild -Bytes $b -Element $top)) {
            if ($c.Tag -ne 0x82) { continue }
            $n = ([System.Text.Encoding]::ASCII.GetString((Get-MspkiDerBytes -Bytes $b -Element $c))).Trim().TrimEnd('.').ToLowerInvariant()
            if ($n -and $out -notcontains $n) { [void]$out.Add($n) }
        }
    }
    catch { Write-MspkiLog -Level Warning -Message ('Subject Alternative Name of {0} could not be read: {1}' -f $Certificate.Thumbprint, $_.Exception.Message) }
    return $out.ToArray()
}
