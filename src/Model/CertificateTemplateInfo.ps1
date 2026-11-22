# Public certificate facts used to tell how a certificate was made: the certificate template extension (v2 "Certificate Template
# Information" 1.3.6.1.4.1.311.21.7, or v1 "Certificate Template Name" 1.3.6.1.4.1.311.20.2), the EKU list and the certificate's role.
# Parsed in memory from the public certificate; nothing is written.

$script:MspkiTemplateInfoOid = '1.3.6.1.4.1.311.21.7'
$script:MspkiTemplateNameOid = '1.3.6.1.4.1.311.20.2'

function ConvertFrom-MspkiTemplateExtension {
    <#
    .SYNOPSIS
    The template a certificate was issued from: { Oid; Name; MajorVersion; MinorVersion; Source } or $null when it has no template extension.
    .DESCRIPTION
    v2: SEQUENCE { templateID OBJECT IDENTIFIER, templateMajorVersion INTEGER, templateMinorVersion INTEGER OPTIONAL }.
    v1: a BMPString (or UTF8String / PrintableString) with the template name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $r = [pscustomobject][ordered]@{ Oid = ''; Name = ''; MajorVersion = $null; MinorVersion = $null; Source = '' }
    $v2 = Get-MspkiCertificateExtension -Certificate $Certificate -Oid $script:MspkiTemplateInfoOid
    if ($null -ne $v2) {
        try {
            $b = [byte[]]$v2.RawData
            $seq = Read-MspkiDerElement -Bytes $b -Offset 0
            $kids = Get-MspkiDerChild -Bytes $b -Element $seq   # returns its array as one object
            $int = { param($el) $hx = [string](ConvertFrom-MspkiDerInteger -Content (Get-MspkiDerBytes -Bytes $b -Element $el)); if (-not $hx) { [int64]0 } else { [Convert]::ToInt64($hx, 16) } }
            if ($kids.Count -ge 1 -and $kids[0].Tag -eq 0x06) { $r.Oid = ConvertFrom-MspkiDerOid -Content (Get-MspkiDerBytes -Bytes $b -Element $kids[0]) }
            if ($kids.Count -ge 2 -and $kids[1].Tag -eq 0x02) { $r.MajorVersion = & $int $kids[1] }
            if ($kids.Count -ge 3 -and $kids[2].Tag -eq 0x02) { $r.MinorVersion = & $int $kids[2] }
            $r.Source = 'TemplateInformation'
        }
        catch { $r.Source = 'TemplateInformation (unreadable)' }
    }
    $v1 = Get-MspkiCertificateExtension -Certificate $Certificate -Oid $script:MspkiTemplateNameOid
    if ($null -ne $v1) {
        try {
            $b = [byte[]]$v1.RawData
            $el = Read-MspkiDerElement -Bytes $b -Offset 0
            $content = Get-MspkiDerBytes -Bytes $b -Element $el
            $r.Name = $(switch ($el.Tag) { 0x1E { [System.Text.Encoding]::BigEndianUnicode.GetString($content) } 0x0C { [System.Text.Encoding]::UTF8.GetString($content) } default { [System.Text.Encoding]::ASCII.GetString($content) } })
            if (-not $r.Source) { $r.Source = 'TemplateName' }
        }
        catch { }
    }
    if (-not $r.Source) { return $null }
    return $r
}

function Get-MspkiCertificateEku {
    # The extended key usage OIDs of a certificate (empty when it has no EKU extension).
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $x = Get-MspkiCertificateExtension -Certificate $Certificate -Oid '2.5.29.37'
    if ($null -eq $x) { return @() }
    $e = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($x, $x.Critical)
    return @($e.EnhancedKeyUsages | ForEach-Object { $_.Value })
}

function Get-MspkiCertificateTemplateLabel {
    <#
    .SYNOPSIS
    Names the template of a certificate in words: the v1 name, or the template in AD whose OID matches the v2 extension, or the OID.
    #>
    [CmdletBinding()]
    param($TemplateInfo, [AllowEmptyCollection()][object[]]$Templates = @())
    if ($null -eq $TemplateInfo) { return '' }
    if ($TemplateInfo.Name) { return $TemplateInfo.Name }
    if ($TemplateInfo.Oid) {
        $t = @($Templates | Where-Object { $null -ne $_ -and [string]$_.Oid -eq $TemplateInfo.Oid }) | Select-Object -First 1
        if ($null -ne $t) { return [string]$t.Name }
        return $TemplateInfo.Oid
    }
    return ''
}
