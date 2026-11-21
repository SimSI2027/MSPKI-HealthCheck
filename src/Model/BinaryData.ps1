# Base64 DATA handling. The only place in the project that decodes Base64 (CLAUDE.md rule 6): it turns the
# certificates and CRLs that a CA returns from GetCAProperty (CR_OUT_BASE64 text) into DER bytes. The bytes are
# only ever parsed as certificates or CRLs; nothing decoded here is executed, loaded as code or written to disk.

function ConvertFrom-MspkiBase64Data {
    <#
    .SYNOPSIS
    Decodes Base64 (or PEM-wrapped Base64) text that holds a certificate or a CRL into DER bytes.

    .DESCRIPTION
    Data only. The text must be a CA property value or a PEM block labelled CERTIFICATE, X509 CRL or PKCS7; any
    other label is rejected. The decoded bytes must start with a DER SEQUENCE (0x30) and are size-limited, so
    anything that is not certificate/CRL-shaped data is refused. The caller passes the bytes to the X509 or CRL
    parser and to nothing else.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [ValidateRange(1, 67108864)][int]$MaxBytes = 33554432
    )
    $t = ([string]$Text).Trim()
    if (-not $t) { throw 'No Base64 data.' }
    $pem = [regex]::Match($t, '^-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----$', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($pem.Success) {
        if (@('CERTIFICATE', 'X509 CRL', 'PKCS7') -notcontains $pem.Groups[1].Value) {
            throw ('PEM label "{0}" is not a certificate or CRL.' -f $pem.Groups[1].Value)
        }
        $t = $pem.Groups[2].Value
    }
    $t = $t -replace '\s', ''
    if ($t -notmatch '^[A-Za-z0-9+/]+={0,2}$') { throw 'The text is not Base64 data.' }
    if ([math]::Floor($t.Length / 4) * 3 -gt ($MaxBytes + 2)) { throw ('Base64 data is larger than the {0} byte limit.' -f $MaxBytes) }
    $bytes = [System.Convert]::FromBase64String($t)
    if ($bytes.Length -gt $MaxBytes) { throw ('Base64 data is larger than the {0} byte limit.' -f $MaxBytes) }
    if ($bytes.Length -lt 4 -or $bytes[0] -ne 0x30) { throw 'The decoded data is not a DER structure (certificate or CRL).' }
    return , $bytes
}
