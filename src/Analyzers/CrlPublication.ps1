# CRL publication check (REQUIREMENTS section 5.2): the CA's own current base and delta CRLs, read through
# GetCAProperty, are compared with what each CDP location serves. The same CRL number means the CRL was
# published correctly; an older number means PUBLICATION_FAIL or STALE_DATA.

function Get-MspkiCaOwnCrl {
    <#
    .SYNOPSIS
    The CA's own current base and delta CRLs (one entry per signing certificate and kind) from the CA properties.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$EnterpriseCAs = @(),
        # Live (decoded) CA properties by CA name. The inventory copy is the JSON-safe summary (string dates, no bytes) and cannot be graded.
        [hashtable]$LiveProperties = @{}
    )
    foreach ($ca in @($EnterpriseCAs)) {
        $props = $ca.Properties
        if ($LiveProperties.ContainsKey($ca.Name)) { $props = $LiveProperties[$ca.Name] }
        if ($null -eq $props) { continue }
        foreach ($s in @($props.SigningCertificates)) {
            foreach ($kind in @('Base', 'Delta')) {
                $crl = $s.($kind + 'Crl')
                if ($null -eq $crl) { continue }
                [pscustomobject]@{
                    CAName = $ca.Name; Config = $ca.Config; Index = $s.Index; Kind = $kind; Crl = $crl
                    PublishStatus = $s.($kind + 'CrlPublishStatus')
                }
            }
        }
    }
}

function Test-MspkiCaCrlPublication {
    <#
    .SYNOPSIS
    Compares the CA's own current CRLs with what each CDP location serves, and grades each CA-held CRL.

    .DESCRIPTION
    Same CRL number: published correctly (Pass, Confirmed). Older number: PUBLICATION_FAIL when the served CRL
    has already expired (Fail) or when the CA's newer CRL is older than the grace period (Warning); STALE_DATA
    when the CA's newer CRL is younger than the grace period, because publication may still be in progress.
    A higher number than the CA reported is a Pass with a note (the CA published again between the two reads).
    Returns { Findings; JudgedUrls } (the locations judged older, so the cross-location check skips them).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$CaCrls = @(),
        [AllowEmptyCollection()][object[]]$Records = @(),
        [AllowEmptyCollection()][object[]]$Certificates = @(),
        [hashtable]$Thresholds = @{},
        [DateTime]$Now = [DateTime]::UtcNow
    )
    $t = Get-MspkiThreshold -Override $Thresholds
    $findings = New-Object System.Collections.ArrayList
    $judged = New-Object System.Collections.ArrayList
    $now = $Now.ToUniversalTime()

    foreach ($own in @($CaCrls)) {
        $pseudo = [pscustomobject]@{
            Kind = 'CDP'; Id = ('CA-{0}-{1}' -f $own.Index, $own.Kind); RelatedCAs = @($own.CAName)
            Sources = @(('CA:{0}:GetCAProperty:{1}CRL' -f $own.CAName, $own.Kind)); Scope = 'Local'
        }
        $rec = [pscustomobject]@{
            Url = ('CA property {0}CRL[{1}] of {2}' -f $own.Kind, $own.Index, $own.Config)
            Lead = $pseudo; Crl = $own.Crl; ExpectedIssuer = @()
        }
        $h = Test-MspkiCrlHealth -Record $rec -Certificates $Certificates -Thresholds $Thresholds -Now $now
        $h.Message = 'CA''s own current ' + $h.Message
        [void]$findings.Add($h)
    }

    foreach ($r in @($Records)) {
        $cands = @($CaCrls | Where-Object { $_.Crl.IssuerRawHex -eq $r.Crl.IssuerRawHex -and $_.Crl.IsDelta -eq $r.Crl.IsDelta })
        if ($cands.Count -eq 0) { continue }
        $own = $null
        if ($r.Crl.CAVersion) { $own = @($cands | Where-Object { $_.Crl.CAVersion -eq $r.Crl.CAVersion }) | Select-Object -First 1 }
        if ($null -eq $own -and $cands.Count -eq 1 -and (-not $r.Crl.CAVersion -or -not $cands[0].Crl.CAVersion)) { $own = $cands[0] }
        if ($null -eq $own) { continue }

        $cmp = Compare-MspkiHexNumber $r.Crl.CrlNumber $own.Crl.CrlNumber
        $type = 'base'
        if ($r.Crl.IsDelta) { $type = 'delta' }
        $ownAge = [math]::Round(($now - $own.Crl.ThisUpdate).TotalMinutes, 0)
        $served = '(none)'
        if ($null -ne $r.Crl.NextUpdate) { $served = $r.Crl.NextUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ') }
        $ev = @(
            ('Location: {0}' -f $r.Url),
            ('CA: {0} ({1}); {2} CRL of signing certificate [{3}] {4}' -f $own.CAName, $own.Config, $type, $own.Index, $own.Crl.CAVersion),
            ('CA''s own CRL number: {0}; this update {1}' -f $own.Crl.CrlNumber, $own.Crl.ThisUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ')),
            ('Location serves CRL number: {0}; this update {1}; next update {2}' -f $r.Crl.CrlNumber, $r.Crl.ThisUpdate.ToString('yyyy-MM-ddTHH:mm:ssZ'), $served)
        )
        if ($null -ne $own.PublishStatus) { $ev += ('CA publish status value for this CRL: {0} (reported as is, not interpreted)' -f $own.PublishStatus) }
        $common = @{
            Stage = 'Analysis'; Category = 'CRL'; Role = 'CDPEndpoint'; Target = $r.Crl.Issuer; Endpoint = $r.Url
            RelatedCA = ((@($r.Lead.RelatedCAs) + @($own.CAName) | Select-Object -Unique) -join ', ')
            Scope = $r.Lead.Scope; Confidence = 'Confirmed'
            Sources = @(@($r.Lead.Sources) + @(('CA:{0}:GetCAProperty:{1}CRL' -f $own.CAName, $own.Kind)))
        }
        if ($cmp -ge 0) {
            $msg = '{0} serves the same {1} CRL number ({2}) as the CA: it was published correctly.' -f $r.Url, $type, $r.Crl.CrlNumber
            $notes = ''
            if ($cmp -gt 0) {
                $msg = '{0} serves {1} CRL number {2}, newer than number {3} that the CA reported when it was read.' -f $r.Url, $type, $r.Crl.CrlNumber, $own.Crl.CrlNumber
                $notes = 'The CA published a newer CRL between reading its properties and downloading this location; not a fault.'
            }
            [void]$findings.Add((New-MspkiFinding @common -Evidence $ev -Status 'Pass' -StatusCode 'OK' -Message $msg -Notes $notes -Layers @{ ContentStatus = 'Pass' }))
            continue
        }

        [void]$judged.Add($r.Url)
        $expired = ($null -ne $r.Crl.NextUpdate -and $r.Crl.NextUpdate -lt $now)
        if ($expired) {
            $status = 'Fail'; $code = 'PUBLICATION_FAIL'
            $why = 'the CRL it serves has already expired'
        }
        elseif ($ownAge -gt $t.CrlPublicationGraceMinutes) {
            $status = 'Warning'; $code = 'PUBLICATION_FAIL'
            $why = 'the CA created its newer CRL {0} minutes ago, longer than the {1} minute grace period' -f $ownAge, $t.CrlPublicationGraceMinutes
        }
        else {
            $status = 'Warning'; $code = 'STALE_DATA'
            $why = 'the CA created its newer CRL only {0} minutes ago (within the {1} minute grace period), so publication may still be in progress' -f $ownAge, $t.CrlPublicationGraceMinutes
        }
        $ev += ('Reasoning: {0}' -f $why)
        $msg = '{0} serves {1} CRL number {2} but the CA holds number {3}: {4}.' -f $r.Url, $type, $r.Crl.CrlNumber, $own.Crl.CrlNumber, $why
        $pf = New-MspkiFinding @common -Evidence $ev -Status $status -StatusCode $code -Message $msg -Layers @{ ContentStatus = 'Warning' } `
            -Remediation 'Check that the CA can publish to this location (permissions on the publication target, replication for LDAP, the web server folder) and publish the CRL again.' `
            -Notes 'Whether the CA is configured to publish to this location is not readable without CA registry access; the location is referenced by the CA''s CDP extension.'
        if ($r.PSObject.Properties['ReviewOnly'] -and $r.ReviewOnly) { $pf = ConvertTo-MspkiReviewFinding -Finding $pf -Reason $r.ReviewReason }
        [void]$findings.Add($pf)
    }
    return [pscustomobject]@{ Findings = $findings.ToArray(); JudgedUrls = $judged.ToArray() }
}
