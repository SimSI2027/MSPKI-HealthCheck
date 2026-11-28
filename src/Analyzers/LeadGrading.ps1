# How a probe result is graded depends on what carries the URL (REQUIREMENTS 5.9: historical references are for review only).
# A URL that only expired or historical CA certificates, or only an older signing-certificate index of a CA, point to is
# not in use by current configuration. A dead host there is a fact worth a look, not a failure that sets exit code 4.
# The decision is made from the lead's carriers; nothing here changes what is probed.


function Get-MspkiLeadGrading {
    <#
    .SYNOPSIS
    Decides whether the probe results of a lead are graded normally or as review items.

    .DESCRIPTION
    Every source of the lead is a carrier. A carrier is historical when it is a CA certificate that has expired or whose
    lifecycle is Historical, or an older signing-certificate index of a CA. Anything else (a current or unknown CA
    certificate that has not expired, the newest signing-certificate index, Active Directory, local policy) is live.
    The result is review-only when there is at least one carrier and every carrier is historical. Pure function.

    .OUTPUTS
    { ReviewOnly; Reason; Live (lines); Historical (lines) }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Lead,
        [AllowNull()]$Inventory = $null,
        [hashtable]$KnownCertificates = @{},
        [DateTime]$Now = (Get-MspkiUtcNow)
    )
    $live = New-Object System.Collections.ArrayList
    $hist = New-Object System.Collections.ArrayList
    $entries = @()
    if ($null -ne $Inventory -and $Inventory.PSObject.Properties['CACertificates']) { $entries = @($Inventory.CACertificates) }
    $carriers = @()
    if ($Lead.PSObject.Properties['Carriers']) { $carriers = @($Lead.Carriers | Where-Object { $_ -like 'CAIndex|*' }) }
    foreach ($c in $carriers) {
        $p = $c -split '\|'
        if ($p.Count -lt 4) { continue }
        if ($p[3] -eq 'Current') { [void]$live.Add(('the newest signing certificate (index {0}) of CA {1}' -f $p[2], $p[1])) }
        else { [void]$hist.Add(('an older signing certificate (index {0}) of CA {1}' -f $p[2], $p[1])) }
    }
    foreach ($s in @($Lead.Sources)) {
        if ($s -match '^CA:(?<n>.+):Cert(Cdp|Aia|AiaOcsp)Urls$') {
            if ($carriers.Count -eq 0) { [void]$live.Add(('the current configuration of CA {0}' -f $Matches['n'])) }
        }
        elseif ($s -match '^Cert:(?<tp>[0-9A-Fa-f]+):') {
            $tp = $Matches['tp']
            $e = @($entries | Where-Object { $_.Thumbprint -eq $tp }) | Select-Object -First 1
            $na = $null; $life = ''; $subject = $tp
            if ($null -ne $e) {
                $na = ConvertTo-MspkiUtcDate -Text ([string]$e.Info.NotAfter); $life = [string]$e.Lifecycle; $subject = '{0} [{1}]' -f $e.Info.Subject, $tp
            }
            elseif ($KnownCertificates.ContainsKey($tp)) {
                $na = $KnownCertificates[$tp].NotAfter.ToUniversalTime(); $subject = '{0} [{1}]' -f $KnownCertificates[$tp].Subject, $tp
            }
            $expired = ($null -ne $na -and $na -lt $Now.ToUniversalTime())
            if ($expired) { [void]$hist.Add(('the expired certificate {0}' -f $subject)) }
            elseif ($life -eq 'Historical') { [void]$hist.Add(('the historical certificate {0}' -f $subject)) }
            else { [void]$live.Add(('the certificate {0}' -f $subject)) }
        }
        else { [void]$live.Add(('source {0}' -f $s)) }
    }
    $reviewOnly = ($live.Count -eq 0 -and $hist.Count -gt 0)
    $reason = ''
    if ($reviewOnly) {
        $reason = 'Every reference to this URL is historical or expired ({0}). A dead or wrong URL there is a review item, not a failure: certificates that carry it may no longer be valid, and this tool cannot see the certificates a CA issued.' -f (@($hist | Select-Object -Unique) -join '; ')
    }
    return [pscustomobject][ordered]@{ ReviewOnly = $reviewOnly; Reason = $reason; Live = @($live | Select-Object -Unique); Historical = @($hist | Select-Object -Unique) }
}

function ConvertTo-MspkiReviewFinding {
    <#
    .SYNOPSIS
    Turns a Fail, Critical or Warning result into a review item: status Information, severity ReviewRequired, the status
    code and every other field kept, and the reason (with the original status) added to the Evidence. Other statuses are
    returned unchanged.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Finding, [Parameter(Mandatory = $true)][string]$Reason)
    if (@('Fail', 'Critical', 'Warning') -notcontains $Finding.Status) { return $Finding }
    $orig = $Finding.Status
    $Finding.Status = 'Information'
    $Finding.Severity = 'ReviewRequired'
    $Finding.Evidence = [string[]](@($Finding.Evidence) + ('Review only: {0} The status would have been {1} for a URL that current configuration references.' -f $Reason, $orig))
    return $Finding
}
