# Hierarchy health (ROADMAP D1), built on the entity graph: CA certificate generations, how AIA/CDP are published and in which order
# Windows tries them, NTAuth versus AIA, offline-root CRL lifetime, OCSP responders nobody points to, HTTPS that closes every
# handshake, and certificate names with no DNS record. Every finding says why it matters and what the owner can do.

$script:MspkiWeakSignatureOid = @{
    '1.2.840.113549.1.1.4' = 'md5RSA'; '1.2.840.113549.1.1.5' = 'sha1RSA'; '1.2.840.10045.4.1' = 'sha1ECDSA'; '1.2.840.10040.4.3' = 'sha1DSA'
}

function New-MspkiHierarchyFinding {
    # Analysis-stage finding with the entity ids it is about.
    param([hashtable]$P, [string[]]$EntityIds = @())
    $P['Stage'] = 'Analysis'
    if (-not $P.ContainsKey('Scope')) { $P['Scope'] = 'Local' }
    return (New-MspkiFinding @P -EntityIds $EntityIds)
}

function Get-MspkiShortName {
    param([string]$DistinguishedName)
    $m = [regex]::Match([string]$DistinguishedName, '(?i)CN=([^,]+)')
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return [string]$DistinguishedName
}

function Test-MspkiPublicationProtocol {
    <#
    .SYNOPSIS
    Grades the AIA or CDP URLs one CA puts in what it issues: published only over LDAP is a design risk (Warning), any HTTP is Pass.
    .PARAMETER Urls
    The URLs in the order they appear. Only http(s) and ldap URLs count; file URLs are ignored (clients never use them).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$IssuerName,
        [Parameter(Mandatory = $true)][ValidateSet('AIA', 'CDP')][string]$Kind,
        [AllowEmptyCollection()][string[]]$Urls = @(),
        [string[]]$Sources = @('Analysis:Hierarchy'),
        [string[]]$EntityIds = @()
    )
    $ldap = @($Urls | Where-Object { $_ -match '^(?i)ldaps?://' })
    $http = @($Urls | Where-Object { $_ -match '^(?i)https?://' })
    if (($ldap.Count + $http.Count) -eq 0) { return $null }
    $what = $(if ($Kind -eq 'AIA') { 'CA certificate (AIA)' } else { 'CRL (CDP)' })
    $ev = @($Urls | ForEach-Object { 'URL: {0}' -f $_ })
    $p = @{ Category = $Kind; Role = $(if ($Kind -eq 'AIA') { 'AIAEndpoint' } else { 'CDPEndpoint' }); Target = $IssuerName; RelatedCA = $IssuerName
        Sources = $Sources; Confidence = 'Confirmed'; Evidence = $ev }
    if ($http.Count -gt 0) {
        $p += @{ Status = 'Pass'; StatusCode = 'OK'; Message = ('{0} publishes its {1} over HTTP ({2} of {3} URLs), so clients that are not in the domain can fetch it.' -f $IssuerName, $what, $http.Count, ($ldap.Count + $http.Count)) }
        return (New-MspkiHierarchyFinding -P $p -EntityIds $EntityIds)
    }
    $p += @{ Status = 'Warning'; StatusCode = 'CONFIG_RISK'; Severity = 'Medium'
        Message = ('{0} publishes its {1} only over LDAP ({2} URL(s), no HTTP URL). Only computers that can query this forest''s Active Directory can fetch it.' -f $IssuerName, $what, $ldap.Count)
        Notes = $(if ($Kind -eq 'CDP') { 'Devices that are not domain members (phones, Intune/SCEP devices, partners, VPN or web clients outside the network, Linux and appliances) cannot download the CRL, so they cannot check revocation: depending on their settings they reject the certificate or skip the check.' } else { 'Devices that are not domain members cannot download the issuing CA certificate, so they cannot build the chain unless the certificate is already installed on them.' })
        Remediation = ('On {0} (Extensions tab): add an HTTP {1} location on a web server that every client can reach, publish the file there, and keep the LDAP location after it if you want. It only affects certificates issued after the change; existing certificates keep their URLs until they are renewed.' -f $IssuerName, $(if ($Kind -eq 'CDP') { 'CRL distribution point (with "Include in the CDP extension of issued certificates")' } else { 'AIA (with "Include in the AIA extension of issued certificates")' })) }
    return (New-MspkiHierarchyFinding -P $p -EntityIds $EntityIds)
}

function Get-MspkiRetrievalUrlKey {
    <#
    .SYNOPSIS
    The key under which a URL is compared in the retrieval-order check: scheme plus the normalised URL (spaces and %20, host case and
    default ports do not matter; http and https stay apart, because a client tries them as two URLs).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Url)
    $n = ConvertTo-MspkiNormalizedUrl -Url $Url
    if (-not $n.Valid) { return ([string]$Url).Trim().ToLowerInvariant() }
    return ('{0}|{1}' -f $n.Scheme, $n.Key)
}

function Get-MspkiRetrievalOutcome {
    <#
    .SYNOPSIS
    Per URL: did a usable object come back? Usable, Failed or NotTested, keyed by Get-MspkiRetrievalUrlKey.
    .DESCRIPTION
    Built from the findings of the probes and the CRL checks, not from the worst status. Failed: a Fail, Critical or Error, or a Warning
    whose code names a retrieval, content or TLS problem (a wrong issuer, a wrong key, a redirect that was not followed, a failure that the
    scope rule reduced to a Warning). Usable: at least one Pass and no failure; a Warning about the age of the object counts, because the
    object was retrieved. NotTested: only Skipped, NotApplicable or Information.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Findings = @())
    $failureCode = '^(DNS_FAIL|TCP_FAIL|TIMEOUT|HTTP_|TLS_|CONTENT_|SIGNATURE_INVALID|RETRIEVAL_FAIL|OBJECT_EXPIRED|PUBLICATION_FAIL|CHAIN_)'
    $state = @{}
    foreach ($f in @($Findings | Where-Object { $_ -and $_.Endpoint -and $_.Category -in @('AIA', 'CDP', 'CRL') })) {
        $k = Get-MspkiRetrievalUrlKey -Url ([string]$f.Endpoint)
        if (-not $state.ContainsKey($k)) { $state[$k] = @{ Failed = $false; Usable = $false } }
        $s = [string]$f.Status
        if ($s -in @('Fail', 'Critical', 'Error')) { $state[$k].Failed = $true }
        elseif ($s -eq 'Warning') {
            if ([string]$f.StatusCode -match $failureCode) { $state[$k].Failed = $true } else { $state[$k].Usable = $true }
        }
        elseif ($s -eq 'Pass') { $state[$k].Usable = $true }
    }
    $out = @{}
    foreach ($k in $state.Keys) {
        $out[$k] = $(if ($state[$k].Failed) { 'Failed' } elseif ($state[$k].Usable) { 'Usable' } else { 'NotTested' })
    }
    return $out
}

function Test-MspkiRetrievalOrder {
    <#
    .SYNOPSIS
    Walks the AIA or CDP URLs in the order Windows clients try them (the order in the extension) with the result of each probe.
    .DESCRIPTION
    CryptoAPI tries the URLs one after the other and stops at the first that returns a usable object; every failing URL before it
    costs a time-out on every client without a cached copy. Pass: the first URL works. Warning: a later one works. Fail: none works.
    URLs are matched after normalisation, and a URL that was not tested from here is neither working nor failing (audit 2 M4).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$IssuerName,
        [Parameter(Mandatory = $true)][ValidateSet('AIA', 'CDP')][string]$Kind,
        [AllowEmptyCollection()][string[]]$Urls = @(),
        # Outcome per URL (Usable, Failed, NotTested) from Get-MspkiRetrievalOutcome. Keys are normalised here, so any spelling works.
        [hashtable]$UrlOutcome = @{},
        [string]$From = '',
        [string[]]$EntityIds = @()
    )
    $list = @($Urls | Where-Object { $_ -match '^(?i)(https?|ldaps?)://' })
    if ($list.Count -eq 0) { return $null }
    $known = @{}
    foreach ($k in $UrlOutcome.Keys) { $known[(Get-MspkiRetrievalUrlKey -Url ([string]$k))] = [string]$UrlOutcome[$k] }
    $ev = New-Object System.Collections.ArrayList
    $first = -1; $failed = 0; $untested = 0; $failedBefore = 0; $untestedBefore = 0
    for ($i = 0; $i -lt $list.Count; $i++) {
        $key = Get-MspkiRetrievalUrlKey -Url $list[$i]
        $st = $(if ($known.ContainsKey($key) -and $known[$key] -in @('Usable', 'Failed')) { $known[$key] } else { 'NotTested' })
        if ($st -eq 'Failed') { $failed++ } elseif ($st -eq 'NotTested') { $untested++ }
        if ($st -eq 'Usable' -and $first -lt 0) { $first = $i; $failedBefore = $failed; $untestedBefore = $untested }
        [void]$ev.Add(('{0}. {1} -> {2}' -f ($i + 1), $list[$i], $st))
    }
    $tested = $list.Count - $untested
    if ($From) { [void]$ev.Insert(0, ('Order taken from: {0}' -f $From)) }
    $what = $(if ($Kind -eq 'AIA') { 'issuing CA certificate' } else { 'CRL' })
    $p = @{ Category = $Kind; Role = $(if ($Kind -eq 'AIA') { 'AIAEndpoint' } else { 'CDPEndpoint' }); Target = $IssuerName; RelatedCA = $IssuerName
        Sources = @('Analysis:RetrievalOrder'); Confidence = 'Confirmed'; Evidence = @($ev) }
    if ($tested -eq 0) {
        $p.Confidence = 'Referenced'
        $p += @{ Status = 'Skipped'; StatusCode = 'NOT_APPLICABLE'; Message = ('None of the {0} {1} URLs of {2} was tested from here, so the order Windows uses could not be checked.' -f $list.Count, $Kind, $IssuerName) }
    }
    elseif ($first -eq 0) {
        $p += @{ Status = 'Pass'; StatusCode = 'OK'; Message = ('Windows clients get the {0} of {1} from the first {2} URL they try ({3}).' -f $what, $IssuerName, $Kind, $list[0]) }
    }
    elseif ($first -gt 0 -and $failedBefore -gt 0) {
        # Only URLs that really failed count as "failing"; an untested one before it makes the finding a review item, not a fact.
        $more = ''
        if ($untestedBefore -gt 0) { $p.Confidence = 'Referenced'; $more = ' {0} more URL(s) before it were not tested from here.' -f $untestedBefore }
        $p += @{ Status = 'Warning'; StatusCode = 'RETRIEVAL_FAIL'; Severity = 'Low'
            Message = ('Windows clients try {0} failing {1} URL(s) before the one that works ({2}) for the {3} of {4}: each failing URL costs a time-out on every client without a cached copy.{5}' -f $failedBefore, $Kind, $list[$first], $what, $IssuerName, $more)
            Remediation = 'Fix or remove the failing URL(s), or move a working HTTP URL to the first place, in the CA''s Extensions tab (affects newly issued certificates).' }
    }
    elseif ($first -gt 0) {
        $p.Confidence = 'Referenced'
        $p += @{ Status = 'Information'; StatusCode = 'OK'
            Message = ('The {0} of {1} is returned by the {2} URL {3}; the {4} URL(s) before it were not tested from here, so it is not known whether clients try them first and fail.' -f $what, $IssuerName, $Kind, $list[$first], $untestedBefore) }
    }
    else {
        if ($untested -gt 0) { $p.Confidence = 'Referenced' }
        if ($untested -gt 0) { $msg = '{0} of the {1} {2} URLs of {3} could be tested from here, and none of them returned the {4}.' -f $tested, $list.Count, $Kind, $IssuerName, $what }
        else { $msg = 'None of the {0} {1} URLs of {2} returned the {3} from here.' -f $list.Count, $Kind, $IssuerName, $what }
        $p += @{ Status = 'Fail'; StatusCode = 'RETRIEVAL_FAIL'; Severity = $(if ($Kind -eq 'CDP') { 'High' } else { 'Medium' })
            Message = $msg
            Notes = $(if ($Kind -eq 'CDP') { 'Without a CRL, clients that check revocation reject certificates issued by this CA (or wait and then fail).' } else { 'Without the issuing CA certificate, clients that do not already have it cannot build the chain.' }) }
    }
    return (New-MspkiHierarchyFinding -P $p -EntityIds $EntityIds)
}

function Test-MspkiCaGeneration {
    <#
    .SYNOPSIS
    One finding per CA certificate generation: chain parent, validity against the parent, key and signature algorithm, whether it is
    the current generation and how it overlaps the next one.
    .PARAMETER Generations
    Objects with Thumbprint, Subject, Issuer, NotBefore, NotAfter (datetime), KeyAlgorithm, KeySize, SignatureAlgorithm,
    SignatureOid, SelfIssued, Lifecycle, CAName, and Parents (objects with Subject, NotAfter, Thumbprint).
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Generations = @(), [datetime]$Now = [DateTime]::UtcNow)
    $out = New-Object System.Collections.ArrayList
    foreach ($ca in @($Generations | Group-Object { if ($_.CAName) { $_.CAName } else { $_.Subject } })) {
        $gens = @($ca.Group | Sort-Object { $_.NotBefore })
        for ($i = 0; $i -lt $gens.Count; $i++) {
            $g = $gens[$i]
            $why = New-Object System.Collections.ArrayList
            $bad = New-Object System.Collections.ArrayList
            $warn = New-Object System.Collections.ArrayList
            $ev = New-Object System.Collections.ArrayList
            [void]$ev.Add(('Generation {0} of {1}; lifecycle {2}; valid {3:yyyy-MM-dd} to {4:yyyy-MM-dd}' -f ($i + 1), $gens.Count, $g.Lifecycle, $g.NotBefore, $g.NotAfter))
            [void]$ev.Add(('Key: {0} {1}; signature: {2}' -f $g.KeyAlgorithm, $g.KeySize, $g.SignatureAlgorithm))
            if ($g.KeyAlgorithm -eq 'RSA' -and [int]$g.KeySize -gt 0 -and [int]$g.KeySize -lt 2048) {
                [void]$bad.Add(('RSA key of {0} bits: below 2048 bits it is considered breakable and current clients reject it' -f $g.KeySize))
            }
            $weak = $script:MspkiWeakSignatureOid.ContainsKey([string]$g.SignatureOid)
            if ($weak -and $g.SelfIssued) { [void]$warn.Add(('self-signature uses {0}; the root''s own signature is not checked by most clients, but audits and some products flag it' -f $script:MspkiWeakSignatureOid[[string]$g.SignatureOid])) }
            elseif ($weak) { [void]$bad.Add(('signed with {0}: clients that block SHA-1/MD5 reject the chain' -f $script:MspkiWeakSignatureOid[[string]$g.SignatureOid])) }
            if ($g.SelfIssued) { [void]$ev.Add('Chain: self-signed root') }
            elseif (@($g.Parents).Count -eq 0) { [void]$ev.Add(('Chain: no issuer certificate for {0} was found in the discovered certificates' -f $g.Issuer)); [void]$warn.Add('its issuer certificate was not found, so the chain cannot be checked') }
            else {
                foreach ($par in @($g.Parents)) {
                    [void]$ev.Add(('Chain: issued by {0} ({1}), valid to {2:yyyy-MM-dd}' -f $par.Subject, $par.Thumbprint, $par.NotAfter))
                }
                $lastParent = @($g.Parents | Sort-Object { $_.NotAfter } -Descending)[0]
                if ($g.NotAfter -gt $lastParent.NotAfter) {
                    [void]$warn.Add(('it is valid until {0:yyyy-MM-dd}, after its issuer ({1:yyyy-MM-dd}): from then on the chain is invalid, so its useful life ends with the issuer''s' -f $g.NotAfter, $lastParent.NotAfter))
                }
            }
            if ($i -lt $gens.Count - 1) {
                $next = $gens[$i + 1]
                if ($next.NotBefore -lt $g.NotAfter) { [void]$ev.Add(('Overlap: the next generation starts {0:yyyy-MM-dd}, {1} days before this one expires (normal for a renewal: certificates issued earlier stay valid)' -f $next.NotBefore, [int]($g.NotAfter - $next.NotBefore).TotalDays)) }
                else { [void]$ev.Add(('No overlap: the next generation starts {0:yyyy-MM-dd}, after this one expired' -f $next.NotBefore)) }
            }
            if ($g.Lifecycle -eq 'Current') { [void]$ev.Add('This is the generation the CA signs with now.') }
            elseif ($g.NotAfter -lt $Now) { [void]$ev.Add('Expired: kept only for old certificates and CRLs.') }
            $p = @{ Category = 'Hierarchy'; Role = $(if ($g.SelfIssued) { 'EnterpriseRoot' } else { 'IssuingCA' }); Target = ('{0} ({1})' -f $g.Subject, $g.Thumbprint)
                RelatedCA = [string]$g.CAName; Sources = @('Analysis:Generations'); Confidence = 'Confirmed'; Evidence = @($ev) }
            if ($bad.Count -gt 0) { $p += @{ Status = 'Fail'; StatusCode = 'CONFIG_RISK'; Severity = 'High'; Message = ('CA certificate generation {0} of {1}: {2}.' -f ($i + 1), $ca.Name, ($bad -join '; ')); Remediation = 'Renew the CA certificate with a new key of at least RSA 2048 (or ECDSA P-256) and SHA-256, and re-issue what depends on it.' } }
            elseif ($warn.Count -gt 0) { $p += @{ Status = 'Warning'; StatusCode = 'CONFIG_RISK'; Severity = 'Low'; Message = ('CA certificate generation {0} of {1}: {2}.' -f ($i + 1), $ca.Name, ($warn -join '; ')) } }
            else { $p += @{ Status = 'Pass'; StatusCode = 'OK'; Message = ('CA certificate generation {0} of {1} ({2}): chain, validity within its issuer, key {3} {4} and signature {5} are fine.' -f ($i + 1), $ca.Name, $g.Lifecycle, $g.KeyAlgorithm, $g.KeySize, $g.SignatureAlgorithm) } }
            [void]$out.Add((New-MspkiHierarchyFinding -P $p -EntityIds @((Get-MspkiEntityId -Type 'CACertificate' -Key $g.Thumbprint))))
        }
    }
    return $out.ToArray()
}

function Test-MspkiNtAuthAiaMatch {
    <#
    .SYNOPSIS
    A CA certificate generation that is in NTAuth (trusted for logon) but not in AIA (where clients find issuers): Warning per generation;
    Pass when every non-expired NTAuth generation is also in AIA.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$CACertificates = @(), [datetime]$Now = [DateTime]::UtcNow)
    $out = New-Object System.Collections.ArrayList
    $nt = @($CACertificates | Where-Object { $_.InNTAuth })
    if ($nt.Count -eq 0) { return , $out.ToArray() }
    $gap = @($nt | Where-Object { -not $_.InAIA -and $_.NotAfter -gt $Now })
    foreach ($c in $gap) {
        $name = Get-MspkiShortName $c.Subject
        [void]$out.Add((New-MspkiHierarchyFinding -EntityIds @((Get-MspkiEntityId -Type 'CACertificate' -Key $c.Thumbprint)) -P @{
            Category = 'Hierarchy'; Role = 'IssuingCA'; Target = ('{0} ({1})' -f $c.Subject, $c.Thumbprint); RelatedCA = $name
            Status = 'Warning'; StatusCode = 'CONFIG_MISMATCH'; Severity = 'Medium'; Confidence = 'Confirmed'; Sources = @('AD:NTAuthCertificates', 'AD:AIA')
            Message = ('A generation of {0} (valid to {1:yyyy-MM-dd}) is in NTAuth but not in the AIA container.' -f $name, $c.NotAfter)
            Evidence = @(('In NTAuth: yes; in AIA: no; lifecycle: {0}' -f $c.Lifecycle), ('Valid {0:yyyy-MM-dd} to {1:yyyy-MM-dd}' -f $c.NotBefore, $c.NotAfter))
            Notes = 'NTAuth decides which CAs may issue logon certificates (smart card, Windows Hello, NDES/Intune device logon); AIA is where domain clients find a CA certificate to build a chain. A generation in NTAuth only is usually an older CA certificate that was renewed: certificates still issued under it may fail to chain on clients that do not have it cached, or it is a leftover that is still trusted for logon.'
            Remediation = ('If certificates issued under this generation are still in use, publish it to the AIA container (owner, with the CA command-line tool: dspublish of the .cer file as type SubCA). If the generation is retired and nothing uses it, remove it from NTAuth (owner: the Enterprise PKI console, Manage AD Containers > NTAuthCertificates).') }))
    }
    if ($gap.Count -eq 0) {
        [void]$out.Add((New-MspkiHierarchyFinding -EntityIds @($nt | ForEach-Object { Get-MspkiEntityId -Type 'CACertificate' -Key $_.Thumbprint }) -P @{
            Category = 'Hierarchy'; Role = 'ADContainer'; Target = 'NTAuthCertificates'; Status = 'Pass'; StatusCode = 'OK'; Confidence = 'Confirmed'
            Sources = @('AD:NTAuthCertificates', 'AD:AIA'); Message = ('Every CA certificate in NTAuth that has not expired ({0}) is also in AIA.' -f $nt.Count) }))
    }
    return $out.ToArray()
}

function Test-MspkiOfflineRootCrl {
    <#
    .SYNOPSIS
    For a root CA that is not an online Enterprise CA (someone has to sign and copy its CRL by hand): how long its CRL lasts and how
    much time is left before clients stop accepting everything under it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RootName,
        [string]$Thumbprint = '',
        $ThisUpdate = $null,
        $NextUpdate = $null,
        [string]$CrlId = '',
        [datetime]$Now = [DateTime]::UtcNow,
        [int]$MinimumLifetimeDays = 30,
        [int]$WarningDays = 14
    )
    $ids = @(@((Get-MspkiEntityId -Type 'CACertificate' -Key $Thumbprint), $CrlId) | Where-Object { $_ -and $_ -ne 'cacert:' })
    $p = @{ Category = 'CRL'; Role = 'StandaloneRoot'; Target = $RootName; RelatedCA = $RootName; Sources = @('Analysis:OfflineRoot'); Confidence = 'Confirmed' }
    $note = 'An offline root signs its CRL only when an administrator starts it. When the CRL''s next-update time passes, every client that checks revocation rejects every certificate under this root, including the issuing CAs.'
    if ($null -eq $NextUpdate -or $NextUpdate -eq '') {
        $p.Confidence = 'Referenced'
        $p += @{ Status = 'Warning'; StatusCode = 'PUBLICATION_FAIL'; Severity = 'High'; Notes = $note
            Message = ('No CRL of the offline root {0} was read from any location, so its lifetime cannot be checked and clients may not be able to check the issuing CAs for revocation.' -f $RootName)
            Remediation = 'Publish the root CRL to every CDP URL in the issuing CA certificates (AD and HTTP).' }
        return (New-MspkiHierarchyFinding -P $p -EntityIds $ids)
    }
    $next = ([datetime]$NextUpdate).ToUniversalTime()
    $life = $(if ($ThisUpdate) { (($next - ([datetime]$ThisUpdate).ToUniversalTime()).TotalDays) } else { -1 })
    $left = ($next - $Now).TotalDays
    $ev = @(('Next update: {0:yyyy-MM-ddTHH:mm:ssZ} ({1:N1} days left)' -f $next, $left), ('Lifetime of the CRL: {0:N1} days' -f $life))
    $p += @{ Evidence = $ev; Notes = $note }
    if ($left -le 0) {
        $p += @{ Status = 'Critical'; StatusCode = 'OBJECT_EXPIRED'; Severity = 'High'; Message = ('The CRL of the offline root {0} expired {1:N1} days ago.' -f $RootName, -$left); Remediation = 'Start the offline root now, sign a new CRL, and copy it to every CDP location.' }
    }
    # Warn WarningDays before expiry, but never earlier than the last quarter of a short-lived CRL (that case is the lifetime warning).
    elseif ($left -lt $(if ($life -gt 0) { [math]::Min($WarningDays, $life * 0.25) } else { $WarningDays })) {
        $p += @{ Status = 'Warning'; StatusCode = 'OBJECT_EXPIRING'; Severity = 'High'; Message = ('The CRL of the offline root {0} expires in {1:N1} days.' -f $RootName, $left); Remediation = 'Schedule the offline root ceremony: sign a new CRL and copy it to every CDP location before it expires.' }
    }
    elseif ($life -ge 0 -and $life -lt $MinimumLifetimeDays) {
        $p += @{ Status = 'Warning'; StatusCode = 'CONFIG_RISK'; Severity = 'Medium'; Message = ('The offline root {0} issues CRLs that last only {1:N1} days: the root must be started that often, and one missed date stops the whole hierarchy.' -f $RootName, $life); Remediation = 'Give the root CRL a longer validity (typically 6-12 months) with an overlap period (CRLPeriod/CRLOverlapPeriod), and calendar the renewal.' }
    }
    else {
        $p += @{ Status = 'Pass'; StatusCode = 'OK'; Message = ('The CRL of the offline root {0} lasts {1:N0} days and has {2:N0} days left.' -f $RootName, $life, $left) }
    }
    return (New-MspkiHierarchyFinding -P $p -EntityIds $ids)
}

function Test-MspkiOcspResponderUse {
    <#
    .SYNOPSIS
    An Online Responder (OCSP) answering on a CA host's standard /ocsp/ path but named in no certificate and no CA property: Warning.
    Referenced: Pass. No responder (404 or no connection): nothing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)]$Http,
        [AllowEmptyCollection()][string[]]$OcspUrls = @(),
        [string[]]$EntityIds = @()
    )
    $present = ([int]$Http.HttpStatus -ge 200 -and [int]$Http.HttpStatus -ne 404)
    if (-not $present) { return $null }
    $refs = @($OcspUrls | Where-Object { (ConvertTo-MspkiNormalizedUrl -Url $_).Host -eq $HostName.ToLowerInvariant() })
    $ev = @(('GET {0}: HTTP {1} after {2} ms (anonymous; any answer other than 404 means the /ocsp/ application exists)' -f $Http.Url, $Http.HttpStatus, $Http.ElapsedMs), ('OCSP URLs in certificates and CA properties: {0}' -f $(if (@($OcspUrls).Count) { ($OcspUrls -join ', ') } else { 'none' })))
    $p = @{ Category = 'OCSP'; Role = 'OCSPEndpoint'; Target = $HostName; Endpoint = $Http.Url; Sources = @('HTTP:StandardPath', 'Analysis:OcspUse'); Evidence = $ev }
    if ($refs.Count -gt 0) {
        $p += @{ Status = 'Pass'; StatusCode = 'OK'; Confidence = 'Confirmed'; Message = ('The OCSP responder on {0} is named in {1} OCSP URL(s), so clients use it.' -f $HostName, $refs.Count) }
    }
    else {
        $p += @{ Status = 'Warning'; StatusCode = 'CONFIG_MISMATCH'; Severity = 'Low'; Confidence = 'Inferred'
            Message = ('An OCSP responder (Online Responder) answers on {0}, but no certificate or CA names it: no client will ever ask it.' -f $HostName)
            Notes = ('HTTP {0} on the standard /ocsp/ path of a proven PKI host. Clients only use OCSP when the certificate''s AIA extension contains an OCSP URL; none does here. Either the role was installed and never finished, or the CA''s AIA OCSP setting was removed. A responder nobody uses still needs patching, its signing certificate renewed, and it can give a false sense that revocation is fast.' -f $Http.HttpStatus)
            Remediation = 'Either finish it: add http://<host>/ocsp to the CA''s Extensions tab ("Include in the online certificate status protocol (OCSP) extension"), configure a revocation configuration and an OCSP Response Signing template, and re-issue; or remove the Online Responder role from this host.' }
    }
    return (New-MspkiHierarchyFinding -P $p -EntityIds $EntityIds)
}

function Test-MspkiTlsResetEndpoint {
    <#
    .SYNOPSIS
    HTTPS endpoints that accept TCP but close the TLS handshake before sending a certificate (from the probe cache): Warning each.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$TlsResults = @(), [hashtable]$HostCategory = @{})
    $out = New-Object System.Collections.ArrayList
    foreach ($t in @($TlsResults | Where-Object { $_ -and $_.ServerClosed })) {
        $h = ([string]$t.Target -split ':')[0]
        $cat = $(if ($HostCategory.ContainsKey($h)) { $HostCategory[$h] } else { 'Hierarchy' })
        [void]$out.Add((New-MspkiHierarchyFinding -EntityIds @((Get-MspkiEntityId -Type 'Host' -Key $h)) -P @{
            Category = $cat; Role = 'Computer'; Target = $t.Target; Endpoint = ('https://{0}/' -f $t.Target)
            Status = 'Warning'; StatusCode = 'TLS_HANDSHAKE_FAIL'; Severity = 'Low'; Confidence = 'Confirmed'; Sources = @('Probe:TLS')
            Layers = @{ TcpStatus = 'Pass'; TlsStatus = 'Fail' }
            Message = ('{0} accepts TCP connections but closes every TLS handshake before sending a certificate.' -f $t.Target)
            Evidence = @(('TLS protocols offered: {0}' -f $t.OfferedProtocols), ('Error: {0}' -f $t.Error), ('Time: {0} ms' -f $t.ElapsedMs))
            Notes = 'Usually an HTTPS binding with no server certificate, a certificate whose private key the web server cannot use, or no TLS version/cipher in common. Nothing that needs HTTPS on this host can work (web enrollment over SSL, CES/CEP, HTTPS AIA/CDP/OCSP). Plain HTTP AIA/CDP is not affected.'
            Remediation = 'On that host (owner): IIS Manager > site > Bindings > https: select a valid server certificate for the host name, or remove the https binding if nothing uses it. "netsh http show sslcert" lists the bindings.' }))
    }
    return $out.ToArray()
}

function Test-MspkiSanDnsName {
    <#
    .SYNOPSIS
    Every DNS name in a certificate's Subject Alternative Name must resolve: a name without a DNS record is an alias nobody can use.
    One Warning per missing name; a Pass when all names resolve.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Subject,
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$Where,
        [AllowEmptyCollection()][string[]]$Names = @(),
        # name -> DNS result { Status, StatusCode, Addresses, Error }
        [hashtable]$Dns = @{},
        [string]$EntityId = ''
    )
    $out = New-Object System.Collections.ArrayList
    $names = @($Names | Where-Object { $_ -and $_ -notlike '*`**' })
    if ($names.Count -eq 0) { return , $out.ToArray() }
    $missing = @($names | Where-Object { $Dns.ContainsKey($_) -and $Dns[$_].StatusCode -eq 'DNS_FAIL' })
    $base = @{ Category = 'Hierarchy'; Role = 'Computer'; Sources = @('Certificate:SubjectAltName', 'DNS'); Confidence = 'Confirmed' }
    foreach ($n in $missing) {
        $p = $base.Clone()
        $p += @{ Target = $n; Status = 'Warning'; StatusCode = 'DNS_FAIL'; Severity = 'Low'; Layers = @{ DnsStatus = 'Fail' }
            Message = ('The certificate {0} ({1}) names {2} in its Subject Alternative Name, but {2} has no DNS record.' -f $Subject, $Where, $n)
            Evidence = @(('Certificate: {0} [{1}]' -f $Subject, $Thumbprint), ('Where: {0}' -f $Where), ('All SAN DNS names: {0}' -f ($names -join ', ')), ('DNS {0}: {1}' -f $n, $Dns[$n].Error))
            Notes = 'Clients that use this name cannot reach the service, and the name still widens what the certificate is valid for. It is usually a planned alias that was never created, or one that was removed.'
            Remediation = ('Create the DNS record for {0} if the alias is meant to be used; otherwise leave it out of the next request or renewal of this certificate.' -f $n) }
        [void]$out.Add((New-MspkiHierarchyFinding -P $p -EntityIds @(@($EntityId, (Get-MspkiEntityId -Type 'Host' -Key $n)) | Where-Object { $_ })))
    }
    if ($missing.Count -eq 0 -and @($names | Where-Object { $Dns.ContainsKey($_) }).Count -gt 0) {
        $p = $base.Clone()
        $p += @{ Target = ('{0} ({1})' -f $Subject, $Thumbprint); Status = 'Pass'; StatusCode = 'OK'; Message = ('Every DNS name in the certificate {0} ({1}) resolves: {2}.' -f $Subject, $Where, ($names -join ', ')) }
        [void]$out.Add((New-MspkiHierarchyFinding -P $p -EntityIds @(@($EntityId) | Where-Object { $_ })))
    }
    return $out.ToArray()
}

function Get-MspkiLocalIssuedCertificate {
    <#
    .SYNOPSIS
    Public certificates in LocalMachine\My that a discovered CA issued (AKI = a CA certificate's SKI). Read-only store access; private
    keys are never touched.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$IssuerKeyIds = @())
    $keys = @($IssuerKeyIds | ForEach-Object { ConvertTo-MspkiKeyIdHex $_ } | Where-Object { $_ })
    if ($keys.Count -eq 0) { return @() }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $list = New-Object System.Collections.ArrayList
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
        foreach ($c in $store.Certificates) {
            $pub = New-MspkiCertificate -Bytes $c.RawData
            $aki = ConvertTo-MspkiKeyIdHex (Get-MspkiCertificateAuthorityKeyId -Certificate $pub)
            if ($aki -and $keys -contains $aki) { [void]$list.Add($pub) }
        }
    }
    finally { $store.Close() }
    return @($list)
}

function Invoke-MspkiHierarchyAnalysis {
    <#
    .SYNOPSIS
    Runs the hierarchy checks on the discovered data, the probe results already in the cache and the entity graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Discovery,
        [AllowEmptyCollection()][object[]]$Findings = @(),
        [int]$TimeoutSeconds = 5,
        [switch]$SkipNetwork
    )
    $out = New-Object System.Collections.ArrayList
    $inv = $Discovery.Inventory
    $entries = @(Get-MspkiDiscoveredCertificateEntry -Discovery $Discovery)
    $now = [DateTime]::UtcNow
    $ms = $TimeoutSeconds * 1000

    # Generations with their parents (by key id, else by name).
    $gens = foreach ($e in $entries) {
        $c = $e.Certificate
        $ski = ConvertTo-MspkiKeyIdHex (Get-MspkiCertificateSubjectKeyId -Certificate $c)
        $aki = ConvertTo-MspkiKeyIdHex (Get-MspkiCertificateAuthorityKeyId -Certificate $c)
        [pscustomobject]@{ Thumbprint = $c.Thumbprint; Subject = $c.Subject; Issuer = $c.Issuer; NotBefore = $c.NotBefore.ToUniversalTime(); NotAfter = $c.NotAfter.ToUniversalTime()
            KeyAlgorithm = $e.Info.KeyAlgorithm; KeySize = $e.Info.KeySize; SignatureAlgorithm = $c.SignatureAlgorithm.FriendlyName; SignatureOid = $c.SignatureAlgorithm.Value
            SelfIssued = [bool]$e.Info.SelfIssued; Lifecycle = $e.Lifecycle; CAName = $e.CAName; Ski = $ski; Aki = $aki; Certificate = $c
            InAIA = [bool]$e.InAIA; InNTAuth = [bool]$e.InNTAuth; Parents = @() }
    }
    $gens = @($gens)
    foreach ($g in $gens) {
        if ($g.SelfIssued) { continue }
        $g.Parents = @($gens | Where-Object { $_.Thumbprint -ne $g.Thumbprint -and (($g.Aki -and $_.Ski -eq $g.Aki) -or (-not $g.Aki -and $_.Subject -eq $g.Issuer)) })
    }
    foreach ($f in (Test-MspkiCaGeneration -Generations $gens -Now $now)) { [void]$out.Add($f) }
    foreach ($f in (Test-MspkiNtAuthAiaMatch -CACertificates $gens -Now $now)) { [void]$out.Add($f) }

    # URL design and retrieval order, per issuing CA: from the certificates it issued (exact order) and from its own URL properties.
    $urlOutcome = Get-MspkiRetrievalOutcome -Findings @($Findings)
    $issuers = @{}
    foreach ($g in @($gens | Where-Object { -not $_.SelfIssued -and $_.NotAfter -gt $now })) {
        $par = @($g.Parents) | Select-Object -First 1
        $iname = $(if ($null -ne $par -and $par.CAName) { $par.CAName } else { Get-MspkiShortName $g.Issuer })
        if (-not $issuers.ContainsKey($iname)) { $issuers[$iname] = @{ AIA = @(); CDP = @(); From = ''; Ids = @() } }
        $u = @(Get-MspkiCertificateUrl -Certificate $g.Certificate | ForEach-Object { $_ })
        $issuers[$iname].AIA += @($u | Where-Object { $_.Kind -eq 'AIA' } | ForEach-Object { $_.Url } | Where-Object { $issuers[$iname].AIA -notcontains $_ })
        $issuers[$iname].CDP += @($u | Where-Object { $_.Kind -eq 'CDP' } | ForEach-Object { $_.Url } | Where-Object { $issuers[$iname].CDP -notcontains $_ })
        if (-not $issuers[$iname].From) { $issuers[$iname].From = ('certificate {0} ({1}) issued by {2}' -f $g.Subject, $g.Thumbprint, $iname) }
    }
    $live = @{}
    if ($null -ne $Discovery.PSObject.Properties['CAProperties'] -and $Discovery.CAProperties -is [hashtable]) { $live = $Discovery.CAProperties }
    $ocspUrls = @(@($inv.Leads) | Where-Object { $_ -and $_.Kind -eq 'OCSP' } | ForEach-Object { $_.Url })
    foreach ($ca in @($inv.EnterpriseCAs | Where-Object { $_ })) {
        if (-not $live.ContainsKey($ca.Name)) { continue }
        $cur = @($live[$ca.Name].SigningCertificates) | Select-Object -Last 1
        if ($null -eq $cur) { continue }
        if (-not $issuers.ContainsKey($ca.Name)) { $issuers[$ca.Name] = @{ AIA = @(); CDP = @(); From = ''; Ids = @() } }
        if ($issuers[$ca.Name].AIA.Count -eq 0) { $issuers[$ca.Name].AIA = @($cur.AiaUrls | Where-Object { $_ }) }
        if ($issuers[$ca.Name].CDP.Count -eq 0) { $issuers[$ca.Name].CDP = @($cur.CdpUrls | Where-Object { $_ }) }
        if (-not $issuers[$ca.Name].From) { $issuers[$ca.Name].From = ('URL properties of {0} (what it writes into the certificates it issues)' -f $ca.Name) }
        $ocspUrls += @($cur.OcspUrls | Where-Object { $_ })
    }
    foreach ($iname in @($issuers.Keys | Sort-Object)) {
        $i = $issuers[$iname]
        $caId = Get-MspkiCAIdByName -Name $iname
        foreach ($k in @('AIA', 'CDP')) {
            $ids = @(@($caId) + @($i[$k] | ForEach-Object { Get-MspkiEndpointEntityId -Url $_ }) | Where-Object { $_ })
            $f = Test-MspkiPublicationProtocol -IssuerName $iname -Kind $k -Urls @($i[$k]) -Sources @('Analysis:Hierarchy', $i.From) -EntityIds $ids
            if ($null -ne $f) { $f.Evidence = [string[]](@($f.Evidence) + ('From: {0}' -f $i.From)); [void]$out.Add($f) }
            $f = Test-MspkiRetrievalOrder -IssuerName $iname -Kind $k -Urls @($i[$k]) -UrlOutcome $urlOutcome -From $i.From -EntityIds $ids
            if ($null -ne $f) { [void]$out.Add($f) }
        }
    }

    # Offline roots: a root that is not an Enterprise CA of this forest.
    $enterpriseNames = @($inv.EnterpriseCAs | ForEach-Object { $_.Name; $_.CommonName })
    foreach ($g in @($gens | Where-Object { $_.SelfIssued -and $_.NotAfter -gt $now })) {
        $name = $(if ($g.CAName) { $g.CAName } else { Get-MspkiShortName $g.Subject })
        if ($enterpriseNames -contains $name) { continue }
        $crlId = Get-MspkiCrlEntityId -AuthorityKeyId $g.Ski -IsDelta $false
        $crl = Get-MspkiEntity -Id $crlId
        $tu = $null; $nu = $null
        if ($null -ne $crl) { $tu = $crl.Properties['ThisUpdate']; $nu = $crl.Properties['NextUpdate'] }
        [void]$out.Add((Test-MspkiOfflineRootCrl -RootName $name -Thumbprint $g.Thumbprint -ThisUpdate $tu -NextUpdate $nu -CrlId $(if ($null -ne $crl) { $crlId } else { '' }) -Now $now))
    }

    # OCSP responders on proven PKI hosts (CA hosts), standard path only, anonymous GET.
    $caHosts = @($inv.EnterpriseCAs | Where-Object { $_.DnsHostName } | ForEach-Object { ([string]$_.DnsHostName).ToLowerInvariant() } | Select-Object -Unique)
    if (-not $SkipNetwork) {
        foreach ($h in $caHosts) {
            if (Test-MspkiCancelled) { break }
            $http = Invoke-MspkiHttpGet -Url ('http://{0}/ocsp/' -f $h) -TimeoutMs $ms -MaxRedirects 0 -DiscardBody
            $hid = Add-MspkiHostEntity -HostName $h
            if ([int]$http.HttpStatus -ge 200 -and [int]$http.HttpStatus -ne 404) {
                $eid = Add-MspkiEndpointEntity -Url ('http://{0}/ocsp/' -f $h) -Kind 'OCSP'
                $sid = Add-MspkiEntity -Type 'Service' -Key ('ocsp:' + $eid) -Name ('OCSP on {0}' -f $h) -Properties @{ Kind = 'OCSP'; Url = ('http://{0}/ocsp/' -f $h) }
                Add-MspkiObservation -EntityId $sid -Kind 'Seen' -Source 'HTTP' -Location $http.Url -Confidence 'Inferred' -Detail ('HTTP {0} on the standard path' -f $http.HttpStatus)
                Add-MspkiRelation -From $eid -Type 'servedBy' -To $sid -Source 'HTTP:StandardPath' -Confidence 'Inferred'
                Add-MspkiRelation -From $sid -Type 'hostedOn' -To $hid -Source 'HTTP:StandardPath'
                $f = Test-MspkiOcspResponderUse -HostName $h -Http $http -OcspUrls $ocspUrls -EntityIds @($sid, $hid)
                if ($null -ne $f) { [void]$out.Add($f) }
            }
        }
    }

    # HTTPS that closes every handshake (from what the other checks already probed).
    $hostCat = @{}
    foreach ($h in $caHosts) { $hostCat[$h] = 'CA' }
    foreach ($n in @($inv.NdesHosts | Where-Object { $_ })) { $hn = $(if ($n -is [string]) { $n } else { [string]$n.HostName }); if ($hn) { $hostCat[$hn.ToLowerInvariant()] = 'NDES' } }
    $tls = @(Get-MspkiProbeCacheEntryList -Prefix 'tls|')
    foreach ($f in (Test-MspkiTlsResetEndpoint -TlsResults $tls -HostCategory $hostCat)) { [void]$out.Add($f) }

    # Certificate names without DNS: server certificates seen in TLS handshakes and this computer's certificates from a discovered CA.
    $certs = New-Object System.Collections.ArrayList
    foreach ($t in @($tls | Where-Object { $_.Thumbprint -and @($_.DnsNames).Count -gt 0 })) {
        [void]$certs.Add([pscustomobject]@{ Subject = $t.Subject; Thumbprint = $t.Thumbprint; Where = ('served by {0}' -f $t.Target); Names = @($t.DnsNames); Host = ($t.Target -split ':')[0]; Local = $false; Certificate = $null })
    }
    try {
        foreach ($c in (Get-MspkiLocalIssuedCertificate -IssuerKeyIds @($gens | ForEach-Object { $_.Ski }))) {
            if (@($certs | Where-Object { $_.Thumbprint -eq $c.Thumbprint }).Count -gt 0) { continue }
            [void]$certs.Add([pscustomobject]@{ Subject = $c.Subject; Thumbprint = $c.Thumbprint; Where = 'LocalMachine\My on this computer'; Names = @(Get-MspkiCertificateDnsName -Certificate $c); Host = ''; Local = $true; Certificate = $c })
        }
    }
    catch { Write-MspkiLog -Level Warning -Message ('Local machine certificates not read: {0}' -f $_.Exception.Message) }
    foreach ($c in $certs) {
        $eid = ''
        if ($c.Local) {
            $eid = Add-MspkiEntity -Type 'LocalCertificate' -Key $c.Thumbprint -Name $c.Subject -Properties @{ Subject = $c.Subject; Issuer = $c.Certificate.Issuer; NotAfter = (Format-MspkiGraphDate $c.Certificate.NotAfter); DnsNames = @($c.Names) }
            Add-MspkiObservation -EntityId $eid -Kind 'Seen' -Source 'LocalStore' -Location 'Cert:\LocalMachine\My' -Confidence 'Confirmed'
            foreach ($p in (Get-MspkiCACertificateIdByKeyId -KeyId (Get-MspkiCertificateAuthorityKeyId -Certificate $c.Certificate))) { Add-MspkiRelation -From $eid -Type 'issuedBy' -To $p -Source 'Certificate:AuthorityKeyIdentifier' -Confidence 'Confirmed' }
        }
        $dns = @{}
        foreach ($n in @($c.Names | Where-Object { $_ -and $_ -notlike '*`**' })) {
            if ($SkipNetwork) { continue }
            $dns[$n] = Resolve-MspkiDnsName -HostName $n -TimeoutMs $ms
            $target = $(if ($c.Host) { Add-MspkiHostEntity -HostName $c.Host } else { @(Get-MspkiEntityList -Type 'Host' | Where-Object { @($_.Properties['Roles']) -contains 'ThisComputer' } | ForEach-Object { $_.Id }) | Select-Object -First 1 })
            if ($n -ne $c.Host -and $target -and $target -ne (Get-MspkiEntityId -Type 'Host' -Key $n)) {
                $aid = Add-MspkiEntity -Type 'Host' -Key $n -Name $n
                Add-MspkiRelation -From $aid -Type 'aliasOf' -To $target -Source ('Certificate:SAN:{0}' -f $c.Thumbprint)
                if ($dns[$n].StatusCode -eq 'DNS_FAIL') { Add-MspkiObservation -EntityId $aid -Kind 'ExpectedMissing' -Source 'DNS' -Location $n -Confidence 'Confirmed' -Detail ('Named in the SAN of {0}; no DNS record' -f $c.Thumbprint) }
            }
        }
        foreach ($f in (Test-MspkiSanDnsName -Subject $c.Subject -Thumbprint $c.Thumbprint -Where $c.Where -Names @($c.Names) -Dns $dns -EntityId $eid)) { [void]$out.Add($f) }
    }
    return $out.ToArray()
}
