# Developer-only (never shipped, never referenced by the product): adds CRL lifecycle data to the demo world's hand-made `mixed-sample`
# results and derives two more hand-made samples from it, for the Timeline and Chain views (GX7) and their snapshots:
#   demo\world\alcyone-mixed-results.json          the CRLs its findings already describe (numbers, this/next update), now as CRL objects
#   demo\world\alcyone-expired-crl-results.json    scenario `expired-crl`: the issuing CA's base CRL is 3 days past its next update
#   demo\world\alcyone-renewal-drift-results.json  scenario `renewal-drift`: a third CA generation; the expired first one still in NTAuth and AIA
# These are HAND-MADE samples (docs\DEMO-WORLD.md), not analyser output: the DS3 generator replaces them. Fictional world names only.
# Idempotent: running it again gives the same files. Windows PowerShell 5.1.
[CmdletBinding()]
param([string]$WorldFolder = '')
$ErrorActionPreference = 'Stop'
if (-not $WorldFolder) { $WorldFolder = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path))) 'demo\world' }
$base = Join-Path $WorldFolder 'alcyone-mixed-results.json'
$doc = Get-Content -LiteralPath $base -Raw | ConvertFrom-Json

$root = 'cacert:1a2b3c4d5e6f708192a3b4c5d6e7f80910111213'
$v0 = 'cacert:2b3c4d5e6f708192a3b4c5d6e7f8091011121314'
$v1 = 'cacert:3c4d5e6f708192a3b4c5d6e7f809101112131415'
$caM = 'ca:issuing-ca.vault.alcyone-orbital.example\alcyone meridian issuing ca'
$caCfg = 'issuing-ca.vault.alcyone-orbital.example\Alcyone Meridian Issuing CA'
$ski = @{ $root = '6F708192A3B4C5D6E7F809101112131415161718'; $v0 = '5E6F708192A3B4C5D6E7F8091011121314151617'; $v1 = '4D5E6F708192A3B4C5D6E7F80910111213141516' }
$rootDn = 'CN=Alcyone Lodestar Root CA, DC=alcyone-orbital, DC=example'
$subDn = 'CN=Alcyone Meridian Issuing CA, DC=alcyone-orbital, DC=example'
$ep = @{
    LdapCdp = 'endpoint:ldap:///cn=alcyone meridian issuing ca,cn=issuing-ca,cn=cdp,cn=public key services,cn=services,cn=configuration,dc=alcyone-orbital,dc=example?certificaterevocationlist?base?objectclass=crldistributionpoint'
    PkiCdp = 'endpoint:web://pki.alcyone-orbital.example/cdp/alcyone meridian issuing ca.crl'
    PkiDelta = 'endpoint:web://pki.alcyone-orbital.example/cdp/alcyone meridian issuing ca+.crl'
    DrCdp = 'endpoint:web://pki-dr.alcyone-orbital.example/cdp/alcyone meridian issuing ca.crl'
    RootCdp = 'endpoint:web://pki.alcyone-orbital.example/cdp/alcyone lodestar root ca.crl'
}

function Get-SampleEntity { param($Doc, [string]$Id) @($Doc.Graph.Entities | Where-Object { $_.Id -eq $Id })[0] }
function Get-SampleUrl { param($Doc, [string]$Id) [string](Get-SampleEntity -Doc $Doc -Id $Id).Properties.Url }
function Set-SampleProp { param($Obj, [string]$Name, $Value) $Obj | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force }

function Reset-SampleCrl {
    # Removes every CRL object, its observations and relations (so that the script can run again).
    param($Doc)
    $Doc.Graph.Entities = @($Doc.Graph.Entities | Where-Object { $_.Id -notlike 'crl:*' })
    $Doc.Graph.Observations = @($Doc.Graph.Observations | Where-Object { $_.EntityId -notlike 'crl:*' })
    $Doc.Graph.Relations = @($Doc.Graph.Relations | Where-Object { $_.From -notlike 'crl:*' -and $_.To -notlike 'crl:*' })
    foreach ($f in $Doc.Findings) { $f.EntityIds = @($f.EntityIds | Where-Object { $_ -notlike 'crl:*' }) }
}

function Add-SampleCrl {
    # One CRL object (newest copy on the object) and one observation per copy: @{ Where = 'CA' | endpoint id; Number; This; Next }.
    param($Doc, [string]$SignerId, [bool]$Delta, [string]$Issuer, [string]$Number, [string]$This, [string]$Next, [string]$Publish, [object[]]$Copies, [string]$Stamp)
    $aki = $ski[$SignerId]
    if (-not $aki) { $aki = [string](Get-SampleEntity -Doc $Doc -Id $SignerId).Properties.SubjectKeyId }
    $id = 'crl:{0}:{1}' -f $aki.ToLowerInvariant(), $(if ($Delta) { 'delta' } else { 'base' })
    $p = [ordered]@{ AuthorityKeyId = $aki; CAVersion = 'V0.0'; CrlNumber = $Number; IsDelta = $Delta; Issuer = $Issuer; NextUpdate = $Next; ThisUpdate = $This }
    if ($Publish) { $p['NextPublish'] = $Publish }
    $name = '{0} CRL of {1}' -f $(if ($Delta) { 'Delta' } else { 'Base' }), $Issuer
    $Doc.Graph.Entities = @($Doc.Graph.Entities) + [pscustomobject]@{ Id = $id; Type = 'CRL'; Name = $name; Properties = [pscustomobject]$p }
    $obs = @(); $rel = @()
    $rel += [pscustomobject]@{ From = $id; Type = 'signedBy'; To = $SignerId; Sources = @('CRL:AuthorityKeyIdentifier'); Confidence = 'Confirmed' }
    foreach ($c in $Copies) {
        if ($c.Where -eq 'CA') {
            $obs += [pscustomobject]@{ EntityId = $id; Kind = 'Seen'; Source = 'CA'; Location = $caCfg; Confidence = 'Confirmed'; Detail = ('The CA''s own current CRL: number {0}, this update {1}, next update {2}' -f $c.Number, $c.This, $c.Next); Timestamp = $Stamp }
            continue
        }
        $url = Get-SampleUrl -Doc $Doc -Id $c.Where
        $src = $(if ($url -like 'ldap:*') { 'LDAP' } else { 'HTTP' })
        if ($c.Missing) { $obs += [pscustomobject]@{ EntityId = $id; Kind = 'ExpectedMissing'; Source = $src; Location = $url; Confidence = 'Confirmed'; Detail = 'Named in CDP of a certificate; not retrieved from this location.'; Timestamp = $Stamp }; continue }
        $obs += [pscustomobject]@{ EntityId = $id; Kind = 'Seen'; Source = $src; Location = $url; Confidence = 'Confirmed'; Detail = ('CRL number {0}, this update {1}, next update {2}' -f $c.Number, $c.This, $c.Next); Timestamp = $Stamp }
        $rel += [pscustomobject]@{ From = $id; Type = 'publishedAt'; To = $c.Where; Sources = @($src); Confidence = 'Confirmed' }
    }
    $Doc.Graph.Observations = @($Doc.Graph.Observations) + $obs
    $Doc.Graph.Relations = @($Doc.Graph.Relations) + $rel
    return $id
}

function Add-SampleFindingLink { param($Doc, [string[]]$FindingIds, [string]$EntityId) foreach ($f in $Doc.Findings) { if ($FindingIds -contains $f.Id -and @($f.EntityIds) -notcontains $EntityId) { $f.EntityIds = @($f.EntityIds) + $EntityId } } }

function Set-SampleFinding {
    param($Doc, [string]$Id, [hashtable]$Values)
    $f = @($Doc.Findings | Where-Object { $_.Id -eq $Id })[0]
    foreach ($k in $Values.Keys) { Set-SampleProp -Obj $f -Name $k -Value $Values[$k] }
}

function Complete-SampleDocument {
    # Counts and the summary recomputed from the graph and the findings.
    param($Doc)
    # The hand-made file keeps its own order; new objects are appended (readers do not depend on the order).
    $g = $Doc.Graph
    $by = [ordered]@{}
    foreach ($t in @('Forest', 'Domain', 'CA', 'CACertificate', 'CRL', 'Endpoint', 'Host', 'Service', 'Template', 'LocalCertificate', 'ADObject', 'Account', 'RACertificate')) { $by[$t] = @($g.Entities | Where-Object { $_.Type -eq $t }).Count }
    $g.Counts = [pscustomobject][ordered]@{ Entities = @($g.Entities).Count; Observations = @($g.Observations).Count; Relations = @($g.Relations).Count
        ExpectedMissing = @($g.Observations | Where-Object { $_.Kind -eq 'ExpectedMissing' }).Count; ByType = [pscustomobject]$by }
    $s = $Doc.Summary
    $s.Total = @($Doc.Findings).Count
    foreach ($k in @($s.ByStatus.PSObject.Properties.Name)) { $s.ByStatus.$k = @($Doc.Findings | Where-Object { $_.Status -eq $k }).Count }
    foreach ($k in @($s.ByConfidence.PSObject.Properties.Name)) { $s.ByConfidence.$k = @($Doc.Findings | Where-Object { $_.Confidence -eq $k }).Count }
    $cats = [ordered]@{}; foreach ($f in $Doc.Findings) { $cats[[string]$f.Category] = 1 + [int]$cats[[string]$f.Category] }
    $s.ByCategory = [pscustomobject]$cats
}

function Save-SampleDocument {
    param($Doc, [string]$Path)
    $json = $Doc | ConvertTo-Json -Depth 30
    [System.IO.File]::WriteAllText($Path, ($json -replace "`r?`n", "`r`n") + "`r`n", (New-Object System.Text.UTF8Encoding($false)))
    Write-Output $Path
}

function Repair-SampleCdpReference {
    # A CA certificate's CDP names the CRL of ITS ISSUER (the root), not its own: the issuing CA's CRL addresses are what the CA writes into
    # the certificates it issues (its CertCdpUrls setting). The first hand-made sample had them on the CA certificate; move them to the CA.
    param($Doc, [string]$CertId, [string]$CaId, [string]$CaName, [string]$RootCdp)
    $keep = @(); $moved = @()
    foreach ($r in $Doc.Graph.Relations) {
        if ($r.From -eq $CertId -and $r.Type -eq 'references' -and $r.To -ne $RootCdp -and (@($r.Sources) -join ',') -match ':CDP$') { $moved += $r.To; continue }
        $keep += $r
    }
    foreach ($to in $moved) {
        if (@($keep | Where-Object { $_.From -eq $CaId -and $_.Type -eq 'references' -and $_.To -eq $to }).Count -eq 0) {
            $keep += [pscustomobject]@{ From = $CaId; Type = 'references'; To = $to; Sources = @(('CA:{0}:CertCdpUrls' -f $CaName)); Confidence = 'Referenced' }
        }
    }
    $thumb = ($CertId -replace '^cacert:', '').ToUpperInvariant()
    if (@($keep | Where-Object { $_.From -eq $CertId -and $_.Type -eq 'references' -and $_.To -eq $RootCdp }).Count -eq 0) {
        $keep += [pscustomobject]@{ From = $CertId; Type = 'references'; To = $RootCdp; Sources = @(('Cert:{0}:CDP' -f $thumb)); Confidence = 'Confirmed' }
    }
    $Doc.Graph.Relations = $keep
}

function Add-SampleLeaf {
    # The ground-station web server's Remote Desktop certificate (docs\DEMO-WORLD.md), in LocalMachine\My of the computer the tool ran on.
    param($Doc, [string]$IssuerId, [string]$Stamp)
    $id = 'localcert:9a8b7c6d5e4f30211203f4e5d6c7b8a99a8b7c6d'
    if (@($Doc.Graph.Entities | Where-Object { $_.Id -eq $id }).Count -gt 0) { return }
    $Doc.Graph.Entities = @($Doc.Graph.Entities) + [pscustomobject]@{ Id = $id; Type = 'LocalCertificate'; Name = 'CN=ground-web.alcyone-orbital.example'; Properties = [pscustomobject][ordered]@{
            DnsNames = @('ground-web.alcyone-orbital.example'); Issuer = $subDn; NotAfter = '2027-03-14T09:12:00Z'; NotBefore = '2026-03-14T09:12:00Z'; Origin = 'Group Policy (Remote Desktop certificate template)'
            Stores = @('Cert:\LocalMachine\My'); Subject = 'CN=ground-web.alcyone-orbital.example'; Template = 'Alcyone-RDPServerAuth' } }
    $Doc.Graph.Observations = @($Doc.Graph.Observations) + [pscustomobject]@{ EntityId = $id; Kind = 'Seen'; Source = 'LocalStore'; Location = 'Cert:\LocalMachine\My'; Confidence = 'Confirmed'; Detail = 'valid until 2027-03-14T09:12:00Z'; Timestamp = $Stamp }
    $Doc.Graph.Relations = @($Doc.Graph.Relations) + [pscustomobject]@{ From = $id; Type = 'issuedBy'; To = $IssuerId; Sources = @('Certificate:AuthorityKeyIdentifier'); Confidence = 'Confirmed' }
}

$stamp = '2026-11-20T09:31:00Z'
Repair-SampleCdpReference -Doc $doc -CertId $v1 -CaId $caM -CaName 'Alcyone Meridian Issuing CA' -RootCdp $ep.RootCdp
Add-SampleLeaf -Doc $doc -IssuerId $v1 -Stamp $stamp
# ---- mixed-sample: the key identifiers and the CRLs its findings describe ----
Reset-SampleCrl -Doc $doc
foreach ($id in @($root, $v0, $v1)) {
    $e = Get-SampleEntity -Doc $doc -Id $id
    Set-SampleProp -Obj $e.Properties -Name 'SubjectKeyId' -Value $ski[$id]
    if ($id -ne $root) { Set-SampleProp -Obj $e.Properties -Name 'AuthorityKeyId' -Value $ski[$root] }
}
$rootCrl = Add-SampleCrl -Doc $doc -SignerId $root -Delta $false -Issuer $rootDn -Number '0C' -This '2026-06-01T08:00:00Z' -Next '2027-06-01T08:00:00Z' -Publish '2027-05-01T08:00:00Z' -Stamp $stamp -Copies @(
    @{ Where = $ep.RootCdp; Number = '0C'; This = '2026-06-01T08:00:00Z'; Next = '2027-06-01T08:00:00Z' })
$baseCrl = Add-SampleCrl -Doc $doc -SignerId $v1 -Delta $false -Issuer $subDn -Number '42' -This '2026-11-18T22:00:00Z' -Next '2026-11-25T10:00:00Z' -Publish '2026-11-24T22:00:00Z' -Stamp $stamp -Copies @(
    @{ Where = 'CA'; Number = '42'; This = '2026-11-18T22:00:00Z'; Next = '2026-11-25T10:00:00Z' }
    @{ Where = $ep.LdapCdp; Number = '42'; This = '2026-11-18T22:00:00Z'; Next = '2026-11-25T10:00:00Z' }
    @{ Where = $ep.PkiCdp; Number = '42'; This = '2026-11-18T22:00:00Z'; Next = '2026-11-25T10:00:00Z' }
    @{ Where = $ep.DrCdp; Number = '41'; This = '2026-11-11T22:00:00Z'; Next = '2026-11-25T10:00:00Z' })
$deltaCrl = Add-SampleCrl -Doc $doc -SignerId $v1 -Delta $true -Issuer $subDn -Number '44' -This '2026-11-19T12:53:00Z' -Next '2026-11-20T13:53:00Z' -Publish '2026-11-20T12:53:00Z' -Stamp $stamp -Copies @(
    @{ Where = 'CA'; Number = '44'; This = '2026-11-19T12:53:00Z'; Next = '2026-11-20T13:53:00Z' }
    @{ Where = $ep.PkiDelta; Number = '43'; This = '2026-11-19T08:53:00Z'; Next = '2026-11-20T09:53:00Z' })
Add-SampleFindingLink -Doc $doc -FindingIds @('F0021', 'F0022', 'F0023', 'F0026') -EntityId $baseCrl
Add-SampleFindingLink -Doc $doc -FindingIds @('F0024', 'F0025') -EntityId $deltaCrl
Complete-SampleDocument -Doc $doc
Save-SampleDocument -Doc $doc -Path $base

# ---- expired-crl: the issuing CA's base CRL is 3 days past its next update, in AD, on the web and at the CA ----
$x = $doc | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$x.RunInfo.RunId = '00000000-0000-4000-8000-000000000002'
Reset-SampleCrl -Doc $x
$rootCrl = Add-SampleCrl -Doc $x -SignerId $root -Delta $false -Issuer $rootDn -Number '0C' -This '2026-06-01T08:00:00Z' -Next '2027-06-01T08:00:00Z' -Publish '2027-05-01T08:00:00Z' -Stamp $stamp -Copies @(
    @{ Where = $ep.RootCdp; Number = '0C'; This = '2026-06-01T08:00:00Z'; Next = '2027-06-01T08:00:00Z' })
$t = '2026-11-10T08:00:00Z'; $n = '2026-11-17T08:00:00Z'
$baseCrl = Add-SampleCrl -Doc $x -SignerId $v1 -Delta $false -Issuer $subDn -Number '42' -This $t -Next $n -Publish '2026-11-16T20:00:00Z' -Stamp $stamp -Copies @(
    @{ Where = 'CA'; Number = '42'; This = $t; Next = $n }
    @{ Where = $ep.LdapCdp; Number = '42'; This = $t; Next = $n }
    @{ Where = $ep.PkiCdp; Number = '42'; This = $t; Next = $n }
    @{ Where = $ep.DrCdp; Number = '41'; This = '2026-11-03T09:30:00Z'; Next = '2026-11-10T09:30:00Z' })
$deltaCrl = Add-SampleCrl -Doc $x -SignerId $v1 -Delta $true -Issuer $subDn -Number '44' -This '2026-11-19T12:53:00Z' -Next '2026-11-20T13:53:00Z' -Publish '2026-11-20T12:53:00Z' -Stamp $stamp -Copies @(
    @{ Where = 'CA'; Number = '44'; This = '2026-11-19T12:53:00Z'; Next = '2026-11-20T13:53:00Z' }
    @{ Where = $ep.PkiDelta; Number = '44'; This = '2026-11-19T12:53:00Z'; Next = '2026-11-20T13:53:00Z' })
$pkiUrl = 'http://pki.alcyone-orbital.example/cdp/Alcyone Meridian Issuing CA.crl'
$ldapUrl = Get-SampleUrl -Doc $x -Id $ep.LdapCdp
$ldapShown = [System.Uri]::UnescapeDataString($ldapUrl)
Set-SampleFinding -Doc $x -Id 'F0021' -Values @{ Status = 'Critical'; StatusCode = 'OBJECT_EXPIRED'; Severity = 'High'; ContentStatus = 'Fail'; Message = ('Base CRL of {0} at {1} has expired ({2}).' -f $subDn, $pkiUrl, $n)
    Evidence = @(('Location: {0}' -f $pkiUrl), ('CRL number: 42; this update {0}; next update {1}' -f $t, $n), 'Validity: 168 h; used 100%; expired 72 h ago'); Remediation = 'Publish a new CRL from the CA now (the CA command-line tool, -CRL), then check that every CDP location serves it.' }
Set-SampleFinding -Doc $x -Id 'F0023' -Values @{ Status = 'Critical'; StatusCode = 'OBJECT_EXPIRED'; Severity = 'High'; ContentStatus = 'Fail'; Message = ('Base CRL of {0} at {1} has expired ({2}).' -f $subDn, $ldapShown, $n)
    Evidence = @(('CRL number 42 at the LDAP location; next update {0}' -f $n)); Remediation = 'Publish a new CRL from the CA now, then let Active Directory replicate it.' }
Set-SampleFinding -Doc $x -Id 'F0022' -Values @{ Status = 'Fail'; StatusCode = 'PUBLICATION_FAIL'; Severity = 'High'
    Message = 'http://pki-dr.alcyone-orbital.example/cdp/Alcyone Meridian Issuing CA.crl serves base CRL number 41 but the CA holds number 42: the CRL it serves has already expired.'
    Evidence = @('Location: http://pki-dr.alcyone-orbital.example/cdp/Alcyone Meridian Issuing CA.crl', ('CA''s own CRL number: 42; this update {0}' -f $t), 'Location serves CRL number: 41; this update 2026-11-03T09:30:00Z; next update 2026-11-10T09:30:00Z', 'Reasoning: the CRL it serves has already expired') }
Set-SampleFinding -Doc $x -Id 'F0024' -Values @{ Status = 'Pass'; StatusCode = 'OK'; Severity = 'None'; Message = 'http://pki.alcyone-orbital.example/cdp/Alcyone Meridian Issuing CA+.crl serves the same delta CRL number (44) as the CA: it was published correctly.'; Evidence = @('CRL number 44 at this location equals the CA number.') }
Set-SampleFinding -Doc $x -Id 'F0026' -Values @{ Status = 'Critical'; StatusCode = 'OBJECT_EXPIRED'; Severity = 'High'
    Message = ('CA''s own current base CRL of {0} at CA property BaseCRL[1] has expired ({1}): the CA has not published a new base CRL for 3 days.' -f $subDn, $n)
    Evidence = @(('This update {0}; next update {1}; Next CRL Publish 2026-11-16T20:00:00Z' -f $t, $n), 'Validity: 168 h; expired 72 h ago')
    Remediation = 'On the CA: check that the Active Directory Certificate Services service runs and that its CRL publication schedule (CRLPeriod) is intact, then publish a new CRL.' }
Add-SampleFindingLink -Doc $x -FindingIds @('F0021', 'F0022', 'F0023', 'F0026') -EntityId $baseCrl
Add-SampleFindingLink -Doc $x -FindingIds @('F0024', 'F0025') -EntityId $deltaCrl
Complete-SampleDocument -Doc $x
Save-SampleDocument -Doc $x -Path (Join-Path $WorldFolder 'alcyone-expired-crl-results.json')

# ---- renewal-drift: a third generation (new key); the first one expired but is still in NTAuth and AIA ----
$r = $doc | ConvertTo-Json -Depth 30 | ConvertFrom-Json
$r.RunInfo.RunId = '00000000-0000-4000-8000-000000000003'
Reset-SampleCrl -Doc $r
$v2 = 'cacert:4e5f708192a3b4c5d6e7f8091011121314151617'
$ski[$v2] = '7A8B9C0D1E2F708192A3B4C5D6E7F80910111213'
$v1e = Get-SampleEntity -Doc $r -Id $v1
Set-SampleProp -Obj $v1e.Properties -Name 'Lifecycle' -Value 'Historical'
$r.Graph.Entities = @($r.Graph.Entities) + [pscustomobject]@{ Id = $v2; Type = 'CACertificate'; Name = $subDn; Properties = [pscustomobject][ordered]@{
        AuthorityKeyId = $ski[$root]; CAName = 'Alcyone Meridian Issuing CA'; Generation = 'V2.2'; Issuer = $rootDn; Lifecycle = 'Current'; LifecycleConfidence = 'Confirmed'
        NotAfter = '2028-10-30T10:00:00Z'; NotBefore = '2026-10-30T10:00:00Z'; Role = 'EnterpriseSubordinate'; Subject = $subDn; SubjectKeyId = $ski[$v2] } }
$copyRel = @($r.Graph.Relations | Where-Object { $_.From -eq $v1 -and $_.Type -eq 'references' })
$newRel = @(
    [pscustomobject]@{ From = $v2; Type = 'certificateOf'; To = $caM; Sources = @(); Confidence = 'Referenced' }
    [pscustomobject]@{ From = $v2; Type = 'issuedBy'; To = $root; Sources = @('Certificate:AuthorityKeyIdentifier'); Confidence = 'Confirmed' }
    [pscustomobject]@{ From = $v2; Type = 'supersedes'; To = $v1; Sources = @('Certificate:NotBefore'); Confidence = 'Inferred' })
foreach ($c in $copyRel) { $newRel += [pscustomobject]@{ From = $v2; Type = 'references'; To = $c.To; Sources = @(([string]@($c.Sources)[0]) -replace '3C4D5E6F708192A3B4C5D6E7F809101112131415', '4E5F708192A3B4C5D6E7F8091011121314151617'); Confidence = $c.Confidence } }
$r.Graph.Relations = @($r.Graph.Relations) + $newRel
$r.Graph.Observations = @($r.Graph.Observations) + @(
    [pscustomobject]@{ EntityId = $v2; Kind = 'Seen'; Source = 'AD'; Location = 'AD:AIA'; Confidence = 'Confirmed'; Detail = 'AD:AIA'; Timestamp = $stamp }
    [pscustomobject]@{ EntityId = $v2; Kind = 'Seen'; Source = 'AD'; Location = 'AD:NTAuthCertificates'; Confidence = 'Confirmed'; Detail = 'AD:NTAuthCertificates'; Timestamp = $stamp }
    [pscustomobject]@{ EntityId = $v2; Kind = 'Seen'; Source = 'CA'; Location = $caCfg; Confidence = 'Confirmed'; Detail = 'CA signing certificate list (GetCAProperty)'; Timestamp = $stamp }
    [pscustomobject]@{ EntityId = $v0; Kind = 'Seen'; Source = 'AD'; Location = 'AD:NTAuthCertificates'; Confidence = 'Confirmed'; Detail = 'AD:NTAuthCertificates'; Timestamp = $stamp })
$inv = @($r.Inventory.CACertificates)
foreach ($c in $inv) { if ($c.Thumbprint -eq '3C4D5E6F708192A3B4C5D6E7F809101112131415') { $c.Lifecycle = 'Historical'; $c.LifecycleBasis = 'CA reports state Valid (not the newest)'; $c.Info.DaysLeft = 893 } }
$r.Inventory.CACertificates = $inv + [pscustomobject]@{ Thumbprint = '4E5F708192A3B4C5D6E7F8091011121314151617'; CAName = 'Alcyone Meridian Issuing CA'; Role = 'EnterpriseSubordinate'; RoleBasis = 'CA properties'
    Lifecycle = 'Current'; LifecycleBasis = 'CA reports state Valid'; LifecycleConfidence = 'Confirmed'; Generation = 'V2.2'; ComState = 'Valid'; ComCrlState = 'Valid'; Sources = @('AD:EnrollmentServices', 'AD:AIA', 'AD:NTAuthCertificates', 'CA:GetCAProperty')
    Info = [pscustomobject]@{ Subject = $subDn; Issuer = $rootDn; Thumbprint = '4E5F708192A3B4C5D6E7F8091011121314151617'; NotBefore = '2026-10-30T10:00:00Z'; NotAfter = '2028-10-30T10:00:00Z'; DaysLeft = 710 } }
$rootCrl = Add-SampleCrl -Doc $r -SignerId $root -Delta $false -Issuer $rootDn -Number '0C' -This '2026-06-01T08:00:00Z' -Next '2027-06-01T08:00:00Z' -Publish '2027-05-01T08:00:00Z' -Stamp $stamp -Copies @(
    @{ Where = $ep.RootCdp; Number = '0C'; This = '2026-06-01T08:00:00Z'; Next = '2027-06-01T08:00:00Z' })
# The CA signs a CRL with every key that is still valid: the new key's CRLs and the previous key's base CRL.
$baseNew = Add-SampleCrl -Doc $r -SignerId $v2 -Delta $false -Issuer $subDn -Number '05' -This '2026-11-18T22:00:00Z' -Next '2026-11-25T10:00:00Z' -Publish '2026-11-24T22:00:00Z' -Stamp $stamp -Copies @(
    @{ Where = 'CA'; Number = '05'; This = '2026-11-18T22:00:00Z'; Next = '2026-11-25T10:00:00Z' }
    @{ Where = $ep.LdapCdp; Number = '05'; This = '2026-11-18T22:00:00Z'; Next = '2026-11-25T10:00:00Z' }
    @{ Where = $ep.PkiCdp; Number = '05'; This = '2026-11-18T22:00:00Z'; Next = '2026-11-25T10:00:00Z' }
    @{ Where = $ep.DrCdp; Number = '04'; This = '2026-11-11T22:00:00Z'; Next = '2026-11-25T10:00:00Z' })
$deltaNew = Add-SampleCrl -Doc $r -SignerId $v2 -Delta $true -Issuer $subDn -Number '07' -This '2026-11-19T12:53:00Z' -Next '2026-11-20T13:53:00Z' -Publish '2026-11-20T12:53:00Z' -Stamp $stamp -Copies @(
    @{ Where = 'CA'; Number = '07'; This = '2026-11-19T12:53:00Z'; Next = '2026-11-20T13:53:00Z' }
    @{ Where = $ep.PkiDelta; Number = '06'; This = '2026-11-19T08:53:00Z'; Next = '2026-11-20T09:53:00Z' })
$baseOld = Add-SampleCrl -Doc $r -SignerId $v1 -Delta $false -Issuer $subDn -Number '43' -This '2026-11-18T22:00:00Z' -Next '2026-11-25T10:00:00Z' -Publish '2026-11-24T22:00:00Z' -Stamp $stamp -Copies @(
    @{ Where = 'CA'; Number = '43'; This = '2026-11-18T22:00:00Z'; Next = '2026-11-25T10:00:00Z' })
Set-SampleFinding -Doc $r -Id 'F0014' -Values @{ Message = 'CA certificate V2.2 of Alcyone Meridian Issuing CA is valid for 710 more days.'; Evidence = @('Thumbprint (SHA-1): 4E5F708192A3B4C5D6E7F8091011121314151617', 'Valid 2026-10-30T10:00:00Z to 2028-10-30T10:00:00Z', 'Thresholds (subordinate CA): warning 180 days, critical 90 days') }
$drift = @($r.Findings | Where-Object { $_.Id -eq 'F0016' })[0] | ConvertTo-Json -Depth 10 | ConvertFrom-Json
$drift.Id = 'F0031'; $drift.Category = 'Hierarchy'; $drift.Target = 'NTAuthCertificates'; $drift.Status = 'Warning'; $drift.StatusCode = 'STALE_REFERENCE'; $drift.Severity = 'Medium'; $drift.Confidence = 'Confirmed'
$drift.Sources = @('AD:NTAuthCertificates', 'AD:AIA')
$drift.Message = 'The expired generation V0.0 of Alcyone Meridian Issuing CA (expired 2024-05-02) is still in NTAuth and in the AIA container.'
$drift.Evidence = @('Thumbprint (SHA-1): 2B3C4D5E6F708192A3B4C5D6E7F8091011121314', 'In NTAuth: yes; in AIA: yes; valid 2019-05-02 to 2024-05-02', 'Newer generations: V1.0 (replaced, valid to 2029-05-02) and V2.2 (current, valid to 2028-10-30)')
$drift.Remediation = 'Remove the expired generation from NTAuth (owner: the Enterprise PKI console, Manage AD Containers > NTAuthCertificates). Keep it in AIA only while certificates it issued are still checked.'
$drift.Notes = 'An expired CA certificate in NTAuth is not trusted for logon any more, but it hides which generations are really in use.'
$drift.EntityIds = @($v0, $caM)
$r.Findings = @($r.Findings | Where-Object { $_.Id -ne 'F0030' }) + $drift + @($r.Findings | Where-Object { $_.Id -eq 'F0030' })
Add-SampleFindingLink -Doc $r -FindingIds @('F0021', 'F0022', 'F0023', 'F0026') -EntityId $baseNew
Add-SampleFindingLink -Doc $r -FindingIds @('F0024', 'F0025') -EntityId $deltaNew
Complete-SampleDocument -Doc $r
Save-SampleDocument -Doc $r -Path (Join-Path $WorldFolder 'alcyone-renewal-drift-results.json')
