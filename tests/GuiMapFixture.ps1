# Test helper: a generated LARGE environment (results.json format 2) for the discovery map, the Map page and the performance guards.
# Only reserved example.test names. Deterministic: the same parameters always give the same document.
# Dot-source it, then: $doc = New-MspkiTestLargeResults -CaCount 8 -EndpointCount 60 -ObjectCount 300

function New-MspkiTestLargeResults {
    param([int]$CaCount = 8, [int]$EndpointCount = 60, [int]$ObjectCount = 300, [int]$HostCount = 0, [switch]$WithUnreadCa)
    $dom = 'corp.example.test'
    $dc = 'DC=corp,DC=example,DC=test'
    $ents = New-Object System.Collections.ArrayList
    $rels = New-Object System.Collections.ArrayList
    $finds = New-Object System.Collections.ArrayList
    $addE = { param($id, $type, $name, $props) [void]$ents.Add([pscustomobject]@{ Id = $id; Type = $type; Name = $name; Properties = [pscustomobject]$props }) }
    $addR = { param($from, $type, $to) [void]$rels.Add([pscustomobject]@{ From = $from; Type = $type; To = $to }) }
    $addF = {
        param($cat, $status, [string[]]$ids, $msg, $target = '')
        $script:__fid++
        [void]$finds.Add([pscustomobject]@{ Id = ('F{0:0000}' -f $script:__fid); Category = $cat; Status = $status; Severity = 'None'; Confidence = 'Confirmed'; StatusCode = $(if ($status -eq 'Pass') { 'OK' } else { 'TEST' }); Message = $msg; Target = $target; Sources = @('TEST'); Evidence = @(); EntityIds = $ids; Remediation = ''; Notes = '' })
    }
    $script:__fid = 0
    & $addE ('forest:' + $dom) 'Forest' $dom @{ ForestMode = 'Windows2016Forest' }
    $roots = [math]::Max(1, [math]::Floor($CaCount / 4))
    $issuing = [math]::Max(1, $CaCount - $roots)
    $rootCert = @()
    for ($r = 0; $r -lt $roots; $r++) {
        $cid = 'cacert:root{0:00}' -f $r
        $subj = 'CN=Example Root CA {0:00}, {1}' -f $r, $dc
        & $addE $cid 'CACertificate' $subj @{ Subject = $subj; Issuer = $subj; Role = 'StandaloneRoot'; Lifecycle = 'Current'; NotBefore = '2016-01-01T00:00:00Z'; NotAfter = '2036-01-01T00:00:00Z' }
        $rootCert += $cid
    }
    $caIds = @(); $caCert = @{}
    for ($i = 0; $i -lt $issuing; $i++) {
        $hn = 'ca{0:00}.{1}' -f $i, $dom
        $nm = 'Example Issuing CA {0:00}' -f $i
        $id = ('ca:{0}\{1}' -f $hn, $nm).ToLowerInvariant()
        $unread = ($WithUnreadCa -and $i -eq ($issuing - 1))
        & $addE $id 'CA' $nm @{ CAType = 'EnterpriseSubordinate'; Config = ('{0}\{1}' -f $hn, $nm); DnsHostName = $hn; Kind = 'Enterprise'; PropertiesRead = (-not $unread) }
        & $addE ('host:' + $hn) 'Host' $hn @{ Roles = 'CA' }
        & $addR $id 'hostedOn' ('host:' + $hn)
        $caIds += $id
        if ($unread) { & $addF 'CA' 'Error' @($id) ('The properties of {0} could not be read.' -f $nm) $nm; continue }
        $cid = 'cacert:issuing{0:00}' -f $i
        $subj = 'CN={0}, {1}' -f $nm, $dc
        & $addE $cid 'CACertificate' $subj @{ Subject = $subj; Issuer = 'root'; Role = 'EnterpriseSubordinate'; CAName = $nm; Lifecycle = 'Current'; NotBefore = '2024-01-01T00:00:00Z'; NotAfter = '2029-01-01T00:00:00Z' }
        & $addR $cid 'certificateOf' $id
        & $addR $cid 'issuedBy' $rootCert[$i % $roots]
        $caCert[$id] = $cid
        & $addF 'CA' 'Pass' @($id) ('{0} answers.' -f $nm) $nm
    }
    if ($HostCount -le 0) { $HostCount = [math]::Max(3, [math]::Floor($EndpointCount / 6)) }
    $kinds = @('CDP', 'AIA', 'CDP', 'OCSP', 'AIA', 'CDP')
    $hostMade = @{}
    $readCas = @($caIds | Where-Object { $caCert.ContainsKey($_) })
    for ($e = 0; $e -lt $EndpointCount; $e++) {
        $owner = $readCas[$e % $readCas.Count]
        $kind = $kinds[$e % $kinds.Count]
        $ext = $(if ($kind -eq 'AIA') { 'crt' } elseif ($kind -eq 'CDP') { 'crl' } else { '' })
        if ($e % 10 -eq 7) {
            $url = 'ldap:///CN=Example Issuing CA {0:00} {1},CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,{2}?certificateRevocationList?base' -f ($e % $issuing), $e, $dc
            $eid = 'endpoint:' + $url.ToLowerInvariant()
            & $addE $eid 'Endpoint' $url @{ Url = $url; UrlType = 'Ldap'; Kinds = @('CDP'); Scope = 'Local' }
        }
        else {
            $hn = 'pki{0:00}.{1}' -f (($e * 7) % $HostCount), $dom
            $file = $(if ($ext) { 'Example Issuing CA {0:00} item {1}.{2}' -f ($e % $issuing), $e, $ext } else { 'ocsp{0}' -f $e })
            $url = 'http://{0}/{1}/{2}' -f $hn, $kind.ToLowerInvariant(), $file
            $eid = 'endpoint:web://' + ('{0}/{1}/{2}' -f $hn, $kind.ToLowerInvariant(), $file).ToLowerInvariant()
            & $addE $eid 'Endpoint' $url @{ Url = $url; UrlType = 'Http'; Kinds = @($kind); Scope = 'Local' }
            if (-not $hostMade.ContainsKey($hn)) { $hostMade[$hn] = $true; & $addE ('host:' + $hn) 'Host' $hn @{ Roles = 'Web' } }
            & $addR $eid 'hostedOn' ('host:' + $hn)
        }
        & $addR $caCert[$owner] 'references' $eid
        $st = $(if ($e % 9 -eq 4) { 'Fail' } elseif ($e % 5 -eq 2) { 'Warning' } else { 'Pass' })
        & $addF $kind $st @($eid) ('{0} address {1} checked.' -f $kind, $e) $url
    }
    $n = 0
    while ($ents.Count -lt $ObjectCount) {
        if ($n % 3 -eq 0) { & $addE ('template:t{0:000}' -f $n) 'Template' ('Template{0:000}' -f $n) @{ SchemaVersion = 2 }; & $addR ('template:t{0:000}' -f $n) 'enrollsVia' $readCas[$n % $readCas.Count] }
        else { & $addE ('adobject:cn=o{0:000},{1}' -f $n, $dc.ToLowerInvariant()) 'ADObject' ('CN=O{0:000},{1}' -f $n, $dc) @{ Kind = 'Container' }; & $addR ('adobject:cn=o{0:000},{1}' -f $n, $dc.ToLowerInvariant()) 'partOf' ('forest:' + $dom) }
        $n++
    }
    $inv = [pscustomobject]@{ AdContext = $null; PksExists = $true; Containers = @(); EnterpriseCAs = @($caIds | ForEach-Object { [pscustomobject]@{ Name = ($_ -split '\\')[1]; Config = ''; DnsHostName = ''; Templates = @(); EnrollmentServers = @(); Properties = $null } }); CACertificates = @(); Leads = @(); LeadStatistics = $null }
    $run = [pscustomobject]@{ RunId = '00000000-0000-4000-8000-000000000500'; Tool = 'MSPKI Health Check'; ToolVersion = '0.1.0'; StartedUtc = '2026-11-20T09:00:00Z'; FinishedUtc = '2026-11-20T09:02:00Z'; Completed = $true; ComputerName = 'CLIENT01'; UserContext = 'CORP\tester'; IsAdmin = $false; Forest = $dom; Domain = $dom; DomainController = ('dc01.' + $dom); Parameters = [pscustomobject]@{ TimeoutSeconds = '5'; SkipNetwork = 'False' }; StageTimings = @(); Methods = @(); Limits = @() }
    return [pscustomobject]@{
        Schema = 'mspki-healthcheck/2'; SchemaVersion = 2; RunInfo = $run; ExitCode = 2; Summary = $null; Inventory = $inv
        Graph = [pscustomobject]@{ SchemaVersion = 2; Counts = $null; Entities = @($ents); Observations = @(); Relations = @($rels) }
        Findings = @($finds)
    }
}
