# Tests for the GUI object views (src/Gui/GuiEntity.ps1, WP5): graph index, object details with "where this exists" (seen and expected but
# missing), related objects in both directions, host identity rows, breadcrumbs and the Objects list. Pure helpers; example.test data only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $gui = Join-Path $script:RepoRoot 'src\Gui'
    . (Join-Path $gui 'GuiModel.ps1')
    . (Join-Path $gui 'GuiView.ps1')
    . (Join-Path $gui 'GuiEntity.ps1')
    $script:graph = ConvertFrom-MspkiJson -Text @'
{ "Entities": [
    { "Id": "ca:ca01.corp.example.test\\example issuing ca", "Type": "CA", "Name": "Example Issuing CA", "Properties": { "Config": "ca01.corp.example.test\\Example Issuing CA" } },
    { "Id": "cacert:aa", "Type": "CACertificate", "Name": "CN=Example Issuing CA", "Properties": { "NotAfter": "2030-01-01T00:00:00Z", "Lifecycle": "Current" } },
    { "Id": "host:ca01.corp.example.test", "Type": "Host", "Name": "ca01.corp.example.test", "Properties": { "A": ["192.0.2.10"], "Ptr": [ { "Address": "192.0.2.10", "Names": [], "Lookup": "NoRecord" } ],
      "AliasChain": ["pki.example.test", "ca01.corp.example.test"], "TlsCertificates": [ { "Port": "443", "Subject": "CN=ca01.corp.example.test", "DnsNames": ["ca01.corp.example.test"] } ], "HttpServer": ["Microsoft-IIS/10.0"], "DnsMethod": "DnsClient" } }
  ],
  "Observations": [
    { "EntityId": "cacert:aa", "Kind": "Seen", "Source": "AD", "Location": "CN=AIA,CN=Public Key Services", "Confidence": "Confirmed", "Detail": "", "Timestamp": "2026-11-22T00:00:00Z" },
    { "EntityId": "cacert:aa", "Kind": "ExpectedMissing", "Source": "LocalStore", "Location": "Cert:\\LocalMachine\\NTAuth", "Confidence": "Confirmed", "Detail": "Published in AD NTAuthCertificates; not in this computer's store", "Timestamp": "2026-11-22T00:00:00Z" }
  ],
  "Relations": [
    { "From": "cacert:aa", "Type": "certificateOf", "To": "ca:ca01.corp.example.test\\example issuing ca", "Sources": ["test"], "Confidence": "Confirmed" },
    { "From": "ca:ca01.corp.example.test\\example issuing ca", "Type": "hostedOn", "To": "host:ca01.corp.example.test", "Sources": ["test"], "Confidence": "Confirmed" }
  ] }
'@
    $script:findings = @([pscustomobject]@{ Id = 'F-1'; Status = 'Warning'; EntityIds = @('cacert:aa') })
    $script:rows = @{ 'F-1' = [pscustomobject]@{ Id = 'F-1'; StatusRank = 3; StatusPill = $null; Message = 'm' } }
}

Describe 'Object views' {
    It 'indexes entities, relations both ways, observations and findings' {
        $ix = New-MspkiGuiGraphIndex -Graph $script:graph -Findings $script:findings
        $ix.Entities.Count | Should -Be 3
        $ix.Out['cacert:aa'].Count | Should -Be 1
        $ix.In['host:ca01.corp.example.test'].Count | Should -Be 1
        $ix.Findings['cacert:aa'] | Should -Be @('F-1')
        New-MspkiGuiGraphIndex -Graph $null | Should -BeNullOrEmpty
    }

    It 'shows where an object was seen and, marked apart, where it is expected but missing' {
        $ix = New-MspkiGuiGraphIndex -Graph $script:graph -Findings $script:findings
        $p = Get-MspkiGuiEntityPane -Index $ix -Id 'cacert:aa' -RowById $script:rows -Trail @('ca:ca01.corp.example.test\example issuing ca', 'cacert:aa')
        $p.Kind | Should -Be 'Entity'
        $p.TypeText | Should -Be 'CA certificate'
        $p.HasAbout | Should -BeTrue
        @($p.Seen).Count | Should -Be 1
        @($p.Missing).Count | Should -Be 1
        $p.Missing[0].KindText | Should -Match 'MISSING'
        $p.Missing[0].IsMissing | Should -BeTrue
        $p.Related[0].Label | Should -Be 'Certificate of'
        $p.Related[0].Tag | Should -Be 'ent:ca:ca01.corp.example.test\example issuing ca'
        $p.FindingCount | Should -Be 1
        @($p.Breadcrumbs).Count | Should -Be 1
        $p.CanGoBack | Should -BeTrue
        $p.CopyText | Should -Match 'MISSING: LocalStore'
    }

    It 'names the reverse direction of a relation, and gives host identity rows for a host' {
        $ix = New-MspkiGuiGraphIndex -Graph $script:graph
        $h = Get-MspkiGuiEntityPane -Index $ix -Id 'host:ca01.corp.example.test'
        $h.Related[0].Label | Should -Be 'Hosts'
        $h.HasHostFacts | Should -BeTrue
        $facts = @{}; foreach ($f in $h.HostFacts) { $facts[$f.Name] = $f.Value }
        $facts['IP addresses'] | Should -Be '192.0.2.10'
        $facts['Reverse DNS (PTR)'] | Should -Match 'no PTR record'
        $facts['Alias chain'] | Should -Be 'pki.example.test > ca01.corp.example.test'
        $facts['TLS certificate names'] | Should -Match 'CN=ca01.corp.example.test'
        $facts['Server header'] | Should -Be 'Microsoft-IIS/10.0'
        $c = Get-MspkiGuiEntityPane -Index $ix -Id 'ca:ca01.corp.example.test\example issuing ca'
        $c.HasHostFacts | Should -BeFalse
    }

    It 'gives a plain view for an unknown object or results without a graph, and lists objects by type' {
        $ix = New-MspkiGuiGraphIndex -Graph $script:graph
        (Get-MspkiGuiEntityPane -Index $ix -Id 'host:other.example.test').Known | Should -BeFalse
        (Get-MspkiGuiEntityPane -Index $null -Id 'x').TypeText | Should -Be 'Not in this run'
        $list = @(Get-MspkiGuiObjectList -Index $ix)
        $list.Count | Should -Be 3
        $list[0].Type | Should -Be 'CA'
        ($list | Where-Object { $_.Id -eq 'cacert:aa' }).HasMissing | Should -BeTrue
        @(Get-MspkiGuiObjectList -Index $null).Count | Should -Be 0
        @(Get-MspkiGuiEntityLink -Index $ix -Ids @('cacert:aa', 'missing:id')).Count | Should -Be 1
    }

    It 'filters the Objects list by words, type and "needs attention", and offers the types that occur' {
        $ix = New-MspkiGuiGraphIndex -Graph $script:graph -Findings $script:findings
        $rows = @{ 'F-1' = [pscustomobject]@{ Id = 'F-1'; StatusRank = 3; Status = 'Warning' } }
        $list = @(Get-MspkiGuiObjectList -Index $ix -RowById $rows)
        $cert = $list | Where-Object { $_.Id -eq 'cacert:aa' }
        $cert.FindingPill.Text | Should -Be '1 finding'
        $cert.MissingPill.Text | Should -Be '1 missing'
        $cert.NeedsAttention | Should -BeTrue
        ($list | Where-Object { $_.Type -eq 'Host' }).NeedsAttention | Should -BeFalse
        @($list | Where-Object { Test-MspkiGuiObjectFilter -Row $_ -Text 'CA01 corp' }).Count | Should -Be 2
        @($list | Where-Object { Test-MspkiGuiObjectFilter -Row $_ -Type 'Host' }).Count | Should -Be 1
        @($list | Where-Object { Test-MspkiGuiObjectFilter -Row $_ -Type 'All' -AttentionOnly }).Count | Should -Be 1
        @($list | Where-Object { Test-MspkiGuiObjectFilter -Row $_ -Text 'no-such-thing' }).Count | Should -Be 0
        Get-MspkiGuiObjectTypeChoice -Rows $list | Should -Be @('All', 'Certification authority', 'CA certificate', 'Host')
    }

    It 'keeps a breadcrumb trail: push, push again to an earlier object, back and jump to a crumb' {
        $t = Step-MspkiGuiTrail -Trail @() -Action Push -Id 'a'
        $t = Step-MspkiGuiTrail -Trail $t -Action Push -Id 'b'
        $t = Step-MspkiGuiTrail -Trail $t -Action Push -Id 'c'
        $t | Should -Be @('a', 'b', 'c')
        Step-MspkiGuiTrail -Trail $t -Action Push -Id 'a' | Should -Be @('a')
        Step-MspkiGuiTrail -Trail $t -Action Back | Should -Be @('a', 'b')
        @(Step-MspkiGuiTrail -Trail @('a') -Action Back).Count | Should -Be 0
        Step-MspkiGuiTrail -Trail $t -Action Crumb -Index 1 | Should -Be @('a', 'b')
        Step-MspkiGuiTrail -Trail $t -Action Crumb -Index 9 | Should -Be @('a', 'b', 'c')
    }

    It 'says where Back goes: the previous object, or the finding or map item the user came from' {
        $ix = New-MspkiGuiGraphIndex -Graph $script:graph
        $one = Get-MspkiGuiEntityPane -Index $ix -Id 'cacert:aa' -Trail @('cacert:aa')
        $one.CanGoBack | Should -BeFalse
        $one.ShowCrumbs | Should -BeFalse
        $from = Get-MspkiGuiEntityPane -Index $ix -Id 'cacert:aa' -Trail @('cacert:aa') -OriginText 'Back to the finding'
        $from.CanGoBack | Should -BeTrue
        $from.BackText | Should -Be 'Back to the finding'
        $two = Get-MspkiGuiEntityPane -Index $ix -Id 'host:ca01.corp.example.test' -Trail @('cacert:aa', 'host:ca01.corp.example.test')
        $two.BackText | Should -Be 'Back to CN=Example Issuing CA'
        $two.ShowCrumbs | Should -BeFalse
        $three = Get-MspkiGuiEntityPane -Index $ix -Id 'host:other.example.test' -Trail @('cacert:aa', 'host:ca01.corp.example.test', 'host:other.example.test')
        $three.ShowCrumbs | Should -BeTrue
        @($three.Breadcrumbs).Count | Should -Be 2
        $three.Breadcrumbs[1].Tag | Should -Be 'crumb:1'
        $c = Get-MspkiGuiEntityPane -Index $ix -Id 'cacert:aa'
        $c.MissingBadge | Should -Be 'Missing in 1 expected place'
        $c.SeenBadge | Should -Be 'Seen or named in 1 place'
        $c.Seen[0].TimeText | Should -Be '2026-11-22 00:00:00 UTC'
    }

    It 'finds the objects behind Discovery map items and adds them as links to a pane' {
        $ix = New-MspkiGuiGraphIndex -Graph $script:graph
        $ca = [pscustomobject]@{ Type = 'CA'; Label = 'Example Issuing CA'; Detail = @('Host: ca01.corp.example.test', 'CA configuration: ca01.corp.example.test\Example Issuing CA'); FindingIds = @() }
        Get-MspkiGuiNodeEntityId -Index $ix -Node $ca | Should -Be @('ca:ca01.corp.example.test\example issuing ca')
        $byName = [pscustomobject]@{ Type = 'CA'; Label = 'example issuing ca'; Detail = @(); FindingIds = @() }
        Get-MspkiGuiNodeEntityId -Index $ix -Node $byName | Should -Be @('ca:ca01.corp.example.test\example issuing ca')
        $cert = [pscustomobject]@{ Type = 'Certificate'; Label = 'CA certificate'; Detail = @('Thumbprint (SHA-1): AA'); FindingIds = @() }
        Get-MspkiGuiNodeEntityId -Index $ix -Node $cert | Should -Be @('cacert:aa')
        $group = [pscustomobject]@{ Type = 'Group'; Label = 'CRLs held by the CA (1)'; Detail = @(); FindingIds = @('F-1') }
        Get-MspkiGuiNodeEntityId -Index $ix -Node $group -RowById @{ 'F-1' = [pscustomobject]@{ Finding = $script:findings[0] } } | Should -Be @('cacert:aa')
        @(Get-MspkiGuiNodeEntityId -Index $null -Node $ca).Count | Should -Be 0
        $pane = Add-MspkiGuiPaneObject -Pane ([pscustomobject]@{ Kind = 'Node' }) -Index $ix -Ids @('cacert:aa', 'unknown:x')
        $pane.HasObjects | Should -BeTrue
        $pane.ObjectCount | Should -Be 1
        $pane.Objects[0].Tag | Should -Be 'ent:cacert:aa'
        @(Find-MspkiGuiEntityId -Index $ix -Name 'CA01.corp.example.test' -Type 'Host').Count | Should -Be 1
    }

    It 'builds a view for every object of the format-2 example fixture, and finds an endpoint behind its map item' {
        $doc = ConvertFrom-MspkiResultsDocument -Document (Read-MspkiResultsJson -Path (Join-Path $PSScriptRoot 'fixtures\demo-results-v2.json'))
        $ix = New-MspkiGuiGraphIndex -Graph $doc.Graph -Findings @($doc.Findings)
        $ix.Entities.Count | Should -BeGreaterThan 20
        foreach ($id in @($ix.Entities.Keys)) { (Get-MspkiGuiEntityPane -Index $ix -Id $id).Known | Should -BeTrue }
        $h = @(Get-MspkiGuiObjectList -Index $ix | Where-Object { $_.Type -eq 'Host' })[0]
        (Get-MspkiGuiEntityPane -Index $ix -Id $h.Id).HasHostFacts | Should -BeTrue
        $tree = ConvertTo-MspkiGuiTreeNode -Node (Get-MspkiDiscoveryTree -Inventory $doc.Inventory -Findings @($doc.Findings) -RunInfo $doc.RunInfo)
        $stack = New-Object System.Collections.Stack; $stack.Push($tree); $ep = $null
        while ($stack.Count -gt 0 -and $null -eq $ep) { $n = $stack.Pop(); if ($n.Type -eq 'Endpoint' -and $n.Label -match 'https?://') { $ep = $n } else { foreach ($c in @($n.Children)) { $stack.Push($c) } } }
        $ep | Should -Not -BeNullOrEmpty
        @(Get-MspkiGuiNodeEntityId -Index $ix -Node $ep).Count | Should -BeGreaterThan 0
    }

    It 'builds the PKI services page: found, named only, not found, cannot be checked from here, and not checked' {
        $g = ConvertFrom-MspkiJson -Text @'
{ "Entities": [
    { "Id": "service:ndes:scep-gw01.corp.example.test", "Type": "Service", "Name": "NDES / SCEP on scep-gw01.corp.example.test", "Properties": { "Kind": "NDES", "HostName": "scep-gw01.corp.example.test" } },
    { "Id": "host:scep-gw01.corp.example.test", "Type": "Host", "Name": "scep-gw01.corp.example.test", "Properties": {} },
    { "Id": "service:cep:x", "Type": "Service", "Name": "CEP https://cep.example.test/policy", "Properties": { "Kind": "CEP", "Url": "https://cep.example.test/policy" } }
  ],
  "Observations": [
    { "EntityId": "service:ndes:scep-gw01.corp.example.test", "Kind": "Seen", "Source": "HTTP", "Location": "scep-gw01.corp.example.test", "Confidence": "Confirmed", "Detail": "Answers GetCACaps / GetCACert", "Timestamp": "2026-11-22T00:00:00Z" },
    { "EntityId": "service:cep:x", "Kind": "Referenced", "Source": "LocalPolicy", "Location": "HKLM/SOFTWARE/Policies/Microsoft/Cryptography/PolicyServers", "Confidence": "Referenced", "Detail": "", "Timestamp": "2026-11-22T00:00:00Z" }
  ],
  "Relations": [ { "From": "service:ndes:scep-gw01.corp.example.test", "Type": "hostedOn", "To": "host:scep-gw01.corp.example.test", "Sources": ["t"], "Confidence": "Confirmed" } ] }
'@
        $mk = {
            param($id, $cat, $status, $code, [string[]]$ents = @())
            $f = [pscustomobject]@{ Id = $id; Category = $cat; Status = $status; StatusCode = $code; EntityIds = $ents; Message = ('{0} {1}' -f $cat, $code) }
            [pscustomobject]@{ Id = $id; Category = $cat; Status = $status; StatusRank = (Get-MspkiGuiRank -Kind Status -Value $status); StatusPill = (Get-MspkiGuiStatusPill -Value $status); Message = $f.Message; Finding = $f }
        }
        $rows = @(
            (& $mk 'F-1' 'NDES' 'Warning' 'OBJECT_EXPIRED' @('service:ndes:scep-gw01.corp.example.test')),
            (& $mk 'F-2' 'WebEnrollment' 'Skipped' 'UNSUPPORTED'),
            (& $mk 'F-3' 'IntuneConnector' 'Information' 'NOT_DISCOVERED'),
            (& $mk 'F-4' 'IntuneConnector' 'Skipped' 'UNSUPPORTED'),
            (& $mk 'F-5' 'CES' 'Information' 'NOT_CONFIGURED'))
        $ix = New-MspkiGuiGraphIndex -Graph $g -Findings @($rows | ForEach-Object { $_.Finding })
        $s = @(Get-MspkiGuiServiceSection -Index $ix -Rows $rows)
        $s.Count | Should -Be 6
        $by = @{}; foreach ($x in $s) { $by[$x.Kind] = $x }
        $by.NDES.StatePill.Text | Should -Be '1 found'
        $by.NDES.Instances[0].HostName | Should -Be 'scep-gw01.corp.example.test'
        $by.NDES.Instances[0].ConfidencePill.Text | Should -Be 'Confirmed'
        $by.NDES.Instances[0].WorstPill.Text | Should -Be 'Warning'
        $by.NDES.Instances[0].Evidence | Should -Be 'HTTP scep-gw01.corp.example.test: Answers GetCACaps / GetCACert'
        $by.NDES.RiskCount | Should -Be 1
        $by.CEP.StatePill.Text | Should -Be 'Named, not confirmed'
        $by.CEP.InstancesTitle | Should -Match 'not confirmed'
        $by.WebEnrollment.StatePill.Text | Should -Be 'Cannot be checked from here'
        $by.CES.StatePill.Text | Should -Be 'None registered in AD'
        $by.IntuneConnector.StatePill.Text | Should -Be 'Not on this computer'
        $by.IntuneConnector.StateWhy | Should -Match 'could not be checked from here'
        $by.IntuneConnector.Scope | Should -Match 'Only this computer'
        $by.OCSP.StatePill.Text | Should -Be 'Not checked in this run'
        @(Get-MspkiGuiServiceSection -Index $null -Rows @()).Count | Should -Be 6
        (Get-MspkiGuiEntityPane -Index $ix -Id 'service:ndes:scep-gw01.corp.example.test').TypeText | Should -Be 'NDES / SCEP'
    }
}

Describe 'Audit 2 M7: the PKI services page never shows an Inferred service as found' {
    BeforeAll {
        $script:graphJson = @'
{ "Entities": [
    { "Id": "service:web:ca01.corp.example.test", "Type": "Service", "Name": "Web Enrollment on ca01.corp.example.test", "Properties": { "Kind": "WebEnrollment", "HostName": "ca01.corp.example.test" } },
    { "Id": "service:ndes:scep-gw01.example.test", "Type": "Service", "Name": "NDES / SCEP on scep-gw01.example.test", "Properties": { "Kind": "NDES", "HostName": "scep-gw01.example.test" } },
    { "Id": "service:ndes:scep-gw02.example.test", "Type": "Service", "Name": "NDES / SCEP on scep-gw02.example.test", "Properties": { "Kind": "NDES", "HostName": "scep-gw02.example.test" } }
  ],
  "Observations": [
    { "EntityId": "service:web:ca01.corp.example.test", "Kind": "Seen", "Source": "HTTP", "Location": "ca01.corp.example.test", "Confidence": "Inferred", "Detail": "HTTP 403 at the standard path", "Timestamp": "2026-11-22T00:00:00Z" },
    { "EntityId": "service:ndes:scep-gw01.example.test", "Kind": "Seen", "Source": "HTTP", "Location": "scep-gw01.example.test", "Confidence": "Confirmed", "Detail": "Answers GetCACaps / GetCACert", "Timestamp": "2026-11-22T00:00:00Z" },
    { "EntityId": "service:ndes:scep-gw02.example.test", "Kind": "Seen", "Source": "HTTP", "Location": "scep-gw02.example.test", "Confidence": "Inferred", "Detail": "HTTP 403", "Timestamp": "2026-11-22T00:00:00Z" }
  ],
  "Relations": [] }
'@
    }
    It 'says "something answers, not confirmed" for an Inferred-only kind, in a tone that is not Good' {
        $ix = New-MspkiGuiGraphIndex -Graph (ConvertFrom-MspkiJson -Text $script:graphJson) -Findings @()
        $by = @{}; foreach ($x in @(Get-MspkiGuiServiceSection -Index $ix -Rows @())) { $by[$x.Kind] = $x }
        $by.WebEnrollment.StatePill.Text | Should -Not -Match 'found'
        $by.WebEnrollment.StatePill.Text | Should -Match 'not confirmed'
        $by.WebEnrollment.StatePill.Tone | Should -Not -Be 'Good'
        $by.WebEnrollment.InstancesTitle | Should -Not -Match '^Found'
        $by.WebEnrollment.Instances[0].StatePill.Text | Should -Not -Be 'Answers'
        $by.WebEnrollment.Instances[0].StatePill.Tone | Should -Not -Be 'Good'
        $by.WebEnrollment.Instances[0].ConfidencePill.Text | Should -Be 'Inferred'
    }
    It 'counts only Confirmed instances as found, and names the Inferred one separately' {
        $ix = New-MspkiGuiGraphIndex -Graph (ConvertFrom-MspkiJson -Text $script:graphJson) -Findings @()
        $by = @{}; foreach ($x in @(Get-MspkiGuiServiceSection -Index $ix -Rows @())) { $by[$x.Kind] = $x }
        $by.NDES.StatePill.Text | Should -Be '1 found'
        $by.NDES.StatePill.Tone | Should -Be 'Good'
        $by.NDES.StateWhy | Should -Match '1 more.*not confirmed'
        $ok = @($by.NDES.Instances | Where-Object { $_.Name -match 'gw01' })[0]
        $ok.StatePill.Text | Should -Be 'Answers'
        $inf = @($by.NDES.Instances | Where-Object { $_.Name -match 'gw02' })[0]
        $inf.StatePill.Tone | Should -Not -Be 'Good'
    }
}

Describe 'Property names and times in the details pane (GX7 round 1: no raw names or ISO times)' {
    It 'writes property names in sentence case with the usual acronyms' {
        Get-MspkiGuiPropertyLabel -Name 'CAVersion' | Should -BeExactly 'CA version'
        Get-MspkiGuiPropertyLabel -Name 'AuthorityKeyId' | Should -BeExactly 'Authority key ID'
        Get-MspkiGuiPropertyLabel -Name 'CrlNumber' | Should -BeExactly 'CRL number'
        Get-MspkiGuiPropertyLabel -Name 'DnsNames' | Should -BeExactly 'DNS names'
        Get-MspkiGuiPropertyLabel -Name 'CAName' | Should -BeExactly 'CA name'
        Get-MspkiGuiPropertyLabel -Name 'IsDelta' | Should -BeExactly 'Delta'
        Get-MspkiGuiPropertyLabel -Name 'UrlType' | Should -BeExactly 'URL type'
        Get-MspkiGuiPropertyLabel -Name 'NextCRLPublish' | Should -BeExactly 'Next CRL publish'
        Get-MspkiGuiPropertyLabel -Name 'Sha1' | Should -BeExactly 'SHA-1'
    }
    It 'shows a UTC time as people read it, in any culture, and leaves other text alone' {
        $old = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('de-DE')
            ConvertTo-MspkiGuiValueText '2026-11-17T08:00:00Z' | Should -BeExactly '17 Nov 2026, 08:00 UTC'
            ConvertTo-MspkiGuiValueText ([datetime]::new(2027, 3, 14, 9, 12, 0, [DateTimeKind]::Utc)) | Should -BeExactly '14 Mar 2027, 09:12 UTC'
        }
        finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $old }
        ConvertTo-MspkiGuiValueText '2026-11-17' | Should -BeExactly '2026-11-17'
        ConvertTo-MspkiGuiValueText 'V1.0' | Should -BeExactly 'V1.0'
    }
}

Describe 'Readable headings (GX7 round 2)' {
    It 'turns a distinguished name inside a name into its common name, and leaves other names alone' {
        Get-MspkiGuiReadableName -Name 'Base CRL of CN=Example Issuing CA, DC=corp, DC=example, DC=test' | Should -BeExactly 'Base CRL of Example Issuing CA'
        Get-MspkiGuiReadableName -Name 'CN=web01.corp.example.test' | Should -BeExactly 'web01.corp.example.test'
        Get-MspkiGuiReadableName -Name 'CN=Example\, Issuing CA,OU=PKI,O=Example' | Should -BeExactly 'Example\, Issuing CA'
        Get-MspkiGuiReadableName -Name 'http://pki.example.test/cdp/Example CA.crl' | Should -BeExactly 'http://pki.example.test/cdp/Example CA.crl'
        Get-MspkiGuiReadableName -Name 'ca01.corp.example.test\Example Issuing CA' | Should -BeExactly 'ca01.corp.example.test\Example Issuing CA'
    }
}
