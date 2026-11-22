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
        @($p.Breadcrumbs).Count | Should -Be 2
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
        $two.ShowCrumbs | Should -BeTrue
        $two.Breadcrumbs[0].NotLast | Should -BeTrue
        $two.Breadcrumbs[1].IsLast | Should -BeTrue
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
}
