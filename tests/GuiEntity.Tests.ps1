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
}
