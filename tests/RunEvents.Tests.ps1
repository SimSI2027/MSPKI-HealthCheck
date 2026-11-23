# GX1: engine events for the live map. With a run control the engine queues one Entity item per new entity (id, type, name, parent ids),
# one Relation item per new relation and Probe start/end items keyed by the entity the probe is about. Without a control nothing changes.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    # A small inventory (example.test only): a forest with a domain, a container, one issuing CA with a CA certificate and two leads.
    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    $script:inv = InModuleScope MspkiHealthCheck -Parameters @{ R = $script:root.Public } {
        param($R)
        $pks = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test'
        [pscustomobject]@{
            AdContext = [pscustomobject]@{ Forest = 'example.test'; ForestDomains = @('example.test', 'corp.example.test'); TrustedDomains = @(); PksDN = $pks
                ConfigNC = 'CN=Configuration,DC=example,DC=test'; DomainController = 'dc01.example.test'; ComputerDomain = 'example.test' }
            Containers = @([pscustomobject]@{ Name = 'AIA'; DistinguishedName = ('CN=AIA,{0}' -f $pks); Kind = 'Container'; Exists = $true; Outcome = 'Success' })
            EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Root CA'; CommonName = 'Example Root CA'; DnsHostName = 'ca01.example.test'; Config = 'ca01.example.test\Example Root CA'
                DistinguishedName = ('CN=Example Root CA,CN=Enrollment Services,{0}' -f $pks); Templates = @(); EnrollmentServers = @(); Properties = $null })
            CACertificates = @([pscustomobject]@{ Thumbprint = $R.Thumbprint; CAName = 'Example Root CA'; Role = 'EnterpriseRoot'; Lifecycle = 'Current'; Generation = 'V0.0'; AssociationBasis = 'Name'
                Sources = @('AD:EnrollmentServices'); InAIA = $false; InNTAuth = $false; Info = [pscustomobject]@{ Subject = $R.Subject; Issuer = $R.Issuer; Thumbprint = $R.Thumbprint
                    SubjectKeyId = (Get-MspkiCertificateSubjectKeyId -Certificate $R); AuthorityKeyId = ''; SelfIssued = $true; KeyAlgorithm = 'RSA'; KeySize = 2048; SignatureAlgorithm = 'sha256RSA'
                    NotBefore = $R.NotBefore.ToUniversalTime().ToString('o'); NotAfter = $R.NotAfter.ToUniversalTime().ToString('o') } })
            Templates = @()
            Leads = @([pscustomobject]@{ Kind = 'AIA'; Url = 'http://pki.example.test/CertEnroll/root.crt'; Scope = 'Local'; Confidence = 'Referenced'; Sources = @('CA:Example Root CA:CertAiaUrls'); RelatedCAs = @('Example Root CA') })
            NdesHosts = @(); CepPolicies = @(); IntuneConnector = $null
        }
    }
    $script:drain = {
        param($Control)
        $items = New-Object System.Collections.ArrayList
        $x = $null
        while ($Control['Queue'].TryDequeue([ref]$x)) { [void]$items.Add($x) }
        return , @($items)
    }
}

Describe 'Entity and Relation events (GX1)' {

    It 'queues one Entity item per new entity and one Relation item per new relation, and nothing for a merge' {
        $out = InModuleScope MspkiHealthCheck {
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try {
                Reset-MspkiEntityGraph
                $f = Add-MspkiEntity -Type 'Forest' -Key 'example.test' -Name 'example.test'
                $d = Add-MspkiEntity -Type 'Domain' -Key 'corp.example.test' -Name 'corp.example.test' -Parents @($f)
                [void](Add-MspkiEntity -Type 'Domain' -Key 'corp.example.test' -Properties @{ InForest = $true })   # a merge: no second item
                Add-MspkiRelation -From $d -Type 'partOf' -To $f -Source 'AD'
                Add-MspkiRelation -From $d -Type 'partOf' -To $f -Source 'AD:again'                                 # a duplicate: no second item
            }
            finally { Set-MspkiRunControl -Control $null }
            $items = @(); $x = $null
            while ($c['Queue'].TryDequeue([ref]$x)) { $items += $x }
            $items
        }
        $ent = @($out | Where-Object { $_.Kind -eq 'Entity' })
        $rel = @($out | Where-Object { $_.Kind -eq 'Relation' })
        $ent.Count | Should -Be 2
        $rel.Count | Should -Be 1
        $ent[0].Id | Should -Be 'forest:example.test'
        $ent[0].Type | Should -Be 'Forest'
        $ent[0].Name | Should -Be 'example.test'
        @($ent[0].Parents).Count | Should -Be 0
        $ent[1].Id | Should -Be 'domain:corp.example.test'
        @($ent[1].Parents) | Should -Be @('forest:example.test')
        $rel[0].From | Should -Be 'domain:corp.example.test'
        $rel[0].Type | Should -Be 'partOf'
        $rel[0].To | Should -Be 'forest:example.test'
    }

    It 'announces every entity and every relation of a built graph (100 percent arrive), with the parents the builder knows' {
        $out = InModuleScope MspkiHealthCheck -Parameters @{ I = $script:inv } {
            param($I)
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try { Reset-MspkiEntityGraph; Add-MspkiInventoryToEntityGraph -Inventory $I; $g = Get-MspkiEntityGraphExport }
            finally { Set-MspkiRunControl -Control $null }
            $items = @(); $x = $null
            while ($c['Queue'].TryDequeue([ref]$x)) { $items += $x }
            [pscustomobject]@{ Items = $items; Graph = $g }
        }
        $ent = @($out.Items | Where-Object { $_.Kind -eq 'Entity' })
        $rel = @($out.Items | Where-Object { $_.Kind -eq 'Relation' })
        $out.Graph.Counts.Entities | Should -BeGreaterThan 6
        $ent.Count | Should -Be $out.Graph.Counts.Entities
        $rel.Count | Should -Be $out.Graph.Counts.Relations
        @($ent.Id | Sort-Object -Unique).Count | Should -Be $ent.Count
        # Every id announced exists in the final graph, with the same type.
        foreach ($e in $ent) { @($out.Graph.Entities | Where-Object { $_.Id -eq $e.Id -and $_.Type -eq $e.Type }).Count | Should -Be 1 }
        # Parents: the CA sits under the forest, the CA certificate under its CA, the endpoint under its host.
        $ca = $ent | Where-Object { $_.Type -eq 'CA' } | Select-Object -First 1
        @($ca.Parents) | Should -Contain 'forest:example.test'
        $cert = $ent | Where-Object { $_.Type -eq 'CACertificate' } | Select-Object -First 1
        @($cert.Parents) | Should -Contain $ca.Id
        $dom = $ent | Where-Object { $_.Id -eq 'domain:corp.example.test' }
        @($dom.Parents) | Should -Contain 'forest:example.test'
    }

    It 'announces an entity before any relation that names it' {
        $out = InModuleScope MspkiHealthCheck -Parameters @{ I = $script:inv } {
            param($I)
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try { Reset-MspkiEntityGraph; Add-MspkiInventoryToEntityGraph -Inventory $I }
            finally { Set-MspkiRunControl -Control $null }
            $items = @(); $x = $null
            while ($c['Queue'].TryDequeue([ref]$x)) { $items += $x }
            $items
        }
        $seen = @{}
        $bad = @()
        foreach ($i in $out) {
            if ($i.Kind -eq 'Entity') { $seen[$i.Id] = $true }
            elseif ($i.Kind -eq 'Relation') { foreach ($id in @($i.From, $i.To)) { if (-not $seen.ContainsKey($id)) { $bad += ('{0} {1} {2}' -f $i.From, $i.Type, $i.To) } } }
        }
        $bad.Count | Should -Be 0 -Because ($bad -join '; ')
    }

    It 'changes nothing for the command line: the graph built with and without a control is identical' {
        $json = InModuleScope MspkiHealthCheck -Parameters @{ I = $script:inv } {
            param($I)
            Set-MspkiRunControl -Control $null
            Reset-MspkiEntityGraph; Add-MspkiInventoryToEntityGraph -Inventory $I
            $without = (Get-MspkiEntityGraphExport | ConvertTo-Json -Depth 8 -Compress)
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try { Reset-MspkiEntityGraph; Add-MspkiInventoryToEntityGraph -Inventory $I; $with = (Get-MspkiEntityGraphExport | ConvertTo-Json -Depth 8 -Compress) }
            finally { Set-MspkiRunControl -Control $null }
            [pscustomobject]@{ Without = $without; With = $with }
        }
        $json.With | Should -BeExactly $json.Without
    }

    It 'announces the endpoints the lead registry holds early, once: the final graph pass does not announce them again' {
        $out = InModuleScope MspkiHealthCheck -Parameters @{ I = $script:inv } {
            param($I)
            Mock Get-MspkiLead { [pscustomobject]@{ Url = 'https://ces.example.test/Example_CES_Kerberos/service.svc'; Kind = 'CES'; Scope = 'Local' } }
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try {
                Reset-MspkiEntityGraph
                Send-MspkiLeadEntityEvent
                Send-MspkiLeadEntityEvent                                  # again: nothing new
                $early = @(); $x = $null
                while ($c['Queue'].TryDequeue([ref]$x)) { $early += $x }
                $I2 = $I | Select-Object -Property *
                $I2 | Add-Member -NotePropertyName Leads -NotePropertyValue @([pscustomobject]@{ Url = 'https://ces.example.test/Example_CES_Kerberos/service.svc'; Kind = 'CES'; Scope = 'Local'; Confidence = 'Inferred'; Sources = @('Constructed:CAHost'); RelatedCAs = @() }) -Force
                Add-MspkiInventoryToEntityGraph -Inventory $I2
                $late = @()
                while ($c['Queue'].TryDequeue([ref]$x)) { $late += $x }
            }
            finally { Set-MspkiRunControl -Control $null }
            [pscustomobject]@{ Early = $early; Late = $late; Graph = (Get-MspkiEntityGraphExport) }
        }
        @($out.Early | Where-Object { $_.Kind -eq 'Entity' }).Count | Should -Be 2   # the endpoint and its host
        $ep = $out.Early | Where-Object { $_.Type -eq 'Endpoint' }
        $ep.Name | Should -Be 'https://ces.example.test/Example_CES_Kerberos/service.svc'
        @($ep.Parents) | Should -Be @('host:ces.example.test')
        @($out.Late | Where-Object { $_.Kind -eq 'Entity' -and $_.Id -in @($ep.Id, 'host:ces.example.test') }).Count | Should -Be 0
        # Everything announced early exists in the final graph.
        foreach ($e in @($out.Early | Where-Object { $_.Kind -eq 'Entity' })) { @($out.Graph.Entities | Where-Object { $_.Id -eq $e.Id }).Count | Should -Be 1 }
    }

    It 'carries the display properties of a new entity, and announces who references an early endpoint, once' {
        $out = InModuleScope MspkiHealthCheck {
            Mock Get-MspkiLead { [pscustomobject]@{ Url = 'http://pki.example.test/CertEnroll/Example-Root-CA.crl'; Kind = 'CDP'; Scope = 'Local'; RelatedCAs = @('Example Root CA'); Sources = @('Cert:0123456789ABCDEF0123456789ABCDEF01234567:CDP') } }
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try {
                Reset-MspkiEntityGraph
                $ca = Add-MspkiEntity -Type 'CA' -Key 'ca01.example.test\Example Root CA' -Name 'Example Root CA' -Properties @{ CAType = 'EnterpriseRootCA'; PropertiesRead = $true; Config = 'not shown' }
                $cert = Add-MspkiEntity -Type 'CACertificate' -Key '0123456789ABCDEF0123456789ABCDEF01234567' -Name 'CN=Example Root CA'
                Send-MspkiLeadEntityEvent
                Add-MspkiRelation -From $ca -Type 'references' -To (Get-MspkiEndpointEntityId -Url 'http://pki.example.test/CertEnroll/Example-Root-CA.crl') -Source 'later'   # already announced: no second item
                $items = @(); $x = $null
                while ($c['Queue'].TryDequeue([ref]$x)) { $items += $x }
            }
            finally { Set-MspkiRunControl -Control $null }
            $items
        }
        $caEv = $out | Where-Object { $_.Kind -eq 'Entity' -and $_.Type -eq 'CA' }
        $caEv.Props.CAType | Should -Be 'EnterpriseRootCA'
        $caEv.Props.PropertiesRead | Should -BeTrue
        $caEv.Props.ContainsKey('Config') | Should -BeFalse
        $ep = $out | Where-Object { $_.Kind -eq 'Entity' -and $_.Type -eq 'Endpoint' }
        $ep.Props.Url | Should -Be 'http://pki.example.test/CertEnroll/Example-Root-CA.crl'
        @($ep.Props.Kinds) | Should -Be @('CDP')
        $rels = @($out | Where-Object { $_.Kind -eq 'Relation' -and $_.Type -eq 'references' })
        $rels.Count | Should -Be 2   # the CA and the CA certificate, once each
        @($rels.To | Select-Object -Unique) | Should -Be @($ep.Id)
        @($rels.From | Sort-Object) | Should -Be @('ca:ca01.example.test\example root ca', 'cacert:0123456789abcdef0123456789abcdef01234567' | Sort-Object)
    }

    It 'queues nothing without a run control' {
        $n = InModuleScope MspkiHealthCheck -Parameters @{ I = $script:inv } {
            param($I)
            Set-MspkiRunControl -Control $null
            Reset-MspkiEntityGraph; Add-MspkiInventoryToEntityGraph -Inventory $I
            Send-MspkiProbeEvent -Phase Start -Probe DNS -Subject 'dc01.example.test'
            (Test-MspkiRunControlActive)
        }
        $n | Should -BeFalse
    }
}

Describe 'Probe events (GX1)' {

    BeforeAll {
        # A port nothing listens on (reserved, then released) for fast, local, refused connections.
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $l.Start(); $script:closedPort = $l.LocalEndpoint.Port; $l.Stop()
        $script:openListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $script:openListener.Start()
        $script:openPort = $script:openListener.LocalEndpoint.Port
    }
    AfterAll { if ($null -ne $script:openListener) { $script:openListener.Stop() } }

    It 'DNS and TCP: a Start and an End item keyed by the host id, with the outcome code; a cached repeat sends none' {
        $out = InModuleScope MspkiHealthCheck -Parameters @{ Open = $script:openPort } {
            param($Open)
            Reset-MspkiProbeCache
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            try {
                [void](Resolve-MspkiDnsName -HostName 'localhost' -TimeoutMs 3000)
                [void](Test-MspkiTcpPort -HostName '127.0.0.1' -Port $Open -TimeoutMs 3000)
                [void](Test-MspkiTcpPort -HostName '127.0.0.1' -Port $Open -TimeoutMs 3000)   # cached
            }
            finally { Set-MspkiRunControl -Control $null }
            $items = @(); $x = $null
            while ($c['Queue'].TryDequeue([ref]$x)) { if ($x.Kind -eq 'Probe') { $items += $x } }
            $items
        }
        $out.Count | Should -Be 4
        ($out | ForEach-Object { '{0}:{1}:{2}' -f $_.Probe, $_.Phase, $_.Id }) | Should -Be @('DNS:Start:host:localhost', 'DNS:End:host:localhost', 'TCP:Start:host:127.0.0.1', 'TCP:End:host:127.0.0.1')
        $out[1].Outcome | Should -Be 'OK'
        $out[3].Outcome | Should -Be 'OK'
    }

    It 'HTTP, TLS and LDAP: keyed by the endpoint id (URLs) or the host id (TLS); every Start has its End, also for a refused connection and a URL that is not contacted' {
        $out = InModuleScope MspkiHealthCheck -Parameters @{ Closed = $script:closedPort } {
            param($Closed)
            Reset-MspkiProbeCache
            $c = New-MspkiRunControl
            Set-MspkiRunControl -Control $c
            $url = 'http://127.0.0.1:{0}/CertEnroll/x.crl' -f $Closed
            try {
                [void](Invoke-MspkiHttpGet -Url $url -TimeoutMs 3000)
                [void](Test-MspkiTlsEndpoint -HostName '127.0.0.1' -Port $Closed -TimeoutMs 3000)
                [void](Get-MspkiLdapUrlContent -Url 'ldap://other.example.test/CN=x,DC=example,DC=test?cACertificate' -DefaultServer 'dc01.example.test' -SkipNetwork)
            }
            finally { Set-MspkiRunControl -Control $null }
            $items = @(); $x = $null
            while ($c['Queue'].TryDequeue([ref]$x)) { if ($x.Kind -eq 'Probe') { $items += $x } }
            [pscustomobject]@{ Items = $items; HttpId = (Get-MspkiEndpointEntityId -Url $url); LdapId = (Get-MspkiEndpointEntityId -Url 'ldap://other.example.test/CN=x,DC=example,DC=test?cACertificate') }
        }
        # The TLS probe opens a TCP connection first, so its TCP pair is nested inside the TLS pair; only the three probes under test are counted.
        $it = @($out.Items | Where-Object { $_.Probe -ne 'TCP' })
        $it.Count | Should -Be 6
        foreach ($p in 'HTTP', 'TLS', 'LDAP') {
            $pair = @($it | Where-Object { $_.Probe -eq $p })
            $pair.Count | Should -Be 2
            $pair[0].Phase | Should -Be 'Start'
            $pair[1].Phase | Should -Be 'End'
            $pair[1].Id | Should -Be $pair[0].Id
        }
        (@($it | Where-Object { $_.Probe -eq 'HTTP' })[0]).Id | Should -Be $out.HttpId
        (@($it | Where-Object { $_.Probe -eq 'HTTP' })[1]).Outcome | Should -Not -Be ''
        (@($it | Where-Object { $_.Probe -eq 'TLS' })[0]).Id | Should -Be 'host:127.0.0.1'
        (@($it | Where-Object { $_.Probe -eq 'LDAP' })[0]).Id | Should -Be $out.LdapId
        (@($it | Where-Object { $_.Probe -eq 'LDAP' })[1]).Outcome | Should -Be 'NOT_APPLICABLE'
    }

    It 'every place that announces a probe start also announces its end (static check of the probe files)' {
        foreach ($f in 'NetworkProbes.ps1', 'WebProbes.ps1') {
            $t = Get-Content -LiteralPath (Join-Path $script:RepoRoot ('src\Probes\' + $f)) -Raw
            foreach ($p in 'DNS', 'TCP', 'HTTP', 'TLS', 'LDAP') {
                $starts = ([regex]::Matches($t, 'Send-MspkiProbeEvent -Phase Start -Probe ' + $p + '\b')).Count
                $ends = ([regex]::Matches($t, 'Send-MspkiProbeEvent -Phase End -Probe ' + $p + '\b')).Count
                if ($starts -gt 0) { $ends | Should -BeGreaterOrEqual $starts -Because ($f + ' ' + $p) }
            }
        }
    }
}
