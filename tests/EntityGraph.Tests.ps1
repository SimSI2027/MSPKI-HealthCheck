BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    # Lab-shaped hierarchy (example.test only): a root, an issuing CA with two generations; the older one only in NTAuth.
    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    $script:subOld = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysBefore 200 -DaysValid 700 -WithAki
    $script:subNew = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysBefore 100 -DaysValid 700 -WithAki

    $script:newInventory = {
        InModuleScope MspkiHealthCheck -Parameters @{ R = $script:root.Public; O = $script:subOld.Public; N = $script:subNew.Public } {
            param($R, $O, $N)
            $pks = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test'
            $info = {
                param($c, [bool]$self)
                [pscustomobject]@{ Subject = $c.Subject; Issuer = $c.Issuer; Thumbprint = $c.Thumbprint; NotBefore = $c.NotBefore.ToUniversalTime().ToString('o'); NotAfter = $c.NotAfter.ToUniversalTime().ToString('o')
                    SubjectKeyId = (Get-MspkiCertificateSubjectKeyId -Certificate $c); AuthorityKeyId = (Get-MspkiCertificateAuthorityKeyId -Certificate $c); SelfIssued = $self
                    KeyAlgorithm = 'RSA'; KeySize = 2048; SignatureAlgorithm = 'sha256RSA' }
            }
            [pscustomobject]@{
                AdContext = [pscustomobject]@{ Forest = 'example.test'; ForestDomains = @('example.test', 'corp.example.test'); TrustedDomains = @(); PksDN = $pks
                    ConfigNC = 'CN=Configuration,DC=example,DC=test'; DomainController = 'dc01.example.test'; ComputerDomain = 'example.test' }
                Containers = @(
                    [pscustomobject]@{ Name = 'AIA'; DistinguishedName = ('CN=AIA,{0}' -f $pks); Kind = 'Container'; Exists = $true; Outcome = 'Success' }
                    [pscustomobject]@{ Name = 'NTAuthCertificates'; DistinguishedName = ('CN=NTAuthCertificates,{0}' -f $pks); Kind = 'Object'; Exists = $true; Outcome = 'Success' }
                    [pscustomobject]@{ Name = 'Certification Authorities'; DistinguishedName = ('CN=Certification Authorities,{0}' -f $pks); Kind = 'Container'; Exists = $true; Outcome = 'Success' }
                    [pscustomobject]@{ Name = 'OID'; DistinguishedName = ('CN=OID,{0}' -f $pks); Kind = 'Container'; Exists = $false; Outcome = 'NotFound' })
                EnterpriseCAs = @(
                    [pscustomobject]@{ Name = 'Example Root CA'; CommonName = 'Example Root CA'; DnsHostName = 'ca01.example.test'; Config = 'ca01.example.test\Example Root CA'
                        DistinguishedName = ('CN=Example Root CA,CN=Enrollment Services,{0}' -f $pks); Templates = @('SubCA'); EnrollmentServers = @(); Properties = $null }
                    [pscustomobject]@{ Name = 'Example Issuing CA'; CommonName = 'Example Issuing CA'; DnsHostName = 'ca02.corp.example.test'; Config = 'ca02.corp.example.test\Example Issuing CA'
                        DistinguishedName = ('CN=Example Issuing CA,CN=Enrollment Services,{0}' -f $pks); Templates = @('WebServer', 'NoSuchTemplate'); EnrollmentServers = @(); Properties = [pscustomobject]@{ CATypeName = 'EnterpriseSubordinate' } })
                CACertificates = @(
                    [pscustomobject]@{ Thumbprint = $R.Thumbprint; CAName = 'Example Root CA'; Role = 'EnterpriseRoot'; Lifecycle = 'Current'; Generation = 'V0.0'; AssociationBasis = 'Name'
                        Sources = @('AD:EnrollmentServices', 'AD:CertificationAuthorities', 'AD:AIA', 'AD:NTAuthCertificates'); InAIA = $true; InNTAuth = $true; InCertificationAuthorities = $true; Info = (& $info $R $true) }
                    [pscustomobject]@{ Thumbprint = $N.Thumbprint; CAName = 'Example Issuing CA'; Role = 'EnterpriseSubordinate'; Lifecycle = 'Current'; Generation = 'V0.0'; AssociationBasis = 'Name'
                        Sources = @('CA:GetCAProperty', 'AD:EnrollmentServices', 'AD:AIA', 'AD:NTAuthCertificates'); InAIA = $true; InNTAuth = $true; Info = (& $info $N $false) }
                    [pscustomobject]@{ Thumbprint = $O.Thumbprint; CAName = 'Example Issuing CA'; Role = 'EnterpriseSubordinate'; Lifecycle = 'Unknown'; Generation = 'V0.0'; AssociationBasis = 'Name'
                        Sources = @('AD:NTAuthCertificates'); InAIA = $false; InNTAuth = $true; Info = (& $info $O $false) })
                Templates = @(
                    [pscustomobject]@{ Name = 'WebServer'; DisplayName = 'Web Server'; DistinguishedName = ('CN=WebServer,CN=Certificate Templates,{0}' -f $pks); Oid = '1.2.3'; SchemaVersion = 1 }
                    [pscustomobject]@{ Name = 'SubCA'; DisplayName = 'Subordinate Certification Authority'; DistinguishedName = ('CN=SubCA,CN=Certificate Templates,{0}' -f $pks); Oid = '1.2.4'; SchemaVersion = 1 })
                Leads = @(
                    [pscustomobject]@{ Kind = 'CDP'; Url = 'ldap:///CN=Example Issuing CA,CN=ca02,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=example,DC=test'; Scope = 'Local'; Confidence = 'Referenced'; Sources = @('CA:Example Issuing CA:CertCdpUrls'); RelatedCAs = @('Example Issuing CA') }
                    [pscustomobject]@{ Kind = 'AIA'; Url = 'http://pki.example.test/CertEnroll/root.crt'; Scope = 'Local'; Confidence = 'Referenced'; Sources = @(('Cert:{0}:AIA' -f $N.Thumbprint)); RelatedCAs = @('Example Issuing CA') }
                    [pscustomobject]@{ Kind = 'CES'; Url = 'https://ca01.example.test/Example%20Root%20CA_CES_Kerberos/service.svc'; Scope = 'Local'; Confidence = 'Inferred'; Sources = @('Constructed:CAHost'); RelatedCAs = @() })
                NdesHosts = @(); CepPolicies = @(); IntuneConnector = $null
            }
        }
    }
    $script:build = {
        $inv = & $script:newInventory
        InModuleScope MspkiHealthCheck -Parameters @{ I = $inv } { param($I) Reset-MspkiEntityGraph; Add-MspkiInventoryToEntityGraph -Inventory $I }
        return $inv
    }
}

Describe 'Entity ids' {
    It 'are stable and normalised: thumbprint case and spaces, host trailing dot, http vs https of the same path' {
        InModuleScope MspkiHealthCheck {
            Get-MspkiEntityId -Type 'CACertificate' -Key 'AB CD EF' | Should -Be 'cacert:abcdef'
            Get-MspkiEntityId -Type 'Host' -Key 'CA01.Example.Test.' | Should -Be 'host:ca01.example.test'
            (Get-MspkiEndpointEntityId -Url 'http://PKI.example.test/CertEnroll/a%20b.crl') | Should -Be (Get-MspkiEndpointEntityId -Url 'https://pki.example.test:443/CertEnroll/a b.crl')
            Get-MspkiCrlEntityId -AuthorityKeyId 'AA:BB' -IsDelta $true | Should -Be 'crl:aabb:delta'
            { Get-MspkiEntityId -Type 'Planet' -Key 'x' } | Should -Throw
        }
    }

    It 'merges duplicate observations and relations and rejects unknown relation types' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiEntityGraph
            $a = Add-MspkiEntity -Type 'Host' -Key 'a.example.test'
            $b = Add-MspkiEntity -Type 'Host' -Key 'b.example.test'
            Add-MspkiObservation -EntityId $a -Kind 'Seen' -Source 'DNS' -Location 'a.example.test'
            Add-MspkiObservation -EntityId $a -Kind 'Seen' -Source 'DNS' -Location 'a.example.test'
            Add-MspkiRelation -From $a -Type 'aliasOf' -To $b -Source 'one'
            Add-MspkiRelation -From $a -Type 'aliasOf' -To $b -Source 'two'
            @(Get-MspkiObservation -EntityId $a).Count | Should -Be 1
            $r = @(Get-MspkiRelation -From $a)
            $r.Count | Should -Be 1
            $r[0].Sources | Should -Be @('one', 'two')
            { Add-MspkiRelation -From $a -Type 'likes' -To $b } | Should -Throw
        }
    }
}

Describe 'Graph from the inventory' {
    BeforeEach { $script:inv = & $script:build }

    It 'records an older CA generation that is in NTAuth but not in AIA as expected-but-missing in AIA (and the current one is not)' {
        InModuleScope MspkiHealthCheck -Parameters @{ O = $script:subOld.Public.Thumbprint; N = $script:subNew.Public.Thumbprint } {
            param($O, $N)
            $old = @(Get-MspkiObservation -EntityId (Get-MspkiEntityId -Type 'CACertificate' -Key $O) -Kind 'ExpectedMissing')
            $old.Count | Should -Be 1
            $old[0].Location | Should -BeLike 'CN=AIA,*'
            $old[0].Detail | Should -Match 'In NTAuth but not in AIA'
            @(Get-MspkiObservation -EntityId (Get-MspkiEntityId -Type 'CACertificate' -Key $N) -Kind 'ExpectedMissing').Count | Should -Be 0
        }
    }

    It 'links the chain by key id, the generations by date, certificates to their CA and templates to the CA that publishes them' {
        InModuleScope MspkiHealthCheck -Parameters @{ R = $script:root.Public.Thumbprint; O = $script:subOld.Public.Thumbprint; N = $script:subNew.Public.Thumbprint } {
            param($R, $O, $N)
            $rid = Get-MspkiEntityId -Type 'CACertificate' -Key $R; $oid = Get-MspkiEntityId -Type 'CACertificate' -Key $O; $nid = Get-MspkiEntityId -Type 'CACertificate' -Key $N
            @(Get-MspkiRelation -From $nid -Type 'issuedBy').To | Should -Be @($rid)
            @(Get-MspkiRelation -From $rid -Type 'issuedBy').Count | Should -Be 0
            @(Get-MspkiRelation -From $nid -Type 'supersedes').To | Should -Be @($oid)
            $caId = Get-MspkiEntityId -Type 'CA' -Key 'ca02.corp.example.test\Example Issuing CA'
            @(Get-MspkiRelation -Type 'certificateOf' -To $caId).Count | Should -Be 2
            @(Get-MspkiRelation -From (Get-MspkiEntityId -Type 'Template' -Key 'WebServer') -Type 'enrollsVia').To | Should -Be @($caId)
            @(Get-MspkiRelation -From $caId -Type 'hostedOn').To | Should -Be @('host:ca02.corp.example.test')
        }
    }

    It 'records a missing standard container and a published template without a template object as expected-but-missing' {
        InModuleScope MspkiHealthCheck {
            @(Get-MspkiObservation -EntityId (Get-MspkiEntityId -Type 'ADObject' -Key 'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test') -Kind 'ExpectedMissing').Count | Should -Be 1
            $t = @(Get-MspkiObservation -EntityId (Get-MspkiEntityId -Type 'Template' -Key 'NoSuchTemplate') -Kind 'ExpectedMissing')
            $t.Count | Should -Be 1
            $t[0].Detail | Should -Match 'Example Issuing CA'
        }
    }

    It 'keeps a constructed candidate URL as Inferred, never Confirmed' {
        InModuleScope MspkiHealthCheck {
            $o = @(Get-MspkiObservation -EntityId (Get-MspkiEndpointEntityId -Url 'https://ca01.example.test/Example%20Root%20CA_CES_Kerberos/service.svc'))
            $o.Count | Should -Be 1
            $o[0].Confidence | Should -Be 'Inferred'
            $o[0].Source | Should -Be 'Constructed'
        }
    }
}

Describe 'Probe observations' {
    BeforeEach { $script:inv = & $script:build }

    It 'records a CRL seen at a location with publishedAt and signedBy, and links a CRL finding about that URL to the CRL' {
        $ski = InModuleScope MspkiHealthCheck -Parameters @{ C = $script:subNew.Public } { param($C) Get-MspkiCertificateSubjectKeyId -Certificate $C }
        $bytes = New-TestCrl -Issuer $script:subNew -Number 7 -AuthorityKeyIdHex $ski
        InModuleScope MspkiHealthCheck -Parameters @{ B = $bytes; L = $script:inv.Leads[0]; N = $script:subNew.Public.Thumbprint } {
            param($B, $L, $N)
            $crl = ConvertFrom-MspkiCrl -Bytes $B
            Register-MspkiProbeResult -Lead $L -Url $L.Url -Result ([pscustomobject]@{ Crl = $crl; Certificate = $null; Validated = $false }) -Tested
            $cid = Get-MspkiCrlEntityId -AuthorityKeyId $crl.AuthorityKeyId -IsDelta $false
            $seen = @(Get-MspkiObservation -EntityId $cid -Kind 'Seen')
            $seen.Count | Should -Be 1
            $seen[0].Source | Should -Be 'LDAP'
            $seen[0].Detail | Should -Match 'CRL number 07|CRL number 7'
            @(Get-MspkiRelation -From $cid -Type 'signedBy').To | Should -Be @(Get-MspkiEntityId -Type 'CACertificate' -Key $N)
            @(Get-MspkiRelation -From $cid -Type 'publishedAt').To | Should -Be @(Get-MspkiEndpointEntityId -Url $L.Url)
            $f = New-MspkiFinding -Category 'CRL' -Target $crl.Issuer -Endpoint $L.Url -Status 'Pass' -StatusCode 'OK' -Sources 'test' -Message 'x'
            Add-MspkiFindingEntityLink -Findings @($f)
            $f.EntityIds | Should -Contain $cid
            $f.EntityIds | Should -Contain (Get-MspkiEndpointEntityId -Url $L.Url)
        }
    }

    It 'records the CA''s own CRL expected but missing at a CDP location from the CA''s CertCdpUrls that returned nothing' {
        InModuleScope MspkiHealthCheck -Parameters @{ L = $script:inv.Leads[0]; C = $script:subNew.Public } {
            param($L, $C)
            Register-MspkiProbeResult -Lead $L -Url $L.Url -Result ([pscustomobject]@{ Crl = $null; Certificate = $null; Validated = $false }) -Tested
            $cid = Get-MspkiCrlEntityId -AuthorityKeyId (Get-MspkiCertificateSubjectKeyId -Certificate $C) -IsDelta $false
            $m = @(Get-MspkiObservation -EntityId $cid -Kind 'ExpectedMissing')
            $m.Count | Should -Be 1
            $m[0].Location | Should -Be $L.Url
        }
    }

    It 'records nothing as missing when the location was not tested (-SkipNetwork)' {
        InModuleScope MspkiHealthCheck -Parameters @{ L = $script:inv.Leads[1] } {
            param($L)
            Register-MspkiProbeResult -Lead $L -Url $L.Url -Result ([pscustomobject]@{ Crl = $null; Certificate = $null; Validated = $false })
            @(Get-MspkiObservation -Kind 'ExpectedMissing' | Where-Object { $_.Location -eq $L.Url }).Count | Should -Be 0
        }
    }

    It 'records the issuer certificate expected but missing at an AIA URL that returned nothing' {
        InModuleScope MspkiHealthCheck -Parameters @{ L = $script:inv.Leads[1]; R = $script:root.Public.Thumbprint } {
            param($L, $R)
            Register-MspkiProbeResult -Lead $L -Url $L.Url -Result ([pscustomobject]@{ Crl = $null; Certificate = $null; Validated = $false }) -Tested
            $m = @(Get-MspkiObservation -EntityId (Get-MspkiEntityId -Type 'CACertificate' -Key $R) -Kind 'ExpectedMissing')
            $m.Count | Should -Be 1
            $m[0].Source | Should -Be 'HTTP'
        }
    }
}

Describe 'Finding links' {
    BeforeEach { $script:inv = & $script:build }

    It 'gives every finding at least one entity id (CA by name or config, thumbprint, template, host; else the forest)' {
        InModuleScope MspkiHealthCheck -Parameters @{ N = $script:subNew.Public.Thumbprint } {
            param($N)
            $fs = @(
                (New-MspkiFinding -Category 'CA' -Target 'Example Issuing CA' -Endpoint 'ca02.corp.example.test\Example Issuing CA' -Status 'Pass' -StatusCode 'OK' -Sources 't' -Message 'x')
                (New-MspkiFinding -Category 'Hierarchy' -Target $N -Status 'Pass' -StatusCode 'OK' -Sources 't' -Message 'x')
                (New-MspkiFinding -Category 'Template' -Target 'WebServer' -Status 'Pass' -StatusCode 'OK' -Sources 't' -Message 'x')
                (New-MspkiFinding -Category 'ADDependency' -Target 'dc01.example.test' -Status 'Pass' -StatusCode 'OK' -Sources 't' -Message 'x')
                (New-MspkiFinding -Category 'Run' -Target 'Run' -Status 'Information' -StatusCode 'OK' -Sources 't' -Message 'x'))
            Add-MspkiFindingEntityLink -Findings $fs
            $fs[0].EntityIds | Should -Be @('ca:ca02.corp.example.test\example issuing ca')
            $fs[1].EntityIds | Should -Contain (Get-MspkiEntityId -Type 'CACertificate' -Key $N)
            $fs[2].EntityIds | Should -Be @('template:webserver')
            $fs[3].EntityIds | Should -Contain 'host:dc01.example.test'
            $fs[4].EntityIds | Should -Be @('forest:example.test')
        }
    }

    It 'keeps ids a finding was created with' {
        InModuleScope MspkiHealthCheck {
            $f = New-MspkiFinding -Category 'Run' -Target 'Run' -Status 'Information' -StatusCode 'OK' -Sources 't' -Message 'x' -EntityIds @('host:x.example.test')
            Add-MspkiFindingEntityLink -Findings @($f)
            $f.EntityIds | Should -Be @('host:x.example.test')
        }
    }
}

Describe 'results.json versions' {
    It 'reads a format-1 file (the demo fixture) through the adapter, with a notice and empty EntityIds' {
        $j = Get-Content (Join-Path $PSScriptRoot 'fixtures\demo-results.json') -Raw | ConvertFrom-Json
        $r = ConvertFrom-MspkiResultsDocument -Document $j
        $r.SchemaVersion | Should -Be 1
        $r.Graph | Should -BeNullOrEmpty
        $r.Notice | Should -Match 'older version'
        @($r.Findings).Count | Should -BeGreaterThan 0
        foreach ($f in $r.Findings) { @($f.EntityIds).Count | Should -Be 0 }
    }

    It 'reads format 2 with its graph, and refuses a newer format with a plain message' {
        $doc = [pscustomobject]@{ Schema = 'mspki-healthcheck/2'; RunInfo = $null; Inventory = $null; ExitCode = 0; Findings = @(); Graph = [pscustomobject]@{ SchemaVersion = 2; Entities = @() } }
        $r = ConvertFrom-MspkiResultsDocument -Document $doc
        $r.SchemaVersion | Should -Be 2
        $r.Graph.SchemaVersion | Should -Be 2
        $r.Notice | Should -BeNullOrEmpty
        { ConvertFrom-MspkiResultsDocument -Document ([pscustomobject]@{ Schema = 'mspki-healthcheck/9'; Findings = @() }) } | Should -Throw '*format version 9*'
        { ConvertFrom-MspkiResultsDocument -Document ([pscustomobject]@{ Schema = 'other'; Findings = @() }) } | Should -Throw '*not a results.json*'
    }

    It 'exports the graph sorted with counts by type' {
        $null = & $script:build
        InModuleScope MspkiHealthCheck {
            $g = Get-MspkiEntityGraphExport
            $g.SchemaVersion | Should -Be 2
            $g.Counts.ByType.CACertificate | Should -Be 3
            $g.Counts.ExpectedMissing | Should -BeGreaterThan 0
            $ids = @($g.Entities | ForEach-Object { $_.Id })
            $ids | Should -Be @($ids | Sort-Object)
        }
    }
}
