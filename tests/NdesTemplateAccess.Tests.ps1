# Tests for NDES discovery without the CA database view (WP3 / D4): NDES RA templates, who may enroll from them, the accounts and the
# host names they give, the template-route findings, RA certificates from GetCACert (roles, template extension) and the graph links.
# example.test names and made-up SIDs only; nothing is contacted (AD reads are mocked).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:dom = 'S-1-5-21-1111-2222-3333'
    $script:enroll = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:ace = { param($Sid, [string]$Type = 'Allow') [pscustomobject]@{ Sid = $Sid; Principal = ''; Type = $Type; Mask = 0x130; ObjectType = $script:enroll; InheritOnly = $false; Inherited = $false; Rights = @('Enroll') } }
    $script:tpl = { param($Name, [string[]]$Eku = @('1.3.6.1.4.1.311.20.2.1'), [int64]$NameFlag = 1, [object[]]$Acl = @())
        [pscustomobject]@{ Name = $Name; DisplayName = $Name; Oid = ('1.3.6.1.4.1.311.21.8.1.{0}' -f $Name.Length); Eku = $Eku; ApplicationPolicies = @(); NameFlag = $NameFlag; Acl = $Acl; AclError = '' } }
}

Describe 'NDES RA templates' {
    It 'recognises the standard templates and copies with the same purpose, and nothing else' {
        InModuleScope MspkiHealthCheck -Parameters @{ T = $script:tpl } {
            param($T)
            (Test-MspkiNdesRaTemplate -Template (& $T 'CEPEncryption')).Kind | Should -Be 'Standard'
            (Test-MspkiNdesRaTemplate -Template (& $T 'EnrollmentAgentOffline')).Kind | Should -Be 'Standard'
            (Test-MspkiNdesRaTemplate -Template (& $T 'ExampleNdesSigning')).Kind | Should -Be 'Equivalent'
            # The online Enrollment Agent builds the subject from AD (no ENROLLEE_SUPPLIES_SUBJECT): not an NDES template.
            Test-MspkiNdesRaTemplate -Template (& $T 'EnrollmentAgent' -NameFlag 2181038080) | Should -BeNullOrEmpty
            Test-MspkiNdesRaTemplate -Template (& $T 'ExampleWebServer' -Eku @('1.3.6.1.5.5.7.3.1')) | Should -BeNullOrEmpty
        }
    }

    It 'lists who may enroll: default admins and broad groups set apart, deny ACEs and unpublished templates ignored' {
        $acl = @((& $script:ace "$($script:dom)-512"), (& $script:ace 'S-1-5-32-544'), (& $script:ace "$($script:dom)-513"), (& $script:ace "$($script:dom)-1119"), (& $script:ace "$($script:dom)-1200" 'Deny'))
        $t1 = & $script:tpl 'ExampleNdesSigning' -Acl $acl
        $t2 = & $script:tpl 'ExampleNdesUnpublished' -Acl @((& $script:ace "$($script:dom)-1300"))
        $r = InModuleScope MspkiHealthCheck -Parameters @{ A = $t1; B = $t2 } { param($A, $B) Get-MspkiNdesTemplatePrincipal -Templates @($A, $B) -PublishedNames @('ExampleNdesSigning') }
        @($r.Templates).Count | Should -Be 2
        ($r.Templates | Where-Object { $_.Name -eq 'ExampleNdesUnpublished' }).Published | Should -BeFalse
        $by = @{}; foreach ($p in $r.Principals) { $by[$p.Sid] = $p }
        $by["$($script:dom)-512"].Class | Should -Be 'DefaultAdmin'
        $by['S-1-5-32-544'].Class | Should -Be 'DefaultAdmin'
        $by["$($script:dom)-513"].Class | Should -Be 'Broad'
        $by["$($script:dom)-1119"].Class | Should -Be 'Candidate'
        $by.ContainsKey("$($script:dom)-1200") | Should -BeFalse
        $by.ContainsKey("$($script:dom)-1300") | Should -BeFalse
    }
}

Describe 'NDES accounts and the hosts they name' {
    It 'reads a service account with two HTTP SPNs as two separate values and keeps the full name only' {
        $rec = @{ objectclass = @('top', 'person', 'organizationalPerson', 'user'); samaccountname = @('svc-ndes'); distinguishedname = @('CN=svc-ndes,OU=Service,DC=corp,DC=example,DC=test')
            serviceprincipalname = @('HTTP/scep-gw01.corp.example.test', 'HTTP/SCEP-GW01'); useraccountcontrol = @(66048) }
        $a = InModuleScope MspkiHealthCheck -Parameters @{ R = $rec } { param($R) ConvertFrom-MspkiNdesAccountRecord -Record $R }
        $a.Class | Should -Be 'user'
        $a.Domain | Should -Be 'corp.example.test'
        $a.Spns.Count | Should -Be 2
        $a.HttpSpnHosts | Should -Be @('scep-gw01.corp.example.test', 'scep-gw01')
        $h = @(InModuleScope MspkiHealthCheck -Parameters @{ A = $a } { param($A) Get-MspkiNdesAccountHostName -Account $A })
        $h.Count | Should -Be 1
        $h[0].Host | Should -Be 'scep-gw01.corp.example.test'
        $h[0].Constructed | Should -BeFalse
    }

    It 'completes a short SPN with the account domain (constructed), uses dNSHostName of a computer, and gives nothing without SPN' {
        InModuleScope MspkiHealthCheck {
            $short = [pscustomobject]@{ Class = 'user'; SamAccountName = 'svc'; Domain = 'corp.example.test'; DnsHostName = ''; HttpSpnHosts = @('scep-gw02') }
            $h = @(Get-MspkiNdesAccountHostName -Account $short)
            $h[0].Host | Should -Be 'scep-gw02.corp.example.test'
            $h[0].Constructed | Should -BeTrue
            $pc = [pscustomobject]@{ Class = 'computer'; SamAccountName = 'SCEP-GW03$'; Domain = 'corp.example.test'; DnsHostName = 'scep-gw03.corp.example.test'; HttpSpnHosts = @() }
            (@(Get-MspkiNdesAccountHostName -Account $pc))[0].How | Should -Match 'dNSHostName'
            $none = [pscustomobject]@{ Class = 'user'; SamAccountName = 'ra'; Domain = 'corp.example.test'; DnsHostName = ''; HttpSpnHosts = @() }
            @(Get-MspkiNdesAccountHostName -Account $none).Count | Should -Be 0
        }
    }

    It 'reads the computers that may use a gMSA from msDS-GroupMSAMembership (the password is never read)' {
        $sd = New-TestSecurityDescriptor -Aces @(@{ Sid = "$($script:dom)-2001"; Type = 'Allow'; Mask = 0xF01FF })
        $rec = @{ objectclass = @('top', 'computer', 'msDS-GroupManagedServiceAccount'); samaccountname = @('gmsa-ndes$'); distinguishedname = @('CN=gmsa-ndes,CN=Managed Service Accounts,DC=corp,DC=example,DC=test'); 'msds-groupmsamembership' = @(, $sd) }
        $a = InModuleScope MspkiHealthCheck -Parameters @{ R = $rec } { param($R) ConvertFrom-MspkiNdesAccountRecord -Record $R }
        $a.Class | Should -Be 'gmsa'
        $a.AllowedSids | Should -Be @("$($script:dom)-2001")
    }

    It 'finds the host through targeted reads only, records an unreadable SID honestly, and expands one group level' {
        $tpl = & $script:tpl 'ExampleNdesSigning' -Acl @((& $script:ace "$($script:dom)-1119"), (& $script:ace "$($script:dom)-1135"), (& $script:ace "$($script:dom)-1400"))
        $inv = [pscustomobject]@{ AdContext = [pscustomobject]@{ DomainController = 'dc01.corp.example.test'; Ready = $true }; Templates = @($tpl); EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('ExampleNdesSigning') }) }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ I = $inv; D = $script:dom } {
            param($I, $D)
            Mock Read-MspkiNdesAccount {
                if ($Sid -like '*-1119') { return [pscustomobject]@{ Status = 'Found'; Error = ''; Account = [pscustomobject]@{ Class = 'user'; SamAccountName = 'svc-ndes'; Domain = 'corp.example.test'; DnsHostName = ''; HttpSpnHosts = @('scep-gw01.corp.example.test'); Spns = @('HTTP/scep-gw01.corp.example.test'); Members = @(); AllowedSids = @(); Disabled = $false; DistinguishedName = 'CN=svc-ndes,DC=corp,DC=example,DC=test' } } }
                if ($Sid -like '*-1400') { return [pscustomobject]@{ Status = 'Found'; Error = ''; Account = [pscustomobject]@{ Class = 'group'; SamAccountName = 'NDES Servers'; Domain = 'corp.example.test'; DnsHostName = ''; HttpSpnHosts = @(); Spns = @(); Members = @('CN=SCEP-GW02,OU=Servers,DC=corp,DC=example,DC=test'); AllowedSids = @(); Disabled = $false; DistinguishedName = 'CN=NDES Servers,DC=corp,DC=example,DC=test' } } }
                if ($DistinguishedName -like 'CN=SCEP-GW02*') { return [pscustomobject]@{ Status = 'Found'; Error = ''; Account = [pscustomobject]@{ Class = 'computer'; SamAccountName = 'SCEP-GW02$'; Domain = 'corp.example.test'; DnsHostName = 'scep-gw02.corp.example.test'; HttpSpnHosts = @(); Spns = @(); Members = @(); AllowedSids = @(); Disabled = $false; DistinguishedName = 'CN=SCEP-GW02,OU=Servers,DC=corp,DC=example,DC=test' } } }
                return [pscustomobject]@{ Status = 'NotFound'; Error = 'There is no such object on the server.'; Account = $null }
            }
            Mock Get-MspkiLdapObject { throw 'no direct searches' }
            Find-MspkiNdesTemplateAccountHost -Inventory $I -TimeoutSeconds 3
        }
        @($r.Hosts | ForEach-Object { $_.Host }) | Should -Be @('scep-gw01.corp.example.test', 'scep-gw02.corp.example.test')
        ($r.Hosts | Where-Object { $_.Host -eq 'scep-gw02.corp.example.test' }).How[0] | Should -Match 'member of the group NDES Servers'
        ($r.Principals | Where-Object { $_.Sid -like '*-1135' }).Lookup | Should -Be 'NotFound'
        $r.Lookups | Should -Be 4
        $r.Server | Should -Be 'dc01.corp.example.test'
        $f = @(InModuleScope MspkiHealthCheck -Parameters @{ R = $r } { param($R) Get-MspkiNdesTemplateAccessFinding -Result $R })
        $f.Count | Should -Be 1
        $f[0].Confidence | Should -Be 'Confirmed'
        ($f[0].Evidence -join "`n") | Should -Match 'deleted, or this account may not read it'
        ($f[0].Evidence -join "`n") | Should -Not -Match 'was deleted\.'
    }

    It 'says so when no template has the NDES RA purpose, or none is published' {
        InModuleScope MspkiHealthCheck {
            $none = Get-MspkiNdesTemplateAccessFinding -Result ([pscustomobject]@{ Templates = @(); Principals = @(); Hosts = @(); Lookups = 0; Server = '' })
            $none.StatusCode | Should -Be 'NOT_DISCOVERED'
            $unpub = Get-MspkiNdesTemplateAccessFinding -Result ([pscustomobject]@{ Templates = @([pscustomobject]@{ Name = 'CEPEncryption'; Why = 'x'; Published = $false; AclRead = $true }); Principals = @(); Hosts = @(); Lookups = 0; Server = '' })
            $unpub.StatusCode | Should -Be 'NOT_CONFIGURED'
            $unpub.Message | Should -Match 'no Enterprise CA publishes them'
        }
    }
}

Describe 'NDES analysis through template permissions' {
    BeforeEach { InModuleScope MspkiHealthCheck { Reset-MspkiLeadRegistry; Reset-MspkiProbeCache; Reset-MspkiEntityGraph } }

    It 'registers a Probable NDES lead from the template route when the CA database is not readable (and probes nothing with -SkipNetwork)' {
        $tpl = & $script:tpl 'ExampleNdesSigning' -Acl @((& $script:ace "$($script:dom)-1119"))
        $d = [pscustomobject]@{ Inventory = [pscustomobject]@{ AdContext = [pscustomobject]@{ ForestDomains = @('corp.example.test'); Ready = $true; DomainController = 'dc01.corp.example.test' }; TemplatesRead = $true; Templates = @($tpl)
                EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Config = 'ca01.corp.example.test\Example Issuing CA'; Templates = @('ExampleNdesSigning'); Properties = $null }) } }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ D = $d } {
            param($D)
            Mock Read-MspkiNdesAccount { [pscustomobject]@{ Status = 'Found'; Error = ''; Account = [pscustomobject]@{ Class = 'user'; SamAccountName = 'svc-ndes'; Domain = 'corp.example.test'; DnsHostName = ''; HttpSpnHosts = @('scep-gw01.corp.example.test'); Spns = @('HTTP/scep-gw01.corp.example.test'); Members = @(); AllowedSids = @(); Disabled = $false; DistinguishedName = 'CN=svc-ndes,DC=corp,DC=example,DC=test' } } }
            Mock Get-MspkiNetBiosDomainMap { @{} }
            Mock Invoke-MspkiHttpGet { throw 'must not be called' }
            Invoke-MspkiNdesAnalysis -Discovery $D -TimeoutSeconds 3 -SkipNetwork
        }
        @($r.Hosts).Count | Should -Be 1
        $r.Hosts[0].Host | Should -Be 'scep-gw01.corp.example.test'
        $r.Hosts[0].Classification | Should -Be 'ProbableCandidate'
        @($r.Findings | Where-Object { $_.Message -like 'Classification NotDiscovered*' }).Count | Should -Be 0
        $sk = @($r.Findings | Where-Object { $_.Target -eq 'scep-gw01.corp.example.test' })
        $sk[0].Status | Should -Be 'Skipped'
        ($sk[0].Evidence -join "`n") | Should -Match 'SPN HTTP/scep-gw01.corp.example.test'
        InModuleScope MspkiHealthCheck {
            @(Get-MspkiRelation | Where-Object { $_.Type -eq 'mayEnroll' -and $_.To -eq 'template:examplendessigning' }).Count | Should -Be 1
            @(Get-MspkiRelation | Where-Object { $_.Type -eq 'identifies' -and $_.To -eq 'host:scep-gw01.corp.example.test' -and $_.Confidence -eq 'Inferred' }).Count | Should -Be 1
        }
    }

    It 'reports the missing CA database reader in words, not as an error' {
        $ca = [pscustomobject]@{ Name = 'Example Issuing CA'; Config = 'ca01.corp.example.test\Example Issuing CA'; Properties = [pscustomobject]@{ ConfigUsed = '' } }
        $r = InModuleScope MspkiHealthCheck -Parameters @{ C = $ca } {
            param($C)
            Mock Invoke-MspkiTimeLimitedScript { [pscustomobject]@{ Completed = $true; TimedOut = $false; ElapsedMs = 5; Errors = @(); Output = @(@{ Rows = @(); Errors = @(); Fatal = @{ HResult = '80040154'; Message = 'Class not registered' }; Trace = @() }) } }
            Get-MspkiNdesCaEvidence -CA $C -TimeoutSeconds 3
        }
        $f = @($r.Findings)
        $f[0].Status | Should -Be 'Skipped'
        $f[0].StatusCode | Should -Be 'NOT_APPLICABLE'
        $f[0].Message | Should -Match 'is not installed on this computer'
        $f[0].Message | Should -Not -Match 'CLSID'
        $r.Read | Should -BeFalse
    }
}

Describe 'RA certificates from GetCACert' {
    BeforeAll {
        $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test'
        $script:issuing = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=example, DC=test' -Signer $script:root.Full -WithAki
        $oid = [System.Security.Cryptography.CryptoConfig]::EncodeOID('1.3.6.1.4.1.311.21.8.1.2')
        $v2 = New-TestDer 0x30 (Join-TestBytes @($oid, (ConvertTo-TestDerInteger 100), (ConvertTo-TestDerInteger 0)))
        $ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension('1.3.6.1.4.1.311.21.7', $v2, $false)
        $script:ra = New-TestCertificate -Subject 'CN=SCEP-GW01-MSCEP-RA, O=Example, C=US' -Signer $script:issuing.Full -IsCA $false -WithAki -Eku @('1.3.6.1.4.1.311.20.2.1') -Extensions @($ext)
        $col = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        [void]$col.Add($script:issuing.Public); [void]$col.Add($script:root.Public); [void]$col.Add($script:ra.Public)
        $script:p7 = $col.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs7)
    }

    It 'returns every certificate as its own object with role, issuer and template (no wrapped list)' {
        $certs = @(InModuleScope MspkiHealthCheck -Parameters @{ B = $script:p7 } { param($B) ConvertFrom-MspkiNdesCaCertificate -Bytes $B | ForEach-Object { $_ } })
        $certs.Count | Should -Be 3
        foreach ($c in $certs) { $c.Subject | Should -BeOfType [string] }
        $ra = @($certs | Where-Object { $_.Role -eq 'RA' })
        $ra.Count | Should -Be 1
        $ra[0].TemplateOid | Should -Be '1.3.6.1.4.1.311.21.8.1.2'
        $ra[0].Issuer | Should -Match 'Example Issuing CA'
        $ra[0].Expired | Should -BeFalse
        @($certs | Where-Object { $_.Role -eq 'CA' }).Count | Should -Be 2
    }

    It 'decodes the v1 template name and the v2 template information, and gives nothing without either' {
        InModuleScope MspkiHealthCheck -Parameters @{ Ra = $script:ra.Public; Root = $script:root.Public } {
            param($Ra, $Root)
            $ti = ConvertFrom-MspkiTemplateExtension -Certificate $Ra
            $ti.Oid | Should -Be '1.3.6.1.4.1.311.21.8.1.2'
            $ti.MajorVersion | Should -Be 100
            $ti.MinorVersion | Should -Be 0
            ConvertFrom-MspkiTemplateExtension -Certificate $Root | Should -BeNullOrEmpty
        }
        $name = [System.Text.Encoding]::BigEndianUnicode.GetBytes('SubCA')
        $v1 = New-Object System.Security.Cryptography.X509Certificates.X509Extension('1.3.6.1.4.1.311.20.2', (New-TestDer 0x1E $name), $false)
        $c = New-TestCertificate -Subject 'CN=Example Sub CA' -Extensions @($v1)
        $t = InModuleScope MspkiHealthCheck -Parameters @{ C = $c.Public } { param($C) ConvertFrom-MspkiTemplateExtension -Certificate $C }
        $t.Name | Should -Be 'SubCA'
        $t.Source | Should -Be 'TemplateName'
    }

    It 'links the RA certificates to the service and to their issuer, and the service only to the CA that issued them' {
        InModuleScope MspkiHealthCheck -Parameters @{ B = $script:p7; I = $script:issuing.Public; R = $script:root.Public } {
            param($B, $I, $R)
            Reset-MspkiEntityGraph
            foreach ($pair in @(@($I, 'ca01.corp.example.test\Example Issuing CA'), @($R, 'ca00.corp.example.test\Example Root CA'))) {
                $cid = Add-MspkiEntity -Type 'CACertificate' -Key $pair[0].Thumbprint -Name $pair[0].Subject -Properties @{ SubjectKeyId = (Get-MspkiCertificateSubjectKeyId -Certificate $pair[0]) }
                $caId = Add-MspkiEntity -Type 'CA' -Key $pair[1] -Name $pair[1]
                Add-MspkiRelation -From $cid -Type 'certificateOf' -To $caId -Source 'test'
            }
            $certs = @(ConvertFrom-MspkiNdesCaCertificate -Bytes $B | ForEach-Object { $_ })
            $res = [pscustomobject]@{ Host = 'scep-gw01.corp.example.test'; Confirmed = $true; Classification = 'ConfirmedEndpoint'; Certificates = $certs; CertUrl = 'https://scep-gw01.corp.example.test/scep?GetCACert' }
            Add-MspkiNdesResultToGraph -Result $res -Lead ([pscustomobject]@{ Url = 'https://scep-gw01.corp.example.test/scep' })
            $via = @(Get-MspkiRelation | Where-Object { $_.Type -eq 'enrollsVia' -and $_.From -eq 'service:ndes:scep-gw01.corp.example.test' })
            $via.Count | Should -Be 1
            $via[0].To | Should -Be 'ca:ca01.corp.example.test\example issuing ca'
            $ra = @(Get-MspkiEntityList -Type 'RACertificate')
            $ra.Count | Should -Be 1
            @(Get-MspkiRelation | Where-Object { $_.From -eq $ra[0].Id -and $_.Type -eq 'certificateOf' }).Count | Should -Be 1
            @(Get-MspkiRelation | Where-Object { $_.From -eq $ra[0].Id -and $_.Type -eq 'issuedBy' -and $_.To -eq (Get-MspkiEntityId -Type 'CACertificate' -Key $I.Thumbprint) }).Count | Should -Be 1
            (@(Get-MspkiObservation | Where-Object { $_.EntityId -eq 'service:ndes:scep-gw01.corp.example.test' -and $_.Kind -eq 'Seen' })).Count | Should -Be 1
        }
    }

    It 'does not mark an unconfirmed NDES candidate as seen' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiEntityGraph
            Add-MspkiNdesResultToGraph -Result ([pscustomobject]@{ Host = 'scep-gw09.corp.example.test'; Confirmed = $false; Classification = 'ProbableCandidate'; Certificates = @(); CertUrl = '' }) -Lead ([pscustomobject]@{ Url = 'https://scep-gw09.corp.example.test/scep' })
            @(Get-MspkiObservation | Where-Object { $_.EntityId -eq 'service:ndes:scep-gw09.corp.example.test' -and $_.Kind -eq 'Seen' }).Count | Should -Be 0
            (Get-MspkiEntity -Id 'host:scep-gw09.corp.example.test').Properties['Roles'] | Should -Be 'NDESCandidate'
        }
    }
}

Describe 'Intune Certificate Connector in the graph' {
    It 'adds no connector when nothing matched (counts of 0), and one when something did' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiEntityGraph
            Add-MspkiInventoryToEntityGraph -Inventory ([pscustomobject]@{ IntuneConnector = [pscustomobject]@{ ComputerName = 'PC01'; ProductsMatched = 0; CertificatesMatched = 0; Evidence = @() } })
            @(Get-MspkiEntityList -Type 'Service' | Where-Object { $_.Properties['Kind'] -eq 'IntuneConnector' }).Count | Should -Be 0
            Add-MspkiInventoryToEntityGraph -Inventory ([pscustomobject]@{ IntuneConnector = [pscustomobject]@{ ComputerName = 'PC01'; ProductsMatched = 1; CertificatesMatched = 0; Evidence = @('product') } })
            @(Get-MspkiEntityList -Type 'Service' | Where-Object { $_.Properties['Kind'] -eq 'IntuneConnector' }).Count | Should -Be 1
        }
    }
}

Describe 'Audit 2 M12: hosts found through a group or a gMSA link to the member accounts, which are entities' {
    BeforeAll {
        $script:findM12 = {
            param($Acl)
            $tpl = & $script:tpl 'ExampleNdesSigning' -Acl $Acl
            $inv = [pscustomobject]@{ AdContext = [pscustomobject]@{ DomainController = 'dc01.corp.example.test'; Ready = $true }; Templates = @($tpl); EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = @('ExampleNdesSigning') }) }
            InModuleScope MspkiHealthCheck -Parameters @{ I = $inv; D = $script:dom } {
                param($I, $D)
                Reset-MspkiEntityGraph
                $script:m12dom = $D
                $script:m12acct = { param($cls, $sam, $dn, $hostName, $sid, $members = @(), $allowed = @())
                    [pscustomobject]@{ Status = 'Found'; Error = ''; Account = [pscustomobject]@{ Class = $cls; SamAccountName = $sam; Domain = 'corp.example.test'; DnsHostName = $hostName; HttpSpnHosts = @(); Spns = @(); Members = @($members); AllowedSids = @($allowed); Disabled = $false; DistinguishedName = $dn; Sid = $sid } } }
                Mock Read-MspkiNdesAccount {
                    if ($Sid -like '*-1400') { return (& $script:m12acct 'group' 'NDES Servers' 'CN=NDES Servers,DC=corp,DC=example,DC=test' '' "$($script:m12dom)-1400" @('CN=SCEP-GW02,OU=Servers,DC=corp,DC=example,DC=test')) }
                    if ($Sid -like '*-1500') { return (& $script:m12acct 'gmsa' 'svc-ndes$' 'CN=svc-ndes,CN=Managed Service Accounts,DC=corp,DC=example,DC=test' '' "$($script:m12dom)-1500" @() @("$($script:m12dom)-3003")) }
                    if ($Sid -like '*-3003') { return (& $script:m12acct 'computer' 'SCEP-GW03$' 'CN=SCEP-GW03,OU=Servers,DC=corp,DC=example,DC=test' 'scep-gw03.corp.example.test' "$($script:m12dom)-3003") }
                    if ($DistinguishedName -like 'CN=SCEP-GW02*') { return (& $script:m12acct 'computer' 'SCEP-GW02$' 'CN=SCEP-GW02,OU=Servers,DC=corp,DC=example,DC=test' 'scep-gw02.corp.example.test' "$($script:m12dom)-3002") }
                    return [pscustomobject]@{ Status = 'NotFound'; Error = 'no'; Account = $null }
                }
                $r = Find-MspkiNdesTemplateAccountHost -Inventory $I -TimeoutSeconds 3
                Add-MspkiNdesTemplateAccessToGraph -Result $r
                $rels = @(Get-MspkiRelation)
                [pscustomobject]@{
                    Result = $r; GroupId = (Get-MspkiEntityId -Type 'Account' -Key "$D-1400"); GmsaId = (Get-MspkiEntityId -Type 'Account' -Key "$D-1500")
                    Entities = @(Get-MspkiEntityList -Type 'Account' | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Name = $_.Name; Class = $_.Properties['AccountClass'] } })
                    Rels = @($rels | ForEach-Object { [pscustomobject]@{ From = $_.From; Type = $_.Type; To = $_.To; Confidence = $_.Confidence } })
                    Seen = @(Get-MspkiObservation | Where-Object { $_.Kind -eq 'Seen' } | ForEach-Object { $_.EntityId })
                }
            }
        }
    }

    It 'makes the member computer of a group an Account entity, links it memberOf the group, and lets the member (not the group) identify the host' {
        $r = & $script:findM12 @((& $script:ace "$($script:dom)-1400"))
        $group = $r.GroupId
        $member = @($r.Entities | Where-Object { $_.Name -eq 'SCEP-GW02$' })
        $member.Count | Should -Be 1 -Because 'a member account is an entity'
        $member[0].Class | Should -Be 'computer'
        @($r.Rels | Where-Object { $_.Type -eq 'memberOf' -and $_.From -eq $member[0].Id -and $_.To -eq $group }).Count | Should -Be 1
        @($r.Rels | Where-Object { $_.Type -eq 'identifies' -and $_.From -eq $member[0].Id -and $_.To -eq 'host:scep-gw02.corp.example.test' }).Count | Should -Be 1
        @($r.Rels | Where-Object { $_.Type -eq 'identifies' -and $_.From -eq $group }).Count | Should -Be 0 -Because 'the group names no host itself'
        $r.Seen | Should -Contain $member[0].Id
    }

    It 'does the same for the computers allowed to use a gMSA (mayUse)' {
        $r = & $script:findM12 @((& $script:ace "$($script:dom)-1500"))
        $gmsa = $r.GmsaId
        $c = @($r.Entities | Where-Object { $_.Name -eq 'SCEP-GW03$' })
        $c.Count | Should -Be 1
        @($r.Rels | Where-Object { $_.Type -eq 'mayUse' -and $_.From -eq $c[0].Id -and $_.To -eq $gmsa }).Count | Should -Be 1
        @($r.Rels | Where-Object { $_.Type -eq 'identifies' -and $_.From -eq $c[0].Id -and $_.To -eq 'host:scep-gw03.corp.example.test' }).Count | Should -Be 1
        @($r.Rels | Where-Object { $_.Type -eq 'identifies' -and $_.From -eq $gmsa }).Count | Should -Be 0
    }

    It 'keeps the host list and its "how" text (the lead registration still gets the hosts)' {
        $r = & $script:findM12 @((& $script:ace "$($script:dom)-1400"))
        @($r.Result.Hosts | ForEach-Object { $_.Host }) | Should -Be @('scep-gw02.corp.example.test')
        ($r.Result.Hosts | Where-Object { $_.Host -eq 'scep-gw02.corp.example.test' }).How[0] | Should -Match 'member of the group NDES Servers'
    }
}
