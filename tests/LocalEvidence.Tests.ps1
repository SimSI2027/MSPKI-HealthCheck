# Tests for local evidence (WP4 / D3): Lifecycle events, how a certificate got here, trust-store coverage, the enrollment policy helpers
# and the analysis with every local read mocked (no real store, log or registry is touched). example.test names only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test'
    $script:issuing = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=example, DC=test' -Signer $script:root.Full -WithAki
    $oid = [System.Security.Cryptography.CryptoConfig]::EncodeOID('1.3.6.1.4.1.311.21.8.1.7')
    $ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension('1.3.6.1.4.1.311.21.7', (New-TestDer 0x30 (Join-TestBytes @($oid, (ConvertTo-TestDerInteger 100), (ConvertTo-TestDerInteger 2)))), $false)
    $script:leaf = New-TestCertificate -Subject 'CN=pc01.corp.example.test' -Signer $script:issuing.Full -IsCA $false -WithAki -Eku @('1.3.6.1.5.5.7.3.1') -Extensions @($ext)
    $script:foreign = New-TestCertificate -Subject 'CN=Other Device' -IsCA $false
    $script:lcXml = @'
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-CertificateServicesClient-Lifecycle-System"/><EventID>1006</EventID><TimeCreated SystemTime="2026-11-05T13:25:56.000Z"/></System>
<UserData><CertNotificationData ProcessName="svchost.exe" AccountName="CORP\PC01$" Context="Machine"><Action>Enroll</Action><CertificateDetails Thumbprint="XTPX"><Template Name="ExampleRdp" OID="1.3.6.1.4.1.311.21.8.1.7"/><SubjectNames><SubjectName>CN=pc01.corp.example.test</SubjectName></SubjectNames><NotValidAfter>2027-02-03T13:15:56Z</NotValidAfter></CertificateDetails></CertNotificationData></UserData></Event>
'@
}

Describe 'Lifecycle events and certificate origin' {
    It 'reads a Lifecycle event: action, process, account, template and thumbprint' {
        $x = $script:lcXml -replace 'XTPX', 'ab cd ef'
        $e = InModuleScope MspkiHealthCheck -Parameters @{ X = $x } { param($X) ConvertFrom-MspkiLifecycleEventXml -Xml $X -Log 'Lifecycle-System' }
        $e.EventId | Should -Be 1006
        $e.Action | Should -Be 'Enroll'
        $e.Process | Should -Be 'svchost.exe'
        $e.Context | Should -Be 'Machine'
        $e.TemplateName | Should -Be 'ExampleRdp'
        $e.TemplateOid | Should -Be '1.3.6.1.4.1.311.21.8.1.7'
        $e.Thumbprint | Should -Be 'ABCDEF'
        $e.Time | Should -Be '2026-11-05T13:25:56Z'
    }

    It 'names the action from the event id when the event has no <Action>' {
        $x = ($script:lcXml -replace '<Action>Enroll</Action>', '') -replace '<EventID>1006</EventID>', '<EventID>1004</EventID>'
        (InModuleScope MspkiHealthCheck -Parameters @{ X = $x } { param($X) ConvertFrom-MspkiLifecycleEventXml -Xml $X }).Action | Should -Be 'Deleted'
    }

    It 'tells a policy enrollment, autoenrollment, a background enrollment and a manual request apart' {
        InModuleScope MspkiHealthCheck {
            $i = [pscustomobject]@{ TemplateName = ''; TemplateDisplay = 'ExampleRdp'; Issuer = 'CN=Example Issuing CA' }
            $bg = [pscustomobject]@{ Action = 'Enroll'; Process = 'svchost.exe'; Account = 'CORP\PC01$'; Context = 'Machine'; Time = '2026-11-05T13:25:56Z' }
            $o = Get-MspkiCertificateOrigin -Info $i -Events @($bg) -RdpTemplate 'ExampleRdp'
            $o.How | Should -Match 'Remote Desktop certificate policy'
            $o.Confidence | Should -Be 'Confirmed'
            (Get-MspkiCertificateOrigin -Info $i -Events @($bg) -AutoEnrollmentEnabled $true).How | Should -Match 'autoenrollment \(the policy is enabled'
            $g = Get-MspkiCertificateOrigin -Info $i -Events @($bg)
            $g.Confidence | Should -Be 'Inferred'
            $man = [pscustomobject]@{ Action = 'Enroll'; Process = 'mmc.exe'; Account = 'CORP\admin'; Context = 'Machine'; Time = '2026-07-23T20:00:08Z' }
            (Get-MspkiCertificateOrigin -Info $i -Events @($man)).How | Should -Match 'manual request'
            $none = Get-MspkiCertificateOrigin -Info $i -Events @()
            $none.Confidence | Should -Be 'Inferred'
            $none.How | Should -Match 'no Lifecycle event'
        }
    }
}

Describe 'Trust store coverage and policy helpers' {
    It 'passes when every published certificate is present, and warns with the missing ones otherwise' {
        InModuleScope MspkiHealthCheck {
            $exp = @([pscustomobject]@{ Thumbprint = 'AA'; Subject = 'CN=Example Root CA' }, [pscustomobject]@{ Thumbprint = 'BB'; Subject = 'CN=Example Issuing CA' })
            $ok = Test-MspkiTrustStoreCoverage -Container 'NTAuthCertificates' -Store 'Cert:\LocalMachine\NTAuth' -Expected $exp -Present @('AA', 'BB') -Enterprise @('AA')
            $ok.Status | Should -Be 'Pass'
            ($ok.Evidence -join "`n") | Should -Match 'Enterprise store, copied from AD'
            $bad = Test-MspkiTrustStoreCoverage -Container 'NTAuthCertificates' -Store 'Cert:\LocalMachine\NTAuth' -Expected $exp -Present @('AA')
            $bad.Status | Should -Be 'Warning'
            $bad.Message | Should -Match '1 of 2'
            $bad.Message | Should -Match 'Example Issuing CA'
            $bad.Remediation | Should -Match 'Nothing is changed by this tool'
        }
    }

    It 'converts the template cache time and explains the autoenrollment policy value' {
        InModuleScope MspkiHealthCheck {
            $ft = [BitConverter]::GetBytes(([DateTime]'2026-11-05T13:25:55Z').ToUniversalTime().ToFileTimeUtc())
            ConvertFrom-MspkiFileTimeBytes $ft | Should -Be '2026-11-05T13:25:55Z'
            ConvertFrom-MspkiFileTimeBytes ([byte[]](1, 2, 3)) | Should -Be ''
            Get-MspkiAutoEnrollmentPolicyText -Value $null | Should -Match 'not configured'
            Get-MspkiAutoEnrollmentPolicyText -Value 7 | Should -Match 'enabled: enroll and renew, update certificates that use templates, remove revoked'
            Get-MspkiAutoEnrollmentPolicyText -Value 0x8000 | Should -Match 'disabled'
        }
    }

    It 'reads the template and issuer key of a local certificate' {
        $i = InModuleScope MspkiHealthCheck -Parameters @{ C = $script:leaf.Public } { param($C) ConvertTo-MspkiLocalCertificateInfo -Certificate $C -Store 'Cert:\LocalMachine\My' }
        $i.TemplateOid | Should -Be '1.3.6.1.4.1.311.21.8.1.7'
        $i.TemplateMajorVersion | Should -Be 100
        $i.Aki | Should -Not -BeNullOrEmpty
        $i.IsCA | Should -BeFalse
        $i.Eku | Should -Be @('1.3.6.1.5.5.7.3.1')
    }
}

Describe 'Local evidence analysis' {
    BeforeAll {
        $script:runIt = {
            param([switch]$MissNtAuth, [switch]$DenyLog, [switch]$Expiring)
            $p = @{ Leaf = $script:leaf.Public; Foreign = $script:foreign.Public; Root = $script:root.Public; Issuing = $script:issuing.Public; Miss = [bool]$MissNtAuth; Deny = [bool]$DenyLog; Exp = [bool]$Expiring; Xml = $script:lcXml }
            InModuleScope MspkiHealthCheck -Parameters $p {
                param($Leaf, $Foreign, $Root, $Issuing, $Miss, $Deny, $Exp, $Xml)
                Reset-MspkiEntityGraph
                foreach ($c in @($Root, $Issuing)) { [void](Add-MspkiEntity -Type 'CACertificate' -Key $c.Thumbprint -Name $c.Subject -Properties @{ SubjectKeyId = (Get-MspkiCertificateSubjectKeyId -Certificate $c) }) }
                [void](Add-MspkiEntity -Type 'Template' -Key 'ExampleRdp' -Name 'ExampleRdp')
                $inv = [pscustomobject]@{ Templates = @([pscustomobject]@{ Name = 'ExampleRdp'; Oid = '1.3.6.1.4.1.311.21.8.1.7' })
                    CACertificates = @([pscustomobject]@{ Thumbprint = $Root.Thumbprint; CAName = 'Example Root CA'; InCertificationAuthorities = $true; InAIA = $true; InNTAuth = $true; Info = [pscustomobject]@{ Subject = $Root.Subject; SelfIssued = $true; NotAfter = '2099-01-01T00:00:00Z' } }
                        [pscustomobject]@{ Thumbprint = $Issuing.Thumbprint; CAName = 'Example Issuing CA'; InCertificationAuthorities = $false; InAIA = $true; InNTAuth = $true; Info = [pscustomobject]@{ Subject = $Issuing.Subject; SelfIssued = $false; NotAfter = '2099-01-01T00:00:00Z' } }) }
                Mock Read-MspkiLocalStore {
                    $certs = switch ($Name) { 'My' { if ($Location -eq 'LocalMachine') { @($Leaf, $Foreign) } else { @() } } 'Root' { @($Root) } 'CA' { @($Issuing) } 'NTAuth' { if ($Miss) { @($Root) } else { @($Root, $Issuing) } } }
                    [pscustomobject]@{ Store = ('Cert:\{0}\{1}' -f $Location, $Name); Certificates = @($certs); Error = $null }
                }
                Mock Get-MspkiEnterpriseStoreThumbprint { [pscustomobject]@{ Store = $Name; Thumbprints = @(); Exists = $true; Error = $null } }
                Mock Get-MspkiLifecycleEvent {
                    if ($Deny) { return [pscustomobject]@{ Events = @(); Logs = @([pscustomobject]@{ Name = 'Lifecycle-System'; Read = $false; Count = 0; Error = (New-MspkiErrorInfo -Class 'PermissionDenied' -Message 'Attempted to perform an unauthorized operation.') }) } }
                    $e = ConvertFrom-MspkiLifecycleEventXml -Xml ($Xml -replace 'XTPX', $Leaf.Thumbprint) -Log 'Lifecycle-System'
                    [pscustomobject]@{ Events = @($e); Logs = @([pscustomobject]@{ Name = 'Lifecycle-System'; Read = $true; Count = 1; Error = $null }) }
                }
                Mock Get-MspkiEnrollmentEvent {
                    $ev = @()
                    if ($Exp) { $ev = @([pscustomobject]@{ Time = '2026-11-01T00:00:00Z'; EventId = 64; Provider = 'Microsoft-Windows-CertificateServicesClient-AutoEnrollment'; Level = 'Warning'; Data = @{ Context = 'local system'; ObjId = ($Leaf.Thumbprint.ToLowerInvariant() -replace '(..)', '$1 ').Trim() }; Message = 'about to expire' }) }
                    [pscustomobject]@{ Events = $ev; Read = $true; Error = $null }
                }
                Mock Get-MspkiEnrollmentPolicyState { [pscustomobject]@{ TemplateCache = @([pscustomobject]@{ Scope = 'Computer'; Path = 'HKLM\x'; Timestamp = '2026-11-05T13:25:55Z'; Templates = @('ExampleRdp'); Exists = $true; Error = $null }); AutoEnrollment = @(); RdpTemplate = [pscustomobject]@{ Path = 'HKLM\y'; Template = 'ExampleRdp'; Error = $null } } }
                $f = Invoke-MspkiLocalEvidenceAnalysis -Inventory $inv
                [pscustomobject]@{ Findings = @($f); Entities = @(Get-MspkiEntityList -Type 'LocalCertificate'); Relations = @(Get-MspkiRelation); Observations = @(Get-MspkiObservation) }
            }
        }
    }

    It 'explains a certificate from this PKI, links it to its issuer and template, and ignores a foreign one' {
        $r = & $script:runIt
        @($r.Entities).Count | Should -Be 1
        $id = $r.Entities[0].Id
        $r.Entities[0].Properties['Origin'] | Should -Match 'Remote Desktop certificate policy'
        @($r.Relations | Where-Object { $_.From -eq $id -and $_.Type -eq 'issuedBy' }).Count | Should -Be 1
        @($r.Relations | Where-Object { $_.From -eq $id -and $_.Type -eq 'references' -and $_.To -eq 'template:examplerdp' }).Count | Should -Be 1
        @($r.Observations | Where-Object { $_.EntityId -eq $id -and $_.Source -eq 'EventLog' }).Count | Should -Be 1
        @($r.Observations | Where-Object { $_.EntityId -eq 'template:examplerdp' -and $_.Source -eq 'LocalPolicy' }).Count | Should -BeGreaterOrEqual 1
        $how = @($r.Findings | Where-Object { $_.Message -like 'How *' })
        $how.Count | Should -Be 1
        $how[0].Confidence | Should -Be 'Confirmed'
        @($r.Findings | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 0
        @($r.Findings | Where-Object { $_.Status -eq 'Pass' }).Count | Should -Be 3
    }

    It 'warns when an NTAuth certificate from AD is missing locally, and records it as expected but missing' {
        $r = & $script:runIt -MissNtAuth
        $w = @($r.Findings | Where-Object { $_.Status -eq 'Warning' -and $_.Target -eq 'Cert:\LocalMachine\NTAuth' })
        $w.Count | Should -Be 1
        $w[0].Message | Should -Match 'Example Issuing CA'
        @($r.Observations | Where-Object { $_.Kind -eq 'ExpectedMissing' -and $_.Location -eq 'Cert:\LocalMachine\NTAuth' }).Count | Should -Be 1
    }

    It 'reports an unreadable event log as permission denied and still explains the certificate (without the event)' {
        $r = & $script:runIt -DenyLog
        @($r.Findings | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' }).Count | Should -Be 1
        $how = @($r.Findings | Where-Object { $_.Message -like 'How *' })
        $how[0].Confidence | Should -Be 'Inferred'
    }

    It 'warns when autoenrollment says a certificate that is still in the store is expiring' {
        $r = & $script:runIt -Expiring
        $w = @($r.Findings | Where-Object { $_.StatusCode -eq 'OBJECT_EXPIRING' })
        $w.Count | Should -Be 1
        $w[0].Status | Should -Be 'Warning'
    }
}
