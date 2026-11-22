BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:rootSubject = 'CN=Example Root CA, DC=example, DC=test'
    $script:subSubject = 'CN=Example Issuing CA, DC=corp, DC=example, DC=test'

    # Synthetic inventory entries (the shape Merge-MspkiCACertificate exports); no certificates are needed here.
    $script:entry = {
        param([hashtable]$o)
        $d = @{
            Thumbprint = 'AA00'; CAName = ''; Role = 'EnterpriseSubordinate'; Lifecycle = 'Current'; LifecycleConfidence = 'Confirmed'; LifecycleBasis = 'CA reports Valid'
            Generation = 'V0.0'; Sources = @('AD:AIA', 'CA:GetCAProperty'); InAIA = $true; InCertificationAuthorities = $false; InNTAuth = $true; InEnrollmentServices = $true
            Subject = $script:subSubject; Issuer = $script:rootSubject; SelfIssued = $false; NotAfter = '2030-01-01T00:00:00Z'
        }
        foreach ($k in $o.Keys) { $d[$k] = $o[$k] }
        [pscustomobject]@{
            Thumbprint = $d.Thumbprint; CAName = $d.CAName; Role = $d.Role; Lifecycle = $d.Lifecycle; LifecycleConfidence = $d.LifecycleConfidence; LifecycleBasis = $d.LifecycleBasis
            Generation = $d.Generation; Sources = $d.Sources; InAIA = $d.InAIA; InCertificationAuthorities = $d.InCertificationAuthorities; InNTAuth = $d.InNTAuth
            InEnrollmentServices = $d.InEnrollmentServices
            Info = [pscustomobject]@{ Subject = $d.Subject; Issuer = $d.Issuer; SelfIssued = $d.SelfIssued; NotAfter = $d.NotAfter }
        }
    }
    $script:rootEntry = { param([hashtable]$o = @{}) $h = @{ Thumbprint = 'R001'; Role = 'StandaloneRoot'; Subject = $script:rootSubject; Issuer = $script:rootSubject; SelfIssued = $true
        InAIA = $false; InCertificationAuthorities = $true; InNTAuth = $false; Sources = @('AD:CertificationAuthorities'); LifecycleConfidence = 'Inferred' }
        foreach ($k in $o.Keys) { $h[$k] = $o[$k] }; & $script:entry $h }
    $script:subEntry = { param([hashtable]$o = @{}) $h = @{ CAName = 'Example Issuing CA' }; foreach ($k in $o.Keys) { $h[$k] = $o[$k] }; & $script:entry $h }

    $script:inv = {
        param($Entries, $Props = $null, $AdTemplates = @('Machine', 'User'), $AdThumbs = @('AA00'), $Templates = $null)
        [pscustomobject]@{
            CACertificates = @($Entries)
            EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = $AdTemplates; CertificateThumbprints = $AdThumbs; Properties = $Props })
            TemplatesRead = ($null -ne $Templates)
            Templates = @($Templates)
        }
    }
    # A template object with the fields the review reads; Eku decides whether it can be used to sign in.
    $script:tpl = {
        param([string]$Name, [string[]]$Eku)
        [pscustomobject]@{ Name = $Name; ApplicationPolicies = @(); Eku = @($Eku); NameFlag = 0; EnrollmentFlag = 0; RaSignature = 0; RaApplicationPolicies = @(); Acl = @(); OwnerSid = ''; Owner = '' }
    }
    $script:clientAuth = '1.3.6.1.5.5.7.3.2'
    $script:serverAuth = '1.3.6.1.5.5.7.3.1'
    $script:props = {
        param($Templates = @('Machine', 'User'), $Signing = @(@{ Thumbprint = 'AA00'; State = 'Valid'; CAVersion = 'V0.0' }))
        [pscustomobject]@{
            Templates = @($Templates | ForEach-Object { [pscustomobject]@{ Name = $_; Oid = '1.2.3' } })
            SigningCertificates = @($Signing | ForEach-Object { [pscustomobject]$_ })
        }
    }
    $script:run = { param($inv) InModuleScope MspkiHealthCheck -Parameters @{ I = $inv } { param($I) Test-MspkiAdContainerConsistency -Inventory $I } }
}

Describe 'Test-MspkiAdContainerConsistency: publication in the AD PKI containers' {
    It 'passes when the current certificate, its root and NTAuth are all published' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry)))
        $pub = @($f | Where-Object { $_.Message -like '*published in the AD PKI containers*' })
        $pub.Count | Should -Be 1
        $pub[0].Status | Should -Be 'Pass'
        $pub[0].Category | Should -Be 'ADContainer'
        $pub[0].Confidence | Should -Be 'Confirmed'
        ($pub[0].Evidence -join "`n") | Should -Match 'Certification Authorities container: root .* published'
    }

    It 'warns (NOT_DISCOVERED, review only) when a CA that publishes a template for signing in is missing from NTAuthCertificates' {
        $tpls = @((& $script:tpl 'Machine' $script:serverAuth), (& $script:tpl 'User' $script:clientAuth))
        $f = & $script:run (& $script:inv -Entries @((& $script:rootEntry), (& $script:subEntry @{ InNTAuth = $false })) -Templates $tpls)
        $w = @($f | Where-Object { $_.Status -eq 'Warning' })
        $w.Count | Should -Be 1
        $w[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        $w[0].Message | Should -Match 'NTAuthCertificates'
        $w[0].Message | Should -Not -Match 'AIA container'
        $w[0].Notes | Should -Match 'sign in to AD'
        ($w[0].Evidence -join "`n") | Should -Match 'publishes 1 template\(s\) that can be used to sign in: User'
    }

    It 'only informs (no warning) when the CA is missing from NTAuthCertificates but publishes no template for signing in' {
        $tpls = @((& $script:tpl 'Machine' $script:serverAuth), (& $script:tpl 'User' $script:serverAuth))
        $f = & $script:run (& $script:inv -Entries @((& $script:rootEntry), (& $script:subEntry @{ InNTAuth = $false })) -Templates $tpls)
        @($f | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 0
        $i = @($f | Where-Object { $_.Message -like '*is not in NTAuthCertificates*' })
        $i.Count | Should -Be 1
        $i[0].Status | Should -Be 'Information'
        $i[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        ($i[0].Evidence -join "`n") | Should -Match 'none of the 2 template\(s\) this CA publishes can be used to sign in'
    }

    It 'only informs, and says why, when the templates were not read so nothing can be said about signing in' {
        $f = & $script:run (& $script:inv -Entries @((& $script:rootEntry), (& $script:subEntry @{ InNTAuth = $false })))
        @($f | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 0
        $i = @($f | Where-Object { $_.Message -like '*is not in NTAuthCertificates*' })
        $i.Count | Should -Be 1
        ($i[0].Evidence -join "`n") | Should -Match 'could not be determined \(the template objects were not read\)'
    }

    It 'treats a template without an EKU as one that can be used to sign in' {
        $f = & $script:run (& $script:inv -Entries @((& $script:rootEntry), (& $script:subEntry @{ InNTAuth = $false })) -Templates @((& $script:tpl 'Machine' @()), (& $script:tpl 'User' $script:serverAuth)))
        @($f | Where-Object { $_.Status -eq 'Warning' -and $_.Message -match 'NTAuthCertificates' }).Count | Should -Be 1
    }

    It 'names every missing place: AIA, NTAuth and the root in Certification Authorities' {
        $tpls = @((& $script:tpl 'Machine' $script:serverAuth), (& $script:tpl 'User' $script:clientAuth))
        $f = & $script:run (& $script:inv -Entries @((& $script:rootEntry @{ InCertificationAuthorities = $false }), (& $script:subEntry @{ InAIA = $false; InNTAuth = $false })) -Templates $tpls)
        $w = @($f | Where-Object { $_.Status -eq 'Warning' })[0]
        $w.Message | Should -Match 'the AIA container'
        $w.Message | Should -Match 'NTAuthCertificates'
        $w.Message | Should -Match 'Certification Authorities container'
        @($w.Evidence | Where-Object { $_ -like '*not found*' }).Count | Should -Be 3
    }

    It 'marks the result Referenced when the CA itself was not read' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry @{ Sources = @('AD:AIA', 'AD:EnrollmentServices') })))
        @($f | Where-Object { $_.Message -like '*published in the AD PKI containers*' })[0].Confidence | Should -Be 'Referenced'
    }

    It 'says so in the evidence when the chain root is not among the discovered certificates' {
        $f = & $script:run (& $script:inv @((& $script:subEntry)))
        $pub = @($f | Where-Object { $_.Message -like '*published in the AD PKI containers*' })
        ($pub[0].Evidence -join "`n") | Should -Match 'Chain root: not found among the discovered CA certificates'
    }

    It 'warns when no CA certificate could be found for an Enterprise CA' {
        $f = & $script:run (& $script:inv @())
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Warning'
        $f[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        $f[0].Confidence | Should -Be 'Referenced'
    }

    It 'reports several certificates without a clear current/historical split' {
        $a = & $script:subEntry @{ Thumbprint = 'AA01'; Lifecycle = 'Unknown'; LifecycleConfidence = 'Inferred'; LifecycleBasis = 'same subject' }
        $b = & $script:subEntry @{ Thumbprint = 'AA02'; Lifecycle = 'Unknown'; LifecycleConfidence = 'Inferred'; LifecycleBasis = 'same subject'; Generation = 'V1.0' }
        $f = & $script:run (& $script:inv @((& $script:rootEntry), $a, $b))
        $split = @($f | Where-Object { $_.Message -like '*no clear current/historical split*' })
        $split.Count | Should -Be 1
        $split[0].Status | Should -Be 'Warning'
        $split[0].Confidence | Should -Be 'Inferred'
        $split[0].Evidence.Count | Should -Be 2
    }

    It 'says plainly when one certificate is current and another one cannot be placed' {
        $unk = & $script:subEntry @{ Thumbprint = 'AA11'; Lifecycle = 'Unknown'; LifecycleConfidence = 'Inferred'; LifecycleBasis = 'in AD only'; Generation = 'V0.0' }
        $cur = & $script:subEntry @{ Thumbprint = 'AA12'; Generation = 'V1.0' }
        $f = & $script:run (& $script:inv @((& $script:rootEntry), $unk, $cur))
        $split = @($f | Where-Object { $_.Message -like '*no clear current/historical split*' })
        $split.Count | Should -Be 1
        $split[0].Message | Should -BeLike '*has 2 CA certificates: one is current, but this run could not tell whether the other one is historical*'
    }

    It 'does not report a split when exactly one certificate is current and the rest are historical' {
        $hist = & $script:subEntry @{ Thumbprint = 'AA09'; Lifecycle = 'Historical'; Generation = 'V0.0'; InNTAuth = $false }
        $cur = & $script:subEntry @{ Thumbprint = 'AA10'; Generation = 'V1.0' }
        $f = & $script:run (& $script:inv @((& $script:rootEntry), $hist, $cur))
        @($f | Where-Object { $_.Message -like '*no clear current/historical split*' }).Count | Should -Be 0
        @($f | Where-Object { $_.Status -eq 'Warning' }).Count | Should -Be 0
    }
}

Describe 'Test-MspkiAdContainerConsistency: AD publication versus the CA properties' {
    It 'passes when templates and certificates agree (template names compared case-insensitively)' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry)) (& $script:props @('machine', 'USER')))
        @($f | Where-Object { $_.Message -like 'The template list in AD and the template list*agree*' })[0].Status | Should -Be 'Pass'
        @($f | Where-Object { $_.Message -like '*carries every certificate*' })[0].Status | Should -Be 'Pass'
    }

    It 'reports templates that exist only in AD or only on the CA as CONFIG_MISMATCH with both lists' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry)) (& $script:props @('Machine', 'WebServer')))
        $t = @($f | Where-Object { $_.Message -like '*differ from the templates the CA reports*' })
        $t.Count | Should -Be 1
        $t[0].Status | Should -Be 'Warning'
        $t[0].StatusCode | Should -Be 'CONFIG_MISMATCH'
        $t[0].Confidence | Should -Be 'Confirmed'
        ($t[0].Evidence -join "`n") | Should -Match 'In AD only: user'
        ($t[0].Evidence -join "`n") | Should -Match 'On the CA only: webserver'
    }

    It 'reports a valid CA certificate that the Enrollment Services object does not carry' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry)) (& $script:props -Signing @(@{ Thumbprint = 'AA00'; State = 'Valid'; CAVersion = 'V0.0' }, @{ Thumbprint = 'BB11'; State = 'Valid'; CAVersion = 'V1.0' })))
        $c = @($f | Where-Object { $_.Message -like '*does not carry*' })
        $c.Count | Should -Be 1
        $c[0].StatusCode | Should -Be 'CONFIG_MISMATCH'
        ($c[0].Evidence -join "`n") | Should -Match 'BB11'
    }

    It 'compares nothing when the CA properties were not read' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry)) $null)
        @($f | Where-Object { $_.Sources -contains 'CA:GetCAProperty' -and $_.Message -like '*template*' }).Count | Should -Be 0
        @($f | Where-Object { $_.Message -like '*Enrollment Services object*' }).Count | Should -Be 0
    }

    It 'handles a missing inventory' {
        $f = & $script:run $null
        @($f | Where-Object { $_ }).Count | Should -Be 0
    }

    It 'never recommends deleting anything and gives every finding a source' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry @{ InCertificationAuthorities = $false }), (& $script:subEntry @{ InAIA = $false; InNTAuth = $false })) (& $script:props @('Machine', 'WebServer')) @('Machine', 'User') @())
        $f.Count | Should -BeGreaterOrEqual 3
        foreach ($x in $f) {
            (@($x.Message, $x.Notes, $x.Remediation, ($x.Evidence -join ' ')) -join ' ') | Should -Not -Match '(?i)\b(delete|remove|purge|clean up)\b'
            @($x.Sources).Count | Should -BeGreaterThan 0
        }
    }
}
