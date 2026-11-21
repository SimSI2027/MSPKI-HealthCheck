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
        param($Entries, $Props = $null, $AdTemplates = @('Machine', 'User'), $AdThumbs = @('AA00'))
        [pscustomobject]@{
            CACertificates = @($Entries)
            EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Issuing CA'; Templates = $AdTemplates; CertificateThumbprints = $AdThumbs; Properties = $Props })
        }
    }
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

    It 'warns (NOT_DISCOVERED, review only) when the CA is missing from NTAuthCertificates' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry @{ InNTAuth = $false })))
        $w = @($f | Where-Object { $_.Status -eq 'Warning' })
        $w.Count | Should -Be 1
        $w[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        $w[0].Message | Should -Match 'NTAuthCertificates'
        $w[0].Message | Should -Not -Match 'AIA container'
        $w[0].Notes | Should -Match 'sign in to AD'
    }

    It 'names every missing place: AIA, NTAuth and the root in Certification Authorities' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry @{ InCertificationAuthorities = $false }), (& $script:subEntry @{ InAIA = $false; InNTAuth = $false })))
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

    It 'reports templates that exist only in AD or only on the CA as STALE_DATA with both lists' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry)) (& $script:props @('Machine', 'WebServer')))
        $t = @($f | Where-Object { $_.Message -like '*differ from the templates the CA reports*' })
        $t.Count | Should -Be 1
        $t[0].Status | Should -Be 'Warning'
        $t[0].StatusCode | Should -Be 'STALE_DATA'
        $t[0].Confidence | Should -Be 'Confirmed'
        ($t[0].Evidence -join "`n") | Should -Match 'In AD only: user'
        ($t[0].Evidence -join "`n") | Should -Match 'On the CA only: webserver'
    }

    It 'reports a valid CA certificate that the Enrollment Services object does not carry' {
        $f = & $script:run (& $script:inv @((& $script:rootEntry), (& $script:subEntry)) (& $script:props -Signing @(@{ Thumbprint = 'AA00'; State = 'Valid'; CAVersion = 'V0.0' }, @{ Thumbprint = 'BB11'; State = 'Valid'; CAVersion = 'V1.0' })))
        $c = @($f | Where-Object { $_.Message -like '*does not carry*' })
        $c.Count | Should -Be 1
        $c[0].StatusCode | Should -Be 'STALE_DATA'
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
