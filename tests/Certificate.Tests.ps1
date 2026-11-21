BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650 -CAVersion 0
    $script:sub0 = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full `
        -DaysBefore 400 -DaysValid 30 -CAVersion 0
    $script:sub1 = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full `
        -DaysBefore 10 -DaysValid 900 -CAVersion 65537 -PreviousHashHex $script:sub0.Public.Thumbprint
}

Describe 'Certificate loading' {
    It 'loads DER, Base64 and PEM and never carries a private key' {
        $der = $script:root.Public.RawData
        $b64 = ConvertTo-TestBase64 $der
        $pem = "-----BEGIN CERTIFICATE-----`r`n" + $b64 + "`r`n-----END CERTIFICATE-----"
        InModuleScope MspkiHealthCheck -Parameters @{ Der = $der; B64 = $b64; Pem = $pem; Tp = $script:root.Public.Thumbprint } {
            param($Der, $B64, $Pem, $Tp)
            foreach ($c in @((New-MspkiCertificate -Bytes $Der), (New-MspkiCertificate -Text $B64), (New-MspkiCertificate -Text $Pem))) {
                $c.Thumbprint | Should -Be $Tp
                $c.HasPrivateKey | Should -BeFalse
            }
            { New-MspkiCertificate -Bytes ([byte[]](1, 2, 3)) } | Should -Throw
        }
    }
}

Describe 'Microsoft CA extensions' {
    It 'decodes CA Version <Hex> as <Label>' -TestCases @(
        @{ Hex = '020100'; Label = 'V0.0' }
        @{ Hex = '020101'; Label = 'V1.0' }
        @{ Hex = '0203010001'; Label = 'V1.1' }
        @{ Hex = '0203020001'; Label = 'V1.2' }
    ) {
        param($Hex, $Label)
        $b = New-Object byte[] ($Hex.Length / 2)
        for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16) }
        InModuleScope MspkiHealthCheck -Parameters @{ B = $b; L = $Label } {
            param($B, $L)
            (ConvertFrom-MspkiCAVersionExtension -RawData $B).Label | Should -Be $L
        }
    }
    It 'returns nothing for malformed CA Version data' {
        InModuleScope MspkiHealthCheck {
            ConvertFrom-MspkiCAVersionExtension -RawData ([byte[]](4, 1, 0)) | Should -BeNullOrEmpty
            ConvertFrom-MspkiCAVersionExtension -RawData ([byte[]](2, 9, 0)) | Should -BeNullOrEmpty
            ConvertFrom-MspkiCAVersionExtension -RawData $null | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-MspkiCertificateInfo' {
    It 'describes a root and a subordinate as plain data' {
        InModuleScope MspkiHealthCheck -Parameters @{ Root = $script:root.Public; Sub = $script:sub1.Public; Prev = $script:sub0.Public.Thumbprint } {
            param($Root, $Sub, $Prev)
            $r = Get-MspkiCertificateInfo -Certificate $Root
            $r.SelfIssued | Should -BeTrue
            $r.IsCA | Should -BeTrue
            $r.KeyAlgorithm | Should -Be 'RSA'
            $r.KeySize | Should -Be 2048
            $r.Sha256 | Should -Match '^[0-9A-F]{64}$'
            $r.NotAfter | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$'
            $r.DaysLeft | Should -BeGreaterThan 3640
            $r.CAVersion | Should -Be 'V0.0'
            $r.KeyUsage | Should -Match 'KeyCertSign'
            $s = Get-MspkiCertificateInfo -Certificate $Sub
            $s.SelfIssued | Should -BeFalse
            $s.CAVersion | Should -Be 'V1.1'
            $s.PreviousCAHash | Should -Be $Prev
            foreach ($p in $s.psobject.Properties) {
                if ($null -ne $p.Value) { $p.Value.GetType().FullName | Should -BeIn @('System.String', 'System.Int32', 'System.Boolean') }
            }
        }
    }
}

Describe 'Merge-MspkiCACertificate' {
    BeforeAll {
        $script:ca = [pscustomobject]@{
            Name = 'Example Issuing CA'; CommonName = 'Example Issuing CA'; DnsHostName = 'ca01.corp.example.test'
            Config = 'ca01.corp.example.test\Example Issuing CA'; Certificates = @($script:sub1.Public)
        }
        $script:props = [pscustomobject]@{
            CATypeName = 'EnterpriseSubordinate'; SigningCertCount = 2
            SigningCertificates = @(
                [pscustomobject]@{ Index = 0; Certificate = $script:sub0.Public; StateName = 'Invalid'; CAVersion = 'V0.0'; CrlStateName = 'Valid' }
                [pscustomobject]@{ Index = 1; Certificate = $script:sub1.Public; StateName = 'Valid'; CAVersion = 'V1.1'; CrlStateName = 'Valid' }
            )
        }
        $script:adEntries = @(
            [pscustomobject]@{ Source = 'AD:CertificationAuthorities'; ObjectName = 'Example Root CA'; Certificate = $script:root.Public }
            [pscustomobject]@{ Source = 'AD:AIA'; ObjectName = 'Example Root CA'; Certificate = $script:root.Public }
            [pscustomobject]@{ Source = 'AD:AIA'; ObjectName = 'Example Issuing CA'; Certificate = $script:sub0.Public }
            [pscustomobject]@{ Source = 'AD:AIA'; ObjectName = 'Example Issuing CA'; Certificate = $script:sub1.Public }
            [pscustomobject]@{ Source = 'AD:NTAuthCertificates'; ObjectName = 'NTAuthCertificates'; Certificate = $script:sub1.Public }
        )
    }

    It 'merges by thumbprint, combines sources and confirms current/historical from the CA' {
        InModuleScope MspkiHealthCheck -Parameters @{ CA = $script:ca; P = $script:props; Ad = $script:adEntries
            Root = $script:root.Public.Thumbprint; S0 = $script:sub0.Public.Thumbprint; S1 = $script:sub1.Public.Thumbprint } {
            param($CA, $P, $Ad, $Root, $S0, $S1)
            $m = @(Merge-MspkiCACertificate -EnterpriseCAs @($CA) -CAProperties @{ $CA.Name = $P } -AdEntries $Ad)
            $m.Count | Should -Be 3
            $cur = $m | Where-Object { $_.Thumbprint -eq $S1 }
            $cur.Lifecycle | Should -Be 'Current'
            $cur.LifecycleConfidence | Should -Be 'Confirmed'
            $cur.Role | Should -Be 'EnterpriseSubordinate'
            $cur.Generation | Should -Be 'V1.1'
            $cur.InNTAuth | Should -BeTrue
            $cur.Sources | Should -Contain 'CA:GetCAProperty'
            $cur.Sources | Should -Contain 'AD:EnrollmentServices'
            $cur.Sources | Should -Contain 'AD:AIA'
            $cur.Sources | Should -Contain 'AD:NTAuthCertificates'
            $cur.Sources.Count | Should -Be 4
            $old = $m | Where-Object { $_.Thumbprint -eq $S0 }
            $old.Lifecycle | Should -Be 'Historical'
            $old.LifecycleConfidence | Should -Be 'Confirmed'
            $r = $m | Where-Object { $_.Thumbprint -eq $Root }
            $r.Role | Should -Be 'StandaloneRoot'
            $r.CAName | Should -Be ''
            $r.Lifecycle | Should -Be 'Current'
            $r.LifecycleConfidence | Should -Be 'Inferred'
            @($r.Sources) | Should -Be @('AD:CertificationAuthorities', 'AD:AIA')
            $f = New-MspkiCACertificateFinding -Entry $cur
            $f.Confidence | Should -Be 'Confirmed'
            $f.Status | Should -Be 'Information'
            $f.StatusCode | Should -Be 'OK'
            $fr = New-MspkiCACertificateFinding -Entry $r
            $fr.Confidence | Should -Be 'Referenced'
            $fr.Notes | Should -Match 'inferred'
        }
    }

    It 'without CA properties: AD current is Referenced, the rest Inferred, never Confirmed' {
        InModuleScope MspkiHealthCheck -Parameters @{ CA = $script:ca; Ad = $script:adEntries
            S0 = $script:sub0.Public.Thumbprint; S1 = $script:sub1.Public.Thumbprint } {
            param($CA, $Ad, $S0, $S1)
            $m = @(Merge-MspkiCACertificate -EnterpriseCAs @($CA) -CAProperties @{} -AdEntries $Ad)
            $cur = $m | Where-Object { $_.Thumbprint -eq $S1 }
            $cur.Lifecycle | Should -Be 'Current'
            $cur.LifecycleConfidence | Should -Be 'Referenced'
            $cur.Role | Should -Be 'EnterpriseSubordinate'
            $old = $m | Where-Object { $_.Thumbprint -eq $S0 }
            $old.Lifecycle | Should -Be 'Historical'
            $old.LifecycleConfidence | Should -Be 'Inferred'
            foreach ($e in $m) {
                (New-MspkiCACertificateFinding -Entry $e).Confidence | Should -Not -Be 'Confirmed'
            }
            $caFinding = New-MspkiEnterpriseCAFinding -CA $CA -Properties $null -Certificates $m
            $caFinding.Confidence | Should -Be 'Referenced'
            $caFinding.Role | Should -Be 'EnterpriseSubordinate'
        }
    }

    It 'flags an AD certificate that the CA does not list as Unknown lifecycle' {
        $stray = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -DaysValid 100
        InModuleScope MspkiHealthCheck -Parameters @{ CA = $script:ca; P = $script:props; Stray = $stray.Public } {
            param($CA, $P, $Stray)
            $ad = @([pscustomobject]@{ Source = 'AD:AIA'; ObjectName = 'Example Issuing CA'; Certificate = $Stray })
            $m = @(Merge-MspkiCACertificate -EnterpriseCAs @($CA) -CAProperties @{ $CA.Name = $P } -AdEntries $ad)
            $s = $m | Where-Object { $_.Thumbprint -eq $Stray.Thumbprint }
            $s.Lifecycle | Should -Be 'Unknown'
            $s.LifecycleBasis | Should -Match 'not among'
        }
    }
}
