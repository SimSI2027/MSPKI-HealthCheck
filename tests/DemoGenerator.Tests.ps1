# The demo site's generator (docs/DEMO-SITE.md, ROADMAP DS1-DS3): the world's public PKI material, the simulation boundary and the
# scenarios. The world uses the fictional demo names of docs/DEMO-WORLD.md (read from site\world by path; tests themselves name only
# example.test). Developer-only tools live in tools\dev and are never referenced by the product (Hygiene.Tests.ps1).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:World = Join-Path $script:RepoRoot 'site\world'
    $script:Pki = Join-Path $script:World 'pki'
    $script:DevTools = Join-Path $script:RepoRoot 'tools\dev\demo-site'
    $script:PkiDoc = Get-Content -Raw -LiteralPath (Join-Path $script:Pki 'pki.json') | ConvertFrom-Json
    $script:DemoClock = [DateTime]::Parse($script:PkiDoc.DemoClock, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
}

Describe 'DS2: the world PKI (public material only, verified with the engine''s own code)' {
    It 'holds only public certificates and CRLs, each listed once in pki.json' {
        $files = @(Get-ChildItem -LiteralPath $script:Pki -File)
        @($files | Where-Object { $_.Extension -notin @('.cer', '.crl', '.json') }).Count | Should -Be 0
        @($files | Where-Object { $_.Extension -eq '.json' }).Count | Should -Be 1
        $listed = @($script:PkiDoc.Files | ForEach-Object { $_.File })
        @($listed | Select-Object -Unique).Count | Should -Be $listed.Count
        foreach ($f in @($files | Where-Object { $_.Extension -ne '.json' })) { $listed | Should -Contain $f.Name }
        foreach ($f in @($files | Where-Object { $_.Extension -eq '.cer' })) {
            $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [System.IO.File]::ReadAllBytes($f.FullName))
            $c.HasPrivateKey | Should -BeFalse -Because $f.Name
            $c.Subject | Should -Match '(?i)DC=(alcyone-orbital|flightops), DC=example$|\.(alcyone-orbital)\.example$|alcyone-orbital\.example$|O=Alcyone Orbital Systems' -Because $f.Name
        }
    }

    It 'verifies every certificate and CRL with the key of its issuer (found by key id), and the forged root verifies nothing' {
        $certs = @{}
        foreach ($f in @($script:PkiDoc.Files | Where-Object Kind -eq 'Certificate')) { $certs[$f.File] = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [System.IO.File]::ReadAllBytes((Join-Path $script:Pki $f.File))) }
        $out = InModuleScope MspkiHealthCheck -Parameters @{ Pki = $script:Pki; Doc = $script:PkiDoc; Certs = $certs } {
            param($Pki, $Doc, $Certs)
            $bySki = @{}
            foreach ($k in $Certs.Keys) { $ski = Get-MspkiCertificateSubjectKeyId -Certificate (New-MspkiCertificate -Bytes $Certs[$k].RawData); if (-not $bySki.ContainsKey($ski)) { $bySki[$ski] = $Certs[$k] } }
            $res = @()
            foreach ($f in $Doc.Files) {
                $bytes = [System.IO.File]::ReadAllBytes((Join-Path $Pki $f.File))
                if ($f.Kind -eq 'Certificate') {
                    $aki = Get-MspkiCertificateAuthorityKeyId -Certificate (New-MspkiCertificate -Bytes $bytes)
                    $issuer = $(if ($aki) { $bySki[$aki] } else { $Certs[$f.File] })
                }
                else { $issuer = $bySki[(ConvertFrom-MspkiCrl -Bytes $bytes).AuthorityKeyId] }
                $v = $(if ($null -ne $issuer) { (Test-MspkiSignature -SignedBytes $bytes -Issuer $issuer).Valid } else { $null })
                $res += [pscustomobject]@{ File = $f.File; Valid = $v }
            }
            $forged = $Certs['lodestar-forged.cer']
            $res += [pscustomobject]@{ File = 'issuing CA checked with the forged root'; Valid = (Test-MspkiSignature -SignedBytes $Certs['meridian-g1.cer'].RawData -Issuer $forged).Valid }
            $res
        }
        foreach ($r in @($out | Where-Object { $_.File -notlike '*forged root' })) { $r.Valid | Should -BeTrue -Because $r.File }
        @($out | Where-Object { $_.File -like '*forged root' })[0].Valid | Should -BeFalse
        $certs['lodestar-forged.cer'].Subject | Should -Be $certs['lodestar-root.cer'].Subject
        $certs['lodestar-forged.cer'].GetPublicKeyString() | Should -Not -Be $certs['lodestar-root.cer'].GetPublicKeyString()
    }

    It 'is dated around the demo clock: only the scenario material meant to be expired is expired' {
        $expiredOk = @('meridian-expired.cer', 'meridian-expired-crl.crl', 'meridian-expired-delta.crl')
        foreach ($f in $script:PkiDoc.Files) {
            $end = [DateTime]::Parse($(if ($f.Kind -eq 'Certificate') { $f.NotAfter } else { $f.NextUpdate }), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
            if ($expiredOk -contains $f.File) { $end | Should -BeLessThan $script:DemoClock -Because $f.File } else { $end | Should -BeGreaterThan $script:DemoClock -Because $f.File }
        }
    }

    It 'creates keys in memory only: the generator never exports, persists or stores a private key' {
        $code = Get-Content -Raw -LiteralPath (Join-Path $script:DevTools 'New-MspkiWorldPki.ps1')
        $code | Should -Not -Match '(?i)ExportParameters\(\s*\$true|ExportPkcs8|ExportRSAPrivateKey|ExportEncrypted|ExportCspBlob|\.Export\(|PersistKeyInCsp|CngKeyCreationParameters|CspParameters|X509Store|CopyWithPrivateKey|\.pfx|\.p12|\.key\b'
        $code | Should -Match 'ExportParameters\(\$false\)'
        @([regex]::Matches($code, 'WriteAll(Bytes|Text)\(\(Join-Path \$Output')).Count | Should -Be 3
        @([regex]::Matches($code, 'WriteAll(Bytes|Text)\(')).Count | Should -Be 3
    }
}
