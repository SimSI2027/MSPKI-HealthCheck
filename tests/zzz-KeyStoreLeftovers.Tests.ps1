# Runs last (Pester runs the files of a folder in name order). A test that creates a persisted key must remove it, even when it fails part-way
# (docs/AUDIT-3-VERIFY.md, Fix log 3). Names only; no key material is read.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

Describe 'No key is left behind by the suite' {
    It 'leaves no new private key container and no new personal certificate in this user''s store' {
        $file = $env:MSPKI_TEST_KEYSTORE_BASELINE
        if (-not $file -or -not (Test-Path -LiteralPath $file)) {
            Set-ItResult -Skipped -Because 'the baseline file tests/000-KeyStoreBaseline.Tests.ps1 did not run first (a partial run); run the whole tests folder'
            return
        }
        $before = @([System.IO.File]::ReadAllLines($file))
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        Remove-Item Env:\MSPKI_TEST_KEYSTORE_BASELINE -ErrorAction SilentlyContinue
        $after = @(Get-TestKeyStoreSnapshot)
        $new = @($after | Where-Object { $before -notcontains $_ })
        $new.Count | Should -Be 0 -Because ('new entries after the suite: ' + ($new -join '; '))
    }

    It 'every test file that persists a key (PersistKeySet) removes it with Remove-TestCertificateKey, and does so in a finally block or AfterAll' {
        $bad = New-Object System.Collections.ArrayList
        foreach ($f in @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1')) {
            if ($f.Name -in @('TestHelpers.ps1', 'zzz-KeyStoreLeftovers.Tests.ps1', 'Hygiene.Tests.ps1')) { continue }   # the last two only name the flag as text
            $t = [System.IO.File]::ReadAllText($f.FullName)
            if ($t -notmatch 'PersistKeySet') { continue }
            if ($t -notmatch 'Remove-TestCertificateKey' -or $t -notmatch '(?s)(finally\s*\{|AfterAll\s*\{).*Remove-TestCertificateKey') { [void]$bad.Add($f.Name) }
        }
        $bad.Count | Should -Be 0 -Because ('files without a guaranteed key cleanup: ' + ($bad -join ', '))
    }

    It 'the cleanup helper deletes a persisted key (self-test: the key container exists after loading and is gone after the call)' {
        $c = New-TestCertificate -Subject 'CN=keycleanup.example.test' -IsCA $false
        $pfx = $c.Full.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'test-only')
        $before = @(Get-TestKeyStoreSnapshot)
        $loaded = $null
        try {
            $loaded = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx, 'test-only', ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'Exportable,PersistKeySet,UserKeySet'))
            $during = @(Get-TestKeyStoreSnapshot)
            @($during | Where-Object { $before -notcontains $_ }).Count | Should -BeGreaterThan 0
        }
        finally { Remove-TestCertificateKey -Certificate $loaded }
        $after = @(Get-TestKeyStoreSnapshot)
        @($after | Where-Object { $before -notcontains $_ }).Count | Should -Be 0
    }
}
