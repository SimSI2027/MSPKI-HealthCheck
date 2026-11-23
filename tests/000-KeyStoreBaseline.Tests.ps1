# Records which private keys and personal certificates exist in this user's store BEFORE the other test files run (Pester runs the files of
# a folder in name order, so this file is first and tests/zzz-KeyStoreLeftovers.Tests.ps1 is last). Names only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

Describe 'Key store baseline' {
    It 'records the keys and certificates that exist before the suite' {
        $snap = Get-TestKeyStoreSnapshot
        $file = Join-Path ([System.IO.Path]::GetTempPath()) ('mspki-keystore-baseline-{0}.txt' -f $PID)
        [System.IO.File]::WriteAllLines($file, [string[]]@($snap))
        $env:MSPKI_TEST_KEYSTORE_BASELINE = $file
        Test-Path -LiteralPath $file | Should -BeTrue
    }
}
