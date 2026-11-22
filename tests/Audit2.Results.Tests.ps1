# Tests for the Batch B fixes of audit 2 (docs/AUDIT-2.md): results that were more confident than the evidence (M1, M2, M7),
# the retrieval-order check (M4), redirects (M5), large CRLs (M3), status codes (M8) and the other Medium and Low items.
# Hosts are 127.0.0.1 and example.test names only; nothing leaves this computer.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root1 = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    # The same name with a new key: the renewed root.
    $script:root2 = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 100 -DaysValid 4000
    $script:subNew = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root2.Full -DaysValid 900 -WithAki
}

Describe 'Audit 2 M1: an AIA location that serves the old CA certificate after a renewal is not Verified' {
    It 'is a key mismatch when the old root is known too (the old generation is still in AD) and the subordinate needs the new key' {
        $tp = $script:subNew.Public.Thumbprint
        $known = @{ $tp = $script:subNew.Public; $script:root1.Public.Thumbprint = $script:root1.Public; $script:root2.Public.Thumbprint = $script:root2.Public }
        $m = InModuleScope MspkiHealthCheck -Parameters @{ D = $script:root1.Public; K = $known; Tp = $tp } {
            param($D, $K, $Tp)
            Test-MspkiAiaCertificateMatch -Downloaded $D -Lead ([pscustomobject]@{ Sources = @(('Cert:{0}:AIA' -f $Tp)) }) -KnownCertificates $K -ExpectedIssuer @('CN=Example Root CA, DC=example, DC=test') }
        $m.Result | Should -Be 'KeyMismatch'
    }
    It 'is still Verified when the downloaded certificate is the new root' {
        $tp = $script:subNew.Public.Thumbprint
        $known = @{ $tp = $script:subNew.Public; $script:root1.Public.Thumbprint = $script:root1.Public; $script:root2.Public.Thumbprint = $script:root2.Public }
        $m = InModuleScope MspkiHealthCheck -Parameters @{ D = $script:root2.Public; K = $known; Tp = $tp } {
            param($D, $K, $Tp)
            Test-MspkiAiaCertificateMatch -Downloaded $D -Lead ([pscustomobject]@{ Sources = @(('Cert:{0}:AIA' -f $Tp)) }) -KnownCertificates $K -ExpectedIssuer @('CN=Example Root CA, DC=example, DC=test') }
        $m.Result | Should -Be 'Verified'
    }
}
