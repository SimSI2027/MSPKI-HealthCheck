# Tests for the Batch E fix N3 (an AIA download above the size cap) of the audit 2 verification (docs/AUDIT-2-VERIFY.md, Fix log 2).
# Loopback server only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'Audit 2 N3: an AIA download above the size cap is not an Information / Confirmed result' {
    BeforeAll {
        $script:routesN3 = [hashtable]::Synchronized(@{})
        $script:serverN3 = Start-TestHttpServer -Routes $script:routesN3
        $script:bN3 = $script:serverN3.Base
        # Larger than the 10 MB general cap (10485760 bytes). A CA certificate is a few KB, so this is not a certificate.
        $big = New-Object byte[] 10600000; $big[0] = 0x30
        $script:routesN3['/big.crt'] = @{ Status = 200; Body = $big; Headers = @{ 'Content-Type' = 'application/x-x509-ca-cert' } }
        $script:routesN3['/big.crl'] = @{ Status = 200; Body = $big }
        $script:probeN3 = {
            param([string]$Path, [string]$Kind)
            InModuleScope MspkiHealthCheck -Parameters @{ U = ($script:bN3 + $Path); K = $Kind } {
                param($U, $K)
                [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry; Reset-MspkiProbeCache; Set-MspkiWebProbeOption
                $lead = Add-MspkiLead -Url $U -Kind $K -Source 'AD:test' -Origin 'test'
                Test-MspkiLeadEndpoint -Lead $lead -Url $lead.Url
            }
        }
    }
    AfterAll { Stop-TestHttpServer -Server $script:serverN3 }

    It 'reports an AIA answer above the cap as a failure, not as Information' {
        $r = & $script:probeN3 '/big.crt' 'AIA'
        $f = @($r.Findings)[0]
        $f.Status | Should -Be 'Fail'
        $f.StatusCode | Should -Be 'SIZE_LIMIT'
        $f.ContentStatus | Should -Be 'Fail'
        $f.Confidence | Should -Not -Be 'Confirmed'
    }

    It 'states the limit that applied to the AIA download (10 MB), not the 64 MB CRL limit, and says a certificate is never that large' {
        $r = & $script:probeN3 '/big.crt' 'AIA'
        $f = @($r.Findings)[0]
        $f.Message | Should -Match '10 MB'
        $f.Message | Should -Not -Match '64 MB'
        $f.Message | Should -Match 'certificate'
        $f.Notes | Should -Not -Match 'large base CRL is normal'
    }

    It 'does not report a CDP answer of 10.6 MB as too large (the CRL cap is 64 MB, so it is read)' {
        $r = & $script:probeN3 '/big.crl' 'CDP'
        @($r.Findings | Where-Object { $_.StatusCode -eq 'SIZE_LIMIT' }).Count | Should -Be 0
    }
}
