# Behavioural tests for audit 2 M4 (the retrieval-order check), added in Batch E of the verification (docs/AUDIT-2-VERIFY.md, Fix log 2).
# The M4 tests of the fix commit call functions that did not exist before it, so against the old code they fail on a missing function
# and show nothing about the old behaviour. These tests use only what exists on both sides: the whole hierarchy analysis
# (Invoke-MspkiHierarchyAnalysis) with a certificate whose CDP URLs are given, and probe findings built by hand. They fail on the old
# code because of the old WRONG RESULT (a Skipped or Pass where a Fail belongs), not because of a missing function.
# Hosts are example.test names only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    # Runs the hierarchy analysis for one issuing CA whose certificate carries these CDP URLs, with these probe findings
    # (Endpoint = the URL the way the probes record it: normalised, a space written as %20).
    $script:analyse = {
        param([string[]]$CdpUrls, [object[]]$ProbeFindings)
        $root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
        $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $root.Full -DaysValid 700 -WithAki -CdpUrls $CdpUrls
        $mk = { param($c, $n, $role, $self) [pscustomobject]@{ Thumbprint = $c.Thumbprint; CAName = $n; Role = $role; Lifecycle = 'Current'; InAIA = $true; InNTAuth = $true
            Info = [pscustomobject]@{ KeyAlgorithm = 'RSA'; KeySize = 2048; SelfIssued = $self } } }
        $d = [pscustomobject]@{
            Inventory = [pscustomobject]@{ CACertificates = @((& $mk $root.Public 'Example Root CA' 'EnterpriseRoot' $true), (& $mk $sub.Public 'Example Issuing CA' 'EnterpriseSubordinate' $false))
                EnterpriseCAs = @([pscustomobject]@{ Name = 'Example Root CA'; CommonName = 'Example Root CA'; DnsHostName = 'ca01.example.test' }); Leads = @(); NdesHosts = @() }
            Certificates = @{ $root.Public.Thumbprint = $root.Public; $sub.Public.Thumbprint = $sub.Public }
        }
        Mock -ModuleName MspkiHealthCheck Get-MspkiLocalIssuedCertificate { @() }
        $fs = @(InModuleScope MspkiHealthCheck -Parameters @{ D = $d; F = @($ProbeFindings) } { param($D, $F)
            Reset-MspkiEntityGraph; Reset-MspkiProbeCache
            Invoke-MspkiHierarchyAnalysis -Discovery $D -Findings $F -SkipNetwork })
        return @($fs | Where-Object { $_.Category -eq 'CDP' -and $_.Sources -contains 'Analysis:RetrievalOrder' })
    }
    $script:probe = { param([string]$Url, [string]$Status, [string]$Code = 'OK') [pscustomobject]@{ Endpoint = $Url; Category = 'CDP'; Status = $Status; StatusCode = $Code } }
}

Describe 'Audit 2 M4, behaviour of the whole retrieval-order analysis' {
    It 'reports a failing CDP URL that contains a space as a Fail, not as "not tested" (the certificate has the space, the probe the %20)' {
        $r = & $script:analyse @('http://pki.example.test/CertEnroll/Example Issuing CA.crl') @(& $script:probe 'http://pki.example.test/CertEnroll/Example%20Issuing%20CA.crl' 'Fail' 'HTTP_404')
        @($r).Count | Should -Be 1
        $r[0].Status | Should -Be 'Fail'
        $r[0].Message | Should -Not -Match 'was tested from here'
    }

    It 'matches an explicit default port and another host case: a working URL is a Pass, not "not tested"' {
        $r = & $script:analyse @('http://PKI.example.test:80/CertEnroll/ca.crl') @(& $script:probe 'http://pki.example.test/CertEnroll/ca.crl' 'Pass')
        @($r).Count | Should -Be 1
        $r[0].Status | Should -Be 'Pass'
    }

    It 'does not count a Warning for the wrong content as a working URL: the only URL gave no usable object, so it is a Fail, not a Pass' {
        $r = & $script:analyse @('http://pki.example.test/CertEnroll/a.crl') @(& $script:probe 'http://pki.example.test/CertEnroll/a.crl' 'Warning' 'CONTENT_WRONG_TYPE')
        @($r).Count | Should -Be 1
        $r[0].Status | Should -Be 'Fail'
    }
}
