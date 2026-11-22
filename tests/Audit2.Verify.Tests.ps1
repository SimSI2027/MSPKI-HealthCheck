# Tests for the fixes of the audit 2 verification (docs/AUDIT-2-VERIFY.md, Fix log 2): N1 (a downloaded CA certificate is trusted only
# as an authoritative copy or by its own verified signature), N5 (live domain controllers only), N6 (referrals never chased) and the
# H2 regression (ESC3 shared principals). Hosts are 127.0.0.1 and example.test names only; nothing leaves this computer.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650
    $script:attacker = New-TestCertificate -Subject 'CN=Example Attacker CA' -DaysValid 3650
    $script:sha = { param($c) InModuleScope MspkiHealthCheck -Parameters @{ C = $c } { param($C) Get-MspkiSha256Hex -Bytes $C.RawData } }
    $script:trust = {
        param($Cert, [object[]]$Authoritative, [object[]]$Trusted)
        $auth = @{}
        foreach ($a in $Authoritative) { $auth[(& $script:sha $a)] = $a }
        InModuleScope MspkiHealthCheck -Parameters @{ C = $Cert; A = $auth; T = $Trusted } { param($C, $A, $T)
            Test-MspkiDownloadedCertificateTrust -Certificate $C -Authoritative $A -TrustedIssuers $T }
    }
}

Describe 'Audit 2 N1: a downloaded CA certificate is trusted only as an authoritative copy or by its own verified signature' {
    BeforeAll {
        $script:sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900
    }

    It 'does not trust a certificate with the root''s name and public key that another key signed (forged)' {
        $forged = New-TestForgedCertificate -Subject $script:root.Public.Subject -PublicKeyOf $script:root.Public -IssuerName 'CN=Example Attacker CA' -SigningKey $script:attacker.Key
        $t = & $script:trust $forged @($script:root.Public, $script:sub.Public) @($script:root.Public, $script:sub.Public)
        $t.Trusted | Should -BeFalse
        $t.Basis | Should -Be ''
        $t.SignatureValid | Should -BeNullOrEmpty
        ($t.Lines -join "`n") | Should -Match 'not trusted'
    }

    It 'does not trust a forged self-signed root (the root''s key, self-signature made with another key), and says the signature is invalid' {
        $forged = New-TestForgedCertificate -Subject $script:root.Public.Subject -PublicKeyOf $script:root.Public -IssuerName $script:root.Public.Subject -SigningKey $script:attacker.Key
        $t = & $script:trust $forged @($script:root.Public) @($script:root.Public)
        $t.Trusted | Should -BeFalse
        $t.SignatureValid | Should -BeFalse
    }

    It 'trusts a self-signed root only as an exact copy of the one read from AD or the CA' {
        $copy = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $script:root.Public.RawData)
        $t = & $script:trust $copy @($script:root.Public) @($script:root.Public)
        $t.Trusted | Should -BeTrue
        $t.Basis | Should -Be 'AuthoritativeCopy'
        $t.SignatureValid | Should -BeTrue
        # A genuine, correctly self-signed root that no authoritative source holds proves nothing by itself.
        $other = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysValid 100
        $t2 = & $script:trust $other.Public @($script:root.Public) @($script:root.Public)
        $t2.Trusted | Should -BeFalse
        $t2.SignatureValid | Should -BeTrue
    }

    It 'trusts a subordinate CA certificate that no authoritative source holds when its own signature verifies with a trusted root' {
        $sub2 = New-TestCertificate -Subject 'CN=Example Policy CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900
        $t = & $script:trust $sub2.Public @($script:root.Public) @($script:root.Public)
        $t.Trusted | Should -BeTrue
        $t.Basis | Should -Be 'IssuerSignature'
    }

    It 'does not trust a certificate with the subordinate''s name and key under the root''s name but signed by another key' {
        $forged = New-TestForgedCertificate -Subject $script:sub.Public.Subject -PublicKeyOf $script:sub.Public -IssuerName $script:root.Public.Subject -SigningKey $script:attacker.Key
        $t = & $script:trust $forged @($script:root.Public) @($script:root.Public)
        $t.Trusted | Should -BeFalse
        $t.SignatureValid | Should -BeFalse
    }

    It 'never trusts an end-entity certificate (Basic Constraints: not a CA) as an issuer' {
        $leaf = New-TestCertificate -Subject 'CN=www.corp.example.test' -Signer $script:root.Full -IsCA $false -DaysValid 100
        $t = & $script:trust $leaf.Public @($script:root.Public) @($script:root.Public)
        $t.Trusted | Should -BeFalse
        # A CA certificate really signed with the end-entity key: still not trusted, because an end-entity certificate cannot vouch for it.
        $keyHolder = New-TestCertificate -Subject 'CN=Example Other CA' -DaysValid 50
        $sub3 = New-TestForgedCertificate -Subject 'CN=Example Other CA' -PublicKeyOf $keyHolder.Public -IssuerName $leaf.Public.Subject -SigningKey $leaf.Key -DaysValid 50
        (& $script:trust $sub3 @($script:root.Public) @($script:root.Public, $leaf.Public)).Trusted | Should -BeFalse
    }
}

Describe 'Audit 2 N1: a forged certificate at an AIA location is not followed' {
    BeforeAll {
        $script:routes = [hashtable]::Synchronized(@{})
        $script:server = Start-TestHttpServer -Routes $script:routes
        $b = $script:server.Base
        $script:planted = 'ldap://planted.corp.example.test/CN=Example Root CA,CN=CDP,DC=corp,DC=example,DC=test?certificateRevocationList?base'
        # The discovered issuing CA points its AIA at /root.crt; the file served there is forged: the root's name and public key, any
        # signature, and a planted LDAP and HTTP link.
        $script:newDiscovery = {
            param([string]$AiaUrl, [object[]]$Extra = @())
            $sub = New-TestCertificate -Subject 'CN=Example Issuing CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 900 -AiaUrls @($AiaUrl)
            $certs = @{ $sub.Public.Thumbprint = $sub.Public; $script:root.Public.Thumbprint = $script:root.Public }
            foreach ($x in $Extra) { $certs[$x.Thumbprint] = $x }
            [pscustomobject]@{
                Certificates = $certs
                Inventory = [pscustomobject]@{
                    AdContext = [pscustomobject]@{ DomainController = 'dc01.corp.example.test'; ForestDomains = @('corp.example.test'); TrustedDomains = @(); DomainControllers = @('dc01.corp.example.test') }
                    CACertificates = @([pscustomobject]@{ Thumbprint = $sub.Public.Thumbprint; CAName = 'Example Issuing CA'; Lifecycle = 'Current'; Info = [pscustomobject]@{ Subject = $sub.Public.Subject; NotAfter = '2999-01-01T00:00:00Z' } })
                    EnterpriseCAs = @()
                }
            }
        }
        $script:run = {
            param($D)
            InModuleScope MspkiHealthCheck -Parameters @{ D = $D } { param($D)
                [void](Initialize-MspkiRun); Reset-MspkiLeadRegistry -LocalDomains @('corp.example.test') -DomainControllers @('dc01.corp.example.test')
                Register-MspkiDiscoveredLead -Discovery $D
                Invoke-MspkiEndpointAnalysis -Discovery $D -TimeoutSeconds 5 }
        }
        $script:forgedRoot = New-TestForgedCertificate -Subject $script:root.Public.Subject -PublicKeyOf $script:root.Public -IssuerName 'CN=Example Attacker CA' `
            -SigningKey $script:attacker.Key -CdpUrls @($script:planted, "$b/planted.crl")
        $script:forgedSelf = New-TestForgedCertificate -Subject $script:root.Public.Subject -PublicKeyOf $script:root.Public -IssuerName $script:root.Public.Subject `
            -SigningKey $script:attacker.Key -CdpUrls @($script:planted)
        $script:routes['/forged.crt'] = @{ Status = 200; Body = $script:forgedRoot.RawData }
        $script:routes['/forged-self.crt'] = @{ Status = 200; Body = $script:forgedSelf.RawData }
        $script:routes['/root.crt'] = @{ Status = 200; Body = $script:root.Public.RawData }
    }
    AfterAll { Stop-TestHttpServer -Server $script:server }

    It 'grades it Referenced (key matches, certificate not proven), creates no lead from it and sends no bind' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
        $f = & $script:run (& $script:newDiscovery "$($script:server.Base)/forged.crt")
        $aia = @($f | Where-Object { $_.Category -eq 'AIA' -and $_.Endpoint -like '*/forged.crt' })
        $aia.Count | Should -Be 1
        $aia[0].Status | Should -Be 'Pass'
        $aia[0].Confidence | Should -Be 'Referenced'
        ($aia[0].Evidence -join "`n") | Should -Match 'Trust: not trusted'
        @(InModuleScope MspkiHealthCheck { Get-MspkiLead | Where-Object { $_.Host -eq 'planted.corp.example.test' } }).Count | Should -Be 0
        @($script:server.Log | Where-Object { $_.Path -eq '/planted.crl' }).Count | Should -Be 0
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
    }

    It 'grades a forged self-signed root SIGNATURE_INVALID and follows nothing from it' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLdapObject { throw 'must not be called' }
        $f = & $script:run (& $script:newDiscovery "$($script:server.Base)/forged-self.crt")
        $aia = @($f | Where-Object { $_.Category -eq 'AIA' -and $_.Endpoint -like '*/forged-self.crt' })
        $aia[0].Status | Should -Be 'Fail'
        $aia[0].StatusCode | Should -Be 'SIGNATURE_INVALID'
        Should -Invoke -ModuleName MspkiHealthCheck Get-MspkiLdapObject -Times 0 -Exactly
    }

    It 'still confirms an exact copy of the discovered root at the AIA location' {
        $f = & $script:run (& $script:newDiscovery "$($script:server.Base)/root.crt")
        $aia = @($f | Where-Object { $_.Category -eq 'AIA' -and $_.Endpoint -like '*/root.crt' })
        $aia[0].Status | Should -Be 'Pass'
        $aia[0].Confidence | Should -Be 'Confirmed'
    }

    It 'follows the links of a subordinate CA certificate that no authoritative source holds when its own signature verifies' {
        $b = $script:server.Base
        $policy = New-TestCertificate -Subject 'CN=Example Policy CA, DC=corp, DC=example, DC=test' -Signer $script:root.Full -DaysValid 1000 -CdpUrls @("$b/policy.crl")
        $script:routes['/policy.crt'] = @{ Status = 200; Body = $policy.Public.RawData }
        $issuing = New-TestCertificate -Subject 'CN=Example Issuing CA 2, DC=corp, DC=example, DC=test' -Signer $policy.Full -DaysValid 900 -AiaUrls @("$b/policy.crt")
        $disc = & $script:newDiscovery "$b/root.crt" @($issuing.Public)
        $f = & $script:run $disc
        $aia = @($f | Where-Object { $_.Category -eq 'AIA' -and $_.Endpoint -like '*/policy.crt' })
        $aia[0].Status | Should -Be 'Pass'
        $aia[0].Confidence | Should -Be 'Confirmed'
        @($script:server.Log | Where-Object { $_.Path -eq '/policy.crl' }).Count | Should -BeGreaterThan 0
    }
}
