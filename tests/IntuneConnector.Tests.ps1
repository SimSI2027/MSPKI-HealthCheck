# Intune Certificate Connector: local detection only (REQUIREMENTS 5.8). Fixtures use invented names.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:srcRoot = Join-Path $script:RepoRoot 'src'
    $script:codeText = {
        param([string]$Path)
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        (@($tokens | Where-Object { $_.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment } | ForEach-Object { $_.Text }) -join ' ')
    }
    $script:svc = { param($n, $d = '', $state = 'Running', $mode = 'Auto', $exe = 'C:\Program Files\Microsoft Intune\PFXCertificateConnector\PfxCreateConnector.exe')
        [pscustomobject]@{ Name = $n; DisplayName = $d; State = $state; StartMode = $mode; ExecutablePath = $exe } }
    $script:local = { param($ev = @(), $methods = @(@{ Method = 'Local:Win32_Service'; Outcome = 'Success'; Items = 1 }, @{ Method = 'Local:Uninstall'; Outcome = 'Success'; Items = 0 }, @{ Method = 'Local:CertStore:My'; Outcome = 'Success'; Items = 0 }))
        [pscustomobject]@{ ComputerName = 'EXAMPLEHOST01'; ServicesChecked = 120; ProductsMatched = 0; CertificatesMatched = 0; Evidence = @($ev); Methods = @($methods | ForEach-Object { [pscustomobject]$_ }) } }
    $script:run = { param($Local, $Ndes = @(), $Computer = 'EXAMPLEHOST01', $Domain = 'corp.example.test')
        InModuleScope MspkiHealthCheck -Parameters @{ L = $Local; N = $Ndes; C = $Computer; D = $Domain } { param($L, $N, $C, $D) Test-MspkiIntuneConnector -Local $L -NdesHosts $N -ComputerName $C -DnsDomain $D } }
}

Describe 'Service executable paths and host names' {
    It 'extracts the executable from a service command line' {
        InModuleScope MspkiHealthCheck {
            Get-MspkiServiceExecutablePath -PathName '"C:\Program Files\Example App\app.exe" -k run' | Should -Be 'C:\Program Files\Example App\app.exe'
            Get-MspkiServiceExecutablePath -PathName 'C:\Example\svc.exe /service' | Should -Be 'C:\Example\svc.exe'
            Get-MspkiServiceExecutablePath -PathName 'C:\Example\svc.exe' | Should -Be 'C:\Example\svc.exe'
            Get-MspkiServiceExecutablePath -PathName '' | Should -Be ''
        }
    }

    It 'recognises this computer by short name and FQDN only' {
        InModuleScope MspkiHealthCheck {
            Test-MspkiIsLocalHost -HostName 'examplehost01' -ComputerName 'EXAMPLEHOST01' | Should -BeTrue
            Test-MspkiIsLocalHost -HostName 'EXAMPLEHOST01.corp.example.test' -ComputerName 'EXAMPLEHOST01' -DnsDomain 'corp.example.test' | Should -BeTrue
            Test-MspkiIsLocalHost -HostName 'examplehost02.corp.example.test' -ComputerName 'EXAMPLEHOST01' -DnsDomain 'corp.example.test' | Should -BeFalse
            Test-MspkiIsLocalHost -HostName 'examplehost01.other.example.test' -ComputerName 'EXAMPLEHOST01' -DnsDomain 'corp.example.test' | Should -BeFalse
            Test-MspkiIsLocalHost -HostName '' -ComputerName 'EXAMPLEHOST01' | Should -BeFalse
        }
    }
}

Describe 'Matching local data against the signatures' {
    It 'treats a documented service name as strong evidence and an unrelated service as none' {
        $ev = InModuleScope MspkiHealthCheck -Parameters @{ S = @((& $script:svc 'PkiCreateConnectorSvc' 'PFX Create Certificate Connector for Microsoft Intune'), (& $script:svc 'Spooler' 'Print Spooler' 'Running' 'Auto' 'C:\Windows\System32\spoolsv.exe')) } { param($S)
            $x = Find-MspkiIntuneConnectorEvidence -Services $S; $x }
        @($ev).Count | Should -Be 1
        $ev[0].Kind | Should -Be 'Service'
        $ev[0].Strength | Should -Be 'Documented'
        $ev[0].Basis | Should -Match 'Documented'
    }

    It 'treats a name that only looks similar as weak evidence' {
        $ev = InModuleScope MspkiHealthCheck -Parameters @{ S = @((& $script:svc 'SomeAgent' 'Example Intune Connector Agent' 'Running' 'Auto' 'C:\Example\agent.exe')) } { param($S) $x = Find-MspkiIntuneConnectorEvidence -Services $S; $x }
        @($ev).Count | Should -Be 1
        $ev[0].Strength | Should -Be 'Pattern'
    }

    It 'matches the connector install folder, products and connector-style certificates' {
        $r = InModuleScope MspkiHealthCheck {
            $svc = @([pscustomobject]@{ Name = 'Other'; DisplayName = 'Other'; State = 'Running'; StartMode = 'Auto'; ExecutablePath = 'C:\Program Files\Microsoft Intune\NDESConnector\x.exe' })
            $prod = @([pscustomobject]@{ DisplayName = 'Certificate Connector for Microsoft Intune'; DisplayVersion = '6.0.1'; Publisher = 'Example'; InstallLocation = '' },
                      [pscustomobject]@{ DisplayName = 'Example Editor'; DisplayVersion = '1.0'; Publisher = 'Example'; InstallLocation = 'C:\Example' })
            $crt = @([pscustomobject]@{ Subject = 'CN=SCEP-GW01-MSCEP-RA, O=Example'; Issuer = 'CN=Example Issuing CA'; Thumbprint = 'AA11'; NotAfter = '2027-01-01T00:00:00Z'; FriendlyName = '' },
                     [pscustomobject]@{ Subject = 'CN=www.example.test'; Issuer = 'CN=Example Issuing CA'; Thumbprint = 'BB22'; NotAfter = '2027-01-01T00:00:00Z'; FriendlyName = '' })
            $x = Find-MspkiIntuneConnectorEvidence -Services $svc -Products $prod -Certificates $crt; $x }
        @($r).Count | Should -Be 3
        (@($r | Where-Object { $_.Kind -eq 'Path' }).Count) | Should -Be 1
        (@($r | Where-Object { $_.Kind -eq 'Product' -and $_.Strength -eq 'Documented' }).Count) | Should -Be 1
        (@($r | Where-Object { $_.Kind -eq 'Certificate' -and $_.Strength -eq 'Pattern' }).Count) | Should -Be 1
        (@($r | Where-Object { $_.Text -match 'Example Editor|www.example.test' }).Count) | Should -Be 0
    }

    It 'keeps every signature in one file, with the Microsoft source named' {
        $sigFile = Join-Path $script:srcRoot 'Discovery\IntuneConnectorSignatures.ps1'
        (Get-Content -LiteralPath $sigFile -Raw) | Should -Match 'learn\.microsoft\.com/en-us/intune/fundamentals/certificates/connector/overview'
        foreach ($f in (Get-ChildItem -LiteralPath $script:srcRoot -Recurse -Filter '*.ps1' -File)) {
            if ($f.Name -eq 'IntuneConnectorSignatures.ps1') { continue }
            [System.IO.File]::ReadAllText($f.FullName) | Should -Not -Match 'PkiCreateConnectorSvc|PkiRevokeConnectorSvc|PfxCreateLegacyConnectorSvc' -Because $f.Name
        }
    }
}

Describe 'Intune connector findings' {
    It 'reports a documented service as detected, with every evidence line, and says that only this computer was checked' {
        $ev = @([pscustomobject]@{ Kind = 'Service'; Strength = 'Documented'; Text = 'Service PkiCreateConnectorSvc ("PFX Create"): state Running, start type Auto, executable C:\x.exe'; Basis = 'Documented: PFX Create Certificate Connector for Microsoft Intune' })
        $f = & $script:run (& $script:local $ev)
        $f.Count | Should -Be 1
        $f[0].Category | Should -Be 'IntuneConnector'
        $f[0].Status | Should -Be 'Information'
        $f[0].StatusCode | Should -Be 'OK'
        $f[0].Confidence | Should -Be 'Confirmed'
        $f[0].Message | Should -Match 'was detected on this computer'
        ($f[0].Evidence -join "`n") | Should -Match 'Service \[Documented\]|Service PkiCreateConnectorSvc'
        ($f[0].Evidence -join "`n") | Should -Match 'this computer only'
        $f[0].Sources | Should -Contain 'Local:Win32_Service'
    }

    It 'does not call weak matches a detected connector (Inferred, "possible")' {
        $ev = @([pscustomobject]@{ Kind = 'Certificate'; Strength = 'Pattern'; Text = 'Certificate CN=SCEP-GW01-MSCEP-RA [AA11]'; Basis = 'weak' })
        $f = & $script:run (& $script:local $ev)
        $f[0].Confidence | Should -Be 'Inferred'
        $f[0].Message | Should -Match 'Possible'
        $f[0].Message | Should -Not -Match 'was detected'
    }

    It 'reports nothing found as not applicable / NOT_DISCOVERED, never as a failure' {
        $f = & $script:run (& $script:local)
        $f[0].Status | Should -Be 'NotApplicable'
        $f[0].StatusCode | Should -Be 'NOT_DISCOVERED'
        $f[0].Confidence | Should -Be 'Confirmed'
        $f[0].Notes | Should -Match 'Only this computer'
    }

    It 'does not claim "not found" when a part of the local read failed' {
        $m = @(@{ Method = 'Local:Win32_Service'; Outcome = 'PermissionDenied'; Items = 0 }, @{ Method = 'Local:Uninstall'; Outcome = 'Success'; Items = 0 }, @{ Method = 'Local:CertStore:My'; Outcome = 'Success'; Items = 0 })
        $f = & $script:run (& $script:local @() $m)
        $f[0].Status | Should -Be 'Skipped'
        $f[0].Confidence | Should -Be 'Unknown'
        ($f[0].Evidence -join "`n") | Should -Match 'Not read: Local:Win32_Service \(PermissionDenied\)'
    }

    It 'reports an NDES host other than this computer as UNSUPPORTED with the Microsoft Graph note, and does not assume it is a connector host' {
        $ndes = @([pscustomobject]@{ Host = 'scep-gw01.corp.example.test'; Classification = 'ConfirmedEndpoint'; Confirmed = $true })
        $f = & $script:run (& $script:local) $ndes
        $u = @($f | Where-Object { $_.StatusCode -eq 'UNSUPPORTED' })
        $u.Count | Should -Be 1
        $u[0].Target | Should -Be 'scep-gw01.corp.example.test'
        $u[0].Status | Should -Be 'Skipped'
        $u[0].Message | Should -Match 'remote connector discovery is not reliable without Microsoft Graph'
        $u[0].Notes | Should -Match 'not assumed to be a connector host'
        @($f | Where-Object { $_.Message -like '*was detected*' }).Count | Should -Be 0
    }

    It 'does not report UNSUPPORTED for this computer or for NDES candidates that are not probable' {
        $ndes = @([pscustomobject]@{ Host = 'examplehost01.corp.example.test'; Classification = 'ConfirmedEndpoint'; Confirmed = $true },
                  [pscustomobject]@{ Host = 'scep-gw09'; Classification = 'UnconfirmedCandidate'; Confirmed = $false })
        $f = & $script:run (& $script:local) $ndes
        @($f | Where-Object { $_.StatusCode -eq 'UNSUPPORTED' }).Count | Should -Be 0
        ($f[0].Evidence -join "`n") | Should -Match 'This computer is also an NDES host \(ConfirmedEndpoint\)'
    }
}

Describe 'Reading this computer' {
    It 'reads services, products and certificate metadata without error and keeps only matching entries' {
        $r = InModuleScope MspkiHealthCheck { Get-MspkiIntuneConnectorLocal }
        @($r.Findings | Where-Object { $_.Status -eq 'Error' }).Count | Should -Be 0
        $r.Data.ComputerName | Should -Be $env:COMPUTERNAME
        $r.Data.ServicesChecked | Should -BeGreaterThan 10
        @($r.Data.Methods).Count | Should -Be 3
    }

    It 'turns a failed read into a finding of its own and still reads the other parts' {
        Mock -ModuleName MspkiHealthCheck Get-MspkiLocalServiceInfo { throw (New-Object System.UnauthorizedAccessException('Access is denied.')) }
        $r = InModuleScope MspkiHealthCheck { Get-MspkiIntuneConnectorLocal }
        $p = @($r.Findings | Where-Object { $_.StatusCode -eq 'PERMISSION_DENIED' })
        $p.Count | Should -Be 1
        $p[0].Category | Should -Be 'IntuneConnector'
        (@($r.Data.Methods | Where-Object { $_.Outcome -eq 'Success' })).Count | Should -Be 2
    }

    It 'exposes only metadata of certificates (no key properties)' {
        $c = InModuleScope MspkiHealthCheck { $x = Get-MspkiLocalCertificateMetadata; $x }
        foreach ($item in @($c)) {
            @($item.psobject.Properties.Name | Sort-Object) | Should -Be @('FriendlyName', 'Issuer', 'NotAfter', 'Subject', 'Thumbprint')
        }
    }

    It 'is local only and read-only: no remoting, no remote registry, certificate store opened read-only' {
        foreach ($n in @('Discovery\IntuneConnector.ps1', 'Analyzers\IntuneConnector.ps1')) {
            $t = & $script:codeText (Join-Path $script:srcRoot $n)
            $t | Should -Not -Match '(?i)Invoke-Command|CimSession|PSSession|Get-WmiObject|OpenRemoteBaseKey' -Because $n
        }
        (& $script:codeText (Join-Path $script:srcRoot 'Discovery\IntuneConnector.ps1')) | Should -Match 'OpenFlags \] :: ReadOnly'
    }
}
