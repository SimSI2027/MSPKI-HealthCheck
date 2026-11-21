BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'New-MspkiFinding' {
    It 'fills defaults, layer statuses and a sequential id' {
        InModuleScope MspkiHealthCheck {
            Reset-MspkiFindingSequence
            $f = New-MspkiFinding -Category CA -Target 'Example CA' -Status Information -StatusCode OK `
                -Sources 'AD:EnrollmentServices' -Message 'found'
            $f.Id | Should -Be 'F0001'
            $f.Timestamp | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$'
            $f.Confidence | Should -Be 'Unknown'
            $f.Severity | Should -Be 'None'
            $f.Scope | Should -Be 'Unknown'
            $f.Role | Should -Be 'Unknown'
            foreach ($l in @('DiscoveryStatus', 'DnsStatus', 'TcpStatus', 'HttpStatus', 'RedirectStatus', 'TlsStatus', 'ContentStatus', 'ChainStatus')) {
                $f.$l | Should -Be 'NotTested'
            }
            ,$f.Sources | Should -BeOfType [string[]]
            $f.Sources.Count | Should -Be 1
            ,$f.Evidence | Should -BeOfType [string[]]
            (New-MspkiFinding -Category CA -Target x -Status Pass -StatusCode OK -Sources s -Message m).Id | Should -Be 'F0002'
        }
    }

    It 'normalises the case of enumerated values' {
        InModuleScope MspkiHealthCheck {
            $f = New-MspkiFinding -Category 'ca' -Target x -Status 'information' -StatusCode 'ok' -Sources s -Message m `
                -Confidence 'referenced' -Layers @{ dnsstatus = 'pass' }
            $f.Category | Should -Be 'CA'
            $f.Status | Should -Be 'Information'
            $f.StatusCode | Should -Be 'OK'
            $f.Confidence | Should -Be 'Referenced'
            $f.DnsStatus | Should -Be 'Pass'
        }
    }

    It 'rejects values outside the schema' {
        InModuleScope MspkiHealthCheck {
            { New-MspkiFinding -Category Nope -Target x -Status Pass -StatusCode OK -Sources s -Message m } | Should -Throw
            { New-MspkiFinding -Category CA -Target x -Status Fine -StatusCode OK -Sources s -Message m } | Should -Throw
            { New-MspkiFinding -Category CA -Target x -Status Pass -StatusCode HTTP_401 -Sources s -Message m } | Should -Throw
            { New-MspkiFinding -Category CA -Target x -Status Pass -StatusCode OK -Sources s -Message m -Confidence Likely } | Should -Throw
            { New-MspkiFinding -Category CA -Target x -Status Pass -StatusCode OK -Sources s -Message m -Layers @{ FooStatus = 'Pass' } } | Should -Throw
            { New-MspkiFinding -Category CA -Target x -Status Pass -StatusCode OK -Sources s -Message m -Layers @{ DnsStatus = 'Great' } } | Should -Throw
        }
    }

    It 'requires at least one non-empty source and removes duplicate sources' {
        InModuleScope MspkiHealthCheck {
            { New-MspkiFinding -Category CA -Target x -Status Pass -StatusCode OK -Sources @('', ' ') -Message m } | Should -Throw
            $f = New-MspkiFinding -Category CA -Target x -Status Pass -StatusCode OK -Sources @('AD:AIA', 'AD:AIA', 'CA:GetCAProperty') -Message m
            $f.Sources.Count | Should -Be 2
        }
    }

    It 'keeps the status code list from REQUIREMENTS separate (no merged codes)' {
        InModuleScope MspkiHealthCheck {
            $codes = (Get-MspkiSchema).StatusCode
            $codes.Count | Should -Be 30
            foreach ($c in @('CONFIG_RISK', 'DNS_FAIL', 'TCP_FAIL', 'TIMEOUT', 'HTTP_REDIRECT', 'HTTP_401_403', 'TLS_NAME_MISMATCH',
                    'TLS_UNTRUSTED_ROOT', 'PERMISSION_DENIED', 'NOT_CONFIGURED', 'NOT_DISCOVERED', 'NOT_APPLICABLE', 'UNSUPPORTED')) {
                $codes | Should -Contain $c
            }
        }
    }
}

Describe 'Get-MspkiErrorInfo and New-MspkiErrorFinding' {
    It 'classifies <Name> as <Class>' -TestCases @(
        @{ Name = 'E_ACCESSDENIED'; HResult = [int]0x80070005; Class = 'PermissionDenied' }
        @{ Name = 'server not operational'; HResult = [int]0x8007203A; Class = 'Unreachable' }
        @{ Name = 'no such object'; HResult = [int]0x80072030; Class = 'NotFound' }
        @{ Name = 'RPC server unavailable'; HResult = [int]0x800706BA; Class = 'Unreachable' }
        @{ Name = 'E_INVALIDARG'; HResult = [int]0x80070057; Class = 'Unsupported' }
        @{ Name = 'WAIT_TIMEOUT'; HResult = [int]0x80070102; Class = 'Timeout' }
        @{ Name = 'unknown HRESULT'; HResult = [int]0x80004005; Class = 'Error' }
    ) {
        param($Name, $HResult, $Class)
        InModuleScope MspkiHealthCheck -Parameters @{ HResult = $HResult; Class = $Class } {
            param($HResult, $Class)
            $ex = New-Object System.Runtime.InteropServices.COMException('test', $HResult)
            (Get-MspkiErrorInfo $ex).Class | Should -Be $Class
            $wrapped = New-Object System.Management.Automation.MethodInvocationException('outer', $ex)
            (Get-MspkiErrorInfo $wrapped).Class | Should -Be $Class
        }
    }

    It 'classifies .NET exception types' {
        InModuleScope MspkiHealthCheck {
            (Get-MspkiErrorInfo (New-Object System.UnauthorizedAccessException('x'))).Class | Should -Be 'PermissionDenied'
            (Get-MspkiErrorInfo (New-Object System.TimeoutException('x'))).Class | Should -Be 'Timeout'
            try { throw 'plain failure' } catch { (Get-MspkiErrorInfo $_).Class | Should -Be 'Error' }
        }
    }

    It 'maps <Class> to <Status>/<Code>' -TestCases @(
        @{ Class = 'PermissionDenied'; Status = 'Skipped'; Code = 'PERMISSION_DENIED'; Layer = 'PermissionDenied' }
        @{ Class = 'NotDomainJoined'; Status = 'Skipped'; Code = 'UNSUPPORTED'; Layer = 'Skipped' }
        @{ Class = 'Unsupported'; Status = 'Skipped'; Code = 'UNSUPPORTED'; Layer = 'Skipped' }
        @{ Class = 'NotFound'; Status = 'Information'; Code = 'NOT_DISCOVERED'; Layer = 'Fail' }
        @{ Class = 'Timeout'; Status = 'Error'; Code = 'TIMEOUT'; Layer = 'Timeout' }
        @{ Class = 'Unreachable'; Status = 'Error'; Code = 'RETRIEVAL_FAIL'; Layer = 'Fail' }
        @{ Class = 'Error'; Status = 'Error'; Code = 'RETRIEVAL_FAIL'; Layer = 'Error' }
    ) {
        param($Class, $Status, $Code, $Layer)
        InModuleScope MspkiHealthCheck -Parameters @{ Class = $Class; Status = $Status; Code = $Code; Layer = $Layer } {
            param($Class, $Status, $Code, $Layer)
            $f = New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class $Class -Message 'msg' -HResult '0x80070005') `
                -Category CA -Target t -Sources 'CA:GetCAProperty' -Action 'testing'
            $f.Status | Should -Be $Status
            $f.StatusCode | Should -Be $Code
            $f.DiscoveryStatus | Should -Be $Layer
            $f.Confidence | Should -Be 'Unknown'
            $f.Evidence | Should -Contain 'HResult: 0x80070005'
        }
    }

    It 'honours NotFoundCode and UnreachableStatus' {
        InModuleScope MspkiHealthCheck {
            (New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class NotFound) -Category ADContainer -Target t -Sources s `
                -Action a -NotFoundCode NOT_CONFIGURED).StatusCode | Should -Be 'NOT_CONFIGURED'
            (New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class Unreachable) -Category CA -Target t -Sources s `
                -Action a -UnreachableStatus Fail).Status | Should -Be 'Fail'
        }
    }
}

Describe 'Host scope' {
    It 'returns <Expected> for <HostName>' -TestCases @(
        @{ HostName = 'ca01.corp.example.test'; Expected = 'Local' }
        @{ HostName = 'CA01.CORP.EXAMPLE.TEST.'; Expected = 'Local' }
        @{ HostName = 'corp.example.test'; Expected = 'Local' }
        @{ HostName = 'pki.partner.example.test'; Expected = 'OtherForest' }
        @{ HostName = 'pki.example.test'; Expected = 'External' }
        @{ HostName = 'notcorp.example.test'; Expected = 'External' }
        @{ HostName = 'ca01'; Expected = 'Unknown' }
        @{ HostName = '192.0.2.10'; Expected = 'Unknown' }
        @{ HostName = ''; Expected = 'Unknown' }
    ) {
        param($HostName, $Expected)
        InModuleScope MspkiHealthCheck -Parameters @{ HostName = $HostName; Expected = $Expected } {
            param($HostName, $Expected)
            Get-MspkiHostScope -HostName $HostName -LocalDomains @('corp.example.test') -TrustedDomains @('partner.example.test') |
                Should -Be $Expected
        }
    }
}

Describe 'Get-MspkiExitCode' {
    BeforeAll {
        $script:mk = {
            param($Status, $Code)
            InModuleScope MspkiHealthCheck -Parameters @{ S = $Status; C = $Code } {
                param($S, $C)
                New-MspkiFinding -Category Run -Target t -Status $S -StatusCode $C -Sources s -Message m
            }
        }
    }
    It 'returns 0 for no findings and for inventory-only findings' {
        InModuleScope MspkiHealthCheck { Get-MspkiExitCode -Findings @() | Should -Be 0 }
        $f = & $script:mk 'Information' 'OK'
        InModuleScope MspkiHealthCheck -Parameters @{ F = @($f, (& $script:mk 'Pass' 'OK')) } { param($F) Get-MspkiExitCode -Findings $F | Should -Be 0 }
    }
    It 'applies the precedence 4 > 6 > 5 > 3 > 2' {
        $info = & $script:mk 'Information' 'NOT_DISCOVERED'
        $warn = & $script:mk 'Warning' 'OBJECT_EXPIRING'
        $unsup = & $script:mk 'Skipped' 'UNSUPPORTED'
        $err = & $script:mk 'Error' 'RETRIEVAL_FAIL'
        $perm = & $script:mk 'Skipped' 'PERMISSION_DENIED'
        $fail = & $script:mk 'Fail' 'TCP_FAIL'
        $crit = & $script:mk 'Critical' 'OBJECT_EXPIRED'
        InModuleScope MspkiHealthCheck -Parameters @{ A = @($info, $warn, $unsup, $err, $perm, $fail, $crit) } {
            param($A)
            Get-MspkiExitCode -Findings @($A[0]) | Should -Be 2
            Get-MspkiExitCode -Findings @($A[0], $A[1]) | Should -Be 3
            Get-MspkiExitCode -Findings @($A[0], $A[1], $A[2]) | Should -Be 5
            Get-MspkiExitCode -Findings @($A[1], $A[3]) | Should -Be 5
            Get-MspkiExitCode -Findings @($A[1], $A[2], $A[4]) | Should -Be 6
            Get-MspkiExitCode -Findings @($A[4], $A[5]) | Should -Be 4
            Get-MspkiExitCode -Findings @($A[6]) | Should -Be 4
        }
    }
}

Describe 'Run context and log' {
    It 'records run metadata, methods, stage timings and limits' {
        InModuleScope MspkiHealthCheck {
            $r = Initialize-MspkiRun -Parameters @{ TimeoutSeconds = 5 }
            $r.RunId | Should -Match '^[0-9a-f-]{36}$'
            $r.ToolVersion | Should -Be $script:MspkiToolVersion
            $r.Parameters.TimeoutSeconds | Should -Be '5'
            Add-MspkiMethodOutcome -Method 'AD:RootDSE' -Outcome 'PermissionDenied' -Detail 'x'
            Add-MspkiStageTiming -Stage 'Test' -Stopwatch ([System.Diagnostics.Stopwatch]::StartNew())
            Add-MspkiRunLimit -Text 'limit'
            Add-MspkiRunLimit -Text 'limit'
            $r.Methods.Count | Should -Be 1
            $r.Methods[0].Outcome | Should -Be 'PermissionDenied'
            $r.StageTimings.Count | Should -Be 1
            $r.Limits.Count | Should -Be 1
            (Get-MspkiLogLine | Where-Object { $_ -like '*AD:RootDSE*' }).Count | Should -Be 1
            Set-MspkiRunValue -Name Forest -Value 'corp.example.test'
            (New-MspkiFinding -Category Run -Target t -Status Pass -StatusCode OK -Sources s -Message m).Forest | Should -Be 'corp.example.test'
        }
    }
}

Describe 'Probes' {
    BeforeEach { InModuleScope MspkiHealthCheck { Reset-MspkiProbeCache } }

    It 'resolves localhost and serves the second lookup from the cache' {
        InModuleScope MspkiHealthCheck {
            $a = Resolve-MspkiDnsName -HostName 'localhost' -TimeoutMs 5000
            $a.Status | Should -Be 'Pass'
            $a.StatusCode | Should -Be 'OK'
            $a.FromCache | Should -BeFalse
            $b = Resolve-MspkiDnsName -HostName 'LOCALHOST.' -TimeoutMs 5000
            $b.FromCache | Should -BeTrue
            Get-MspkiProbeCacheCount | Should -Be 1
        }
    }

    It 'reports DNS_FAIL for a name under the reserved .invalid TLD' {
        InModuleScope MspkiHealthCheck {
            $r = Resolve-MspkiDnsName -HostName 'no-such-host.invalid' -TimeoutMs 5000
            $r.Status | Should -BeIn @('Fail', 'Timeout')
            $r.StatusCode | Should -BeIn @('DNS_FAIL', 'TIMEOUT')
        }
    }

    It 'separates TCP pass and TCP fail on loopback' {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            $port = $listener.LocalEndpoint.Port
            InModuleScope MspkiHealthCheck -Parameters @{ Port = $port } {
                param($Port)
                (Test-MspkiTcpPort -HostName '127.0.0.1' -Port $Port -TimeoutMs 3000).Status | Should -Be 'Pass'
            }
        }
        finally { $listener.Stop() }
        InModuleScope MspkiHealthCheck -Parameters @{ Port = $port } {
            param($Port)
            Reset-MspkiProbeCache
            $r = Test-MspkiTcpPort -HostName '127.0.0.1' -Port $Port -TimeoutMs 3000
            $r.Status | Should -BeIn @('Fail', 'Timeout')
            $r.StatusCode | Should -BeIn @('TCP_FAIL', 'TIMEOUT')
        }
    }

    It 'returns the output of a time-limited script and stops waiting after the limit' {
        InModuleScope MspkiHealthCheck {
            $ok = Invoke-MspkiTimeLimitedScript -ScriptBlock { param($a) @{ Value = $a * 2 } } -ArgumentList @(21) -TimeoutSeconds 10
            $ok.Completed | Should -BeTrue
            $ok.Output[0].Value | Should -Be 42
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $slow = Invoke-MspkiTimeLimitedScript -ScriptBlock { Start-Sleep -Seconds 20 } -TimeoutSeconds 1
            $slow.TimedOut | Should -BeTrue
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 10
        }
    }
}
