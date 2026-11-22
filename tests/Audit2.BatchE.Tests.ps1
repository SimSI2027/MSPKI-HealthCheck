# Tests for the Batch E fixes of the audit 2 verification (docs/AUDIT-2-VERIFY.md, Fix log 2): M8 remainder (status codes for the causes
# that still reported RETRIEVAL_FAIL). Hosts are example.test names only; nothing leaves this computer.
# The discovery cases (DIRECTORY_UNAVAILABLE and DC_NOT_FOUND from the RootDSE stage) are in tests/Discovery.Tests.ps1.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    foreach ($g in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1') { . (Join-Path $script:RepoRoot ('src\Gui\' + $g)) }
}

Describe 'Audit 2 M8 remainder: one status code per cause where the error number tells them apart' {
    It 'reports <Name> (<HResult>) as <Code>, not as RETRIEVAL_FAIL' -TestCases @(
        @{ Name = 'a directory server that is not operational'; HResult = '0x8007203A'; Code = 'DIRECTORY_UNAVAILABLE' }
        @{ Name = 'a domain that cannot be contacted'; HResult = '0x8007054B'; Code = 'DIRECTORY_UNAVAILABLE' }
        @{ Name = 'an RPC server that is unavailable'; HResult = '0x800706BA'; Code = 'RPC_FAIL' }
        @{ Name = 'an RPC endpoint that is not registered (service not running)'; HResult = '0x800706D9'; Code = 'RPC_FAIL' }
        @{ Name = 'a network path that was not found'; HResult = '0x80070035'; Code = 'NETWORK_PATH_FAIL' }
    ) {
        param($Name, $HResult, $Code)
        InModuleScope MspkiHealthCheck -Parameters @{ H = $HResult; C = $Code } { param($H, $C)
            $f = New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Unreachable' -Message 'msg' -HResult $H) `
                -Category CA -Target t -Sources 'CA:GetCAProperty' -Action 'testing'
            $f.StatusCode | Should -Be $C
            $f.Status | Should -Be 'Error'
            $f.DiscoveryStatus | Should -Be 'Fail'
        }
    }

    It 'classifies a real exception with the directory-server-down HRESULT the same way' {
        InModuleScope MspkiHealthCheck {
            $ex = New-Object System.Runtime.InteropServices.COMException('The server is not operational.', [int]0x8007203A)
            $f = New-MspkiErrorFinding -ErrorInfo (Get-MspkiErrorInfo $ex) -Category ADDependency -Target t -Sources 'AD:RootDSE' -Action 'testing'
            $f.StatusCode | Should -Be 'DIRECTORY_UNAVAILABLE'
        }
    }

    It 'keeps RETRIEVAL_FAIL when the failure is unreachable but its error number does not say why (the causes cannot be told apart)' {
        InModuleScope MspkiHealthCheck {
            $f = New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Unreachable' -Message 'no detail') `
                -Category CA -Target t -Sources 'CA:GetCAProperty' -Action 'testing'
            $f.StatusCode | Should -Be 'RETRIEVAL_FAIL'
        }
    }

    It 'leaves the other classes alone' {
        InModuleScope MspkiHealthCheck {
            (New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Timeout') -Category CA -Target t -Sources s -Action a).StatusCode | Should -Be 'TIMEOUT'
            (New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'Error') -Category CA -Target t -Sources s -Action a).StatusCode | Should -Be 'INTERNAL_ERROR'
        }
    }
}

Describe 'Audit 2 M8 remainder: an LDAP URL read that fails gets a code for what failed' {
    It 'reports <Name> as <Code>' -TestCases @(
        @{ Name = 'a directory server that is not operational'; Ex = 'down'; Code = 'DIRECTORY_UNAVAILABLE'; N = 1 }
        @{ Name = 'an error that is not classified'; Ex = 'other'; Code = 'DIRECTORY_ERROR'; N = 2 }
        @{ Name = 'an access denied'; Ex = 'denied'; Code = 'PERMISSION_DENIED'; N = 3 }
        @{ Name = 'a missing object'; Ex = 'missing'; Code = 'PUBLICATION_FAIL'; N = 4 }
    ) {
        param($Name, $Ex, $Code, $N)
        InModuleScope MspkiHealthCheck -Parameters @{ Ex = $Ex; Code = $Code; N = $N } { param($Ex, $Code, $N)
            Mock Get-MspkiLdapObject {
                switch ($Ex) {
                    'down' { throw (New-Object System.Runtime.InteropServices.COMException('The server is not operational.', [int]0x8007203A)) }
                    'denied' { throw (New-Object System.UnauthorizedAccessException('denied')) }
                    'missing' { throw (New-Object System.Runtime.InteropServices.COMException('No such object', [int]0x80072030)) }
                    default { throw (New-Object System.Runtime.InteropServices.COMException('An unexpected directory error', [int]0x80004005)) }
                }
            }
            $r = Get-MspkiLdapUrlContent -Url ('ldap:///CN=m8e{0},DC=corp,DC=example,DC=test?cACertificate?base' -f $N) -DefaultServer 'dc01.corp.example.test'
            $r.Code | Should -Be $Code
        }
    }

    It 'counts <Code> as a failure in the retrieval-order check when the scope rule has made it a Warning, as RETRIEVAL_FAIL was' -TestCases @(
        @{ Code = 'DIRECTORY_UNAVAILABLE' }, @{ Code = 'DIRECTORY_ERROR' }
    ) {
        param($Code)
        InModuleScope MspkiHealthCheck -Parameters @{ C = $Code } { param($C)
            $u = 'ldap:///CN=a,DC=corp,DC=example,DC=test'
            $f = New-MspkiFinding -Category 'AIA' -Role 'AIAEndpoint' -Target $u -Endpoint $u -Status 'Warning' -StatusCode $C `
                -Sources 'AD:CA' -Message 'The CA certificate could not be read from LDAP.' -Confidence 'Confirmed'
            $o = Get-MspkiRetrievalOutcome -Findings @($f)
            $o[(Get-MspkiRetrievalUrlKey -Url $u)] | Should -Be 'Failed'
        }
    }
}

Describe 'Audit 2 M8 remainder: the schema accepts the new codes' {
    It 'accepts <Code> as a status code' -TestCases @(
        @{ Code = 'DIRECTORY_UNAVAILABLE' }, @{ Code = 'DIRECTORY_ERROR' }, @{ Code = 'DC_NOT_FOUND' }, @{ Code = 'NETWORK_PATH_FAIL' }
    ) {
        param($Code)
        InModuleScope MspkiHealthCheck -Parameters @{ C = $Code } { param($C)
            (New-MspkiFinding -Category CA -Target t -Status 'Fail' -StatusCode $C -Sources s -Message m).StatusCode | Should -Be $C
        }
    }
}

Describe 'Audit 2 M8 remainder: the GUI and the report can filter on the new codes' {
    It 'finds a finding by <Code> in the GUI search box, and does not find it by another code' -TestCases @(
        @{ Code = 'DIRECTORY_UNAVAILABLE' }, @{ Code = 'DIRECTORY_ERROR' }, @{ Code = 'DC_NOT_FOUND' }, @{ Code = 'NETWORK_PATH_FAIL' }
    ) {
        param($Code)
        $C = $Code
        $mk = { param($Sc) InModuleScope MspkiHealthCheck -Parameters @{ S = $Sc } { param($S) New-MspkiFinding -Category CA -Target t -Status 'Fail' -StatusCode $S -Sources s -Message 'm' } }
        $rows = ConvertTo-MspkiGuiRowList -Findings @((& $mk $C), (& $mk 'RETRIEVAL_FAIL'))
        @(Get-MspkiGuiFilteredRow -Rows $rows -Text $C).Count | Should -Be 1
        @(Get-MspkiGuiFilteredRow -Rows $rows -Text $C)[0].StatusCode | Should -Be $C
    }

    It 'lists the new codes in the status code filter of the report' {
        InModuleScope MspkiHealthCheck {
            $o = New-MspkiHtmlOptions -Values @('DIRECTORY_UNAVAILABLE', 'DIRECTORY_ERROR', 'DC_NOT_FOUND', 'NETWORK_PATH_FAIL', 'RETRIEVAL_FAIL') -AllLabel 'Any status code'
            foreach ($c in @('DIRECTORY_UNAVAILABLE', 'DIRECTORY_ERROR', 'DC_NOT_FOUND', 'NETWORK_PATH_FAIL', 'RETRIEVAL_FAIL')) { $o | Should -Match ('value="{0}"' -f $c) }
        }
    }
}
