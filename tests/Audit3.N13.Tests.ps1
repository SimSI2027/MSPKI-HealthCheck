# Fix log 3, N13 (docs/AUDIT-3-VERIFY.md): during a TLS handshake the Windows chain engine may contact an ldap:// or http:// host named in
# the server's certificate. The tool cannot bound it; it must say so, and say what was measured. Documentation tests.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'N13: the chain engine''s own connections are stated plainly' {
    It 'the run limit of a run with network checks says the host can be any host, ldap:// included, anonymous only, never a bind' {
        $a = InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun -Parameters @{ SkipNetwork = $false }); @($script:MspkiRun.Limits) }
        $l = @($a | Where-Object { $_ -match 'chain' -and $_ -match 'not bounded' })
        $l.Count | Should -Be 1
        $l[0] | Should -Match 'ldap://'
        $l[0] | Should -Match 'any host'
        $l[0] | Should -Match 'anonymous'
        $l[0] | Should -Match 'never a directory bind'
        $l[0] | Should -Match 'server''s certificate'
    }

    It 'a run with -SkipNetwork makes no TLS handshake and does not carry the limit' {
        $b = InModuleScope MspkiHealthCheck { [void](Initialize-MspkiRun -Parameters @{ SkipNetwork = $true }); @($script:MspkiRun.Limits) }
        @($b | Where-Object { $_ -match 'chain building' }).Count | Should -Be 0
    }

    It 'docs/RESEARCH.md records the measurement and CLAUDE.md rule 4 names it as a limit' {
        $research = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'docs\RESEARCH.md'))
        $research | Should -Match 'chain engine contacts hosts the server certificate names'
        $research | Should -Match 'anonymous search'
        $research | Should -Match 'no bind request'
        $claude = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'CLAUDE.md'))
        $claude | Should -Match 'chain engine may itself contact'
        $claude | Should -Match 'never a bind'
    }
}
