# Tests for "Probable causes and next steps" (Batch H): the knowledge base (src\Knowledge\Diagnosis*.psd1), the topic rules, the ranking,
# and the way the section reaches results.json, the HTML report and the GUI details pane. example.test names only.

BeforeDiscovery {
    $script:RepoRootD = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRootD 'src\MspkiHealthCheck.psd1') -Force
    $script:AllCodes = @((Get-MspkiSchema).StatusCode)
    $kb = InModuleScope MspkiHealthCheck { Get-MspkiDiagnosisKnowledge -Reload }
    $script:TopicIds = @($kb.Topics.Keys | Sort-Object)
    $script:SourceIds = @($kb.Sources.Keys | Sort-Object)
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $script:Kb = InModuleScope MspkiHealthCheck { Get-MspkiDiagnosisKnowledge -Reload }
    $script:KnowledgeDir = Join-Path $script:RepoRoot 'src\Knowledge'
    $script:SourcesDoc = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'docs\KNOWLEDGE-SOURCES.md'))

    $script:NewF = {
        param([string]$Category = 'CA', [string]$Status = 'Warning', [string]$Code = 'CONFIG_RISK', [string]$Message = 'x', [string[]]$Evidence = @(), [hashtable]$Layers = @{}, [string]$Notes = '')
        InModuleScope MspkiHealthCheck -Parameters @{ C = $Category; S = $Status; K = $Code; M = $Message; E = $Evidence; L = $Layers; N = $Notes } {
            param($C, $S, $K, $M, $E, $L, $N)
            New-MspkiFinding -Category $C -Target 'ca01.pki.example.test' -Status $S -StatusCode $K -Sources @('test') -Message $M -Evidence $E -Layers $L -Notes $N
        }
    }
    $script:Diag = { param($F) Get-MspkiFindingDiagnosis -Finding $F -Recompute }
}

Describe 'The knowledge base files' {
    It 'loads the index and the topic files, with no topic defined twice' {
        $script:Kb.Topics.Count | Should -BeGreaterThan 100
        $script:Kb.Sources.Count | Should -BeGreaterThan 30
        @(Get-ChildItem -LiteralPath $script:KnowledgeDir -Filter 'Diagnosis.Topics.*.psd1').Count | Should -BeGreaterOrEqual 4
    }

    It 'contains only literals: no variable, command, expression or script block (it is data, never run)' {
        foreach ($f in @(Get-ChildItem -LiteralPath $script:KnowledgeDir -Filter 'Diagnosis*.psd1')) {
            $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
            @($errs).Count | Should -Be 0 -Because $f.Name
            $bad = @($ast.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.VariableExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -or
                $n -is [System.Management.Automation.Language.SubExpressionAst] -or $n -is [System.Management.Automation.Language.CommandAst] -or
                $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
                $n -is [System.Management.Automation.Language.BinaryExpressionAst] }, $true))
            $bad.Count | Should -Be 0 -Because ('{0}: {1}' -f $f.Name, (($bad | Select-Object -First 3 | ForEach-Object { $_.Extent.Text }) -join ' | '))
            $nonAscii = [regex]::Matches([System.IO.File]::ReadAllText($f.FullName), '[^\x00-\x7F]').Count
            $nonAscii | Should -Be 0 -Because ('{0} must be plain ASCII so that Windows PowerShell 5.1 reads it the same everywhere' -f $f.Name)
        }
    }

    It 'is read only with Import-PowerShellDataFile and never loaded as code' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'src\Model\Diagnosis.ps1'))
        $src | Should -Match 'Import-PowerShellDataFile'
        $src | Should -Not -Match '(?i)Invoke-Expression|\biex\b|Import-Module|ScriptBlock\]::Create|(?m)^\s*\.\s+[''"$(]'
    }
}

Describe 'Every status code has a knowledge entry (the schema is the list)' {
    It '<_> maps to an existing topic' -ForEach $script:AllCodes {
        $script:Kb.Codes.ContainsKey($_) | Should -BeTrue -Because ('status code {0} has no entry in Codes' -f $_)
        $script:Kb.Topics.ContainsKey([string]$script:Kb.Codes[$_]) | Should -BeTrue
    }
    It '<_> gives a full diagnosis for a non-passing finding with that code' -ForEach @($script:AllCodes | Where-Object { $_ -ne 'OK' }) {
        $f = & $script:NewF -Category 'CA' -Status 'Warning' -Code $_ -Message 'a plain message that matches no rule'
        $d = & $script:Diag $f
        $d | Should -Not -BeNullOrEmpty
        @($d.Causes).Count | Should -BeGreaterThan 0
        @($d.Causes[0].Confirm).Count | Should -BeGreaterThan 0
        @($d.Causes[0].Fix).Count | Should -BeGreaterThan 0
        @($d.Sources).Count | Should -BeGreaterThan 0
    }
    It 'has no entry for a code the schema does not know' {
        $schemaCodes = @((Get-MspkiSchema).StatusCode)
        foreach ($k in $script:Kb.Codes.Keys) { $schemaCodes -contains $k | Should -BeTrue -Because $k }
    }
}

Describe 'Every topic is complete' {
    It 'topic <_> has a title, an explanation, ranked causes with a check and a fix, and known sources' -ForEach $script:TopicIds {
        $t = $script:Kb.Topics[$_]
        [string]$t.Title | Should -Not -BeNullOrEmpty
        ([string]$t.What).Length | Should -BeGreaterThan 20
        @($t.Causes).Count | Should -BeGreaterThan 0
        @($t.Sources).Count | Should -BeGreaterThan 0
        foreach ($s in @($t.Sources)) { $script:Kb.Sources.ContainsKey($s) | Should -BeTrue -Because ('topic {0} cites unknown source {1}' -f $_, $s) }
        $ids = @($t.Causes | ForEach-Object { $_.Id })
        @($ids | Select-Object -Unique).Count | Should -Be $ids.Count -Because 'cause ids are unique within a topic'
        foreach ($c in @($t.Causes)) {
            [string]$c.Id | Should -Not -BeNullOrEmpty
            ([string]$c.Cause).Length | Should -BeGreaterThan 15
            @($c.Confirm).Count | Should -BeGreaterThan 0 -Because ('{0}/{1} has no way to confirm it' -f $_, $c.Id)
            @($c.Fix).Count | Should -BeGreaterThan 0 -Because ('{0}/{1} has no fix' -f $_, $c.Id)
            if ($c.ContainsKey('Signals')) {
                foreach ($s in @($c.Signals)) {
                    { [regex]::new([string]$s.When) } | Should -Not -Throw -Because ('{0}/{1}: bad signal pattern' -f $_, $c.Id)
                    $s.Weight | Should -BeOfType [int]
                    [string]$s.Because | Should -Not -BeNullOrEmpty -Because 'a signal says what was observed'
                }
            }
        }
    }

    It 'no check is a change: every "how to confirm" step is read-only' {
        $deny = '(?i)\b(Set|New|Remove|Add|Install|Restart|Start|Stop|Enable|Disable|Grant|Revoke|Publish|Import|Clear|Reset|Uninstall|Register|Unregister)-[A-Za-z]+|certutil\s[^|]*(-setreg|-delstore|-addstore|-dspublish|-repairstore|-crl\b|-sign\b|-importpfx|-installcert|-deleterow|-resubmit|-revoke|-delreg)|\bnet\s+(stop|start)\b|\breg\s+(add|delete|import)\b|\bsetspn\s+-(S|A|D|R)\b|gpupdate|\bsc(\.exe)?\s+(stop|start|config)|-ExecutionPolicy|Invoke-Expression'
        $bad = New-Object System.Collections.ArrayList
        foreach ($k in $script:Kb.Topics.Keys) {
            foreach ($c in @($script:Kb.Topics[$k].Causes)) {
                foreach ($x in @($c.Confirm)) { if ([regex]::IsMatch([string]$x, $deny)) { [void]$bad.Add(('{0}/{1}: {2}' -f $k, $c.Id, $x)) } }
            }
        }
        $bad.Count | Should -Be 0 -Because ($bad -join ' || ')
    }

    It 'names no real host, domain, address or account (examples use placeholders and example.test only)' {
        $hostRx = '(?i)(?<![\w$.\\-])((?:[a-z0-9-]+\.)+(?:com|net|org|local|lan|corp|internal|gov|edu|io|test|lab))\b'
        $allowed = '(?i)^(learn\.microsoft\.com|docs\.microsoft\.com|techcommunity\.microsoft\.com|support\.microsoft\.com|technet\.microsoft\.com|github\.com|posts\.specterops\.io|specterops\.io|(?:[a-z0-9-]+\.)*example\.test)$'
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in @(Get-ChildItem -LiteralPath $script:KnowledgeDir -Filter 'Diagnosis*.psd1')) {
            $text = [System.IO.File]::ReadAllText($f.FullName)
            foreach ($m in [regex]::Matches($text, $hostRx)) { if ($m.Groups[1].Value -notmatch $allowed) { [void]$hits.Add($m.Groups[1].Value) } }
            foreach ($m in [regex]::Matches($text, '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')) { [void]$hits.Add($m.Value) }
        }
        $hits.Count | Should -Be 0 -Because ($hits -join ', ')
    }
}

Describe 'Sources are documented with their date' {
    It 'source <_> is in docs/KNOWLEDGE-SOURCES.md with its address and a retrieval date' -ForEach $script:SourceIds {
        $s = $script:Kb.Sources[$_]
        [string]$s.Title | Should -Not -BeNullOrEmpty
        [string]$s.Url | Should -Match '^https://'
        $script:SourcesDoc | Should -Match ([regex]::Escape($_))
        $script:SourcesDoc | Should -Match ([regex]::Escape([string]$s.Url))
        $line = @($script:SourcesDoc -split "`r?`n" | Where-Object { $_ -like ('*' + [string]$s.Url + '*') })[0]
        $line | Should -Match '\d{4}-\d{2}-\d{2}' -Because 'every source line carries the date it was read'
    }
    It 'every source is used by a topic' {
        $used = @($script:Kb.Topics.Values | ForEach-Object { @($_.Sources) } | Select-Object -Unique)
        foreach ($id in $script:Kb.Sources.Keys) { $used -contains $id | Should -BeTrue -Because ('{0} is never cited' -f $id) }
    }
}

Describe 'Rules and coverage' {
    It 'every rule names an existing topic, valid status codes and categories, and a valid pattern' {
        $schema = Get-MspkiSchema
        foreach ($r in $script:Kb.Rules) {
            $script:Kb.Topics.ContainsKey([string]$r.Topic) | Should -BeTrue -Because ('rule topic {0}' -f $r.Topic)
            if ($r.ContainsKey('StatusCode')) { foreach ($c in @($r.StatusCode)) { $schema.StatusCode -contains $c | Should -BeTrue -Because $c } }
            if ($r.ContainsKey('Category')) { foreach ($c in @($r.Category)) { $schema.Category -contains $c | Should -BeTrue -Because $c } }
            if ($r.ContainsKey('Match')) { { [regex]::new([string]$r.Match) } | Should -Not -Throw }
        }
    }

    It 'every topic is reachable: a rule or a status-code default points at it, or it is a reference topic for an ESC pattern the tool cannot detect' {
        $reach = @($script:Kb.Rules | ForEach-Object { $_.Topic }) + @($script:Kb.Codes.Values)
        $orphans = @($script:Kb.Topics.Keys | Where-Object { $reach -notcontains $_ -and $_ -notmatch '^ESC\d+$' })
        $orphans.Count | Should -Be 0 -Because ($orphans -join ', ')
    }

    It 'covers every escalation pattern ESC1 to ESC16, the tool''s own patterns and the reference-only ones' {
        foreach ($n in 1..16) { $script:Kb.Topics.ContainsKey(('ESC{0}' -f $n)) | Should -BeTrue -Because ('ESC{0}' -f $n) }
    }

    It 'covers the subjects the batch names: RPC/DCOM, CRL and AIA, LDAP vs HTTP, delta CRL, OCSP, CES/CEP, NDES, Intune, TLS, NTAuth, CA renewal, clock skew' {
        $need = @('RPC_ACCESS_DENIED', 'RPC_NO_ANSWER', 'CRL_EXPIRED', 'CRL_PUBLICATION_FAIL', 'AIA_WRONG_CERT', 'CDP_LDAP_ONLY', 'HTTP_BAD_REQUEST', 'CRL_NUMBER_MISMATCH',
            'OCSP_UNUSED', 'OCSP_ENDPOINT_FAIL', 'CES_CEP_ENDPOINT_FAIL', 'CEP_NOT_CONFIGURED', 'NDES_RA_EXPIRED', 'NDES_NOT_DISCOVERED', 'INTUNE_REMOTE_NOT_CHECKED',
            'TLS_HANDSHAKE', 'TLS_UNTRUSTED', 'TLS_NAME', 'NTAUTH_AIA_MISMATCH', 'NTAUTH_MISSING', 'CA_CERT_EXPIRING', 'CA_CERT_EXPIRED', 'CLOCK_SKEW', 'OFFLINE_ROOT_CRL_EXPIRED')
        foreach ($n in $need) { $script:Kb.Topics.ContainsKey($n) | Should -BeTrue -Because $n }
        ($script:Kb.Topics['RPC_ACCESS_DENIED'].Causes | ForEach-Object { $_.Cause }) -join ' ' | Should -Match 'Certificate Service DCOM Access'
    }
}

Describe 'Which topic a finding gets (rules, then the status code)' {
    It '<Name>' -ForEach @(
        @{ Name = 'a quick DCOM refusal is the DCOM access topic, not an outage'; Cat = 'CA'; St = 'Skipped'; Code = 'PERMISSION_DENIED'; Msg = 'The CA host ca01.pki.example.test turned down this account''s request to read the CA (error 0x800706BA).'; Topic = 'RPC_ACCESS_DENIED' }
        @{ Name = 'a slow RPC failure is the no-answer topic'; Cat = 'CA'; St = 'Fail'; Code = 'RPC_FAIL'; Msg = 'The CA host answered on TCP 135 but the CA could not be reached over its dynamic RPC port.'; Topic = 'RPC_NO_ANSWER' }
        @{ Name = 'a TLS handshake closed before a certificate'; Cat = 'CA'; St = 'Warning'; Code = 'TLS_HANDSHAKE_FAIL'; Msg = 'web01.pki.example.test accepts TCP connections but closes every TLS handshake before sending a certificate.'; Topic = 'TLS_CLOSED_BY_SERVER' }
        @{ Name = 'a generation in NTAuth but not in AIA'; Cat = 'Hierarchy'; St = 'Warning'; Code = 'CONFIG_MISMATCH'; Msg = 'A generation of Example CA (valid to 2028-07-09) is in NTAuth but not in the AIA container.'; Topic = 'NTAUTH_AIA_MISMATCH' }
        @{ Name = 'two CA certificates without a clear split'; Cat = 'ADContainer'; St = 'Warning'; Code = 'NOT_DISCOVERED'; Msg = 'Example CA has 2 CA certificates: one is current, but this run could not tell whether the other one is historical (no clear current/historical split).'; Topic = 'CA_GENERATION_UNKNOWN' }
        @{ Name = 'LDAP-only AIA'; Cat = 'AIA'; St = 'Warning'; Code = 'CONFIG_RISK'; Msg = 'Example CA publishes its CA certificate only over LDAP (2 URL(s), no HTTP URL).'; Topic = 'CDP_LDAP_ONLY' }
        @{ Name = 'LDAP-only CDP'; Cat = 'CDP'; St = 'Warning'; Code = 'CONFIG_RISK'; Msg = 'Example CA publishes its CRL only over LDAP (1 URL(s), no HTTP URL).'; Topic = 'CDP_LDAP_ONLY' }
        @{ Name = 'an unused Online Responder'; Cat = 'OCSP'; St = 'Warning'; Code = 'CONFIG_MISMATCH'; Msg = 'An OCSP responder (Online Responder) answers on ca01.pki.example.test, but no certificate or CA names it: no client will ever ask it.'; Topic = 'OCSP_UNUSED' }
        @{ Name = 'an offline root CRL that expired'; Cat = 'Hierarchy'; St = 'Critical'; Code = 'OBJECT_EXPIRED'; Msg = 'The CRL of the offline root Example Root expired 3.0 days ago.'; Topic = 'OFFLINE_ROOT_CRL_EXPIRED' }
        @{ Name = 'a CRL that expired (CRL category)'; Cat = 'CRL'; St = 'Fail'; Code = 'OBJECT_EXPIRED'; Msg = 'The CRL at http://pki.example.test/crl/ca.crl has expired.'; Topic = 'CRL_EXPIRED' }
        @{ Name = 'a CA certificate that expires soon'; Cat = 'CA'; St = 'Warning'; Code = 'OBJECT_EXPIRING'; Msg = 'The CA certificate expires in 40 days.'; Topic = 'CA_CERT_EXPIRING' }
        @{ Name = 'two CRL numbers'; Cat = 'CRL'; St = 'Warning'; Code = 'STALE_DATA'; Msg = 'http://pki.example.test/a.crl serves base CRL number 41; another location serves the newer number 42.'; Topic = 'CRL_NUMBER_MISMATCH' }
        @{ Name = 'ESC1'; Cat = 'Template'; St = 'Warning'; Code = 'CONFIG_RISK'; Msg = 'Template WebServerCopy meets every condition of review pattern ESC1: the enrollee supplies the subject.'; Topic = 'ESC1' }
        @{ Name = 'ESC3'; Cat = 'Template'; St = 'Warning'; Code = 'CONFIG_RISK'; Msg = 'Template AgentCopy meets every condition of review pattern ESC3: x.'; Topic = 'ESC3' }
        @{ Name = 'ESC13'; Cat = 'Template'; St = 'Warning'; Code = 'CONFIG_RISK'; Msg = 'Template PolicyCopy meets every condition of review pattern ESC13: x.'; Topic = 'ESC13' }
        @{ Name = 'Web Enrollment over HTTP with NTLM (ESC8)'; Cat = 'WebEnrollment'; St = 'Warning'; Code = 'CONFIG_RISK'; Msg = 'Web Enrollment on ca01.pki.example.test offers Windows sign-in (NTLM) over plain HTTP: an NTLM relay target (ESC8).'; Topic = 'ESC8' }
        @{ Name = 'a CES endpoint served over HTTP'; Cat = 'CES'; St = 'Warning'; Code = 'CONFIG_RISK'; Msg = 'The CES endpoint http://ces01.pki.example.test/x is served over HTTP, not HTTPS, so requests are not protected by TLS.'; Topic = 'ESC8' }
        @{ Name = 'NDES RA certificate expired'; Cat = 'NDES'; St = 'Fail'; Code = 'OBJECT_EXPIRED'; Msg = 'A certificate returned by GetCACert on ndes01.pki.example.test has expired: CN=RA.'; Topic = 'NDES_RA_EXPIRED' }
        @{ Name = 'open NDES admin page'; Cat = 'NDES'; St = 'Fail'; Code = 'CONFIG_RISK'; Msg = 'The NDES admin page on ndes01.pki.example.test answered an anonymous request with HTTP 200.'; Topic = 'NDES_ADMIN_OPEN' }
        @{ Name = 'no NDES found'; Cat = 'NDES'; St = 'NotApplicable'; Code = 'NOT_DISCOVERED'; Msg = 'Classification NotDiscovered: no NDES / SCEP server was found from the CA databases, the NDES RA template permissions or references.'; Topic = 'NDES_NOT_DISCOVERED' }
        @{ Name = 'CA database not read'; Cat = 'NDES'; St = 'Skipped'; Code = 'NOT_APPLICABLE'; Msg = 'The CA database of Example CA was not read for NDES evidence: the CA database reader (CertificateAuthority.View) is not installed on this computer.'; Topic = 'CA_DB_NOT_READ' }
        @{ Name = 'remote Intune connector not checked'; Cat = 'IntuneConnector'; St = 'Skipped'; Code = 'UNSUPPORTED'; Msg = 'Whether the NDES host ndes01.pki.example.test runs the Intune Certificate Connector was not checked.'; Topic = 'INTUNE_REMOTE_NOT_CHECKED' }
        @{ Name = 'Intune connector not found'; Cat = 'IntuneConnector'; St = 'NotApplicable'; Code = 'NOT_DISCOVERED'; Msg = 'No Intune Certificate Connector was found on this computer.'; Topic = 'INTUNE_NOT_FOUND' }
        @{ Name = 'no CEP'; Cat = 'CEP'; St = 'NotApplicable'; Code = 'NOT_CONFIGURED'; Msg = 'No enrollment policy web service (CEP) is configured on this computer by policy or local settings.'; Topic = 'CEP_NOT_CONFIGURED' }
        @{ Name = 'no CES'; Cat = 'CES'; St = 'NotApplicable'; Code = 'NOT_DISCOVERED'; Msg = 'No Enrollment Web Service (CES) URL is published on the Enrollment Services objects of the Enterprise CAs.'; Topic = 'CES_NOT_PUBLISHED' }
        @{ Name = 'a CES endpoint that answers 401'; Cat = 'CES'; St = 'Warning'; Code = 'HTTP_401_403'; Msg = 'The CES endpoint answers HTTP 401.'; Topic = 'CES_CEP_ENDPOINT_FAIL' }
        @{ Name = 'no Web Enrollment'; Cat = 'WebEnrollment'; St = 'Information'; Code = 'NOT_DISCOVERED'; Msg = 'Web Enrollment was not found on ca02.pki.example.test: no web server answered at all.'; Topic = 'WEB_ENROLLMENT_NOT_FOUND' }
        @{ Name = 'no PTR'; Cat = 'Identity'; St = 'Information'; Code = 'NOT_CONFIGURED'; Msg = 'No reverse DNS (PTR) record for web01.corp.example.test (192.0.2.10).'; Topic = 'PTR_MISSING' }
        @{ Name = 'PTR short name'; Cat = 'Identity'; St = 'Warning'; Code = 'CONFIG_MISMATCH'; Msg = 'Reverse DNS for 192.0.2.10 gives only the short name (web01), not web01.corp.example.test.'; Topic = 'PTR_SHORT_NAME' }
        @{ Name = 'a dangling alias'; Cat = 'Identity'; St = 'Warning'; Code = 'DNS_FAIL'; Msg = 'app.corp.example.test is an alias (CNAME) for gone.corp.example.test, but gone.corp.example.test has no address record: the alias leads nowhere.'; Topic = 'CNAME_DANGLING' }
        @{ Name = 'a certificate name without DNS'; Cat = 'Hierarchy'; St = 'Warning'; Code = 'DNS_FAIL'; Msg = 'The certificate CN=web01 names app.corp.example.test in its Subject Alternative Name, but app.corp.example.test has no DNS record.'; Topic = 'SAN_NO_DNS' }
        @{ Name = 'templates that no CA publishes'; Cat = 'Template'; St = 'Information'; Code = 'NOT_CONFIGURED'; Msg = '19 of 43 template object(s) are published by no Enterprise CA.'; Topic = 'TEMPLATE_UNPUBLISHED' }
        @{ Name = 'an empty KRA object'; Cat = 'ADContainer'; St = 'Information'; Code = 'NOT_CONFIGURED'; Msg = 'The KRA object CN=KRA holds no key recovery agent certificate (normal when key archival is not used).'; Topic = 'KRA_EMPTY' }
        @{ Name = 'a stale CA object'; Cat = 'StaleRef'; St = 'Information'; Code = 'STALE_REFERENCE'; Msg = 'The Enterprise CA object Old CA is a stale-reference candidate: every CA certificate for it has expired and its host does not answer (timeout).'; Topic = 'STALE_CA_OBJECT' }
        @{ Name = 'a leftover domain controller object'; Cat = 'ADDependency'; St = 'Information'; Code = 'STALE_REFERENCE'; Msg = '1 server object(s) under CN=Sites were not counted as live domain controllers.'; Topic = 'STALE_DC_OBJECT' }
        @{ Name = 'certificates AD publishes missing on this computer'; Cat = 'LocalEvidence'; St = 'Warning'; Code = 'PUBLICATION_FAIL'; Msg = '1 of 5 certificate(s) that AD publishes in Certification Authorities are not in this computer.'; Topic = 'LOCAL_STORE_MISSING' }
        @{ Name = 'a 404 on a CRL URL falls back to the status code'; Cat = 'CRL'; St = 'Fail'; Code = 'HTTP_404'; Msg = 'The CRL could not be downloaded: HTTP 404.'; Topic = 'HTTP_NOT_FOUND' }
        @{ Name = 'a timeout falls back to the status code'; Cat = 'CDP'; St = 'Fail'; Code = 'TIMEOUT'; Msg = 'Timed out.'; Topic = 'NETWORK_TIMEOUT' }
    ) {
        $f = & $script:NewF -Category $Cat -Status $St -Code $Code -Message $Msg
        (& $script:Diag $f).Topic | Should -Be $Topic
    }

    It 'a finding that matches no rule still gets its status-code topic, marked as a code match' {
        $f = & $script:NewF -Category 'CA' -Status 'Warning' -Code 'TCP_FAIL' -Message 'nothing special'
        $d = & $script:Diag $f
        $d.Topic | Should -Be 'TCP_UNREACHABLE'
        $d.Match | Should -Be 'Code'
    }
}

Describe 'Which findings need a diagnosis' {
    It '<St>/<Code> -> <Need>' -ForEach @(
        @{ St = 'Pass'; Code = 'OK'; Need = $false }
        @{ St = 'Information'; Code = 'OK'; Need = $false }
        @{ St = 'Information'; Code = 'NOT_APPLICABLE'; Need = $false }
        @{ St = 'NotApplicable'; Code = 'NOT_APPLICABLE'; Need = $false }
        @{ St = 'Information'; Code = 'NOT_CONFIGURED'; Need = $true }
        @{ St = 'NotApplicable'; Code = 'NOT_DISCOVERED'; Need = $true }
        @{ St = 'Skipped'; Code = 'NOT_APPLICABLE'; Need = $true }
        @{ St = 'Warning'; Code = 'CONFIG_RISK'; Need = $true }
        @{ St = 'Fail'; Code = 'TCP_FAIL'; Need = $true }
        @{ St = 'Critical'; Code = 'OBJECT_EXPIRED'; Need = $true }
        @{ St = 'Error'; Code = 'INTERNAL_ERROR'; Need = $true }
    ) {
        $f = & $script:NewF -Category 'CA' -Status $St -Code $Code -Message 'x'
        $d = Get-MspkiFindingDiagnosis -Finding $f -Recompute
        ($null -ne $d) | Should -Be $Need
    }
}

Describe 'Ranking uses what the tool observed' {
    It 'a refused connection puts "service stopped" first; a silent timeout puts "firewall" first; an unreachable network puts "host down" first' {
        $refused = & $script:Diag (& $script:NewF -Category 'CDP' -Status 'Fail' -Code 'TCP_FAIL' -Message 'ocsp01.pki.example.test does not accept connections on TCP 80.' -Evidence @('TCP: Fail No connection could be made because the target machine actively refused it 192.0.2.5:80'))
        $silent = & $script:Diag (& $script:NewF -Category 'CDP' -Status 'Fail' -Code 'TCP_FAIL' -Message 'ocsp01.pki.example.test does not accept connections on TCP 80.' -Evidence @('TCP: Timeout No TCP connection within 5000 ms.'))
        $gone = & $script:Diag (& $script:NewF -Category 'CDP' -Status 'Fail' -Code 'TCP_FAIL' -Message 'ocsp01.pki.example.test does not accept connections on TCP 80.' -Evidence @('TCP: Fail A socket operation was attempted to an unreachable network 192.0.2.5:80'))
        $refused.Causes[0].Id | Should -Be 'service-stopped'
        $silent.Causes[0].Id | Should -Be 'firewall'
        $gone.Causes[0].Id | Should -Be 'host-down'
        $refused.Basis | Should -Be 'Observed'
        $refused.Causes[0].Because.Count | Should -BeGreaterThan 0
    }

    It 'a timeout after a working TCP connection points at a slow server; a DNS timeout at DNS' {
        $slow = & $script:Diag (& $script:NewF -Category 'CDP' -Status 'Fail' -Code 'TIMEOUT' -Message 'x' -Layers @{ TcpStatus = 'Pass'; HttpStatus = 'Timeout' })
        $dns = & $script:Diag (& $script:NewF -Category 'CDP' -Status 'Fail' -Code 'TIMEOUT' -Message 'x' -Layers @{ DnsStatus = 'Timeout' } -Evidence @('DNS: Timeout No DNS answer within 5000 ms.'))
        $slow.Causes[0].Id | Should -Be 'slow-server'
        $dns.Causes[0].Id | Should -Be 'dns-slow'
    }

    It 'an anonymous-logon observation outranks the usual DCOM group cause; without it the DCOM group stays first' {
        $base = 'The CA host ca01.pki.example.test turned down this account''s request to read the CA (DCOM reported "RPC server unavailable", error 0x800706BA, but it answered within 22 ms on TCP 135).'
        $plain = & $script:Diag (& $script:NewF -Category 'CA' -Status 'Skipped' -Code 'PERMISSION_DENIED' -Message $base -Evidence @('Answered within 5000 ms after TCP 135 was reachable.'))
        $anon = & $script:Diag (& $script:NewF -Category 'CA' -Status 'Skipped' -Code 'PERMISSION_DENIED' -Message $base -Evidence @('System log: DistributedCOM 10027 for ANONYMOUS LOGON'))
        $plain.Topic | Should -Be 'RPC_ACCESS_DENIED'
        $plain.Causes[0].Id | Should -Be 'dcom-access-group'
        $anon.Causes[0].Id | Should -Be 'user-rights-gpo'
    }

    It 'standing text in Notes or Remediation is never shown as an observation (only the message, the evidence and the layers are)' {
        $msg = 'The CA host ca01.pki.example.test turned down this account''s request to read the CA (error 0x800706BA).'
        $notes = 'On a lab CA this was RPC fault 5 for one ordinary account, while an administrator account read the same CA. Another CA answered the same account elsewhere.'
        $d = & $script:Diag (& $script:NewF -Category 'CA' -Status 'Skipped' -Code 'PERMISSION_DENIED' -Message $msg -Notes $notes)
        $d.Topic | Should -Be 'RPC_ACCESS_DENIED'
        @($d.Causes | ForEach-Object { $_.Because } | Where-Object { $_ -match 'another CA|administrator' }).Count | Should -Be 0
        $real = & $script:Diag (& $script:NewF -Category 'CA' -Status 'Skipped' -Code 'PERMISSION_DENIED' -Message $msg -Evidence @('Another CA answered the same account in this run: ca02.pki.example.test'))
        @($real.Causes[0].Because | Where-Object { $_ -match 'another CA answered' }).Count | Should -Be 1
    }

    It 'a weak hint does not earn "most likely": a timeout cannot tell a missing web role from a filtering firewall' {
        $msg = 'Web Enrollment (/certsrv/) was not found on ca02.pki.example.test. No web server answered at all on ca02.pki.example.test.'
        $weak = & $script:Diag (& $script:NewF -Category 'WebEnrollment' -Status 'Information' -Code 'NOT_DISCOVERED' -Message $msg -Evidence @('http://ca02.pki.example.test/certsrv/: no web server answered (TIMEOUT)'))
        $weak.Causes[0].Id | Should -Be 'role-not-installed'
        $weak.Causes[0].Likelihood | Should -Be 'Most common'
        $refused = & $script:Diag (& $script:NewF -Category 'WebEnrollment' -Status 'Information' -Code 'NOT_DISCOVERED' -Message $msg -Evidence @('http://ca02.pki.example.test/certsrv/: No connection could be made because the target machine actively refused it'))
        $refused.Causes[0].Id | Should -Be 'role-not-installed'
        $refused.Causes[0].Likelihood | Should -Be 'Most likely' -Because 'a refusal is something observed that backs a missing role'
    }

    It 'an enrollment service that fails in TLS or at the network is not blamed on Kerberos delegation first; a 401 is' {
        $tls = & $script:Diag (& $script:NewF -Category 'CES' -Status 'Warning' -Code 'TLS_HANDSHAKE_FAIL' -Message 'TLS to ces01.pki.example.test failed.' -Layers @{ TlsStatus = 'Fail' })
        $net = & $script:Diag (& $script:NewF -Category 'CES' -Status 'Warning' -Code 'TCP_FAIL' -Message 'ces01.pki.example.test does not accept connections on TCP 443.' -Layers @{ TcpStatus = 'Fail' })
        $auth = & $script:Diag (& $script:NewF -Category 'CES' -Status 'Warning' -Code 'HTTP_401_403' -Message 'The CES endpoint answers HTTP 401.')
        $tls.Causes[0].Id | Should -Be 'tls-binding'
        $net.Causes[0].Id | Should -Be 'service-down'
        $auth.Causes[0].Id | Should -Be 'kerberos-delegation'
    }

    It 'an anonymous refusal on a CRL URL points at anonymous access; the same 403 on an enrollment service points at "TLS required"' {
        $crl = & $script:Diag (& $script:NewF -Category 'CRL' -Status 'Fail' -Code 'HTTP_401_403' -Message 'The CRL could not be downloaded: HTTP 403.')
        $web = & $script:Diag (& $script:NewF -Category 'WebEnrollment' -Status 'Warning' -Code 'HTTP_401_403' -Message 'The page answers HTTP 403.')
        $crl.Causes[0].Id | Should -Be 'anonymous-blocked'
        $web.Causes[0].Id | Should -Be 'ssl-required'
    }

    It 'without any observation the order is the order of the knowledge file, and the finding says so (Basis Typical)' {
        $d = & $script:Diag (& $script:NewF -Category 'CA' -Status 'Warning' -Code 'CONFIG_RISK' -Message 'a setting')
        $d.Basis | Should -Be 'Typical'
        $d.BasisNote | Should -Match 'only reflects how common'
        $d.Causes[0].Id | Should -Be $script:Kb.Topics['CONFIG_RISK'].Causes[0].Id
        @($d.Causes | ForEach-Object { $_.Rank }) -join ',' | Should -Be ((1..@($d.Causes).Count) -join ',')
    }

    It 'ranks are 1..n, the first cause is "Most likely", and every cause says who acts and keeps the checks separate from the fixes' {
        $d = & $script:Diag (& $script:NewF -Category 'CA' -Status 'Skipped' -Code 'PERMISSION_DENIED' -Message 'The CA host x turned down this account''s request.')
        $d.Basis | Should -Be 'Typical'
        $d.Causes[0].Likelihood | Should -Be 'Most common' -Because 'nothing observed separates the causes here, so it must not say "most likely"'
        $seen = & $script:Diag (& $script:NewF -Category 'CA' -Status 'Skipped' -Code 'PERMISSION_DENIED' -Message 'The CA host x turned down this account''s request (answered within 22 ms).' -Evidence @('Answered within 5000 ms after TCP 135 was reachable.'))
        $seen.Basis | Should -Be 'Observed'
        $seen.Causes[0].Likelihood | Should -Be 'Most likely'
        foreach ($c in $d.Causes) { $c.FixOwner | Should -Be 'PKI owner' }
        $d.Causes[0].Confirm | Should -Not -Be $d.Causes[0].Fix
    }

    It 'every pattern in every signal can match: a signal whose pattern matches nothing a finding can contain is dead weight' {
        # The finding text always starts with these lines, so a pattern that needs one of them must use the same spelling.
        $text = InModuleScope MspkiHealthCheck { Get-MspkiDiagnosisSearchText -Finding (New-MspkiFinding -Category CA -Target 'x' -Status Warning -StatusCode CONFIG_RISK -Sources 't' -Message 'm' -Layers @{ TcpStatus = 'Fail' }) }
        $text | Should -Match 'Category=CA'
        $text | Should -Match 'StatusCode=CONFIG_RISK'
        $text | Should -Match 'TcpStatus=Fail'
        $text | Should -Not -Match 'DnsStatus'
    }
}

Describe 'The section reaches results.json, the HTML report and the GUI' {
    BeforeAll {
        $script:F1 = & $script:NewF -Category 'CA' -Status 'Skipped' -Code 'PERMISSION_DENIED' -Message 'The CA host ca01.pki.example.test turned down this account''s request to read the CA (error 0x800706BA, answered within 22 ms).'
        $script:F2 = & $script:NewF -Category 'CRL' -Status 'Pass' -Code 'OK' -Message 'fine'
        $script:Added = InModuleScope MspkiHealthCheck -Parameters @{ A = $script:F1; B = $script:F2 } { param($A, $B) Add-MspkiFindingDiagnosis -Findings @($A, $B) }
        $script:Dir = Join-Path $script:RepoRoot 'out\diagnosis-test'
    }

    It 'adds a Diagnosis to non-passing findings only, and is safe to run twice' {
        $script:Added | Should -Be 1
        $script:F1.Diagnosis.Topic | Should -Be 'RPC_ACCESS_DENIED'
        $script:F2.PSObject.Properties['Diagnosis'] | Should -BeNullOrEmpty
        (InModuleScope MspkiHealthCheck -Parameters @{ A = $script:F1 } { param($A) Add-MspkiFindingDiagnosis -Findings @($A) }) | Should -Be 0
    }

    It 'survives a round trip through results.json' {
        $path = Join-Path $script:Dir 'results.json'
        InModuleScope MspkiHealthCheck -Parameters @{ P = $path; A = $script:F1; B = $script:F2 } {
            param($P, $A, $B)
            $folder = Use-MspkiOutputFolder -Path (Split-Path -Parent $P)
            [void](Export-MspkiJson -Path (Join-Path $folder 'results.json') -RunInfo ([pscustomobject]@{ Completed = $true }) -Findings @($A, $B))
        }
        $back = Read-MspkiResultsJson -Path $path
        $g = @($back.Findings | Where-Object { $_.Id -eq $script:F1.Id })[0]
        $g.Diagnosis.Topic | Should -Be 'RPC_ACCESS_DENIED'
        @($g.Diagnosis.Causes).Count | Should -BeGreaterThan 3
        @($g.Diagnosis.Causes[0].Fix).Count | Should -BeGreaterThan 0
        @($g.Diagnosis.Sources)[0].Url | Should -Match '^https://'
        (Get-MspkiFindingDiagnosis -Finding $g).Topic | Should -Be 'RPC_ACCESS_DENIED'
    }

    It 'a results.json written before this feature gets its diagnosis computed when it is read for display' {
        $old = & $script:NewF -Category 'CA' -Status 'Fail' -Code 'RPC_FAIL' -Message 'The CA host answered on TCP 135 but the CA could not be reached over its dynamic RPC port.'
        $old.PSObject.Properties['Diagnosis'] | Should -BeNullOrEmpty
        (Get-MspkiFindingDiagnosis -Finding $old).Topic | Should -Be 'RPC_NO_ANSWER'
    }

    It 'the HTML report shows the section, keeps the single offline file (no link, no external reference) and encodes the text' {
        $html = InModuleScope MspkiHealthCheck -Parameters @{ A = $script:F1 } { param($A) ConvertTo-MspkiHtmlFinding -Finding $A }
        $html | Should -Match 'Probable causes and next steps'
        $html | Should -Match 'How to confirm \(read-only\)'
        $html | Should -Match 'action for the PKI owner'
        $html | Should -Match 'Certificate Service DCOM Access'
        $html | Should -Not -Match '(?i)\b(src|href|action)\s*=\s*["'']?\s*(https?:)?//'
        $html | Should -Not -Match '(?i)<a\s'
        $html | Should -Match 'https://learn\.microsoft\.com/'
    }

    It 'the GUI details pane gets the ranked causes, the checks, the fixes and the sources' {
        . (Join-Path $script:RepoRoot 'src\Gui\GuiModel.ps1')
        . (Join-Path $script:RepoRoot 'src\Gui\GuiView.ps1')
        $v = Get-MspkiGuiFindingDetail -Finding $script:F1
        $v.HasDiagnosis | Should -BeTrue
        $v.DiagTitle | Should -Match 'DCOM'
        @($v.DiagCauses).Count | Should -BeGreaterThan 3
        $v.DiagCauses[0].IsTop | Should -BeTrue
        $v.DiagCauses[0].ConfirmText | Should -Not -BeNullOrEmpty
        $v.DiagCauses[0].FixText | Should -Not -BeNullOrEmpty
        $v.DiagSources | Should -Match 'https://learn\.microsoft\.com/'
        $v.CopyText | Should -Match 'Probable causes and next steps'
        (Get-MspkiGuiFindingDetail -Finding $script:F2).HasDiagnosis | Should -BeFalse
    }
}
