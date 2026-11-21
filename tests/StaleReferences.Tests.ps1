# Historical and stale references (REQUIREMENTS 5.9): every classification has evidence, and a stale-reference
# candidate needs ALL of its conditions. Synthetic example.test data.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:entry = { param($tp, $life, $notAfter, $conf = 'Confirmed', $ca = 'Example Issuing CA')
        [pscustomobject]@{ Thumbprint = $tp; CAName = $ca; Lifecycle = $life; LifecycleConfidence = $conf; LifecycleBasis = 'test'; Info = [pscustomobject]@{ Subject = ('CN={0}, DC=example, DC=test' -f $tp); NotAfter = $notAfter } } }
    $script:inv = { param($certs = $null, $cas = $null)
        if ($null -eq $certs) { $certs = @((& $script:entry 'C001' 'Current' '2099-01-01T00:00:00Z'), (& $script:entry 'B001' 'Historical' '2099-01-01T00:00:00Z'), (& $script:entry 'E001' 'Historical' '2020-01-01T00:00:00Z')) }
        if ($null -eq $cas) { $cas = @() }
        [pscustomobject]@{ CACertificates = @($certs); EnterpriseCAs = @($cas) } }
    $script:lead = { param($url, $sources, $kind = 'CDP', $id = 'L0001')
        [pscustomobject]@{ Id = $id; Kind = $kind; Url = $url; Host = ([uri]$url).Host; Scope = 'Local'; Depth = 0; Variants = @($url); Sources = @($sources); Origins = @('test fixture'); RelatedCAs = @('Example Issuing CA') } }
    $script:pf = { param([string]$Url, [string]$Status, [string]$Code, [string]$Category = 'CDP', [hashtable]$Layers = @{})
        InModuleScope MspkiHealthCheck -Parameters @{ U = $Url; S = $Status; C = $Code; K = $Category; L = $Layers } { param($U, $S, $C, $K, $L)
            New-MspkiFinding -Category $K -Target 'host' -Endpoint $U -Status $S -StatusCode $C -Sources 'test' -Message ('probe ' + $C) -Layers $L } }
    $script:run = { param($inv, $leads, $findings = @())
        InModuleScope MspkiHealthCheck -Parameters @{ I = $inv; L = @($leads); F = @($findings) } { param($I, $L, $F) Test-MspkiStaleReference -Inventory $I -Leads $L -Findings $F } }
    $script:url = 'http://pki.corp.example.test/CertEnroll/Example%20Issuing%20CA.crl'
    $script:cls = { param($f, $class) , @($f | Where-Object { $_.Category -eq 'StaleRef' -and $_.Evidence[0] -eq ('Classification: {0}' -f $class) }) }
    $script:ok = { param($u = $script:url) & $script:pf $u 'Pass' 'OK' 'CDP' @{ DnsStatus = 'Pass'; TcpStatus = 'Pass'; HttpStatus = 'Pass'; ContentStatus = 'Pass' } }
    $script:dnsFail = { param($u = $script:url) & $script:pf $u 'Fail' 'DNS_FAIL' 'CDP' @{ DnsStatus = 'Fail' } }
    $script:summary = { param($f) @($f | Where-Object { $_.Message -like 'Reference review:*' })[0] }
}

Describe 'ActiveConfirmed' {
    It 'is a reference of current configuration that the probe confirmed, listed with its evidence in the summary' {
        $l = & $script:lead $script:url @('CA:Example Issuing CA:CertCdpUrls')
        $f = & $script:run (& $script:inv) @($l) @((& $script:ok))
        (& $script:cls $f 'ActiveConfirmed').Count | Should -Be 0
        $s = & $script:summary $f
        $s.Message | Should -Match '^Reference review: 1 active and confirmed, 0 current, 0 historical, 0 unreachable, 0 stale'
        ($s.Evidence -join "`n") | Should -Match 'ActiveConfirmed: http://pki.corp.example.test/CertEnroll/.* - the current configuration of Enterprise CA Example Issuing CA'
    }

    It 'also holds for a reference carried by the current CA certificate' {
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url @('Cert:C001:CDP'))) @((& $script:ok))
        (& $script:summary $f).Message | Should -Match ': 1 active and confirmed'
    }

    It 'is not ActiveConfirmed when only historical certificates carry the reference, even if it answers' {
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url @('Cert:B001:CDP'))) @((& $script:ok))
        (& $script:summary $f).Message | Should -Match ': 0 active and confirmed'
        (& $script:cls $f 'HistoricalReference').Count | Should -Be 1
    }
}

Describe 'CurrentReference' {
    It 'is reported as information when the reference was not probed' {
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url @('CA:Example Issuing CA:CertCdpUrls')))
        $r = & $script:cls $f 'CurrentReference'
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'Information'
        $r[0].StatusCode | Should -Be 'NOT_APPLICABLE'
        $r[0].Confidence | Should -Be 'Referenced'
        ($r[0].Evidence -join "`n") | Should -Match 'Probe outcome: NotTested'
    }

    It 'is a warning when the reference answers but with a problem (Partial) or answers with an error (Failing)' {
        $l = & $script:lead $script:url @('AD:EnrollmentServices:msPKI-Enrollment-Servers') 'CES'
        $partial = & $script:run (& $script:inv) @($l) @((& $script:ok), (& $script:pf $script:url 'Fail' 'OBJECT_EXPIRED' 'CDP'))
        $p = & $script:cls $partial 'CurrentReference'
        $p[0].Status | Should -Be 'Warning'
        $p[0].StatusCode | Should -Be 'OBJECT_EXPIRED'
        $failing = & $script:run (& $script:inv) @($l) @((& $script:pf $script:url 'Fail' 'HTTP_404' 'CES'))
        $q = & $script:cls $failing 'CurrentReference'
        $q[0].StatusCode | Should -Be 'HTTP_404'
        ($q[0].Evidence -join "`n") | Should -Match 'Probe outcome: Failing'
    }

    It 'treats CEP policy on this computer as current configuration' {
        $l = & $script:lead 'https://cep.corp.example.test/ADPolicyProvider_CEP_Kerberos/service.svc' @('Policy:CEP:HKLM') 'CEP'
        $f = & $script:run (& $script:inv) @($l)
        $r = & $script:cls $f 'CurrentReference'
        ($r[0].Evidence -join "`n") | Should -Match 'enrollment policy on this computer \(Policy:CEP:HKLM\)'
    }
}

Describe 'HistoricalReference' {
    It 'is found only in historical CA certificates, with the evidence and the caveat' {
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url @('Cert:B001:CDP', 'Cert:E001:CDP'))) @((& $script:ok))
        $r = & $script:cls $f 'HistoricalReference'
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'Information'
        $ev = $r[0].Evidence -join "`n"
        $ev | Should -Match 'Referenced by CA certificate CN=B001.*\[Confirmed|Referenced by CA certificate CN=B001'
        $ev | Should -Match 'EXPIRED 2020-01-01'
        $ev | Should -Match 'Current reference: no'
        $ev | Should -Match 'may still be needed by certificates that have not expired'
    }

    It 'is Inferred when the lifecycle of the carrying certificate is only inferred' {
        $inv = & $script:inv @((& $script:entry 'B002' 'Historical' '2099-01-01T00:00:00Z' 'Inferred'))
        $f = & $script:run $inv @((& $script:lead $script:url @('Cert:B002:CDP')))
        (& $script:cls $f 'HistoricalReference')[0].Confidence | Should -Be 'Inferred'
    }

    It 'a current reference wins over a historical one' {
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url @('Cert:E001:CDP', 'CA:Example Issuing CA:CertCdpUrls'))) @((& $script:ok))
        (& $script:cls $f 'HistoricalReference').Count | Should -Be 0
        (& $script:summary $f).Message | Should -Match ': 1 active and confirmed'
    }
}

Describe 'UnreachableReference' {
    It 'is a warning when current configuration references a host that does not answer' {
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url @('CA:Example Issuing CA:CertCdpUrls'))) @((& $script:dnsFail))
        $r = & $script:cls $f 'UnreachableReference'
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'Warning'
        $r[0].StatusCode | Should -Be 'DNS_FAIL'
        $r[0].Message | Should -Match 'referenced by current configuration'
        ($r[0].Evidence -join "`n") | Should -Match 'Probe outcome: Unreachable at DNS'
    }

    It 'is information when a historical certificate that has not expired carries it (not a stale candidate)' {
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url @('Cert:B001:CDP', 'Cert:E001:CDP'))) @((& $script:pf $script:url 'Fail' 'TCP_FAIL' 'CDP' @{ DnsStatus = 'Pass'; TcpStatus = 'Fail' }))
        $r = & $script:cls $f 'UnreachableReference'
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'Information'
        $r[0].StatusCode | Should -Be 'TCP_FAIL'
        (& $script:cls $f 'StaleReferenceCandidate').Count | Should -Be 0
    }
}

Describe 'StaleReferenceCandidate: needs every condition' {
    It 'fires when only expired CA certificates carry the reference, nothing current does, and the host does not answer' {
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url @('Cert:E001:CDP'))) @((& $script:dnsFail))
        $r = & $script:cls $f 'StaleReferenceCandidate'
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'Information'
        $r[0].StatusCode | Should -Be 'STALE_REFERENCE'
        $r[0].Severity | Should -Be 'ReviewRequired'
        $r[0].Confidence | Should -Be 'Inferred'
        $ev = $r[0].Evidence -join "`n"
        $ev | Should -Match 'Rule: only expired CA certificates carry it'
        $ev | Should -Match 'EXPIRED 2020-01-01'
        $ev | Should -Match 'Current reference: no'
        $ev | Should -Match 'all of them expired: True'
        $ev | Should -Match 'Probe outcome: Unreachable at DNS'
        $ev | Should -Match 'cannot see the certificates a CA issued'
        $ev | Should -Match 'none of which is enough alone'
    }

    It 'must not fire when <Why>' -ForEach @(
        @{ Why = 'the host still answers'; Sources = @('Cert:E001:CDP'); Probe = 'ok'; Expect = 'HistoricalReference' }
        @{ Why = 'the host answers with an HTTP error (it is alive, the object is missing)'; Sources = @('Cert:E001:CDP'); Probe = '404'; Expect = 'HistoricalReference' }
        @{ Why = 'nothing was probed'; Sources = @('Cert:E001:CDP'); Probe = 'none'; Expect = 'HistoricalReference' }
        @{ Why = 'a current configuration still references it'; Sources = @('Cert:E001:CDP', 'CA:Example Issuing CA:CertCdpUrls'); Probe = 'dns'; Expect = 'UnreachableReference' }
        @{ Why = 'the current CA certificate carries it'; Sources = @('Cert:E001:CDP', 'Cert:C001:CDP'); Probe = 'dns'; Expect = 'UnreachableReference' }
        @{ Why = 'a historical certificate that has not expired also carries it'; Sources = @('Cert:E001:CDP', 'Cert:B001:CDP'); Probe = 'dns'; Expect = 'UnreachableReference' }
        @{ Why = 'AD Enrollment Services references it'; Sources = @('Cert:E001:CDP', 'AD:EnrollmentServices:msPKI-Enrollment-Servers'); Probe = 'dns'; Expect = 'UnreachableReference' }
    ) {
        $findings = @()
        switch ($Probe) { 'ok' { $findings = @((& $script:ok)) } '404' { $findings = @((& $script:pf $script:url 'Fail' 'HTTP_404' 'CDP')) } 'dns' { $findings = @((& $script:dnsFail)) } }
        $f = & $script:run (& $script:inv) @((& $script:lead $script:url $Sources)) $findings
        (& $script:cls $f 'StaleReferenceCandidate').Count | Should -Be 0
        (& $script:cls $f $Expect).Count | Should -Be 1
    }

    It 'does not classify by host name or age: an unreachable host with a current carrier is never a candidate however old the object' {
        $inv = & $script:inv @((& $script:entry 'C009' 'Current' '2099-01-01T00:00:00Z')) @()
        $f = & $script:run $inv @((& $script:lead 'http://old-pki.corp.example.test/x.crl' @('Cert:C009:CDP'))) @((& $script:dnsFail 'http://old-pki.corp.example.test/x.crl'))
        (& $script:cls $f 'StaleReferenceCandidate').Count | Should -Be 0
    }
}

Describe 'References that are not classified' {
    It 'skips constructed candidates, CRL-only references and certificates downloaded during the run, and counts them' {
        $leads = @((& $script:lead 'https://ca01.corp.example.test/x_CES_Kerberos/service.svc' @('Constructed:CAHost') 'CES' 'L0001'),
                   (& $script:lead 'http://pki.corp.example.test/delta.crl' @('Crl:ABCDEF:FreshestCRL') 'FreshestCRL' 'L0002'),
                   (& $script:lead 'http://pki.corp.example.test/parent.crt' @('Cert:0F0F0F:AIA') 'AIA' 'L0003'))
        $f = & $script:run (& $script:inv) $leads
        @($f | Where-Object { $_.Category -eq 'StaleRef' -and $_.Message -notlike 'Reference review:*' -and $_.Target -ne 'Example Issuing CA' }).Count | Should -Be 0
        ((& $script:summary $f).Evidence -join "`n") | Should -Match 'not classified .*: 3'
    }
}

Describe 'Enterprise CA objects' {
    BeforeAll {
        $script:caFail = { param($code = 'DNS_FAIL', $layers = @{ DnsStatus = 'Fail' })
            InModuleScope MspkiHealthCheck -Parameters @{ C = $code; L = $layers } { param($C, $L) New-MspkiFinding -Category 'CA' -Target 'Example Issuing CA' -Status 'Fail' -StatusCode $C -Sources 'test' -Message ('CA host ' + $C) -Layers $L } }
        $script:ca = { param($props = $null) [pscustomobject]@{ Name = 'Example Issuing CA'; DnsHostName = 'ca01.corp.example.test'; Config = 'ca01.corp.example.test\Example Issuing CA'; WhenChanged = '2025-01-01T00:00:00Z'; Properties = $props } }
    }

    It 'lists a CA that answered as ActiveConfirmed in the summary' {
        $f = & $script:run (& $script:inv $null @((& $script:ca ([pscustomobject]@{ Templates = @() })))) @()
        (& $script:summary $f).Message | Should -Match ': 1 active and confirmed'
        ((& $script:summary $f).Evidence -join "`n") | Should -Match 'ActiveConfirmed: Enterprise CA Example Issuing CA - the CA answered with its properties'
    }

    It 'reports a registered CA whose host does not resolve as UnreachableReference while a CA certificate is still valid' {
        $f = & $script:run (& $script:inv $null @((& $script:ca $null))) @() @((& $script:caFail))
        $r = & $script:cls $f 'UnreachableReference'
        $r.Count | Should -Be 1
        $r[0].Status | Should -Be 'Warning'
        $r[0].StatusCode | Should -Be 'DNS_FAIL'
        ($r[0].Evidence -join "`n") | Should -Match 'CA certificate CN=C001'
        (& $script:cls $f 'StaleReferenceCandidate').Count | Should -Be 0
    }

    It 'is a stale candidate only when the host does not answer AND every CA certificate for the object has expired' {
        $certs = @((& $script:entry 'E001' 'Historical' '2020-01-01T00:00:00Z'), (& $script:entry 'E002' 'Historical' '2021-01-01T00:00:00Z'))
        $f = & $script:run (& $script:inv $certs @((& $script:ca $null))) @() @((& $script:caFail 'TCP_FAIL' @{ DnsStatus = 'Pass'; TcpStatus = 'Fail' }))
        $r = & $script:cls $f 'StaleReferenceCandidate'
        $r.Count | Should -Be 1
        $r[0].StatusCode | Should -Be 'STALE_REFERENCE'
        $r[0].Severity | Should -Be 'ReviewRequired'
        $r[0].Confidence | Should -Be 'Inferred'
        ($r[0].Evidence -join "`n") | Should -Match 'valid until 2020-01-01T00:00:00Z \(EXPIRED\)'
        # Expired certificates alone (the CA answers) or an unreachable host alone (a valid certificate) are not enough.
        $answers = & $script:run (& $script:inv $certs @((& $script:ca ([pscustomobject]@{ Templates = @() })))) @() @()
        (& $script:cls $answers 'StaleReferenceCandidate').Count | Should -Be 0
        $noCerts = & $script:run (& $script:inv @() @((& $script:ca $null))) @() @((& $script:caFail))
        (& $script:cls $noCerts 'StaleReferenceCandidate').Count | Should -Be 0
    }

    It 'does not treat a permission problem as an unreachable host' {
        $perm = InModuleScope MspkiHealthCheck { New-MspkiFinding -Category 'CA' -Target 'Example Issuing CA' -Status 'Skipped' -StatusCode 'PERMISSION_DENIED' -Sources 'test' -Message 'Permission denied' }
        $f = & $script:run (& $script:inv $null @((& $script:ca $null))) @() @($perm)
        (& $script:cls $f 'UnreachableReference').Count | Should -Be 0
        $c = & $script:cls $f 'CurrentReference'
        $c.Count | Should -Be 1
        ($c[0].Evidence -join "`n") | Should -Match 'PERMISSION_DENIED'
    }
}

Describe 'Every result has evidence and is review only' {
    It 'gives each classification a Classification line, a Rule or facts, and never says to delete anything' {
        $leads = @((& $script:lead $script:url @('CA:Example Issuing CA:CertCdpUrls') 'CDP' 'L0001'),
                   (& $script:lead 'http://h.corp.example.test/a.crl' @('Cert:B001:CDP') 'CDP' 'L0002'),
                   (& $script:lead 'http://u.corp.example.test/a.crl' @('CA:Example Issuing CA:CertCdpUrls') 'CDP' 'L0003'),
                   (& $script:lead 'http://s.corp.example.test/a.crl' @('Cert:E001:CDP') 'CDP' 'L0004'),
                   (& $script:lead 'http://n.corp.example.test/a.crl' @('AD:EnrollmentServices:msPKI-Enrollment-Servers') 'CES' 'L0005'))
        $findings = @((& $script:ok), (& $script:ok 'http://h.corp.example.test/a.crl'), (& $script:dnsFail 'http://u.corp.example.test/a.crl'), (& $script:dnsFail 'http://s.corp.example.test/a.crl'))
        $f = & $script:run (& $script:inv) $leads $findings
        $stale = @($f | Where-Object { $_.Category -eq 'StaleRef' -and $_.Message -notlike 'Reference review:*' })
        $stale.Count | Should -Be 4
        foreach ($x in $f) {
            $x.Category | Should -Be 'StaleRef'
            @($x.Evidence).Count | Should -BeGreaterThan 1
            @($x.Sources).Count | Should -BeGreaterThan 0
            (@($x.Message, $x.Notes, $x.Remediation, ($x.Evidence -join ' ')) -join ' ') | Should -Not -Match '(?i)\b(delete|remove|purge|clean up|decommission)\b'
        }
        foreach ($x in $stale) { $x.Evidence[0] | Should -Match '^Classification: (CurrentReference|HistoricalReference|UnreachableReference|StaleReferenceCandidate)$' }
        @($stale | ForEach-Object { $_.Evidence[0] -replace '^Classification: ', '' } | Sort-Object) | Should -Be @('CurrentReference', 'HistoricalReference', 'StaleReferenceCandidate', 'UnreachableReference')
    }

    It 'reads the lead registry in the run (Invoke-MspkiStaleReferenceAnalysis)' {
        $d = [pscustomobject]@{ Inventory = (& $script:inv) }
        $f = InModuleScope MspkiHealthCheck -Parameters @{ D = $d } { param($D)
            Reset-MspkiLeadRegistry
            $null = Add-MspkiLead -Url 'http://pki.corp.example.test/CertEnroll/x.crl' -Kind CDP -Source 'Cert:E001:CDP' -Origin 'test'
            Invoke-MspkiStaleReferenceAnalysis -Discovery $D -Findings @() }
        @($f | Where-Object { $_.Evidence[0] -eq 'Classification: HistoricalReference' }).Count | Should -Be 1
    }
}
