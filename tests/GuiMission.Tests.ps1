# Mission-control Overview helpers (src/Gui/GuiMission.ps1): the health score, "What to do next" and the discovery map model.
# Pure functions: no window is needed. The score formula is docs/GUI-EXPERIENCE.md section 6.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $script:RepoRoot 'src\MspkiHealthCheck.psd1') -Force
    foreach ($f in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1', 'GuiMission.ps1') { . (Join-Path $script:RepoRoot ('src\Gui\' + $f)) }
    $script:F = {
        param([string]$Id, [string]$Category, [string]$Status, [string]$Severity = 'None', $Diagnosis = $null, [string[]]$EntityIds = @())
        $o = [pscustomobject]@{ Id = $Id; Category = $Category; Status = $Status; Severity = $Severity; Message = ('Message of ' + $Id); Target = ''; EntityIds = $EntityIds }
        if ($null -ne $Diagnosis) { $o | Add-Member -NotePropertyName Diagnosis -NotePropertyValue $Diagnosis }
        $o
    }
    $script:Diag = {
        param([string]$Topic, [string]$Basis = 'Typical', [string]$Likelihood = 'Most common')
        [pscustomobject]@{ Topic = $Topic; Title = ('Title of ' + $Topic); Basis = $Basis; Causes = @([pscustomobject]@{ Rank = 1; Cause = ('Cause of ' + $Topic); Likelihood = $Likelihood }) }
    }
}

Describe 'Get-MspkiGuiHealthScore' {
    It 'gives 71 for one failure and 90 for one warning (every 40 points halve an area)' {
        $s = Get-MspkiGuiHealthScore -Findings @((& $script:F 'F1' 'CRL' 'Fail'))
        $s.HasScore | Should -BeTrue
        $s.Overall | Should -Be 71
        $s.Band | Should -Be 'Needs attention'
        (@($s.Areas | Where-Object Key -eq 'Revocation'))[0].Score | Should -Be 71
        (Get-MspkiGuiHealthScore -Findings @((& $script:F 'F1' 'AIA' 'Warning'))).Overall | Should -Be 90
        (Get-MspkiGuiHealthScore -Findings @((& $script:F 'F1' 'AIA' 'Warning'))).Band | Should -Be 'Healthy'
    }
    It 'weights critical findings and severity (Critical 35 x High 1.4 = 49 points)' {
        (Get-MspkiGuiHealthScore -Findings @((& $script:F 'F1' 'Template' 'Critical' 'High'))).Overall | Should -Be 43
        (Get-MspkiGuiHealthScore -Findings @((& $script:F 'F1' 'Template' 'Fail' 'Low'))).Overall | Should -Be 81
    }
    It 'caps the overall score at the weakest area + 30' {
        $fs = @((& $script:F 'P1' 'ADContainer' 'Pass'), (& $script:F 'F1' 'CRL' 'Fail'), (& $script:F 'F2' 'CRL' 'Fail'), (& $script:F 'F3' 'OCSP' 'Fail'))
        $s = Get-MspkiGuiHealthScore -Findings $fs
        (@($s.Areas | Where-Object Key -eq 'Revocation'))[0].Score | Should -Be 35
        $s.Overall | Should -Be 65
        $s.Band | Should -Be 'Needs attention'
    }
    It 'marks the score partial when a check could not run or the run did not finish' {
        $s = Get-MspkiGuiHealthScore -Findings @((& $script:F 'P1' 'CA' 'Pass'), (& $script:F 'E1' 'CA' 'Error'))
        $s.Overall | Should -Be 100
        $s.Partial | Should -BeTrue
        $s.PartialText | Should -Match '1 check could not run'
        (Get-MspkiGuiHealthScore -Findings @((& $script:F 'P1' 'CA' 'Pass')) -Completed $false).PartialText | Should -Match 'did not finish'
        (Get-MspkiGuiHealthScore -Findings @((& $script:F 'P1' 'CA' 'Pass'))).Partial | Should -BeFalse
    }
    It 'gives no score without a CA, and does not score the areas either' {
        $s = Get-MspkiGuiHealthScore -Findings @((& $script:F 'F1' 'CRL' 'Fail')) -HasCa $false
        $s.HasScore | Should -BeFalse
        $s.Reason | Should -Match 'No Enterprise CA'
        @($s.Areas | Where-Object { $null -ne $_.Score }).Count | Should -Be 0
    }
    It 'does not score run or local-evidence findings, and an area without findings has no score' {
        $s = Get-MspkiGuiHealthScore -Findings @((& $script:F 'R1' 'Run' 'Fail'), (& $script:F 'L1' 'LocalEvidence' 'Warning'))
        $s.HasScore | Should -BeFalse
        $s.Reason | Should -Match 'No finding'
        (@($s.Areas | Where-Object Key -eq 'Security'))[0].ScoreText | Should -Be ([string][char]0x2014)
    }
    It 'explains itself in plain words' {
        (Get-MspkiGuiHealthScore -Findings @()).HowText | Should -Match 'not a certification'
    }
}

Describe 'Get-MspkiGuiNextAction' {
    It 'groups findings by diagnosis topic, most urgent first, and leaves passing findings out' {
        $fs = @(
            (& $script:F 'W1' 'CRL' 'Warning' 'None' (& $script:Diag 'crl-late'))
            (& $script:F 'W2' 'CRL' 'Warning' 'None' (& $script:Diag 'crl-late'))
            (& $script:F 'F1' 'AIA' 'Fail' 'None' (& $script:Diag 'aia-missing' 'Observed' 'Most likely'))
            (& $script:F 'I1' 'CA' 'Information')
            (& $script:F 'P1' 'CA' 'Pass')
        )
        $a = Get-MspkiGuiNextAction -Findings $fs -Max 5
        $a.Total | Should -Be 2
        $a.Items[0].Title | Should -Be 'Title of aia-missing'
        $a.Items[0].Rank | Should -Be 1
        $a.Items[0].Observed | Should -BeTrue
        $a.Items[0].Cause | Should -Be 'Most likely: Cause of aia-missing'
        $a.Items[0].Tag | Should -Be 'F1'
        $a.Items[1].Count | Should -Be 2
        $a.Items[1].CountText | Should -Be '2 findings'
        $a.Items[1].Observed | Should -BeFalse
        $a.Items[1].AreaName | Should -Be 'Revocation'
    }
    It 'keeps the first -Max actions and counts them all' {
        $fs = @(1..7 | ForEach-Object { & $script:F ('W' + $_) 'CRL' 'Warning' 'None' (& $script:Diag ('t' + $_)) })
        $a = Get-MspkiGuiNextAction -Findings $fs -Max 3
        $a.Total | Should -Be 7
        @($a.Items).Count | Should -Be 3
    }
    It 'returns nothing to do for a clean run' {
        (Get-MspkiGuiNextAction -Findings @((& $script:F 'P1' 'CA' 'Pass'))).Total | Should -Be 0
    }
}

Describe 'Get-MspkiGuiMapModel and its layout' {
    BeforeAll {
        $e = { param($id, $type, $name, $props = @{}) [pscustomobject]@{ Id = $id; Type = $type; Name = $name; Properties = [pscustomobject]$props } }
        $r = { param($from, $type, $to) [pscustomobject]@{ From = $from; Type = $type; To = $to } }
        $graph = [pscustomobject]@{
            Entities = @(
                (& $e 'forest:corp.example.test' 'Forest' 'corp.example.test')
                (& $e 'cacert:aa' 'CACertificate' 'CN=Example Root CA')
                (& $e 'cacert:bb' 'CACertificate' 'CN=Example Issuing CA')
                (& $e 'ca:ca01.corp.example.test\example issuing ca' 'CA' 'Example Issuing CA' @{ CAType = 'EnterpriseSubordinate'; PropertiesRead = $true })
                (& $e 'ca:ca02.corp.example.test\example other ca' 'CA' 'Example Other CA' @{ PropertiesRead = $false })
                (& $e 'endpoint:http://pki.corp.example.test/a.crl' 'Endpoint' 'http://pki.corp.example.test/a.crl' @{ Url = 'http://pki.corp.example.test/a.crl'; Kinds = @('CDP') })
                (& $e 'endpoint:http://pki2.corp.example.test/a.crl' 'Endpoint' 'http://pki2.corp.example.test/a.crl' @{ Url = 'http://pki2.corp.example.test/a.crl'; Kinds = @('CDP') })
                (& $e 'endpoint:ldap:///cn=example issuing ca,cn=aia' 'Endpoint' 'ldap:///CN=Example Issuing CA,CN=AIA' @{ Url = 'ldap:///CN=Example%20Issuing%20CA,CN=AIA'; Kinds = @('AIA') })
                (& $e 'host:pki.corp.example.test' 'Host' 'pki.corp.example.test')
                (& $e 'host:pki2.corp.example.test' 'Host' 'pki2.corp.example.test')
            )
            Relations = @(
                (& $r 'cacert:bb' 'certificateOf' 'ca:ca01.corp.example.test\example issuing ca')
                (& $r 'cacert:bb' 'issuedBy' 'cacert:aa')
                (& $r 'cacert:bb' 'references' 'endpoint:http://pki.corp.example.test/a.crl')
                (& $r 'ca:ca01.corp.example.test\example issuing ca' 'references' 'endpoint:http://pki2.corp.example.test/a.crl')
                (& $r 'cacert:bb' 'references' 'endpoint:ldap:///cn=example issuing ca,cn=aia')
                (& $r 'endpoint:http://pki.corp.example.test/a.crl' 'hostedOn' 'host:pki.corp.example.test')
                (& $r 'endpoint:http://pki2.corp.example.test/a.crl' 'hostedOn' 'host:pki2.corp.example.test')
            )
            Observations = @()
        }
        $fs = @(
            (& $script:F 'F1' 'CDP' 'Fail' 'None' $null @('endpoint:http://pki2.corp.example.test/a.crl'))
            (& $script:F 'P1' 'CDP' 'Pass' 'None' $null @('endpoint:http://pki.corp.example.test/a.crl'))
            (& $script:F 'I1' 'CA' 'Information' 'None' $null @('ca:ca01.corp.example.test\example issuing ca'))
        )
        $script:Ix = New-MspkiGuiGraphIndex -Graph $graph -Findings $fs
        $script:St = @{ F1 = 'Fail'; P1 = 'Pass'; I1 = 'Information' }
    }
    It 'puts roots, issuing CAs, addresses and their hosts in columns, with chain, publish and host links' {
        $m = Get-MspkiGuiMapModel -Index $script:Ix -FindingStatus $script:St
        $node = @{}; foreach ($n in $m.Nodes) { $node[$n.Id] = $n }
        $m.Layers | Should -Be 4
        $node['cagroup:cn=example root ca'].Layer | Should -Be 0
        $node['ca:ca01.corp.example.test\example issuing ca'].Layer | Should -Be 1
        # A CA whose properties were not read is not a root: it sits with the issuing CAs and says it was not checked.
        $node['ca:ca02.corp.example.test\example other ca'].Layer | Should -Be 1
        $node['ca:ca02.corp.example.test\example other ca'].Tone | Should -Be 'Admin'
        $node['ca:ca02.corp.example.test\example other ca'].Sub | Should -Match 'not read'
        $node['endpoint:http://pki.corp.example.test/a.crl'].Layer | Should -Be 2
        $node['host:pki.corp.example.test'].Layer | Should -Be 3
        # LDAP addresses without a host are served by the directory (the forest).
        $node['forest:corp.example.test'].Kind | Should -Be 'Directory'
        @($m.Links | Where-Object { $_.Kind -eq 'chain' }).Count | Should -Be 1
        @($m.Links | Where-Object { $_.From -eq 'endpoint:ldap:///cn=example issuing ca,cn=aia' -and $_.To -eq 'forest:corp.example.test' }).Count | Should -Be 1
    }
    It 'colours nodes by their own findings (Information says nothing about health)' {
        $m = Get-MspkiGuiMapModel -Index $script:Ix -FindingStatus $script:St
        $node = @{}; foreach ($n in $m.Nodes) { $node[$n.Id] = $n }
        $node['endpoint:http://pki2.corp.example.test/a.crl'].Tone | Should -Be 'Bad'
        $node['endpoint:http://pki.corp.example.test/a.crl'].Tone | Should -Be 'Good'
        $node['ca:ca01.corp.example.test\example issuing ca'].Tone | Should -Be 'Neutral'
    }
    It 'shortens labels (shared first word, file names) and tells same-named addresses apart by host' {
        $m = Get-MspkiGuiMapModel -Index $script:Ix -FindingStatus $script:St
        $node = @{}; foreach ($n in $m.Nodes) { $node[$n.Id] = $n }
        $node['ca:ca01.corp.example.test\example issuing ca'].Label | Should -Be 'Issuing CA'
        $node['ca:ca01.corp.example.test\example issuing ca'].FullName | Should -Be 'Example Issuing CA'
        $node['endpoint:http://pki.corp.example.test/a.crl'].Label | Should -Be 'a.crl'
        $node['endpoint:http://pki.corp.example.test/a.crl'].Sub | Should -Match 'CDP over HTTP . pki$'
        $node['endpoint:http://pki2.corp.example.test/a.crl'].Sub | Should -Match 'pki2$'
    }
    It 'lays the columns out left to right without overlap, inside the canvas' {
        $m = Get-MspkiGuiMapModel -Index $script:Ix -FindingStatus $script:St
        foreach ($w in 560, 1200) {
            $h = Set-MspkiGuiMapLayout -Model $m -Width $w
            $h | Should -BeGreaterOrEqual 200
            foreach ($l in 0..3) {
                $ys = @($m.Nodes | Where-Object { [int]$_.Layer -eq $l } | ForEach-Object { [double]$_.Y } | Sort-Object)
                for ($i = 1; $i -lt $ys.Count; $i++) { ($ys[$i] - $ys[$i - 1]) | Should -BeGreaterOrEqual 32 }
                foreach ($y in $ys) { $y | Should -BeGreaterOrEqual 24; $y | Should -BeLessOrEqual ($h - 24) }
            }
            $xs = @(0..3 | ForEach-Object { $l = $_; @($m.Nodes | Where-Object { [int]$_.Layer -eq $l })[0].X })
            for ($i = 1; $i -lt 4; $i++) { $xs[$i] | Should -BeGreaterThan $xs[$i - 1] }
            @($m.Nodes | Where-Object { $_.LabelWidth -lt 40 }).Count | Should -Be 0
        }
    }
    It 'builds in discovery order: CAs, then each address (probed, then graded), hosts after their first address' {
        $m = Get-MspkiGuiMapModel -Index $script:Ix -FindingStatus $script:St
        [void](Set-MspkiGuiMapLayout -Model $m -Width 900)
        $total = Set-MspkiGuiMapTimeline -Model $m
        $node = @{}; foreach ($n in $m.Nodes) { $node[$n.Id] = $n }
        $ep = $node['endpoint:http://pki.corp.example.test/a.crl']
        $node['cagroup:cn=example root ca'].AppearMs | Should -BeLessThan $ep.AppearMs
        $ep.ProbeMs | Should -BeGreaterThan $ep.AppearMs
        $ep.ResultMs | Should -BeGreaterThan $ep.ProbeMs
        $node['host:pki.corp.example.test'].AppearMs | Should -BeGreaterThan $ep.AppearMs
        $total | Should -BeGreaterThan (@($m.Nodes | ForEach-Object { $_.ResultMs }) | Measure-Object -Maximum).Maximum
    }
    It 'returns no map without a graph (results from an older version)' {
        Get-MspkiGuiMapModel -Index $null | Should -BeNullOrEmpty
    }
}

Describe 'Score bands and the plain-words explanation (GX2)' {
    It 'puts every score in its band: 100 and 90 Healthy, 89 and 60 Needs attention, 59 and 0 At risk' -TestCases @(
        @{ Sc = 100; Bd = 'Healthy'; Tn = 'Good' }, @{ Sc = 90; Bd = 'Healthy'; Tn = 'Good' }, @{ Sc = 89; Bd = 'Needs attention'; Tn = 'Warn' }
        @{ Sc = 60; Bd = 'Needs attention'; Tn = 'Warn' }, @{ Sc = 59; Bd = 'At risk'; Tn = 'Bad' }, @{ Sc = 0; Bd = 'At risk'; Tn = 'Bad' }
    ) {
        $band = Get-MspkiGuiScoreBand -Score $Sc
        $band.Band | Should -Be $Bd
        $band.Tone | Should -Be $Tn
    }
    It 'a clean run scores 100 and Healthy, and is not partial' {
        $s = Get-MspkiGuiHealthScore -Findings @((& $script:F 'P1' 'CA' 'Pass'), (& $script:F 'P2' 'CRL' 'Pass'))
        $s.Overall | Should -Be 100
        $s.Band | Should -Be 'Healthy'
        $s.Partial | Should -BeFalse
    }
    It 'the explanation names the penalties, the halving, the average, the weakest area, partial scores and that it is not a certification, in plain words' {
        $h = (Get-MspkiGuiHealthScore -Findings @()).HowText
        $h | Should -Match '20 points'
        $h | Should -Match 'critical finding 35'
        $h | Should -Match 'warning 6'
        $h | Should -Match 'halve'
        $h | Should -Match 'weakest'
        $h | Should -Match 'partial'
        $h | Should -Match 'not a certification'
    }
}

Describe 'Get-MspkiGuiHeadline (journey J2: the sentence that answers "is my PKI healthy?")' {
    BeforeAll {
        $script:Act = { param($n, $title = 'A CRL has expired') [pscustomobject]@{ Total = $n; Items = @(if ($n -gt 0) { [pscustomobject]@{ Title = $title } }) } }
        $script:Sc = { param($v) [pscustomobject]@{ HasScore = $true; Overall = $v } }
        $script:Hl = { param($level, $title = 'Healthy') [pscustomobject]@{ Level = $level; Title = $title } }
    }
    It 'names the number of actions and the most urgent one' {
        Get-MspkiGuiHeadline -Health (& $script:Hl 'Red' 'Action needed') -Actions (& $script:Act 3) -Score (& $script:Sc 60) | Should -Be '3 actions need attention. Most urgent: A CRL has expired.'
        Get-MspkiGuiHeadline -Health (& $script:Hl 'Amber') -Actions (& $script:Act 1 'The CA certificate will expire soon.') -Score (& $script:Sc 90) | Should -Be '1 action needs attention. Most urgent: The CA certificate will expire soon.'
    }
    It 'says everything checked is healthy only for a healthy run with nothing to do' {
        Get-MspkiGuiHeadline -Health (& $script:Hl 'Green') -Actions (& $script:Act 0) -Score (& $script:Sc 100) | Should -Be 'Everything checked is healthy.'
        Get-MspkiGuiHeadline -Health (& $script:Hl 'Amber' 'Needs review') -Actions (& $script:Act 0) -Score (& $script:Sc 100) | Should -Be 'Needs review'
        Get-MspkiGuiHeadline -Health (& $script:Hl 'Green') -Actions (& $script:Act 0) -Score (& $script:Sc 85) | Should -Not -Be 'Everything checked is healthy.'
    }
    It 'says so when there is no CA, and when the run did not finish' {
        Get-MspkiGuiHeadline -Health (& $script:Hl 'Green') -Actions (& $script:Act 0) -Score $null -HasCa $false | Should -Be 'No Enterprise CA was found'
        Get-MspkiGuiHeadline -Health (& $script:Hl 'Amber') -Actions (& $script:Act 0) -Score (& $script:Sc 100) -Completed $false | Should -BeLike 'This run did not finish*'
        Get-MspkiGuiHeadline -Health (& $script:Hl 'Red') -Actions (& $script:Act 2) -Score (& $script:Sc 70) -Completed $false | Should -BeLike 'Partial run: 2 actions need attention*'
    }
}

Describe 'The live state of a run (GX1 items to the live map)' {
    BeforeAll {
        $script:Ent = { param($id, $type, $name, $props = @{}) [pscustomobject]@{ Kind = 'Entity'; Id = $id; Type = $type; Name = $name; Parents = @(); Props = $props; Time = [DateTime]::Now } }
        $script:Rel = { param($from, $type, $to) [pscustomobject]@{ Kind = 'Relation'; From = $from; Type = $type; To = $to; Time = [DateTime]::Now } }
        $script:Prb = { param($phase, $id, $outcome = '') [pscustomobject]@{ Kind = 'Probe'; Phase = $phase; Probe = 'HTTP'; Id = $id; Outcome = $outcome; Time = [DateTime]::Now } }
        $script:Feed = {
            $st = New-MspkiGuiLiveState
            $items = @(
                (& $script:Ent 'forest:corp.example.test' 'Forest' 'corp.example.test')
                (& $script:Ent 'cacert:aa' 'CACertificate' 'CN=Example Root CA')
                (& $script:Ent 'cacert:bb' 'CACertificate' 'CN=Example Issuing CA')
                (& $script:Ent 'ca:ca01.corp.example.test\example issuing ca' 'CA' 'Example Issuing CA' @{ CAType = 'EnterpriseSubordinate'; PropertiesRead = $true })
                (& $script:Rel 'cacert:bb' 'certificateOf' 'ca:ca01.corp.example.test\example issuing ca')
                (& $script:Rel 'cacert:bb' 'issuedBy' 'cacert:aa')
                (& $script:Ent 'endpoint:http://pki.corp.example.test/a.crl' 'Endpoint' 'http://pki.corp.example.test/a.crl' @{ Url = 'http://pki.corp.example.test/a.crl'; Kinds = @('CDP') })
                (& $script:Ent 'host:pki.corp.example.test' 'Host' 'pki.corp.example.test')
                (& $script:Rel 'cacert:bb' 'references' 'endpoint:http://pki.corp.example.test/a.crl')
                (& $script:Rel 'endpoint:http://pki.corp.example.test/a.crl' 'hostedOn' 'host:pki.corp.example.test')
            )
            foreach ($i in $items) { [void](Add-MspkiGuiLiveItem -State $st -Item $i) }
            $st
        }
    }
    It 'adds each entity and relation once, and says whether the picture changed' {
        $st = New-MspkiGuiLiveState
        Add-MspkiGuiLiveItem -State $st -Item (& $script:Ent 'host:a' 'Host' 'a') | Should -BeTrue
        Add-MspkiGuiLiveItem -State $st -Item (& $script:Ent 'host:a' 'Host' 'a') | Should -BeFalse
        Add-MspkiGuiLiveItem -State $st -Item (& $script:Rel 'host:a' 'aliasOf' 'host:b') | Should -BeTrue
        Add-MspkiGuiLiveItem -State $st -Item (& $script:Rel 'host:a' 'aliasOf' 'host:b') | Should -BeFalse
        Add-MspkiGuiLiveItem -State $st -Item ([pscustomobject]@{ Kind = 'Log'; Text = 'x' }) | Should -BeFalse
        $st.Entities.Count | Should -Be 1
        @($st.Relations).Count | Should -Be 1
        $st.Version | Should -Be 2
    }
    It 'tracks the probes that run now and keeps the worst outcome of each object' {
        $st = New-MspkiGuiLiveState
        [void](Add-MspkiGuiLiveItem -State $st -Item (& $script:Prb 'Start' 'endpoint:x'))
        $st.Probes.Contains('endpoint:x') | Should -BeTrue
        [void](Add-MspkiGuiLiveItem -State $st -Item (& $script:Prb 'End' 'endpoint:x' 'OK'))
        $st.Probes.Contains('endpoint:x') | Should -BeFalse
        $st.Outcomes['endpoint:x'] | Should -Be 'OK'
        [void](Add-MspkiGuiLiveItem -State $st -Item (& $script:Prb 'End' 'endpoint:x' 'TCP_FAIL'))
        $st.Outcomes['endpoint:x'] | Should -Be 'TCP_FAIL'
        [void](Add-MspkiGuiLiveItem -State $st -Item (& $script:Prb 'End' 'endpoint:x' 'OK'))
        $st.Outcomes['endpoint:x'] | Should -Be 'TCP_FAIL'
        [void](Add-MspkiGuiLiveItem -State $st -Item (& $script:Prb 'End' 'endpoint:y' 'NOT_APPLICABLE'))
        $st.Outcomes.ContainsKey('endpoint:y') | Should -BeFalse
    }
    It 'builds the same map as a finished run: roots, issuing CAs, addresses and hosts in columns, from the announced items only' {
        $m = Get-MspkiGuiLiveMapModel -State (& $script:Feed)
        $m.Layers | Should -Be 4
        $kinds = @($m.Nodes | ForEach-Object { $_.Kind } | Sort-Object)
        $kinds | Should -Be @('CA', 'CA', 'Endpoint', 'Host')
        @($m.Links | Where-Object { $_.Kind -eq 'chain' }).Count | Should -Be 1
        @($m.Links | Where-Object { $_.Kind -eq 'publishes' }).Count | Should -Be 1
        @($m.Links | Where-Object { $_.Kind -eq 'hostedOn' }).Count | Should -Be 1
        (Get-MspkiGuiLiveMapModel -State (New-MspkiGuiLiveState)) | Should -BeNullOrEmpty
    }
    It 'colours a probed object by its probe (answered: Info; did not answer: Warn) and leaves the CAs neutral, never green or red' {
        $st = & $script:Feed
        [void](Add-MspkiGuiLiveItem -State $st -Item (& $script:Prb 'End' 'endpoint:http://pki.corp.example.test/a.crl' 'OK'))
        $ep = @((Get-MspkiGuiLiveMapModel -State $st).Nodes | Where-Object { $_.Kind -eq 'Endpoint' })[0]
        $ep.Tone | Should -Be 'Info'
        [void](Add-MspkiGuiLiveItem -State $st -Item (& $script:Prb 'End' 'endpoint:http://pki.corp.example.test/a.crl' 'TIMEOUT'))
        @((Get-MspkiGuiLiveMapModel -State $st).Nodes | Where-Object { $_.Kind -eq 'Endpoint' })[0].Tone | Should -Be 'Warn'
        @((Get-MspkiGuiLiveMapModel -State $st).Nodes | Where-Object { $_.Kind -eq 'CA' } | ForEach-Object { $_.Tone } | Select-Object -Unique) | Should -Be @('Neutral')
    }
    It 'says what has been found so far, in words' {
        Get-MspkiGuiLiveFoundText -State (New-MspkiGuiLiveState) | Should -Be ''
        Get-MspkiGuiLiveFoundText -State (& $script:Feed) | Should -Be '1 CA, 1 published address and 1 host found so far'
    }
}
