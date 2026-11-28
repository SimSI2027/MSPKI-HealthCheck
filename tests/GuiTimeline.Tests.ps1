# GX7: the Timeline page. Pure side (src/Gui/GuiLifecycle.ps1: lifecycle model, countdowns, CRL copies, axis, rows, certificate chain) and the
# page in the real window (src/Gui/GuiTimelinePage.ps1). The demo world's samples are read by path (no name of them appears here); the LARGE
# estate is generated (tests\GuiMapFixture.ps1, example.test only).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    foreach ($f in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1', 'GuiMission.ps1', 'GuiLifecycle.ps1') { . (Join-Path $script:RepoRoot ('src\Gui\' + $f)) }
    . (Join-Path $PSScriptRoot 'GuiMapFixture.ps1')
    $script:Load = {
        param([string]$Name)
        $d = Read-MspkiGuiResults -Path (Join-Path $script:RepoRoot ('demo\world\alcyone-{0}-results.json' -f $Name))
        $ix = New-MspkiGuiGraphIndex -Graph $d.Graph -Findings $d.Findings
        $st = @{}; foreach ($f in $d.Findings) { $st[[string]$f.Id] = [string]$f.Status }
        [pscustomobject]@{ Doc = $d; Ix = $ix; St = $st; Now = (ConvertTo-MspkiGuiDateTime -Value $d.RunInfo.StartedUtc) }
    }
    $script:Expired = & $script:Load 'expired-crl'
    $script:Drift = & $script:Load 'renewal-drift'
    $script:Mixed = & $script:Load 'mixed'
    $script:ModelOf = { param($w) Get-MspkiGuiLifecycleModel -Index $w.Ix -FindingStatus $w.St -Now $w.Now -RunInfo $w.Doc.RunInfo }
    $script:GroupOf = { param($m, [string]$like) @($m.Groups | Where-Object { $_.Name -like $like })[0] }
}

Describe 'Countdowns and copies in plain words' {
    It 'says a span the way people do, and only the largest unit where room is tight' {
        Get-MspkiGuiSpanText -Days 900 | Should -Be '2 years 5 months'
        Get-MspkiGuiSpanText -Days 365.3 | Should -Be '1 year'
        Get-MspkiGuiSpanText -Days 200 | Should -Be '6 months'
        Get-MspkiGuiSpanText -Days 20 | Should -Be '20 days'
        Get-MspkiGuiSpanText -Days 3.25 | Should -Be '3 days 6 hours'
        Get-MspkiGuiSpanText -Days 3.25 -Coarse | Should -Be '3 days'
        Get-MspkiGuiSpanText -Days -1 | Should -Be '24 hours'
        Get-MspkiGuiSpanText -Days 0.2 | Should -Be '4 hours'
        Get-MspkiGuiSpanText -Days 0.01 | Should -Be '14 minutes'
        Get-MspkiGuiSpanText -Days 0.0001 | Should -Be '1 minute'
    }
    It 'reads the CRL copies the engine records (at an address and at the CA), and nothing else' {
        # The contract with the engine: run its own recorders, then read their observation details back.
        $details = InModuleScope MspkiHealthCheck {
            Reset-MspkiEntityGraph
            $crl = [pscustomobject]@{ Issuer = 'CN=Example Issuing CA, DC=corp, DC=example, DC=test'; IsDelta = $false; AuthorityKeyId = 'AABB'; CAVersion = 'V0.0'; CrlNumber = '2A'
                ThisUpdate = [datetime]'2026-11-18T22:00:00Z'; NextUpdate = [datetime]'2026-11-25T10:00:00Z'; NextPublish = $null; Sha1 = '' }
            Register-MspkiCaOwnCrl -OwnCrls @([pscustomobject]@{ Config = 'ca01.corp.example.test\Example Issuing CA'; Crl = $crl })
            $lead = [pscustomobject]@{ Kind = 'CDP'; Url = 'http://pki.example.test/CertEnroll/Example Issuing CA.crl'; Scope = 'Local'; Confidence = 'Referenced'; Sources = @('test'); RelatedCAs = @() }
            Register-MspkiProbeResult -Lead $lead -Url $lead.Url -Result ([pscustomobject]@{ Crl = $crl; Certificate = $null; Validated = $false }) -Tested
            @(Get-MspkiObservation -EntityId (Get-MspkiCrlEntityId -AuthorityKeyId 'AABB' -IsDelta $false) -Kind 'Seen' | ForEach-Object { $_.Detail })
        }
        $details.Count | Should -Be 2
        foreach ($d in $details) {
            $c = Read-MspkiGuiCrlCopy -Detail $d
            $c.Number | Should -Be '2A'
            $c.ThisUpdate | Should -Be ([datetime]::new(2026, 11, 18, 22, 0, 0, [DateTimeKind]::Utc))
            $c.NextUpdate.Kind | Should -Be 'Utc'
            $c.NextUpdate | Should -Be ([datetime]::new(2026, 11, 25, 10, 0, 0, [DateTimeKind]::Utc))
        }
        Read-MspkiGuiCrlCopy -Detail 'Named in CDP of a certificate; not retrieved from this location.' | Should -BeNullOrEmpty
    }
    It 'compares CRL numbers as the hex numbers they are' {
        Compare-MspkiGuiHexNumber '29' '2A' | Should -Be -1
        Compare-MspkiGuiHexNumber '0100' 'FF' | Should -Be 1
        Compare-MspkiGuiHexNumber '2a' '2A' | Should -Be 0
    }
}

Describe 'The lifecycle model (scenario expired-crl)' {
    BeforeAll { $script:M = & $script:ModelOf $script:Expired; $script:Mer = & $script:GroupOf $script:M '*Meridian*' }
    It 'puts the root first, then the issuing CAs, and a CA it could not read with the issuing CAs' {
        $script:M.Groups[0].Name | Should -BeLike '*Lodestar Root*'
        $z = & $script:GroupOf $script:M '*Zenith*'
        $z.Depth | Should -Be 1
    }
    It 'shows the expired base CRL as failing, counted from the run (not from today), with every copy expired' {
        $base = @($script:Mer.Crls | Where-Object { -not $_.Delta })[0]
        $base.State | Should -Be 'Expired'
        $base.Tone | Should -Be 'Bad'
        $base.Countdown | Should -Be 'Expired 3 days 1 hour ago'
        @($base.Copies).Count | Should -Be 4
        @($base.Copies | Where-Object { $_.Tone -ne 'Bad' }).Count | Should -Be 0
        @($base.Copies | Where-Object { $_.Where -like 'At the CA*' }).Count | Should -Be 1
        # The same results read a day later say the same: the countdown is the run's.
        $later = Get-MspkiGuiLifecycleModel -Index $script:Expired.Ix -FindingStatus $script:Expired.St -Now $script:Expired.Now.AddDays(1) -RunInfo $script:Expired.Doc.RunInfo
        @((& $script:GroupOf $later '*Meridian*').Crls | Where-Object { -not $_.Delta })[0].Countdown | Should -Be 'Expired 4 days 1 hour ago'
    }
    It 'draws the overlap from Next CRL Publish to Next Update' {
        $base = @($script:Mer.Crls | Where-Object { -not $_.Delta })[0]
        $base.Mark | Should -Not -BeNullOrEmpty
        $base.Mark | Should -BeLessThan $base.End
        $base.Tip | Should -Match 'Next CRL Publish'
    }
    It 'puts the expired CRL first in "runs out first" and says it in the CA''s summary' {
        $script:M.NextToLapse[0].Id | Should -Be @($script:Mer.Crls | Where-Object { -not $_.Delta })[0].Id
        $script:M.NextToLapse[0].Tone | Should -Be 'Bad'
        $script:M.NextToLapse[0].Short | Should -Be 'Meridian Issuing CA'
        $script:Mer.CrlSummary | Should -Be 'Base CRL: expired 3 days 1 hour ago'
        $script:Mer.Tone | Should -Be 'Bad'
    }
    It 'never shows a CA it could not read as healthy: a row says so, in the could-not-check tone' {
        $z = & $script:GroupOf $script:M '*Zenith*'
        @($z.Certs).Count | Should -Be 1
        $z.Certs[0].Kind | Should -Be 'Missing'
        $z.Certs[0].Tone | Should -Be 'Admin'
        $z.Certs[0].Tip | Should -Match 'could not read'
        $z.Tone | Should -Be 'Admin'
        $z.CrlSummary | Should -Be 'CRLs not read'
    }
    It 'gives each view its own CA status: the CRL fails, the certificates do not' {
        $script:Mer.CrlTone | Should -Be 'Bad'
        $script:Mer.CertTone | Should -Not -Be 'Bad'
        $items = Get-MspkiGuiTimelineItemList -Model $script:M -View Certificates -Range $null
        $grp = @($items | Where-Object { $_.Kind -eq 'Group' -and $_.Title -like '*Meridian*' })[0]
        $grp.Pill.Tone | Should -Be $script:Mer.CertTone
        $grp.TitleWrap | Should -Be 'Wrap'
        $items = Get-MspkiGuiTimelineItemList -Model $script:M -View Crls -Range $null
        @($items | Where-Object { $_.Kind -eq 'Group' -and $_.Title -like '*Meridian*' })[0].Pill.Tone | Should -Be 'Bad'
    }
    It 'returns nothing for results without a graph' { Get-MspkiGuiLifecycleModel -Index $null -Now (Get-Date) | Should -BeNullOrEmpty }
}

Describe 'The lifecycle model (scenario renewal-drift)' {
    BeforeAll { $script:D = & $script:ModelOf $script:Drift; $script:DMer = & $script:GroupOf $script:D '*Meridian*' }
    It 'shows the three generations in the order they started, the newest current' {
        $subs = @($script:DMer.Certs | ForEach-Object { $_.Sub })
        $subs | Should -Be @('generation V0.0 · replaced', 'generation V1.0 · replaced', 'generation V2.2 · current')
        $script:DMer.Certs[2].Countdown | Should -Be 'Expires in 1 year 11 months'
        $script:DMer.Certs[1].State | Should -Be 'Replaced'
        $script:DMer.Certs[1].Tone | Should -Be 'Good'
    }
    It 'keeps an expired replaced generation neutral by itself, but a finding about it (still in NTAuth) makes it a warning' {
        $script:DMer.Certs[0].State | Should -Be 'Replaced'
        $script:DMer.Certs[0].Countdown | Should -Match '^Expired '
        $script:DMer.Certs[0].Tone | Should -Be 'Warn'
        @($script:DMer.Certs[0].Findings).Count | Should -BeGreaterThan 0
    }
    It 'shows the CRL of every key that still signs, and names the key when a CA has two' {
        @($script:DMer.Crls | Where-Object { -not $_.Delta }).Count | Should -Be 2
        @($script:D.NextToLapse | Where-Object { $_.Label -match '^Base CRL \(V' }).Count | Should -Be 2
    }
    It 'lists the certificates that run out first in the Certificates view and the CRLs in the CRLs view, and says a replaced one in the largest unit' {
        @($script:D.NextCerts).Count | Should -BeGreaterThan 0
        foreach ($n in $script:D.NextCerts) { $n.Kind | Should -Not -Be 'Crl' }
        @($script:D.NextCrls).Count | Should -BeGreaterThan 0
        foreach ($n in $script:D.NextCrls) { $n.Kind | Should -Be 'Crl' }
        $script:DMer.Certs[0].Countdown | Should -Match '^Expired \d+ years? ago$'
    }
}

Describe 'The time axis' {
    BeforeAll { $script:Now0 = [datetime]::new(2026, 11, 20, 9, 0, 0, [DateTimeKind]::Utc) }
    It 'fits every bar in Auto, keeps the short CRL heartbeats readable, and puts the run a third of the way into a fixed span' {
        $short = [pscustomobject]@{ Start = $script:Now0.AddDays(-2); End = $script:Now0.AddDays(5); Mark = $null; Copies = @() }
        $long = [pscustomobject]@{ Start = $script:Now0.AddDays(-170); End = $script:Now0.AddDays(195); Mark = $null; Copies = @() }
        $r = Get-MspkiGuiTimelineRange -Rows @($short, $long) -Now $script:Now0
        $r.Start | Should -BeLessThan $long.Start
        $r = Get-MspkiGuiTimelineRange -Rows @($short, $long) -Now $script:Now0 -FocusDays 31
        ($r.End - $r.Start).TotalDays | Should -BeLessThan 10
        $r = Get-MspkiGuiTimelineRange -Rows @($long) -Now $script:Now0 -FocusDays 31
        ($r.End - $r.Start).TotalDays | Should -BeGreaterThan 300
        $r = Get-MspkiGuiTimelineRange -Rows @($short) -Now $script:Now0 -SpanDays 90
        [math]::Round(($script:Now0 - $r.Start).TotalDays) | Should -Be 30
    }
    It 'places a bar with its overlap, says when it runs past the axis, and when it lies outside it' {
        $range = [pscustomobject]@{ Start = $script:Now0.AddDays(-10); End = $script:Now0.AddDays(10) }
        $b = Get-MspkiGuiTimelineBar -Row ([pscustomobject]@{ Start = $script:Now0.AddDays(-5); End = $script:Now0.AddDays(5); Mark = $script:Now0.AddDays(3) }) -Range $range -Now $script:Now0
        $b.HasBar | Should -BeTrue
        @($b.Before, $b.Main, $b.Tail, $b.After) | Should -Be @(5.0, 8.0, 2.0, 5.0)
        @($b.NowBefore, $b.NowAfter) | Should -Be @(10.0, 10.0)
        $b = Get-MspkiGuiTimelineBar -Row ([pscustomobject]@{ Start = $script:Now0.AddDays(-30); End = $script:Now0.AddDays(30); Mark = $null }) -Range $range -Now $script:Now0
        $b.ClipStart | Should -BeTrue; $b.ClipEnd | Should -BeTrue
        (Get-MspkiGuiTimelineBar -Row ([pscustomobject]@{ Start = $script:Now0.AddDays(-40); End = $script:Now0.AddDays(-20); Mark = $null }) -Range $range -Now $script:Now0).Outside | Should -Be 'Before'
        (Get-MspkiGuiTimelineBar -Row ([pscustomobject]@{ Start = $null; End = $script:Now0; Mark = $null }) -Range $range -Now $script:Now0).HasBar | Should -BeFalse
    }
    It 'labels the axis by hours, days, months or years, in order and inside the range' {
        foreach ($span in 1, 14, 90, 700, 7300) {
            $s = $script:Now0.AddDays(-$span / 3); $e = $script:Now0.AddDays($span * 2 / 3)
            $t = @(Get-MspkiGuiTimelineTick -Start $s -End $e)
            $t.Count | Should -BeGreaterThan 1
            $t.Count | Should -BeLessThan 16
            for ($i = 1; $i -lt $t.Count; $i++) { $t[$i].Fraction | Should -BeGreaterThan $t[$i - 1].Fraction }
            $t[0].Fraction | Should -BeGreaterOrEqual 0
            $t[-1].Fraction | Should -BeLessOrEqual 1
        }
        @(Get-MspkiGuiTimelineTick -Start ([datetime]'2016-01-01') -End ([datetime]'2036-12-31'))[0].Text | Should -Match '^\d{4}$'
        @(Get-MspkiGuiTimelineTick -Start $script:Now0.AddDays(-4) -End $script:Now0.AddDays(10))[0].Text | Should -Match '^\d{1,2} [A-Z][a-z]{2}$'
        # Months always carry their year ("Jan 2027", not a bare "2027" between "Dec 2026" and "Feb 2027").
        $mt = @(Get-MspkiGuiTimelineTick -Start ([datetime]::new(2026, 10, 15, 0, 0, 0, [DateTimeKind]::Utc)) -End ([datetime]::new(2027, 2, 20, 0, 0, 0, [DateTimeKind]::Utc)))
        @($mt | ForEach-Object { $_.Text }) | Should -Be @('Nov 2026', 'Dec 2026', 'Jan 2027', 'Feb 2027')
    }
}

Describe 'Timeline rows' {
    It 'builds a CA row, its rows and every copy, with star widths the window binds as they are (in any culture)' {
        $m = & $script:ModelOf $script:Expired
        $old = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('de-DE')
            $r = Invoke-MspkiGuiTimelineJob -Request @{ Kind = 'Timeline'; Gen = 1; Options = @{ Now = $script:Expired.Now; RunInfo = $script:Expired.Doc.RunInfo; View = 'Crls'; SpanDays = 0; Copies = $true } } -Index $script:Expired.Ix -Status $script:Expired.St -Cache @{}
        }
        finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $old }
        $items = @($r.Items)
        @($items | Where-Object Kind -eq 'Group').Count | Should -Be 3
        @($items | Where-Object Kind -eq 'Copy').Count | Should -Be 7
        @($items | Where-Object Kind -eq 'Note').Count | Should -Be 1
        foreach ($it in $items) { foreach ($w in 'WBefore', 'WMain', 'WTail', 'WAfter', 'NowL', 'NowR') { [string]$it.$w | Should -Match '^\d+(\.\d+)?\*$' } }
        $row = @($items | Where-Object { $_.Kind -eq 'Row' -and $_.Title -eq 'Base CRL' -and $_.Sub -like '*V1.0*' })[0]
        $row.Due.Text | Should -Be 'Expired 3 days 1 hour ago'
        $row.AutomationName | Should -Match 'Failing'
        $row.HasTail | Should -BeTrue
        @($items | Where-Object Kind -eq 'Copy')[0].Due.Text | Should -Match '^Number \w+ · '
        # Without the copies: only the CA and CRL rows.
        $r2 = Invoke-MspkiGuiTimelineJob -Request @{ Kind = 'Timeline'; Gen = 1; Options = @{ Now = $script:Expired.Now; View = 'Crls'; SpanDays = 0; Copies = $false } } -Index $script:Expired.Ix -Status $script:Expired.St -Cache @{ TlGen = 1; TlModel = $m }
        @($r2.Items | Where-Object Kind -eq 'Copy').Count | Should -Be 0
    }
}

Describe 'The certificate chain' {
    It 'starts from a certificate on this computer, and shows where revocation checking breaks (scenario expired-crl)' {
        $ch = @(Get-MspkiGuiChainChoice -Index $script:Expired.Ix)
        $ch[0].Kind | Should -Be 'Local'
        $ch[0].Text | Should -Match ' · on this computer$'
        $c = Get-MspkiGuiChainModel -Index $script:Expired.Ix -FindingStatus $script:Expired.St -StartId $ch[0].Id -Now $script:Expired.Now
        @($c.Cards).Count | Should -Be 3
        $c.Cards[2].Root | Should -BeTrue
        $c.HeadlineTone | Should -Be 'Bad'
        $c.Headline | Should -Match 'cannot check whether .+ was revoked'
        # The leaf's addresses come from its CA's settings and say so (Inferred).
        $c.Cards[0].Note | Should -Match 'Inferred'
        @($c.Cards[0].Cdp).Count | Should -Be 3
        foreach ($a in $c.Cards[0].Cdp) { $a.Tone | Should -Be 'Bad'; $a.Text | Should -Match '^Served CRL number \w+ · expired ' }
        # A certificate whose every CDP address fails is itself failing (the card's colour), even though its dates are fine.
        $c.Cards[0].ValidityTone | Should -Be 'Good'
        $c.Cards[0].Tone | Should -Be 'Bad'
        # One CDP address with a warning (and none failing) is a warning, not a failure.
        $c.Cards[1].Tone | Should -Be 'Warn'
    }
    It 'says each link''s result in plain words, and an address this run did not check is never shown as healthy (mixed sample)' {
        $ch = @(Get-MspkiGuiChainChoice -Index $script:Mixed.Ix)
        $ca = @($ch | Where-Object { $_.Kind -eq 'CA' -and $_.Text -match 'current' })[0]
        $c = Get-MspkiGuiChainModel -Index $script:Mixed.Ix -FindingStatus $script:Mixed.St -StartId $ca.Id -Now $script:Mixed.Now
        $c.Links[0].Text | Should -Match 'issued .+ Clients can fetch .+ from both addresses in the certificate'
        $c.Links[0].Tone | Should -Be 'Good'
        $ocsp = @($c.Cards[0].Ocsp)[0]
        $ocsp.Tone | Should -Be 'Neutral'
        $ocsp.Text | Should -Be 'Not checked in this run'
    }
    It 'ends with "Issuer not found" when the issuer is not in the results' {
        $g = [pscustomobject]@{
            Entities = @(
                [pscustomobject]@{ Id = 'cacert:aa'; Type = 'CACertificate'; Name = 'CN=Example Issuing CA, DC=example, DC=test'; Properties = [pscustomobject]@{ Subject = 'CN=Example Issuing CA, DC=example, DC=test'; Issuer = 'CN=Gone Root, DC=example, DC=test'; NotAfter = '2030-01-01T00:00:00Z' } }
                [pscustomobject]@{ Id = 'localcert:bb'; Type = 'LocalCertificate'; Name = 'CN=host.example.test'; Properties = [pscustomobject]@{ NotAfter = '2027-01-01T00:00:00Z' } })
            Observations = @(); Relations = @([pscustomobject]@{ From = 'localcert:bb'; Type = 'issuedBy'; To = 'cacert:aa'; Sources = @(); Confidence = 'Confirmed' }) }
        $ix = New-MspkiGuiGraphIndex -Graph $g -Findings @()
        $c = Get-MspkiGuiChainModel -Index $ix -StartId 'localcert:bb' -Now ([datetime]::new(2026, 11, 20, 0, 0, 0, [DateTimeKind]::Utc))
        $c.Cards[-1].Placeholder | Should -BeTrue
        $c.Cards[-1].Title | Should -Be 'Issuer not found'
        $c.Links[-1].Text | Should -Match '^Issuer not confirmed'
        $c.HeadlineTone | Should -Be 'Neutral'
    }
}

Describe 'Chain link headings (GX7 round 2: an address that answered with a warning served the issuer)' {
    It 'counts an address with a warning as served, and says the warning' {
        Get-MspkiGuiChainLinkHeading -Link ([pscustomobject]@{ Ok = 1; Warn = 1; Total = 1 }) | Should -BeExactly 'Issued by · its AIA address served it, with a warning'
        Get-MspkiGuiChainLinkHeading -Link ([pscustomobject]@{ Ok = 0; Warn = 0; Total = 1 }) | Should -BeExactly 'Issued by · its AIA address did not serve it'
        Get-MspkiGuiChainLinkHeading -Link ([pscustomobject]@{ Ok = 2; Warn = 1; Total = 3 }) | Should -BeExactly 'Issued by · 2 of 3 AIA addresses served it, 1 with a warning'
        Get-MspkiGuiChainLinkHeading -Link ([pscustomobject]@{ Ok = 2; Total = 2 }) | Should -BeExactly 'Issued by · 2 of 2 AIA addresses served it'
        Get-MspkiGuiChainLinkHeading -Link ([pscustomobject]@{ Ok = 0; Warn = 0; Total = 0 }) | Should -BeExactly 'Issued by'
    }
}

Describe 'Performance budget (GX7: the timeline is computed off the UI thread)' {
    It 'computes the model and the rows of a 300-object estate (8 CAs, 60 addresses) in well under 300 ms (the background worker''s job)' {
        $doc = New-MspkiTestLargeResults -CaCount 8 -EndpointCount 60 -ObjectCount 300 -WithUnreadCa -WithLifecycle
        $ix = New-MspkiGuiGraphIndex -Graph $doc.Graph -Findings $doc.Findings
        $st = @{}; foreach ($f in $doc.Findings) { $st[[string]$f.Id] = [string]$f.Status }
        $now = ConvertTo-MspkiGuiDateTime -Value $doc.RunInfo.StartedUtc
        $best = [double]::MaxValue; $r = $null
        foreach ($i in 1..3) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = Invoke-MspkiGuiTimelineJob -Request @{ Kind = 'Timeline'; Gen = $i; Options = @{ Now = $now; RunInfo = $doc.RunInfo; View = 'Crls'; SpanDays = 0; Copies = $true } } -Index $ix -Status $st -Cache @{}
            $best = [math]::Min($best, $sw.Elapsed.TotalMilliseconds)
        }
        @($r.Items).Count | Should -BeGreaterThan 80
        $best | Should -BeLessThan 300
        Write-Host ('    timeline job (model and {0} CRL rows, 300-object estate): {1:0} ms, best of 3' -f @($r.Items).Count, $best)
    }
}

Describe 'The Timeline page in the real window (scenario expired-crl, keyboard, Back, chain, palette, budgets)' {
    BeforeAll {
        $script:GuiFolder = Join-Path $script:RepoRoot 'src\Gui'
        function Invoke-InStaRunspace {
            param([string]$Script, [object[]]$Arguments = @())
            $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
            $rs.ApartmentState = [System.Threading.ApartmentState]::STA
            $rs.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
            $rs.Open()
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.Runspace = $rs
            [void]$ps.AddScript($Script)
            foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
            try {
                $out = @($ps.Invoke())
                if ($ps.Streams.Error.Count -gt 0) { throw ($ps.Streams.Error | ForEach-Object { $_.ToString() }) -join '; ' }
                return $out
            }
            finally { $ps.Dispose(); $rs.Dispose() }
        }
        $outRoot = Join-Path $TestDrive 'out'
        New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
        $large = Join-Path $outRoot 'large.json'
        [IO.File]::WriteAllText($large, ((New-MspkiTestLargeResults -CaCount 8 -EndpointCount 60 -ObjectCount 300 -WithUnreadCa -WithLifecycle) | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding $false))
        $res = Join-Path $script:RepoRoot 'demo\world\alcyone-expired-crl-results.json'
        $script:Win = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $res, $outRoot, $large) -Script {
            param($folder, $module, $results, $outRoot, $large)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            function Show-MspkiGuiMessage { param($Text, $Title, $Icon) Write-Output ('MESSAGEBOX: ' + $Text) }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $g = $script:MspkiGui; $ui = $g.Ui
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show(); [void]$win.Activate()
            Wait-MspkiGuiIdle -Rounds 4
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            $key = { param([string]$k, [bool]$c = $false, [bool]$a = $false) $h = Invoke-MspkiGuiShortcut -Key $k -Ctrl $c -Alt $a -Shift $false; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2; $h }
            $r = [ordered]@{}
            # Pages: Ctrl+4 is the Timeline, Ctrl+7 the run log; the switch time.
            $sw = [Diagnostics.Stopwatch]::StartNew()
            [void](& $key 'D4' $true)
            $r.SwitchMs = $sw.ElapsedMilliseconds
            $r.OnTimeline = ($ui.Tabs.SelectedItem -eq $ui.TabTimeline)
            # Opened on the view of what runs out first, with it selected and open in the pane.
            $r.View = $(if ($ui.RbTlCrls.IsChecked) { 'Crls' } elseif ($ui.RbTlCerts.IsChecked) { 'Certificates' } else { 'Chain' })
            $r.Selected = [string]$ui.TlList.SelectedItem.Id
            $r.First = [string]$g.TlModel.NextToLapse[0].Id
            $r.PaneTitle = [string]$ui.TimelineHost.Content.Title
            $r.AsOf = [string]$ui.TxtTlAsOf.Text
            $r.Axis = $ui.TlAxisHost.Children.Count
            $r.NextChips = @($ui.TlNext.ItemsSource).Count
            # Keyboard: Down selects the next row and opens it; Enter opens the selected row.
            [void][System.Windows.Input.Keyboard]::Focus($ui.TlList); Wait-MspkiGuiIdle -Rounds 1
            $ui.TlList.SelectedIndex = 0; Wait-MspkiGuiIdle -Rounds 1
            $r.GroupPane = [string]$ui.TimelineHost.Content.Kind
            $src = [System.Windows.PresentationSource]::FromVisual($ui.TlList)
            $ev = New-Object System.Windows.Input.KeyEventArgs([System.Windows.Input.Keyboard]::PrimaryDevice, $src, 0, [System.Windows.Input.Key]::Return)
            $ev.RoutedEvent = [System.Windows.Input.Keyboard]::PreviewKeyDownEvent
            $ui.TlList.SelectedIndex = 1
            Reset-MspkiGuiPaneNav -HostName 'TimelineHost'; $ui.TimelineHost.Content = $null
            $ui.TlList.RaiseEvent($ev); Wait-MspkiGuiIdle -Rounds 1
            $r.EnterOpened = ($null -ne $ui.TimelineHost.Content -and [string]$ui.TimelineHost.Content.Id -eq [string]$ui.TlList.SelectedItem.Id)
            # Back: open a related object from the pane, then Alt+Left returns and the list keeps the row selected.
            $row = $ui.TlList.SelectedItem
            $rel = @($ui.TimelineHost.Content.Related | Where-Object { $_.Known }) | Select-Object -First 1
            if ($null -ne $rel) { Invoke-MspkiGuiPaneCommand -HostName 'TimelineHost' -Tag ([string]$rel.Tag); Wait-MspkiGuiIdle -Rounds 1 }
            $r.Related = ($null -ne $rel -and [string]$ui.TimelineHost.Content.Id -ne [string]$row.Id)
            [void](& $key 'Left' $false $true)
            $r.BackTo = ([string]$ui.TimelineHost.Content.Id -eq [string]$row.Id)
            $r.StillSelected = ($ui.TlList.SelectedItem -eq $row)
            # Range: two weeks.
            $ui.FltTlSpan.SelectedIndex = 1; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 1
            $r.TwoWeeks = [math]::Round(($g.TlRange.End - $g.TlRange.Start).TotalDays)
            # Certificates view: the CA it could not read has a could-not-check row.
            $ui.RbTlCerts.IsChecked = $true; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 1
            $miss = @($g.TlItems | Where-Object { $_.Kind -eq 'Row' -and $_.HasOutside -and $_.Tone -eq 'Admin' })
            $r.Missing = $miss.Count
            # Chain: starts from the certificate on this computer; a click on an address opens it in the pane.
            $ui.RbTlChain.IsChecked = $true; Wait-MspkiGuiIdle -Rounds 2
            $r.ChainCards = @($ui.TlChain.ItemsSource | Where-Object { $_.Kind -eq 'Card' }).Count
            $r.ChainHead = [string]$ui.TlChainHead.DataContext.Tone
            $r.ChainPane = [string]$ui.TimelineHost.Content.Id
            $addr = @(@($ui.TlChain.ItemsSource)[0].Sections)[0].Items[0]
            Invoke-MspkiGuiTimelineTag -Tag ([string]$addr.Tag); Wait-MspkiGuiIdle -Rounds 1
            $r.AddressPane = ([string]$ui.TimelineHost.Content.Id -eq ([string]$addr.Tag).Substring(4))
            # F6 reaches the chain and the pane; the palette offers the page and the commands.
            $r.Palette = (@(Get-MspkiGuiPalettePage | ForEach-Object { $_.Title }) -join ',')
            $r.Commands = (@(Get-MspkiGuiPaletteCommand -Available (Get-MspkiGuiCommandAvailability) | ForEach-Object { $_.Action }) -join ',')
            [void](& $key 'D7' $true); $r.Ctrl7 = ($ui.Tabs.SelectedItem -eq $ui.TabLog)
            # Every interactive element of the page has an accessible name.
            $unnamed = New-Object System.Collections.ArrayList
            foreach ($n in 'RbTlCerts', 'RbTlCrls', 'RbTlChain', 'FltTlSpan', 'FltTlChain', 'ChkTlCopies', 'TlList', 'TlChain') { if (-not [System.Windows.Automation.AutomationProperties]::GetName($ui[$n])) { [void]$unnamed.Add($n) } }
            $r.Unnamed = ($unnamed -join ',')
            # The LARGE estate: rows from the worker; the UI-thread part (putting them on screen) stays under 50 ms.
            Open-MspkiGuiResultsFile -Path $large
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            $ui.Tabs.SelectedItem = $ui.TabTimeline; $ui.RbTlCrls.IsChecked = $true; Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            $req = @{ Kind = 'Timeline'; Gen = [int]$g.MapGen; Options = @{ Now = $g.TlNow; RunInfo = $g.TlRunInfo; View = 'Crls'; SpanDays = 0; Copies = $true } }
            $res2 = Invoke-MspkiGuiTimelineJob -Request $req -Index $g.Index -Status $g.MapStatus -Cache @{}
            $best = [double]::MaxValue
            foreach ($i in 1..3) { $sw.Restart(); Complete-MspkiGuiTimelineJob -Result $res2; Wait-MspkiGuiIdle -Rounds 1; $best = [math]::Min($best, $sw.Elapsed.TotalMilliseconds) }
            $r.LargeApplyMs = $best
            $r.LargeRows = @($g.TlItems).Count
            $win.Close()
            [pscustomobject]$r
        }
        $script:WinR = @($script:Win | Where-Object { $_ -isnot [string] })[-1]
        $script:WinMsg = @($script:Win | Where-Object { $_ -is [string] })
    }
    It 'opened without a Windows message box' { $script:WinMsg.Count | Should -Be 0 }
    It 'is page 4 (Ctrl+4) and opens within the page-switch budget; the run log moved to Ctrl+7' {
        $script:WinR.OnTimeline | Should -BeTrue
        $script:WinR.SwitchMs | Should -BeLessThan 150
        $script:WinR.Ctrl7 | Should -BeTrue
        Write-Host ('    window: switch to the Timeline {0} ms; LARGE estate rows ({1}) put on screen in {2:0} ms' -f $script:WinR.SwitchMs, $script:WinR.LargeRows, $script:WinR.LargeApplyMs)
    }
    It 'opens on the CRLs with the expired CRL selected and open in the details pane, counted from the run' {
        $script:WinR.View | Should -Be 'Crls'
        $script:WinR.Selected | Should -Be $script:WinR.First
        $script:WinR.PaneTitle | Should -Match '^Base CRL of '
        $script:WinR.AsOf | Should -Be 'As of the run: 20 Nov 2026, 09:29 UTC'
        $script:WinR.Axis | Should -BeGreaterThan 3
        $script:WinR.NextChips | Should -Be 3
    }
    It 'opens a row with the keyboard (selection and Enter), and Alt+Left goes back with the row still selected' {
        $script:WinR.GroupPane | Should -Be 'Entity'
        $script:WinR.EnterOpened | Should -BeTrue
        $script:WinR.Related | Should -BeTrue
        $script:WinR.BackTo | Should -BeTrue
        $script:WinR.StillSelected | Should -BeTrue
    }
    It 'changes the range, and shows the CA it could not read as "could not check"' {
        $script:WinR.TwoWeeks | Should -Be 14
        $script:WinR.Missing | Should -Be 1
    }
    It 'shows the chain from the certificate on this computer, with the break, and opens an address in the pane' {
        $script:WinR.ChainCards | Should -Be 3
        $script:WinR.ChainHead | Should -Be 'Bad'
        $script:WinR.ChainPane | Should -BeLike 'localcert:*'
        $script:WinR.AddressPane | Should -BeTrue
    }
    It 'offers the page and its commands in the palette, and names every control' {
        $script:WinR.Palette | Should -Match 'Go to Timeline'
        foreach ($c in 'cmd:tlcerts', 'cmd:tlcrls', 'cmd:tlchain') { $script:WinR.Commands | Should -Match ([regex]::Escape($c)) }
        $script:WinR.Unnamed | Should -Be ''
    }
    It 'puts the rows of the LARGE estate on screen in under 50 ms of UI-thread work' {
        $script:WinR.LargeRows | Should -BeGreaterThan 80
        $script:WinR.LargeApplyMs | Should -BeLessThan 50
    }
}
