# GX6: the discovery map, pure side (src/Gui/GuiMap.ps1) and the full-page map in the real window (src/Gui/GuiMapPage.ps1).
# Pure tests use the demo world's results file (read by path; no name of it appears here) and a generated LARGE estate
# (tests\GuiMapFixture.ps1, example.test only). The window tests run the real window off-screen in a single-threaded runspace.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    foreach ($f in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1', 'GuiMission.ps1', 'GuiState.ps1') { . (Join-Path $script:RepoRoot ('src\Gui\' + $f)) }
    . (Join-Path $PSScriptRoot 'GuiMapFixture.ps1')
    $script:WorldFile = Join-Path $script:RepoRoot 'demo\world\alcyone-mixed-results.json'
    $script:World = Read-MspkiGuiResults -Path $script:WorldFile
    $script:WorldIx = New-MspkiGuiGraphIndex -Graph $script:World.Graph -Findings $script:World.Findings
    $script:WorldSt = @{}; foreach ($f in $script:World.Findings) { $script:WorldSt[[string]$f.Id] = [string]$f.Status }
    $script:NewWorldModel = { Get-MspkiGuiMapModel -Index $script:WorldIx -FindingStatus $script:WorldSt }
    $script:Large = New-MspkiTestLargeResults -CaCount 12 -EndpointCount 200 -ObjectCount 500 -WithUnreadCa
    $script:LargeIx = New-MspkiGuiGraphIndex -Graph $script:Large.Graph -Findings $script:Large.Findings
    $script:LargeSt = @{}; foreach ($f in $script:Large.Findings) { $script:LargeSt[[string]$f.Id] = [string]$f.Status }
    $script:LargeModel = Get-MspkiGuiMapModel -Index $script:LargeIx -FindingStatus $script:LargeSt
    $script:NodeOf = { param($m) $h = @{}; foreach ($n in $m.Nodes) { $h[[string]$n.Id] = $n }; $h }
}

Describe 'Owner review: every CA shows its relationship (item 1)' {
    It 'links a CA whose issuer was not confirmed to the only root CA with a dashed "not confirmed" link that says why' {
        $m = & $script:NewWorldModel
        $unread = @($m.Nodes | Where-Object { $_.Kind -eq 'CA' -and $_.Unread })
        $unread.Count | Should -Be 1
        $l = @($m.Links | Where-Object { $_.To -eq $unread[0].Id })
        $l.Count | Should -Be 1
        $l[0].Kind | Should -Be 'unconfirmed'
        $root = (& $script:NodeOf $m)[[string]$l[0].From]
        $root.Layer | Should -Be 0
        $l[0].Text | Should -Match '^Issuer not confirmed: the properties of .+ could not be read'
        $l[0].Text | Should -Match 'is the only root CA this run found, so it is the most likely issuer'
    }
    It 'uses an "Unknown issuer" placeholder when there is no single root to point to' {
        $doc = New-MspkiTestLargeResults -CaCount 8 -EndpointCount 6 -ObjectCount 40 -WithUnreadCa
        $ix = New-MspkiGuiGraphIndex -Graph $doc.Graph -Findings $doc.Findings
        $m = Get-MspkiGuiMapModel -Index $ix -FindingStatus @{}
        $u = @($m.Nodes | Where-Object { $_.Kind -eq 'Unknown' })
        $u.Count | Should -Be 1
        $u[0].Layer | Should -Be 0
        @($m.Links | Where-Object { $_.From -eq 'unknown-issuer' -and $_.Kind -eq 'unconfirmed' }).Count | Should -Be 1
        @($m.Links | Where-Object { $_.From -eq 'unknown-issuer' })[0].Text | Should -Match 'found 2 root CAs, so it cannot say which one'
    }
    It 'leaves the inference out of the live map (the CAs are still being read)' {
        $m = Get-MspkiGuiMapModel -Index $script:WorldIx -FindingStatus $script:WorldSt -Live
        @($m.Links | Where-Object { $_.Kind -eq 'unconfirmed' }).Count | Should -Be 0
    }
}

Describe 'Owner review: fewer crossings (item 2)' {
    It 'counts crossings correctly on a two-by-two example' {
        $N = { param($id, $l, $o) [pscustomobject]@{ Id = $id; Layer = $l; Order = $o; Y = $o * 40 } }
        $m = [pscustomobject]@{ Nodes = @((& $N 'a' 0 0), (& $N 'b' 0 1), (& $N 'c' 1 0), (& $N 'd' 1 1)); Links = @([pscustomobject]@{ From = 'a'; To = 'd' }, [pscustomobject]@{ From = 'b'; To = 'c' }) }
        Get-MspkiGuiMapCrossing -Model $m -By Order | Should -Be 1
        $m.Nodes[2].Order = 1; $m.Nodes[3].Order = 0
        Get-MspkiGuiMapCrossing -Model $m -By Order | Should -Be 0
    }
    It 'brings the crossings on the demo world down from the plain order to none, and the laid-out map keeps that' {
        # The GX6 shape of the world (the issuing CA's own certificate named its CRL addresses; GX7 corrected the sample, whose plain order
        # has no crossing left): rebuilt in memory, so the owner's "12 -> 0" stays asserted on the Alcyone world.
        $cert = 'cacert:3c4d5e6f708192a3b4c5d6e7f809101112131415'
        $caM = @($script:World.Graph.Entities | Where-Object { $_.Type -eq 'CA' -and $_.Name -like '*Meridian*' })[0].Id
        $cdp = @($script:World.Graph.Relations | Where-Object { $_.From -eq $caM -and $_.Type -eq 'references' -and (@($_.Sources) -join ',') -like '*CertCdpUrls' })
        $cdp.Count | Should -Be 3
        $old = @($script:World.Graph.Relations | Where-Object { -not ($_.From -eq $caM -and $_.Type -eq 'references' -and (@($_.Sources) -join ',') -like '*CertCdpUrls' -and $_.To -notlike '*//pki.*') -and -not ($_.From -eq $cert -and $_.Type -eq 'references' -and (@($_.Sources) -join ',') -like '*:CDP') })
        $old += @($cdp | ForEach-Object { [pscustomobject]@{ From = $cert; Type = 'references'; To = $_.To; Sources = @('Cert:3C4D5E6F708192A3B4C5D6E7F809101112131415:CDP'); Confidence = 'Confirmed' } })
        $ix = New-MspkiGuiGraphIndex -Graph ([pscustomobject]@{ Entities = $script:World.Graph.Entities; Observations = $script:World.Graph.Observations; Relations = $old }) -Findings $script:World.Findings
        $m = Get-MspkiGuiMapModel -Index $ix -FindingStatus $script:WorldSt
        $o = Set-MspkiGuiMapOrder -Model $m
        $o.Before | Should -Be 12
        $o.After | Should -Be 0
        $m = Get-MspkiGuiMapModel -Index $ix -FindingStatus $script:WorldSt
        [void](Set-MspkiGuiMapLayout -Model $m -Width 1040 -LabelWidth 190)
        Get-MspkiGuiMapCrossing -Model $m -By Y | Should -Be 0
        # The world as it is now: no crossing, before or after the layout.
        $m = & $script:NewWorldModel
        (Set-MspkiGuiMapOrder -Model $m).After | Should -Be 0
        $m = & $script:NewWorldModel
        [void](Set-MspkiGuiMapLayout -Model $m -Width 1040 -LabelWidth 190)
        Get-MspkiGuiMapCrossing -Model $m -By Y | Should -Be 0
    }
    It 'also lowers the crossings of the large estate' {
        $v = Get-MspkiGuiMapView -Model $script:LargeModel
        [void](Set-MspkiGuiMapLayout -Model $v -Natural -LabelWidth 200 -Gap 46)
        $v.Crossings.After | Should -BeLessThan $v.Crossings.Before
    }
    It 'keeps every column in its order, without overlap, inside the canvas' {
        $m = & $script:NewWorldModel
        $h = Set-MspkiGuiMapLayout -Model $m -Natural -LabelWidth 200 -Gap 46
        foreach ($l in 0..($m.Layers - 1)) {
            $col = @($m.Nodes | Where-Object { [int]$_.Layer -eq $l } | Sort-Object Order)
            for ($i = 1; $i -lt $col.Count; $i++) { ($col[$i].Y - $col[$i - 1].Y) | Should -BeGreaterOrEqual 45 }
            foreach ($n in $col) { $n.Y | Should -BeGreaterOrEqual 24; $n.Y | Should -BeLessOrEqual ($h - 24) }
        }
    }
}

Describe 'Owner review: path health and plain words on the links (items 5 and 6)' {
    It 'marks the links into a failing address red and a warning amber; healthy links stay plain' {
        $m = & $script:NewWorldModel
        $n = & $script:NodeOf $m
        $bad = @($m.Links | Where-Object { $_.Kind -eq 'publishes' -and $n[[string]$_.To].Tone -eq 'Bad' })
        $bad.Count | Should -BeGreaterThan 0
        foreach ($l in $bad) { $l.Tone | Should -Be 'Bad' }
        foreach ($l in @($m.Links | Where-Object { $_.Kind -eq 'publishes' -and $n[[string]$_.To].Tone -eq 'Warn' })) { $l.Tone | Should -Be 'Warn' }
        foreach ($l in @($m.Links | Where-Object { $_.Kind -eq 'publishes' -and $n[[string]$_.To].Tone -eq 'Good' })) { $l.Tone | Should -Be '' }
        # The host behind a failing address that is failing itself: the break shows on both links.
        @($m.Links | Where-Object { $_.Kind -eq 'hostedOn' -and $_.Tone -eq 'Bad' }).Count | Should -BeGreaterThan 0
    }
    It 'explains an AIA link in plain words, naming the issuer, and says where the chain breaks' {
        $m = & $script:NewWorldModel
        $n = & $script:NodeOf $m
        $aia = @($m.Links | Where-Object { $_.Kind -eq 'publishes' -and $n[[string]$_.To].KindText -eq 'AIA' -and $_.Via -eq 'certificate' -and $_.Tone -eq 'Bad' })[0]
        $aia.Text | Should -Match '^.+''s certificate says to fetch its issuer''s certificate \(.+\) from this address\.'
        $aia.Text | Should -Match 'it failed: this is where the chain breaks\.$'
        foreach ($l in $m.Links) { $l.Text | Should -Not -BeNullOrEmpty }
        @($m.Links | Where-Object { $_.Kind -eq 'hostedOn' -and $n[[string]$_.To].Kind -eq 'Directory' })[0].Text | Should -Match '^Active Directory serves this LDAP address'
        @($m.Links | Where-Object { $_.Kind -eq 'chain' })[0].Text | Should -Match ' was issued by .+ signed the certificate of '
    }
}

Describe 'Full-page map views: filters, focus, search and groups' {
    It 'shows only failing objects with the path to them as context' {
        $v = Get-MspkiGuiMapView -Model (& $script:NewWorldModel) -Status Bad
        @($v.Nodes | Where-Object { -not $_.Context } | ForEach-Object { $_.Tone } | Select-Object -Unique) | Should -Be @('Bad')
        @($v.Nodes | Where-Object { $_.Context }).Count | Should -BeGreaterThan 0
        foreach ($c in @($v.Nodes | Where-Object { $_.Context })) { $c.Kind | Should -BeIn @('CA', 'Unknown', 'Endpoint', 'Cluster') }
        $v.Filtered | Should -BeTrue
    }
    It 'shows only problems (failing, warning, could not check), and a problem host keeps the addresses that lead to it' {
        $v = Get-MspkiGuiMapView -Model (& $script:NewWorldModel) -OnlyProblems
        foreach ($n in @($v.Nodes | Where-Object { -not $_.Context })) { $n.Tone | Should -BeIn @('Bad', 'Warn', 'Admin') }
        $ids = @{}; foreach ($n in $v.Nodes) { $ids[[string]$n.Id] = $true }
        foreach ($h in @($v.Nodes | Where-Object { $_.Kind -in @('Host', 'Directory') })) { @($v.Links | Where-Object { $_.To -eq $h.Id }).Count | Should -BeGreaterThan 0 }
    }
    It 'filters by type, closing up the empty columns' {
        $v = Get-MspkiGuiMapView -Model (& $script:NewWorldModel) -Type CA
        @($v.Nodes | Where-Object { $_.Kind -ne 'CA' }).Count | Should -Be 0
        $v.Layers | Should -Be 2
    }
    It 'focuses on one CA: what it issued, publishes and depends on, and its issuers; not the other CAs' {
        $m = & $script:NewWorldModel
        $ca = @($m.Nodes | Where-Object { $_.Kind -eq 'CA' -and [int]$_.Layer -eq 1 -and -not $_.Unread })[0]
        $v = Get-MspkiGuiMapView -Model $m -FocusId $ca.Id
        @($v.Nodes | Where-Object { $_.Unread }).Count | Should -Be 0
        @($v.Nodes | Where-Object { $_.Layer -eq 0 }).Count | Should -Be 1
        @($v.Nodes | Where-Object { $_.Kind -eq 'Endpoint' }).Count | Should -BeGreaterThan 3
    }
    It 'marks search matches without hiding anything (the window dims the rest)' {
        $m = & $script:NewWorldModel
        $word = ([string]@($m.Nodes | Where-Object { $_.Kind -eq 'Host' })[0].Label)
        $v = Get-MspkiGuiMapView -Model $m -Search $word
        $v.Shown | Should -Be @($m.Nodes).Count
        $v.Matches | Should -BeGreaterThan 0
        $v.Matches | Should -BeLessThan $v.Shown
        @($v.Nodes | Where-Object { -not $_.Match }).Count | Should -Be ($v.Shown - $v.Matches)
    }
    It 'never changes the base model' {
        $m = & $script:NewWorldModel
        $before = (@($m.Nodes | ForEach-Object { '{0}:{1}:{2}' -f $_.Id, $_.Layer, $_.Context }) -join '|')
        [void](Get-MspkiGuiMapView -Model $m -Status Bad -Search 'x')
        (@($m.Nodes | ForEach-Object { '{0}:{1}:{2}' -f $_.Id, $_.Layer, $_.Context }) -join '|') | Should -Be $before
    }
    It 'groups the addresses of a host above the threshold, with the worst status, and expands a group on request' {
        $v = Get-MspkiGuiMapView -Model $script:LargeModel
        $v.Groups | Should -BeGreaterThan 0
        $v.Shown | Should -BeLessThan $v.Total
        $grp = @($v.Nodes | Where-Object { $_.Kind -eq 'Cluster' })
        foreach ($c in $grp) { $c.Count | Should -BeGreaterOrEqual 3; $c.Label | Should -Match '^\d+ .*addresses$'; $c.Sub | Should -Match '^on .+ select to expand$' }
        $bad = @($grp | Where-Object { $_.Tone -eq 'Bad' })[0]
        $bad | Should -Not -BeNullOrEmpty
        @($v.Links | Where-Object { $_.To -eq $bad.Id -and $_.Tone -eq 'Bad' }).Count | Should -BeGreaterThan 0
        $e = Get-MspkiGuiMapView -Model $script:LargeModel -Expanded @{ ([string]$bad.HostId) = $true }
        @($e.Nodes | Where-Object { $_.Id -eq $bad.Id }).Count | Should -Be 0
        $e.Groups | Should -Be ($v.Groups - 1)
        @($e.Nodes | Where-Object { $_.Kind -eq 'Endpoint' -and $_.HostId -eq $bad.HostId }).Count | Should -Be $bad.Count
    }
    It 'does not group a small estate' {
        (Get-MspkiGuiMapView -Model (& $script:NewWorldModel)).Groups | Should -Be 0
    }
}

Describe 'Keyboard neighbours and zoom arithmetic' {
    It 'moves up and down a column, left and right to a linked node, Home and End to the ends' {
        $m = & $script:NewWorldModel
        [void](Set-MspkiGuiMapLayout -Model $m -Natural -LabelWidth 200 -Gap 46)
        $first = Find-MspkiGuiMapNeighbor -Model $m -Id '' -Direction Down
        (& $script:NodeOf $m)[$first].Layer | Should -Be 0
        $right = Find-MspkiGuiMapNeighbor -Model $m -Id $first -Direction Right
        (& $script:NodeOf $m)[$right].Layer | Should -Be 1
        @($m.Links | Where-Object { ($_.From -eq $first -and $_.To -eq $right) }).Count | Should -Be 1
        $col = @($m.Nodes | Where-Object { [int]$_.Layer -eq 1 } | Sort-Object Y)
        $down = Find-MspkiGuiMapNeighbor -Model $m -Id $col[0].Id -Direction Down
        $down | Should -Be $col[1].Id
        Find-MspkiGuiMapNeighbor -Model $m -Id $down -Direction Up | Should -Be $col[0].Id
        Find-MspkiGuiMapNeighbor -Model $m -Id $col[-1].Id -Direction Down | Should -Be $col[-1].Id
        Find-MspkiGuiMapNeighbor -Model $m -Id $first -Direction Left | Should -Be $first
        $ep = @($m.Nodes | Where-Object { $_.Kind -eq 'Endpoint' } | Sort-Object Y)
        Find-MspkiGuiMapNeighbor -Model $m -Id $ep[3].Id -Direction Home | Should -Be $ep[0].Id
        Find-MspkiGuiMapNeighbor -Model $m -Id $ep[3].Id -Direction End | Should -Be $ep[-1].Id
    }
    It 'fits a map into the view without blowing a small one up, and zooms by stops around a point' {
        (Get-MspkiGuiMapFit -ContentWidth 400 -ContentHeight 300 -ViewWidth 1000 -ViewHeight 800).Scale | Should -Be 1
        $f = Get-MspkiGuiMapFit -ContentWidth 2000 -ContentHeight 1000 -ViewWidth 1000 -ViewHeight 800
        $f.Scale | Should -BeLessThan 0.5
        ($f.X + 2000 * $f.Scale) | Should -BeLessOrEqual 1000
        Step-MspkiGuiMapZoom -Scale 1 -Direction In | Should -Be 1.1
        Step-MspkiGuiMapZoom -Scale 0.25 -Direction Out | Should -Be 0.25
        Step-MspkiGuiMapZoom -Scale 2.5 -Direction In | Should -Be 2.5
        $o = Get-MspkiGuiMapZoomAt -Scale 1 -NewScale 2 -OffsetX 10 -OffsetY 20 -PointX 300 -PointY 200
        # The map point under (300, 200) was (290, 180); after the zoom it is still under the mouse.
        ($o.X + 290 * 2) | Should -Be 300
        ($o.Y + 180 * 2) | Should -Be 200
    }
}

Describe 'Performance budget (GX6 acceptance: 500 objects lay out in under 300 ms)' {
    It 'lays the grouped view of a generated 500-object estate out in under 300 ms (best of five)' {
        $doc = $script:Large
        @($doc.Graph.Entities).Count | Should -BeGreaterOrEqual 500
        $views = @(); $layouts = @()
        foreach ($i in 1..5) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $v = Get-MspkiGuiMapView -Model $script:LargeModel
            $views += $sw.ElapsedMilliseconds; $sw.Restart()
            [void](Set-MspkiGuiMapLayout -Model $v -Natural -LabelWidth 200 -Gap 46)
            $layouts += $sw.ElapsedMilliseconds
        }
        ($layouts | Measure-Object -Minimum).Minimum | Should -BeLessThan 300
        ($views | Measure-Object -Minimum).Minimum | Should -BeLessThan 300
        Write-Host ('    500-object estate: view {0} ms, layout {1} ms (best of five)' -f ($views | Measure-Object -Minimum).Minimum, ($layouts | Measure-Object -Minimum).Minimum)
    }
    It 'runs the whole page job (model once, then view and layout) the same way inline and in a worker' {
        $cache = @{}
        $r = Invoke-MspkiGuiMapJob -Request @{ Kind = 'Page'; Gen = 1; Options = @{} } -Index $script:LargeIx -Status $script:LargeSt -Cache $cache
        $r.Empty | Should -BeFalse
        $r.View.Groups | Should -BeGreaterThan 0
        $r.View.Width | Should -BeGreaterThan 0
        $r2 = Invoke-MspkiGuiMapJob -Request @{ Kind = 'Page'; Gen = 1; Options = @{ Search = 'pki01' } } -Index $script:LargeIx -Status $script:LargeSt -Cache $cache
        [object]::ReferenceEquals($r.Base, $r2.Base) | Should -BeTrue
        $r2.View.Matches | Should -BeGreaterThan 0
        (Invoke-MspkiGuiMapJob -Request @{ Kind = 'Page'; Gen = 2; Options = @{} } -Index $null -Cache $cache).Empty | Should -BeTrue
    }
}

Describe 'Export path and the report next to a loaded run (owner review item 9)' {
    It 'writes the map image into the run folder inside out\, otherwise into out\ itself, never anywhere else' {
        $root = Join-Path $TestDrive 'out'
        $now = [datetime]'2026-11-27T10:00:00'
        Get-MspkiGuiMapExportPath -RunFolder (Join-Path $root 'run1') -AllowedRoot $root -Now $now | Should -Be (Join-Path $root 'run1\discovery-map-20261127-100000.png')
        Get-MspkiGuiMapExportPath -RunFolder (Join-Path $TestDrive 'elsewhere') -AllowedRoot $root -Now $now | Should -Be (Join-Path $root 'discovery-map-20261127-100000.png')
        Get-MspkiGuiMapExportPath -RunFolder (Join-Path $root '..\x') -AllowedRoot $root -Now $now | Should -Be (Join-Path $root 'discovery-map-20261127-100000.png')
    }
    It 'finds report.html or <name>-report.html beside a results file' {
        $d = Join-Path $TestDrive 'rep'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $res = Join-Path $d 'world-results.json'; Set-Content -LiteralPath $res -Value '{}'
        Find-MspkiGuiReportPath -ResultsPath $res | Should -Be ''
        Set-Content -LiteralPath (Join-Path $d 'world-report.html') -Value '<html></html>'
        Find-MspkiGuiReportPath -ResultsPath $res | Should -Be (Join-Path $d 'world-report.html')
        Set-Content -LiteralPath (Join-Path $d 'report.html') -Value '<html></html>'
        Find-MspkiGuiReportPath -ResultsPath $res | Should -Be (Join-Path $d 'report.html')
    }
}

Describe 'The full-page map in the real window (large estate, keyboard, Back, zoom, export, owner review items 7-9)' {
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
        $runDir = Join-Path $outRoot 'large-run'
        New-Item -ItemType Directory -Path $runDir -Force | Out-Null
        $res = Join-Path $runDir 'results.json'
        [IO.File]::WriteAllText($res, ($script:Large | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding $false))
        [IO.File]::WriteAllText((Join-Path $runDir 'report.html'), '<html><body>report</body></html>')
        $script:Win = Invoke-InStaRunspace -Arguments @($script:GuiFolder, $script:ModulePath, $res, $outRoot) -Script {
            param($folder, $module, $results, $outRoot)
            Import-Module $module -Force
            . (Join-Path $folder 'GuiModel.ps1'); . (Join-Path $folder 'GuiView.ps1'); . (Join-Path $folder 'GuiEntity.ps1'); . (Join-Path $folder 'GuiApp.ps1'); . (Join-Path $folder 'GuiSnapshot.ps1')
            Import-MspkiGuiAssembly
            function Show-MspkiGuiMessage { param($Text, $Title, $Icon) Write-Output ('MESSAGEBOX: ' + $Text) }
            $win = Initialize-MspkiGuiApplication -ModulePath $module -XamlPath (Join-Path $folder 'MainWindow.xaml') -OutputPath $outRoot -OpenResults $results
            $g = $script:MspkiGui; $ui = $g.Ui
            $win.WindowStartupLocation = 'Manual'; $win.Left = -32000; $win.Top = 0; $win.Width = 1360; $win.Height = 860; $win.Show(); [void]$win.Activate()
            Wait-MspkiGuiIdle -Rounds 4
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            $r = [ordered]@{}
            # Owner review items 7-9 on a loaded earlier run.
            $r.StatusText = $ui.TxtStage.Text; $r.StatusIcon = [int][char]$ui.StatusIcon.Text
            $r.NoteRun = [string]$ui.BtnNoteRun.Visibility
            $r.ReportOn = [bool]$ui.BtnOpenReport.IsEnabled
            $r.OverviewDrawn = ($null -ne $g.MapDrawn -and $g.MapDrawn.Nodes.Count -gt 0)
            $r.OverviewGroups = [int]$g.MapModel.Groups
            # The map page: switch time; the map was laid out by the worker and drawn in slices.
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $ui.Tabs.SelectedItem = $ui.TabMap
            Wait-MspkiGuiIdle -Rounds 1
            $r.PageSwitchMs = $sw.ElapsedMilliseconds
            Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 2
            $m = $g.MapPageModel
            $r.PageGroups = [int]$m.Groups; $r.Total = [int]$m.Total
            $r.MaxSliceMs = [int]$g.MapPerf.MaxSliceMs; $r.LayoutMs = [int]$g.MapPerf.LastLayoutMs
            $tk = $g.MapPerf.Ticks.ToArray(); [Array]::Sort($tk); $r.Ticks = $tk.Count; $r.P95Ms = $tk[[int][math]::Floor(0.95 * ($tk.Count - 1))]; $r.P99Ms = $tk[[int][math]::Floor(0.99 * ($tk.Count - 1))]; $r.GcTicks = (@($g.MapPerf.GcTicks) -join ',')
            $r.Worker = ($null -ne $g.MapWorker)
            $r.Mini = [string]$ui.MiniMap.Visibility
            $r.Replay = [bool]$ui.BtnMapReplay.IsEnabled; $r.Export = [bool]$ui.BtnMapExport.IsEnabled
            # Pan and zoom only change two transforms (timed over 50 moves).
            $sw.Restart(); foreach ($i in 1..50) { Move-MspkiGuiMapPan -DX 3 -DY 2 }; $r.PanMs = $sw.Elapsed.TotalMilliseconds / 50
            Set-MspkiGuiMapFit
            $z0 = $g.MapZoom
            [void](Invoke-MspkiGuiShortcut -Key 'OemPlus' -Ctrl $true); $r.ZoomIn = ($g.MapZoom -gt $z0)
            [void](Invoke-MspkiGuiShortcut -Key 'D0' -Ctrl $true); $r.FitBack = ([math]::Abs($g.MapZoom - $z0) -lt 0.001)
            # Keyboard: focus the map, move, open, move, open, then Alt+Left back to the first.
            [void][System.Windows.Input.Keyboard]::Focus($ui.MapViewport); Wait-MspkiGuiIdle -Rounds 1
            $start = $g.MapFocusId
            [void](Invoke-MspkiGuiMapKey -Key 'Right'); [void](Invoke-MspkiGuiMapKey -Key 'Down')
            $r.Moved = ([bool]$g.MapFocusId -and $g.MapFocusId -ne $start)
            $r.RingShown = [string]$g.MapFocusRing.Visibility
            # Open an issuing CA, then the one below it, then go back with Alt+Left.
            [void](Invoke-MspkiGuiMapKey -Key 'Home')
            $guard = 0; while ($g.MapPageDrawn.ById[$g.MapFocusId].Node.Kind -ne 'CA' -and $guard -lt 40) { [void](Invoke-MspkiGuiMapKey -Key 'Down'); $guard++ }
            [void](Invoke-MspkiGuiMapKey -Key 'Enter'); Wait-MspkiGuiIdle -Rounds 1
            $first = $g.MapSelectedEntity
            $r.PaneKind = [string]$ui.MapHost.Content.Kind
            [void](Invoke-MspkiGuiMapKey -Key 'Down'); [void](Invoke-MspkiGuiMapKey -Key 'Enter'); Wait-MspkiGuiIdle -Rounds 1
            $r.Second = ([bool]$g.MapSelectedEntity -and $g.MapSelectedEntity -ne $first)
            [void](Invoke-MspkiGuiShortcut -Key 'Left' -Alt $true); Wait-MspkiGuiIdle -Rounds 1
            $r.BackToFirst = ($g.MapSelectedEntity -eq $first)
            # A group opens with Enter: one group fewer, the focus inside it.
            $grp = @($g.MapPageDrawn.Nodes | Where-Object { $_.Node.Kind -eq 'Cluster' })[0]
            $g.MapFocusId = [string]$grp.Node.Id
            [void](Invoke-MspkiGuiMapKey -Key 'Enter'); Wait-MspkiGuiMapIdle; Wait-MspkiGuiIdle -Rounds 1
            $r.GroupsAfterExpand = [int]$g.MapPageModel.Groups
            $r.FocusInGroup = (@($grp.Node.Members) -contains $g.MapFocusId)
            # Only problems, then Esc clears it.
            $ui.ChkMapProblems.IsChecked = $true; Update-MspkiGuiMapPage; Wait-MspkiGuiMapIdle
            $r.ProblemsFiltered = [bool]$g.MapPageModel.Filtered
            [System.Windows.Input.Keyboard]::Focus($ui.MapViewport) | Out-Null
            [void](Invoke-MspkiGuiShortcut -Key 'Escape'); Wait-MspkiGuiMapIdle
            $r.EscCleared = (-not [bool]$ui.ChkMapProblems.IsChecked -and -not $g.MapPageModel.Filtered)
            $r.PaletteMap = (@(Get-MspkiGuiPaletteCommand -Available (Get-MspkiGuiCommandAvailability) | ForEach-Object { $_.Action }) -join ',')
            # Export: a PNG inside the run folder (inside out).
            $p = Export-MspkiGuiMapPng
            $r.ExportPath = [string]$p
            $r.ExportBytes = $(if ($p -and (Test-Path -LiteralPath $p)) { (Get-Item -LiteralPath $p).Length } else { 0 })
            # The tree stays the text alternative and takes the pane.
            $ui.RbMapTree.IsChecked = $true; Wait-MspkiGuiIdle -Rounds 1
            $r.TreeVisible = [bool]$ui.MapTree.IsVisible; $r.PaneAfterTree = [string]$ui.MapHost.Content.Kind
            $win.Close()
            [pscustomobject]$r
        }
        $script:WinR = @($script:Win | Where-Object { $_ -isnot [string] })[-1]
        $script:WinMsg = @($script:Win | Where-Object { $_ -is [string] })
    }
    It 'opened without a Windows message box' { $script:WinMsg.Count | Should -Be 0 }
    It 'says an earlier run is on show with the info icon, offers Run now in the banner, and enables the report next to it' {
        $script:WinR.StatusText | Should -Be 'Showing an earlier run'
        $script:WinR.StatusIcon | Should -Be 0xE946
        $script:WinR.NoteRun | Should -Be 'Visible'
        $script:WinR.ReportOn | Should -BeTrue
    }
    It 'draws the Overview map grouped and the full-page map from the worker, in slices: 99 % under 50 ms (full garbage collections counted apart)' {
        $script:WinR.OverviewDrawn | Should -BeTrue
        $script:WinR.OverviewGroups | Should -BeGreaterThan 0
        $script:WinR.Worker | Should -BeTrue
        $script:WinR.Total | Should -BeGreaterThan 200
        $script:WinR.PageGroups | Should -BeGreaterThan 0
        $script:WinR.P99Ms | Should -BeLessThan 50
        # A single tick can be stretched by the machine (a loaded full test run measured 54 ms once); it stays far from a freeze.
        $script:WinR.MaxSliceMs | Should -BeLessThan 100
        $script:WinR.PageSwitchMs | Should -BeLessThan 150
        $script:WinR.PanMs | Should -BeLessThan 5
        $script:WinR.Mini | Should -Be 'Visible'
        $script:WinR.Replay | Should -BeTrue
        $script:WinR.Export | Should -BeTrue
        Write-Host ('    window: page switch {0} ms, map ticks {4} (95th percentile {5} ms, worst {1} ms; ticks with a full .NET garbage collection, counted apart: [{6}]), layout {2} ms (worker), pan {3:0.00} ms' -f $script:WinR.PageSwitchMs, $script:WinR.MaxSliceMs, $script:WinR.LayoutMs, $script:WinR.PanMs, $script:WinR.Ticks, $script:WinR.P95Ms, $script:WinR.GcTicks)
    }
    It 'zooms with Ctrl+plus and fits again with Ctrl+0' { $script:WinR.ZoomIn | Should -BeTrue; $script:WinR.FitBack | Should -BeTrue }
    It 'moves between nodes with the arrow keys, opens with Enter, and Alt+Left returns to the previous object' {
        $script:WinR.Moved | Should -BeTrue
        $script:WinR.RingShown | Should -Be 'Visible'
        $script:WinR.PaneKind | Should -Be 'Entity'
        $script:WinR.Second | Should -BeTrue
        $script:WinR.BackToFirst | Should -BeTrue
    }
    It 'expands a group with Enter and keeps the focus inside it' {
        $script:WinR.GroupsAfterExpand | Should -Be ($script:WinR.PageGroups - 1)
        $script:WinR.FocusInGroup | Should -BeTrue
    }
    It 'clears the map filters with Esc' { $script:WinR.ProblemsFiltered | Should -BeTrue; $script:WinR.EscCleared | Should -BeTrue }
    It 'offers the map commands in the palette' { foreach ($c in 'cmd:mapfit', 'cmd:mapproblems', 'cmd:mapreplay', 'cmd:mapexport') { $script:WinR.PaletteMap | Should -Match ([regex]::Escape($c)) } }
    It 'exports the whole map as a PNG into the run folder under the output folder only' {
        $script:WinR.ExportPath | Should -Match '\\out\\large-run\\discovery-map-\d{8}-\d{6}\.png$'
        $script:WinR.ExportBytes | Should -BeGreaterThan 10000
    }
    It 'keeps the tree as the text alternative' { $script:WinR.TreeVisible | Should -BeTrue; $script:WinR.PaneAfterTree | Should -Be 'Node' }
}
