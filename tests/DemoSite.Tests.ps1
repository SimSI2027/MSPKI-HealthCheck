# The demo site (docs/DEMO-SITE.md, ROADMAP DS4-DS6): the static shell, the design tokens generated from the window's theme, and the
# scenario view model computed by the window's own helpers. Builds two scenarios under out\ only (developer tools in tools\dev).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Site = Join-Path $script:RepoRoot 'site'
    $script:Dev = Join-Path $script:RepoRoot 'tools\dev\demo-site'
    $script:Data = Join-Path $script:RepoRoot 'out\test-demo-site-data'
    $script:Built = Join-Path $script:RepoRoot 'out\test-demo-site'
    & powershell -NoProfile -File (Join-Path $script:Dev 'Invoke-MspkiScenario.ps1') -Scenario 'baseline,healthy' -Output $script:Data -Commit 'test' | Out-Null
    & powershell -NoProfile -File (Join-Path $script:Dev 'Build-MspkiDemoSite.ps1') -SkipGenerate -DataRoot $script:Data -Output $script:Built | Out-Null
    $script:Gzip = {
        param([byte[]]$Bytes)
        $ms = New-Object System.IO.MemoryStream
        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionLevel]::Optimal)
        $gz.Write($Bytes, 0, $Bytes.Length); $gz.Dispose()
        return $ms.ToArray().Length
    }
}

Describe 'DS4: the site shell and its design tokens' {
    It 'generates tokens.css from the window''s palettes and type ramp, and the committed file has not drifted' {
        $tmp = Join-Path $TestDrive 'tokens.css'
        & powershell -NoProfile -File (Join-Path $script:Dev 'Build-MspkiDemoSite.ps1') -TokensOnly -TokensPath $tmp | Out-Null
        [System.IO.File]::ReadAllText($tmp) | Should -BeExactly ([System.IO.File]::ReadAllText((Join-Path $script:Site 'assets\tokens.css')))
        $css = [System.IO.File]::ReadAllText($tmp)
        foreach ($k in 'B.Accent', 'B.Card', 'B.Text', 'B.BadFore', 'B.GoodData', 'B.FocusRing') {
            $name = '--' + (($k -replace '^B\.', 'c-') -creplace '([a-z0-9])([A-Z])', '$1-$2').ToLowerInvariant()
            $light = [regex]::Match([System.IO.File]::ReadAllText((Join-Path $script:RepoRoot 'src\Gui\Palette.Light.xaml')), ('x:Key="{0}" Color="(#[0-9A-Fa-f]+)"' -f [regex]::Escape($k))).Groups[1].Value
            $css | Should -Match ([regex]::Escape(('{0}: {1};' -f $name, $light.ToUpperInvariant())))
        }
        $css | Should -Match 'prefers-color-scheme: dark'
        $css | Should -Match ':root\[data-theme="dark"\]'
    }

    It 'is plain HTML, CSS and JavaScript with a strict Content-Security-Policy, no inline code and no third-party request' {
        $html = [System.IO.File]::ReadAllText((Join-Path $script:Site 'index.html'))
        $html | Should -Match "Content-Security-Policy\"" content=\""default-src 'self'"
        $html | Should -Not -Match "unsafe-inline|unsafe-eval"
        $html | Should -Not -Match '<script(?![^>]*\bsrc=)[^>]*>'
        $html | Should -Not -Match '<style|\sstyle=|\son[a-z]+='
        foreach ($f in Get-ChildItem -LiteralPath $script:Site -Recurse -File | Where-Object { $_.Extension -in @('.html', '.css', '.js') -and $_.FullName -notlike '*\world\*' }) {
            $t = [System.IO.File]::ReadAllText($f.FullName)
            $urls = @([regex]::Matches($t, '(?i)\b(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}[^\s''"<>)]*') | ForEach-Object { $_.Value } | Where-Object { $_ -notmatch '^http://www\.w3\.org/2000/svg$' })
            $urls | Should -BeNullOrEmpty -Because $f.Name
            $t | Should -Not -Match '(?i)innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|localStorage|document\.cookie' -Because $f.Name
        }
    }

    It 'shows the simulated-environment banner with the version and commit on every page' {
        $html = [System.IO.File]::ReadAllText((Join-Path $script:Site 'index.html'))
        $html | Should -Match 'Simulated environment\.'
        $html | Should -Match 'Alcyone Orbital Systems is fictional'
        $html | Should -Match 'Nothing here touched a real network'
        $html | Should -Match 'id="sim-version"'
        $html | Should -Match 'id="sim-commit"'
        $idx = Get-Content -Raw -LiteralPath (Join-Path $script:Built 'data\scenarios.json') | ConvertFrom-Json
        $idx.commit | Should -Be 'test'
        $idx.version | Should -Not -BeNullOrEmpty
        $js = [System.IO.File]::ReadAllText((Join-Path $script:Site 'assets\app.js'))
        $js | Should -Match "getElementById\('sim-version'\)\.textContent = site\.version"
    }

    It 'parses as JavaScript (node --check, when node is installed)' -Skip:(-not (Get-Command node -ErrorAction SilentlyContinue)) {
        & node --check (Join-Path $script:Site 'assets\app.js') 2>&1 | Out-String | Should -BeNullOrEmpty
        $LASTEXITCODE | Should -Be 0
    }
}

Describe 'DS7: the Pages workflow' -Skip:(-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) '.github\workflows\pages.yml'))) {
    It 'pins every action to a full commit SHA, reads only by default, and gives Pages rights to the deploy job alone' {
        $y = [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot '.github\workflows\pages.yml'))
        $uses = @([regex]::Matches($y, '(?m)^\s*uses:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value })
        $uses.Count | Should -BeGreaterThan 3
        foreach ($u in $uses) { $u | Should -Match '^actions/[a-z-]+@[0-9a-f]{40}$' -Because $u }
        $y | Should -Match '(?m)^permissions:\s*\r?\n\s+contents: read\s*$'
        @([regex]::Matches($y, '(?m)^\s+pages: write')).Count | Should -Be 1
        @([regex]::Matches($y, '(?m)^\s+id-token: write')).Count | Should -Be 1
        $y | Should -Match 'shell: powershell'
        $y | Should -Match 'persist-credentials: false'
        $y | Should -Not -Match '(?i)secrets\.|pull_request_target'
    }
    It 'never commits generated site data' {
        [System.IO.File]::ReadAllText((Join-Path $script:RepoRoot '.gitignore')) | Should -Match '(?m)^site/data/\s*$'
        if (Get-Command git -ErrorAction SilentlyContinue) { @(& git -C $script:RepoRoot ls-files 'site/data' 'out') | Should -BeNullOrEmpty }
    }
}

Describe 'DS5: the scenario view is what the window shows for the same results' {
    BeforeAll {
        Import-Module $script:ModulePath -Force
        foreach ($n in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1', 'GuiMission.ps1', 'GuiMap.ps1') { . (Join-Path $script:RepoRoot ('src\Gui\' + $n)) }
    }
    It 'has the same score, areas, actions and headline as the window''s helpers, for <Id>' -ForEach @(@{ Id = 'baseline' }, @{ Id = 'healthy' }) {
        $view = Get-Content -Raw -LiteralPath (Join-Path $script:Built "data\$Id\view.json") | ConvertFrom-Json
        $data = Read-MspkiGuiResults -Path (Join-Path $script:Data "$Id\results.json")
        $f = @($data.Findings)
        $hasCa = (@($data.Inventory.EnterpriseCAs | Where-Object { $null -ne $_ }).Count -gt 0)
        $score = Get-MspkiGuiHealthScore -Findings $f -Completed ([bool]$data.RunInfo.Completed) -HasCa $hasCa
        $actions = Get-MspkiGuiNextAction -Findings $f -Max 1000
        [string]$view.score.text | Should -Be ([string]$score.OverallText)
        $view.score.band | Should -Be $score.Band
        @($view.score.areas).Count | Should -Be @($score.Areas).Count
        for ($i = 0; $i -lt @($score.Areas).Count; $i++) { $view.score.areas[$i].text | Should -Be ([string]@($score.Areas)[$i].ScoreText); $view.score.areas[$i].name | Should -Be @($score.Areas)[$i].Name }
        $view.actions.total | Should -Be $actions.Total
        @($view.actions.items | ForEach-Object { $_.title }) | Should -Be @(@($actions.Items) | ForEach-Object { $_.Title })
        @($view.findings).Count | Should -Be $f.Count
        foreach ($x in $f) { $view.details.($x.Id) | Should -Not -BeNullOrEmpty -Because $x.Id }
        $s = Get-MspkiGuiSummary -RunInfo $data.RunInfo -Inventory $data.Inventory -Findings $f -ExitCode $data.ExitCode
        $view.headline | Should -Be (Get-MspkiGuiHeadline -Health $s.Health -Actions $actions -Score $score -Completed ([bool]$data.RunInfo.Completed) -HasCa $hasCa -AsOf '')
    }

    It 'carries the walkthrough (causes, read-only checks, fix, sources) for non-passing findings, and a laid-out map with its replay' {
        $view = Get-Content -Raw -LiteralPath (Join-Path $script:Built 'data\baseline\view.json') | ConvertFrom-Json
        $warn = @($view.findings | Where-Object { $_.status -eq 'Warning' })[0]
        $d = $view.details.($warn.id)
        @($d.diag.causes).Count | Should -BeGreaterThan 0
        @($d.diag.causes | Where-Object { @($_.checks).Count -gt 0 }).Count | Should -BeGreaterThan 0
        @($view.map.nodes).Count | Should -BeGreaterThan 5
        foreach ($n in $view.map.nodes) { [int]$n.x | Should -BeGreaterOrEqual 0; [int]$n.y | Should -BeGreaterOrEqual 0 }
        @($view.replay | Where-Object { $_.k -eq 'e' }).Count | Should -BeGreaterThan 10
        $healthy = Get-Content -Raw -LiteralPath (Join-Path $script:Built 'data\healthy\view.json') | ConvertFrom-Json
        $healthy.actions.total | Should -Be 0
    }

    It 'loads fast: the first view under 150 KB compressed, each scenario''s data under 60 KB compressed' {
        $first = 0
        foreach ($f in 'index.html', 'assets\app.css', 'assets\tokens.css', 'assets\app.js', 'assets\favicon.svg', 'data\scenarios.json') { $first += & $script:Gzip ([System.IO.File]::ReadAllBytes((Join-Path $script:Built $f))) }
        $first | Should -BeLessThan 150KB
        foreach ($id in 'baseline', 'healthy') { (& $script:Gzip ([System.IO.File]::ReadAllBytes((Join-Path $script:Built "data\$id\view.json")))) | Should -BeLessThan 60KB -Because $id }
    }
}
