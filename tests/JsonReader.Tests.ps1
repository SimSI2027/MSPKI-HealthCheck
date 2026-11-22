# Tests for the size-unlimited JSON reader (src/Model/JsonReader.ps1): same shape as ConvertFrom-Json, and a results.json of
# 10 MB or more opens in the GUI model, in the report re-export and in the plain reader. example.test data only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    . (Join-Path $script:RepoRoot 'src\Gui\GuiModel.ps1')

    # One big results.json, written by the real writer (Export-MspkiJson) so the test reads exactly what a run writes.
    $script:bigDir = Join-Path $TestDrive 'big'
    $null = New-Item -ItemType Directory -Path $script:bigDir
    $script:bigPath = Join-Path $script:bigDir 'results.json'
    InModuleScope MspkiHealthCheck -Parameters @{ Dir = $script:bigDir; P = $script:bigPath } {
        param($Dir, $P)
        Set-MspkiOutputFolder -Path $Dir
        $run = Initialize-MspkiRun -Parameters @{ OutputPath = $Dir }
        $pad = 'x' * 4000
        $findings = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt 600; $i++) {
            $findings.Add((New-MspkiFinding -Category CDP -Target ('http://pki.example.test/crl/{0}.crl' -f $i) -Status Warning `
                -StatusCode OBJECT_EXPIRING -Sources @('Certificate:CDP', 'HTTP') -Confidence Confirmed -Message ('finding {0}' -f $i) `
                -Evidence @(('a{0} {1}' -f $i, $pad), ('b{0} {1}' -f $i, $pad), ('c{0} {1}' -f $i, $pad))))
        }
        $entities = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt 3000; $i++) {
            $entities.Add([pscustomobject][ordered]@{ Id = ('host:h{0}.corp.example.test' -f $i); Type = 'Host'; Name = ('h{0}.corp.example.test' -f $i)
                Properties = [pscustomobject][ordered]@{ Addresses = @('192.0.2.1'); Roles = @('CDP'); Note = ('n' * 200) } })
        }
        $graph = [pscustomobject][ordered]@{ SchemaVersion = 2; Counts = [pscustomobject]@{ Entities = $entities.Count }; Entities = $entities.ToArray(); Observations = @(); Relations = @() }
        Complete-MspkiRun
        Export-MspkiJson -Path $P -RunInfo ([pscustomobject]$run) -Inventory ([pscustomobject]@{ Forest = 'example.test' }) -Findings $findings.ToArray() -ExitCode 3 -Graph $graph | Out-Null
    }
}

Describe 'ConvertFrom-MspkiJson' {
    It 'gives the same shape as ConvertFrom-Json for small documents' {
        $text = '{"A":1,"B":"tÃ©st","C":[],"D":[{"E":true}],"F":null,"G":[[1,2],[3]],"H":{},"I":2.5,"J":["one"]}'
        $mine = ConvertFrom-MspkiJson -Text $text
        $theirs = $text | ConvertFrom-Json
        ($mine | ConvertTo-Json -Depth 10 -Compress) | Should -Be ($theirs | ConvertTo-Json -Depth 10 -Compress)
        $mine.A | Should -Be 1
        $mine.B | Should -Be 'tÃ©st'
        @($mine.C).Count | Should -Be 0
        $mine.D[0].E | Should -BeTrue
        $mine.D[0] | Should -BeOfType [pscustomobject]
        $mine.F | Should -BeNullOrEmpty
        $mine.G[0].Count | Should -Be 2
        @($mine.J).Count | Should -Be 1
        $mine.PSObject.Properties.Name[0] | Should -Be 'A'
    }

    It 'returns a top-level array as an array and throws on invalid JSON' {
        $a = ConvertFrom-MspkiJson -Text '[{"X":1},{"X":2}]'
        $a.Count | Should -Be 2
        $a[1].X | Should -Be 2
        { ConvertFrom-MspkiJson -Text '{ not json' } | Should -Throw
    }
}

Describe 'A results.json of 10 MB or more' {
    It 'is at least 10 MB' {
        (Get-Item -LiteralPath $script:bigPath).Length | Should -BeGreaterOrEqual 10MB
    }

    It 'opens with the reader and keeps every finding and entity' {
        $j = Read-MspkiResultsJson -Path $script:bigPath
        $j.Schema | Should -Be 'mspki-healthcheck/2'
        @($j.Findings).Count | Should -Be 600
        @($j.Graph.Entities).Count | Should -Be 3000
        @($j.Findings[599].Evidence).Count | Should -Be 3
        $j.Graph.Entities[0].Properties.Addresses[0] | Should -Be '192.0.2.1'
    }

    It 'opens in the GUI model' {
        $d = Read-MspkiGuiResults -Path $script:bigPath
        @($d.Findings).Count | Should -Be 600
        $d.SchemaVersion | Should -Be 2
        @($d.Graph.Entities).Count | Should -Be 3000
    }

    It 'can be re-exported to report.html and findings.csv' {
        $out = Join-Path $TestDrive 'reexport'
        $r = Export-MspkiReportFromResults -ResultsPath $script:bigPath -OutputFolder $out
        $r.Findings | Should -Be 600
        Test-Path -LiteralPath $r.HtmlPath | Should -BeTrue
        Test-Path -LiteralPath $r.CsvPath | Should -BeTrue
    }
}
