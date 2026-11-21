BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
}

Describe 'Output folder guard' {
    It 'creates a timestamped folder and writes only inside it' {
        $root = Join-Path $TestDrive 'out'
        InModuleScope MspkiHealthCheck -Parameters @{ Root = $root; Outside = (Join-Path $TestDrive 'outside.txt') } {
            param($Root, $Outside)
            $now = [datetime]'2026-01-02T03:04:05'
            $a = New-MspkiOutputFolder -Root $Root -Now $now
            (Split-Path -Leaf $a) | Should -Be '20260102-030405'
            $b = New-MspkiOutputFolder -Root $Root -Now $now
            (Split-Path -Leaf $b) | Should -Be '20260102-030405-2'
            Write-MspkiOutputFile -Path (Join-Path $b 'x.txt') -Content 'ok'
            Test-Path -LiteralPath (Join-Path $b 'x.txt') | Should -BeTrue
            { Write-MspkiOutputFile -Path $Outside -Content 'no' } | Should -Throw '*outside the run output folder*'
            { Write-MspkiOutputFile -Path (Join-Path $b '..\escape.txt') -Content 'no' } | Should -Throw
            Test-Path -LiteralPath $Outside | Should -BeFalse
        }
    }
}

Describe 'Export-MspkiJson' {
    It 'writes valid UTF-8 JSON without BOM, with summary, run info and string timestamps' {
        $dir = Join-Path $TestDrive 'json'
        $null = New-Item -ItemType Directory -Path $dir
        InModuleScope MspkiHealthCheck -Parameters @{ Dir = $dir } {
            param($Dir)
            Set-MspkiOutputFolder -Path $Dir
            $run = Initialize-MspkiRun -Parameters @{ OutputPath = $Dir }
            $f1 = New-MspkiFinding -Category CA -Target 'Example CA' -Status Information -StatusCode OK -Sources @('AD:EnrollmentServices') `
                -Confidence Referenced -Message 'one source' -Evidence @('single line')
            $f2 = New-MspkiFinding -Category CRL -Target 'Example CA' -Status Warning -StatusCode OBJECT_EXPIRING -Sources @('a', 'b') -Message 'two'
            Complete-MspkiRun
            $p = Join-Path $Dir 'results.json'
            Export-MspkiJson -Path $p -RunInfo ([pscustomobject]$run) -Inventory ([pscustomobject]@{ X = 1 }) -Findings @($f1, $f2) -ExitCode 3 | Out-Null
            $bytes = [System.IO.File]::ReadAllBytes($p)
            ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB) | Should -BeFalse
            $j = [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
            $j.Schema | Should -Be 'mspki-healthcheck/1'
            $j.ExitCode | Should -Be 3
            $j.Summary.Total | Should -Be 2
            $j.Summary.ByStatus.Warning | Should -Be 1
            $j.Summary.ByConfidence.Referenced | Should -Be 1
            $j.RunInfo.Completed | Should -BeTrue
            $j.RunInfo.StartedUtc | Should -Match '^\d{4}-\d\d-\d\dT'
            $j.Findings.Count | Should -Be 2
            @($j.Findings[0].Sources).Count | Should -Be 1
            @($j.Findings[0].Evidence).Count | Should -Be 1
            $j.Findings[0].Timestamp | Should -BeOfType [string]
            [System.Text.Encoding]::UTF8.GetString($bytes) | Should -Not -Match '\\/Date\('
        }
    }
}

Describe 'Start-MspkiHealthCheck end to end (local machine, -SkipNetwork)' {
    It 'writes results.json and run.log and returns a consistent exit code' {
        $out = Join-Path $TestDrive 'run'
        $r = Start-MspkiHealthCheck -OutputPath $out -TimeoutSeconds 2 -SkipNetwork
        Test-Path -LiteralPath $r.ResultsPath | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $r.OutputFolder 'run.log') | Should -BeTrue
        $r.OutputFolder | Should -BeLike ((Join-Path $out '*'))
        $j = Get-Content -LiteralPath $r.ResultsPath -Raw | ConvertFrom-Json
        $j.ExitCode | Should -Be $r.ExitCode
        $r.ExitCode | Should -BeIn @(0, 2, 3, 4, 5, 6)
        $j.RunInfo.Completed | Should -BeTrue
        @($j.RunInfo.Methods).Count | Should -BeGreaterThan 0
        foreach ($f in $j.Findings) {
            @($f.Sources).Count | Should -BeGreaterThan 0
            $f.Confidence | Should -BeIn @('Confirmed', 'Referenced', 'Inferred', 'Unknown')
        }
    }
}

Describe 'Invoke-MspkiHealthCheck.ps1 entry point' {
    It 'runs in Windows PowerShell 5.1 and exits with the code stored in results.json' {
        $out = Join-Path $TestDrive 'entry'
        $entry = Join-Path $script:RepoRoot 'Invoke-MspkiHealthCheck.ps1'
        $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $null = & $ps -NoProfile -NonInteractive -File $entry -OutputPath $out -SkipNetwork -TimeoutSeconds 2
        $code = $LASTEXITCODE
        $json = @(Get-ChildItem -LiteralPath $out -Recurse -Filter 'results.json')
        $json.Count | Should -Be 1
        $j = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json
        $code | Should -Be $j.ExitCode
        $j.RunInfo.PSEdition | Should -Be 'Desktop'
    }
}
