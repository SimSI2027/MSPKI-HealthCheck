# Static checks for the hard rules in CLAUDE.md: parses in Windows PowerShell 5.1, read-only, AV/EDR-safe
# patterns, naming, and no real environment names in the public repository.

BeforeDiscovery {
    $repo = Split-Path -Parent $PSScriptRoot
    $script:codeFiles = @(Get-ChildItem -LiteralPath (Join-Path $repo 'src') -Recurse -File |
        Where-Object { @('.ps1', '.psm1', '.psd1') -contains $_.Extension } | ForEach-Object { @{ Path = $_.FullName; Name = $_.Name } })
    $script:codeFiles += @{ Path = (Join-Path $repo 'Invoke-MspkiHealthCheck.ps1'); Name = 'Invoke-MspkiHealthCheck.ps1' }
    $script:codeFiles += @{ Path = (Join-Path $repo 'Start-MspkiHealthCheckGui.ps1'); Name = 'Start-MspkiHealthCheckGui.ps1' }
    $script:codeFiles += @{ Path = (Join-Path $repo 'demo\Invoke-MspkiDemo.ps1'); Name = 'Invoke-MspkiDemo.ps1' }
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    function Get-CodeText {
        # Source text without comments, so that comments may name what the code avoids.
        param([string]$Path)
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        return (@($tokens | Where-Object { $_.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment } |
            ForEach-Object { $_.Text }) -join ' ')
    }

    $script:forbidden = [ordered]@{
        'Invoke-Expression'            = '(?i)Invoke-Expression|\biex\b'
        # Only "Add-Type -AssemblyName <in-box WPF assembly>" is allowed (CLAUDE.md rule 6), plus System.Web.Extensions in JsonReader.ps1
        # (handled in the test below); -TypeDefinition / -MemberDefinition are not.
        'Add-Type'                     = '(?i)Add-Type(?!\s+-AssemblyName\s+(PresentationFramework|PresentationCore|WindowsBase)\b)'
        'encoded command'              = '(?i)-EncodedCommand|\s-enc\s|\s-e\s'
        'Base64 decoding'              = '(?i)FromBase64'
        'execution policy'             = '(?i)ExecutionPolicy'
        'hidden window'                = '(?i)WindowStyle|CreateNoWindow'
        'download'                     = '(?i)DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient|Start-BitsTransfer'
        'process start'                = '(?i)Start-Process|Diagnostics\.Process|ProcessStartInfo'
        'certutil'                     = '(?i)certutil'
        'private reflection'           = '(?i)BindingFlags|NonPublic|GetField\(|InvokeMember'
        'CA admin / enrollment COM'    = '(?i)CertificateAuthority\.Admin|ICertAdmin|CX509Enrollment|CertificateAuthority\.Request.{0,40}Submit|\.Submit\('
        'AD writes'                    = '(?i)\.CommitChanges\(|\.SetInfo\(|\.Put\(|\.PutEx\(|DeleteTree|\.Rename\(|\.MoveTo\('
        'registry writes'              = '(?i)Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Rename-ItemProperty|SetValue\(|CreateSubKey|DeleteSubKey|DeleteValue'
        'service changes'              = '(?i)(Start|Stop|Restart|Set|New|Remove|Suspend|Resume)-Service|ServiceController'
        'credentials to mscep_admin'   = '(?i)mscep_admin'
        'default credentials'          = '(?i)UseDefaultCredentials\s*=\s*\$true|DefaultNetworkCredentials'
        'PS7-only -Parallel'           = '(?i)-Parallel\b'
        'private keys'                 = '(?i)PrivateKey|ExportPkcs12|\.Export\('
    }
    $script:writePattern = '(?i)WriteAllText|AppendAllText|WriteAllBytes|WriteAllLines|Set-Content|Add-Content|Out-File|New-Item|CreateDirectory|Export-Csv|Export-Clixml|StreamWriter|FileStream|Copy-Item|Move-Item|Rename-Item|Remove-Item|Clear-Content'
    # GuiSnapshot.ps1 writes the developer snapshots (PNG) and only after Test-MspkiGuiSnapshotFolder accepted a folder inside out\ (tests\Gui.Tests.ps1).
    $script:writeAllowed = @('OutputFolder.ps1', 'GuiSnapshot.ps1')
}

Describe 'Code file <Name>' -ForEach $script:codeFiles {
    It 'parses without errors in Windows PowerShell 5.1' {
        $PSVersionTable.PSEdition | Should -Be 'Desktop'
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0 -Because (@($errors | ForEach-Object { $_.Message }) -join '; ')
    }

    It 'uses no forbidden pattern' {
        $text = Get-CodeText -Path $Path
        foreach ($k in $script:forbidden.Keys) {
            # Base64 DATA (certificates/CRLs from CA properties) may be decoded in exactly one file (CLAUDE.md rule 6).
            if ($k -eq 'Base64 decoding' -and $Name -eq 'BinaryData.ps1') { continue }
            # The NDES request table is the one place that may name the admin path (anonymous GET only; see tests/Ndes.Tests.ps1).
            if ($k -eq 'credentials to mscep_admin' -and $Name -eq 'NdesProbe.ps1') { continue }
            $t = $text
            # The JSON reader may load the in-box System.Web.Extensions assembly (JavaScriptSerializer); no other file may.
            if ($k -eq 'Add-Type' -and $Name -eq 'JsonReader.ps1') { $t = $t -replace '(?i)Add-Type\s+-AssemblyName\s+System\.Web\.Extensions\b', '' }
            if ($k -eq 'Add-Type' -and $Name -ne 'JsonReader.ps1') { $t | Should -Not -Match '(?i)System\.Web\.Extensions' }
            $t | Should -Not -Match $script:forbidden[$k] -Because ('{0} is not allowed (CLAUDE.md hard rules)' -f $k)
        }
    }

    It 'writes files only through the output-folder guard' {
        if ($script:writeAllowed -notcontains $Name) {
            Get-CodeText -Path $Path | Should -Not -Match $script:writePattern
        }
    }

    It 'never loads anything from ref/' {
        Get-CodeText -Path $Path | Should -Not -Match '(?i)[''"\\/]ref[\\/]'
    }
}

Describe 'Function naming and help' {
    It 'every function uses an approved verb and the Mspki noun prefix' {
        $verbs = @(Get-Verb | ForEach-Object { $_.Verb })
        $files = Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -Filter '*.ps1' -File
        foreach ($f in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
            foreach ($d in $defs) {
                $parts = $d.Name -split '-', 2
                $verbs | Should -Contain $parts[0] -Because ('{0} in {1}' -f $d.Name, $f.Name)
                $parts[1] | Should -BeLike 'Mspki*' -Because ('{0} in {1}' -f $d.Name, $f.Name)
            }
        }
    }

    It 'exports the manifest functions with comment-based help' {
        $m = Get-Module MspkiHealthCheck
        $data = Import-PowerShellDataFile -Path $script:ModulePath
        @($m.ExportedFunctions.Keys | Sort-Object) | Should -Be @($data.FunctionsToExport | Sort-Object)
        foreach ($fn in $data.FunctionsToExport) {
            $h = Get-Help $fn
            [string]$h.Synopsis | Should -Not -BeNullOrEmpty
            [string]$h.Synopsis | Should -Not -BeLike "*$fn*[[]*"
        }
    }

    It 'keeps the manifest version and the tool version in step' {
        $data = Import-PowerShellDataFile -Path $script:ModulePath
        InModuleScope MspkiHealthCheck -Parameters @{ V = $data.ModuleVersion } { param($V) $script:MspkiToolVersion | Should -Be $V }
    }
}

Describe 'Public repository hygiene' {
    BeforeAll {
        $skip = '(?i)[\\/](\.git|ref|out)([\\/]|$)'
        $ext = @('.ps1', '.psm1', '.psd1', '.md', '.json', '.txt', '.xml', '.xaml', '.html', '.css', '.csv', '.yml', '.yaml', '')
        $script:textFiles = @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File -Force |
            Where-Object { $_.FullName -notmatch $skip -and ($ext -contains $_.Extension -or $_.Name -eq '.gitignore') })
        $script:hostCi = '(?i)(?<![\w$.\\-])((?:[a-z0-9-]+\.)+(?:com|net|org|local|lan|corp|internal|intra|gov|edu|io|uk|de|nl|ie|eu|fr|ch|be|au|info|biz|cloud|online|tech|test|lab))\b'
        $script:hostLc = '(?-i)(?<![\w$.\\-])((?:[a-z0-9-]+\.)+(?:domain|ad|ca|co|us|int|home|site|priv|private))\b'
        $script:hostAllowed = '(?i)^((?:[a-z0-9-]+\.)*example\.test|system\.(?:[a-z]+\.)*(?:io|net)|asp\.net|learn\.microsoft\.com|docs\.microsoft\.com|github\.com|claude\.com|anthropic\.com|www\.w3\.org|schemas\.xmlsoap\.org|schemas\.microsoft\.com)$'
        $script:ipv4 = '(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])'
        $script:ipAllowed = '^(127\.|0\.0\.0\.0$|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2\.5\.29\.|2\.5\.4\.)'
        $script:email = '(?i)[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+'
        $script:emailAllowed = '(?i)(@(?:[a-z0-9-]+\.)*example\.test|^noreply@anthropic\.com|@users\.noreply\.github\.com)$'
    }

    It 'finds text files to scan' { $script:textFiles.Count | Should -BeGreaterThan 10 }

    It 'contains no real host names, domains, IP addresses or e-mail addresses' {
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in $script:textFiles) {
            $text = [System.IO.File]::ReadAllText($f.FullName)
            foreach ($rx in @($script:hostCi, $script:hostLc)) {
                foreach ($m in [regex]::Matches($text, $rx)) {
                    if ($m.Groups[1].Value -notmatch $script:hostAllowed) { [void]$hits.Add(('{0}: {1}' -f $f.Name, $m.Groups[1].Value)) }
                }
            }
            foreach ($m in [regex]::Matches($text, $script:ipv4)) {
                if ($m.Value -notmatch $script:ipAllowed) { [void]$hits.Add(('{0}: {1}' -f $f.Name, $m.Value)) }
            }
            foreach ($m in [regex]::Matches($text, $script:email)) {
                if ($m.Value -notmatch $script:emailAllowed) { [void]$hits.Add(('{0}: {1}' -f $f.Name, $m.Value)) }
            }
        }
        $hits.Count | Should -Be 0 -Because ($hits -join '; ')
    }

    It 'ignores ref/ and out/ in git' {
        $gi = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.gitignore')
        $gi | Should -Contain 'ref/'
        $gi | Should -Contain 'out/'
    }

    It 'detects a planted host name (self-test of the scanner)' {
        # Built by concatenation so that this file itself stays clean for the scan above.
        $sample = 'see pki01.sample' + '.local and 10.20.' + '30.40 and admin@sample' + '.org but not ca.corp.example.test'
        @([regex]::Matches($sample, $script:hostCi) | Where-Object { $_.Groups[1].Value -notmatch $script:hostAllowed }).Count | Should -Be 2
        @([regex]::Matches($sample, $script:ipv4) | Where-Object { $_.Value -notmatch $script:ipAllowed }).Count | Should -Be 1
    }
}
