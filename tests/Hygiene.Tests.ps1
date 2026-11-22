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
        $joined = (@($tokens | Where-Object { $_.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment } |
            ForEach-Object { $_.Text }) -join ' ')
        # Tokens are joined with spaces ('$de . CommitChanges ( )'); put method calls back together so that patterns such as
        # '\.CommitChanges\(' can match (audit 2 M14: they never did).
        $joined = [regex]::Replace($joined, '\s*\.\s*(?=[A-Za-z_])', '.')
        $joined = [regex]::Replace($joined, '([A-Za-z0-9_])\s+\(', '$1(')
        return $joined
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
        # Audit 2 M10: no key may ever be persisted, and certificate bytes are loaded only by src/Model/Certificate.ps1, which checks
        # the content type first and refuses PKCS #12 / PFX (the TLS probe may copy the server certificate it was handed).
        'key persistence'              = '(?i)PersistKeySet|MachineKeySet|UserKeySet'
        'certificate loading'          = '(?i)\.Import\(|X509Certificate2\s*\(|X509Certificate2\s*\]\s*::\s*(?!GetCertContentType\b)'
    }
    $script:writePattern = '(?i)WriteAllText|AppendAllText|WriteAllBytes|WriteAllLines|Set-Content|Add-Content|Out-File|New-Item|CreateDirectory|Export-Csv|Export-Clixml|StreamWriter|FileStream|Copy-Item|Move-Item|Rename-Item|Remove-Item|Clear-Content|File\s*\]\s*::\s*(Create|CreateText|OpenWrite|AppendText|Replace|Move|Copy|Delete|SetAttributes)|OpenWrite|\.Save\(|SaveAs\(|Tee-Object'
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
            if ($k -eq 'certificate loading' -and $Name -eq 'Certificate.ps1') { continue }
            if ($k -eq 'certificate loading' -and $Name -eq 'WebProbes.ps1') {
                # Only the copy of the X509Certificate that the TLS callback receives (never bytes).
                ($text -replace '(?i)X509Certificate2\s*\(\s*\$cert\s*\)', '') | Should -Not -Match $script:forbidden[$k]
                continue
            }
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

Context 'Audit 2 M14: more of the hard rules are enforced by the hygiene tests' {
    BeforeAll {
        # The same patterns as in the code-file test above, kept here so that a self-test can show that they match what they should.
        $script:storeWrite = '(?i)ReadWrite\b|MaxAllowed|\$\w*store\w*\.(Add|Remove|AddRange|RemoveRange)\('
        $script:adsiWrite = '(?i)\.DeleteObject\(|\.InvokeSet\(|\.Invoke\(\s*[''"]|SetPassword|ChangePassword'
        $script:itemInvoke = '(?i)Invoke-Item'
        $script:invokeItemAllowed = @('GuiApp.ps1', 'Invoke-MspkiHealthCheck.ps1', 'Invoke-MspkiDemo.ps1')
    }

    It 'the patterns match what they are meant to catch (self-test) and not ReadWriteTimeout' {
        '$s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)' | Should -Match $script:storeWrite
        '$store = New-Object System.Security.Cryptography.X509Certificates.X509Store; $store.Add($c)' | Should -Match $script:storeWrite
        '$req.ReadWriteTimeout = 5' | Should -Not -Match $script:storeWrite
        '$de.Invoke("SetPassword", $x)' | Should -Match $script:adsiWrite
        '$de.DeleteObject(0)' | Should -Match $script:adsiWrite
        '$ps.Invoke()' | Should -Not -Match $script:adsiWrite
    }

    It 'the code-file scan sees method calls: the forbidden patterns match code written the way the code files write it (self-test)' {
        $f = Join-Path $TestDrive 'planted.ps1'
        [System.IO.File]::WriteAllText($f, '$de.CommitChanges(); $k.SetValue(1, 2); $c.Export(1); $x.Put("a", 1); $s.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)')
        $text = Get-CodeText -Path $f
        $text | Should -Match $script:forbidden['AD writes']
        $text | Should -Match $script:forbidden['registry writes']
        $text | Should -Match $script:forbidden['private keys']
        $text | Should -Match $script:storeWrite
    }
    It 'no code file writes to a certificate store, changes AD through ADSI methods, or starts a file with Invoke-Item unlisted' {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -File -Filter '*.ps1') +
            @(Get-Item -LiteralPath (Join-Path $script:RepoRoot 'Invoke-MspkiHealthCheck.ps1'), (Join-Path $script:RepoRoot 'Start-MspkiHealthCheckGui.ps1'), (Join-Path $script:RepoRoot 'demo\Invoke-MspkiDemo.ps1'))
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in $files) {
            $text = Get-CodeText -Path $f.FullName
            if ($text -match $script:storeWrite) { [void]$hits.Add('store write: ' + $f.Name) }
            if ($text -match $script:adsiWrite) { [void]$hits.Add('ADSI write: ' + $f.Name) }
            if ($text -match $script:itemInvoke -and $script:invokeItemAllowed -notcontains $f.Name) { [void]$hits.Add('Invoke-Item: ' + $f.Name) }
        }
        $hits.Count | Should -Be 0 -Because ($hits -join '; ')
    }

    It 'every commit message and author in the history is free of real names, and the author is the noreply identity' -Skip:(-not ((Get-Command git -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) '.git')))) {
        Push-Location $script:RepoRoot
        try {
            $log = @(& git log --all --format='%an|%ae|%cn|%ce|%s%n%b%n--END--' 2>$null)
            $authors = @(& git log --all --format='%an|%ae|%cn|%ce' 2>$null | Sort-Object -Unique)
        }
        finally { Pop-Location }
        $log.Count | Should -BeGreaterThan 10
        foreach ($a in $authors) {
            $p = $a -split '\|'
            $p[0] | Should -Be 'ED'
            $p[1] | Should -Match '@users\.noreply\.github\.com$'
        }
        $text = $log -join "`n"
        $hits = New-Object System.Collections.ArrayList
        foreach ($rx in @($script:hostCi, $script:hostLc)) {
            foreach ($m in [regex]::Matches($text, $rx)) { if ($m.Groups[1].Value -notmatch $script:hostAllowed -and $m.Groups[1].Value -notmatch '^users\.noreply\.github\.com$') { [void]$hits.Add($m.Groups[1].Value) } }
        }
        foreach ($m in [regex]::Matches($text, $script:ipv4)) { if ($m.Value -notmatch $script:ipAllowed) { [void]$hits.Add($m.Value) } }
        foreach ($m in [regex]::Matches($text, $script:email)) { if ($m.Value -notmatch $script:emailAllowed -and $m.Value -notmatch 'noreply@anthropic\.com') { [void]$hits.Add($m.Value) } }
        $hits.Count | Should -Be 0 -Because ($hits -join '; ')
    }
}
}

Describe 'Audit 2 N7: the hygiene patterns match the rules they guard' {
    BeforeAll {
        $script:certTypeRx = '(^|\.)X509Certificate2(\[\])?$'
        # Files whose functions take an already built certificate as a typed parameter. PowerShell converts a byte array or a path string to
        # [X509Certificate2] when a caller passes one, which builds a certificate without the content-type check, so a typed parameter
        # in any other file is a decision to make on purpose, not by accident.
        $script:typedCertParamFiles = @('CACertificateHealth.ps1', 'EndpointHealth.ps1', 'LocalEvidence.ps1', 'Certificate.ps1', 'CertificateTemplateInfo.ps1', 'CertificateUrls.ps1', 'Signature.ps1')

        function Get-CertificateBuildSite {
            # Every place that can turn bytes or a path into a certificate object: [X509Certificate2]::new(...) or any static member other than
            # GetCertContentType, New-Object, a cast or a typed variable, and a parameter typed [X509Certificate2].
            param([string]$Path)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
            $sites = New-Object System.Collections.ArrayList
            foreach ($n in @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $x.Static }, $true))) {
                if ($n.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and $n.Expression.TypeName.FullName -match $script:certTypeRx -and [string]$n.Member.Value -ne 'GetCertContentType') {
                    [void]$sites.Add(@{ Kind = 'static member'; Text = $n.Extent.Text })
                }
            }
            foreach ($n in @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] -and $x.GetCommandName() -eq 'New-Object' }, $true))) {
                if ($n.Extent.Text -match 'X509Certificate2(?!Collection|Ui|Extension|Enumerator)') { [void]$sites.Add(@{ Kind = 'New-Object'; Text = $n.Extent.Text }) }
            }
            foreach ($n in @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.ConvertExpressionAst] }, $true))) {
                if ($n.Type.TypeName.FullName -match $script:certTypeRx) { [void]$sites.Add(@{ Kind = 'cast'; Text = $n.Extent.Text }) }
            }
            foreach ($n in @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.ParameterAst] }, $true))) {
                foreach ($a in @($n.Attributes | Where-Object { $_ -is [System.Management.Automation.Language.TypeConstraintAst] })) {
                    if ($a.TypeName.FullName -match $script:certTypeRx) { [void]$sites.Add(@{ Kind = 'typed parameter'; Text = $n.Extent.Text }) }
                }
            }
            return @($sites)
        }

        function Get-FileRedirectionSite {
            # Every redirection of output to a file (> and >>), whatever the stream; `> $null` and merges such as 2>&1 are not files.
            param([string]$Path)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
            $sites = @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FileRedirectionAst] }, $true) |
                Where-Object { $_.Location.Extent.Text -ne '$null' } | ForEach-Object { $_.Extent.Text })
            return @($sites)
        }

        function Get-StoreOpenWithoutExistingOnly {
            # Every X509Store.Open call that does not carry OpenExistingOnly (without it, Open creates a store that does not exist: a write).
            param([string]$Path)
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
            $sites = @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and [string]$x.Member.Value -eq 'Open' -and $x.Extent.Text -match 'OpenFlags' }, $true) |
                Where-Object { $_.Extent.Text -notmatch 'OpenExistingOnly' } | ForEach-Object { $_.Extent.Text })
            return @($sites)
        }

        $script:plant = {
            param([string]$Code)
            $f = Join-Path $TestDrive ('planted{0}.ps1' -f ([guid]::NewGuid().ToString('N')))
            [System.IO.File]::WriteAllText($f, $Code)
            return $f
        }
        $script:t = 'System.Security.Cryptography.X509Certificates'
    }

    It 'sees every way of building a certificate from bytes or a path (self-test), and not the safe uses' -TestCases @(
        @{ Name = 'the .NET constructor'; Code = '$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($b)'; Hit = $true }
        @{ Name = 'New-Object with -ArgumentList'; Code = '$c = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$b)'; Hit = $true }
        @{ Name = '[X509Certificate2]::new'; Code = '$c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($b)'; Hit = $true }
        @{ Name = 'a cast from bytes'; Code = '$c = [System.Security.Cryptography.X509Certificates.X509Certificate2]$b'; Hit = $true }
        @{ Name = 'a typed variable'; Code = '[System.Security.Cryptography.X509Certificates.X509Certificate2]$c = $b'; Hit = $true }
        @{ Name = 'a parameter typed X509Certificate2 (PowerShell converts bytes and paths)'; Code = 'function Test-Mspki { param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) }'; Hit = $true }
        @{ Name = 'a static member such as Import'; Code = '$c = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromCertFile($p)'; Hit = $true }
        @{ Name = 'GetCertContentType (reads the type, builds nothing)'; Code = '$t = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($b)'; Hit = $false }
        @{ Name = 'an X509Certificate2Collection'; Code = '$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection'; Hit = $false }
        @{ Name = 'a parameter of another type'; Code = 'function Test-Mspki { param([byte[]]$Bytes) }'; Hit = $false }
    ) {
        param($Name, $Code, $Hit)
        $sites = @(Get-CertificateBuildSite -Path (& $script:plant $Code))
        if ($Hit) { $sites.Count | Should -BeGreaterThan 0 } else { $sites.Count | Should -Be 0 }
    }

    It 'the text scan for certificate loading matches [X509Certificate2]::new and other static members, not only the constructor' {
        $f = & $script:plant '$a = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($b)'
        $text = Get-CodeText -Path $f
        $text | Should -Match $script:forbidden['certificate loading']
    }

    It 'no code file builds a certificate except through src/Model/Certificate.ps1, apart from the TLS callback copy and the typed parameters of the listed files' {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -File -Filter '*.ps1') +
            @(Get-Item -LiteralPath (Join-Path $script:RepoRoot 'Invoke-MspkiHealthCheck.ps1'), (Join-Path $script:RepoRoot 'Start-MspkiHealthCheckGui.ps1'), (Join-Path $script:RepoRoot 'demo\Invoke-MspkiDemo.ps1'))
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in $files) {
            if ($f.Name -eq 'Certificate.ps1') { continue }
            foreach ($s in @(Get-CertificateBuildSite -Path $f.FullName)) {
                if ($s.Kind -eq 'typed parameter' -and $script:typedCertParamFiles -contains $f.Name) { continue }
                # The TLS probe copies the server certificate that the callback handed it (never bytes or a path).
                if ($f.Name -eq 'WebProbes.ps1' -and $s.Kind -eq 'New-Object' -and $s.Text -match 'X509Certificate2\s*\(\s*\$cert\s*\)') { continue }
                [void]$hits.Add(('{0}: {1}: {2}' -f $f.Name, $s.Kind, $s.Text))
            }
        }
        $hits.Count | Should -Be 0 -Because ($hits -join '; ')
    }

    It 'sees every way of writing a file (self-test), and not a comparison, a merge or a redirect to $null' -TestCases @(
        @{ Name = 'File.Create'; Code = '$s = [System.IO.File]::Create($p)'; Hit = $true }
        @{ Name = 'File.OpenWrite'; Code = '$s = [System.IO.File]::OpenWrite($p)'; Hit = $true }
        @{ Name = 'a Save method'; Code = '$img.Save($p)'; Hit = $true }
        @{ Name = 'Tee-Object'; Code = '$x | Tee-Object -FilePath $p'; Hit = $true }
        @{ Name = 'a redirect >'; Code = '"text" > $p'; Hit = $true }
        @{ Name = 'an append >>'; Code = '"text" >> $p'; Hit = $true }
        @{ Name = 'an error redirect 2>'; Code = 'Get-Item $x 2> $p'; Hit = $true }
        @{ Name = 'Out-File'; Code = '"x" | Out-File $p'; Hit = $true }
        @{ Name = 'a comparison'; Code = 'if ($a -gt $b) { 1 }'; Hit = $false }
        @{ Name = 'a merge 2>&1'; Code = 'Get-Item $x 2>&1'; Hit = $false }
        @{ Name = 'a redirect to $null'; Code = 'Get-Item $x > $null'; Hit = $false }
        @{ Name = 'a string with an arrow'; Code = '$m = "a > b"'; Hit = $false }
    ) {
        param($Name, $Code, $Hit)
        $f = & $script:plant $Code
        $found = ((Get-CodeText -Path $f) -match $script:writePattern) -or (@(Get-FileRedirectionSite -Path $f).Count -gt 0)
        $found | Should -Be $Hit
    }

    It 'no code file redirects output to a file, apart from the ones allowed to write' {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -File -Filter '*.ps1') +
            @(Get-Item -LiteralPath (Join-Path $script:RepoRoot 'Invoke-MspkiHealthCheck.ps1'), (Join-Path $script:RepoRoot 'Start-MspkiHealthCheckGui.ps1'), (Join-Path $script:RepoRoot 'demo\Invoke-MspkiDemo.ps1'))
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in $files) {
            if ($script:writeAllowed -contains $f.Name) { continue }
            foreach ($s in @(Get-FileRedirectionSite -Path $f.FullName)) { [void]$hits.Add(('{0}: {1}' -f $f.Name, $s)) }
        }
        $hits.Count | Should -Be 0 -Because ($hits -join '; ')
    }

    It 'sees a store opened without OpenExistingOnly (self-test)' {
        $bad = & $script:plant ('$s = New-Object {0}.X509Store(''My'', ''LocalMachine''); $s.Open([{0}.OpenFlags]::ReadOnly)' -f $script:t)
        $good = & $script:plant ('$s = New-Object {0}.X509Store(''My'', ''LocalMachine''); $s.Open([{0}.OpenFlags]''ReadOnly, OpenExistingOnly'')' -f $script:t)
        @(Get-StoreOpenWithoutExistingOnly -Path $bad).Count | Should -Be 1
        @(Get-StoreOpenWithoutExistingOnly -Path $good).Count | Should -Be 0
    }

    It 'every certificate store is opened read-only and existing-only' {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src') -Recurse -File -Filter '*.ps1')
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in $files) { foreach ($s in @(Get-StoreOpenWithoutExistingOnly -Path $f.FullName)) { [void]$hits.Add(('{0}: {1}' -f $f.Name, $s)) } }
        $hits.Count | Should -Be 0 -Because ($hits -join '; ')
    }
}
