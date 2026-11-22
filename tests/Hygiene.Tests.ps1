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

    # The patterns of the repository scans (files, and the whole history in the Audit 2 M14 tests below).
        $script:hostCi = '(?i)(?<![\w$.\\-])((?:[a-z0-9-]+\.)+(?:com|net|org|local|lan|corp|internal|intra|gov|edu|io|uk|de|nl|ie|eu|fr|ch|be|au|info|biz|cloud|online|tech|test|lab))\b'
        $script:hostLc = '(?-i)(?<![\w$.\\-])((?:[a-z0-9-]+\.)+(?:domain|ad|ca|co|us|int|home|site|priv|private))\b'
        $script:hostAllowed = '(?i)^((?:[a-z0-9-]+\.)*example\.test|system\.(?:[a-z]+\.)*(?:io|net)|asp\.net|learn\.microsoft\.com|docs\.microsoft\.com|github\.com|claude\.com|anthropic\.com|www\.w3\.org|schemas\.xmlsoap\.org|schemas\.microsoft\.com)$'
        $script:ipv4 = '(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])'
        $script:ipAllowed = '^(127\.|0\.0\.0\.0$|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|2\.5\.29\.|2\.5\.4\.)'
        $script:email = '(?i)[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+'
        $script:emailAllowed = '(?i)(@(?:[a-z0-9-]+\.)*example\.test|^noreply@anthropic\.com|@users\.noreply\.github\.com)$'

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

Describe 'Audit 2 M14: the whole history is checked, author and committer, messages and the content of every commit' {
    BeforeAll {
        $script:gitAvailable = [bool](Get-Command git -ErrorAction SilentlyContinue)
        # Counts only. Nothing that matched is ever returned or printed: the hits can be real names, and the repository is public.
        $script:scanHistory = {
            param([string]$Repo)
            $r = @{ Commits = 0; Identity = 0; Message = 0; Content = 0; Path = 0 }
            $noreply = '@users\.noreply\.github\.com$'
            # Which matches are real names: the same allowances as the scan of the working tree.
            $isReal = {
                param([string]$Kind, [string]$Value)
                switch ($Kind) {
                    'host' { return ($Value -notmatch $script:hostAllowed -and $Value -notmatch '^users\.noreply\.github\.com$') }
                    'ip' { return ($Value -notmatch $script:ipAllowed) }
                    default { return ($Value -notmatch $script:emailAllowed -and $Value -notmatch 'noreply@anthropic\.com') }
                }
            }
            $inText = {
                param([string]$Text)
                $set = New-Object System.Collections.Generic.HashSet[string]
                foreach ($rx in @($script:hostCi, $script:hostLc)) { foreach ($m in [regex]::Matches($Text, $rx)) { if (& $isReal 'host' $m.Groups[1].Value) { [void]$set.Add($m.Groups[1].Value) } } }
                foreach ($m in [regex]::Matches($Text, $script:ipv4)) { if (& $isReal 'ip' $m.Value) { [void]$set.Add($m.Value) } }
                foreach ($m in [regex]::Matches($Text, $script:email)) { if (& $isReal 'email' $m.Value) { [void]$set.Add($m.Value) } }
                return $set.Count
            }
            Push-Location $Repo
            try {
                $revs = @(& git rev-list --all 2>$null)
                $r.Commits = $revs.Count
                # Author AND committer: both must be the project identity (name ED, GitHub noreply address).
                foreach ($line in @(& git log --all --format='%an|%ae|%cn|%ce' 2>$null | Sort-Object -Unique)) {
                    $p = $line -split '\|'
                    if ($p.Count -ne 4 -or $p[0] -ne 'ED' -or $p[2] -ne 'ED' -or $p[1] -notmatch $noreply -or $p[3] -notmatch $noreply) { $r.Identity++ }
                }
                # Messages, subject and body of every commit on every ref.
                $r.Message = & $inText ((@(& git log --all --format='%B' 2>$null)) -join "`n")
                # File paths of every commit (a name can sit in a path that a later commit removed).
                $r.Path = & $inText ((@(& git log --all --name-only --format= 2>$null | Sort-Object -Unique)) -join "`n")
                # The full content of every file in every commit, found with git grep over the revisions (text and binary files).
                # The matches are collected here and never leave this function; only the count does.
                $found = New-Object System.Collections.Generic.HashSet[string]
                $patterns = @(@('host', $script:hostCi), @('host', $script:hostLc), @('ip', $script:ipv4), @('email', $script:email))
                for ($i = 0; $i -lt $revs.Count; $i += 40) {
                    $batch = @($revs[$i..([math]::Min($i + 39, $revs.Count - 1))])
                    foreach ($pt in $patterns) {
                        foreach ($m in @(& git grep -a -h -o -P -e $pt[1] @batch -- 2>$null)) {
                            if ($m -and (& $isReal $pt[0] ([string]$m))) { [void]$found.Add([string]$m) }
                        }
                    }
                }
                $r.Content = $found.Count
            }
            finally { Pop-Location }
            return $r
        }
        $script:scanHistoryNames = {
            param([string]$Repo, [string]$NamesFile)
            $r = @{ Commits = 0; Names = 0; InContent = 0; InMessage = 0; InPath = 0; InIdentity = 0; CommitsWithContentHit = 0 }
            $names = @([System.IO.File]::ReadAllLines($NamesFile) | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -and -not $_.StartsWith('#') } | Sort-Object -Unique)
            $r.Names = $names.Count
            Push-Location $Repo
            try {
                $revs = @(& git rev-list --all 2>$null)
                $r.Commits = $revs.Count
                $ident = ((@(& git log --all --format='%an %ae %cn %ce' 2>$null)) -join "`n").ToLowerInvariant()
                $msg = ((@(& git log --all --format='%B' 2>$null)) -join "`n").ToLowerInvariant()
                $path = ((@(& git log --all --name-only --format= 2>$null)) -join "`n").ToLowerInvariant()
                $commits = New-Object System.Collections.Generic.HashSet[string]
                foreach ($n in $names) {
                    if ($ident.Contains($n)) { $r.InIdentity++ }
                    if ($msg.Contains($n)) { $r.InMessage++ }
                    if ($path.Contains($n)) { $r.InPath++ }
                    $hit = $false
                    for ($i = 0; $i -lt $revs.Count; $i += 40) {
                        $batch = @($revs[$i..([math]::Min($i + 39, $revs.Count - 1))])
                        foreach ($o in @(& git grep -a -l -i -F -e $n @batch -- 2>$null)) { $hit = $true; [void]$commits.Add(([string]$o -split ':')[0]) }
                    }
                    if ($hit) { $r.InContent++ }
                }
                $r.CommitsWithContentHit = $commits.Count
            }
            finally { Pop-Location }
            return $r
        }
        $script:newRepo = {
            param([string]$Name)
            $d = Join-Path $TestDrive $Name
            New-Item -ItemType Directory -Path $d | Out-Null
            Push-Location $d
            try { & git init -q 2>$null | Out-Null } finally { Pop-Location }
            return $d
        }
        $script:commit = {
            param([string]$Repo, [string]$Message, [hashtable]$Files = @{}, [string[]]$Remove = @(), [string]$Author = ('ED|1+ed@users' + '.noreply.github.com'), [string]$Committer = ('ED|1+ed@users' + '.noreply.github.com'))
            Push-Location $Repo
            try {
                foreach ($k in $Files.Keys) { [System.IO.File]::WriteAllText((Join-Path $Repo $k), [string]$Files[$k]); & git add -- $k 2>$null | Out-Null }
                foreach ($k in $Remove) { & git rm -q -- $k 2>$null | Out-Null }
                $a = $Author -split '\|'; $c = $Committer -split '\|'
                $env:GIT_AUTHOR_NAME = $a[0]; $env:GIT_AUTHOR_EMAIL = $a[1]; $env:GIT_COMMITTER_NAME = $c[0]; $env:GIT_COMMITTER_EMAIL = $c[1]
                & git -c commit.gpgsign=false -c core.hooksPath=NUL commit -q --allow-empty -m $Message 2>$null | Out-Null
            }
            finally {
                'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL' | ForEach-Object { Remove-Item "Env:$_" -ErrorAction SilentlyContinue }
                Pop-Location
            }
        }
        # Built by concatenation so that this file itself stays clean for the scan of the repository.
        $script:plantHost = 'pki01.sample' + '.local'
        $script:plantMail = 'admin@sample' + '.org'
    }

    It 'finds a real name that sits in the committer fields only' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $d = & $script:newRepo 'committer'
        & $script:commit $d 'clean message' @{ 'a.txt' = 'clean' } -Committer ('Some Name|' + $script:plantMail)
        $r = & $script:scanHistory $d
        $r.Identity | Should -BeGreaterThan 0
    }

    It 'finds a real name in a file of an OLD commit that a later commit removed' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $d = & $script:newRepo 'oldcontent'
        & $script:commit $d 'add' @{ 'notes.txt' = ('see ' + $script:plantHost) }
        & $script:commit $d 'remove' -Remove @('notes.txt')
        $r = & $script:scanHistory $d
        $r.Content | Should -BeGreaterThan 0
    }

    It 'finds a real name in a file path of an older commit' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $d = & $script:newRepo 'path'
        & $script:commit $d 'add' @{ ($script:plantHost + '.txt') = 'clean' }
        & $script:commit $d 'remove' -Remove @(($script:plantHost + '.txt'))
        $r = & $script:scanHistory $d
        $r.Path | Should -BeGreaterThan 0
    }

    It 'finds a real name in a commit message' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $d = & $script:newRepo 'message'
        & $script:commit $d ('fix ' + $script:plantHost) @{ 'a.txt' = 'clean' }
        $r = & $script:scanHistory $d
        $r.Message | Should -BeGreaterThan 0
    }

    It 'finds nothing in a clean history (example.test names and the noreply identity)' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $d = & $script:newRepo 'clean'
        & $script:commit $d 'add ca.corp.example.test' @{ 'a.txt' = 'host pki.example.test, 192.0.2.10 and 127.0.0.1' }
        $r = & $script:scanHistory $d
        $r.Identity + $r.Message + $r.Content + $r.Path | Should -Be 0
    }

    It 'returns counts only, never the names that matched' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $d = & $script:newRepo 'countsonly'
        & $script:commit $d ('see ' + $script:plantHost) @{ 'a.txt' = $script:plantHost }
        $r = & $script:scanHistory $d
        foreach ($v in $r.Values) { $v | Should -BeOfType [int] }
        ($r | Out-String) | Should -Not -Match 'sample'
    }

    It 'the history of this repository has no real name: author and committer fields, messages, file paths and the content of every commit (counts only)' -Skip:(-not ((Get-Command git -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) '.git')))) {
        $r = & $script:scanHistory $script:RepoRoot
        $r.Commits | Should -BeGreaterThan 10
        # Only counts are printed: the names themselves can be real, and this repository is public.
        $summary = 'commits scanned {0}; identities that are not the project identity {1}; distinct names in messages {2}, in file paths {3}, in file content {4}' -f $r.Commits, $r.Identity, $r.Message, $r.Path, $r.Content
        ($r.Identity + $r.Message + $r.Path + $r.Content) | Should -Be 0 -Because $summary
    }

    # An optional private list of names (one per line, kept outside the repository; set MSPKI_PRIVATE_NAMES_FILE to its path) can be checked
    # against the same history. The tool never needs it; it is for the person who owns the real environment. Counts only.
    It 'counts the names of a private list in the whole history, per place (self-test on a planted history)' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $d = & $script:newRepo 'privatelist'
        & $script:commit $d ('fix ' + $script:plantHost) @{ ($script:plantHost + '.txt') = ('see ' + $script:plantHost) } -Committer ('Some Name|x@sample' + '.org')
        & $script:commit $d 'remove' -Remove @(($script:plantHost + '.txt'))
        $list = Join-Path $TestDrive 'names.txt'
        [System.IO.File]::WriteAllText($list, ($script:plantHost + "`n" + 'unrelated-name'))
        $r = & $script:scanHistoryNames $d $list
        $r.Names | Should -Be 2
        $r.InContent | Should -Be 1
        $r.InMessage | Should -Be 1
        $r.InPath | Should -Be 1
        $r.InIdentity | Should -Be 0
    }

    It 'finds none of the names of the private list in the history of this repository (runs only when MSPKI_PRIVATE_NAMES_FILE names a file)' -Skip:(-not ($env:MSPKI_PRIVATE_NAMES_FILE -and (Test-Path -LiteralPath $env:MSPKI_PRIVATE_NAMES_FILE))) {
        $r = & $script:scanHistoryNames $script:RepoRoot $env:MSPKI_PRIVATE_NAMES_FILE
        $summary = 'names checked {0}; found in file content {1}, messages {2}, file paths {3}, identities {4}; commits whose content has one: {5} of {6}' -f $r.Names, $r.InContent, $r.InMessage, $r.InPath, $r.InIdentity, $r.CommitsWithContentHit, $r.Commits
        ($r.InContent + $r.InMessage + $r.InPath + $r.InIdentity) | Should -Be 0 -Because $summary
    }
}
