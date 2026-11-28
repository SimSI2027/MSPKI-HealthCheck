# GX8b consistency pass (docs/REVIEW-GX.md): one status vocabulary and one icon per meaning, readable and distinct titles, the Findings
# grid without a horizontal scroll, coverage in words, one time format. Pure helpers; example.test data only.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force
    $gui = Join-Path $script:RepoRoot 'src\Gui'
    foreach ($n in 'GuiModel.ps1', 'GuiView.ps1', 'GuiEntity.ps1', 'GuiMission.ps1') { . (Join-Path $gui $n) }
    $script:Design = Get-Content -Raw -LiteralPath (Join-Path $script:RepoRoot 'docs\GUI-DESIGN.md')
    function New-TestFinding { param([string]$Status, [string]$Code = 'OK', [string]$Category = 'CRL', [string]$Target = 'CN=Example Issuing CA, DC=corp, DC=example, DC=test', [string]$Endpoint = '', [string]$Message = 'm')
        [pscustomobject]@{ Id = 'F1'; Status = $Status; StatusCode = $Code; Category = $Category; Target = $Target; Endpoint = $Endpoint; Message = $Message; Severity = 'None'; Confidence = 'Confirmed'; Sources = @('AD:CDP') }
    }
}

Describe 'D-03 / D-14: one status vocabulary' {
    It 'calls a permission or support skip "Could not check" with the lock, everywhere' {
        Get-MspkiGuiStatusKey -Status Skipped -StatusCode PERMISSION_DENIED | Should -Be 'CouldNotCheck'
        Get-MspkiGuiStatusKey -Status Skipped -StatusCode UNSUPPORTED | Should -Be 'CouldNotCheck'
        Get-MspkiGuiStatusKey -Status Skipped -StatusCode NOT_APPLICABLE | Should -Be 'Skipped'
        $p = Get-MspkiGuiStatusPill -Value CouldNotCheck
        $p.Text | Should -Be 'Could not check'; $p.Tone | Should -Be 'Admin'; $p.Glyph | Should -Be ([string][char]0xE72E)
        $row = ConvertTo-MspkiGuiRow -Finding (New-TestFinding -Status Skipped -Code PERMISSION_DENIED)
        $row.StatusKey | Should -Be 'CouldNotCheck'
        $row.StatusPill.Text | Should -Be 'Could not check'
        Test-MspkiGuiRowFilter -Row $row -Status @('CouldNotCheck') | Should -BeTrue
        Test-MspkiGuiRowFilter -Row $row -Status @('Skipped') | Should -BeFalse
    }
    It 'uses the GUI-DESIGN section 9 words in sentence case, never a power button' {
        (Get-MspkiGuiStatusPill -Value Fail).Text | Should -Be 'Failing'
        (Get-MspkiGuiStatusPill -Value Error).Text | Should -Be 'Check failed'
        (Get-MspkiGuiStatusPill -Value NotApplicable).Text | Should -Be 'Not applicable'
        (Get-MspkiGuiStatusPill -Value ReviewRequired -Kind Severity).Text | Should -Be 'Review required'
        (Get-MspkiGuiStatusPill -Value Skipped).Glyph | Should -Not -Be ([string][char]0xE7E8)
        foreach ($s in (Get-MspkiGuiStatusOrder)) { (Get-MspkiGuiStatusPill -Value $s).Glyph | Should -Not -Be ([string][char]0xE7E8) -Because $s }
        $gui = Join-Path $script:RepoRoot 'src\Gui'
        foreach ($f in Get-ChildItem -LiteralPath $gui -Include *.ps1, *.xaml -Recurse) { (Get-Content -Raw -LiteralPath $f.FullName) | Should -Not -Match '(?i)0xE7E8|&#xE7E8;' -Because $f.Name }
    }
    It 'matches the icon table of GUI-DESIGN section 8 for every status pill' {
        $map = @{ Critical = 'EA39'; Fail = 'E711'; Error = 'E783'; Warning = 'E7BA'; CouldNotCheck = 'E72E'; Skipped = 'E893'; Information = 'E946'; Pass = 'E73E'; NotApplicable = 'E738' }
        foreach ($k in $map.Keys) {
            (Get-MspkiGuiStatusPill -Value $k).Glyph | Should -Be ([string][char][Convert]::ToInt32($map[$k], 16)) -Because $k
            $script:Design | Should -Match ('\|\s*{0}\s*\|' -f $map[$k]) -Because ('the section 8 table lists {0}' -f $map[$k])
        }
    }
    It 'hides a severity of None (D-29)' {
        (Get-MspkiGuiStatusPill -Value None -Kind Severity).Text | Should -Be ''
        (ConvertTo-MspkiGuiRow -Finding (New-TestFinding -Status Fail)).SeverityText | Should -Be ''
    }
}

Describe 'D-11 / D-12: readable, distinct titles' {
    It 'names the copy of a CRL by where it was read, never by a distinguished name' {
        $a = Get-MspkiGuiFindingTitle -Finding (New-TestFinding -Status Critical -Endpoint 'http://pki.example.test/cdp/Example Issuing CA.crl')
        $b = Get-MspkiGuiFindingTitle -Finding (New-TestFinding -Status Critical -Endpoint 'ldap:///CN=Example Issuing CA,CN=ca01,CN=CDP,CN=Public Key Services?certificateRevocationList')
        $c = Get-MspkiGuiFindingTitle -Finding (New-TestFinding -Status Critical -Endpoint 'CA property BaseCRL[1] of ca01.example.test\Example Issuing CA')
        $a | Should -Be ('CRL {0} Example Issuing CA {0} at pki (HTTP)' -f [char]0x00B7)
        $b | Should -Match 'in AD \(LDAP\)$'
        $c | Should -Match 'at the CA \(base CRL\)$'
        foreach ($t in $a, $b, $c) { $t | Should -Not -Match 'CN=|DC=' }
        @($a, $b, $c | Select-Object -Unique).Count | Should -Be 3
    }
    It 'names the file when the subject is the host itself' {
        $t = Get-MspkiGuiFindingTitle -Finding (New-TestFinding -Status Fail -Category AIA -Target 'legacy.example.test' -Endpoint 'http://legacy.example.test/aia/Example%20Root%20CA.crt')
        $t | Should -Match 'legacy\.example\.test . Example Root CA\.crt \(HTTP\)$'
    }
    It 'gives the grid a readable target with the full name in the tooltip' {
        $r = ConvertTo-MspkiGuiRow -Finding (New-TestFinding -Status Critical -Endpoint 'http://pki.example.test/cdp/x.crl')
        $r.TargetText | Should -Not -Match 'CN='
        $r.TargetTip | Should -Match 'CN=Example Issuing CA'
    }
}

Describe 'D-05: the Findings grid never scrolls sideways' {
    It 'keeps the fixed columns inside the width at every window size, with room for the message' {
        foreach ($w in 420, 480, 560, 640, 700, 800, 900, 1100, 1400) {
            $p = Get-MspkiGuiGridColumnPlan -Width $w
            $fixed = $p.Status + $p.Target + $p.Category + $p.Severity + $p.Confidence + $p.ConfidenceIcon
            if ($w -ge 560) { ($w - 22 - $fixed) | Should -BeGreaterOrEqual 140 -Because ('message room at {0}' -f $w) }
            if (($w - 22) -ge 880) { $p.Confidence | Should -BeGreaterThan 0 } else { $p.ConfidenceIcon | Should -BeGreaterThan 0 }
        }
    }
}

Describe 'D-20 / D-30: coverage in words, one time format' {
    It 'says what was refused and links the finding that explains it' {
        $ri = [pscustomobject]@{ Methods = @([pscustomobject]@{ Method = 'CA:GetCAProperty'; Outcome = 'PermissionDenied'; Detail = 'ca02.example.test\Example Second CA: 0x80070005'; ElapsedMs = 10 }) }
        $f = New-TestFinding -Status Skipped -Code PERMISSION_DENIED -Category CA -Target 'Example Second CA' -Endpoint 'ca02.example.test\Example Second CA'
        $f.Sources = @('CA:GetCAProperty')
        $c = Get-MspkiGuiCoverage -RunInfo $ri -Findings @($f)
        $i = $c.Items[0]
        $i.MethodText | Should -Be 'Reading the CA''s properties'
        $i.Reason | Should -Match 'was refused \(access denied, 0x80070005\)'
        $i.Reason | Should -Not -Match '\\'
        $i.FindingTag | Should -Be 'F1'
        $i.Pill.Text | Should -Be 'Access denied'
        $c.Text | Should -Match 'could not check'
    }
    It 'writes every time the same way, also inside engine messages' {
        Format-MspkiGuiTime -Value ([datetime]::new(2026, 11, 17, 8, 0, 0, [DateTimeKind]::Utc)) | Should -Be '17 Nov 2026, 08:00 UTC'
        Format-MspkiGuiTextTimes -Text 'has expired (2026-11-17T08:00:00Z).' | Should -Be 'has expired (17 Nov 2026, 08:00 UTC).'
        (ConvertTo-MspkiGuiRow -Finding (New-TestFinding -Status Fail -Message 'expired 2026-11-17T08:00:00Z')).Message | Should -Be 'expired 17 Nov 2026, 08:00 UTC'
    }
}

Describe 'D-13: no internal id under a title' {
    It 'keeps the technical id as the last property of an object, and the Objects list says type, host and state in words' {
        $graph = ConvertFrom-MspkiJson -Text '{ "Entities": [ { "Id": "endpoint:web://pki.example.test/cdp/x.crl", "Type": "Endpoint", "Name": "http://pki.example.test/cdp/x.crl", "Properties": {} } ], "Relations": [], "Observations": [] }'
        $idx = New-MspkiGuiGraphIndex -Graph $graph -Findings @()
        $pane = Get-MspkiGuiEntityPane -Index $idx -Id 'endpoint:web://pki.example.test/cdp/x.crl'
        @($pane.Facts)[-1].Name | Should -Be 'Technical id'
        $row = @(Get-MspkiGuiObjectList -Index $idx)[0]
        $row.SubText | Should -Match 'pki\.example\.test'
        $row.SubText | Should -Not -Match 'endpoint:'
        $xaml = Get-Content -Raw -LiteralPath (Join-Path $script:RepoRoot 'src\Gui\MainWindow.xaml')
        $xaml | Should -Not -Match '<TextBox Text="\{Binding Id, Mode=OneWay\}"'
    }
}

Describe 'GUI files never define the same function twice' {
    It 'has one definition per function name across src\Gui (a later file would silently replace an earlier one)' {
        $seen = @{}
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'src\Gui') -Filter *.ps1) {
            foreach ($m in [regex]::Matches((Get-Content -Raw -LiteralPath $f.FullName), '(?im)^function\s+([\w-]+)')) {
                $n = $m.Groups[1].Value.ToLowerInvariant()
                $seen.ContainsKey($n) | Should -BeFalse -Because ('{0} is defined in {1} and {2}' -f $m.Groups[1].Value, $seen[$n], $f.Name)
                $seen[$n] = $f.Name
            }
        }
    }
}

Describe 'D-02 / D-24 / D-25 / D-08: the Overview says which run, why the score, and what to do after an error' {
    It 'starts the headline of an earlier run with its date' {
        $a = [pscustomobject]@{ Total = 2; Items = @([pscustomobject]@{ Title = 'A CRL has expired' }) }
        Get-MspkiGuiHeadline -Actions $a -AsOf '20 Nov 2026, 09:29 UTC' | Should -Be 'As of 20 Nov 2026, 09:29 UTC: 2 actions need attention. Most urgent: A CRL has expired.'
        Get-MspkiGuiHeadline -Actions $a | Should -Not -Match '^As of'
    }
    It 'names the area that holds the overall score down, and says "not scored" for an empty area' {
        $f = @(
            [pscustomobject]@{ Id = 'F1'; Status = 'Critical'; Severity = 'High'; Category = 'CRL'; StatusCode = 'EXPIRED' }
            [pscustomobject]@{ Id = 'F2'; Status = 'Critical'; Severity = 'High'; Category = 'CRL'; StatusCode = 'EXPIRED' }
            [pscustomobject]@{ Id = 'F3'; Status = 'Pass'; Severity = 'None'; Category = 'CA'; StatusCode = 'OK' }
            [pscustomobject]@{ Id = 'F4'; Status = 'Pass'; Severity = 'None'; Category = 'ADContainer'; StatusCode = 'OK' }
            [pscustomobject]@{ Id = 'F5'; Status = 'Pass'; Severity = 'None'; Category = 'CES'; StatusCode = 'OK' }
        )
        $s = Get-MspkiGuiHealthScore -Findings $f
        $s.HasScore | Should -BeTrue
        $s.HeldText | Should -Match '^Held down by .+ \(\d+\)$'
        $s.HeldTip | Should -Match 'weakest area \+ 30'
    }
    It 'explains a run that ended without results with ranked causes and read-only checks' {
        $v = Get-MspkiGuiRunErrorView -Problem 'The domain controller could not be reached (LDAP bind timed out after 5 s).' -TimeoutSeconds 5
        $v.Meaning | Should -Not -BeNullOrEmpty
        @($v.Causes).Count | Should -BeGreaterOrEqual 3
        @($v.Causes | Where-Object { $_.Text -match 'timeout \(5 s\)' }).Count | Should -Be 1
        foreach ($c in @($v.Causes)) { $c.Check | Should -Match '^(Check \(read-only\)|Change options)' }
    }
}

Describe 'D-17 / readable text: checks ready to paste, names without DNs, the rest of the sentence kept' {
    It 'shortens a DN inside a sentence without eating the rest of it' {
        Get-MspkiGuiReadableName -Name 'Base CRL of CN=Example Issuing CA, DC=corp, DC=example, DC=test at http://pki.example.test/x.crl has expired (17 Nov 2026).' |
            Should -Be 'Base CRL of Example Issuing CA at http://pki.example.test/x.crl has expired (17 Nov 2026).'
        Get-MspkiGuiReadableName -Name 'CN=Example CA, OU=PKI, O=Example Org, C=US' | Should -Be 'Example CA'
        Get-MspkiGuiReadableName -Name 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example,DC=test' | Should -Be 'Enrollment Services'
    }
    It 'fills the placeholders a finding answers and leaves the others' {
        $f = [pscustomobject]@{ Endpoint = 'http://pki.example.test/cdp/Example%20CA.crl'; Target = 'CN=Example CA'; Category = 'CRL'; RelatedCA = ''; Domain = 'corp.example.test'; Forest = 'example.test' }
        Expand-MspkiGuiCheckText -Text 'certutil -URL <Url>' -Finding $f | Should -Be 'certutil -URL http://pki.example.test/cdp/Example%20CA.crl'
        Expand-MspkiGuiCheckText -Text 'Test-NetConnection <Host> -Port <Port>' -Finding $f | Should -Be 'Test-NetConnection pki.example.test -Port 80'
        Expand-MspkiGuiCheckText -Text 'nltest /dsgetdc:<DomainDnsName>' -Finding $f | Should -Be 'nltest /dsgetdc:corp.example.test'
        Expand-MspkiGuiCheckText -Text 'look at <TemplateName>' -Finding $f | Should -Be 'look at <TemplateName>'
        Test-MspkiGuiCheckIsCommand -Text 'certutil -URL x' | Should -BeTrue
        Test-MspkiGuiCheckIsCommand -Text 'On the CA (owner): Application log' | Should -BeFalse
    }
}

Describe 'D-21: findings without a knowledge topic become one plain action per category and status' {
    It 'groups 22 topic-less AIA failures into one action with a plain title' {
        $f = @(foreach ($i in 1..22) { [pscustomobject]@{ Id = ('F{0:000}' -f $i); Status = 'Fail'; Severity = 'Medium'; Category = 'AIA'; StatusCode = 'TEST'; Target = ('h{0}.example.test' -f $i); Message = ('AIA address {0} checked.' -f $i); Evidence = @(); Sources = @() } })
        $a = Get-MspkiGuiNextAction -Findings $f -Max 10
        $a.Total | Should -Be 1
        $a.Items[0].Title | Should -Be '22 AIA addresses failing'
        $a.Items[0].Count | Should -Be 22
    }
    It 'says a single plain finding in words too' {
        Get-MspkiGuiPlainActionTitle -Category CDP -Status Warning -Count 1 | Should -Be '1 CRL address with a warning'
    }
}

Describe 'D-10: places and counts agree' {
    It 'says where an Enterprise CA was read even when the results file did not record it' {
        $graph = ConvertFrom-MspkiJson -Text '{ "Entities": [ { "Id": "ca:example-ca", "Type": "CA", "Name": "Example CA", "Properties": { "Kind": "Enterprise" } } ], "Relations": [], "Observations": [] }'
        $idx = New-MspkiGuiGraphIndex -Graph $graph -Findings @()
        $p = Get-MspkiGuiEntityPane -Index $idx -Id 'ca:example-ca'
        $p.SeenCount | Should -Be 1
        $p.Seen[0].Source | Should -Be 'AD'
    }
    It 'counts a service''s findings from the addresses it serves, as the PKI services card does' {
        $graph = ConvertFrom-MspkiJson -Text '{ "Entities": [ { "Id": "service:ces:x", "Type": "Service", "Name": "CES https://enroll.example.test/CES", "Properties": { "Kind": "CES", "Url": "https://enroll.example.test/CES" } }, { "Id": "endpoint:x", "Type": "Endpoint", "Name": "https://enroll.example.test/CES", "Properties": {} } ], "Relations": [ { "From": "endpoint:x", "Type": "servedBy", "To": "service:ces:x" } ], "Observations": [] }'
        $f = [pscustomobject]@{ Id = 'F9'; Status = 'Warning'; StatusCode = 'TLS'; Category = 'CES'; Target = 'enroll.example.test'; Endpoint = 'https://enroll.example.test/CES'; Message = 'm'; Severity = 'None'; Confidence = 'Confirmed'; Sources = @(); EntityIds = @('endpoint:x') }
        $rows = ConvertTo-MspkiGuiRowList -Findings @($f)
        $byId = @{}; foreach ($r in $rows) { $byId[$r.Id] = $r }
        $idx = New-MspkiGuiGraphIndex -Graph $graph -Findings @($f)
        (Get-MspkiGuiEntityPane -Index $idx -Id 'service:ces:x' -RowById $byId).FindingCount | Should -Be 1
    }
}
