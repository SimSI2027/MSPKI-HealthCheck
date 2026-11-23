BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module $script:ModulePath -Force

    $script:root = New-TestCertificate -Subject 'CN=Example Root CA, DC=example, DC=test' -DaysBefore 800 -DaysValid 3650 -CAVersion 0
}

Describe 'ConvertFrom-MspkiBase64Data' {
    It 'decodes Base64 (also with line breaks) and PEM certificate/CRL data to DER bytes' {
        $crl = New-TestCrl -Issuer $script:root -Number 3
        $b64 = ConvertTo-TestBase64 $crl
        $wrapped = ($b64 -split '(.{64})' | Where-Object { $_ }) -join "`r`n"
        $pem = "-----BEGIN X509 CRL-----`r`n$wrapped`r`n-----END X509 CRL-----"
        InModuleScope MspkiHealthCheck -Parameters @{ Crl = $crl; B64 = $b64; Wrapped = $wrapped; Pem = $pem } {
            param($Crl, $B64, $Wrapped, $Pem)
            foreach ($text in @($B64, $Wrapped, $Pem)) {
                $bytes = ConvertFrom-MspkiBase64Data -Text $text
                ($bytes -join ',') | Should -Be ($Crl -join ',')
            }
        }
    }

    It 'refuses text that is not certificate or CRL shaped data' {
        InModuleScope MspkiHealthCheck {
            { ConvertFrom-MspkiBase64Data -Text '' } | Should -Throw
            { ConvertFrom-MspkiBase64Data -Text 'not base64 at all!' } | Should -Throw
            # Valid Base64 whose bytes are plain text, not a DER SEQUENCE
            $text = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes('Write-Output hello'))
            { ConvertFrom-MspkiBase64Data -Text $text } | Should -Throw '*not a DER structure*'
            { ConvertFrom-MspkiBase64Data -Text ("-----BEGIN PRIV" + "ATE KEY-----`nMAMCAQA=`n-----END PRIV" + "ATE KEY-----") } | Should -Throw '*not a certificate or CRL*'
            { ConvertFrom-MspkiBase64Data -Text ([Convert]::ToBase64String([byte[]](0x30, 0x03, 0x02, 0x01, 0x00))) -MaxBytes 2 } | Should -Throw '*larger than*'
        }
    }

    It 'is the only place that decodes Base64, and its callers are fixed' {
        $src = Join-Path $script:RepoRoot 'src'
        $hits = @(Get-ChildItem -LiteralPath $src -Recurse -Filter '*.ps1' | Select-String -Pattern 'FromBase64' | Where-Object { $_.Line -notmatch '^\s*#' })
        @($hits | ForEach-Object { $_.Filename } | Select-Object -Unique) | Should -Be @('BinaryData.ps1')
        $callers = @(Get-ChildItem -LiteralPath $src -Recurse -Filter '*.ps1' | Select-String -Pattern 'ConvertFrom-MspkiBase64Data\s+-Text' |
            ForEach-Object { $_.Filename } | Select-Object -Unique | Sort-Object)
        $callers | Should -Be @('CAProperty.ps1', 'Certificate.ps1')
    }
}

Describe 'CA own CRL properties' {
    It 'decodes the CA base CRL and treats an empty delta property as "no delta CRL"' {
        $base = New-TestCrl -Issuer $script:root -Number 9 -CAVersion 0
        $raw = @{
            Values = @{ CAType = 1; CAName = 'Example Issuing CA'; 'BaseCrl[0]' = (ConvertTo-TestBase64 $base); 'CASigCert[0]' = (ConvertTo-TestBase64 $script:root.Public.RawData) }
            Errors = @{ 'DeltaCrl[0]' = @{ HResult = '80094004'; Message = 'Property empty.' } }
            Fatal = $null; Count = 1
        }
        InModuleScope MspkiHealthCheck -Parameters @{ Raw = $raw } {
            param($Raw)
            $p = ConvertFrom-MspkiCAPropertyResult -Raw $Raw
            $s = $p.SigningCertificates[0]
            $s.BaseCrlState | Should -Be 'Read'
            $s.BaseCrl.CrlNumber | Should -Be '09'
            $s.BaseCrl.CAVersion | Should -Be 'V0.0'
            $s.DeltaCrlState | Should -Be 'Empty'
            $s.DeltaCrl | Should -BeNullOrEmpty
            @($p.PropertyErrors | Where-Object { $_.Property -like 'DeltaCrl*' }).Count | Should -Be 0
            $summary = ConvertTo-MspkiCrlSummary -Crl $s.BaseCrl
            $summary.psobject.Properties.Name | Should -Not -Contain 'Bytes'
            $summary.CrlNumber | Should -Be '09'
        }
    }

    It 'reports a CRL value that is not valid data as an error state, not as a crash' {
        $raw = @{
            Values = @{ CAType = 1; 'BaseCrl[0]' = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes('plain text, not a CRL')); 'CASigCert[0]' = (ConvertTo-TestBase64 $script:root.Public.RawData) }
            Errors = @{ 'DeltaCrl[0]' = @{ HResult = '80070005'; Message = 'Access denied.' } }
            Fatal = $null; Count = 1
        }
        InModuleScope MspkiHealthCheck -Parameters @{ Raw = $raw } {
            param($Raw)
            $s = (ConvertFrom-MspkiCAPropertyResult -Raw $Raw).SigningCertificates[0]
            $s.BaseCrlState | Should -Be 'Error'
            $s.BaseCrlDetail | Should -Match 'not a DER'
            $s.DeltaCrlState | Should -Be 'Error'
            $s.DeltaCrlDetail | Should -Match 'PermissionDenied'
        }
    }
}

Describe 'Test-MspkiCaCrlPublication' {
    BeforeAll {
        $script:run = {
            param($Own, $Served, $Extra = @{})
            # $Own / $Served: arrays of @{ Bytes; Url }. Returns the result of the comparison.
            InModuleScope MspkiHealthCheck -Parameters @{ Own = $Own; Served = $Served } {
                param($Own, $Served)
                $i = 0
                $own = @($Own | ForEach-Object {
                    $i++
                    [pscustomobject]@{ CAName = 'Example Issuing CA'; Config = 'ca01.corp.example.test\Example Issuing CA'; Index = 0
                        Kind = $(if ($_.Delta) { 'Delta' } else { 'Base' }); Crl = (ConvertFrom-MspkiCrl -Bytes $_.Bytes); PublishStatus = 0 }
                })
                $recs = @($Served | ForEach-Object {
                    [pscustomobject]@{ Url = $_.Url
                        Lead = [pscustomobject]@{ Kind = 'CDP'; Id = 'L1'; RelatedCAs = @('Example Issuing CA'); Sources = @('Cert:AA:CDP'); Scope = 'Local' }
                        Crl = (ConvertFrom-MspkiCrl -Bytes $_.Bytes); ExpectedIssuer = @() }
                })
                Test-MspkiCaCrlPublication -CaCrls $own -Records $recs -Certificates @()
            }
        }
        $script:url1 = 'http://pki.corp.example.test/cdp/Example Issuing CA.crl'
        $script:url2 = 'http://pki2.corp.example.test/cdp/Example Issuing CA.crl'
    }

    It 'reports the same CRL number as published correctly (Pass, Confirmed)' {
        $own = New-TestCrl -Issuer $script:root -Number 12 -CAVersion 0
        $r = & $script:run @(@{ Bytes = $own }) @(@{ Bytes = $own; Url = $script:url1 })
        $f = @($r.Findings | Where-Object { $_.Endpoint -eq $script:url1 })
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Pass'
        $f[0].StatusCode | Should -Be 'OK'
        $f[0].Confidence | Should -Be 'Confirmed'
        $f[0].Message | Should -Match 'published correctly'
        @($f[0].Sources) | Should -Contain 'CA:Example Issuing CA:GetCAProperty:BaseCRL'
        $r.JudgedUrls.Count | Should -Be 0
    }

    It 'reports an older number as PUBLICATION_FAIL when the CA created its newer CRL longer ago than the grace period' {
        $own = New-TestCrl -Issuer $script:root -Number 12 -CAVersion 0 -HoursBefore 6
        $old = New-TestCrl -Issuer $script:root -Number 11 -CAVersion 0 -HoursBefore 200 -HoursValid 240
        $r = & $script:run @(@{ Bytes = $own }) @(@{ Bytes = $old; Url = $script:url1 })
        $f = @($r.Findings | Where-Object { $_.Endpoint -eq $script:url1 })
        $f[0].StatusCode | Should -Be 'PUBLICATION_FAIL'
        $f[0].Status | Should -Be 'Warning'
        ($f[0].Evidence -join "`n") | Should -Match 'grace period'
        @($r.JudgedUrls) | Should -Be @($script:url1)
    }

    It 'reports an older number as STALE_DATA when the CA created its newer CRL within the grace period' {
        $own = New-TestCrl -Issuer $script:root -Number 12 -CAVersion 0 -HoursBefore 0.2
        $old = New-TestCrl -Issuer $script:root -Number 11 -CAVersion 0 -HoursBefore 100 -HoursValid 240
        $r = & $script:run @(@{ Bytes = $own }) @(@{ Bytes = $old; Url = $script:url1 })
        $f = @($r.Findings | Where-Object { $_.Endpoint -eq $script:url1 })
        $f[0].StatusCode | Should -Be 'STALE_DATA'
        $f[0].Status | Should -Be 'Warning'
    }

    It 'fails with PUBLICATION_FAIL when the older CRL that is served has expired' {
        $own = New-TestCrl -Issuer $script:root -Number 12 -CAVersion 0 -HoursBefore 1
        $old = New-TestCrl -Issuer $script:root -Number 11 -CAVersion 0 -HoursBefore 300 -HoursValid 240
        $r = & $script:run @(@{ Bytes = $own }) @(@{ Bytes = $old; Url = $script:url1 })
        $f = @($r.Findings | Where-Object { $_.Endpoint -eq $script:url1 })
        $f[0].StatusCode | Should -Be 'PUBLICATION_FAIL'
        $f[0].Status | Should -Be 'Fail'
    }

    It 'accepts a higher number as a pass with a note, and compares delta CRLs only with delta CRLs' {
        $ownBase = New-TestCrl -Issuer $script:root -Number 12 -CAVersion 0
        $ownDelta = New-TestCrl -Issuer $script:root -Number 13 -CAVersion 0 -Delta -BaseNumber 12
        $newerBase = New-TestCrl -Issuer $script:root -Number 14 -CAVersion 0
        $r = & $script:run @(@{ Bytes = $ownBase }, @{ Bytes = $ownDelta; Delta = $true }) @(@{ Bytes = $newerBase; Url = $script:url1 }, @{ Bytes = $ownDelta; Url = $script:url2 })
        $a = @($r.Findings | Where-Object { $_.Endpoint -eq $script:url1 })
        $a[0].Status | Should -Be 'Pass'
        $a[0].Notes | Should -Match 'not a fault'
        $b = @($r.Findings | Where-Object { $_.Endpoint -eq $script:url2 })
        $b[0].Message | Should -Match 'same delta CRL number'
    }

    It 'matches the key generation by the CA version extension' {
        $gen0 = New-TestCrl -Issuer $script:root -Number 4 -CAVersion 0
        $gen1 = New-TestCrl -Issuer $script:root -Number 2 -CAVersion 65537
        $r = & $script:run @(@{ Bytes = $gen0 }, @{ Bytes = $gen1 }) @(@{ Bytes = $gen1; Url = $script:url1 })
        $f = @($r.Findings | Where-Object { $_.Endpoint -eq $script:url1 })
        $f.Count | Should -Be 1
        $f[0].StatusCode | Should -Be 'OK'
    }

    It 'also grades the CA''s own CRL (freshness) and labels its source' {
        $own = New-TestCrl -Issuer $script:root -Number 12 -CAVersion 0 -HoursBefore 235 -HoursValid 240
        $r = & $script:run @(@{ Bytes = $own }) @()
        $f = @($r.Findings)
        $f.Count | Should -Be 1
        $f[0].Status | Should -Be 'Critical'
        $f[0].Message | Should -Match '^CA''s own current'
        @($f[0].Sources) | Should -Contain 'CA:Example Issuing CA:GetCAProperty:BaseCRL'
    }

    It 'lets the cross-location check skip locations already judged against the CA' {
        $old = New-TestCrl -Issuer $script:root -Number 5
        $new = New-TestCrl -Issuer $script:root -Number 7
        InModuleScope MspkiHealthCheck -Parameters @{ O = $old; N = $new; U1 = $script:url1; U2 = $script:url2 } {
            param($O, $N, $U1, $U2)
            $lead = [pscustomobject]@{ Kind = 'CDP'; Id = 'L1'; RelatedCAs = @(); Sources = @('x'); Scope = 'Local' }
            $recs = @(
                [pscustomobject]@{ Url = $U1; Lead = $lead; Crl = (ConvertFrom-MspkiCrl -Bytes $N); ExpectedIssuer = @() }
                [pscustomobject]@{ Url = $U2; Lead = $lead; Crl = (ConvertFrom-MspkiCrl -Bytes $O); ExpectedIssuer = @() }
            )
            $all = Test-MspkiCrlConsistency -Records $recs
            $skipped = Test-MspkiCrlConsistency -Records $recs -ExcludeUrl @($U2)
            @($all).Count | Should -Be 1
            @($skipped).Count | Should -Be 0
        }
    }
}

Describe 'Get-MspkiCaOwnCrl uses the live CA properties, not the JSON-safe inventory summary' {
    It 'returns the decoded CRL (DateTime dates) and grading it does not throw' {
        $bytes = New-TestCrl -Issuer $script:root -Number 5 -CAVersion 0
        $r = InModuleScope MspkiHealthCheck -Parameters @{ Bytes = $bytes } {
            param($Bytes)
            $live = ConvertFrom-MspkiCrl -Bytes $Bytes
            # What the inventory holds: dates as strings (ConvertTo-MspkiCrlSummary), no raw bytes.
            $summary = ConvertTo-MspkiCrlSummary -Crl $live
            $ca = [pscustomobject]@{ Name = 'Example Issuing CA'; Config = 'ca01.corp.example.test\Example Issuing CA'
                Properties = [pscustomobject]@{ SigningCertificates = @([pscustomobject]@{ Index = 0; BaseCrl = $summary; DeltaCrl = $null; BaseCrlPublishStatus = 0 }) } }
            $fromSummary = @(Get-MspkiCaOwnCrl -EnterpriseCAs @($ca))
            $fromLive = @(Get-MspkiCaOwnCrl -EnterpriseCAs @($ca) -LiveProperties @{
                'Example Issuing CA' = [pscustomobject]@{ SigningCertificates = @([pscustomobject]@{ Index = 0; BaseCrl = $live; DeltaCrl = $null; BaseCrlPublishStatus = 0 }) } })
            $graded = Test-MspkiCaCrlPublication -CaCrls $fromLive -Records @() -Certificates @()
            [pscustomobject]@{ SummaryNextUpdateType = $fromSummary[0].Crl.NextUpdate.GetType().Name; LiveNextUpdateType = $fromLive[0].Crl.NextUpdate.GetType().Name; Graded = @($graded.Findings).Count }
        }
        $r.SummaryNextUpdateType | Should -Be 'String'
        $r.LiveNextUpdateType | Should -Be 'DateTime'
        $r.Graded | Should -Be 1
    }
}
