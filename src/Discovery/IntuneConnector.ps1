# Local detection of the Certificate Connector for Microsoft Intune (REQUIREMENTS 5.8). Local only: Windows
# services (name, state, start type, executable path), installed products and certificate metadata of THIS
# computer. Read-only. Certificates: subject, issuer, thumbprint and validity only (never keys). Only entries that
# match the signatures in IntuneConnectorSignatures.ps1 are kept, so the rest of the installed software is not exported.

function Get-MspkiServiceExecutablePath {
    <#
    .SYNOPSIS
    The executable path of a service command line (the part before the arguments).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$PathName)
    $p = ([string]$PathName).Trim()
    if (-not $p) { return '' }
    if ($p.StartsWith('"')) {
        $end = $p.IndexOf('"', 1)
        if ($end -gt 1) { return $p.Substring(1, $end - 1) }
        return $p.Trim('"')
    }
    $m = [regex]::Match($p, '^(.*?\.exe)(\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($m.Success) { return $m.Groups[1].Value }
    return $p
}

function Find-MspkiIntuneConnectorEvidence {
    <#
    .SYNOPSIS
    Matches local services, installed products and certificate metadata against the connector signatures. Pure.

    .OUTPUTS
    Evidence entries { Kind (Service / Product / Path / Certificate), Strength (Documented / Pattern), Text, Basis }.
    Documented = strong (a name Microsoft documents); Pattern = weak (looks like it, other software could match).
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Services = @(),
        [AllowEmptyCollection()][object[]]$Products = @(),
        [AllowEmptyCollection()][object[]]$Certificates = @()
    )
    $out = New-Object System.Collections.ArrayList
    foreach ($s in @($Services | Where-Object { $_ })) {
        $doc = @($script:MspkiIntuneServiceName | Where-Object { $_.Name -ieq [string]$s.Name })
        $text = 'Service {0} ("{1}"): state {2}, start type {3}, executable {4}' -f $s.Name, $s.DisplayName, $s.State, $s.StartMode, $s.ExecutablePath
        if ($doc.Count -gt 0) { [void]$out.Add([pscustomobject]@{ Kind = 'Service'; Strength = 'Documented'; Text = $text; Basis = $doc[0].Basis }); continue }
        $pat = @($script:MspkiIntuneServiceDisplayPattern | Where-Object { [string]$s.DisplayName -match $_ -or [string]$s.Name -match $_ })
        if ($pat.Count -gt 0) { [void]$out.Add([pscustomobject]@{ Kind = 'Service'; Strength = 'Pattern'; Text = $text; Basis = ('The name matches the pattern {0}' -f $pat[0]) }); continue }
        if ([string]$s.ExecutablePath -match $script:MspkiIntunePathPattern) {
            [void]$out.Add([pscustomobject]@{ Kind = 'Path'; Strength = 'Pattern'; Text = $text; Basis = 'The executable is in the connector install folder' })
        }
    }
    foreach ($p in @($Products | Where-Object { $_ })) {
        $text = 'Installed product "{0}" version {1} (publisher {2})' -f $p.DisplayName, $p.DisplayVersion, $p.Publisher
        $doc = @($script:MspkiIntuneProductName | Where-Object { [string]$p.DisplayName -match $_.Pattern })
        if ($doc.Count -gt 0) { [void]$out.Add([pscustomobject]@{ Kind = 'Product'; Strength = 'Documented'; Text = $text; Basis = $doc[0].Basis }); continue }
        if ([string]$p.InstallLocation -match $script:MspkiIntunePathPattern) {
            [void]$out.Add([pscustomobject]@{ Kind = 'Path'; Strength = 'Pattern'; Text = $text; Basis = 'The install location is the connector install folder' })
        }
    }
    foreach ($c in @($Certificates | Where-Object { $_ })) {
        $hay = ('{0} {1} {2}' -f $c.Subject, $c.Issuer, $c.FriendlyName)
        $pat = @($script:MspkiIntuneCertificatePattern | Where-Object { $hay -match $_ })
        if ($pat.Count -gt 0) {
            [void]$out.Add([pscustomobject]@{ Kind = 'Certificate'; Strength = 'Pattern'
                Text = ('Certificate {0} [{1}], issuer {2}, valid until {3}' -f $c.Subject, $c.Thumbprint, $c.Issuer, $c.NotAfter)
                Basis = ('The subject, issuer or friendly name matches the pattern {0} (certificate names are weak evidence)' -f $pat[0]) })
        }
    }
    return , $out.ToArray()
}

function Get-MspkiLocalServiceInfo {
    <#
    .SYNOPSIS
    Reads the Windows services of this computer (name, display name, state, start mode, executable path) through CIM.
    #>
    [CmdletBinding()]
    param()
    $list = New-Object System.Collections.ArrayList
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Property Name, DisplayName, State, StartMode, PathName -OperationTimeoutSec 20 -ErrorAction Stop)) {
        [void]$list.Add([pscustomobject][ordered]@{
            Name = [string]$s.Name; DisplayName = [string]$s.DisplayName; State = [string]$s.State; StartMode = [string]$s.StartMode
            ExecutablePath = (Get-MspkiServiceExecutablePath -PathName ([string]$s.PathName)) })
    }
    return , $list.ToArray()
}

function Get-MspkiLocalProductInfo {
    <#
    .SYNOPSIS
    Reads the installed products of this computer from the Uninstall registry keys (read-only) and keeps only those
    that match a connector signature.
    #>
    [CmdletBinding()]
    param()
    $list = New-Object System.Collections.ArrayList
    $paths = @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($path in $paths) {
        $base = $null
        try {
            $base = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $false)
            if ($null -eq $base) { continue }
            foreach ($sn in $base.GetSubKeyNames()) {
                $k = $null
                try {
                    $k = $base.OpenSubKey($sn, $false)
                    if ($null -eq $k) { continue }
                    $name = [string]$k.GetValue('DisplayName', '')
                    if (-not $name) { continue }
                    $loc = [string]$k.GetValue('InstallLocation', '')
                    $hit = (@($script:MspkiIntuneProductName | Where-Object { $name -match $_.Pattern }).Count -gt 0) -or ($loc -match $script:MspkiIntunePathPattern)
                    if ($hit) {
                        [void]$list.Add([pscustomobject][ordered]@{ DisplayName = $name; DisplayVersion = [string]$k.GetValue('DisplayVersion', ''); Publisher = [string]$k.GetValue('Publisher', ''); InstallLocation = $loc })
                    }
                }
                finally { if ($null -ne $k) { $k.Close() } }
            }
        }
        finally { if ($null -ne $base) { $base.Close() } }
    }
    return , $list.ToArray()
}

function Get-MspkiLocalCertificateMetadata {
    <#
    .SYNOPSIS
    Reads certificate METADATA (subject, issuer, thumbprint, validity, friendly name) from the Personal store of the local
    computer, opened read-only, and keeps only certificates that match a connector pattern. No key material is touched.
    #>
    [CmdletBinding()]
    param()
    $list = New-Object System.Collections.ArrayList
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
        foreach ($c in $store.Certificates) {
            $hay = ('{0} {1} {2}' -f $c.Subject, $c.Issuer, $c.FriendlyName)
            if (@($script:MspkiIntuneCertificatePattern | Where-Object { $hay -match $_ }).Count -gt 0) {
                [void]$list.Add([pscustomobject][ordered]@{ Subject = $c.Subject; Issuer = $c.Issuer; Thumbprint = $c.Thumbprint
                    NotAfter = $c.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); FriendlyName = [string]$c.FriendlyName })
            }
        }
    }
    finally { $store.Close() }
    return , $list.ToArray()
}

function Get-MspkiIntuneConnectorLocal {
    <#
    .SYNOPSIS
    Reads the local services, products and certificate metadata (each with its own try/catch) and matches them against
    the connector signatures.

    .OUTPUTS
    Data: { ComputerName, Evidence, Methods }. Findings: read failures (permission kept apart from other errors).
    #>
    [CmdletBinding()]
    param([string]$ComputerName = $env:COMPUTERNAME)
    $findings = New-Object System.Collections.ArrayList
    $methods = New-Object System.Collections.ArrayList
    $services = @(); $products = @(); $certs = @()
    $steps = @(
        @{ Name = 'Local:Win32_Service'; What = 'the Windows services of this computer'; Fn = { Get-MspkiLocalServiceInfo }; Set = 'services' }
        @{ Name = 'Local:Uninstall'; What = 'the installed products of this computer'; Fn = { Get-MspkiLocalProductInfo }; Set = 'products' }
        @{ Name = 'Local:CertStore:My'; What = 'certificate metadata in the local computer''s Personal store'; Fn = { Get-MspkiLocalCertificateMetadata }; Set = 'certs' }
    )
    foreach ($st in $steps) {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $r = & $st.Fn
            switch ($st.Set) { 'services' { $services = @($r) } 'products' { $products = @($r) } 'certs' { $certs = @($r) } }
            Add-MspkiMethodOutcome -Method $st.Name -Outcome 'Success' -Detail ('{0} item(s)' -f @($r).Count) -ElapsedMs $sw.ElapsedMilliseconds
            [void]$methods.Add([pscustomobject]@{ Method = $st.Name; Outcome = 'Success'; Items = @($r).Count })
        }
        catch {
            $ei = Get-MspkiErrorInfo $_
            Add-MspkiMethodOutcome -Method $st.Name -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
            [void]$methods.Add([pscustomobject]@{ Method = $st.Name; Outcome = $ei.Class; Items = 0 })
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'IntuneConnector' -Role 'Computer' -Target $ComputerName -Sources $st.Name `
                -Action ('reading {0}' -f $st.What) -Scope 'Local'))
        }
    }
    $evidence = Find-MspkiIntuneConnectorEvidence -Services $services -Products $products -Certificates $certs
    return [pscustomobject]@{
        Data = [pscustomobject][ordered]@{ ComputerName = $ComputerName; ServicesChecked = $services.Count; ProductsMatched = $products.Count; CertificatesMatched = $certs.Count
            Evidence = @($evidence); Methods = @($methods) }
        Findings = @($findings)
    }
}
