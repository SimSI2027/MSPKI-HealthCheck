# DEVELOPER-ONLY (tools\dev, never shipped, never referenced by the product). Reads a simulated world (site\world: world.json, a scenario
# overlay and the public PKI material) and installs the simulated I/O boundary in the imported MspkiHealthCheck module, so that the real
# engine runs against the world and nothing else. docs/DEMO-SITE.md section 3; the boundary list is Boundary.psd1 next to this file.

function Merge-MspkiSimData {
    # Deep merge of parsed JSON: objects merge by property (a null value removes the property), anything else replaces.
    param($Base, $Overlay)
    if ($null -eq $Overlay) { return $Base }
    if ($Base -is [System.Management.Automation.PSCustomObject] -and $Overlay -is [System.Management.Automation.PSCustomObject]) {
        $out = [ordered]@{}
        foreach ($p in $Base.PSObject.Properties) { $out[$p.Name] = $p.Value }
        foreach ($p in $Overlay.PSObject.Properties) {
            if ($null -eq $p.Value) { $out.Remove($p.Name); continue }
            if ($out.Contains($p.Name)) { $out[$p.Name] = Merge-MspkiSimData -Base $out[$p.Name] -Overlay $p.Value } else { $out[$p.Name] = $p.Value }
        }
        return [pscustomobject]$out
    }
    return $Overlay
}

function ConvertFrom-MspkiSimValue {
    # One fixture value: "pki:<file>" -> DER bytes, "b64pki:<file>" -> the Base64 TEXT of that file (what a CA COM property returns),
    # "sddl:<sddl>" -> a binary security descriptor, "sid:<sid>" -> a binary SID, "time:<iso>" -> a UTC date. Anything else as is.
    param($Value, [string]$Pki)
    if ($Value -isnot [string]) { return $Value }
    if ($Value.StartsWith('pki:')) { return , [System.IO.File]::ReadAllBytes((Join-Path $Pki $Value.Substring(4))) }
    if ($Value.StartsWith('b64pki:')) { return [Convert]::ToBase64String([System.IO.File]::ReadAllBytes((Join-Path $Pki $Value.Substring(7)))) }
    if ($Value.StartsWith('sddl:')) {
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($Value.Substring(5))
        $b = New-Object byte[] $sd.BinaryLength; $sd.GetBinaryForm($b, 0); return , $b
    }
    if ($Value.StartsWith('sid:')) {
        $s = New-Object System.Security.Principal.SecurityIdentifier($Value.Substring(4))
        $b = New-Object byte[] $s.BinaryLength; $s.GetBinaryForm($b, 0); return , $b
    }
    if ($Value.StartsWith('time:')) { return [DateTime]::Parse($Value.Substring(5), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') }
    return $Value
}

function ConvertTo-MspkiSimTable {
    # A parsed JSON object as a hashtable (one level; values converted with ConvertFrom-MspkiSimValue, arrays element by element).
    param($Object, [string]$Pki)
    $h = @{}
    if ($null -eq $Object) { return $h }
    foreach ($p in $Object.PSObject.Properties) {
        $v = $p.Value
        if ($v -is [array]) { $h[$p.Name] = @($v | ForEach-Object { , (ConvertFrom-MspkiSimValue -Value $_ -Pki $Pki) }) }
        else { $h[$p.Name] = ConvertFrom-MspkiSimValue -Value $v -Pki $Pki }
    }
    return $h
}

function Read-MspkiSimWorld {
    <#
    .SYNOPSIS
    The simulated world of one scenario: world.json merged with scenarios\<id>.json (its "world" part), values resolved, indexed for the
    boundary functions. Returns a hashtable (see SimBoundary.ps1 for how each part is used).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root, [string]$Scenario = 'baseline')
    $pki = Join-Path $Root 'pki'
    $base = Get-Content -Raw -LiteralPath (Join-Path $Root 'world.json') | ConvertFrom-Json
    $scen = Get-Content -Raw -LiteralPath (Join-Path $Root ('scenarios\{0}.json' -f $Scenario)) | ConvertFrom-Json
    $w = Merge-MspkiSimData -Base $base -Overlay $scen.world
    $clock = [DateTime]::Parse([string]$w.clock, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')

    # Directory: objects by DN (lower case), parent keys, SIDs.
    $objs = New-Object System.Collections.ArrayList
    $byDn = @{}
    foreach ($p in $w.directory.objects.PSObject.Properties) {
        if ($null -eq $p.Value) { continue }
        $dn = [string]$p.Name
        $attrs = @{}
        foreach ($a in $p.Value.PSObject.Properties) {
            $vals = @($a.Value)
            $attrs[$a.Name.ToLowerInvariant()] = @($vals | ForEach-Object { , (ConvertFrom-MspkiSimValue -Value $_ -Pki $pki) })
        }
        $attrs['distinguishedname'] = @($dn)
        $key = $dn.ToLowerInvariant()
        $i = $key.IndexOf(',')
        $sid = ''
        if ($attrs.ContainsKey('objectsid')) { $sid = (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$attrs['objectsid'][0], 0)).Value.ToUpperInvariant() }
        $o = @{ Dn = $dn; Key = $key; Parent = $(if ($i -ge 0) { $key.Substring($i + 1) } else { '' }); Attrs = $attrs; Sid = $sid }
        [void]$objs.Add($o)
        $byDn[$key] = $o
    }
    $denied = @{}
    if ($null -ne $w.directory.denied) { foreach ($p in $w.directory.denied.PSObject.Properties) { $denied[$p.Name.ToLowerInvariant()] = [string]$p.Value } }
    $names = @{}
    foreach ($o in $objs) { if ($o.Sid -and $o.Attrs.ContainsKey('samaccountname')) { $names[$o.Sid] = '{0}\{1}' -f $w.computer.netbios, [string]$o.Attrs['samaccountname'][0] } }
    if ($null -ne $w.directory.accountNames) { foreach ($p in $w.directory.accountNames.PSObject.Properties) { $names[$p.Name.ToUpperInvariant()] = [string]$p.Value } }
    $directory = @{
        Servers = @($w.directory.servers | ForEach-Object { ([string]$_).ToLowerInvariant() })
        Unreachable = @($w.directory.unreachable | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        RootDse = (ConvertTo-MspkiSimTable -Object $w.directory.rootDse -Pki $pki)
        Objects = $objs.ToArray(); ByDn = $byDn; Denied = $denied
        Absent = @($w.directory.absent | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        KnownParents = @($objs | ForEach-Object { $_.Key })
        AccountNames = $names
    }

    # CAs: the answers of GetCAProperty per configuration string, and the database view.
    $cas = @{}
    foreach ($p in $w.cas.PSObject.Properties) {
        $c = $p.Value
        if ($null -eq $c) { continue }
        $errs = @{}
        if ($null -ne $c.errors) { foreach ($e in $c.errors.PSObject.Properties) { $errs[$e.Name] = @{ HResult = [string]$e.Value.hresult; Message = [string]$e.Value.message } } }
        $cas[$p.Name.ToLowerInvariant()] = @{
            Values = (ConvertTo-MspkiSimTable -Object $c.values -Pki $pki); Errors = $errs
            Fatal = $(if ($null -ne $c.fatal) { @{ HResult = [string]$c.fatal.hresult; Message = [string]$c.fatal.message } } else { $null })
            FatalMs = $(if ($null -ne $c.fatalMs) { [double]$c.fatalMs } else { 30.0 })
            DatabaseFatal = $(if ($null -ne $c.databaseFatal) { @{ HResult = [string]$c.databaseFatal.hresult; Message = [string]$c.databaseFatal.message } } else { $null })
            Database = @($c.database | Where-Object { $_ } | ForEach-Object { $r = @{}; foreach ($q in $_.PSObject.Properties) { $r[$q.Name] = [string]$q.Value }; $r })
        }
    }

    # Network: DNS, PTR, SRV, TCP, TLS and HTTP answers.
    $dns = @{}
    foreach ($p in $w.network.dns.PSObject.Properties) {
        $v = $p.Value
        $dns[$p.Name.ToLowerInvariant()] = $(if ($null -eq $v -or $v -eq 'nxdomain') { @{ A = @(); AAAA = @(); Cname = '' } } else { @{ A = @($v.a | Where-Object { $_ }); AAAA = @($v.aaaa | Where-Object { $_ }); Cname = [string]$v.cname } })
    }
    $ptr = @{}; foreach ($p in $w.network.ptr.PSObject.Properties) { $ptr[$p.Name] = @($p.Value | Where-Object { $_ }) }
    $srv = @{}; foreach ($p in $w.network.srv.PSObject.Properties) { $srv[$p.Name.ToLowerInvariant()] = @($p.Value | Where-Object { $_ }) }
    $tcp = @{}; foreach ($p in $w.network.tcp.PSObject.Properties) { $tcp[$p.Name.ToLowerInvariant()] = [string]$p.Value }
    $tls = @{}
    foreach ($p in $w.network.tls.PSObject.Properties) {
        $t = $p.Value
        $tls[$p.Name.ToLowerInvariant()] = @{ Reset = [bool]$t.reset; Code = [string]$t.code; NameMatch = [bool]$t.nameMatch; DnsNames = @($t.dnsNames | Where-Object { $_ })
            ChainErrors = @($t.chainErrors | Where-Object { $_ }); Certificate = $(if ($t.certificate) { ConvertFrom-MspkiSimValue -Value ([string]$t.certificate) -Pki $pki } else { $null }) }
    }
    $http = @{}
    foreach ($p in $w.network.http.PSObject.Properties) {
        $r = $p.Value
        if ($null -eq $r) { continue }
        $body = $null
        if ($r.body) { $body = $(if (([string]$r.body).StartsWith('text:')) { [System.Text.Encoding]::UTF8.GetBytes(([string]$r.body).Substring(5)) } else { ConvertFrom-MspkiSimValue -Value ([string]$r.body) -Pki $pki }) }
        $http[([System.Uri]$p.Name).AbsoluteUri] = @{ Status = [int]$r.status; Location = [string]$r.location; Server = [string]$r.server; Auth = @($r.auth | Where-Object { $_ }); ContentType = [string]$r.contentType; Body = $body }
    }

    # This computer.
    $l = $w.local
    $stores = @{}; foreach ($p in $l.stores.PSObject.Properties) { $stores[$p.Name] = @($p.Value | ForEach-Object { , (ConvertFrom-MspkiSimValue -Value $_ -Pki $pki) }) }
    $ent = @{}; foreach ($p in $l.enterprise.PSObject.Properties) { $ent[$p.Name] = @($p.Value | ForEach-Object { if (([string]$_).StartsWith('pki:')) { (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]](ConvertFrom-MspkiSimValue -Value $_ -Pki $pki))).Thumbprint } else { [string]$_ } }) }
    $trusted = @($l.trustedRoots | ForEach-Object { (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]](ConvertFrom-MspkiSimValue -Value $_ -Pki $pki))).Thumbprint.ToUpperInvariant() })
    $ps = @{}
    if ($null -ne $l.policyServers) { foreach ($p in $l.policyServers.PSObject.Properties) { $ps[$p.Name] = @($p.Value | ForEach-Object { @{ KeyName = [string]$_.keyName; Values = (ConvertTo-MspkiSimTable -Object $_.values -Pki $pki) } }) } }
    $tc = @{}; foreach ($p in $l.policy.templateCache.PSObject.Properties) { $tc[$p.Name] = @{ Timestamp = [string]$p.Value.timestamp; Templates = @($p.Value.templates) } }
    $aep = @{}; foreach ($p in $l.policy.aePolicy.PSObject.Properties) { $aep[$p.Name] = $p.Value }
    $toHash = { param($o) $h = [ordered]@{}; foreach ($q in $o.PSObject.Properties) { $h[$q.Name] = $q.Value }; $h }
    $local = @{
        Stores = $stores; Enterprise = $ent; TrustedRoots = $trusted; PolicyServers = $ps
        Policy = @{ TemplateCache = $tc; AEPolicy = $aep; RdpTemplate = [string]$l.policy.rdpTemplate }
        LifecycleEvents = @($l.lifecycleEvents | Where-Object { $_ } | ForEach-Object { & $toHash $_ })
        EnrollmentEvents = @($l.enrollmentEvents | Where-Object { $_ } | ForEach-Object { $h = & $toHash $_; if ($null -ne $h['Data']) { $h['Data'] = & $toHash $h['Data'] }; $h })
        Services = @($l.services | Where-Object { $_ } | ForEach-Object { & $toHash $_ })
        Products = @($l.products | Where-Object { $_ } | ForEach-Object { & $toHash $_ })
    }
    $lat = @{}; foreach ($p in $w.latency.PSObject.Properties) { $lat[$p.Name] = [double]$p.Value }
    return @{
        Scenario = $Scenario; Title = [string]$scen.title; Clock = $clock; StartClock = $clock; RunId = [string]$w.runId
        Computer = @{ Name = [string]$w.computer.name; User = [string]$w.computer.user; IsAdmin = [bool]$w.computer.isAdmin; PartOfDomain = [bool]$w.computer.partOfDomain
            Domain = [string]$w.computer.domain; DnsDomain = [string]$w.computer.dnsDomain; Site = [string]$w.computer.site; NetBios = [string]$w.computer.netbios }
        Forest = @{ Name = [string]$w.forest.name; RootDomain = [string]$w.forest.rootDomain; ForestMode = [string]$w.forest.forestMode; Domains = @($w.forest.domains)
            Trusts = @($w.forest.trusts | Where-Object { $_ } | ForEach-Object { @{ Source = [string]$_.source; TargetName = [string]$_.targetName; TrustType = [string]$_.trustType; TrustDirection = [string]$_.trustDirection } }) }
        Directory = $directory; Cas = $cas; Dns = $dns; Ptr = $ptr; Srv = $srv; Tcp = $tcp; Tls = $tls; Http = $http; Machine = $local; Latency = $lat
        Expect = $scen.expect
    }
}

function Enable-MspkiSimulation {
    <#
    .SYNOPSIS
    Installs the simulated boundary (SimBoundary.ps1) in the imported MspkiHealthCheck module and gives it the world. Checks that every
    function named in Boundary.psd1 (Replaced) now comes from SimBoundary.ps1, so a missed one fails here instead of reaching the network.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$World)
    $m = Get-Module MspkiHealthCheck
    if ($null -eq $m) { throw 'Import the MspkiHealthCheck module first.' }
    $sim = Join-Path $PSScriptRoot 'SimBoundary.ps1'
    . $m { param($w, $p) $script:MspkiSim = $w; . $p } $World $sim
    $list = Import-PowerShellDataFile -LiteralPath (Join-Path $PSScriptRoot 'Boundary.psd1')
    foreach ($n in @($list.Replaced) + @($list.Shadowed)) {
        $f = & $m { param($n) Get-Command -Name $n -CommandType Function -ErrorAction SilentlyContinue } $n
        if ($null -eq $f -or $f.ScriptBlock.File -ne $sim) { throw ('SIMULATION: {0} is not replaced by SimBoundary.ps1.' -f $n) }
    }
}
