# Seeds: domain membership, RootDSE (domain controller and naming contexts), forest, domains, trusts and
# AD site. Every method has its own try/catch; a failure becomes a finding and the run continues.

function Get-MspkiComputerSystemInfo {
    <#
    .SYNOPSIS
    Local, read-only: is this computer domain-joined, and to which domain.
    #>
    [CmdletBinding()]
    param()
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -Property PartOfDomain, Domain -ErrorAction Stop
    return [pscustomobject]@{ PartOfDomain = [bool]$cs.PartOfDomain; Domain = [string]$cs.Domain }
}

function Get-MspkiRootDse {
    <#
    .SYNOPSIS
    Reads RootDSE from one LDAP path ('LDAP://RootDSE' is the serverless bind: the DC locator picks the domain controller).

    .DESCRIPTION
    RootDSE is read as a directory entry with RefreshCache. It is never read with a DirectorySearcher: the LDAP provider answers a
    search on RootDSE with "The provider does not support searching and cannot search LDAP://RootDSE".
    #>
    [CmdletBinding()]
    param([string]$Path = 'LDAP://RootDSE')
    $props = @('configurationNamingContext', 'rootDomainNamingContext', 'defaultNamingContext',
        'schemaNamingContext', 'dnsHostName', 'serverName', 'currentTime', 'domainControllerFunctionality')
    $entry = New-Object System.DirectoryServices.DirectoryEntry($Path)
    try {
        $entry.RefreshCache([string[]]$props)
        $out = [ordered]@{}
        foreach ($p in $props) {
            $v = $null
            if ($entry.Properties.Contains($p)) { $v = $entry.Properties[$p].Value }
            if ($null -eq $v) { $out[$p] = '' } else { $out[$p] = [string]$v }
        }
    }
    finally { $entry.Dispose() }
    if (-not $out['configurationNamingContext']) { throw 'RootDSE has no configurationNamingContext.' }
    return [pscustomobject]$out
}

function Get-MspkiLiveDomainControllerName {
    <#
    .SYNOPSIS
    Live evidence of the forest's domain controllers: the targets of the DNS SRV records _ldap._tcp.dc._msdcs.<domain> of every forest
    domain (Resolve-DnsName, DNS only). Where the DnsClient module is missing, the in-box DC locator (DomainController.FindAll, which
    reads the same DNS records) is used. Runs in one time-limited runspace. No directory bind is made.

    .OUTPUTS
    { Names (host names); Method ('DnsSrv' or 'DcLocator'); Errors (text); Completed (bool) }
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Domains = @(), [int]$TimeoutSeconds = 15)
    $doms = @($Domains | ForEach-Object { ConvertTo-MspkiHostName $_ } | Where-Object { $_ } | Select-Object -Unique)
    $hasDnsClient = $null -ne (Get-Command -Name 'Resolve-DnsName' -ErrorAction SilentlyContinue)
    $out = [pscustomobject]@{ Names = @(); Method = $(if ($hasDnsClient) { 'DnsSrv' } else { 'DcLocator' }); Errors = @(); Completed = $false }
    if ($doms.Count -eq 0) { $out.Errors = @('No forest domain is known.'); return $out }
    $script = {
        param([string[]]$Domains, [bool]$UseDnsClient)
        foreach ($d in $Domains) {
            $names = @(); $errs = @()
            if ($UseDnsClient) {
                try {
                    $names = @(Resolve-DnsName -Name ('_ldap._tcp.dc._msdcs.' + $d) -Type SRV -DnsOnly -QuickTimeout -ErrorAction Stop |
                        Where-Object { $null -ne $_.PSObject.Properties['NameTarget'] } | ForEach-Object { [string]$_.NameTarget })
                }
                catch { $errs += ('DNS SRV for {0}: {1}' -f $d, $_.Exception.Message) }
            }
            else {
                try {
                    $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain, $d)
                    foreach ($x in [System.DirectoryServices.ActiveDirectory.DomainController]::FindAll($ctx)) { $names += [string]$x.Name; $x.Dispose() }
                }
                catch { $errs += ('DC locator for {0}: {1}' -f $d, $_.Exception.Message) }
            }
            @{ Domain = $d; Names = [string[]]$names; Errors = [string[]]$errs }
        }
    }
    $limit = [int][Math]::Min(600, [Math]::Max(10, $TimeoutSeconds * (1 + $doms.Count)))
    $call = Invoke-MspkiTimeLimitedScript -ScriptBlock $script -ArgumentList @([string[]]$doms, $hasDnsClient) -TimeoutSeconds $limit `
        -ProgressText ('Domain controllers of {0} domain(s) (DNS SRV records)' -f $doms.Count)
    $names = @(); $errs = @()
    foreach ($o in @($call.Output | ForEach-Object { $_ })) {
        if ($o -isnot [hashtable]) { continue }
        foreach ($n in @($o.Names)) { $h = ConvertTo-MspkiHostName $n; if ($h -and $names -notcontains $h) { $names += $h } }
        $errs += @($o.Errors | Where-Object { $_ })
    }
    if ($call.TimedOut) { $errs += ('No answer within {0} s.' -f $limit) }
    $errs += @($call.Errors | Where-Object { $_ })
    $out.Names = $names; $out.Errors = $errs; $out.Completed = [bool]$call.Completed
    return $out
}

function Get-MspkiForestDomainController {
    <#
    .SYNOPSIS
    The DNS names of the forest's live domain controllers (audit 2 verification N5). Read-only. Besides the selected domain controller,
    these are the only named hosts that an LDAP URL may reach without other proof (audit 2 H1).

    .DESCRIPTION
    A domain controller counts only when both hold:
    - its server object under CN=Sites of the Configuration partition has an NTDS Settings (nTDSDSA) child. A removed domain controller
      whose metadata was not cleaned up leaves a server object without one;
    - live evidence names it: a DNS SRV record _ldap._tcp.dc._msdcs.<domain> of a forest domain, or the DC locator
      (Get-MspkiLiveDomainControllerName). A stale name whose DNS record was scavenged can be registered again by any user.
    The two directory reads are subtree searches on the selected domain controller. Every server object that is not counted is
    returned in Excluded with the reason.

    .OUTPUTS
    The host names; with -Detail { Names; Excluded ({ Name; Reason }); Live (see Get-MspkiLiveDomainControllerName) }.
    #>
    [CmdletBinding()]
    param(
        [string]$Server = '',
        [Parameter(Mandatory = $true)][string]$ConfigNC,
        [int]$TimeoutSeconds = 15,
        # The forest's DNS domains (whose SRV records are read).
        [AllowEmptyCollection()][string[]]$Domains = @(),
        [switch]$Detail
    )
    $base = 'CN=Sites,{0}' -f $ConfigNC
    $servers = @(Get-MspkiLdapObject -Server $Server -BaseDN $base -Scope Subtree `
        -Filter '(&(objectClass=server)(dNSHostName=*))' -Properties @('dNSHostName', 'distinguishedName') -TimeoutSeconds $TimeoutSeconds)
    $ntds = @(Get-MspkiLdapObject -Server $Server -BaseDN $base -Scope Subtree -Filter '(objectClass=nTDSDSA)' `
        -Properties @('distinguishedName') -TimeoutSeconds $TimeoutSeconds)
    # The parent of CN=NTDS Settings,CN=<server>,CN=Servers,... is the server object.
    $withNtds = @{}
    foreach ($n in $ntds) {
        $dn = [string](Get-MspkiLdapValue -Record $n -Name 'distinguishedName')
        $m = [regex]::Match($dn, '^(?:[^,\\]|\\.)*,(?<parent>.+)$')
        if ($m.Success) { $withNtds[$m.Groups['parent'].Value.ToLowerInvariant()] = $true }
    }
    $live = Get-MspkiLiveDomainControllerName -Domains $Domains -TimeoutSeconds $TimeoutSeconds
    $names = @(); $excluded = New-Object System.Collections.ArrayList
    foreach ($r in $servers) {
        $h = ConvertTo-MspkiHostName ([string](Get-MspkiLdapValue -Record $r -Name 'dNSHostName'))
        if (-not $h -or $names -contains $h) { continue }
        $dn = ([string](Get-MspkiLdapValue -Record $r -Name 'distinguishedName')).ToLowerInvariant()
        if (-not $withNtds.ContainsKey($dn)) {
            [void]$excluded.Add([pscustomobject]@{ Name = $h; Reason = 'its server object has no NTDS Settings object (a server object that a removed domain controller left behind looks like this)' })
            continue
        }
        if (@($live.Names) -notcontains $h) {
            $why = 'no DNS SRV record (_ldap._tcp.dc._msdcs.<domain>) of a forest domain names it'
            if ($live.Method -eq 'DcLocator') { $why = 'the DC locator does not find it' }
            if (@($live.Names).Count -eq 0 -and @($live.Errors).Count -gt 0) { $why = ('the live domain controllers could not be read ({0})' -f (@($live.Errors) -join '; ')) }
            [void]$excluded.Add([pscustomobject]@{ Name = $h; Reason = $why })
            continue
        }
        $names += $h
    }
    if ($Detail) { return [pscustomobject]@{ Names = $names; Excluded = @($excluded); Live = $live } }
    return , $names
}

function Get-MspkiDomainControllerName {
    <#
    .SYNOPSIS
    DNS name of a domain controller of this computer's domain, chosen by the DC locator (System.DirectoryServices.ActiveDirectory).
    #>
    [CmdletBinding()]
    param()
    $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain)
    $dc = [System.DirectoryServices.ActiveDirectory.DomainController]::FindOne($ctx)
    try { return [string]$dc.Name } finally { $dc.Dispose() }
}

function Get-MspkiGlobalCatalogName {
    <#
    .SYNOPSIS
    DNS name of a Global Catalog server of the current forest (System.DirectoryServices.ActiveDirectory).
    #>
    [CmdletBinding()]
    param()
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    try {
        $gc = $forest.FindGlobalCatalog()
        try { return [string]$gc.Name } finally { $gc.Dispose() }
    }
    finally { $forest.Dispose() }
}

function Get-MspkiForestRootName {
    <#
    .SYNOPSIS
    DNS name of the forest root domain (System.DirectoryServices.ActiveDirectory).
    #>
    [CmdletBinding()]
    param()
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    try { return [string]$forest.RootDomain.Name } finally { $forest.Dispose() }
}

function ConvertTo-MspkiDomainDistinguishedName {
    <#
    .SYNOPSIS
    Converts corp.example.test to DC=corp,DC=example,DC=test ('' when the name is empty or not a dotted DNS name).
    #>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$DnsName)
    $n = ([string]$DnsName).Trim().TrimEnd('.')
    if ($n -notmatch '^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$') { return '' }
    return (($n.Split('.') | ForEach-Object { 'DC=' + $_ }) -join ',')
}

function Find-MspkiRootDse {
    <#
    .SYNOPSIS
    Finds the naming contexts, trying several ways in turn and recording each attempt.

    .DESCRIPTION
    Order: serverless LDAP://RootDSE, a domain controller from the DC locator, LDAP://<domain DNS name>/RootDSE, a Global Catalog,
    and last the Configuration naming context built from the forest root domain name (Inferred). Stops at the first success. One
    failed attempt never ends the search. Returns Root (or $null), Attempts (name, outcome, detail, HResult, path), Method
    (the attempt that worked) and Constructed.
    #>
    [CmdletBinding()]
    param([string]$ComputerDomain = '')
    $attempts = New-Object System.Collections.ArrayList
    $try = {
        param([string]$Name, [scriptblock]$Body)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $r = & $Body
            [void]$attempts.Add([pscustomobject]@{ Name = $Name; Outcome = 'Success'; Detail = ''; HResult = ''; Path = $r.Path })
            Add-MspkiMethodOutcome -Method ('AD:RootDSE:{0}' -f $Name) -Outcome 'Success' -Detail $r.Path -ElapsedMs $sw.ElapsedMilliseconds
            return $r
        }
        catch {
            $ei = Get-MspkiErrorInfo $_
            $detail = '{0} {1}: {2}' -f $ei.ExceptionType, $ei.HResult, $ei.Message
            [void]$attempts.Add([pscustomobject]@{ Name = $Name; Outcome = $ei.Class; Detail = $detail; HResult = $ei.HResult; Path = '' })
            Add-MspkiMethodOutcome -Method ('AD:RootDSE:{0}' -f $Name) -Outcome $ei.Class -Detail $detail -ElapsedMs $sw.ElapsedMilliseconds
            return $null
        }
    }
    $steps = @(
        @{ Name = 'Serverless'; Body = { $p = 'LDAP://RootDSE'; [pscustomobject]@{ Path = $p; Root = (Get-MspkiRootDse -Path $p) } } },
        @{ Name = 'DomainController'; Body = {
            $dc = Get-MspkiDomainControllerName
            if (-not $dc) { throw 'The DC locator returned no domain controller.' }
            $p = 'LDAP://{0}/RootDSE' -f $dc
            [pscustomobject]@{ Path = $p; Root = (Get-MspkiRootDse -Path $p) } } },
        @{ Name = 'DomainDnsName'; Body = {
            if (-not $ComputerDomain) { throw 'The domain DNS name of this computer is not known.' }
            $p = 'LDAP://{0}/RootDSE' -f $ComputerDomain
            [pscustomobject]@{ Path = $p; Root = (Get-MspkiRootDse -Path $p) } } },
        @{ Name = 'GlobalCatalog'; Body = {
            $gc = Get-MspkiGlobalCatalogName
            if (-not $gc) { throw 'No Global Catalog was found.' }
            $p = 'GC://{0}/RootDSE' -f $gc
            [pscustomobject]@{ Path = $p; Root = (Get-MspkiRootDse -Path $p) } } })
    foreach ($s in $steps) {
        $r = & $try $s.Name $s.Body
        if ($null -ne $r) {
            return [pscustomobject]@{ Root = $r.Root; Attempts = @($attempts); Method = $s.Name; Constructed = $false }
        }
    }
    # Last resort: no directory answered. Build the Configuration NC from the forest root domain name (or, when even that is
    # unknown, the domain of this computer). The result is a guess: the next stages show whether a domain controller serves it.
    $r = & $try 'ConstructedFromName' {
        $name = ''
        $source = 'forest root domain'
        try { $name = Get-MspkiForestRootName } catch { $name = '' }
        if (-not $name) { $name = $ComputerDomain; $source = 'domain of this computer' }
        $nc = ConvertTo-MspkiDomainDistinguishedName $name
        if (-not $nc) { throw 'No forest or domain DNS name is known, so no naming context can be built.' }
        $cfg = 'CN=Configuration,{0}' -f $nc
        $def = ConvertTo-MspkiDomainDistinguishedName $ComputerDomain
        if (-not $def) { $def = $nc }
        [pscustomobject]@{ Path = ('built from the {0}' -f $source); Root = [pscustomobject][ordered]@{
            configurationNamingContext = $cfg; rootDomainNamingContext = $nc; defaultNamingContext = $def
            schemaNamingContext = ('CN=Schema,{0}' -f $cfg); dnsHostName = ''; serverName = ''; currentTime = ''
            domainControllerFunctionality = '' } }
    }
    if ($null -ne $r) {
        return [pscustomobject]@{ Root = $r.Root; Attempts = @($attempts); Method = 'ConstructedFromName'; Constructed = $true }
    }
    return [pscustomobject]@{ Root = $null; Attempts = @($attempts); Method = ''; Constructed = $false }
}

function Get-MspkiForestInfo {
    <#
    .SYNOPSIS
    Current forest, its domains and the trusts of the forest and the current domain
    (System.DirectoryServices.ActiveDirectory, read-only).
    #>
    [CmdletBinding()]
    param()
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    try {
        $domains = @($forest.Domains | ForEach-Object { ([string]$_.Name).ToLowerInvariant() })
        $trusts = New-Object System.Collections.ArrayList
        $trustErrors = New-Object System.Collections.ArrayList
        try {
            foreach ($t in $forest.GetAllTrustRelationships()) {
                [void]$trusts.Add([pscustomobject]@{
                    Source = 'Forest'; TargetName = ([string]$t.TargetName).ToLowerInvariant()
                    TrustType = [string]$t.TrustType; TrustDirection = [string]$t.TrustDirection
                })
            }
        }
        catch { [void]$trustErrors.Add((Get-MspkiErrorInfo $_)) }
        try {
            $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            try {
                foreach ($t in $dom.GetAllTrustRelationships()) {
                    [void]$trusts.Add([pscustomobject]@{
                        Source = 'Domain'; TargetName = ([string]$t.TargetName).ToLowerInvariant()
                        TrustType = [string]$t.TrustType; TrustDirection = [string]$t.TrustDirection
                    })
                }
            }
            finally { $dom.Dispose() }
        }
        catch { [void]$trustErrors.Add((Get-MspkiErrorInfo $_)) }
        return [pscustomobject]@{
            Name        = ([string]$forest.Name).ToLowerInvariant()
            RootDomain  = ([string]$forest.RootDomain.Name).ToLowerInvariant()
            ForestMode  = [string]$forest.ForestMode
            Domains     = $domains
            Trusts      = @($trusts)
            TrustErrors = @($trustErrors)
        }
    }
    finally { $forest.Dispose() }
}

function Get-MspkiComputerSiteName {
    [CmdletBinding()]
    param()
    $site = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
    try { return [string]$site.Name } finally { $site.Dispose() }
}

function Get-MspkiAdContext {
    <#
    .SYNOPSIS
    Discovers the AD context for the run: domain membership, domain controller, naming contexts,
    forest, domains, trusts and site. Returns Data (context) and Findings. With -SkipNetwork the live domain controllers are not read
    from DNS: only the selected domain controller may then receive a bind, so the list is not needed.
    #>
    [CmdletBinding()]
    param([int]$TimeoutSeconds = 5, [switch]$SkipNetwork)

    $findings = New-Object System.Collections.ArrayList
    $ctx = [ordered]@{
        Ready          = $false
        IsDomainJoined = $false
        ComputerDomain = ''
        DomainController = ''
        ConfigNC       = ''
        RootDomainNC   = ''
        DefaultNC      = ''
        SchemaNC       = ''
        PksDN          = ''
        Forest         = ''
        ForestSource   = ''
        ForestMode     = ''
        Domain         = ''
        ForestDomains  = @()
        DomainControllers = @()
        Trusts         = @()
        TrustedDomains = @()
        Site           = ''
        DcTimeUtc      = ''
    }
    $ldapTimeout = [math]::Max(10, $TimeoutSeconds * 3)

    # 1. Domain membership (local, read-only).
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $cs = Get-MspkiComputerSystemInfo
        Add-MspkiMethodOutcome -Method 'Local:Win32_ComputerSystem' -Outcome 'Success' -ElapsedMs $sw.ElapsedMilliseconds
        if (-not $cs.PartOfDomain) {
            [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo (New-MspkiErrorInfo -Class 'NotDomainJoined') `
                -Category 'ADDependency' -Role 'Computer' -Target ([Environment]::MachineName) `
                -Sources 'Local:Win32_ComputerSystem' -Action 'discovering Active Directory' -Scope 'Local' `
                -Notes 'Run the tool on a domain-joined computer. AD CS discovery needs the AD Configuration partition.'))
            Add-MspkiRunLimit -Text 'This computer is not domain-joined: AD and CA discovery did not run.'
            return [pscustomobject]@{ Data = [pscustomobject]$ctx; Findings = @($findings) }
        }
        $ctx.IsDomainJoined = $true
        $ctx.ComputerDomain = ([string]$cs.Domain).ToLowerInvariant()
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'Local:Win32_ComputerSystem' -Outcome $ei.Class -Detail $ei.Message
        # Not fatal: RootDSE below shows whether AD can be reached.
        $ctx.IsDomainJoined = $true
    }

    # 2. RootDSE: domain controller and naming contexts. Several ways are tried in turn (see Find-MspkiRootDse); every attempt is
    # logged and listed in the evidence.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $found = Find-MspkiRootDse -ComputerDomain $ctx.ComputerDomain
    $attemptEvidence = @($found.Attempts | ForEach-Object {
        if ($_.Outcome -eq 'Success') { 'RootDSE attempt {0}: succeeded ({1})' -f $_.Name, $_.Path }
        else { 'RootDSE attempt {0}: {1}; {2}' -f $_.Name, $_.Outcome, $_.Detail }
    })
    if ($null -eq $found.Root) {
        $first = @($found.Attempts)[0]
        $ei = New-MspkiErrorInfo -Class $first.Outcome -Message $first.Detail -HResult $first.HResult
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADDependency' -Role 'DomainController' `
            -Target $(if ($ctx.ComputerDomain) { $ctx.ComputerDomain } else { 'RootDSE' }) -Sources 'AD:RootDSE' `
            -Action 'reading RootDSE from a domain controller (every method failed)' -UnreachableStatus 'Fail' -Scope 'Local' `
            -Evidence $attemptEvidence))
        Add-MspkiRunLimit -Text 'RootDSE could not be read and no naming context could be built: AD and CA discovery did not run.'
        return [pscustomobject]@{ Data = [pscustomobject]$ctx; Findings = @($findings) }
    }
    $root = $found.Root
    $ctx.DomainController = ConvertTo-MspkiHostName $root.dnsHostName
    $ctx.ConfigNC = $root.configurationNamingContext
    $ctx.RootDomainNC = $root.rootDomainNamingContext
    $ctx.DefaultNC = $root.defaultNamingContext
    $ctx.SchemaNC = $root.schemaNamingContext
    $ctx.PksDN = 'CN=Public Key Services,CN=Services,{0}' -f $root.configurationNamingContext
    $ctx.Domain = ConvertFrom-MspkiDistinguishedName $root.defaultNamingContext
    $ctx.Forest = ConvertFrom-MspkiDistinguishedName $root.rootDomainNamingContext
    $ctx.ForestSource = 'AD:RootDSE'
    $ctx.DcTimeUtc = ConvertTo-MspkiIsoTime $root.currentTime
    if (-not $ctx.ComputerDomain) { $ctx.ComputerDomain = $ctx.Domain }
    $ctx.Ready = $true
    Set-MspkiRunValue -Name 'DomainController' -Value $ctx.DomainController
    Set-MspkiRunValue -Name 'Domain' -Value $ctx.Domain
    Set-MspkiRunValue -Name 'Forest' -Value $ctx.Forest
    if ($found.Constructed) {
        $ctx.ForestSource = 'Constructed'
        [void]$findings.Add((New-MspkiFinding -Category 'ADDependency' -Role 'DomainController' -Target $ctx.Domain `
            -Status 'Warning' -StatusCode 'RETRIEVAL_FAIL' -Confidence 'Inferred' -Sources 'AD:RootDSE' -Scope 'Local' `
            -Message 'No domain controller answered for RootDSE. The Configuration naming context was built from the domain name; the next stages show whether a domain controller serves it.' `
            -Layers @{ DiscoveryStatus = 'Warning' } -Evidence (@($attemptEvidence) + @(
                ('configurationNamingContext (built, not read): {0}' -f $root.configurationNamingContext),
                'The domain controller is not known: later reads use a serverless bind.'))))
    }
    else {
        Add-MspkiMethodOutcome -Method 'AD:RootDSE' -Outcome 'Success' -Detail ('{0} via {1}' -f $root.dnsHostName, $found.Method) -ElapsedMs $sw.ElapsedMilliseconds
        [void]$findings.Add((New-MspkiFinding -Category 'ADDependency' -Role 'DomainController' -Target $ctx.DomainController `
            -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' -Sources 'AD:RootDSE' -Scope 'Local' `
            -Message ('Using domain controller {0} for domain {1}.' -f $ctx.DomainController, $ctx.Domain) `
            -Layers @{ DiscoveryStatus = 'Pass' } -Evidence (@(
                ('dnsHostName: {0}' -f $root.dnsHostName),
                ('defaultNamingContext: {0}' -f $root.defaultNamingContext),
                ('rootDomainNamingContext: {0}' -f $root.rootDomainNamingContext),
                ('configurationNamingContext: {0}' -f $root.configurationNamingContext),
                ('domainControllerFunctionality: {0}' -f $root.domainControllerFunctionality),
                ('Bind: {0}' -f $found.Method)) + @($attemptEvidence))))
    }

    # 3. Forest, domains and trusts.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $fi = Get-MspkiForestInfo
        Add-MspkiMethodOutcome -Method 'AD:Forest' -Outcome 'Success' -Detail $fi.Name -ElapsedMs $sw.ElapsedMilliseconds
        $ctx.Forest = $fi.Name
        $ctx.ForestSource = 'AD:Forest'
        $ctx.ForestMode = $fi.ForestMode
        $ctx.ForestDomains = @($fi.Domains)
        $ctx.Trusts = @($fi.Trusts)
        $ctx.TrustedDomains = @($fi.Trusts | ForEach-Object { $_.TargetName } | Where-Object { $_ } | Select-Object -Unique)
        Set-MspkiRunValue -Name 'Forest' -Value $ctx.Forest
        $ev = @(('Forest root domain: {0}' -f $fi.RootDomain), ('Forest mode: {0}' -f $fi.ForestMode))
        $ev += @($fi.Domains | ForEach-Object { 'Domain: {0}' -f $_ })
        $ev += @($fi.Trusts | ForEach-Object { 'Trust ({0}): {1} {2} {3}' -f $_.Source, $_.TargetName, $_.TrustType, $_.TrustDirection })
        foreach ($te in $fi.TrustErrors) {
            $ev += ('Trusts not fully read: {0} {1}' -f $te.Class, $te.Message)
            Add-MspkiMethodOutcome -Method 'AD:Trusts' -Outcome $te.Class -Detail $te.Message
        }
        [void]$findings.Add((New-MspkiFinding -Category 'ADDependency' -Role 'Forest' -Target $ctx.Forest `
            -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' -Sources 'AD:Forest' -Scope 'Local' `
            -Message ('Forest {0}: {1} domain(s), {2} trust(s).' -f $ctx.Forest, @($fi.Domains).Count, @($fi.Trusts).Count) `
            -Layers @{ DiscoveryStatus = 'Pass' } -Evidence $ev))
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:Forest' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        $ctx.ForestDomains = @($ctx.Domain)
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADDependency' -Role 'Forest' -Target $ctx.Forest `
            -Sources 'AD:Forest' -Action 'reading the forest, its domains and trusts' -Scope 'Local' `
            -Notes 'The forest name below comes from RootDSE (rootDomainNamingContext). Scope checks only know the current domain.'))
        Add-MspkiRunLimit -Text 'Forest domains and trusts were not read: hosts in other forest domains may show as External.'
    }

    # 3b. The forest's domain controllers (Configuration partition). Only these and the selected domain controller may receive a
    # directory bind for an LDAP URL that names a host, unless a verified object names it (audit 2 H1).
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ($found.Constructed) {
        # No domain controller answered: there is nothing to read the list from, and no LDAP URL that names a host is contacted.
        Add-MspkiMethodOutcome -Method 'AD:Sites:Servers' -Outcome 'Skipped' -Detail 'no domain controller answered for RootDSE'
    }
    elseif ($SkipNetwork) {
        $ctx.DomainControllers = @($ctx.DomainController | Where-Object { $_ })
        Add-MspkiMethodOutcome -Method 'AD:Sites:Servers' -Outcome 'Skipped' -Detail '-SkipNetwork: only the selected domain controller is contacted'
    }
    else { try {
        # Only live domain controllers count: a server object with NTDS Settings that DNS SRV records (or the DC locator) also name
        # (audit 2 verification N5). Stale server objects are reported, never contacted.
        $doms = @($ctx.ForestDomains | Where-Object { $_ })
        if ($doms.Count -eq 0 -and $ctx.Domain) { $doms = @($ctx.Domain) }
        $dcInfo = Get-MspkiForestDomainController -Server $ctx.DomainController -ConfigNC $ctx.ConfigNC -TimeoutSeconds $ldapTimeout -Domains $doms -Detail
        $ctx.DomainControllers = @($dcInfo.Names)
        if ($ctx.DomainController -and $ctx.DomainControllers -notcontains $ctx.DomainController) { $ctx.DomainControllers = @($ctx.DomainControllers) + $ctx.DomainController }
        Add-MspkiMethodOutcome -Method 'AD:Sites:Servers' -Outcome 'Success' -ElapsedMs $sw.ElapsedMilliseconds `
            -Detail ('{0} live domain controller(s) ({1}); {2} server object(s) not counted' -f @($ctx.DomainControllers).Count, $dcInfo.Live.Method, @($dcInfo.Excluded).Count)
        if (@($dcInfo.Live.Names).Count -eq 0 -and @($dcInfo.Live.Errors).Count -gt 0) {
            Write-MspkiLog -Level Warning -Message ('Live domain controllers not read: {0}' -f (@($dcInfo.Live.Errors) -join '; '))
            Add-MspkiRunLimit -Text 'The forest''s live domain controllers could not be read from DNS: LDAP URLs that name a domain controller other than the selected one were contacted only when trusted evidence named them.'
        }
        if (@($dcInfo.Excluded).Count -gt 0) {
            [void]$findings.Add((New-MspkiFinding -Category 'ADDependency' -Role 'DomainController' -Target $ctx.Forest `
                -Status 'Information' -StatusCode 'STALE_REFERENCE' -Confidence 'Confirmed' -Sources 'AD:Sites:Servers' -Scope 'Local' `
                -Message ('{0} server object(s) under CN=Sites were not counted as live domain controllers.' -f @($dcInfo.Excluded).Count) `
                -Layers @{ DiscoveryStatus = 'Pass' } -Evidence @($dcInfo.Excluded | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Reason }) `
                -Notes 'This tool never sends a directory bind to these names because of their server objects. A server object without NTDS Settings usually remains after a domain controller was removed without metadata cleanup; check it and remove it if the domain controller is gone.'))
        }
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:Sites:Servers' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        $ctx.DomainControllers = @($ctx.DomainController | Where-Object { $_ })
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADDependency' -Role 'DomainController' -Target $ctx.Forest `
            -Sources 'AD:Sites:Servers' -Action 'reading the forest''s domain controllers from the Configuration partition' -Scope 'Local' `
            -Notes 'LDAP URLs that name a domain controller other than the selected one are not contacted in this run.'))
        Add-MspkiRunLimit -Text 'The forest''s domain controllers were not read: LDAP URLs that name another domain controller were not contacted.'
    } }

    # 4. AD site of this computer.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ctx.Site = Get-MspkiComputerSiteName
        Set-MspkiRunValue -Name 'Site' -Value $ctx.Site
        Add-MspkiMethodOutcome -Method 'AD:ComputerSite' -Outcome 'Success' -Detail $ctx.Site -ElapsedMs $sw.ElapsedMilliseconds
        [void]$findings.Add((New-MspkiFinding -Category 'ADDependency' -Role 'Site' -Target $ctx.Site `
            -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' -Sources 'AD:ComputerSite' -Scope 'Local' `
            -Message ('This computer is in AD site {0}.' -f $ctx.Site) -Layers @{ DiscoveryStatus = 'Pass' }))
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:ComputerSite' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADDependency' -Role 'Site' -Target 'Computer site' `
            -Sources 'AD:ComputerSite' -Action 'reading the AD site of this computer' -Scope 'Local'))
    }

    return [pscustomobject]@{ Data = [pscustomobject]$ctx; Findings = @($findings) }
}
