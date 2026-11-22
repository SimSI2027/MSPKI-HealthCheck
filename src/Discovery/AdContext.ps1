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

function Get-MspkiForestDomainController {
    <#
    .SYNOPSIS
    The DNS names of the forest's domain controllers: the server objects (with a dNSHostName) under CN=Sites of the Configuration
    partition, read with one subtree search on the selected domain controller. Read-only. These are the only named hosts, besides
    the selected domain controller, that an LDAP URL may reach without other proof (audit 2 H1).
    #>
    [CmdletBinding()]
    param([string]$Server = '', [Parameter(Mandatory = $true)][string]$ConfigNC, [int]$TimeoutSeconds = 15)
    $recs = @(Get-MspkiLdapObject -Server $Server -BaseDN ('CN=Sites,{0}' -f $ConfigNC) -Scope Subtree `
        -Filter '(&(objectClass=server)(dNSHostName=*))' -Properties @('dNSHostName') -TimeoutSeconds $TimeoutSeconds)
    $out = @()
    foreach ($r in $recs) {
        $h = ConvertTo-MspkiHostName ([string](Get-MspkiLdapValue -Record $r -Name 'dNSHostName'))
        if ($h -and $out -notcontains $h) { $out += $h }
    }
    return , $out
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
    forest, domains, trusts and site. Returns Data (context) and Findings.
    #>
    [CmdletBinding()]
    param([int]$TimeoutSeconds = 5)

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
    else { try {
        $ctx.DomainControllers = @(Get-MspkiForestDomainController -Server $ctx.DomainController -ConfigNC $ctx.ConfigNC -TimeoutSeconds $ldapTimeout)
        if ($ctx.DomainController -and $ctx.DomainControllers -notcontains $ctx.DomainController) { $ctx.DomainControllers = @($ctx.DomainControllers) + $ctx.DomainController }
        Add-MspkiMethodOutcome -Method 'AD:Sites:Servers' -Outcome 'Success' -Detail ('{0} domain controller(s)' -f @($ctx.DomainControllers).Count) -ElapsedMs $sw.ElapsedMilliseconds
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
