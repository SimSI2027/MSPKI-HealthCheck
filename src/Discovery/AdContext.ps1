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
    Reads RootDSE through a serverless bind (the DC locator picks the domain controller).
    #>
    [CmdletBinding()]
    param([int]$TimeoutSeconds = 30)
    $props = @('configurationNamingContext', 'rootDomainNamingContext', 'defaultNamingContext',
        'schemaNamingContext', 'dnsHostName', 'serverName', 'currentTime', 'domainControllerFunctionality')
    $r = @(Get-MspkiLdapObject -BaseDN 'RootDSE' -Scope Base -Properties $props -TimeoutSeconds $TimeoutSeconds)
    if ($r.Count -eq 0) { throw 'RootDSE returned no data.' }
    $rec = $r[0]
    $out = [ordered]@{}
    foreach ($p in $props) { $out[$p] = [string](Get-MspkiLdapValue -Record $rec -Name $p) }
    if (-not $out['configurationNamingContext']) { throw 'RootDSE has no configurationNamingContext.' }
    return [pscustomobject]$out
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

    # 2. RootDSE: domain controller and naming contexts.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $root = Get-MspkiRootDse -TimeoutSeconds $ldapTimeout
        Add-MspkiMethodOutcome -Method 'AD:RootDSE' -Outcome 'Success' -Detail $root.dnsHostName -ElapsedMs $sw.ElapsedMilliseconds
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
        [void]$findings.Add((New-MspkiFinding -Category 'ADDependency' -Role 'DomainController' -Target $ctx.DomainController `
            -Status 'Information' -StatusCode 'OK' -Confidence 'Confirmed' -Sources 'AD:RootDSE' -Scope 'Local' `
            -Message ('Using domain controller {0} for domain {1}.' -f $ctx.DomainController, $ctx.Domain) `
            -Layers @{ DiscoveryStatus = 'Pass' } -Evidence @(
                ('dnsHostName: {0}' -f $root.dnsHostName),
                ('defaultNamingContext: {0}' -f $root.defaultNamingContext),
                ('rootDomainNamingContext: {0}' -f $root.rootDomainNamingContext),
                ('configurationNamingContext: {0}' -f $root.configurationNamingContext),
                ('domainControllerFunctionality: {0}' -f $root.domainControllerFunctionality),
                ('Bind: serverless (DC locator), time limit {0} s' -f $ldapTimeout))))
    }
    catch {
        $ei = Get-MspkiErrorInfo $_
        Add-MspkiMethodOutcome -Method 'AD:RootDSE' -Outcome $ei.Class -Detail $ei.Message -ElapsedMs $sw.ElapsedMilliseconds
        [void]$findings.Add((New-MspkiErrorFinding -ErrorInfo $ei -Category 'ADDependency' -Role 'DomainController' `
            -Target $(if ($ctx.ComputerDomain) { $ctx.ComputerDomain } else { 'RootDSE' }) -Sources 'AD:RootDSE' `
            -Action 'reading RootDSE from a domain controller' -UnreachableStatus 'Fail' -Scope 'Local'))
        Add-MspkiRunLimit -Text 'RootDSE could not be read: AD and CA discovery did not run.'
        return [pscustomobject]@{ Data = [pscustomobject]$ctx; Findings = @($findings) }
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
