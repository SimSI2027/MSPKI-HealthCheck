# NDES evidence without the CA database view (ROADMAP D4, evidence 2): an NDES server enrolls for its own RA certificates from the
# "CEP Encryption" and "Exchange Enrollment Agent (Offline request)" templates (or copies with the same purpose), so the accounts that
# hold Enroll on those templates name the NDES service account or computer. Each such account is read with one targeted lookup by SID
# (<SID=...>, base scope, on the selected domain controller: never a search over all computers), and its dNSHostName or HTTP/ SPNs
# name the host. Group members (one level) and the computers that may use a group managed service account are read the same way.
# Read-only: LDAP reads of objects that an ACE named; nothing else is contacted here.

$script:MspkiCertRequestAgentOid = '1.3.6.1.4.1.311.20.2.1'
$script:MspkiNdesStandardTemplate = @{ 'cepencryption' = 'CEP Encryption'; 'enrollmentagentoffline' = 'Exchange Enrollment Agent (Offline request)' }
$script:MspkiNdesAccountProperties = @('objectClass', 'sAMAccountName', 'distinguishedName', 'dNSHostName', 'servicePrincipalName', 'userAccountControl', 'member', 'msDS-GroupMSAMembership')

function Test-MspkiNdesRaTemplate {
    <#
    .SYNOPSIS
    Whether a template is one NDES uses for its RA certificates: $null, or { Name; DisplayName; Kind (Standard / Equivalent); Why }.
    .DESCRIPTION
    Standard: the template is CEPEncryption or EnrollmentAgentOffline. Equivalent: a copy with the same purpose, i.e. the Certificate
    Request Agent EKU (1.3.6.1.4.1.311.20.2.1) and the subject supplied in the request (msPKI-Certificate-Name-Flag bit 1), which is what
    both NDES templates have. The online Enrollment Agent template builds the subject from AD and is not matched.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Template)
    $n = ([string]$Template.Name).ToLowerInvariant()
    if ($script:MspkiNdesStandardTemplate.ContainsKey($n)) {
        return [pscustomobject][ordered]@{ Name = $Template.Name; DisplayName = $Template.DisplayName; Kind = 'Standard'; Why = ('the standard NDES template "{0}"' -f $script:MspkiNdesStandardTemplate[$n]) }
    }
    $ekus = @(@($Template.Eku) + @($Template.ApplicationPolicies) | Where-Object { $_ })
    $flag = [int64]0
    try { $flag = [int64]$Template.NameFlag } catch { $flag = 0 }
    if ($ekus -contains $script:MspkiCertRequestAgentOid -and ($flag -band 1) -ne 0) {
        return [pscustomobject][ordered]@{ Name = $Template.Name; DisplayName = $Template.DisplayName; Kind = 'Equivalent'
            Why = 'Certificate Request Agent EKU with the subject supplied in the request: the purpose of the NDES templates CEP Encryption and Exchange Enrollment Agent (Offline request)' }
    }
    return $null
}

function Test-MspkiDefaultAdminSid {
    # The built-in administrative principals that every template grants by default; they do not point at an NDES host.
    param([AllowEmptyString()][string]$Sid)
    if ($Sid -in @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-9', 'S-1-3-0')) { return $true }
    return ($Sid -match '^S-1-5-21-\d+-\d+-\d+-(498|512|516|518|519|521)$')
}

function Get-MspkiNdesTemplatePrincipal {
    <#
    .SYNOPSIS
    Who holds Enroll on the NDES RA templates. Pure. Returns { Templates; Principals } where each principal is
    { Sid; Principal; Class (Candidate / DefaultAdmin / Broad); BroadLabel; Templates[] }.
    #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][object[]]$Templates = @(), [AllowEmptyCollection()][string[]]$PublishedNames = @())
    $tpl = New-Object System.Collections.ArrayList
    $by = [ordered]@{}
    foreach ($t in @($Templates | Where-Object { $null -ne $_ })) {
        $ra = Test-MspkiNdesRaTemplate -Template $t
        if ($null -eq $ra) { continue }
        $pub = @($PublishedNames | Where-Object { $_ -ieq $t.Name }).Count -gt 0
        [void]$tpl.Add([pscustomobject][ordered]@{ Name = $t.Name; DisplayName = $t.DisplayName; Kind = $ra.Kind; Why = $ra.Why; Published = $pub; AclRead = (-not $t.AclError) })
        if (-not $pub) { continue }
        foreach ($ace in @($t.Acl | Where-Object { $null -ne $_ })) {
            if (-not (Test-MspkiAceGrant -Ace $ace -Right 'Enroll')) { continue }
            $sid = [string]$ace.Sid
            if (-not $by.Contains($sid)) {
                $broad = Get-MspkiBroadPrincipal -Sid $sid
                $cls = $(if (Test-MspkiDefaultAdminSid -Sid $sid) { 'DefaultAdmin' } elseif ($broad) { 'Broad' } else { 'Candidate' })
                $by[$sid] = [pscustomobject][ordered]@{ Sid = $sid; Principal = [string]$ace.Principal; Class = $cls; BroadLabel = $broad; Templates = (New-Object System.Collections.ArrayList) }
            }
            if (-not $by[$sid].Templates.Contains([string]$t.Name)) { [void]$by[$sid].Templates.Add([string]$t.Name) }
        }
    }
    return [pscustomobject][ordered]@{ Templates = @($tpl); Principals = @($by.Values) }
}

function ConvertFrom-MspkiNdesAccountRecord {
    <#
    .SYNOPSIS
    One AD account (LDAP record of an object named by SID) as plain data. Pure: Class (computer / gmsa / msa / group / user), SamAccountName,
    DistinguishedName, Domain (from the DN), DnsHostName, Spns, HttpSpnHosts (host part of HTTP/ SPNs), Disabled, Members (DNs), AllowedSids
    (who may read a gMSA's password: the SIDs in msDS-GroupMSAMembership; the password itself is never read).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Record)
    $g = { param($n) Get-MspkiLdapValue -Record $Record -Name $n }
    # Get-MspkiLdapValues returns the value array as one object; assigning and emitting it unrolls the values.
    $m = { param($n) $v = Get-MspkiLdapValues -Record $Record -Name $n; $v }
    $oc = @(& $m 'objectClass' | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $class = $(if ($oc -contains 'msds-groupmanagedserviceaccount') { 'gmsa' } elseif ($oc -contains 'msds-managedserviceaccount') { 'msa' } elseif ($oc -contains 'computer') { 'computer' } elseif ($oc -contains 'group') { 'group' } else { 'user' })
    $dn = [string](& $g 'distinguishedName')
    $dom = (@([regex]::Matches($dn, '(?i)(?:^|,)DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value }) -join '.').ToLowerInvariant()
    $spns = @(& $m 'servicePrincipalName' | ForEach-Object { [string]$_ } | Where-Object { $_ })
    $http = @($spns | ForEach-Object { $x = [regex]::Match($_, '^(?i)HTTP/([^:/]+)'); if ($x.Success) { $x.Groups[1].Value.ToLowerInvariant().TrimEnd('.') } } | Where-Object { $_ } | Select-Object -Unique)
    $uac = 0
    $u = & $g 'userAccountControl'
    if ($null -ne $u) { $uac = [int64](ConvertTo-MspkiUInt32 $u) }
    $allowed = @()
    $sd = & $g 'msDS-GroupMSAMembership'
    if ($null -ne $sd -and $sd -is [byte[]]) {
        try { $allowed = @((ConvertFrom-MspkiSecurityDescriptor -Bytes ([byte[]]$sd)).Aces | Where-Object { $_.Type -eq 'Allow' } | ForEach-Object { $_.Sid } | Select-Object -Unique) } catch { $allowed = @() }
    }
    return [pscustomobject][ordered]@{
        Class = $class; SamAccountName = [string](& $g 'sAMAccountName'); DistinguishedName = $dn; Domain = $dom; DnsHostName = ([string](& $g 'dNSHostName')).ToLowerInvariant().TrimEnd('.')
        Spns = $spns; HttpSpnHosts = $http; Disabled = (($uac -band 2) -ne 0); Members = @(& $m 'member' | ForEach-Object { [string]$_ }); AllowedSids = $allowed
    }
}

function Get-MspkiNdesAccountHostName {
    <#
    .SYNOPSIS
    The host names one account points at, with how each was found. Pure. Returns { Host; How; Constructed }.
    .DESCRIPTION
    A computer account names itself (dNSHostName). A user or managed service account that runs NDES in IIS has HTTP/<host> SPNs; a
    short SPN host is completed with the account's own domain (Constructed: the caller checks it in DNS) unless the full name is also there.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Account)
    $out = New-Object System.Collections.ArrayList
    if ($Account.Class -eq 'computer' -and $Account.DnsHostName) {
        [void]$out.Add([pscustomobject][ordered]@{ Host = $Account.DnsHostName; How = ('dNSHostName of the computer account {0}' -f $Account.SamAccountName); Constructed = $false })
    }
    $full = @($Account.HttpSpnHosts | Where-Object { $_ -like '*.*' })
    foreach ($h in $full) { [void]$out.Add([pscustomobject][ordered]@{ Host = $h; How = ('SPN HTTP/{0} on {1} ({2})' -f $h, $Account.SamAccountName, $Account.Class); Constructed = $false }) }
    foreach ($s in @($Account.HttpSpnHosts | Where-Object { $_ -notlike '*.*' })) {
        if (@($full | Where-Object { ($_ -split '\.')[0] -eq $s }).Count -gt 0) { continue }
        if (-not $Account.Domain) { continue }
        [void]$out.Add([pscustomobject][ordered]@{ Host = ('{0}.{1}' -f $s, $Account.Domain); How = ('SPN HTTP/{0} on {1} ({2}), completed with the account''s domain {3}' -f $s, $Account.SamAccountName, $Account.Class, $Account.Domain); Constructed = $true })
    }
    $seen = @{}
    return @($out | Where-Object { if ($seen.ContainsKey($_.Host)) { $false } else { $seen[$_.Host] = $true; $true } })
}

function Read-MspkiNdesAccount {
    <#
    .SYNOPSIS
    Reads one AD object by SID or DN (base scope, read-only) on the selected domain controller. Returns { Account; Status (Found /
    NotFound / Error); Error }. NotFound means the object was deleted or this account may not read it; the two cannot be told apart.
    #>
    [CmdletBinding()]
    param([string]$Sid = '', [string]$DistinguishedName = '', [string]$Server = '', [int]$TimeoutSeconds = 10)
    $base = $(if ($Sid) { '<SID={0}>' -f $Sid } else { $DistinguishedName })
    try {
        $recs = @(Get-MspkiLdapObject -Server $Server -BaseDN $base -Scope Base -Properties $script:MspkiNdesAccountProperties -TimeoutSeconds $TimeoutSeconds)
        if ($recs.Count -eq 0) { return [pscustomobject]@{ Account = $null; Status = 'NotFound'; Error = 'No object returned.' } }
        return [pscustomobject]@{ Account = (ConvertFrom-MspkiNdesAccountRecord -Record $recs[0]); Status = 'Found'; Error = '' }
    }
    catch {
        $e = $_.Exception
        $hr = 0
        while ($null -ne $e) { if ($e -is [System.Runtime.InteropServices.COMException]) { $hr = $e.ErrorCode }; $e = $e.InnerException }
        $msg = (Get-MspkiErrorInfo $_).Message
        if ($hr -eq -2147016656 -or $msg -match '(?i)no such object') { return [pscustomobject]@{ Account = $null; Status = 'NotFound'; Error = 'There is no such object on the server.' } }
        return [pscustomobject]@{ Account = $null; Status = 'Error'; Error = $msg }
    }
}

function Find-MspkiNdesTemplateAccountHost {
    <#
    .SYNOPSIS
    NDES host candidates from the Enroll permissions of the NDES RA templates: reads every candidate principal by SID (and one level of
    group members, and the computers allowed to use a gMSA), and returns { Templates; Principals; Hosts; Lookups }.
    Hosts = { Host; Constructed; How[]; Principals[]; Templates[] }. Lookups counts the targeted LDAP reads.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Inventory, [int]$TimeoutSeconds = 5, [int]$MaxMembers = 25)
    $ctx = $Inventory.AdContext
    $server = $(if ($null -ne $ctx -and $ctx.DomainController) { [string]$ctx.DomainController } else { '' })
    $published = @($Inventory.EnterpriseCAs | Where-Object { $null -ne $_ } | ForEach-Object { @($_.Templates) } | Where-Object { $_ } | Select-Object -Unique)
    $tp = Get-MspkiNdesTemplatePrincipal -Templates @($Inventory.Templates) -PublishedNames $published
    $hosts = [ordered]@{}
    $lookups = 0
    $addHost = {
        param($h, $principalText, $templates)
        if (-not $hosts.Contains($h.Host)) { $hosts[$h.Host] = [pscustomobject][ordered]@{ Host = $h.Host; Constructed = $h.Constructed; How = (New-Object System.Collections.ArrayList); Principals = (New-Object System.Collections.ArrayList); Templates = (New-Object System.Collections.ArrayList) } }
        $x = $hosts[$h.Host]
        if (-not $h.Constructed) { $x.Constructed = $false }
        if (-not $x.How.Contains($h.How)) { [void]$x.How.Add($h.How) }
        if (-not $x.Principals.Contains($principalText)) { [void]$x.Principals.Add($principalText) }
        foreach ($t in $templates) { if (-not $x.Templates.Contains($t)) { [void]$x.Templates.Add($t) } }
    }
    foreach ($p in @($tp.Principals | Where-Object { $_.Class -eq 'Candidate' })) {
        if (Test-MspkiCancelled) { break }
        $lookups++
        $r = Read-MspkiNdesAccount -Sid $p.Sid -Server $server -TimeoutSeconds $TimeoutSeconds
        $p | Add-Member -NotePropertyName 'Lookup' -NotePropertyValue $r.Status -Force
        $p | Add-Member -NotePropertyName 'LookupError' -NotePropertyValue $r.Error -Force
        $p | Add-Member -NotePropertyName 'Account' -NotePropertyValue $r.Account -Force
        $p | Add-Member -NotePropertyName 'Hosts' -NotePropertyValue @() -Force
        $p | Add-Member -NotePropertyName 'Via' -NotePropertyValue @() -Force
        if ($r.Status -ne 'Found') { continue }
        $a = $r.Account
        $label = $(if ($a.SamAccountName) { $a.SamAccountName } else { $p.Principal })
        $found = @(Get-MspkiNdesAccountHostName -Account $a)
        $via = New-Object System.Collections.ArrayList
        if ($a.Class -eq 'group') {
            foreach ($dn in @($a.Members | Select-Object -First $MaxMembers)) {
                $lookups++
                $mr = Read-MspkiNdesAccount -DistinguishedName $dn -Server $server -TimeoutSeconds $TimeoutSeconds
                if ($mr.Status -ne 'Found') { continue }
                foreach ($h in (Get-MspkiNdesAccountHostName -Account $mr.Account)) {
                    $h.How = ('{0}, member of the group {1}' -f $h.How, $label); $found += $h
                    [void]$via.Add($mr.Account.SamAccountName)
                }
            }
        }
        if ($a.Class -eq 'gmsa') {
            foreach ($s in @($a.AllowedSids | Select-Object -First $MaxMembers)) {
                $lookups++
                $mr = Read-MspkiNdesAccount -Sid $s -Server $server -TimeoutSeconds $TimeoutSeconds
                if ($mr.Status -ne 'Found' -or $mr.Account.Class -ne 'computer' -or -not $mr.Account.DnsHostName) { continue }
                $found += [pscustomobject][ordered]@{ Host = $mr.Account.DnsHostName; How = ('computer {0} may use the group managed service account {1} (msDS-GroupMSAMembership)' -f $mr.Account.SamAccountName, $label); Constructed = $false }
            }
        }
        $p.Hosts = @($found | ForEach-Object { $_.Host } | Select-Object -Unique)
        $p.Via = @($via)
        foreach ($h in $found) { & $addHost $h ('{0} ({1})' -f $label, $a.Class) @($p.Templates) }
    }
    return [pscustomobject][ordered]@{ Templates = @($tp.Templates); Principals = @($tp.Principals); Hosts = @($hosts.Values); Lookups = $lookups; Server = $server }
}
