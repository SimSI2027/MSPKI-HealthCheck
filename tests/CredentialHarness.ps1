# Credential harness (audit 2 verification, Fix log 2 item 5). Records every directory bind, every HTTP request (and the loopback
# server records any credentials sent) and every TLS handshake the tool attempts, so a test can prove that no Windows credentials go to
# a host because of an object that was not verified.
#
# How it works, and why it does not depend on new functions of the tool:
# - Directory: the tool builds every DirectoryEntry and DirectorySearcher with New-Object (src/Discovery/Ldap.ps1, AdContext.ps1).
#   The harness mocks New-Object for those two types inside the module and returns fakes. Nothing reaches a network. A fake searcher's
#   FindAll and a fake entry's RefreshCache record a bind (the moment the real classes bind with the running user's credentials) and
#   ask $script:TestDirectoryHandler for the answer.
# - Referrals are modelled on the documented search preference (ADS_SEARCHPREF_CHASE_REFERRALS): when the handler answers with a
#   referral and the searcher's ReferralChasing includes External (the .NET default) the fake follows it, as the directory client would,
#   and records a "ChasedBind" to the referred host. With None it throws 0x8007202B ("a referral was returned from the server"). A live
#   chase could not be reproduced in the lab: a base search for a DN of another domain fails at bind time with 0x8007202B for None,
#   External and All alike (docs/AUDIT-2-VERIFY.md, Fix log 2).
# - TLS and HTTP: Test-MspkiTlsEndpoint and Invoke-MspkiHttpGet (the only places that open a TLS stream or an HTTP request) are wrapped:
#   each call is recorded, then the original runs.
# Hosts are example.test names and 127.0.0.1 only.

$script:CredentialLog = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
$script:TestDirectoryHandler = { param($Query) @{ Records = @() } }

function ConvertFrom-TestAdsPath {
    param([string]$Path)
    $m = [regex]::Match($Path, '^(?i)(?<scheme>LDAP|GC)://(?:(?<host>[^/=,]+)/)?(?<dn>.*)$')
    if (-not $m.Success) { return [pscustomobject]@{ Server = ''; Dn = $Path } }
    $h = ($m.Groups['host'].Value.ToLowerInvariant() -replace ':\d+$', '').TrimEnd('.')
    return [pscustomobject]@{ Server = $h; Dn = $m.Groups['dn'].Value }
}

function New-TestFakeDirectoryEntry {
    param([object[]]$ArgumentList)
    $path = [string]@($ArgumentList)[0]
    $auth = ''
    if (@($ArgumentList).Count -ge 4) { $auth = [string]@($ArgumentList)[3] }
    $p = ConvertFrom-TestAdsPath -Path $path
    $e = [pscustomobject]@{ Path = $path; Server = $p.Server; Dn = $p.Dn; AuthenticationType = $auth; Properties = @{}; Options = $null }
    $e | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
    $e | Add-Member -MemberType ScriptMethod -Name RefreshCache -Value {
        param([string[]]$Names)
        [void]$script:CredentialLog.Add([pscustomobject]@{ Kind = 'Bind'; Server = $this.Server; Dn = $this.Dn; Detail = 'RefreshCache' })
        $a = & $script:TestDirectoryHandler ([pscustomobject]@{ Server = $this.Server; BaseDN = $this.Dn; Scope = 'Base'; Filter = ''; Properties = $Names })
        $rec = @(@($a.Records) | Select-Object -First 1)
        if ($rec.Count -gt 0) { foreach ($k in $rec[0].Keys) { $this.Properties[$k] = @($rec[0][$k]) } }
    }
    return $e
}

function New-TestFakeDirectorySearcher {
    param($Entry)
    $s = [pscustomobject]@{
        SearchRoot = $Entry; Filter = '(objectClass=*)'; SearchScope = [System.DirectoryServices.SearchScope]::Subtree; PageSize = 0
        ClientTimeout = [TimeSpan]::Zero; ServerTimeLimit = [TimeSpan]::Zero; SecurityMasks = [System.DirectoryServices.SecurityMasks]::None
        # The .NET default of DirectorySearcher.ReferralChasing.
        ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::External
        PropertiesToLoad = (New-Object System.Collections.ArrayList)
    }
    $s | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
    $s | Add-Member -MemberType ScriptMethod -Name FindAll -Value {
        $root = $this.SearchRoot
        [void]$script:CredentialLog.Add([pscustomobject]@{ Kind = 'Bind'; Server = $root.Server; Dn = $root.Dn; Detail = ('search {0} {1}; referral chasing {2}' -f $this.SearchScope, $this.Filter, $this.ReferralChasing) })
        $q = [pscustomobject]@{ Server = $root.Server; BaseDN = $root.Dn; Scope = [string]$this.SearchScope; Filter = [string]$this.Filter; Properties = @($this.PropertiesToLoad) }
        $a = & $script:TestDirectoryHandler $q
        $records = @($a.Records)
        if ($a.Referral) {
            if (([int]$this.ReferralChasing -band 0x40) -ne 0) {
                # External (or All): the directory client binds to the referred server with the same credentials and repeats the search.
                [void]$script:CredentialLog.Add([pscustomobject]@{ Kind = 'ChasedBind'; Server = ([string]$a.Referral).ToLowerInvariant(); Dn = $root.Dn; Detail = ('referral from {0}' -f $root.Server) })
                $records = @($a.ReferralRecords)
            }
            else { throw (New-Object System.Runtime.InteropServices.COMException('A referral was returned from the server.', -2147016661)) }
        }
        $list = New-Object System.Collections.ArrayList
        foreach ($r in $records) {
            $h = @{}
            foreach ($k in $r.Keys) { $h[$k] = @($r[$k]) }
            $h['PropertyNames'] = @($r.Keys)
            [void]$list.Add([pscustomobject]@{ Properties = $h })
        }
        Add-Member -InputObject $list -MemberType ScriptMethod -Name Dispose -Value { }
        return , $list
    }
    return $s
}

function Install-TestCredentialRecorder {
    <#
    Call inside a Pester block (BeforeEach or It). Clears the log and installs the fakes and wrappers. -Handler answers directory
    searches: param($Query) -> @{ Records = @(hashtables) } or @{ Referral = 'host'; ReferralRecords = @() }.
    #>
    param([scriptblock]$Handler = { param($Query) @{ Records = @() } })
    $script:CredentialLog.Clear()
    $script:TestDirectoryHandler = $Handler
    $script:OriginalTls = & (Get-Module MspkiHealthCheck) { (Get-Command Test-MspkiTlsEndpoint).ScriptBlock }
    $script:OriginalHttp = & (Get-Module MspkiHealthCheck) { (Get-Command Invoke-MspkiHttpGet).ScriptBlock }
    Mock -ModuleName MspkiHealthCheck New-Object -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectoryEntry' } -MockWith {
        New-TestFakeDirectoryEntry -ArgumentList $ArgumentList
    }
    Mock -ModuleName MspkiHealthCheck New-Object -ParameterFilter { $TypeName -eq 'System.DirectoryServices.DirectorySearcher' } -MockWith {
        New-TestFakeDirectorySearcher -Entry @($ArgumentList)[0]
    }
    Mock -ModuleName MspkiHealthCheck Test-MspkiTlsEndpoint -MockWith {
        [void]$script:CredentialLog.Add([pscustomobject]@{ Kind = 'Tls'; Server = ([string]$PesterBoundParameters['HostName']).ToLowerInvariant(); Dn = ''; Detail = 'Test-MspkiTlsEndpoint' })
        & $script:OriginalTls @PesterBoundParameters
    }
    Mock -ModuleName MspkiHealthCheck Invoke-MspkiHttpGet -MockWith {
        $u = [System.Uri][string]$PesterBoundParameters['Url']
        [void]$script:CredentialLog.Add([pscustomobject]@{ Kind = 'Http'; Server = $u.Host.ToLowerInvariant(); Dn = ''; Detail = $u.AbsoluteUri })
        if ($u.Scheme -eq 'https') { [void]$script:CredentialLog.Add([pscustomobject]@{ Kind = 'Tls'; Server = $u.Host.ToLowerInvariant(); Dn = ''; Detail = 'HTTPS request' }) }
        & $script:OriginalHttp @PesterBoundParameters
    }
}

function Get-TestCredentialEvent {
    <# The recorded events, optionally only binds (Bind and ChasedBind), TLS handshakes or HTTP requests, and only to one host. #>
    param([ValidateSet('Any', 'Bind', 'Tls', 'Http')][string]$Kind = 'Any', [string]$Server = '')
    @($script:CredentialLog | Where-Object {
        ($Kind -eq 'Any' -or ($Kind -eq 'Bind' -and $_.Kind -in @('Bind', 'ChasedBind')) -or $_.Kind -eq $Kind) -and
        (-not $Server -or $_.Server -eq $Server.ToLowerInvariant()) })
}

function Get-TestCredentialedRequest {
    <# Requests that reached a loopback test server with credentials (Authorization or Proxy-Authorization header). #>
    param([Parameter(Mandatory = $true)]$Server)
    @($Server.Log | Where-Object { ($_.Headers -join "`n") -match '(?im)^(Authorization|Proxy-Authorization):' })
}
