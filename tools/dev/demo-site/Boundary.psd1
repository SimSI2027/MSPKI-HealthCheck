# The simulation boundary of the demo site (docs/DEMO-SITE.md section 3). DATA ONLY.
# Replaced: the engine functions that the demo generator replaces, inside the module scope, with functions that answer from the
# simulated world (tools\dev\demo-site\SimBoundary.ps1). Every engine function that calls an I/O API is either replaced or listed under
# Exempt with the reason it never reaches the outside world when the replaced functions are in place. tests\DemoGenerator.Tests.ps1 scans
# the engine (src, without src\Gui) and fails when a function that uses an I/O API is in neither list.
@{
    Replaced = @(
        # Clock: every "now" and every recorded elapsed time
        'Get-MspkiUtcNow', 'New-MspkiStopwatch',
        # This computer and the run
        'Get-MspkiRunHostInfo', 'New-MspkiRunId', 'Get-MspkiDotNetRelease', 'Get-MspkiLocalComputerName', 'Get-MspkiLocalComputerIdentity', 'Get-MspkiComputerSystemInfo',
        # Active Directory
        'Get-MspkiRootDse', 'Get-MspkiDomainControllerName', 'Get-MspkiGlobalCatalogName', 'Get-MspkiForestRootName', 'Get-MspkiForestInfo',
        'Get-MspkiComputerSiteName', 'Get-MspkiLdapObject', 'Get-MspkiLiveDomainControllerName', 'ConvertTo-MspkiAccountName',
        # Name resolution, TCP, TLS, HTTP
        'Resolve-MspkiDnsName', 'Resolve-MspkiDnsEntry', 'Test-MspkiTcpPort', 'Test-MspkiTlsEndpoint', 'Invoke-MspkiHttpRequest',
        # Calls the engine runs in a time-limited runspace (CA COM, CA database view, DNS identity and SRV scripts)
        'Invoke-MspkiTimeLimitedScript',
        # This computer's stores, registry, event logs and services
        'Read-MspkiLocalStore', 'Get-MspkiEnterpriseStoreThumbprint', 'Get-MspkiLifecycleEvent', 'Get-MspkiEnrollmentEvent',
        'Get-MspkiEnrollmentPolicyState', 'Read-MspkiPolicyServerKey', 'Get-MspkiLocalServiceInfo', 'Get-MspkiLocalProductInfo',
        'Get-MspkiLocalCertificateMetadata', 'Get-MspkiLocalIssuedCertificate', 'Test-MspkiTrustedRoot'
    )
    Exempt = @{
        'Wait-MspkiAsyncResult'          = 'Waits on a real asynchronous call; only the replaced DNS and TCP probes call it.'
        'Get-MspkiErrorInfo'             = 'Names directory exception types to classify an error; makes no call.'
        'Get-MspkiUnreachableStatusCode' = 'Names directory exception types to classify an error; makes no call.'
        'Get-MspkiDnsIdentityScript'     = 'Returns the DNS lookup script; it runs only through Invoke-MspkiTimeLimitedScript (replaced).'
        'Invoke-MspkiTimeLimitedScript'  = 'Replaced.'
        'Invoke-MspkiHttpGet'            = 'Asks Windows for the system proxy object only with -UseSystemProxy (never set by the generator); every request goes through Invoke-MspkiHttpRequest (replaced).'
        'Invoke-MspkiReaderCall'         = 'Defined inside the CA property reader script, which runs only through Invoke-MspkiTimeLimitedScript (replaced).'
    }
    # Shadowed inside the module scope for the engine's own DNS scripts, which then run unchanged (DNS identity, SRV records).
    Shadowed = @('Resolve-DnsName')
    # I/O API patterns the guard looks for in each engine function (own body, nested functions excluded).
    Patterns = @(
        'System\.DirectoryServices', '-ComObject', 'System\.Net\.(HttpWebRequest|WebRequest|Sockets\.TcpClient|Security\.SslStream|NetworkInformation)',
        '\[System\.Net\.Dns\]', 'Resolve-DnsName', 'Get-WinEvent', 'X509Store', 'Microsoft\.Win32\.Registry', 'Get-CimInstance', 'Get-WmiObject',
        'WindowsIdentity', '\.Translate\(', '\[Environment\]::(MachineName|UserName|UserDomainName)', '\$env:(COMPUTERNAME|USERNAME|USERDOMAIN)',
        '\[(?i:datetime)\]::(UtcNow|Now|Today)', 'Get-Date', 'Stopwatch\]::StartNew', 'NewGuid', 'certutil'
    )
}
