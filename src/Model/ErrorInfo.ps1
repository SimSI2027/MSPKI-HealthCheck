# Classifies exceptions so that permission failures, unreachable servers, timeouts, missing objects
# and unsupported features each become a different finding. Classification uses HRESULT codes and
# exception types, never the (localised) message text.

$script:MspkiHResultClass = @{
    '80070005' = 'PermissionDenied'   # E_ACCESSDENIED
    '8007052E' = 'PermissionDenied'   # ERROR_LOGON_FAILURE
    '80072098' = 'PermissionDenied'   # ERROR_DS_INSUFF_ACCESS_RIGHTS
    '80072030' = 'NotFound'           # ERROR_DS_NO_SUCH_OBJECT
    '80070490' = 'NotFound'           # ERROR_NOT_FOUND
    '80070002' = 'NotFound'           # ERROR_FILE_NOT_FOUND
    '80094004' = 'NotFound'           # CERTSRV_E_PROPERTY_EMPTY
    '8007203A' = 'Unreachable'        # ERROR_DS_SERVER_DOWN (server is not operational)
    '8007054B' = 'Unreachable'        # ERROR_NO_SUCH_DOMAIN (domain cannot be contacted)
    '800706BA' = 'Unreachable'        # RPC_S_SERVER_UNAVAILABLE
    '800706D9' = 'Unreachable'        # EPT_S_NOT_REGISTERED (no endpoint: service not running)
    '80070035' = 'Unreachable'        # ERROR_BAD_NETPATH
    '80070102' = 'Timeout'            # WAIT_TIMEOUT
    '800705B4' = 'Timeout'            # ERROR_TIMEOUT
    '80072023' = 'Timeout'            # ERROR_DS_TIMELIMIT_EXCEEDED
    '80070057' = 'Unsupported'        # E_INVALIDARG (for example a CA property this CA version lacks)
    '80004001' = 'Unsupported'        # E_NOTIMPL
    '80040154' = 'Unsupported'        # REGDB_E_CLASSNOTREG (COM class not available)
}

# Within the Unreachable class the error number says what could not be reached (audit 2 M8 remainder). An unreachable failure whose
# number is not listed here cannot be told apart and stays RETRIEVAL_FAIL.
$script:MspkiUnreachableCode = @{
    '8007203A' = 'DIRECTORY_UNAVAILABLE'   # the directory server is not operational
    '8007054B' = 'DIRECTORY_UNAVAILABLE'   # the domain cannot be contacted
    '800706BA' = 'RPC_FAIL'                # RPC server unavailable
    '800706D9' = 'RPC_FAIL'                # no RPC endpoint registered: the service is not running
    '80070035' = 'NETWORK_PATH_FAIL'       # the network path was not found
}

function Get-MspkiUnreachableStatusCode {
    <#
    .SYNOPSIS
    The status code for a failure of the Unreachable class: DIRECTORY_UNAVAILABLE, RPC_FAIL or NETWORK_PATH_FAIL by error number,
    RETRIEVAL_FAIL when the number does not say what could not be reached.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$ErrorInfo)
    $hr = ([string]$ErrorInfo.HResult).Trim()
    if ($hr.StartsWith('0x', [System.StringComparison]::OrdinalIgnoreCase)) { $hr = $hr.Substring(2) }
    $hr = $hr.ToUpperInvariant()
    if ($script:MspkiUnreachableCode.ContainsKey($hr)) { return $script:MspkiUnreachableCode[$hr] }
    if ([string]$ErrorInfo.ExceptionType -eq 'System.DirectoryServices.ActiveDirectory.ActiveDirectoryServerDownException') { return 'DIRECTORY_UNAVAILABLE' }
    return 'RETRIEVAL_FAIL'
}

function Get-MspkiErrorInfo {
    <#
    .SYNOPSIS
    Classifies an ErrorRecord or Exception into PermissionDenied, NotFound, Unreachable, Timeout,
    Unsupported, NotDomainJoined, Cancelled (the user stopped the run) or Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$InputError
    )
    $ex = $InputError
    if ($InputError -is [System.Management.Automation.ErrorRecord]) { $ex = $InputError.Exception }

    $chain = @()
    $e = $ex
    while ($null -ne $e) { $chain += $e; $e = $e.InnerException }
    $inner = $chain[-1]

    $class = 'Error'
    $hr = ''
    foreach ($c in $chain) {
        $code = ('{0:X8}' -f $c.HResult)
        if ($script:MspkiHResultClass.ContainsKey($code)) {
            $class = $script:MspkiHResultClass[$code]; $hr = '0x' + $code; break
        }
    }
    if ($class -eq 'Error') {
        foreach ($c in $chain) {
            if ($c -is [System.UnauthorizedAccessException] -or $c -is [System.Security.SecurityException]) { $class = 'PermissionDenied'; break }
            if ($c -is [System.OperationCanceledException]) { $class = 'Cancelled'; break }
            if ($c -is [System.TimeoutException]) { $class = 'Timeout'; break }
            if ($c -is [System.NotSupportedException] -or $c -is [System.PlatformNotSupportedException]) {
                $class = 'Unsupported'; break
            }
            if ($c -is [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException]) {
                $class = 'NotFound'; break
            }
            if ($c -is [System.DirectoryServices.ActiveDirectory.ActiveDirectoryServerDownException]) {
                $class = 'Unreachable'; break
            }
        }
    }
    if (-not $hr) { $hr = ('0x{0:X8}' -f $inner.HResult) }

    return [pscustomobject]@{
        Class         = $class
        HResult       = $hr
        ExceptionType = $inner.GetType().FullName
        Message       = ([string]$inner.Message).Trim()
    }
}

function New-MspkiErrorInfo {
    <#
    .SYNOPSIS
    Builds an error-info object by hand (for failures that are not exceptions, such as timeouts).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Class,
        [string]$Message = '',
        [string]$HResult = ''
    )
    return [pscustomobject]@{ Class = $Class; HResult = $HResult; ExceptionType = ''; Message = $Message }
}
