# Allowed values for every enumerated field of a finding (docs/REQUIREMENTS.md section 3).
# This table is the single source of truth: New-MspkiFinding validates against it and the
# reporters use it for column order and filters.

$script:MspkiToolName    = 'MSPKI Health Check'
$script:MspkiToolVersion = '0.1.0'
$script:MspkiJsonSchema  = 'mspki-healthcheck/1'

$script:MspkiSchema = @{
    Category    = @('CA', 'Hierarchy', 'CRL', 'AIA', 'CDP', 'OCSP', 'ADContainer', 'Template', 'CEP', 'CES',
                    'NDES', 'IntuneConnector', 'StaleRef', 'ADDependency', 'Run')
    Status      = @('Pass', 'Information', 'Warning', 'Fail', 'Critical', 'NotApplicable', 'Skipped', 'Error')
    Confidence  = @('Confirmed', 'Referenced', 'Inferred', 'Unknown')
    Severity    = @('None', 'High', 'Medium', 'Low', 'Information', 'ReviewRequired')
    Scope       = @('Local', 'OtherForest', 'External', 'Unknown')
    Stage       = @('Discovery', 'Probe', 'Analysis', 'Report', 'Run')
    Layer       = @('DiscoveryStatus', 'DnsStatus', 'TcpStatus', 'HttpStatus', 'RedirectStatus', 'TlsStatus',
                    'ContentStatus', 'ChainStatus')
    LayerStatus = @('NotTested', 'Pass', 'Warning', 'Fail', 'Skipped', 'NotApplicable', 'Error',
                    'PermissionDenied', 'Timeout', 'Unknown')
    Role        = @('EnterpriseRoot', 'EnterpriseSubordinate', 'StandaloneRoot', 'StandaloneSubordinate',
                    'Intermediate', 'IssuingCA', 'CrossCertificate', 'AIAEndpoint', 'CDPEndpoint', 'OCSPEndpoint',
                    'CEPEndpoint', 'CESEndpoint', 'NDESEndpoint', 'IntuneConnector', 'DomainController', 'Forest',
                    'Domain', 'Site', 'Trust', 'ADContainer', 'Template', 'Computer', 'Run', 'Unknown')
    StatusCode  = @('DNS_FAIL', 'TCP_FAIL', 'TIMEOUT', 'HTTP_REDIRECT', 'HTTP_400', 'HTTP_401_403', 'HTTP_404',
                    'HTTP_500', 'TLS_HANDSHAKE_FAIL', 'TLS_UNTRUSTED_ROOT', 'TLS_PARTIAL_CHAIN', 'TLS_NAME_MISMATCH',
                    'CONTENT_WRONG_TYPE', 'SIGNATURE_INVALID', 'OBJECT_EXPIRED', 'OBJECT_EXPIRING', 'STALE_DATA',
                    'PUBLICATION_FAIL', 'RETRIEVAL_FAIL', 'EXPECTED_OFFLINE', 'PERMISSION_DENIED', 'NOT_CONFIGURED',
                    'NOT_DISCOVERED', 'NOT_APPLICABLE', 'UNSUPPORTED', 'OK')
}

function Resolve-MspkiSchemaValue {
    <#
    .SYNOPSIS
    Returns the canonical spelling of a schema value, or throws when the value is not allowed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Field,
        [AllowEmptyString()][string]$Value
    )
    $allowed = $script:MspkiSchema[$Field]
    if ($null -eq $allowed) { throw ('Unknown schema field "{0}".' -f $Field) }
    foreach ($a in $allowed) {
        if ([string]::Equals($a, $Value, [System.StringComparison]::OrdinalIgnoreCase)) { return $a }
    }
    throw ('Invalid {0} "{1}". Allowed: {2}.' -f $Field, $Value, ($allowed -join ', '))
}

function Get-MspkiSchema {
    <#
    .SYNOPSIS
    Returns a copy of the finding schema (allowed values per field).
    #>
    [CmdletBinding()]
    param()
    $copy = @{}
    foreach ($k in $script:MspkiSchema.Keys) { $copy[$k] = @($script:MspkiSchema[$k]) }
    return $copy
}
