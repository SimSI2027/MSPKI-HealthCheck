# The standard result object. Every result of the tool is created here.

$script:MspkiFindingSequence = 0

function Reset-MspkiFindingSequence {
    [CmdletBinding()]
    param()
    $script:MspkiFindingSequence = 0
}

function New-MspkiFinding {
    <#
    .SYNOPSIS
    Creates one standard MSPKI Health Check finding.

    .DESCRIPTION
    Every result of the tool is a finding with the fields described in docs/REQUIREMENTS.md section 3.
    Enumerated fields are validated against the schema in src/Model/Schema.ps1. Sources are mandatory:
    each finding must say where its data came from. Layer statuses default to NotTested.

    .PARAMETER Layers
    Hashtable of layer statuses to set, for example @{ DnsStatus = 'Pass'; TcpStatus = 'Fail' }.

    .EXAMPLE
    New-MspkiFinding -Category CA -Target 'Example Issuing CA' -Status Information -StatusCode OK `
        -Sources 'AD:EnrollmentServices' -Confidence Referenced -Message 'Enterprise CA object found.'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $true)][string]$StatusCode,
        [Parameter(Mandatory = $true)][string[]]$Sources,
        [Parameter(Mandatory = $true)][string]$Message,
        [string]$Confidence = 'Unknown',
        [string]$Stage = 'Discovery',
        [string]$Role = 'Unknown',
        [string]$Endpoint = '',
        [string]$RelatedCA = '',
        [string[]]$Evidence = @(),
        [string]$Remediation = '',
        [string]$Notes = '',
        [string]$Severity = 'None',
        [string]$Scope = 'Unknown',
        [string]$Forest = $null,
        [string]$Domain = $null,
        [hashtable]$Layers = @{},
        [string[]]$EntityIds = @()
    )

    $srcList = @($Sources | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() } |
        Select-Object -Unique)
    if ($srcList.Count -eq 0) { throw 'New-MspkiFinding: at least one source is required.' }

    $layerValues = [ordered]@{}
    foreach ($l in $script:MspkiSchema.Layer) { $layerValues[$l] = 'NotTested' }
    foreach ($k in $Layers.Keys) {
        $name = Resolve-MspkiSchemaValue -Field 'Layer' -Value ([string]$k)
        $layerValues[$name] = Resolve-MspkiSchemaValue -Field 'LayerStatus' -Value ([string]$Layers[$k])
    }

    if ($null -eq $Forest -or $Forest -eq '') { $Forest = Get-MspkiRunValue -Name 'Forest' }
    if ($null -eq $Domain -or $Domain -eq '') { $Domain = Get-MspkiRunValue -Name 'Domain' }

    $script:MspkiFindingSequence++
    $f = [ordered]@{
        PSTypeName = 'Mspki.Finding'
        Id         = ('F{0:D4}' -f $script:MspkiFindingSequence)
        Timestamp  = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Stage      = (Resolve-MspkiSchemaValue -Field 'Stage' -Value $Stage)
        Category   = (Resolve-MspkiSchemaValue -Field 'Category' -Value $Category)
        Role       = (Resolve-MspkiSchemaValue -Field 'Role' -Value $Role)
        Target     = $Target
        Endpoint   = $Endpoint
        RelatedCA  = $RelatedCA
        Sources    = [string[]]$srcList
        Confidence = (Resolve-MspkiSchemaValue -Field 'Confidence' -Value $Confidence)
    }
    foreach ($l in $layerValues.Keys) { $f[$l] = $layerValues[$l] }
    $f['Status']      = (Resolve-MspkiSchemaValue -Field 'Status' -Value $Status)
    $f['Severity']    = (Resolve-MspkiSchemaValue -Field 'Severity' -Value $Severity)
    $f['StatusCode']  = (Resolve-MspkiSchemaValue -Field 'StatusCode' -Value $StatusCode)
    $f['Scope']       = (Resolve-MspkiSchemaValue -Field 'Scope' -Value $Scope)
    $f['Forest']      = [string]$Forest
    $f['Domain']      = [string]$Domain
    $f['Message']     = $Message
    $f['Evidence']    = [string[]]@($Evidence | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    $f['Remediation'] = $Remediation
    $f['Notes']       = $Notes
    $f['EntityIds']   = [string[]]@($EntityIds | Where-Object { $_ })
    return [pscustomobject]$f
}

function New-MspkiErrorFinding {
    <#
    .SYNOPSIS
    Turns a classified failure (see Get-MspkiErrorInfo) into a finding with consistent status codes.

    .DESCRIPTION
    Permission failures and infrastructure failures are kept apart:
    PermissionDenied -> Skipped/PERMISSION_DENIED, Unsupported or NotDomainJoined -> Skipped/UNSUPPORTED,
    NotFound -> Information/<NotFoundCode>, Timeout -> <UnreachableStatus>/TIMEOUT,
    Unreachable -> <UnreachableStatus>/RETRIEVAL_FAIL. Anything that could not be classified (an unexpected exception,
    which can be a fault in this tool itself) -> Error/INTERNAL_ERROR, so it is never mistaken for an unreachable server.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$ErrorInfo,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Target,
        [Parameter(Mandatory = $true)][string[]]$Sources,
        [Parameter(Mandatory = $true)][string]$Action,
        [string]$Role = 'Unknown',
        [string]$Endpoint = '',
        [string]$RelatedCA = '',
        [string]$NotFoundCode = 'NOT_DISCOVERED',
        [string]$UnreachableStatus = 'Error',
        [string[]]$Evidence = @(),
        [string]$Stage = 'Discovery',
        [string]$Scope = 'Unknown',
        [string]$Notes = ''
    )
    $layer = 'Error'
    switch ($ErrorInfo.Class) {
        'PermissionDenied' { $st = 'Skipped'; $code = 'PERMISSION_DENIED'; $layer = 'PermissionDenied'
                             $msg = ('Permission denied while {0}.' -f $Action) }
        'NotDomainJoined'  { $st = 'Skipped'; $code = 'UNSUPPORTED'; $layer = 'Skipped'
                             $msg = ('Not supported while {0}: this computer is not joined to a domain.' -f $Action) }
        'Unsupported'      { $st = 'Skipped'; $code = 'UNSUPPORTED'; $layer = 'Skipped'
                             $msg = ('Not supported while {0}.' -f $Action) }
        'NotFound'         { $st = 'Information'; $code = $NotFoundCode; $layer = 'Fail'
                             $msg = ('Nothing found while {0}.' -f $Action) }
        'Cancelled'        { $st = 'Skipped'; $code = 'NOT_APPLICABLE'; $layer = 'Skipped'
                             $msg = ('Stopped because the run was cancelled while {0}; this part is incomplete.' -f $Action) }
        'Timeout'          { $st = $UnreachableStatus; $code = 'TIMEOUT'; $layer = 'Timeout'
                             $msg = ('Timed out while {0}.' -f $Action) }
        'Unreachable'      { $st = $UnreachableStatus; $code = 'RETRIEVAL_FAIL'; $layer = 'Fail'
                             $msg = ('Server not reachable while {0}.' -f $Action) }
        default            { $st = 'Error'; $code = 'INTERNAL_ERROR'
                             $msg = ('Unexpected error while {0}.' -f $Action) }
    }
    # The real error is part of the message, not only of the evidence: "Unsupported" alone does not say what failed.
    $detail = @()
    if ($ErrorInfo.HResult) { $detail += ('error {0}' -f $ErrorInfo.HResult) }
    if ($ErrorInfo.Message) { $detail += $ErrorInfo.Message.TrimEnd('.') }
    if ($detail.Count -gt 0) { $msg = '{0} ({1})' -f $msg, ($detail -join ': ') }
    $ev = @($Evidence)
    if ($ErrorInfo.HResult) { $ev += ('HResult: {0}' -f $ErrorInfo.HResult) }
    if ($ErrorInfo.ExceptionType) { $ev += ('Exception: {0}' -f $ErrorInfo.ExceptionType) }
    if ($ErrorInfo.Message) { $ev += ('Message: {0}' -f $ErrorInfo.Message) }
    $p = @{
        Category = $Category; Target = $Target; Status = $st; StatusCode = $code; Sources = $Sources
        Message = $msg; Confidence = 'Unknown'; Stage = $Stage; Role = $Role; Endpoint = $Endpoint
        RelatedCA = $RelatedCA; Evidence = $ev; Scope = $Scope; Notes = $Notes
        Layers = @{ DiscoveryStatus = $layer }
    }
    return (New-MspkiFinding @p)
}
