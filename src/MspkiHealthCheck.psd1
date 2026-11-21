@{
    RootModule           = 'MspkiHealthCheck.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '7c3821b9-5ec2-41c1-82e7-3177285c57a3'
    Author               = 'ED'
    Copyright            = '(c) ED. All rights reserved.'
    Description          = 'Read-only, self-discovering health check for Microsoft AD CS (Windows PowerShell 5.1).'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop')
    FunctionsToExport    = @('Start-MspkiHealthCheck', 'New-MspkiFinding', 'Get-MspkiSchema', 'Export-MspkiReportFromResults')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{ PSData = @{ Tags = @('PKI', 'ADCS', 'HealthCheck', 'ReadOnly') } }
}
