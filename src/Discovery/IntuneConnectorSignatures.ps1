# Signatures of the Certificate Connector for Microsoft Intune, in one place (REQUIREMENTS 5.8). They are used only
# to recognise the connector on THIS computer (services, installed products, files, certificate metadata).
#
# Microsoft sources (Microsoft Learn):
#   Overview of the Certificate Connector for Microsoft Intune:
#     https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/overview
#     (the connector replaced the "PFX Certificate Connector for Microsoft Intune" and the
#      "Microsoft Intune Connector" on 29 July 2021; installer IntuneCertificateConnector.exe; default install folder
#      %ProgramFiles%\Microsoft Intune\PFXCertificateConnector)
#   Install the Certificate Connector for Microsoft Intune:
#     https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/setup-connector
#   Service names (the three connector services that are restarted after a configuration change):
#     https://learn.microsoft.com/en-us/intune/fundamentals/certificates/digicert-pkcs
#     PFX Create Certificate Connector (PkiCreateConnectorSvc), PFX Revoke Certificate Connector (PkiRevokeConnectorSvc),
#     PFX Create Legacy Connector (PfxCreateLegacyConnectorSvc).
# A name that Microsoft documents is "Documented" (strong evidence). Patterns that only look like these names are
# "Pattern" (weak evidence, Inferred): another product could match them. Names change between connector versions, so
# keep this list current; nothing else in the code base names the connector.

$script:MspkiIntuneSignatureSource = 'https://learn.microsoft.com/en-us/intune/fundamentals/certificates/connector/overview'

# Windows service names documented by Microsoft.
$script:MspkiIntuneServiceName = @(
    @{ Name = 'PkiCreateConnectorSvc';      Basis = 'Documented: PFX Create Certificate Connector for Microsoft Intune' }
    @{ Name = 'PkiRevokeConnectorSvc';      Basis = 'Documented: PFX Revoke Certificate Connector for Microsoft Intune' }
    @{ Name = 'PfxCreateLegacyConnectorSvc'; Basis = 'Documented: PFX Create Legacy Connector for Microsoft Intune' }
)

# Display-name patterns of services (weak evidence).
$script:MspkiIntuneServiceDisplayPattern = @(
    '(?i)Intune.*Connector'
    '(?i)PFX (Create|Revoke).*Connector'
)

# Installed product names (Add/Remove Programs). Documented product names are strong evidence.
$script:MspkiIntuneProductName = @(
    @{ Pattern = '(?i)^Certificate Connector for Microsoft Intune'; Basis = 'Documented product name' }
    @{ Pattern = '(?i)^PFX Certificate Connector for Microsoft Intune'; Basis = 'Documented product name (replaced connector)' }
    @{ Pattern = '(?i)^Microsoft Intune Connector'; Basis = 'Documented product name (replaced connector)' }
)

# Install folder of the connector's files (weak evidence on its own: it is a path pattern).
$script:MspkiIntunePathPattern = '(?i)\\Microsoft Intune\\(PFXCertificateConnector|NDESConnector)'

# Certificate metadata in the local computer's Personal store (weak evidence): the connector works with the NDES
# RA certificate (named <host>-MSCEP-RA) and with certificates that name Intune.
$script:MspkiIntuneCertificatePattern = @('(?i)Intune', '(?i)-MSCEP-RA')
