# MSPKI Health Check: diagnosis knowledge base. DATA ONLY (Import-PowerShellDataFile reads it; nothing in it is ever run).
# Every non-passing finding gets "Probable causes and next steps" built from the topic that matches it (Rules, then Codes),
# ranked with what the tool observed (Signals). See docs/KNOWLEDGE-SOURCES.md for the sources and docs/ROADMAP.md (Batch H).
#
# The topics themselves live in Diagnosis.Topics.<Area>.psd1 next to this file (Import-PowerShellDataFile refuses a data file
# above a node limit, so one file cannot hold them all; every topic id is unique across the files).
# Topic    : Title, What (plain-language explanation), Causes (ordered: the first is the most common one when nothing was observed),
#            Sources (ids from the Sources table below).
# Cause    : Id, Cause, Confirm (safe, read-only checks), Fix (actions for the PKI owner; this tool never changes anything),
#            Signals (optional: @{ When = regex on the finding text; Weight = score change; Because = what was observed }).
# The text a Signal sees is built from Category, Status, StatusCode, Confidence, Target, Endpoint, Message, Notes, Evidence, layer
# results (for example "TcpStatus=Pass") and Remediation of the finding.
# Placeholders in commands: <CAHost>, <CAName>, <Host>, <Url>, <Account>. Real names never appear here (docs/NAMING.md).
# Rules: the first matching rule wins; a rule may name Category, StatusCode (string or list) and Match (regex on Message, Target
# and Notes). Codes: the default topic of each StatusCode, so every code has an entry (tests/Diagnosis.Tests.ps1).
@{
    SchemaVersion = 1
    Updated       = '2026-11-22'

    Sources = @{
        'S01' = @{ Title = 'Error 0x800706ba "The RPC server is unavailable" when you enroll a certificate'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/error-0x800706ba-certificate-enrollment' }
        'S02' = @{ Title = 'CertUtil -ping fails: RPC server unavailable (community thread)'; Publisher = 'Microsoft Q&A'; Url = 'https://learn.microsoft.com/en-us/answers/questions/1136418/certutil-ping-fails-rpc-server-unavailable' }
        'S03' = @{ Title = 'Error 0x80092013 (CRYPT_E_REVOCATION_OFFLINE): causes and resolution'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/directaccess-clients-unable-connect-error-0x80092013' }
        'S04' = @{ Title = 'Common NDES configuration wizard failures'; Publisher = 'Microsoft Tech Community (Ask the Directory Services Team)'; Url = 'https://techcommunity.microsoft.com/blog/askds/common-network-device-enrollment-service-ndes-configuration-wizard-failures/3879101' }
        'S05' = @{ Title = 'NDES and the dreaded 2 / 10 event IDs: "The parameter is incorrect"'; Publisher = 'Microsoft Tech Community (Ask the Directory Services Team)'; Url = 'https://techcommunity.microsoft.com/blog/askds/ndes-and-the-dreaded-2--10-event-ids-stating-%E2%80%9Cthe-parameter-is-incorrect/3906775' }
        'S06' = @{ Title = 'Troubleshooting device to NDES server communication for SCEP certificate profiles in Microsoft Intune'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/troubleshoot-scep-certificate-device-to-ndes' }
        'S07' = @{ Title = 'Troubleshooting the NDES policy module in Microsoft Intune'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/troubleshoot-scep-certificate-ndes-policy-module' }
        'S08' = @{ Title = 'You cannot assign SCEP certificates to devices in Intune after a certificate renewal'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/cannot-assign-scep-certificates' }
        'S09' = @{ Title = 'NDES Connector sign-in error 80004003'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/ndes-connector-signin-error-80004003' }
        'S10' = @{ Title = 'Certificate Connector for Microsoft Intune: overview'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/mem/intune/protect/certificate-connector-overview' }
        'S11' = @{ Title = 'Configure Certificate Enrollment Web Service (CES)'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-certificate-enrollment-web-service' }
        'S12' = @{ Title = 'Certificate enrollment web services and certificate key based renewal'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-enrollment-certificate-key-based-renewal' }
        'S13' = @{ Title = 'Event ID 66: AD CS Certificate Revocation List (CRL) Publishing'; Publisher = 'Microsoft TechNet (archive)'; Url = 'https://technet.microsoft.com/library/dd300123.aspx' }
        'S14' = @{ Title = 'CRL and AIA publishing guidance (Practical PKI, part 2)'; Publisher = 'Microsoft Tech Community (Core Infrastructure and Security Blog)'; Url = 'https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/crl--aia-publishing-guidance-practical-pki-part-2/4485713' }
        'S15' = @{ Title = 'Configure the CDP and AIA extensions on a CA'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-the-cdp-and-aia-extensions-on-ca1' }
        'S16' = @{ Title = 'Certificate Authority disaster recovery steps when no valid CRL can be published'; Publisher = 'Microsoft Learn (Ask the Directory Services Team archive)'; Url = 'https://learn.microsoft.com/en-us/archive/blogs/askds/certificate-authority-disaster-recovery-steps-when-smartcard-logon-is-required-but-no-valid-crl-can-be-published' }
        'S17' = @{ Title = 'certutil command reference'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil' }
        'S18' = @{ Title = 'Certificate security posture assessments (ESC4, ESC7, ESC8, ESC11)'; Publisher = 'Microsoft Learn (Defender for Identity)'; Url = 'https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates' }
        'S19' = @{ Title = 'KB5014754: Certificate-based authentication changes on Windows domain controllers'; Publisher = 'Microsoft Support'; Url = 'https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16' }
        'S20' = @{ Title = 'ADCS ESC13 abuse technique'; Publisher = 'SpecterOps'; Url = 'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53' }
        'S21' = @{ Title = 'Certipy wiki: privilege escalation (ESC1 to ESC16 explained)'; Publisher = 'GitHub (Certipy project)'; Url = 'https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation' }
        'S22' = @{ Title = 'Certified Pre-Owned: abusing Active Directory Certificate Services'; Publisher = 'SpecterOps'; Url = 'https://specterops.io/research/certified-pre-owned/' }
        'S23' = @{ Title = 'Maximum tolerance for computer clock synchronization (Kerberos)'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization' }
        'S24' = @{ Title = 'How to import third-party CA certificates into the Enterprise NTAuth store'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/import-third-party-ca-to-enterprise-ntauth-store' }
        'S25' = @{ Title = 'Troubleshoot Online Responders'; Publisher = 'Microsoft TechNet (archive)'; Url = 'https://technet.microsoft.com/de-de/library/cc725774.aspx' }
        'S26' = @{ Title = 'Renew a root CA certificate'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/renew-root-ca-certificate' }
        'S27' = @{ Title = 'Certificate template concepts'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts' }
        'S28' = @{ Title = 'Locksmith: AD CS misconfiguration finder and fixer (project page)'; Publisher = 'GitHub (Trimarc)'; Url = 'https://github.com/TrimarcJake/Locksmith' }
        'S29' = @{ Title = 'PSPKIAudit: PowerShell toolkit for auditing AD CS (project page)'; Publisher = 'GitHub (GhostPack)'; Url = 'https://github.com/GhostPack/PSPKIAudit' }
        'S30' = @{ Title = 'KB5005413: Mitigating NTLM relay attacks on Active Directory Certificate Services'; Publisher = 'Microsoft Support'; Url = 'https://support.microsoft.com/help/5005413' }
        'S31' = @{ Title = 'Security assessment: edit vulnerable Certificate Authority setting (ESC6)'; Publisher = 'Microsoft Learn (Defender for Identity)'; Url = 'https://learn.microsoft.com/en-gb/defender-for-identity/security-assessment-edit-vulnerable-ca-setting' }
        'S32' = @{ Title = 'Basic CRL checking with certutil'; Publisher = 'Microsoft Learn (PKI blog archive)'; Url = 'https://learn.microsoft.com/en-gb/archive/blogs/pki/basic-crl-checking-with-certutil' }
        'S33' = @{ Title = 'Decommissioning an old certification authority without affecting previously issued certificates'; Publisher = 'Microsoft Learn (PKI blog archive)'; Url = 'https://docs.microsoft.com/en-us/archive/blogs/pki/decommissioning-an-old-certification-authority-without-affecting-previously-issued-certificates-and-then-switching-operations-to-a-new-one' }
        'S34' = @{ Title = 'SSL/TLS alert protocol and the alert codes'; Publisher = 'Microsoft Learn (blog archive)'; Url = 'https://learn.microsoft.com/en-nz/archive/blogs/kaushal/ssltls-alert-protocol-the-alert-codes' }
        'S35' = @{ Title = 'How to configure the Windows Time service against a large time offset'; Publisher = 'Microsoft Support'; Url = 'https://support.microsoft.com/kb/884776' }
        'S36' = @{ Title = 'Event ID 17: AD CS Online Responder Service'; Publisher = 'Microsoft TechNet (archive)'; Url = 'https://technet.microsoft.com/library/cc774551(v=ws.10)' }
        'S37' = @{ Title = 'Event ID 74: AD CS Certificate Revocation List (CRL) Publishing'; Publisher = 'Microsoft Learn (archive)'; Url = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc726336(v=ws.10)' }
        'S38' = @{ Title = 'Certification Authority configuration to publish certificates in Active Directory of a trusted domain'; Publisher = 'Microsoft Support'; Url = 'https://support.microsoft.com/kb/281271' }
        'S39' = @{ Title = 'HTTP error 500 internal server error (certificate services web pages)'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-US/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/http-error-500-internal-server-error' }
        'S40' = @{ Title = 'HTTP 500 errors on CertificateRegistrationSvc verify request in Intune'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/certificateregistrationsvc-verify-request-error' }
        'S41' = @{ Title = 'Understanding and managing the certificate stores used for smart card logon (NTAuth)'; Publisher = 'Microsoft Learn (blog archive)'; Url = 'https://docs.microsoft.com/en-us/archive/blogs/muaddib/understanding-and-managing-the-certificate-stores-used-for-smart-card-logon' }
        'S42' = @{ Title = 'Service overview and network port requirements for Windows'; Publisher = 'Microsoft Learn'; Url = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements' }
    }

    Codes = @{
        'DNS_FAIL' = 'DNS_NO_ANSWER'; 'TCP_FAIL' = 'TCP_UNREACHABLE'; 'TIMEOUT' = 'NETWORK_TIMEOUT'; 'HTTP_REDIRECT' = 'HTTP_REDIRECT'
        'HTTP_400' = 'HTTP_BAD_REQUEST'; 'HTTP_401_403' = 'HTTP_AUTH_REFUSED'; 'HTTP_404' = 'HTTP_NOT_FOUND'; 'HTTP_500' = 'HTTP_SERVER_ERROR'
        'HTTP_OTHER' = 'HTTP_OTHER'; 'TLS_HANDSHAKE_FAIL' = 'TLS_HANDSHAKE'; 'TLS_UNTRUSTED_ROOT' = 'TLS_UNTRUSTED'; 'TLS_PARTIAL_CHAIN' = 'TLS_PARTIAL'
        'TLS_NAME_MISMATCH' = 'TLS_NAME'; 'CONTENT_WRONG_TYPE' = 'CONTENT_WRONG_TYPE'; 'CONTENT_MISMATCH' = 'CONTENT_MISMATCH'; 'SIZE_LIMIT' = 'SIZE_LIMIT'
        'RPC_FAIL' = 'RPC_NO_ANSWER'; 'RETRIEVAL_ORDER' = 'RETRIEVAL_ORDER'; 'ENROLLMENT_FAIL' = 'ENROLLMENT_FAIL'; 'SIGNATURE_INVALID' = 'SIGNATURE_INVALID'
        'OBJECT_EXPIRED' = 'OBJECT_EXPIRED'; 'OBJECT_EXPIRING' = 'OBJECT_EXPIRING'; 'STALE_DATA' = 'CRL_STALE'; 'PUBLICATION_FAIL' = 'PUBLICATION_FAIL'
        'RETRIEVAL_FAIL' = 'RETRIEVAL_FAIL'; 'EXPECTED_OFFLINE' = 'EXPECTED_OFFLINE'; 'PERMISSION_DENIED' = 'PERMISSION_DENIED'; 'NOT_CONFIGURED' = 'NOT_CONFIGURED'
        'NOT_DISCOVERED' = 'NOT_DISCOVERED'; 'NOT_APPLICABLE' = 'NOT_APPLICABLE'; 'UNSUPPORTED' = 'UNSUPPORTED'; 'OK' = 'OK'
        'CHAIN_UNTRUSTED_ROOT' = 'CHAIN_UNTRUSTED_ROOT'; 'CHAIN_PARTIAL' = 'CHAIN_PARTIAL'; 'CHAIN_INVALID' = 'CHAIN_INVALID'; 'CONFIG_RISK' = 'CONFIG_RISK'
        'INTERNAL_ERROR' = 'INTERNAL_ERROR'; 'CLOCK_SKEW' = 'CLOCK_SKEW'; 'CONFIG_MISMATCH' = 'CONFIG_MISMATCH'; 'STALE_REFERENCE' = 'STALE_REFERENCE'
        'DIRECTORY_UNAVAILABLE' = 'DIRECTORY_UNAVAILABLE'; 'DIRECTORY_ERROR' = 'DIRECTORY_ERROR'; 'DC_NOT_FOUND' = 'DC_NOT_FOUND'; 'NETWORK_PATH_FAIL' = 'NETWORK_PATH_FAIL'
    }

    Rules = @(
        @{ StatusCode = 'PERMISSION_DENIED'; Match = 'turned down this account'; Topic = 'RPC_ACCESS_DENIED' }
        @{ StatusCode = 'CONFIG_MISMATCH'; Match = 'no Certification Authority named'; Topic = 'CA_NAME_NOT_ON_HOST' }
        @{ StatusCode = 'UNSUPPORTED'; Match = 'CertificateAuthority\.Request|not registered on this computer'; Topic = 'CA_COM_CLASS_MISSING' }
        @{ StatusCode = 'NOT_CONFIGURED'; Match = 'no dNSHostName'; Topic = 'CA_NO_HOSTNAME' }
        @{ StatusCode = 'NOT_APPLICABLE'; Match = 'CA database|CertificateAuthority\.View'; Topic = 'CA_DB_NOT_READ' }
        @{ StatusCode = 'TLS_HANDSHAKE_FAIL'; Match = 'closes every TLS handshake'; Topic = 'TLS_CLOSED_BY_SERVER' }
        @{ StatusCode = 'NOT_DISCOVERED'; Match = 'no clear current/historical split|marked Unknown'; Topic = 'CA_GENERATION_UNKNOWN' }
        @{ StatusCode = 'CONFIG_MISMATCH'; Match = 'in NTAuth but not in the AIA'; Topic = 'NTAUTH_AIA_MISMATCH' }
        @{ Match = 'is not in NTAuthCertificates'; Topic = 'NTAUTH_MISSING' }
        @{ Category = 'ADContainer'; StatusCode = 'NOT_DISCOVERED'; Match = 'No CA certificate was found|was not found in'; Topic = 'AD_CA_CERT_NOT_PUBLISHED' }
        @{ StatusCode = 'NOT_DISCOVERED'; Match = 'No Enterprise CA is registered'; Topic = 'NO_ENTERPRISE_CA' }
        @{ StatusCode = 'CONFIG_MISMATCH'; Match = 'differ from the templates the CA reports|differ'; Topic = 'TEMPLATE_LIST_MISMATCH' }
        @{ StatusCode = 'CONFIG_MISMATCH'; Match = 'does not carry'; Topic = 'ENROLLMENT_OBJECT_CERT_MISMATCH' }
        @{ StatusCode = 'NOT_DISCOVERED'; Match = 'no template object exists'; Topic = 'TEMPLATE_OBJECT_MISSING' }
        @{ StatusCode = 'NOT_CONFIGURED'; Match = 'published by no Enterprise CA'; Topic = 'TEMPLATE_UNPUBLISHED' }
        @{ StatusCode = 'NOT_CONFIGURED'; Match = 'holds no key recovery agent'; Topic = 'KRA_EMPTY' }
        @{ StatusCode = 'OBJECT_EXPIRED'; Match = 'KRA object'; Topic = 'KRA_EXPIRED' }
        @{ StatusCode = 'NOT_DISCOVERED'; Match = 'key recovery agent certificate'; Topic = 'KRA_PARTIAL' }
        @{ StatusCode = 'NOT_DISCOVERED'; Match = 'OID .* linked to a group'; Topic = 'OID_LINK_BROKEN' }
        @{ Category = 'Template'; Match = 'review pattern ESC1:'; Topic = 'ESC1' }
        @{ Category = 'Template'; Match = 'review pattern ESC2:'; Topic = 'ESC2' }
        @{ Category = 'Template'; Match = 'review pattern ESC3:'; Topic = 'ESC3' }
        @{ Category = 'Template'; Match = 'review pattern ESC4:'; Topic = 'ESC4' }
        @{ Category = 'Template'; Match = 'review pattern ESC9:'; Topic = 'ESC9' }
        @{ Category = 'Template'; Match = 'review pattern ESC13:'; Topic = 'ESC13' }
        @{ Category = 'Template'; Match = 'could not be read|were not returned by the directory|review was not done'; Topic = 'TEMPLATE_ACL_UNREADABLE' }
        @{ Category = 'NDES'; StatusCode = 'OBJECT_EXPIRED'; Topic = 'NDES_RA_EXPIRED' }
        @{ Category = 'NDES'; StatusCode = 'CONFIG_RISK'; Match = 'admin page'; Topic = 'NDES_ADMIN_OPEN' }
        @{ Category = 'NDES'; Match = 'no NDES / SCEP server'; Topic = 'NDES_NOT_DISCOVERED' }
        @{ Category = 'NDES'; Match = 'No certificate template in AD has the NDES RA purpose'; Topic = 'NDES_RA_TEMPLATE_MISSING' }
        @{ Category = 'NDES'; Match = 'no Enterprise CA publishes them'; Topic = 'NDES_RA_TEMPLATE_UNPUBLISHED' }
        @{ Category = 'NDES'; Match = 'UnconfirmedCandidate'; Topic = 'NDES_CANDIDATE_UNCONFIRMED' }
        @{ Category = 'IntuneConnector'; StatusCode = 'UNSUPPORTED'; Topic = 'INTUNE_REMOTE_NOT_CHECKED' }
        @{ Category = 'IntuneConnector'; Match = 'Possible Intune'; Topic = 'INTUNE_WEAK_MATCH' }
        @{ Category = 'IntuneConnector'; StatusCode = @('NOT_DISCOVERED', 'NOT_CONFIGURED'); Topic = 'INTUNE_NOT_FOUND' }
        @{ Category = 'CEP'; Match = 'No enrollment policy web service'; Topic = 'CEP_NOT_CONFIGURED' }
        @{ Category = 'CES'; Match = 'No Enrollment Web Service'; Topic = 'CES_NOT_PUBLISHED' }
        @{ Category = @('CES', 'CEP'); Match = 'constructed CEP/CES candidate'; Topic = 'CES_CEP_CANDIDATES_SILENT' }
        @{ Category = @('CES', 'CEP'); Match = 'served over HTTP, not HTTPS'; Topic = 'ESC8' }
        @{ Category = @('CES', 'CEP'); Match = 'not a valid service response'; Topic = 'CES_CEP_NOT_A_SERVICE' }
        @{ Category = @('CES', 'CEP'); StatusCode = @('HTTP_401_403', 'HTTP_500', 'TLS_HANDSHAKE_FAIL', 'TLS_UNTRUSTED_ROOT', 'TLS_NAME_MISMATCH', 'TCP_FAIL', 'TIMEOUT', 'DNS_FAIL'); Topic = 'CES_CEP_ENDPOINT_FAIL' }
        @{ Category = 'WebEnrollment'; StatusCode = 'NOT_DISCOVERED'; Topic = 'WEB_ENROLLMENT_NOT_FOUND' }
        @{ Category = 'WebEnrollment'; StatusCode = 'CONFIG_RISK'; Topic = 'ESC8' }
        @{ StatusCode = 'CONFIG_RISK'; Match = 'NTLM relay target|offers Windows sign-in'; Topic = 'ESC8' }
        @{ Category = 'Identity'; StatusCode = 'NOT_CONFIGURED'; Match = 'No reverse DNS'; Topic = 'PTR_MISSING' }
        @{ Category = 'Identity'; StatusCode = 'CONFIG_MISMATCH'; Match = 'gives only the short name'; Topic = 'PTR_SHORT_NAME' }
        @{ Category = 'Identity'; StatusCode = 'CONFIG_MISMATCH'; Match = 'names another host'; Topic = 'PTR_OTHER_HOST' }
        @{ StatusCode = 'DNS_FAIL'; Match = 'alias \(CNAME\)|leads nowhere'; Topic = 'CNAME_DANGLING' }
        @{ StatusCode = 'DNS_FAIL'; Match = 'Subject Alternative Name'; Topic = 'SAN_NO_DNS' }
        @{ StatusCode = 'TLS_NAME_MISMATCH'; Match = 'alias'; Topic = 'TLS_NAME_ALIAS' }
        @{ Category = 'OCSP'; StatusCode = 'CONFIG_MISMATCH'; Match = 'no client will ever ask'; Topic = 'OCSP_UNUSED' }
        @{ Category = 'OCSP'; StatusCode = @('HTTP_401_403', 'HTTP_404', 'HTTP_500', 'HTTP_OTHER', 'TCP_FAIL', 'TIMEOUT', 'DNS_FAIL', 'TLS_HANDSHAKE_FAIL'); Topic = 'OCSP_ENDPOINT_FAIL' }
        @{ StatusCode = 'CONFIG_RISK'; Match = 'only over LDAP'; Topic = 'CDP_LDAP_ONLY' }
        @{ StatusCode = 'CONFIG_RISK'; Match = 'issues CRLs that last only'; Topic = 'OFFLINE_ROOT_CRL_SHORT' }
        @{ StatusCode = 'CONFIG_RISK'; Match = 'CA certificate generation'; Topic = 'CA_CERT_WEAK' }
        @{ StatusCode = 'PUBLICATION_FAIL'; Match = 'No CRL of the offline root'; Topic = 'OFFLINE_ROOT_CRL_UNKNOWN' }
        @{ StatusCode = 'OBJECT_EXPIRED'; Match = 'offline root'; Topic = 'OFFLINE_ROOT_CRL_EXPIRED' }
        @{ StatusCode = 'OBJECT_EXPIRING'; Match = 'offline root'; Topic = 'OFFLINE_ROOT_CRL_EXPIRING' }
        @{ StatusCode = 'STALE_DATA'; Match = 'newer number'; Topic = 'CRL_NUMBER_MISMATCH' }
        @{ Category = 'AIA'; StatusCode = @('CONTENT_MISMATCH', 'SIGNATURE_INVALID'); Topic = 'AIA_WRONG_CERT' }
        @{ Category = @('CRL', 'CDP'); StatusCode = 'OBJECT_EXPIRED'; Topic = 'CRL_EXPIRED' }
        @{ Category = @('CRL', 'CDP'); StatusCode = 'OBJECT_EXPIRING'; Topic = 'CRL_EXPIRING' }
        @{ Category = @('CRL', 'CDP', 'AIA'); StatusCode = 'PUBLICATION_FAIL'; Topic = 'CRL_PUBLICATION_FAIL' }
        @{ Category = @('CA', 'Hierarchy', 'AIA'); StatusCode = 'OBJECT_EXPIRED'; Topic = 'CA_CERT_EXPIRED' }
        @{ Category = @('CA', 'Hierarchy', 'AIA'); StatusCode = 'OBJECT_EXPIRING'; Topic = 'CA_CERT_EXPIRING' }
        @{ Category = 'LocalEvidence'; StatusCode = 'PUBLICATION_FAIL'; Topic = 'LOCAL_STORE_MISSING' }
        @{ Category = 'StaleRef'; StatusCode = 'STALE_REFERENCE'; Match = 'Enterprise CA object'; Topic = 'STALE_CA_OBJECT' }
        @{ Category = 'StaleRef'; StatusCode = 'STALE_REFERENCE'; Topic = 'STALE_URL_REFERENCE' }
        @{ StatusCode = 'STALE_REFERENCE'; Match = 'server object|NTDS'; Topic = 'STALE_DC_OBJECT' }
    )

}
