# Knowledge sources

Every cause, check and fix in `src/Knowledge/Diagnosis*.psd1` ("Probable causes and next steps") rests on the sources below. The knowledge base is paraphrased
from them: no text and no code was copied (quotes are not used at all). Sources are only cited by address; the report never links to them (it is one offline file), and the
window shows the address as text.

**How far each source was read.** Research was done on 2026-11-22 with web search and page fetches. "Read" means the page was fetched and the parts the advice relies on
were read. "Fetched, read in part" means the page was fetched but only names, headings or a section were used. "Search summary only" means the claim comes from a search
result summary: before you act on a fix that cites such a source alone, read the page. Several pages are old TechNet articles (Windows Server 2008 era); the steps are
still valid in principle but screens and names may differ on a current Windows Server. Community and vendor pages (GitHub projects, security research) are cited for the
attack technique only; the fixes for them follow Microsoft guidance where Microsoft gave any.

The date in the last column is the day the source was read. `tests/Diagnosis.Tests.ps1` checks that every source in the knowledge base is listed here with its address
and a date, and that every source is used by at least one topic.

| Id | Title | Publisher | Address | How read | Used by (topics) | Date read |
|---|---|---|---|---|---|---|
| S01 | Error 0x800706ba "The RPC server is unavailable" when you enroll a certificate | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/error-0x800706ba-certificate-enrollment` | Read (the page was fetched and the relevant parts read) | 7 | 2026-11-22 |
| S02 | CertUtil -ping fails: RPC server unavailable (community thread) | Microsoft Q&A | `https://learn.microsoft.com/en-us/answers/questions/1136418/certutil-ping-fails-rpc-server-unavailable` | Search summary only (the page itself was not read) | 2 | 2026-11-22 |
| S03 | Error 0x80092013 (CRYPT_E_REVOCATION_OFFLINE): causes and resolution | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/directaccess-clients-unable-connect-error-0x80092013` | Read (the page was fetched and the relevant parts read) | 6 | 2026-11-22 |
| S04 | Common NDES configuration wizard failures | Microsoft Tech Community (Ask the Directory Services Team) | `https://techcommunity.microsoft.com/blog/askds/common-network-device-enrollment-service-ndes-configuration-wizard-failures/3879101` | Read (the page was fetched and the relevant parts read) | 8 | 2026-11-22 |
| S05 | NDES and the dreaded 2 / 10 event IDs: "The parameter is incorrect" | Microsoft Tech Community (Ask the Directory Services Team) | `https://techcommunity.microsoft.com/blog/askds/ndes-and-the-dreaded-2--10-event-ids-stating-%E2%80%9Cthe-parameter-is-incorrect/3906775` | Read (the page was fetched and the relevant parts read) | 3 | 2026-11-22 |
| S06 | Troubleshooting device to NDES server communication for SCEP certificate profiles in Microsoft Intune | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/troubleshoot-scep-certificate-device-to-ndes` | Read (the page was fetched and the relevant parts read) | 11 | 2026-11-22 |
| S07 | Troubleshooting the NDES policy module in Microsoft Intune | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/troubleshoot-scep-certificate-ndes-policy-module` | Fetched, read in part or only for names and headings | 1 | 2026-11-22 |
| S08 | You cannot assign SCEP certificates to devices in Intune after a certificate renewal | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/cannot-assign-scep-certificates` | Fetched, read in part or only for names and headings | 1 | 2026-11-22 |
| S09 | NDES Connector sign-in error 80004003 | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/ndes-connector-signin-error-80004003` | Fetched, read in part or only for names and headings | 1 | 2026-11-22 |
| S10 | Certificate Connector for Microsoft Intune: overview | Microsoft Learn | `https://learn.microsoft.com/en-us/mem/intune/protect/certificate-connector-overview` | Fetched, read in part or only for names and headings | 4 | 2026-11-22 |
| S11 | Configure Certificate Enrollment Web Service (CES) | Microsoft Learn | `https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/configure-certificate-enrollment-web-service` | Fetched, read in part or only for names and headings | 7 | 2026-11-22 |
| S12 | Certificate enrollment web services and certificate key based renewal | Microsoft Learn | `https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-enrollment-certificate-key-based-renewal` | Fetched, read in part or only for names and headings | 13 | 2026-11-22 |
| S13 | Event ID 66: AD CS Certificate Revocation List (CRL) Publishing | Microsoft TechNet (archive) | `https://technet.microsoft.com/library/dd300123.aspx` | Read (the page was fetched and the relevant parts read) | 5 | 2026-11-22 |
| S14 | CRL and AIA publishing guidance (Practical PKI, part 2) | Microsoft Tech Community (Core Infrastructure and Security Blog) | `https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/crl--aia-publishing-guidance-practical-pki-part-2/4485713` | Read (the page was fetched and the relevant parts read) | 39 | 2026-11-22 |
| S15 | Configure the CDP and AIA extensions on a CA | Microsoft Learn | `https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-the-cdp-and-aia-extensions-on-ca1` | Fetched, read in part or only for names and headings | 10 | 2026-11-22 |
| S16 | Certificate Authority disaster recovery steps when no valid CRL can be published | Microsoft Learn (Ask the Directory Services Team archive) | `https://learn.microsoft.com/en-us/archive/blogs/askds/certificate-authority-disaster-recovery-steps-when-smartcard-logon-is-required-but-no-valid-crl-can-be-published` | Fetched, read in part or only for names and headings | 6 | 2026-11-22 |
| S17 | certutil command reference | Microsoft Learn | `https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil` | Fetched, read in part or only for names and headings | 3 | 2026-11-22 |
| S18 | Certificate security posture assessments (ESC4, ESC7, ESC8, ESC11) | Microsoft Learn (Defender for Identity) | `https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates` | Read (the page was fetched and the relevant parts read) | 7 | 2026-11-22 |
| S19 | KB5014754: Certificate-based authentication changes on Windows domain controllers | Microsoft Support | `https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16` | Read (the page was fetched and the relevant parts read) | 4 | 2026-11-22 |
| S20 | ADCS ESC13 abuse technique | SpecterOps | `https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53` | Fetched, read in part or only for names and headings | 2 | 2026-11-22 |
| S21 | Certipy wiki: privilege escalation (ESC1 to ESC16 explained) | GitHub (Certipy project) | `https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation` | Read (the page was fetched and the relevant parts read) | 18 | 2026-11-22 |
| S22 | Certified Pre-Owned: abusing Active Directory Certificate Services | SpecterOps | `https://specterops.io/research/certified-pre-owned/` | Search summary only (the page itself was not read) | 4 | 2026-11-22 |
| S23 | Maximum tolerance for computer clock synchronization (Kerberos) | Microsoft Learn | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-tolerance-for-computer-clock-synchronization` | Read (the page was fetched and the relevant parts read) | 1 | 2026-11-22 |
| S24 | How to import third-party CA certificates into the Enterprise NTAuth store | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/import-third-party-ca-to-enterprise-ntauth-store` | Search summary only (the page itself was not read) | 7 | 2026-11-22 |
| S25 | Troubleshoot Online Responders | Microsoft TechNet (archive) | `https://technet.microsoft.com/de-de/library/cc725774.aspx` | Search summary only (the page itself was not read) | 3 | 2026-11-22 |
| S26 | Renew a root CA certificate | Microsoft Learn | `https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/renew-root-ca-certificate` | Search summary only (the page itself was not read) | 12 | 2026-11-22 |
| S27 | Certificate template concepts | Microsoft Learn | `https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts` | Fetched, read in part or only for names and headings | 7 | 2026-11-22 |
| S28 | Locksmith: AD CS misconfiguration finder and fixer (project page) | GitHub (Trimarc) | `https://github.com/TrimarcJake/Locksmith` | Fetched, read in part or only for names and headings | 6 | 2026-11-22 |
| S29 | PSPKIAudit: PowerShell toolkit for auditing AD CS (project page) | GitHub (GhostPack) | `https://github.com/GhostPack/PSPKIAudit` | Fetched, read in part or only for names and headings | 1 | 2026-11-22 |
| S30 | KB5005413: Mitigating NTLM relay attacks on Active Directory Certificate Services | Microsoft Support | `https://support.microsoft.com/help/5005413` | Search summary only (the page itself was not read) | 2 | 2026-11-22 |
| S31 | Security assessment: edit vulnerable Certificate Authority setting (ESC6) | Microsoft Learn (Defender for Identity) | `https://learn.microsoft.com/en-gb/defender-for-identity/security-assessment-edit-vulnerable-ca-setting` | Search summary only (the page itself was not read) | 1 | 2026-11-22 |
| S32 | Basic CRL checking with certutil | Microsoft Learn (PKI blog archive) | `https://learn.microsoft.com/en-gb/archive/blogs/pki/basic-crl-checking-with-certutil` | Search summary only (the page itself was not read) | 2 | 2026-11-22 |
| S33 | Decommissioning an old certification authority without affecting previously issued certificates | Microsoft Learn (PKI blog archive) | `https://docs.microsoft.com/en-us/archive/blogs/pki/decommissioning-an-old-certification-authority-without-affecting-previously-issued-certificates-and-then-switching-operations-to-a-new-one` | Search summary only (the page itself was not read) | 10 | 2026-11-22 |
| S34 | SSL/TLS alert protocol and the alert codes | Microsoft Learn (blog archive) | `https://learn.microsoft.com/en-nz/archive/blogs/kaushal/ssltls-alert-protocol-the-alert-codes` | Search summary only (the page itself was not read) | 2 | 2026-11-22 |
| S35 | How to configure the Windows Time service against a large time offset | Microsoft Support | `https://support.microsoft.com/kb/884776` | Search summary only (the page itself was not read) | 1 | 2026-11-22 |
| S36 | Event ID 17: AD CS Online Responder Service | Microsoft TechNet (archive) | `https://technet.microsoft.com/library/cc774551(v=ws.10)` | Search summary only (the page itself was not read) | 2 | 2026-11-22 |
| S37 | Event ID 74: AD CS Certificate Revocation List (CRL) Publishing | Microsoft Learn (archive) | `https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc726336(v=ws.10)` | Search summary only (the page itself was not read) | 2 | 2026-11-22 |
| S38 | Certification Authority configuration to publish certificates in Active Directory of a trusted domain | Microsoft Support | `https://support.microsoft.com/kb/281271` | Search summary only (the page itself was not read) | 2 | 2026-11-22 |
| S39 | HTTP error 500 internal server error (certificate services web pages) | Microsoft Learn | `https://learn.microsoft.com/en-US/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/http-error-500-internal-server-error` | Search summary only (the page itself was not read) | 2 | 2026-11-22 |
| S40 | HTTP 500 errors on CertificateRegistrationSvc verify request in Intune | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/certificateregistrationsvc-verify-request-error` | Search summary only (the page itself was not read) | 1 | 2026-11-22 |
| S41 | Understanding and managing the certificate stores used for smart card logon (NTAuth) | Microsoft Learn (blog archive) | `https://docs.microsoft.com/en-us/archive/blogs/muaddib/understanding-and-managing-the-certificate-stores-used-for-smart-card-logon` | Search summary only (the page itself was not read) | 5 | 2026-11-22 |
| S42 | Service overview and network port requirements for Windows | Microsoft Learn | `https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements` | Read (the page was fetched and the relevant parts read) | 17 | 2026-11-22 |

## Subjects and the sources behind them

| Subject | Topics (ids in the knowledge base) | Main sources |
|---|---|---|
| RPC / DCOM errors (0x800706BA, access denied) | RPC_ACCESS_DENIED, RPC_NO_ANSWER, PERMISSION_DENIED, NETWORK_PATH_FAIL | S01, S02, S04, S42 |
| CRL and AIA publication, expiry, offline root | CRL_EXPIRED, CRL_EXPIRING, CRL_STALE, CRL_PUBLICATION_FAIL, OFFLINE_ROOT_CRL_*, AIA_WRONG_CERT | S03, S13, S14, S16, S37, S38 |
| LDAP versus HTTP CDP/AIA, retrieval order | CDP_LDAP_ONLY, RETRIEVAL_ORDER, HTTP_* topics | S14, S15 |
| Delta CRLs | HTTP_BAD_REQUEST, CRL_NUMBER_MISMATCH, OFFLINE_ROOT_CRL_SHORT | S03, S13, S14 |
| OCSP / Online Responder | OCSP_UNUSED, OCSP_ENDPOINT_FAIL | S25, S36 |
| CES / CEP and Web Enrollment | CES_*, CEP_NOT_CONFIGURED, WEB_ENROLLMENT_NOT_FOUND | S11, S12, S18, S30 |
| NDES / SCEP | NDES_* | S04, S05, S06 |
| Intune Certificate Connector | INTUNE_* | S07, S08, S09, S10, S40 |
| TLS problems | TLS_* | S34, S06, S41 |
| NTAuth and AD containers | NTAUTH_*, AD_CA_CERT_NOT_PUBLISHED, CA_GENERATION_UNKNOWN, TEMPLATE_LIST_MISMATCH | S24, S41, S33 |
| Template security, ESC1 to ESC16 | ESC1 to ESC16, TEMPLATE_*, KRA_*, OID_LINK_BROKEN | S18, S19, S20, S21, S22, S28, S29, S31 |
| CA certificate renewal and decommissioning | CA_CERT_EXPIRED, CA_CERT_EXPIRING, CA_CERT_WEAK, CHAIN_*, STALE_CA_OBJECT | S26, S33, S12 |
| Time skew | CLOCK_SKEW | S23, S35 |

## Limits of this knowledge

- Causes are **probable**, never proven. A cause is ranked from what this run observed (the facts listed under it) on top of how common it is in the sources;
  with no separating observation the finding says so ("Typical").
- The "how to confirm" steps are read-only checks; a test refuses a write verb in them. The "how to fix" steps change things on servers the tool never touches: they are marked
  as actions for the PKI owner.
- Some patterns (ESC5, ESC6, ESC7, ESC10 to ESC12, ESC14 to ESC16) cannot be detected without rights this tool does not use (CA registry, domain controller registry); their entries are
  review guidance only.
- Security research cited here (SpecterOps, Certipy) explains how a weakness works. It is not a recommendation to test it. Use the Microsoft guidance in the fixes.
- Add new sources to `Diagnosis.psd1` (Sources) and to this table together; run the Pester tests.
