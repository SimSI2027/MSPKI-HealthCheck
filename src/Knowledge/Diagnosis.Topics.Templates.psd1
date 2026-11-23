# MSPKI Health Check diagnosis knowledge base, topics: Templates. DATA ONLY. Format and rules: see Diagnosis.psd1.
@{
        # ===== Templates, key recovery, escalation review patterns (ESC1 to ESC16) =====
        # The tool names its patterns ESC1 ... after public research (S22, S21). A review pattern is a finding to REVIEW, not proof of an attack.
        'TEMPLATE_OBJECT_MISSING' = @{
            Title = 'A CA publishes a template name for which no template object exists'
            What = 'The Enrollment Services object lists a template the forest does not have (anymore). Users cannot enroll for it and the CA cannot issue it.'
            Sources = @('S27', 'S12')
            Causes = @(
                @{ Id = 'template-deleted'; Cause = 'The template was deleted from AD, but not removed from the CA''s list of templates to issue.'
                   Confirm = @('Compare the names in the finding with CN=Certificate Templates in ADSI Edit (view only).')
                   Fix = @('Remove the stale name from the CA''s Certificate Templates list (CA console), or recreate the template.') }
                @{ Id = 'replication'; Cause = 'The template object was created but has not replicated to the domain controller that was read.'
                   Confirm = @('Read it from another domain controller; repadmin /showrepl.')
                   Fix = @('Wait for replication or fix it.') }
            ) }

        'TEMPLATE_UNPUBLISHED' = @{
            Title = 'Template objects exist that no Enterprise CA publishes'
            What = 'Template objects in AD that no CA issues are unused. They are harmless unless someone publishes them, but each one is a permission surface that nobody reviews.'
            Sources = @('S27', 'S28')
            Causes = @(
                @{ Id = 'defaults-and-leftovers'; Cause = 'The forest still has the default templates (a fresh forest has about 30 that are never used) plus old copies that nobody deleted.'
                   Confirm = @('List which templates each CA publishes (CA console) and compare with the AD list in the finding.')
                   Fix = @('Delete templates nobody needs, after checking no application references them. Review the permissions of the ones kept.') }
            ) }

        'KRA_EMPTY' = @{
            Title = 'A key recovery agent object holds no certificate'
            What = 'The CA''s KRA object exists but is empty. This is the normal state when key archival is not used.'
            Sources = @('S27')
            Causes = @(
                @{ Id = 'no-key-archival'; Cause = 'Key archival is not used.'
                   Confirm = @('Check whether any template has "Archive subject''s encryption private key" ticked.')
                   Fix = @('Nothing to do if archival is not wanted.') }
            ) }

        'KRA_EXPIRED' = @{
            Title = 'Every key recovery agent certificate has expired'
            What = 'The CA''s KRA object holds only expired certificates. If templates archive keys, new requests for them will fail, and recovery of earlier archived keys depends on the agent''s private key.'
            Sources = @('S27')
            Causes = @(
                @{ Id = 'not-renewed'; Cause = 'The key recovery agent certificate was never renewed.'
                   Confirm = @('Look at the certificate validity in the finding evidence.')
                   Fix = @('Issue a new recovery agent certificate and add it to the CA (never delete the old one if archived keys exist).') }
            ) }

        'KRA_PARTIAL' = @{
            Title = 'A CA is configured with more recovery agent certificates than it can use'
            What = 'Some key recovery agent certificates in the CA configuration are not usable (expired, revoked or not found), so key archival may not use every agent.'
            Sources = @('S27')
            Causes = @(
                @{ Id = 'stale-agent-entry'; Cause = 'An agent certificate expired or was removed but the CA still lists it.'
                   Confirm = @('Compare the agent list in the CA properties with the certificates in the KRA object.')
                   Fix = @('Update the CA''s recovery agent list.') }
            ) }

        'OID_LINK_BROKEN' = @{
            Title = 'An issuance policy is linked to a group that cannot be found'
            What = 'An issuance policy OID points at an AD group that does not resolve (deleted, or unreadable by this account). A template that uses it behaves unpredictably, and a recreated group with that name could receive the link''s effect (see ESC13).'
            Sources = @('S20', 'S21')
            Causes = @(
                @{ Id = 'group-deleted'; Cause = 'The group was deleted or renamed; the link stayed.'
                   Confirm = @('Read msDS-OIDToGroupLink on the OID object (ADSI Edit, view only).')
                   Fix = @('Remove the stale link or point it at the right group.') }
                @{ Id = 'not-readable'; Cause = 'The group is in a domain this account cannot read.'
                   Confirm = @('Look up the group''s SID from a domain that can resolve it.')
                   Fix = @('Check the link as a user of that domain.') }
            ) }

        'TEMPLATE_ACL_UNREADABLE' = @{
            Title = 'Template permissions could not be read, so some reviews were not done'
            What = 'The template review needs each template''s permissions. For some or all templates the directory did not return them, so the escalation patterns could not be evaluated for those templates.'
            Sources = @('S27', 'S28')
            Causes = @(
                @{ Id = 'directory-failed'; Cause = 'The directory read failed earlier (see the discovery findings).'
                   Confirm = @('Look for directory or permission findings above this one.')
                   Fix = @('Fix the directory connection and run again.')
                   Signals = @(@{ When = 'could not be read|see the discovery'; Weight = 15; Because = 'the template objects could not be read' }) }
                @{ Id = 'acl-restricted'; Cause = 'The permissions of those templates hide the security descriptor from this account.'
                   Confirm = @('Run as an account the PKI owner allows to read the security descriptors.')
                   Fix = @('The PKI owner runs the review, or grants the audit account read access.') }
            ) }

        'ESC1' = @{
            Title = 'Review pattern ESC1: the requester names the identity in a sign-in certificate'
            What = 'A published template lets the requester supply the subject (or Subject Alternative Name), the certificate can be used to sign in, and a broad group (for example Authenticated Users or Domain Users) may enroll without approval. Anyone in that group could ask for a certificate in the name of any account, including an administrator, and use it to sign in. This is a pattern to review, not proof that anyone did it.'
            Sources = @('S22', 'S21', 'S18', 'S28', 'S29')
            Causes = @(
                @{ Id = 'app-needed-supply-subject'; Cause = 'The template was built for an application that needs its own subject names (web servers, network devices, a legacy system) and was left open to a broad group.'
                   Confirm = @('Read the template flags: certutil -v -template <TemplateName> (read only), look for ENROLLEE_SUPPLIES_SUBJECT and the application policies.', 'Check who actually uses the template (the CA database or the application owner).')
                   Fix = @('Remove the broad group from the Enroll permission and give it to the specific group of servers or service accounts that need it; or turn off "Supply in the request" and build the name from AD; or require CA manager approval.')
                   Signals = @(@{ When = 'Authenticated Users|Domain Users|Everyone|Domain Computers'; Weight = 10; Because = 'a broad group can enroll' }) }
                @{ Id = 'copied-default'; Cause = 'The template is a copy of a built-in one (such as Web Server) that kept the default permissions.'
                   Confirm = @('Compare the template with the original it was duplicated from.')
                   Fix = @('Restrict enrollment on the copy and prefer an unused template removed from the CA.') }
                @{ Id = 'unused-published'; Cause = 'The template is published but no longer used.'
                   Confirm = @('Look for issued certificates of this template on the CA (the CA owner).')
                   Fix = @('Remove it from the CA''s published templates.') }
            ) }

        'ESC2' = @{
            Title = 'Review pattern ESC2: a certificate valid for any purpose can be requested by a broad group'
            What = 'A template has the Any Purpose usage (or no usage restriction) and a broad group can enroll without approval. Such a certificate can be used for sign-in, as an enrollment agent, or as a sub-CA depending on its other settings, so it is more powerful than its owner usually thinks.'
            Sources = @('S22', 'S21', 'S28')
            Causes = @(
                @{ Id = 'sub-ca-or-legacy-template'; Cause = 'The template is a SubCA or legacy template, or was made without choosing a usage.'
                   Confirm = @('certutil -v -template <TemplateName> (read only): look at the application policies.')
                   Fix = @('Give the template only the usages it needs; restrict Enroll to the few accounts that need it; require manager approval for any template that can issue CA certificates.') }
            ) }

        'ESC3' = @{
            Title = 'Review pattern ESC3: a broad group can get an enrollment agent certificate'
            What = 'A broad group can enroll for a Certificate Request Agent certificate without approval, and another published template accepts that agent. With such a certificate a requester can enroll on behalf of other users, including privileged ones.'
            Sources = @('S22', 'S21', 'S28')
            Causes = @(
                @{ Id = 'agent-template-open'; Cause = 'The enrollment agent template was left open to a broad group (for a smart card or help desk process that is now narrower).'
                   Confirm = @('Read the template permissions in the CA console or certutil -v -template <TemplateName>.', 'List who truly acts as an enrollment agent.')
                   Fix = @('Limit Enroll on the agent template to the few agent accounts, require approval, and configure "Restrict enrollment agents" on the CA so agents can only act for named templates and users.')
                   }
            ) }

        'ESC4' = @{
            Title = 'Review pattern ESC4: a broad group can change a template'
            What = 'A broad group has write, owner or full-control rights on a template object. Anyone who can change a template can make it dangerous (for example turn on "supply in the request") and then use it.'
            Sources = @('S18', 'S21', 'S28')
            Causes = @(
                @{ Id = 'inherited-or-wide-acl'; Cause = 'Permissions on the template or its container were widened (a delegation for template management that included Authenticated Users, or Full Control left by a copy).'
                   Confirm = @('Read the template Security tab in the Certificate Templates console, or Get-Acl on the AD object path (view only).')
                   Fix = @('Remove write, owner and full-control rights from broad groups; the owner of a template should be a privileged, monitored account (Microsoft recommends this).') }
            ) }

        'ESC5' = @{
            Title = 'ESC5: unsafe permissions on PKI objects in Active Directory'
            What = 'Permissions on the CA computer object, the PKI containers (Public Key Services, NTAuthCertificates, AIA, CDP), or on the CA server itself let a low-privileged account change how the PKI works. This tool lists the template pattern ESC4 only; this entry is guidance for the wider review.'
            Sources = @('S21', 'S22')
            Causes = @(
                @{ Id = 'wide-container-permissions'; Cause = 'A group other than Enterprise Admins and the CA computer accounts can write to a PKI container.'
                   Confirm = @('Read the Security tab of CN=Public Key Services (ADSI Edit, view only).')
                   Fix = @('Remove write permissions for everyone except the PKI owners and the CA computer accounts that need them.') }
            ) }

        'ESC6' = @{
            Title = 'ESC6: the CA lets requesters name the identity in any request'
            What = 'When the flag EDITF_ATTRIBUTESUBJECTALTNAME2 is set on a CA, requesters can add any Subject Alternative Name to a request, whatever the template says. Together with a template that allows sign-in, this lets anyone impersonate anyone. This tool does not read the CA registry (it needs rights on the CA host); this entry is for the owner''s review.'
            Sources = @('S31', 'S21')
            Causes = @(
                @{ Id = 'flag-set-for-an-old-app'; Cause = 'The flag was set years ago to make an old application work.'
                   Confirm = @('On the CA (owner): certutil -getreg policy\EditFlags  (read only; look for EDITF_ATTRIBUTESUBJECTALTNAME2).')
                   Fix = @('Clear the flag (certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2), restart Certificate Services, and use the SAN field of a template instead.') }
            ) }

        'ESC7' = @{
            Title = 'ESC7: broad groups hold Manage CA or Manage Certificates on a CA'
            What = 'Whoever holds Manage Certificates can approve pending requests; whoever holds Manage CA can change CA settings, including the flag that causes ESC6. Both rights belong only to the PKI administrators.'
            Sources = @('S18', 'S21')
            Causes = @(
                @{ Id = 'wide-ca-acl'; Cause = 'The CA security tab grants these rights to a broad or unprivileged group.'
                   Confirm = @('On the CA (owner): CA properties > Security tab.')
                   Fix = @('Remove Manage CA and Manage Certificates from every unprivileged group.') }
            ) }

        'ESC8' = @{
            Title = 'ESC8: an enrollment web page accepts Windows sign-in over plain HTTP or without relay protection'
            What = 'Web Enrollment or an enrollment web service that accepts NTLM sign-in without HTTPS and Extended Protection for Authentication can be used for an NTLM relay: an attacker makes a privileged computer (such as a domain controller) authenticate to them and forwards it to the CA, then receives a certificate in that computer''s name. This has been used to take over whole domains.'
            Sources = @('S18', 'S30', 'S21')
            Causes = @(
                @{ Id = 'http-and-ntlm'; Cause = 'The enrollment pages are served over HTTP, or over HTTPS without Extended Protection, with NTLM allowed.'
                   Confirm = @('On the web server (owner): IIS > the Certsrv or CES application > Authentication (Windows authentication providers) and SSL settings; the finding evidence lists the schemes offered.')
                   Fix = @('Require HTTPS, turn on Extended Protection for Authentication (Required) in Windows authentication, disable NTLM on those endpoints where possible, or remove the Web Enrollment role if nobody uses it. See Microsoft KB5005413.')
                   Signals = @(@{ When = 'plain HTTP|served over HTTP|over HTTP'; Weight = 25; Because = 'sign-in is offered over plain HTTP' }
                               @{ When = 'NTLM'; Weight = 10; Because = 'NTLM is offered' }) }
                @{ Id = 'role-not-needed'; Cause = 'Web Enrollment was installed with the CA and is not used (clients enroll through the console or autoenrollment).'
                   Confirm = @('Ask whether anyone uses the certsrv web pages.')
                   Fix = @('Uninstall the Web Enrollment role service.') }
            ) }

        'ESC9' = @{
            Title = 'Review pattern ESC9: a template issues certificates without the security identifier'
            What = 'A published template does not put the requester''s security identifier (SID) into the certificate, the certificate can be used to sign in, and a broad group can enroll. Domain controllers then map the certificate by name only, which can be abused to impersonate another account. How much this matters depends on whether the domain controllers enforce strong certificate mapping.'
            Sources = @('S19', 'S21')
            Causes = @(
                @{ Id = 'security-extension-off'; Cause = 'The template has the flag that turns off the szOID_NTDS_CA_SECURITY_EXT extension (a legacy compatibility setting).'
                   Confirm = @('certutil -v -template <TemplateName> (read only): look for CT_FLAG_NO_SECURITY_EXTENSION.', 'On a domain controller (owner): reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement')
                   Fix = @('Remove the flag from the template unless a documented legacy need exists; keep the domain controllers in Full Enforcement mode (the default since the February 2025 update, see KB5014754).')
                   Signals = @(@{ When = 'ReviewRequired'; Weight = 5; Because = 'the tool marks this pattern for review only' }) }
            ) }

        'ESC10' = @{
            Title = 'ESC10: weak certificate mapping on domain controllers'
            What = 'If domain controllers still map certificates to accounts the old, weak way (registry settings StrongCertificateBindingEnforcement or CertificateMappingMethods), an attacker who can change an account name can obtain a certificate that maps to another account. This tool does not read domain controller registry settings; this entry is for the owner''s review.'
            Sources = @('S19', 'S21')
            Causes = @(
                @{ Id = 'compat-mode'; Cause = 'The domain controllers are in Compatibility or Disabled mode for strong mapping.'
                   Confirm = @('On a domain controller (owner): reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement', 'reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL /v CertificateMappingMethods')
                   Fix = @('Set StrongCertificateBindingEnforcement to 2 (Full Enforcement) once the audit events show no weakly mapped certificate, and remove the weak Schannel mapping methods.') }
            ) }

        'ESC11' = @{
            Title = 'ESC11: the CA''s RPC enrollment interface does not require encryption'
            What = 'If the CA does not insist on encrypted RPC requests (the flag IF_ENFORCEENCRYPTICERTREQUEST is off), NTLM relay works against the RPC enrollment interface like it does against the web pages (ESC8). Microsoft''s own assessment lists it. This tool cannot read the CA registry; this entry is for the owner''s review.'
            Sources = @('S18', 'S21')
            Causes = @(
                @{ Id = 'flag-off-for-old-clients'; Cause = 'The flag was turned off to support old clients (Windows XP).'
                   Confirm = @('On the CA (owner): certutil -getreg CA\InterfaceFlags  (read only).')
                   Fix = @('Turn the flag on (certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST), restart Certificate Services; test with a non-production CA first.') }
            ) }

        'ESC12' = @{
            Title = 'ESC12: CA key stored on a network HSM with a shared secret'
            What = 'When a CA''s private key sits on a network HSM that is reachable by people who can run code on the CA host, the key can be used by them. This only applies to specific HSM setups. This tool cannot see it.'
            Sources = @('S21')
            Causes = @(
                @{ Id = 'hsm-access'; Cause = 'The CA key store provider grants access to anyone who can log in to the CA host.'
                   Confirm = @('Review the HSM client configuration with the HSM administrator.')
                   Fix = @('Protect the HSM key with a separate authentication that the CA host users do not hold.') }
            ) }

        'ESC13' = @{
            Title = 'Review pattern ESC13: an issuance policy is linked to a group that a broad group can obtain'
            What = 'A template carries an issuance policy that is linked to an AD group, and a broad group can enroll. A certificate with that policy adds the linked group to the holder''s Kerberos ticket, so enrolling is a way to gain that group''s rights.'
            Sources = @('S20', 'S21')
            Causes = @(
                @{ Id = 'policy-linked-to-privileged-group'; Cause = 'The link was made for a scoped access scenario (a certificate-based group membership) and the template is open to too many accounts.'
                   Confirm = @('Read msDS-OIDToGroupLink on the issuance policy OID, and the group''s members and rights.')
                   Fix = @('Limit Enroll on the template to the accounts that should hold the group''s rights, or remove the link, or do not link to groups with powerful rights.') }
            ) }

        'ESC14' = @{
            Title = 'ESC14: weak explicit certificate mapping (altSecurityIdentities)'
            What = 'If an account''s altSecurityIdentities attribute holds a weak mapping (by subject or issuer name only), someone who can obtain a certificate that matches it, or who can write the attribute, can sign in as that account. This tool does not read this attribute.'
            Sources = @('S21', 'S19')
            Causes = @(
                @{ Id = 'weak-mapping'; Cause = 'Explicit mappings by name were created for smart card or application sign-in.'
                   Confirm = @('Read altSecurityIdentities of privileged accounts (view only) and look for mappings that are not by issuer plus serial number, SKI or SHA1 of the public key.')
                   Fix = @('Replace weak mappings with strong ones and limit who can write the attribute.') }
            ) }

        'ESC15' = @{
            Title = 'ESC15: version 1 templates accept injected application policies (CVE-2024-49019)'
            What = 'On an unpatched CA, a requester could add extra application policies to a request for a schema version 1 template that lets the requester name the subject, and obtain a certificate with more uses than the template allows. Microsoft fixed this in November 2024.'
            Sources = @('S21')
            Causes = @(
                @{ Id = 'unpatched-ca-and-v1-template'; Cause = 'The CA misses the November 2024 security updates, and a schema version 1 template with "supply in the request" is published.'
                   Confirm = @('On the CA (owner): Get-HotFix or Settings > Windows Update history for the November 2024 and later cumulative updates.', 'certutil -v -template <TemplateName>: the schema version is the first line of properties.')
                   Fix = @('Install the CA security updates, and replace version 1 templates with version 2 or later copies.') }
            ) }

        'ESC16' = @{
            Title = 'ESC16: the CA switches off the security identifier extension for every certificate'
            What = 'A CA setting can disable the security identifier (SID) extension on all certificates it issues, which has the same effect as ESC9 for every template. This tool does not read the CA registry.'
            Sources = @('S21', 'S19')
            Causes = @(
                @{ Id = 'ca-wide-disable'; Cause = 'The CA''s policy module lists the SID extension OID as disabled (a compatibility setting).'
                   Confirm = @('On the CA (owner): certutil -getreg policy\DisableExtensionList  (read only).')
                   Fix = @('Remove 1.3.6.1.4.1.311.25.2 from the list unless a documented need exists, and keep domain controllers in Full Enforcement mode.') }
            ) }

        'OBJECT_EXPIRED' = @{
            Title = 'A certificate or object has expired'
            What = 'Something with an end date (a certificate, a CRL, a recovery agent) is past it. What breaks depends on what it is: the finding message says which.'
            Sources = @('S03', 'S26')
            Causes = @(
                @{ Id = 'renewal-missed'; Cause = 'It was not renewed in time (no autoenrollment, no calendar entry, an owner who left).'
                   Confirm = @('Read the end date in the finding; Get-ChildItem Cert:\LocalMachine\My | Select Subject, NotAfter on the host.')
                   Fix = @('Renew it and add monitoring for the next expiry.') }
                @{ Id = 'old-history'; Cause = 'It is an old, replaced object that is still listed.'
                   Confirm = @('Check whether a valid replacement exists.')
                   Fix = @('Remove the old entry when no valid certificate depends on it.') }
            ) }

        'OBJECT_EXPIRING' = @{
            Title = 'A certificate or object expires soon'
            What = 'Something with an end date is close to it. Renew before it ends; after that the finding becomes an expiry.'
            Sources = @('S26')
            Causes = @(
                @{ Id = 'normal-lifecycle'; Cause = 'Normal end of life; renewal is due.'
                   Confirm = @('Read the end date in the finding.')
                   Fix = @('Renew it in time and check that autoenrollment or the renewal process works.') }
            ) }

        'PUBLICATION_FAIL' = @{
            Title = 'Something that should be published is not where it is expected'
            What = 'An object, file or value that the PKI should publish (to AD, to a web server, to this computer''s store) is missing or has no value.'
            Sources = @('S13', 'S37', 'S38')
            Causes = @(
                @{ Id = 'permissions-on-target'; Cause = 'The publishing account or the CA computer account may not write to the target.'
                   Confirm = @('Application log of the CA (owner): events 74 and 66 name the target and the error.')
                   Fix = @('Fix the permission on the target (Cert Publishers for AD containers, folder rights for web folders).') }
                @{ Id = 'never-published'; Cause = 'The publish step was never done or the option is switched off.'
                   Confirm = @('CA properties > Extensions: the "Publish" boxes.')
                   Fix = @('Enable publishing and publish again.') }
            ) }

        'SIGNATURE_INVALID' = @{
            Title = 'A signature does not verify'
            What = 'A certificate or CRL claims to be signed by a CA, but the signature does not verify with that CA''s key. The object is not what it claims to be, or the wrong key was used to check it.'
            Sources = @('S14', 'S26')
            Causes = @(
                @{ Id = 'wrong-generation'; Cause = 'The object is checked against another generation of the CA (after a renewal with a new key).'
                   Confirm = @('Compare the Authority Key Identifier of the object with the Subject Key Identifier of each CA generation.')
                   Fix = @('Publish the matching CA generation, or the file that was signed by the current key.') }
                @{ Id = 'tampered-or-wrong-file'; Cause = 'The file is not from this CA (a wrong file at the URL, a damaged download, or a forged object).'
                   Confirm = @('Fetch the file again and compare its hash with the CA''s own copy.')
                   Fix = @('Restore the file from the CA and restrict who can write to the folder.') }
            ) }

        'CHAIN_UNTRUSTED_ROOT' = @{
            Title = 'A CA certificate chain ends at a root that is not trusted here'
            What = 'The chain of a CA certificate ends at a self-signed root that this computer does not have in its Trusted Root store.'
            Sources = @('S41', 'S24')
            Causes = @(
                @{ Id = 'root-not-distributed'; Cause = 'The enterprise root is published in AD but this computer has not received it yet (Group Policy refresh, a non-domain computer).'
                   Confirm = @('Get-ChildItem Cert:\LocalMachine\Root | Select Subject, Thumbprint', 'gpresult /r  (are the computer policies applied?)')
                   Fix = @('Let the domain deliver the root (run gpupdate /force on this computer, then check again), or install it where it is needed.') }
                @{ Id = 'foreign-root'; Cause = 'The root belongs to another PKI that this computer does not trust by design.'
                   Confirm = @('Read the root''s name in the evidence.')
                   Fix = @('Trust it deliberately (cross-certification or the Trusted Root store) only if you mean to.') }
            ) }

        'CHAIN_PARTIAL' = @{
            Title = 'A CA certificate chain cannot be completed'
            What = 'An intermediate CA certificate needed to link this certificate to a root is missing and could not be fetched.'
            Sources = @('S14', 'S15', 'S32')
            Causes = @(
                @{ Id = 'aia-missing'; Cause = 'The AIA extension points to a location that is down, or only to LDAP.'
                   Confirm = @('certutil -verify -urlfetch <CertificateFile> (read only) lists every URL tried.')
                   Fix = @('Publish the issuing CA certificate to a working HTTP AIA location.') }
                @{ Id = 'not-in-ad'; Cause = 'The issuing CA certificate is not in the AIA container of AD.'
                   Confirm = @('Compare with the AIA container (ADSI Edit, view only).')
                   Fix = @('Publish the CA certificate to AD.') }
            ) }

        'CHAIN_INVALID' = @{
            Title = 'A CA certificate chain has a problem'
            What = 'A CA certificate fails a chain check: a certificate is outside its issuer''s validity, has a constraint problem, or the chain engine reported another error. The finding message names it.'
            Sources = @('S26', 'S14')
            Causes = @(
                @{ Id = 'validity-outside-issuer'; Cause = 'The CA certificate ends after (or begins before) the certificate that issued it.'
                   Confirm = @('Compare the dates of the chain in the evidence.')
                   Fix = @('Renew the CA certificate with a validity inside its issuer''s.') }
                @{ Id = 'revocation-offline'; Cause = 'A certificate in the chain cannot be checked for revocation because its CRL is expired or unreachable.'
                   Confirm = @('certutil -verify -urlfetch <CaCertificateFile> (read only).')
                   Fix = @('Fix the CRL publication (see the CRL topics).')
                   Signals = @(@{ When = 'revocation|CRL'; Weight = 20; Because = 'the finding mentions revocation or a CRL' }) }
            ) }

        'ENROLLMENT_FAIL' = @{
            Title = 'This computer reported an enrollment problem'
            What = 'Windows logged an enrollment failure on this computer (autoenrollment or a manual request). The event text names the template and the CA when Windows knows them.'
            Sources = @('S01', 'S12')
            Causes = @(
                @{ Id = 'ca-unreachable-or-denied'; Cause = 'The CA could not be reached over RPC, or the account may not enroll (the same causes as the DCOM and RPC topics).'
                   Confirm = @('certutil -config "<CAHost>\<CAName>" -ping from this computer.', 'Read the Application log event text for the HRESULT.')
                   Fix = @('See the RPC and DCOM topics; for 0x800706BA check the DCOM access group on the CA host.')
                   Signals = @(@{ When = '800706BA|RPC'; Weight = 25; Because = 'the event names an RPC failure' }) }
                @{ Id = 'template-permission'; Cause = 'The account lacks Enroll or Autoenroll on the template, or the template is not published by that CA.'
                   Confirm = @('Look at the template permissions and the CA''s published template list.')
                   Fix = @('Grant Enroll (and Autoenroll for automatic requests) to the right group; publish the template.') }
                @{ Id = 'request-rejected'; Cause = 'The CA policy denied the request (subject name rules, a missing manager approval, key size).'
                   Confirm = @('CA Application log (owner): the failed request event with the disposition text.')
                   Fix = @('Fix the request or the template settings.') }
            ) }

        'CONFIG_RISK' = @{
            Title = 'A setting increases risk'
            What = 'The configuration works today, but the way it is set up weakens security or resilience. The message names the setting.'
            Sources = @('S14', 'S21')
            Causes = @(
                @{ Id = 'historic-default'; Cause = 'It is an old default or a choice made for a use that has changed.'
                   Confirm = @('Read the message and the evidence; ask who owns the setting.')
                   Fix = @('Change it in the way the finding''s remediation describes, in a test environment first.') }
                @{ Id = 'intentional'; Cause = 'It is deliberate and the risk is accepted.'
                   Confirm = @('Check the PKI design document.')
                   Fix = @('Document the decision.') }
            ) }

        'CONFIG_MISMATCH' = @{
            Title = 'Two sources of the same fact disagree'
            What = 'Two places that should agree (for example AD and the CA, or two publication locations) differ. One of them is wrong or out of date.'
            Sources = @('S12', 'S14')
            Causes = @(
                @{ Id = 'one-side-not-updated'; Cause = 'A change was made in one place and not in the other (a renewal, a rename, a published template).'
                   Confirm = @('Compare the two values shown in the evidence.')
                   Fix = @('Update the one that is out of date from the CA, which is the source of truth for its own configuration.') }
                @{ Id = 'replication'; Cause = 'Directory replication has not finished.'
                   Confirm = @('Read the object from another domain controller; repadmin /showrepl.')
                   Fix = @('Wait, or fix replication.') }
            ) }
}
