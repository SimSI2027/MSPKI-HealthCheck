# MSPKI Health Check diagnosis knowledge base, topics: Pki. DATA ONLY. Format and rules: see Diagnosis.psd1.
@{
        # ===== CRL, AIA, CDP, CA certificates, AD containers, OCSP =====
        'CRL_EXPIRED' = @{
            Title = 'A CRL has expired'
            What = 'A certificate revocation list is past its Next Update time. Clients cannot prove that certificates from this CA are not revoked, so revocation checks fail (error 0x80092013, "revocation server was offline") and logons, TLS connections or even the CA itself can stop working.'
            Sources = @('S03', 'S14', 'S16', 'S13', 'S32')
            Causes = @(
                @{ Id = 'publication-stopped'; Cause = 'The CA could not publish a new CRL on schedule (the CA service stopped, or publishing to a CDP location is failing: permissions on the AD container or the web folder, a dead share).'
                   Confirm = @('On the CA (owner): Application log, source CertificationAuthority, events 74 and 66 (the path and error are in the text).', 'certutil -URL <Url>  (shows what each CDP location returns)')
                   Fix = @('Fix the permission or path named in the event (the CA computer account needs write access to the AD CDP container and the web folder), then publish a new CRL from the CA console.')
                   Signals = @(@{ When = 'Category=CRL'; Weight = 5; Because = 'the finding is about a CRL' }) }
                @{ Id = 'offline-root-forgotten'; Cause = 'It is the CRL of an offline root CA, and nobody started the root before the CRL ran out.'
                   Confirm = @('Look at the CRL Next Update date against the CA validity period setting.')
                   Fix = @('Start the offline root, sign and publish a new CRL, copy it to every CDP location, then lengthen the CRL period to what the ceremony calendar can keep.')
                   Signals = @(@{ When = 'offline root|EnterpriseRoot|StandaloneRoot'; Weight = 30; Because = 'the CRL belongs to a root CA' }) }
                @{ Id = 'copy-not-refreshed'; Cause = 'The CA made a new CRL, but the copy at the HTTP location was not refreshed (a manual copy step), so clients still see the old file.'
                   Confirm = @('Compare the CRL number at the URL with the CRL number the CA reports (CA properties, or the CA''s own CRL in the findings).')
                   Fix = @('Copy the new CRL to the web folder, and automate the copy.')
                   Signals = @(@{ When = 'newer number|another location'; Weight = 40; Because = 'another location already serves a newer CRL' }) }
            ) }

        'CRL_EXPIRING' = @{
            Title = 'A CRL is close to its expiry'
            What = 'A CRL will pass its Next Update soon. If nothing publishes a new one before then, revocation checks fail for everyone.'
            Sources = @('S14', 'S16')
            Causes = @(
                @{ Id = 'normal-cycle'; Cause = 'It is simply late in the CRL cycle. An online CA publishes a new CRL before it expires (at half the period for a base CRL, by default).'
                   Confirm = @('Check again after the scheduled publication time.')
                   Fix = @('Nothing if the next publication succeeds; otherwise see the publication topic.') }
                @{ Id = 'publication-broken'; Cause = 'The scheduled publication is failing and this is the first visible sign.'
                   Confirm = @('On the CA (owner): Application log events 74 / 66, and certutil -URL <Url>.')
                   Fix = @('Fix the publication problem now; do not wait for the expiry.') }
            ) }

        'CRL_STALE' = @{
            Title = 'A CRL or published data is older than it should be'
            What = 'A location serves a copy of a CRL that is out of date compared with what the CA itself has. Clients that use that location see old revocation data.'
            Sources = @('S14', 'S13', 'S03')
            Causes = @(
                @{ Id = 'one-location-not-updated'; Cause = 'The CA publishes to several locations; one failed (AD, an HTTP folder, a file share) and the others are current.'
                   Confirm = @('Compare the CRL number from each location in the finding evidence.')
                   Fix = @('Fix the failing location (permissions or path) and publish again.')
                   Signals = @(@{ When = 'newer number|another location'; Weight = 30; Because = 'another location has a newer CRL number' }) }
                @{ Id = 'replication-delay'; Cause = 'The CRL object in AD has not replicated yet to the domain controller that was read.'
                   Confirm = @('Read the same object from another domain controller; repadmin /showrepl.')
                   Fix = @('Wait for replication or fix the replication that is stuck.')
                   Signals = @(@{ When = 'LDAP|ldap:'; Weight = 15; Because = 'the stale copy is in AD' }) }
                @{ Id = 'cache'; Cause = 'A proxy or the web server caches the old file.'
                   Confirm = @('Request the URL with a cache-busting query from the client network.')
                   Fix = @('Exclude CRL URLs from caching, or lower the cache time.') }
            ) }

        'CRL_NUMBER_MISMATCH' = @{
            Title = 'Two locations serve different CRL numbers'
            What = 'The same CA''s CRL has a lower number at one location than at another. Clients see different revocation data depending on which URL they use first.'
            Sources = @('S14', 'S13')
            Causes = @(
                @{ Id = 'publish-partly-failed'; Cause = 'The last publication reached some locations only (a failed write to the web folder or to AD).'
                   Confirm = @('Application log of the CA (owner): events 74 (base CRL) and 66 (delta CRL) name the failed path.')
                   Fix = @('Fix the failing path, then publish again so all locations match.') }
                @{ Id = 'manual-copy-lag'; Cause = 'An HTTP location is filled by a manual or scheduled copy that has not run yet.'
                   Confirm = @('Check the time of the file on the web server against the CA''s publication time.')
                   Fix = @('Automate the copy, or publish directly to the web folder.') }
            ) }

        'CRL_PUBLICATION_FAIL' = @{
            Title = 'A CRL or CA certificate is not published where the extension says'
            What = 'A CDP or AIA location was reached, but the object or file that should be there is missing or has no value, so clients that use this location get nothing.'
            Sources = @('S13', 'S37', 'S38', 'S14')
            Causes = @(
                @{ Id = 'ad-permissions'; Cause = 'The CA computer account cannot write to its CDP or AIA object in AD (it is not in Cert Publishers, or the container permissions were changed, or the CA is in another domain than the container).'
                   Confirm = @('On the CA (owner): Application log events 74 or 66; look for error 0x80072098 or 0x80070005.', 'Check that the CA computer account is a member of Cert Publishers in the domain that holds the container.')
                   Fix = @('Add the CA computer account to Cert Publishers (in every domain that hosts the containers) and fix the container permissions; then publish a new CRL.')
                   Signals = @(@{ When = 'ldap:|LDAP|does not match the URL filter|no .* value'; Weight = 20; Because = 'the missing object is in Active Directory' }) }
                @{ Id = 'never-published'; Cause = 'The CA never published to that location (the "Publish CRLs to this location" box is unticked), or a new CA key was never published there.'
                   Confirm = @('CA properties > Extensions > select CRL Distribution Point, and read the boxes for the location.')
                   Fix = @('Enable publishing for the location, or remove the location from the extension if it is not maintained.') }
                @{ Id = 'object-removed'; Cause = 'Someone cleaned up the AD PKI containers and removed the CRL or certificate object.'
                   Confirm = @('Check the container in ADSI Edit (view only).')
                   Fix = @('Publish again from the CA.') }
            ) }

        'CDP_LDAP_ONLY' = @{
            Title = 'Revocation and CA certificate data is published only over LDAP'
            What = 'The CA lists only LDAP URLs for its CDP or AIA. Only computers that can query this forest''s directory can fetch the CRL or the CA certificate. Computers outside the domain, non-Windows systems, devices and other forests cannot, so their revocation checks fail or are skipped.'
            Sources = @('S14', 'S15')
            Causes = @(
                @{ Id = 'ldap-only-by-choice'; Cause = 'It is a deliberate or inherited choice: an Enterprise CA can serve a domain-only audience with LDAP alone, and nobody added an HTTP location.'
                   Confirm = @('Ask which computers and devices need to check certificates from this CA (non-domain computers, Linux, network devices, other forests).')
                   Fix = @('If any such client exists, add an HTTP CDP and AIA location on a simple web server (port 80), publish the files there, and put the HTTP URLs first. This only affects certificates issued afterwards.')
                   Signals = @(@{ When = 'no HTTP URL'; Weight = 10; Because = 'the extension lists no HTTP URL at all' }) }
                @{ Id = 'only-domain-clients'; Cause = 'All clients are domain members in this forest, so LDAP is enough for them. It then works, with the risk that outside clients fail.'
                   Confirm = @('Check whether any device or partner validates certificates from this CA.')
                   Fix = @('Accept it and document it, or add HTTP anyway for resilience (Microsoft recommends HTTP as the main method).') }
            ) }

        'OFFLINE_ROOT_CRL_SHORT' = @{
            Title = 'An offline root issues CRLs that last only a few days'
            What = 'An offline root must be started to sign each new CRL. A short validity means frequent ceremonies, and one missed date stops revocation checking for the whole hierarchy.'
            Sources = @('S14', 'S16')
            Causes = @(
                @{ Id = 'default-period'; Cause = 'The root still uses a short default CRL period or was never tuned for an offline root.'
                   Confirm = @('CA properties > Revocation or certutil -getreg CA\CRLPeriod and CA\CRLPeriodUnits on the root (read only).')
                   Fix = @('Set the base CRL period for the root to months (Microsoft examples use 6 to 12 months) and disable delta CRLs on the root, then sign a new CRL.') }
            ) }

        'OFFLINE_ROOT_CRL_UNKNOWN' = @{
            Title = 'No CRL of an offline root could be read'
            What = 'The tool found no CRL of this root in any location, so it cannot judge its lifetime. Clients may not be able to check the issuing CAs for revocation.'
            Sources = @('S14', 'S15')
            Causes = @(
                @{ Id = 'never-published'; Cause = 'The root''s CRL was never published to AD or a web server (a manual step that nobody did).'
                   Confirm = @('On the root: look for the .crl file in the CertEnroll folder, and check the CDP extension of the issuing CAs.')
                   Fix = @('Publish the root CRL to the locations named in the CDP extension of its certificates.')
                   Signals = @(@{ When = 'No CRL .* was read from any location'; Weight = 10; Because = 'no location returned a CRL for this root' }) }
                @{ Id = 'urls-unreachable'; Cause = 'The root has no usable CDP URL, or every URL is unreachable from here.'
                   Confirm = @('Run: certutil -verify -urlfetch on an issuing CA certificate and read the CDP results.')
                   Fix = @('Add an HTTP CDP location and publish the CRL there.') }
            ) }

        'OFFLINE_ROOT_CRL_EXPIRED' = @{
            Title = 'The CRL of an offline root has expired'
            What = 'The last CRL signed by the root is past its Next Update. Chain validation for every certificate below the root, and the start-up of the issuing CAs, can fail.'
            Sources = @('S16', 'S14', 'S03')
            Causes = @(
                @{ Id = 'ceremony-missed'; Cause = 'The root was not started in time to sign a new CRL.'
                   Confirm = @('Compare the Next Update time in the finding with today.')
                   Fix = @('Start the offline root, sign a new CRL, copy it to every CDP location, and lengthen the CRL period. Keep the ceremony in a calendar.') }
                @{ Id = 'copy-missed'; Cause = 'A new CRL exists on the root but was never copied to the web server or AD.'
                   Confirm = @('Compare the CRL number on the root with the one at the URL.')
                   Fix = @('Copy it to every location named in the CDP extension.') }
            ) }

        'OFFLINE_ROOT_CRL_EXPIRING' = @{
            Title = 'The CRL of an offline root is close to expiry'
            What = 'The next CRL ceremony for the root is due soon. If it is missed, revocation checking for the whole hierarchy fails.'
            Sources = @('S14', 'S16')
            Causes = @(
                @{ Id = 'schedule'; Cause = 'The date is simply near; the ceremony may already be planned.'
                   Confirm = @('Check the ceremony calendar.')
                   Fix = @('Schedule it and start the root before the expiry.') }
            ) }

        'AIA_WRONG_CERT' = @{
            Title = 'The CA certificate at an AIA location is not the expected one'
            What = 'An AIA URL returns a certificate that is the wrong issuer, has a bad signature, or has the right name with a different key. Clients that follow this URL to build a chain get the wrong certificate and chain building fails.'
            Sources = @('S14', 'S26', 'S15')
            Causes = @(
                @{ Id = 'renewed-not-republished'; Cause = 'The CA certificate was renewed with a new key and the AIA file was not replaced, or was replaced under another name.'
                   Confirm = @('Compare the thumbprint of the file at the URL with the CA certificate generations in AD.')
                   Fix = @('Publish the current CA certificate to the exact file name the AIA URL uses.')
                   Signals = @(@{ When = 'not the key|not the expected issuer'; Weight = 15; Because = 'the file is a different key or issuer' }) }
                @{ Id = 'tampered'; Cause = 'The file was replaced by something that is not a CA certificate of this hierarchy (a wrong file, or a malicious one).'
                   Confirm = @('Check whether the signature verifies; compare the file hash with the CA certificate in AD.')
                   Fix = @('Restore the right file from the CA and review who can write to the web folder.')
                   Signals = @(@{ When = 'signature does not verify|SIGNATURE_INVALID'; Weight = 35; Because = 'the signature of the file does not verify' }) }
            ) }

        'CA_CERT_EXPIRED' = @{
            Title = 'A CA certificate has expired'
            What = 'A CA certificate is past its end date. Every certificate chained to it is invalid, and the CA cannot issue valid certificates until it has a new certificate.'
            Sources = @('S26', 'S33')
            Causes = @(
                @{ Id = 'renewal-missed'; Cause = 'The CA certificate was not renewed in time.'
                   Confirm = @('certutil -verify <CaCertificateFile>', 'Look at the Valid to date in the finding.')
                   Fix = @('Renew the CA certificate (new key or same key, as the PKI design requires) and publish it to AD and the AIA location.') }
                @{ Id = 'old-generation'; Cause = 'It is an old generation from before a renewal, still listed in AD. Expired old generations are harmless unless certificates issued under them are still in use.'
                   Confirm = @('Check whether a newer generation of the same CA exists and is valid.')
                   Fix = @('Remove expired generations from AIA and NTAuth when no certificate that has not expired depends on them.')
                   Signals = @(@{ When = 'generation|Historical|historical'; Weight = 25; Because = 'the finding is about an older generation' }) }
            ) }

        'CA_CERT_EXPIRING' = @{
            Title = 'A CA certificate will expire soon'
            What = 'A CA certificate is near its end date. When it expires, everything it issued stops being valid. Renewal takes planning because the new certificate must reach every client.'
            Sources = @('S26', 'S12')
            Causes = @(
                @{ Id = 'lifecycle'; Cause = 'Normal end of the CA certificate lifetime.'
                   Confirm = @('Valid to date in the finding.')
                   Fix = @('Plan the renewal now: renew the CA certificate, publish it (AD, AIA), let clients receive it, then reissue or let autoenrollment replace what it issued.') }
            ) }

        'CA_CERT_WEAK' = @{
            Title = 'A CA certificate uses weak or short-lived cryptography'
            What = 'The CA certificate uses a short key, an outdated hash, an unusual validity, or does not chain to its issuer in the way expected. These settings are fixed when the CA certificate is made; changing them means renewing the CA.'
            Sources = @('S26', 'S14')
            Causes = @(
                @{ Id = 'old-defaults'; Cause = 'The CA was installed years ago with defaults that were acceptable then (SHA-1 signature, 1024-bit key).'
                   Confirm = @('The finding names the weak property; certutil -dump <CaCertificateFile> shows key length and signature algorithm.')
                   Fix = @('Renew the CA certificate with a new key (RSA 2048 or more, SHA-256 or better) and migrate issuance.') }
                @{ Id = 'validity-inside-issuer'; Cause = 'The validity of the CA certificate runs longer than that of its issuer, or begins before it.'
                   Confirm = @('Compare the validity dates of the CA and its issuer in the finding evidence.')
                   Fix = @('Renew the CA certificate with a validity that stays inside its issuer''s.') }
            ) }

        'CA_GENERATION_UNKNOWN' = @{
            Title = 'A CA has more than one certificate in AD and the tool cannot tell which one is old'
            What = 'AD holds more than one certificate for the same CA name. One is the current one; for the others the tool cannot tell whether they are older generations that belong to this CA (after a renewal) or belong to an earlier installation of a CA with the same name. The CA itself lists only its current signing certificate. Old generations are harmless unless certificates issued under them are still in use, but they widen what AD trusts for logon (NTAuth) and what clients try to build chains with.'
            Sources = @('S26', 'S33', 'S24')
            Causes = @(
                @{ Id = 'earlier-installation'; Cause = 'The CA was rebuilt or reinstalled with the same name (a new key), and the objects of the earlier installation were never cleaned out of AD.'
                   Confirm = @('Compare the validity dates and key of the "Unknown" certificate with the current one: an earlier installation has its own key and start date, not a renewal of the same key.', 'The CA''s own list of signing certificates (CA console > Properties > General > CA certificates) names only the current certificate.', 'certutil -viewstore -enterprise NTAuth lists which generations AD trusts for logon.')
                   Fix = @('If nothing issued under the earlier installation is still in use, remove the old certificate from the AD containers that hold it (Certification Authorities, AIA, NTAuth, Enrollment Services). If something still depends on it, keep it and note why. Both are actions for the PKI owner (Enterprise Admin rights).')
                   Signals = @(@{ When = '(?m)^Evidence:.*not among the CA''s own signing certificates'; Weight = 20; Because = 'the CA does not list this certificate among its own signing certificates' }) }
                @{ Id = 'renewal-generation'; Cause = 'It is an older generation from a renewal with a new key, and the CA no longer lists it as a signing certificate because it expired or was archived.'
                   Confirm = @('Check whether the certificate has the same subject and was signed by the same root, and whether its dates precede the current certificate.')
                   Fix = @('Keep it while certificates issued under it are valid; remove it afterwards.') }
                @{ Id = 'read-incomplete'; Cause = 'The CA could not be asked for its signing certificates in this run, so no certificate could be marked historical.'
                   Confirm = @('Look for a CA finding (permission denied or RPC) in the same run.')
                   Fix = @('Fix the CA connection and run again; the split is then usually clear.')
                   Signals = @(@{ When = 'could not be read|was not read'; Weight = 25; Because = 'the CA was not read in this run' }) }
            ) }
        'NTAUTH_AIA_MISMATCH' = @{
            Title = 'A CA certificate generation is in NTAuth but not in the AIA container'
            What = 'A generation of the CA''s certificate is listed in NTAuthCertificates (so AD trusts it for logon) but is missing from the AIA container (so clients cannot download it to build a chain). Certificates signed under that generation may fail chain building, or an old generation may stay trusted for logon longer than intended.'
            Sources = @('S24', 'S41', 'S26')
            Causes = @(
                @{ Id = 'renewal-leftover'; Cause = 'The CA certificate was renewed with a new key. Windows adds each new generation to NTAuth and AIA, but an old generation was removed from AIA (or never added), while it stayed in NTAuth.'
                   Confirm = @('certutil -viewstore -enterprise NTAuth  (lists the NTAuth certificates)', 'certutil -viewstore "ldap:///CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,<ForestDN>?cACertificate?one?objectClass=certificationAuthority"  (or ADSI Edit, view only)', 'Compare thumbprints and note which generation is missing from AIA.')
                   Fix = @('If certificates issued under the old generation are still in use: publish that generation to AIA again. If none are: remove the old generation from NTAuth so logon does not trust it any longer. Both are actions for the PKI owner (Enterprise Admin rights).')
                   Signals = @(@{ When = 'lifecycle: Historical'; Weight = 15; Because = 'the CA lists this generation as a historical one of its own signing certificates' }) }
                @{ Id = 'earlier-installation'; Cause = 'The CA was rebuilt or reinstalled with the same name (a new key) and the certificate of the earlier installation stayed in NTAuth, but was never put into AIA. This is not a renewal: the CA itself does not list that certificate.'
                   Confirm = @('Compare the key and start date of the certificate with the current one; an earlier installation has its own key, not a renewal of the same key.', 'The CA''s own list of signing certificates (CA console > Properties > General > CA certificates) names only the current certificate.', 'certutil -viewstore -enterprise NTAuth lists which generations AD trusts for logon.')
                   Fix = @('If nothing issued under the earlier installation is still in use, remove that certificate from NTAuth (and from the other AD containers that hold it), so logon no longer trusts it. If something still depends on it, publish it to AIA and note why. Both are actions for the PKI owner (Enterprise Admin rights).')
                   Signals = @(@{ When = 'lifecycle: Unknown'; Weight = 25; Because = 'the CA does not list this generation among its own signing certificates (lifecycle Unknown), which fits an earlier installation better than a renewal' }) }
                @{ Id = 'manual-ntauth-entry'; Cause = 'Someone added the certificate to NTAuth by hand (for a third-party or test CA) without publishing it to AIA.'
                   Confirm = @('Check which CA the certificate belongs to and who published it (the AD object change history, if auditing is on).')
                   Fix = @('Publish the CA''s certificate chain to AIA as well, or remove the NTAuth entry if the CA should not be trusted for logon.') }
            ) }

        'NTAUTH_MISSING' = @{
            Title = 'A CA certificate is not in NTAuthCertificates'
            What = 'Certificates from this CA are not accepted for smart card, Windows Hello for Business or domain controller logon until its certificate is in NTAuthCertificates. For a CA that does not issue sign-in certificates this is correct.'
            Sources = @('S24', 'S41')
            Causes = @(
                @{ Id = 'not-a-logon-ca'; Cause = 'The CA issues certificates that are not used to sign in to AD (web servers, code signing), so it does not need an NTAuth entry.'
                   Confirm = @('Check the templates the CA publishes: any smart card logon or domain controller template means it needs the entry.')
                   Fix = @('Nothing if it is not a logon CA.') }
                @{ Id = 'standalone-or-third-party'; Cause = 'It is a standalone or third-party CA. These are not added automatically; only an Enterprise CA installed by an Enterprise Admin gets its certificate in NTAuth.'
                   Confirm = @('certutil -viewstore -enterprise NTAuth')
                   Fix = @('Publish the CA certificate to the NTAuth store (an Enterprise Admin action), then run gpupdate on clients.') }
            ) }

        'AD_CA_CERT_NOT_PUBLISHED' = @{
            Title = 'A CA certificate is missing in an AD PKI container'
            What = 'The current CA certificate (or its root) was not found where AD should publish it (Certification Authorities, AIA, Enrollment Services). Domain computers only learn about the CA from these containers.'
            Sources = @('S24', 'S33', 'S12')
            Causes = @(
                @{ Id = 'publish-never-done'; Cause = 'The CA certificate was never published to AD (an offline root that was only installed on the CA, or the CA was installed by an account that could not write to the containers).'
                   Confirm = @('Look for the certificate in ADSI Edit under CN=Public Key Services (view only).')
                   Fix = @('Publish it with an Enterprise Admin account (the AD CS documentation describes the dsPublish step).')
                   Signals = @(@{ When = 'EnterpriseRoot|StandaloneRoot|root'; Weight = 10; Because = 'it is a root CA, whose certificate is published by hand' }) }
                @{ Id = 'cleaned-up'; Cause = 'An administrator removed the object during cleanup.'
                   Confirm = @('Check recent AD changes in the PKI containers.')
                   Fix = @('Publish the certificate again.') }
            ) }

        'NO_ENTERPRISE_CA' = @{
            Title = 'No Enterprise CA is registered in Active Directory'
            What = 'The Enrollment Services container has no CA. Either the forest has no AD-integrated CA, or this account cannot read the container.'
            Sources = @('S12', 'S33')
            Causes = @(
                @{ Id = 'no-enterprise-ca'; Cause = 'The forest uses standalone or external CAs only, or has no PKI.'
                   Confirm = @('Ask the PKI owner; check for a standalone CA or a cloud PKI.')
                   Fix = @('Nothing to fix if it is intended.') }
                @{ Id = 'cannot-read'; Cause = 'The directory read failed earlier in the run (see the directory findings), so the container looked empty.'
                   Confirm = @('Look for DIRECTORY or DC findings in the same run.')
                   Fix = @('Fix the directory connection and run again.') }
            ) }

        'TEMPLATE_LIST_MISMATCH' = @{
            Title = 'The templates in AD and on the CA differ'
            What = 'The list of templates an Enterprise CA publishes in AD does not match the list the CA reports itself. Users see the AD list but the CA enforces its own, so a template may show up but fail on request, or the reverse.'
            Sources = @('S27', 'S12')
            Causes = @(
                @{ Id = 'replication-or-delay'; Cause = 'A recent change has not replicated, or the CA has not reloaded its template list.'
                   Confirm = @('Wait one replication cycle and run again; compare with certutil -CATemplates on a CA that allows it.')
                   Fix = @('Let replication finish; restart Certificate Services only if the lists still differ later.') }
                @{ Id = 'edited-one-side'; Cause = 'An administrator changed templates in the CA console on one CA while a second view (another DC) still shows the old state.'
                   Confirm = @('Read the template list from two domain controllers.')
                   Fix = @('Fix replication problems; avoid editing from different places.') }
            ) }

        'ENROLLMENT_OBJECT_CERT_MISMATCH' = @{
            Title = 'The Enrollment Services object does not carry every valid CA certificate'
            What = 'The CA reports valid signing certificates that the Enrollment Services object in AD does not contain, so domain computers may not know every certificate they can meet from this CA.'
            Sources = @('S26', 'S33')
            Causes = @(
                @{ Id = 'renewal-not-published'; Cause = 'The CA was renewed and the new certificate was not published to the Enrollment Services object.'
                   Confirm = @('Compare the certificates in the object with the CA''s signing certificates (finding evidence).')
                   Fix = @('Publish the CA certificates to AD from the CA (the PKI owner re-runs the publish step).') }
            ) }

        'OCSP_UNUSED' = @{
            Title = 'An Online Responder answers but nothing points to it'
            What = 'An OCSP responder exists on a host, but no certificate and no CA setting names it in an AIA OCSP URL, so no client will ever ask it. It does no harm, but it also does nothing, and it may be half configured.'
            Sources = @('S25', 'S36', 'S14')
            Causes = @(
                @{ Id = 'role-installed-not-published'; Cause = 'The Online Responder role was installed (often together with the CA) and the OCSP URL was never added to the CA''s AIA extension. A URL added later only appears on certificates issued afterwards.'
                   Confirm = @('CA properties > Extensions > Authority Information Access: look for an http URL that ends in /ocsp and is ticked "Include in the online certificate status protocol (OCSP) extension".')
                   Fix = @('Either finish it (add the OCSP URL to the AIA extension, create the revocation configuration on the responder, reissue certificates) or remove the unused role. HTTP CRLs alone are fine for most environments.')
                   Signals = @(@{ When = 'HTTP 5\d\d|answers HTTP 500|500'; Weight = 15; Because = 'the responder path returns a server error, which fits an unconfigured role' }) }
                @{ Id = 'leftover'; Cause = 'The responder belongs to an earlier design and was kept.'
                   Confirm = @('Ask the owner; check whether any certificate names this host in its AIA.')
                   Fix = @('Remove the role if nothing uses it.') }
            ) }

        'OCSP_ENDPOINT_FAIL' = @{
            Title = 'An OCSP URL does not answer'
            What = 'A certificate or CA names an OCSP URL, but the host or path does not answer as an Online Responder should. Clients that follow it get no revocation answer.'
            Sources = @('S25', 'S36')
            Causes = @(
                @{ Id = 'responder-down'; Cause = 'The Online Responder service or its web application is stopped or broken.'
                   Confirm = @('On the responder (owner): the Online Responder console shows the array and revocation configuration status; System and Application logs for OCSP events (17 means no CRL data, 23 a missing signing certificate, 26 an expired signing certificate).')
                   Fix = @('Refresh revocation data, assign or renew the signing certificate, or fix the web application.') }
                @{ Id = 'path-or-binding'; Cause = 'The URL has the wrong path or host header.'
                   Confirm = @('Compare the URL with the one in the AIA extension; the usual path ends in /ocsp.')
                   Fix = @('Correct the extension for new certificates.') }
            ) }
}
