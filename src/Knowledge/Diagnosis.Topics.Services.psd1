# MSPKI Health Check diagnosis knowledge base, topics: Services. DATA ONLY. Format and rules: see Diagnosis.psd1.
@{
        # ===== NDES / SCEP, Intune Certificate Connector, CES / CEP, Web Enrollment, identity and local evidence =====
        'NDES_NOT_DISCOVERED' = @{
            Title = 'No NDES / SCEP server was found'
            What = 'The tool looked for a Network Device Enrollment Service (the Windows SCEP server used by network devices and by Intune SCEP profiles) through the CA database, the permissions on the NDES templates and references in AD. It found none. That does not prove there is none: an NDES server leaves few traces in AD.'
            Sources = @('S04', 'S06', 'S10')
            Causes = @(
                @{ Id = 'none-exists'; Cause = 'This environment has no NDES server (certificates reach devices another way: autoenrollment, PKCS through Intune, a cloud PKI).'
                   Confirm = @('Ask the PKI and device-management owners whether SCEP profiles or network devices request certificates.')
                   Fix = @('Nothing to do if there is none.') }
                @{ Id = 'invisible-to-this-account'; Cause = 'An NDES server exists but leaves no trace this account can read: the CA database reader is not installed here, the CA refused the account, and the template permissions name an account the tool cannot resolve.'
                   Confirm = @('Look for a CA database finding above (reader not installed, or permission denied).', 'In IIS logs of a suspected host: requests to the SCEP path (the Microsoft article on device to NDES communication shows the pattern).')
                   Fix = @('Run the check once from a computer that has the AD CS management tools and an account that may read the CA database, or ask the PKI owner to list the NDES servers.')
                   Signals = @(@{ When = 'not installed|permission|did not answer'; Weight = 15; Because = 'the CA database route was not available in this run' }) }
                @{ Id = 'other-forest-or-vendor'; Cause = 'SCEP is provided by another product or in another forest.'
                   Confirm = @('Check the SCEP URLs in the device-management profiles.')
                   Fix = @('Run the check in that forest or against that product.') }
            ) }

        'NDES_RA_EXPIRED' = @{
            Title = 'A registration authority certificate returned by an NDES server has expired'
            What = 'NDES uses two registration authority certificates (an enrollment agent signing certificate and an encryption certificate). If one expires or fails its revocation check, NDES stops answering correctly, usually with HTTP 500 or event IDs 2 and 10 ("The parameter is incorrect"), and no device can enroll.'
            Sources = @('S05', 'S04', 'S06')
            Causes = @(
                @{ Id = 'ra-not-renewed'; Cause = 'The RA certificates were never renewed (NDES does not renew them by itself unless they were enrolled for it).'
                   Confirm = @('On the NDES server (owner): certlm.msc > Personal > Certificates: look at the two certificates issued from the NDES templates and their Valid to dates.')
                   Fix = @('Request new RA certificates from the same templates, give the SCEP application pool identity access to their private keys, and select them again in the NDES configuration (the Microsoft article describes the registry values), then restart IIS.')
                   Signals = @(@{ When = 'has expired'; Weight = 10; Because = 'a certificate returned by the server is past its end date' }) }
                @{ Id = 'revocation-failing'; Cause = 'The RA certificates (or the CA chain) fail revocation checks because a CRL is expired or unreachable from the NDES server.'
                   Confirm = @('On the NDES server (owner): certutil -verify -urlfetch <RaCertificateFile> (read only).')
                   Fix = @('Fix the CRL publication or the access from the NDES server to the CDP.') }
                @{ Id = 'app-pool-key-access'; Cause = 'After renewal the application pool identity has no permission to the new private key.'
                   Confirm = @('certlm.msc > the certificate > All Tasks > Manage Private Keys: is the application pool identity listed?')
                   Fix = @('Grant the application pool identity read access to both RA certificates'' private keys.') }
            ) }

        'NDES_ADMIN_OPEN' = @{
            Title = 'The NDES admin page answers an anonymous request'
            What = 'The NDES administration page is meant for the NDES administrator, because it can generate enrollment challenge passwords. An open page lets anyone who can reach it obtain a challenge and request certificates.'
            Sources = @('S06', 'S04')
            Causes = @(
                @{ Id = 'anonymous-enabled'; Cause = 'Anonymous authentication is enabled on the admin application, or the site allows everyone.'
                   Confirm = @('On the NDES server (owner): IIS > the NDES admin application > Authentication.')
                   Fix = @('Require Windows authentication and limit the path to administrators; if Intune is used, the admin page is not needed at all and can be blocked.') }
                @{ Id = 'exposed-by-proxy'; Cause = 'A reverse proxy publishes the whole site, including the admin path, to a wider network.'
                   Confirm = @('Check the proxy''s publishing rules.')
                   Fix = @('Publish only the SCEP service path, not the admin path.') }
            ) }

        'NDES_RA_TEMPLATE_MISSING' = @{
            Title = 'No certificate template for the NDES registration authority exists'
            What = 'NDES needs templates for its two registration authority certificates (CEP Encryption and Exchange Enrollment Agent (Offline request), or copies of them). None exists in AD, so no NDES server can be set up or renew its certificates.'
            Sources = @('S04', 'S05')
            Causes = @(
                @{ Id = 'no-ndes-planned'; Cause = 'NDES was never installed in this forest.'
                   Confirm = @('Check with the PKI owner.')
                   Fix = @('Nothing to do if NDES is not wanted.') }
                @{ Id = 'templates-deleted'; Cause = 'The templates were deleted or renamed after an NDES server was set up.'
                   Confirm = @('Look for NDES RA template names in the NDES server configuration (registry, owner).')
                   Fix = @('Recreate the templates (copies of the two built-ins) and publish them.') }
            ) }

        'NDES_RA_TEMPLATE_UNPUBLISHED' = @{
            Title = 'NDES registration authority templates exist but no CA publishes them'
            What = 'The templates for the NDES RA certificates are in AD, but no Enterprise CA issues them. An NDES server can then not enroll for or renew its RA certificates, so it will stop when the current ones expire.'
            Sources = @('S04', 'S05')
            Causes = @(
                @{ Id = 'unpublished-after-setup'; Cause = 'The templates were unpublished after the NDES server got its certificates.'
                   Confirm = @('CA console > Certificate Templates: are the NDES RA templates in the list?')
                   Fix = @('Publish them again on the CA that issues the NDES RA certificates before the certificates expire.') }
            ) }

        'NDES_CANDIDATE_UNCONFIRMED' = @{
            Title = 'A possible NDES host was found from evidence but not confirmed'
            What = 'Certificates issued from NDES templates, or accounts allowed to enroll for them, name a host, but no name could be built or it does not resolve, so no SCEP request was sent to it. It is a lead, not a finding.'
            Sources = @('S04', 'S06')
            Causes = @(
                @{ Id = 'host-renamed-or-retired'; Cause = 'The NDES server was renamed, retired or is registered under a different DNS name.'
                   Confirm = @('Ask the PKI owner for the NDES server list; Resolve-DnsName <Host>.')
                   Fix = @('Remove the stale evidence (old certificates, account permissions) once the old server is gone.') }
                @{ Id = 'dns-gap'; Cause = 'The host exists but its DNS record is missing from the zone this computer uses.'
                   Confirm = @('Resolve-DnsName <Host> -DnsOnly from another network.')
                   Fix = @('Create the DNS record.') }
            ) }

        'INTUNE_REMOTE_NOT_CHECKED' = @{
            Title = 'The Intune Certificate Connector on an NDES host was not checked'
            What = 'The Certificate Connector for Microsoft Intune runs on the NDES server. This tool reads only the computer it runs on, because checking a remote server''s services and software reliably needs administrator rights on that server. So whether the connector there is healthy is unknown, not "fine".'
            Sources = @('S10', 'S07', 'S08', 'S09')
            Causes = @(
                @{ Id = 'remote-not-possible'; Cause = 'The tool does not check other computers.'
                   Confirm = @('On the NDES host (owner): Event Viewer > Applications and Services Logs > Microsoft > Intune > CertificateConnectors (Admin and Operational); Get-Service for the connector services.', 'The Intune admin center shows the connector status and the last check-in time.')
                   Fix = @('Run this tool on the NDES server itself, or check the connector status in the Intune admin center.') }
                @{ Id = 'connector-certificate-expired'; Cause = 'If SCEP profiles fail on devices, a common connector problem is an expired or stale client authentication certificate that the policy module keeps using after renewal.'
                   Confirm = @('On the NDES host (owner): look for errors in the connector logs and the policy module log (CertificateRegistrationPoint log).')
                   Fix = @('Reinstall or re-sign in the connector so it picks the renewed certificate, then restart the connector service and the web publishing service (see the Microsoft article).') }
            ) }

        'INTUNE_NOT_FOUND' = @{
            Title = 'No Intune Certificate Connector was found on this computer'
            What = 'On the computer that ran the check there are no connector services, products or certificates. That is normal on a client or on a CA host. It says nothing about the NDES server.'
            Sources = @('S10')
            Causes = @(
                @{ Id = 'not-here'; Cause = 'The connector is not installed on this computer, which is expected unless this is the NDES server.'
                   Confirm = @('If this is the NDES server: Get-Service | Where Name -like ''*Intune*'' and Event Viewer > Microsoft > Intune.')
                   Fix = @('Nothing to do when this is not the NDES server.') }
            ) }

        'INTUNE_WEAK_MATCH' = @{
            Title = 'Possible Intune Certificate Connector parts were found'
            What = 'Some names look like connector parts, but none matches a documented service or product name, so the connector is not confirmed.'
            Sources = @('S10')
            Causes = @(
                @{ Id = 'leftover-or-lookalike'; Cause = 'A leftover of an older connector (the separate PFX and SCEP connectors, retired in 2021) or an unrelated component with a similar name.'
                   Confirm = @('List what the finding names and compare with the product list on the connector server (owner).')
                   Fix = @('Remove the retired connectors and install the current Certificate Connector for Microsoft Intune.') }
            ) }

        'CEP_NOT_CONFIGURED' = @{
            Title = 'No enrollment policy web service (CEP) is configured on this computer'
            What = 'This computer gets its enrollment policy from AD, not from a Certificate Enrollment Policy web service. That is the normal state for a domain computer.'
            Sources = @('S11', 'S12')
            Causes = @(
                @{ Id = 'ad-policy'; Cause = 'The domain uses the AD enrollment policy only.'
                   Confirm = @('certutil -v -enrollmentServerURL (read only) lists configured policy servers.')
                   Fix = @('Nothing to do unless this computer must enroll over the internet or from another forest, which needs CEP and CES.') }
            ) }

        'CES_NOT_PUBLISHED' = @{
            Title = 'No Certificate Enrollment Web Service (CES) URL is published on the CAs'
            What = 'None of the Enterprise CAs lists a CES URL in its Enrollment Services object (msPKI-Enrollment-Servers). The enrollment web services are not in use.'
            Sources = @('S11', 'S12')
            Causes = @(
                @{ Id = 'not-deployed'; Cause = 'CES and CEP are not deployed; all clients enroll over DCOM/RPC.'
                   Confirm = @('Ask whether non-domain or internet clients need to enroll.')
                   Fix = @('Nothing to do if not needed; deploy CES and CEP only for clients that cannot reach the CA over RPC.') }
            ) }

        'CES_CEP_CANDIDATES_SILENT' = @{
            Title = 'Standard enrollment web service addresses on CA hosts did not answer'
            What = 'The tool tried the standard Microsoft CES and CEP paths on the hosts of the Enterprise CAs and none answered as a service. Nothing in AD names such a service, so this is the expected result when CES/CEP is not used.'
            Sources = @('S11')
            Causes = @(
                @{ Id = 'not-installed'; Cause = 'CES and CEP are not installed on the CA hosts.'
                   Confirm = @('Ask the PKI owner; IIS on a CA host (owner) shows the CES and CEP applications if they exist.')
                   Fix = @('Nothing to do if they are not used.') }
                @{ Id = 'other-host'; Cause = 'CES and CEP run on separate servers, which the tool cannot know unless AD or a certificate names them.'
                   Confirm = @('Look at the enrollment service URLs in Group Policy or on a client (certutil -v -enrollmentServerURL).')
                   Fix = @('Register the service URL in the CA''s Enrollment Services object so tools and clients can discover it.') }
            ) }

        'CES_CEP_NOT_A_SERVICE' = @{
            Title = 'An enrollment web service address answers, but not as the service'
            What = 'A request returned HTTP 200, but the answer is not the WSDL, SOAP or enrollment XML that proves a real service. It may be a default page, a removed service behind a site-wide rule or a proxy page.'
            Sources = @('S11', 'S12')
            Causes = @(
                @{ Id = 'wrong-site-or-removed'; Cause = 'The service application was removed but the site still answers, or the address belongs to another site or a proxy.'
                   Confirm = @('Open the URL with ?wsdl added in a browser and read what is returned.')
                   Fix = @('Remove the stale URL from the Enrollment Services object, or repair the service.') }
            ) }

        'CES_CEP_ENDPOINT_FAIL' = @{
            Title = 'An enrollment web service address does not work'
            What = 'A CES or CEP address referenced in AD or Group Policy did not answer correctly. Clients that use it cannot enroll.'
            Sources = @('S11', 'S12', 'S06')
            Causes = @(
                @{ Id = 'kerberos-delegation'; Cause = 'For CES (HTTP 401 on the service while the policy service answers): the CES service account is not trusted for constrained delegation to the CA host, or its SPN is missing or duplicated, so the service cannot pass the user''s identity to the CA.'
                   Confirm = @('setspn -L <CesServiceAccount> (read only) and check for duplicates: setspn -Q HTTP/<Host>', 'Active Directory Users and Computers > the account > Delegation tab (view).')
                   Fix = @('Register the SPN once, and set constrained delegation to the CA host''s services (the Microsoft CES guide lists the exact steps), or use renewal-only mode when only renewals are needed.')
                   Signals = @(@{ When = 'StatusCode=HTTP_401_403|HTTP 401'; Weight = 20; Because = 'the enrollment service answered 401 or 403, which is the typical sign of a delegation or SPN problem' }) }
                @{ Id = 'tls-binding'; Cause = 'The TLS certificate of the site is untrusted, expired or does not cover the name.'
                   Confirm = @('Open the URL in a browser from a domain computer.')
                   Fix = @('Bind a certificate from the enterprise CA that names the host.')
                   Signals = @(@{ When = 'TLS|TlsStatus=Fail'; Weight = 25; Because = 'the TLS step failed' }) }
                @{ Id = 'service-down'; Cause = 'The web server or application pool is stopped, or the host was retired.'
                   Confirm = @('Test-NetConnection <Host> -Port 443')
                   Fix = @('Repair the host or remove the stale URL.')
                   Signals = @(@{ When = 'TcpStatus=Fail|DnsStatus=Fail|TIMEOUT'; Weight = 30; Because = 'the host does not answer at the network level' }) }
            ) }

        'WEB_ENROLLMENT_NOT_FOUND' = @{
            Title = 'No Web Enrollment (certsrv pages) was found on a CA host'
            What = 'The standard Certification Authority Web Enrollment pages were not found on this CA host. Most PKIs do not install them, and their absence removes an NTLM relay target (see ESC8).'
            Sources = @('S18', 'S30')
            Causes = @(
                @{ Id = 'role-not-installed'; Cause = 'The Web Enrollment role is not installed, or the host has no web server at all. This is the preferred state.'
                   Confirm = @('The finding says whether any web server answered on the host.')
                   Fix = @('Nothing to do unless you need the web pages; if so, protect them (HTTPS plus Extended Protection).')
                   Signals = @(@{ When = 'no web server answered at all'; Weight = 5; Because = 'no web server answered on this host at all (a missing role and a filtering firewall look the same from here; a refusal would point to a missing role)' }
                               @{ When = 'actively refused|refused'; Weight = 30; Because = 'the host refused the connection, which fits a missing web server role' }) }
                @{ Id = 'firewall'; Cause = 'The ports are filtered from this computer, so a web server may exist but cannot be seen.'
                   Confirm = @('Test-NetConnection <CAHost> -Port 443 from a computer in the CA network.')
                   Fix = @('Nothing is needed; the finding is only informational.')
                   Signals = @(@{ When = 'TIMEOUT'; Weight = 10; Because = 'both addresses timed out instead of refusing, which a filtering firewall also produces' }) }
            ) }

        'PTR_MISSING' = @{
            Title = 'A host has no reverse DNS (PTR) record'
            What = 'DNS has no name for the host''s IP address. Many PKI functions do not need it, but some tools and Kerberos-related lookups do, and it makes servers harder to identify in logs.'
            Sources = @('S42')
            Causes = @(
                @{ Id = 'no-reverse-zone'; Cause = 'No reverse lookup zone exists for the subnet, or dynamic registration of PTR records is off.'
                   Confirm = @('Resolve-DnsName <IpAddress> -Type PTR -DnsOnly', 'Check the reverse zones of the DNS server (owner).')
                   Fix = @('Create the reverse zone and let the host register, or add the PTR record by hand.') }
            ) }

        'PTR_SHORT_NAME' = @{
            Title = 'Reverse DNS gives only the short name'
            What = 'The PTR record names the host without its DNS suffix, so a reverse lookup does not give the name that certificates and URLs use.'
            Sources = @('S42')
            Causes = @(
                @{ Id = 'registered-short'; Cause = 'The PTR was registered with the short name (a manual entry or an old client).'
                   Confirm = @('Resolve-DnsName <IpAddress> -Type PTR -DnsOnly')
                   Fix = @('Replace the record with the fully qualified name.') }
            ) }

        'PTR_OTHER_HOST' = @{
            Title = 'Reverse DNS names another host'
            What = 'The IP address of a PKI host has a PTR record for a different name. The address was reused or the record is stale.'
            Sources = @('S42')
            Causes = @(
                @{ Id = 'stale-ptr'; Cause = 'The address belonged to another server earlier and its PTR was never removed.'
                   Confirm = @('Resolve-DnsName <IpAddress> -Type PTR -DnsOnly and compare with the forward lookup.')
                   Fix = @('Delete the stale PTR and register the right one.') }
            ) }

        'CNAME_DANGLING' = @{
            Title = 'A DNS alias leads to a name with no address'
            What = 'A CNAME points to a name that has no A or AAAA record, so the alias resolves to nothing. Anything that uses the alias fails.'
            Sources = @('S14', 'S42')
            Causes = @(
                @{ Id = 'target-removed'; Cause = 'The server the alias pointed to was removed or renamed.'
                   Confirm = @('Resolve-DnsName <Alias> -DnsOnly (shows the chain) and Resolve-DnsName <Target> -DnsOnly.')
                   Fix = @('Point the alias at the current server, or delete the alias.') }
            ) }

        'SAN_NO_DNS' = @{
            Title = 'A certificate names a host that has no DNS record'
            What = 'A certificate lists a DNS name in its Subject Alternative Name that does not resolve. The name is an alias or a retired host. Clients that use the name fail before they ever see the certificate.'
            Sources = @('S14', 'S42')
            Causes = @(
                @{ Id = 'alias-never-created'; Cause = 'The certificate was requested with a name that was never added to DNS (a planned alias).'
                   Confirm = @('Resolve-DnsName <Name> -DnsOnly')
                   Fix = @('Create the DNS record, or reissue the certificate without the name.') }
                @{ Id = 'retired-name'; Cause = 'The name belonged to a retired host or service.'
                   Confirm = @('Check whether anything still uses the name.')
                   Fix = @('Leave it until the certificate expires, or reissue it.') }
            ) }

        'LOCAL_STORE_MISSING' = @{
            Title = 'Certificates that AD publishes have not reached this computer'
            What = 'AD publishes CA certificates, and Group Policy normally copies them into the Root, Intermediate and NTAuth stores of every domain computer. Some are missing here, so chains that depend on them may not build on this computer.'
            Sources = @('S41', 'S24')
            Causes = @(
                @{ Id = 'gpo-not-applied'; Cause = 'Group Policy has not applied (a recent join, no connection to the domain, a policy filter).'
                   Confirm = @('gpresult /r  (are the computer policies applied?)', 'Get-ChildItem Cert:\LocalMachine\Root | Select Subject, Thumbprint')
                   Fix = @('Fix policy application on this computer (gpupdate /force, then run the check again).') }
                @{ Id = 'recent-publication'; Cause = 'The certificate was published recently and has not arrived yet (it can take hours).'
                   Confirm = @('Look at the certificate''s publication time in AD and wait one refresh cycle.')
                   Fix = @('Nothing to fix; check again later.') }
            ) }
}
