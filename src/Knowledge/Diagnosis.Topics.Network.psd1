# MSPKI Health Check diagnosis knowledge base, topics: Network. DATA ONLY. Format and rules: see Diagnosis.psd1.
@{
        # ===== Network and web protocol =====
        'DNS_NO_ANSWER' = @{
            Title = 'A host name does not resolve'
            What = 'This computer asked DNS for the address of a name that came from AD, a certificate or a CA setting, and got no usable answer. Everything that needs that name (a CRL, a CA certificate, an enrollment service) cannot be reached by clients that use the same DNS.'
            Sources = @('S14', 'S42')
            Causes = @(
                @{ Id = 'no-record'; Cause = 'The DNS record was never created, or was removed (a decommissioned server, a renamed host or a CNAME that was not added).'
                   Confirm = @('Resolve-DnsName <Host> -DnsOnly -Type A', 'nslookup <Host>  (try a second DNS server of the domain to rule out one stale server)')
                   Fix = @('Create or restore the A/AAAA (or CNAME) record in the DNS zone that serves this name, or change the PKI setting (CDP/AIA/OCSP URL, CA setting) that still points at the old name.')
                   Signals = @(@{ When = 'does not resolve|has no DNS record|No addresses returned'; Weight = 10; Because = 'DNS answered, but with no address for the name' }) }
                @{ Id = 'wrong-dns-server'; Cause = 'This computer uses a DNS server or search suffix that does not know the zone (split-brain DNS, a VPN, a workgroup or a different network).'
                   Confirm = @('Get-DnsClientServerAddress', 'Resolve-DnsName <Host> -DnsOnly -Server <DnsServerOfTheDomain>')
                   Fix = @('Point the computer at the domain DNS servers, or add a conditional forwarder for the zone on the DNS server it uses.')
                   Signals = @(@{ When = 'No DNS answer within|Timeout'; Weight = 25; Because = 'DNS did not answer in time, so the DNS server itself may be wrong or unreachable' }) }
                @{ Id = 'typo-or-stale-url'; Cause = 'The name is wrong in the certificate extension or CA setting (a typo, or a host that was replaced years ago). Certificates already issued keep the old URL.'
                   Confirm = @('Look at the URL in the finding evidence and compare it with the real PKI web server name.')
                   Fix = @('Fix the CDP/AIA/OCSP setting for new certificates and publish a DNS alias for the old name until the certificates that carry it have expired.')
                   Signals = @(@{ When = 'Category=(AIA|CDP|OCSP)'; Weight = 10; Because = 'the name comes from a certificate or CA URL setting' }) }
            ) }

        'TCP_UNREACHABLE' = @{
            Title = 'A host does not accept connections on a port'
            What = 'The name resolved, but opening a TCP connection to the port failed. Either nothing listens there, or something on the path refuses it.'
            Sources = @('S42', 'S14')
            Causes = @(
                @{ Id = 'service-stopped'; Cause = 'The service that should listen (web server, Online Responder, Certificate Services endpoint mapper) is stopped or not installed on that host. The host answers, so it actively refuses the connection.'
                   Confirm = @('Test-NetConnection <Host> -Port <Port>', 'On the host (owner): Get-Service W3SVC, CertSvc')
                   Fix = @('Start the service or remove the stale URL/role reference; if the role was never meant to be there, remove it from the CA extension or AD object that names it.')
                   Signals = @(@{ When = 'actively refused'; Weight = 40; Because = 'the host answered with a refusal, so it is up and nothing listens on the port' }
                               @{ When = 'No TCP connection within|Timeout'; Weight = -25; Because = 'there was no answer at all, which fits a firewall better than a stopped service' }) }
                @{ Id = 'firewall'; Cause = 'A host or network firewall drops the traffic, so the connection attempt gets no answer.'
                   Confirm = @('Test-NetConnection <Host> -Port <Port> -InformationLevel Detailed  (a silent timeout points to a drop rule)', 'Compare with a computer on the same network as the server.')
                   Fix = @('Allow the port from client networks (80 for CRL/AIA over HTTP, 443 for HTTPS services, 135 plus the dynamic RPC range for CA management).')
                   Signals = @(@{ When = 'No TCP connection within|Timeout'; Weight = 30; Because = 'the connection attempt timed out without any answer' }) }
                @{ Id = 'host-down'; Cause = 'The host is switched off, was retired, or the address in DNS is stale.'
                   Confirm = @('Test-Connection <Host> -Count 2', 'Check the address in DNS against the real server address.')
                   Fix = @('Restore or replace the host, or remove the references to it.')
                   Signals = @(@{ When = 'unreachable|No route'; Weight = 35; Because = 'the network reported the host or network as unreachable' }) }
            ) }

        'NETWORK_TIMEOUT' = @{
            Title = 'A network request timed out'
            What = 'The tool waited its time limit for an answer and got none. A timeout is different from a refusal: nobody said no, nobody answered.'
            Sources = @('S42', 'S06')
            Causes = @(
                @{ Id = 'firewall-drop'; Cause = 'A firewall silently drops the traffic between this computer and the target.'
                   Confirm = @('Test-NetConnection <Host> -Port <Port>', 'Repeat from a computer in the server network: if it works there, the path is filtered.')
                   Fix = @('Open the needed port from the client network, or move the check to a network that is allowed.')
                   Signals = @(@{ When = 'TcpStatus=Timeout|No TCP connection within'; Weight = 20; Because = 'the TCP connection itself timed out' }) }
                @{ Id = 'slow-server'; Cause = 'The server is overloaded or slow to answer (an application pool that is recycling, a CA under load, a slow DC).'
                   Confirm = @('Run the tool again; compare the time with another request to the same host.', 'On the server (owner): check CPU, memory and the web server application pool.')
                   Fix = @('Reduce the load or fix the slow component; raise -TimeoutSeconds only to learn whether the server answers eventually.')
                   Signals = @(@{ When = 'TcpStatus=Pass'; Weight = 25; Because = 'the TCP connection worked, so the server is up but slow to answer' }) }
                @{ Id = 'dns-slow'; Cause = 'DNS did not answer in time (an unreachable DNS server in the list).'
                   Confirm = @('Resolve-DnsName <Host> -DnsOnly', 'Get-DnsClientServerAddress')
                   Fix = @('Remove or repair the dead DNS server entry.')
                   Signals = @(@{ When = 'No DNS answer within|DnsStatus=Timeout'; Weight = 40; Because = 'the DNS step is the one that timed out' }) }
            ) }

        'HTTP_REDIRECT' = @{
            Title = 'A URL answers with a redirect'
            What = 'A CRL, CA certificate or service URL redirects to another address. Windows revocation checking does not follow redirects to another host in every case, and a redirect to a login page never returns a CRL.'
            Sources = @('S14', 'S15')
            Causes = @(
                @{ Id = 'http-to-https'; Cause = 'The web server redirects HTTP to HTTPS. CRL and AIA must be reachable over plain HTTP: a client cannot check the revocation of the web server certificate that protects its own CRL.'
                   Confirm = @('Invoke the URL in a browser with developer tools or run certutil -URL <Url> and look at the first response.')
                   Fix = @('Exclude the CRL/AIA virtual directory from the HTTPS redirect (keep it on port 80).')
                   Signals = @(@{ When = 'https://'; Weight = 15; Because = 'the redirect target is an HTTPS address' }) }
                @{ Id = 'moved-content'; Cause = 'The files were moved to another web server or path and the old server redirects.'
                   Confirm = @('Follow the redirect target and check that it returns the CRL or certificate.')
                   Fix = @('Update the CDP/AIA extension to the final address for new certificates; keep the old redirect only while old certificates exist.') }
                @{ Id = 'sign-in-page'; Cause = 'A proxy, captive portal or web application firewall redirects anonymous requests to a sign-in page.'
                   Confirm = @('Request the URL from the client network without credentials and look at the page returned.')
                   Fix = @('Exempt the CRL/AIA URLs from authentication and inspection.') }
            ) }

        'HTTP_BAD_REQUEST' = @{
            Title = 'A URL answers HTTP 400 (bad request)'
            What = 'The web server refused the request as malformed. For CRL URLs the usual reason is a character the server will not accept in the file name.'
            Sources = @('S03', 'S14')
            Causes = @(
                @{ Id = 'double-escaping'; Cause = 'A delta CRL file name contains a plus sign (CRL names such as Name+.crl) and IIS request filtering rejects it because double escaping is not allowed.'
                   Confirm = @('Request the delta CRL URL (the one ending in +.crl) and compare it with the base CRL URL.')
                   Fix = @('On the CDP web site allow double escaping in request filtering, or stop publishing delta CRLs if clients do not need them.')
                   Signals = @(@{ When = '\+\.crl|\+%'; Weight = 40; Because = 'the URL ends in a delta CRL name with a plus sign' }) }
                @{ Id = 'bad-url'; Cause = 'The URL in the certificate has a typo, a space or an unfilled placeholder.'
                   Confirm = @('Read the URL character by character in the finding evidence.')
                   Fix = @('Correct the URL in the CA extension for new certificates.') }
            ) }

        'HTTP_AUTH_REFUSED' = @{
            Title = 'A URL answers HTTP 401 or 403 (sign-in required or forbidden)'
            What = 'The server understood the request and refused it. CRL, CA certificate and SCEP URLs must answer anonymously. For some paths a 403 is the normal answer to an anonymous request (the page exists but the site requires TLS or a client certificate).'
            Sources = @('S14', 'S06', 'S15')
            Causes = @(
                @{ Id = 'anonymous-blocked'; Cause = 'Anonymous access is disabled for the CRL/AIA directory, or the file permissions do not allow the web server to read the files (IIS_IUSRS or the anonymous account).'
                   Confirm = @('Request the URL from a computer that is not signed in, or run certutil -URL <Url>.', 'On the web server (owner): check the NTFS permissions of the CRL folder and the authentication settings of the virtual directory.')
                   Fix = @('Enable anonymous authentication for the CRL/AIA virtual directory and grant read access on the folder.')
                   Signals = @(@{ When = 'Category=(CRL|AIA|CDP)'; Weight = 20; Because = 'a CRL or CA certificate must be served anonymously' }) }
                @{ Id = 'ssl-required'; Cause = 'The path requires TLS (HTTP 403.4) or a client certificate, which is normal for Web Enrollment and enrollment services but wrong for CRL and AIA.'
                   Confirm = @('Request the same path over https:// and compare the answer.')
                   Fix = @('For CRL/AIA: serve the directory over plain HTTP without "Require SSL". For enrollment pages a 403 over HTTP is expected and not a fault.')
                   Signals = @(@{ When = 'Category=(WebEnrollment|CES|CEP|NDES)'; Weight = 25; Because = 'enrollment services normally answer 401 or 403 to an anonymous request' }) }
                @{ Id = 'proxy-or-waf'; Cause = 'A reverse proxy or web application firewall in front of the server blocks the request or the tool user agent.'
                   Confirm = @('Compare the answer from a computer inside the server network with the answer from here.')
                   Fix = @('Add a rule that lets the PKI paths through without authentication.') }
            ) }

        'HTTP_NOT_FOUND' = @{
            Title = 'A URL answers HTTP 404 (not found)'
            What = 'The web server is up but has no file at that address. For a CRL or CA certificate that means clients cannot download it, so revocation checks or chain building fail for everyone who needs this URL.'
            Sources = @('S14', 'S15', 'S03')
            Causes = @(
                @{ Id = 'not-published'; Cause = 'The CRL or CA certificate was never copied to the web server, or the CA writes to a different folder than the web server serves (an HTTP CDP needs a publish step or a manual copy).'
                   Confirm = @('Compare the file name in the URL with the files in the CRL folder on the web server (owner).', 'On a CA: look at the CDP extension "Publish CRLs to this location" setting.')
                   Fix = @('Publish a new CRL and make sure the CA writes into the folder the web site serves; copy offline root files by hand.')
                   Signals = @(@{ When = 'Category=(CRL|CDP)'; Weight = 15; Because = 'the missing file is a CRL' }) }
                @{ Id = 'name-mismatch'; Cause = 'The file name differs from the name in the extension (renewal suffix such as (1) in the CA certificate name, spaces or case). The name must match exactly.'
                   Confirm = @('List the web folder and compare each character of the file name with the URL in the certificate.')
                   Fix = @('Copy the file under the exact name the URL uses, or correct the extension for new certificates.')
                   Signals = @(@{ When = 'Category=AIA'; Weight = 15; Because = 'CA certificate file names change after a renewal with a new key' }) }
                @{ Id = 'wrong-virtual-dir'; Cause = 'The virtual directory or the host name is wrong, or the site does not serve that host header (a retired web server answers for the name).'
                   Confirm = @('Open the base URL (without the file name) and look at what the site serves.')
                   Fix = @('Fix the binding, virtual directory or the DNS alias so that the name leads to the right site.') }
            ) }

        'HTTP_SERVER_ERROR' = @{
            Title = 'A URL answers HTTP 500 or another server error'
            What = 'The web server accepted the request but failed while handling it. The server is reachable; its software or configuration is broken.'
            Sources = @('S06', 'S39', 'S25', 'S40')
            Causes = @(
                @{ Id = 'app-pool-identity'; Cause = 'The application pool identity cannot read what it needs (the IIS_IUSRS group lacks rights, the account is locked, or a certificate private key is unreadable).'
                   Confirm = @('On the server (owner): read the IIS log line for the request and the Application event log at that time.')
                   Fix = @('Give the application pool identity the permissions the service documents; for NDES see the NDES topics.')
                   Signals = @(@{ When = 'Category=NDES'; Weight = 20; Because = 'NDES answers 500 when its application pool cannot read its RA certificates' }) }
                @{ Id = 'role-half-installed'; Cause = 'A role such as the Online Responder is installed but not configured, so its web path exists and fails.'
                   Confirm = @('On the server (owner): open the Online Responder console and check the array and revocation configuration state.')
                   Fix = @('Finish configuring the role, or remove the role and the URL that points to it.')
                   Signals = @(@{ When = 'Category=OCSP|ocsp'; Weight = 30; Because = 'the failing path belongs to an Online Responder' }) }
                @{ Id = 'expired-or-broken-cert'; Cause = 'A certificate the service depends on is expired, revoked or fails its own revocation check, so the service cannot start.'
                   Confirm = @('On the server (owner): Get-ChildItem Cert:\LocalMachine\My | Select Subject, NotAfter')
                   Fix = @('Renew the certificate and make sure its CRL is reachable from that server.') }
            ) }

        'HTTP_OTHER' = @{
            Title = 'A URL answers an unexpected HTTP status'
            What = 'The server answered with a status this tool does not treat as success or as a known failure (for example 405, 410 or 503). The finding message shows the exact status.'
            Sources = @('S06', 'S39')
            Causes = @(
                @{ Id = 'service-unavailable'; Cause = 'HTTP 503: the application pool is stopped or the site is being recycled, often because a dependency (an expired certificate, a blocked CRL URL) made the pool crash.'
                   Confirm = @('On the server (owner): check the application pool state in IIS and the System and Application logs.')
                   Fix = @('Start the pool after fixing what stopped it; do not only restart it.')
                   Signals = @(@{ When = '503'; Weight = 40; Because = 'the server answered 503 (service unavailable)' }) }
                @{ Id = 'method-or-gone'; Cause = 'HTTP 405 or 410: the path exists but does not accept this request, or the file was deliberately removed.'
                   Confirm = @('Request the URL with a browser and read the status line.')
                   Fix = @('If the file was removed on purpose, remove the URL from the CA extension; otherwise restore the content.')
                   Signals = @(@{ When = '40[5-9]|410'; Weight = 40; Because = 'the status is 405 or 410' }) }
            ) }

        'TLS_HANDSHAKE' = @{
            Title = 'The TLS handshake failed'
            What = 'A TCP connection opened, but the encrypted session could not be set up. The service behind the port is not usable over TLS from this computer.'
            Sources = @('S34', 'S06')
            Causes = @(
                @{ Id = 'no-certificate-bound'; Cause = 'The web site has an HTTPS binding without a usable certificate (none selected, expired, or its private key unreadable), so the server cannot answer the handshake.'
                   Confirm = @('On the server (owner): in IIS, open the site bindings and look at the HTTPS certificate; check the System log for Schannel events 36874 and 36888.')
                   Fix = @('Bind a valid certificate whose subject name matches the host name used by clients, or remove the HTTPS binding if the site is HTTP only.')
                   Signals = @(@{ When = 'closes every TLS|before sending a certificate|reset'; Weight = 25; Because = 'the server closed the connection before it sent a certificate' }) }
                @{ Id = 'protocol-mismatch'; Cause = 'Client and server share no TLS version or cipher suite (an old server limited to TLS 1.0 or a hardened server that allows only TLS 1.2 and above).'
                   Confirm = @('On the server (owner): read the Schannel events in the System log; compare the enabled protocols with what this computer offers.')
                   Fix = @('Enable TLS 1.2 on both sides, or update the old server.') }
                @{ Id = 'middlebox'; Cause = 'A firewall or load balancer in the path closes or inspects the connection.'
                   Confirm = @('Test from a computer in the server network; if it works there, the path is the cause.')
                   Fix = @('Pass the traffic through, or terminate TLS on a device that presents a valid certificate.') }
            ) }

        'TLS_CLOSED_BY_SERVER' = @{
            Title = 'A host accepts the connection and then closes every TLS handshake'
            What = 'Port 443 is open, but the server hangs up before it sends its certificate, with every TLS version. This is typical for a web site whose HTTPS binding has no working certificate.'
            Sources = @('S34', 'S01')
            Causes = @(
                @{ Id = 'https-binding-without-cert'; Cause = 'The HTTPS binding exists but has no certificate, or the selected certificate was deleted, expired, or lost its private key. A role installer can create the binding before a certificate is chosen.'
                   Confirm = @('On the host (owner): IIS Manager > Sites > Bindings > https > the selected certificate; netsh http show sslcert lists the binding and its certificate hash.', 'System log: Schannel errors 36874 / 36888 at the time of a run.')
                   Fix = @('Select a valid server certificate for the binding (a certificate for the host name, with a reachable CRL), or delete the HTTPS binding if HTTPS is not wanted.')
                   Signals = @(@{ When = 'closes every TLS handshake'; Weight = 20; Because = 'every TLS version was closed before a certificate was sent' }) }
                @{ Id = 'client-certificate-or-policy'; Cause = 'The server requires something this client cannot offer (a protocol it does not allow, or a rule on the server that rejects the client).'
                   Confirm = @('On the host (owner): look for Schannel events that name the alert sent to the client.')
                   Fix = @('Align the TLS settings with the clients that must connect.') }
                @{ Id = 'not-a-pki-need'; Cause = 'Nobody needs HTTPS on this host: the PKI uses plain HTTP for CRL and AIA. The failing HTTPS port is then only a leftover.'
                   Confirm = @('Check whether any certificate or enrollment setting names an https:// URL on this host.')
                   Fix = @('Leave it, or remove the unused binding so scanners stop reporting it.')
                   Signals = @(@{ When = 'Category=CA'; Weight = 5; Because = 'the host is a CA host, where HTTPS is optional' }) }
            ) }

        'TLS_UNTRUSTED' = @{
            Title = 'The server certificate chains to a root that this computer does not trust'
            What = 'The server presents a certificate, but the chain ends at a root that is not in the Trusted Root store of the computer that ran the check. Other computers may trust it; this one does not.'
            Sources = @('S41', 'S24')
            Causes = @(
                @{ Id = 'root-not-distributed'; Cause = 'The enterprise root is not in this computer''s Trusted Root store (a workgroup computer, or Group Policy has not applied yet).'
                   Confirm = @('Get-ChildItem Cert:\LocalMachine\Root | Select Subject, Thumbprint', 'gpresult /r  (is the computer in the domain and are policies applied?)')
                   Fix = @('Let the domain distribute the root (Certification Authorities container in AD) or install it with Group Policy on computers that need it.')
                   Signals = @(@{ When = 'not trusted by this computer'; Weight = 15; Because = 'only this computer was asked' }) }
                @{ Id = 'private-or-self-signed'; Cause = 'The service uses a self-signed or third-party certificate from outside the enterprise PKI.'
                   Confirm = @('Read the issuer of the certificate shown in the finding evidence.')
                   Fix = @('Replace it with a certificate from the enterprise CA, or add the issuing root to the stores that need it.') }
            ) }

        'TLS_PARTIAL' = @{
            Title = 'The server certificate chain is incomplete'
            What = 'The certificate was accepted only partly: an intermediate CA certificate is missing and could not be fetched, so the chain cannot be built to a trusted root.'
            Sources = @('S14', 'S15')
            Causes = @(
                @{ Id = 'aia-not-reachable'; Cause = 'The certificate''s AIA extension points to a URL that is down, or only to LDAP, which this computer cannot reach.'
                   Confirm = @('certutil -verify -urlfetch <CertificateFile>  (shows each AIA and CDP URL tried)')
                   Fix = @('Publish the issuing CA certificate to a reachable HTTP URL and put it in the AIA extension.')
                   Signals = @(@{ When = 'Category=(AIA|CDP)'; Weight = 10; Because = 'the chain depends on AIA publication' }) }
                @{ Id = 'server-sends-no-intermediate'; Cause = 'The server only sends its own certificate and not the intermediate. Clients that already have the intermediate cached build the chain; others fail.'
                   Confirm = @('Compare the chain shown by a browser from a fresh computer with one that has visited the site before.')
                   Fix = @('Install the intermediate CA certificate in the server certificate chain (the Intermediate store of the server) so it is sent.') }
            ) }

        'TLS_NAME' = @{
            Title = 'The server certificate does not cover the host name used'
            What = 'The certificate is valid, but none of its names (Subject Alternative Name) matches the name clients type or find in AD. Clients that check the name reject the connection.'
            Sources = @('S11', 'S06')
            Causes = @(
                @{ Id = 'alias-not-in-san'; Cause = 'Clients use an alias (a CNAME or load-balancer name) that was not put into the certificate when it was requested.'
                   Confirm = @('Compare the name in the URL with the DNS names in the certificate (finding evidence lists them).')
                   Fix = @('Request a new certificate that lists every name clients use, or make clients use the name in the certificate.')
                   Signals = @(@{ When = 'alias|CNAME'; Weight = 25; Because = 'the name used is an alias for another host' }) }
                @{ Id = 'wrong-certificate-bound'; Cause = 'A different certificate (for another service or host) is bound to the site.'
                   Confirm = @('On the server (owner): IIS Manager > Bindings > the HTTPS certificate subject and SAN.')
                   Fix = @('Bind the certificate that was issued for this host name.') }
            ) }

        'TLS_NAME_ALIAS' = @{
            Title = 'An alias leads to a host whose certificate does not name the alias'
            What = 'A DNS alias points at a server, but the TLS certificate that server presents does not cover the alias name. Clients that use the alias see a name warning or fail.'
            Sources = @('S11', 'S14')
            Causes = @(
                @{ Id = 'san-missing-alias'; Cause = 'The certificate was issued for the server name only; the alias was added to DNS afterwards.'
                   Confirm = @('Compare the alias with the DNS names listed in the certificate evidence.')
                   Fix = @('Re-issue the certificate with the alias in its Subject Alternative Name, or stop using the alias for HTTPS.') }
                @{ Id = 'alias-leftover'; Cause = 'The alias is a leftover from an older design that nobody uses any more.'
                   Confirm = @('Search the PKI settings and certificates for the alias name.')
                   Fix = @('Remove the alias from DNS if nothing uses it.') }
            ) }

        'CONTENT_WRONG_TYPE' = @{
            Title = 'A location returns data of the wrong kind'
            What = 'The answer is not what the URL promises (for example an HTML page where a CRL or certificate was expected, or an AD object without the expected attribute).'
            Sources = @('S14', 'S15')
            Causes = @(
                @{ Id = 'error-page'; Cause = 'A proxy, captive portal or web server default page answers instead of the file.'
                   Confirm = @('Open the URL in a browser and read what is returned; run certutil -URL <Url>.')
                   Fix = @('Fix the site or exempt the path from inspection so the real file is served.') }
                @{ Id = 'ad-attribute-wrong'; Cause = 'An AD PKI container object holds a value that is not a readable certificate or CRL (corrupted or published by another tool).'
                   Confirm = @('Read the object named in the finding with ADSI Edit (view only) and check the attribute.')
                   Fix = @('Republish the certificate or CRL from the CA that owns the object.')
                   Signals = @(@{ When = 'Category=ADContainer|AD:'; Weight = 25; Because = 'the finding is about an AD container object' }) }
            ) }

        'CONTENT_MISMATCH' = @{
            Title = 'A location returns a different certificate or CRL than expected'
            What = 'The file at the URL is valid, but it is not the one the URL is supposed to hold (another CA, an older generation, or a different key).'
            Sources = @('S14', 'S26')
            Causes = @(
                @{ Id = 'renewal-not-published'; Cause = 'The CA certificate was renewed (new key) but the AIA or CDP location still holds the old file, or the new file was published under another name.'
                   Confirm = @('Compare the thumbprint and key of the file at the URL with the CA certificate in AD (finding evidence).')
                   Fix = @('Publish the current CA certificate under the exact file name the AIA URL uses.')
                   Signals = @(@{ When = 'not the key that signed|not the expected issuer'; Weight = 20; Because = 'the file belongs to a different CA or key' }) }
                @{ Id = 'shared-path'; Cause = 'Two CAs write to the same file name, so the last one overwrites the other.'
                   Confirm = @('Check the CDP/AIA file name templates of both CAs for a CA name variable.')
                   Fix = @('Give each CA its own file name (use the CA name and key suffix variables in the extension).') }
            ) }

        'SIZE_LIMIT' = @{
            Title = 'A download was larger than this tool''s limit'
            What = 'The tool refuses to read huge answers. A CA certificate is a few kilobytes and a normal CRL is small, so a very large answer is not a certificate or an ordinary CRL.'
            Sources = @('S14')
            Causes = @(
                @{ Id = 'not-the-file'; Cause = 'The URL returns something else (a web page, a large file, a download portal).'
                   Confirm = @('Open the URL in a browser and look at the size and content type.')
                   Fix = @('Serve only the CRL or certificate at that URL.') }
                @{ Id = 'huge-crl'; Cause = 'The CRL is genuinely very large (a CA that has revoked a very large number of certificates).'
                   Confirm = @('Check the file size on the web server (owner).')
                   Fix = @('Consider shorter-lived certificates, delta CRLs, or an Online Responder for large CAs.')
                   Signals = @(@{ When = 'Category=CRL|CDP'; Weight = 15; Because = 'the oversized item is a CRL' }) }
            ) }

        'RETRIEVAL_FAIL' = @{
            Title = 'A read failed and the reason is not specific'
            What = 'The tool could not get data from a source and the error did not say clearly why. The message and evidence of the finding hold the exact error.'
            Sources = @('S42', 'S01')
            Causes = @(
                @{ Id = 'network-path'; Cause = 'A network problem between this computer and the source (firewall, routing, name resolution).'
                   Confirm = @('Test-NetConnection <Host> -Port <Port>', 'Resolve-DnsName <Host>')
                   Fix = @('Fix the path, then run the check again.') }
                @{ Id = 'service-state'; Cause = 'The service on the other side is stopped or restarting.'
                   Confirm = @('Ask the owner to check the service state and its event logs.')
                   Fix = @('Start or repair the service.') }
                @{ Id = 'permissions'; Cause = 'The account running the tool is not allowed to read the source. The tool keeps permission failures separate when it can tell; this one it could not.'
                   Confirm = @('Run the tool as an account with read access to the PKI and compare.')
                   Fix = @('Grant read access (never more) to the account that runs the health check.') }
            ) }

        'RETRIEVAL_ORDER' = @{
            Title = 'A failing URL sits before a working one in the CDP or AIA list'
            What = 'Windows tries the URLs of a CDP or AIA extension in the order they are listed. A dead URL placed first costs every client a timeout before it reaches the working one.'
            Sources = @('S14', 'S15')
            Causes = @(
                @{ Id = 'dead-url-first'; Cause = 'An old or unreachable URL (often LDAP or a retired web server) is still listed before the working HTTP URL.'
                   Confirm = @('Look at the CDP/AIA order in the CA properties > Extensions tab, or the order shown in the finding evidence.')
                   Fix = @('Put the working HTTP URL first and remove URLs that no longer answer. Existing certificates keep their old order until re-issued.')
                   Signals = @(@{ When = 'time-out|timeout'; Weight = 10; Because = 'each failing URL costs a timeout' }) }
                @{ Id = 'ldap-from-outside'; Cause = 'The first URL is LDAP, which computers outside the domain network cannot use, so they always wait for it to fail.'
                   Confirm = @('Check whether the failing URL starts with ldap://.')
                   Fix = @('List the HTTP URL first.')
                   Signals = @(@{ When = 'ldap:'; Weight = 20; Because = 'the failing URL is an LDAP URL' }) }
            ) }
}
