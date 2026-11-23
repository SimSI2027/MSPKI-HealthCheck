# MSPKI Health Check diagnosis knowledge base, topics: Directory. DATA ONLY. Format and rules: see Diagnosis.psd1.
@{
        # ===== Directory, RPC/DCOM and run-level topics =====
        'DIRECTORY_UNAVAILABLE' = @{
            Title = 'A domain controller or directory service did not answer'
            What = 'An LDAP request to Active Directory failed because no server answered ("server is not operational", or the domain could not be contacted). Everything that is read from AD after this point is missing from the result.'
            Sources = @('S42')
            Causes = @(
                @{ Id = 'not-on-network'; Cause = 'This computer is not on the corporate network (VPN down, a guest or home network), so it cannot reach any domain controller.'
                   Confirm = @('nltest /dsgetdc:<DomainDnsName>', 'Test-NetConnection <DomainController> -Port 389')
                   Fix = @('Connect to the corporate network or VPN and run the check again.')
                   Signals = @(@{ When = 'DC_NOT_FOUND|No domain controller answered'; Weight = 20; Because = 'no domain controller answered at all' }) }
                @{ Id = 'dc-down-or-stale'; Cause = 'The domain controller this computer picked is down, was retired, or is stale in DNS (an old SRV record or server object).'
                   Confirm = @('nltest /dsgetdc:<DomainDnsName> /force', 'Resolve-DnsName _ldap._tcp.dc._msdcs.<DomainDnsName> -Type SRV')
                   Fix = @('Remove the stale SRV records and server objects of retired domain controllers (metadata cleanup), and check replication health.') }
                @{ Id = 'firewall-ldap'; Cause = 'A firewall blocks LDAP (TCP 389, 636, 3268) between this computer and the domain controllers.'
                   Confirm = @('Test-NetConnection <DomainController> -Port 389')
                   Fix = @('Allow LDAP from client networks to the domain controllers.') }
            ) }

        'DIRECTORY_ERROR' = @{
            Title = 'Active Directory returned an error this tool cannot name more precisely'
            What = 'A directory read failed with an LDAP error that does not say whether the server, the permissions or the object is at fault. The exact error is in the finding message and evidence.'
            Sources = @('S42')
            Causes = @(
                @{ Id = 'referral'; Cause = 'The server answered with a referral to another server or domain. The tool never follows referrals, because that would send a second directory bind.'
                   Confirm = @('Read the error code in the evidence; a referral shows as 0x8007202B.')
                   Fix = @('Run the check from a computer in the domain that holds the object, or ask the owner to fix the DNS name that produced the referral.')
                   Signals = @(@{ When = '202B|referral'; Weight = 40; Because = 'the error is a referral' }) }
                @{ Id = 'object-or-attribute'; Cause = 'The object or attribute named in the URL does not exist (a CDP or AIA URL that points at an AD object that was deleted or never published).'
                   Confirm = @('Open the LDAP path from the evidence in ADSI Edit (view only).')
                   Fix = @('Republish the CA''s CRL or certificate to AD, or remove the URL from the extension.')
                   Signals = @(@{ When = 'ldap:'; Weight = 15; Because = 'the failing source is an LDAP URL' }) }
                @{ Id = 'insufficient-access'; Cause = 'The account running the tool may not read that object (permissions on a container).'
                   Confirm = @('Compare with an account that is a member of Domain Admins (read only).')
                   Fix = @('Grant read access on the container to Authenticated Users (the default for PKI containers).') }
            ) }

        'DC_NOT_FOUND' = @{
            Title = 'No domain controller could be found; the directory location was guessed from the domain name'
            What = 'The tool could not read RootDSE from any domain controller. It built the Configuration naming context from the domain name so later reads can still try, but nothing it reports from AD can be fully trusted.'
            Sources = @('S42')
            Causes = @(
                @{ Id = 'off-network'; Cause = 'The computer is not connected to the domain network.'
                   Confirm = @('nltest /dsgetdc:<DomainDnsName>', 'echo %LOGONSERVER%')
                   Fix = @('Connect to the network or VPN, then run the check again.') }
                @{ Id = 'dns-not-ad'; Cause = 'The computer''s DNS servers do not host the AD zones (no SRV records for domain controllers).'
                   Confirm = @('Resolve-DnsName _ldap._tcp.dc._msdcs.<DomainDnsName> -Type SRV')
                   Fix = @('Point the computer at DNS servers that host the AD zones.') }
                @{ Id = 'not-joined'; Cause = 'The computer is not joined to a domain, so there is nothing to discover.'
                   Confirm = @('(Get-CimInstance Win32_ComputerSystem).PartOfDomain')
                   Fix = @('Run the tool from a domain-joined computer.') }
            ) }

        'NETWORK_PATH_FAIL' = @{
            Title = 'A network path or computer name was not found'
            What = 'A Windows call to a remote computer failed with "network path not found". The name did not resolve for that service, or the remote service is not reachable.'
            Sources = @('S42', 'S01')
            Causes = @(
                @{ Id = 'name-resolution'; Cause = 'The computer name does not resolve (NetBIOS and DNS differ, a short name without a suffix, a retired host).'
                   Confirm = @('Resolve-DnsName <Host> -DnsOnly', 'ping -a <Address>')
                   Fix = @('Fix DNS for the host or correct the name stored in AD.') }
                @{ Id = 'smb-or-rpc-blocked'; Cause = 'File and printer sharing or RPC is blocked by the host firewall.'
                   Confirm = @('Test-NetConnection <Host> -Port 445', 'Test-NetConnection <Host> -Port 135')
                   Fix = @('Allow the needed ports from the management network only.') }
            ) }

        'RPC_NO_ANSWER' = @{
            Title = 'The CA host answers on port 135 but the CA itself does not answer'
            What = 'The first step of a DCOM call to the CA (the endpoint mapper on TCP 135) worked, but the call to the CA did not complete, and it took a long time to fail. That points to the path to the CA''s dynamic RPC port, or to a CA service that is not running. A quick refusal is a different case (an access problem), reported separately.'
            Sources = @('S42', 'S04', 'S01', 'S02')
            Causes = @(
                @{ Id = 'dynamic-ports-blocked'; Cause = 'A firewall between this computer and the CA host blocks the dynamic RPC ports (49152-65535, or the fixed port the CA uses), so the connection after the endpoint mapper hangs.'
                   Confirm = @('Test-NetConnection <CAHost> -Port 135  (works if the mapper is reachable)', 'certutil -config "<CAHost>\<CAName>" -ping  (a slow failure points at the ports)', 'On a computer in the CA network the same ping works.')
                   Fix = @('Allow RPC dynamic ports from client or management networks to the CA host, or fix the CA to one RPC port and allow only that.')
                   Signals = @(@{ When = 'dynamic RPC port|firewall'; Weight = 20; Because = 'the failure was slow after TCP 135 answered, which fits blocked dynamic ports' }) }
                @{ Id = 'certsvc-stopped'; Cause = 'The Certificate Services service on the CA host is stopped, hung or still starting, so no endpoint answers behind the mapper.'
                   Confirm = @('Ask the CA owner to run: Get-Service CertSvc on the CA host', 'certutil -config "<CAHost>\<CAName>" -ping from the CA host itself')
                   Fix = @('Start Certificate Services; if it stops again, read the Application log of the CA host (events from CertificationAuthority) and fix the cause, such as an expired CRL (see the CRL topics).')
                   }
                @{ Id = 'dcom-hardening'; Cause = 'DCOM hardening (KB5004442) rejects the call because client and server do not agree on the authentication level.'
                   Confirm = @('On the CA host (owner): System log, source DistributedCOM, events 10036 and 10037.')
                   Fix = @('Update the older side so both use packet integrity; do not turn the hardening off.') }
            ) }

        'RPC_ACCESS_DENIED' = @{
            Title = 'The CA host turned down this account (DCOM access denied, shown as "RPC server unavailable")'
            What = 'The CA host answered quickly on TCP 135, then refused the DCOM request of the account that runs the tool. Windows shows that refusal as error 0x800706BA, "RPC server unavailable", which is misleading: the network and the CA service are fine, this one account is not allowed to talk to the CA over DCOM. The tool infers this from the timing (confidence Inferred), because the real fault code (access denied) is not visible to it.'
            Sources = @('S01', 'S04', 'S02')
            Causes = @(
                @{ Id = 'dcom-access-group'; Cause = 'The local group "Certificate Service DCOM Access" on the CA host does not contain Authenticated Users (the CA setup adds it; a rebuild or an upgrade can lose it), or the account is in none of the groups that group allows.'
                   Confirm = @('On the CA host (owner): lusrmgr.msc > Groups > Certificate Service DCOM Access > members.', 'From this computer as the same account: certutil -config "<CAHost>\<CAName>" -ping  (the same 0x800706BA in a fraction of a second confirms the refusal).')
                   Fix = @('Add NT AUTHORITY\Authenticated Users to the "Certificate Service DCOM Access" group on the CA host (the Microsoft default), then run the check again.')
                   Signals = @(@{ When = '(?m)^Evidence:.*(another CA answered|answered the same account)'; Weight = 20; Because = 'another CA answered the same account in this run, so the cause is a per-account setting on this host' }
                               @{ When = 'within \d+ ms|Answered within'; Weight = 10; Because = 'the refusal came back within a few seconds after TCP 135 answered' }) }
                @{ Id = 'com-security-limits'; Cause = 'The machine-wide COM Security limits of the CA host (Access and Launch/Activation permissions) no longer grant "Certificate Service DCOM Access" the Remote Access and Remote Activation rights.'
                   Confirm = @('On the CA host (owner): dcomcnfg > Component Services > Computers > My Computer > Properties > COM Security > Edit Limits (both Access and Launch and Activation).', 'System log: DistributedCOM events 10027 / 10028 / 10036 at the time of a run name the account and the reason.')
                   Fix = @('Give the "Certificate Service DCOM Access" group Local and Remote Access, and Local and Remote Launch and Activation, in the Edit Limits dialogs.')
                   Signals = @(@{ When = 'DCOM'; Weight = 5; Because = 'DCOM is named in the finding' }) }
                @{ Id = 'user-rights-gpo'; Cause = 'A Group Policy on the CA host denies the account network logon: "Access this computer from the network" omits the user, or "Deny access to this computer from the network" includes Everyone, Users or a group the account belongs to. Kerberos then fails and the call falls back to an anonymous logon, which DCOM refuses.'
                   Confirm = @('On the CA host (owner): gpresult /h <file>.html and read Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment.', 'System log: DistributedCOM 10027 naming ANONYMOUS LOGON.')
                   Fix = @('Add the right groups to "Access this computer from the network" and remove the account''s group from the deny policy; talk to the security team first, the policy is there for a reason.')
                   Signals = @(@{ When = 'ANONYMOUS LOGON'; Weight = 40; Because = 'an anonymous logon was recorded' }) }
                @{ Id = 'users-group'; Cause = 'The local Users group on the CA host lost its default members (Domain Users, Authenticated Users, INTERACTIVE).'
                   Confirm = @('On the CA host (owner): lusrmgr.msc > Groups > Users.')
                   Fix = @('Restore the default members of the Users group.') }
                @{ Id = 'ca-security'; Cause = 'The account has no Read or Request Certificates permission in the CA''s own Security tab.'
                   Confirm = @('On the CA host (owner): Certification Authority console > CA Properties > Security.')
                   Fix = @('Grant Authenticated Users Read and Request Certificates (the default).') }
                @{ Id = 'enabledcom-or-rpc-policy'; Cause = 'DCOM is switched off (EnableDCOM = N in the OLE registry key) or the policy "Restrictions for Unauthenticated RPC Clients" is set on the CA host.'
                   Confirm = @('On the CA host (owner): reg query HKLM\Software\Microsoft\OLE /v EnableDCOM', 'gpresult /h <file>.html and look for Restrictions for Unauthenticated RPC Client.')
                   Fix = @('Set EnableDCOM to Y (restart needed) or set the RPC restriction policy to Not Configured, as the Microsoft article describes.') }
            ) }

        'PERMISSION_DENIED' = @{
            Title = 'The account running the tool was not allowed to read something'
            What = 'A read was refused for permission reasons. This tool reads only and keeps permission failures apart from outages, so the part of the PKI behind this refusal is simply not checked in this run.'
            Sources = @('S01', 'S18')
            Causes = @(
                @{ Id = 'standard-user'; Cause = 'The data needs more rights than an ordinary domain user has (for example the CA database, the CA registry, or a remote service state). This is expected for a standard user.'
                   Confirm = @('Run the tool again from an account the PKI owner has granted read access, and compare the results.')
                   Fix = @('If the check matters, ask the PKI owner for a read-only audit account, or let the owner run the check. Do not give the account administrator rights.')
                   Signals = @(@{ When = 'Standard user|standard account'; Weight = 10; Because = 'the run is under a standard account' }) }
                @{ Id = 'object-acl'; Cause = 'An AD object (a template, a container, a user) has permissions that exclude this account.'
                   Confirm = @('Open the object in ADSI Edit as view only and read its Security tab.')
                   Fix = @('Grant Read to Authenticated Users on PKI containers, which is the default; non-default permissions should be reviewed by the PKI owner.') }
                @{ Id = 'remote-host-policy'; Cause = 'The remote host''s DCOM, firewall or user-rights policy refuses this account.'
                   Confirm = @('See the DCOM access topic: certutil -config "<CAHost>\<CAName>" -ping as the same account.')
                   Fix = @('The PKI owner adjusts the host''s DCOM and user-rights settings.') }
            ) }

        'CA_NAME_NOT_ON_HOST' = @{
            Title = 'The host answers, but no CA of the expected name runs there'
            What = 'The CA host was reached, but the Certification Authority name that AD publishes for it does not exist on that host. The AD object and the real CA no longer agree.'
            Sources = @('S33', 'S12')
            Causes = @(
                @{ Id = 'ca-renamed-or-rebuilt'; Cause = 'The CA was rebuilt, renamed or reinstalled with a different name while the old Enrollment Services object stayed in AD.'
                   Confirm = @('certutil -config "<CAHost>" -ping  (lists the CA names that answer on that host)', 'Compare with the Enrollment Services object name in AD (finding evidence).')
                   Fix = @('Remove the stale Enrollment Services object (and AIA, CDP and KRA objects of the old CA) as part of a decommission, or reinstall the CA under the published name.')
                   Signals = @(@{ When = 'ParentCA|rebuilt|renamed'; Weight = 5; Because = 'the finding mentions a rebuilt or renamed CA' }) }
                @{ Id = 'wrong-host-in-ad'; Cause = 'The Enrollment Services object points to a host that is no longer the CA host (the CA moved to another server).'
                   Confirm = @('Check dNSHostName on the Enrollment Services object and the real CA server name.')
                   Fix = @('Correct the object by re-registering the CA, or remove it if the CA is gone.') }
            ) }

        'CA_COM_CLASS_MISSING' = @{
            Title = 'This computer has no CA client component'
            What = 'The in-box COM class used to ask a CA for its properties is not registered on this computer, so no CA could be asked.'
            Sources = @('S17')
            Causes = @(
                @{ Id = 'client-without-component'; Cause = 'The computer is a stripped-down or non-Windows-PowerShell-5.1 environment, or the Certificate Services client component is missing.'
                   Confirm = @('$PSVersionTable.PSVersion', 'Run the tool in Windows PowerShell 5.1 (not PowerShell 7).')
                   Fix = @('Run the tool from a normal domain-joined Windows computer with Windows PowerShell 5.1.') }
            ) }

        'CA_NO_HOSTNAME' = @{
            Title = 'The Enrollment Services object has no host name'
            What = 'The AD object that registers the CA does not say which server it runs on, so the tool cannot contact it.'
            Sources = @('S33')
            Causes = @(
                @{ Id = 'damaged-object'; Cause = 'The object was damaged or created by hand, or left half-removed during a decommission.'
                   Confirm = @('Read the dNSHostName attribute of the Enrollment Services object (ADSI Edit, view only).')
                   Fix = @('Re-register the CA (certutil -dsPublish is not enough; reinstall or repair the CA), or delete the dead object.') }
            ) }

        'CA_DB_NOT_READ' = @{
            Title = 'The CA database was not read'
            What = 'The tool can use the CA''s issued-certificates database as one more source (for NDES evidence). It was skipped, so that source is missing. This is not a fault of the PKI.'
            Sources = @('S17')
            Causes = @(
                @{ Id = 'reader-not-installed'; Cause = 'The AD CS management tools are not installed on this computer, so the in-box database reader is not registered.'
                   Confirm = @('The finding message says whether the reader is missing; an ordinary client does not have it.')
                   Fix = @('Nothing to fix. Other routes (template permissions, SPNs) are used instead.')
                   Signals = @(@{ When = 'not installed on this computer'; Weight = 30; Because = 'the database reader is not installed here' }) }
                @{ Id = 'ca-did-not-answer'; Cause = 'The CA did not answer earlier in the run, so its database was not tried.'
                   Confirm = @('Look at the CA findings above this one (RPC or permission).')
                   Fix = @('Fix the CA connection first (see the RPC topics).')
                   Signals = @(@{ When = 'did not answer earlier'; Weight = 40; Because = 'the CA did not answer earlier in the run' }) }
                @{ Id = 'skipnetwork'; Cause = 'The run used -SkipNetwork, which turns off every network read.'
                   Confirm = @('Check how the run was started.')
                   Fix = @('Run without -SkipNetwork.')
                   Signals = @(@{ When = 'SkipNetwork'; Weight = 50; Because = 'the run was started with -SkipNetwork' }) }
            ) }

        'CLOCK_SKEW' = @{
            Title = 'Clocks differ by more than the tolerance'
            What = 'Two clocks that must agree do not. Kerberos allows 5 minutes by default; a CA clock that is wrong also issues certificates and CRLs with wrong validity dates.'
            Sources = @('S23', 'S35')
            Causes = @(
                @{ Id = 'time-source'; Cause = 'The Windows Time service on one side does not sync with the domain hierarchy (a wrong NTP source on the PDC emulator, or a stopped service).'
                   Confirm = @('w32tm /query /status', 'w32tm /monitor')
                   Fix = @('Point the PDC emulator at a reliable time source and let all other computers use the domain hierarchy.') }
                @{ Id = 'vm-time-sync'; Cause = 'A virtual machine takes its time from its host and the host clock is off.'
                   Confirm = @('Compare the VM clock with a domain controller: w32tm /stripchart /computer:<DomainController> /samples:3 /dataonly')
                   Fix = @('Disable host time sync for domain members, or fix the host clock.') }
                @{ Id = 'wrong-timezone'; Cause = 'A wrong time zone or a manually set clock.'
                   Confirm = @('Get-TimeZone; Get-Date')
                   Fix = @('Correct the time zone and let Windows Time set the clock.') }
            ) }

        'INTERNAL_ERROR' = @{
            Title = 'The tool hit an unexpected error'
            What = 'Something the tool did not expect happened while it ran one check. It is more likely a fault in this tool than a problem in the PKI, so the check was skipped and the run went on.'
            Sources = @('S42')
            Causes = @(
                @{ Id = 'tool-bug'; Cause = 'A defect in this tool, triggered by data it has not seen before.'
                   Confirm = @('Open run.log in the output folder and find the line for this check; it has the error and the first lines of the stack.')
                   Fix = @('Report it with run.log (after you remove real names from it). The check can be repeated after an update.')
                   Signals = @(@{ When = 'Exception'; Weight = 5; Because = 'the finding carries an exception' }) }
                @{ Id = 'environment'; Cause = 'A restricted environment (Constrained Language Mode, an antivirus that blocks a call, a missing in-box component).'
                   Confirm = @('$ExecutionContext.SessionState.LanguageMode  (should be FullLanguage)', 'Check the antivirus log for a blocked call at the time of the run.')
                   Fix = @('Run the tool in a standard Windows PowerShell 5.1 session.') }
            ) }

        'UNSUPPORTED' = @{
            Title = 'This feature is not available here'
            What = 'The tool tried something this computer, this PowerShell host or the remote server does not support. The check was skipped.'
            Sources = @('S17')
            Causes = @(
                @{ Id = 'environment'; Cause = 'The computer lacks the component (an older Windows build, a non-domain computer, or a CA property this CA version does not have).'
                   Confirm = @('Read the message: it names the component or property.')
                   Fix = @('Run from a supported computer (domain-joined Windows with Windows PowerShell 5.1 and .NET Framework 4.x).') }
                @{ Id = 'remote-not-possible'; Cause = 'A remote check is not reliable without administrator rights on the other host (for example whether the Intune Certificate Connector runs on a remote NDES server).'
                   Confirm = @('The check is only done on the computer running the tool.')
                   Fix = @('Run the tool on the server itself, or let its owner check.')
                   Signals = @(@{ When = 'remote'; Weight = 15; Because = 'the check would need to run on the other host' }) }
            ) }

        'NOT_CONFIGURED' = @{
            Title = 'Something is not set up'
            What = 'The tool looked in the place where a setting should be and found it empty. Whether that is a problem depends on whether you want that feature. Many are normal (no key archival, no CEP policy servers, no HTTP CDP).'
            Sources = @('S14')
            Causes = @(
                @{ Id = 'not-used'; Cause = 'The feature is not used in this PKI, on purpose.'
                   Confirm = @('Check the design document or the PKI owner.')
                   Fix = @('Nothing to do if it is intended.') }
                @{ Id = 'forgotten'; Cause = 'It should be set up and was missed (a CDP without HTTP, a published template list that is empty, a PTR record that was never created).'
                   Confirm = @('Read the finding message: it names what is missing and what depends on it.')
                   Fix = @('Configure it if clients depend on it; otherwise accept and document it.') }
            ) }

        'NOT_DISCOVERED' = @{
            Title = 'Nothing was found in the places the tool may look'
            What = 'The tool only checks hosts and objects that an authoritative source names (AD, CA properties, certificates). It found nothing for this item. That does not prove it does not exist: it may live where the tool is not allowed or not able to look.'
            Sources = @('S14', 'S42')
            Causes = @(
                @{ Id = 'not-present'; Cause = 'The service or object does not exist in this environment.'
                   Confirm = @('Ask the PKI owner whether it should exist.')
                   Fix = @('Nothing to do if it should not.') }
                @{ Id = 'no-reference'; Cause = 'It exists, but nothing in AD or in the certificates names it, so the tool has no authoritative lead (a standalone offline CA, a web server nobody registered).'
                   Confirm = @('Look at the server list of the PKI owner and compare.')
                   Fix = @('Register or reference it where clients and tools can find it (AD publication, CDP/AIA extensions).') }
                @{ Id = 'access'; Cause = 'This account or network cannot see it (a different forest, permission, or a firewall).'
                   Confirm = @('Run the tool from the server network or with a read-only audit account.')
                   Fix = @('Run it from where the item is visible.') }
            ) }

        'NOT_APPLICABLE' = @{
            Title = 'The check does not apply or could not be done'
            What = 'The tool skipped this check because something it depends on was missing or turned off, or because the item is not relevant here. The message says which.'
            Sources = @('S14')
            Causes = @(
                @{ Id = 'dependency-missing'; Cause = 'An earlier step failed or found nothing, so this step had nothing to check.'
                   Confirm = @('Look at the findings above it for the first failure.')
                   Fix = @('Fix the first failure; this one then runs.') }
                @{ Id = 'switch'; Cause = 'A run option turned it off (-SkipNetwork, a missing opt-in switch).'
                   Confirm = @('Check how the run was started.')
                   Fix = @('Run with the option if you want the check.')
                   Signals = @(@{ When = 'SkipNetwork'; Weight = 40; Because = 'the run used -SkipNetwork' }) }
            ) }

        'OK' = @{
            Title = 'Nothing to fix'
            What = 'This result passed or is informational.'
            Sources = @('S14')
            Causes = @(
                @{ Id = 'none'; Cause = 'No problem was found by this check.'; Confirm = @('Nothing to confirm.'); Fix = @('No action needed.') }
            ) }

        'EXPECTED_OFFLINE' = @{
            Title = 'A component is offline by design'
            What = 'An offline root CA is switched off on purpose. Its certificate and CRL are published by hand, so it cannot answer a network check.'
            Sources = @('S14', 'S16')
            Causes = @(
                @{ Id = 'offline-root'; Cause = 'This is a standalone offline root, as recommended for a two-tier hierarchy.'
                   Confirm = @('Check that its CRL is still valid (see the offline root topics).')
                   Fix = @('Nothing to fix; keep a calendar entry for the next CRL ceremony.') }
            ) }

        'STALE_REFERENCE' = @{
            Title = 'Something refers to a server or object that no longer answers'
            What = 'A name, URL or AD object still points at something that seems retired. The reference is old data rather than live configuration, but it can still slow clients down or hide a real gap.'
            Sources = @('S33', 'S14')
            Causes = @(
                @{ Id = 'decommission-leftover'; Cause = 'A CA, web server or domain controller was removed without cleaning up its AD objects and URLs.'
                   Confirm = @('Check with the PKI owner that the server is really retired.')
                   Fix = @('Remove the leftover object or URL after confirming that no certificate that has not expired still needs it.') }
            ) }

        'STALE_DC_OBJECT' = @{
            Title = 'A server object of a removed domain controller is still in AD'
            What = 'A server object under the Sites container looks like a domain controller, but it has no NTDS Settings object or no DNS record, so it is a leftover. The tool does not count it as a live domain controller and never contacts it.'
            Sources = @('S42')
            Causes = @(
                @{ Id = 'incomplete-demotion'; Cause = 'A domain controller was removed by force, or its metadata cleanup was never completed.'
                   Confirm = @('repadmin /showrepl  (replication partners)', 'nltest /dclist:<DomainDnsName>')
                   Fix = @('Complete the metadata cleanup of the removed domain controller (the AD owner does this).') }
            ) }

        'STALE_CA_OBJECT' = @{
            Title = 'An Enterprise CA is registered in AD, but its host does not answer'
            What = 'The Enrollment Services object of a CA exists, but the host does not answer and every CA certificate has expired or cannot be confirmed. The CA is probably decommissioned without cleanup.'
            Sources = @('S33', 'S12')
            Causes = @(
                @{ Id = 'decommissioned-ca'; Cause = 'The CA was shut down without removing its AD objects (Enrollment Services, AIA, CDP, KRA).'
                   Confirm = @('Confirm with the PKI owner that the CA is retired and that no valid certificate depends on its CRL.')
                   Fix = @('Follow the decommission steps: keep the CRL published until the last certificate expires, then remove the objects.')
                   Signals = @(@{ When = 'every CA certificate for it has expired'; Weight = 25; Because = 'every certificate of this CA has expired' }) }
                @{ Id = 'host-temporarily-down'; Cause = 'The CA host is down for a reason that is not permanent (maintenance, a network problem on the check path).'
                   Confirm = @('Test-NetConnection <CAHost> -Port 135 from the CA network.')
                   Fix = @('Bring the host back; if it stays down, treat it as retired.') }
            ) }

        'STALE_URL_REFERENCE' = @{
            Title = 'A URL in old certificates points at a host that does not answer'
            What = 'A CDP or AIA URL appears only in expired or historical CA certificates and its host does not answer. It is probably a leftover from an earlier design. The tool cannot see the certificates a CA issued, so it cannot say whether certificates that are still valid carry it.'
            Sources = @('S14', 'S33')
            Causes = @(
                @{ Id = 'old-design'; Cause = 'An earlier CA design used that host and it was retired.'
                   Confirm = @('Check which certificates carry the URL (the CA database, or a sample).')
                   Fix = @('If valid certificates still carry it, restore a working endpoint for it; otherwise nothing to do, and keep it off new certificates.') }
            ) }
}
