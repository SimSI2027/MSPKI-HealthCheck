# Glossary for the GUI's Explain mode and Learn page (GX9). DATA ONLY: read with Import-PowerShellDataFile, never run.
# Keys are the words the window shows (docs/GUI-DESIGN.md section 9 and the PKI acronyms on the Overview). Sources: docs/KNOWLEDGE-SOURCES.md.
@{
    Version = '2026-11-28'
    Terms   = @(
        @{ Term = 'CA'; Also = @('certification authority', 'CAs'); Short = 'A certification authority: the server role that signs certificates and publishes the list of the ones it revoked.'
           More = 'An Enterprise CA is registered in Active Directory and issues certificates from templates. A root CA signs only itself and the CAs below it; an issuing CA signs the certificates people and computers use.'; Related = @('root CA', 'issuing CA', 'chain') }
        @{ Term = 'root CA'; Also = @('root CAs'); Short = 'The CA at the top of a chain: its certificate is signed by itself and trusted because it was installed, not because something vouches for it.'
           More = 'Roots are often kept offline. Their CRL still has to be published on time, or every chain below them fails revocation checks.'; Related = @('CA', 'chain', 'CRL') }
        @{ Term = 'issuing CA'; Also = @('issuing CAs', 'subordinate CA'); Short = 'A CA below a root that signs the certificates of users, computers and services.'
           More = 'An issuing CA has its own certificate from the CA above it, and its own CRL. Most findings about expiry and publication are about issuing CAs.'; Related = @('CA', 'root CA') }
        @{ Term = 'AIA'; Also = @('Authority Information Access'); Short = 'Authority Information Access: the addresses in a certificate where a client can download the issuing CA''s certificate.'
           More = 'Clients use the AIA addresses to build the chain when they do not already have the CA certificate. If none of them answers with the right certificate, the chain cannot be built.'; Related = @('published address', 'chain', 'CDP') }
        @{ Term = 'CDP'; Also = @('CRL distribution point', 'CRL addresses'); Short = 'CRL distribution point: the addresses in a certificate where a client downloads the CRL to check that the certificate was not revoked.'
           More = 'Every address listed should serve the current CRL. A failing or stale CDP makes revocation checks fail, which blocks logons, VPN and TLS clients that require them.'; Related = @('CRL', 'published address', 'next update') }
        @{ Term = 'CRL'; Also = @('CRLs', 'certificate revocation list', 'base CRL', 'delta CRL'); Short = 'Certificate revocation list: a signed list of the certificates a CA has revoked, valid until its next update.'
           More = 'Each CA key has a base CRL and may have a delta CRL with the changes since. An expired CRL makes clients treat the CA''s certificates as unverifiable.'; Related = @('CDP', 'next update', 'next publish', 'copy') }
        @{ Term = 'OCSP'; Also = @('Online Responder', 'OCSP responder'); Short = 'Online Certificate Status Protocol: a web service that answers "is this one certificate revoked?" instead of a whole CRL.'
           More = 'An OCSP address in a certificate is tried before the CDP by most clients. A responder that answers with an old or wrong signing certificate is reported here.'; Related = @('CDP', 'published address') }
        @{ Term = 'LDAP'; Also = @('ldap://'); Short = 'The directory protocol. An ldap:// address points into Active Directory, where CAs often publish their certificates and CRLs.'
           More = 'Only domain-joined clients can usually read LDAP addresses, so a certificate used outside the domain needs an HTTP address as well.'; Related = @('AIA', 'CDP', 'published address') }
        @{ Term = 'CES'; Also = @('Certificate Enrollment Web Service'); Short = 'Certificate Enrollment Web Service: lets clients request certificates over HTTPS instead of DCOM.'
           More = 'CES works with CEP. It is listed on the CA''s Enrollment Services object in Active Directory, and its address must answer over TLS with a valid certificate.'; Related = @('CEP', 'PKI services') }
        @{ Term = 'CEP'; Also = @('Certificate Enrollment Policy Web Service'); Short = 'Certificate Enrollment Policy Web Service: tells clients over HTTPS which templates they may enroll for.'
           More = 'Clients outside the domain, or in another forest, use CEP and CES together to enroll.'; Related = @('CES', 'certificate template') }
        @{ Term = 'NDES'; Also = @('SCEP', 'Network Device Enrollment Service'); Short = 'Network Device Enrollment Service: the SCEP server that lets network devices and Intune-managed devices get certificates.'
           More = 'NDES uses registration authority (RA) certificates of its own and a template it may enroll for. The tool only sends anonymous requests to it; the admin page is opt-in.'; Related = @('PKI services', 'certificate template') }
        @{ Term = 'certificate template'; Also = @('template', 'templates', 'certificate templates'); Short = 'A recipe in Active Directory that says what an Enterprise CA puts in a certificate and who may enroll for it.'
           More = 'A CA issues only the templates it publishes. Template permissions and settings decide most enrollment risks (the ESC findings).'; Related = @('CA', 'area') }
        @{ Term = 'NTAuth'; Also = @('NTAuthCertificates'); Short = 'The list in Active Directory of CAs trusted to issue logon certificates (smart card, Windows Hello for Business, some VPN).'
           More = 'A CA missing from NTAuth cannot issue certificates that work for domain logon, even when everything else is fine.'; Related = @('CA') }
        @{ Term = 'Enrollment Services container'; Also = @('Enrollment Services object'); Short = 'The Active Directory container that lists every Enterprise CA of the forest, with its host, templates and enrollment addresses.'
           More = 'The tool starts here: every Enterprise CA it checks was found in this container.'; Related = @('CA', 'CES') }
        @{ Term = 'published address'; Also = @('published addresses', 'address', 'addresses'); Short = 'An AIA, CDP, OCSP or enrollment URL that a CA names in its certificates or properties.'
           More = 'The tool contacts only addresses that came from your PKI itself, with anonymous requests, and checks what each one serves.'; Related = @('AIA', 'CDP', 'OCSP', 'host') }
        @{ Term = 'host'; Also = @('hosts', 'web host'); Short = 'The computer a published address names, found by its DNS name.'
           More = 'One host often serves many addresses; on the map they fold into a group with a count.'; Related = @('published address', 'group') }
        @{ Term = 'finding'; Also = @('findings'); Short = 'One thing the run checked and what it saw: a status, how sure the tool is, where it came from, and the evidence.'
           More = 'Every finding that is not passing explains itself: probable causes, read-only checks and the fix with its owner.'; Related = @('could not check', 'health score') }
        @{ Term = 'could not check'; Also = @('could not be checked'); Short = 'The run was not allowed to read something (permission denied) or it is not supported from here, so nothing is known about it.'
           More = 'It is not a failure of your PKI. It costs no points, but it makes the score partial: run again with an account that may read it, or check it on the server.'; Related = @('partial score', 'finding') }
        @{ Term = 'health score'; Also = @('score', 'out of 100'); Short = 'A summary of the findings from 0 to 100: each area starts at 100 and loses points per failure and warning.'
           More = 'The overall score is the average of the areas, but never more than the weakest area + 30, so one broken area cannot hide behind healthy ones. It is not a certification.'; Related = @('held down by', 'partial score', 'area') }
        @{ Term = 'held down by'; Also = @('holds the score'); Short = 'The weakest area limits the overall score: it can be at most that area''s score + 30.'
           More = 'Fix the area named here first: it moves the overall score the most.'; Related = @('health score', 'area') }
        @{ Term = 'partial score'; Also = @('partial'); Short = 'Some checks could not run (or the run did not finish), so the score covers only what was checked.'
           More = 'The missing checks cost nothing, so a partial score can look better than the real state. The coverage section says what was not read.'; Related = @('could not check', 'health score') }
        @{ Term = 'area'; Also = @('By area', 'CA hierarchy', 'Revocation', 'Publication', 'Enrollment security', 'Enrollment services', 'Directory'); Short = 'One of six parts of the PKI scored on its own: CA hierarchy, Revocation, Publication, Enrollment security, Enrollment services and Directory.'
           More = 'Select an area to see its findings. An area without findings says "not scored".'; Related = @('health score', 'held down by') }
        @{ Term = 'next update'; Also = @('NextUpdate', 'valid until'); Short = 'The time a CRL stops being valid. After it, clients reject the CRL until a newer one is published.'
           More = 'Every countdown on the Timeline counts from the time of the run, not from today.'; Related = @('next publish', 'CRL', 'as of the run') }
        @{ Term = 'next publish'; Also = @('Next CRL Publish', 'overlap'); Short = 'The time the CA plans to write its next CRL, before the current one runs out. The gap between the two is the overlap.'
           More = 'A short or missing overlap leaves no time to copy the new CRL to every address.'; Related = @('next update', 'CRL') }
        @{ Term = 'copy'; Also = @('copies'); Short = 'A CRL as one address (or the CA itself) served it. Copies of the same CRL can differ when a copy job fails.'
           More = 'The Timeline shows the copy at every address next to the CA''s own.'; Related = @('CRL', 'published address') }
        @{ Term = 'chain'; Also = @('certificate chain'); Short = 'From a certificate up to its root CA, with the result of each AIA and CDP address on the way.'
           More = 'A chain that ends at a root this computer does not trust, or that cannot be built from the AIA addresses, fails for every certificate below it.'; Related = @('AIA', 'root CA') }
        @{ Term = 'issuer not confirmed'; Also = @('Unknown issuer'); Short = 'The CA''s issuer could not be read, so the map shows the most likely one dashed.'
           More = 'It usually means the CA''s own certificate could not be read (for example permission denied on the CA).'; Related = @('chain', 'could not check') }
        @{ Term = 'group'; Also = @('groups'); Short = 'The addresses one host serves, folded into one node with a count on large maps. Select it to expand it.'
           More = 'Groups keep a large estate readable; nothing is hidden, and search still finds the addresses inside.'; Related = @('host', 'published address') }
        @{ Term = 'earlier run'; Also = @('run on show'); Short = 'A results.json opened from disk: the window shows what that run saw, and nothing is scanned.'
           More = 'The date at the top says when it ran. Run now starts a new, read-only run.'; Related = @('as of the run', 'History') }
        @{ Term = 'as of the run'; Also = @('As of'); Short = 'Every countdown counts from the time the run read the data, not from today.'
           More = 'An earlier run keeps its own time, so its countdowns do not change when you open it later.'; Related = @('earlier run', 'next update') }
        @{ Term = 'History'; Also = @('What changed', 'compare'); Short = 'The page with the earlier runs of this forest, the score over time and what changed between two runs.'
           More = 'New problems, resolved, changed and still open are worked out from each finding''s stable key.'; Related = @('earlier run') }
        @{ Term = 'confidence'; Also = @('Confirmed', 'Referenced', 'Inferred'); Short = 'How sure the tool is: Confirmed (it read or tested it), Referenced (something it read names it), Inferred (worked out, not seen).'
           More = 'An Inferred result is never shown as Confirmed.'; Related = @('finding') }
        @{ Term = 'PKI services'; Also = @('Web Enrollment', 'Intune connector'); Short = 'The services around the CAs: Web Enrollment, CES, CEP, NDES/SCEP, OCSP and the Intune Certificate Connector.'
           More = 'Each one shows whether it was found, where, and what this run could see of it from this computer.'; Related = @('CES', 'CEP', 'NDES', 'OCSP') }
    )
}
