# Data model: entity graph (results.json format 2)

The findings say *what is wrong*. The entity graph says *what exists, where each object was seen (or should have been and was not),
and how objects relate*. It is the base for drill-down (G1), the "where this exists" panel (G2) and for hierarchy analysis that can
explain **why** something fails. Code: `src/Model/EntityGraph.ps1` (store, ids, export, results adapter) and
`src/Model/EntityGraphBuilder.ps1` (built from the inventory, the probes and the findings). Tests: `tests/EntityGraph.Tests.ps1`.

## Ids
Every entity has a deterministic id `<prefix>:<normalised natural key>`. The same object gets the same id in every run on every
computer, so two runs can be compared by id. Keys are trimmed and lower-cased.

| Type | Prefix | Natural key | Notes |
|---|---|---|---|
| Forest | `forest` | forest DNS name | |
| Domain | `domain` | domain DNS name | `InForest`, `Trusted` properties |
| CA | `ca` | CA config string `host\name` (else the CA name) | Enterprise CAs from Enrollment Services |
| CACertificate | `cacert` | SHA-1 thumbprint (no spaces) | one entity per **generation** |
| CRL | `crl` | `<AKI hex>:base` or `<AKI hex>:delta` | one per CA **key** and kind; AKI = SKI of the signing CA certificate. Without an AKI: `name=<issuer>;v=<CA version>` |
| Endpoint | `endpoint` | the lead registry's normalised URL key | http and https of one path, case, default ports and `%20` give one endpoint |
| Host | `host` | DNS name without trailing dot | `Addresses` from this run's DNS cache (no extra lookup), `Roles` |
| Service | `service` | `<kind>:<endpoint id or host>` | kinds: WebEnrollment, CES, CEP, NDES, OCSP, IntuneConnector |
| Template | `template` | template `cn` | |
| LocalCertificate | `localcert` | thumbprint | `LocalMachine\My` certificates issued by a discovered CA (public part only); more with D3 |
| ADObject | `adobject` | distinguished name | PKI containers and objects |

## Observations: where an entity exists
`{ EntityId, Kind, Source, Location, Confidence, Detail, Timestamp }`

- **Kind**: `Seen` (the object itself was read there), `Referenced` (something names it there, e.g. a URL inside a certificate or a
  CA property), `ExpectedMissing` (it should be there and was looked for, but is not).
- **Source**: `AD`, `CA` (GetCAProperty), `HTTP`, `LDAP`, `File`, `Certificate`, `CRL`, `DNS`, `LocalStore`, `LocalPolicy`, `EventLog`,
  `Constructed` (a standard path tried on a proven PKI host).
- **Location**: the exact place: a DN, a URI, a CA config string, a store path, a thumbprint, an event log name.
- **Confidence**: same scale as findings. A constructed candidate is `Inferred` until it answers; never `Confirmed`.
- Duplicates (same entity, kind, source, location) are merged.

ExpectedMissing is recorded only when the place was really checked:
- an Enterprise CA certificate generation that is not expired and not in AIA (detail says when it *is* in NTAuth), or not in NTAuth;
  an Enterprise root not in Certification Authorities;
- a standard PKI container that was looked for and not found;
- a template published on a CA with no template object;
- an AIA URL that returned no proven issuer certificate: on every CA certificate whose SKI is the AKI of the referencing certificate;
- a CDP / Freshest CRL URL that returned no CRL: on the CRL entity of the key that should sign it (for a URL from the CA's own
  `CertCdpUrls`, the CA's current key);
- nothing is recorded as missing when a URL was not tested (for example with `-SkipNetwork`).

## Relations
`{ From, Type, To, Sources[], Confidence }`, directed:

| Type | From → To | Meaning |
|---|---|---|
| `issuedBy` | CACertificate → CACertificate | chain, by AKI = SKI (Confirmed); by issuer name only when there is no AKI (Inferred) |
| `signedBy` | CRL → CACertificate | the CA key that signs the CRL (CRL AKI) |
| `publishedAt` | CACertificate/CRL → Endpoint or ADObject | the object was read at that place |
| `references` | CACertificate/CA → Endpoint | a URL in the certificate's AIA/CDP, or in the CA's URL properties |
| `hostedOn` | CA/Endpoint/Service → Host | |
| `servedBy` | Endpoint → Service | e.g. an OCSP URL and its responder |
| `resolvesTo` | Host → Host | DNS alias (CNAME) chain to the real host (D2) |
| `aliasOf` | Host → Host | a name in the SAN of a certificate served by (or installed on) that host; ExpectedMissing DNS when it does not resolve |
| `enrollsVia` | Template/Service → CA | the template is published on the CA; CES enrolls through the CA |
| `supersedes` | CACertificate → CACertificate | the newer generation of the same CA (by NotBefore; Inferred) |
| `certificateOf` | CACertificate → CA | the generation belongs to that CA (added; needed to join CA and certificate) |
| `partOf` | Domain/CA/ADObject → Forest | (added) |

## Findings
Every finding has `EntityIds` (string[]): the entities it is about. Ids set when the finding is created are kept; the linker adds ids
from RelatedCA, Endpoint (URL → endpoint and host; config string → CA), thumbprints in Target/Message, the template, container, host
or domain named in Target, and for CRL findings the CRL served at that URL. A finding about the run itself links to the forest (or to
this computer when there is no forest), so the list is never empty.

## results.json
- `Schema` = `mspki-healthcheck/2`, `SchemaVersion` = 2, new `Graph` = `{ SchemaVersion; Counts { Entities, Observations, Relations,
  ExpectedMissing, ByType }; Entities[]; Observations[]; Relations[] }`, sorted by id. Entity = `{ Id; Type; Name; Properties }`.
- Readers go through `ConvertFrom-MspkiResultsDocument` (exported): format 1 is accepted (no graph, empty `EntityIds`, a `Notice` the
  GUI shows in its banner); a newer format throws a plain-language message. The report re-export uses the same adapter.
- Size: every reader (GUI, report re-export, tests) goes through `ConvertFrom-MspkiJson` (`src/Model/JsonReader.ps1`: in-box JavaScriptSerializer,
  `MaxJsonLength = [int]::MaxValue`), so there is no ~2 MB limit; a 10 MB file is tested. Still keep entity
  properties short (no certificate bytes, no ACLs in the graph).

## How it is built during a run
1. After discovery: `Add-MspkiInventoryToEntityGraph` (forest, domains, containers, CAs, CA certificate generations, templates).
2. During the endpoint checks: `Register-MspkiProbeResult` per URL variant (CRL or certificate seen, or expected and missing) and
   `Register-MspkiCaOwnCrl` (the CA's own CRLs).
3. At the end (also for a cancelled run): the inventory pass again (leads, NDES hosts, CEP, connector are known by then), then
   `Add-MspkiFindingEntityLink`, then `Get-MspkiEntityGraphExport` into results.json.
