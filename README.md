# cswb — Switchboard

Implementation in progress. Admission composes current Charter, Profile and Guard
with one-use challenges and per-request device possession. Runtime integration
and qualification remain required.

## Scope

Own bounded volatile presence, device-bound attendance generations, complete entry replacement, deadlines and departure. Lookup derives its indexes from committed entries.

Require current owner-verified credential, device possession and public-profile
Guard before publication. The binding MVP scope now also requires original G2
frontier/ZK currentness and public punishment; those owner ports are pending, so
this candidate is not complete admission authority. Reserved formats grant none. A newer
device generation replaces prior attendance; departure/expiry removes live data.
Heartbeat cadence and schema-change policy come from verified platform settings,
not a local policy engine. No durable history, contact graph, issuer lookup or
profile keys.

## Dependencies and validation

Reuse the existing volatile storage port and Guard rather than duplicate their mechanisms. CI resolves one lock snapshot and gates stable checks plus exact line and branch coverage. Passing a storage transition test does not establish admission integration.

Profile verifies the complete original signed publication; Charter provides
authenticated policy and revocation floors. Maintained ed25519-dalek verifies
fresh request possession, sha2 hashes exact request/publication bytes, url checks
canonical HTTPS origins, and data-encoding encodes opaque random handles.
