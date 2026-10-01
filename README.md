# cswb — Switchboard

Implementation in progress. Admission is unavailable until current trust, public-record and device-authority capabilities are integrated.

## Scope

Own bounded volatile presence, device-bound attendance generations, complete entry replacement, deadlines and departure. Lookup derives its indexes from committed entries.

Require current owner-verified credential, device possession, public-profile Guard and local record capabilities before publication. A newer device generation replaces the prior attendance; departure/expiry removes live data. Heartbeat cadence, record quorum and schema-change policy come from verified platform settings, not a local policy engine. No durable history, contact graph, issuer lookup or profile keys.

## Dependencies and validation

Reuse the existing volatile storage port and Guard rather than duplicate their mechanisms. CI resolves one lock snapshot and gates stable checks plus exact line and branch coverage. Passing a storage transition test does not establish admission integration.
