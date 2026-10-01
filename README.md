# cswb — Switchboard

Implementation in progress. Admission is unavailable until current trust, public-record and device-authority capabilities are integrated.

## Scope

Own bounded volatile presence, device-bound attendance generations, complete entry replacement, deadlines and departure. Lookup derives its indexes from committed entries.

## Dependencies and validation

Reuse the existing volatile storage port and Guard rather than duplicate their mechanisms. CI resolves one lock snapshot and gates stable checks plus exact line and branch coverage. Passing a storage transition test does not establish admission integration.
