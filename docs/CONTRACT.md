# Switchboard contract

Own authoritative bounded volatile attendance under Gather. One community pseudonym has one current device generation. New attendance atomically replaces the former generation. Complete publication bytes and ciphertext are replaced together; Lookup may index only committed entries.

The service supplies one scoped volatile Store, clock, CSPRNG-backed Tokens and explicit resource limits. The store contract lives in cmmr and is wired through cvtl by the door. Every write has an exclusive deadline bounded by the liveness lease and admission authority. Heartbeats cannot extend the original authority. Reads check current binding, schema, epoch, device and deadline. Stale generations cannot read, change or delete replacements. Departure deletes the generation including its ciphertext and indexes. CAS conflicts require renewed verification; uncertain commits must be reconciled, never blindly retried.

## Verification boundaries

Production admission is unavailable. Admission and Current have no public constructors. DeviceVerifier and RecordVerifier have typed, uninhabited success capabilities pending their concrete owner APIs; Unavailable always refuses. No raw key, parsed credential, cached presentation, caller boolean or bearer handle supplies authority. Current Guard integration and the Profile publication verifier must be wired alongside those owners before constructing admission. Credential-gated challenges and per-request device possession are still required, not implemented by this storage core.

## Tests and remaining acceptance

Native tests exercise the actual state transitions and Memory storage at the internal verified-input precondition: replacement, stale disconnects, CAS contention, delayed writes, expiry, clock regression, capacity, malformed state and immediate epoch/schema invalidation. They do not test or establish a trust/device/record round trip. Coverage excludes test sources only; no production exclusion is configured.

Open acceptance: real current trust/credential/publication/record/device integration; bounded one-use challenges; request possession and replay protection; current reciprocal Lookup reads; lost-write reconciliation and full concurrent worker scheduling. A shared presence vector now targets real Memory and disposable Valkey: concurrent revision replacement, stale disconnects, exclusive expiry, capacity and cleanup. A dropped reply after an actual Valkey script verifies unavailable fencing and explicit reopen/current-revision reconciliation; the exact protected-main suite now validates this extension. No admission, service or security acceptance is claimed from core coverage.

Opaque generation names use maintained data-encoding hexadecimal encoding;
Switchboard does not implement cryptographic or encoding primitives.

G1 credential/Guard checks belong to `cgrd::check_published`, referenced through
Charter and Assurance. Envoy (`cnvy`) fetches/follows feeds; it does not verify
authority. Concrete G2 public-record and G3 device capabilities must be composed
with those current owner checks before any admission succeeds. No second verifier
or optional check is introduced here.
