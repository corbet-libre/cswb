# Switchboard contract

Own authoritative bounded volatile attendance under Gather. One community pseudonym has one current device generation. New attendance atomically replaces the former generation. Complete publication bytes and ciphertext are replaced together; Lookup may index only committed entries.

The service supplies one scoped volatile Store, clock, CSPRNG-backed Tokens and explicit resource limits. The store contract lives in cmmr and is wired through cvtl by the door. Every write has an exclusive deadline bounded by the liveness lease and admission authority. Heartbeats cannot extend the original authority. Reads check current binding, schema, epoch, device and deadline. Stale generations cannot read, change or delete replacements. Departure deletes the generation including its ciphertext and indexes. CAS conflicts require renewed verification; uncertain commits must be reconciled, never blindly retried.

## Verification boundaries

Admission and Current have no unchecked public constructors. `challenge` verifies
the whole original publication through Profile and Charter's published Guard
policy before storing an expiring, opaque challenge. `admit` repeats current
verification, checks the certified device's signature over the expected HTTPS
origin, community, challenge, deadline and exact publication digest, then consumes
the challenge by atomic generation deletion. Only one racing consumer succeeds.

`authorize` checks the stored original publication against current trust and
revocations, then verifies the exact origin, action, session, nonce and canonical
unsigned request body. A successful nonce insertion is required before returning
Current; replay conflicts. Invalid current publication withdraws that attendance
generation. A session bearer alone never grants a read. The generated dispatcher
must select the expected origin/action/body itself, consume current verification
for every operation and supervise mutations through request cancellation.

The service supplies the trusted admission action (the identity owner defines
its spelling), maximum snapshot age and a current VerifiedCharter from Assurance.
Leases are bounded by Profile's authenticated exclusive authority deadline and
Charter validity, converted from Unix seconds to storage milliseconds without
extending either. `replacement` verifies both originals and requires an increasing
Profile revision before issuing its sealed Admission. The05:45 binding MVP
correction requires original G2 Beacon frontier/zero-knowledge currentness and
public punishment. Those ports are not yet integrated; this older partial
admission candidate must not be released as complete Forum authority. No person
lookup, accepting record verifier or observation certificate substitutes for G2.

## Tests and remaining acceptance

Existing native storage tests exercise replacement, stale disconnects, CAS
contention, delayed writes, expiry, clock regression, capacity, malformed state
and immediate epoch/schema invalidation. New admission vectors use actual issuer
and device signatures, Charter, Profile, Guard and encrypted Profile publication
against both real storage backends. They cover challenge binding/replay, exact
request/body binding, nonce replay, replacement and current revocation withdrawal.
Fixture signing custody is test setup, not production pairing authority. Coverage
excludes test sources only; no production exclusion is configured.

Open acceptance: execute and qualify the new admission vectors; current reciprocal
Lookup reads; generated controller wiring; cancellation-supervised mutation and
lost-write reconciliation; full concurrent worker scheduling. Existing real
Memory/Valkey parity and dropped-reply vectors remain unchanged. Source code or
storage coverage alone is not service or security acceptance.

Opaque generation names use maintained data-encoding hexadecimal encoding;
Switchboard does not implement cryptographic or encoding primitives.

G1 credential/Guard checks belong to `cgrd::check_published`, referenced through
Charter and Assurance. Envoy (`cnvy`) fetches/follows feeds; it does not verify
authority. Current credentials certify device keys from Membership's live passkey
bindings; their separate current revocations plus fresh device possession remain
mandatory. No second policy verifier or optional identity check is introduced.

VerifiedPresence is an internal committed row, not a disclosure capability.
Lookup obtains it only after current requester possession, rechecks its original
publication through Profile and Charter, and calls confirm immediately before
returning a result. confirm uses the storage owner's atomic multi-record read
check; any changed revision or exclusive deadline refuses the entire response.

Nonce markers live through the original verified authority interval, because a
heartbeat can extend the shorter presence lease. Their deadlines never extend
past current credential/snapshot authority. Deployment TTL must accommodate that
bounded interval; nonce capacity exhaustion refuses new operations. A successful
replacement attendance erases the displaced generation's nonce/cursor state.
No request body, IP, action history or profile key is stored in a nonce marker.
