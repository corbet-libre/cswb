# Switchboard contract

Own authoritative bounded volatile attendance under Gather. One community pseudonym holds one current generation per device; every device keeps its own simultaneous session. New attendance of a device atomically replaces that device's former generation and leaves every other device session live. Complete publication bytes and ciphertext are replaced together; Lookup may index only committed entries. Member counts deduplicate by member identity: presence enumeration may return several device rows per member, and every member-visible count (search, watch, capacity) keeps one entry per member.

The service supplies one scoped volatile Store, clock, CSPRNG-backed Tokens and explicit resource limits. The store contract lives in cmmr and is wired through cvtl by the door. Every write has an exclusive deadline bounded by the liveness lease and admission authority. Heartbeats cannot extend the original authority. Reads check current binding, schema, epoch, device and deadline. Stale generations cannot read, change or delete replacements. Departure deletes the generation including its ciphertext and indexes. CAS conflicts require renewed verification; uncertain commits must be reconciled, never blindly retried.

## Verification boundaries

Admission and Current have no unchecked public constructors. `challenge` verifies
the whole original publication through Profile and Charter's published Guard
policy before storing an expiring, opaque challenge. `admit_enter` repeats current
verification and checks the certified device's signature over the expected HTTPS
origin, community, challenge, deadline and exact publication digest. One existing
multi-record CAS replaces the original pending revision with a private consumed
marker and commits the complete attendance row and its indexes together. Only one
racing consumer succeeds; an attendance conflict does not spend the challenge.

The marker contains one fixed byte, no member, publication, request, action or
private key. It retains the original challenge key, separate generation and
exclusive deadline, with a fresh revision and no indexes. Live-marker replay is
Stale; after its original expiry the challenge is Absent. The initial attendance
deadline cannot exceed that challenge. The original lower-owner partial `admit`
and `enter` remain available; `admit` uses the same conditional marker replacement
so it cannot delete a composed winner's marker or mint a second Admission.
Gather routes the single composed operation.

The configured storage batch must allow two writes. A first attendance requires
one free record slot while retaining the consumed marker; capacity exhaustion
refuses both changes. Replacement of existing attendance needs no additional
slot. Marker expiry reclaims its slot without extending retention. Displaced
generation cleanup follows the commit and cannot delete the new attendance or
the challenge marker. Clock regression or elapsed authority refuses completion.
An uncertain network result remains fenced and requires current-revision
reconciliation; neither absence nor a superseding write proves no commit occurred.
The existing backends provide atomic visibility, not rollback of an unexpected
post-write Lua failure. The door must supervise mutations through cancellation.

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
The atomic admission source vectors use the same real signing flow and both
actual stores, including races between partial and composed consumers, failed
attendance CAS, exclusive commit expiry, capacity and lost replies/cancellation.
They have not been executed as part of this source change and do not qualify G2.
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

## Opaque accounting composition port

`challenge_bound` first performs the original current person/profile/device
verification. Its builder receives that exact Binding, the exclusive pending
challenge deadline, and 32 independently generated bytes from two original
Tokens draws. The returned bounded payload is stored in Pending and included in
the original device-signed `challenge_message`. Admission compares the payload
exactly; a new device signature cannot change the service-selected context.
The original empty challenge omits the new field and retains its original wire
transcript. A payload is data, not a verified accounting result.

`prepare_entry` retains the genuine verified G1/device scope and original pending
revision in a sealed, nonserializable PreparedEntry. It checks completion time
after the owner/store await and exposes only scope, payload and deadline. Gather
must obtain its actual accounting decision before consuming this value through
`commit_entry`. Switchboard has no accounting dependency or optional verifier.
The commit uses the existing atomic pair and checks its retained clock floor
before and after awaits. The initial attendance deadline is the minimum of the
original lease, pending challenge deadline and supplied fresh commit deadline.
Each backend prevalidates every new row deadline before writing either row. The
consumed marker keeps its original pending deadline, so earlier attendance expiry
cannot make that challenge reusable.

Attachment validates opaque nonempty bytes against the existing
MAX_PUBLICATION_BYTES syntax ceiling and carries an exclusive retained-record
deadline. The real backend still enforces its ceiling on the whole serialized
attendance record, including the original publication and attachment; that
ceiling is never replaced by the per-field syntax bound. Entry authority is G1
intersected with the attachment interval. Admission, Current and VerifiedPresence
expose the retained bytes for the higher owner to reverify. Authorization and
presence verification retain that bound. Heartbeats retain the attachment;
ordinary publication replacement preserves it, while a higher owner can attach
newly verified data to the replacement Admission before the same CAS.
Current::bounded_until only shortens an already verified capability, allowing a
fresh higher-owner bound to constrain the subsequent heartbeat/storage write.
Later genuine heartbeats may outlast the shorter initial commit interval, while
remaining below the original retained authority interval.

The new genuine signed Memory/Valkey vectors qualify only these lower-owner data,
time and atomic-storage semantics when executed. Their opaque test bytes provide
no G2 proof. Complete Forum admission still requires the concrete accounting
owner, current signed material and consuming higher-owner composition.
