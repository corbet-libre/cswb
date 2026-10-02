# cswb — Switchboard

Implementation in progress. Admission is unavailable until current trust, public-record and device-authority capabilities are integrated.

## Scope

### Purpose

cswb is the server side of presence: it keeps the forum's live attendance — who is here, with which entry, until they leave.

### Owns

| Area | Responsibility |
|---|---|
| Live entry | The authoritative live entry keyed by the community pseudonym: authenticated connect, publication of the whole entry (public bundle, own rules including blocks, reachability, encrypted private profile), revision replacement, heartbeat, departure, and expiry. |
| Presence | Presence is the connection: an entry stays live only while its deadline holds, and a heartbeat renews an expiring entry. One active attendance per member; a newer device session replaces the older one. |
| Checks | The cgrd guard check on every entry and change, covering person and profile together; entries whose ciphertext exceeds the bound are refused. Entries affected by a schema change that hides or removes a public field are withdrawn at once. The presented accounting record (relative shares only, after a quorum) is checked locally before listing. |
| Downstream | Committed-entry events feed clkp Lookup, which derives its indexes from them. |

### Never

| Area | Boundary |
|---|---|
| Authority | No runtime queries to the admission authority about a member; no full private presentations or private salts; a credential alone is never proof of possession; no hidden presence. |
| Retention | Nothing is retained after departure or expiry: no entry, history, login times, network identifiers, or activity records. Signed bytes are never mutated to hide a field. |
| Identity | Entries are keyed by the stable member identifier, not per-session pseudonyms. No contact presence, favourites, online notifications, or device marking; contact liveness stays peer to peer. |
| Storage | No profile copies beyond the live entry and no separate durable record store. |
| Switch | No presence on/off switch. |

### States

Absent, Challenged, Validating, Present (with generation, revision, and deadline), then Departed/Absent. The deadline is bounded by the liveness lease, the credential, and current trust validity. Every served operation rechecks epoch, revocation, and deadline; a heartbeat cannot extend authority, and a bad update leaves the prior valid entry in place. Disconnect, expiry, revocation, or schema incompatibility ends the attendance.

### Test obligations

| Area | Expectation |
|---|---|
| Admission | A real credential, device challenge, and guard round trip admits; a stolen or replayed bundle cannot create a session. Person and profile are always checked together; a valid profile never admits an invalid credential. |
| Record proof | A missing, stale, below-quorum, or wrong-context accounting record proof prevents listing. |
| Concurrency | A stale generation cannot update or delete its replacement; when devices race, the newer session wins. A block takes effect while the blocker is online and is gone on disconnect. A restricted public field changed without a fresh pin is refused. |
| Expiry | Expiry or departure removes the entry, its ciphertext, and derived visibility; revoked or expired credentials and schema changes stop reads promptly. A dead connection expires without its cooperation, and a restart resurrects nothing. |
| Load | Presence renewals at ten thousand simultaneous connections keep service and storage CPU below 50% with renewals p99 below 200 ms.

## Dependencies and validation

Reuse the existing volatile storage port and Guard rather than duplicate their mechanisms. CI resolves one lock snapshot and gates stable checks plus exact line and branch coverage. Passing a storage transition test does not establish admission integration.
