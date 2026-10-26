# cswb agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cswb` — exit 101 at HEAD: lib
  `10 passed` plus `2 failed`, both requiring `VALKEY_URL` (panic at
  `tests/internal/backends.rs:85`); CI provides a disposable Valkey
  (`.ci/bin/valkey-helpers.sh`, `start_valkey`). Integration binaries also
  contain Valkey tests (`tests/admission.rs:309`, `atomic.rs`, `attachments.rs`).
- `~/agents/scratch/cbuild <lane> fmt -p cswb -- --check` — must be clean
- `clippy -p cswb --all-targets -- -D warnings` is red at HEAD from upstream
  `ckmg` lints (unused `SigningPhase` import, dead `label`/`insert`), not this
  crate. Full gate (coverage) runs in CI only: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test; lib tests live in `src/lib.rs` via
`tests/internal/`):
- One current device generation; replacement is one atomic CAS, never a
  second admission -> `transitions::replacement_heartbeat_and_departure_are_whole_and_fenced`
- Heartbeat/renewal never extends expiry or authority deadline
  -> `transitions::expiry_and_authority_deadlines_never_extend_on_heartbeat`
- Nonce single-use; stale generations cannot read/change/delete replacements
  -> `transitions::nonce_cannot_replay_after_heartbeat_extends_its_original_lease`,
  `transitions::rejected_updates_keep_prior_entry_and_wrong_device_cannot_read`
- Departure deletes the generation including ciphertext and indexes;
  concurrent updates have exactly one winner
  -> `transitions::concurrent_updates_have_one_winner_and_departure_stops_old_writes`
- Capacity, clock regression and corrupt storage refuse; bounds fail before write
  -> `transitions::storage_capacity_clock_regression_and_close_are_refusals`,
  `transitions::bounds_and_scope_fail_before_a_write`
- Challenge binds origin/publication/expiry/single consumer; forged
  publications and revoked challenges never publish
  -> `tests/admission.rs` memory tests (binary also holds Valkey tests: CI-only)
- `forbid(unsafe_code)` (`src/lib.rs:4`); hostile wire refused
  (`deny_unknown_fields`, `src/entry.rs:6`, `src/lib.rs:44`)

Pointers: `src/lib.rs`, `tests/admission.rs`, `tests/internal/`,
`docs/CONTRACT.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking exception; no registry publication.
