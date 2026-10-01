# Agent instructions

Write code, comments and documentation in English.

Switchboard implements only the Scope and docs/CONTRACT.md. Reuse existing owners and maintained dependencies; no own crypto, persistent forum member storage, request logging, or member lookup to cvld.

Run Rust checks only in CI. Stable fmt, Clippy and real tests plus exact 100% reachable line and branch coverage are required. First-party dependencies follow main with one locked revision per crate. No synthetic admission authority or skipped proof checks. Commit explicit paths in plain English; no attribution or registry publication.
