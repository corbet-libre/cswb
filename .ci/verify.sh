#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
: "${CI_COMMIT_SHA:?verify requires the exact source revision}"
: "${ARTIFACT_ROOT:?verify requires an absolute ARTIFACT_ROOT}"
[[ "$ARTIFACT_ROOT" = /* ]] || { echo "ARTIFACT_ROOT must be absolute" >&2; exit 2; }
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"
python3 .github/check-first-party.py
rustc --version
cargo fmt --all
git diff -- '*.rs' > "$ARTIFACT_ROOT/format.patch"
test ! -s "$ARTIFACT_ROOT/format.patch"
# shellcheck disable=SC1091
. "$PWD/.ci/bin/valkey-helpers.sh"

# Disposable Valkey fixture (reviewed cmbl/cvlk lifecycle byte pattern): one
# owned server, unique loopback port (never shared 6379), exact PID/start-tick/
# argv identity, detached stdio, BOTH job lock fds 8/9 closed in the server
# child, readiness on the owned PID only, cleanup kills the owned process only
# (never a sibling job's fixture). Hosted used a docker service on fixed 6379;
# the nix server keeps the hosted flags (--save '' --appendonly no
# --maxmemory 64mb --maxmemory-policy noeviction) with VALKEY_URL pointing at
# the owned fixture, which the tests require.
# FIXTURE-BEGIN
start_valkey() {
  VALKEY_TMP="$(mktemp -d)"
  export VALKEY_TMP
  VALKEY_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
  export VALKEY_PORT
  printf 'port %s\nbind 127.0.0.1\nprotected-mode yes\ndir %s\ndbfilename dump.rdb\n' "$VALKEY_PORT" "$VALKEY_TMP" > "$VALKEY_TMP/valkey.conf"
  export VALKEY_CONF="$VALKEY_TMP/valkey.conf"
  export VALKEY_PIDFILE="$VALKEY_TMP/valkey.pid"
  export VALKEY_STARTTICKFILE="$VALKEY_TMP/valkey.starttick"
  valkey-server "$VALKEY_CONF" --daemonize no --logfile "$VALKEY_TMP/valkey.log" \
    0</dev/null >>"$VALKEY_TMP/valkey.log" 2>&1 8>&- 9>&- &
  echo "$!" > "$VALKEY_PIDFILE"
  record_server_identity "$!" "$VALKEY_STARTTICKFILE"
  # Readiness: the port is ephemeral, so a ping alone proves nothing — recheck
  # the recorded PID/start-tick identity on EVERY step. Otherwise a recycled
  # port could let us trust a sibling job's fixture.
  assert_owned_ready() {
    _aor_pid="$(cat "$VALKEY_PIDFILE")"
    _aor_tick="$(cat "$VALKEY_STARTTICKFILE")"
    is_owned_server "$_aor_pid" "$_aor_tick" || return 1
    proc_alive "$_aor_pid" || return 1
  }
  for _ in $(seq 1 50); do
    assert_owned_ready || { echo "cswb fixture: owned server lost during readiness" >&2; return 1; }
    if valkey-cli -p "$VALKEY_PORT" ping >/dev/null 2>&1; then break; fi
    sleep 0.2
  done
  assert_owned_ready || { echo "cswb fixture: refusing ping from unowned server" >&2; return 1; }
  valkey-cli -p "$VALKEY_PORT" ping
  valkey-cli -p "$VALKEY_PORT" CONFIG SET save ""
  valkey-cli -p "$VALKEY_PORT" CONFIG SET appendonly no
  valkey-cli -p "$VALKEY_PORT" CONFIG SET maxmemory 64mb
  valkey-cli -p "$VALKEY_PORT" CONFIG SET maxmemory-policy noeviction
  export VALKEY_URL="redis://127.0.0.1:${VALKEY_PORT}"
}
stop_valkey() {
  if [ -n "${VALKEY_PIDFILE:-}" ] && [ -f "$VALKEY_PIDFILE" ] \
    && [ -n "${VALKEY_STARTTICKFILE:-}" ] && [ -f "$VALKEY_STARTTICKFILE" ]; then
    pid="$(cat "$VALKEY_PIDFILE")"
    expected_tick="$(cat "$VALKEY_STARTTICKFILE")"
    # Only signal the owned server (PID + start tick); then confirm exit
    # BEFORE deleting the data dir, so no live server ever loses its files.
    if is_owned_server "$pid" "$expected_tick"; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 100); do
        proc_alive "$pid" || break
        sleep 0.1
      done
      if proc_alive "$pid"; then
        kill -9 "$pid" 2>/dev/null || true
        sleep 0.5
      fi
      if proc_alive "$pid"; then
        echo "cswb fixture: owned server PID $pid did not exit; keeping $VALKEY_TMP" >&2
        return 1
      fi
    fi
  fi
  if [ -n "${VALKEY_TMP:-}" ] && [ -d "$VALKEY_TMP" ]; then
    rm -rf "$VALKEY_TMP"
  fi
  unset VALKEY_PIDFILE VALKEY_STARTTICKFILE VALKEY_CONF VALKEY_PORT VALKEY_TMP VALKEY_URL || true
}
cleanup_valkey() { stop_valkey; }
# FIXTURE-END
trap cleanup_valkey EXIT
start_valkey
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
stop_valkey
trap - EXIT
rustup run nightly rustc --version
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
"$NIGHTLY_CARGO" llvm-cov --version
"$NIGHTLY_CARGO" llvm-cov --locked --workspace --all-features --branch --no-cfg-coverage --no-cfg-coverage-nightly --ignore-filename-regex "/tests/" --json --output-path coverage.json
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --lcov --output-path coverage.lcov
"$NIGHTLY_CARGO" llvm-cov report --locked --branch --ignore-filename-regex '/tests/' --text > coverage.txt
python3 .github/check-coverage.py coverage.lcov coverage.json coverage.txt
