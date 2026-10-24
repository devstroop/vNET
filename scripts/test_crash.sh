#!/usr/bin/env bash
# Crash recovery test: kill -9 a daemon that owns host state, verify a dry-run
# doctor does not mutate anything, then repair the journal and restore the
# pre-start host state. Also covers malformed journal tails and the live-daemon
# safety guard. Runs in a private netns with veth pairs; no host changes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VROUTER_CRASH_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VROUTER_CRASH_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VROUTER_CRASH_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
for tool in ip unshare "$ZIG"; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FAIL: $tool is required" >&2
        exit 1
    }
done

WORK="$(mktemp -d)"
CFG="$WORK/crash.json"
BIN="$ROOT/zig-out/bin"
export VROUTER_RUN_DIR="$WORK/run"
LOG="$VROUTER_RUN_DIR/vrouterd.log"

dev="cr$$"
peer="cp$$"
vpid=""

cleanup() {
    [ -n "$vpid" ] && kill -9 "$vpid" 2>/dev/null || true
    if [ -x "$BIN/vrouter" ] && [ -f "$CFG" ]; then
        "$BIN/vrouter" down -c "$CFG" >/dev/null 2>&1 || true
    fi
    ip link del "$dev" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

log() { printf '==> %s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

log "build"
(cd "$ROOT" && "$ZIG" build) || die "build failed"

cat >"$CFG" <<'JSON'
{
  "version": 1,
  "instance": "crash-test",
  "ports": {
    "lan-a": { "kind": "l2", "device": "__DEV__", "pvid": 10 }
  },
  "bridges": {
    "br": { "ports": ["lan-a"], "vlan_aware": true, "offload": "kernel" }
  },
  "interfaces": {
    "lan0": { "bridge": "br", "address": "10.40.50.1/24", "vlan": 10 }
  },
  "firewall": { "default_in": "accept", "default_forward": "accept" }
}
JSON
sed -i "s/__DEV__/$dev/" "$CFG"

log "topology"
ip link set lo up
ip link add "$dev" type veth peer name "$peer" || die "create veth pair"
ip link set "$dev" up
ip link set "$peer" up
ip addr add 10.99.99.1/32 dev "$dev"
ip addr add 10.99.99.2/32 dev "$peer"

JOURNAL="$VROUTER_RUN_DIR/crash-test.journal"

log "start daemon and journal host state"
"$BIN/vrouter" up -c "$CFG" | tee "$WORK/up.log"
grep -q "started instance=crash-test" "$LOG" || {
    cat "$LOG" >&2
    die "vrouterd did not start"
}
vpid="$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' "$WORK/up.log" | head -n 1)"
[ -n "$vpid" ] || die "vrouter up did not report a pid"
"$BIN/vrouter" doctor -c "$CFG" >"$WORK/doctor-ready.log"
grep -q "ok: daemon pid=" "$WORK/doctor-ready.log" || die "daemon did not become ready"
[ -f "$JOURNAL" ] || die "offload journal was not written"
grep -q '"link_add"' "$JOURNAL" || die "journal missing link_add"

bridge_dev="$(sed -n 's/.*"op":"link_add","dev":"\([^"]*\)","kind":"bridge".*/\1/p' "$JOURNAL" | head -n 1)"
vrouter_dev="$(sed -n 's/.*"op":"link_add","dev":"\([^"]*\)","kind":"veth".*/\1/p' "$JOURNAL" | head -n 1)"
[ -n "$bridge_dev" ] || die "could not determine kernel bridge name"
[ -n "$vrouter_dev" ] || die "could not determine vrouter veth name"
ip link show "$bridge_dev" >/dev/null || die "kernel bridge $bridge_dev missing"
ip link show "$vrouter_dev" >/dev/null || die "vrouter veth $vrouter_dev missing"

log "dry run leaves state untouched"
"$BIN/vrouter" doctor -c "$CFG" | tee "$WORK/doctor-dry.log"
grep -q "journal pending=" "$WORK/doctor-dry.log" || die "doctor did not report pending journal"
ip link show "$bridge_dev" >/dev/null || die "dry run removed the kernel bridge"
[ -f "$JOURNAL" ] || die "dry run removed the journal"

log "repair refuses a live daemon"
if "$BIN/vrouter" doctor --repair -c "$CFG" >"$WORK/doctor-live.log" 2>&1; then
    die "repair ran while the daemon was live"
fi
grep -q "daemon is running or starting" "$WORK/doctor-live.log" ||
    die "wrong live-daemon error"
ip link show "$bridge_dev" >/dev/null || die "refused repair mutated host state"
[ -f "$JOURNAL" ] || die "refused repair removed the journal"

log "kill -9 and dry-run diagnostics"
kill -9 "$vpid"
wait "$vpid" 2>/dev/null || true
vpid=""
[ -S "$VROUTER_RUN_DIR/control.sock" ] || die "stale control socket was not left behind"
"$BIN/vrouter" doctor -c "$CFG" | tee "$WORK/doctor-crash.log"
grep -q "daemon not running (stale socket)" "$WORK/doctor-crash.log" ||
    die "doctor did not recognize the stale socket"
grep -q "journal pending=" "$WORK/doctor-crash.log" || die "doctor did not report pending journal"
ip link show "$bridge_dev" >/dev/null || die "dry run after crash mutated state"

log "repair restores pre-start state"
"$BIN/vrouter" doctor --repair -c "$CFG" | tee "$WORK/repair.log"
grep -q "ok: restored " "$WORK/repair.log" || die "repair did not restore records"
[ ! -f "$JOURNAL" ] || die "journal not cleared after repair"
if ip link show "$bridge_dev" >/dev/null 2>&1; then
    die "kernel bridge still present after repair"
fi
if ip link show "$vrouter_dev" >/dev/null 2>&1; then
    die "vrouter veth still present after repair"
fi
ip link show "$dev" >/dev/null || die "pre-existing port was removed"
if ip link show "$dev" | grep -q "master "; then
    die "pre-existing port is still enslaved after repair"
fi
ip -4 -brief addr show "$dev" | grep -q "10.99.99.1/32" ||
    die "unmanaged address on $dev was removed"
ip -4 -brief addr show "$peer" | grep -q "10.99.99.2/32" ||
    die "unmanaged address on $peer was removed"
"$BIN/vrouter" doctor --repair -c "$CFG" >"$WORK/repair-noop.log"
grep -q "ok: no journaled state" "$WORK/repair-noop.log" ||
    die "second repair was not a no-op"

log "malformed tail is quarantined"
"$BIN/vrouter" iface set "$peer" 10.88.0.1/24 -c "$CFG"
printf 'not json\n' >>"$JOURNAL"
"$BIN/vrouter" doctor -c "$CFG" | tee "$WORK/doctor-malformed.log"
grep -q "malformed journal tail" "$WORK/doctor-malformed.log" ||
    die "doctor did not warn about the malformed tail"
"$BIN/vrouter" doctor --repair -c "$CFG" | tee "$WORK/repair-malformed.log"
grep -q "quarantined 1 malformed record" "$WORK/repair-malformed.log" ||
    die "repair did not quarantine the malformed record"
[ ! -f "$JOURNAL" ] || die "journal not cleared after quarantine repair"
if ip -4 -brief addr show "$peer" | grep -q "10.88.0.1/24"; then
    die "address from valid journal record was not restored"
fi
quarantine_file="$(ls "$VROUTER_RUN_DIR"/crash-test.journal.quarantine.* | head -n 1)"
[ -n "$quarantine_file" ] || die "quarantine file missing"
grep -q "not json" "$quarantine_file" || die "quarantine file lost the malformed record"

log "malformed middle refuses repair without mutation"
"$BIN/vrouter" iface set "$peer" 10.87.0.1/24 -c "$CFG"
valid_line="$(head -n 1 "$JOURNAL")"
printf 'not json\n%s\n' "$valid_line" >>"$JOURNAL"
if "$BIN/vrouter" doctor --repair -c "$CFG" >"$WORK/repair-invalid.log" 2>&1; then
    die "repair accepted malformed records before valid ones"
fi
grep -q "refusing to repair" "$WORK/repair-invalid.log" ||
    die "wrong malformed-middle error"
ip -4 -brief addr show "$peer" | grep -q "10.87.0.1/24" ||
    die "refused repair mutated host state"
grep -q "not json" "$JOURNAL" || die "refused repair altered the journal"

ip addr del 10.87.0.1/24 dev "$peer" 2>/dev/null || true
rm -f "$JOURNAL"

ok "test_crash"
