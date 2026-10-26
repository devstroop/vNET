#!/usr/bin/env bash
# Journal/rollback test: iface/route mutations are recorded before they are
# applied and `vnet down` restores the pre-command state. Runs in a private
# netns with a veth pair; no host changes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VNET_JOURNAL_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VNET_JOURNAL_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VNET_JOURNAL_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
for tool in ip unshare "$ZIG"; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "FAIL: $tool is required" >&2
        exit 1
    }
done
WORK="$(mktemp -d)"
CFG="$WORK/journal.json"
BIN="$ROOT/zig-out/bin"
export VNET_RUN_DIR="$WORK/run"

dev="jn$$"
peer="jp$$"

cleanup() {
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

cat > "$CFG" <<'EOF'
{
  "version": 1,
  "instance": "journal-test"
}
EOF

log "topology"
ip link set lo up
ip link add "$dev" type veth peer name "$peer" || die "create veth pair"
ip link set "$dev" up
ip link set "$peer" up

expect_addr() {
    ip -4 -brief addr show "$dev" | grep -q "$1" || die "expected address $1 on $dev"
}
expect_no_addr() {
    if ip -4 -brief addr show "$dev" | grep -q "$1"; then
        die "address $1 still present on $dev"
    fi
}
expect_route() {
    ip route show "$1" | grep -q "$2" || die "expected route $1 via $2"
}
expect_no_route() {
    if ip route show "$1" | grep -q "$2"; then
        die "route $1 via $2 still present"
    fi
}
expect_addr6() {
    ip -6 -brief addr show "$dev" | grep -q "$1" || die "expected address $1 on $dev"
}
expect_no_addr6() {
    if ip -6 -brief addr show "$dev" | grep -q "$1"; then
        die "address $1 still present on $dev"
    fi
}
expect_route6() {
    ip -6 route show "$1" | grep -q "$2" || die "expected IPv6 route $1 via $2"
}
expect_no_route6() {
    if ip -6 route show "$1" | grep -q "$2"; then
        die "IPv6 route $1 via $2 still present"
    fi
}
expect_link() {
    local state
    state="$(ip -brief link show "$dev" | awk '{print $2}')"
    [ "$state" = "$1" ] || die "expected link $1, got $state"
}

log "address set, duplicate, link toggles"
"$BIN/vnet" iface set "$dev" 10.99.0.1/24 -c "$CFG"
expect_addr 10.99.0.1/24
"$BIN/vnet" iface set "$dev" 10.99.0.1/24 -c "$CFG"
[ "$(grep -c 'addr_add' "$VNET_RUN_DIR/journal-test.journal")" = "1" ] ||
    die "duplicate set was journaled"

"$BIN/vnet" iface down "$dev" -c "$CFG"
expect_link DOWN
"$BIN/vnet" iface up "$dev" -c "$CFG"
expect_link UP

log "route add and del"
"$BIN/vnet" route add 10.98.0.0/24 via 10.99.0.2 dev "$dev" metric 50 -c "$CFG"
expect_route 10.98.0.0/24 "10.99.0.2"
"$BIN/vnet" route del 10.98.0.0/24 via 10.99.0.2 dev "$dev" metric 50 -c "$CFG"
expect_no_route 10.98.0.0/24 "10.99.0.2"

log "IPv6 address and route"
"$BIN/vnet" iface set "$dev" 2001:db8:99::1/64 -c "$CFG"
expect_addr6 2001:db8:99::1/64
"$BIN/vnet" route add 2001:db8:98::/48 via 2001:db8:99::2 dev "$dev" metric 50 -c "$CFG"
expect_route6 2001:db8:98::/48 "2001:db8:99::2"

log "journal contents"
"$BIN/vnet" journal -c "$CFG" | grep -q '"route_del"' || die "journal missing route_del"
"$BIN/vnet" journal -c "$CFG" | grep -q '2001:db8:98::/48' || die "journal missing IPv6 route"

log "rollback"
"$BIN/vnet" down -c "$CFG"
expect_no_addr 10.99.0.1/24
expect_no_route 10.98.0.0/24 "10.99.0.2"
expect_no_addr6 2001:db8:99::1/64
expect_no_route6 2001:db8:98::/48 "2001:db8:99::2"
expect_link UP
[ ! -f "$VNET_RUN_DIR/journal-test.journal" ] || die "journal not cleared"
"$BIN/vnet" down -c "$CFG" | grep -q "no journaled state" || die "second down not a no-op"

log "address del is ownership-gated"
"$BIN/vnet" iface set "$dev" 10.96.0.1/24 -c "$CFG"
"$BIN/vnet" iface del "$dev" 10.96.0.1/24 -c "$CFG"
expect_no_addr 10.96.0.1/24
if "$BIN/vnet" iface del "$dev" 10.95.0.1/24 -c "$CFG" 2>/dev/null; then
    die "del of an unmanaged address succeeded"
fi
"$BIN/vnet" down -c "$CFG"
expect_no_addr 10.96.0.1/24

log "failed add does not take ownership"
ip addr add 10.92.0.1/24 dev "$dev"
if "$BIN/vnet" iface set "$dev" 10.92.0.1/24 -c "$CFG" 2>/dev/null; then
    die "set of an existing address succeeded"
fi
[ ! -f "$VNET_RUN_DIR/journal-test.journal" ] ||
    die "failed add left a journal entry"
"$BIN/vnet" down -c "$CFG" >/dev/null
expect_addr 10.92.0.1/24
ip addr del 10.92.0.1/24 dev "$dev"

log "pre-existing state is preserved"
ip addr add 10.94.0.1/24 dev "$dev"
"$BIN/vnet" iface set "$dev" 10.93.0.1/24 -c "$CFG"
"$BIN/vnet" down -c "$CFG"
expect_addr 10.94.0.1/24
expect_no_addr 10.93.0.1/24
ip addr del 10.94.0.1/24 dev "$dev"

log "cleanup"
ip link del "$dev"
ok "test_journal"
