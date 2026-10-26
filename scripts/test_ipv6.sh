#!/usr/bin/env bash
# IPv6 forwarding test: two isolated hosts talk through vnetd across two L2
# ports. Exercises NDP, hop-limit decrement, ICMPv6 echo and TCP checksum repair.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ "${VNET_IPV6_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VNET_IPV6_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VNET_IPV6_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
    exit 1
}

WORK="$(mktemp -d)"
export VNET_RUN_DIR="$WORK/run"
BIN="$ROOT/zig-out/bin"
CFG="$WORK/vnet-ipv6.json"
LOG="$WORK/vnetd.log"
HTTP_LOG="$WORK/http.log"

vpid=""
hpid=""
pidA=""
pidB=""

cleanup() {
    [ -n "$hpid" ] && kill "$hpid" 2>/dev/null || true
    [ -n "$vpid" ] && kill -TERM "$vpid" 2>/dev/null || true
    [ -n "$pidA" ] && kill "$pidA" 2>/dev/null || true
    [ -n "$pidB" ] && kill "$pidB" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

log() { printf '==> %s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

for tool in ip unshare nsenter python3; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

log "build"
(cd "$ROOT" && "$ZIG" build) || die "build failed"

cat > "$CFG" <<'EOF'
{
  "version": 1,
  "instance": "ipv6-test",
  "ports": {
    "lan": { "kind": "l2", "device": "ra" },
    "wan": { "kind": "l2", "device": "rb" }
  },
  "interfaces": {
    "lan0": { "port": "lan", "addresses": ["2001:db8:1::1/64"] },
    "wan0": { "port": "wan", "addresses": ["2001:db8:2::1/64"] }
  },
  "firewall": {
    "default_in": "accept",
    "default_forward": "accept",
    "rules": [
      { "action": "accept", "family": "ipv6", "proto": "icmpv6" }
    ]
  }
}
EOF

"$BIN/vnet" validate "$CFG" >/dev/null || die "config validation failed"
probe="$("$BIN/vnet" firewall test --proto icmpv6 \
    --src 2001:db8:1::2 --dst 2001:db8:2::2 -c "$CFG")" || die "firewall probe failed"
printf '%s\n' "$probe" | grep -q "rule 1: accept" || die "unexpected firewall probe: $probe"
ok "IPv6 config validates and firewall probe matches icmpv6"

log "topology"
ip link set lo up
sysctl -q -w net.ipv6.conf.all.forwarding=0 || true
ip link add ra type veth peer name a0 || die "create veth pair ra/a0"
ip link add rb type veth peer name b0 || die "create veth pair rb/b0"
ip link set ra up
ip link set rb up

start_host() {
    local peer="$1" addr="$2" gw="$3" marker="$4"
    unshare -n bash -c '
        peer=$1; addr=$2; gw=$3; marker=$4
        while ! ip link show "$peer" >/dev/null 2>&1; do sleep 0.02; done
        ip link set "$peer" name eth0
        ip link set eth0 up
        ip link set lo up
        ip -6 addr add "$addr/64" dev eth0 nodad
        ip -6 route add default via "$gw" dev eth0
        touch "$marker"
        sleep 120
    ' _ "$peer" "$addr" "$gw" "$marker" </dev/null >"$WORK/$peer.log" 2>&1 &
    echo $!
}

pidA="$(start_host a0 2001:db8:1::2 2001:db8:1::1 "$WORK/a.ready")"
pidB="$(start_host b0 2001:db8:2::2 2001:db8:2::1 "$WORK/b.ready")"

ip link set a0 netns "$pidA" || die "move a0 into host A"
ip link set b0 netns "$pidB" || die "move b0 into host B"

for i in $(seq 1 250); do
    [ -f "$WORK/a.ready" ] && [ -f "$WORK/b.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/a.ready" ] || die "host A did not configure"
[ -f "$WORK/b.ready" ] || die "host B did not configure"
ok "hosts 2001:db8:1::2/64 and 2001:db8:2::2/64 via vnetd"

log "vnetd"
"$BIN/vnetd" -c "$CFG" >"$LOG" 2>&1 &
vpid=$!

for i in $(seq 1 100); do
    grep -q "started instance" "$LOG" && break
    if ! kill -0 "$vpid" 2>/dev/null; then
        cat "$LOG"
        die "vnetd exited"
    fi
    sleep 0.02
done
grep -q "started instance" "$LOG" || {
    cat "$LOG"
    die "vnetd did not start"
}

log "icmpv6"
nsenter -t "$pidA" -n ping -6 -c 1 -W 1 2001:db8:2::2 >/dev/null 2>&1 || true
ping_out="$(nsenter -t "$pidA" -n ping -6 -c 3 -W 1 2001:db8:2::2 2>&1)" || {
    echo "$ping_out"
    cat "$LOG"
    die "ping6 failed"
}
echo "$ping_out" | grep -q "3 received" || {
    echo "$ping_out"
    die "ping6 loss"
}
echo "$ping_out" | grep -Eq "ttl=63|hlim=63|hop limit[^0-9]*63" || {
    echo "$ping_out"
    die "expected hop limit 63 after forwarding"
}
ok "ping6 2001:db8:1::2 -> 2001:db8:2::2 (hop limit 63)"

local_ping="$(nsenter -t "$pidA" -n ping -6 -c 2 -W 1 2001:db8:1::1 2>&1)" || {
    echo "$local_ping"
    cat "$LOG"
    die "local ping6 to the router failed"
}
echo "$local_ping" | grep -q "2 received" || {
    echo "$local_ping"
    die "local ping6 loss"
}
ok "ping6 2001:db8:1::2 -> 2001:db8:1::1 (local ICMPv6 echo)"

log "tcp"
nsenter -t "$pidB" -n python3 -m http.server 8080 --bind 2001:db8:2::2 >"$HTTP_LOG" 2>&1 &
hpid=$!

for i in $(seq 1 100); do
    nsenter -t "$pidB" -n ss -ltn 2>/dev/null | grep -q ':8080' && break
    if ! kill -0 "$hpid" 2>/dev/null; then
        cat "$HTTP_LOG"
        die "http server exited"
    fi
    sleep 0.02
done

tcp_ok=0
for i in $(seq 1 10); do
    if timeout 5 nsenter -t "$pidA" -n python3 -c '
import socket, sys
try:
    s = socket.create_connection(("2001:db8:2::2", 8080), 3)
    s.sendall(b"GET / HTTP/1.0\r\nHost: test\r\n\r\n")
    line = s.recv(64)
    sys.exit(0 if line.startswith(b"HTTP/1.0 200") else 1)
except Exception:
    sys.exit(1)
' 2>/dev/null; then
        tcp_ok=1
        break
    fi
    sleep 0.1
done
[ "$tcp_ok" = "1" ] || {
    cat "$HTTP_LOG"
    tail -20 "$LOG"
    die "IPv6 tcp request failed"
}
ok "tcp6 2001:db8:1::2 -> [2001:db8:2::2]:8080 (http 200)"

kill -0 "$vpid" 2>/dev/null || die "vnetd exited during test"
kill -TERM "$vpid"
for i in $(seq 1 100); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.02
done
kill -KILL "$vpid" 2>/dev/null || true
wait "$vpid" 2>/dev/null || true
vpid=""

grep -Eq "ipv6 forwarded=[1-9][0-9]*" "$LOG" || {
    cat "$LOG"
    die "missing IPv6 forwarding counters"
}
grep -Eq "ndp=[1-9][0-9]*/[1-9][0-9]*/" "$LOG" || {
    cat "$LOG"
    die "missing NDP request/advertisement counters"
}
grep -Eq "icmpv6=[0-9]+/[1-9][0-9]*" "$LOG" || {
    cat "$LOG"
    die "missing ICMPv6 echo counters"
}

echo "--- vnetd ---"
cat "$LOG"
ok "test_ipv6"
