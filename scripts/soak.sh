#!/usr/bin/env bash
# Linux soak: continuous SNAT traffic with link flaps, live NAT edits and
# daemon restarts. Runs inside a fresh network namespace.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

show_usage() {
    cat <<'EOF'
usage: scripts/soak.sh [options]

  --duration TIME        total soak time, e.g. 24h, 90m, 30s (default 24h)
  --interval SECONDS     traffic/NAT check interval (default 5)
  --flap-interval SEC    link flap interval (default 30)
  --restart-interval SEC daemon restart interval (default 300)
  --no-build             reuse zig-out release binaries
  --keep                 keep logs under /tmp
  -h, --help             show this help
EOF
}

case "${1:-}" in
    -h|--help) show_usage; exit 0 ;;
esac

if [ "${VNET_SOAK_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VNET_SOAK_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VNET_SOAK_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
fi

ZIG="${ZIG:-zig}"
command -v "$ZIG" >/dev/null 2>&1 || {
    echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
    exit 1
}

WORK="$(mktemp -d)"
BIN="$ROOT/zig-out/bin"
LOADGEN="$WORK/loadgen"
OFFLOAD_HELPER="$WORK/netdev_offload"
CFG="$WORK/vnet-soak.json"
LOG="$WORK/vnetd.log"
ECHO_LOG="$WORK/echo.log"
DURATION="24h"
INTERVAL="5"
FLAP_INTERVAL="30"
RESTART_INTERVAL="300"
DO_BUILD="1"
KEEP="0"

vpid=""
echo_pid=""
pidA=""
pidB=""


parse_duration() {
    local value="$1"
    case "$value" in
        *h) echo $(( ${value%h} * 3600 )) ;;
        *m) echo $(( ${value%m} * 60 )) ;;
        *s) echo "${value%s}" ;;
        '') echo 0 ;;
        *[!0-9]*) echo 0 ;;
        *) echo "$value" ;;
    esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --duration) DURATION="${2:-}"; shift 2 ;;
        --interval) INTERVAL="${2:-}"; shift 2 ;;
        --flap-interval) FLAP_INTERVAL="${2:-}"; shift 2 ;;
        --restart-interval) RESTART_INTERVAL="${2:-}"; shift 2 ;;
        --no-build) DO_BUILD="0"; shift ;;
        --keep) KEEP="1"; shift ;;
        -h|--help) show_usage; exit 0 ;;
        *) echo "FAIL: unknown argument: $1" >&2; show_usage >&2; exit 2 ;;
    esac
done

DURATION_SECS="$(parse_duration "$DURATION")"
if [ "$DURATION_SECS" -le 0 ]; then
    echo "FAIL: invalid duration: $DURATION" >&2
    exit 2
fi
case "$INTERVAL" in ''|*[!0-9]*) echo "FAIL: invalid interval" >&2; exit 2 ;; esac
case "$FLAP_INTERVAL" in ''|*[!0-9]*) echo "FAIL: invalid flap interval" >&2; exit 2 ;; esac
case "$RESTART_INTERVAL" in ''|*[!0-9]*) echo "FAIL: invalid restart interval" >&2; exit 2 ;; esac
[ "$INTERVAL" -gt 0 ] || { echo "FAIL: interval must be positive" >&2; exit 2; }
[ "$FLAP_INTERVAL" -gt 0 ] || { echo "FAIL: flap interval must be positive" >&2; exit 2; }
[ "$RESTART_INTERVAL" -gt 0 ] || { echo "FAIL: restart interval must be positive" >&2; exit 2; }

log() { printf '==> %s\n' "$*"; }
die() {
    printf 'FAIL: %s\n' "$*" >&2
    [ -f "$LOG" ] && tail -30 "$LOG" >&2 || true
    exit 1
}

stop_pid() {
    local pid="$1"
    [ -n "$pid" ] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    stop_pid "$echo_pid"; echo_pid=""
    stop_pid "$vpid"; vpid=""
    stop_pid "$pidA"; pidA=""
    stop_pid "$pidB"; pidB=""
    ip link del ra 2>/dev/null || true
    ip link del rb 2>/dev/null || true
    if [ "$KEEP" = "1" ]; then
        printf 'kept: %s\n' "$WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT INT TERM

for tool in ip unshare nsenter ping cc; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

if [ "$DO_BUILD" = "1" ]; then
    log "build release"
    (cd "$ROOT" && "$ZIG" build --release=fast) || die "build failed"
fi
[ -x "$BIN/vnetd" ] || die "missing $BIN/vnetd (run without --no-build)"
cc -O2 -std=c11 -Wall -Wextra -Werror -o "$LOADGEN" "$ROOT/scripts/loadgen.c" ||
    die "failed to build loadgen"
cc -O2 -std=c11 -Wall -Wextra -Werror -o "$OFFLOAD_HELPER" "$ROOT/scripts/netdev_offload.c" ||
    die "failed to build netdev_offload helper"

start_host() {
    local peer="$1" addr="$2" gw="$3" marker="$4"
    unshare -n bash -c '
        peer=$1; addr=$2; gw=$3; marker=$4
        while ! ip link show "$peer" >/dev/null 2>&1; do sleep 0.02; done
        ip link set "$peer" name eth0
        ip link set eth0 up
        ip link set lo up
        ip addr add "$addr" dev eth0
        ip route add default via "$gw"
        touch "$marker"
        sleep 90000
    ' _ "$peer" "$addr" "$gw" "$marker" </dev/null >"$WORK/$peer.log" 2>&1 &
    echo $!
}

start_vnetd() {
    : >"$LOG"
    "$BIN/vnetd" -c "$CFG" >"$LOG" 2>&1 &
    vpid=$!
    for _ in $(seq 1 150); do
        grep -q "started instance" "$LOG" && return 0
        if ! kill -0 "$vpid" 2>/dev/null; then
            cat "$LOG" >&2
            die "vnetd exited during startup"
        fi
        sleep 0.02
    done
    cat "$LOG" >&2
    die "vnetd did not start"
}

check_daemon() {
    if ! kill -0 "$vpid" 2>/dev/null; then
        cat "$LOG" >&2
        die "vnetd exited"
    fi
}

check_traffic() {
    local out
    out="$(nsenter -t "$pidA" -n timeout 10 "$LOADGEN" udp-rtt 10.0.2.2 5299 20 2>&1)" ||
        die "traffic check failed: $out"
    case "$out" in
        *lost=0*) ;;
        *) die "traffic loss: $out" ;;
    esac
}

check_nat_edit() {
    local out
    "$BIN/vnet" nat add port-forward --proto tcp --ext-port 8081 \
        --to 10.0.1.2:8080 -c "$CFG" >/dev/null || die "nat add failed"
    out="$("$BIN/vnet" nat list -c "$CFG")" || die "nat list failed"
    case "$out" in
        *8081*) ;;
        *) die "added port-forward missing from nat list" ;;
    esac
    "$BIN/vnet" nat del port-forward --proto tcp --ext-port 8081 -c "$CFG" >/dev/null ||
        die "nat del failed"
    out="$("$BIN/vnet" nat list -c "$CFG")" || die "nat list failed"
    case "$out" in
        *8081*) die "deleted port-forward still present" ;;
    esac
}

flap_link() {
    ip link set ra down || die "link down failed"
    sleep 0.2
    ip link set ra up || die "link up failed"
    sleep 1
    check_traffic
}

restart_daemon() {
    kill -TERM "$vpid" 2>/dev/null || die "vnetd restart: not running"
    for _ in $(seq 1 150); do
        kill -0 "$vpid" 2>/dev/null || break
        sleep 0.02
    done
    if kill -0 "$vpid" 2>/dev/null; then
        kill -KILL "$vpid" 2>/dev/null || true
        wait "$vpid" 2>/dev/null || true
        die "vnetd did not stop"
    fi
    wait "$vpid" 2>/dev/null || true
    start_vnetd
    check_traffic
}

cat >"$CFG" <<'EOF'
{
  "version": 1,
  "instance": "soak",
  "ports": {
    "lan": { "kind": "l2", "device": "ra" },
    "wan": { "kind": "l2", "device": "rb" }
  },
  "interfaces": {
    "lan0": { "port": "lan", "address": "10.0.1.1/24" },
    "wan0": { "port": "wan", "address": "10.0.2.1/24" }
  },
  "nat": { "masquerade": [ { "out": "wan0" } ] },
  "firewall": { "default_in": "accept", "default_forward": "accept", "default_out": "accept" }
}
EOF

VNET_RUN_DIR="$WORK/run"
export VNET_RUN_DIR
rm -rf "$VNET_RUN_DIR"

log "build topology"
ip link set lo up
ip link add ra type veth peer name a0 || die "create veth pair ra/a0"
ip link add rb type veth peer name b0 || die "create veth pair rb/b0"
ip link set ra up
ip link set rb up

pidA="$(start_host a0 10.0.1.2/24 10.0.1.1 "$WORK/a.ready")"
pidB="$(start_host b0 10.0.2.2/24 10.0.2.1 "$WORK/b.ready")"
ip link set a0 netns "$pidA" || die "move a0 into host A"
ip link set b0 netns "$pidB" || die "move b0 into host B"

for _ in $(seq 1 250); do
    [ -f "$WORK/a.ready" ] && [ -f "$WORK/b.ready" ] && break
    sleep 0.02
done
[ -f "$WORK/a.ready" ] || die "host A did not configure"
[ -f "$WORK/b.ready" ] || die "host B did not configure"
nsenter -t "$pidA" -n "$OFFLOAD_HELPER" eth0 off || die "disable offloads on A"
nsenter -t "$pidB" -n "$OFFLOAD_HELPER" eth0 off || die "disable offloads on B"

log "start daemon"
start_vnetd
nsenter -t "$pidB" -n "$LOADGEN" udp-echo 10.0.2.2 5299 >"$ECHO_LOG" 2>&1 &
echo_pid=$!
for _ in $(seq 1 100); do
    grep -q '^READY' "$ECHO_LOG" && break
    kill -0 "$echo_pid" 2>/dev/null || { cat "$ECHO_LOG" >&2; die "echo server exited"; }
    sleep 0.02
done
grep -q '^READY' "$ECHO_LOG" || die "echo server did not start"
if ! nsenter -t "$pidA" -n ping -c 1 -W 2 10.0.2.2 >/dev/null 2>&1; then
    cat "$LOG" >&2
    die "initial ping failed"
fi
check_traffic

start_ts="$(date +%s)"
deadline=$((start_ts + DURATION_SECS))
last_flap=$((start_ts - FLAP_INTERVAL))
last_restart=$((start_ts - RESTART_INTERVAL))
iterations=0
flaps=0
restarts=0
nat_edits=0

log "soak duration=${DURATION_SECS}s interval=${INTERVAL}s flap=${FLAP_INTERVAL}s restart=${RESTART_INTERVAL}s"
while :; do
    now="$(date +%s)"
    [ "$now" -ge "$deadline" ] && break
    iterations=$((iterations + 1))
    check_daemon
    check_traffic
    check_nat_edit
    nat_edits=$((nat_edits + 1))
    now="$(date +%s)"

    if [ $((now - last_flap)) -ge "$FLAP_INTERVAL" ]; then
        flap_link
        flaps=$((flaps + 1))
        last_flap="$(date +%s)"
    fi
    now="$(date +%s)"
    if [ $((now - last_restart)) -ge "$RESTART_INTERVAL" ]; then
        restart_daemon
        restarts=$((restarts + 1))
        last_restart="$(date +%s)"
    fi

    if [ $((iterations % 12)) -eq 0 ]; then
        elapsed=$(( $(date +%s) - start_ts ))
        printf 'soak: elapsed=%ss iterations=%d flaps=%d restarts=%d nat_edits=%d\n' \
            "$elapsed" "$iterations" "$flaps" "$restarts" "$nat_edits"
    fi
    sleep "$INTERVAL"
done

check_daemon
check_traffic
kill -TERM "$vpid" 2>/dev/null || true
for _ in $(seq 1 150); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.02
done
if kill -0 "$vpid" 2>/dev/null; then
    kill -KILL "$vpid" 2>/dev/null || true
    die "vnetd did not stop at end of soak"
fi
wait "$vpid" 2>/dev/null || true
vpid=""
"$BIN/vnet" doctor -c "$CFG" >/dev/null || die "doctor failed after soak"

printf 'PASS soak duration=%ss iterations=%d flaps=%d restarts=%d nat_edits=%d\n' \
    "$DURATION_SECS" "$iterations" "$flaps" "$restarts" "$nat_edits"
