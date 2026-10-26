#!/usr/bin/env bash
# Linux forwarding performance smoke: L3 forward, L2 bridge and SNAT using a
# self-contained traffic generator. Runs inside a fresh network namespace.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

show_usage() {
    cat <<'EOF'
usage: scripts/perf.sh [options]

  --scenario forward|l2|nat|all   scenario to run (default: all)
  --duration SECONDS              UDP sampling duration (default: 5)
  --tcp-bytes BYTES               TCP transfer size (default: 268435456)
  --rtt-count COUNT               UDP RTT samples (default: 500)
  --no-build                      reuse zig-out release binaries
  --keep                          keep logs under /tmp
  --no-offload-reset              leave veth checksum/GSO offloads enabled
  -h, --help                      show this help
EOF
}

case "${1:-}" in
    -h|--help) show_usage; exit 0 ;;
esac

if [ "${VNET_PERF_NETNS:-0}" != "1" ]; then
    ZIG="${ZIG:-zig}"
    command -v "$ZIG" >/dev/null 2>&1 || {
        echo "FAIL: zig not found (set ZIG=/path/to/zig)" >&2
        exit 1
    }
    if [ "${EUID}" -eq 0 ]; then
        exec unshare -n env VNET_PERF_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
    fi
    exec unshare -rn env VNET_PERF_NETNS=1 "ZIG=$(command -v "$ZIG")" bash "$0" "$@"
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
CFG="$WORK/vnet-perf.json"
LOG="$WORK/vnetd.log"
SCENARIO="all"
DURATION="5"
TCP_BYTES="268435456"
RTT_COUNT="500"
DO_BUILD="1"
KEEP="0"
OFFLOAD_RESET="1"

vpid=""
spid=""
pidA=""
pidB=""


while [ $# -gt 0 ]; do
    case "$1" in
        --scenario) SCENARIO="${2:-}"; shift 2 ;;
        --duration) DURATION="${2:-}"; shift 2 ;;
        --tcp-bytes) TCP_BYTES="${2:-}"; shift 2 ;;
        --rtt-count) RTT_COUNT="${2:-}"; shift 2 ;;
        --no-build) DO_BUILD="0"; shift ;;
        --keep) KEEP="1"; shift ;;
        --no-offload-reset) OFFLOAD_RESET="0"; shift ;;
        -h|--help) show_usage; exit 0 ;;
        *) echo "FAIL: unknown argument: $1" >&2; show_usage >&2; exit 2 ;;
    esac
done

case "$SCENARIO" in
    forward|l2|nat|all) ;;
    *) echo "FAIL: invalid scenario: $SCENARIO" >&2; exit 2 ;;
esac
case "$DURATION" in
    ''|*[!0-9]*) echo "FAIL: duration must be a positive integer" >&2; exit 2 ;;
esac
case "$TCP_BYTES" in
    ''|*[!0-9]*) echo "FAIL: tcp-bytes must be a positive integer" >&2; exit 2 ;;
esac
case "$RTT_COUNT" in
    ''|*[!0-9]*) echo "FAIL: rtt-count must be a positive integer" >&2; exit 2 ;;
esac
[ "$DURATION" -gt 0 ] || { echo "FAIL: duration must be positive" >&2; exit 2; }
[ "$TCP_BYTES" -gt 0 ] || { echo "FAIL: tcp-bytes must be positive" >&2; exit 2; }
[ "$RTT_COUNT" -gt 0 ] || { echo "FAIL: rtt-count must be positive" >&2; exit 2; }

log() { printf '==> %s\n' "$*"; }
die() {
    printf 'FAIL: %s\n' "$*" >&2
    if [ -f "$LOG" ]; then
        tail -20 "$LOG" >&2 || true
    fi
    exit 1
}

stop_pid() {
    local pid="$1"
    [ -n "$pid" ] || return 0
    kill -TERM "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

cleanup_scenario() {
    stop_pid "$spid"; spid=""
    stop_pid "$vpid"; vpid=""
    stop_pid "$pidA"; pidA=""
    stop_pid "$pidB"; pidB=""
    ip link del ra 2>/dev/null || true
    ip link del rb 2>/dev/null || true
    rm -rf "${VNET_RUN_DIR:-}" 2>/dev/null || true
}

cleanup() {
    cleanup_scenario
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
        if [ "$gw" != "-" ]; then
            ip route add default via "$gw"
        fi
        touch "$marker"
        sleep 600
    ' _ "$peer" "$addr" "$gw" "$marker" </dev/null >"$WORK/$peer.log" 2>&1 &
    echo $!
}

wait_ready() {
    local file="$1" pid="$2"
    for _ in $(seq 1 250); do
        grep -q '^READY' "$file" 2>/dev/null && return 0
        if ! kill -0 "$pid" 2>/dev/null; then
            cat "$file" >&2 || true
            die "traffic server exited before ready"
        fi
        sleep 0.02
    done
    cat "$file" >&2 || true
    die "traffic server did not become ready"
}

start_topology() {
    local scenario="$1"
    local a_addr b_addr a_gw b_gw
    case "$scenario" in
        forward|nat)
            a_addr="10.0.1.2/24"; a_gw="10.0.1.1"
            b_addr="10.0.2.2/24"; b_gw="10.0.2.1"
            SERVER_IP="10.0.2.2"
            ;;
        l2)
            a_addr="10.0.1.2/24"; a_gw="-"
            b_addr="10.0.1.3/24"; b_gw="-"
            SERVER_IP="10.0.1.3"
            ;;
    esac

    ip link set lo up
    ip link add ra type veth peer name a0 || die "create veth pair ra/a0"
    ip link add rb type veth peer name b0 || die "create veth pair rb/b0"
    ip link set ra up
    ip link set rb up
    pidA="$(start_host a0 "$a_addr" "$a_gw" "$WORK/a.ready")"
    pidB="$(start_host b0 "$b_addr" "$b_gw" "$WORK/b.ready")"
    ip link set a0 netns "$pidA" || die "move a0 into host A"
    ip link set b0 netns "$pidB" || die "move b0 into host B"

    for _ in $(seq 1 250); do
        [ -f "$WORK/a.ready" ] && [ -f "$WORK/b.ready" ] && break
        sleep 0.02
    done
    [ -f "$WORK/a.ready" ] || die "host A did not configure"
    [ -f "$WORK/b.ready" ] || die "host B did not configure"
    if [ "$OFFLOAD_RESET" = "1" ]; then
        nsenter -t "$pidA" -n "$OFFLOAD_HELPER" eth0 off ||
            die "failed to disable offloads on host A"
        nsenter -t "$pidB" -n "$OFFLOAD_HELPER" eth0 off ||
            die "failed to disable offloads on host B"
    fi
}

write_config() {
    local scenario="$1"
    case "$scenario" in
        forward)
            cat >"$CFG" <<'EOF'
{
  "version": 1,
  "instance": "perf-forward",
  "ports": {
    "lan": { "kind": "l2", "device": "ra" },
    "wan": { "kind": "l2", "device": "rb" }
  },
  "interfaces": {
    "lan0": { "port": "lan", "address": "10.0.1.1/24" },
    "wan0": { "port": "wan", "address": "10.0.2.1/24" }
  },
  "firewall": { "default_in": "accept", "default_forward": "accept", "default_out": "accept" }
}
EOF
            ;;
        l2)
            cat >"$CFG" <<'EOF'
{
  "version": 1,
  "instance": "perf-l2",
  "ports": {
    "lan": { "kind": "l2", "device": "ra" },
    "wan": { "kind": "l2", "device": "rb" }
  },
  "bridges": { "br0": { "ports": ["lan", "wan"] } },
  "interfaces": { "br0svi": { "bridge": "br0", "address": "10.0.1.1/24" } },
  "firewall": { "default_in": "accept", "default_forward": "accept", "default_out": "accept" }
}
EOF
            ;;
        nat)
            cat >"$CFG" <<'EOF'
{
  "version": 1,
  "instance": "perf-nat",
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
            ;;
    esac
}

start_vnetd() {
    local scenario="$1"
    VNET_RUN_DIR="$WORK/run-$scenario"
    export VNET_RUN_DIR
    rm -rf "$VNET_RUN_DIR"
    : >"$LOG"
    write_config "$scenario"
    "$BIN/vnet" validate "$CFG" >/dev/null || die "config validation failed"
    "$BIN/vnetd" -c "$CFG" >"$LOG" 2>&1 &
    vpid=$!
    for _ in $(seq 1 100); do
        grep -q "started instance" "$LOG" && return 0
        if ! kill -0 "$vpid" 2>/dev/null; then
            cat "$LOG" >&2
            die "vnetd exited"
        fi
        sleep 0.02
    done
    cat "$LOG" >&2
    die "vnetd did not start"
}

warmup() {
    if ! nsenter -t "$pidA" -n ping -c 1 -W 2 "$SERVER_IP" >/dev/null 2>&1; then
        cat "$WORK/a.log" >&2 || true
        cat "$WORK/b.log" >&2 || true
        cat "$LOG" >&2 || true
        die "warmup ping to $SERVER_IP failed"
    fi
}

wait_server() {
    local pid="$1" file="$2"
    for _ in $(seq 1 100); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        cat "$file" >&2 || true
        die "traffic server did not finish"
    fi
    wait "$pid" 2>/dev/null || {
        cat "$file" >&2 || true
        die "traffic server failed"
    }
}

run_udp() {
    local label="$1" size="$2" port="$3"
    local slog="$WORK/${label}-server.log"
    local clog="$WORK/${label}-client.log"
    : >"$slog"
    : >"$clog"
    nsenter -t "$pidB" -n "$LOADGEN" udp-sink "$SERVER_IP" "$port" >"$slog" 2>&1 &
    spid=$!
    wait_ready "$slog" "$spid"
    timeout $((DURATION + 10)) nsenter -t "$pidA" -n "$LOADGEN" udp-source "$SERVER_IP" "$port" "$DURATION" "$size" >"$clog" 2>&1 ||
        die "$label client failed"
    wait_server "$spid" "$slog"
    spid=""
    grep '^RESULT' "$clog" || die "$label missing client result"
    grep '^RESULT' "$slog" || die "$label missing server result"
}

run_rtt() {
    local slog="$WORK/rtt-server.log"
    local clog="$WORK/rtt-client.log"
    : >"$slog"
    : >"$clog"
    nsenter -t "$pidB" -n "$LOADGEN" udp-echo "$SERVER_IP" 5204 >"$slog" 2>&1 &
    spid=$!
    wait_ready "$slog" "$spid"
    timeout 30 nsenter -t "$pidA" -n "$LOADGEN" udp-rtt "$SERVER_IP" 5204 "$RTT_COUNT" >"$clog" 2>&1 ||
        die "rtt client failed"
    stop_pid "$spid"; spid=""
    grep '^RESULT' "$clog" || die "missing rtt result"
}

run_tcp() {
    local slog="$WORK/tcp-server.log"
    local clog="$WORK/tcp-client.log"
    : >"$slog"
    : >"$clog"
    nsenter -t "$pidB" -n "$LOADGEN" tcp-sink "$SERVER_IP" 5205 "$TCP_BYTES" >"$slog" 2>&1 &
    spid=$!
    wait_ready "$slog" "$spid"
    timeout 120 nsenter -t "$pidA" -n "$LOADGEN" tcp-source "$SERVER_IP" 5205 "$TCP_BYTES" >"$clog" 2>&1 ||
        die "tcp client failed"
    wait_server "$spid" "$slog"
    spid=""
    grep '^RESULT' "$clog" || die "tcp missing client result"
    grep '^RESULT' "$slog" || die "tcp missing server result"
}

run_scenario() {
    local scenario="$1"
    log "scenario $scenario"
    start_topology "$scenario"
    start_vnetd "$scenario"
    warmup
    log "$scenario udp 64B"
    run_udp "$scenario-udp64" 64 5201
    log "$scenario udp 1400B"
    run_udp "$scenario-udp1400" 1400 5202
    log "$scenario tcp"
    run_tcp
    log "$scenario rtt"
    run_rtt
    cleanup_scenario
    rm -f "$WORK/a.ready" "$WORK/b.ready"
}

echo "host=$(uname -srm) cpus=$(getconf _NPROCESSORS_ONLN) duration=${DURATION}s tcp_bytes=${TCP_BYTES}"
case "$SCENARIO" in
    all)
        run_scenario forward
        run_scenario l2
        run_scenario nat
        ;;
    *)
        run_scenario "$SCENARIO"
        ;;
esac
log "perf complete"
