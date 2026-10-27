#!/usr/bin/env bash
# Build a Linux release tarball and Debian package without dpkg-deb.
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ZIG="${ZIG:-zig}"
OUT="$ROOT/dist"
TARGET=""
VERSION=""
BUILD_RPM="0"

usage() {
    cat <<'USAGE'
usage: scripts/package.sh [options]

  --version VERSION   package version (default: build.zig.zon)
  --target TRIPLE     Zig target, e.g. aarch64-linux-gnu (default: native)
  --out DIR           output directory (default: dist)
  --rpm               also build an RPM (requires rpmbuild)
  -h, --help          show this help

Environment: ZIG=/path/to/zig
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:-}"; shift 2 ;;
        --target) TARGET="${2:-}"; shift 2 ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --rpm) BUILD_RPM="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

command -v "$ZIG" >/dev/null 2>&1 || {
    echo "zig not found: $ZIG (set ZIG=/path/to/zig)" >&2
    exit 1
}
for tool in ar tar gzip sha256sum install du; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "$tool is required" >&2
        exit 1
    }
done

if [ -z "$VERSION" ]; then
    VERSION="$(sed -n 's/^[[:space:]]*\.version = "\([^"]*\)".*/\1/p' "$ROOT/build.zig.zon" | head -n1)"
fi
case "$VERSION" in
    ''|*[!0-9A-Za-z.+~-]*) echo "invalid version: $VERSION" >&2; exit 2 ;;
esac
case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "version must be semantic: $VERSION" >&2; exit 2 ;;
esac

case "$TARGET" in
    ''|native) HOST_ARCH="$(uname -m)" ;;
    *) HOST_ARCH="${TARGET%%-*}" ;;
esac
case "$HOST_ARCH" in
    x86_64|amd64) ARCH="amd64"; RPM_ARCH="x86_64" ;;
    aarch64|arm64) ARCH="arm64"; RPM_ARCH="aarch64" ;;
    armv7*|armhf|arm) ARCH="armhf"; RPM_ARCH="armv7hl" ;;
    riscv64) ARCH="riscv64"; RPM_ARCH="riscv64" ;;
    *) ARCH="$HOST_ARCH"; RPM_ARCH="$HOST_ARCH" ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
STAGE="$WORK/stage"
TARROOT="$WORK/tar/vnet-$VERSION"
mkdir -p "$STAGE/usr" "$TARROOT" "$OUT"
OUT="$(cd "$OUT" && pwd)"

echo "==> building vNET $VERSION for $ARCH${TARGET:+ ($TARGET)}"
build_args=(--release=fast --prefix "$STAGE/usr")
if [ -n "$TARGET" ] && [ "$TARGET" != "native" ]; then
    build_args+=(-Dtarget="$TARGET")
fi
(cd "$ROOT" && "$ZIG" build "${build_args[@]}")

for bin in vnet vnetd; do
    [ -x "$STAGE/usr/bin/$bin" ] || {
        echo "missing staged binary: $bin" >&2
        exit 1
    }
done

install -Dm644 "$ROOT/packaging/vnetd.service" \
    "$STAGE/lib/systemd/system/vnetd.service"
install -Dm644 "$ROOT/examples/minimal.json" \
    "$STAGE/etc/vnet/vnet.json.example"
install -Dm644 "$ROOT/README.md" "$STAGE/usr/share/doc/vnet/README.md"
install -Dm644 "$ROOT/CHANGELOG.md" "$STAGE/usr/share/doc/vnet/CHANGELOG.md"
install -Dm644 "$ROOT/LICENSE" "$STAGE/usr/share/doc/vnet/LICENSE"
for doc in QUICKSTART TROUBLESHOOTING PERFORMANCE RELEASE; do
    install -Dm644 "$ROOT/docs/$doc.md" "$STAGE/usr/share/doc/vnet/$doc.md"
done
cp -a "$ROOT/examples" "$STAGE/usr/share/doc/vnet/examples"

TARBALL="vnet-$VERSION-linux-$ARCH.tar.gz"
cp -a "$STAGE/." "$TARROOT/"
tar -C "$WORK/tar" -czf "$OUT/$TARBALL" "vnet-$VERSION"

DEBROOT="$WORK/deb"
mkdir -p "$DEBROOT/control"
cat >"$DEBROOT/control/control" <<CONTROL
Package: vnet
Version: $VERSION-1
Architecture: $ARCH
Maintainer: devstroop <devstroop@users.noreply.github.com>
Installed-Size: $(du -sk "$STAGE" | cut -f1)
Section: net
Priority: optional
Homepage: https://github.com/devstroop/vnet
Description: portable virtual router
 vNET provides L2/L3 forwarding, bridging, NAT, DHCP, DNS and a
 stateful firewall for Linux. This package contains vnet, vnetd,
 the systemd unit, the C ABI library and the user documentation.
CONTROL
cat >"$DEBROOT/control/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = configure ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
POSTINST
cat >"$DEBROOT/control/prerm" <<'PRERM'
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -d /run/systemd/system ]; then
    systemctl stop vnetd.service >/dev/null 2>&1 || true
fi
exit 0
PRERM
cat >"$DEBROOT/control/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
POSTRM
chmod 755 "$DEBROOT/control/postinst" "$DEBROOT/control/prerm" "$DEBROOT/control/postrm"
printf '2.0\n' >"$DEBROOT/debian-binary"
tar --owner=0 --group=0 --numeric-owner -C "$STAGE" -czf "$DEBROOT/data.tar.gz" .
tar --owner=0 --group=0 --numeric-owner -C "$DEBROOT/control" -czf "$DEBROOT/control.tar.gz" .
DEB="vnet_${VERSION}_${ARCH}.deb"
(cd "$DEBROOT" && ar rcsD "$OUT/$DEB" debian-binary control.tar.gz data.tar.gz)

if [ "$BUILD_RPM" = "1" ]; then
    command -v rpmbuild >/dev/null 2>&1 || {
        echo "rpmbuild is required for --rpm" >&2
        exit 1
    }
    mkdir -p "$WORK/rpm/db"
    rpmbuild -bb \
        --define "_topdir $WORK/rpm" \
        --define "_dbpath $WORK/rpm/db" \
        --define "vnet_version $VERSION" \
        --define "vnet_release 1" \
        --define "vnet_arch $RPM_ARCH" \
        --define "vnet_stage $STAGE" \
        --target "$RPM_ARCH" \
        "$ROOT/packaging/vnet.spec"
    RPM_FILE="$WORK/rpm/RPMS/$RPM_ARCH/vnet-$VERSION-1.$RPM_ARCH.rpm"
    [ -f "$RPM_FILE" ] || {
        echo "rpmbuild produced no package" >&2
        exit 1
    }
    cp "$RPM_FILE" "$OUT/"
fi

if [ "$BUILD_RPM" = "1" ]; then
    (cd "$OUT" && sha256sum "$TARBALL" "$DEB" "vnet-$VERSION-1.$RPM_ARCH.rpm" >"SHA256SUMS-$ARCH")
else
    (cd "$OUT" && sha256sum "$TARBALL" "$DEB" >"SHA256SUMS-$ARCH")
fi
echo "==> wrote:"
echo "    $OUT/$TARBALL"
echo "    $OUT/$DEB"
[ "$BUILD_RPM" = "1" ] && echo "    $OUT/vnet-$VERSION-1.$RPM_ARCH.rpm"
echo "    $OUT/SHA256SUMS-$ARCH"
