# Quickstart

This guide runs vNET as a Linux router with two packet ports, a LAN DHCP
server and source NAT on the uplink. Replace `eth0`/`eth1` with your devices.

## Requirements

- Linux with `AF_PACKET` support
- root or `CAP_NET_ADMIN`, `CAP_NET_RAW` and (for DHCP/DNS) `CAP_NET_BIND_SERVICE`
- Zig 0.16.x to build from source
- `iproute2` for inspection

## Build and test

```sh
zig build --release=fast
zig build test
```

The binaries are `zig-out/bin/vnet` and `zig-out/bin/vnetd`. The release
package installs the same files under `/usr/bin`.

## Install a package

```sh
sudo apt install ./vnet_0.2.0_amd64.deb
# or: sudo rpm -i vnet-0.2.0-1.x86_64.rpm
# or unpack dist/vnet-0.2.0-linux-amd64.tar.gz over /
```

The package installs the systemd unit but does not start the daemon until
`/etc/vnet/vnet.json` exists:

```sh
sudo cp /etc/vnet/vnet.json.example /etc/vnet/vnet.json
sudoedit /etc/vnet/vnet.json
sudo vnet validate /etc/vnet/vnet.json
sudo systemctl enable --now vnetd
```

Check it:

```sh
sudo vnet status -c /etc/vnet/vnet.json
sudo journalctl -u vnetd -f
```

## Example configuration

```json
{
  "version": 1,
  "instance": "router",
  "ports": {
    "wan": { "kind": "l2", "device": "eth0" },
    "lan": { "kind": "l2", "device": "eth1" }
  },
  "interfaces": {
    "wan0": { "port": "wan", "address": "dhcp" },
    "lan0": { "port": "lan", "address": "10.0.0.1/24" }
  },
  "dhcp": [
    { "iface": "lan0", "pool": "10.0.0.100-10.0.0.200" }
  ],
  "nat": {
    "masquerade": [ { "out": "wan0" } ]
  },
  "firewall": {
    "default_in": "accept",
    "default_forward": "accept",
    "default_out": "accept"
  }
}
```

For a static uplink, replace `"address": "dhcp"` with the upstream address and
add a default route in the configuration.

## Run from the build tree

```sh
./zig-out/bin/vnet validate examples/minimal.json
sudo ./zig-out/bin/vnetd -c examples/minimal.json
```

Use a second terminal:

```sh
sudo ./zig-out/bin/vnet status -c examples/minimal.json
```

## Move a port to a bridge

A port belongs to at most one bridge or router zone. An SVI is a separate
logical interface attached to the bridge:

```json
{
  "ports": {
    "lan1": { "kind": "l2", "device": "eth1" },
    "lan2": { "kind": "l2", "device": "eth2" }
  },
  "bridges": {
    "br0": { "ports": ["lan1", "lan2"] }
  },
  "interfaces": {
    "br0svi": { "bridge": "br0", "address": "10.0.0.1/24" }
  }
}
```

## Stop and clean up

Normal stop:

```sh
sudo systemctl stop vnetd
```

If the daemon crashed or was killed, replay the journal:

```sh
sudo vnet doctor -c /etc/vnet/vnet.json
sudo vnet doctor --repair -c /etc/vnet/vnet.json
```

`vnet down` is the CLI teardown path when no daemon is running. Always inspect
`vnet journal` before repairing an unfamiliar system.

## Next steps

- [Configuration and scope](CORE-SCOPE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Performance](PERFORMANCE.md)
- [Release process](RELEASE.md)
