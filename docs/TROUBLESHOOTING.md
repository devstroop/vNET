# Troubleshooting

Start with the validation path for the exact config file:

```sh
vnet validate /etc/vnet/vnet.json
sudo vnet status -c /etc/vnet/vnet.json
sudo vnet doctor -c /etc/vnet/vnet.json
sudo vnet journal -c /etc/vnet/vnet.json
sudo journalctl -u vnetd -b
```

## `vnetd` does not start

- **Missing config:** the packaged unit has
  `ConditionPathExists=/etc/vnet/vnet.json`. Copy the example and validate it.
- **`permission denied` / `EPERM`:** grant capabilities or run as root. The
  packaged unit grants `CAP_NET_ADMIN`, `CAP_NET_RAW` and
  `CAP_NET_BIND_SERVICE`; a manual launch needs the same.
- **`address in use` or `FileExists`:** another daemon or an unmanaged address
  owns the device. Check `vnet doctor`, `ip addr`, and the instance name.
- **instance mismatch:** the running daemon uses a different `instance` value
  than the config passed to `vnet up`/`vnet status`.
- **control socket errors:** check `$VNET_RUN_DIR/control.sock` (default
  `/run/vnet/control.sock`) and the daemon log.

## No forwarding

```sh
sudo vnet status -c /etc/vnet/vnet.json
ip route
ip neigh
ping -c 3 <peer>
```

- Confirm both ports are `LINK=up` and the subnets are distinct.
- A port may belong to a bridge or a router zone, not both.
- The default inbound/forward policy is drop unless the config accepts it.
- NAT requires a masquerade rule on the egress interface.
- Check the kernel forwarding sysctls if traffic is routed outside vNET.

## TCP stalls, checksum errors or large packets disappear

AF_PACKET sees frames before the peer's checksum offload is complete. vNET
repairs IPv4/IPv6 TCP/UDP checksums on forwarded packets (ADR-007), but it does
not reassemble 64 KiB GSO frames from a local veth peer. For synthetic tests,
disable offloads on the peer veths:

```sh
cc -O2 -o /tmp/netdev_offload scripts/netdev_offload.c
sudo /tmp/netdev_offload eth0 off
```

On physical devices use `ethtool -K <dev> tx off gso off tso off gro off` when
diagnosing. Do not leave offloads disabled on a production NIC without a
reason. See [PERFORMANCE.md](PERFORMANCE.md) for the measured impact.

## DHCP or DNS does not answer

- DHCP needs UDP/67 and DNS needs UDP/53 and TCP/53. The packaged unit grants
  `CAP_NET_BIND_SERVICE`.
- The service must have an address on the listening interface.
- Check the pool, reservations, `lease_db` permissions and
  `vnet dhcp status`.
- For DNS, verify the listener address, upstreams, split zones and the
  `vnet.` status zone with `vnet dns query`.

## A crash left routes or rules behind

```sh
sudo vnet doctor -c /etc/vnet/vnet.json
sudo vnet doctor --repair -c /etc/vnet/vnet.json
```

`vnet doctor --repair` refuses to run while a daemon is live. Malformed journal
tails are quarantined next to the journal. Do not delete the journal before
capturing it for diagnosis.

## A NAT edit does not survive

`vnet nat add` and `vnet nat del` save the configuration atomically and apply
it through the control socket. If no daemon is running, the change is saved
with a warning and takes effect on the next start. Check that the same `-c`
path and `VNET_RUN_DIR` are used by the daemon and the CLI.

## systemd hardening blocks a feature

The unit uses `ProtectSystem=strict`, `ProtectKernelTunables=yes` and a
capability bounding set. TUN/TAP and AF_PACKET need the listed capabilities.
If a local deployment needs a narrower or wider policy, override the unit with
`systemctl edit vnetd` rather than running the daemon unconfined.

## Collecting a report

```sh
vnet version
uname -a
sudo vnet status -c /etc/vnet/vnet.json
sudo vnet journal -c /etc/vnet/vnet.json
sudo journalctl -u vnetd -b --no-pager
```

Never include packet payloads, keys or credentials in a bug report.
