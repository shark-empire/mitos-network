# mitos-network

The network policy and management daemon for mitosOS.

mitos-network does not implement TCP/IP -- the Linux kernel already does
that. This crate is the layer above it: interfaces, addresses, routes,
Wi-Fi, DHCP, DNS, VPNs, the firewall, and internet sharing, all driven
through the kernel's own netlink/generic-netlink APIs and a small number of
well-established external tools (`wpa_supplicant`, `hostapd`, `nft`,
`openvpn`, `bluetoothctl`) rather than reimplemented from scratch --
WireGuard is the one VPN backend that talks to the kernel directly (its own
generic-netlink family) rather than shelling out to a CLI tool. See
[`docs/architecture.md`](docs/architecture.md) for the full picture and
[`INTEGRATION.md`](INTEGRATION.md) for how other mitosOS components (or
anything else) talk to it.

## Building

```
cargo build --release
```

Produces two binaries: `mitos-network` (the daemon) and `mitos-netctl` (the
CLI client). Both live in the same Cargo package (`src/lib.rs` is the
shared library the two binaries build on).

```
cargo test
```

Runs the pure-logic test suite in `tests/` -- packet framing, address math,
config/profile persistence, rule rendering, and so on. It does **not**
exercise the real netlink/DHCP-socket/wpa_supplicant/`nft` code paths,
which need root, real hardware, and a live network to test meaningfully.
See [`docs/networking.md`](docs/networking.md)'s Testing section.

## Running

```
sudo mitos-network --config-dir /etc/mitos-network
mitos-netctl status
mitos-netctl device list
mitos-netctl wifi scan wlan0
mitos-netctl wifi connect wlan0 "Home Network" "the-passphrase"
```

The daemon expects `wpa_supplicant` already running (with a matching
`ctrl_interface=` directory, see `config/wireless.toml`) against any Wi-Fi
interface it should manage, and `hostapd`/`nft`/`openvpn`/`bluetoothctl`
available on `$PATH` for the features that use them (WireGuard needs no
external binary -- it talks to the kernel's `wireguard` generic-netlink
family directly, so only the kernel module, `modprobe wireguard`, has to
be present). See
[`services/mitos-network.service`](services/mitos-network.service) for the
systemd unit and the capabilities it grants.

## Directory layout

```
config/       Default network.toml / interfaces.toml / dns.toml / wireless.toml
data/         Illustrative only -- shows the shape of the real runtime data
              root (profiles/, leases/, secrets/), which actually lives at
              /var/lib/mitos-network by default. See data/README.md.
src/          The daemon + shared library (see docs/architecture.md)
bin/          mitos-netctl, the CLI client
services/     systemd unit
tests/        Integration tests (pure-logic; see above)
docs/         Architecture, protocol, security, and troubleshooting docs
```

## Status: what's done, what isn't

This is a complete architectural scaffold with real protocol
implementations in every subsystem the user-facing feature list calls
for -- not a hardened, field-tested daemon yet. Concretely:

**Fully real, not stubbed:**
- rtnetlink and generic-netlink clients (links, addresses, routes, FIB
  rules, and WireGuard's own `WG_CMD_SET_DEVICE` family) -- hand-rolled,
  zero wrapper-crate dependency
- DHCPv4 and DHCPv6 clients (full protocol exchange, including DHCPv6
  stateful IA_NA address assignment) and a DHCPv4 server
- wpa_supplicant control-socket client (real protocol, not shelling out to
  `wpa_cli`), including the `ATTACH`/`CTRL-EVENT-*` event stream for real
  scan-complete notification
- WPA-Enterprise with optional pinned `eap`/`phase2` method
- OpenVPN session tracking via OpenVPN's own management interface (real
  interface name, connection state, and clean shutdown)
- A PAC (proxy auto-config) evaluator -- fetches and actually runs
  `FindProxyForURL()` via a small hand-rolled JS-subset interpreter,
  rather than just storing the URL
- nftables ruleset generation + `nft -f` application
- Config loading/validation, connection-profile persistence, DHCP-lease
  persistence (v4 and v6), proxy-config persistence
- The IPC protocol, server, client, and `mitos-netctl` -- including Wi-Fi,
  Bluetooth, and (new) proxy management end to end

**Real but narrower than a production tool, or explicitly stubbed:**
see [`docs/networking.md`](docs/networking.md)'s "Deliberate stubs"
section -- Bluetooth still shells out to `bluetoothctl` rather than
talking to `org.bluez` over D-Bus directly (already fully reachable via
IPC/`mitos-netctl`, this is purely an implementation-detail gap), and the
captive-portal login flow is deliberately left to a future desktop shell
rather than this daemon. The PAC interpreter and DHCPv6 client each have a
couple of narrow, documented scope boundaries (no loops/arrays in PAC
scripts, UTC-only `dateRange`/`timeRange`; DHCPv6 Renew/Rebind always
multicast rather than taking an optional unicast shortcut) -- see
`docs/networking.md` for the reasoning behind each.

**The single biggest gap:** this was written and manually reviewed
(brace/paren balance, cross-module symbol references checked by hand) in an
environment with no Rust toolchain, no root access, and no real network
hardware -- so **nothing here has been compiled, let alone run.** The next
concrete step for this project is a real `cargo build` on a Linux box,
followed by working through whatever the compiler disagrees with first,
then the same against a real `wpa_supplicant`/`nft`/DHCP server.

## License

MIT. See [`LICENSE`](LICENSE).
