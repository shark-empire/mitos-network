# mitos-network

The network policy and management daemon for mitosOS.

mitos-network does not implement TCP/IP -- the Linux kernel already does
that. This crate is the layer above it: interfaces, addresses, routes,
Wi-Fi, DHCP, DNS, VPNs, the firewall, and internet sharing, all driven
through the kernel's own netlink API and a small number of well-established
external tools (`wpa_supplicant`, `hostapd`, `nft`, `wg`, `openvpn`,
`bluetoothctl`) rather than reimplemented from scratch. See
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
interface it should manage, and `hostapd`/`nft`/`wg`/`openvpn`/
`bluetoothctl` available on `$PATH` for the features that use them. See
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
- rtnetlink client (links, addresses, routes, FIB rules) -- hand-rolled,
  zero wrapper-crate dependency
- DHCPv4 client and server (full protocol exchange)
- wpa_supplicant control-socket client (real protocol, not shelling out to
  `wpa_cli`)
- nftables ruleset generation + `nft -f` application
- Config loading/validation, connection-profile persistence, DHCP-lease
  persistence
- The IPC protocol, server, client, and `mitos-netctl`

**Real but narrower than a production tool, or explicitly stubbed:**
see [`docs/networking.md`](docs/networking.md)'s "Partially implemented" /
"Deliberate stubs" sections -- DHCPv6 (stateless only), WPA-Enterprise
(no cert pinning yet), OpenVPN session tracking (no management-interface
introspection), Wi-Fi scan result freshness (polls rather than subscribing
to events), PAC proxy evaluation (stored, not evaluated).

**The single biggest gap:** this was written and manually reviewed
(brace/paren balance, cross-module symbol references checked by hand) in an
environment with no Rust toolchain, no root access, and no real network
hardware -- so **nothing here has been compiled, let alone run.** The next
concrete step for this project is a real `cargo build` on a Linux box,
followed by working through whatever the compiler disagrees with first,
then the same against a real `wpa_supplicant`/`nft`/DHCP server.

## License

MIT. See [`LICENSE`](LICENSE).
