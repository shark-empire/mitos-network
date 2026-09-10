# Troubleshooting

## `mitos-netctl` says "could not connect to mitos-network"

The daemon isn't running, or `general.socket-path` in `network.toml`
doesn't match what `mitos-netctl` is looking at (it reads the same
compiled-in default, `/run/mitos-network/network.sock`, unless a future
`--socket` flag is added). Check `systemctl status mitos-network`.

## A device stays in `Unavailable`

`Unavailable` means the interface exists but has no carrier
(`ip::interface::Interface::has_carrier`, backed by the kernel's
`IFF_RUNNING` flag). For Ethernet: check the cable, and cross-check against
`ethernet::link::has_carrier`'s `ETHTOOL_GLINK` answer -- a persistent
mismatch between the two is itself worth reporting, since it usually means
a driver bug. For Wi-Fi: `Unavailable` before any association attempt is
normal; if it stays `Unavailable` after mitos-network should have tried to
autoconnect, check that `wpa_supplicant` is actually running against that
interface with a control-interface directory matching
`wireless.ctrl-interface-dir`.

## Wi-Fi won't connect and there's no clear error

`wifi::wifi::connect` polls wpa_supplicant's `STATUS` command every 300ms
for the `wpa_state` field. Run `mitos-netctl device show <iface>` mid-attempt
and separately (with `wpa_cli -i <iface> status`, outside mitos-network
entirely) to see wpa_supplicant's own view -- if the two disagree, or if
`wpa_state` is stuck at `FOUR_WAY_HANDSHAKE` or `WRONG_KEY`, that's a
passphrase problem, not a mitos-network bug. This is one of the specific
gaps noted in `docs/networking.md`: without subscribing to
wpa_supplicant's unsolicited event stream, mitos-network can only poll,
not react instantly to a `CTRL-EVENT-*` failure notification.

## DHCP times out

1. Check that another DHCP client isn't already bound to port 68 on the
   same interface (`ss -ulnp | grep :68`) -- `dhcp::client` uses
   `SO_BINDTODEVICE` specifically to avoid cross-interface interference,
   but two processes both binding *the same* interface's port 68 will
   still collide.
2. Check the interface actually has carrier first
   (`mitos-netctl device show <iface>`) -- a DHCP timeout on a device with
   no carrier is expected, not a bug.
3. `dhcp::client::acquire`'s retry loop re-sends DISCOVER/REQUEST every 3
   seconds until the overall timeout; a single dropped broadcast is not
   itself a problem, but a full timeout with a live cable/AP association
   suggests either no DHCP server on that network or a firewall dropping
   UDP 67/68.

## The firewall doesn't seem to be applying

`firewall::nftables::apply` shells out to `nft -f`; run `nft list table inet
mitos_network` directly to see what's actually loaded versus what
`mitos-netctl` believes the state to be. A silent failure here would show
up in the daemon's log (`logging::logger`) as an `nft -f exited with ...`
error -- check `journalctl -u mitos-network` first.

## Hotspot clients don't get an IP

Check `sharing::dhcp_server`'s pool isn't already exhausted
(`journalctl -u mitos-network`, filtered for the hotspot interface) and that
`net.ipv4.ip_forward` is actually `1` (`sysctl net.ipv4.ip_forward`) if
internet sharing (not just local AP connectivity) is the symptom.

## Nothing here has been run against a real kernel yet

Every subsystem in this crate was written and manually reviewed (brace/
paren balance, cross-module symbol references) without access to a Rust
toolchain, a Linux kernel, or root privileges in the environment it was
written in. The single most valuable next step for this project isn't a
new feature -- it's `cargo build` on a real Linux box, followed by working
through whatever the compiler and then a real `wpa_supplicant`/`nft`/DHCP
server disagree with this document about.
