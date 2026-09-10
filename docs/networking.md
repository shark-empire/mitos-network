# Networking details, protocol notes, and known gaps

This document is the honest accounting of what's fully implemented, what's
partially implemented, and what's a deliberate stub -- so the next person
(or session) working on this crate knows exactly where to look before
assuming something works.

## Fully implemented

- **rtnetlink** (`ip/netlink.rs`): link (get/set flags/MTU/hwaddr,
  create/delete virtual links), address (add/del/list), route (add/del/list,
  default-route replacement), and FIB rules (policy routing) -- all via a
  hand-rolled `AF_NETLINK` client, not a wrapper crate.
- **DHCPv4 client** (`dhcp/dhcp4.rs`, `dhcp/client.rs`): full
  DISCOVER/OFFER/REQUEST/ACK/NAK exchange, renewal, and release, over a
  real broadcast UDP socket bound to the target interface via
  `SO_BINDTODEVICE`.
- **DHCPv4 server** (`sharing/dhcp_server.rs`): for hotspot/sharing clients,
  reusing the same packet code as the client.
- **wpa_supplicant control protocol** (`wifi/wpa.rs`): `SCAN`, `SCAN_RESULTS`,
  `ADD_NETWORK`/`SET_NETWORK`/`SELECT_NETWORK`, `STATUS`, `SIGNAL_POLL`,
  `DISCONNECT`, etc., over the real Unix-domain-socket control interface.
- **nftables ruleset generation** (`firewall/nftables.rs`), applied via
  `nft -f`.

## Partially implemented (works, but narrower than a production tool)

- **DHCPv6** (`dhcp/dhcp6.rs`): only the stateless Information-Request
  exchange (DNS servers/search domains on top of SLAAC). No IA_NA
  (stateful address assignment) support -- most networks don't need it
  since SLAAC handles addressing, but a network that requires stateful
  DHCPv6 won't get an address from this client.
- **802.1X / WPA-Enterprise** (`wifi/wifi.rs::connect`): sets `identity`/
  `password` for a basic PEAP/TTLS-style setup, but doesn't yet expose CA
  certificate pinning or client-certificate (EAP-TLS) configuration through
  `ConnectionProfile`.
- **OpenVPN session tracking** (`vpn/openvpn.rs`): spawns and can kill the
  process, but doesn't use OpenVPN's management interface, so it doesn't
  know the real tun/tap interface name OpenVPN picked, real-time connection
  status, or reconnect events. A logical placeholder name
  (`openvpn-<profile-id>`) stands in for the interface name in
  `ipc::messages` responses.
- **Wi-Fi scan freshness** (`wifi/scanner.rs`): triggers a scan and waits a
  fixed 3 seconds rather than subscribing to wpa_supplicant's unsolicited
  `CTRL-EVENT-SCAN-RESULTS` event (which requires an `ATTACH`'d socket and
  an event-reading loop that isn't implemented). Good enough given
  `manager::scheduler` re-scans periodically anyway, but a manually
  triggered scan can return slightly stale-feeling results.
- **PAC-based proxy auto-config** (`proxy/proxy.rs`): the URL is stored and
  returned via IPC status queries, but never evaluated (`FindProxyForURL`
  is a JavaScript function -- no JS engine dependency was pulled in for
  this).

## Deliberate stubs / not started

- **WireGuard configuration via generic netlink**: `vpn/wireguard.rs`
  creates the link via rtnetlink but sets keys/peers via the `wg` CLI tool
  rather than the kernel's WireGuard generic-netlink family directly.
- **BlueZ D-Bus API**: `bluetooth/` shells out to `bluetoothctl`/`bt-network`
  rather than talking to `org.bluez` over D-Bus, to avoid a D-Bus client
  dependency. Worth revisiting if mitosOS ends up with a D-Bus story anyway
  (see [[mitos-session]]).
- **Captive-portal browser flow**: `connectivity` detects a portal
  (`ConnectivityState::Portal`) and broadcasts it as an event; actually
  popping open a browser to the portal's login page is a desktop-shell
  concern, not this daemon's.

## Why the connectivity check uses plain HTTP

`connectivity::checker` deliberately probes a plain-`http://` URL, not
`https://`. A captive portal's entire mechanism *is* intercepting
unencrypted HTTP and substituting a redirect to its login page -- probing
over HTTPS would just get a TLS handshake failure (indistinguishable from
"no internet at all") instead of the redirect this code needs to see to
correctly report `ConnectivityState::Portal`. This is the same reason every
major OS/browser vendor's own connectivity-check endpoint is plain HTTP.

## Testing

Given no Rust toolchain was available while writing this (see the top-level
README), every module's logic was manually reviewed for brace/paren balance
and cross-module symbol references, but **nothing here has been compiled or
run**. `tests/` covers what can be tested without root, real hardware, or a
running `wpa_supplicant`/`hostapd`/`nft`/kernel-with-CAP_NET_ADMIN: pure
packet (de)serialization, address math, config/profile persistence
round-trips, and rule-rendering output. It does not cover the actual
netlink/DHCP-socket/wpa_supplicant-socket/nft-invocation code paths --
that needs a real Linux box, root, and (ideally) a VM with a spare network
interface to test against safely.
