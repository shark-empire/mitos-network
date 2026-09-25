# Networking details, protocol notes, and known gaps

This document is the honest accounting of what's fully implemented, what's
partially implemented, and what's a deliberate stub -- so the next person
(or session) working on this crate knows exactly where to look before
assuming something works.

## Fully implemented

- **rtnetlink** (`ip/netlink.rs`): link (get/set flags/MTU/hwaddr,
  create/delete virtual links), address (add/del/list), route (add/del/list,
  default-route replacement), and FIB rules (policy routing) -- all via a
  hand-rolled `AF_NETLINK` client, not a wrapper crate. `netlink.rs` is
  `pub(crate)` (not fully private) specifically so `vpn::wireguard` can
  reuse its `NlSocket`/`AttrBuilder` transport for generic netlink too,
  rather than duplicating it.
- **Generic netlink** (`ip/genetlink.rs`): family-id resolution via
  `nlctrl`/`CTRL_CMD_GETFAMILY`, the piece `NETLINK_GENERIC` families
  (as opposed to `NETLINK_ROUTE`'s fixed message-type space) need before
  anything else is possible.
- **WireGuard configuration via generic netlink** (`vpn/wireguard.rs`):
  the link is created via rtnetlink (as before), and keys/peers/
  allowed-ips are now set via `WG_CMD_SET_DEVICE` against the kernel's
  own `"wireguard"` genl family, cross-referenced against the public
  protocol WireGuard documents at wireguard.com/embedding/ -- not the
  `wg` CLI. This is a real security improvement, not just an internal
  cleanup: the private key is decoded in-process and handed straight to
  the kernel inside a netlink message, so it never touches disk, a
  process argv, or another process's environment, even briefly.
- **DHCPv4 client** (`dhcp/dhcp4.rs`, `dhcp/client.rs`): full
  DISCOVER/OFFER/REQUEST/ACK/NAK exchange, renewal, and release, over a
  real broadcast UDP socket bound to the target interface via
  `SO_BINDTODEVICE`.
- **DHCPv4 server** (`sharing/dhcp_server.rs`): for hotspot/sharing clients,
  reusing the same packet code as the client.
- **DHCPv6** (`dhcp/dhcp6.rs`): both stateless Information-Request (DNS
  servers/search domains on top of SLAAC) and full stateful IA_NA
  address assignment -- Solicit (with Rapid Commit, falling back to the
  full Solicit/Advertise/Request/Reply exchange if a server doesn't
  honor it), Renew, Rebind, and Release, with lease persistence
  mirroring the v4 client's. A per-connection `ipv6_method` setting
  (`Slaac` / `SlaacWithStatelessDhcp` / `Dhcp6`) picks which mode a
  connection uses; `Slaac` (the default) is unchanged from before this
  field existed. One deliberate scope limit: Renew/Rebind always go out
  multicast rather than unicast to the granting server, since taking
  the unicast shortcut requires tracking a server-provided "Server
  Unicast" option this client doesn't parse -- multicast is always
  spec-valid per RFC 8415 18.2.4, just not the optimization.
- **wpa_supplicant control protocol** (`wifi/wpa.rs`): `SCAN`,
  `SCAN_RESULTS`, `ADD_NETWORK`/`SET_NETWORK`/`SELECT_NETWORK`, `STATUS`,
  `SIGNAL_POLL`, `DISCONNECT`, etc., over the real Unix-domain-socket
  control interface -- plus, now, `ATTACH`/`DETACH` and the unsolicited
  `CTRL-EVENT-*` push stream (`WpaMonitor`), deliberately a *second*
  connection to the control socket rather than a second use of
  `WpaCtrl`'s, for the same reason `wpa_cli` itself keeps separate
  `ctrl_conn`/`mon_conn` sockets (see the doc comment on `WpaMonitor`).
- **802.1X / WPA-Enterprise** (`wifi/wifi.rs::connect`, `configure_eap`):
  sets `identity`, a CA certificate (`ca_cert`) for RADIUS server
  validation, and optionally a client certificate + private key
  (EAP-TLS), sourced from `ConnectionProfile`'s `WifiSettings` (the
  `eap_*` fields) and `security::secrets` -- and can now pin a specific
  `eap`/`phase2` method (`WifiSettings::eap_method`/`eap_phase2`,
  validated against an allow-list before being sent unquoted to
  wpa_supplicant) instead of letting it negotiate one from whatever the
  RADIUS server offers. No CA certificate is still accepted (with a
  logged warning) for guest/captive EAP deployments that genuinely have
  nothing to pin, but this is the one Enterprise configuration that's
  meaningfully *less* safe to use than PSK, since it means the RADIUS
  server's identity goes unverified.
- **OpenVPN session tracking** (`vpn/openvpn.rs`): tracks sessions
  through OpenVPN's own management interface rather than just a `Child`
  handle. mitos-network binds the management socket itself and passes
  `--management-client` so openvpn connects *out* to it (no race
  against polling for a socket file openvpn hasn't created yet), reads
  the live `>STATE:` event feed for real connection status
  (`openvpn::status`), and captures the real tun/tap interface name via
  a tiny generated `--up` script (OpenVPN's own official mechanism for
  reporting it, through the `$dev` environment variable). `disconnect`
  sends `signal SIGTERM` over the management connection rather than
  killing whatever process the initial `Child` handle happens to point
  at, which --daemon's re-exec makes unreliable.
- **PAC-based proxy auto-config** (`proxy/pac.rs`, `proxy/proxy.rs`):
  fetches the PAC script over plain HTTP and actually evaluates
  `FindProxyForURL()` via a small hand-rolled interpreter for the
  subset of JavaScript real-world PAC scripts use (`var`, `if`/`else`,
  `return`, string/number/boolean literals and concatenation,
  comparisons, `&&`/`||`/`!`, function declarations/calls), plus the
  standard PAC helper functions (`isPlainHostName`, `dnsDomainIs`,
  `isResolvable`, `dnsResolve`, `myIpAddress`, `isInNet`, `shExpMatch`,
  `weekdayRange`/`dateRange`/`timeRange`, `alert`) implemented natively.
  `proxy::resolve_for_url` is the real interface for `Auto` mode (a
  static shell env var fundamentally can't represent "the proxy depends
  on which URL you're asking about"); it's wired through
  `ipc::messages::Request::{SetProxyConfig,GetProxyConfig,ResolveProxy}`
  and `mitos-netctl proxy {show,resolve,set}`. The whole proxy
  subsystem was previously unreachable from anything outside its own
  module (the same issue Bluetooth had, see below) -- fixed as part of
  this work, not just the PAC evaluation itself. Deliberately not
  supported: loops, arrays/objects, and general JS beyond the above
  (untrusted, network-supplied script content -- without loops, every
  script this interpreter accepts is statically guaranteed to
  terminate); `weekdayRange`/`dateRange`/`timeRange` use UTC rather
  than the client's local time zone, since correct local-time handling
  needs a tzdata parser this crate doesn't carry.
- **nftables ruleset generation** (`firewall/nftables.rs`), applied via
  `nft -f`.

## Deliberate stubs / not started

- **BlueZ D-Bus API**: `bluetooth/` shells out to `bluetoothctl`/`bt-network`
  rather than talking to `org.bluez` over D-Bus, to avoid a D-Bus client
  dependency. Worth revisiting if mitosOS ends up with a D-Bus story anyway
  (see [[mitos-session]]). This module is fully wired up through
  `ipc::messages` and `mitos-netctl bluetooth ...` (list/power/scan/
  pair/trust/connect/disconnect/remove) -- the D-Bus-vs-`bluetoothctl`
  question is just an implementation detail of an already-usable feature.
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
The PAC fetcher (`proxy::pac::fetch`) is plain-HTTP-only for a related but
different reason: it has no TLS client at all, and PAC/WPAD deployment is
overwhelmingly plain HTTP by convention anyway.

## Testing

Given no Rust toolchain was available while writing this (see the top-level
README), every module's logic was manually reviewed for brace/paren balance
and cross-module symbol references, but **nothing here has been compiled or
run**. `tests/` and inline `#[cfg(test)]` modules (notably
`vpn::wireguard`, `dhcp::dhcp6`, and `proxy::pac`, the three most
protocol-detail-heavy additions) cover what can be tested without root,
real hardware, or a running `wpa_supplicant`/`hostapd`/`nft`/kernel-with-
CAP_NET_ADMIN: pure packet (de)serialization, address/sockaddr-layout math,
config/profile persistence round-trips, rule-rendering output, and (new)
PAC script evaluation against known scripts/inputs. It does not cover the
actual netlink/generic-netlink/DHCP-socket/wpa_supplicant-socket/openvpn-
management-socket/nft-invocation code paths -- that needs a real Linux box,
root, and (ideally) a VM with a spare network interface to test against
safely. **Running a real `cargo build` on such a machine is the necessary
next step this session couldn't take.**
