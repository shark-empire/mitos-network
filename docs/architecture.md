# mitos-network architecture

## The one rule

**mitos-network does not implement TCP/IP.** The Linux kernel already has a
complete, battle-tested networking stack: interfaces, addresses, routes,
sockets, drivers. mitos-network is the *policy and management layer* on top
of it -- the same role NetworkManager, systemd-networkd, and ConnMan play on
other Linux systems.

```
                 MITOS
                   |
             mitos-network
                   |
       +-----------+-----------+
       |           |           |
    Ethernet      Wi-Fi       VPN
       |           |           |
       +-----------+-----------+
                   |
              Linux kernel
                   |
             network drivers
                   |
             network hardware
```

Concretely, this split shows up as:

| Concern              | Who owns it                                   |
|-----------------------|-----------------------------------------------|
| Packet forwarding, TCP/IP state machines, sockets | Linux kernel |
| Interfaces, addresses, routes | Linux kernel, driven via `AF_NETLINK` (`src/ip/netlink.rs`) |
| Wi-Fi association, WPA/WPA3 crypto | `wpa_supplicant` (driven via its control socket, `src/wifi/wpa.rs`) |
| Access-point mode | `hostapd` (`src/wifi/hotspot.rs`) |
| DHCP client protocol | mitos-network itself (`src/dhcp/`) -- Linux has no built-in DHCP client |
| Firewall rule compilation | `nft`, driven via generated rulesets (`src/firewall/nftables.rs`) |
| WireGuard crypto/handshake | the kernel's WireGuard module + the `wg` tool (`src/vpn/wireguard.rs`) |
| OpenVPN | the `openvpn` binary (`src/vpn/openvpn.rs`) |
| Bluetooth stack | BlueZ, via `bluetoothctl`/`bt-network` (`src/bluetooth/`) |

## Process model

One daemon process, `mitos-network`, running as a single Rust binary with
several threads:

- **The manager thread** (`manager::manager::NetworkManager::run`) is the
  only thread that ever touches device/connection/firewall state. Every
  other thread only ever sends it a `manager::Command` over an `mpsc`
  channel and waits for a reply if it needs one. This mirrors the design
  principle [[mitos-session]] documents for its own architecture:
  single-threaded core, other threads only move bytes.
- **One thread per IPC connection** (`ipc::server`), each split into a
  request/response loop (blocking read of the client's socket half) and a
  small event-forwarding thread (relays the manager's broadcast `Event`s to
  that client).
- **The hotplug monitor thread** (`device::discovery::spawn_monitor`), which
  blocks on a netlink multicast socket and forwards link/address change
  notifications.
- **Scheduler threads** (`manager::scheduler`), one per periodic job
  (connectivity check, Wi-Fi scan, DHCP lease renewal check, a fallback
  device-state poll) -- each just sleeps and sends a `Command::Tick`.
- **A signal-watcher thread**, since the actual `SIGTERM`/`SIGINT` handler
  only sets an atomic flag (the only thing safe to do inside a signal
  handler) and this thread turns that into a clean `Command::Shutdown`.

`mitos-netctl` is a separate, short-lived binary: it connects to the
daemon's Unix socket, sends one request (or, for `monitor`, loops reading
events), prints the result, and exits.

## Module map

- `ip/` -- the netlink client (`netlink.rs`, private) and the public
  policy surface on top of it: `interface`, `address`, `route`, `neighbor`,
  `ipv4`/`ipv6` math, and `monitor` (the multicast-socket wrapper the
  hotplug monitor uses).
- `device/` -- what interfaces exist and what kind/state they're in.
  `discovery` classifies interfaces (loopback / physical Ethernet / Wi-Fi /
  virtual-by-`IFLA_LINKINFO`-kind) and runs the hotplug monitor;
  `manager` is the in-memory registry.
- `ethernet/` -- `ETHTOOL` ioctls for driver-level link speed/duplex/carrier,
  layered on top of `device`/`ip`.
- `wifi/` -- `wpa.rs` is the wpa_supplicant control-socket client; `wifi.rs`
  is the connect/disconnect orchestration `connection::activation` calls;
  `scanner`, `network`, `security`, `roaming` are the supporting policy;
  `hotspot.rs` drives `hostapd` for AP mode.
- `dhcp/` -- a real DHCPv4 client (full DISCOVER/OFFER/REQUEST/ACK) and a
  lighter stateless-only DHCPv6 client (see `docs/networking.md` for what's
  not covered).
- `dns/` -- writes `/etc/resolv.conf`, merges DNS servers from multiple
  active connections by priority, hostname get/set, a small TTL cache, and
  fallback-server logic.
- `connection/` -- `profile.rs` is the persisted "thing you connect to";
  `activation`/`deactivation` orchestrate device+ip+dhcp+dns+routing+wifi/vpn
  for one profile; `autoconnect` picks which profile to activate.
- `routing/` -- default-route installation, per-device-type metric
  assignment (`metrics.rs`, so Ethernet always beats Wi-Fi which always
  beats Bluetooth, with VPNs preferred over all of them), and FIB-rule-based
  policy routing for split-tunnel VPNs.
- `vpn/` -- WireGuard (netlink link creation + `wg` for crypto params) and
  OpenVPN (process supervision).
- `firewall/` -- a small zone/rule model rendered to nftables syntax and
  applied via `nft -f`.
- `sharing/` -- internet connection sharing: a hand-rolled DHCP *server*
  (reusing `dhcp::dhcp4`'s packet code) plus NAT/forwarding via `firewall`.
- `bluetooth/` -- device pairing/connection via `bluetoothctl`, PAN
  tethering via `bt-network`.
- `connectivity/` -- the internet-reachability HTTP probe and captive-portal
  classification.
- `security/` -- capability-based authorization for IPC requests, input
  validation shared by everything that generates a config file for another
  process, and the secrets-storage trait (see `docs/security.md`).
- `ipc/` -- the wire protocol, Unix-socket server/client, and
  `SO_PEERCRED`-based peer identification.
- `persistence/` -- connection profiles and DHCP lease state on disk.
- `manager/` -- the coordinator described above.
- `monitoring/` -- read-only health/diagnostics reporting.
- `logging/` -- daemon log + a separate security audit log.
- `config/` -- daemon configuration (`network.toml`/`interfaces.toml`/
  `dns.toml`/`wireless.toml`), distinct from connection profiles.
