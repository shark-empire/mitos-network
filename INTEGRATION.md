# Integrating with mitos-network

mitos-network is a standalone daemon, not a library other mitosOS
components link into for their own logic. Everything it does (bringing up
interfaces, joining Wi-Fi networks, managing the firewall) happens inside
the one `mitos-network` process; other components integrate with it the
same way `mitos-netctl` does -- as a client of its IPC protocol.

## 1. Talking to the daemon from Rust

If the calling component is Rust (`mitos-gui`, `mitos-shell`, a future
`mitos-utils` network applet), add this crate as a path dependency and use
its `ipc` module directly rather than re-implementing the wire format:

```toml
# in the other crate's Cargo.toml
mitos-network = { path = "../mitos-network" }
```

```rust
use mitos_network::ipc::client::Client;
use mitos_network::ipc::messages::{Request, Response};
use mitos_network::config;

let mut client = Client::connect(config::defaults_socket_path())?;
match client.request(Request::GetState)? {
    Response::State(state) => { /* ... */ }
    Response::Error(msg) => { /* ... */ }
    _ => unreachable!(),
}
```

`Client` is a blocking client (one `TcpStream`-equivalent `UnixStream`
connection, one request in flight at a time per connection) -- open one
long-lived connection per component rather than reconnecting per request,
since that's also how event delivery works (see below).

### Receiving live updates (a network status indicator, etc.)

Every connection implicitly receives the daemon's broadcast `Event` stream
for as long as it stays open -- there's no separate subscribe call. A
component that wants to react to state changes (a desktop shell's Wi-Fi
icon, for instance) should keep one connection open and call
`Client::next_event()` in a loop on a dedicated thread, while using a
*separate* connection for on-demand `request()` calls (mixing the two
patterns on one connection is possible -- `request()` already knows to skip
over interleaved `Event`s -- but a separate connection per concern keeps the
calling code simpler). See `docs/ipc.md` for the full `Event` enum.

## 2. Talking to the daemon from anything else

The wire protocol (`docs/ipc.md`) is deliberately simple -- a 4-byte
little-endian length prefix plus that many bytes of JSON, over a Unix
socket at `general.socket-path` (default `/run/mitos-network/network.sock`)
-- specifically so a non-Rust component doesn't need a copy of this crate's
type definitions, just a length-prefixed-JSON reader/writer and the message
shapes documented in `docs/ipc.md` / `src/ipc/messages.rs`.

Simplest of all: shell out to `mitos-netctl` and parse its (JSON, for
anything beyond a bare `OK`) stdout. This is the lowest-effort integration
path and is perfectly fine for anything that doesn't need live event
updates.

## 3. Specific mitosOS components

- **mitos-gui**: the natural integration point is a status-bar network
  indicator -- connect once at startup, render from `Request::GetState` /
  `Request::ListDevices` initially, then update live from the `Event`
  stream. A Wi-Fi picker UI would drive `Request::ScanWifi` /
  `Request::ListWifiNetworks` / `Request::ConnectWifi`. Not implemented in
  this session -- this document describes the integration surface, not a
  finished mitos-gui feature.
- **mitos-session**: no direct integration today. The two daemons don't
  currently need to coordinate (mitos-network doesn't gate on user login,
  and mitos-session doesn't need network state for lock/idle/auth policy).
  If that changes -- e.g. "lock the screen when leaving a trusted Wi-Fi
  network" -- that policy belongs in mitos-session, consuming
  mitos-network's `Event` stream as one more input, the same way it already
  reads `HotplugEvent`-style updates from other sources.
- **mitos-shell / mitos-utils**: no network-aware utilities exist in
  mitos-utils yet (per its own docs, its `ps`/`free`/etc. utilities are
  written against the Linux interface as a spec for mitosOS's future
  userspace syscalls, not integrated with mitos-network). A future
  `mitos-utils` applet wanting network info should shell out to
  `mitos-netctl`, the same as any other external tool, rather than linking
  this crate directly -- mitos-utils' own architecture deliberately stays
  at zero (or near-zero) dependencies.
- **mitosOS kernel**: mitos-network is, like `mitos-utils` and
  `mitos-shell`, written against a **hosted Linux environment** (real
  `AF_NETLINK` sockets, a real `/sys/class/net`, a real `wpa_supplicant`/
  `hostapd`/`nft`), not mitosOS's own freestanding kernel. mitosOS's kernel
  currently has no equivalent networking syscalls, netlink-like IPC, or
  userspace socket API of its own (see `mitos-utils`' own architecture
  notes for the same gap in a different subsystem). Every "shell out to
  `nft`", "raw `AF_NETLINK` socket", and "`SO_BINDTODEVICE` UDP socket" in
  this codebase is implicitly a specification for what mitosOS's kernel
  will eventually need to expose if mitos-network is ever ported to run on
  it directly, rather than on Linux.

## 4. Service startup ordering

`services/mitos-network.service` starts after `network-pre.target` (the
kernel networking stack existing) and before `network.target` (the point at
which other services expect network *configuration* to be underway). It
doesn't depend on `mitos-session` or `mitos-gui`, and neither of those
should need to depend on it at the systemd level -- the IPC-connection
retry a client does on `Client::connect` failing is the right way to
handle "mitos-network isn't up yet", not a `Wants=`/`After=` ordering.
