# IPC protocol

## Transport

A Unix domain socket at `general.socket-path` (default
`/run/mitos-network/network.sock`), mode `0666` at the socket-file level
(finer-grained authorization happens per-request, see below -- the socket
itself being world-connectable is what lets an unprivileged desktop session
read state and, e.g., join a Wi-Fi network without a `sudo` prompt, the same
UX every mainstream desktop network manager provides).

## Framing

Every message (in either direction) is:

```
+----------------------+----------------------------+
| length: u32, little- | that many bytes of JSON |
| endian (4 bytes) | |
+----------------------+----------------------------+
```

JSON, not a binary format, so that a shell script or a tool written in
anything else can speak this protocol with nothing more than a
length-prefixed-JSON reader -- no shared Rust type definitions required.
Messages are capped at 16 MiB.

## Message shapes

See `src/ipc/messages.rs` for the authoritative definitions (they're plain
Rust enums with `#[derive(Serialize, Deserialize)]`; serde's default
representation for an enum variant with named fields is a single-key JSON
object, e.g. `{"ActivateConnection":{"id":"home-wifi"}}`).

- **`Request`** -- sent client -> daemon. One request, one reply.
- **`Response`** -- sent daemon -> client, always exactly one per `Request`.
- **`Event`** -- sent daemon -> client, unsolicited, any time after the
connection is established (there's no separate subscribe step -- every
connection implicitly receives every broadcast event for as long as it
stays open).
- **`ServerMessage`** -- the actual top-level type on the wire from the
daemon's side: `{"Response": ...}` or `{"Event": ...}`. A client waiting
on a `Response` to a specific request it just sent should skip over any
`Event`s it reads in the meantime (`ipc::client::Client::request` does
exactly this).

## Authorization

Every `Request` maps to a `security::policy::Capability`
(`ipc::server::required_capability`). On each new connection, the daemon
resolves the peer's `uid`/`gid` via `SO_PEERCRED` and checks it against the
capability the specific request needs:

| Capability | Who's allowed |
|---|---|
| `ViewState` (read-only queries) | anyone |
| `ManageConnections`, `ManageWifi`, `ManageFirewall`, `ManageHotspot` | root, or a member of the `netdev` group |
| `Admin` (config reload) | root only |

This is the same trust model as the traditional `netdev`/`wheel` group
convention: a logged-in desktop user shouldn't need a password prompt to
join a Wi-Fi network, but shouldn't be able to reload the daemon's
configuration out from under a multi-user machine either.

## `mitos-netctl`

The reference client. `mitos-netctl <noun> <verb> [args...]` -- run it with
no arguments (or `--help`, once that's wired up beyond the current bare
usage string) to see the full command list. Every subcommand is a thin
one-request-one-response wrapper; `mitos-netctl monitor` is the one
exception, looping on `Client::next_event` to print the daemon's event
stream live.
