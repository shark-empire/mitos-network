# Security model

## Secrets: never in connection profiles

`connection::profile::ConnectionProfile` (the on-disk, TOML,
`<data-dir>/profiles/<id>.toml` representation of a saved connection) never
contains a password, PSK, or private key -- only a `has_secret: bool` flag.
Every secret lives in `security::secrets` instead, keyed by the profile's
id. This is deliberate: a profile file is the kind of thing a user might
`cat`, back up, version-control, or paste into a bug report, and NetworkManager's
early history of storing Wi-Fi passwords in plaintext keyfiles is exactly the
mistake this split avoids repeating.

### The current backend is an interim measure

`security::secrets::FileSecretsBackend` stores each secret as a single
`0600`-permission file under `<data-dir>/secrets/`, root-owned. This is
*safe* (no world/group access, atomic writes) but is not the intended
long-term design. The `SecretsBackend` trait exists specifically so this can
be swapped for a real secrets service -- `mitos-auth` (the sibling daemon
mentioned in this project's own notes) or a desktop keyring -- by changing
one line in `manager::manager::NetworkManager::new` (where the backend is
constructed) rather than anything in `connection::activation` or the IPC
layer, both of which only ever see `&dyn SecretsBackend`.

## IPC authorization

See `docs/ipc.md`'s Authorization section. Short version: read-only queries
are open to any local user; anything that changes network state needs root
or `netdev` group membership; daemon-config reload needs root.

## Input validation

Everything that ends up embedded in a config file for another process to
parse -- an SSID or passphrase into wpa_supplicant's config, an interface
name into a `hostapd.conf` or nftables ruleset, a connection/profile id into
a filename -- goes through `security::validation` first
(`validate_ssid`, `validate_wpa_passphrase`, `validate_interface_name`,
`validate_identifier`). This is a real injection-prevention boundary, not
just input sanity-checking: an unchecked identifier used to build a
filesystem path is a path-traversal vector, and an unchecked string spliced
into a generated config file is a config-injection vector.

## Process privilege

mitos-network runs as root (see `services/mitos-network.service`) because
essentially everything it does requires it on stock Linux: rtnetlink
link/address/route changes, binding raw sockets on port 68/546 for DHCP,
`nft`, and `sethostname(2)`. The shipped systemd unit sets
`AmbientCapabilities`/`CapabilityBoundingSet` to the specific capabilities
actually needed (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`,
plus `CAP_SYS_ADMIN` for `sethostname`) as a starting point for tightening
this further, along with `ProtectSystem=strict` and a narrow
`ReadWritePaths`. Dropping to a genuinely unprivileged worker process for
the parts that don't need root (the IPC server's read-only query handling,
for instance) is a reasonable future hardening step, not something this
first pass attempts.

## Audit log

`logging::audit` writes a separate, append-only, `0600`-permission log
(`<data-dir>/audit.log`) for security-relevant actions, with
`actor=uid:<n> action=<action> detail=<detail>` lines. Deliberately kept
separate from the regular daemon log (`logging::logger`) so it can be
shipped/rotated/reviewed independently of routine operational chatter.

`actor` is the resolved IPC peer's uid (via `SO_PEERCRED`,
`ipc::permissions`), threaded through `Command::Request` into
`NetworkManager::handle_request` -- **not** the manager process's own uid.
An earlier version of this code recorded `getuid()` of the daemon itself
here, which on a `User=root` service means every line said `uid:0`
regardless of which actual user asked for the change; fixed so the log is
actually useful for "who did this" on a multi-user machine. Actions
triggered by the daemon's own autoconnect logic (not a specific IPC
request) record `actor=system:autoconnect` instead.

Covered actions: `connection.add`, `connection.delete`,
`connection.activate`, `connection.deactivate`, `wifi.connect`,
`wifi.forget`, `hotspot.start`, `hotspot.stop`, `firewall.zone`,
`firewall.rule.add`, `firewall.rule.remove`, `bluetooth.power`,
`bluetooth.pair`, `bluetooth.trust`, `bluetooth.connect`,
`bluetooth.disconnect`, `bluetooth.remove`, `config.reload`. Read-only
requests (`GetState`, `ListDevices`, Wi-Fi/Bluetooth scans, ...) are
deliberately not logged -- this is an audit trail for changes, not an
access log. VPN session start/stop is covered indirectly today, via the
generic `connection.activate`/`connection.deactivate` entries for a VPN
profile; a VPN-specific action name (distinguishing it from an ordinary
interface activation) is a reasonable follow-up.

## Resource limits (IPC)

The IPC socket is `0666` -- any local user can open a connection, whether
or not they hold any `Capability` (see above). Without a cap, that alone
is a denial-of-service primitive: open connections in a loop and never
send anything, and each one costs the daemon a thread indefinitely.
`ipc::server` bounds this two ways: at most `MAX_CONNECTIONS` (128)
connections at once (past that, a new connection is refused before a
thread is even spawned), and each connection's thread gets a 256 KiB
stack instead of the 8 MiB default (request handling here is shallow --
parse JSON, one channel round-trip, write JSON back -- with no deep
recursion). The per-message size cap (`ipc::protocol::MAX_MESSAGE_LEN`)
is 1 MiB, checked before the receive buffer is allocated, for the same
reason: real messages here are a few KiB at most.

Event delivery (`manager::events::EventBus`) is similarly bounded: each
connected client's event queue is a bounded channel, and a client that
isn't draining its events (a frozen process, or a socket whose peer
never reads) has new events dropped for it rather than growing the
daemon's memory without limit or blocking the single-threaded manager
loop that broadcasts them.

## Temp files and subprocess secrets

WireGuard's private key, OpenVPN's `auth-user-pass` file, and the
wpa_supplicant control-socket client path all need *some* path on disk
(none of the three tools involved accept the underlying data via stdin
or a file descriptor for these particular purposes). `security::tempfile`
generates these with a 128-bit random name and creates them with
`O_CREAT|O_EXCL` semantics (`create_new`) and mode `0600` set atomically
at creation, rather than a predictable name plus `create()`+chmod: the
latter both lets another local user pre-place a symlink at a guessed
path (which `create()` would happily follow) and leaves a brief window
where the file exists with a more permissive default mode before the
chmod lands. `PrivateTmp=true` in the shipped unit file already isolates
`/tmp` per-service, which independently blocks this; the fixes here mean
the code doesn't *rely* on that setting being in place. The nftables
ruleset has the same shape of problem solved a different way: it's piped
to `nft -f -` on stdin instead of ever touching a temp file at all.

`AddFirewallRule`'s `source` field and `SetFirewallZone`'s `interface`
are both reachable by any `netdev`-group caller (not just root) and end
up interpolated into generated nftables ruleset text -- both are now
validated (a real CIDR, and `security::validation::validate_interface_name`
respectively) before being accepted, so a rule can't break out of its
intended `ip saddr <src>`/`iifname { ... }` expression and inject
arbitrary additional ruleset text. `wifi::wpa::WpaCtrl::set_network_quoted`
similarly rejects a value containing a quote or backslash before it goes
into a `SET_NETWORK ... "<value>"` control command -- relevant because an
SSID is attacker-broadcastable (any nearby AP can advertise one), not
just user-typed.
