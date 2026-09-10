# Security model

## Secrets: never in connection profiles

`connection::profile::ConnectionProfile` (the on-disk, TOML,
`data/profiles/<id>.toml` representation of a saved connection) never
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
(`<data-dir>/audit.log`) for security-relevant actions -- currently just
connection activation, with `actor=uid:<n> action=connection.activate
detail=<profile> on <device>` lines. Deliberately kept separate from the
regular daemon log (`logging::logger`) so it can be shipped/rotated/reviewed
independently of routine operational chatter. Extending it to cover
firewall rule changes, Wi-Fi credential changes, and VPN session
start/stop is a natural next step -- the `AuditLog::record` call is already
a one-line addition wherever it's needed.
