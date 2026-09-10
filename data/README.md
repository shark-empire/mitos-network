# This directory is illustrative, not runtime state

Nothing under `data/` in this repository is ever read or written by the
daemon. At runtime, mitos-network uses `general.data-dir` from
`config/network.toml`, which defaults to:

```
/var/lib/mitos-network/
```

(see `DEFAULT_DATA_DIR` in `src/config/defaults.rs` -- that constant, not
this directory, is what a real install actually uses).

This `data/` tree exists purely so the *shape* of that runtime directory is
visible in the repository, matching the layout given when this project was
first scoped:

```
data/
├── profiles/ connection profiles: one <id>.toml per saved connection
│ (see connection::profile::ConnectionProfile;
│ persistence::profiles reads/writes this directory)
├── leases/ DHCP leases: one <interface>.json per interface with an
│ active lease (see dhcp::Lease; persistence::state
│ reads/writes this directory)
└── secrets/ Wi-Fi/VPN secrets: one 0600 file per (profile, key) pair
(see security::secrets::FileSecretsBackend -- an interim
backend, not the intended long-term design; see
docs/security.md)
```

Each subdirectory contains only a `.gitkeep` placeholder here. Real content
(actual profiles, leases, secret files) only ever appears under whatever
`general.data-dir` resolves to on a running system, and `.gitignore` is set
up so that if you point a local `--config-dir` at this checkout for testing,
anything real that lands in these three subdirectories stays untracked.

## Local development

If you want a daemon run against this checkout to actually populate this
folder instead of `/var/lib/mitos-network` (handy for testing without
root), set `general.data-dir` in your own config directory's
`network.toml` to an absolute path pointing here, e.g.:

```toml
[general]
data-dir = "/home/you/mitos-network/data"
```

then run `mitos-network --config-dir /path/to/that/config`. There's no
"repo-relative by default" behavior in the daemon itself -- the default is
always the FHS path above, on purpose, so a real system install behaves the
same way regardless of where the source happened to be built.
