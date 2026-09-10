//! Bluetooth device management (`bluetooth`) and PAN tethering
//! (`tethering`). mitos-network doesn't speak the Bluetooth protocol
//! stack itself -- BlueZ (`bluetoothd`) already owns that, the same
//! division of labor as Wi-Fi/wpa_supplicant.
//!
//! Driven via `bluetoothctl`'s non-interactive single-command mode
//! (BlueZ 5.65+) rather than BlueZ's D-Bus API directly, keeping this
//! module dependency-free the same way the rest of mitos-network is --
//! a D-Bus client crate would be the one dependency pulled in solely
//! for this module. Noted as a reasonable future upgrade in
//! `docs/networking.md` if mitosOS ends up with a D-Bus story anyway
//! (mitos-session already uses one, per its own architecture).

pub mod bluetooth;
pub mod tethering;
