use super::events::EventBus;
use super::state::{overall_state, NetworkState};
use crate::config::NetworkConfig;
use crate::connection::{profile::ConnectionProfile, ActiveConnection};
use crate::connectivity::ConnectivityState;
use crate::device::{discovery::HotplugEvent, DeviceRegistry, DeviceState, DeviceType};
use crate::errors::{NetworkError, Result};
use crate::firewall::Firewall;
use crate::ipc::messages::{Event, Request, Response};
use crate::security::secrets::{FileSecretsBackend, SecretsBackend};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickKind {
    Connectivity,
    WifiScan,
    LeaseCheck,
    DeviceRefresh,
}

pub enum Command {
    Request(Request, Sender<Response>),
    RegisterEventClient(Sender<(u64, std::sync::mpsc::Receiver<Event>)>),
    UnregisterEventClient(u64),
    Hotplug(HotplugEvent),
    Tick(TickKind),
    Shutdown,
}

pub struct NetworkManager {
    config: NetworkConfig,
    profiles_dir: PathBuf,
    devices: DeviceRegistry,
    connections: Vec<ConnectionProfile>,
    active: HashMap<String, ActiveConnection>,
    secrets: Box<dyn SecretsBackend>,
    firewall: Firewall,
    dns_registry: crate::dns::servers::DnsServerRegistry,
    connectivity: ConnectivityState,
    events: EventBus,
    audit: crate::logging::audit::AuditLog,
}

impl NetworkManager {
    pub fn new(config: NetworkConfig) -> Result<Self> {
        let data_dir = PathBuf::from(&config.general.data_dir);
        crate::persistence::state::init(&data_dir);
        crate::wifi::wifi::init(&config.wireless.ctrl_interface_dir);
        crate::logging::logger::set_level(&config.general.log_level);

        let profiles_dir = data_dir.join("profiles");
        let connections = crate::persistence::profiles::load_all(&profiles_dir)?;
        let secrets: Box<dyn SecretsBackend> = Box::new(FileSecretsBackend::new(&data_dir));
        let audit = crate::logging::audit::AuditLog::new(data_dir.join("audit.log"));

        let mut devices = DeviceRegistry::new();
        devices.refresh(&config.general.unmanaged_devices)?;

        let mut firewall = Firewall::new();
        for dev in devices.all() {
            let _ = firewall.ensure_default_zone(&dev.name);
        }

        crate::dns::resolver::apply_from_config(&config.dns).ok();

        Ok(NetworkManager {
            config,
            profiles_dir,
            devices,
            connections,
            active: HashMap::new(),
            secrets,
            firewall,
            dns_registry: crate::dns::servers::DnsServerRegistry::default(),
            connectivity: ConnectivityState::Unknown,
            events: EventBus::new(),
            audit,
        })
    }

    pub fn run(mut self, rx: Receiver<Command>) {
        crate::logging::logger::info("mitos-network manager started");
        self.try_autoconnect_all();
        for cmd in rx.iter() {
            match cmd {
                Command::Request(req, resp_tx) => {
                    let resp = self.handle_request(req);
                    let _ = resp_tx.send(resp);
                }
                Command::RegisterEventClient(reply_tx) => {
                    let (id, internal_rx) = self.events.register();
                    let _ = reply_tx.send((id, internal_rx));
                }
                Command::UnregisterEventClient(id) => self.events.unregister(id),
                Command::Hotplug(ev) => self.handle_hotplug(ev),
                Command::Tick(kind) => self.handle_tick(kind),
                Command::Shutdown => break,
            }
        }
        crate::logging::logger::info("mitos-network manager stopped");
    }

    fn broadcast_state(&mut self) {
        let devices: Vec<_> = self.devices.all().cloned().collect();
        let state = overall_state(&devices, self.connectivity);
        self.events.broadcast(Event::StateChanged(state));
    }

    fn handle_hotplug(&mut self, ev: HotplugEvent) {
        match ev {
            HotplugEvent::LinkAdded(name) => {
                let _ = self.devices.refresh(&self.config.general.unmanaged_devices.clone());
                let _ = self.firewall.ensure_default_zone(&name);
                if let Some(dev) = self.devices.get(&name) {
                    self.events.broadcast(Event::DeviceAdded(dev.clone()));
                }
                self.try_autoconnect(&name);
            }
            HotplugEvent::LinkRemoved(name) => {
                self.active.remove(&name);
                self.devices.remove(&name);
                self.events.broadcast(Event::DeviceRemoved(name));
            }
            HotplugEvent::LinkChanged(name) | HotplugEvent::AddressChanged(name) => {
                let _ = self.devices.refresh(&self.config.general.unmanaged_devices.clone());
                if let Some(dev) = self.devices.get(&name) {
                    self.events.broadcast(Event::DeviceStateChanged { device: name, state: dev.state });
                }
            }
        }
        self.broadcast_state();
    }

    fn handle_tick(&mut self, kind: TickKind) {
        match kind {
            TickKind::Connectivity => {
                let url = self.config.general.connectivity_check_url.clone();
                let new_state = crate::connectivity::checker::check(&url, Duration::from_secs(5))
                    .unwrap_or(ConnectivityState::Unknown);
                if new_state != self.connectivity {
                    self.connectivity = new_state;
                    self.events.broadcast(Event::ConnectivityChanged(new_state));
                    self.broadcast_state();
                }
            }
            TickKind::WifiScan => {
                let wifi_devices: Vec<String> = self
                    .devices
                    .all()
                    .filter(|d| d.device_type == DeviceType::WiFi && d.state != DeviceState::Unmanaged)
                    .map(|d| d.name.clone())
                    .collect();
                for name in wifi_devices {
                    self.try_autoconnect(&name);
                }
            }
            TickKind::LeaseCheck => {
                for (device_name, active) in self.active.clone() {
                    if active.state != crate::connection::ActiveConnectionState::Activated {
                        continue;
                    }
                    if let Ok(Some(lease)) = crate::persistence::state::load_lease(&device_name) {
                        if std::time::SystemTime::now() >= lease.renewal_time() {
                            if let Ok(new_lease) = crate::dhcp::client::renew(&device_name, &lease) {
                                let _ = crate::persistence::state::save_lease(&device_name, &new_lease);
                            }
                        }
                    }
                }
            }
            TickKind::DeviceRefresh => {
                let _ = self.devices.refresh(&self.config.general.unmanaged_devices.clone());
                let names: Vec<String> = self.devices.all().map(|d| d.name.clone()).collect();
                for name in names {
                    self.try_autoconnect(&name);
                }
            }
        }
    }

    /// Attempts autoconnect on every currently-known device -- called
    /// once at startup.
    fn try_autoconnect_all(&mut self) {
        let names: Vec<String> = self.devices.all().map(|d| d.name.clone()).collect();
        for name in names {
            self.try_autoconnect(&name);
        }
    }

    fn try_autoconnect(&mut self, device_name: &str) {
        let Some(device) = self.devices.get(device_name) else { return };
        if device.state == DeviceState::Unmanaged || device.active_connection.is_some() {
            return;
        }
        if !matches!(device.state, DeviceState::Disconnected | DeviceState::Unavailable) {
            return;
        }

        let sorted = crate::persistence::profiles::recently_used_first(&self.profiles_dir, self.connections.clone());

        let chosen = if device.device_type == DeviceType::WiFi {
            if !device.carrier {
                return; // radio not associated to anything to scan against yet handled by wpa_supplicant itself
            }
            let visible = crate::wifi::scanner::last_results(&self.config.wireless.ctrl_interface_dir, device_name)
                .map(|nets| nets.into_iter().map(|n| n.ssid).collect::<Vec<_>>())
                .unwrap_or_default();
            crate::connection::autoconnect::select_wifi(device, &sorted, &visible).cloned()
        } else {
            if !device.carrier {
                return;
            }
            crate::connection::autoconnect::select(device, &sorted).cloned()
        };

        if let Some(profile) = chosen {
            self.activate_profile(&profile.id);
        }
    }

    fn find_device_for_profile(&self, profile: &ConnectionProfile) -> Option<String> {
        self.devices
            .all()
            .find(|d| {
                d.device_type == profile.device_type
                    && d.active_connection.is_none()
                    && profile.interface_name.as_deref().map(|n| n == d.name).unwrap_or(true)
            })
            .map(|d| d.name.clone())
    }

    fn activate_profile(&mut self, profile_id: &str) -> Response {
        let Some(profile) = self.connections.iter().find(|p| p.id == profile_id).cloned() else {
            return Response::Error(format!("no such connection profile '{profile_id}'"));
        };
        let Some(device_name) = self.find_device_for_profile(&profile) else {
            return Response::Error(format!("no available {} device for '{profile_id}'", profile.device_type));
        };
        let Some(device) = self.devices.get_mut(&device_name) else {
            return Response::Error(format!("device '{device_name}' disappeared"));
        };

        match crate::connection::activation::activate(&profile, device, self.secrets.as_ref()) {
            Ok(active) => {
                let state = device.state;
                self.active.insert(device_name.clone(), active);
                let _ = crate::persistence::profiles::touch(&self.profiles_dir, profile_id);
                self.audit.record(&format!("uid:{}", nix_uid()), "connection.activate", &format!("{profile_id} on {device_name}"));
                self.events.broadcast(Event::DeviceStateChanged { device: device_name.clone(), state });
                self.events.broadcast(Event::ConnectionActivated(profile_id.to_string()));
                self.broadcast_state();
                Response::Ok
            }
            Err(e) => {
                device.state = DeviceState::Failed;
                Response::Error(format!("activation failed: {e}"))
            }
        }
    }

    fn deactivate_profile(&mut self, profile_id: &str) -> Response {
        let Some((device_name, _)) = self.active.iter().find(|(_, a)| a.profile_id == profile_id).map(|(n, a)| (n.clone(), a.clone())) else {
            return Response::Error(format!("connection '{profile_id}' is not active"));
        };
        let Some(mut active) = self.active.remove(&device_name) else {
            return Response::Error("internal state inconsistency".into());
        };
        let Some(device) = self.devices.get_mut(&device_name) else {
            return Response::Error(format!("device '{device_name}' disappeared"));
        };
        match crate::connection::deactivation::deactivate(&mut active, device) {
            Ok(()) => {
                self.events.broadcast(Event::ConnectionDeactivated(profile_id.to_string()));
                self.broadcast_state();
                Response::Ok
            }
            Err(e) => Response::Error(format!("deactivation failed: {e}")),
        }
    }

    fn handle_request(&mut self, req: Request) -> Response {
        match req {
            Request::GetState => {
                let devices: Vec<_> = self.devices.all().cloned().collect();
                Response::State(overall_state(&devices, self.connectivity))
            }
            Request::ListDevices => Response::Devices(self.devices.all().cloned().collect()),
            Request::GetDevice { name } => self
                .devices
                .get(&name)
                .cloned()
                .map(Response::Device)
                .unwrap_or_else(|| Response::Error(format!("no such device '{name}'"))),
            Request::ListConnections => Response::Connections(self.connections.clone()),
            Request::GetConnection { id } => self
                .connections
                .iter()
                .find(|p| p.id == id)
                .cloned()
                .map(Response::Connection)
                .unwrap_or_else(|| Response::Error(format!("no such connection '{id}'"))),
            Request::AddConnection { profile } => match crate::persistence::profiles::save(&self.profiles_dir, &profile) {
                Ok(()) => {
                    self.connections.retain(|p| p.id != profile.id);
                    self.connections.push(profile);
                    Response::Ok
                }
                Err(e) => Response::Error(e.to_string()),
            },
            Request::DeleteConnection { id } => {
                if self.active.values().any(|a| a.profile_id == id) {
                    self.deactivate_profile(&id);
                }
                match crate::persistence::profiles::delete(&self.profiles_dir, &id) {
                    Ok(()) => {
                        self.connections.retain(|p| p.id != id);
                        let _ = self.secrets.delete_all(&id);
                        Response::Ok
                    }
                    Err(e) => Response::Error(e.to_string()),
                }
            }
            Request::ActivateConnection { id } => self.activate_profile(&id),
            Request::DeactivateConnection { id } => self.deactivate_profile(&id),
            Request::ScanWifi { device } => match crate::wifi::scanner::scan(&self.config.wireless.ctrl_interface_dir, &device) {
                Ok(nets) => Response::WifiNetworks(nets),
                Err(e) => Response::Error(e.to_string()),
            },
            Request::ListWifiNetworks { device } => {
                match crate::wifi::scanner::last_results(&self.config.wireless.ctrl_interface_dir, &device) {
                    Ok(nets) => Response::WifiNetworks(nets),
                    Err(e) => Response::Error(e.to_string()),
                }
            }
            Request::ConnectWifi { device, ssid, security, passphrase } => {
                let id = format!("wifi-{ssid}");
                if let Some(pass) = &passphrase {
                    if let Err(e) = self.secrets.set(&id, "psk", pass) {
                        return Response::Error(e.to_string());
                    }
                }
                let mut profile = ConnectionProfile::new_wifi(id.clone(), ssid, security);
                profile.interface_name = Some(device);
                if let Err(e) = crate::persistence::profiles::save(&self.profiles_dir, &profile) {
                    return Response::Error(e.to_string());
                }
                self.connections.retain(|p| p.id != profile.id);
                self.connections.push(profile);
                self.activate_profile(&id)
            }
            Request::ForgetWifi { device, ssid } => {
                let id = format!("wifi-{ssid}");
                let _ = crate::wifi::wifi::forget(&device, &ssid);
                let _ = self.secrets.delete_all(&id);
                let _ = crate::persistence::profiles::delete(&self.profiles_dir, &id);
                self.connections.retain(|p| p.id != id);
                Response::Ok
            }
            Request::StartHotspot { device, ssid, passphrase, uplink } => {
                match crate::sharing::hotspot::start(&device, &ssid, passphrase.as_deref(), uplink.as_deref(), &mut self.firewall) {
                    Ok(_session) => Response::Ok, // session handle intentionally not tracked yet -- see docs/networking.md
                    Err(e) => Response::Error(e.to_string()),
                }
            }
            Request::StopHotspot { device } => {
                crate::wifi::hotspot::stop(&device);
                Response::Ok
            }
            Request::SetFirewallZone { interface, zone } => match self.firewall.assign_zone(&interface, &zone) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            },
            Request::AddFirewallRule { rule } => match self.firewall.add_rule(rule) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            },
            Request::RemoveFirewallRule { id } => match self.firewall.remove_rule(&id) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Error(e.to_string()),
            },
            Request::GetConnectivity => Response::Connectivity(self.connectivity),
            Request::Diagnose => {
                let devices: Vec<_> = self.devices.all().cloned().collect();
                match crate::monitoring::diagnostics::collect(devices, self.connectivity) {
                    Ok(report) => Response::Diagnostics(Box::new(report)),
                    Err(e) => Response::Error(e.to_string()),
                }
            }
            Request::Reload => match crate::config::load(std::path::Path::new(crate::config::defaults_config_dir())) {
                Ok(cfg) => {
                    self.config = cfg;
                    Response::Ok
                }
                Err(e) => Response::Error(e.to_string()),
            },
        }
    }
}

fn nix_uid() -> u32 {
    // SAFETY: getuid(2) has no failure mode.
    unsafe { libc::getuid() }
}

impl std::fmt::Debug for NetworkManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkManager").field("devices", &self.devices.len()).finish()
    }
}
