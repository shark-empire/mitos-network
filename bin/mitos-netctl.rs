//! `mitos-netctl`: the command-line client for mitos-network. Every
//! subcommand is a thin wrapper that builds one `ipc::messages::Request`,
//! sends it, and prints the `Response` -- all the actual logic lives in
//! the daemon, on the other end of the socket.

use mitos_network::config;
use mitos_network::ipc::client::Client;
use mitos_network::ipc::messages::{Request, Response};
use mitos_network::proxy::{ProxyConfig, ProxyMode};
use mitos_network::wifi::SecurityType;

fn usage() -> ! {
    eprintln!(
        "mitos-netctl {}
Usage:
  mitos-netctl status
  mitos-netctl connectivity
  mitos-netctl device list
  mitos-netctl device show <name>
  mitos-netctl connection list
  mitos-netctl connection show <id>
  mitos-netctl connection up <id>
  mitos-netctl connection down <id>
  mitos-netctl connection delete <id>
  mitos-netctl wifi scan <device>
  mitos-netctl wifi list <device>
  mitos-netctl wifi connect <device> <ssid> [passphrase]
  mitos-netctl wifi forget <device> <ssid>
  mitos-netctl hotspot start <device> <ssid> [passphrase] [uplink]
  mitos-netctl hotspot stop <device>
  mitos-netctl firewall zone <interface> <zone>
  mitos-netctl bluetooth list
  mitos-netctl bluetooth power <on|off>
  mitos-netctl bluetooth scan <on|off>
  mitos-netctl bluetooth pair <mac>
  mitos-netctl bluetooth trust <mac>
  mitos-netctl bluetooth connect <mac>
  mitos-netctl bluetooth disconnect <mac>
  mitos-netctl bluetooth remove <mac>
  mitos-netctl proxy show
  mitos-netctl proxy resolve <url>
  mitos-netctl proxy set none
  mitos-netctl proxy set manual <http_proxy> [https_proxy]
  mitos-netctl proxy set auto <pac_url>
  mitos-netctl diagnose
  mitos-netctl monitor
  mitos-netctl reload",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}

fn connect() -> Client {
    match Client::connect(config::defaults_socket_path()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn send(req: Request) {
    let mut client = connect();
    match client.request(req) {
        Ok(Response::Ok) => println!("OK"),
        Ok(Response::Error(e)) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
        Ok(other) => print_response(&other),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn print_response(resp: &Response) {
    // Every non-trivial payload is just pretty-printed JSON: this tool
    // is meant for scripting and troubleshooting, not a polished
    // human-facing report (that's a future desktop shell's job, talking
    // to the same IPC protocol directly).
    match serde_json::to_string_pretty(resp) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{resp:?}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        usage()
    };

    let req = match command {
        "status" => Request::GetState,
        "connectivity" => Request::GetConnectivity,
        "diagnose" => Request::Diagnose,
        "reload" => Request::Reload,
        "monitor" => {
            let mut client = connect();
            loop {
                match client.next_event() {
                    Ok(ev) => match serde_json::to_string(&ev) {
                        Ok(s) => println!("{s}"),
                        Err(_) => println!("{ev:?}"),
                    },
                    Err(e) => {
                        eprintln!("monitor stream ended: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        "device" => match args.get(1).map(String::as_str) {
            Some("list") => Request::ListDevices,
            Some("show") => Request::GetDevice {
                name: args.get(2).cloned().unwrap_or_else(|| usage()),
            },
            _ => usage(),
        },
        "connection" => match args.get(1).map(String::as_str) {
            Some("list") => Request::ListConnections,
            Some("show") => Request::GetConnection {
                id: arg_or_usage(&args, 2),
            },
            Some("up") => Request::ActivateConnection {
                id: arg_or_usage(&args, 2),
            },
            Some("down") => Request::DeactivateConnection {
                id: arg_or_usage(&args, 2),
            },
            Some("delete") => Request::DeleteConnection {
                id: arg_or_usage(&args, 2),
            },
            _ => usage(),
        },
        "wifi" => match args.get(1).map(String::as_str) {
            Some("scan") => Request::ScanWifi {
                device: arg_or_usage(&args, 2),
            },
            Some("list") => Request::ListWifiNetworks {
                device: arg_or_usage(&args, 2),
            },
            Some("connect") => {
                let device = arg_or_usage(&args, 2);
                let ssid = arg_or_usage(&args, 3);
                let passphrase = args.get(4).cloned();
                let security = if passphrase.is_some() {
                    SecurityType::Wpa2Psk
                } else {
                    SecurityType::Open
                };
                Request::ConnectWifi {
                    device,
                    ssid,
                    security,
                    passphrase,
                }
            }
            Some("forget") => Request::ForgetWifi {
                device: arg_or_usage(&args, 2),
                ssid: arg_or_usage(&args, 3),
            },
            _ => usage(),
        },
        "hotspot" => match args.get(1).map(String::as_str) {
            Some("start") => Request::StartHotspot {
                device: arg_or_usage(&args, 2),
                ssid: arg_or_usage(&args, 3),
                passphrase: args.get(4).cloned(),
                uplink: args.get(5).cloned(),
            },
            Some("stop") => Request::StopHotspot {
                device: arg_or_usage(&args, 2),
            },
            _ => usage(),
        },
        "firewall" => match args.get(1).map(String::as_str) {
            Some("zone") => Request::SetFirewallZone {
                interface: arg_or_usage(&args, 2),
                zone: arg_or_usage(&args, 3),
            },
            _ => usage(),
        },
        "bluetooth" => match args.get(1).map(String::as_str) {
            Some("list") => Request::ListBluetoothDevices,
            Some("power") => Request::BluetoothPower {
                on: on_off_or_usage(&args, 2),
            },
            Some("scan") => Request::BluetoothScan {
                on: on_off_or_usage(&args, 2),
            },
            Some("pair") => Request::PairBluetooth {
                mac: arg_or_usage(&args, 2),
            },
            Some("trust") => Request::TrustBluetooth {
                mac: arg_or_usage(&args, 2),
            },
            Some("connect") => Request::ConnectBluetooth {
                mac: arg_or_usage(&args, 2),
            },
            Some("disconnect") => Request::DisconnectBluetooth {
                mac: arg_or_usage(&args, 2),
            },
            Some("remove") => Request::RemoveBluetooth {
                mac: arg_or_usage(&args, 2),
            },
            _ => usage(),
        },
        "proxy" => match args.get(1).map(String::as_str) {
            Some("show") => Request::GetProxyConfig,
            Some("resolve") => Request::ResolveProxy {
                url: arg_or_usage(&args, 2),
            },
            Some("set") => match args.get(2).map(String::as_str) {
                Some("none") => Request::SetProxyConfig {
                    config: ProxyConfig { mode: ProxyMode::None, ..Default::default() },
                },
                Some("manual") => Request::SetProxyConfig {
                    config: ProxyConfig {
                        mode: ProxyMode::Manual,
                        http: Some(arg_or_usage(&args, 3)),
                        https: args.get(4).cloned(),
                        ..Default::default()
                    },
                },
                Some("auto") => Request::SetProxyConfig {
                    config: ProxyConfig {
                        mode: ProxyMode::Auto,
                        pac_url: Some(arg_or_usage(&args, 3)),
                        ..Default::default()
                    },
                },
                _ => usage(),
            },
            _ => usage(),
        },
        _ => usage(),
    };

    send(req);
}

fn arg_or_usage(args: &[String], index: usize) -> String {
    args.get(index).cloned().unwrap_or_else(|| usage())
}

fn on_off_or_usage(args: &[String], index: usize) -> bool {
    match args.get(index).map(String::as_str) {
        Some("on") => true,
        Some("off") => false,
        _ => usage(),
    }
}
