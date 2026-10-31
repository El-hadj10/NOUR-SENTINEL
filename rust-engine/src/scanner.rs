
use serde::Serialize;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct NetworkDevice {
    pub ip: String,
    pub mac: String,
    pub interface: String,
}

#[derive(Debug, Serialize)]
pub struct PortObservation {
    pub ip: String,
    pub port: u16,
    pub state: String,
}

pub fn discover_neighbors() -> Vec<NetworkDevice> {
    let mut devices = Vec::new();

    // Lecture passive de la table ARP Linux.
    let content = match fs::read_to_string("/proc/net/arp") {
        Ok(content) => content,
        Err(_) => return devices,
    };

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() < 6 {
            continue;
        }

        let ip = fields[0].to_string();
        let mac = fields[3].to_string();
        let interface = fields[5].to_string();

        if mac != "00:00:00:00:00:00" {
            devices.push(NetworkDevice {
                ip,
                mac,
                interface,
            });
        }
    }

    devices
}

pub fn scan_tcp_ports(
    targets: &[String],
    ports: &[u16],
    timeout_ms: u64,
) -> Vec<PortObservation> {
    let mut observations = Vec::new();
    let timeout = Duration::from_millis(timeout_ms);

    for target in targets {
        let ip: IpAddr = match target.parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("[WARNING] Adresse IP invalide : {}", target);
                continue;
            }
        };

        for port in ports {
            let address = SocketAddr::new(ip, *port);

            let state = match TcpStream::connect_timeout(&address, timeout) {
                Ok(_) => "open",
                Err(error)
                    if error.kind()
                        == std::io::ErrorKind::ConnectionRefused =>
                {
                    "closed"
                }
                Err(_) => "filtered_or_unreachable",
            };

            observations.push(PortObservation {
                ip: target.clone(),
                port: *port,
                state: state.to_string(),
            });
        }
    }

    observations
}
