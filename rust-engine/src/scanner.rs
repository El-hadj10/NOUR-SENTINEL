
use serde::Serialize;
use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
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

/// Découverte passive des appareils présents dans la table ARP Linux.
pub fn discover_neighbors() -> Vec<NetworkDevice> {
    crate::gate::require()
        .expect("découverte ARP refusée sans autorisation");

    let mut devices = Vec::new();

    let content = match fs::read_to_string("/proc/net/arp") {
        Ok(content) => content,
        Err(error) => {
            eprintln!("[WARNING] Impossible de lire la table ARP : {}", error);
            return devices;
        }
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

/// Exécute des tâches en parallèle avec un nombre maximal de workers.
/// Les résultats conservent l'ordre des tâches initiales.
fn parallel_map_ordered<T, R, F>(
    items: &[T],
    max_workers: usize,
    operation: F,
) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    if items.is_empty() || max_workers == 0 {
        return Vec::new();
    }

    let worker_count = max_workers.min(items.len());
    let next_job = AtomicUsize::new(0);

    let results: Mutex<Vec<Option<R>>> = Mutex::new(
        (0..items.len()).map(|_| None).collect()
    );

    thread::scope(|scope| {
        for _ in 0..worker_count {
            let operation = &operation;
            let next_job = &next_job;
            let results = &results;

            scope.spawn(move || {
                loop {
                    let index = next_job.fetch_add(1, Ordering::Relaxed);

                    if index >= items.len() {
                        break;
                    }

                    let result = operation(&items[index]);

                    let mut output = results
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());

                    output[index] = Some(result);
                }
            });
        }
    });

    let output = results
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    output.into_iter().flatten().collect()
}

/// Vérifie un port TCP et retourne son état.
fn check_tcp_port(ip: IpAddr, port: u16, timeout: Duration) -> String {
    let address = SocketAddr::new(ip, port);

    match TcpStream::connect_timeout(&address, timeout) {
        Ok(_) => "open".to_string(),
        Err(error)
            if error.kind() == std::io::ErrorKind::ConnectionRefused =>
        {
            "closed".to_string()
        }
        Err(_) => "filtered_or_unreachable".to_string(),
    }
}

/// Scanner TCP concurrent avec limite effective de workers.
pub fn scan_tcp_ports(
    targets: &[String],
    ports: &[u16],
    timeout_ms: u64,
    max_concurrency: usize,
) -> Vec<PortObservation> {
    crate::gate::require()
        .expect("scan TCP refusé sans autorisation");

    if targets.is_empty()
        || ports.is_empty()
        || timeout_ms == 0
        || max_concurrency == 0
    {
        return Vec::new();
    }

    let timeout = Duration::from_millis(timeout_ms);

    let mut jobs: Vec<(String, IpAddr, u16)> = Vec::new();

    for target in targets {
        let ip: IpAddr = match target.parse() {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("[WARNING] Adresse IP invalide : {}", target);
                continue;
            }
        };

        for port in ports {
            jobs.push((target.clone(), ip, *port));
        }
    }

    parallel_map_ordered(
        &jobs,
        max_concurrency,
        |job| {
            let (target, ip, port) = job;

            let state = check_tcp_port(*ip, *port, timeout);

            PortObservation {
                ip: target.clone(),
                port: *port,
                state,
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn rejects_invalid_ip() {
        let targets = vec!["not-an-ip".to_string()];
        let ports = vec![22];

        let result = scan_tcp_ports(&targets, &ports, 500, 2);

        assert!(result.is_empty());
    }

    #[test]
    fn handles_empty_targets() {
        let targets: Vec<String> = Vec::new();
        let ports = vec![22, 443];

        let result = scan_tcp_ports(&targets, &ports, 500, 2);

        assert!(result.is_empty());
    }

    #[test]
    fn handles_empty_ports() {
        let targets = vec!["127.0.0.1".to_string()];
        let ports: Vec<u16> = Vec::new();

        let result = scan_tcp_ports(&targets, &ports, 500, 2);

        assert!(result.is_empty());
    }

    #[test]
    fn rejects_zero_concurrency() {
        let targets = vec!["127.0.0.1".to_string()];
        let ports = vec![22];

        let result = scan_tcp_ports(&targets, &ports, 500, 0);

        assert!(result.is_empty());
    }

    #[test]
    fn rejects_zero_timeout() {
        let targets = vec!["127.0.0.1".to_string()];
        let ports = vec![22];

        let result = scan_tcp_ports(&targets, &ports, 0, 2);

        assert!(result.is_empty());
    }

    #[test]
    fn respects_maximum_worker_concurrency() {
        let jobs: Vec<usize> = (0..12).collect();

        let active_workers = AtomicUsize::new(0);
        let maximum_observed = AtomicUsize::new(0);

        let results = parallel_map_ordered(
            &jobs,
            2,
            |_| {
                let active = active_workers.fetch_add(1, Ordering::SeqCst) + 1;

                maximum_observed.fetch_max(active, Ordering::SeqCst);

                // Simule une tâche suffisamment longue
                // pour permettre le chevauchement des workers.
                thread::sleep(Duration::from_millis(50));

                active_workers.fetch_sub(1, Ordering::SeqCst);

                "completed"
            },
        );

        assert_eq!(results.len(), 12);

        let maximum = maximum_observed.load(Ordering::SeqCst);

        assert!(
            maximum <= 2,
            "La limite de concurrence a été dépassée : {}",
            maximum
        );

        assert!(
            maximum >= 2,
            "Le test n'a pas observé deux workers actifs simultanément."
        );
    }

    #[test]
    fn preserves_result_order() {
        let jobs = vec![10, 20, 30, 40, 50];

        let results = parallel_map_ordered(
            &jobs,
            3,
            |value| value * 2,
        );

        assert_eq!(results, vec![20, 40, 60, 80, 100]);
    }
}
