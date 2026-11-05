//! Inventaire local des services en écoute.
//!
//! Objectif v0.5.0 : répondre à « quel processus, quel paquet, quelle unité,
//! quel conteneur écoute sur ce port ? » sans dépendance externe.
//!
//! Toutes les lectures partent de `/proc` et `/sys` sous une racine
//! injectable, ce qui rend l'attribution testable avec des fixtures.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Socket en écoute, attribué autant que possible.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Listener {
    pub address: String,
    pub port: u16,
    pub family: String,
    pub state: String,
    pub pid: Option<i32>,
    pub uid: Option<u32>,
    pub user: Option<String>,
    pub process: Option<String>,
    pub exe: Option<String>,
    pub unit: Option<String>,
    pub container: Option<String>,
    /// `confirmed` si le processus est identifié, `probable` si seul le
    /// socket l'est, `unknown` sans attribution.
    pub confidence: String,
}

/// Interface réseau et ses adresses.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Interface {
    pub name: String,
    pub state: String,
    pub mac: Option<String>,
    pub addresses: Vec<String>,
}

/// Contexte hôte transmis à Python.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HostContext {
    pub hostname: Option<String>,
    pub kernel: Option<String>,
    pub distribution: Option<String>,
    pub interfaces: Vec<Interface>,
    pub listeners: Vec<Listener>,
}

impl HostContext {
    pub fn empty() -> Self {
        Self {
            hostname: None,
            kernel: None,
            distribution: None,
            interfaces: Vec::new(),
            listeners: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct RawSocket {
    address: String,
    port: u16,
    family: String,
    state: String,
    uid: Option<u32>,
    inode: u64,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: i32,
    process: Option<String>,
    exe: Option<String>,
    unit: Option<String>,
    container: Option<String>,
}

/// Lit l'inventaire complet sous `root` (`/` en production).
pub fn read_inventory(root: &Path) -> HostContext {
    HostContext {
        hostname: read_trimmed(&root.join("etc/hostname")),
        kernel: read_trimmed(&root.join("proc/sys/kernel/osrelease")),
        distribution: read_distribution(&root.join("etc/os-release")),
        interfaces: read_interfaces(root),
        listeners: read_listeners(root),
    }
}

fn read_trimmed(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let trimmed = text.trim();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn read_distribution(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;

    text.lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .map(|value| value.trim().trim_matches('"').to_string())
}

fn read_listeners(root: &Path) -> Vec<Listener> {
    let processes = scan_processes(root);
    let users = read_passwd(root);

    let mut raw = Vec::new();

    for (path, family) in [
        ("proc/net/tcp", "ipv4"),
        ("proc/net/tcp6", "ipv6"),
    ] {
        if let Ok(text) = fs::read_to_string(root.join(path)) {
            raw.extend(parse_proc_net(&text, family));
        }
    }

    raw.into_iter()
        .filter(|socket| socket.state == "listen")
        .map(|socket| {
            let process = processes.get(&socket.inode);

            Listener {
                address: socket.address,
                port: socket.port,
                family: socket.family,
                state: socket.state,
                pid: process.map(|info| info.pid),
                uid: socket.uid,
                user: socket.uid.and_then(|uid| users.get(&uid).cloned()),
                process: process.and_then(|info| info.process.clone()),
                exe: process.and_then(|info| info.exe.clone()),
                unit: process.and_then(|info| info.unit.clone()),
                container: process.and_then(|info| info.container.clone()),
                confidence: match process {
                    Some(info) if info.exe.is_some() => "confirmed".to_string(),
                    Some(_) => "probable".to_string(),
                    None => "unknown".to_string(),
                },
            }
        })
        .collect()
}

/// Analyse une table `/proc/net/tcp` ou `tcp6`.
fn parse_proc_net(text: &str, family: &str) -> Vec<RawSocket> {
    let mut sockets = Vec::new();

    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();

        if fields.len() < 10 {
            continue;
        }

        let Some((address_hex, port_hex)) = fields[1].split_once(':') else {
            continue;
        };

        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };

        let Ok(inode) = fields[9].parse::<u64>() else {
            continue;
        };

        let address = if family == "ipv6" {
            decode_ipv6(address_hex)
        } else {
            decode_ipv4(address_hex)
        };

        let Some(address) = address else {
            continue;
        };

        // Le propriétaire du socket reste lisible sans privilèges, même
        // quand le processus ne l'est pas.
        let uid = fields[7].parse::<u32>().ok();

        sockets.push(RawSocket {
            address,
            port,
            family: family.to_string(),
            state: decode_state(fields[3]).to_string(),
            uid,
            inode,
        });
    }

    sockets
}

/// Table `uid -> nom` depuis `/etc/passwd` (lecture seule, sans privilèges).
fn read_passwd(root: &Path) -> HashMap<u32, String> {
    let mut users = HashMap::new();

    let Ok(text) = fs::read_to_string(root.join("etc/passwd")) else {
        return users;
    };

    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();

        if fields.len() < 3 {
            continue;
        }

        if let Ok(uid) = fields[2].parse::<u32>() {
            users.entry(uid).or_insert_with(|| fields[0].to_string());
        }
    }

    users
}

fn decode_state(code: &str) -> &'static str {
    match code {
        "01" => "established",
        "02" => "syn_sent",
        "06" => "time_wait",
        "07" => "closed",
        "0A" => "listen",
        _ => "other",
    }
}

/// `0100007F` -> 127.0.0.1 (octets little-endian).
fn decode_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }

    let value = u32::from_str_radix(hex, 16).ok()?;

    Some(std::net::Ipv4Addr::from(value.to_le_bytes()).to_string())
}

/// Quatre mots de 32 bits little-endian (`/proc/net/tcp6`).
fn decode_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }

    let mut bytes = [0u8; 16];

    for index in 0..4 {
        let word = u32::from_str_radix(&hex[index * 8..index * 8 + 8], 16).ok()?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }

    Some(IpAddr::V6(Ipv6Addr::from(bytes)).to_string())
}

/// Octets dans l'ordre réseau (`/proc/net/if_inet6`, format non compressé).
fn decode_ipv6_network_order(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }

    let mut bytes = [0u8; 16];

    for index in 0..16 {
        bytes[index] = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }

    Some(IpAddr::V6(Ipv6Addr::from(bytes)).to_string())
}

/// Indexe les sockets ouverts par processus.
fn scan_processes(root: &Path) -> HashMap<u64, ProcessInfo> {
    let mut sockets = HashMap::new();
    let proc_dir = root.join("proc");

    let Ok(entries) = fs::read_dir(&proc_dir) else {
        return sockets;
    };

    let mut pids: Vec<i32> = entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<i32>().ok())
        .collect();

    pids.sort_unstable();

    for pid in pids {
        let directory = proc_dir.join(pid.to_string());
        let inodes = socket_inodes(&directory.join("fd"));

        if inodes.is_empty() {
            continue;
        }

        let info = process_info(root, pid, &directory);

        for inode in inodes {
            sockets.entry(inode).or_insert_with(|| info.clone());
        }
    }

    sockets
}

fn socket_inodes(fd_dir: &Path) -> Vec<u64> {
    let Ok(entries) = fs::read_dir(fd_dir) else {
        return Vec::new();
    };

    entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| fs::read_link(entry.path()).ok())
        .filter_map(|target| {
            let text = target.to_string_lossy().to_string();
            text.strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse::<u64>()
                .ok()
        })
        .collect()
}

fn process_info(root: &Path, pid: i32, directory: &Path) -> ProcessInfo {
    let cgroup = fs::read_to_string(directory.join("cgroup")).unwrap_or_default();

    ProcessInfo {
        pid,
        process: read_trimmed(&directory.join("comm")),
        exe: fs::read_link(directory.join("exe"))
            .ok()
            .map(|path| display_path(&path, root)),
        unit: parse_unit(&cgroup),
        container: parse_container(&cgroup),
    }
}

fn display_path(path: &Path, root: &Path) -> String {
    let text = path.to_string_lossy().to_string();

    if root == Path::new("/") {
        return text;
    }

    let prefix = format!("{}/", root.display());

    text.strip_prefix(&prefix).unwrap_or(&text).to_string()
}

/// `.../system.slice/ssh.service` -> `ssh.service`.
fn parse_unit(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        let path = line.splitn(3, ':').nth(2)?;

        for segment in path.split('/').rev() {
            if segment.ends_with(".service") || segment.ends_with(".socket") {
                return Some(segment.to_string());
            }

            if segment.ends_with(".scope") {
                break;
            }
        }
    }

    None
}

/// Identifie un conteneur par le plus long identifiant hexadécimal du cgroup.
fn parse_container(cgroup: &str) -> Option<String> {
    longest_hex_run(cgroup).map(|value| value[..12].to_string())
}

fn longest_hex_run(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut best = "";
    let mut index = 0;

    while index < bytes.len() {
        if !bytes[index].is_ascii_hexdigit() {
            index += 1;
            continue;
        }

        let start = index;

        while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
            index += 1;
        }

        if index - start > best.len() {
            best = &text[start..index];
        }
    }

    if best.len() >= 32 {
        Some(best)
    } else {
        None
    }
}

fn read_interfaces(root: &Path) -> Vec<Interface> {
    let mut interfaces: BTreeMap<String, Interface> = BTreeMap::new();

    if let Ok(entries) = fs::read_dir(root.join("sys/class/net")) {
        for entry in entries.filter_map(|entry| entry.ok()) {
            let name = entry.file_name().to_string_lossy().to_string();
            let base = entry.path();

            interfaces.insert(
                name.clone(),
                Interface {
                    state: read_trimmed(&base.join("operstate")).unwrap_or_else(|| "unknown".into()),
                    mac: read_trimmed(&base.join("address")),
                    addresses: Vec::new(),
                    name,
                },
            );
        }
    }

    // Adresses IPv6 disponibles sans commande externe.
    if let Ok(text) = fs::read_to_string(root.join("proc/net/if_inet6")) {
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();

            if fields.len() < 6 {
                continue;
            }

            // Le préfixe est exprimé en hexadécimal (`80` = /128).
            if let (Some(address), Ok(prefix)) = (
                decode_ipv6_network_order(fields[0]),
                u8::from_str_radix(fields[2], 16),
            ) {
                interfaces
                    .entry(fields[5].to_string())
                    .or_insert_with(|| Interface {
                        name: fields[5].to_string(),
                        state: "unknown".into(),
                        mac: None,
                        addresses: Vec::new(),
                    })
                    .addresses
                    .push(format!("{}/{}", address, prefix));
            }
        }
    }

    // Adresses IPv4 : `ip -j addr show` si iproute2 est disponible.
    if root == Path::new("/") {
        if let Some(json) = run_ip_addr_json() {
            for (name, addresses) in parse_ip_addr_json(&json) {
                interfaces
                    .entry(name.clone())
                    .or_insert_with(|| Interface {
                        name,
                        state: "unknown".into(),
                        mac: None,
                        addresses: Vec::new(),
                    })
                    .addresses
                    .extend(addresses);
            }
        }
    }

    let mut result: Vec<Interface> = interfaces.into_values().collect();

    for interface in &mut result {
        interface.addresses.sort();
        interface.addresses.dedup();
    }

    result
}

fn run_ip_addr_json() -> Option<String> {
    let output = Command::new("ip")
        .args(["-j", "addr", "show"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_ip_addr_json(text: &str) -> HashMap<String, Vec<String>> {
    let mut addresses = HashMap::new();

    let Ok(entries) = serde_json::from_str::<serde_json::Value>(text) else {
        return addresses;
    };

    let Some(items) = entries.as_array() else {
        return addresses;
    };

    for item in items {
        let Some(name) = item.get("ifname").and_then(|value| value.as_str()) else {
            continue;
        };

        let Some(list) = item.get("addr_info").and_then(|value| value.as_array()) else {
            continue;
        };

        for entry in list {
            let Some(local) = entry.get("local").and_then(|value| value.as_str()) else {
                continue;
            };

            let prefix = entry
                .get("prefixlen")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);

            addresses
                .entry(name.to_string())
                .or_insert_with(Vec::new)
                .push(format!("{}/{}", local, prefix));
        }
    }

    addresses
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn temp_root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "nour-inventory-{}-{}",
            name,
            std::process::id()
        ));

        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();

        path
    }

    fn write(root: &Path, relative: &str, content: &str) {
        let path = root.join(relative);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }

        fs::write(path, content).unwrap();
    }

    const TCP_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    #[test]
    fn parses_ipv4_listener() {
        let sockets = parse_proc_net(
            &format!(
                "{}   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0 100 0 0 10 0\n",
                TCP_HEADER
            ),
            "ipv4",
        );

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].address, "127.0.0.1");
        assert_eq!(sockets[0].port, 22);
        assert_eq!(sockets[0].state, "listen");
        assert_eq!(sockets[0].inode, 4242);
    }

    #[test]
    fn parses_ipv6_listener() {
        let sockets = parse_proc_net(
            &format!(
                "{}   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777 1 0 100 0 0 10 0\n",
                TCP_HEADER
            ),
            "ipv6",
        );

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].address, "::1");
        assert_eq!(sockets[0].port, 22);
        assert_eq!(sockets[0].family, "ipv6");
    }

    #[test]
    fn ignores_established_sockets() {
        let root = temp_root("established");
        write(
            &root,
            "proc/net/tcp",
            &format!(
                "{}   0: 0100007F:0016 0100007F:C350 01 00000000:00000000 00:00000000 00000000     0        0 99 1 0 100 0 0 10 0\n",
                TCP_HEADER
            ),
        );

        assert!(read_listeners(&root).is_empty());
    }

    #[test]
    fn rejects_malformed_lines() {
        let sockets = parse_proc_net(
            &format!("{}\n   0: nonsense\n   1: 0100007F 00000000:0000 0A\n", TCP_HEADER),
            "ipv4",
        );

        assert!(sockets.is_empty());
    }

    #[test]
    fn ignores_zero_port_oddities_gracefully() {
        // Un port nul ne doit pas paniquer le parseur.
        let sockets = parse_proc_net(
            &format!(
                "{}   0: 0100007F:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0\n",
                TCP_HEADER
            ),
            "ipv4",
        );

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 0);
    }

    #[test]
    fn attributes_socket_to_process_and_unit() {
        let root = temp_root("attribution");
        write(
            &root,
            "proc/net/tcp",
            &format!(
                "{}   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0 100 0 0 10 0\n",
                TCP_HEADER
            ),
        );
        write(&root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n");
        write(&root, "proc/4242/comm", "sshd\n");
        write(&root, "proc/4242/cgroup", "0::/system.slice/ssh.service\n");
        fs::create_dir_all(root.join("proc/4242/fd")).unwrap();
        symlink("socket:[111]", root.join("proc/4242/fd/3")).unwrap();
        symlink("/usr/sbin/sshd", root.join("proc/4242/exe")).unwrap();

        let listeners = read_listeners(&root);

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].pid, Some(4242));
        assert_eq!(listeners[0].process.as_deref(), Some("sshd"));
        assert_eq!(listeners[0].unit.as_deref(), Some("ssh.service"));
        assert_eq!(listeners[0].uid, Some(0));
        assert_eq!(listeners[0].user.as_deref(), Some("root"));
        assert_eq!(listeners[0].confidence, "confirmed");
    }

    #[test]
    fn resolves_owner_without_process_attribution() {
        let root = temp_root("owner");
        write(
            &root,
            "proc/net/tcp",
            &format!(
                "{}   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   102        0 444 1 0 100 0 0 10 0\n",
                TCP_HEADER
            ),
        );
        write(
            &root,
            "etc/passwd",
            "systemd-resolve:x:102:102:systemd Resolver:/:/usr/sbin/nologin\n",
        );

        let listeners = read_listeners(&root);

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].uid, Some(102));
        assert_eq!(listeners[0].user.as_deref(), Some("systemd-resolve"));
        assert_eq!(listeners[0].process, None);
        assert_eq!(listeners[0].confidence, "unknown");
    }

    #[test]
    fn attributes_docker_container() {
        let root = temp_root("container");
        write(
            &root,
            "proc/net/tcp",
            &format!(
                "{}   0: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0 100 0 0 10 0\n",
                TCP_HEADER
            ),
        );
        write(&root, "proc/900/comm", "dockerd\n");
        write(
            &root,
            "proc/900/cgroup",
            "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n",
        );
        fs::create_dir_all(root.join("proc/900/fd")).unwrap();
        symlink("socket:[222]", root.join("proc/900/fd/7")).unwrap();

        let listeners = read_listeners(&root);

        assert_eq!(
            listeners[0].container.as_deref(),
            Some("0123456789ab"),
            "l'identifiant de conteneur doit être raccourci à 12 caractères"
        );
        assert_eq!(listeners[0].address, "0.0.0.0");
    }

    #[test]
    fn unattributed_socket_has_unknown_confidence() {
        let root = temp_root("unattributed");
        write(
            &root,
            "proc/net/tcp",
            &format!(
                "{}   0: 0100007F:1596 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 333 1 0 100 0 0 10 0\n",
                TCP_HEADER
            ),
        );

        let listeners = read_listeners(&root);

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].pid, None);
        assert_eq!(listeners[0].confidence, "unknown");
    }

    #[test]
    fn missing_files_produce_empty_inventory() {
        let root = temp_root("missing");

        let inventory = read_inventory(&root);

        assert!(inventory.listeners.is_empty());
        assert!(inventory.interfaces.is_empty());
        assert_eq!(inventory.hostname, None);
    }

    #[test]
    fn reads_host_context() {
        let root = temp_root("host");
        write(&root, "etc/hostname", "nour-test\n");
        write(&root, "proc/sys/kernel/osrelease", "6.8.0-test\n");
        write(
            &root,
            "etc/os-release",
            "NAME=\"Kali\"\nPRETTY_NAME=\"Kali GNU/Linux Rolling\"\n",
        );

        let inventory = read_inventory(&root);

        assert_eq!(inventory.hostname.as_deref(), Some("nour-test"));
        assert_eq!(inventory.kernel.as_deref(), Some("6.8.0-test"));
        assert_eq!(
            inventory.distribution.as_deref(),
            Some("Kali GNU/Linux Rolling")
        );
    }

    #[test]
    fn reads_interfaces_with_ipv6_addresses() {
        let root = temp_root("interfaces");
        write(&root, "sys/class/net/lo/operstate", "unknown\n");
        write(&root, "sys/class/net/lo/address", "00:00:00:00:00:00\n");
        write(
            &root,
            "proc/net/if_inet6",
            "00000000000000000000000000000001 01 80 10 80 lo\n",
        );

        let interfaces = read_interfaces(&root);

        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "lo");
        assert_eq!(interfaces[0].addresses, vec!["::1/128".to_string()]);
    }

    #[test]
    fn parses_ip_json_addresses() {
        let json = r#"[
            {"ifname": "wlp2s0", "addr_info": [
                {"local": "192.168.1.13", "prefixlen": 24, "family": "inet"},
                {"local": "fe80::1", "prefixlen": 64, "family": "inet6"}
            ]}
        ]"#;

        let addresses = parse_ip_addr_json(json);

        assert_eq!(
            addresses.get("wlp2s0"),
            Some(&vec![
                "192.168.1.13/24".to_string(),
                "fe80::1/64".to_string()
            ])
        );
    }

    #[test]
    fn detects_container_ids_only_when_long_enough() {
        assert_eq!(longest_hex_run("docker-abc"), None);
        assert_eq!(
            longest_hex_run(
                "/docker/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
    }
}
