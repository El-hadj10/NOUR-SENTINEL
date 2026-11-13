
mod auth;
mod gate;
mod inventory;
mod scanner;
mod history;
mod version;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Plafond de concurrence : protège des configurations accidentelles.
const MAX_CONCURRENCY: usize = 256;
const DEFAULT_GATEWAY_TARGET: &str = "default_gateway";

#[derive(Deserialize)]
struct Settings {
    application: ApplicationSettings,
    engines: Engines,
    network: NetworkSettings,
    analysis: AnalysisSettings,
    security: SecuritySettings,
}

#[derive(Deserialize)]
struct ApplicationSettings {
    name: String,
    version: String,
    environment: String,
}

#[derive(Deserialize)]
struct Engines {
    rust: EngineSettings,
    python: PythonSettings,
}

#[derive(Deserialize)]
struct EngineSettings {
    enabled: bool,
}

#[derive(Deserialize)]
struct PythonSettings {
    enabled: bool,
}

#[derive(Deserialize)]
struct NetworkSettings {
    targets: Vec<String>,
    discover_arp: bool,
    scan_discovered_devices: bool,
    ports: Vec<u16>,
    timeout_ms: u64,
    max_concurrency: usize,
}

#[derive(Deserialize, Serialize)]
struct AnalysisSettings {
    sensitive_ports: Vec<u16>,
    known_services: HashMap<String, String>,
}

#[derive(Deserialize)]
struct SecuritySettings {
    authorized_scanning_only: bool,
    automatic_actions: bool,
}

/// Valide les paramètres avant toute opération réseau.
fn validate_settings(settings: &Settings) -> Result<(), String> {
    if !settings.engines.rust.enabled {
        return Err("Rust engine is disabled".into());
    }

    if !settings.engines.python.enabled {
        return Err("Python engine is disabled".into());
    }

    if !settings.security.authorized_scanning_only {
        return Err("Authorized scanning policy must be enabled".into());
    }

    if settings.security.automatic_actions {
        return Err("Automatic security actions are not supported".into());
    }

    if settings.network.scan_discovered_devices {
        return Err(
            "Automatic scanning of ARP-discovered devices is not implemented".into()
        );
    }

    if settings.network.targets.is_empty() {
        return Err("No authorized target configured".into());
    }

    if settings.network.ports.is_empty() {
        return Err("No TCP port configured".into());
    }

    if settings.network.timeout_ms == 0 {
        return Err("TCP timeout must be greater than zero".into());
    }

    if settings.network.max_concurrency == 0 {
        return Err("Maximum concurrency must be greater than zero".into());
    }

    if settings.network.max_concurrency > MAX_CONCURRENCY {
        return Err(format!(
            "Maximum concurrency must not exceed {}",
            MAX_CONCURRENCY
        ));
    }

    if settings.network.ports.contains(&0) {
        return Err("Port 0 is not a valid TCP port".into());
    }

    validate_targets(&settings.network.targets)?;

    // Vérification des ports sensibles.
    for port in &settings.analysis.sensitive_ports {
        if *port == 0 {
            return Err("Sensitive port configuration contains port 0".into());
        }
    }

    Ok(())
}

fn validate_targets(targets: &[String]) -> Result<(), String> {
    if targets.len() == 1 && targets[0] == DEFAULT_GATEWAY_TARGET {
        return Ok(());
    }

    for target in targets {
        if target == DEFAULT_GATEWAY_TARGET {
            return Err("default_gateway must be the only authorized target".into());
        }

        target
            .parse::<IpAddr>()
            .map_err(|_| format!("Invalid target IP: {}", target))?;
    }

    Ok(())
}

fn resolve_targets(targets: &[String]) -> Result<Vec<String>, String> {
    validate_targets(targets)?;

    if targets.len() == 1 && targets[0] == DEFAULT_GATEWAY_TARGET {
        return Ok(vec![resolve_default_gateway()?.to_string()]);
    }

    Ok(targets.to_vec())
}

fn resolve_default_gateway() -> Result<Ipv4Addr, String> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .map_err(|error| format!("Cannot read default IPv4 route: {}", error))?;

    if !output.status.success() {
        return Err("`ip -4 route show default` failed".into());
    }

    let routes = String::from_utf8_lossy(&output.stdout);
    parse_default_gateway(&routes)
}

fn parse_default_gateway(output: &str) -> Result<Ipv4Addr, String> {
    let routes: Vec<Vec<&str>> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.split_whitespace().collect())
        .collect();

    if routes.len() != 1 || routes[0].first() != Some(&"default") {
        return Err("A unique default IPv4 route is required".into());
    }

    let via_indices: Vec<usize> = routes[0]
        .iter()
        .enumerate()
        .filter_map(|(index, field)| (*field == "via").then_some(index))
        .collect();

    if via_indices.len() != 1 || via_indices[0] + 1 >= routes[0].len() {
        return Err("The default IPv4 route must have one gateway".into());
    }

    let gateway = routes[0][via_indices[0] + 1]
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IPv4 gateway address".to_string())?;

    if !gateway.is_private() || gateway.is_loopback() || gateway.is_link_local() {
        return Err("The default gateway must be a private RFC1918 IPv4 address".into());
    }

    Ok(gateway)
}

/// Exécute le moteur réseau et transmet les observations à Python.
fn run() -> Result<(), String> {
    // Localisation de la racine du projet.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("Project root not found")?
        .to_path_buf();

    // Le processus Python est démarré AVANT toute configuration, lecture ARP
    // ou tentative TCP (0.6.0-beta.4). Il exécute l'Auth Gate Argon2id et
    // n'émet AUTH_OK qu'après succès ; aucune collecte ne commence avant.
    let python = auth::ensure_interpreter(&root)?;
    let python_script = root.join("python-brain/main.py");

    if !python_script.is_file() {
        return Err(format!(
            "Python entrypoint not found: {}",
            python_script.display()
        ));
    }

    let mut child = Command::new(&python)
        .arg(&python_script)
        .arg("--handshake")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("Cannot start Python: {}", error))?;

    let mut child_stdin = child.stdin.take().ok_or("Python stdin unavailable")?;
    let child_stdout = child.stdout.take().ok_or("Python stdout unavailable")?;
    let mut child_reader = BufReader::new(child_stdout);
    let mut handshake = String::new();

    child_reader
        .read_line(&mut handshake)
        .map_err(|error| format!("Auth Gate handshake failed: {}", error))?;

    if handshake.trim() != "AUTH_OK" {
        let _ = child.wait();
        return Err("authentification refusée".to_string());
    }

    // Défense en profondeur : aucune collecte ni écriture SQLite ne doit
    // pouvoir précéder l'authentification, même après un futur remaniement.
    gate::authorize();

    // Chargement de la configuration.
    let config_path = match std::env::var("NOUR_SENTINEL_CONFIG") {
        Ok(path) => PathBuf::from(path),
        Err(_) => root.join("config/settings.json"),
    };

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|error| format!("Cannot read configuration: {}", error))?;

    let settings: Settings = serde_json::from_str(&config_text)
        .map_err(|error| format!("Invalid configuration: {}", error))?;

    // Sections transmises telles quelles à Python : le contrat JSON reste la
    // source de vérité, sans duplication de schéma côté Rust.
    let raw_settings: Value = serde_json::from_str(&config_text)
        .map_err(|error| format!("Invalid configuration: {}", error))?;

    validate_settings(&settings)?;
    let resolved_targets = resolve_targets(&settings.network.targets)?;

    // Périmètre réellement vérifié : cibles et ports dédupliqués et triés.
    // Il sert à la fois au scan et à la comparaison historique.
    let scope = history::ScanScope::new(&resolved_targets, &settings.network.ports);

    println!("==============================================");
    println!("  NOUR SENTINEL");
    println!("    moteur (core)  : v{}", version::CORE_VERSION);
    println!("    laboratoire    : v{}", version::LAB_VERSION);
    println!("    protocole JSON : v{}", version::PROTOCOL_VERSION);
    println!("==============================================");

    println!(
        "[RUST] Environment: {}",
        settings.application.environment
    );

    println!(
        "[RUST] Profile: {} v{}",
        settings.application.name,
        settings.application.version
    );

    println!(
        "[RUST] Configuration: {}",
        config_path.display()
    );

    println!("[RUST] Configuration validated.");

    // Découverte passive ARP.
    let devices = if settings.network.discover_arp {
        println!("[RUST] Passive ARP discovery...");
        scanner::discover_neighbors()
    } else {
        Vec::new()
    };

    println!(
        "[RUST] {} neighbor(s) discovered.",
        devices.len()
    );

    // Vérification TCP concurrente.
    println!("[RUST] Concurrent TCP verification...");

    println!(
        "[RUST] Maximum concurrency: {}",
        settings.network.max_concurrency
    );

    let observations = scanner::scan_tcp_ports(
        scope.targets(),
        scope.ports(),
        settings.network.timeout_ms,
        settings.network.max_concurrency,
    );

    println!(
        "[RUST] {} observation(s) completed.",
        observations.len()
    );

    // Inventaire local des services en écoute (v0.5.0).
    // Aucune opération réseau : uniquement /proc et /sys.
    let inventory_enabled = raw_settings["intelligence"]["local_inventory"]
        .as_bool()
        .unwrap_or(true);

    let inventory = if inventory_enabled {
        println!("[RUST] Local service inventory...");
        inventory::read_inventory(Path::new("/"))
    } else {
        inventory::HostContext::empty()
    };

    for listener in &inventory.listeners {
        println!(
            "[INVENTORY] {}:{} {} pid={} process={} confidence={}",
            listener.address,
            listener.port,
            listener.family,
            listener
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string()),
            listener.process.as_deref().unwrap_or("-"),
            listener.confidence
        );
    }

    println!(
        "[RUST] {} listening socket(s) inventoried, {} interface(s).",
        inventory.listeners.len(),
        inventory.interfaces.len()
    );

    // Conversion des observations en événements JSON.
    let events: Vec<Value> = observations
        .iter()
        .map(|item| {
            json!({
                "type": "port_observed",
                "ip": item.ip,
                "port": item.port,
                "state": item.state
            })
        })
        .collect();

    // Construction du message destiné au moteur Python.
    let input_data = json!({
        "source": "rust-network-engine",
        "devices": devices,
        "events": events,
        "analysis_config": &settings.analysis,
        "inventory": inventory,
        "authorized_targets": scope.targets(),
        "intelligence_config": raw_settings
            .get("intelligence")
            .cloned()
            .unwrap_or_else(|| json!({})),
        "tools_config": raw_settings
            .get("tools")
            .cloned()
            .unwrap_or_else(|| json!({}))
    });

    println!("[RUST] Sending observations to Python...");

    // Sérialisation JSON.
    let input = serde_json::to_vec(&input_data)
        .map_err(|error| format!("JSON serialization failed: {}", error))?;

    // Transmission des données au processus Python déjà authentifié.
    child_stdin
        .write_all(&input)
        .map_err(|error| format!("Data transmission failed: {}", error))?;
    drop(child_stdin);

    // Attente de la fin du moteur Python.
    let mut output = String::new();
    child_reader
        .read_to_string(&mut output)
        .map_err(|error| format!("Python output read failed: {}", error))?;

    let status = child
        .wait()
        .map_err(|error| format!("Python execution failed: {}", error))?;

    if !status.success() {
        return Err("Python analysis failed".into());
    }

    // Vérification de la réponse JSON.
    let mut result: Value = serde_json::from_str(&output)
        .map_err(|error| format!("Invalid Python JSON response: {}", error))?;

    // Historique et détection de changements (v0.4.1).
    record_history(&root, &scope, &events, &mut result);

    println!("\n[RUST] Security report:\n");

    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .map_err(|error| format!("JSON display error: {}", error))?
    );

    println!(
        "\n[SUCCESS] NOUR SENTINEL core v{} / lab v{} operational.",
        version::CORE_VERSION,
        version::LAB_VERSION
    );

    Ok(())
}

/// Enregistre le scan et expose explicitement l'état de l'historique dans le
/// rapport : aucune panne de stockage n'est masquée par un message de succès.
fn record_history(root: &Path, scope: &history::ScanScope, events: &[Value], result: &mut Value) {
    if let Some(obj) = result.as_object_mut() {
        obj.insert(
            "events".to_string(),
            serde_json::to_value(events).unwrap_or(json!([])),
        );
    }

    let conn = match history::init_db(root) {
        Ok(conn) => conn,
        Err(error) => {
            eprintln!("[WARNING] History unavailable: {}", error);
            set_history_status(
                result,
                json!({ "status": "unavailable", "error": error.to_string() }),
            );
            return;
        }
    };

    println!("[RUST] Behavioral intelligence: tracking history...");

    let scan_id = match history::save_scan(&conn, scope, result) {
        Ok(scan_id) => scan_id,
        Err(error) => {
            eprintln!("[WARNING] Scan not recorded in history: {}", error);
            set_history_status(
                result,
                json!({ "status": "not_recorded", "error": error.to_string() }),
            );
            return;
        }
    };

    println!("[RUST] Scan recorded in history (ID: {}).", scan_id);

    let comparison = match history::detect_scan_changes(&conn, scan_id) {
        Ok(comparison) => comparison,
        Err(error) => {
            eprintln!("[WARNING] Behavioral comparison failed: {}", error);
            set_history_status(
                result,
                json!({ "status": "recorded", "scan_id": scan_id, "error": error.to_string() }),
            );
            return;
        }
    };

    if comparison.scope_changed {
        println!(
            "[BEHAVIORAL] Scan scope changed: comparison limited to an identical scope."
        );
    }

    print_changes(&comparison.changes);

    if let Some(obj) = result.as_object_mut() {
        obj.insert(
            "behavioral_changes".to_string(),
            serde_json::to_value(&comparison.changes).unwrap_or(json!([])),
        );
        obj.insert("scope_changed".to_string(), json!(comparison.scope_changed));
    }

    set_history_status(
        result,
        json!({
            "status": "recorded",
            "scan_id": scan_id,
            "previous_scan_id": comparison.previous_scan_id,
            "scope_changed": comparison.scope_changed
        }),
    );
}

fn set_history_status(result: &mut Value, status: Value) {
    if let Some(obj) = result.as_object_mut() {
        obj.insert("history".to_string(), status);
    }
}

fn print_changes(changes: &[history::BehavioralChange]) {
    if changes.is_empty() {
        println!("[BEHAVIORAL] No changes detected since last comparable scan.");
        return;
    }

    println!("\n[BEHAVIORAL] Changes detected since last comparable scan:");

    for change in changes {
        match &change.change_type {
            history::ChangeType::New => {
                println!("  [NEW] {}:{} is now open", change.ip, change.port)
            }
            history::ChangeType::Removed => println!(
                "  [REMOVED] {}:{} no longer observed as open",
                change.ip, change.port
            ),
            history::ChangeType::StateChanged => println!(
                "  [CHANGED] {}:{} {} -> {}",
                change.ip,
                change.port,
                change.previous_state.as_deref().unwrap_or("unknown"),
                change.current_state.as_deref().unwrap_or("unknown")
            ),
        }
    }

    println!();
}

fn main() {
    if let Err(error) = run() {
        eprintln!("[ERROR] {}", error);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_gateway_is_the_only_dynamic_target() {
        assert!(validate_targets(&[DEFAULT_GATEWAY_TARGET.to_string()]).is_ok());
        assert!(
            validate_targets(&[DEFAULT_GATEWAY_TARGET.to_string(), "127.0.0.1".to_string()])
                .is_err()
        );
    }

    #[test]
    fn default_gateway_parser_requires_one_private_route() {
        assert_eq!(
            parse_default_gateway("default via 10.23.45.1 dev test0 proto dhcp metric 600\n")
                .unwrap(),
            Ipv4Addr::new(10, 23, 45, 1)
        );

        assert!(parse_default_gateway("").is_err());
        assert!(parse_default_gateway(
            "default via 10.23.45.1 dev test0\ndefault via 10.0.0.1 dev test1\n"
        )
        .is_err());
        assert!(parse_default_gateway("default via 8.8.8.8 dev test0\n").is_err());
        assert!(parse_default_gateway("default dev test0\n").is_err());
    }
}
