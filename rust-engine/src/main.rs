
mod scanner;
mod history;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    executable: String,
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

    if settings.engines.python.executable.trim().is_empty() {
        return Err("Python executable is empty".into());
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

    // Vérification des adresses IP.
    for target in &settings.network.targets {
        target
            .parse::<IpAddr>()
            .map_err(|_| format!("Invalid target IP: {}", target))?;
    }

    // Vérification des ports sensibles.
    for port in &settings.analysis.sensitive_ports {
        if *port == 0 {
            return Err("Sensitive port configuration contains port 0".into());
        }
    }

    Ok(())
}

/// Exécute le moteur réseau et transmet les observations à Python.
fn run() -> Result<(), String> {
    // Localisation de la racine du projet.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("Project root not found")?
        .to_path_buf();

    // Chargement de la configuration.
    let config_path = match std::env::var("NOUR_SENTINEL_CONFIG") {
        Ok(path) => PathBuf::from(path),
        Err(_) => root.join("config/settings.json"),
    };

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|error| format!("Cannot read configuration: {}", error))?;

    let settings: Settings = serde_json::from_str(&config_text)
        .map_err(|error| format!("Invalid configuration: {}", error))?;

    validate_settings(&settings)?;

    println!("====================================");
    println!(
        "       {} v{}",
        settings.application.name,
        settings.application.version
    );
    println!("====================================");

    println!(
        "[RUST] Environment: {}",
        settings.application.environment
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
        &settings.network.targets,
        &settings.network.ports,
        settings.network.timeout_ms,
        settings.network.max_concurrency,
    );

    println!(
        "[RUST] {} observation(s) completed.",
        observations.len()
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
        "analysis_config": &settings.analysis
    });

    // Localisation du moteur Python.
    let python_script = root.join("python-brain/main.py");

    println!("[RUST] Sending observations to Python...");

    // Démarrage du processus Python.
    let mut child = Command::new(&settings.engines.python.executable)
        .arg(&python_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("Cannot start Python: {}", error))?;

    // Sérialisation JSON.
    let input = serde_json::to_vec(&input_data)
        .map_err(|error| format!("JSON serialization failed: {}", error))?;

    // Transmission des données à Python.
    child
        .stdin
        .take()
        .ok_or("Python stdin unavailable")?
        .write_all(&input)
        .map_err(|error| format!("Data transmission failed: {}", error))?;

    // Attente de la fin du moteur Python.
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Python execution failed: {}", error))?;

    if !output.status.success() {
        return Err("Python analysis failed".into());
    }

    // Vérification de la réponse JSON.
    let mut result: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Invalid Python JSON response: {}", error))?;

    // Historique et détection de changements (v0.4.1).
    // Le périmètre réellement vérifié conditionne la comparaison historique.
    let scope = history::ScanScope::new(&settings.network.targets, &settings.network.ports);

    record_history(&root, &scope, &events, &mut result);

    println!("\n[RUST] Security report:\n");

    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .map_err(|error| format!("JSON display error: {}", error))?
    );

    println!(
        "\n[SUCCESS] {} v{} operational.",
        settings.application.name,
        settings.application.version
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
