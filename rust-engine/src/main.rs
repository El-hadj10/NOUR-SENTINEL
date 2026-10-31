
mod scanner;

use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Deserialize)]
struct Settings {
    engines: Engines,
    network: NetworkSettings,
}

#[derive(Deserialize)]
struct Engines {
    python: PythonSettings,
}

#[derive(Deserialize)]
struct PythonSettings {
    executable: String,
}

#[derive(Deserialize)]
struct NetworkSettings {
    targets: Vec<String>,
    ports: Vec<u16>,
    timeout_ms: u64,
}

fn main() {
    println!("====================================");
    println!("       NOUR SENTINEL v0.2.0");
    println!("====================================");

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Project root not found")
        .to_path_buf();

    let config_path = root.join("config/settings.json");

    let config_text = std::fs::read_to_string(&config_path)
        .expect("Cannot read settings.json");

    let settings: Settings = serde_json::from_str(&config_text)
        .expect("Invalid configuration");

    println!("[RUST] Configuration chargée.");

    println!("[RUST] Découverte passive des voisins...");
    let devices = scanner::discover_neighbors();

    println!(
        "[RUST] {} voisin(s) trouvé(s) dans la table ARP.",
        devices.len()
    );

    println!("[RUST] Vérification des ports TCP autorisés...");

    let observations = scanner::scan_tcp_ports(
        &settings.network.targets,
        &settings.network.ports,
        settings.network.timeout_ms,
    );

    println!(
        "[RUST] {} observation(s) réalisée(s).",
        observations.len()
    );

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

    let input_data = json!({
        "source": "rust-network-engine",
        "devices": devices,
        "events": events
    });

    let python_script = root.join("python-brain/main.py");

    println!("[RUST] Transmission au cerveau Python...");

    let mut child = Command::new(&settings.engines.python.executable)
        .arg(&python_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Impossible de lancer Python");

    let input = serde_json::to_vec(&input_data)
        .expect("JSON serialization failed");

    child.stdin
        .take()
        .expect("Python stdin unavailable")
        .write_all(&input)
        .expect("Data transmission failed");

    let output = child.wait_with_output()
        .expect("Python communication failed");

    if !output.status.success() {
        eprintln!("[ERROR] Python analysis failed.");
        std::process::exit(1);
    }

    let result: Value = serde_json::from_slice(&output.stdout)
        .expect("Invalid Python JSON response");

    println!("\n[RUST] Rapport de sécurité :\n");

    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .expect("JSON display error")
    );

    println!("\n[SUCCESS] NOUR SENTINEL v0.2.0 opérationnel.");
}
