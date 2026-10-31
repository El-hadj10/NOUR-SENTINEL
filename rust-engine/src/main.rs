mod scanner;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// ============================================
// NOUR SENTINEL v0.2.1
// Configuration structures
// ============================================

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

// ============================================
// Configuration validation
// ============================================

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
        return Err("Automatic scanning of ARP-discovered devices is not implemented".into());
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

    for target in &settings.network.targets {
        target
            .parse::<IpAddr>()
            .map_err(|_| format!("Invalid target IP: {}", target))?;
    }

    for port in &settings.analysis.sensitive_ports {
        if *port == 0 {
            return Err("Sensitive port configuration contains port 0".into());
        }
    }

    Ok(())
}

// ============================================
// Main execution
// ============================================

fn run() -> Result<(), String> {
    println!("====================================");
    println!("       NOUR SENTINEL v0.2.1");
    println!("====================================");

    // Project root
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("Project root not found")?
        .to_path_buf();

    // Load configuration
    let config_path = root.join("config/settings.json");

    let config_text = std::fs::read_to_string(&config_path)
        .map_err(|error| format!("Cannot read configuration: {}", error))?;

    let settings: Settings = serde_json::from_str(&config_text)
        .map_err(|error| format!("Invalid configuration: {}", error))?;

    // Validate configuration
    validate_settings(&settings)?;

    println!(
        "[RUST] {} v{}",
        settings.application.name, settings.application.version
    );

    println!("[RUST] Environment: {}", settings.application.environment);

    println!("[RUST] Configuration validated.");

    // ========================================
    // Passive ARP discovery
    // ========================================

    let devices = if settings.network.discover_arp {
        println!("[RUST] Passive ARP discovery...");

        scanner::discover_neighbors()
    } else {
        Vec::new()
    };

    println!("[RUST] {} neighbor(s) discovered.", devices.len());

    // ========================================
    // TCP scanning
    // ========================================

    println!("[RUST] TCP verification...");

    let observations = scanner::scan_tcp_ports(
        &settings.network.targets,
        &settings.network.ports,
        settings.network.timeout_ms,
    );

    println!("[RUST] {} observation(s) completed.", observations.len());

    // ========================================
    // Convert observations to JSON events
    // ========================================

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

    // ========================================
    // Build complete Python input
    // ========================================

    let input_data = json!({
        "source": "rust-network-engine",
        "devices": devices,
        "events": events,
        "analysis_config": &settings.analysis
    });

    // ========================================
    // Python brain communication
    // ========================================

    let python_script = root.join("python-brain/main.py");

    println!("[RUST] Sending observations to Python...");

    let mut child = Command::new(&settings.engines.python.executable)
        .arg(&python_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("Cannot start Python: {}", error))?;

    // Serialize input
    let input = serde_json::to_vec(&input_data)
        .map_err(|error| format!("JSON serialization failed: {}", error))?;

    // Send JSON to Python stdin
    child
        .stdin
        .take()
        .ok_or("Python stdin unavailable")?
        .write_all(&input)
        .map_err(|error| format!("Data transmission failed: {}", error))?;

    // Wait for Python response
    let output = child
        .wait_with_output()
        .map_err(|error| format!("Python execution failed: {}", error))?;

    // Validate Python process
    if !output.status.success() {
        return Err("Python analysis failed".into());
    }

    // ========================================
    // Parse Python JSON response
    // ========================================

    let result: Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Invalid Python JSON response: {}", error))?;

    // ========================================
    // Display security report
    // ========================================

    println!("\n[RUST] Security report:\n");

    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .map_err(|error| { format!("JSON display error: {}", error) })?
    );

    println!("\n[SUCCESS] NOUR SENTINEL v0.2.1 operational.");

    Ok(())
}

// ============================================
// Application entry point
// ============================================

fn main() {
    if let Err(error) = run() {
        eprintln!("[ERROR] {}", error);

        std::process::exit(1);
    }
}
