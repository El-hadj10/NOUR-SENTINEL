
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    println!("====================================");
    println!("       NOUR SENTINEL v0.1.0");
    println!("====================================");

    println!("[RUST] Initialisation du moteur...");

    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("Impossible de trouver la racine du projet")
        .to_path_buf();

    let python_script = project_root
        .join("python-brain")
        .join("main.py");

    let input_data = json!({
        "source": "rust-engine",
        "events": [
            {
                "type": "port_observed",
                "port": 22,
                "state": "open"
            },
            {
                "type": "port_observed",
                "port": 443,
                "state": "open"
            },
            {
                "type": "port_observed",
                "port": 3389,
                "state": "open"
            }
        ]
    });

    println!("[RUST] Transmission des données à Python...");

    let mut child = Command::new("python3")
        .arg(&python_script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Impossible de lancer Python");

    let input = serde_json::to_vec(&input_data)
        .expect("Erreur de sérialisation JSON");

    child.stdin
        .take()
        .expect("Entrée Python indisponible")
        .write_all(&input)
        .expect("Erreur de transmission");

    let output = child.wait_with_output()
        .expect("Erreur de communication avec Python");

    if !output.status.success() {
        eprintln!("[ERROR] Le moteur Python a échoué.");
        std::process::exit(1);
    }

    let result: Value = serde_json::from_slice(&output.stdout)
        .expect("Réponse JSON invalide");

    println!("\n[RUST] Analyse reçue !");
    println!("[RUST] Rapport de sécurité :\n");

    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .expect("Erreur d'affichage JSON")
    );

    println!("\n[SUCCESS] NOUR SENTINEL fonctionne.");
}
