//! Contrôle d'accès propriétaire, exécuté avant configuration et réseau.
//!
//! Le secret est vérifié par l'Auth Gate Python (Argon2id). Le moteur Rust
//! consomme ensuite une session locale courte, fichier 0600, pour éviter une
//! double saisie. Un lancement direct sans session valide demande la phrase
//! secrète sur un terminal interactif ; sans terminal, il est refusé.

use serde::Deserialize;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Une session ne peut jamais dépasser une heure, même si le fichier ment.
const MAX_SESSION_SECONDS: i64 = 3600;

#[derive(Deserialize)]
struct SessionFile {
    expires_at: i64,
}

pub fn session_path() -> PathBuf {
    if let Ok(path) = std::env::var("NOUR_SENTINEL_SESSION") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }

    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());

    PathBuf::from(home).join(".config/nour-sentinel/session.json")
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Vérifie forme, permissions et expiration de la session.
pub fn validate_session(path: &Path, current: i64) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| "session absente : authentification requise".to_string())?;

    if !metadata.file_type().is_file() {
        return Err("session refusée : fichier ordinaire requis".to_string());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("session refusée : permissions trop larges (0600 requis)".to_string());
        }
    }

    let text = fs::read_to_string(path)
        .map_err(|error| format!("session illisible: {}", error))?;
    let session: SessionFile = serde_json::from_str(&text)
        .map_err(|_| "session invalide : JSON attendu".to_string())?;

    if session.expires_at <= current {
        return Err("session expirée : authentifiez-vous à nouveau".to_string());
    }

    if session.expires_at > current + MAX_SESSION_SECONDS {
        return Err("session refusée : durée anormale".to_string());
    }

    Ok(())
}

/// Authentifie avant toute lecture de configuration.
pub fn enforce(root: &Path) -> Result<(), String> {
    let path = session_path();

    if validate_session(&path, now()).is_ok() {
        return Ok(());
    }

    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "Accès refusé : authentifiez-vous avec ./lancer-nour-sentinel.sh (session attendue: {})",
            path.display()
        ));
    }

    let python = std::env::var("NOUR_SENTINEL_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let script = root.join("python-brain/security_intelligence/auth_gate.py");

    let status = Command::new(python)
        .arg(script)
        .arg("login")
        .arg("--session-file")
        .arg(&path)
        .status()
        .map_err(|error| format!("Auth Gate indisponible: {}", error))?;

    if !status.success() {
        return Err("authentification refusée".to_string());
    }

    validate_session(&path, now())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fixture(contents: &str, mode: u32) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let identifier = COUNTER.fetch_add(1, Ordering::SeqCst);
        let directory = std::env::temp_dir().join(format!(
            "nour-auth-{}-{}",
            std::process::id(),
            identifier
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

        let path = directory.join("session.json");
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();

        (directory, path)
    }

    #[test]
    fn accepts_valid_session() {
        let (directory, path) = fixture(r#"{"expires_at": 2000}"#, 0o600);

        assert!(validate_session(&path, 1000).is_ok());

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_expired_session() {
        let (directory, path) = fixture(r#"{"expires_at": 900}"#, 0o600);

        assert!(validate_session(&path, 1000).is_err());

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_overlong_session() {
        let (directory, path) = fixture(r#"{"expires_at": 9000}"#, 0o600);

        assert!(validate_session(&path, 1000).is_err());

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_loose_permissions() {
        let (directory, path) = fixture(r#"{"expires_at": 2000}"#, 0o644);

        assert!(validate_session(&path, 1000).is_err());

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_malformed_session() {
        let (directory, path) = fixture("not-json", 0o600);

        assert!(validate_session(&path, 1000).is_err());

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_symlinked_session() {
        let (directory, path) = fixture(r#"{"expires_at": 2000}"#, 0o600);
        let link = directory.join("session-link.json");

        symlink(&path, &link).unwrap();

        assert!(validate_session(&link, 1000).is_err());

        let _ = fs::remove_dir_all(directory);
    }
}
