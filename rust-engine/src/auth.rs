//! Contrôle d'accès propriétaire, exécuté avant configuration et réseau.
//!
//! Aucune session locale n'est acceptée. Le moteur exige un terminal
//! interactif puis délègue la vérification Argon2id à l'Auth Gate Python.
//! L'interpréteur et le script sont determinés depuis la racine du projet :
//! aucune variable d'environnement ne peut les substituer.

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Interpréteur Python privé du laboratoire, créé par ``--setup-deps``.
pub fn python_interpreter(root: &Path) -> PathBuf {
    root.join(".venv/bin/python")
}

/// Script d'authentification livré avec le laboratoire.
pub fn auth_script(root: &Path) -> PathBuf {
    root.join("python-brain/security_intelligence/auth_gate.py")
}

/// Refuse un lancement non interactif avant toute collecte.
pub fn require_terminal(is_terminal: bool) -> Result<(), String> {
    if !is_terminal {
        return Err(
            "terminal interactif requis : authentifiez-vous avec ./lancer-nour-sentinel.sh"
                .to_string(),
        );
    }

    Ok(())
}

/// Construit la commande d'authentification, sans secret ni session.
pub fn auth_command(root: &Path) -> Result<Command, String> {
    let python = python_interpreter(root);
    let script = auth_script(root);

    if !python.is_file() {
        return Err(format!(
            "environnement Python du laboratoire absent ({}); exécutez --setup-deps",
            python.display()
        ));
    }

    if !script.is_file() {
        return Err(format!(
            "Auth Gate introuvable: {}",
            script.display()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(&python)
            .map_err(|error| format!("interpréteur Python illisible: {}", error))?
            .permissions()
            .mode();

        if mode & 0o111 == 0 {
            return Err(format!(
                "interpréteur Python non exécutable: {}",
                python.display()
            ));
        }
    }

    let mut command = Command::new(&python);
    command.arg(&script).arg("authenticate");

    Ok(command)
}

/// Authentifie avant toute lecture de configuration.
pub fn enforce(root: &Path) -> Result<(), String> {
    require_terminal(std::io::stdin().is_terminal())?;

    let mut command = auth_command(root)?;
    let status = command
        .status()
        .map_err(|error| format!("Auth Gate indisponible: {}", error))?;

    if !status.success() {
        return Err("authentification refusée".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fixture(with_files: bool) -> PathBuf {
        let identifier = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "nour-auth-{}-{}",
            std::process::id(),
            identifier
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        if with_files {
            let python = python_interpreter(&root);
            let script = auth_script(&root);

            fs::create_dir_all(python.parent().unwrap()).unwrap();
            fs::create_dir_all(script.parent().unwrap()).unwrap();
            fs::write(&python, b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&python, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&script, b"# fixture\n").unwrap();
        }

        root
    }

    #[test]
    fn uses_deterministic_project_interpreter() {
        let root = Path::new("/opt/nour-sentinel");

        assert_eq!(
            python_interpreter(root),
            PathBuf::from("/opt/nour-sentinel/.venv/bin/python")
        );
        assert_eq!(
            auth_script(root),
            PathBuf::from("/opt/nour-sentinel/python-brain/security_intelligence/auth_gate.py")
        );
    }

    #[test]
    fn builds_authenticate_command_without_secret_or_session() {
        let root = fixture(true);
        let command = auth_command(&root).unwrap();
        let arguments: Vec<String> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().to_string())
            .collect();

        assert_eq!(command.get_program(), python_interpreter(&root));
        assert_eq!(arguments, vec![
            auth_script(&root).to_string_lossy().to_string(),
            "authenticate".to_string()
        ]);
        assert!(!arguments.iter().any(|argument| argument.contains("session")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refuses_missing_interpreter_or_gate() {
        let root = fixture(false);

        let error = auth_command(&root).unwrap_err();

        assert!(error.contains("Python du laboratoire absent"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refuses_non_interactive_terminal() {
        assert!(require_terminal(false).is_err());
        assert!(require_terminal(true).is_ok());
    }
}
