//! Interpréteur Python déterministe du laboratoire.
//!
//! L'authentification est désormais exécutée dans le processus Python avant
//! lecture du payload. Rust se contente de vérifier que l'interpréteur privé
//! `.venv/bin/python` existe et est exécutable ; aucune variable
//! d'environnement ne peut le substituer.

use std::fs;
use std::path::{Path, PathBuf};

/// Interpréteur Python privé du laboratoire, créé par ``--setup-deps``.
pub fn python_interpreter(root: &Path) -> PathBuf {
    root.join(".venv/bin/python")
}

/// Valide l'interpréteur avant de démarrer le processus Python.
pub fn ensure_interpreter(root: &Path) -> Result<PathBuf, String> {
    let python = python_interpreter(root);

    if !python.is_file() {
        return Err(format!(
            "environnement Python du laboratoire absent ({}); exécutez --setup-deps",
            python.display()
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

    Ok(python)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fixture(with_files: bool) -> PathBuf {
        let identifier = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root =
            std::env::temp_dir().join(format!("nour-auth-{}-{}", std::process::id(), identifier));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        if with_files {
            let python = python_interpreter(&root);
            fs::create_dir_all(python.parent().unwrap()).unwrap();
            fs::write(&python, b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(&python, fs::Permissions::from_mode(0o700)).unwrap();
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
    }

    #[test]
    fn refuses_missing_or_non_executable_interpreter() {
        let root = fixture(false);
        let error = ensure_interpreter(&root).unwrap_err();
        assert!(error.contains("Python du laboratoire absent"));
        let _ = fs::remove_dir_all(root);

        let root = fixture(true);
        let python = python_interpreter(&root);
        fs::set_permissions(&python, fs::Permissions::from_mode(0o600)).unwrap();
        let error = ensure_interpreter(&root).unwrap_err();
        assert!(error.contains("non exécutable"));
        let _ = fs::remove_dir_all(root);
    }
}
