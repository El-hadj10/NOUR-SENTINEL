//! Verrou d'autorisation interne au processus Rust.
//!
//! L'Auth Gate Python n'émet `AUTH_OK` qu'après vérification Argon2id.
//! `main` appelle alors `authorize()` ; les fonctions de collecte et de
//! persistance vérifient ce verrou avant d'agir.
//!
//! Cette protection est une défense en profondeur contre un réordonnancement
//! accidentel du binaire. Elle ne prétend pas empêcher un administrateur de
//! modifier le programme ni d'appeler `authorize()` depuis du code injecté :
//! cette limite reste celle du modèle de menace documenté.

use std::sync::atomic::{AtomicBool, Ordering};

static AUTHORIZED: AtomicBool = AtomicBool::new(false);

/// Marque le processus comme autorisé. Appelé une seule fois, après AUTH_OK.
pub fn authorize() {
    AUTHORIZED.store(true, Ordering::SeqCst);
}

fn check(authorized: bool) -> Result<(), String> {
    if authorized {
        Ok(())
    } else {
        Err("collecte refusée : autorisation Argon2id absente".to_string())
    }
}

/// Refuse toute opération sensible tant que `AUTH_OK` n'a pas été reçu.
pub fn require() -> Result<(), String> {
    // En tests unitaires, le harnais exerce les fonctions de collecte sans
    // Auth Gate. Le binaire réel (compilé sans `cfg(test)`) applique le
    // verrou, et les tests E2E le prouvent avant/après authentification.
    #[cfg(test)]
    {
        Ok(())
    }

    #[cfg(not(test))]
    {
        check(AUTHORIZED.load(Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_refuses_without_authorization() {
        assert!(check(false).is_err());
    }

    #[test]
    fn check_accepts_after_authorization() {
        assert!(check(true).is_ok());
    }

    #[test]
    fn authorize_sets_the_process_latch() {
        authorize();
        assert!(AUTHORIZED.load(Ordering::SeqCst));
    }
}
