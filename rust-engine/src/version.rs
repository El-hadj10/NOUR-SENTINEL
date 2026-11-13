//! Versions affichées par le binaire.
//!
//! Elles sont synchronisées avec `python-brain/version.py` par un test.

pub const CORE_VERSION: &str = "0.5.0";
pub const LAB_VERSION: &str = "0.6.0-beta.4";
pub const PROTOCOL_VERSION: &str = "3.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_match_python_source() {
        let source = include_str!("../../python-brain/version.py");

        assert!(source.contains(&format!("CORE_VERSION = \"{}\"", CORE_VERSION)));
        assert!(source.contains(&format!("LAB_VERSION = \"{}\"", LAB_VERSION)));
        assert!(source.contains(&format!(
            "PROTOCOL_VERSION = \"{}\"",
            PROTOCOL_VERSION
        )));
    }
}
