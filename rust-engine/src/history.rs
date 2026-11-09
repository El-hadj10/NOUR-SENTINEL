use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Répertoire d'historique alternatif (utilisé notamment par les tests).
pub const HISTORY_DIR_ENV: &str = "NOUR_SENTINEL_HISTORY_DIR";

const SCHEMA_VERSION: i64 = 1;

const TABLES: &str = "
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    targets TEXT NOT NULL,
    ports TEXT NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    open_ports_count INTEGER NOT NULL,
    findings_count INTEGER NOT NULL,
    raw_report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
";

const INDEXES: &str = "
CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id ON scan_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_ip_port ON scan_events(ip, port);
CREATE INDEX IF NOT EXISTS idx_scans_scope ON scans(scope, id);
";

/// Erreur explicite de la couche d'historique : aucune erreur de stockage
/// n'est ignorée silencieusement.
#[derive(Debug)]
pub enum HistoryError {
    Database(rusqlite::Error),
    Io(std::io::Error),
    InvalidData(String),
}

impl fmt::Display for HistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryError::Database(error) => write!(formatter, "database error: {}", error),
            HistoryError::Io(error) => write!(formatter, "filesystem error: {}", error),
            HistoryError::InvalidData(message) => write!(formatter, "invalid history data: {}", message),
        }
    }
}

impl std::error::Error for HistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HistoryError::Database(error) => Some(error),
            HistoryError::Io(error) => Some(error),
            HistoryError::InvalidData(_) => None,
        }
    }
}

impl From<rusqlite::Error> for HistoryError {
    fn from(error: rusqlite::Error) -> Self {
        HistoryError::Database(error)
    }
}

impl From<std::io::Error> for HistoryError {
    fn from(error: std::io::Error) -> Self {
        HistoryError::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, HistoryError>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanRecord {
    pub id: i64,
    pub timestamp: String,
    pub targets: String,
    pub ports: String,
    pub open_ports_count: i32,
    pub findings_count: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    New,
    Removed,
    StateChanged,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BehavioralChange {
    pub port: u16,
    pub ip: String,
    pub change_type: ChangeType,
    pub previous_state: Option<String>,
    pub current_state: Option<String>,
}

/// Périmètre d'un scan : cibles et ports réellement vérifiés.
///
/// Deux scans ne sont comparables que si leurs périmètres sont identiques.
/// L'ordre de déclaration est neutre : les valeurs sont triées et dédupliquées.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanScope {
    targets: Vec<String>,
    ports: Vec<u16>,
}

impl ScanScope {
    pub fn new(targets: &[String], ports: &[u16]) -> Self {
        let mut targets = targets.to_vec();
        targets.sort();
        targets.dedup();

        let mut ports = ports.to_vec();
        ports.sort_unstable();
        ports.dedup();

        ScanScope { targets, ports }
    }

    pub fn targets(&self) -> &[String] {
        &self.targets
    }

    pub fn ports(&self) -> &[u16] {
        &self.ports
    }

    fn fingerprint(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(u16::to_string).collect();

        format!("{}|{}", self.targets.join(","), ports.join(","))
    }
}

/// Résultat d'une comparaison historique.
#[derive(Debug, Serialize, Clone)]
pub struct ScopeComparison {
    /// Identifiant du scan de même périmètre réellement utilisé.
    pub previous_scan_id: Option<i64>,
    /// Vrai si le scan immédiatement précédent avait un autre périmètre.
    pub scope_changed: bool,
    pub changes: Vec<BehavioralChange>,
}

/// Résout le répertoire d'historique (surcharge explicite ou emplacement par défaut).
pub fn resolve_history_dir(root: &Path, override_dir: Option<&Path>) -> PathBuf {
    match override_dir {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => root.join("data").join("history"),
    }
}

fn history_dir(root: &Path) -> PathBuf {
    let override_dir = env::var_os(HISTORY_DIR_ENV).map(PathBuf::from);

    resolve_history_dir(root, override_dir.as_deref())
}

/// Ouvre (ou crée) la base d'historique et applique le schéma.
pub fn init_db(root: &Path) -> Result<Connection> {
    init_db_in(&history_dir(root))
}

/// Ouvre la base dans un répertoire donné, en propageant toute erreur.
pub fn init_db_in(dir: &Path) -> Result<Connection> {
    crate::gate::require()
        .expect("ouverture SQLite refusée sans autorisation");

    fs::create_dir_all(dir)?;

    let conn = Connection::open(dir.join("nour_sentinel.db"))?;

    // Les contraintes déclarées ne sont appliquées que si le PRAGMA est actif.
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.busy_timeout(Duration::from_secs(5))?;

    migrate(&conn)?;

    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(TABLES)?;

    // Migration depuis la base v0.4.0, qui ne stockait pas le périmètre.
    ensure_column(conn, "scans", "ports", "TEXT NOT NULL DEFAULT ''")?;
    ensure_column(conn, "scans", "scope", "TEXT NOT NULL DEFAULT ''")?;

    conn.execute_batch(INDEXES)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;

    Ok(())
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let mut rows = statement.query([])?;

    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;

        if name == column {
            return Ok(true);
        }
    }

    Ok(false)
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    if !has_column(conn, table, column)? {
        conn.execute(
            &format!("ALTER TABLE {} ADD COLUMN {} {}", table, column, definition),
            [],
        )?;
    }

    Ok(())
}

/// États d'observation acceptés : ceux produits par le scanner.
const VALID_STATES: [&str; 3] = ["open", "closed", "filtered_or_unreachable"];

/// Valide une observation avant enregistrement et après lecture.
fn validate_event(ip: &str, port: u16, state: &str) -> Result<()> {
    ip.parse::<IpAddr>()
        .map_err(|_| HistoryError::InvalidData(format!("invalid event ip: {}", ip)))?;

    if port == 0 {
        return Err(HistoryError::InvalidData("event port 0 is not valid".into()));
    }

    if !VALID_STATES.contains(&state) {
        return Err(HistoryError::InvalidData(format!(
            "invalid event state: {}",
            state
        )));
    }

    Ok(())
}

/// Enregistre un scan et ses événements dans une transaction atomique.
/// Les événements sont validés avant toute écriture : en cas de donnée
/// invalide, rien n'est enregistré et l'erreur est retournée.
pub fn save_scan(conn: &Connection, scope: &ScanScope, report: &Value) -> Result<i64> {
    crate::gate::require()
        .expect("écriture SQLite refusée sans autorisation");

    let timestamp = Utc::now().to_rfc3339();
    let targets = scope.targets().join(",");
    let ports: Vec<String> = scope.ports().iter().map(u16::to_string).collect();
    let ports = ports.join(",");
    let fingerprint = scope.fingerprint();

    let open_ports = report["network"]["open_ports"].as_i64().unwrap_or(0);
    let findings_count = report["findings_count"].as_i64().unwrap_or(0);

    let raw_report = serde_json::to_string(report)
        .map_err(|error| HistoryError::InvalidData(format!("report is not serializable: {}", error)))?;

    let mut events: Vec<(&str, u16, &str)> = Vec::new();

    if let Some(items) = report["events"].as_array() {
        for event in items {
            let ip = event["ip"]
                .as_str()
                .ok_or_else(|| HistoryError::InvalidData("event without ip".into()))?;

            let raw_port = event["port"]
                .as_u64()
                .ok_or_else(|| HistoryError::InvalidData("event without port".into()))?;

            let port = u16::try_from(raw_port).map_err(|_| {
                HistoryError::InvalidData(format!("event port out of range: {}", raw_port))
            })?;

            let state = event["state"]
                .as_str()
                .ok_or_else(|| HistoryError::InvalidData("event without state".into()))?;

            validate_event(ip, port, state)?;

            events.push((ip, port, state));
        }
    }

    let transaction = conn.unchecked_transaction()?;

    transaction.execute(
        "INSERT INTO scans (timestamp, targets, ports, scope, open_ports_count, findings_count, raw_report)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            timestamp,
            targets,
            ports,
            fingerprint,
            open_ports,
            findings_count,
            raw_report
        ],
    )?;

    let scan_id = transaction.last_insert_rowid();

    for (ip, port, state) in &events {
        transaction.execute(
            "INSERT INTO scan_events (scan_id, ip, port, state) VALUES (?1, ?2, ?3, ?4)",
            params![scan_id, ip, port, state],
        )?;
    }

    transaction.commit()?;

    Ok(scan_id)
}

/// Charge l'état observé de chaque (ip, port) pour un scan donné.
fn load_states(conn: &Connection, scan_id: i64) -> Result<HashMap<(String, u16), String>> {
    let mut statement = conn.prepare("SELECT ip, port, state FROM scan_events WHERE scan_id = ?1")?;

    let rows = statement.query_map(params![scan_id], |row| {
        let ip: String = row.get(0)?;
        let raw_port: i64 = row.get(1)?;

        // Refus explicite d'une valeur hors plage plutôt que troncature.
        let port = u16::try_from(raw_port)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, raw_port))?;

        let state: String = row.get(2)?;

        Ok(((ip, port), state))
    })?;

    let mut states = HashMap::new();

    for row in rows {
        let ((ip, port), state) = row?;

        // Les données relues sont validées comme celles écrites : une base
        // modifiée à la main ne doit pas produire d'analyse silencieuse.
        validate_event(&ip, port, &state)?;

        states.insert((ip, port), state);
    }

    Ok(states)
}

/// Détecte les changements entre deux scans de périmètre identique et signale
/// les changements de périmètre.
///
/// Les scans dont les cibles ou les ports diffèrent ne sont jamais comparés :
/// une différence de périmètre n'est pas une apparition ni une disparition de
/// service.
pub fn detect_scan_changes(conn: &Connection, current_scan_id: i64) -> Result<ScopeComparison> {
    let current_scope: Option<String> = conn
        .query_row(
            "SELECT scope FROM scans WHERE id = ?1",
            params![current_scan_id],
            |row| row.get(0),
        )
        .optional()?;

    let Some(current_scope) = current_scope else {
        return Err(HistoryError::InvalidData(format!(
            "unknown scan id: {}",
            current_scan_id
        )));
    };

    let latest_previous: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, scope FROM scans WHERE id < ?1 ORDER BY id DESC LIMIT 1",
            params![current_scan_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let scope_changed = latest_previous
        .as_ref()
        .map(|(_, previous_scope)| *previous_scope != current_scope)
        .unwrap_or(false);

    let previous_scan_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM scans WHERE id < ?1 AND scope = ?2 ORDER BY id DESC LIMIT 1",
            params![current_scan_id, current_scope],
            |row| row.get(0),
        )
        .optional()?;

    let Some(previous_scan_id) = previous_scan_id else {
        return Ok(ScopeComparison {
            previous_scan_id: None,
            scope_changed,
            changes: Vec::new(),
        });
    };

    let changes = compare_scans(conn, previous_scan_id, current_scan_id)?;

    Ok(ScopeComparison {
        previous_scan_id: Some(previous_scan_id),
        scope_changed,
        changes,
    })
}

/// Détecte les changements entre le scan courant et le dernier scan comparable.
///
/// Trois états sont distingués : `open`, `closed`, `filtered_or_unreachable`.
/// Une transition `open -> filtered_or_unreachable` est signalée comme un état
/// indéterminé et n'est jamais comptée comme une fermeture de port.
pub fn detect_changes(conn: &Connection, current_scan_id: i64) -> Result<Vec<BehavioralChange>> {
    Ok(detect_scan_changes(conn, current_scan_id)?.changes)
}

fn compare_scans(
    conn: &Connection,
    previous_scan_id: i64,
    current_scan_id: i64,
) -> Result<Vec<BehavioralChange>> {
    let previous = load_states(conn, previous_scan_id)?;
    let current = load_states(conn, current_scan_id)?;

    let mut changes: Vec<BehavioralChange> = Vec::new();

    for (key, curr_state) in &current {
        let prev_state = previous.get(key);

        match (prev_state.map(String::as_str), curr_state.as_str()) {
            // Port jamais observé qui devient ouvert.
            (None, "open") => changes.push(BehavioralChange {
                port: key.1,
                ip: key.0.clone(),
                change_type: ChangeType::New,
                previous_state: None,
                current_state: Some("open".to_string()),
            }),
            // Port connu mais qui n'était pas ouvert et le devient.
            (Some(state), "open") if state != "open" => changes.push(BehavioralChange {
                port: key.1,
                ip: key.0.clone(),
                change_type: ChangeType::StateChanged,
                previous_state: Some(state.to_string()),
                current_state: Some("open".to_string()),
            }),
            // Fermeture réelle.
            (Some("open"), "closed") => changes.push(BehavioralChange {
                port: key.1,
                ip: key.0.clone(),
                change_type: ChangeType::StateChanged,
                previous_state: Some("open".to_string()),
                current_state: Some("closed".to_string()),
            }),
            // Indéterminé : filtrage ou cible injoignable, pas une fermeture.
            (Some("open"), "filtered_or_unreachable") => changes.push(BehavioralChange {
                port: key.1,
                ip: key.0.clone(),
                change_type: ChangeType::StateChanged,
                previous_state: Some("open".to_string()),
                current_state: Some("filtered_or_unreachable".to_string()),
            }),
            // filtered -> closed n'est pas une fermeture démontrée : ignoré.
            _ => {}
        }
    }

    // Ports ouverts au scan précédent et absents du scan courant.
    for (key, prev_state) in &previous {
        if prev_state == "open" && !current.contains_key(key) {
            changes.push(BehavioralChange {
                port: key.1,
                ip: key.0.clone(),
                change_type: ChangeType::Removed,
                previous_state: Some("open".to_string()),
                current_state: None,
            });
        }
    }

    changes.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.port.cmp(&b.port)));

    Ok(changes)
}

/// Retourne les `limit` derniers scans, du plus récent au plus ancien.
pub fn get_history_summary(conn: &Connection, limit: i32) -> Result<Vec<ScanRecord>> {
    let limit = if limit > 0 { limit } else { 10 };

    let mut statement = conn.prepare(
        "SELECT id, timestamp, targets, ports, open_ports_count, findings_count
         FROM scans ORDER BY id DESC LIMIT ?1",
    )?;

    let rows = statement.query_map(params![limit], |row| {
        Ok(ScanRecord {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            targets: row.get(2)?,
            ports: row.get(3)?,
            open_ports_count: row.get(4)?,
            findings_count: row.get(5)?,
        })
    })?;

    let mut records = Vec::new();

    for row in rows {
        records.push(row?);
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nour_sentinel_history_{}_{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn scope(ports: &[u16]) -> ScanScope {
        ScanScope::new(&["127.0.0.1".to_string()], ports)
    }

    fn report(events: &[(&str, u16, &str)]) -> Value {
        json!({
            "network": {
                "open_ports": events.iter().filter(|(_, _, state)| *state == "open").count(),
            },
            "findings_count": 0,
            "events": events
                .iter()
                .map(|(ip, port, state)| json!({ "ip": ip, "port": port, "state": state }))
                .collect::<Vec<Value>>(),
        })
    }

    fn insert_legacy_scan(conn: &Connection) -> i64 {
        conn.execute(
            "INSERT INTO scans (timestamp, targets, ports, scope, open_ports_count, findings_count, raw_report)
             VALUES ('legacy', '127.0.0.1', '22', '127.0.0.1|22', 1, 0, '{}')",
            [],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn init_creates_required_tables() {
        let root = temp_root("init");
        let conn = init_db(&root).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN ('scans', 'scan_events')",
                [],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(count, 2);

        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();

        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let root = temp_root("foreign_keys");
        let conn = init_db(&root).unwrap();

        let result = conn.execute(
            "INSERT INTO scan_events (scan_id, ip, port, state)
             VALUES (999, '127.0.0.1', 22, 'open')",
            [],
        );

        assert!(result.is_err(), "une clé étrangère invalide doit être refusée");
    }

    #[test]
    fn save_scan_records_scan_and_events() {
        let root = temp_root("save");
        let conn = init_db(&root).unwrap();

        let scan_id = save_scan(
            &conn,
            &scope(&[22, 443]),
            &report(&[("127.0.0.1", 22, "open"), ("127.0.0.1", 443, "closed")]),
        )
        .unwrap();

        let (targets, ports, open_ports): (String, String, i64) = conn
            .query_row(
                "SELECT targets, ports, open_ports_count FROM scans WHERE id = ?1",
                params![scan_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        let events: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_events WHERE scan_id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .unwrap();

        assert_eq!(targets, "127.0.0.1");
        assert_eq!(ports, "22,443");
        assert_eq!(open_ports, 1);
        assert_eq!(events, 2);
    }

    #[test]
    fn invalid_event_port_is_rejected_without_writing() {
        let root = temp_root("invalid_port");
        let conn = init_db(&root).unwrap();

        // Valeur hors plage u16 : doit être refusée avant toute écriture.
        let invalid = json!({
            "network": { "open_ports": 1 },
            "findings_count": 0,
            "events": [{ "ip": "127.0.0.1", "port": 70000, "state": "open" }],
        });

        assert!(save_scan(&conn, &scope(&[22]), &invalid).is_err());

        let scans: i64 = conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .unwrap();

        assert_eq!(scans, 0, "aucune écriture partielle ne doit subsister");
    }

    #[test]
    fn invalid_stored_port_is_reported_not_truncated() {
        let root = temp_root("stored_port");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let corrupt_scan = insert_legacy_scan(&conn);

        conn.execute(
            "INSERT INTO scan_events (scan_id, ip, port, state)
             VALUES (?1, '127.0.0.1', 70000, 'open')",
            params![corrupt_scan],
        )
        .unwrap();

        let result = detect_changes(&conn, corrupt_scan);

        assert!(result.is_err(), "un port stocké hors plage doit produire une erreur");
        assert!(matches!(result, Err(HistoryError::Database(_))));
    }

    #[test]
    fn invalid_event_ip_is_rejected_without_writing() {
        let root = temp_root("invalid_ip");
        let conn = init_db(&root).unwrap();

        let invalid = json!({
            "network": { "open_ports": 1 },
            "findings_count": 0,
            "events": [{ "ip": "not-an-ip", "port": 22, "state": "open" }],
        });

        assert!(save_scan(&conn, &scope(&[22]), &invalid).is_err());

        let scans: i64 = conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .unwrap();

        assert_eq!(scans, 0, "aucune écriture partielle ne doit subsister");
    }

    #[test]
    fn invalid_event_state_is_rejected_without_writing() {
        let root = temp_root("invalid_state");
        let conn = init_db(&root).unwrap();

        let invalid = json!({
            "network": { "open_ports": 0 },
            "findings_count": 0,
            "events": [{ "ip": "127.0.0.1", "port": 22, "state": "probably_open" }],
        });

        assert!(save_scan(&conn, &scope(&[22]), &invalid).is_err());

        let scans: i64 = conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))
            .unwrap();

        assert_eq!(scans, 0, "aucune écriture partielle ne doit subsister");
    }

    #[test]
    fn invalid_stored_state_is_reported() {
        let root = temp_root("invalid_stored_state");
        let conn = init_db(&root).unwrap();
        let scan_id = insert_legacy_scan(&conn);

        conn.execute(
            "INSERT INTO scan_events (scan_id, ip, port, state)
             VALUES (?1, '127.0.0.1', 22, 'probably_open')",
            params![scan_id],
        )
        .unwrap();

        // Lecture : un état inconnu est refusé, pas interprété.
        assert!(load_states(&conn, scan_id).is_err());
    }

    #[test]
    fn first_scan_has_no_changes() {
        let root = temp_root("first");
        let conn = init_db(&root).unwrap();

        let scan_id = save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let comparison = detect_scan_changes(&conn, scan_id).unwrap();

        assert!(comparison.changes.is_empty());
        assert_eq!(comparison.previous_scan_id, None);
        assert!(!comparison.scope_changed);
    }

    #[test]
    fn detect_changes_reports_newly_open_port() {
        let root = temp_root("new");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &scope(&[22, 8080]),
            &report(&[("127.0.0.1", 22, "closed")]),
        )
        .unwrap();

        let second = save_scan(
            &conn,
            &scope(&[22, 8080]),
            &report(&[("127.0.0.1", 22, "closed"), ("127.0.0.1", 8080, "open")]),
        )
        .unwrap();

        let changes = detect_changes(&conn, second).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].port, 8080);
        assert_eq!(changes[0].change_type, ChangeType::New);
        assert_eq!(changes[0].current_state.as_deref(), Some("open"));
    }

    #[test]
    fn detect_changes_reports_real_closure() {
        let root = temp_root("closed");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let second = save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "closed")]),
        )
        .unwrap();

        let changes = detect_changes(&conn, second).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::StateChanged);
        assert_eq!(changes[0].previous_state.as_deref(), Some("open"));
        assert_eq!(changes[0].current_state.as_deref(), Some("closed"));
    }

    #[test]
    fn filtered_is_not_reported_as_closed() {
        let root = temp_root("filtered");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let second = save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "filtered_or_unreachable")]),
        )
        .unwrap();

        let changes = detect_changes(&conn, second).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0].current_state.as_deref(),
            Some("filtered_or_unreachable")
        );
        assert_ne!(changes[0].current_state.as_deref(), Some("closed"));
    }

    #[test]
    fn unobserved_open_port_is_removed_not_closed() {
        let root = temp_root("removed");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let second = save_scan(&conn, &scope(&[22]), &report(&[])).unwrap();

        let changes = detect_changes(&conn, second).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Removed);
        assert_eq!(changes[0].current_state, None);
    }

    #[test]
    fn scope_change_is_not_a_service_change() {
        let root = temp_root("scope_change");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        // Le port 443 entre dans le périmètre : ce n'est pas une apparition.
        let second = save_scan(
            &conn,
            &scope(&[22, 443]),
            &report(&[("127.0.0.1", 22, "open"), ("127.0.0.1", 443, "open")]),
        )
        .unwrap();

        let comparison = detect_scan_changes(&conn, second).unwrap();

        assert!(comparison.scope_changed);
        assert_eq!(comparison.previous_scan_id, None);
        assert!(comparison.changes.is_empty());
    }

    #[test]
    fn target_change_is_not_a_service_change() {
        let root = temp_root("target_change");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &scope(&[22]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        // Nouvelle cible : le périmètre change, aucun service n'apparaît.
        let second = save_scan(
            &conn,
            &ScanScope::new(&["127.0.0.2".to_string()], &[22]),
            &report(&[("127.0.0.2", 22, "open")]),
        )
        .unwrap();

        let comparison = detect_scan_changes(&conn, second).unwrap();

        assert!(comparison.scope_changed);
        assert_eq!(comparison.previous_scan_id, None);
        assert!(comparison.changes.is_empty());
    }

    #[test]
    fn comparable_scope_ignores_declaration_order() {
        let root = temp_root("scope_order");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &ScanScope::new(&["127.0.0.1".to_string()], &[22, 443]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let second = save_scan(
            &conn,
            &ScanScope::new(&["127.0.0.1".to_string()], &[443, 22]),
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let comparison = detect_scan_changes(&conn, second).unwrap();

        assert!(!comparison.scope_changed);
        assert_eq!(comparison.previous_scan_id, Some(1));
        assert!(comparison.changes.is_empty());
    }

    #[test]
    fn legacy_database_is_migrated() {
        let root = temp_root("legacy");
        let history_dir = root.join("data").join("history");
        fs::create_dir_all(&history_dir).unwrap();

        {
            let legacy = Connection::open(history_dir.join("nour_sentinel.db")).unwrap();
            legacy
                .execute_batch(
                    "CREATE TABLE scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        targets TEXT NOT NULL,
                        open_ports_count INTEGER NOT NULL,
                        findings_count INTEGER NOT NULL,
                        raw_report TEXT NOT NULL
                    );
                    CREATE TABLE scan_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        ip TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        state TEXT NOT NULL
                    );",
                )
                .unwrap();
        }

        let conn = init_db(&root).unwrap();

        assert!(has_column(&conn, "scans", "scope").unwrap());
        assert!(has_column(&conn, "scans", "ports").unwrap());
    }

    #[test]
    fn corrupt_database_is_reported() {
        let root = temp_root("corrupt");
        let history_dir = root.join("data").join("history");
        fs::create_dir_all(&history_dir).unwrap();
        fs::write(history_dir.join("nour_sentinel.db"), b"not a sqlite database").unwrap();

        assert!(init_db(&root).is_err());
    }

    #[test]
    fn history_directory_override_is_resolved() {
        let root = Path::new("/tmp/nour-root");

        assert_eq!(
            resolve_history_dir(root, Some(Path::new("/tmp/nour-history"))),
            PathBuf::from("/tmp/nour-history")
        );

        assert_eq!(
            resolve_history_dir(root, None),
            PathBuf::from("/tmp/nour-root/data/history")
        );
    }

    #[test]
    fn summary_returns_recent_scans_first() {
        let root = temp_root("summary");
        let conn = init_db(&root).unwrap();

        save_scan(&conn, &scope(&[22]), &report(&[])).unwrap();
        let second = save_scan(&conn, &scope(&[22]), &report(&[])).unwrap();

        let records = get_history_summary(&conn, 5).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, second);
        assert_eq!(records[0].ports, "22");
    }
}
