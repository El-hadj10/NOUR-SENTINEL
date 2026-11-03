use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanRecord {
    pub id: i64,
    pub timestamp: String,
    pub targets: String,
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

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    targets TEXT NOT NULL,
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
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id ON scan_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_events_ip_port ON scan_events(ip, port);
";

fn get_db_path(root: &Path) -> PathBuf {
    let data_dir = root.join("data").join("history");
    let _ = fs::create_dir_all(&data_dir);
    data_dir.join("nour_sentinel.db")
}

/// Ouvre (ou crée) la base d'historique et applique le schéma.
pub fn init_db(root: &Path) -> Result<Connection> {
    let conn = Connection::open(get_db_path(root))?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Enregistre un scan et ses événements dans une transaction atomique.
/// Retourne l'identifiant du scan inséré.
pub fn save_scan(conn: &Connection, targets: &[String], report: &Value) -> Result<i64> {
    let timestamp = Utc::now().to_rfc3339();
    let targets_str = targets.join(",");
    let open_ports = report["network"]["open_ports"].as_i64().unwrap_or(0);
    let findings_count = report["findings_count"].as_i64().unwrap_or(0);
    let raw_report = serde_json::to_string(report).unwrap_or_default();

    let tx = conn.unchecked_transaction()?;

    tx.execute(
        "INSERT INTO scans (timestamp, targets, open_ports_count, findings_count, raw_report)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![timestamp, targets_str, open_ports, findings_count, raw_report],
    )?;

    let scan_id = tx.last_insert_rowid();

    if let Some(events) = report["events"].as_array() {
        for event in events {
            if let (Some(ip), Some(port), Some(state)) = (
                event["ip"].as_str(),
                event["port"].as_u64(),
                event["state"].as_str(),
            ) {
                tx.execute(
                    "INSERT INTO scan_events (scan_id, ip, port, state) VALUES (?1, ?2, ?3, ?4)",
                    params![scan_id, ip, port as i64, state],
                )?;
            }
        }
    }

    tx.commit()?;

    Ok(scan_id)
}

/// Charge l'état observé de chaque (ip, port) pour un scan donné.
fn load_states(conn: &Connection, scan_id: i64) -> Result<HashMap<(String, u16), String>> {
    let mut stmt = conn.prepare("SELECT ip, port, state FROM scan_events WHERE scan_id = ?1")?;
    let rows = stmt.query_map(params![scan_id], |row| {
        Ok((
            (row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u16),
            row.get::<_, String>(2)?,
        ))
    })?;

    let mut states = HashMap::new();
    for row in rows {
        let (key, state) = row?;
        states.insert(key, state);
    }

    Ok(states)
}

/// Détecte les changements entre le scan courant et le scan précédent.
///
/// Trois états sont distingués : `open`, `closed`, `filtered_or_unreachable`.
/// Une transition `open -> filtered_or_unreachable` est signalée comme un état
/// indéterminé et n'est jamais comptée comme une fermeture de port.
pub fn detect_changes(conn: &Connection, current_scan_id: i64) -> Result<Vec<BehavioralChange>> {
    let prev_scan_id: Option<i64> = conn
        .query_row(
            "SELECT id FROM scans WHERE id < ?1 ORDER BY id DESC LIMIT 1",
            params![current_scan_id],
            |row| row.get(0),
        )
        .optional()?;

    let Some(prev_scan_id) = prev_scan_id else {
        return Ok(Vec::new());
    };

    let previous = load_states(conn, prev_scan_id)?;
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

    let mut stmt = conn.prepare(
        "SELECT id, timestamp, targets, open_ports_count, findings_count
         FROM scans ORDER BY id DESC LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit], |row| {
        Ok(ScanRecord {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            targets: row.get(2)?,
            open_ports_count: row.get(3)?,
            findings_count: row.get(4)?,
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

    fn report(events: &[(&str, u16, &str)]) -> Value {
        json!({
            "network": {
                "open_ports": events.iter().filter(|(_, _, s)| *s == "open").count(),
            },
            "findings_count": 0,
            "events": events
                .iter()
                .map(|(ip, port, state)| json!({ "ip": ip, "port": port, "state": state }))
                .collect::<Vec<Value>>(),
        })
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
    }

    #[test]
    fn save_scan_records_scan_and_events() {
        let root = temp_root("save");
        let conn = init_db(&root).unwrap();

        let scan_id = save_scan(
            &conn,
            &["127.0.0.1".to_string()],
            &report(&[("127.0.0.1", 22, "open"), ("127.0.0.1", 443, "closed")]),
        )
        .unwrap();

        let (targets, open_ports): (String, i64) = conn
            .query_row(
                "SELECT targets, open_ports_count FROM scans WHERE id = ?1",
                params![scan_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
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
        assert_eq!(open_ports, 1);
        assert_eq!(events, 2);
    }

    #[test]
    fn first_scan_has_no_changes() {
        let root = temp_root("first");
        let conn = init_db(&root).unwrap();

        let scan_id =
            save_scan(&conn, &["127.0.0.1".to_string()], &report(&[("127.0.0.1", 22, "open")]))
                .unwrap();

        assert!(detect_changes(&conn, scan_id).unwrap().is_empty());
    }

    #[test]
    fn detect_changes_reports_newly_open_port() {
        let root = temp_root("new");
        let conn = init_db(&root).unwrap();

        save_scan(
            &conn,
            &["127.0.0.1".to_string()],
            &report(&[("127.0.0.1", 22, "closed")]),
        )
        .unwrap();

        let second = save_scan(
            &conn,
            &["127.0.0.1".to_string()],
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
            &["127.0.0.1".to_string()],
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let second = save_scan(
            &conn,
            &["127.0.0.1".to_string()],
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
            &["127.0.0.1".to_string()],
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let second = save_scan(
            &conn,
            &["127.0.0.1".to_string()],
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
            &["127.0.0.1".to_string()],
            &report(&[("127.0.0.1", 22, "open")]),
        )
        .unwrap();

        let second = save_scan(&conn, &["127.0.0.1".to_string()], &report(&[])).unwrap();

        let changes = detect_changes(&conn, second).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].change_type, ChangeType::Removed);
        assert_eq!(changes[0].current_state, None);
    }

    #[test]
    fn summary_returns_recent_scans_first() {
        let root = temp_root("summary");
        let conn = init_db(&root).unwrap();

        save_scan(&conn, &["127.0.0.1".to_string()], &report(&[])).unwrap();
        let second = save_scan(&conn, &["127.0.0.1".to_string()], &report(&[])).unwrap();

        let records = get_history_summary(&conn, 5).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, second);
    }
}