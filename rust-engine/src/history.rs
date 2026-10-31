use chrono::Utc;
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanRecord {
    pub id: i64,
    pub timestamp: String,
    pub targets: String,
    pub open_ports_count: i32,
    pub findings_count: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortChange {
    pub ip: String,
    pub port: u16,
    pub change: String, // "new", "removed", "unchanged"
    pub previous_state: Option<String>,
    pub current_state: Option<String>,
}

fn get_db_path(root: &PathBuf) -> PathBuf {
    let data_dir = root.join("data").join("history");
    let _ = fs::create_dir_all(&data_dir);
    data_dir.join("nour_sentinel.db")
}

pub fn init_db(root: &PathBuf) -> Result<Connection> {
    let db_path = get_db_path(root);
    let conn = Connection::open(db_path)?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            targets TEXT NOT NULL,
            open_ports_count INTEGER NOT NULL,
            findings_count INTEGER NOT NULL,
            raw_report TEXT NOT NULL
        )",
        [],
    )?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            state TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_events_scan_id ON scan_events(scan_id)",
        [],
    )?;
    
    Ok(conn)
}

pub fn save_scan(conn: &Connection, targets: &[String], report: &serde_json::Value) -> Result<i64> {
    let timestamp = Utc::now().to_rfc3339();
    let targets_str = targets.join(",");
    
    let open_ports = report["network"]["open_ports"].as_i64().unwrap_or(0) as i32;
    let findings_count = report["findings_count"].as_i64().unwrap_or(0) as i32;
    let raw_report = serde_json::to_string(report).unwrap_or_default();
    
    conn.execute(
        "INSERT INTO scans (timestamp, targets, open_ports_count, findings_count, raw_report)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![timestamp, targets_str, open_ports, findings_count, raw_report],
    )?;
    
    let scan_id = conn.last_insert_rowid();
    
    // Save events
    if let Some(events) = report["events"].as_array() {
        for event in events {
            if let (Some(ip), Some(port), Some(state)) = (
                event["ip"].as_str(),
                event["port"].as_u64(),
                event["state"].as_str(),
            ) {
                let _ = conn.execute(
                    "INSERT INTO scan_events (scan_id, ip, port, state) VALUES (?1, ?2, ?3, ?4)",
                    params![scan_id, ip, port as i32, state],
                );
            }
        }
    } else if let Some(findings) = report["findings"].as_array() {
        for finding in findings {
            if let (Some(ip), Some(port)) = (finding["ip"].as_str(), finding["port"].as_u64()) {
                let _ = conn.execute(
                    "INSERT INTO scan_events (scan_id, ip, port, state) VALUES (?1, ?2, ?3, ?4)",
                    params![scan_id, ip, port as i32, "open"],
                );
            }
        }
    }
    
    Ok(scan_id)
}

pub fn get_last_scan(conn: &Connection) -> Result<Option<i64>> {
    let mut stmt = conn.prepare("SELECT id FROM scans ORDER BY id DESC LIMIT 1")?;
    let mut rows = stmt.query([])?;
    
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

pub fn detect_changes(conn: &Connection, current_scan_id: i64) -> Result<Vec<PortChange>> {
    let last_scan_id = match get_last_scan(conn)? {
        Some(id) if id != current_scan_id => {
            // Get previous scan (second to last)
            let mut stmt = conn.prepare("SELECT id FROM scans ORDER BY id DESC LIMIT 2")?;
            let mut rows = stmt.query([])?;
            rows.next()?; // skip current
            if let Some(row) = rows.next()? {
                Some(row.get::<_, i64>(0)?)
            } else {
                None
            }
        }
        _ => None,
    };
    
    if last_scan_id.is_none() {
        return Ok(Vec::new());
    }
    
    let prev_id = last_scan_id.unwrap();
    let mut changes = Vec::new();
    
    // Get previous open ports
    let mut prev_stmt = conn.prepare(
        "SELECT ip, port, state FROM scan_events WHERE scan_id = ?1 AND state = 'open'"
    )?;
    let mut prev_rows = prev_stmt.query(params![prev_id])?;
    let mut prev_ports: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
    while let Some(row) = prev_rows.next()? {
        let ip: String = row.get(0)?;
        let port: i32 = row.get(1)?;
        prev_ports.insert((ip, port as u16));
    }
    
    // Get current open ports
    let mut curr_stmt = conn.prepare(
        "SELECT ip, port, state FROM scan_events WHERE scan_id = ?1 AND state = 'open'"
    )?;
    let mut curr_rows = curr_stmt.query(params![current_scan_id])?;
    let mut curr_ports: std::collections::HashSet<(String, u16)> = std::collections::HashSet::new();
    while let Some(row) = curr_rows.next()? {
        let ip: String = row.get(0)?;
        let port: i32 = row.get(1)?;
        curr_ports.insert((ip.clone(), port as u16));
        if !prev_ports.contains(&(ip.clone(), port as u16)) {
            changes.push(PortChange {
                ip,
                port: port as u16,
                change: "new".to_string(),
                previous_state: Some("closed/absent".to_string()),
                current_state: Some("open".to_string()),
            });
        }
    }
    
    // Check for removed
    for (ip, port) in &prev_ports {
        if !curr_ports.contains(&(ip.clone(), *port)) {
            changes.push(PortChange {
                ip: ip.clone(),
                port: *port,
                change: "removed".to_string(),
                previous_state: Some("open".to_string()),
                current_state: Some("closed/absent".to_string()),
            });
        }
    }
    
    Ok(changes)
}

pub fn get_history_summary(conn: &Connection, limit: i32) -> Result<Vec<ScanRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, timestamp, targets, open_ports_count, findings_count 
         FROM scans ORDER BY id DESC LIMIT ?1"
    )?;
    let mut rows = stmt.query(params![limit])?;
    let mut records = Vec::new();
    
    while let Some(row) = rows.next()? {
        records.push(ScanRecord {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            targets: row.get(2)?,
            open_ports_count: row.get(3)?,
            findings_count: row.get(4)?,
        });
    }
    
    Ok(records)
}
