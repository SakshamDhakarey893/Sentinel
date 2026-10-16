use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;

pub const DB_PATH: &str = "data/sentinel.db";

pub fn get_db_path() -> String {
    std::env::var("DATABASE_PATH").unwrap_or_else(|_| DB_PATH.to_string())
}

const LEGACY_USERS_FILE: &str = "data/users.json";
const LEGACY_QUEUE_FILE: &str = "data/queue.json";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub created_at: String,
    pub public_key: Option<String>,
    pub signed_prekey: Option<String>,
    pub one_time_prekeys: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct QueuedMessage {
    pub from: String,
    pub to: String,
    pub text: String,
    pub ts: String,
}

pub fn init_db(path_str: &str) -> Result<Connection> {
    if let Some(parent) = Path::new(path_str).parent() {
        fs::create_dir_all(parent).context("Failed to create database directory")?;
    }

    let conn = Connection::open(path_str).context("Failed to open SQLite database")?;

    // Performance & Durability Pragmas
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .context("Failed to apply SQLite PRAGMAs")?;

    // Schema DDL
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            created_at TEXT NOT NULL,
            public_key TEXT,
            signed_prekey TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS prekeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE,
            key_data TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_prekeys_user ON prekeys(username);

        CREATE TABLE IF NOT EXISTS queued_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user TEXT NOT NULL COLLATE NOCASE,
            to_user TEXT NOT NULL COLLATE NOCASE,
            text TEXT NOT NULL,
            ts TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_queue_to_user ON queued_messages(to_user);

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL COLLATE NOCASE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);",
    )
    .context("Failed to initialize SQLite tables")?;

    // Auto-migrate: Add expires_at column to sessions table if upgrading from older schema
    let _ = conn.execute("ALTER TABLE sessions ADD COLUMN expires_at TEXT", []);

    // Auto-migrate from legacy JSON files if they exist
    migrate_from_json(&conn)?;

    Ok(conn)
}

fn migrate_from_json(conn: &Connection) -> Result<()> {
    // 1. Check if users table is empty and legacy users.json exists
    let user_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap_or(0);

    if user_count == 0 && Path::new(LEGACY_USERS_FILE).exists() {
        if let Ok(content) = fs::read_to_string(LEGACY_USERS_FILE) {
            if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, User>>(&content) {
                tracing::info!("Migrating {} users from legacy JSON to SQLite...", map.len());
                let tx = conn.unchecked_transaction()?;
                for (_, user) in map {
                    tx.execute(
                        "INSERT OR REPLACE INTO users (id, username, created_at, public_key, signed_prekey)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            user.id,
                            user.username.to_lowercase(),
                            user.created_at,
                            user.public_key,
                            user.signed_prekey
                        ],
                    )?;

                    for opk in user.one_time_prekeys {
                        tx.execute(
                            "INSERT INTO prekeys (username, key_data, created_at)
                             VALUES (?1, ?2, ?3)",
                            params![
                                user.username.to_lowercase(),
                                opk,
                                chrono::Utc::now().to_rfc3339()
                            ],
                        )?;
                    }
                }
                tx.commit()?;
                tracing::info!("User migration to SQLite complete!");
            }
        }
    }

    // 2. Check if queued messages table is empty and legacy queue.json exists
    let queue_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM queued_messages", [], |r| r.get(0))
        .unwrap_or(0);

    if queue_count == 0 && Path::new(LEGACY_QUEUE_FILE).exists() {
        if let Ok(content) = fs::read_to_string(LEGACY_QUEUE_FILE) {
            if let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, Vec<QueuedMessage>>>(&content) {
                tracing::info!("Migrating queued messages from legacy JSON to SQLite...");
                let tx = conn.unchecked_transaction()?;
                for (_, list) in map {
                    for qm in list {
                        tx.execute(
                            "INSERT INTO queued_messages (from_user, to_user, text, ts)
                             VALUES (?1, ?2, ?3, ?4)",
                            params![
                                qm.from.to_lowercase(),
                                qm.to.to_lowercase(),
                                qm.text,
                                qm.ts
                            ],
                        )?;
                    }
                }
                tx.commit()?;
                tracing::info!("Queue migration to SQLite complete!");
            }
        }
    }

    Ok(())
}

// ─── User Queries ──────────────────────────────────────────────────────────

pub fn get_user(conn: &Connection, username: &str) -> Result<Option<User>> {
    let mut stmt = conn.prepare(
        "SELECT id, username, created_at, public_key, signed_prekey
         FROM users WHERE username = ?1 COLLATE NOCASE",
    )?;

    let mut user_iter = stmt.query_map(params![username], |row| {
        Ok(User {
            id: row.get(0)?,
            username: row.get(1)?,
            created_at: row.get(2)?,
            public_key: row.get(3)?,
            signed_prekey: row.get(4)?,
            one_time_prekeys: vec![],
        })
    })?;

    if let Some(user_res) = user_iter.next() {
        let mut user = user_res?;
        user.one_time_prekeys = get_user_one_time_prekeys(conn, &user.username)?;
        Ok(Some(user))
    } else {
        Ok(None)
    }
}

pub fn save_user(conn: &Connection, user: &User) -> Result<()> {
    conn.execute(
        "INSERT INTO users (id, username, created_at, public_key, signed_prekey)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(username) DO UPDATE SET
            public_key = excluded.public_key,
            signed_prekey = excluded.signed_prekey",
        params![
            user.id,
            user.username.to_lowercase(),
            user.created_at,
            user.public_key,
            user.signed_prekey
        ],
    )?;
    Ok(())
}

pub fn count_users(conn: &Connection) -> Result<usize> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
    Ok(count as usize)
}

// ─── Prekey Queries ────────────────────────────────────────────────────────

pub fn get_user_one_time_prekeys(conn: &Connection, username: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT key_data FROM prekeys WHERE username = ?1 COLLATE NOCASE ORDER BY id ASC",
    )?;
    let keys = stmt
        .query_map(params![username], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(keys)
}

#[allow(dead_code)]
pub fn set_signed_prekey(conn: &Connection, username: &str, spk: &str) -> Result<()> {
    conn.execute(
        "UPDATE users SET signed_prekey = ?1 WHERE username = ?2 COLLATE NOCASE",
        params![spk, username],
    )?;
    Ok(())
}

pub fn replace_prekeys(
    conn: &mut Connection,
    username: &str,
    signed_prekey: &str,
    opks: &[String],
) -> Result<usize> {
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE users SET signed_prekey = ?1 WHERE username = ?2 COLLATE NOCASE",
        params![signed_prekey, username],
    )?;
    tx.execute(
        "DELETE FROM prekeys WHERE username = ?1 COLLATE NOCASE",
        params![username],
    )?;

    let now = chrono::Utc::now().to_rfc3339();
    for opk in opks {
        tx.execute(
            "INSERT INTO prekeys (username, key_data, created_at) VALUES (?1, ?2, ?3)",
            params![username.to_lowercase(), opk, now],
        )?;
    }
    tx.commit()?;
    Ok(opks.len())
}

pub fn append_one_time_prekeys(
    conn: &Connection,
    username: &str,
    opks: &[String],
) -> Result<usize> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut count = 0;
    for opk in opks {
        conn.execute(
            "INSERT INTO prekeys (username, key_data, created_at) VALUES (?1, ?2, ?3)",
            params![username.to_lowercase(), opk, now],
        )?;
        count += 1;
    }
    Ok(count)
}

pub fn count_one_time_prekeys(conn: &Connection, username: &str) -> Result<usize> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM prekeys WHERE username = ?1 COLLATE NOCASE",
        params![username],
        |r| r.get(0),
    )?;
    Ok(count as usize)
}

pub fn consume_one_time_prekey(conn: &Connection, username: &str) -> Result<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT id, key_data FROM prekeys WHERE username = ?1 COLLATE NOCASE ORDER BY id ASC LIMIT 1",
    )?;

    let result = stmt.query_row(params![username], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    });

    match result {
        Ok((id, key_data)) => {
            conn.execute("DELETE FROM prekeys WHERE id = ?1", params![id])?;
            Ok(Some(key_data))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

// ─── Queued Messages ───────────────────────────────────────────────────────

pub fn enqueue_message(conn: &Connection, qm: &QueuedMessage) -> Result<()> {
    conn.execute(
        "INSERT INTO queued_messages (from_user, to_user, text, ts) VALUES (?1, ?2, ?3, ?4)",
        params![
            qm.from.to_lowercase(),
            qm.to.to_lowercase(),
            qm.text,
            qm.ts
        ],
    )?;
    Ok(())
}

pub fn pop_queued_messages(conn: &Connection, to_user: &str) -> Result<Vec<QueuedMessage>> {
    let mut stmt = conn.prepare(
        "SELECT id, from_user, to_user, text, ts
         FROM queued_messages WHERE to_user = ?1 COLLATE NOCASE ORDER BY id ASC",
    )?;

    let messages = stmt
        .query_map(params![to_user], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                QueuedMessage {
                    from: row.get(1)?,
                    to: row.get(2)?,
                    text: row.get(3)?,
                    ts: row.get(4)?,
                },
            ))
        })?
        .collect::<Result<Vec<(i64, QueuedMessage)>, _>>()?;

    if !messages.is_empty() {
        conn.execute(
            "DELETE FROM queued_messages WHERE to_user = ?1 COLLATE NOCASE",
            params![to_user],
        )?;
    }

    Ok(messages.into_iter().map(|(_, qm)| qm).collect())
}

// ─── Sessions ──────────────────────────────────────────────────────────────

pub fn get_session_ttl_secs() -> i64 {
    std::env::var("SESSION_TTL_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|&v| v > 0)
        .unwrap_or(7 * 24 * 3600) // Default: 7 days (604,800 seconds)
}

pub fn save_session(conn: &Connection, token: &str, username: &str) -> Result<()> {
    let now = chrono::Utc::now();
    let ttl = get_session_ttl_secs();
    let expires = now + chrono::Duration::seconds(ttl);

    // Invalidate existing sessions for this username (token rotation upon authentication)
    let _ = conn.execute(
        "DELETE FROM sessions WHERE username = ?1 COLLATE NOCASE",
        params![username],
    );

    conn.execute(
        "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            token,
            username.to_lowercase(),
            now.to_rfc3339(),
            expires.to_rfc3339(),
        ],
    )?;
    Ok(())
}

pub fn verify_session(conn: &Connection, token: &str, username: &str) -> Result<bool> {
    let mut stmt = conn.prepare(
        "SELECT username, created_at, expires_at FROM sessions WHERE token = ?1",
    )?;
    let res = stmt.query_row(params![token], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    });

    match res {
        Ok((stored_user, created_at_opt, expires_at_opt)) => {
            let now = chrono::Utc::now();
            let is_expired = if let Some(exp_str) = expires_at_opt {
                chrono::DateTime::parse_from_rfc3339(&exp_str)
                    .map(|exp| now > exp)
                    .unwrap_or(false)
            } else if let Some(created_str) = created_at_opt {
                chrono::DateTime::parse_from_rfc3339(&created_str)
                    .map(|created| now > created + chrono::Duration::seconds(get_session_ttl_secs()))
                    .unwrap_or(false)
            } else {
                false
            };

            if is_expired {
                // Reject expired sessions and purge them from the database
                let _ = conn.execute("DELETE FROM sessions WHERE token = ?1", params![token]);
                return Ok(false);
            }

            Ok(stored_user.eq_ignore_ascii_case(username))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[allow(dead_code)]
pub fn invalidate_session(conn: &Connection, token: &str) -> Result<()> {
    conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                created_at TEXT NOT NULL,
                public_key TEXT,
                signed_prekey TEXT
            );
            CREATE TABLE prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE,
                key_data TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE queued_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL COLLATE NOCASE,
                to_user TEXT NOT NULL COLLATE NOCASE,
                text TEXT NOT NULL,
                ts TEXT NOT NULL
            );
            CREATE TABLE sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL COLLATE NOCASE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );",
        )
        .unwrap();
        conn
    }

    #[test]
    fn test_user_lifecycle() {
        let conn = setup_test_db();
        let user = User {
            id: "uid-1".into(),
            username: "Alice".into(),
            created_at: "2026-10-16T00:00:00Z".into(),
            public_key: Some("spki_base64_alice".into()),
            signed_prekey: None,
            one_time_prekeys: vec![],
        };

        save_user(&conn, &user).unwrap();
        assert_eq!(count_users(&conn).unwrap(), 1);

        let fetched = get_user(&conn, "alice").unwrap().expect("User should exist");
        assert_eq!(fetched.id, "uid-1");
        assert_eq!(fetched.username, "alice");
        assert_eq!(fetched.public_key, Some("spki_base64_alice".into()));
    }

    #[test]
    fn test_prekey_atomic_consumption() {
        let mut conn = setup_test_db();
        let user = User {
            id: "uid-2".into(),
            username: "bob".into(),
            created_at: "2026-10-16T00:00:00Z".into(),
            public_key: Some("bob_pk".into()),
            signed_prekey: None,
            one_time_prekeys: vec![],
        };
        save_user(&conn, &user).unwrap();

        let opks = vec!["opk1".to_string(), "opk2".to_string(), "opk3".to_string()];
        replace_prekeys(&mut conn, "bob", "spk_bob", &opks).unwrap();

        assert_eq!(count_one_time_prekeys(&conn, "bob").unwrap(), 3);

        // Consume first key
        let consumed1 = consume_one_time_prekey(&conn, "bob").unwrap();
        assert_eq!(consumed1, Some("opk1".into()));
        assert_eq!(count_one_time_prekeys(&conn, "bob").unwrap(), 2);

        // Consume second key
        let consumed2 = consume_one_time_prekey(&conn, "bob").unwrap();
        assert_eq!(consumed2, Some("opk2".into()));
        assert_eq!(count_one_time_prekeys(&conn, "bob").unwrap(), 1);

        // Append 2 more keys
        append_one_time_prekeys(&conn, "bob", &["opk4".into(), "opk5".into()]).unwrap();
        assert_eq!(count_one_time_prekeys(&conn, "bob").unwrap(), 3);
    }

    #[test]
    fn test_sessions_and_queue() {
        let conn = setup_test_db();

        // Test sessions
        save_session(&conn, "tok-123", "charlie").unwrap();
        assert!(verify_session(&conn, "tok-123", "charlie").unwrap());
        assert!(verify_session(&conn, "tok-123", "CHARLIE").unwrap());
        assert!(!verify_session(&conn, "tok-123", "dave").unwrap());
        assert!(!verify_session(&conn, "wrong-tok", "charlie").unwrap());

        // Test token rotation on new save_session for same username
        save_session(&conn, "tok-456", "charlie").unwrap();
        assert!(!verify_session(&conn, "tok-123", "charlie").unwrap());
        assert!(verify_session(&conn, "tok-456", "charlie").unwrap());

        // Test expired session rejection and cleanup
        let past = (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params!["expired-tok", "dave", past, past],
        ).unwrap();
        assert!(!verify_session(&conn, "expired-tok", "dave").unwrap());
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sessions WHERE token = 'expired-tok'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);

        // Test offline message queue
        let msg1 = QueuedMessage {
            from: "alice".into(),
            to: "charlie".into(),
            text: "enc_msg_1".into(),
            ts: "2026-10-16T00:00:01Z".into(),
        };
        let msg2 = QueuedMessage {
            from: "bob".into(),
            to: "charlie".into(),
            text: "enc_msg_2".into(),
            ts: "2026-10-16T00:00:02Z".into(),
        };

        enqueue_message(&conn, &msg1).unwrap();
        enqueue_message(&conn, &msg2).unwrap();

        let popped = pop_queued_messages(&conn, "charlie").unwrap();
        assert_eq!(popped.len(), 2);
        assert_eq!(popped[0].text, "enc_msg_1");
        assert_eq!(popped[1].text, "enc_msg_2");

        // Subsequent pop should be empty
        let empty_pop = pop_queued_messages(&conn, "charlie").unwrap();
        assert!(empty_pop.is_empty());
    }
}

