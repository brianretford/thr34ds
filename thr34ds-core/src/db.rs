use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// A top-level conversation thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    pub id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A message belonging to a thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub thread_id: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

/// Wrapper around the local SQLite connection.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (or create) the local database file inside the app data directory.
    /// Falls back to an in-memory database for tests / environments where
    /// the standard dirs are unavailable.
    pub fn open() -> Result<Self> {
        let conn = Self::connect()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn connect() -> Result<Connection> {
        // Try to place the DB in a sensible OS-specific location.
        if let Some(mut path) = dirs::data_local_dir() {
            path.push("thr34ds");
            std::fs::create_dir_all(&path).ok();
            path.push("thr34ds.db");
            return Connection::open(&path);
        }
        // Fallback: in-memory (browser / WASM environments or missing dirs).
        Connection::open_in_memory()
    }

    /// Apply the schema (idempotent – uses CREATE TABLE IF NOT EXISTS).
    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS threads (
                 id         TEXT PRIMARY KEY NOT NULL,
                 title      TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS messages (
                 id         TEXT PRIMARY KEY NOT NULL,
                 thread_id  TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                 body       TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_messages_thread
                 ON messages(thread_id, created_at);
            ",
        )
    }

    // ── Threads ────────────────────────────────────────────────────────────

    pub fn list_threads(&self) -> Result<Vec<Thread>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, created_at, updated_at
               FROM threads
              ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Thread {
                id: row.get(0)?,
                title: row.get(1)?,
                created_at: parse_dt(row.get::<_, String>(2)?),
                updated_at: parse_dt(row.get::<_, String>(3)?),
            })
        })?;
        rows.collect()
    }

    pub fn insert_thread(&self, thread: &Thread) -> Result<()> {
        self.conn.execute(
            "INSERT INTO threads (id, title, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                thread.id,
                thread.title,
                thread.created_at.to_rfc3339(),
                thread.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn delete_thread(&self, id: &str) -> Result<usize> {
        self.conn
            .execute("DELETE FROM threads WHERE id = ?1", params![id])
    }

    // ── Messages ───────────────────────────────────────────────────────────

    pub fn list_messages(&self, thread_id: &str) -> Result<Vec<Message>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, thread_id, body, created_at
               FROM messages
              WHERE thread_id = ?1
              ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![thread_id], |row| {
            Ok(Message {
                id: row.get(0)?,
                thread_id: row.get(1)?,
                body: row.get(2)?,
                created_at: parse_dt(row.get::<_, String>(3)?),
            })
        })?;
        rows.collect()
    }

    pub fn insert_message(&self, msg: &Message) -> Result<()> {
        self.conn.execute(
            "INSERT INTO messages (id, thread_id, body, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                msg.id,
                msg.thread_id,
                msg.body,
                msg.created_at.to_rfc3339(),
            ],
        )?;
        // Bump the parent thread's updated_at timestamp.
        self.conn.execute(
            "UPDATE threads SET updated_at = ?1 WHERE id = ?2",
            params![msg.created_at.to_rfc3339(), msg.thread_id],
        )?;
        Ok(())
    }

    pub fn delete_message(&self, id: &str) -> Result<usize> {
        self.conn
            .execute("DELETE FROM messages WHERE id = ?1", params![id])
    }
}

fn parse_dt(s: String) -> DateTime<Utc> {
    s.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now())
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn in_memory_db() -> Database {
        let conn = Connection::open_in_memory().unwrap();
        let db = Database { conn };
        db.migrate().unwrap();
        db
    }

    #[test]
    fn thread_crud() {
        let db = in_memory_db();

        let t = Thread {
            id: Uuid::new_v4().to_string(),
            title: "Hello thr34ds".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db.insert_thread(&t).unwrap();

        let threads = db.list_threads().unwrap();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].title, "Hello thr34ds");

        db.delete_thread(&t.id).unwrap();
        assert!(db.list_threads().unwrap().is_empty());
    }

    #[test]
    fn message_crud() {
        let db = in_memory_db();

        let t = Thread {
            id: Uuid::new_v4().to_string(),
            title: "Thread A".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db.insert_thread(&t).unwrap();

        let m = Message {
            id: Uuid::new_v4().to_string(),
            thread_id: t.id.clone(),
            body: "First message".into(),
            created_at: Utc::now(),
        };
        db.insert_message(&m).unwrap();

        let msgs = db.list_messages(&t.id).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].body, "First message");

        db.delete_message(&m.id).unwrap();
        assert!(db.list_messages(&t.id).unwrap().is_empty());
    }

    #[test]
    fn cascade_delete_messages_with_thread() {
        let db = in_memory_db();

        let t = Thread {
            id: Uuid::new_v4().to_string(),
            title: "Cascade Test".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        db.insert_thread(&t).unwrap();

        for i in 0..3 {
            db.insert_message(&Message {
                id: Uuid::new_v4().to_string(),
                thread_id: t.id.clone(),
                body: format!("msg {i}"),
                created_at: Utc::now(),
            })
            .unwrap();
        }

        db.delete_thread(&t.id).unwrap();
        // All messages should be gone due to ON DELETE CASCADE.
        assert!(db.list_messages(&t.id).unwrap().is_empty());
    }
}
