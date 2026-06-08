//! Local SQLite persistence for the thread-based task manager.
//!
//! The data model:
//!
//! * **threads** nest other threads (`parent_id` self-reference) and each owns
//!   its **own** post-quantum signed timeline (a hash chain). A thread's chain
//!   head (`chain_seq`, `chain_head`) is stored on the row; its genesis entry is
//!   the `thread.created` event.
//! * **respondents** are participants modeled on the vCard schema (see
//!   [`crate::respondent`]) — humans or summoned agents.
//! * **messages** belong to a thread and are attributed to a respondent.
//! * **timeline** holds the [`SignedTimestamp`] entries; every mutation is
//!   sealed onto the owning thread's chain by the app [`Notary`].
//!
//! A single app signing key (persisted as a seed in the `meta` table) signs all
//! threads' chains, but each thread is an independent, separately verifiable
//! chain.
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::merkle::{self, MerkleStep, MerkleTree};
use crate::respondent::{Respondent, RespondentKind};
use crate::signed_time::{self, verify_chain, Notary, SignedTimestamp, ALGORITHM, GENESIS_HASH};

const CATEGORY_SEP: char = '\u{1f}'; // ASCII unit separator

/// A task thread. Threads nest via `parent_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thread {
    pub id: String,
    /// Parent thread id, or `None` for a root thread.
    pub parent_id: Option<String>,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A message belonging to a thread, attributed to a respondent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub thread_id: String,
    /// The respondent (human or agent) credited with this message.
    pub respondent_uid: Option<String>,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

/// A Merkle root over every thread's chain head, signed by the one app actor.
///
/// All per-thread chains aggregate into `root`; the actor's post-quantum
/// signature over it is a single commitment to the whole task manager's state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedStateRoot {
    /// Hex-encoded Merkle root over all thread chain heads.
    pub root: String,
    /// Number of threads (leaves) committed.
    pub leaf_count: usize,
    /// RFC-3339 UTC time the root was signed.
    pub time: String,
    /// Signature algorithm (the actor's PQ scheme).
    pub algorithm: String,
    /// The one actor's hex-encoded public key.
    pub public_key: String,
    /// Hex-encoded detached signature over the canonical root.
    pub signature: String,
}

impl SignedStateRoot {
    fn canonical(&self) -> String {
        format!(
            "thr34ds-state-root/v1\n{}\n{}\n{}\n{}",
            self.algorithm, self.leaf_count, self.time, self.root
        )
    }

    /// Verify the actor's post-quantum signature over this root.
    pub fn verify(&self) -> bool {
        signed_time::verify_signature(&self.public_key, self.canonical().as_bytes(), &self.signature)
    }
}

/// Proof that a single thread is committed under a [`SignedStateRoot`], without
/// revealing the other threads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInclusion {
    pub thread_id: String,
    /// The committed leaf preimage (`<thread_id>:<chain_head>`).
    pub leaf: String,
    /// Index of this thread's leaf in the (id-sorted) tree.
    pub index: usize,
    /// Merkle inclusion proof.
    pub proof: Vec<MerkleStep>,
    /// The signed root the proof resolves to.
    pub state_root: SignedStateRoot,
}

impl ThreadInclusion {
    /// Verify both the actor's signature over the root **and** that this
    /// thread's leaf is included under it.
    pub fn verify(&self) -> bool {
        if !self.state_root.verify() {
            return false;
        }
        let Ok(root_bytes) = hex::decode(&self.state_root.root) else {
            return false;
        };
        let Ok(root): std::result::Result<[u8; 32], _> = root_bytes.try_into() else {
            return false;
        };
        merkle::verify_proof(self.leaf.as_bytes(), &self.proof, &root)
    }
}

/// Wrapper around the local SQLite connection plus the signed-time notary.
pub struct Database {
    conn: Connection,
    /// Hex seed of the app's ML-DSA signing key (the timeline identity).
    notary_seed: String,
    /// Clock offset (ms) applied to seal times after an atomic-clock sync.
    time_offset_ms: i64,
    /// Human-readable provenance of sealed times.
    time_source: String,
}

impl Database {
    /// Open (or create) the on-device database, falling back to in-memory.
    pub fn open() -> Result<Self> {
        Self::from_conn(Self::connect()?)
    }

    fn connect() -> Result<Connection> {
        if let Some(mut path) = dirs::data_local_dir() {
            path.push("thr34ds");
            std::fs::create_dir_all(&path).ok();
            path.push("thr34ds.db");
            return Connection::open(&path);
        }
        Connection::open_in_memory()
    }

    /// Build a `Database` from an existing connection: migrate the schema and
    /// load (or create) the signing key.
    fn from_conn(conn: Connection) -> Result<Self> {
        let mut db = Self {
            conn,
            notary_seed: String::new(),
            time_offset_ms: 0,
            time_source: "local (unsynced)".to_string(),
        };
        db.migrate()?;
        db.notary_seed = db.load_or_create_seed()?;
        Ok(db)
    }

    /// Apply the schema. Idempotent, and migrates pre-existing flat databases by
    /// adding the new columns.
    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY NOT NULL,
                 value TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS threads (
                 id         TEXT PRIMARY KEY NOT NULL,
                 parent_id  TEXT REFERENCES threads(id) ON DELETE CASCADE,
                 title      TEXT NOT NULL,
                 chain_seq  INTEGER NOT NULL DEFAULT 0,
                 chain_head TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS respondents (
                 uid         TEXT PRIMARY KEY NOT NULL,
                 thread_id   TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                 kind        TEXT NOT NULL,
                 fn          TEXT NOT NULL,
                 family_name TEXT,
                 given_name  TEXT,
                 nickname    TEXT,
                 email       TEXT,
                 tel         TEXT,
                 org         TEXT,
                 title       TEXT,
                 role        TEXT,
                 url         TEXT,
                 photo       TEXT,
                 note        TEXT,
                 categories  TEXT,
                 behavior    TEXT,
                 models_uid  TEXT,
                 created_at  TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS messages (
                 id             TEXT PRIMARY KEY NOT NULL,
                 thread_id      TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                 respondent_uid TEXT REFERENCES respondents(uid) ON DELETE SET NULL,
                 body           TEXT NOT NULL,
                 created_at     TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS timeline (
                 id           TEXT PRIMARY KEY NOT NULL,
                 thread_id    TEXT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
                 seq          INTEGER NOT NULL,
                 kind         TEXT NOT NULL,
                 time         TEXT NOT NULL,
                 time_source  TEXT NOT NULL,
                 payload_hash TEXT NOT NULL,
                 prev_hash    TEXT NOT NULL,
                 hash         TEXT NOT NULL,
                 algorithm    TEXT NOT NULL,
                 public_key   TEXT NOT NULL,
                 signature    TEXT NOT NULL,
                 anchor       TEXT,
                 UNIQUE(thread_id, seq)
             );

             CREATE INDEX IF NOT EXISTS idx_threads_parent   ON threads(parent_id, updated_at);
             CREATE INDEX IF NOT EXISTS idx_messages_thread  ON messages(thread_id, created_at);
             CREATE INDEX IF NOT EXISTS idx_respondents_thread ON respondents(thread_id);
             CREATE INDEX IF NOT EXISTS idx_timeline_thread  ON timeline(thread_id, seq);
            ",
        )
    }

    fn load_or_create_seed(&self) -> Result<String> {
        let existing: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'notary_seed'", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(seed) = existing {
            return Ok(seed);
        }
        let seed = Notary::generate().seed_hex();
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('notary_seed', ?1)",
            params![seed],
        )?;
        Ok(seed)
    }

    /// The app's hex-encoded ML-DSA public key (the timeline's signer identity).
    pub fn timeline_public_key(&self) -> String {
        Notary::from_seed_hex(&self.notary_seed)
            .expect("stored notary seed is valid")
            .public_key_hex()
            .to_string()
    }

    /// Record an atomic-clock sync so subsequent sealed times use the corrected
    /// clock and record their provenance.
    pub fn set_synced_time(&mut self, offset_ms: i64, server: &str) {
        self.time_offset_ms = offset_ms;
        self.time_source = format!("ntp:{server} offset={offset_ms:+}ms");
    }

    fn current_time(&self) -> (DateTime<Utc>, String) {
        let now = Utc::now() + chrono::Duration::milliseconds(self.time_offset_ms);
        (now, self.time_source.clone())
    }

    // ── Signed-time sealing ──────────────────────────────────────────────────

    /// Seal an event payload onto a thread's own chain and persist the entry.
    fn seal_event(&self, thread_id: &str, kind: &str, payload: &[u8]) -> Result<SignedTimestamp> {
        let (seq, head): (i64, String) = self.conn.query_row(
            "SELECT chain_seq, chain_head FROM threads WHERE id = ?1",
            params![thread_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let mut notary = Notary::resume(&self.notary_seed, seq as u64, head)
            .expect("stored notary seed and chain head are valid");
        let (time, source) = self.current_time();
        let ts = notary.seal(payload, time, source);

        self.conn.execute(
            "INSERT INTO timeline
                (id, thread_id, seq, kind, time, time_source, payload_hash,
                 prev_hash, hash, algorithm, public_key, signature, anchor)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                Uuid::new_v4().to_string(),
                thread_id,
                ts.seq as i64,
                kind,
                ts.time,
                ts.time_source,
                ts.payload_hash,
                ts.prev_hash,
                ts.hash,
                ts.algorithm,
                ts.public_key,
                ts.signature,
                Option::<String>::None, // anchors are attached out-of-band
            ],
        )?;

        self.conn.execute(
            "UPDATE threads SET chain_seq = ?1, chain_head = ?2, updated_at = ?3 WHERE id = ?4",
            params![ts.seq as i64, ts.hash, ts.time, thread_id],
        )?;

        Ok(ts)
    }

    /// Return a thread's signed timeline, ordered by sequence.
    pub fn list_timeline(&self, thread_id: &str) -> Result<Vec<SignedTimestamp>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, time, time_source, payload_hash, prev_hash, hash,
                    algorithm, public_key, signature
               FROM timeline
              WHERE thread_id = ?1
              ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(params![thread_id], |row| {
            Ok(SignedTimestamp {
                seq: row.get::<_, i64>(0)? as u64,
                time: row.get(1)?,
                time_source: row.get(2)?,
                payload_hash: row.get(3)?,
                prev_hash: row.get(4)?,
                hash: row.get(5)?,
                algorithm: row.get(6)?,
                public_key: row.get(7)?,
                signature: row.get(8)?,
                anchor: None,
            })
        })?;
        rows.collect()
    }

    /// Verify a thread's chain end-to-end. `Ok(())` if intact; `Err(Some(i))`
    /// points at the first bad entry; `Err(None)` if the thread has no chain.
    pub fn verify_thread(&self, thread_id: &str) -> Result<std::result::Result<(), usize>> {
        let entries = self.list_timeline(thread_id)?;
        if entries.is_empty() {
            return Ok(Err(0));
        }
        Ok(verify_chain(&entries))
    }

    // ── Merkle aggregation (all chains → one signed actor root) ──────────────

    /// Deterministically ordered `(thread_id, leaf_preimage)` pairs. The leaf
    /// commits the thread id together with its current chain head.
    fn ordered_leaves(&self) -> Result<Vec<(String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, chain_head FROM threads ORDER BY id ASC")?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let head: String = row.get(1)?;
            Ok((id.clone(), format!("{id}:{head}")))
        })?;
        rows.collect()
    }

    /// Build a Merkle root over every thread's chain head and sign it with the
    /// one app actor. This is the single commitment all per-thread chains roll
    /// up to.
    pub fn state_root(&self) -> Result<SignedStateRoot> {
        let leaves = self.ordered_leaves()?;
        let preimages: Vec<Vec<u8>> = leaves.iter().map(|(_, l)| l.as_bytes().to_vec()).collect();
        let tree = MerkleTree::from_leaves(&preimages);

        let notary = Notary::from_seed_hex(&self.notary_seed).expect("stored notary seed is valid");
        let (time, _) = self.current_time();

        let mut sr = SignedStateRoot {
            root: hex::encode(tree.root()),
            leaf_count: leaves.len(),
            time: time.to_rfc3339(),
            algorithm: ALGORITHM.to_string(),
            public_key: notary.public_key_hex().to_string(),
            signature: String::new(),
        };
        sr.signature = notary.sign_message(sr.canonical().as_bytes());
        Ok(sr)
    }

    /// Produce an inclusion proof that `thread_id` is committed under the
    /// current signed state root. Returns `None` if the thread does not exist.
    pub fn prove_thread(&self, thread_id: &str) -> Result<Option<ThreadInclusion>> {
        let leaves = self.ordered_leaves()?;
        let Some(index) = leaves.iter().position(|(id, _)| id == thread_id) else {
            return Ok(None);
        };
        let preimages: Vec<Vec<u8>> = leaves.iter().map(|(_, l)| l.as_bytes().to_vec()).collect();
        let tree = MerkleTree::from_leaves(&preimages);

        Ok(Some(ThreadInclusion {
            thread_id: thread_id.to_string(),
            leaf: leaves[index].1.clone(),
            index,
            proof: tree.proof(index),
            state_root: self.state_root()?,
        }))
    }

    // ── Threads ──────────────────────────────────────────────────────────────

    /// Create a thread (root if `parent_id` is `None`, otherwise a sub-thread)
    /// and seal its `thread.created` genesis event. Returns the thread and the
    /// sealed entry.
    pub fn create_thread(
        &self,
        parent_id: Option<&str>,
        title: &str,
    ) -> Result<(Thread, SignedTimestamp)> {
        let now = Utc::now();
        let thread = Thread {
            id: Uuid::new_v4().to_string(),
            parent_id: parent_id.map(str::to_string),
            title: title.to_string(),
            created_at: now,
            updated_at: now,
        };
        self.conn.execute(
            "INSERT INTO threads (id, parent_id, title, chain_seq, chain_head, created_at, updated_at)
             VALUES (?1, ?2, ?3, 0, ?4, ?5, ?5)",
            params![
                thread.id,
                thread.parent_id,
                thread.title,
                GENESIS_HASH,
                now.to_rfc3339(),
            ],
        )?;

        let payload = format!(
            "thread.created\nid={}\nparent={}\ntitle={}",
            thread.id,
            thread.parent_id.as_deref().unwrap_or(""),
            thread.title
        );
        let ts = self.seal_event(&thread.id, "thread.created", payload.as_bytes())?;
        Ok((thread, ts))
    }

    /// All threads, most-recently-updated first (flat).
    pub fn list_threads(&self) -> Result<Vec<Thread>> {
        self.query_threads("SELECT id, parent_id, title, created_at, updated_at
                              FROM threads ORDER BY updated_at DESC", params![])
    }

    /// Root threads (no parent), most-recently-updated first.
    pub fn list_root_threads(&self) -> Result<Vec<Thread>> {
        self.query_threads(
            "SELECT id, parent_id, title, created_at, updated_at
               FROM threads WHERE parent_id IS NULL ORDER BY updated_at DESC",
            params![],
        )
    }

    /// Direct sub-threads of `parent_id`.
    pub fn list_child_threads(&self, parent_id: &str) -> Result<Vec<Thread>> {
        self.query_threads(
            "SELECT id, parent_id, title, created_at, updated_at
               FROM threads WHERE parent_id = ?1 ORDER BY updated_at DESC",
            params![parent_id],
        )
    }

    pub fn get_thread(&self, id: &str) -> Result<Option<Thread>> {
        self.query_threads(
            "SELECT id, parent_id, title, created_at, updated_at FROM threads WHERE id = ?1",
            params![id],
        )
        .map(|mut v| v.pop())
    }

    fn query_threads(&self, sql: &str, p: impl rusqlite::Params) -> Result<Vec<Thread>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(p, |row| {
            Ok(Thread {
                id: row.get(0)?,
                parent_id: row.get(1)?,
                title: row.get(2)?,
                created_at: parse_dt(row.get::<_, String>(3)?),
                updated_at: parse_dt(row.get::<_, String>(4)?),
            })
        })?;
        rows.collect()
    }

    /// Delete a thread and everything beneath it (sub-threads, messages,
    /// respondents, timeline) via cascade.
    pub fn delete_thread(&self, id: &str) -> Result<usize> {
        self.conn.execute("DELETE FROM threads WHERE id = ?1", params![id])
    }

    // ── Respondents (vCard) ──────────────────────────────────────────────────

    /// Add a human respondent to a thread and seal a `respondent.added` event.
    pub fn add_respondent(
        &self,
        thread_id: &str,
        name: &str,
    ) -> Result<(Respondent, SignedTimestamp)> {
        let r = Respondent::human(Uuid::new_v4().to_string(), thread_id, name);
        let ts = self.insert_respondent(&r, "respondent.added")?;
        Ok((r, ts))
    }

    /// Summon an agent that stands in for (and models the behavior of) a human
    /// respondent. The agent is a `KIND:application` vCard linked to the human
    /// via `RELATED;TYPE=agent`. Seals an `agent.summoned` event.
    pub fn summon_agent(
        &self,
        thread_id: &str,
        name: &str,
        models_uid: Option<&str>,
        behavior: Option<&str>,
    ) -> Result<(Respondent, SignedTimestamp)> {
        let mut agent = Respondent::agent(Uuid::new_v4().to_string(), thread_id, name);
        agent.models_uid = models_uid.map(str::to_string);
        agent.behavior = behavior.map(str::to_string);
        let ts = self.insert_respondent(&agent, "agent.summoned")?;
        Ok((agent, ts))
    }

    /// Persist a respondent and seal its event (the sealed payload is the
    /// respondent's full vCard, so the chain commits to its identity).
    fn insert_respondent(&self, r: &Respondent, event_kind: &str) -> Result<SignedTimestamp> {
        self.conn.execute(
            "INSERT INTO respondents
                (uid, thread_id, kind, fn, family_name, given_name, nickname, email,
                 tel, org, title, role, url, photo, note, categories, behavior,
                 models_uid, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
            params![
                r.uid,
                r.thread_id,
                r.kind.as_vcard(),
                r.formatted_name,
                r.family_name,
                r.given_name,
                r.nickname,
                r.email,
                r.tel,
                r.org,
                r.title,
                r.role,
                r.url,
                r.photo,
                r.note,
                encode_categories(&r.categories),
                r.behavior,
                r.models_uid,
                r.created_at.to_rfc3339(),
            ],
        )?;
        self.seal_event(&r.thread_id, event_kind, r.to_vcard().as_bytes())
    }

    /// List a thread's respondents (humans and agents), oldest first.
    pub fn list_respondents(&self, thread_id: &str) -> Result<Vec<Respondent>> {
        let mut stmt = self.conn.prepare(
            "SELECT uid, thread_id, kind, fn, family_name, given_name, nickname, email,
                    tel, org, title, role, url, photo, note, categories, behavior,
                    models_uid, created_at
               FROM respondents WHERE thread_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![thread_id], |row| {
            Ok(Respondent {
                uid: row.get(0)?,
                thread_id: row.get(1)?,
                kind: RespondentKind::from_vcard(&row.get::<_, String>(2)?),
                formatted_name: row.get(3)?,
                family_name: row.get(4)?,
                given_name: row.get(5)?,
                nickname: row.get(6)?,
                email: row.get(7)?,
                tel: row.get(8)?,
                org: row.get(9)?,
                title: row.get(10)?,
                role: row.get(11)?,
                url: row.get(12)?,
                photo: row.get(13)?,
                note: row.get(14)?,
                categories: decode_categories(row.get::<_, Option<String>>(15)?),
                behavior: row.get(16)?,
                models_uid: row.get(17)?,
                created_at: parse_dt(row.get::<_, String>(18)?),
            })
        })?;
        rows.collect()
    }

    pub fn delete_respondent(&self, uid: &str) -> Result<usize> {
        self.conn.execute("DELETE FROM respondents WHERE uid = ?1", params![uid])
    }

    // ── Messages ─────────────────────────────────────────────────────────────

    pub fn list_messages(&self, thread_id: &str) -> Result<Vec<Message>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, thread_id, respondent_uid, body, created_at
               FROM messages WHERE thread_id = ?1 ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map(params![thread_id], |row| {
            Ok(Message {
                id: row.get(0)?,
                thread_id: row.get(1)?,
                respondent_uid: row.get(2)?,
                body: row.get(3)?,
                created_at: parse_dt(row.get::<_, String>(4)?),
            })
        })?;
        rows.collect()
    }

    /// Append a message to a thread, attributed to `respondent_uid`, and seal a
    /// `message.created` event onto the thread's chain.
    pub fn create_message(
        &self,
        thread_id: &str,
        respondent_uid: Option<&str>,
        body: &str,
    ) -> Result<(Message, SignedTimestamp)> {
        let msg = Message {
            id: Uuid::new_v4().to_string(),
            thread_id: thread_id.to_string(),
            respondent_uid: respondent_uid.map(str::to_string),
            body: body.to_string(),
            created_at: Utc::now(),
        };
        self.conn.execute(
            "INSERT INTO messages (id, thread_id, respondent_uid, body, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                msg.id,
                msg.thread_id,
                msg.respondent_uid,
                msg.body,
                msg.created_at.to_rfc3339(),
            ],
        )?;
        let payload = format!(
            "message.created\nid={}\nrespondent={}\nbody={}",
            msg.id,
            msg.respondent_uid.as_deref().unwrap_or(""),
            msg.body
        );
        let ts = self.seal_event(thread_id, "message.created", payload.as_bytes())?;
        Ok((msg, ts))
    }

    pub fn delete_message(&self, id: &str) -> Result<usize> {
        self.conn.execute("DELETE FROM messages WHERE id = ?1", params![id])
    }
}

fn parse_dt(s: String) -> DateTime<Utc> {
    s.parse::<DateTime<Utc>>().unwrap_or_else(|_| Utc::now())
}

fn encode_categories(cats: &[String]) -> Option<String> {
    if cats.is_empty() {
        None
    } else {
        Some(cats.join(&CATEGORY_SEP.to_string()))
    }
}

fn decode_categories(s: Option<String>) -> Vec<String> {
    match s {
        Some(s) if !s.is_empty() => s.split(CATEGORY_SEP).map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Database {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        Database::from_conn(conn).unwrap()
    }

    #[test]
    fn create_thread_seals_genesis() {
        let db = db();
        let (t, ts) = db.create_thread(None, "Plan trip").unwrap();
        assert!(t.parent_id.is_none());
        assert_eq!(ts.seq, 1);
        assert_eq!(ts.prev_hash, GENESIS_HASH);
        assert!(ts.verify());
        // The thread's chain verifies end-to-end.
        assert_eq!(db.verify_thread(&t.id).unwrap(), Ok(()));
    }

    #[test]
    fn threads_nest() {
        let db = db();
        let (root, _) = db.create_thread(None, "Trip").unwrap();
        let (child, _) = db.create_thread(Some(&root.id), "Book flights").unwrap();
        let (grand, _) = db.create_thread(Some(&child.id), "Compare prices").unwrap();

        assert_eq!(db.list_root_threads().unwrap().len(), 1);
        let kids = db.list_child_threads(&root.id).unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].id, child.id);
        assert_eq!(grand.parent_id.as_deref(), Some(child.id.as_str()));
    }

    #[test]
    fn deleting_root_cascades_to_descendants() {
        let db = db();
        let (root, _) = db.create_thread(None, "Trip").unwrap();
        let (child, _) = db.create_thread(Some(&root.id), "Sub").unwrap();
        db.add_respondent(&child.id, "Alice").unwrap();
        db.create_message(&child.id, None, "hi").unwrap();

        db.delete_thread(&root.id).unwrap();
        assert!(db.list_threads().unwrap().is_empty());
        assert!(db.list_respondents(&child.id).unwrap().is_empty());
        assert!(db.list_messages(&child.id).unwrap().is_empty());
        assert!(db.list_timeline(&child.id).unwrap().is_empty());
    }

    #[test]
    fn summon_agent_models_a_human() {
        let db = db();
        let (t, _) = db.create_thread(None, "Design review").unwrap();
        let (human, _) = db.add_respondent(&t.id, "Grace Hopper").unwrap();
        let (agent, ts) = db
            .summon_agent(
                &t.id,
                "Grace (agent)",
                Some(&human.uid),
                Some("Pragmatic, terse, systems-minded."),
            )
            .unwrap();

        assert!(agent.is_agent());
        assert_eq!(agent.models_uid.as_deref(), Some(human.uid.as_str()));
        assert_eq!(ts.algorithm, "ML-DSA-65");

        let people = db.list_respondents(&t.id).unwrap();
        assert_eq!(people.len(), 2);
        let reloaded_agent = people.iter().find(|r| r.is_agent()).unwrap();
        assert!(reloaded_agent.to_vcard().contains("KIND:application"));
        assert!(reloaded_agent.to_vcard().contains("RELATED;TYPE=agent"));
    }

    #[test]
    fn message_is_attributed_and_sealed() {
        let db = db();
        let (t, _) = db.create_thread(None, "Standup").unwrap();
        let (alice, _) = db.add_respondent(&t.id, "Alice").unwrap();
        let (msg, ts) = db
            .create_message(&t.id, Some(&alice.uid), "Shipping the parser today")
            .unwrap();

        assert_eq!(msg.respondent_uid.as_deref(), Some(alice.uid.as_str()));
        assert!(ts.verify());
        let msgs = db.list_messages(&t.id).unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].respondent_uid.as_deref(), Some(alice.uid.as_str()));
    }

    #[test]
    fn each_thread_has_an_independent_chain() {
        let db = db();
        let (a, _) = db.create_thread(None, "A").unwrap();
        let (b, _) = db.create_thread(None, "B").unwrap();

        db.create_message(&a.id, None, "a1").unwrap();
        db.create_message(&a.id, None, "a2").unwrap();
        db.create_message(&b.id, None, "b1").unwrap();

        // A: created + 2 messages = 3; B: created + 1 message = 2.
        assert_eq!(db.list_timeline(&a.id).unwrap().len(), 3);
        assert_eq!(db.list_timeline(&b.id).unwrap().len(), 2);
        // Independent sequence numbering.
        assert_eq!(db.list_timeline(&b.id).unwrap()[1].seq, 2);
        // Both chains verify on their own.
        assert_eq!(db.verify_thread(&a.id).unwrap(), Ok(()));
        assert_eq!(db.verify_thread(&b.id).unwrap(), Ok(()));
    }

    #[test]
    fn tampered_timeline_entry_is_detected() {
        let db = db();
        let (t, _) = db.create_thread(None, "Ledger").unwrap();
        db.create_message(&t.id, None, "one").unwrap();
        db.create_message(&t.id, None, "two").unwrap();

        let mut entries = db.list_timeline(&t.id).unwrap();
        // Forge the second entry's payload hash.
        entries[1].payload_hash =
            "f".repeat(64);
        assert!(matches!(verify_chain(&entries), Err(1)));
    }

    #[test]
    fn state_root_is_signed_by_the_one_actor() {
        let db = db();
        db.create_thread(None, "A").unwrap();
        db.create_thread(None, "B").unwrap();

        let sr = db.state_root().unwrap();
        assert_eq!(sr.leaf_count, 2);
        assert_eq!(sr.algorithm, "ML-DSA-65");
        assert_eq!(sr.public_key, db.timeline_public_key());
        assert!(sr.verify(), "actor signature over root must verify");
    }

    #[test]
    fn root_changes_when_a_thread_chain_advances() {
        let db = db();
        let (t, _) = db.create_thread(None, "A").unwrap();
        db.create_thread(None, "B").unwrap();

        let before = db.state_root().unwrap().root;
        db.create_message(&t.id, None, "advance A's chain").unwrap();
        let after = db.state_root().unwrap().root;
        assert_ne!(before, after, "advancing a thread chain must change the root");
    }

    #[test]
    fn thread_inclusion_proof_verifies_under_signed_root() {
        let db = db();
        let (a, _) = db.create_thread(None, "A").unwrap();
        db.create_thread(None, "B").unwrap();
        db.create_thread(None, "C").unwrap();

        let proof = db.prove_thread(&a.id).unwrap().expect("thread exists");
        assert_eq!(proof.thread_id, a.id);
        assert!(proof.verify(), "inclusion proof must verify against signed root");

        // A proof for a non-existent thread is None.
        assert!(db.prove_thread("does-not-exist").unwrap().is_none());
    }

    #[test]
    fn tampered_inclusion_leaf_fails() {
        let db = db();
        let (a, _) = db.create_thread(None, "A").unwrap();
        db.create_thread(None, "B").unwrap();

        let mut proof = db.prove_thread(&a.id).unwrap().unwrap();
        proof.leaf = format!("{}:{}", a.id, "0".repeat(64)); // forge the chain head
        assert!(!proof.verify());
    }

    #[test]
    fn categories_round_trip() {
        let db = db();
        let (t, _) = db.create_thread(None, "T").unwrap();
        let mut r = Respondent::human(Uuid::new_v4().to_string(), &t.id, "Cat Person");
        r.categories = vec!["vip".into(), "reviewer".into()];
        db.insert_respondent(&r, "respondent.added").unwrap();
        let reloaded = db.list_respondents(&t.id).unwrap();
        assert_eq!(reloaded[0].categories, vec!["vip", "reviewer"]);
    }
}
