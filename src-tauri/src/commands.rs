use tauri::State;
use chrono::Utc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

use crate::AppState;
use thr34ds_core::{
    db::{Thread, Message},
    timesync,
};

// ── Error type ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct CommandError(String);

impl<E: std::fmt::Display> From<E> for CommandError {
    fn from(e: E) -> Self {
        CommandError(e.to_string())
    }
}

type CmdResult<T> = Result<T, CommandError>;

// ── Thread commands ────────────────────────────────────────────────────────

/// Return all threads ordered by most-recently-updated first.
#[tauri::command]
pub fn list_threads(state: State<'_, AppState>) -> CmdResult<Vec<Thread>> {
    let db = state.db.lock().map_err(|e| CommandError(e.to_string()))?;
    Ok(db.list_threads()?)
}

#[derive(Deserialize)]
pub struct CreateThreadInput {
    pub title: String,
}

/// Create a new thread and return it.
#[tauri::command]
pub fn create_thread(
    input: CreateThreadInput,
    state: State<'_, AppState>,
) -> CmdResult<Thread> {
    let now = Utc::now();
    let thread = Thread {
        id: Uuid::new_v4().to_string(),
        title: input.title,
        created_at: now,
        updated_at: now,
    };
    let db = state.db.lock().map_err(|e| CommandError(e.to_string()))?;
    db.insert_thread(&thread)?;
    Ok(thread)
}

/// Delete a thread (and all its messages via cascade).
#[tauri::command]
pub fn delete_thread(
    id: String,
    state: State<'_, AppState>,
) -> CmdResult<()> {
    let db = state.db.lock().map_err(|e| CommandError(e.to_string()))?;
    db.delete_thread(&id)?;
    Ok(())
}

// ── Message commands ───────────────────────────────────────────────────────

/// Return all messages in a thread ordered by creation time.
#[tauri::command]
pub fn list_messages(
    thread_id: String,
    state: State<'_, AppState>,
) -> CmdResult<Vec<Message>> {
    let db = state.db.lock().map_err(|e| CommandError(e.to_string()))?;
    Ok(db.list_messages(&thread_id)?)
}

#[derive(Deserialize)]
pub struct CreateMessageInput {
    pub thread_id: String,
    pub body: String,
}

/// Append a new message to a thread and return it.
#[tauri::command]
pub fn create_message(
    input: CreateMessageInput,
    state: State<'_, AppState>,
) -> CmdResult<Message> {
    let msg = Message {
        id: Uuid::new_v4().to_string(),
        thread_id: input.thread_id,
        body: input.body,
        created_at: Utc::now(),
    };
    let db = state.db.lock().map_err(|e| CommandError(e.to_string()))?;
    db.insert_message(&msg)?;
    Ok(msg)
}

/// Delete a single message.
#[tauri::command]
pub fn delete_message(
    id: String,
    state: State<'_, AppState>,
) -> CmdResult<()> {
    let db = state.db.lock().map_err(|e| CommandError(e.to_string()))?;
    db.delete_message(&id)?;
    Ok(())
}

// ── Time-sync command ──────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SyncedTimeResponse {
    /// ISO-8601 UTC timestamp from the NTP server.
    pub utc_now: String,
    /// Clock offset between NTP and local system clock (milliseconds).
    pub offset_ms: i64,
    /// NTP server that responded.
    pub server: String,
}

/// Query a public NTP server and return the current atomic-clock-synced time.
#[tauri::command]
pub fn get_synced_time() -> CmdResult<SyncedTimeResponse> {
    let result = timesync::query_ntp()?;
    Ok(SyncedTimeResponse {
        utc_now: result.utc_now.to_rfc3339(),
        offset_ms: result.offset_ms,
        server: result.server,
    })
}
