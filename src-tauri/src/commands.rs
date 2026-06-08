use serde::{Deserialize, Serialize};
use tauri::State;

use crate::AppState;
use thr34ds_core::{
    db::{Message, SignedStateRoot, SummonsCertificate, Thread, ThreadInclusion},
    signed_time::{Anchor, SignedTimestamp},
    timesync, Respondent, Summons,
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

/// Lock the database, mapping a poisoned mutex to a command error.
macro_rules! db {
    ($state:expr) => {
        $state.db.lock().map_err(|e| CommandError(e.to_string()))?
    };
}

// ── Threads ──────────────────────────────────────────────────────────────────

/// All threads (flat), most-recently-updated first.
#[tauri::command]
pub fn list_threads(state: State<'_, AppState>) -> CmdResult<Vec<Thread>> {
    Ok(db!(state).list_threads()?)
}

/// Root threads (no parent).
#[tauri::command]
pub fn list_root_threads(state: State<'_, AppState>) -> CmdResult<Vec<Thread>> {
    Ok(db!(state).list_root_threads()?)
}

/// Direct sub-threads of a parent.
#[tauri::command]
pub fn list_child_threads(parent_id: String, state: State<'_, AppState>) -> CmdResult<Vec<Thread>> {
    Ok(db!(state).list_child_threads(&parent_id)?)
}

#[derive(Deserialize)]
pub struct CreateThreadInput {
    pub title: String,
    /// Parent thread id for a sub-thread; omit for a root thread.
    #[serde(default)]
    pub parent_id: Option<String>,
}

/// Create a thread (root or sub-thread) and seal its genesis event.
#[tauri::command]
pub fn create_thread(input: CreateThreadInput, state: State<'_, AppState>) -> CmdResult<Thread> {
    let (thread, _ts) = db!(state).create_thread(input.parent_id.as_deref(), &input.title)?;
    Ok(thread)
}

/// Delete a thread and everything beneath it.
#[tauri::command]
pub fn delete_thread(id: String, state: State<'_, AppState>) -> CmdResult<()> {
    db!(state).delete_thread(&id)?;
    Ok(())
}

// ── Messages ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub fn list_messages(thread_id: String, state: State<'_, AppState>) -> CmdResult<Vec<Message>> {
    Ok(db!(state).list_messages(&thread_id)?)
}

#[derive(Deserialize)]
pub struct CreateMessageInput {
    pub thread_id: String,
    pub body: String,
    /// The respondent (human or agent) credited with this message.
    #[serde(default)]
    pub respondent_uid: Option<String>,
}

/// Append a message attributed to a respondent and seal it onto the chain.
#[tauri::command]
pub fn create_message(input: CreateMessageInput, state: State<'_, AppState>) -> CmdResult<Message> {
    let (msg, _ts) =
        db!(state).create_message(&input.thread_id, input.respondent_uid.as_deref(), &input.body)?;
    Ok(msg)
}

#[tauri::command]
pub fn delete_message(id: String, state: State<'_, AppState>) -> CmdResult<()> {
    db!(state).delete_message(&id)?;
    Ok(())
}

// ── Respondents (vCard) ──────────────────────────────────────────────────────

#[tauri::command]
pub fn list_respondents(thread_id: String, state: State<'_, AppState>) -> CmdResult<Vec<Respondent>> {
    Ok(db!(state).list_respondents(&thread_id)?)
}

#[derive(Deserialize)]
pub struct AddRespondentInput {
    pub thread_id: String,
    pub name: String,
}

/// Add a human respondent (`KIND:individual`).
#[tauri::command]
pub fn add_respondent(input: AddRespondentInput, state: State<'_, AppState>) -> CmdResult<Respondent> {
    let (r, _ts) = db!(state).add_respondent(&input.thread_id, &input.name)?;
    Ok(r)
}

#[derive(Deserialize)]
pub struct SummonAgentInput {
    pub thread_id: String,
    pub name: String,
    /// The human respondent the agent stands in for.
    #[serde(default)]
    pub models_uid: Option<String>,
    /// The behavior the agent models.
    #[serde(default)]
    pub behavior: Option<String>,
}

/// Summon an agent (`KIND:application`) that models a human respondent.
#[tauri::command]
pub fn summon_agent(input: SummonAgentInput, state: State<'_, AppState>) -> CmdResult<Respondent> {
    let (agent, _ts) = db!(state).summon_agent(
        &input.thread_id,
        &input.name,
        input.models_uid.as_deref(),
        input.behavior.as_deref(),
    )?;
    Ok(agent)
}

// ── Summonses (legal-grade) ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct IssueSummonsInput {
    pub thread_id: String,
    pub agent_name: String,
    #[serde(default)]
    pub in_lieu_of_uid: Option<String>,
    #[serde(default)]
    pub behavior: Option<String>,
    pub purpose: String,
    #[serde(default)]
    pub jurisdiction: Option<String>,
}

/// Issue a legal-grade summons: create the agent, build and seal the summons
/// document. Returns the summons document.
#[tauri::command]
pub fn issue_summons(input: IssueSummonsInput, state: State<'_, AppState>) -> CmdResult<Summons> {
    let (summons, _agent, _ts) = db!(state).issue_summons(
        &input.thread_id,
        &input.agent_name,
        input.in_lieu_of_uid.as_deref(),
        input.behavior.as_deref(),
        &input.purpose,
        input.jurisdiction.as_deref(),
    )?;
    Ok(summons)
}

#[tauri::command]
pub fn list_summonses(thread_id: String, state: State<'_, AppState>) -> CmdResult<Vec<Summons>> {
    Ok(db!(state).list_summonses(&thread_id)?)
}

#[derive(Serialize)]
pub struct CertifiedSummons {
    pub certificate: SummonsCertificate,
    pub content_committed: bool,
    pub entry_signed: bool,
    pub included_under_root: bool,
    pub matter_consistent: bool,
    pub ok: bool,
    pub render: String,
}

/// Produce a verifiable summons certificate together with its verification.
#[tauri::command]
pub fn certify_summons(id: String, state: State<'_, AppState>) -> CmdResult<Option<CertifiedSummons>> {
    let Some(cert) = db!(state).certify_summons(&id)? else {
        return Ok(None);
    };
    let v = cert.verify();
    Ok(Some(CertifiedSummons {
        content_committed: v.content_committed,
        entry_signed: v.entry_signed,
        included_under_root: v.included_under_root,
        matter_consistent: v.matter_consistent,
        ok: v.ok(),
        render: cert.render_text(),
        certificate: cert,
    }))
}

// ── Signed timeline & proofs ──────────────────────────────────────────────────

#[tauri::command]
pub fn list_timeline(thread_id: String, state: State<'_, AppState>) -> CmdResult<Vec<SignedTimestamp>> {
    Ok(db!(state).list_timeline(&thread_id)?)
}

#[derive(Serialize)]
pub struct VerifyThreadResult {
    pub ok: bool,
    /// Index of the first bad entry, if any.
    pub bad_index: Option<usize>,
}

/// Verify a thread's chain end-to-end.
#[tauri::command]
pub fn verify_thread(thread_id: String, state: State<'_, AppState>) -> CmdResult<VerifyThreadResult> {
    Ok(match db!(state).verify_thread(&thread_id)? {
        Ok(()) => VerifyThreadResult { ok: true, bad_index: None },
        Err(i) => VerifyThreadResult { ok: false, bad_index: Some(i) },
    })
}

/// The actor-signed Merkle root over every thread's chain head.
#[tauri::command]
pub fn state_root(state: State<'_, AppState>) -> CmdResult<SignedStateRoot> {
    Ok(db!(state).state_root()?)
}

/// Prove a thread is committed under the signed state root.
#[tauri::command]
pub fn prove_thread(thread_id: String, state: State<'_, AppState>) -> CmdResult<Option<ThreadInclusion>> {
    Ok(db!(state).prove_thread(&thread_id)?)
}

/// The app's post-quantum custodian public key.
#[tauri::command]
pub fn timeline_public_key(state: State<'_, AppState>) -> CmdResult<String> {
    Ok(db!(state).timeline_public_key())
}

#[derive(Deserialize)]
pub struct AttachAnchorInput {
    pub thread_id: String,
    /// Payload hash of the document/entry to anchor (e.g. a summons content hash).
    pub payload_hash: String,
    pub anchor: Anchor,
}

/// Attach an external/on-chain time anchor (e.g. a Boundless settlement) to a
/// sealed timeline entry. Returns whether a matching entry was updated.
#[tauri::command]
pub fn attach_anchor(input: AttachAnchorInput, state: State<'_, AppState>) -> CmdResult<bool> {
    Ok(db!(state).attach_anchor(&input.thread_id, &input.payload_hash, &input.anchor)?)
}

// ── Time-sync command ──────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SyncedTimeResponse {
    pub utc_now: String,
    pub offset_ms: i64,
    pub server: String,
}

/// Query a public NTP server, record the offset so subsequent sealed times use
/// the corrected clock, and return the synced time.
#[tauri::command]
pub fn get_synced_time(state: State<'_, AppState>) -> CmdResult<SyncedTimeResponse> {
    let result = timesync::query_ntp()?;
    {
        let mut db = state.db.lock().map_err(|e| CommandError(e.to_string()))?;
        db.set_synced_time(result.offset_ms, &result.server);
    }
    Ok(SyncedTimeResponse {
        utc_now: result.utc_now.to_rfc3339(),
        offset_ms: result.offset_ms,
        server: result.server,
    })
}
