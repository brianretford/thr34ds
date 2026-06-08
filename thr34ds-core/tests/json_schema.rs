//! Cuts and documents must conform to the published JSON Schemas
//! (`schemas/*.schema.json`).
//!
//! The guarantee is stronger than "the cut envelope validates": a cut attests to
//! every thread's chain head, which commits every sealed document — so **each
//! attested document in each cut conforms to its schema**. This test builds a
//! multi-thread system, takes a clean cut, and validates every attested
//! document the cut covers, so the schemas and the Rust types can never silently
//! drift apart.

use serde::Serialize;
use serde_json::Value;
use thr34ds_core::signed_time::Anchor;
use thr34ds_core::Database;

const ANCHOR_SCHEMA: &str = include_str!("../../schemas/anchor.schema.json");
const SIGNED_TIMESTAMP_SCHEMA: &str = include_str!("../../schemas/signed_timestamp.schema.json");
const SIGNED_STATE_ROOT_SCHEMA: &str = include_str!("../../schemas/signed_state_root.schema.json");
const SUMMONS_SCHEMA: &str = include_str!("../../schemas/summons.schema.json");
const POSTERITY_SCHEMA: &str = include_str!("../../schemas/posterity.schema.json");
const CUT_SCHEMA: &str = include_str!("../../schemas/cut.schema.json");
const BOUNDLESS_JOURNAL_SCHEMA: &str = include_str!("../../schemas/boundless_journal.schema.json");

fn assert_conforms<T: Serialize>(schema_src: &str, value: &T, label: &str) {
    let schema: Value = serde_json::from_str(schema_src).expect("schema parses");
    let instance: Value = serde_json::to_value(value).expect("value serializes");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    if let Err(error) = validator.validate(&instance) {
        panic!(
            "{label} does not conform to its JSON Schema: {error}\ninstance = {}",
            serde_json::to_string_pretty(&instance).unwrap()
        );
    }
}

#[test]
fn each_attested_document_in_each_cut_conforms() {
    let db = Database::open_in_memory().expect("in-memory db");

    // Build a multi-thread system: nested threads, respondents, summonses,
    // attributed messages, and an on-chain posterity.
    let (root, _) = db.create_thread(None, "Acme v. Roe").unwrap();
    let (sub, _) = db.create_thread(Some(&root.id), "Discovery").unwrap();
    let (other, _) = db.create_thread(None, "Doe Estate").unwrap();

    let (jane, _) = db.add_respondent(&root.id, "Jane Roe").unwrap();
    let (summons, _agent, _ts) = db
        .issue_summons(
            &root.id,
            "Roe (agent)",
            Some(&jane.uid),
            Some("Answers as the respondent would."),
            "Respond to interrogatories.",
            Some("Delaware"),
        )
        .unwrap();
    assert_conforms(SUMMONS_SCHEMA, &summons, "Summons");

    db.create_message(&sub.id, None, "Produced documents A–C.").unwrap();
    db.issue_summons(&other.id, "Executor (agent)", None, None, "Appear.", None)
        .unwrap();

    // Record the document's on-chain receipt (posterity), once.
    let anchor = Anchor::boundless("ethereum-sepolia", r#"{"tx_hash":"0xabc"}"#);
    assert_conforms(ANCHOR_SCHEMA, &anchor, "Anchor");
    let posterity = db
        .record_posterity(&root.id, &summons.content_hash(), &anchor)
        .unwrap();
    assert_conforms(POSTERITY_SCHEMA, &posterity, "Posterity");

    // Take a clean cut over the whole system.
    let cut = db.record_cut().unwrap();
    assert_conforms(CUT_SCHEMA, &cut, "Cut");
    assert!(cut.verify(), "cut must be actor-signed");

    // The cut attests to every thread; validate EVERY attested document it
    // covers — every sealed entry across every thread — against its schema.
    let threads = db.list_threads().unwrap();
    assert_eq!(threads.len(), 3);
    let mut attested_documents = 0;
    for thread in &threads {
        // The cut's leaf commits this thread's chain head; the head commits the
        // whole chain. Each entry is an attested document.
        for entry in db.list_timeline(&thread.id).unwrap() {
            assert_conforms(
                SIGNED_TIMESTAMP_SCHEMA,
                &entry,
                &format!("SignedTimestamp (thread {}, seq {})", thread.title, entry.seq),
            );
            attested_documents += 1;
        }
        // Summons documents in the thread, too.
        for s in db.list_summonses(&thread.id).unwrap() {
            assert_conforms(SUMMONS_SCHEMA, &s, "Summons");
        }
    }
    assert!(attested_documents >= 6, "expected attested documents across all threads");

    // The state root the cut captured, and an anchored cut, also conform.
    assert_conforms(SIGNED_STATE_ROOT_SCHEMA, &cut.state_root, "SignedStateRoot");
    db.anchor_cut(&cut.id, &anchor).unwrap();
    assert_conforms(CUT_SCHEMA, &db.get_cut(&cut.id).unwrap().unwrap(), "Cut (anchored)");

    // The on-chain Boundless journal derived from this cut (documentHash = the
    // cut's Merkle root) must conform to the same contract the guest and the
    // DocumentTimeOracle enforce. This is what "validate on-chain against the
    // same contract" means: one journal shape, three enforcers.
    let on_chain_journal = serde_json::json!({
        "document_hash": format!("0x{}", cut.state_root.root),
        "midpoint_unix_ms": 1_700_000_000_000_i64,
        "radius_ms": 10_000
    });
    let schema: Value = serde_json::from_str(BOUNDLESS_JOURNAL_SCHEMA).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(
        validator.is_valid(&on_chain_journal),
        "the on-chain journal for a cut must conform to boundless_journal.schema.json"
    );

    // And a malformed journal (un-prefixed hash) must be rejected.
    let bad = serde_json::json!({
        "document_hash": cut.state_root.root, // missing 0x prefix
        "midpoint_unix_ms": 1_700_000_000_000_i64,
        "radius_ms": 10_000
    });
    assert!(!validator.is_valid(&bad), "schema must reject a non-bytes32 hash");
}
