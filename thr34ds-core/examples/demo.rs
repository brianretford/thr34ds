//! End-to-end demo of the thr34ds engine, headless.
//!
//!     cargo run -p thr34ds-core --example demo
//!
//! One person, multiple threads, cleanly recorded in time, forever.

use thr34ds_core::signed_time::Anchor;
use thr34ds_core::Database;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = Database::open_in_memory()?;
    println!("== thr34ds ==");
    println!("custodian (one person) key: {}…\n", &db.timeline_public_key()[..32]);

    // 1. Threads nest.
    let (matter, _) = db.create_thread(None, "Acme v. Roe")?;
    let (discovery, _) = db.create_thread(Some(&matter.id), "Discovery")?;
    println!("thread:  {}", matter.title);
    println!("  └─ sub-thread: {}\n", discovery.title);

    // 2. A human respondent (your own work) + a summoned agent (modelled work).
    let (jane, _) = db.add_respondent(&matter.id, "Jane Roe")?;
    let (summons, agent, _ts) = db.issue_summons(
        &matter.id,
        "Roe (agent)",
        Some(&jane.uid),
        Some("Answers as the respondent would."),
        "Respond to interrogatories within 30 days.",
        Some("Delaware"),
    )?;
    println!("respondent (human):  {}  [{}]", jane.formatted_name, jane.kind.as_vcard());
    println!("summoned agent:      {}  [{}] models {}", agent.formatted_name, agent.kind.as_vcard(), jane.formatted_name);
    println!("\n--- summons document ---\n{}\n", summons.render_text());

    // 3. Attributed work in the sub-thread.
    db.create_message(&discovery.id, Some(&jane.uid), "Produced documents A–C.")?;

    // 4. Record the document's on-chain receipt — posterity, once.
    let anchor = Anchor::boundless("ethereum-sepolia", r#"{"tx_hash":"0xabc123"}"#);
    let posterity = db.record_posterity(&matter.id, &summons.content_hash(), &anchor)?;
    println!("posterity recorded once at seq {} (anchor: {})", posterity.seq, posterity.anchor.kind);

    // 5. Verify the matter's chain and prove its inclusion under the actor root.
    let chain_ok = db.verify_thread(&matter.id)?.is_ok();
    let inclusion = db.prove_thread(&matter.id)?.unwrap();
    println!("matter chain verifies: {chain_ok}");
    println!("inclusion proof verifies under signed root: {}\n", inclusion.verify());

    // 6. Signed timeline of the matter.
    println!("--- matter timeline (post-quantum signed) ---");
    for e in db.list_timeline(&matter.id)? {
        let anch = e.anchor.as_ref().map(|a| format!("  ⚓ {}", a.kind)).unwrap_or_default();
        println!("  seq {} | {} | {}…{}", e.seq, e.time, &e.payload_hash[..12], anch);
    }

    // 7. A clean cut over every thread, signed by the one actor.
    let cut = db.record_cut()?;
    println!("\n--- clean cut (all threads, one actor) ---");
    println!("  root:       {}", cut.state_root.root);
    println!("  threads:    {}", cut.state_root.leaf_count);
    println!("  algorithm:  {}", cut.state_root.algorithm);
    println!("  signed ok:  {}", cut.verify());
    println!("\nthis cut's root is the single document you post to Boundless to");
    println!("checkpoint the whole system on-chain. ✔");

    Ok(())
}
