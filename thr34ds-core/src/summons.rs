//! Legal-grade **summons** documents.
//!
//! In thr34ds a *summon* brings an agent in *in lieu of* a human respondent. For
//! that act to carry evidentiary weight it must be a self-contained, verifiable
//! document binding:
//!
//! * the **issuer** (the one actor that signs the timeline),
//! * the **agent** summoned (a `KIND:application` vCard),
//! * the **human respondent** stood in for,
//! * the **matter** (thread) it pertains to,
//! * its **purpose / mandate**, optional **jurisdiction**, and
//! * the **time** it was issued.
//!
//! [`Summons::canonical_document`] is the deterministic byte representation that
//! is hashed, sealed onto the thread's post-quantum chain, and used as the
//! Roughtime nonce for an external time-window attestation. [`Summons::content_hash`]
//! is that hash.
//!
//! ## Honest scope
//!
//! This produces a *legal-grade-ready* artifact: strong (post-quantum)
//! non-repudiation, tamper-evidence, an immutable ordered audit trail, and a
//! trusted-time anchor hook. True legal admissibility additionally requires
//! binding the issuer key to a real, vetted identity (e.g. an eIDAS qualified
//! certificate) and a *qualified* timestamp authority (eIDAS / RFC 3161). Those
//! are deployment concerns layered on top of this structure, not invented here.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A summons document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summons {
    /// Unique summons id.
    pub id: String,
    /// When the summons was issued (RFC-3339 UTC; trusted time when synced).
    pub issued_at: DateTime<Utc>,
    /// The matter: the thread this summons pertains to.
    pub matter_thread_id: String,
    /// Human-readable title of the matter.
    pub matter_title: String,
    /// Hex public key of the issuing actor (signs the timeline).
    pub issuer_key: String,
    /// Optional human-readable issuer identity.
    pub issuer_name: Option<String>,
    /// The summoned agent's vCard `UID`.
    pub agent_uid: String,
    /// The summoned agent's display name.
    pub agent_name: String,
    /// `UID` of the human respondent the agent stands in for, if any.
    pub in_lieu_of_uid: Option<String>,
    /// Name of the human respondent stood in for, if known.
    pub in_lieu_of_name: Option<String>,
    /// The mandate: why the agent is summoned / what it is authorized to do.
    pub purpose: String,
    /// Optional governing jurisdiction.
    pub jurisdiction: Option<String>,
}

impl Summons {
    /// Deterministic, signable byte representation. This is what gets hashed,
    /// sealed on-chain, and used as the time-attestation nonce.
    pub fn canonical_document(&self) -> String {
        let mut s = String::from("thr34ds-summons/v1\n");
        s.push_str(&field("id", &self.id));
        s.push_str(&field("issued_at", &self.issued_at.to_rfc3339()));
        s.push_str(&field("matter_thread", &self.matter_thread_id));
        s.push_str(&field("matter_title", &self.matter_title));
        s.push_str(&field("issuer_key", &self.issuer_key));
        s.push_str(&field("issuer_name", opt(&self.issuer_name)));
        s.push_str(&field("agent_uid", &self.agent_uid));
        s.push_str(&field("agent_name", &self.agent_name));
        s.push_str(&field("in_lieu_of_uid", opt(&self.in_lieu_of_uid)));
        s.push_str(&field("in_lieu_of_name", opt(&self.in_lieu_of_name)));
        s.push_str(&field("jurisdiction", opt(&self.jurisdiction)));
        s.push_str(&field("purpose", &self.purpose));
        s
    }

    /// Hex SHA-256 of the canonical document — its content hash / nonce.
    pub fn content_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.canonical_document().as_bytes());
        hex::encode(h.finalize())
    }

    /// A human-readable rendering of the summons.
    pub fn render_text(&self) -> String {
        let in_lieu = match (&self.in_lieu_of_name, &self.in_lieu_of_uid) {
            (Some(name), _) => format!("{name}"),
            (None, Some(uid)) => format!("respondent {uid}"),
            _ => "an unnamed human respondent".to_string(),
        };
        let juris = self
            .jurisdiction
            .as_deref()
            .map(|j| format!(" under the jurisdiction of {j}"))
            .unwrap_or_default();
        format!(
            "SUMMONS {id}\n\
             Issued: {issued} (issuer {issuer})\n\
             In the matter of: {matter} [{thread}]{juris}\n\n\
             The agent \"{agent}\" ({agent_uid}) is hereby summoned to appear and act\n\
             in lieu of {in_lieu}, modeling that respondent's behavior.\n\n\
             Purpose: {purpose}\n\n\
             Content hash (SHA-256): {hash}",
            id = self.id,
            issued = self.issued_at.to_rfc3339(),
            issuer = self.issuer_name.as_deref().unwrap_or(&self.issuer_key),
            matter = self.matter_title,
            thread = self.matter_thread_id,
            juris = juris,
            agent = self.agent_name,
            agent_uid = self.agent_uid,
            in_lieu = in_lieu,
            purpose = self.purpose,
            hash = self.content_hash(),
        )
    }
}

fn field(key: &str, value: &str) -> String {
    format!("{key}: {}\n", esc(value))
}

fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("-")
}

/// Escape so a value cannot inject line boundaries into the canonical form.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Summons {
        Summons {
            id: "s1".into(),
            issued_at: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            matter_thread_id: "t1".into(),
            matter_title: "Acme v. Roe".into(),
            issuer_key: "abcd".into(),
            issuer_name: Some("Clerk".into()),
            agent_uid: "a1".into(),
            agent_name: "Roe (agent)".into(),
            in_lieu_of_uid: Some("h1".into()),
            in_lieu_of_name: Some("Jane Roe".into()),
            purpose: "Respond to interrogatories.".into(),
            jurisdiction: Some("Delaware".into()),
        }
    }

    #[test]
    fn canonical_is_deterministic() {
        let s = sample();
        assert_eq!(s.canonical_document(), s.canonical_document());
        assert!(s.canonical_document().starts_with("thr34ds-summons/v1\n"));
    }

    #[test]
    fn content_hash_changes_with_any_field() {
        let s = sample();
        let h1 = s.content_hash();
        let mut s2 = s.clone();
        s2.purpose = "Something else.".into();
        assert_ne!(h1, s2.content_hash());
    }

    #[test]
    fn injection_cannot_forge_fields() {
        // A newline in a value must not create a new canonical line.
        let mut s = sample();
        s.purpose = "ok\nissuer_key: attacker".into();
        assert!(!s.canonical_document().contains("\nissuer_key: attacker"));
    }

    #[test]
    fn render_mentions_key_parties() {
        let txt = sample().render_text();
        assert!(txt.contains("Roe (agent)"));
        assert!(txt.contains("Jane Roe"));
        assert!(txt.contains("Acme v. Roe"));
    }
}
