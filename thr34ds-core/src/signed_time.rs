//! **Cryptographically signed time** — the skeleton of thr34ds.
//!
//! Every meaningful event in the app (a thread created, a message posted, an
//! agent summoned) is sealed onto an append-only, tamper-evident timeline. Each
//! entry binds together:
//!
//! * a monotonically increasing **sequence** number,
//! * the **time** the event happened (ideally atomic-clock-synced UTC; see
//!   [`crate::timesync`]),
//! * a **hash of the payload** (what happened),
//! * the **hash of the previous entry** (forming a hash chain), and
//! * a **post-quantum signature** over all of the above.
//!
//! Signatures use **ML-DSA-65** (FIPS 204, the NIST-standardized, Dilithium-based
//! post-quantum signature scheme), via the pure-Rust [`ml_dsa`] crate so the
//! skeleton cross-compiles to desktop and mobile without a C toolchain.
//!
//! ## External anchoring
//!
//! Our signatures are self-issued: they prove *integrity and ordering* of the
//! timeline, but not that the wall-clock time is honest. For third-party
//! attestation of the time itself, each entry carries an optional [`Anchor`]
//! slot. Today there is no turnkey public **post-quantum** timestamp authority
//! (Google/Cloudflare Roughtime sign with Ed25519; an experimental ML-DSA-44
//! Roughtime variant and Google Cloud KMS PQ signing exist but aren't drop-in
//! free TSAs). The [`Anchor`] is the upgrade hook: it can hold a Roughtime
//! proof now and an ML-DSA Roughtime / KMS co-signature as those mature.
use chrono::{DateTime, Utc};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey, B32,
};
use rand_core::{OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The ML-DSA parameter set used for the timeline's own signatures.
pub const ALGORITHM: &str = "ML-DSA-65";

/// `prev_hash` value for the first (genesis) entry in a chain.
pub const GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// An optional external attestation of the time in a [`SignedTimestamp`].
///
/// This is the pluggable hook for third-party (ideally post-quantum) timestamp
/// authorities such as Roughtime or a cloud KMS co-signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Anchor {
    /// Anchor source, e.g. `"roughtime"`, `"rfc3161"`, `"cloud-kms"`.
    pub kind: String,
    /// Signature algorithm the anchor used, e.g. `"ML-DSA-44"`, `"Ed25519"`.
    pub algorithm: String,
    /// Identifier of the attesting server / authority.
    pub server: String,
    /// Opaque proof blob (hex/base64) returned by the authority.
    pub proof: String,
}

impl Anchor {
    /// Construct an anchor for an on-chain Boundless settlement: the document's
    /// time window was proven and settled on-chain. `network` identifies the
    /// chain (e.g. `"ethereum-sepolia"`); `proof` carries the settlement
    /// reference (e.g. a JSON blob with `request_id` and `tx_hash`).
    pub fn boundless(network: impl Into<String>, proof: impl Into<String>) -> Self {
        Anchor {
            kind: "boundless".to_string(),
            algorithm: "risc0".to_string(),
            server: network.into(),
            proof: proof.into(),
        }
    }
}

/// One sealed entry on the signed timeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedTimestamp {
    /// Monotonic sequence number (1-based; genesis is 1).
    pub seq: u64,
    /// Event time as an RFC-3339 UTC string.
    pub time: String,
    /// Provenance of `time`, e.g. `"ntp:time.cloudflare.com offset=+3ms"` or
    /// `"local"`.
    pub time_source: String,
    /// Hex SHA-256 of the event payload.
    pub payload_hash: String,
    /// Hex hash of the previous entry (or [`GENESIS_HASH`]).
    pub prev_hash: String,
    /// Hex hash of this entry (binds the canonical fields *and* the signature);
    /// this is what the next entry chains onto.
    pub hash: String,
    /// Signature algorithm (always [`ALGORITHM`] for entries we issue).
    pub algorithm: String,
    /// Hex-encoded ML-DSA public (verifying) key.
    pub public_key: String,
    /// Hex-encoded ML-DSA signature over the canonical bytes.
    pub signature: String,
    /// Optional external time attestation.
    pub anchor: Option<Anchor>,
}

impl SignedTimestamp {
    /// Recompute the canonical, to-be-signed representation of this entry.
    fn canonical(&self) -> String {
        canonical(
            self.seq,
            &self.time,
            &self.time_source,
            &self.prev_hash,
            &self.payload_hash,
            &self.algorithm,
        )
    }

    /// Verify this entry's post-quantum signature **and** that its `hash`
    /// correctly commits to its contents. Does not check chain linkage — see
    /// [`SignedTimestamp::verify_follows`] / [`verify_chain`].
    pub fn verify(&self) -> bool {
        let canon = self.canonical();

        // 1. The stored hash must commit to canonical bytes + signature.
        if entry_hash(&canon, &self.signature) != self.hash {
            return false;
        }

        // 2. The signature must verify under the embedded public key.
        let Some(vk) = decode_verifying_key(&self.public_key) else {
            return false;
        };
        let Some(sig) = decode_signature(&self.signature) else {
            return false;
        };
        vk.verify(canon.as_bytes(), &sig).is_ok()
    }

    /// Verify this entry is internally valid *and* correctly chains onto `prev`.
    pub fn verify_follows(&self, prev: &SignedTimestamp) -> bool {
        self.seq == prev.seq + 1 && self.prev_hash == prev.hash && self.verify()
    }
}

/// Verify a full timeline: every entry is valid, sequence numbers are
/// contiguous, and the hash chain is intact. Returns the index of the first bad
/// entry on failure.
pub fn verify_chain(entries: &[SignedTimestamp]) -> Result<(), usize> {
    for (i, entry) in entries.iter().enumerate() {
        let ok = match i {
            0 => entry.seq == 1 && entry.prev_hash == GENESIS_HASH && entry.verify(),
            _ => entry.verify_follows(&entries[i - 1]),
        };
        if !ok {
            return Err(i);
        }
    }
    Ok(())
}

/// Holds the post-quantum signing key and the running chain head. Seals events
/// into [`SignedTimestamp`]s.
pub struct Notary {
    signing_key: SigningKey<MlDsa65>,
    public_key_hex: String,
    seq: u64,
    last_hash: String,
}

impl Notary {
    /// Create a notary with a freshly generated random key, starting a new
    /// chain at genesis.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut seed)
            .expect("OS RNG unavailable for key generation");
        Self::from_seed_bytes(&seed).expect("freshly generated 32-byte seed is valid")
    }

    /// Reconstruct a notary from a previously persisted 32-byte seed (hex),
    /// starting a fresh chain. Use [`Notary::resume`] to continue an existing
    /// chain.
    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(seed_hex.trim()).map_err(|e| e.to_string())?;
        Self::from_seed_bytes(&bytes)
    }

    fn from_seed_bytes(bytes: &[u8]) -> Result<Self, String> {
        let seed = B32::try_from(bytes).map_err(|_| "seed must be exactly 32 bytes".to_string())?;
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        let public_key_hex = hex::encode(signing_key.verifying_key().encode().as_slice());
        Ok(Self {
            signing_key,
            public_key_hex,
            seq: 0,
            last_hash: GENESIS_HASH.to_string(),
        })
    }

    /// Continue an existing chain from persisted state (its last sequence number
    /// and last entry hash).
    pub fn resume(seed_hex: &str, last_seq: u64, last_hash: impl Into<String>) -> Result<Self, String> {
        let mut n = Self::from_seed_hex(seed_hex)?;
        n.seq = last_seq;
        n.last_hash = last_hash.into();
        Ok(n)
    }

    /// The 32-byte signing seed, hex-encoded. **Secret** — persist securely.
    pub fn seed_hex(&self) -> String {
        hex::encode(self.signing_key.to_seed().as_slice())
    }

    /// The hex-encoded ML-DSA public (verifying) key.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Sequence number of the most recently sealed entry (0 before any).
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Hash of the most recently sealed entry (chain head).
    pub fn last_hash(&self) -> &str {
        &self.last_hash
    }

    /// Produce a detached post-quantum signature over `msg` with the actor's
    /// key. Does **not** touch the chain — used to sign aggregate commitments
    /// such as a Merkle state root. Returns the hex-encoded signature.
    pub fn sign_message(&self, msg: &[u8]) -> String {
        let sig: Signature<MlDsa65> = self.signing_key.sign(msg);
        hex::encode(sig.encode().as_slice())
    }

    /// Seal an event payload at the given time onto the timeline.
    pub fn seal(
        &mut self,
        payload: &[u8],
        time: DateTime<Utc>,
        time_source: impl Into<String>,
    ) -> SignedTimestamp {
        self.seal_inner(payload, time, time_source.into(), None)
    }

    /// Seal an event with an external time [`Anchor`] attached.
    pub fn seal_with_anchor(
        &mut self,
        payload: &[u8],
        time: DateTime<Utc>,
        time_source: impl Into<String>,
        anchor: Anchor,
    ) -> SignedTimestamp {
        self.seal_inner(payload, time, time_source.into(), Some(anchor))
    }

    fn seal_inner(
        &mut self,
        payload: &[u8],
        time: DateTime<Utc>,
        time_source: String,
        anchor: Option<Anchor>,
    ) -> SignedTimestamp {
        let seq = self.seq + 1;
        let time_str = time.to_rfc3339();
        let payload_hash = sha256_hex(payload);

        let canon = canonical(
            seq,
            &time_str,
            &time_source,
            &self.last_hash,
            &payload_hash,
            ALGORITHM,
        );

        // ML-DSA signing via the `Signer` trait (deterministic variant).
        let sig: Signature<MlDsa65> = self.signing_key.sign(canon.as_bytes());
        let signature = hex::encode(sig.encode().as_slice());
        let hash = entry_hash(&canon, &signature);

        let entry = SignedTimestamp {
            seq,
            time: time_str,
            time_source,
            payload_hash,
            prev_hash: std::mem::replace(&mut self.last_hash, hash.clone()),
            hash,
            algorithm: ALGORITHM.to_string(),
            public_key: self.public_key_hex.clone(),
            signature,
            anchor,
        };
        self.seq = seq;
        entry
    }
}

// ── Canonicalization & hashing ───────────────────────────────────────────────

/// Deterministic, to-be-signed byte representation of an entry. Excludes the
/// signature, the entry hash, the public key, and the (unsigned) anchor.
fn canonical(
    seq: u64,
    time: &str,
    time_source: &str,
    prev_hash: &str,
    payload_hash: &str,
    algorithm: &str,
) -> String {
    format!(
        "thr34ds-signed-time/v1\n{algorithm}\n{seq}\n{time}\n{time_source}\n{prev_hash}\n{payload_hash}"
    )
}

/// This entry's chain hash: commits to the canonical bytes *and* the signature.
fn entry_hash(canonical: &str, signature_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    h.update(b"\n");
    h.update(signature_hex.as_bytes());
    hex::encode(h.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Verify a detached signature (as produced by [`Notary::sign_message`])
/// against a public key. Both key and signature are hex-encoded.
pub fn verify_signature(public_key_hex: &str, msg: &[u8], signature_hex: &str) -> bool {
    let Some(vk) = decode_verifying_key(public_key_hex) else {
        return false;
    };
    let Some(sig) = decode_signature(signature_hex) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

fn decode_verifying_key(hex_str: &str) -> Option<VerifyingKey<MlDsa65>> {
    let bytes = hex::decode(hex_str).ok()?;
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(&bytes[..]).ok()?;
    Some(VerifyingKey::<MlDsa65>::decode(&enc))
}

fn decode_signature(hex_str: &str) -> Option<Signature<MlDsa65>> {
    let bytes = hex::decode(hex_str).ok()?;
    let enc = EncodedSignature::<MlDsa65>::try_from(&bytes[..]).ok()?;
    Signature::<MlDsa65>::decode(&enc)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn seals_and_verifies_a_single_entry() {
        let mut n = Notary::generate();
        let ts = n.seal(b"thread created: Plan trip", at(1_700_000_000), "local");
        assert_eq!(ts.seq, 1);
        assert_eq!(ts.prev_hash, GENESIS_HASH);
        assert_eq!(ts.algorithm, ALGORITHM);
        assert!(ts.verify());
    }

    #[test]
    fn builds_a_valid_chain() {
        let mut n = Notary::generate();
        let a = n.seal(b"a", at(1), "local");
        let b = n.seal(b"b", at(2), "local");
        let c = n.seal(b"c", at(3), "local");

        assert_eq!((a.seq, b.seq, c.seq), (1, 2, 3));
        assert_eq!(b.prev_hash, a.hash);
        assert_eq!(c.prev_hash, b.hash);
        assert!(b.verify_follows(&a));
        assert!(c.verify_follows(&b));
        verify_chain(&[a, b, c]).expect("chain must verify");
    }

    #[test]
    fn tampering_with_payload_hash_is_detected() {
        let mut n = Notary::generate();
        let mut ts = n.seal(b"original", at(10), "local");
        ts.payload_hash = sha256_hex(b"forged");
        assert!(!ts.verify());
    }

    #[test]
    fn tampering_with_time_is_detected() {
        let mut n = Notary::generate();
        let mut ts = n.seal(b"x", at(10), "local");
        ts.time = at(99_999).to_rfc3339();
        assert!(!ts.verify());
    }

    #[test]
    fn reordering_breaks_the_chain() {
        let mut n = Notary::generate();
        let a = n.seal(b"a", at(1), "local");
        let b = n.seal(b"b", at(2), "local");
        // Swapped order: b no longer chains onto genesis correctly.
        assert!(matches!(verify_chain(&[b, a]), Err(0)));
    }

    #[test]
    fn resume_continues_chain_deterministically() {
        let mut n = Notary::generate();
        let seed = n.seed_hex();
        let a = n.seal(b"a", at(1), "local");

        // Resume from persisted state and append.
        let mut n2 = Notary::resume(&seed, a.seq, &a.hash).unwrap();
        let b = n2.seal(b"b", at(2), "local");
        assert!(b.verify_follows(&a));
        assert_eq!(b.seq, 2);
    }

    #[test]
    fn anchor_is_carried_but_not_part_of_signature() {
        let mut n = Notary::generate();
        let anchor = Anchor {
            kind: "roughtime".into(),
            algorithm: "Ed25519".into(),
            server: "roughtime.cloudflare.com".into(),
            proof: "deadbeef".into(),
        };
        let ts = n.seal_with_anchor(b"x", at(5), "local", anchor.clone());
        assert_eq!(ts.anchor, Some(anchor));
        // Anchor is metadata; the entry still verifies, and mutating the anchor
        // does not invalidate the PQ signature (anchor carries its own proof).
        assert!(ts.verify());
    }
}
