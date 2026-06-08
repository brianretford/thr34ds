/**
 * Document time-window attestation — the prototype's core claim.
 *
 * Proves that a *document* existed within a bounded time window
 *   [ midpoint - radius , midpoint + radius ]
 * attested by a post-quantum (ML-DSA-65) Roughtime-style signature and wrapped
 * in a (mock) RISC Zero journal suitable for on-chain verification.
 *
 * This is the browser-side generator for the `Anchor` slot in the Rust
 * signed-time core (`thr34ds_core::signed_time::Anchor`). `toAnchor(receipt)`
 * yields the exact `{ kind, algorithm, server, proof }` shape the backend
 * stores alongside a sealed event.
 *
 * NOTE: `mldsa-wasm` is loaded from a CDN, so this module needs network access
 * at runtime. The RISC Zero seal is explicitly a mock — real seal generation
 * happens prover-side; on-chain the verifier would check the real seal plus the
 * journal's time window.
 */
import * as mldsa from "https://esm.sh/mldsa-wasm";

const enc = new TextEncoder();

/** Default attestation domain (versioned). */
export const DOMAIN = "reforged.roughtime.zk.v1";

export function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

export async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

/** Deterministic, key-sorted JSON so signer and verifier hash identical bytes. */
function canonical(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

function toBytes(document) {
  return typeof document === "string" ? enc.encode(document) : document;
}

/** Generate an ML-DSA-65 keypair (the time oracle's signing identity). */
export async function keygen() {
  return mldsa.keygen();
}

/**
 * Build and ML-DSA-sign a time-window journal committing `document`, then wrap
 * it in a mock RISC Zero receipt.
 *
 * The document hash IS the Roughtime nonce: rather than a random nonce, the
 * document itself is the value presented to the oracle, so the signed response
 * binds the attested time window directly to the document.
 *
 * @param {{publicKey: Uint8Array, secretKey: Uint8Array}} keypair
 * @param {Uint8Array|string} document  the document to time-stamp
 * @param {{radiusMs?: number, source?: string, domain?: string}} [opts]
 * @returns {Promise<object>} the receipt artifact
 */
export async function proveDocumentTimeWindow(keypair, document, opts = {}) {
  const docBytes = toBytes(document);
  const radiusMs = opts.radiusMs ?? 10_000;
  const source = opts.source ?? "local-demo-roughtime";

  // The document is the nonce.
  const nonce = await sha256Hex(docBytes);

  const journal = {
    domain: opts.domain ?? DOMAIN,
    nonce,
    midpoint_unix_ms: Date.now(),
    radius_ms: radiusMs,
    source,
    alg: "ML-DSA-65",
  };

  const message = enc.encode(canonical(journal));
  const signature = await mldsa.sign(keypair.secretKey, message);

  return {
    kind: "mock-risc0-receipt",
    warning:
      "This is not a real RISC Zero receipt. Real seal generation happens prover-side.",
    image_id: "0xMOCK_TIME_GUEST_IMAGE_ID",
    seal: "0xMOCK_RISC0_SEAL",
    journal,
    signature_hex: bytesToHex(signature),
    public_key_hash: await sha256Hex(keypair.publicKey),
  };
}

/**
 * Verify a receipt: the ML-DSA signature over the journal, that the journal's
 * nonce commits `document` (if provided), and that `atMs` falls inside the
 * attested window. Mirrors what an on-chain verifier would enforce (minus the
 * real seal).
 *
 * @param {Uint8Array|{publicKey: Uint8Array}} publicKeyOrKeypair
 * @param {object} artifact  receipt from {@link proveDocumentTimeWindow}
 * @param {{document?: Uint8Array|string, atMs?: number}} [opts]
 */
export async function verifyDocumentTimeWindow(publicKeyOrKeypair, artifact, opts = {}) {
  const publicKey = publicKeyOrKeypair.publicKey ?? publicKeyOrKeypair;
  const atMs = opts.atMs ?? Date.now();
  const j = artifact.journal;

  const message = enc.encode(canonical(j));
  const sigOk = await mldsa.verify(
    publicKey,
    hexToBytes(artifact.signature_hex),
    message,
  );

  let documentOk = true;
  if (opts.document !== undefined) {
    // The document is the nonce: re-derive and compare.
    documentOk = (await sha256Hex(toBytes(opts.document))) === j.nonce;
  }

  const lower = j.midpoint_unix_ms - j.radius_ms;
  const upper = j.midpoint_unix_ms + j.radius_ms;
  const inWindow = atMs >= lower && atMs <= upper;

  return {
    ok: sigOk && documentOk && inWindow,
    sigOk,
    documentOk,
    inWindow,
    window: [lower, upper],
  };
}

/**
 * Map a receipt into the backend `signed_time::Anchor` shape so it can be
 * persisted alongside a sealed thr34ds event:
 *   Anchor { kind, algorithm, server, proof }
 */
export function toAnchor(artifact) {
  return {
    kind: "roughtime-zk",
    algorithm: artifact.journal.alg,
    server: artifact.journal.source,
    proof: JSON.stringify(artifact),
  };
}

/**
 * Project a receipt into the canonical **Boundless journal** — the single
 * contract shared by the zkVM guest, the on-chain DocumentTimeOracle contract,
 * and `schemas/boundless_journal.schema.json`. This is what gets committed
 * in-zk and decoded on-chain (ABI: bytes32, uint256, uint256). The document
 * hash (Roughtime nonce, or a cut's Merkle root) is 0x-prefixed for Solidity.
 */
export function toBoundlessJournal(artifact) {
  const j = artifact.journal;
  return {
    document_hash: "0x" + j.nonce,
    midpoint_unix_ms: j.midpoint_unix_ms,
    radius_ms: j.radius_ms,
  };
}

/**
 * Structurally validate a Boundless journal against the shared contract before
 * posting (the same invariants the guest and contract enforce). Returns
 * `{ ok, errors }`. Mirrors `schemas/boundless_journal.schema.json`.
 */
export function validateBoundlessJournal(journal) {
  const errors = [];
  if (!/^0x[0-9a-fA-F]{64}$/.test(journal.document_hash ?? "")) {
    errors.push("document_hash must be 0x + 64 hex (bytes32)");
  }
  if (!Number.isInteger(journal.midpoint_unix_ms) || journal.midpoint_unix_ms < 1) {
    errors.push("midpoint_unix_ms must be a positive integer");
  }
  if (!Number.isInteger(journal.radius_ms) || journal.radius_ms < 1) {
    errors.push("radius_ms must be a positive integer");
  }
  return { ok: errors.length === 0, errors };
}
