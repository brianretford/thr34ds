/**
 * Posterity status UX — the user must *know*, unambiguously, that a document's
 * posterity has been recorded on-chain (permanently).
 *
 * A document moves through clear states:
 *
 *   idle        → not yet anchored on-chain
 *   attesting   → signing the post-quantum time attestation (ML-DSA-65)
 *   submitting  → posting the single request to Boundless
 *   settling    → awaiting on-chain settlement
 *   recorded    → posterity recorded on-chain, forever  ✓   (the confirmation)
 *   failed      → something went wrong
 *
 * This module is framework-free and reusable: the Tauri app derives a state from
 * a sealed entry's `Anchor` (`stateFromAnchor`) and renders it with `render`;
 * the standalone demo drives the full flow with `runPosterityFlow`.
 */

export const STATE = Object.freeze({
  IDLE: "idle",
  ATTESTING: "attesting",
  SUBMITTING: "submitting",
  SETTLING: "settling",
  RECORDED: "recorded",
  FAILED: "failed",
});

const LABELS = {
  [STATE.IDLE]: "Not yet anchored on-chain",
  [STATE.ATTESTING]: "Signing post-quantum time attestation…",
  [STATE.SUBMITTING]: "Posting to Boundless…",
  [STATE.SETTLING]: "Awaiting on-chain settlement…",
  [STATE.RECORDED]: "Posterity recorded on-chain · forever",
  [STATE.FAILED]: "Could not record on-chain",
};

const BUSY = new Set([STATE.ATTESTING, STATE.SUBMITTING, STATE.SETTLING]);

/** Explorer link for a settlement tx (best-effort by network name). */
export function explorerTxUrl(network, txHash) {
  const bases = {
    "ethereum-sepolia": "https://sepolia.etherscan.io/tx/",
    "ethereum-mainnet": "https://etherscan.io/tx/",
    "base-sepolia": "https://sepolia.basescan.org/tx/",
    base: "https://basescan.org/tx/",
  };
  const base = bases[network];
  return base ? base + txHash : null;
}

/**
 * Derive a posterity UX state from a core `signed_time::Anchor` (or null).
 * A present Boundless anchor means posterity is recorded.
 * @returns {{state: string, data: object}}
 */
export function stateFromAnchor(anchor) {
  if (!anchor) return { state: STATE.IDLE, data: {} };
  let proof = {};
  try {
    proof = typeof anchor.proof === "string" ? JSON.parse(anchor.proof) : anchor.proof || {};
  } catch {
    proof = {};
  }
  return {
    state: STATE.RECORDED,
    data: {
      network: anchor.server,
      txHash: proof.tx_hash,
      requestId: proof.request_id,
      settledAt: proof.settled_at,
      documentHash: proof.document_hash,
    },
  };
}

function short(s, head = 10, tail = 8) {
  if (!s) return "";
  return s.length > head + tail + 1 ? `${s.slice(0, head)}…${s.slice(-tail)}` : s;
}

/**
 * Render the posterity status into `el`.
 * @param {HTMLElement} el
 * @param {string} state
 * @param {object} [data]  { network, txHash, requestId, settledAt, documentHash, error }
 */
export function render(el, state, data = {}) {
  const busy = BUSY.has(state);
  const dot = busy ? '<span class="po-spinner" aria-hidden="true"></span>' : '<span class="po-dot"></span>';

  let detail = "";
  if (state === STATE.RECORDED) {
    const link = data.txHash && explorerTxUrl(data.network, data.txHash);
    const txLine = data.txHash
      ? `<div class="po-row"><span>tx</span>${
          link
            ? `<a href="${link}" target="_blank" rel="noopener">${short(data.txHash)} ↗</a>`
            : `<code>${short(data.txHash)}</code>`
        }</div>`
      : "";
    const when = data.settledAt
      ? `<div class="po-row"><span>settled</span><code>${formatWhen(data.settledAt)}</code></div>`
      : "";
    const net = data.network ? `<div class="po-row"><span>network</span><code>${data.network}</code></div>` : "";
    const doc = data.documentHash
      ? `<div class="po-row"><span>document</span><code>${short(data.documentHash)}</code></div>`
      : "";
    detail = `<div class="po-detail">${net}${txLine}${when}${doc}</div>`;
  } else if (state === STATE.FAILED && data.error) {
    detail = `<div class="po-detail po-err">${data.error}</div>`;
  }

  el.className = `po po-${state}`;
  el.innerHTML = `
    <div class="po-badge">
      ${dot}
      <span class="po-label">${LABELS[state] || state}</span>
      ${state === STATE.RECORDED ? '<span class="po-check">⛓</span>' : ""}
    </div>
    ${detail}
  `;
}

function formatWhen(v) {
  // Accept unix seconds, unix ms, or an ISO string.
  let d;
  if (typeof v === "number") d = new Date(v < 1e12 ? v * 1000 : v);
  else d = new Date(v);
  return isNaN(d.getTime()) ? String(v) : d.toLocaleString();
}

/**
 * Drive the full record-posterity flow, updating `el` at each step. Reusable in
 * the app: pass a `submit` that posts to Boundless and returns
 * `{ txHash, requestId, settledAt }`, and a `persist` that records the anchor
 * (e.g. invoke("record_posterity", …)). Returns the final anchor-like object.
 *
 * @param {HTMLElement} el
 * @param {object} deps
 * @param {() => Promise<object>} deps.attest    produce the receipt (oracle.js)
 * @param {(journal:object) => Promise<{txHash:string,requestId?:string,settledAt?:number}>} deps.submit
 * @param {(result:object) => Promise<void>} [deps.persist]
 * @param {string} [deps.network]
 */
export async function runPosterityFlow(el, deps) {
  const network = deps.network || "ethereum-sepolia";
  try {
    render(el, STATE.ATTESTING);
    const receipt = await deps.attest();

    render(el, STATE.SUBMITTING);
    const { toBoundlessJournal } = await import("./oracle.js");
    const journal = toBoundlessJournal(receipt);

    const settle = await deps.submit(journal);

    render(el, STATE.SETTLING);
    // `submit` may resolve once settled; this state is shown briefly for UX.
    await new Promise((r) => setTimeout(r, 250));

    const data = {
      network,
      txHash: settle.txHash,
      requestId: settle.requestId,
      settledAt: settle.settledAt,
      documentHash: journal.document_hash,
    };
    if (deps.persist) await deps.persist({ journal, settle, network });
    render(el, STATE.RECORDED, data);
    return data;
  } catch (err) {
    render(el, STATE.FAILED, { error: String(err && err.message ? err.message : err) });
    throw err;
  }
}
