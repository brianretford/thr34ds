/**
 * thr34ds frontend
 *
 * Communicates with the Rust backend via Tauri's invoke() IPC bridge.
 * Falls back to a simple in-memory store when running outside of Tauri
 * (e.g. a plain browser for development).
 */

// Posterity status component (pure, no network imports).
import { render as renderPosterity, stateFromAnchor, STATE } from "./posterity.js";

// ── Tauri IPC bridge ────────────────────────────────────────────────────────

/**
 * Call a Tauri backend command.
 * @template T
 * @param {string} cmd
 * @param {Record<string, unknown>} [args]
 * @returns {Promise<T>}
 */
async function invoke(cmd, args = {}) {
  if (window.__TAURI__) {
    return window.__TAURI__.core.invoke(cmd, args);
  }
  // ── Dev fallback: in-memory store ──────────────────────────────────────
  return devInvoke(cmd, args);
}

// ── In-memory dev store ─────────────────────────────────────────────────────

const devStore = { threads: [], messages: [], timeline: {}, summonses: {}, posterity: [], cuts: [] };

function makeId() {
  return crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
}

function nowIso() {
  return new Date().toISOString();
}

function devHash() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Seal a dev timeline entry onto a thread's chain. */
function devSeal(threadId) {
  const list = (devStore.timeline[threadId] ||= []);
  const entry = {
    seq: list.length + 1,
    time: nowIso(),
    time_source: "local (dev)",
    payload_hash: devHash(),
    prev_hash: list.length ? list[list.length - 1].hash : "0".repeat(64),
    hash: devHash(),
    algorithm: "ML-DSA-65",
    public_key: "dev",
    signature: "dev",
    anchor: null,
  };
  list.push(entry);
  return entry;
}

/** Minimal dev-mode fallback so the UI works in a plain browser. */
async function devInvoke(cmd, args) {
  switch (cmd) {
    case "list_threads":
      return [...devStore.threads].sort((a, b) =>
        b.updated_at.localeCompare(a.updated_at)
      );

    case "create_thread": {
      const now = nowIso();
      const t = {
        id: makeId(),
        parent_id: args.input.parent_id ?? null,
        title: args.input.title,
        created_at: now,
        updated_at: now,
      };
      devStore.threads.push(t);
      devSeal(t.id); // genesis: thread.created
      return t;
    }

    case "delete_thread":
      devStore.threads = devStore.threads.filter((t) => t.id !== args.id);
      devStore.messages = devStore.messages.filter((m) => m.thread_id !== args.id);
      return null;

    case "list_messages":
      return devStore.messages
        .filter((m) => m.thread_id === args.thread_id)
        .sort((a, b) => a.created_at.localeCompare(b.created_at));

    case "create_message": {
      const now = nowIso();
      const m = {
        id: makeId(),
        thread_id: args.input.thread_id,
        body: args.input.body,
        created_at: now,
      };
      devStore.messages.push(m);
      const thread = devStore.threads.find((t) => t.id === m.thread_id);
      if (thread) thread.updated_at = now;
      devSeal(m.thread_id); // message.created
      return m;
    }

    case "delete_message":
      devStore.messages = devStore.messages.filter((m) => m.id !== args.id);
      return null;

    case "list_timeline":
      return [...(devStore.timeline[args.thread_id] || [])];

    case "issue_summons": {
      const { thread_id, agent_name, purpose } = args.input;
      const entry = devSeal(thread_id); // summons.issued (payload = the document)
      const s = {
        id: makeId(),
        issued_at: nowIso(),
        matter_thread_id: thread_id,
        matter_title: "",
        issuer_key: "dev",
        issuer_name: null,
        agent_uid: makeId(),
        agent_name,
        in_lieu_of_uid: args.input.in_lieu_of_uid ?? null,
        in_lieu_of_name: null,
        purpose: purpose ?? "",
        jurisdiction: args.input.jurisdiction ?? null,
      };
      (devStore.summonses[thread_id] ||= []).push(s);
      return s;
    }

    case "list_summonses":
      return [...(devStore.summonses[args.thread_id] || [])];

    case "record_posterity": {
      const { thread_id, document_hash, anchor } = args.input;
      let p = devStore.posterity.find(
        (x) => x.thread_id === thread_id && x.document_hash === document_hash
      );
      if (!p) {
        const list = devStore.timeline[thread_id] || [];
        const target = list.find((e) => e.payload_hash === document_hash);
        if (target) target.anchor = anchor; // bind the receipt onto the document
        const entry = devSeal(thread_id); // posterity (receipt of the receipt)
        p = {
          thread_id,
          document_hash,
          anchor,
          seq: entry.seq,
          entry_hash: entry.hash,
          recorded_at: nowIso(),
        };
        devStore.posterity.push(p);
      }
      return p;
    }

    case "get_posterity":
      return (
        devStore.posterity.find(
          (x) => x.thread_id === args.thread_id && x.document_hash === args.document_hash
        ) || null
      );

    case "settle_posterity": {
      // Browser demo: simulate a single Boundless request + settlement.
      const { thread_id, document_hash } = args.input;
      await new Promise((r) => setTimeout(r, 900));
      const proof = JSON.stringify({
        status: "settled",
        network: "ethereum-sepolia (demo)",
        document_hash: "0x" + document_hash,
        request_id: "0x" + Math.random().toString(16).slice(2, 10),
        tx_hash:
          "0x" +
          Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
        settled_at: Math.floor(Date.now() / 1000),
      });
      const anchor = {
        kind: "boundless",
        algorithm: "risc0",
        server: "ethereum-sepolia (demo)",
        proof,
      };
      return devInvoke("record_posterity", {
        input: { thread_id, document_hash, anchor },
      });
    }

    case "record_cut": {
      const cut = {
        id: makeId(),
        state_root: {
          root: devHash(),
          leaf_count: devStore.threads.length,
          time: nowIso(),
          algorithm: "ML-DSA-65",
          public_key: "dev",
          signature: "dev",
        },
        posterities: devStore.posterity.map((p) => ({ ...p })),
        anchor: null,
        recorded_at: nowIso(),
      };
      devStore.cuts.push(cut);
      return cut;
    }

    case "list_cuts":
      return [...devStore.cuts].reverse();

    case "get_synced_time":
      return {
        utc_now: new Date().toISOString(),
        offset_ms: 0,
        server: "dev-fallback (no NTP in browser)",
      };

    default:
      throw new Error(`Unknown dev command: ${cmd}`);
  }
}

// ── App state ───────────────────────────────────────────────────────────────

let currentThreadId = null;

// ── DOM refs ────────────────────────────────────────────────────────────────

const threadList      = document.getElementById("thread-list");
const emptyState      = document.getElementById("empty-state");
const threadView      = document.getElementById("thread-view");
const threadTitleEl   = document.getElementById("thread-title");
const messageListEl   = document.getElementById("message-list");
const messageInput    = document.getElementById("message-input");
const messageForm     = document.getElementById("message-form");
const newThreadBtn    = document.getElementById("new-thread-btn");
const newThreadForm   = document.getElementById("new-thread-form");
const newThreadTitle  = document.getElementById("new-thread-title");
const newThreadSubmit = document.getElementById("new-thread-submit");
const newThreadCancel = document.getElementById("new-thread-cancel");
const deleteThreadBtn = document.getElementById("delete-thread-btn");
const syncTimeBtn     = document.getElementById("sync-time-btn");
const syncStatus      = document.getElementById("sync-status");
const overlayClock      = document.getElementById("overlay-clock");
const overlayThreadList = document.getElementById("overlay-thread-list");
const documentList      = document.getElementById("document-list");
const issueSummonsBtn   = document.getElementById("issue-summons-btn");
const takeCutBtn        = document.getElementById("take-cut-btn");
const showCutsBtn       = document.getElementById("show-cuts-btn");
const cutsModal         = document.getElementById("cuts-modal");
const cutsList          = document.getElementById("cuts-list");
const closeCuts         = document.getElementById("close-cuts");

// ── Thread list ──────────────────────────────────────────────────────────────

async function loadThreads() {
  const threads = await invoke("list_threads");
  threadList.innerHTML = "";
  for (const t of threads) {
    const li = document.createElement("li");
    if (t.id === currentThreadId) li.classList.add("active");

    const nameSpan = document.createElement("span");
    nameSpan.className = "thread-name";
    nameSpan.textContent = t.title;
    nameSpan.addEventListener("click", () => selectThread(t.id, t.title));

    const delBtn = document.createElement("button");
    delBtn.className = "thread-delete";
    delBtn.textContent = "✕";
    delBtn.title = "Delete thread";
    delBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteThread(t.id);
    });

    li.appendChild(nameSpan);
    li.appendChild(delBtn);
    threadList.appendChild(li);
  }
  refreshOverlayThreads(threads);
}

// ── Select / open a thread ───────────────────────────────────────────────────

async function selectThread(id, title) {
  currentThreadId = id;
  threadTitleEl.textContent = title;
  emptyState.classList.add("hidden");
  threadView.classList.remove("hidden");
  await loadMessages();
  await loadDocuments();
  await loadThreads(); // refresh sidebar to highlight active
}

// ── Documents & posterity ─────────────────────────────────────────────────────

/** Load the thread's signed timeline and render each attested document. */
async function loadDocuments() {
  const entries = await invoke("list_timeline", { thread_id: currentThreadId });
  documentList.innerHTML = "";
  for (const entry of entries) renderDocument(entry);
}

/** Render one attested document (a sealed timeline entry) with its posterity badge. */
function renderDocument(entry) {
  const li = document.createElement("li");
  li.className = "document";

  const head = document.createElement("div");
  head.className = "document-head";
  head.innerHTML =
    `<span class="doc-seq">#${entry.seq}</span>` +
    `<code class="doc-hash" title="${entry.payload_hash}">${entry.payload_hash.slice(0, 16)}…</code>` +
    `<span class="doc-time">${formatDate(entry.time)}</span>`;

  const badge = document.createElement("div");
  const { state, data } = stateFromAnchor(entry.anchor);
  renderPosterity(badge, state, data);

  // If not yet on-chain, offer to record its posterity.
  if (state === STATE.IDLE) {
    const btn = document.createElement("button");
    btn.className = "mini record-btn";
    btn.textContent = "Record posterity on-chain";
    btn.addEventListener("click", () => recordOnChain(entry.payload_hash, badge, btn));
    head.appendChild(btn);
  }

  li.appendChild(head);
  li.appendChild(badge);
  documentList.appendChild(li);
}

const randHex = (n) =>
  Array.from(crypto.getRandomValues(new Uint8Array(n)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

/**
 * Record a document's posterity on-chain via a single Boundless request. The
 * backend (settle_posterity) posts the request, awaits settlement, and records
 * the posterity from the real result — so the green "recorded forever" state is
 * backed by an actual on-chain proof. (In a plain browser the dev fallback
 * simulates settlement.)
 */
async function recordOnChain(documentHash, badge, btn) {
  if (btn) btn.remove();
  renderPosterity(badge, STATE.SUBMITTING);
  await sleep(150);
  renderPosterity(badge, STATE.SETTLING);
  try {
    const posterity = await invoke("settle_posterity", {
      input: { thread_id: currentThreadId, document_hash: documentHash },
    });
    const { state, data } = stateFromAnchor(posterity.anchor);
    renderPosterity(badge, state, data);
  } catch (err) {
    renderPosterity(badge, STATE.FAILED, { error: String(err) });
  }
}

issueSummonsBtn.addEventListener("click", async () => {
  if (!currentThreadId) return;
  const agentName = prompt("Summon an agent named:", "Roe (agent)");
  if (!agentName) return;
  const purpose = prompt("Purpose / mandate:", "Respond to interrogatories.") || "";
  await invoke("issue_summons", {
    input: { thread_id: currentThreadId, agent_name: agentName, purpose },
  });
  await loadDocuments();
});

// ── Clean cuts (with attached posterities) ────────────────────────────────────

takeCutBtn.addEventListener("click", async () => {
  await invoke("record_cut");
  await openCuts();
});

showCutsBtn.addEventListener("click", openCuts);
closeCuts.addEventListener("click", () => cutsModal.classList.add("hidden"));
cutsModal.addEventListener("click", (e) => {
  if (e.target === cutsModal) cutsModal.classList.add("hidden");
});

async function openCuts() {
  cutsModal.classList.remove("hidden");
  const cuts = await invoke("list_cuts");
  cutsList.innerHTML = "";
  if (!cuts.length) {
    cutsList.innerHTML = `<li class="cut-empty">No cuts yet — take one to checkpoint every thread.</li>`;
    return;
  }
  for (const cut of cuts) renderCut(cut);
}

/** Render one cut and the posterities attached to it. */
function renderCut(cut) {
  const li = document.createElement("li");
  li.className = "cut";

  const head = document.createElement("div");
  head.className = "cut-head";
  head.innerHTML =
    `<code class="cut-root" title="${cut.state_root.root}">root ${cut.state_root.root.slice(0, 16)}…</code>` +
    `<span class="cut-meta">${cut.state_root.leaf_count} threads · ${cut.state_root.algorithm}</span>` +
    `<span class="doc-time">${formatDate(cut.recorded_at)}</span>`;
  li.appendChild(head);

  const posterities = cut.posterities || [];
  const sub = document.createElement("div");
  sub.className = "cut-posterities";
  if (!posterities.length) {
    sub.innerHTML = `<span class="cut-empty">references no posterities yet</span>`;
  } else {
    const label = document.createElement("div");
    label.className = "cut-pcount";
    label.textContent = `attached posterities (${posterities.length}):`;
    sub.appendChild(label);
    for (const p of posterities) {
      const row = document.createElement("div");
      row.className = "cut-posterity";
      const tag = document.createElement("code");
      tag.className = "doc-hash";
      tag.title = p.document_hash;
      tag.textContent = p.document_hash.slice(0, 14) + "…";
      const badge = document.createElement("div");
      const { state, data } = stateFromAnchor(p.anchor);
      renderPosterity(badge, state, data);
      row.appendChild(tag);
      row.appendChild(badge);
      sub.appendChild(row);
    }
  }
  li.appendChild(sub);
  cutsList.appendChild(li);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Create thread ────────────────────────────────────────────────────────────

newThreadBtn.addEventListener("click", () => {
  newThreadForm.classList.toggle("hidden");
  if (!newThreadForm.classList.contains("hidden")) newThreadTitle.focus();
});

newThreadCancel.addEventListener("click", () => {
  newThreadForm.classList.add("hidden");
  newThreadTitle.value = "";
});

newThreadSubmit.addEventListener("click", async () => {
  const title = newThreadTitle.value.trim();
  if (!title) return;
  const t = await invoke("create_thread", { input: { title } });
  newThreadTitle.value = "";
  newThreadForm.classList.add("hidden");
  await loadThreads();
  await selectThread(t.id, t.title);
});

newThreadTitle.addEventListener("keydown", (e) => {
  if (e.key === "Enter") newThreadSubmit.click();
  if (e.key === "Escape") newThreadCancel.click();
});

// ── Delete thread ────────────────────────────────────────────────────────────

async function deleteThread(id) {
  await invoke("delete_thread", { id });
  if (currentThreadId === id) {
    currentThreadId = null;
    threadView.classList.add("hidden");
    emptyState.classList.remove("hidden");
  }
  await loadThreads();
}

deleteThreadBtn.addEventListener("click", () => {
  if (currentThreadId) deleteThread(currentThreadId);
});

// ── Messages ─────────────────────────────────────────────────────────────────

async function loadMessages() {
  const msgs = await invoke("list_messages", { thread_id: currentThreadId });
  messageListEl.innerHTML = "";
  for (const m of msgs) renderMessage(m);
  messageListEl.scrollTop = messageListEl.scrollHeight;
}

function renderMessage(msg) {
  const div = document.createElement("div");
  div.className = "message-bubble";
  div.dataset.id = msg.id;

  const body = document.createElement("p");
  body.className = "message-body";
  body.textContent = msg.body;

  const meta = document.createElement("div");
  meta.className = "message-meta";

  const ts = document.createElement("span");
  ts.textContent = formatDate(msg.created_at);

  const delBtn = document.createElement("button");
  delBtn.className = "message-delete";
  delBtn.textContent = "delete";
  delBtn.addEventListener("click", async () => {
    await invoke("delete_message", { id: msg.id });
    div.remove();
  });

  meta.appendChild(ts);
  meta.appendChild(delBtn);
  div.appendChild(body);
  div.appendChild(meta);
  messageListEl.appendChild(div);
}

messageForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = messageInput.value.trim();
  if (!body || !currentThreadId) return;
  messageInput.value = "";
  const msg = await invoke("create_message", {
    input: { thread_id: currentThreadId, body },
  });
  renderMessage(msg);
  messageListEl.scrollTop = messageListEl.scrollHeight;
  await loadThreads(); // update thread order in sidebar
});

messageInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    messageForm.dispatchEvent(new Event("submit"));
  }
});

// ── Atomic-clock time sync ───────────────────────────────────────────────────

syncTimeBtn.addEventListener("click", async () => {
  syncStatus.textContent = "Syncing…";
  try {
    const result = await invoke("get_synced_time");
    const offset = result.offset_ms;
    const sign   = offset >= 0 ? "+" : "";
    syncStatus.textContent = `${formatDate(result.utc_now)} (${sign}${offset}ms via ${result.server})`;
  } catch (err) {
    syncStatus.textContent = `Sync failed: ${err}`;
  }
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(isoStr) {
  try {
    return new Date(isoStr).toLocaleString();
  } catch {
    return isoStr;
  }
}

// ── Overlay: live clock + thread list ───────────────────────────────────────

/** Update the overlay clock display with the current local time. */
function tickClock() {
  overlayClock.textContent = new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

tickClock();
setInterval(tickClock, 1000);

/** Rebuild the overlay thread list. Called whenever threads change. */
function refreshOverlayThreads(threads) {
  overlayThreadList.innerHTML = "";
  if (!threads.length) {
    const li = document.createElement("li");
    li.className = "overlay-empty";
    li.textContent = "No threads yet";
    overlayThreadList.appendChild(li);
    return;
  }
  for (const t of threads) {
    const li = document.createElement("li");
    li.textContent = t.title;
    li.title = t.title;
    if (t.id === currentThreadId) li.classList.add("active");
    li.addEventListener("click", () => selectThread(t.id, t.title));
    overlayThreadList.appendChild(li);
  }
}

// ── Boot ─────────────────────────────────────────────────────────────────────

loadThreads();
