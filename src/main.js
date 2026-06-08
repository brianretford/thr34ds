/**
 * thr34ds frontend
 *
 * Communicates with the Rust backend via Tauri's invoke() IPC bridge.
 * Falls back to a simple in-memory store when running outside of Tauri
 * (e.g. a plain browser for development).
 */

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

const devStore = { threads: [], messages: [] };

function makeId() {
  return crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
}

function nowIso() {
  return new Date().toISOString();
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
      const t = { id: makeId(), title: args.input.title, created_at: now, updated_at: now };
      devStore.threads.push(t);
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
      return m;
    }

    case "delete_message":
      devStore.messages = devStore.messages.filter((m) => m.id !== args.id);
      return null;

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
  await loadThreads(); // refresh sidebar to highlight active
}

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
