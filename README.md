# thr34ds

A **thread-based custodial document-retention prover system**.

thr34ds lets you **attest to your own work on anything** — and to **modelled work
by others**. Every document you produce lives in a thread, is sealed onto an
append-only post-quantum-signed timeline, aggregated into a single signed
commitment, and can be anchored to verifiable on-chain time. The result is a
custodial record you can later *prove*: what was written, by (or on behalf of)
whom, and within what time window.

## The two kinds of work it attests to

| | Who | How it's modelled | What's proven |
|---|---|---|---|
| **Your own work** | a **human respondent** (vCard `KIND:individual`) | you author messages/documents in a thread | authorship, integrity, ordering, time |
| **Modelled work by others** | a **summoned agent** (vCard `KIND:application`, `RELATED;TYPE=agent`) | the agent stands in *in lieu of* a human and **models their behavior** | that the work is *modelled* (not authored by the human), who it models, and under what summons |

A *summon* — bringing an agent in in lieu of a human respondent — is a
**legal-grade document**: a self-contained, verifiable record of who summoned
whom, in what matter, for what purpose, and when.

## How retention becomes proof

```
threads  (nest via parent_id)
   └─ each thread owns its own post-quantum signed chain (ML-DSA-65 / FIPS 204)
        every event (document, message, summons) is sealed: {seq, time, payload-hash, prev-hash}+signature
   └─ respondents (vCard 4.0): humans (KIND:individual) + summoned agents (KIND:application)
   └─ messages / documents → attributed to a respondent

all thread chain heads ──Merkle──► one root ──signed──► THE ACTOR (custodian)
                                                  (ML-DSA-65 SignedStateRoot)
   + per-thread inclusion proofs (prove one thread under the signed root)

document hash ──► PQ Roughtime-style time window (oracle.js)
              ──► single Boundless request ──► DocumentTimeOracle.settle()
                  verifies the proof + corroborates the claimed window against
                  block.timestamp  →  on-chain time oracle
```

Each layer is independently verifiable:

- **Integrity / ordering** — per-thread hash chain; any tamper or reorder is detected.
- **Non-repudiation** — every event is signed with a **post-quantum** (ML-DSA-65) key.
- **Custody** — all chains Merklize into one root signed by a single actor (the custodian).
- **Trusted time** — a document's hash is the nonce of an ML-DSA Roughtime-style
  attestation; a single Boundless request settles it on-chain, where the contract
  requires consensus `block.timestamp` to fall inside the claimed window (hybrid time).

## Repository layout

```
thr34ds/
├── thr34ds-core/         # pure-Rust core (no UI), 39 unit tests
│   └── src/
│       ├── signed_time.rs  # PQ (ML-DSA-65) notary: hash-chained signed timeline + Anchor slot
│       ├── merkle.rs       # Merkle aggregation of all chains → one root
│       ├── respondent.rs   # vCard 4.0 respondents: humans + summoned agents
│       ├── summons.rs      # legal-grade summons documents
│       ├── db.rs           # nested threads, per-thread chains, state root, summons certificates
│       └── timesync.rs     # atomic-clock (NTP) sync
├── boundless/            # on-chain time oracle via single Boundless proof requests
│   ├── methods/guest/    # RISC Zero guest (commits document hash + claimed window)
│   ├── contracts/        # DocumentTimeOracle.sol (verify seal + hybrid chain-time check)
│   └── apps/             # single-request host (Boundless built-in USD price oracle)
├── src/                  # web frontend (Tauri) + oracle.js / oracle.html (time-window prover)
└── src-tauri/            # Tauri v2 desktop/mobile shell
```

## Cryptographic choices

| Concern | Mechanism |
|---|---|
| Signatures | **ML-DSA-65** (FIPS 204, post-quantum), pure-Rust `ml-dsa` (cross-compiles to mobile) |
| Hashing / chains | SHA-256, domain-separated Merkle (`0x00` leaf / `0x01` node) |
| Participants | **vCard 4.0** (RFC 6350): `KIND:individual` / `KIND:application` + `RELATED;TYPE=agent` |
| Trusted time | ML-DSA Roughtime-style attestation (document hash = nonce) + on-chain settlement |
| On-chain proof | RISC Zero receipt settled via Boundless; verifier + hybrid `block.timestamp` check |

## Honest scope (prototype)

This is a working prototype with real cryptography, not a certified product:

- The **RISC Zero seal** in `oracle.js` is a mock; the real seal is produced by a
  prover (see `boundless/`). The guest binds document/window, and the ML-DSA
  signature is verified app-side (not in-zk).
- **Legal-grade** summonses have strong non-repudiation, tamper-evidence, an
  immutable audit trail, and a trusted-time hook. True legal admissibility still
  requires binding the actor key to a vetted identity (e.g. an eIDAS qualified
  certificate) and a *qualified* timestamp authority — both have explicit slots
  in the data model.
- The **Tauri shell** is mid-migration to the new core API; the `thr34ds-core`
  crate and the `boundless/` + `oracle.*` prototypes are the verified units.

## Development

```bash
cargo test -p thr34ds-core      # 39 unit tests, no system deps required
```

The document time-window prover runs standalone in a browser:

```bash
# open src/oracle.html  →  Arm oracle · Prove · Verify
```

For the on-chain time oracle, see [`boundless/README.md`](boundless/README.md).
For the Tauri desktop/mobile shell prerequisites, see <https://v2.tauri.app/start/prerequisites/>.

## Data & privacy

Thread, message, respondent, and timeline data live in a local SQLite database on
your device. The post-quantum signing key (the custodian identity) is stored
locally. Only the document **hash** and claimed time window are ever posted to
Boundless / on-chain — never document contents.
