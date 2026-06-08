# thr34ds · on-chain time oracle (Boundless)

Synthesise an **on-chain time oracle** from **single Boundless proof requests** —
one request per document. Everything else (threads, summonses, the document hash
itself) lives in the thr34ds app; this directory is *only* the Boundless
round-trip.

## How it works (hybrid time)

```
app: document  ──sha256──►  documentHash   (the Roughtime nonce)
oracle.js:      claimed window { midpoint, radius }   (ML-DSA-signed, kept app-side)
        │
        ▼  one single Boundless request, input = abi(documentHash, midpoint, radius)
   guest: commits (documentHash, midpoint, radius) to the journal
        │  prover fulfils → seal
        ▼
   DocumentTimeOracle.settle(seal, documentHash, midpoint, radius):
     • verifier.verify(seal, imageId, sha256(journal))     ← proof is valid
     • require block.timestamp ∈ [midpoint−radius, midpoint+radius]  ← consensus
       corroborates the claimed window  (the HYBRID check)
     • store documentHash → { midpoint, radius, settledAt = block.timestamp }
```

The claimed window comes from the off-chain ML-DSA Roughtime attestation; the
chain’s `block.timestamp` corroborates it at settlement. Neither alone is
trusted — the contract requires both to agree.

> The ML-DSA signature is verified **in the app**, not in-zk. The proof binds the
> document hash to a claimed window and yields one on-chain-settleable receipt.

## Files in this directory

| File | Drop into | Purpose |
|------|-----------|---------|
| `methods/guest/src/main.rs` | `methods/guest/src/main.rs` | the time-oracle guest |
| `contracts/DocumentTimeOracle.sol` | `contracts/src/DocumentTimeOracle.sol` | consumer contract |
| `apps/src/main.rs` | `apps/src/main.rs` | single-request host |

These are written against the **Boundless foundry template** API so versions are
inherited from upstream and don’t rot.

## Setup

1. Install RISC Zero + Boundless tooling:
   ```sh
   curl -L https://risczero.com/install | bash && rzup install
   ```

2. Scaffold the template (gives you the workspace, Cargo pins, remappings):
   ```sh
   forge init thr34ds-boundless --template boundless-xyz/boundless-foundry-template
   cd thr34ds-boundless
   ```

3. Replace the three files with the ones here. Name the guest package
   `time-oracle` so `risc0-build` emits `TIME_ORACLE_ELF` / `TIME_ORACLE_ID`
   (re-exported by the `guests` crate the host imports).

4. Point the consumer contract at the real verifier. `contracts/src` already
   remaps `risc0/` → the RISC Zero ethereum contracts; deploy
   `DocumentTimeOracle` with `(verifier, TIME_ORACLE_ID)`.

## Environment

```sh
export RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
export PRIVATE_KEY="0x…"                       # funded requestor key
export PINATA_JWT="…"                           # optional: auto-upload guest to IPFS
export DOCUMENT_TIME_ORACLE_ADDRESS="0x…"       # deployed DocumentTimeOracle
```

## Build & deploy

```sh
cargo build                # builds guest + host; prints TIME_ORACLE_ID
forge build
# deploy DocumentTimeOracle(verifier, TIME_ORACLE_ID) with your preferred script
```

## Timestamp one document (a single request)

```sh
RUST_LOG=info cargo run --bin app -- \
  --document-hash 0x<summons.content_hash() / oracle.js nonce> \
  --midpoint-ms   <unix-ms from the attestation> \
  --radius-ms     10000
# (omit --program-url to auto-upload the embedded guest via PINATA_JWT,
#  or pass --program-url <ipfs/s3 url> if you uploaded it yourself)
```

The host submits **one** request, waits for a prover to fulfil it, then calls
`DocumentTimeOracle.settle(...)`. Offer pricing uses the client’s default offer
layer, which converts a USD price to token via Boundless’s **built-in price
oracle** at request time.

## App integration

The thr34ds core already produces the document hash:

- `Summons::content_hash()` (legal-grade summons) or any sealed event’s
  `payload_hash`, **or**
- the `oracle.js` nonce = `sha256(document)`.

Feed that as `--document-hash`, and the attestation’s midpoint as `--midpoint-ms`.
After settlement, store the returned tx hash / `request_id` in the core
`signed_time::Anchor` (`kind = "boundless"`) so the app’s signed timeline records
its on-chain time anchor.
