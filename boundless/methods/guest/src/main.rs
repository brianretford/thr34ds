// Guest: document time-window oracle.
//
// Reads an ABI-encoded request `(bytes32 documentHash, uint256 midpointMs,
// uint256 radiusMs)` and commits the same triple to the journal so the on-chain
// consumer can decode it. The document hash is the Roughtime nonce produced by
// the app (`oracle.js` / `summons.content_hash()`); the claimed window is
// `[midpoint - radius, midpoint + radius]`.
//
// Per the hybrid design we do NOT verify the ML-DSA signature in-zk (the app
// holds the signed attestation). The proof's job is to bind the document hash
// to a claimed window and produce a single on-chain-settleable receipt; the
// consumer contract corroborates the claim against `block.timestamp`.
use alloy_primitives::{FixedBytes, U256};
use alloy_sol_types::SolValue;
use risc0_zkvm::guest::env;

fn main() {
    // Input is one ABI-encoded frame written by the host via `with_stdin`.
    let input: Vec<u8> = env::read_frame();
    let (document_hash, midpoint_ms, radius_ms) =
        <(FixedBytes<32>, U256, U256)>::abi_decode(&input, true)
            .expect("malformed time-oracle request");

    // Enforce the shared journal contract in-zk — the same invariants declared
    // in schemas/boundless_journal.schema.json and re-checked on-chain by
    // DocumentTimeOracle.settle(). The proof attests these held.
    assert!(radius_ms > U256::ZERO, "radius must be positive");
    assert!(midpoint_ms > U256::ZERO, "midpoint must be set");

    // Commit the triple for on-chain decoding.
    let journal = (document_hash, midpoint_ms, radius_ms).abi_encode();
    env::commit_slice(&journal);
}
