// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IRiscZeroVerifier} from "risc0/IRiscZeroVerifier.sol";

/// @title DocumentTimeOracle
/// @notice On-chain time oracle synthesised from single Boundless proof requests.
///
/// Each settlement verifies a RISC Zero receipt whose journal is
/// `(bytes32 documentHash, uint256 midpointMs, uint256 radiusMs)` — the claimed
/// time window for a document — and corroborates it against consensus time by
/// requiring `block.timestamp` to fall inside the claimed window (the hybrid
/// design). The document hash is the Roughtime nonce produced by the app.
contract DocumentTimeOracle {
    /// @notice The RISC Zero verifier contract.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Image ID of the time-oracle guest this contract accepts.
    bytes32 public immutable imageId;

    struct Attestation {
        uint256 midpointMs; // claimed window midpoint (unix ms)
        uint256 radiusMs; // claimed window radius (ms)
        uint256 settledAt; // block.timestamp (seconds) when settled on-chain
        bool exists;
    }

    /// @notice documentHash => its on-chain time attestation.
    mapping(bytes32 => Attestation) public attestations;

    event DocumentTimestamped(
        bytes32 indexed documentHash,
        uint256 midpointMs,
        uint256 radiusMs,
        uint256 settledAt
    );

    constructor(IRiscZeroVerifier _verifier, bytes32 _imageId) {
        verifier = _verifier;
        imageId = _imageId;
    }

    /// @notice Settle a document's time window on-chain.
    /// @param seal         The Boundless/RISC Zero proof seal.
    /// @param documentHash The document's hash (Roughtime nonce).
    /// @param midpointMs   Claimed window midpoint (unix ms).
    /// @param radiusMs     Claimed window radius (ms).
    function settle(
        bytes calldata seal,
        bytes32 documentHash,
        uint256 midpointMs,
        uint256 radiusMs
    ) external {
        // On-chain validation of the shared journal contract — the same
        // invariants asserted by the zkVM guest and declared in
        // schemas/boundless_journal.schema.json (required + positive).
        require(documentHash != bytes32(0), "documentHash required");
        require(midpointMs > 0, "midpointMs must be positive");
        require(radiusMs > 0, "radiusMs must be positive");

        // Reconstruct the journal the guest committed and verify the proof.
        bytes memory journal = abi.encode(documentHash, midpointMs, radiusMs);
        verifier.verify(seal, imageId, sha256(journal));

        // Hybrid corroboration: consensus time must fall in the claimed window.
        uint256 nowMs = block.timestamp * 1000;
        require(
            midpointMs <= nowMs + radiusMs && nowMs <= midpointMs + radiusMs,
            "chain time outside claimed window"
        );

        attestations[documentHash] = Attestation({
            midpointMs: midpointMs,
            radiusMs: radiusMs,
            settledAt: block.timestamp,
            exists: true
        });

        emit DocumentTimestamped(documentHash, midpointMs, radiusMs, block.timestamp);
    }

    /// @notice Whether a document was timestamped, and its settlement time (s).
    function settledAt(bytes32 documentHash) external view returns (bool, uint256) {
        Attestation storage a = attestations[documentHash];
        return (a.exists, a.settledAt);
    }
}
