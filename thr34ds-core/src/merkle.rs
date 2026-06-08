//! Binary Merkle tree used to aggregate every thread's chain head into a single
//! commitment. The root is signed by the one app actor (see
//! [`crate::db::Database::state_root`]), so all per-thread chains roll up to a
//! single post-quantum-signed root while each thread stays independently
//! provable via a compact inclusion proof.
//!
//! Hashing is domain-separated (`0x00` for leaves, `0x01` for internal nodes) to
//! prevent leaf/node second-preimage confusion. Odd levels duplicate the final
//! node. Inclusion proofs carry the sibling's side explicitly, so verification
//! needs nothing but the leaf, the proof, and the root.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One step of a Merkle inclusion proof: a sibling hash (hex) and which side it
/// sits on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleStep {
    /// Hex-encoded sibling node hash.
    pub hash: String,
    /// `true` if the sibling is the right child (so the running hash is left).
    pub sibling_on_right: bool,
}

/// Leaf hash: `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// Internal node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of an empty tree: `SHA-256("")`.
pub fn empty_root() -> [u8; 32] {
    Sha256::digest([]).into()
}

/// A built Merkle tree, retaining every level so inclusion proofs can be
/// generated cheaply.
pub struct MerkleTree {
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a tree over `leaves` (raw leaf preimages; they are leaf-hashed
    /// internally).
    pub fn from_leaves(leaves: &[Vec<u8>]) -> Self {
        if leaves.is_empty() {
            return Self {
                levels: vec![vec![empty_root()]],
            };
        }
        let base: Vec<[u8; 32]> = leaves.iter().map(|l| leaf_hash(l)).collect();
        let mut levels = vec![base];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                let right = if i + 1 < cur.len() { cur[i + 1] } else { cur[i] };
                next.push(node_hash(&left, &right));
                i += 2;
            }
            levels.push(next);
        }
        Self { levels }
    }

    /// The Merkle root.
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }

    /// An inclusion proof for the leaf at `index`.
    pub fn proof(&self, mut index: usize) -> Vec<MerkleStep> {
        let mut steps = Vec::new();
        for level in &self.levels[..self.levels.len() - 1] {
            let is_right = index % 2 == 1;
            let sib_idx = if is_right { index - 1 } else { index + 1 };
            let sib = if sib_idx < level.len() {
                level[sib_idx]
            } else {
                level[index] // duplicated final node
            };
            steps.push(MerkleStep {
                hash: hex::encode(sib),
                sibling_on_right: !is_right,
            });
            index /= 2;
        }
        steps
    }
}

/// Verify that `leaf` is included under `root` via `proof`.
pub fn verify_proof(leaf: &[u8], proof: &[MerkleStep], root: &[u8; 32]) -> bool {
    let mut h = leaf_hash(leaf);
    for step in proof {
        let Ok(bytes) = hex::decode(&step.hash) else {
            return false;
        };
        let Ok(sib): std::result::Result<[u8; 32], _> = bytes.try_into() else {
            return false;
        };
        h = if step.sibling_on_right {
            node_hash(&h, &sib)
        } else {
            node_hash(&sib, &h)
        };
    }
    &h == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect()
    }

    #[test]
    fn single_leaf_root_is_its_leaf_hash() {
        let l = leaves(1);
        let tree = MerkleTree::from_leaves(&l);
        assert_eq!(tree.root(), leaf_hash(b"leaf-0"));
    }

    #[test]
    fn two_leaves_root_matches_manual() {
        let l = leaves(2);
        let tree = MerkleTree::from_leaves(&l);
        let expected = node_hash(&leaf_hash(b"leaf-0"), &leaf_hash(b"leaf-1"));
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn proofs_verify_for_every_leaf() {
        for n in 1..=17 {
            let l = leaves(n);
            let tree = MerkleTree::from_leaves(&l);
            let root = tree.root();
            for (i, leaf) in l.iter().enumerate() {
                let proof = tree.proof(i);
                assert!(verify_proof(leaf, &proof, &root), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn wrong_leaf_fails_verification() {
        let l = leaves(5);
        let tree = MerkleTree::from_leaves(&l);
        let root = tree.root();
        let proof = tree.proof(2);
        assert!(!verify_proof(b"not-a-leaf", &proof, &root));
    }

    #[test]
    fn changing_any_leaf_changes_the_root() {
        let mut l = leaves(4);
        let r1 = MerkleTree::from_leaves(&l).root();
        l[2] = b"tampered".to_vec();
        let r2 = MerkleTree::from_leaves(&l).root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn empty_tree_has_empty_root() {
        let tree = MerkleTree::from_leaves(&[]);
        assert_eq!(tree.root(), empty_root());
    }
}
