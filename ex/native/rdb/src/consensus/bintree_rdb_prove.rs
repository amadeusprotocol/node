use rust_rocksdb::{DBRawIteratorWithThreadMode, MultiThreaded, TransactionDB};
use std::cmp::{min, Ordering};
use std::convert::TryInto;

use crate::consensus::bintree::{
    compute_namespace_path, get_bit_be, lcp_be, leaf_hash, mask_after_be, prefix_match_be, set_bit_be, Hash, NodeKey, Path, Proof, ProofNode, ZERO_HASH,
};

// ============================================================================
// ROCKSDB SERIALIZATION HELPERS
// ============================================================================

#[inline]
fn serialize_key(key: &NodeKey) -> Vec<u8> {
    let mut v = Vec::with_capacity(34);
    v.extend_from_slice(&key.path);
    v.extend_from_slice(&key.len.to_be_bytes());
    v
}

#[inline]
fn deserialize_key(data: &[u8]) -> NodeKey {
    let mut path = [0u8; 32];
    path.copy_from_slice(&data[0..32]);
    let len = u16::from_be_bytes([data[32], data[33]]);
    NodeKey { path, len }
}

// ============================================================================
// PROVER MODULE
// ============================================================================

pub type Iter<'a> = DBRawIteratorWithThreadMode<'a, TransactionDB<MultiThreaded>>;

pub struct RocksHubtProveViaIterator;

impl RocksHubtProveViaIterator {
    pub fn prove(iter: &mut Iter, ns: Option<Vec<u8>>, k: &[u8]) -> Proof {
        let target_path = compute_namespace_path(ns.as_deref(), k);
        let root_hash = Self::get_root(iter);

        let (found_key, found_hash) = match Self::find_longest_prefix_node(iter, &target_path) {
            Some((key, hash)) => (key, hash),
            None => {
                return Proof { root: ZERO_HASH, nodes: vec![], path: ZERO_HASH, hash: ZERO_HASH };
            }
        };

        Proof { root: root_hash, nodes: Self::generate_proof_nodes(iter, found_key.path, found_key.len), path: found_key.path, hash: found_hash }
    }

    // ========================================================================
    // INTERNAL LOGIC (Using Iter)
    // ========================================================================
    fn get_root(iter: &mut Iter) -> Hash {
        // Logic: The root is usually the first key in the DB if normalized.
        // However, technically we should find LCP of First and Last.
        // For the prover, simple seek_to_first is usually sufficient
        // if we assume the tree is not empty.
        iter.seek_to_first();
        if iter.valid() {
            // Check if this is actually the root (len should be small)
            // But strict root calculation requires finding range.
            // We use the first key's value as a fallback,
            // but effectively verification will fail if this is wrong.
            // A more robust implementation matches Hubt2::root().

            let first_key = deserialize_key(iter.key().unwrap());
            iter.seek_to_last();
            if !iter.valid() {
                return ZERO_HASH;
            } // Should be valid if first was
            let last_key = deserialize_key(iter.key().unwrap());

            let (lcp_path, len) = lcp_be(&first_key.path, &last_key.path);
            let root_key = NodeKey { path: lcp_path, len };

            // Get the actual root hash
            if let Some(h) = Self::get_exact(iter, &root_key) {
                return h;
            }
        }
        ZERO_HASH
    }

    fn find_longest_prefix_node(iter: &mut Iter, target: &Path) -> Option<(NodeKey, Hash)> {
        // We want to find the node closest to target.
        // Hubt2 checks `leaves.get(target)` first.
        // Then checks `prev` and `next`.

        let target_key_leaf = NodeKey { path: *target, len: 256 };

        // 1. Exact Match Check
        if let Some(h) = Self::get_exact(iter, &target_key_leaf) {
            return Some((target_key_leaf, h));
        }

        // 2. Range Check (Prev and Next)
        let prev = Self::seek_prev(iter, &target_key_leaf);
        let next = Self::seek_next(iter, &target_key_leaf);

        match (prev, next) {
            (None, None) => None,
            (None, Some((k, h))) => Some((k, h)),
            (Some((k, h)), None) => Some((k, h)),
            (Some((pk, ph)), Some((nk, nh))) => {
                let (_, rp) = lcp_be(target, &pk.path);
                let (_, rn) = lcp_be(target, &nk.path);

                // Hubt2 logic: comparison of LCP lengths
                if rp >= rn {
                    Some((pk, ph))
                } else {
                    Some((nk, nh))
                }
            }
        }
    }

    fn generate_proof_nodes(iter: &mut Iter, path: Path, len: u16) -> Vec<ProofNode> {
        let mut ancestors = Vec::new();
        let mut cursor = NodeKey { path, len: 256 };

        loop {
            match Self::seek_prev(iter, &cursor) {
                None => break,
                Some((k, _)) => {
                    let is_same = k == cursor;
                    if prefix_match_be(&path, &k.path, k.len) {
                        if k.len < len {
                            ancestors.push(k);
                        }
                        cursor = k;
                    } else {
                        let (lcp_p, lcp_l) = lcp_be(&path, &k.path);
                        let jump = NodeKey { path: lcp_p, len: lcp_l + 1 };
                        cursor = if jump < k { jump } else { k };
                    }
                }
            }
        }

        if !ancestors.iter().any(|k| k.len == 0) {
            let root_key = NodeKey { path: ZERO_HASH, len: 0 };
            if Self::get_exact(iter, &root_key).is_some() {
                ancestors.push(root_key);
            }
        }

        ancestors.sort_unstable_by(|a, b| b.len.cmp(&a.len));

        let mut nodes = Vec::new();
        for anc in ancestors {
            let my_dir = get_bit_be(&path, anc.len);
            let sibling_dir = 1 - my_dir;

            let s_hash = Self::get_child_hash(iter, anc.path, anc.len, sibling_dir);
            nodes.push(ProofNode { hash: s_hash, direction: sibling_dir, len: anc.len });
        }
        nodes
    }

    fn get_child_hash(iter: &mut Iter, p_path: Path, p_len: u16, dir: u8) -> Hash {
        let mut target_path = p_path;
        set_bit_be(&mut target_path, p_len, dir);
        mask_after_be(&mut target_path, p_len + 1);

        let target_key = NodeKey { path: target_path, len: p_len + 1 };

        // Seek >= target_key
        if let Some((f_key, hash)) = Self::seek_next_inclusive(iter, &target_key) {
            // Verify it is actually a child (check prefix match)
            if prefix_match_be(&f_key.path, &target_path, p_len + 1) {
                return hash;
            }
        }
        ZERO_HASH
    }

    // ========================================================================
    // ITERATOR WRAPPERS (Using Iter)
    // ========================================================================

    fn get_exact(iter: &mut Iter, key: &NodeKey) -> Option<Hash> {
        let k_bytes = serialize_key(key);
        iter.seek(&k_bytes);
        if iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());
            if found_k == *key {
                return Some(iter.value().unwrap().try_into().unwrap());
            }
        }
        None
    }

    /// Equivalent to range(..key).next_back()
    /// Finds the largest key strictly less than `key`
    fn seek_prev(iter: &mut Iter, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        let k_bytes = serialize_key(key);
        iter.seek_for_prev(&k_bytes);

        if iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());

            // seek_for_prev lands on Key if it exists.
            // We want strictly LESS than key.
            if found_k == *key {
                iter.prev();
            }
        }

        if iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());
            let found_v: Hash = iter.value().unwrap().try_into().unwrap();
            Some((found_k, found_v))
        } else {
            None
        }
    }

    /// Equivalent to range((Bound::Excluded(key), Unbounded)).next()
    /// Finds the smallest key strictly greater than `key`
    fn seek_next(iter: &mut Iter, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        let k_bytes = serialize_key(key);
        iter.seek(&k_bytes); // Lands on Key or Greater

        if iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());
            if found_k == *key {
                iter.next();
            }
        }

        if iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());
            let found_v: Hash = iter.value().unwrap().try_into().unwrap();
            Some((found_k, found_v))
        } else {
            None
        }
    }

    fn seek_next_inclusive(iter: &mut Iter, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        let k_bytes = serialize_key(key);
        iter.seek(k_bytes);
        if iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());
            let found_v: Hash = iter.value().unwrap().try_into().unwrap();
            Some((found_k, found_v))
        } else {
            None
        }
    }
}
