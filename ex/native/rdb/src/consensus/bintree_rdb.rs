use crate::consensus::bintree::{
    compute_namespace_path, get_bit_be, lcp_be, leaf_hash, mask_after_be, node_hash, prefix_match_be, set_bit_be, sha256, Hash, NodeKey, Op, Path, Proof,
    ProofNode, VerifyStatus, ZERO_HASH,
};
use crate::consensus::consensus_kv::{kv_delete, kv_put};
use crate::consensus::{self, consensus_apply};
use consensus_apply::ApplyEnv;

use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::cmp::{min, Ordering};
use std::collections::BTreeSet;
use std::convert::TryInto;

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
// ROCKSDB HUBT
// ============================================================================

pub struct RocksHubt<'env, 'a> {
    env: &'env mut ApplyEnv<'a>,
}

impl<'env, 'a> RocksHubt<'env, 'a> {
    pub fn new(env: &'env mut ApplyEnv<'a>) -> Self {
        Self { env }
    }

    pub fn root(&self) -> Hash {
        let first = self.seek_first();
        let last = self.seek_last();
        match (first, last) {
            (Some((fk, fv)), Some((lk, _))) => {
                if fk.path == lk.path {
                    return fv;
                }
                let (lcp_path, len) = lcp_be(&fk.path, &lk.path);
                if let Some(h) = self.get_exact(&NodeKey { path: lcp_path, len }) {
                    return h;
                }
                ZERO_HASH
            }
            _ => ZERO_HASH,
        }
    }

    // ========================================================================
    // BATCH UPDATE (Same logic as before, verified)
    // ========================================================================
    pub fn batch_update(&mut self, ops: Vec<Op>) {
        let mut prepared: Vec<(bool, Path, Hash)> = ops
            .into_par_iter()
            .map(|op| match op {
                Op::Insert(ns, k, v) => {
                    let path = compute_namespace_path(ns.as_deref(), &k);
                    (true, path, leaf_hash(&path, &k, &v))
                }
                Op::Delete(ns, k) => {
                    let path = compute_namespace_path(ns.as_deref(), &k);
                    (false, path, ZERO_HASH)
                }
            })
            .collect();
        prepared.par_sort_unstable_by(|a, b| match a.1.cmp(&b.1) {
            Ordering::Equal => a.0.cmp(&b.0),
            other => other,
        });

        let mut dirty_leaf_paths = BTreeSet::new();

        for (is_ins, p, l) in &prepared {
            let key = NodeKey { path: *p, len: 256 };
            if *is_ins {
                // INSERT
                self.insert_raw(key, *l);
                dirty_leaf_paths.insert(*p);
            } else {
                // DELETE
                // If it exists, remove and mark neighbors dirty.
                if self.exists_raw(&key) {
                    self.remove_raw(&key);
                    dirty_leaf_paths.insert(*p);

                    // Find neighbors of the "hole" we just made.
                    // seek_prev(key) gives the one before.
                    // seek(key) gives the one after (since key is now deleted).
                    if let Some((prev_k, _)) = self.seek_prev_inclusive(&key) {
                        if prev_k.len == 256 {
                            dirty_leaf_paths.insert(prev_k.path);
                        }
                    }
                    if let Some((next_k, _)) = self.seek_next(&key) {
                        if next_k.len == 256 {
                            dirty_leaf_paths.insert(next_k.path);
                        }
                    }
                }
            }
        }

        let mut dirty_internal_nodes = BTreeSet::new();

        for p in &dirty_leaf_paths {
            if let Some(leaf_hash) = self.get_exact(&NodeKey { path: *p, len: 256 }) {
                self.ensure_split_points(*p, leaf_hash, &mut dirty_internal_nodes);
            }
        }
        for p in &dirty_leaf_paths {
            self.collect_dirty_ancestors(*p, &mut dirty_internal_nodes);
        }

        self.rehash_and_prune(dirty_internal_nodes);
    }

    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================
    fn ensure_split_points(&mut self, path: Path, leaf: Hash, dirty: &mut BTreeSet<NodeKey>) {
        let key = NodeKey { path, len: 256 };

        // Check Previous Neighbor
        // Since we are iterating known existing leaves, we look for neighbors in the DB
        if let Some((n_key, n_leaf)) = self.seek_prev_db(&key) {
            // seek_prev_db excludes self
            if n_key.len == 256 {
                self.check_neighbor(path, leaf, n_key.path, n_leaf, dirty);
            }
        }

        // Check Next Neighbor
        if let Some((n_key, n_leaf)) = self.seek_next(&key) {
            if n_key.len == 256 {
                self.check_neighbor(path, leaf, n_key.path, n_leaf, dirty);
            }
        }
    }

    fn check_neighbor(&mut self, path: Path, leaf: Hash, n_path: Path, n_leaf: Hash, dirty: &mut BTreeSet<NodeKey>) {
        let (lcp_path, len) = lcp_be(&path, &n_path);
        let dir = get_bit_be(&path, len);
        let temp_val = if dir == 0 { node_hash(&lcp_path, len, &leaf, &n_leaf) } else { node_hash(&lcp_path, len, &n_leaf, &leaf) };

        let node_key = NodeKey { path: lcp_path, len };
        // Insert node if not exists or if it needs update (we just overwrite, it's safer)
        self.insert_raw(node_key, temp_val);
        dirty.insert(node_key);
    }

    fn collect_dirty_ancestors(&self, target_path: Path, acc: &mut BTreeSet<NodeKey>) {
        let mut cursor = NodeKey { path: target_path, len: 256 };
        loop {
            // seek_prev_inclusive behaves like range(..cursor).next_back() PLUS checking exact cursor.
            // But we want ancestors, which have len < cursor.len.
            // Also prefix match.

            match self.seek_prev_inclusive(&cursor) {
                None => break,
                Some((k, _)) => {
                    // Prevent infinite loop if we find ourselves
                    if k == cursor {
                        if k.len > 0 {
                            cursor = NodeKey { path: k.path, len: k.len - 1 };
                            continue;
                        } else {
                            break;
                        }
                    }

                    if prefix_match_be(&target_path, &k.path, k.len) {
                        acc.insert(k);
                        cursor = k;
                    } else {
                        // Sibling jump
                        let (lcp_p, lcp_l) = lcp_be(&target_path, &k.path);
                        let jump = NodeKey { path: lcp_p, len: lcp_l + 1 };
                        cursor = if jump < k { jump } else { k };
                    }
                }
            }
        }
    }

    fn rehash_and_prune(&mut self, dirty_nodes: BTreeSet<NodeKey>) {
        let mut sorted_nodes: Vec<NodeKey> = dirty_nodes.into_iter().collect();
        // Bottom-up: sort by len descending
        sorted_nodes.sort_unstable_by(|a, b| b.len.cmp(&a.len));

        for node in sorted_nodes {
            if node.len == 256 {
                continue;
            }

            // Get children hashes.
            // This unifies the logic: check for direct child node OR descendant leaf/node.
            let l_hash = self.get_child_hash(node.path, node.len, 0);
            let r_hash = self.get_child_hash(node.path, node.len, 1);

            if l_hash != ZERO_HASH && r_hash != ZERO_HASH {
                self.insert_raw(node, node_hash(&node.path, node.len, &l_hash, &r_hash));
            } else {
                self.remove_raw(&node);
            }
        }
    }

    /// Unified Child Hash Retrieval for RocksDB
    fn get_child_hash(&self, p_path: Path, p_len: u16, dir: u8) -> Hash {
        let mut target_path = p_path;
        set_bit_be(&mut target_path, p_len, dir);
        mask_after_be(&mut target_path, p_len + 1);
        let child_len = p_len + 1;

        let target_key = NodeKey { path: target_path, len: child_len };

        // We seek to the location of the child.
        // If the child exists (Internal or Leaf at that exact path), we get it.
        // If the child does NOT exist, but a descendant exists (compressed edge),
        // the seek will land on that descendant (which shares the prefix).

        // Use seek_next_inclusive logic (iter.seek)
        if let Some((found_k, found_h)) = self.seek_next_inclusive(&target_key) {
            if prefix_match_be(&found_k.path, &target_path, child_len) {
                return found_h;
            }
        }

        ZERO_HASH
    }

    // ========================================================================
    // INTERNAL DB HELPERS
    // ========================================================================
    fn insert_raw(&mut self, key: NodeKey, val: Hash) {
        let k = serialize_key(&key);
        kv_put(self.env, &k, &val);
    }

    fn remove_raw(&mut self, key: &NodeKey) {
        let k = serialize_key(key);
        kv_delete(self.env, &k);
    }

    fn exists_raw(&self, key: &NodeKey) -> bool {
        self.get_exact(key).is_some()
    }

    fn get_exact(&self, key: &NodeKey) -> Option<Hash> {
        let k = serialize_key(key);
        match self.env.txn.get_cf(&self.env.cf, k) {
            Ok(Some(v)) => Some(v.try_into().unwrap()),
            _ => None,
        }
    }

    // ========================================================================
    // ITERATOR WRAPPERS
    // ========================================================================

    fn seek_first(&self) -> Option<(NodeKey, Hash)> {
        let mut iter = self.env.txn.raw_iterator_cf(&self.env.cf);
        iter.seek_to_first();
        if iter.valid() {
            Some((deserialize_key(iter.key().unwrap()), iter.value().unwrap().try_into().unwrap()))
        } else {
            None
        }
    }

    fn seek_last(&self) -> Option<(NodeKey, Hash)> {
        let mut iter = self.env.txn.raw_iterator_cf(&self.env.cf);
        iter.seek_to_last();
        if iter.valid() {
            Some((deserialize_key(iter.key().unwrap()), iter.value().unwrap().try_into().unwrap()))
        } else {
            None
        }
    }

    /// Finds key <= target
    fn seek_prev_inclusive(&self, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        let k_bytes = serialize_key(key);
        let mut iter = self.env.txn.raw_iterator_cf(&self.env.cf);
        iter.seek_for_prev(k_bytes);

        if iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());
            let found_v: Hash = iter.value().unwrap().try_into().unwrap();
            Some((found_k, found_v))
        } else {
            None
        }
    }

    /// Finds key < target
    fn seek_prev_db(&self, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        let k_bytes = serialize_key(key);
        let mut iter = self.env.txn.raw_iterator_cf(&self.env.cf);
        iter.seek_for_prev(k_bytes);

        if iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());
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

    /// Finds key > target (Strictly Greater)
    fn seek_next(&self, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        let k_bytes = serialize_key(key);
        let mut iter = self.env.txn.raw_iterator_cf(&self.env.cf);
        iter.seek(k_bytes);

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

    /// Finds key >= target (Inclusive)
    /// Used for finding if a child exists at a specific prefix
    fn seek_next_inclusive(&self, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        let k_bytes = serialize_key(key);
        let mut iter = self.env.txn.raw_iterator_cf(&self.env.cf);
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
