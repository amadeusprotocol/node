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

        // Empty tree
        if Self::seek_first_leaf(iter).is_none() {
            return Proof { root: ZERO_HASH, nodes: vec![], path: ZERO_HASH, hash: ZERO_HASH };
        }

        // Exact-match (inclusion)
        let target_leaf = NodeKey { path: target_path, len: 256 };
        if let Some(h) = Self::get_exact(iter, &target_leaf) {
            return Proof {
                root: root_hash,
                nodes: Self::generate_proof_nodes(iter, target_path, 256),
                path: target_path,
                hash: h,
            };
        }

        // Non-existence: descending walk (mirror of Hubt::find_proof_path_descending).
        let proof_path = Self::find_proof_path_descending(iter, &target_path);
        let proof_hash = Self::get_exact(iter, &NodeKey { path: proof_path, len: 256 }).unwrap_or(ZERO_HASH);
        Proof {
            root: root_hash,
            nodes: Self::generate_proof_nodes(iter, proof_path, 256),
            path: proof_path,
            hash: proof_hash,
        }
    }

    /// RocksDB equivalent of `Hubt::find_proof_path_descending` — walks
    /// down toward `target` from the topmost internal, returning a leaf
    /// path that lets the verifier conclude NonExistence.
    fn find_proof_path_descending(iter: &mut Iter, target: &Path) -> Path {
        let first = match Self::seek_first_leaf(iter) { Some((k, _)) => k.path, None => return [0u8; 32] };
        let last  = match Self::seek_last_leaf(iter)  { Some((k, _)) => k.path, None => return [0u8; 32] };
        if first == last { return first; }

        let (root_path, root_len) = lcp_be(&first, &last);

        // Target outside the tree's prefix — fall back to nearest-leaf.
        if !prefix_match_be(target, &root_path, root_len) {
            return Self::find_longest_prefix_node(iter, target)
                .map(|(k, _)| k.path)
                .unwrap_or(first);
        }

        let mut cur_path = root_path;
        let mut cur_len  = root_len;

        loop {
            let target_dir = get_bit_be(target, cur_len);

            let mut t_child = cur_path;
            set_bit_be(&mut t_child, cur_len, target_dir);
            mask_after_be(&mut t_child, cur_len + 1);

            // First internal under target's side
            let next_int = {
                let key = NodeKey { path: t_child, len: cur_len + 1 };
                let kb = serialize_key(&key);
                iter.seek(&kb);
                let mut found = None;
                while iter.valid() {
                    let k = deserialize_key(iter.key().unwrap());
                    if k.len == 256 { iter.next(); continue; }
                    if prefix_match_be(&k.path, &t_child, cur_len + 1) {
                        found = Some(k);
                    }
                    break;
                }
                found
            };
            // First leaf under target's side
            let next_leaf = {
                let key = NodeKey { path: t_child, len: 256 };
                let kb = serialize_key(&key);
                iter.seek(&kb);
                let mut found = None;
                while iter.valid() {
                    let k = deserialize_key(iter.key().unwrap());
                    if k.len != 256 { iter.next(); continue; }
                    if prefix_match_be(&k.path, &t_child, cur_len + 1) {
                        found = Some(k.path);
                    }
                    break;
                }
                found
            };

            match (next_int, next_leaf) {
                (None, None) => {
                    // Empty target side: any leaf on opposite side
                    let opp_dir = 1 - target_dir;
                    let mut o_child = cur_path;
                    set_bit_be(&mut o_child, cur_len, opp_dir);
                    mask_after_be(&mut o_child, cur_len + 1);
                    let key = NodeKey { path: o_child, len: 256 };
                    let kb = serialize_key(&key);
                    iter.seek(&kb);
                    while iter.valid() {
                        let k = deserialize_key(iter.key().unwrap());
                        if k.len == 256 && prefix_match_be(&k.path, &o_child, cur_len + 1) {
                            return k.path;
                        }
                        if k.len != 256 { iter.next(); continue; }
                        break;
                    }
                    return first;
                }
                (None, Some(leaf_path)) => {
                    return leaf_path;
                }
                (Some(int_k), _) => {
                    if !prefix_match_be(target, &int_k.path, int_k.len) {
                        // Compressed-edge divergence between current internal
                        // and int_k — descent can't yield a NonExistence proof.
                        return Self::find_longest_prefix_node(iter, target)
                            .map(|(k, _)| k.path)
                            .unwrap_or(first);
                    }
                    cur_path = int_k.path;
                    cur_len  = int_k.len;
                    if cur_len >= 255 {
                        return next_leaf.unwrap_or(first);
                    }
                }
            }
        }
    }

    // ========================================================================
    // INTERNAL LOGIC (Using Iter)
    // ========================================================================
    fn get_root(iter: &mut Iter) -> Hash {
        // Mirror `Hubt::root` — LCP of FIRST LEAF and LAST LEAF, looked up
        // as an internal node. Previously walked first/last of the mixed
        // CF which could land on an internal node; "worked by accident"
        // but drifted from in-memory semantics.
        let first = match Self::seek_first_leaf(iter) {
            Some((k, _)) => k,
            None => return ZERO_HASH,
        };
        let last = match Self::seek_last_leaf(iter) {
            Some((k, _)) => k,
            None => return ZERO_HASH,
        };

        // Single-leaf tree: in-memory returns the leaf's hash directly.
        if first.path == last.path {
            return Self::get_exact(iter, &first).unwrap_or(ZERO_HASH);
        }
        let (lcp_path, len) = lcp_be(&first.path, &last.path);
        Self::get_exact(iter, &NodeKey { path: lcp_path, len }).unwrap_or(ZERO_HASH)
    }

    fn find_longest_prefix_node(iter: &mut Iter, target: &Path) -> Option<(NodeKey, Hash)> {
        // Mirror Hubt: search LEAVES ONLY (in-memory uses `self.leaves` map).
        let target_key_leaf = NodeKey { path: *target, len: 256 };

        if let Some(h) = Self::get_exact(iter, &target_key_leaf) {
            return Some((target_key_leaf, h));
        }

        let prev = Self::seek_prev_leaf_exclusive(iter, &target_key_leaf);
        let next = Self::seek_next_leaf_exclusive(iter, &target_key_leaf);

        match (prev, next) {
            (None, None) => None,
            (None, Some((k, h))) => Some((k, h)),
            (Some((k, h)), None) => Some((k, h)),
            (Some((pk, ph)), Some((nk, nh))) => {
                let (_, rp) = lcp_be(target, &pk.path);
                let (_, rn) = lcp_be(target, &nk.path);
                if rp >= rn { Some((pk, ph)) } else { Some((nk, nh)) }
            }
        }
    }

    fn generate_proof_nodes(iter: &mut Iter, path: Path, len: u16) -> Vec<ProofNode> {
        // Mirror Hubt::generate_proof_nodes which walks `self.internals`
        // (internals-only). The previous version walked the mixed CF and
        // sibling-jumped off leaves, dropping some ancestors (notably the
        // root) — same family as the bug in `collect_dirty_ancestors`.
        let mut ancestors = Vec::new();
        let mut cursor = NodeKey { path, len: 256 };

        loop {
            match Self::seek_prev_internal_exclusive(iter, &cursor) {
                None => break,
                Some((k, _)) => {
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

    /// Generic seek-with-filter, exclusive of `key`. Walks past entries
    /// that don't satisfy `accept`. Used by the leaf-only and internal-only
    /// variants so the proof prover ignores cross-contaminated CF entries.
    fn seek_exclusive_where(
        iter: &mut Iter,
        key: &NodeKey,
        forward: bool,
        accept: impl Fn(&NodeKey) -> bool,
    ) -> Option<(NodeKey, Hash)> {
        let k_bytes = serialize_key(key);
        if forward { iter.seek(&k_bytes); } else { iter.seek_for_prev(&k_bytes); }
        while iter.valid() {
            let found_k = deserialize_key(iter.key().unwrap());
            if found_k != *key && accept(&found_k) {
                let found_v: Hash = iter.value().unwrap().try_into().unwrap();
                return Some((found_k, found_v));
            }
            if forward { iter.next(); } else { iter.prev(); }
        }
        None
    }

    fn seek_prev_internal_exclusive(iter: &mut Iter, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        Self::seek_exclusive_where(iter, key, false, |k| k.len < 256)
    }
    fn seek_prev_leaf_exclusive(iter: &mut Iter, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        Self::seek_exclusive_where(iter, key, false, |k| k.len == 256)
    }
    fn seek_next_leaf_exclusive(iter: &mut Iter, key: &NodeKey) -> Option<(NodeKey, Hash)> {
        Self::seek_exclusive_where(iter, key, true, |k| k.len == 256)
    }

    fn seek_first_leaf(iter: &mut Iter) -> Option<(NodeKey, Hash)> {
        iter.seek_to_first();
        while iter.valid() {
            let k = deserialize_key(iter.key().unwrap());
            if k.len == 256 {
                let v: Hash = iter.value().unwrap().try_into().unwrap();
                return Some((k, v));
            }
            iter.next();
        }
        None
    }

    fn seek_last_leaf(iter: &mut Iter) -> Option<(NodeKey, Hash)> {
        iter.seek_to_last();
        while iter.valid() {
            let k = deserialize_key(iter.key().unwrap());
            if k.len == 256 {
                let v: Hash = iter.value().unwrap().try_into().unwrap();
                return Some((k, v));
            }
            iter.prev();
        }
        None
    }
}
