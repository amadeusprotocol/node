use sha2::{Digest, Sha256};
use std::cmp::{min, Ordering};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use rayon::prelude::*;

pub type Hash = [u8; 32];
pub type Path = [u8; 32];
pub const ZERO_HASH: Hash = [0u8; 32];

// ============================================================================
// STRUCTS
// ============================================================================

#[derive(Debug, Clone)]
pub struct Proof {
    pub root: Hash,
    pub nodes: Vec<ProofNode>,
    pub path: Path,
    pub hash: Hash,
}

#[derive(Debug, Clone)]
pub struct ProofNode {
    pub hash: Hash,
    pub direction: u8,
    pub len: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct NodeKey {
    pub path: Path,
    pub len: u16,
}

impl PartialOrd for NodeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.path.cmp(&other.path) {
            Ordering::Equal => self.len.cmp(&other.len),
            other => other,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Op {
    Insert(Option<Vec<u8>>, Vec<u8>, Vec<u8>),
    Delete(Option<Vec<u8>>, Vec<u8>),
}

#[derive(Debug, PartialEq)]
pub enum VerifyStatus {
    Included,
    Mismatch,
    NonExistence,
    Invalid,
}

// ============================================================================
// BIT HELPERS
// ============================================================================

#[inline]
pub fn compute_namespace_path(namespace: Option<&[u8]>, key: &[u8]) -> Path {
    let key_hash = sha256(key);
    let mut path = [0u8; 32];
    if let Some(ns) = namespace {
        let ns_hash = sha256(ns);
        path[0..8].copy_from_slice(&ns_hash[0..8]);
    }
    path[8..32].copy_from_slice(&key_hash[0..24]);
    path
}

#[inline]
pub fn node_hash(prefix: &Path, len: u16, left: &Hash, right: &Hash) -> Hash {
    let mut p = *prefix;
    mask_after_be(&mut p, len);

    let mut hasher = Sha256::new();
    hasher.update(b"NODE");
    hasher.update(&len.to_be_bytes());
    hasher.update(&p);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

#[inline]
pub fn leaf_hash(path: &Path, key: &[u8], value: &[u8]) -> Hash {
    let k_len = key.len() as u64;
    let mut hasher = Sha256::new();
    hasher.update(b"LEAF");
    hasher.update(path);
    hasher.update(&k_len.to_be_bytes());
    hasher.update(key);
    hasher.update(value);
    hasher.finalize().into()
}

#[inline(always)]
pub fn get_bit_be(data: &[u8], index: u16) -> u8 {
    if index >= 256 { return 0; }
    let byte_idx = (index >> 3) as usize;
    let bit_offset = 7 - (index & 7);
    (data[byte_idx] >> bit_offset) & 1
}

#[inline(always)]
pub fn set_bit_be(data: &mut [u8], index: u16, val: u8) {
    if index >= 256 { return; }
    let byte_idx = (index >> 3) as usize;
    let bit_offset = 7 - (index & 7);
    if val == 1 {
        data[byte_idx] |= 1 << bit_offset;
    } else {
        data[byte_idx] &= !(1 << bit_offset);
    }
}

#[inline]
pub fn mask_after_be(data: &mut [u8], len: u16) {
    if len >= 256 { return; }
    let byte_idx = (len >> 3) as usize;
    let start_clean_bit = len;

    for i in start_clean_bit..((byte_idx as u16 + 1) << 3) {
        let off = 7 - (i & 7);
        let mask = !(1 << off);
        data[byte_idx] &= mask;
    }
    if byte_idx + 1 < 32 {
        data[(byte_idx + 1)..].fill(0);
    }
}

#[inline]
pub fn lcp_be(p1: &Path, p2: &Path) -> (Path, u16) {
    let mut len = 0;
    let mut byte_idx = 0;
    while byte_idx < 32 && p1[byte_idx] == p2[byte_idx] {
        len += 8;
        byte_idx += 1;
    }
    if byte_idx < 32 {
        for i in 0..8 {
            let idx = (byte_idx << 3) + i;
            if get_bit_be(p1, idx as u16) == get_bit_be(p2, idx as u16) { len += 1; }
            else { break; }
        }
    }
    let mut prefix = *p1;
    mask_after_be(&mut prefix, len);
    (prefix, len)
}

#[inline]
pub fn prefix_match_be(target: &Path, path: &Path, len: u16) -> bool {
    let full_bytes = (len >> 3) as usize;
    if target[..full_bytes] != path[..full_bytes] {
        return false;
    }
    let rem = len & 7;
    if rem > 0 {
        let mask = 0xFF << (8 - rem);
        if (target[full_bytes] & mask) != (path[full_bytes] & mask) {
            return false;
        }
    }
    true
}

#[inline]
pub fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ============================================================================
// HUBT IMPLEMENTATION (Split Storage)
// ============================================================================

pub struct Hubt {
    /// Stores ONLY leaves (len == 256).
    pub leaves: BTreeMap<Path, Hash>,
    /// Stores ONLY internal nodes (len < 256).
    pub internals: BTreeMap<NodeKey, Hash>,
}

impl Hubt {
    pub fn new() -> Self {
        Hubt {
            leaves: BTreeMap::new(),
            internals: BTreeMap::new(),
        }
    }

    pub fn root(&self) -> Hash {
        if self.leaves.is_empty() {
            return ZERO_HASH;
        }

        let first = self.leaves.first_key_value().unwrap();
        let last = self.leaves.last_key_value().unwrap();

        // Single item optimization
        if first.0 == last.0 {
            return *first.1;
        }

        // Calculate the "Top" of the tree (LCP of first and last)
        let (lcp_path, len) = lcp_be(first.0, last.0);

        // This node MUST exist in internals if the tree is valid
        if let Some(h) = self.internals.get(&NodeKey { path: lcp_path, len }) {
            return *h;
        }

        // Should not happen if rehash is working
        ZERO_HASH
    }

    pub fn batch_update(&mut self, ops: Vec<Op>) {
        // 1. Preprocess Ops (Parallel)
        let mut prepared: Vec<(bool, Path, Hash)> = ops.into_par_iter().map(|op| {
            match op {
                Op::Insert(ns, k, v) => {
                    let path = compute_namespace_path(ns.as_deref(), &k);
                    (true, path, leaf_hash(&path, &k, &v))
                },
                Op::Delete(ns, k) => {
                    let path = compute_namespace_path(ns.as_deref(), &k);
                    (false, path, ZERO_HASH)
                }
            }
        }).collect();

        // FIX: Sort by Path AND OpType.
        // We want `false` (Delete) to come before `true` (Insert) for the same path.
        // This ensures an "Upsert" (Delete+Insert) results in the value existing.
        prepared.par_sort_unstable_by(|a, b| {
            match a.1.cmp(&b.1) {
                Ordering::Equal => a.0.cmp(&b.0), // bool cmp: false < true
                other => other,
            }
        });

        // 2. Update LEAVES Map
        // We track all paths that need split-point recalculation OR ancestor hashing.
        let mut dirty_leaf_paths = BTreeSet::new();

        for (is_ins, p, l) in &prepared {
            if *is_ins {
                self.leaves.insert(*p, *l);
                dirty_leaf_paths.insert(*p);
            } else {
                // DELETE LOGIC:
                // If the key exists, remove it and mark its neighbors as dirty.
                if self.leaves.contains_key(p) {
                    self.leaves.remove(p);

                    // Mark 'p' as dirty so we clean up its old ancestors
                    dirty_leaf_paths.insert(*p);

                    // Find who is sitting next to the "hole" left by 'p'.
                    if let Some((k, _)) = self.leaves.range(..*p).next_back() {
                        dirty_leaf_paths.insert(*k);
                    }
                    if let Some((k, _)) = self.leaves.range((Bound::Excluded(*p), Bound::Unbounded)).next() {
                        dirty_leaf_paths.insert(*k);
                    }
                }
            }
        }

        // 3. Ensure Split Points (Correct Topology)
        // Only existing leaves need split points.
        for p in &dirty_leaf_paths {
            if let Some(h) = self.leaves.get(p) {
                self.ensure_split_points(*p, *h);
            }
        }

        // 4. Collect Dirty Ancestors
        // We iterate the set of all touched paths once.
        let mut dirty_internal_nodes = BTreeSet::new();
        for p in &dirty_leaf_paths {
            self.collect_dirty_ancestors(*p, &mut dirty_internal_nodes);
        }

        // 5. Rehash Internal Nodes
        self.rehash_and_prune(dirty_internal_nodes);
    }

    fn ensure_split_points(&mut self, path: Path, leaf_hash: Hash) {
        if let Some((n_path, n_hash)) = self.leaves.range(..path).next_back() {
            self.check_neighbor(path, leaf_hash, *n_path, *n_hash);
        }
        if let Some((n_path, n_hash)) = self.leaves.range((Bound::Excluded(path), Bound::Unbounded)).next() {
            self.check_neighbor(path, leaf_hash, *n_path, *n_hash);
        }
    }

    fn check_neighbor(&mut self, path: Path, leaf: Hash, n_path: Path, n_leaf: Hash) {
        let (lcp_path, len) = lcp_be(&path, &n_path);
        let dir = get_bit_be(&path, len);
        let temp_val = if dir == 0 {
            node_hash(&lcp_path, len, &leaf, &n_leaf)
        } else {
            node_hash(&lcp_path, len, &n_leaf, &leaf)
        };
        self.internals.insert(NodeKey { path: lcp_path, len }, temp_val);
    }

    fn collect_dirty_ancestors(&self, target_path: Path, acc: &mut BTreeSet<NodeKey>) {
        let mut cursor = NodeKey { path: target_path, len: 256 };
        loop {
            match self.internals.range(..cursor).next_back() {
                None => break,
                Some((k, _)) => {
                    if prefix_match_be(&target_path, &k.path, k.len) {
                        acc.insert(*k);
                        cursor = *k;
                    } else {
                        let (lcp_p, lcp_l) = lcp_be(&target_path, &k.path);
                        let jump = NodeKey{ path: lcp_p, len: lcp_l + 1 };
                        cursor = if jump < *k { jump } else { *k };
                    }
                }
            }
        }
    }

    fn rehash_and_prune(&mut self, dirty_nodes: BTreeSet<NodeKey>) {
        let mut sorted_nodes: Vec<NodeKey> = dirty_nodes.into_iter().collect();
        sorted_nodes.sort_unstable_by(|a, b| b.len.cmp(&a.len));

        for node in sorted_nodes {
            if node.len == 256 { continue; }

            let l_hash = self.get_child_hash(node.path, node.len, 0);
            let r_hash = self.get_child_hash(node.path, node.len, 1);

            if l_hash != ZERO_HASH && r_hash != ZERO_HASH {
                self.internals.insert(node, node_hash(&node.path, node.len, &l_hash, &r_hash));
            } else {
                self.internals.remove(&node);
            }
        }
    }

    fn get_child_hash(&self, p_path: Path, p_len: u16, dir: u8) -> Hash {
        let mut target_path = p_path;
        set_bit_be(&mut target_path, p_len, dir);
        mask_after_be(&mut target_path, p_len + 1);

        let child_len = p_len + 1;

        // 1. Quick check Leaves
        if child_len == 256 {
             if let Some(h) = self.leaves.get(&target_path) { return *h; }
             return ZERO_HASH;
        }

        // 2. Check Internals
        let target_key = NodeKey { path: target_path, len: child_len };
        if let Some((f_key, hash)) = self.internals.range(target_key..).next() {
             if prefix_match_be(&f_key.path, &target_path, child_len) {
                 return *hash;
             }
        }

        // 3. Check Leaves (Skip)
        if let Some((l_path, l_hash)) = self.leaves.range(target_path..).next() {
             if prefix_match_be(l_path, &target_path, child_len) {
                 return *l_hash;
             }
        }

        ZERO_HASH
    }

    // ========================================================================
    // PROOF LOGIC
    // ========================================================================

    pub fn prove(&self, ns: Option<Vec<u8>>, k: Vec<u8>) -> Proof {
        let target_path = compute_namespace_path(ns.as_deref(), &k);

        let (found_key, found_hash) = match self.find_longest_prefix_node(&target_path) {
            Some((key, hash)) => (key, hash),
            None => {
                return Proof {
                    root: ZERO_HASH,
                    nodes: vec![],
                    path: ZERO_HASH,
                    hash: ZERO_HASH
                };
            }
        };

        Proof {
            root: self.root(),
            nodes: self.generate_proof_nodes(found_key.path, found_key.len),
            path: found_key.path,
            hash: found_hash,
        }
    }

    fn generate_proof_nodes(&self, path: Path, len: u16) -> Vec<ProofNode> {
        let mut ancestors = Vec::new();
        let mut cursor = NodeKey { path, len: 256 };

        loop {
            match self.internals.range(..cursor).next_back() {
                None => break,
                Some((k, _)) => {
                    if prefix_match_be(&path, &k.path, k.len) {
                        if k.len < len { ancestors.push(*k); }
                        cursor = *k;
                    } else {
                         let (lcp_p, lcp_l) = lcp_be(&path, &k.path);
                         let jump = NodeKey{ path: lcp_p, len: lcp_l + 1 };
                         cursor = if jump < *k { jump } else { *k };
                    }
                }
            }
        }
        if !ancestors.iter().any(|k| k.len == 0) && self.internals.contains_key(&NodeKey{path:ZERO_HASH, len:0}) {
             ancestors.push(NodeKey{path:ZERO_HASH, len:0});
        }
        ancestors.sort_unstable_by(|a, b| b.len.cmp(&a.len));

        let mut nodes = Vec::new();
        for anc in ancestors {
            let my_dir = get_bit_be(&path, anc.len);
            let sibling_dir = 1 - my_dir;
            nodes.push(ProofNode {
                hash: self.get_child_hash(anc.path, anc.len, sibling_dir),
                direction: sibling_dir,
                len: anc.len,
            });
        }
        nodes
    }

    fn find_longest_prefix_node(&self, target: &Path) -> Option<(NodeKey, Hash)> {
        if let Some(h) = self.leaves.get(target) {
            return Some((NodeKey { path: *target, len: 256 }, *h));
        }

        let prev = self.leaves.range(..*target).next_back();
        let next = self.leaves.range((Bound::Excluded(*target), Bound::Unbounded)).next();

        match (prev, next) {
            (None, None) => None,
            (None, Some((k, h))) => Some((NodeKey{path:*k, len:256}, *h)),
            (Some((k, h)), None) => Some((NodeKey{path:*k, len:256}, *h)),
            (Some((pk, ph)), Some((nk, nh))) => {
                let (_, rp) = lcp_be(target, pk);
                let (_, rn) = lcp_be(target, nk);
                if rp >= rn {
                    Some((NodeKey{path:*pk, len:256}, *ph))
                } else {
                    Some((NodeKey{path:*nk, len:256}, *nh))
                }
            }
        }
    }

    pub fn verify(proof: &Proof, ns: Option<Vec<u8>>, k: Vec<u8>, v: Vec<u8>) -> VerifyStatus {
        let target_path = compute_namespace_path(ns.as_deref(), &k);
        let claimed_leaf_hash = leaf_hash(&target_path, &k, &v);

        if proof.root == ZERO_HASH && proof.hash == ZERO_HASH && proof.path == ZERO_HASH && proof.nodes.is_empty() {
            return VerifyStatus::NonExistence;
        }

        if !Self::verify_integrity(proof) { return VerifyStatus::Invalid; }
        if proof.hash == claimed_leaf_hash { return VerifyStatus::Included; }
        if proof.path == target_path { return VerifyStatus::Mismatch; }

        let (_, div_len) = lcp_be(&target_path, &proof.path);

        if let Some(node) = proof.nodes.iter().find(|n| n.len == div_len) {
            let target_dir = get_bit_be(&target_path, div_len);

            if node.direction != target_dir {
                return VerifyStatus::Invalid;
            }

            if node.hash == ZERO_HASH {
                // The sibling is empty -> Target definitely does not exist.
                return VerifyStatus::NonExistence;
            } else {
                // The sibling is NOT empty.
                // This means something exists in the target's subtree.
                // This proof (which points to a different leaf) fails to prove the target is missing.
                return VerifyStatus::Invalid;
            }
        }
        let deepest_node_len = proof.nodes.first().map(|n| n.len);
        match deepest_node_len {
            None => {
                let target_dir = get_bit_be(&target_path, div_len);
                let proof_dir = get_bit_be(&proof.path, div_len);

                if target_dir != proof_dir && proof.hash != ZERO_HASH {
                    return VerifyStatus::NonExistence;
                }
                VerifyStatus::Invalid
            },
            Some(max_len) if div_len < max_len => {
                // CASE: Malleable Gap
                // The divergence happened ABOVE the deepest node.
                // Since there is no node at 'div_len', the tree claims the edge is solid.
                // Therefore, proof.path and target_path SHOULD match here.
                // The fact that they diverge implies proof.path was tampered with (malleability attack).
                VerifyStatus::Invalid
            },
            Some(max_len) if div_len == max_len => {
                // CASE: Exact Match Divergent Case
                // The divergence happens exactly at the depth of the deepest proof node.
                // The proof node at max_len establishes the branching structure.
                // We need to check if the target direction represents the empty child.
                let target_dir = get_bit_be(&target_path, div_len);
                let proof_dir = get_bit_be(&proof.path, div_len);

                // Find the proof node at max_len
                if let Some(anc) = proof.nodes.iter().find(|n| n.len == max_len) {
                    // anc.direction is the sibling of proof.path at level max_len
                    // anc.direction != proof_dir == true always (verified in verify_integrity)

                    if target_dir == anc.direction {
                        // target goes toward the sibling's direction
                        // Check if that sibling is empty
                        if anc.hash == ZERO_HASH {
                            return VerifyStatus::NonExistence;
                        }
                    } else if target_dir == proof_dir {
                        // target goes same direction as proof.path
                        // But they diverge at this level, and proof reaches a different leaf
                        // So target must be empty along this branch
                        return VerifyStatus::NonExistence;
                    }
                }

                // target points to a non-empty child or ambiguity remains
                VerifyStatus::Invalid
            },
            _ => {
                // CASE: Suffix Divergence (div_len > max_len OR No nodes at all)
                // The divergence happened BELOW the deepest internal node.
                // This means the Proof Leaf and the Target share the exact same structural edge
                // down to the bottom of the tree.
                // Since we already checked (proof.hash != claimed_leaf_hash) in Step 1,
                // we know the leaf residing at the end of this path is NOT the target.
                // Since the tree has no branches below this point, the Target CANNOT exist.
                VerifyStatus::Invalid
            }
        }
    }

    fn verify_integrity(proof: &Proof) -> bool {
        // 1. Handle Empty Tree Case
        if proof.root == ZERO_HASH {
            return proof.nodes.is_empty() && proof.hash == ZERO_HASH;
        }

        let mut current_hash = proof.hash;
        // Start at the bottom (Leaf Depth = 256)
        let mut last_len = 256u16;

        for node in &proof.nodes {
            // 2. Topology Check: Ensure we are strictly climbing UP the tree.
            // The ancestors must be sorted deepest-to-shallowest.
            // Since we start at leaf (256), the first ancestor must be < 256.
            if node.len >= last_len {
                return false;
            }
            last_len = node.len;

            // 3. Path Consistency Check: Bind the Hashing Direction to proof.path.
            // get_bit_be returns the direction WE are taking (0=Left, 1=Right).
            let path_bit = get_bit_be(&proof.path, node.len);

            // node.direction is the SIBLING's direction.
            // If we go Left (0), Sibling must be Right (1).
            // If we go Right (1), Sibling must be Left (0).
            // Therefore, they must strictily DISAGREE.
            if node.direction == path_bit {
                return false;
            }

            let mut prefix = proof.path;
            mask_after_be(&mut prefix, node.len);

            // 4. Hash Aggregation
            if node.direction == 0 {
                // Sibling is Left, Current is Right
                current_hash = node_hash(&prefix, node.len, &node.hash, &current_hash);
            } else {
                // Sibling is Right, Current is Left
                current_hash = node_hash(&prefix, node.len, &current_hash, &node.hash);
            }
        }

        current_hash == proof.root
    }
}

// ============================================================================
// TESTS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_proof_logic() {
        let mut hubt = Hubt::new();
        let k1 = b"user:1".to_vec();
        let v1 = b"100".to_vec();
        let k2 = b"user:2".to_vec();
        let v2 = b"200".to_vec();
        // Insert Key 1
        hubt.batch_update(vec![Op::Insert(None, k1.clone(), v1.clone())]);

        // Case 1: Inclusion (Key exists, Value matches)
        let proof_inc = hubt.prove(None, k1.clone());
        assert_eq!(Hubt::verify(&proof_inc, None, k1.clone(), v1.clone()), VerifyStatus::Included);

        // Case 2: Mismatch (Key exists, Value differs)
        let v1_fake = b"999".to_vec();
        let proof_mis = hubt.prove(None, k1.clone()); // Same proof generation!
        assert_eq!(Hubt::verify(&proof_mis, None, k1.clone(), v1_fake), VerifyStatus::Mismatch);

        // Case 3: Non-Existence in single key tree (Key does not exist)
        let k_missing = b"user:999".to_vec();
        let proof_non = hubt.prove(None, k_missing.clone());
        let res = Hubt::verify(&proof_non, None, k_missing.to_vec(), v1.clone());
        assert!(res == VerifyStatus::NonExistence || res == VerifyStatus::Invalid);

        // Case 4: Non-Existence in multi key tree (Key does not exist)
        hubt.batch_update(vec![Op::Insert(None, k2.clone(), v2.clone())]);
        assert_eq!(Hubt::verify(&proof_non, None, k_missing, v1.clone()), VerifyStatus::NonExistence);
    }

    #[test]
    fn test_proof_integrity() {
        let mut hubt = Hubt::new();
        // Insert multiple items to create depth
        hubt.batch_update(vec![
            Op::Insert(None, b"A".to_vec(), b"1".to_vec()),
            Op::Insert(None, b"B".to_vec(), b"2".to_vec()),
            Op::Insert(None, b"C".to_vec(), b"3".to_vec()),
        ]);

        let k = b"B".to_vec();
        let proof = hubt.prove(None, k);
        assert!(Hubt::verify_integrity(&proof));
    }

    fn insert_one(h: &mut Hubt, k: &[u8], v: &[u8]) {
        h.batch_update(vec![Op::Insert(None, k.to_vec(), v.to_vec())]);
    }

    fn insert_two(h: &mut Hubt, k0: &[u8], v0: &[u8], k1: &[u8], v1: &[u8]) {
        h.batch_update(vec![
            Op::Insert(None, k0.to_vec(), v0.to_vec()),
            Op::Insert(None, k1.to_vec(), v1.to_vec()),
        ]);
    }

    fn delete_one(h: &mut Hubt, k: &[u8]) {
        h.batch_update(vec![Op::Delete(None, k.to_vec())]);
    }

    fn insert_two_none(h: &mut Hubt, k0: &[u8], v0: &[u8], k1: &[u8], v1: &[u8]) {
        h.batch_update(vec![
            Op::Insert(None, k0.to_vec(), v0.to_vec()),
            Op::Insert(None, k1.to_vec(), v1.to_vec()),
        ]);
    }

    fn flip_bit(path: &mut Path, idx: u16) {
        let b = get_bit_be(path, idx);
        set_bit_be(path, idx, 1 - b);
    }


    #[test]
    fn test_repro_7_is_fixed() {
        let k_a = b"KiK2ZWe".to_vec();
        let k_b = b"KqhFWCE".to_vec();
        let k_c = b"KPyYngF".to_vec();
        let v = b"v".to_vec();

        let mut hub_fwd = Hubt::new();
        insert_one(&mut hub_fwd, &k_a, &v);
        insert_one(&mut hub_fwd, &k_b, &v);
        insert_one(&mut hub_fwd, &k_c, &v);
        hub_fwd.batch_update(vec![Op::Delete(None, k_a.to_vec())]);
        insert_one(&mut hub_fwd, &k_a, &v);
        let root_fwd = hub_fwd.root();

        let mut hub_rev = Hubt::new();
        insert_one(&mut hub_rev, &k_c, &v);
        insert_one(&mut hub_rev, &k_b, &v);
        insert_one(&mut hub_rev, &k_a, &v);
        hub_rev.batch_update(vec![Op::Delete(None, k_a.to_vec())]);
        insert_one(&mut hub_rev, &k_a, &v);
        let root_rev = hub_rev.root();

        assert_eq!(root_fwd, root_rev);
    }

    #[test]
    fn repro_8_prove_finds_correct_leaf_for_missing_key() {
        // This test ensures we find the CLOSEST LEAF for non-existence,
        // rather than crashing or returning an internal node (which we don't store in leaves).
        let inserted = [
            b"I9382df".to_vec(), b"Ifx1kVZ".to_vec(), b"IQ2tqMn".to_vec(),
            b"IMcLRkB".to_vec(),
        ];
        let v = b"v".to_vec();
        let mut hubt = Hubt::new();
        for k in inserted.iter() { insert_one(&mut hubt, k, &v); }

        let missing = b"MOzZU3G".to_vec();
        let target_path = compute_namespace_path(None, &missing);

        let (found_key, _found_hash) = hubt
            .find_longest_prefix_node(&target_path)
            .expect("tree should be non-empty");

        // We must find a leaf (len 256)
        assert_eq!(found_key.len, 256);

        let proof = hubt.prove(None, missing);

        // Integrity should PASS
        assert!(Hubt::verify_integrity(&proof));
    }

    #[test]
    fn test_deletion_and_upsert_logic() {
        let mut hubt = Hubt::new();
        let k = b"key1".to_vec();
        let v1 = b"val1".to_vec();
        let v2 = b"val2".to_vec();

        // 1. Insert
        hubt.batch_update(vec![Op::Insert(None, k.clone(), v1.clone())]);
        assert_eq!(Hubt::verify(&hubt.prove(None, k.clone()), None, k.clone(), v1.clone()), VerifyStatus::Included);

        // 2. Delete
        hubt.batch_update(vec![Op::Delete(None, k.clone())]);
        assert_eq!(Hubt::verify(&hubt.prove(None, k.clone()), None, k.clone(), v1.clone()), VerifyStatus::NonExistence);

        // 3. Upsert (Delete + Insert in same batch) - Should result in INSERT
        hubt.batch_update(vec![
            Op::Delete(None, k.clone()),
            Op::Insert(None, k.clone(), v2.clone())
        ]);
        assert_eq!(Hubt::verify(&hubt.prove(None, k.clone()), None, k.clone(), v2.clone()), VerifyStatus::Included);
    }

    #[test]
    fn attack_namespace_swap_allows_false_inclusion_even_with_multiple_leaves() {
        let mut hubt = Hubt::new();

        let ns_a = b"namespace-A".to_vec();
        let ns_b = b"namespace-B".to_vec();

        let k0 = b"user:1".to_vec();
        let v0 = b"100".to_vec();
        let k1 = b"user:2".to_vec();
        let v1 = b"200".to_vec();

        // Insert two keys ONLY into namespace A
        hubt.batch_update(vec![
            Op::Insert(Some(ns_a.clone()), k0.clone(), v0.clone()),
            Op::Insert(Some(ns_a.clone()), k1.clone(), v1.clone()),
        ]);

        // Honest inclusion proof in namespace A should work
        let proof_a = hubt.prove(Some(ns_a.clone()), k0.clone());
        assert!(Hubt::verify_integrity(&proof_a));
        assert_eq!(
            Hubt::verify(&proof_a, Some(ns_a.clone()), k0.clone(), v0.clone()),
            VerifyStatus::Included
        );

        // Forge: rewrite the claimed leaf path to namespace B but keep hashes/nodes the same.
        // This is "sanitized": it's just a different 32-byte path.
        let mut forged = proof_a.clone();
        forged.path = compute_namespace_path(Some(ns_b.as_slice()), k0.as_slice());

        // A correct verifier MUST NOT return Included here (key was never inserted into ns_b).
        // Current code returns Included -> this test FAILS until you fix the design.
        let status = Hubt::verify(&forged, Some(ns_b), k0, v0);
        assert_ne!(
            status,
            VerifyStatus::Included,
            "BUG: proof from namespace A can be replayed as Included in namespace B"
        );
    }

    #[test]
    fn attack_proof_path_bitflip_can_turn_invalid_into_false_nonexistence() {
        let mut hubt = Hubt::new();

        let k0 = b"key0".to_vec();
        let v0 = b"val0".to_vec();
        let k1 = b"key1".to_vec();
        let v1 = b"val1".to_vec();

        insert_two_none(&mut hubt, &k0, &v0, &k1, &v1);

        // Get a valid proof for k0
        let proof0 = hubt.prove(None, k0.clone());
        assert!(Hubt::verify_integrity(&proof0));
        assert!(!proof0.nodes.is_empty(), "two-leaf tree should have at least one proof node");

        // Baseline: using k0's proof to verify k1 should be Invalid
        assert_eq!(
            Hubt::verify(&proof0, None, k1.clone(), v1.clone()),
            VerifyStatus::Invalid
        );

        // Forge: flip a high-level bit that is not authenticated by any proof node (bit 0).
        // This is still "sanitized": it's just a different path value.
        let mut forged = proof0.clone();
        flip_bit(&mut forged.path, 0);

        // Correct behavior: this should still be Invalid (it is a proof for the wrong leaf),
        // and MUST NOT become NonExistence for an actually included key.
        //
        // Current code returns NonExistence -> this test FAILS until you fix the design.
        let status = Hubt::verify(&forged, None, k1, v1);
        assert_eq!(
            status,
            VerifyStatus::Invalid,
            "BUG: path malleability + div_len logic allows false NonExistence"
        );
    }

    #[test]
    fn attack_len_malleability_can_turn_invalid_into_false_nonexistence() {
        let mut hubt = Hubt::new();

        let k0 = b"key0".to_vec();
        let v0 = b"val0".to_vec();
        let k1 = b"key1".to_vec();
        let v1 = b"val1".to_vec();

        insert_two_none(&mut hubt, &k0, &v0, &k1, &v1);

        let proof0 = hubt.prove(None, k0.clone());
        assert!(Hubt::verify_integrity(&proof0));
        assert!(!proof0.nodes.is_empty(), "two-leaf tree should have at least one proof node");

        // Baseline: wrong leaf proof for an existing key should be Invalid.
        assert_eq!(
            Hubt::verify(&proof0, None, k1.clone(), v1.clone()),
            VerifyStatus::Invalid
        );

        // Find divergence depth between target_path(k1) and proof.path(k0)
        let target_path = compute_namespace_path(None, k1.as_slice());
        let (_, div_len) = lcp_be(&target_path, &proof0.path);

        // Find the proof node at that divergence depth
        let idx = proof0
            .nodes
            .iter()
            .position(|n| n.len == div_len)
            .expect("expected divergence node to appear in proof for a two-leaf tree");

        // Forge: move that node.len to a different value while still passing verify_integrity() checks.
        let mut forged = proof0.clone();
        let direction = forged.nodes[idx].direction;

        // Pick any len != div_len such that direction != bit(proof.path, len).
        // This keeps inputs "sanitized": len<256, still strictly decreasing (single node case).
        let mut new_len: Option<u16> = None;
        for cand in 0u16..256u16 {
            if cand == div_len {
                continue;
            }
            if get_bit_be(&forged.path, cand) != direction {
                new_len = Some(cand);
                break;
            }
        }
        let new_len = new_len.expect("should always find an alternate len");
        forged.nodes[idx].len = new_len;

        // Correct behavior: still Invalid (wrong proof), MUST NOT turn into NonExistence.
        //
        // Current code returns NonExistence -> this test FAILS until you fix the design.
        let status = Hubt::verify(&forged, None, k1, v1);
        assert_eq!(
            status,
            VerifyStatus::Invalid,
            "BUG: len malleability makes verifier fall through to NonExistence"
        );
    }
}
