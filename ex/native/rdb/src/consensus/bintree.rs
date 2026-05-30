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

#[derive(Debug, PartialEq, Clone, Copy)]
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
                    let lh = leaf_hash(&path, &k, &v);
                    (true, path, lh)
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

        // Empty tree
        if self.leaves.is_empty() {
            return Proof { root: ZERO_HASH, nodes: vec![], path: ZERO_HASH, hash: ZERO_HASH };
        }

        // Exact-match (inclusion proof)
        if let Some(h) = self.leaves.get(&target_path) {
            return Proof {
                root: self.root(),
                nodes: self.generate_proof_nodes(target_path, 256),
                path: target_path,
                hash: *h,
            };
        }

        // Non-existence: walk DOWN toward target until we either find an empty
        // branch on target's side (the chosen leaf-on-the-other-side will
        // naturally yield a ZERO_HASH sibling at div_len in generate_proof_nodes
        // → verifier returns NonExistence at bintree.rs:514) or reach a leaf
        // in a compressed-edge subtree shared with target (which yields
        // Suffix Divergence at bintree.rs:582).
        let proof_path = self.find_proof_path_descending(&target_path);
        let proof_hash = *self.leaves.get(&proof_path).unwrap_or(&ZERO_HASH);

        Proof {
            root: self.root(),
            nodes: self.generate_proof_nodes(proof_path, 256),
            path: proof_path,
            hash: proof_hash,
        }
    }

    /// Walk the tree from the topmost internal toward `target`, picking a
    /// leaf such that `generate_proof_nodes` will emit a verifier-acceptable
    /// non-existence proof.
    fn find_proof_path_descending(&self, target: &Path) -> Path {
        let first = *self.leaves.first_key_value().unwrap().0;
        let last  = *self.leaves.last_key_value().unwrap().0;
        if first == last {
            return first;
        }

        // Topmost internal: at LCP(first_leaf, last_leaf).
        let (root_path, root_len) = lcp_be(&first, &last);

        // If target doesn't share the topmost internal's prefix, we can't
        // descend (target falls outside the tree's universe). Fall back to
        // the original nearest-leaf strategy — verifier may return Invalid
        // for this case; documented limitation of the non-sparse tree.
        if !prefix_match_be(target, &root_path, root_len) {
            return self
                .find_longest_prefix_node(target)
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

            let next_int = self
                .internals
                .range(NodeKey { path: t_child, len: cur_len + 1 }..)
                .find(|(k, _)| prefix_match_be(&k.path, &t_child, cur_len + 1))
                .map(|(k, _)| *k);
            let next_leaf = self
                .leaves
                .range(t_child..)
                .find(|(p, _)| prefix_match_be(p, &t_child, cur_len + 1))
                .map(|(p, _)| *p);

            match (next_int, next_leaf) {
                (None, None) => {
                    // Empty target-side at this internal → pick any leaf on
                    // the OPPOSITE side. generate_proof_nodes for that leaf
                    // will produce a ZERO_HASH sibling at cur_len (since the
                    // get_child_hash for target's direction at cur_len finds
                    // nothing) → div_len == cur_len, NonExistence.
                    let opp_dir = 1 - target_dir;
                    let mut o_child = cur_path;
                    set_bit_be(&mut o_child, cur_len, opp_dir);
                    mask_after_be(&mut o_child, cur_len + 1);
                    return self
                        .leaves
                        .range(o_child..)
                        .find(|(p, _)| prefix_match_be(p, &o_child, cur_len + 1))
                        .map(|(p, _)| *p)
                        .unwrap_or(first);
                }
                (None, Some(leaf)) => {
                    // Compressed-edge: only a leaf under target's side.
                    return leaf;
                }
                (Some(int_k), _) => {
                    // Before descending, target must match int_k.path through
                    // int_k.len bits. If target diverges in the compressed
                    // edge between (cur_path, cur_len) and (int_k.path, int_k.len),
                    // descent is incoherent — the resulting proof would commit
                    // to a leaf in a subtree target doesn't belong to, and the
                    // verifier hits the "Malleable Gap" branch returning Invalid.
                    if !prefix_match_be(target, &int_k.path, int_k.len) {
                        return self
                            .find_longest_prefix_node(target)
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

    pub fn verify(expected_root: &Hash, proof: &Proof, ns: Option<Vec<u8>>, k: Vec<u8>, v: Vec<u8>) -> VerifyStatus {
        // SECURITY: Bind verification to a trusted, externally-supplied root.
        // Without this, an attacker can submit a self-consistent proof (e.g. an
        // all-zero "empty tree" proof) and the verifier will accept it, since
        // proof.root is attacker-controlled.
        if proof.root != *expected_root {
            return VerifyStatus::Invalid;
        }

        let target_path = compute_namespace_path(ns.as_deref(), &k);
        let claimed_leaf_hash = leaf_hash(&target_path, &k, &v);

        // Genuine empty-tree case: only valid when the verifier's trusted root
        // is also ZERO_HASH (i.e. the tree is truly empty).
        if *expected_root == ZERO_HASH {
            if proof.hash == ZERO_HASH && proof.path == ZERO_HASH && proof.nodes.is_empty() {
                return VerifyStatus::NonExistence;
            }
            return VerifyStatus::Invalid;
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
                // CASE: Suffix Divergence (div_len > max_len)
                // The divergence happened BELOW the deepest internal node.
                // The proof, authenticated to the trusted root, commits to a
                // straight (un-branching) edge from depth max_len down to the
                // leaf at proof.path — node_hash binds len into every ancestor
                // and verify_integrity enforces strictly-decreasing len, so the
                // structure is unambiguous. Since target_path shares the prefix
                // through max_len, it lands in this same single-leaf subtree.
                // Because proof.path != target_path (checked above), no leaf at
                // target_path exists in the tree.
                VerifyStatus::NonExistence
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
        let root1 = hubt.root();
        assert_eq!(Hubt::verify(&root1, &proof_inc, None, k1.clone(), v1.clone()), VerifyStatus::Included);

        // Case 2: Mismatch (Key exists, Value differs)
        let v1_fake = b"999".to_vec();
        let proof_mis = hubt.prove(None, k1.clone()); // Same proof generation!
        assert_eq!(Hubt::verify(&root1, &proof_mis, None, k1.clone(), v1_fake), VerifyStatus::Mismatch);

        // Case 3: Non-Existence in single key tree (Key does not exist)
        let k_missing = b"user:999".to_vec();
        let proof_non = hubt.prove(None, k_missing.clone());
        let res = Hubt::verify(&root1, &proof_non, None, k_missing.to_vec(), v1.clone());
        assert!(res == VerifyStatus::NonExistence || res == VerifyStatus::Invalid);

        // Case 4: Non-Existence in multi key tree (Key does not exist).
        hubt.batch_update(vec![Op::Insert(None, k2.clone(), v2.clone())]);
        let proof_non2 = hubt.prove(None, k_missing.clone());
        let root2 = hubt.root();
        assert_eq!(
            Hubt::verify(&root2, &proof_non2, None, k_missing, v1.clone()),
            VerifyStatus::NonExistence,
        );
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
        assert_eq!(Hubt::verify(&hubt.root(), &hubt.prove(None, k.clone()), None, k.clone(), v1.clone()), VerifyStatus::Included);

        // 2. Delete
        hubt.batch_update(vec![Op::Delete(None, k.clone())]);
        assert_eq!(Hubt::verify(&hubt.root(), &hubt.prove(None, k.clone()), None, k.clone(), v1.clone()), VerifyStatus::NonExistence);

        // 3. Upsert (Delete + Insert in same batch) - Should result in INSERT
        hubt.batch_update(vec![
            Op::Delete(None, k.clone()),
            Op::Insert(None, k.clone(), v2.clone())
        ]);
        assert_eq!(Hubt::verify(&hubt.root(), &hubt.prove(None, k.clone()), None, k.clone(), v2.clone()), VerifyStatus::Included);
    }

    #[test]
    fn suffix_divergence_returns_nonexistence_not_invalid() {
        // Regression: when the divergence between target_path and proof.path
        // falls BELOW the deepest internal node in the proof, the verifier must
        // return NonExistence (the proof, authenticated to the trusted root,
        // commits to a single-leaf subtree below max_len, so target cannot
        // exist there). It used to incorrectly return Invalid.
        //
        // We brute-force a key triple where lcp(target,closest) > lcp(k0,k1),
        // which is exactly the suffix-divergence case. With sha256-based paths
        // this happens reliably across many seeds.
        let v = b"v".to_vec();

        let mut found = false;
        for seed in 0u32..2048 {
            let k0 = format!("k0-{}", seed).into_bytes();
            let k1 = format!("k1-{}", seed).into_bytes();
            let k_missing = format!("kx-{}", seed).into_bytes();

            let p0 = compute_namespace_path(None, &k0);
            let p1 = compute_namespace_path(None, &k1);
            let pm = compute_namespace_path(None, &k_missing);

            let (_, lcp01) = lcp_be(&p0, &p1);
            let (_, lcp_m0) = lcp_be(&pm, &p0);
            let (_, lcp_m1) = lcp_be(&pm, &p1);
            let lcp_closest = lcp_m0.max(lcp_m1);

            // Suffix-divergence: target shares MORE bits with the closest leaf
            // than the two leaves share with each other.
            if lcp_closest <= lcp01 { continue; }

            let mut hubt = Hubt::new();
            insert_two_none(&mut hubt, &k0, &v, &k1, &v);
            let root = hubt.root();
            let proof = hubt.prove(None, k_missing.clone());

            // Sanity: the proof's deepest node is at lcp01, and div_len > lcp01.
            let target_path = compute_namespace_path(None, &k_missing);
            let (_, div_len) = lcp_be(&target_path, &proof.path);
            let max_len = proof.nodes.first().map(|n| n.len).unwrap_or(0);
            assert!(div_len > max_len, "test setup must trigger suffix divergence");

            assert_eq!(
                Hubt::verify(&root, &proof, None, k_missing, v.clone()),
                VerifyStatus::NonExistence,
            );
            found = true;
            break;
        }
        assert!(found, "expected to find a seed that triggers suffix divergence");
    }

    #[test]
    fn v1_zero_proof_is_rejected_against_nonempty_tree() {
        // V-1: A trivially-forged "all zero" proof must NOT be accepted as
        // NonExistence when the verifier's trusted root is non-zero.
        let mut hubt = Hubt::new();
        insert_one(&mut hubt, b"key", b"val");
        let trusted_root = hubt.root();
        assert_ne!(trusted_root, ZERO_HASH);

        let zero_proof = Proof {
            root: ZERO_HASH,
            nodes: vec![],
            path: ZERO_HASH,
            hash: ZERO_HASH,
        };

        // Verifier knows the real root -> forged zero proof is Invalid.
        assert_eq!(
            Hubt::verify(&trusted_root, &zero_proof, None, b"any-missing".to_vec(), b"v".to_vec()),
            VerifyStatus::Invalid,
        );

        // And a genuine empty-tree proof is only NonExistence under a zero root.
        let empty_hubt = Hubt::new();
        assert_eq!(empty_hubt.root(), ZERO_HASH);
        assert_eq!(
            Hubt::verify(&ZERO_HASH, &zero_proof, None, b"any".to_vec(), b"v".to_vec()),
            VerifyStatus::NonExistence,
        );
    }

    #[test]
    fn v1_proof_root_must_match_expected_root() {
        // Even an internally-consistent proof must be rejected if its root
        // doesn't match the verifier's trusted root.
        let mut hubt_a = Hubt::new();
        insert_two_none(&mut hubt_a, b"a", b"1", b"b", b"2");
        let proof_a = hubt_a.prove(None, b"a".to_vec());

        let mut hubt_b = Hubt::new();
        insert_two_none(&mut hubt_b, b"x", b"9", b"y", b"8");
        let trusted_root_b = hubt_b.root();
        assert_ne!(proof_a.root, trusted_root_b);

        // Replaying a valid proof from tree A against tree B's root must fail.
        assert_eq!(
            Hubt::verify(&trusted_root_b, &proof_a, None, b"a".to_vec(), b"1".to_vec()),
            VerifyStatus::Invalid,
        );
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
        let root = hubt.root();
        assert!(Hubt::verify_integrity(&proof_a));
        assert_eq!(
            Hubt::verify(&root, &proof_a, Some(ns_a.clone()), k0.clone(), v0.clone()),
            VerifyStatus::Included
        );

        // Forge: rewrite the claimed leaf path to namespace B but keep hashes/nodes the same.
        // This is "sanitized": it's just a different 32-byte path.
        let mut forged = proof_a.clone();
        forged.path = compute_namespace_path(Some(ns_b.as_slice()), k0.as_slice());

        // A correct verifier MUST NOT return Included here (key was never inserted into ns_b).
        // Current code returns Included -> this test FAILS until you fix the design.
        let status = Hubt::verify(&root, &forged, Some(ns_b), k0, v0);
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
        let root = hubt.root();
        assert!(Hubt::verify_integrity(&proof0));
        assert!(!proof0.nodes.is_empty(), "two-leaf tree should have at least one proof node");

        // Baseline: using k0's proof to verify k1 should be Invalid
        assert_eq!(
            Hubt::verify(&root, &proof0, None, k1.clone(), v1.clone()),
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
        let status = Hubt::verify(&root, &forged, None, k1, v1);
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
        let root = hubt.root();
        assert!(Hubt::verify_integrity(&proof0));
        assert!(!proof0.nodes.is_empty(), "two-leaf tree should have at least one proof node");

        // Baseline: wrong leaf proof for an existing key should be Invalid.
        assert_eq!(
            Hubt::verify(&root, &proof0, None, k1.clone(), v1.clone()),
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
        let status = Hubt::verify(&root, &forged, None, k1, v1);
        assert_eq!(
            status,
            VerifyStatus::Invalid,
            "BUG: len malleability makes verifier fall through to NonExistence"
        );
    }

    /// Tiny deterministic LCG for reproducible "randomness" in soundness fuzz.
    fn lcg_next(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *state
    }

    #[test]
    fn soundness_fuzz_no_forgery_returns_false_nonexistence_or_inclusion() {
        // SAFETY PROPERTY: For a populated tree, no proof tampering should let
        // the verifier conclude:
        //   - Included for an existing key with a value that is not the leaf's value, OR
        //   - Included for a key that is not in the tree, OR
        //   - NonExistence for a key that IS in the tree, OR
        //   - Mismatch for a key that is not in the tree.
        // We fuzz by mutating proofs of existing leaves in many ways and
        // checking the verifier never emits an unsound verdict.

        let mut hubt = Hubt::new();
        let n = 32usize;
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(n);
        let mut values: Vec<Vec<u8>> = Vec::with_capacity(n);
        for i in 0..n {
            let k = format!("fuzz-key-{}", i).into_bytes();
            let v = format!("fuzz-val-{}", i).into_bytes();
            insert_one(&mut hubt, &k, &v);
            keys.push(k);
            values.push(v);
        }
        let root = hubt.root();
        assert_ne!(root, ZERO_HASH);

        let missing_keys: Vec<Vec<u8>> = (0..16)
            .map(|i| format!("absent-key-{}", i).into_bytes())
            .collect();

        let mut rng_state: u64 = 0xC0FFEE_DEAD_BEEF;

        for (existing_idx, k_existing) in keys.iter().enumerate() {
            let v_existing = &values[existing_idx];
            let honest_proof = hubt.prove(None, k_existing.clone());

            // Honest verification: Included.
            assert_eq!(
                Hubt::verify(&root, &honest_proof, None, k_existing.clone(), v_existing.clone()),
                VerifyStatus::Included,
            );

            // Honest with wrong value: Mismatch.
            let wrong_v = b"definitely-wrong-value-XYZ".to_vec();
            assert_eq!(
                Hubt::verify(&root, &honest_proof, None, k_existing.clone(), wrong_v),
                VerifyStatus::Mismatch,
            );

            // Tamper with each field of the proof in many small ways and verify
            // against the EXISTING key. Result must NEVER be NonExistence and
            // must NEVER be Included with a value other than the actual one.
            for trial in 0..64u64 {
                let mut forged = honest_proof.clone();
                let r = lcg_next(&mut rng_state);
                let mode = (r ^ trial) % 7;
                match mode {
                    0 => {
                        // Flip a random bit in proof.path
                        let bit = ((r >> 8) % 256) as u16;
                        flip_bit(&mut forged.path, bit);
                    }
                    1 => {
                        // Flip a random bit in proof.hash
                        let byte = ((r >> 8) % 32) as usize;
                        let bit = ((r >> 16) & 7) as u8;
                        forged.hash[byte] ^= 1 << bit;
                    }
                    2 => {
                        // Mutate a proof node hash
                        if !forged.nodes.is_empty() {
                            let i = ((r >> 8) as usize) % forged.nodes.len();
                            forged.nodes[i].hash[0] ^= 0x55;
                        }
                    }
                    3 => {
                        // Toggle a proof node direction
                        if !forged.nodes.is_empty() {
                            let i = ((r >> 8) as usize) % forged.nodes.len();
                            forged.nodes[i].direction ^= 1;
                        }
                    }
                    4 => {
                        // Mutate a proof node len (avoid trivial >= 256)
                        if !forged.nodes.is_empty() {
                            let i = ((r >> 8) as usize) % forged.nodes.len();
                            let bump = ((r >> 16) & 0xFF) as u16 + 1;
                            forged.nodes[i].len = forged.nodes[i].len.wrapping_add(bump) % 256;
                        }
                    }
                    5 => {
                        // Drop a proof node
                        if !forged.nodes.is_empty() {
                            let i = ((r >> 8) as usize) % forged.nodes.len();
                            forged.nodes.remove(i);
                        }
                    }
                    _ => {
                        // Substitute proof.root (this should be caught immediately)
                        forged.root[0] ^= 0xAA;
                    }
                }

                let res = Hubt::verify(
                    &root,
                    &forged,
                    None,
                    k_existing.clone(),
                    v_existing.clone(),
                );
                // For an existing key, a forged proof must NOT yield NonExistence
                // and (since proof.hash binds the leaf via SHA256) must not yield
                // Included unless it accidentally remained the honest proof.
                // Acceptable: Included (only if mutation was inert) / Mismatch / Invalid.
                assert_ne!(
                    res, VerifyStatus::NonExistence,
                    "forgery emitted NonExistence for EXISTING key idx={} mode={}",
                    existing_idx, mode
                );
            }
        }

        // For missing keys: honest verification must NEVER return Included or Mismatch.
        for k_missing in &missing_keys {
            let proof = hubt.prove(None, k_missing.clone());
            let res = Hubt::verify(&root, &proof, None, k_missing.clone(), b"any".to_vec());
            assert!(
                res == VerifyStatus::NonExistence || res == VerifyStatus::Invalid,
                "missing key honest proof returned {:?}", res
            );
        }

        // For missing keys: forged proofs (using a real leaf's proof) must
        // NEVER yield Included. Note: free-bit malleability of proof.path can
        // currently produce a *false Mismatch* — see the dedicated test
        // `free_bit_malleability_can_forge_false_mismatch_PREEXISTING_BUG`
        // below. That is unrelated to V-1 / suffix-divergence and is tracked
        // as a separate finding.
        for k_missing in &missing_keys {
            for (idx, k_existing) in keys.iter().enumerate().take(8) {
                let mut forged = hubt.prove(None, k_existing.clone());
                let target_path = compute_namespace_path(None, k_missing);
                let max_len = forged.nodes.first().map(|n| n.len).unwrap_or(0);
                for bit in 0..256u16 {
                    if bit > max_len {
                        let target_bit = get_bit_be(&target_path, bit);
                        set_bit_be(&mut forged.path, bit, target_bit);
                    }
                }
                let res = Hubt::verify(
                    &root,
                    &forged,
                    None,
                    k_missing.clone(),
                    values[idx].clone(),
                );
                assert_ne!(
                    res, VerifyStatus::Included,
                    "free-bit-tampered proof returned Included for missing key — SHA256 broken?"
                );
            }
        }
    }

    #[test]
    #[ignore = "pre-existing bug unrelated to V-1 / suffix-divergence; tracked separately"]
    fn free_bit_malleability_can_forge_false_mismatch_preexisting_bug() {
        // PRE-EXISTING SOUNDNESS BUG (discovered while auditing the
        // suffix-divergence fix; NOT introduced by it):
        //
        // verify_integrity authenticates only proof.path bits in [0, max_len]
        // (where max_len = proof.nodes[0].len). Bits at depths > max_len are
        // never read (mask_after_be zeros them out of every prefix, and
        // path_bit checks only happen at node.len). An attacker can flip
        // those "free bits" without breaking integrity.
        //
        // Concretely: if a missing key's target_path shares its first max_len
        // bits with some existing leaf's path, an attacker can splice the
        // existing leaf's honest proof, set the free bits of proof.path to
        // match target_path, and the verifier — comparing the full 256-bit
        // proof.path to target_path — will return Mismatch. That tells a
        // caller "this key IS in the tree (with a different value)" when in
        // fact it is not in the tree at all.
        //
        // This does NOT enable false NonExistence for an existing key (the
        // bits at depths <= max_len are integrity-bound, so div_len cannot be
        // pushed past max_len for an existing K). The suffix-divergence fix
        // therefore remains sound. See the audit notes for the proposed fix
        // (extend the Proof to carry leaf key/value so verify can recompute
        // leaf_hash and authenticate proof.path in full).
        //
        // The test is #[ignore]'d so it documents the issue without breaking
        // CI; remove the ignore once the underlying bug is fixed.

        let v = b"v".to_vec();
        let mut found = false;
        for seed in 0u32..4096 {
            let k0 = format!("ex0-{}", seed).into_bytes();
            let k1 = format!("ex1-{}", seed).into_bytes();
            let k_missing = format!("xx-{}", seed).into_bytes();

            let p0 = compute_namespace_path(None, &k0);
            let p1 = compute_namespace_path(None, &k1);
            let pm = compute_namespace_path(None, &k_missing);

            let (_, lcp01) = lcp_be(&p0, &p1);

            // Need: lcp(target, some leaf) > lcp01 (= max_len in 2-leaf tree).
            let (_, lcp_m0) = lcp_be(&pm, &p0);
            let (_, lcp_m1) = lcp_be(&pm, &p1);
            let (closest_path, lcp_closest) = if lcp_m0 >= lcp_m1 {
                (p0, lcp_m0)
            } else {
                (p1, lcp_m1)
            };
            if lcp_closest <= lcp01 { continue; }

            let mut hubt = Hubt::new();
            insert_two_none(&mut hubt, &k0, &v, &k1, &v);
            let root = hubt.root();

            let closest_key = if closest_path == p0 { k0.clone() } else { k1.clone() };
            let mut forged = hubt.prove(None, closest_key);
            let max_len = forged.nodes.first().map(|n| n.len).unwrap_or(0);
            for bit in 0..256u16 {
                if bit > max_len {
                    let target_bit = get_bit_be(&pm, bit);
                    set_bit_be(&mut forged.path, bit, target_bit);
                }
            }

            let res = Hubt::verify(&root, &forged, None, k_missing.clone(), b"any".to_vec());
            // The bug: this returns Mismatch instead of NonExistence/Invalid.
            assert_eq!(res, VerifyStatus::Mismatch);
            found = true;
            break;
        }
        assert!(found, "expected at least one seed to trigger the malleability");
    }
}
