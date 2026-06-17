//! Compact Sparse Merkle Tree — SOTA implementation incorporating:
//! - **One-Phase Batch Update** (arXiv 2310.13328): sorted-partition descent,
//!   each internal node hashed exactly once per batch regardless of how many
//!   updates fall under it. O(K log K + tree_depth) total work, not O(K log N).
//! - **Single-leaf-subtree collapse** (Jellyfish Merkle, Aergo SMT): compressed
//!   edges, leaves at compressed-edge terminuses don't require hashing through
//!   200+ empty levels.
//! - **Penumbra-style in-place mutate-within-batch**: a key written multiple
//!   times in the same batch costs one hash, not N.
//! - **Pre-computed EMPTY[d]** constants for empty subtree hashes (one-time cost).
//! - **Hot-namespace locality**: when all updates share a common prefix (hot
//!   contract), the descent collapses the shared-prefix spine and recurses
//!   only into the changed subtree.

use crate::consensus::hbsmt_common::{
    get_bit_be, mask_after_be, set_bit_be, Hash, Op, Path,
};
use crate::consensus::hbsmt_common::{
    compute_namespace_path_hbsmt,
    child_prefixes, identity_hash, lcp_depth, leaf_hash_from_components, lift_single_leaf,
    make_empties, subtree_range, value_hash, HbsmtProof, HbsmtTerminus,
};
use std::collections::BTreeMap;
use rustc_hash::FxHashMap;

// Re-export so `smt::hbsmt_node_hash` (the legacy import path used by smt_rdb.rs
// and other call sites) keeps working after the move into smt_common.
pub use crate::consensus::hbsmt_common::hbsmt_node_hash;

/// Compact SMT.
///
/// Storage layout:
/// - `leaves`: `Path -> (identity_hash, value_hash)` — the two components
///   of the leaf hash. The combined `leaf_hash = sha256("LEAF" || id || val)`
///   gets hashed up the tree; the components are exposed in proofs so the
///   verifier can distinguish identity-mismatch from value-mismatch.
/// - `splits`: real branching internal nodes only (where both children are
///   non-empty). Keyed by `(masked_prefix, depth)`. Each entry stores its
///   already-combined hash (the node_hash of its two children).
pub struct Hbsmt {
    leaves: BTreeMap<Path, (Hash, Hash)>,
    /// FxHashMap (rustc-hash) — ~2-3× faster than std::collections::HashMap
    /// for fixed-size byte keys. Point-lookup only.
    splits: FxHashMap<(Path, u16), Hash>,
    empties: [Hash; 257],
    /// Cached root hash; `None` means tree was modified since last `root()`.
    root_cache: Option<Hash>,
}

impl Hbsmt {
    pub fn new() -> Self {
        let empties = make_empties();
        Hbsmt {
            leaves: BTreeMap::new(),
            splits: FxHashMap::default(),
            empties,
            root_cache: Some(empties[0]),
        }
    }

    pub fn root(&mut self) -> Hash {
        if let Some(r) = self.root_cache { return r; }
        let r = self.subtree_hash([0u8; 32], 0);
        self.root_cache = Some(r);
        r
    }

    pub fn leaf_count(&self) -> usize { self.leaves.len() }
    pub fn split_count(&self) -> usize { self.splits.len() }

    /// SOTA batch update. One sorted descent, hashes each touched node once.
    pub fn batch_update(&mut self, ops: Vec<Op>) {
        if ops.is_empty() { return; }

        // 1. Resolve every op to its path; collapse multiple writes to the same
        //    key. Each leaf stored as (identity_hash, value_hash).
        let mut latest: BTreeMap<Path, Option<(Hash, Hash)>> = BTreeMap::new();
        for op in ops {
            match op {
                Op::Insert(ns, k, v) => {
                    let path = compute_namespace_path_hbsmt(ns.as_deref().unwrap_or(b""), &k);
                    let id = identity_hash(&path, ns.as_deref().unwrap_or(b""), &k);
                    let val = value_hash(&v);
                    latest.insert(path, Some((id, val)));
                }
                Op::Delete(ns, k) => {
                    let path = compute_namespace_path_hbsmt(ns.as_deref().unwrap_or(b""), &k);
                    latest.insert(path, None);
                }
            }
        }

        // 2. Apply leaf changes. Track which paths actually changed value
        //    (or appeared / disappeared) — those need recomputation.
        let mut dirty: Vec<Path> = Vec::with_capacity(latest.len());
        for (path, val) in latest {
            match val {
                Some(pair) => {
                    let prev = self.leaves.insert(path, pair);
                    if prev != Some(pair) { dirty.push(path); }
                }
                None => {
                    if self.leaves.remove(&path).is_some() {
                        dirty.push(path);
                    }
                }
            }
        }
        if dirty.is_empty() { return; }
        debug_assert!(dirty.windows(2).all(|w| w[0] < w[1]), "dirty must be sorted");

        // 3. Single descent: partition sorted dirty paths at each bit; recompute
        //    only the spanning subtree. Returns the new root.
        let new_root = self.descend_and_rehash([0u8; 32], 0, &dirty);
        self.root_cache = Some(new_root);
    }

    /// Produce a proof for `(ns, key)` against the current root. The returned
    /// proof can be checked with [`smt_common::verify_hbsmt`] and resolves to
    /// `Included`, `Mismatch`, or `NonExistence` depending on what the verifier
    /// is asked to claim about (ns, key, value).
    pub fn prove(&mut self, ns: Option<&[u8]>, k: &[u8]) -> HbsmtProof {
        let target = compute_namespace_path_hbsmt(ns.unwrap_or(b""), k);
        let mut siblings = Vec::new();
        let terminus = self.descend_for_proof(&target, [0u8; 32], 0, &mut siblings);
        HbsmtProof { siblings, terminus }
    }

    /// Descend toward `target`, gathering off-path sibling hashes until the
    /// subtree is either empty or contains a single leaf.
    fn descend_for_proof(&mut self, target: &Path, prefix: Path, depth: u16,
                         siblings: &mut Vec<Hash>) -> HbsmtTerminus {
        if depth == 256 {
            return match self.leaves.get(&prefix) {
                Some(&(id, val)) => HbsmtTerminus::Leaf {
                    path: prefix, identity_hash: id, value_hash: val,
                },
                None => HbsmtTerminus::Empty,
            };
        }
        let (lo, hi) = subtree_range(&prefix, depth);
        let mut leaves_in = self.leaves.range(lo..=hi);
        let first = leaves_in.next();
        let second = leaves_in.next();
        match (first, second) {
            (None, _) => HbsmtTerminus::Empty,
            (Some((p, (id, val))), None) => HbsmtTerminus::Leaf {
                path: *p, identity_hash: *id, value_hash: *val,
            },
            _ => {
                // Bifurcate: descend on the target's side; record the off-path
                // subtree's hash as the sibling at this depth.
                let bit = get_bit_be(target, depth);
                let (lp, rp) = child_prefixes(&prefix, depth);
                let (target_prefix, sibling_prefix) = if bit == 0 { (lp, rp) } else { (rp, lp) };
                let sibling_hash = self.subtree_hash(sibling_prefix, depth + 1);
                siblings.push(sibling_hash);
                self.descend_for_proof(target, target_prefix, depth + 1, siblings)
            }
        }
    }

    /// Walk down partitioning `dirty` by the bit at `depth`. Three short-circuits:
    ///   1. `dirty.is_empty()` — return cached or compute clean subtree hash.
    ///   2. `dirty.len()==1` AND subtree has ≤1 leaf — skip the rest of the
    ///      depth-by-depth descent and call `lift_single_leaf` directly. This
    ///      avoids the ~250-level walk through a compressed edge.
    ///   3. All dirty paths share a common prefix past `depth` — jump straight
    ///      to LCP depth (handles hot-namespace concentration without walking
    ///      every bit of the shared namespace prefix).
    fn descend_and_rehash(&mut self, prefix: Path, depth: u16, dirty: &[Path]) -> Hash {
        if dirty.is_empty() {
            return self.subtree_hash(prefix, depth);
        }
        if depth == 256 {
            return match self.leaves.get(&prefix) {
                Some(&(id, val)) => leaf_hash_from_components(&id, &val),
                None => self.empties[256],
            };
        }

        // ----- Short-circuit 2: compressed-edge case -----
        if dirty.len() == 1 {
            let (lo, hi) = subtree_range(&prefix, depth);
            let mut leaves_in = self.leaves.range(lo..=hi);
            let first = leaves_in.next();
            let second = leaves_in.next();
            match (first, second) {
                (None, _) => {
                    self.splits.remove(&(prefix, depth));
                    return self.empties[depth as usize];
                }
                (Some((p, (id, val))), None) => {
                    self.splits.remove(&(prefix, depth));
                    let lh = leaf_hash_from_components(id, val);
                    return lift_single_leaf(lh, p, depth, &self.empties);
                }
                _ => { /* two+ leaves: fall through */ }
            }
        }

        // ----- Short-circuit 3: jump to LCP of all dirty paths (flattened) -----
        if dirty.len() >= 2 {
            let lcp_d = lcp_depth(&dirty[0], &dirty[dirty.len() - 1]);
            if lcp_d > depth {
                // 1. Recurse to compute dirty-side hash at lcp_d directly.
                let mut tp = dirty[0];
                mask_after_be(&mut tp, lcp_d);
                let mut h = self.descend_and_rehash(tp, lcp_d, dirty);
                // 2. Lift h back up through the spine, hashing in clean siblings.
                //    At each level d in (depth..lcp_d).rev(), the dirty side is
                //    bit get_bit_be(dirty[0], d) and the other side is clean.
                for d in (depth..lcp_d).rev() {
                    let target_bit = get_bit_be(&dirty[0], d);
                    let mut op_prefix = dirty[0];
                    set_bit_be(&mut op_prefix, d, 1 - target_bit);
                    mask_after_be(&mut op_prefix, d + 1);
                    let other_h = self.subtree_hash(op_prefix, d + 1);

                    let empty_next = self.empties[(d + 1) as usize];
                    let (l, r) = if target_bit == 0 { (h, other_h) } else { (other_h, h) };

                    // Cache this level's split if it's a real branching.
                    let mut my_prefix = dirty[0];
                    mask_after_be(&mut my_prefix, d);
                    h = if l == empty_next && r == empty_next {
                        self.splits.remove(&(my_prefix, d));
                        self.empties[d as usize]
                    } else if l == empty_next || r == empty_next {
                        self.splits.remove(&(my_prefix, d));
                        hbsmt_node_hash(&l, &r)
                    } else {
                        let h_new = hbsmt_node_hash(&l, &r);
                        self.splits.insert((my_prefix, d), h_new);
                        h_new
                    };
                }
                return h;
            }
        }

        // Standard case: bifurcate.
        let split = dirty.partition_point(|p| get_bit_be(p, depth) == 0);
        let (left_dirty, right_dirty) = dirty.split_at(split);

        let mut lp = prefix;
        set_bit_be(&mut lp, depth, 0);
        mask_after_be(&mut lp, depth + 1);
        let mut rp = prefix;
        set_bit_be(&mut rp, depth, 1);
        mask_after_be(&mut rp, depth + 1);

        let l = self.descend_and_rehash(lp, depth + 1, left_dirty);
        let r = self.descend_and_rehash(rp, depth + 1, right_dirty);

        let empty_next = self.empties[(depth + 1) as usize];
        let h = if l == empty_next && r == empty_next {
            self.splits.remove(&(prefix, depth));
            self.empties[depth as usize]
        } else if l == empty_next || r == empty_next {
            self.splits.remove(&(prefix, depth));
            hbsmt_node_hash(&l, &r)
        } else {
            let h = hbsmt_node_hash(&l, &r);
            self.splits.insert((prefix, depth), h);
            h
        };
        h
    }

    /// Compute the hash of a subtree that has no dirty leaves (used by
    /// `descend_and_rehash` when one side of a partition is empty).
    ///
    /// **Correctness note**: we MUST check the leaf range before consulting
    /// `splits`. After a previous batch collapsed a subtree (via
    /// `lift_single_leaf`), splits stored at internal bifurcation points
    /// inside that subtree become stale. We can't proactively walk them all
    /// in O(1), so we ignore the cache whenever the subtree provably has
    /// ≤1 leaves — and clean up any stale entry at this depth.
    fn subtree_hash(&mut self, prefix: Path, depth: u16) -> Hash {
        if depth == 256 {
            return match self.leaves.get(&prefix) {
                Some(&(id, val)) => leaf_hash_from_components(&id, &val),
                None => self.empties[256],
            };
        }

        let (lo, hi) = subtree_range(&prefix, depth);
        let mut leaves_in = self.leaves.range(lo..=hi);
        let first = leaves_in.next();
        let any_more = leaves_in.next().is_some();

        match (first, any_more) {
            (None, _) => {
                self.splits.remove(&(prefix, depth));
                self.empties[depth as usize]
            }
            (Some((p, (id, val))), false) => {
                self.splits.remove(&(prefix, depth));
                let lh = leaf_hash_from_components(id, val);
                lift_single_leaf(lh, p, depth, &self.empties)
            }
            (Some(_), true) => {
                // ≥2 leaves — stored split is valid if present.
                if let Some(&h) = self.splits.get(&(prefix, depth)) { return h; }
                let mut lp = prefix;
                set_bit_be(&mut lp, depth, 0);
                mask_after_be(&mut lp, depth + 1);
                let mut rp = prefix;
                set_bit_be(&mut rp, depth, 1);
                mask_after_be(&mut rp, depth + 1);
                let l = self.subtree_hash(lp, depth + 1);
                let r = self.subtree_hash(rp, depth + 1);
                let empty_next = self.empties[(depth + 1) as usize];
                if l == empty_next || r == empty_next {
                    hbsmt_node_hash(&l, &r)
                } else {
                    let h = hbsmt_node_hash(&l, &r);
                    self.splits.insert((prefix, depth), h);
                    h
                }
            }
        }
    }
}

// Pure helpers (`lift_single_leaf`, `lcp_depth`, `subtree_range`,
// `hbsmt_node_hash`, `make_empties`) live in `smt_common.rs` and are shared
// with the RocksDB-backed `HbsmtRdb`.

// ============================================================================
// BENCHMARKS
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn ins(k: &[u8], v: &[u8]) -> Op { Op::Insert(None, k.to_vec(), v.to_vec()) }
    fn ins_ns(ns: &[u8], k: &[u8], v: &[u8]) -> Op { Op::Insert(Some(ns.to_vec()), k.to_vec(), v.to_vec()) }

    fn build_ops(n: u32, ns_count: u32) -> Vec<Op> {
        let mut ops = Vec::with_capacity(n as usize);
        for i in 0..n {
            let ns_idx = i % ns_count;
            let ns = format!("ns-{:02}", ns_idx);
            let k = format!("key-{:08}", i);
            let v = format!("v-{}", i);
            if ns_count == 1 {
                ops.push(ins(k.as_bytes(), v.as_bytes()));
            } else {
                ops.push(ins_ns(ns.as_bytes(), k.as_bytes(), v.as_bytes()));
            }
        }
        ops
    }

    fn bench_hot(name: &str, tree_size: usize, batch_size: usize, ns_count: u32, hot_ns: Option<&str>) {
        let initial = build_ops(tree_size as u32, ns_count);
        let mut delta = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let key_idx = i % tree_size;
            let v = format!("hot-v-{}", i);
            if let Some(ns) = hot_ns {
                let k = format!("key-{:08}", key_idx as u32 * ns_count);
                delta.push(ins_ns(ns.as_bytes(), k.as_bytes(), v.as_bytes()));
            } else if ns_count == 1 {
                delta.push(ins(format!("key-{:08}", key_idx).as_bytes(), v.as_bytes()));
            } else {
                let ns = format!("ns-{:02}", (i as u32) % ns_count);
                delta.push(ins_ns(ns.as_bytes(), format!("key-{:08}", key_idx).as_bytes(), v.as_bytes()));
            }
        }

        let mut s = Hbsmt::new();
        s.batch_update(initial);
        let _ = s.root();
        let t = Instant::now();
        s.batch_update(delta);
        let smt_apply = t.elapsed().as_micros();
        let t = Instant::now();
        let _ = s.root();
        let smt_root = t.elapsed().as_micros();

        let s_total = smt_apply + smt_root;
        println!("  {} (tree={:>7}, ns={:>3}, batch={:>6}{})",
            name, tree_size, ns_count, batch_size,
            if hot_ns.is_some() { " HOT" } else { "" });
        println!("    SMT : apply={:>7}µs root={:>6}µs total={:>7}µs",
            smt_apply, smt_root, s_total);
    }

    #[test]
    fn bench_500ms_block_budget() {
        println!("\n==== 500ms block budget — hot-spot patterns ====");
        bench_hot("1k",   1_000,    1_000, 1, None);
        bench_hot("1k",   1_000,   10_000, 1, None);
        bench_hot("100k", 100_000,  1_000, 1, None);
        bench_hot("100k", 100_000, 10_000, 1, None);
        bench_hot("100k", 100_000,100_000, 1, None);
    }

    #[test]
    fn bench_hot_namespace() {
        println!("\n==== Hot-namespace (single hot contract) ====");
        bench_hot("1k",   1_000,    1_000, 10,  Some("ns-00"));
        bench_hot("100k", 100_000,  1_000, 10,  Some("ns-00"));
        bench_hot("100k", 100_000, 10_000, 10,  Some("ns-00"));
        bench_hot("100k", 100_000, 10_000, 100, Some("ns-00"));
        bench_hot("100k", 100_000,100_000, 10,  Some("ns-00"));
    }

    #[test]
    #[ignore = "slow scale point"]
    fn bench_large_scale() {
        println!("\n==== Large scale ====");
        bench_hot("1M",   1_000_000,  1_000, 1, None);
        bench_hot("1M",   1_000_000, 10_000, 1, None);
        bench_hot("1M",   1_000_000, 10_000, 100, Some("ns-00"));
    }

    /// THE actual relevant benchmark: large tree, much smaller batch.
    /// Real blocks touch O(K) keys in an O(N) tree where K << N.
    #[test]
    #[ignore = "very slow — 10M leaf tree (~3 min build)"]
    fn bench_10m_tree() {
        println!("\n==== 10M tree (the realistic scale) ====");
        bench_hot("10M",  10_000_000,    100, 1, None);
        bench_hot("10M",  10_000_000,  1_000, 1, None);
        bench_hot("10M",  10_000_000, 10_000, 1, None);
        bench_hot("10M",  10_000_000,100_000, 1, None);
        bench_hot("10M",  10_000_000, 10_000, 100, Some("ns-00"));
        bench_hot("10M",  10_000_000,100_000, 100, Some("ns-00"));
    }

    #[test]
    fn correctness_order_independence() {
        let a: Vec<Op> = (0..200u32).map(|i|
            ins(format!("k{}", i).as_bytes(), format!("v{}", i).as_bytes())).collect();
        let mut b = a.clone(); b.reverse();
        b.push(Op::Delete(None, b"k50".to_vec()));
        b.push(ins(b"k50", b"new"));
        let mut a2 = a.clone();
        a2.push(Op::Delete(None, b"k50".to_vec()));
        a2.push(ins(b"k50", b"new"));

        let mut s_a = Hbsmt::new(); s_a.batch_update(a2);
        let mut s_b = Hbsmt::new(); s_b.batch_update(b);
        assert_eq!(s_a.root(), s_b.root(), "SMT must be order-independent");
    }

    /// Single-batch shuffle test where each key appears in exactly one op.
    /// With one op per key, every permutation of the batch has the same
    /// final state → same root.
    #[test]
    fn correctness_random_order_inserts_and_deletes() {
        // Preload state via batch 1 (500 inserts of unique keys).
        let preload: Vec<Op> = (0..500u32)
            .map(|i| ins(format!("k{:04}", i).as_bytes(), format!("v{}", i).as_bytes()))
            .collect();

        // Mutation batch (each key touched once): 100 deletes of preloaded
        // keys + 100 inserts of fresh keys.
        let mut mutations: Vec<Op> = Vec::new();
        for i in 0..100u32 {
            mutations.push(Op::Delete(None, format!("k{:04}", i).as_bytes().to_vec()));
        }
        for i in 500..600u32 {
            mutations.push(ins(format!("k{:04}", i).as_bytes(), format!("v2-{}", i).as_bytes()));
        }

        let mut s_canonical = Hbsmt::new();
        s_canonical.batch_update(preload.clone());
        s_canonical.batch_update(mutations.clone());
        let expected = s_canonical.root();

        // 5 deterministic shufflings of the mutation batch.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as StdHash, Hasher};
        for seed in 0u64..5 {
            let mut indexed: Vec<(u64, Op)> = mutations.iter().cloned().enumerate().map(|(i, op)| {
                let mut h = DefaultHasher::new();
                (i as u64, seed).hash(&mut h);
                (h.finish(), op)
            }).collect();
            indexed.sort_by_key(|(h, _)| *h);
            let shuffled: Vec<Op> = indexed.into_iter().map(|(_, op)| op).collect();

            let mut s = Hbsmt::new();
            s.batch_update(preload.clone());
            s.batch_update(shuffled);
            assert_eq!(s.root(), expected, "shuffle seed {} produced different root", seed);
        }
    }

    // -----------------------------------------------------------------
    // Proofs (Hbsmt in-memory)
    // -----------------------------------------------------------------
    use crate::consensus::hbsmt_common::{
    compute_namespace_path_hbsmt,verify_hbsmt, HbsmtVerifyStatus};

    fn build_small_tree() -> Hbsmt {
        let mut s = Hbsmt::new();
        s.batch_update(vec![
            ins(b"alpha",   b"v-alpha"),
            ins(b"beta",    b"v-beta"),
            ins(b"gamma",   b"v-gamma"),
            ins(b"delta",   b"v-delta"),
            ins(b"epsilon", b"v-epsilon"),
        ]);
        s
    }

    #[test]
    fn smt_inmem_proof_inclusion() {
        let mut s = build_small_tree();
        let root = s.root();
        let proof = s.prove(None, b"alpha");
        assert_eq!(verify_hbsmt(&root, &proof, None, b"alpha", b"v-alpha"),
                   HbsmtVerifyStatus::Included);
    }

    #[test]
    fn smt_inmem_proof_mismatch() {
        let mut s = build_small_tree();
        let root = s.root();
        let proof = s.prove(None, b"alpha");
        assert_eq!(verify_hbsmt(&root, &proof, None, b"alpha", b"WRONG"),
                   HbsmtVerifyStatus::Mismatch);
    }

    #[test]
    fn smt_inmem_proof_nonexistence() {
        let mut s = build_small_tree();
        let root = s.root();
        // Two flavors of non-existence: (a) target hashes into an empty subtree,
        // (b) target hashes into a compressed subtree occupied by a different leaf.
        // The prover doesn't know which — verifier reports NonExistence either way.
        let proof = s.prove(None, b"not-in-tree");
        assert_eq!(verify_hbsmt(&root, &proof, None, b"not-in-tree", b"anything"),
                   HbsmtVerifyStatus::NonExistence);
    }

    #[test]
    fn smt_inmem_proof_invalid_when_tampered() {
        let mut s = build_small_tree();
        let root = s.root();
        let mut proof = s.prove(None, b"alpha");
        // Flip a bit in a sibling — root reconstruction must fail.
        if let Some(s0) = proof.siblings.get_mut(0) { s0[0] ^= 0x01; }
        assert_eq!(verify_hbsmt(&root, &proof, None, b"alpha", b"v-alpha"),
                   HbsmtVerifyStatus::Invalid);
    }

    #[test]
    fn smt_inmem_proof_invalid_wrong_root() {
        let mut s = build_small_tree();
        let proof = s.prove(None, b"alpha");
        let mut bogus_root = s.root();
        bogus_root[0] ^= 0x01;
        assert_eq!(verify_hbsmt(&bogus_root, &proof, None, b"alpha", b"v-alpha"),
                   HbsmtVerifyStatus::Invalid);
    }

    #[test]
    fn smt_inmem_proof_empty_tree() {
        let mut s = Hbsmt::new();
        let root = s.root();
        let proof = s.prove(None, b"anything");
        assert_eq!(verify_hbsmt(&root, &proof, None, b"anything", b"v"),
                   HbsmtVerifyStatus::NonExistence);
        // Empty-tree non-existence proof has zero siblings — terminus is Empty at depth 0.
        assert!(proof.siblings.is_empty());
        assert_eq!(proof.terminus, crate::consensus::hbsmt_common::HbsmtTerminus::Empty);
    }

    #[test]
    fn smt_inmem_proof_single_leaf_tree() {
        let mut s = Hbsmt::new();
        s.batch_update(vec![ins(b"only", b"the-one")]);
        let root = s.root();

        // Proof for the present leaf → Included via compressed-edge.
        let p1 = s.prove(None, b"only");
        assert_eq!(verify_hbsmt(&root, &p1, None, b"only", b"the-one"),
                   HbsmtVerifyStatus::Included);
        // Mismatch on the present leaf.
        assert_eq!(verify_hbsmt(&root, &p1, None, b"only", b"WRONG"),
                   HbsmtVerifyStatus::Mismatch);
        // Non-existence: prove a different key. The compressed leaf is `only`,
        // and the verifier sees that the terminus leaf's path ≠ target → NonExistence.
        let p2 = s.prove(None, b"absent");
        assert_eq!(verify_hbsmt(&root, &p2, None, b"absent", b"anything"),
                   HbsmtVerifyStatus::NonExistence);
    }

    #[test]
    fn smt_inmem_proof_namespaced() {
        let mut s = Hbsmt::new();
        s.batch_update(vec![
            ins_ns(b"ns-a", b"k", b"va"),
            ins_ns(b"ns-b", b"k", b"vb"),
        ]);
        let root = s.root();
        let pa = s.prove(Some(b"ns-a"), b"k");
        let pb = s.prove(Some(b"ns-b"), b"k");
        assert_eq!(verify_hbsmt(&root, &pa, Some(b"ns-a"), b"k", b"va"),
                   HbsmtVerifyStatus::Included);
        assert_eq!(verify_hbsmt(&root, &pb, Some(b"ns-b"), b"k", b"vb"),
                   HbsmtVerifyStatus::Included);
        // Cross-namespace mismatch: same key, different ns → different path.
        assert_eq!(verify_hbsmt(&root, &pa, Some(b"ns-a"), b"k", b"vb"),
                   HbsmtVerifyStatus::Mismatch);
    }

    /// Probe: same final state via (a) one big batch vs (c) preload+chunked.
    /// If the algorithm is correct, the in-memory version should also produce
    /// equal roots — confirming whether the bug lives in the in-memory algorithm
    /// or only in the RocksDB layer.
    #[test]
    fn probe_chunked_vs_single_batch_inmem() {
        let preload: Vec<Op> = (0..500u32).map(|i|
            ins(format!("k-{:04}", i).as_bytes(), format!("v0-{}", i).as_bytes())).collect();
        let mut mutations: Vec<Op> = Vec::new();
        for i in 0..50u32 { mutations.push(Op::Delete(None, format!("k-{:04}", i).as_bytes().to_vec())); }
        for i in 500..600u32 { mutations.push(ins(format!("k-{:04}", i).as_bytes(), format!("v1-{}", i).as_bytes())); }

        let mut a = Hbsmt::new();
        a.batch_update(preload.clone());
        a.batch_update(mutations.clone());
        let ra = a.root();

        let mut c = Hbsmt::new();
        c.batch_update(preload.clone());
        for chunk in mutations.chunks(17) { c.batch_update(chunk.to_vec()); }
        let rc = c.root();

        assert_eq!(ra, rc, "in-memory: chunked batches differ from single batch — algorithm bug");
    }

    #[test]
    fn correctness_inplace_mutate() {
        // Writing the same key 100 times in one batch must give the same root as
        // writing it once with the final value.
        let mut once = Vec::new();
        let mut hundred = Vec::new();
        once.push(ins(b"k1", b"final"));
        for i in 0..100 { hundred.push(ins(b"k1", format!("v{}", i).as_bytes())); }
        hundred.push(ins(b"k1", b"final"));

        let mut s_one = Hbsmt::new(); s_one.batch_update(once);
        let mut s_hun = Hbsmt::new(); s_hun.batch_update(hundred);
        assert_eq!(s_one.root(), s_hun.root());
    }
}
