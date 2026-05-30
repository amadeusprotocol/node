//! RocksDB-backed Compact Sparse Merkle Tree. Same algorithm as the in-memory
//! `Hbsmt` but with persistent storage — leaves and splits live in
//! dedicated CFs, accessed transactionally during each batch.
//!
//! Storage layout (single TransactionDB, multiple CFs):
//!   - `smt_leaves`:  key = `path[32]`,                  value = `leaf_hash[32]`
//!   - `smt_splits`:  key = `path[32] || depth_be[2]`,   value = `node_hash[32]`
//!
//! Performance optimizations carried over:
//!   - One-Phase Batch Update (sorted-partition descent, one hash per node).
//!   - Single-leaf-subtree collapse via `lift_single_leaf`.
//!   - LCP-jump for hot-namespace concentration (all dirty paths share prefix).
//!   - Per-batch in-memory write-back cache so a node touched multiple times
//!     in one batch is hashed once and written once.

use crate::consensus::bintree::{
    get_bit_be, mask_after_be, set_bit_be, Hash, Op, Path, ZERO_HASH,
};
use crate::consensus::hbsmt_common::{
    compute_namespace_path_hbsmt,
    child_prefixes, identity_hash, lcp_depth, leaf_hash_from_components, lift_single_leaf,
    make_empties, hbsmt_node_hash, subtree_range, value_hash, HbsmtProof, HbsmtTerminus,
};

/// Leaves CF stores 64 bytes per entry: `identity_hash (32) || value_hash (32)`.
#[inline]
fn encode_leaf(id: &Hash, val: &Hash) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(id);
    out[32..64].copy_from_slice(val);
    out
}
#[inline]
fn decode_leaf(bytes: &[u8]) -> Option<(Hash, Hash)> {
    if bytes.len() != 64 { return None; }
    let mut id = [0u8; 32];
    let mut val = [0u8; 32];
    id.copy_from_slice(&bytes[0..32]);
    val.copy_from_slice(&bytes[32..64]);
    Some((id, val))
}
use rust_rocksdb::{
    BlockBasedOptions, BoundColumnFamily, Cache, ColumnFamilyDescriptor, DBCompressionType,
    MultiThreaded, Options, ReadOptions, Transaction, TransactionDB, TransactionDBOptions,
};
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;
use std::sync::Arc;

const CF_LEAVES: &str = "smt_leaves";
const CF_SPLITS: &str = "smt_splits";

pub struct HbsmtRdb {
    db: TransactionDB<MultiThreaded>,
    empties: [Hash; 257],
}

impl HbsmtRdb {
    /// Default: 256MB block cache.
    pub fn open(path: &std::path::Path) -> Self {
        Self::open_with_cache(path, 256 * 1024 * 1024)
    }

    /// Open with an explicit shared block-cache size (bytes). Larger cache
    /// → fewer SST seeks during batch_update → much faster apply on big trees.
    pub fn open_with_cache(path: &std::path::Path, block_cache_bytes: usize) -> Self {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        db_opts.set_max_background_jobs(4);
        db_opts.increase_parallelism(4);

        let cache = Cache::new_lru_cache(block_cache_bytes);

        let mut bbt = BlockBasedOptions::default();
        bbt.set_block_cache(&cache);
        bbt.set_block_size(4 * 1024);
        bbt.set_bloom_filter(10.0, false);
        bbt.set_cache_index_and_filter_blocks(true);
        bbt.set_pin_l0_filter_and_index_blocks_in_cache(true);

        let mut leaves_opts = Options::default();
        leaves_opts.set_write_buffer_size(128 * 1024 * 1024);
        leaves_opts.set_block_based_table_factory(&bbt);
        leaves_opts.set_compression_type(DBCompressionType::None);

        let mut splits_opts = Options::default();
        splits_opts.set_write_buffer_size(256 * 1024 * 1024);
        splits_opts.set_block_based_table_factory(&bbt);
        splits_opts.set_compression_type(DBCompressionType::None);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_LEAVES, leaves_opts),
            ColumnFamilyDescriptor::new(CF_SPLITS, splits_opts),
        ];
        let txn_db_opts = TransactionDBOptions::default();
        let db = TransactionDB::<MultiThreaded>::open_cf_descriptors(
            &db_opts, &txn_db_opts, path, cfs,
        )
        .unwrap();

        HbsmtRdb { db, empties: make_empties() }
    }

    pub fn root(&self) -> Hash {
        let cf_splits = self.db.cf_handle(CF_SPLITS).unwrap();
        let key = split_key(&[0u8; 32], 0);
        if let Some(v) = self.db.get_cf(&cf_splits, key).ok().flatten() {
            return v.try_into().unwrap_or(self.empties[0]);
        }
        // No stored top-level split: the tree is empty, a single leaf is lifted
        // to the root, or all leaves cluster on one side of depth 0. Walk to compute.
        let cf_leaves = self.db.cf_handle(CF_LEAVES).unwrap();
        self.subtree_hash_db(&cf_leaves, &cf_splits, [0u8; 32], 0)
    }

    /// Produce a proof for `(ns, key)` against the current root. Read-only;
    /// no transaction. Verify with [`smt_common::verify_hbsmt`].
    pub fn prove(&self, ns: Option<&[u8]>, k: &[u8]) -> HbsmtProof {
        let target = compute_namespace_path_hbsmt(ns.unwrap_or(b""), k);
        let cf_leaves = self.db.cf_handle(CF_LEAVES).unwrap();
        let cf_splits = self.db.cf_handle(CF_SPLITS).unwrap();
        let mut siblings = Vec::new();
        let terminus = self.descend_for_proof(
            &cf_leaves, &cf_splits, &target, [0u8; 32], 0, &mut siblings);
        HbsmtProof { siblings, terminus }
    }

    fn descend_for_proof(
        &self,
        cf_leaves: &Arc<BoundColumnFamily<'_>>,
        cf_splits: &Arc<BoundColumnFamily<'_>>,
        target: &Path,
        prefix: Path,
        depth: u16,
        siblings: &mut Vec<Hash>,
    ) -> HbsmtTerminus {
        if depth == 256 {
            return match self.db.get_cf(cf_leaves, prefix).ok().flatten() {
                Some(v) => match decode_leaf(&v) {
                    Some((id, val)) => HbsmtTerminus::Leaf {
                        path: prefix, identity_hash: id, value_hash: val,
                    },
                    None => HbsmtTerminus::Empty,
                },
                None => HbsmtTerminus::Empty,
            };
        }
        let (lo, hi) = subtree_range(&prefix, depth);
        let (first, more) = self.first_two_leaves(cf_leaves, &lo, &hi);
        match (first, more) {
            (None, _) => HbsmtTerminus::Empty,
            (Some((p, id, val)), false) => HbsmtTerminus::Leaf {
                path: p, identity_hash: id, value_hash: val,
            },
            _ => {
                let bit = get_bit_be(target, depth);
                let (lp, rp) = child_prefixes(&prefix, depth);
                let (target_prefix, sibling_prefix) = if bit == 0 { (lp, rp) } else { (rp, lp) };
                let sibling_hash = self.subtree_hash_db(cf_leaves, cf_splits, sibling_prefix, depth + 1);
                siblings.push(sibling_hash);
                self.descend_for_proof(cf_leaves, cf_splits, target, target_prefix, depth + 1, siblings)
            }
        }
    }

    /// Read-only subtree hash for proof generation (no transaction).
    /// Read-only subtree hash. **Correctness**: checks leaf count before
    /// consulting the stored split CF — stored splits in a collapsed subtree
    /// are stale and must not be trusted. Matches the invariant enforced in
    /// the transactional `subtree_hash` and in `Hbsmt::subtree_hash`.
    fn subtree_hash_db(
        &self,
        cf_leaves: &Arc<BoundColumnFamily<'_>>,
        cf_splits: &Arc<BoundColumnFamily<'_>>,
        prefix: Path,
        depth: u16,
    ) -> Hash {
        if depth == 256 {
            return match self.db.get_cf(cf_leaves, prefix).ok().flatten() {
                Some(v) => match decode_leaf(&v) {
                    Some((id, val)) => leaf_hash_from_components(&id, &val),
                    None => self.empties[256],
                },
                None => self.empties[256],
            };
        }
        let (lo, hi) = subtree_range(&prefix, depth);
        let (first, more) = self.first_two_leaves(cf_leaves, &lo, &hi);
        match (first, more) {
            (None, _) => self.empties[depth as usize],
            (Some((p, id, val)), false) => {
                let lh = leaf_hash_from_components(&id, &val);
                lift_single_leaf(lh, &p, depth, &self.empties)
            }
            _ => {
                if let Some(v) = self.db.get_cf(cf_splits, split_key(&prefix, depth)).ok().flatten() {
                    return v.try_into().unwrap_or(self.empties[depth as usize]);
                }
                let (lp, rp) = child_prefixes(&prefix, depth);
                let l = self.subtree_hash_db(cf_leaves, cf_splits, lp, depth + 1);
                let r = self.subtree_hash_db(cf_leaves, cf_splits, rp, depth + 1);
                hbsmt_node_hash(&l, &r)
            }
        }
    }

    fn first_two_leaves(
        &self,
        cf_leaves: &Arc<BoundColumnFamily<'_>>,
        lo: &Path,
        hi: &Path,
    ) -> (Option<(Path, Hash, Hash)>, bool) {
        let mut iter = self.db.raw_iterator_cf(cf_leaves);
        iter.seek(lo);
        if !iter.valid() { return (None, false); }
        let k = match iter.key() { Some(k) => k, None => return (None, false) };
        if k > hi.as_slice() { return (None, false); }
        let mut path = [0u8; 32];
        path.copy_from_slice(k);
        let v = iter.value().unwrap();
        let (id, val) = match decode_leaf(v) {
            Some(t) => t,
            None => return (None, false),
        };
        iter.next();
        let more = iter.valid()
            && iter.key().map(|k2| k2 <= hi.as_slice()).unwrap_or(false);
        (Some((path, id, val)), more)
    }

    /// Apply ops in a single transaction. Reads through the txn so intra-batch
    /// writes are visible to subsequent reads.
    pub fn batch_update(&self, ops: Vec<Op>) {
        if ops.is_empty() { return; }

        // 1. Collapse multi-writes to same key. Each leaf stored as
        //    (identity_hash, value_hash) so proofs can distinguish
        //    Mismatch from NonExistence under (logic-error) path-collision.
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

        let cf_leaves = self.db.cf_handle(CF_LEAVES).unwrap();
        let cf_splits = self.db.cf_handle(CF_SPLITS).unwrap();
        let txn = self.db.transaction();

        // 2. Apply leaf changes; collect dirty paths.
        //    Batch-prefetch existing values via multi_get_cf (RocksDB's bulk
        //    read path is roughly 2-3× faster than individual gets when keys
        //    aren't already in block cache).
        let paths_ordered: Vec<Path> = latest.keys().copied().collect();
        let mg_keys: Vec<(&Arc<BoundColumnFamily>, &Path)> =
            paths_ordered.iter().map(|p| (&cf_leaves, p)).collect();
        let prev_values = txn.multi_get_cf(mg_keys.iter().map(|(c, k)| (*c, *k)));

        let mut dirty: Vec<Path> = Vec::with_capacity(latest.len());
        for (i, path) in paths_ordered.iter().enumerate() {
            let prev = prev_values.get(i).and_then(|r| r.as_ref().ok()).cloned().flatten();
            let new_val = latest.get(path).unwrap();
            match new_val {
                Some((id, val)) => {
                    let encoded = encode_leaf(id, val);
                    if prev.as_deref() != Some(&encoded[..]) {
                        txn.put_cf(&cf_leaves, path, encoded).unwrap();
                        dirty.push(*path);
                    }
                }
                None => {
                    if prev.is_some() {
                        txn.delete_cf(&cf_leaves, path).unwrap();
                        dirty.push(*path);
                    }
                }
            }
        }
        if dirty.is_empty() {
            txn.commit().unwrap();
            return;
        }

        // 3. Descend and rehash. Use a per-batch in-memory cache to avoid
        //    re-reading nodes from RocksDB within the same descent.
        let mut ctx = Ctx {
            txn: &txn,
            cf_leaves: &cf_leaves,
            cf_splits: &cf_splits,
            empties: &self.empties,
            split_cache: FxHashMap::default(),
            split_writes: FxHashMap::default(),
            split_deletes: Vec::new(),
        };
        let _ = descend_and_rehash(&mut ctx, [0u8; 32], 0, &dirty);

        for ((path, depth), hash) in ctx.split_writes {
            txn.put_cf(&cf_splits, split_key(&path, depth), hash).unwrap();
        }
        for (path, depth) in ctx.split_deletes {
            let _ = txn.delete_cf(&cf_splits, split_key(&path, depth));
        }
        txn.commit().unwrap();
    }
}

#[inline]
fn split_key(path: &Path, depth: u16) -> [u8; 34] {
    let mut k = [0u8; 34];
    k[0..32].copy_from_slice(path);
    k[32..34].copy_from_slice(&depth.to_be_bytes());
    k
}

struct Ctx<'a> {
    txn: &'a Transaction<'a, TransactionDB<MultiThreaded>>,
    cf_leaves: &'a Arc<BoundColumnFamily<'a>>,
    cf_splits: &'a Arc<BoundColumnFamily<'a>>,
    empties: &'a [Hash; 257],
    split_cache: FxHashMap<(Path, u16), Hash>,
    split_writes: FxHashMap<(Path, u16), Hash>,
    split_deletes: Vec<(Path, u16)>,
}

impl<'a> Ctx<'a> {
    #[inline]
    fn get_split(&mut self, prefix: &Path, depth: u16) -> Option<Hash> {
        let key = (*prefix, depth);
        if let Some(h) = self.split_cache.get(&key) { return Some(*h); }
        if let Some(h) = self.split_writes.get(&key) { return Some(*h); }
        match self.txn.get_cf(self.cf_splits, split_key(prefix, depth)) {
            Ok(Some(v)) => {
                let h: Hash = v.try_into().unwrap_or(ZERO_HASH);
                self.split_cache.insert(key, h);
                Some(h)
            }
            _ => None,
        }
    }
    #[inline]
    fn put_split(&mut self, prefix: Path, depth: u16, h: Hash) {
        self.split_writes.insert((prefix, depth), h);
        self.split_cache.insert((prefix, depth), h);
    }
    #[inline]
    fn remove_split(&mut self, prefix: Path, depth: u16) {
        self.split_writes.remove(&(prefix, depth));
        self.split_cache.remove(&(prefix, depth));
        self.split_deletes.push((prefix, depth));
    }

    /// Two leaves at or after `lo`, matching `prefix` for `prefix_bits`, ≤ `hi`.
    /// Returns `(path, identity_hash, value_hash)` per leaf.
    fn first_two_leaves_in(&self, lo: &Path, hi: &Path) -> (Option<(Path, Hash, Hash)>, bool) {
        let mut iter = self.txn.raw_iterator_cf(self.cf_leaves);
        iter.seek(lo);
        if !iter.valid() { return (None, false); }
        let k = iter.key().unwrap();
        if k > hi.as_slice() { return (None, false); }
        let mut path = [0u8; 32];
        path.copy_from_slice(k);
        let v = iter.value().unwrap();
        let (id, val) = match decode_leaf(v) {
            Some(t) => t,
            None => return (None, false),
        };
        iter.next();
        let more = iter.valid() && iter.key().map(|k2| k2 <= hi.as_slice()).unwrap_or(false);
        (Some((path, id, val)), more)
    }
}

fn descend_and_rehash(ctx: &mut Ctx, prefix: Path, depth: u16, dirty: &[Path]) -> Hash {
    if dirty.is_empty() {
        return subtree_hash(ctx, prefix, depth);
    }
    if depth == 256 {
        match ctx.txn.get_cf(ctx.cf_leaves, prefix).ok().flatten() {
            Some(v) => match decode_leaf(&v) {
                Some((id, val)) => leaf_hash_from_components(&id, &val),
                None => ctx.empties[256],
            },
            None => ctx.empties[256],
        }
    } else {
        // Short-circuit 2: dirty.len()==1, check if subtree has only one leaf.
        if dirty.len() == 1 {
            let (lo, hi) = subtree_range(&prefix, depth);
            let (first, more) = ctx.first_two_leaves_in(&lo, &hi);
            match (first, more) {
                (None, _) => {
                    ctx.remove_split(prefix, depth);
                    return ctx.empties[depth as usize];
                }
                (Some((path, id, val)), false) => {
                    ctx.remove_split(prefix, depth);
                    let lh = leaf_hash_from_components(&id, &val);
                    return lift_single_leaf(lh, &path, depth, ctx.empties);
                }
                _ => {}
            }
        }

        // Short-circuit 3: LCP jump.
        if dirty.len() >= 2 {
            let lcp_d = lcp_depth(&dirty[0], &dirty[dirty.len() - 1]);
            if lcp_d > depth {
                let mut tp = dirty[0];
                mask_after_be(&mut tp, lcp_d);
                let mut h = descend_and_rehash(ctx, tp, lcp_d, dirty);
                for d in (depth..lcp_d).rev() {
                    let target_bit = get_bit_be(&dirty[0], d);
                    let mut op_prefix = dirty[0];
                    set_bit_be(&mut op_prefix, d, 1 - target_bit);
                    mask_after_be(&mut op_prefix, d + 1);
                    let other_h = subtree_hash(ctx, op_prefix, d + 1);

                    let empty_next = ctx.empties[(d + 1) as usize];
                    let (l, r) = if target_bit == 0 { (h, other_h) } else { (other_h, h) };

                    let mut my_prefix = dirty[0];
                    mask_after_be(&mut my_prefix, d);
                    h = if l == empty_next && r == empty_next {
                        ctx.remove_split(my_prefix, d);
                        ctx.empties[d as usize]
                    } else if l == empty_next || r == empty_next {
                        ctx.remove_split(my_prefix, d);
                        hbsmt_node_hash(&l, &r)
                    } else {
                        let new = hbsmt_node_hash(&l, &r);
                        ctx.put_split(my_prefix, d, new);
                        new
                    };
                }
                return h;
            }
        }

        // Standard bifurcation.
        let split = dirty.partition_point(|p| get_bit_be(p, depth) == 0);
        let (left_dirty, right_dirty) = dirty.split_at(split);

        let mut lp = prefix; set_bit_be(&mut lp, depth, 0); mask_after_be(&mut lp, depth + 1);
        let mut rp = prefix; set_bit_be(&mut rp, depth, 1); mask_after_be(&mut rp, depth + 1);

        let l = descend_and_rehash(ctx, lp, depth + 1, left_dirty);
        let r = descend_and_rehash(ctx, rp, depth + 1, right_dirty);

        let empty_next = ctx.empties[(depth + 1) as usize];
        if l == empty_next && r == empty_next {
            ctx.remove_split(prefix, depth);
            ctx.empties[depth as usize]
        } else if l == empty_next || r == empty_next {
            ctx.remove_split(prefix, depth);
            hbsmt_node_hash(&l, &r)
        } else {
            let new = hbsmt_node_hash(&l, &r);
            ctx.put_split(prefix, depth, new);
            new
        }
    }
}

/// Compute the subtree hash at (prefix, depth) using the txn cache.
///
/// **Correctness note**: we check leaf count BEFORE consulting stored splits.
/// A stored split for a subtree that collapsed in a previous batch becomes
/// stale (the split records an old bifurcation hash that no longer matches
/// the post-collapse state). Trusting it produces wrong roots. We instead
/// drop the cache whenever the subtree provably has ≤1 leaves and clean up
/// the stale entry. See the matching guard in `Hbsmt::subtree_hash`.
fn subtree_hash(ctx: &mut Ctx, prefix: Path, depth: u16) -> Hash {
    if depth == 256 {
        return match ctx.txn.get_cf(ctx.cf_leaves, prefix).ok().flatten() {
            Some(v) => match decode_leaf(&v) {
                Some((id, val)) => leaf_hash_from_components(&id, &val),
                None => ctx.empties[256],
            },
            None => ctx.empties[256],
        };
    }
    let (lo, hi) = subtree_range(&prefix, depth);
    let (first, more) = ctx.first_two_leaves_in(&lo, &hi);
    match (first, more) {
        (None, _) => {
            ctx.remove_split(prefix, depth);
            ctx.empties[depth as usize]
        }
        (Some((path, id, val)), false) => {
            ctx.remove_split(prefix, depth);
            let lh = leaf_hash_from_components(&id, &val);
            lift_single_leaf(lh, &path, depth, ctx.empties)
        }
        (Some(_), true) => {
            // ≥2 leaves — stored split is valid if present.
            if let Some(h) = ctx.get_split(&prefix, depth) { return h; }
            let mut lp = prefix; set_bit_be(&mut lp, depth, 0); mask_after_be(&mut lp, depth + 1);
            let mut rp = prefix; set_bit_be(&mut rp, depth, 1); mask_after_be(&mut rp, depth + 1);
            let l = subtree_hash(ctx, lp, depth + 1);
            let r = subtree_hash(ctx, rp, depth + 1);
            let empty_next = ctx.empties[(depth + 1) as usize];
            if l == empty_next || r == empty_next {
                hbsmt_node_hash(&l, &r)
            } else {
                let new = hbsmt_node_hash(&l, &r);
                ctx.put_split(prefix, depth, new);
                new
            }
        }
    }
}

// Pure helpers live in `smt_common.rs` — see those for `lift_single_leaf`,
// `lcp_depth`, `subtree_range`, `child_prefixes`, `make_empties`, `hbsmt_node_hash`.

// ============================================================================
// TESTS + one shipping benchmark (1M hot-namespace 10k batch)
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tempfile::TempDir;

    fn ins(k: &[u8], v: &[u8]) -> Op { Op::Insert(None, k.to_vec(), v.to_vec()) }
    fn ins_ns(ns: &[u8], k: &[u8], v: &[u8]) -> Op { Op::Insert(Some(ns.to_vec()), k.to_vec(), v.to_vec()) }
    fn del(k: &[u8]) -> Op { Op::Delete(None, k.to_vec()) }

    fn build_ops(n: u32, ns_count: u32) -> Vec<Op> {
        let mut ops = Vec::with_capacity(n as usize);
        for i in 0..n {
            if ns_count == 1 {
                ops.push(ins(format!("key-{:08}", i).as_bytes(), format!("v-{}", i).as_bytes()));
            } else {
                let ns = format!("ns-{:02}", i % ns_count);
                ops.push(ins_ns(ns.as_bytes(), format!("key-{:08}", i).as_bytes(), format!("v-{}", i).as_bytes()));
            }
        }
        ops
    }

    // -----------------------------------------------------------------
    // Correctness
    // -----------------------------------------------------------------

    /// Same key written multiple times in one batch collapses to the last value.
    #[test]
    fn smt_rdb_collapse_duplicate_keys() {
        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());
        smt.batch_update(vec![ins(b"k1", b"v1"), ins(b"k2", b"v2"), ins(b"k1", b"v1b")]);
        let r1 = smt.root();

        let dir2 = TempDir::new().unwrap();
        let smt2 = HbsmtRdb::open(dir2.path());
        smt2.batch_update(vec![ins(b"k2", b"v2"), ins(b"k1", b"v1b")]);
        assert_eq!(r1, smt2.root());
    }

    /// Reversing an insert-only batch produces the same root.
    /// Within a single batch, the algorithm collapses ops to last-write-wins
    /// per key; with one op per key, every permutation has the same final state.
    #[test]
    fn smt_rdb_reversed_batch_same_root() {
        let ops: Vec<Op> = (0..100u32)
            .map(|i| ins(format!("k{}", i).as_bytes(), format!("v{}", i).as_bytes()))
            .collect();

        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());
        smt.batch_update(ops.clone());
        let r1 = smt.root();

        let mut rev = ops;
        rev.reverse();
        let dir2 = TempDir::new().unwrap();
        let smt2 = HbsmtRdb::open(dir2.path());
        smt2.batch_update(rev);
        assert_eq!(r1, smt2.root());
    }

    /// Strong out-of-order test:
    ///   - A batch of 150 mutations where each key appears in exactly one op
    ///     (50 deletes of preloaded keys + 100 inserts of fresh keys).
    ///   - Applied (a) in original order, (b) shuffled — must yield the same root.
    /// The single-op-per-key invariant is what makes shuffling well-defined.
    #[test]
    fn smt_rdb_out_of_order_inserts_and_deletes() {
        // Preload tree with 500 keys.
        let preload: Vec<Op> = (0..500u32)
            .map(|i| ins(format!("k-{:04}", i).as_bytes(), format!("v0-{}", i).as_bytes()))
            .collect();

        // Mutation batch: 50 deletes of preloaded keys + 100 fresh inserts.
        // Each key in this batch is touched once → order-independent.
        let mut mutations: Vec<Op> = Vec::new();
        for i in 0..50u32 {
            mutations.push(del(format!("k-{:04}", i).as_bytes()));
        }
        for i in 500..600u32 {
            mutations.push(ins(format!("k-{:04}", i).as_bytes(), format!("v1-{}", i).as_bytes()));
        }

        // (a) Preload + mutations in original order.
        let dir_a = TempDir::new().unwrap();
        let smt_a = HbsmtRdb::open(dir_a.path());
        smt_a.batch_update(preload.clone());
        smt_a.batch_update(mutations.clone());
        let r_a = smt_a.root();

        // (b) Preload + shuffled mutations.
        let mut shuffled = mutations.clone();
        let mut state: u64 = 0xdead_beef_cafe_babe;
        for i in (1..shuffled.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let j = (state as usize) % (i + 1);
            shuffled.swap(i, j);
        }
        let dir_b = TempDir::new().unwrap();
        let smt_b = HbsmtRdb::open(dir_b.path());
        smt_b.batch_update(preload.clone());
        smt_b.batch_update(shuffled);
        let r_b = smt_b.root();

        // (c) Preload + mutations applied as N small batches in original order.
        //     Order between batches is preserved → equivalent to (a).
        let dir_c = TempDir::new().unwrap();
        let smt_c = HbsmtRdb::open(dir_c.path());
        smt_c.batch_update(preload);
        for chunk in mutations.chunks(17) {
            smt_c.batch_update(chunk.to_vec());
        }
        let r_c = smt_c.root();

        assert_eq!(r_a, r_b, "shuffled mutation batch differs from in-order");
        assert_eq!(r_a, r_c, "chunked mutation batches differ from single batch");
    }

    /// Cross-instance equivalence: deletions and reinsertions hashed correctly.
    /// Inserts a leaf, deletes it, reinserts it with the same value — the
    /// resulting root must equal a tree where the leaf was just inserted once.
    #[test]
    fn smt_rdb_delete_then_reinsert_equals_single_insert() {
        let dir1 = TempDir::new().unwrap();
        let smt1 = HbsmtRdb::open(dir1.path());
        smt1.batch_update(vec![ins(b"a", b"1"), ins(b"b", b"2")]);
        smt1.batch_update(vec![del(b"a")]);
        smt1.batch_update(vec![ins(b"a", b"1")]);
        let r1 = smt1.root();

        let dir2 = TempDir::new().unwrap();
        let smt2 = HbsmtRdb::open(dir2.path());
        smt2.batch_update(vec![ins(b"a", b"1"), ins(b"b", b"2")]);
        let r2 = smt2.root();

        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------
    // Proofs (RocksDB-backed)
    // -----------------------------------------------------------------
    use crate::consensus::hbsmt_common::{
    compute_namespace_path_hbsmt,verify_hbsmt, HbsmtVerifyStatus, HbsmtTerminus};

    fn build_small_rdb() -> (TempDir, HbsmtRdb) {
        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());
        smt.batch_update(vec![
            ins(b"alpha",   b"v-alpha"),
            ins(b"beta",    b"v-beta"),
            ins(b"gamma",   b"v-gamma"),
            ins(b"delta",   b"v-delta"),
            ins(b"epsilon", b"v-epsilon"),
        ]);
        (dir, smt)
    }

    #[test]
    fn smt_rdb_proof_inclusion() {
        let (_dir, smt) = build_small_rdb();
        let root = smt.root();
        let proof = smt.prove(None, b"alpha");
        assert_eq!(verify_hbsmt(&root, &proof, None, b"alpha", b"v-alpha"),
                   HbsmtVerifyStatus::Included);
    }

    #[test]
    fn smt_rdb_proof_mismatch() {
        let (_dir, smt) = build_small_rdb();
        let root = smt.root();
        let proof = smt.prove(None, b"alpha");
        assert_eq!(verify_hbsmt(&root, &proof, None, b"alpha", b"WRONG"),
                   HbsmtVerifyStatus::Mismatch);
    }

    #[test]
    fn smt_rdb_proof_nonexistence() {
        let (_dir, smt) = build_small_rdb();
        let root = smt.root();
        let proof = smt.prove(None, b"not-in-tree");
        assert_eq!(verify_hbsmt(&root, &proof, None, b"not-in-tree", b"anything"),
                   HbsmtVerifyStatus::NonExistence);
    }

    #[test]
    fn smt_rdb_proof_invalid_when_tampered() {
        let (_dir, smt) = build_small_rdb();
        let root = smt.root();
        let mut proof = smt.prove(None, b"alpha");
        if let Some(s0) = proof.siblings.get_mut(0) { s0[0] ^= 0x01; }
        assert_eq!(verify_hbsmt(&root, &proof, None, b"alpha", b"v-alpha"),
                   HbsmtVerifyStatus::Invalid);
    }

    #[test]
    fn smt_rdb_proof_invalid_wrong_root() {
        let (_dir, smt) = build_small_rdb();
        let proof = smt.prove(None, b"alpha");
        let mut bogus_root = smt.root();
        bogus_root[0] ^= 0x01;
        assert_eq!(verify_hbsmt(&bogus_root, &proof, None, b"alpha", b"v-alpha"),
                   HbsmtVerifyStatus::Invalid);
    }

    #[test]
    fn smt_rdb_proof_empty_tree() {
        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());
        let root = smt.root();
        let proof = smt.prove(None, b"anything");
        assert_eq!(verify_hbsmt(&root, &proof, None, b"anything", b"v"),
                   HbsmtVerifyStatus::NonExistence);
        assert!(proof.siblings.is_empty());
        assert_eq!(proof.terminus, HbsmtTerminus::Empty);
    }

    #[test]
    fn smt_rdb_proof_single_leaf_tree() {
        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());
        smt.batch_update(vec![ins(b"only", b"the-one")]);
        let root = smt.root();

        let p1 = smt.prove(None, b"only");
        assert_eq!(verify_hbsmt(&root, &p1, None, b"only", b"the-one"),
                   HbsmtVerifyStatus::Included);
        assert_eq!(verify_hbsmt(&root, &p1, None, b"only", b"WRONG"),
                   HbsmtVerifyStatus::Mismatch);
        let p2 = smt.prove(None, b"absent");
        assert_eq!(verify_hbsmt(&root, &p2, None, b"absent", b"anything"),
                   HbsmtVerifyStatus::NonExistence);
    }

    #[test]
    fn smt_rdb_proof_namespaced() {
        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());
        smt.batch_update(vec![
            ins_ns(b"ns-a", b"k", b"va"),
            ins_ns(b"ns-b", b"k", b"vb"),
        ]);
        let root = smt.root();
        let pa = smt.prove(Some(b"ns-a"), b"k");
        let pb = smt.prove(Some(b"ns-b"), b"k");
        assert_eq!(verify_hbsmt(&root, &pa, Some(b"ns-a"), b"k", b"va"),
                   HbsmtVerifyStatus::Included);
        assert_eq!(verify_hbsmt(&root, &pb, Some(b"ns-b"), b"k", b"vb"),
                   HbsmtVerifyStatus::Included);
        assert_eq!(verify_hbsmt(&root, &pa, Some(b"ns-a"), b"k", b"vb"),
                   HbsmtVerifyStatus::Mismatch);
    }

    /// Brute-force two distinct namespace strings sharing the same 4-byte
    /// `sha256(ns)[0..4]` prefix. The 4-byte prefix has ~2^32 entropy, so by
    /// birthday this resolves in well under 200k tries on average.
    fn find_4byte_ns_collision() -> (Vec<u8>, Vec<u8>) {
        use sha2::{Digest, Sha256};
        let mut seen: std::collections::HashMap<[u8; 4], Vec<u8>> = std::collections::HashMap::new();
        let mut i: u64 = 0;
        loop {
            let candidate = format!("ns-collide-{}", i).into_bytes();
            let mut h = Sha256::new();
            h.update(&candidate);
            let full: [u8; 32] = h.finalize().into();
            let mut prefix = [0u8; 4];
            prefix.copy_from_slice(&full[0..4]);
            if let Some(other) = seen.get(&prefix) {
                if other != &candidate {
                    return (other.clone(), candidate);
                }
            } else {
                seen.insert(prefix, candidate);
            }
            i += 1;
            assert!(i < 5_000_000, "no 4-byte collision found in 5M tries (unexpected)");
        }
    }

    /// **Cross-namespace NonExistence (defense-in-depth)** — proves the
    /// two-component leaf-hash design correctly handles the case where the
    /// application convention is VIOLATED: a writer forgets to embed the
    /// namespace identifier in the key, two ns happen to share the 4-byte
    /// path prefix, and both write the same key. Only one leaf physically
    /// exists. The verifier must report `NonExistence` for the non-writer
    /// namespace — never `Mismatch` (which would leak the other writer's
    /// value as "this exists with a different value").
    ///
    /// Under enforced convention this scenario cannot occur; under broken
    /// convention this fallback is what keeps the proof system honest.
    #[test]
    fn collided_namespace_same_key_nonexistence_not_mismatch() {
        let (ns_a, ns_b) = find_4byte_ns_collision();
        assert_ne!(ns_a, ns_b);

        // Paths actually collide on 4-byte prefix; same key → full collision.
        let p_a = compute_namespace_path_hbsmt(&ns_a, b"k");
        let p_b = compute_namespace_path_hbsmt(&ns_b, b"k");
        assert_eq!(p_a, p_b, "engineered same-key cross-ns path collision");

        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());
        smt.batch_update(vec![Op::Insert(Some(ns_a.clone()), b"k".to_vec(), b"v_a".to_vec())]);
        let root = smt.root();

        let p = smt.prove(Some(&ns_a), b"k");
        assert_eq!(verify_hbsmt(&root, &p, Some(&ns_a), b"k", b"v_a"), HbsmtVerifyStatus::Included);
        assert_eq!(verify_hbsmt(&root, &p, Some(&ns_a), b"k", b"WRONG"), HbsmtVerifyStatus::Mismatch);
        // The crucial one: ns_b never wrote here → NonExistence, NOT Mismatch.
        assert_eq!(verify_hbsmt(&root, &p, Some(&ns_b), b"k", b"v_a"), HbsmtVerifyStatus::NonExistence,
            "collided ns must NOT report Mismatch — it would leak ns_a's value");
        assert_eq!(verify_hbsmt(&root, &p, Some(&ns_b), b"k", b"WRONG"), HbsmtVerifyStatus::NonExistence);

        // ns_b overwrites; symmetric — ns_a now sees NonExistence.
        smt.batch_update(vec![Op::Insert(Some(ns_b.clone()), b"k".to_vec(), b"v_b".to_vec())]);
        let root = smt.root();
        let p = smt.prove(Some(&ns_b), b"k");
        assert_eq!(verify_hbsmt(&root, &p, Some(&ns_b), b"k", b"v_b"), HbsmtVerifyStatus::Included);
        assert_eq!(verify_hbsmt(&root, &p, Some(&ns_a), b"k", b"v_a"), HbsmtVerifyStatus::NonExistence);
    }

    /// Collided namespaces with DIFFERENT keys → distinct leaves at distinct
    /// paths (the normal case under enforced convention). Both verify
    /// independently; cross-queries → NonExistence.
    #[test]
    fn collided_namespace_different_keys_independent_leaves() {
        let (ns_a, ns_b) = find_4byte_ns_collision();

        // Different keys → paths must differ in bytes 4..32.
        let p_a = compute_namespace_path_hbsmt(&ns_a, b"key-a");
        let p_b = compute_namespace_path_hbsmt(&ns_b, b"key-b");
        assert_eq!(p_a[0..4], p_b[0..4], "ns prefixes collide as engineered");
        assert_ne!(p_a, p_b, "different keys → different paths");

        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());
        smt.batch_update(vec![
            Op::Insert(Some(ns_a.clone()), b"key-a".to_vec(), b"v-a".to_vec()),
            Op::Insert(Some(ns_b.clone()), b"key-b".to_vec(), b"v-b".to_vec()),
        ]);
        let root = smt.root();

        let pa = smt.prove(Some(&ns_a), b"key-a");
        let pb = smt.prove(Some(&ns_b), b"key-b");
        assert_eq!(verify_hbsmt(&root, &pa, Some(&ns_a), b"key-a", b"v-a"), HbsmtVerifyStatus::Included);
        assert_eq!(verify_hbsmt(&root, &pb, Some(&ns_b), b"key-b", b"v-b"), HbsmtVerifyStatus::Included);

        // Cross-queries with a different ns AND/OR different key land at a
        // path different from the proved leaf's path → NonExistence.
        assert_eq!(verify_hbsmt(&root, &pa, Some(&ns_b), b"key-a", b"v-a"), HbsmtVerifyStatus::NonExistence);
        assert_eq!(verify_hbsmt(&root, &pb, Some(&ns_a), b"key-b", b"v-b"), HbsmtVerifyStatus::NonExistence);
    }

    /// Roots must match between in-memory and RocksDB versions for the same
    /// workload — proves both implementations share the algorithm exactly.
    #[test]
    fn smt_inmem_and_rdb_roots_agree() {
        let ops = vec![
            ins(b"a", b"1"),
            ins(b"b", b"2"),
            ins_ns(b"ns-1", b"c", b"3"),
            ins_ns(b"ns-2", b"c", b"4"),
            ins(b"a", b"1b"),  // duplicate-key collapse
            del(b"b"),
            ins(b"d", b"5"),
        ];

        let mut mem = crate::consensus::hbsmt::Hbsmt::new();
        mem.batch_update(ops.clone());
        let r_mem = mem.root();

        let dir = TempDir::new().unwrap();
        let rdb = HbsmtRdb::open(dir.path());
        rdb.batch_update(ops);
        let r_rdb = rdb.root();

        assert_eq!(r_mem, r_rdb, "in-memory and RocksDB SMT must produce identical roots");
    }

    // -----------------------------------------------------------------
    // Shipping benchmark: 1M tree, hot-namespace 10k batch.
    // Single test that proves the production target (<500ms apply).
    // -----------------------------------------------------------------
    #[test]
    #[ignore = "perf — 100k tree, 10k hot-ns batch"]
    fn bench_smtrdb_100k_hot_ns() {
        const TREE_SIZE: usize = 100_000;
        const BATCH_SIZE: usize = 10_000;
        const NS_COUNT: u32 = 100;
        const HOT_NS: &str = "ns-00";

        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());

        let initial = build_ops(TREE_SIZE as u32, NS_COUNT);
        let t = Instant::now();
        for chunk in initial.chunks(50_000) {
            smt.batch_update(chunk.to_vec());
        }
        let build_ms = t.elapsed().as_millis();

        let mut delta = Vec::with_capacity(BATCH_SIZE);
        for i in 0..BATCH_SIZE {
            let key_idx = (i % TREE_SIZE) as u32;
            let k = format!("key-{:08}", key_idx * NS_COUNT);
            let v = format!("hot-v-{}", i);
            delta.push(ins_ns(HOT_NS.as_bytes(), k.as_bytes(), v.as_bytes()));
        }

        let t = Instant::now();
        smt.batch_update(delta);
        let apply_ms = t.elapsed().as_millis();
        let t = Instant::now();
        let _ = smt.root();
        let root_us = t.elapsed().as_micros();

        println!("\n==== HbsmtRdb 100k, hot-namespace 10k batch ====");
        println!("    build={}ms  apply={}ms  root={}µs", build_ms, apply_ms, root_us);
        assert!(apply_ms < 500, "100k apply must be <500ms, got {}ms", apply_ms);
    }

    #[test]
    #[ignore = "slow — production-target benchmark (1M tree, 10k hot-ns batch)"]
    fn bench_smtrdb_1m_hot_ns() {
        const TREE_SIZE: usize = 1_000_000;
        const BATCH_SIZE: usize = 10_000;
        const NS_COUNT: u32 = 100;
        const HOT_NS: &str = "ns-00";

        let dir = TempDir::new().unwrap();
        let smt = HbsmtRdb::open(dir.path());

        // Build the tree in 50k-op chunks.
        let initial = build_ops(TREE_SIZE as u32, NS_COUNT);
        let t = Instant::now();
        for chunk in initial.chunks(50_000) {
            smt.batch_update(chunk.to_vec());
        }
        let build_ms = t.elapsed().as_millis();

        // Hot-namespace delta: 10k updates all in ns-00.
        let mut delta = Vec::with_capacity(BATCH_SIZE);
        for i in 0..BATCH_SIZE {
            let key_idx = (i % TREE_SIZE) as u32;
            let k = format!("key-{:08}", key_idx * NS_COUNT);
            let v = format!("hot-v-{}", i);
            delta.push(ins_ns(HOT_NS.as_bytes(), k.as_bytes(), v.as_bytes()));
        }

        let t = Instant::now();
        smt.batch_update(delta);
        let apply_ms = t.elapsed().as_millis();
        let t = Instant::now();
        let _ = smt.root();
        let root_us = t.elapsed().as_micros();

        println!("\n==== HbsmtRdb 1M, hot-namespace 10k batch ====");
        println!("    build={}ms  apply={}ms  root={}µs", build_ms, apply_ms, root_us);
        assert!(apply_ms < 500, "production target: apply must be <500ms, got {}ms", apply_ms);
    }
}
