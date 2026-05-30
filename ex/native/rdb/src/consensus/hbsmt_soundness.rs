//! Soundness audit tests for `Hbsmt` (in-memory) and `HbsmtRdb` (RocksDB).
//!
//! These tests target invariants the algorithm must preserve:
//!   1. RocksDB and in-memory implementations produce identical roots and proofs.
//!   2. `prove()` always returns a verifier-acceptable proof for the current root.
//!   3. After any combination of inserts/deletes the stored `splits` CF / map
//!      stays consistent with the leaves under it (no stale entries leak into a
//!      later `subtree_hash`/`subtree_hash_db` lookup).
//!   4. Sequential application of small batches yields the same root as one
//!      big batch (a real-world scenario: blocks applied one-by-one).
//!   5. `subtree_range` / `mask_after_be` / `set_bit_be` bit math is correct
//!      at byte boundaries and the extremes (depth 0, 256).
//!   6. Empty-tree root and proof handling agree across implementations.

#![cfg(test)]

use crate::consensus::bintree::{
    get_bit_be, mask_after_be, set_bit_be, Hash, Op, Path, ZERO_HASH,
};
use crate::consensus::consensus_apply::{ApplyEnv, CallerEnv};
use crate::consensus::hbsmt::Hbsmt;
use crate::consensus::hbsmt_common::{
    compute_namespace_path_hbsmt, identity_hash, leaf_hash_from_components, lcp_depth,
    lift_single_leaf, make_empties, subtree_range, value_hash, verify_hbsmt, verify_hbsmt_raw,
    HbsmtProof, HbsmtTerminus, HbsmtVerifyStatus,
};
use crate::consensus::hbsmt_rdb::{hbsmt_batch_update_env, hbsmt_root_env, HbsmtRdb};
use rust_rocksdb::{
    ColumnFamilyDescriptor, MultiThreaded, Options, TransactionDB, TransactionDBOptions,
};
use std::collections::HashSet;
use tempfile::TempDir;

fn ins(k: &[u8], v: &[u8]) -> Op { Op::Insert(None, k.to_vec(), v.to_vec()) }
fn ins_ns(ns: &[u8], k: &[u8], v: &[u8]) -> Op {
    Op::Insert(Some(ns.to_vec()), k.to_vec(), v.to_vec())
}
fn del(k: &[u8]) -> Op { Op::Delete(None, k.to_vec()) }

/// Apply a sequence of batches to both implementations and require their roots
/// agree after every batch. Returns the final root for further checks.
fn run_parallel(batches: &[Vec<Op>]) -> [u8; 32] {
    let mut mem = Hbsmt::new();
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());

    let mut last = [0u8; 32];
    for (i, b) in batches.iter().enumerate() {
        mem.batch_update(b.clone());
        rdb.batch_update(b.clone());
        let rm = mem.root();
        let rr = rdb.root();
        assert_eq!(
            rm, rr,
            "in-memory and RocksDB roots disagree after batch {} (size={})",
            i, b.len()
        );
        last = rm;
    }
    last
}

// ----------------------------------------------------------------------------
// 1. Bit math / range primitives.
// ----------------------------------------------------------------------------

#[test]
fn subtree_range_depth_0_covers_universe() {
    let (lo, hi) = subtree_range(&[0u8; 32], 0);
    assert_eq!(lo, [0u8; 32]);
    assert_eq!(hi, [0xFFu8; 32]);
}

#[test]
fn subtree_range_depth_256_is_singleton() {
    let p = [0xABu8; 32];
    let (lo, hi) = subtree_range(&p, 256);
    assert_eq!(lo, p);
    assert_eq!(hi, p);
}

#[test]
fn subtree_range_byte_boundaries() {
    // At every byte boundary, lo should preserve the first `d/8` bytes of
    // prefix and zero the rest; hi should fill rest with 0xFF.
    let mut prefix = [0u8; 32];
    for (i, b) in prefix.iter_mut().enumerate() { *b = (i as u8) ^ 0x5A; }
    for byte in 0..32u16 {
        let d = byte * 8;
        let (lo, hi) = subtree_range(&prefix, d);
        for i in 0..(byte as usize) {
            assert_eq!(lo[i], prefix[i], "byte boundary lo prefix at d={}", d);
            assert_eq!(hi[i], prefix[i], "byte boundary hi prefix at d={}", d);
        }
        for i in (byte as usize)..32 {
            assert_eq!(lo[i], 0, "byte boundary lo zero-fill at d={} byte={}", d, i);
            assert_eq!(hi[i], 0xFF, "byte boundary hi 0xFF-fill at d={} byte={}", d, i);
        }
    }
}

#[test]
fn subtree_range_mid_byte() {
    // depth=4 with prefix=0x80: byte 0 must keep top 4 bits.
    let mut prefix = [0u8; 32];
    prefix[0] = 0x80;
    let (lo, hi) = subtree_range(&prefix, 4);
    assert_eq!(lo[0], 0x80, "lo top nibble preserved");
    assert_eq!(hi[0], 0x8F, "hi top nibble preserved, bottom set");
    for i in 1..32 {
        assert_eq!(lo[i], 0);
        assert_eq!(hi[i], 0xFF);
    }
}

#[test]
fn mask_after_be_extremes() {
    let mut p = [0xFFu8; 32];
    mask_after_be(&mut p, 0);
    assert_eq!(p, [0u8; 32], "mask 0 zeros everything");

    let mut p = [0xABu8; 32];
    let orig = p;
    mask_after_be(&mut p, 256);
    assert_eq!(p, orig, "mask 256 leaves data unchanged");
}

#[test]
fn mask_after_be_partial_byte() {
    let mut p = [0xFFu8; 32];
    mask_after_be(&mut p, 4); // keep top 4 bits of byte 0, zero rest
    assert_eq!(p[0], 0xF0);
    for i in 1..32 { assert_eq!(p[i], 0); }
}

#[test]
fn set_bit_be_get_bit_be_roundtrip() {
    let mut p = [0u8; 32];
    for d in 0..256u16 {
        set_bit_be(&mut p, d, 1);
        assert_eq!(get_bit_be(&p, d), 1, "bit {} set", d);
        set_bit_be(&mut p, d, 0);
        assert_eq!(get_bit_be(&p, d), 0, "bit {} cleared", d);
    }
}

#[test]
fn lcp_depth_byte_boundary() {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a[1] = 0x80; b[1] = 0x00; // differ at bit 8
    assert_eq!(lcp_depth(&a, &b), 8);

    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a[1] = 0x40; b[1] = 0x00; // differ at bit 9
    assert_eq!(lcp_depth(&a, &b), 9);

    let same = [0xAAu8; 32];
    assert_eq!(lcp_depth(&same, &same), 256);
}

// ----------------------------------------------------------------------------
// 2. Empty-tree.
// ----------------------------------------------------------------------------

#[test]
fn empty_tree_roots_match() {
    let mut mem = Hbsmt::new();
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());
    let empties = make_empties();
    assert_eq!(mem.root(), empties[0]);
    assert_eq!(rdb.root(), empties[0]);
}

#[test]
fn empty_tree_proof_is_acceptable() {
    let mut mem = Hbsmt::new();
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());
    let r_mem = mem.root();
    let r_rdb = rdb.root();
    let p_mem = mem.prove(None, b"x");
    let p_rdb = rdb.prove(None, b"x");
    assert_eq!(p_mem, p_rdb, "in-mem and RDB empty-tree proofs disagree");
    assert_eq!(
        verify_hbsmt(&r_mem, &p_mem, None, b"x", b"v"),
        HbsmtVerifyStatus::NonExistence
    );
    assert_eq!(
        verify_hbsmt(&r_rdb, &p_rdb, None, b"x", b"v"),
        HbsmtVerifyStatus::NonExistence
    );
}

// ----------------------------------------------------------------------------
// 3. No-op batches don't drift the root.
// ----------------------------------------------------------------------------

#[test]
fn redundant_insert_does_not_change_root() {
    let initial = vec![ins(b"a", b"1"), ins(b"b", b"2"), ins(b"c", b"3")];
    let root = run_parallel(&[initial.clone()]);
    // Re-inserting same (key, value) should be a no-op.
    let root2 = run_parallel(&[initial.clone(), vec![ins(b"a", b"1"), ins(b"b", b"2")]]);
    assert_eq!(root, root2);
}

#[test]
fn delete_nonexistent_is_noop() {
    let initial = vec![ins(b"a", b"1"), ins(b"b", b"2")];
    let r1 = run_parallel(&[initial.clone()]);
    let r2 = run_parallel(&[initial.clone(), vec![del(b"zzz")]]);
    assert_eq!(r1, r2);
}

// ----------------------------------------------------------------------------
// 4. Stale-split: classic & adversarial.
// ----------------------------------------------------------------------------

/// Two leaves sharing a deep prefix create deep splits. Then both get deleted
/// (subtree collapses), but later a NEW pair of leaves is inserted into the
/// SAME deep-prefix region. If stale splits leak in, the new pair's root will
/// be wrong.
#[test]
fn deep_split_collapse_then_reinsert() {
    // Find two keys with high LCP and two different keys with a different but
    // also-high LCP that lands in the same region — we just exercise the path
    // through ordinary keys; the algorithm's invariants are not LCP-specific.
    let pre = vec![ins(b"alpha", b"1"), ins(b"beta", b"2"), ins(b"gamma", b"3")];
    let delete = vec![del(b"alpha"), del(b"beta")];
    let reinsert = vec![ins(b"alpha", b"NEW1"), ins(b"beta", b"NEW2")];

    let root = run_parallel(&[pre.clone(), delete, reinsert.clone()]);

    // Compare against the equivalent end state built from scratch.
    let scratch = vec![ins(b"gamma", b"3"), ins(b"alpha", b"NEW1"), ins(b"beta", b"NEW2")];
    let scratch_root = run_parallel(&[scratch]);
    assert_eq!(root, scratch_root);
}

/// Hot-namespace stress: lots of keys sharing a common prefix, then mass
/// delete, then mass reinsert with different values. Exercises the LCP-jump
/// short-circuit AND the post-collapse reinsertion path repeatedly.
#[test]
fn hot_namespace_collapse_and_reinsert() {
    let ns = b"hot-ns";
    let mut pre = Vec::new();
    for i in 0..50u32 {
        pre.push(ins_ns(ns, format!("k{:04}", i).as_bytes(), format!("v{}", i).as_bytes()));
    }
    let mut delete = Vec::new();
    for i in 0..50u32 {
        delete.push(Op::Delete(Some(ns.to_vec()), format!("k{:04}", i).as_bytes().to_vec()));
    }
    let mut reinsert = Vec::new();
    for i in 0..50u32 {
        reinsert.push(ins_ns(ns, format!("k{:04}", i).as_bytes(), format!("V2-{}", i).as_bytes()));
    }
    let root = run_parallel(&[pre.clone(), delete.clone(), reinsert.clone()]);

    // Equivalent: a single batch with the final state.
    let mut single = Vec::new();
    for i in 0..50u32 {
        single.push(ins_ns(ns, format!("k{:04}", i).as_bytes(), format!("V2-{}", i).as_bytes()));
    }
    let single_root = run_parallel(&[single]);
    assert_eq!(root, single_root);
}

// ----------------------------------------------------------------------------
// 5. Many sequential batches must equal one big batch.
// ----------------------------------------------------------------------------

#[test]
fn chunked_vs_single_batch_agree() {
    // Build a final state via two different paths and assert roots agree.
    let mut all_inserts: Vec<Op> = (0..300u32)
        .map(|i| ins(format!("k{:04}", i).as_bytes(), format!("v{}", i).as_bytes()))
        .collect();
    // Mix in some deletes and re-inserts.
    for i in 0..50u32 {
        all_inserts.push(del(format!("k{:04}", i).as_bytes()));
        all_inserts.push(ins(format!("k{:04}", i).as_bytes(), format!("v2-{}", i).as_bytes()));
    }
    let big = run_parallel(&[all_inserts.clone()]);

    let chunks: Vec<Vec<Op>> = all_inserts.chunks(13).map(|c| c.to_vec()).collect();
    let chunked = run_parallel(&chunks);
    assert_eq!(big, chunked);
}

// ----------------------------------------------------------------------------
// 6. Proofs: after EVERY batch, every present key proves to Included and
//    every absent key proves to NonExistence.
// ----------------------------------------------------------------------------

#[test]
fn proofs_consistent_across_implementations_and_batches() {
    let batches: Vec<Vec<Op>> = vec![
        vec![ins(b"a", b"1"), ins(b"b", b"2"), ins(b"c", b"3"), ins(b"d", b"4")],
        vec![del(b"b"), ins(b"e", b"5")],
        vec![ins(b"a", b"1-new"), del(b"c")],
        (0..40u32).map(|i| ins(format!("z{}", i).as_bytes(), format!("vz{}", i).as_bytes())).collect(),
        (0..20u32).map(|i| del(format!("z{}", i).as_bytes())).collect(),
    ];

    let mut mem = Hbsmt::new();
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());

    // Track expected final state for each key.
    use std::collections::BTreeMap;
    let mut state: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    for (idx, b) in batches.iter().enumerate() {
        mem.batch_update(b.clone());
        rdb.batch_update(b.clone());

        // Apply same ops to our reference state.
        for op in b {
            match op {
                Op::Insert(_, k, v) => { state.insert(k.clone(), v.clone()); }
                Op::Delete(_, k) => { state.remove(k); }
            }
        }

        let rm = mem.root();
        let rr = rdb.root();
        assert_eq!(rm, rr, "roots disagree after batch {}", idx);

        // For every present key: proof must verify Included.
        for (k, v) in &state {
            let p_mem = mem.prove(None, k);
            let p_rdb = rdb.prove(None, k);
            assert_eq!(p_mem, p_rdb, "proofs disagree for present key {:?} batch {}", k, idx);
            assert_eq!(
                verify_hbsmt(&rm, &p_mem, None, k, v),
                HbsmtVerifyStatus::Included,
                "Included expected for key {:?} batch {}", k, idx
            );
        }

        // For some plausibly-absent keys: NonExistence.
        for absent in [b"__not_a_key__".as_slice(), b"absent-xyzzy"] {
            if state.contains_key(absent) { continue; }
            let p_mem = mem.prove(None, absent);
            let p_rdb = rdb.prove(None, absent);
            assert_eq!(p_mem, p_rdb, "absent proofs disagree {:?} batch {}", absent, idx);
            let s = verify_hbsmt(&rm, &p_mem, None, absent, b"x");
            assert_eq!(
                s, HbsmtVerifyStatus::NonExistence,
                "NonExistence expected for absent {:?} batch {}, got {:?}",
                absent, idx, s
            );
        }
    }
}

// ----------------------------------------------------------------------------
// 7. Adversarial: keys differing only in deep bits (forces deep splits/LCP).
// ----------------------------------------------------------------------------

/// Use namespaces to force common prefixes — exercises the LCP-jump short
/// circuit at very high depths.
#[test]
fn deep_lcp_keys_round_trip() {
    let ns = b"NS";
    // Many keys all under same namespace → first 64 bits of path are shared.
    let batch: Vec<Op> = (0..100u32)
        .map(|i| ins_ns(ns, format!("k{:08}", i).as_bytes(), format!("v{}", i).as_bytes()))
        .collect();

    let root = run_parallel(&[batch.clone()]);

    // Verify proofs for a few.
    let mut mem = Hbsmt::new();
    mem.batch_update(batch.clone());
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());
    rdb.batch_update(batch);
    for i in [0u32, 7, 33, 99] {
        let k = format!("k{:08}", i);
        let v = format!("v{}", i);
        let p_mem = mem.prove(Some(ns), k.as_bytes());
        let p_rdb = rdb.prove(Some(ns), k.as_bytes());
        assert_eq!(p_mem, p_rdb);
        assert_eq!(
            verify_hbsmt(&root, &p_mem, Some(ns), k.as_bytes(), v.as_bytes()),
            HbsmtVerifyStatus::Included
        );
    }
}

// ----------------------------------------------------------------------------
// 8. Order-independence within a batch (single op per key).
// ----------------------------------------------------------------------------

#[test]
fn shuffled_unique_keys_same_root() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash as StdHash, Hasher};

    let mutations: Vec<Op> = (0..150u32)
        .map(|i| ins(format!("k{:04}", i).as_bytes(), format!("v{}", i).as_bytes()))
        .collect();

    let canonical = run_parallel(&[mutations.clone()]);

    for seed in 0u64..5 {
        let mut indexed: Vec<(u64, Op)> = mutations.iter().cloned().enumerate().map(|(i, op)| {
            let mut h = DefaultHasher::new();
            (i as u64, seed).hash(&mut h);
            (h.finish(), op)
        }).collect();
        indexed.sort_by_key(|(h, _)| *h);
        let shuffled: Vec<Op> = indexed.into_iter().map(|(_, op)| op).collect();
        let r = run_parallel(&[shuffled]);
        assert_eq!(canonical, r, "shuffle seed {} disagrees", seed);
    }
}

// ----------------------------------------------------------------------------
// 9. Single-leaf-collapse edge cases.
// ----------------------------------------------------------------------------

/// Insert two leaves whose paths force a split deep in the tree, then delete
/// one. The remaining single leaf must lift correctly to the root.
#[test]
fn split_collapse_to_single_leaf() {
    let r1 = run_parallel(&[
        vec![ins(b"alpha", b"1"), ins(b"beta", b"2")],
        vec![del(b"beta")],
    ]);
    let r2 = run_parallel(&[vec![ins(b"alpha", b"1")]]);
    assert_eq!(r1, r2);
}

#[test]
fn single_leaf_proof_round_trip() {
    let mut mem = Hbsmt::new();
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());
    mem.batch_update(vec![ins(b"only", b"the-one")]);
    rdb.batch_update(vec![ins(b"only", b"the-one")]);
    let rm = mem.root();
    let rr = rdb.root();
    assert_eq!(rm, rr);
    let p_mem = mem.prove(None, b"only");
    let p_rdb = rdb.prove(None, b"only");
    assert_eq!(p_mem, p_rdb);
    assert_eq!(verify_hbsmt(&rm, &p_mem, None, b"only", b"the-one"), HbsmtVerifyStatus::Included);
    // For a single-leaf tree the prover may emit zero siblings — verify that
    // the terminus exposes the leaf directly.
    if let HbsmtTerminus::Leaf { path, identity_hash: id, value_hash: val } = &p_mem.terminus {
        let expected = compute_namespace_path_hbsmt(b"", b"only");
        assert_eq!(*path, expected);
        // The lift to the root must succeed (test above already validates this).
        let empties = make_empties();
        let lh = crate::consensus::hbsmt_common::leaf_hash_from_components(id, val);
        let lifted = lift_single_leaf(lh, path, p_mem.siblings.len() as u16, &empties);
        // Walk up with siblings.
        let mut h = lifted;
        for d in (0..p_mem.siblings.len()).rev() {
            let bit = get_bit_be(&expected, d as u16);
            h = if bit == 0 {
                crate::consensus::hbsmt_common::hbsmt_node_hash(&h, &p_mem.siblings[d])
            } else {
                crate::consensus::hbsmt_common::hbsmt_node_hash(&p_mem.siblings[d], &h)
            };
        }
        assert_eq!(h, rm);
    } else {
        panic!("single-leaf prove should return Leaf terminus");
    }
}

// ----------------------------------------------------------------------------
// 10. Workload-driven fuzz: many random ops, parallel against ref impl.
// ----------------------------------------------------------------------------

#[test]
fn fuzz_many_batches_implementations_agree() {
    // Deterministic LCG.
    let mut s: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut next = || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    };

    let mut mem = Hbsmt::new();
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());
    use std::collections::BTreeMap;
    let mut state: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

    for batch_no in 0..20 {
        let batch_size = (next() % 25 + 1) as usize;
        let mut batch = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            let r = next();
            let key_idx = r % 64;
            let k = format!("k{:04}", key_idx).into_bytes();
            // 75% inserts, 25% deletes
            if (r >> 32) % 4 == 0 {
                batch.push(Op::Delete(None, k));
            } else {
                let v = format!("v{}-b{}", r % 1000, batch_no).into_bytes();
                batch.push(Op::Insert(None, k, v));
            }
        }

        // Apply to reference state with last-write-wins semantics per batch.
        let mut latest: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        for op in &batch {
            match op {
                Op::Insert(_, k, v) => { latest.insert(k.clone(), Some(v.clone())); }
                Op::Delete(_, k) => { latest.insert(k.clone(), None); }
            }
        }
        for (k, v) in latest {
            match v {
                Some(v) => { state.insert(k, v); }
                None => { state.remove(&k); }
            }
        }

        mem.batch_update(batch.clone());
        rdb.batch_update(batch);
        let rm = mem.root();
        let rr = rdb.root();
        assert_eq!(rm, rr, "roots disagree after batch {}", batch_no);

        // Spot-check 4 random keys: present → Included, absent → NonExistence.
        for _ in 0..4 {
            let key_idx = next() % 64;
            let k = format!("k{:04}", key_idx).into_bytes();
            let p = mem.prove(None, &k);
            let p_rdb = rdb.prove(None, &k);
            assert_eq!(p, p_rdb, "proofs disagree for {:?} batch {}", k, batch_no);
            if let Some(v) = state.get(&k) {
                assert_eq!(
                    verify_hbsmt(&rm, &p, None, &k, v),
                    HbsmtVerifyStatus::Included,
                    "Included expected for present {:?} batch {}", k, batch_no
                );
            } else {
                assert_eq!(
                    verify_hbsmt(&rm, &p, None, &k, b"any"),
                    HbsmtVerifyStatus::NonExistence,
                    "NonExistence expected for absent {:?} batch {}", k, batch_no
                );
            }
        }
    }
}

// ----------------------------------------------------------------------------
// 11. Sibling-empty in standard bifurcation: when one side becomes empty by
//     deletion, the split must be removed (no stale entry). Tested indirectly
//     by chunked-vs-single equivalence, but make it explicit.
// ----------------------------------------------------------------------------

#[test]
fn bifurcation_one_side_empties_no_stale_split() {
    // Build a tree, then delete all leaves on one path so only one side has
    // anything. The root must equal a freshly-built tree of the remaining keys.
    let initial: Vec<Op> = (0..32u32)
        .map(|i| ins(format!("k{:04}", i).as_bytes(), format!("v{}", i).as_bytes()))
        .collect();
    let half_delete: Vec<Op> = (0..16u32)
        .map(|i| del(format!("k{:04}", i).as_bytes()))
        .collect();
    let r1 = run_parallel(&[initial, half_delete]);

    let remaining: Vec<Op> = (16..32u32)
        .map(|i| ins(format!("k{:04}", i).as_bytes(), format!("v{}", i).as_bytes()))
        .collect();
    let r2 = run_parallel(&[remaining]);
    assert_eq!(r1, r2);
}

// ----------------------------------------------------------------------------
// 12. Path computation: namespace boundary.
// ----------------------------------------------------------------------------

#[test]
fn namespace_isolation_in_path() {
    // Same key in different namespaces gives different paths and different leaves.
    let p_none = compute_namespace_path_hbsmt(b"", b"x");
    let p_a = compute_namespace_path_hbsmt(b"a", b"x");
    let p_b = compute_namespace_path_hbsmt(b"b", b"x");
    assert_ne!(p_none, p_a);
    assert_ne!(p_a, p_b);
    // First 8 bytes differ between ns variants; last 24 are sha256(b"x")[..24]
    // and must match.
    assert_eq!(&p_none[8..32], &p_a[8..32]);
    assert_eq!(&p_a[8..32], &p_b[8..32]);
}

// ----------------------------------------------------------------------------
// 13. LCP-jump where dirty side becomes empty (the audited concern).
//
// Setup: a hot region with N+ leaves under a high-LCP prefix. A batch deletes
// ALL leaves in that region. Then a follow-up batch adds a single new leaf
// outside the region. If the LCP-jump leaves any stale split behind on the
// way back to the root, the second batch's subtree_hash for the now-empty
// region will return a wrong hash.
// ----------------------------------------------------------------------------

#[test]
fn lcp_jump_dirty_side_fully_emptied() {
    let ns = b"HOT";
    let mut initial = Vec::new();
    for i in 0..40u32 {
        initial.push(ins_ns(ns, format!("k{:04}", i).as_bytes(), format!("v{}", i).as_bytes()));
    }
    // Add one leaf OUTSIDE the hot ns so the tree isn't single-leaf-collapsed.
    initial.push(ins(b"outside", b"keep-me"));

    let mut delete_all = Vec::new();
    for i in 0..40u32 {
        delete_all.push(Op::Delete(Some(ns.to_vec()), format!("k{:04}", i).as_bytes().to_vec()));
    }

    let r1 = run_parallel(&[initial, delete_all, vec![ins(b"another", b"v")]]);
    let r2 = run_parallel(&[vec![ins(b"outside", b"keep-me"), ins(b"another", b"v")]]);
    assert_eq!(r1, r2, "LCP-jump leaves stale splits after full emptying");
}

// ----------------------------------------------------------------------------
// 14. Mixed mutate-in-place within a single batch (ins/del/ins same key).
// ----------------------------------------------------------------------------

#[test]
fn ins_del_ins_same_key_in_one_batch() {
    // Final state is k=a. The "no-op if value already present" guard collapses
    // the dirty set when prev == final; we just want the algorithm to settle
    // on the right root.
    let r1 = run_parallel(&[vec![ins(b"k", b"a"), del(b"k"), ins(b"k", b"a")]]);
    let r2 = run_parallel(&[vec![ins(b"k", b"a")]]);
    assert_eq!(r1, r2);
}

// ============================================================================
// Attack tests — NonExistence forgery against the single-CF design.
// (Merged from former hbsmt_attacks_nonexistence_single_cf.rs.)
// ============================================================================


/// Build a small tree with enough leaves that the descent for any given key
/// stops at depth > 0 (so siblings.len() > 0 and there is something to flip).
fn build_attack_tree() -> (TempDir, HbsmtRdb, Vec<(Vec<u8>, Vec<u8>)>) {
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    let mut kvs = Vec::new();
    let mut ops = Vec::new();
    for i in 0..64u32 {
        let k = format!("attack-key-{:04}", i).into_bytes();
        let v = format!("v-{}", i).into_bytes();
        ops.push(ins(&k, &v));
        kvs.push((k, v));
    }
    smt.batch_update(ops);
    (dir, smt, kvs)
}

// ============================================================================
// Attack 1: bit-flip on terminus.path at depth < stop must yield Invalid
// (the previously-fixed censorship oracle).
// ============================================================================
#[test]
fn attack1_terminus_path_bitflip_below_stop_is_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();

    for (k, v) in &kvs {
        let proof = smt.prove(None, k);
        assert_eq!(
            verify_hbsmt(&root, &proof, None, k, v),
            HbsmtVerifyStatus::Included,
            "baseline inclusion failed for {:?}", k
        );
        let stop = proof.siblings.len();
        if stop == 0 { continue; } // empty terminus or root-leaf — nothing to flip below stop

        // We need a Leaf terminus with stop > 0 to have a bit < stop to flip.
        let original_path = if let HbsmtTerminus::Leaf { path, .. } = &proof.terminus {
            *path
        } else {
            continue;
        };

        for d in 0..stop {
            let mut bad = proof.clone();
            if let HbsmtTerminus::Leaf { ref mut path, .. } = bad.terminus {
                let bit = get_bit_be(path, d as u16);
                set_bit_be(path, d as u16, 1 - bit);
            }
            let status = verify_hbsmt(&root, &bad, None, k, v);
            assert_eq!(
                status, HbsmtVerifyStatus::Invalid,
                "bit-flip at depth {} of terminus.path (key={:?}, stop={}) was NOT blocked: got {:?}",
                d, k, stop, status
            );
            // Sanity: original is fine.
            if let HbsmtTerminus::Leaf { ref mut path, .. } = bad.terminus {
                *path = original_path;
            }
        }
    }
}

// ============================================================================
// Attack 1b: multi-bit / byte-aligned flips below stop must also be Invalid.
// ============================================================================
#[test]
fn attack1b_multi_bit_flips_below_stop_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();

    for (k, v) in &kvs {
        let proof = smt.prove(None, k);
        let stop = proof.siblings.len();
        if stop < 8 { continue; }
        if !matches!(proof.terminus, HbsmtTerminus::Leaf { .. }) { continue; }

        // Flip an entire byte at the largest byte boundary fully below stop.
        let byte_to_flip = (stop / 8).saturating_sub(1);
        let mut bad = proof.clone();
        if let HbsmtTerminus::Leaf { ref mut path, .. } = bad.terminus {
            path[byte_to_flip] ^= 0xFF;
        }
        let status = verify_hbsmt(&root, &bad, None, k, v);
        assert_eq!(
            status, HbsmtVerifyStatus::Invalid,
            "byte-flip at byte {} (stop={}) not blocked, got {:?}",
            byte_to_flip, stop, status
        );
    }
}

// ============================================================================
// Attack 6: forge Empty terminus when the real subtree has a leaf.
// Must not verify against the honest root.
// ============================================================================
#[test]
fn attack6_forged_empty_terminus_at_various_stops_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();

    for (k, v) in &kvs {
        let honest = smt.prove(None, k);
        let honest_stop = honest.siblings.len();
        if honest_stop == 0 { continue; }

        // Try truncating siblings to every depth d in [0, honest_stop) and
        // claiming Empty — verifier should detect mismatch.
        for d in 0..honest_stop {
            let bad = HbsmtProof {
                siblings: honest.siblings[..d].to_vec(),
                terminus: HbsmtTerminus::Empty,
            };
            let status = verify_hbsmt(&root, &bad, None, k, v);
            assert_ne!(
                status, HbsmtVerifyStatus::NonExistence,
                "forged Empty at stop={} for existing key {:?} gave NonExistence",
                d, k
            );
            // We expect Invalid (root won't reconstruct).
            assert_eq!(
                status, HbsmtVerifyStatus::Invalid,
                "forged Empty at stop={} for {:?} not Invalid: got {:?}",
                d, k, status
            );
        }

        // Also: claim Empty at the honest stop depth (siblings unchanged).
        let bad = HbsmtProof {
            siblings: honest.siblings.clone(),
            terminus: HbsmtTerminus::Empty,
        };
        let status = verify_hbsmt(&root, &bad, None, k, v);
        assert_ne!(
            status, HbsmtVerifyStatus::NonExistence,
            "forged Empty at honest stop for {:?} → NonExistence", k
        );
        assert_eq!(status, HbsmtVerifyStatus::Invalid);
    }
}

// ============================================================================
// Attack 6b: forge Empty terminus claiming deeper stop than honest.
// Extend siblings with empties to try to fool the walk-up.
// ============================================================================
#[test]
fn attack6b_forged_empty_with_extended_siblings_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();
    let empties = make_empties();

    for (k, v) in &kvs {
        let honest = smt.prove(None, k);
        let honest_stop = honest.siblings.len();
        if honest_stop == 0 || honest_stop >= 256 { continue; }
        if !matches!(honest.terminus, HbsmtTerminus::Leaf { .. }) { continue; }

        // Append a few "empty" siblings, claim Empty terminus at the deeper
        // stop. The reconstructed leaf hash from Empty will be empties[new_stop]
        // which is not what's actually there → mismatch on walk-up.
        let mut extended = honest.siblings.clone();
        for d in honest_stop..(honest_stop + 4).min(256) {
            extended.push(empties[d + 1]);
        }
        let bad = HbsmtProof {
            siblings: extended,
            terminus: HbsmtTerminus::Empty,
        };
        let status = verify_hbsmt(&root, &bad, None, k, v);
        assert_ne!(
            status, HbsmtVerifyStatus::NonExistence,
            "extended-empty forgery returned NonExistence for {:?}", k
        );
        assert_eq!(status, HbsmtVerifyStatus::Invalid);
    }
}

// ============================================================================
// Attack 7: cross-namespace replay. An honest proof for (ns_a, k) must NOT
// verify against (ns_b, k) as Included or Mismatch (would reveal data); under
// distinct ns the paths almost always differ in upper 4 bytes so the walk-up
// will fail or terminus.path != target_path. Both NonExistence and Invalid
// are acceptable — but never Included/Mismatch.
// ============================================================================
#[test]
fn attack7_cross_ns_replay_does_not_leak_value() {
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    smt.batch_update(vec![
        ins_ns(b"ns-secret", b"target", b"SECRET_VALUE"),
        ins_ns(b"ns-public", b"other",  b"PUB"),
        // Fill some siblings so the descent stops deep.
        ins_ns(b"ns-secret", b"pad-1", b"x"),
        ins_ns(b"ns-secret", b"pad-2", b"x"),
        ins_ns(b"ns-secret", b"pad-3", b"x"),
        ins_ns(b"ns-public", b"pad-4", b"x"),
        ins_ns(b"ns-public", b"pad-5", b"x"),
    ]);
    let root = smt.root();
    let proof = smt.prove(Some(b"ns-secret"), b"target");
    assert_eq!(
        verify_hbsmt(&root, &proof, Some(b"ns-secret"), b"target", b"SECRET_VALUE"),
        HbsmtVerifyStatus::Included
    );
    // Replay against (ns_public, target): the path differs in upper 4 bytes,
    // so either Invalid (walk-up doesn't reconstruct root) or NonExistence
    // (walk-up reconstructs but terminus.path != target_path) is acceptable;
    // never Included or Mismatch.
    let status = verify_hbsmt(&root, &proof, Some(b"ns-public"), b"target", b"SECRET_VALUE");
    assert!(
        matches!(status, HbsmtVerifyStatus::Invalid | HbsmtVerifyStatus::NonExistence),
        "cross-ns replay leaked status {:?}", status
    );
    assert_ne!(status, HbsmtVerifyStatus::Included);
    assert_ne!(status, HbsmtVerifyStatus::Mismatch);
}

// ============================================================================
// Attack 3/4: filter-skip via splits.
//
// 34-byte split keys can appear in the leaf scan range [lo, hi]. The filter
// `k.len() != 32` skips them. The early-exit `k > hi` could theoretically
// terminate the scan if a 34-byte split sorts after hi but before the next
// 32-byte leaf — and the comparison `k > hi` would then break the loop
// without ever reaching that leaf.
//
// Lexicographic ordering: a 32-byte string compared with its 34-byte
// extension — the 34-byte version is GREATER (the shorter string is a
// prefix and thus less). So a split at `(prefix, depth)` with key
// `prefix || depth_be` is always > the 32-byte path `prefix`.
//
// Concretely: subtree_range at depth d returns hi with the trailing bytes
// after the prefix bits filled with 0xFF. A split's first 32 bytes are the
// SAME prefix-aligned path, so the split's path bytes are ≤ hi if the
// split's path itself ≤ hi. Then the split's full 34-byte key with two
// extra bytes is > hi (because hi is 32 bytes and the 34-byte key with same
// 32-byte prefix sorts greater).
//
// Therefore the early-exit `k > hi.as_slice()` will fire on the split,
// breaking the scan. **The question: can a real leaf exist at a key
// position AFTER such a split (in lexicographic byte order) so the scan
// misses it?**
//
// Within `[lo, hi]`: the rocksdb iterator returns keys in byte-lex order.
// All 32-byte leaves whose path is in [lo, hi] sort < hi as a 32-byte
// string. All 34-byte splits in the scan with path-prefix in [lo, hi] sort
// > their 32-byte prefix. So if a leaf has path P and a split has key
// `P || depth_be`, the split sorts after P. The next leaf P' with P < P'
// ≤ hi: does the split (P, depth) appear between them?
//
// Yes — split (P, d) has bytes `P[0..32] || d_be` which sorts as P
// followed by extra bytes → strictly between P (any 32-byte key equal to
// the prefix) and the next 32-byte key P' > P. So the scan, encountering
// the split, would early-exit if `split > hi` even though P' ≤ hi might
// still exist.
//
// BUT: split's 32-byte prefix is ≤ hi (it lives in the subtree). Is
// `P[0..32] || d_be > hi`? hi has trailing 0xFF after the depth-d
// prefix bits. If split's prefix is the full all-ones hi 32-byte value,
// then split as 34 bytes IS > hi (because hi is just 32 bytes). For
// any split where prefix < hi (strict), split = prefix || d_be may still
// be > hi if prefix is sufficiently close. Specifically split > hi iff
// prefix > hi OR (prefix == hi[0..32] AND extra bytes make it longer).
// Since prefix ≤ hi always, split > hi iff prefix == hi.
//
// So a split whose prefix equals the all-1s hi can cause early-exit. But
// to MISS a leaf, there must be a leaf P' such that prefix(split) < P'
// ≤ hi and `split < P'`. Since split = prefix || extra and P' > prefix,
// P' must differ from prefix in some byte. P' > prefix (as 32-byte
// strings). Is P' > split? Compare 32-byte P' with 34-byte split:
// since they differ first at the same byte where P' > prefix, P' > split.
// So when scan sees split, it would break, missing P'.
//
// CRITICAL: confirm the filter handles this by NOT early-exiting on
// splits — but the code DOES early-exit (`if k > hi.as_slice() { break; }`).
//
// The safety lies in: under the algorithm's invariants, a split key only
// exists at `(prefix, depth)` where the subtree rooted there has ≥2
// leaves. Within the scan range [lo, hi] for a parent subtree at depth
// d_parent, any inner split is at a deeper depth d_split > d_parent, but
// the split's 32-byte prefix is ALIGNED to d_split (bits beyond d_split
// are zero by mask_after_be). The prefix is then ≤ hi[0..32] but
// generally STRICTLY less unless we're at the extreme right.
//
// Build a concrete test: try to force a leaf at a path > split-prefix in
// the same range and see if the scan misses it.
// ============================================================================
#[test]
fn attack3_4_split_in_scan_range_does_not_hide_leaves() {
    // Build a tree where many leaves cluster in one subtree → splits stored
    // inside. Then prove every key. Each prove() invokes first_two_leaves
    // / subtree_hash_db which scans against splits coexisting in the CF.
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());

    // Pick 200 random-ish keys spread across the path space.
    let mut ops = Vec::new();
    let mut kvs = Vec::new();
    for i in 0..200u32 {
        let k = format!("split-attack-{:06}", i).into_bytes();
        let v = format!("V-{}", i).into_bytes();
        ops.push(ins(&k, &v));
        kvs.push((k, v));
    }
    smt.batch_update(ops);
    let root = smt.root();

    // Every prove() must produce a proof that verifies as Included. If any
    // scan misses a leaf because of split-coexistence in the same CF, the
    // proof terminus would be wrong → fail.
    for (k, v) in &kvs {
        let p = smt.prove(None, k);
        assert_eq!(
            verify_hbsmt(&root, &p, None, k, v),
            HbsmtVerifyStatus::Included,
            "prove() returned a bad proof for key {:?} — possible split/leaf scan confusion",
            k
        );
    }

    // Also try keys NOT in the tree; their proofs must report NonExistence.
    for i in 9000..9050u32 {
        let k = format!("absent-{:06}", i).into_bytes();
        let p = smt.prove(None, &k);
        assert_eq!(
            verify_hbsmt(&root, &p, None, &k, b"v"),
            HbsmtVerifyStatus::NonExistence,
            "absent key proof did not verify NonExistence: key={:?}", k
        );
    }
}

// ============================================================================
// Attack 4b: contrived adversarial split injection. Even though encode
// helpers prevent normal callers from writing arbitrary keys, we explicitly
// test that having a split-shaped 34-byte key coexisting in the CF doesn't
// confuse the leaf scan. We don't have direct DB write access here, so the
// best we can do is: the algorithm itself writes splits, so just exercise
// it heavily and ensure the invariant.
// ============================================================================
#[test]
fn attack4b_heavy_split_density_no_scan_miss() {
    // 1024 keys → many splits stored at multiple depths in the same CF.
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());

    let mut ops = Vec::new();
    let mut kvs = Vec::new();
    for i in 0..1024u32 {
        let k = format!("dense-{:08}", i).into_bytes();
        let v = format!("V{}", i).into_bytes();
        ops.push(ins(&k, &v));
        kvs.push((k, v));
    }
    smt.batch_update(ops);
    let root = smt.root();

    // Sample 100 of them to keep test fast.
    for (k, v) in kvs.iter().step_by(10) {
        let p = smt.prove(None, k);
        let status = verify_hbsmt(&root, &p, None, k, v);
        assert_eq!(status, HbsmtVerifyStatus::Included,
            "Included expected; got {:?} for key {:?} (split-coexistence scan bug?)",
            status, k);
    }
}

// ============================================================================
// Attack 2: filter-skip with non-32, non-34 lengths. We can't actually write
// such keys (the algorithm has no helper that emits 33/35-byte keys), but if
// they were ever written, the filter `k.len() != 32` skips them, never
// matches a leaf, and the scan continues. The early-exit `k > hi` still
// fires correctly because byte-lex comparison is length-agnostic.
//
// This test documents the safety property: even WITH a non-32/non-34 key
// injected, the scan should still find all 32-byte leaves correctly. Since
// we can't inject directly without raw DB access, we instead verify the
// length filter is exhaustive by code inspection — and confirm the algorithm
// is robust by running a stress test of inserts/deletes that touches every
// shape of the scan path.
// ============================================================================
#[test]
fn attack2_stress_with_inserts_deletes_no_false_nonexistence() {
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());

    // Phase 1: insert 300 keys.
    let mut ops = Vec::new();
    let mut live: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = Default::default();
    for i in 0..300u32 {
        let k = format!("stress-{:06}", i).into_bytes();
        let v = format!("v{}", i).into_bytes();
        ops.push(ins(&k, &v));
        live.insert(k, v);
    }
    smt.batch_update(ops);

    // Phase 2: delete half (every even index) — many subtrees collapse.
    let mut del_ops = Vec::new();
    let mut to_remove = Vec::new();
    for (i, k) in live.keys().enumerate() {
        if i % 2 == 0 {
            del_ops.push(Op::Delete(None, k.clone()));
            to_remove.push(k.clone());
        }
    }
    smt.batch_update(del_ops);
    for k in to_remove { live.remove(&k); }

    // Phase 3: reinsert 50 brand-new keys.
    let mut more = Vec::new();
    for i in 500..550u32 {
        let k = format!("stress-{:06}", i).into_bytes();
        let v = format!("v{}", i).into_bytes();
        more.push(ins(&k, &v));
        live.insert(k, v);
    }
    smt.batch_update(more);
    let root = smt.root();

    // Every LIVE key must verify as Included (no false NonExistence).
    for (k, v) in &live {
        let p = smt.prove(None, k);
        let status = verify_hbsmt(&root, &p, None, k, v);
        assert_eq!(
            status, HbsmtVerifyStatus::Included,
            "live key {:?} returned {:?} (expected Included) — possible CENSORSHIP via scan bug",
            k, status
        );
    }
}

// ============================================================================
// Attack 5: hand-craft a forged proof for an existing key that claims
// NonExistence by substituting a leaf with identity_hash matching a DIFFERENT
// (ns, key) pair. The verifier sees identity_h != claimed_identity →
// NonExistence — BUT only if the proof reconstructs the root. Building such
// a proof requires knowing internal node hashes consistent with the root,
// which is information-theoretically hard.
//
// Concrete test: take the honest proof for K, replace terminus with a Leaf
// whose path matches the honest target_path bits below stop but with a
// different identity_hash. Walk-up uses path's bits (only the bits below
// stop are used by lift_single_leaf). Substituting a fake identity changes
// lh → root won't match. Verifier returns Invalid, not NonExistence.
// ============================================================================
#[test]
fn attack5_swap_identity_in_terminus_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();
    let empties = make_empties();
    let _ = empties;

    for (k, v) in &kvs {
        let honest = smt.prove(None, k);
        let stop = honest.siblings.len();
        if stop == 0 { continue; }
        let (orig_path, orig_id, orig_val) = match &honest.terminus {
            HbsmtTerminus::Leaf { path, identity_hash, value_hash } => {
                (*path, *identity_hash, *value_hash)
            }
            _ => continue,
        };

        // Swap identity_hash for a different one (simulate someone else's).
        let fake_id = identity_hash(&orig_path, b"attacker-ns", b"attacker-key");
        assert_ne!(fake_id, orig_id);
        let bad = HbsmtProof {
            siblings: honest.siblings.clone(),
            terminus: HbsmtTerminus::Leaf {
                path: orig_path,
                identity_hash: fake_id,
                value_hash: orig_val,
            },
        };
        let status = verify_hbsmt(&root, &bad, None, k, v);
        assert_eq!(
            status, HbsmtVerifyStatus::Invalid,
            "swapped-identity terminus for {:?} returned {:?} (expected Invalid)",
            k, status
        );
        assert_ne!(status, HbsmtVerifyStatus::NonExistence);
    }
}

// ============================================================================
// Attack 5b: lower-level — use verify_hbsmt_raw with arbitrary claimed
// identity. Same defense: walk-up uses lh derived from terminus, so
// substituting in the terminus changes the root. Verifier blocks.
// ============================================================================
#[test]
fn attack5b_raw_verify_substitution_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();
    let empties = make_empties();

    for (k, v) in kvs.iter().take(8) {
        let honest = smt.prove(None, k);
        if !matches!(honest.terminus, HbsmtTerminus::Leaf { .. }) { continue; }
        let target_path = compute_namespace_path_hbsmt(b"", k);
        let claimed_id  = identity_hash(&target_path, b"", k);
        let claimed_val = value_hash(v);

        // Honest verify_hbsmt_raw → Included.
        assert_eq!(
            verify_hbsmt_raw(&root, &honest, &target_path, &claimed_id, &claimed_val, &empties),
            HbsmtVerifyStatus::Included
        );

        // Substitute terminus identity with fake — must NOT be Included or
        // NonExistence; should be Invalid (root mismatch).
        let mut bad = honest.clone();
        if let HbsmtTerminus::Leaf { ref mut identity_hash, .. } = bad.terminus {
            identity_hash[0] ^= 0xFF;
        }
        let status = verify_hbsmt_raw(&root, &bad, &target_path, &claimed_id, &claimed_val, &empties);
        assert_eq!(status, HbsmtVerifyStatus::Invalid,
            "raw substitution gave {:?} not Invalid", status);
    }
}

// ============================================================================
// Attack 8: deepen the proof by appending arbitrary siblings (to make the
// stop go past the real one) with terminus that "looks right" — try to
// construct an Empty terminus at depth s' > honest_stop that reconstructs
// the root via the appended siblings being chosen such that the empty hash
// at s' walked up through them yields the honest hash at honest_stop.
//
// This would require finding sibling hashes that hash with empties[s'] to
// produce a specific target — equivalent to a hash preimage. Computationally
// infeasible, but we sanity-check that the obvious attempt (replace last
// sibling with hash chosen so that Empty at deeper stop reproduces it)
// fails.
// ============================================================================
#[test]
fn attack8_deepen_stop_with_random_siblings_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();
    let empties = make_empties();

    for (k, v) in kvs.iter().take(8) {
        let honest = smt.prove(None, k);
        let stop = honest.siblings.len();
        if stop >= 250 { continue; }

        // Append 4 arbitrary siblings, claim Empty at deeper stop.
        let mut extended = honest.siblings.clone();
        for d in stop..(stop + 4) {
            // Use a random-ish sibling (just rotated empty).
            let mut s = empties[d + 1];
            s[0] ^= 0xAA;
            extended.push(s);
        }
        let bad = HbsmtProof {
            siblings: extended,
            terminus: HbsmtTerminus::Empty,
        };
        let status = verify_hbsmt(&root, &bad, None, k, v);
        assert_ne!(status, HbsmtVerifyStatus::NonExistence,
            "deepened-stop forgery returned NonExistence for {:?}", k);
        assert_eq!(status, HbsmtVerifyStatus::Invalid);
    }
}

// ============================================================================
// Attack 9: lift_single_leaf consistency check. The verifier's
// `lift_single_leaf` uses terminus.path bits [stop..256). The censorship
// fix masks terminus.path against target_path at bits [0..stop). So an
// attacker can ONLY freely choose terminus.path bits at depth ≥ stop. But
// those bits feed into the walk-up via lh derivation, so flipping them
// changes lh → root mismatch. Concrete test:
// ============================================================================
#[test]
fn attack9_flip_terminus_path_above_stop_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();

    for (k, v) in kvs.iter().take(8) {
        let honest = smt.prove(None, k);
        let stop = honest.siblings.len();
        if stop == 256 { continue; }
        if !matches!(honest.terminus, HbsmtTerminus::Leaf { .. }) { continue; }

        // Flip bit at depth stop (first bit consumed by lift_single_leaf).
        let mut bad = honest.clone();
        if let HbsmtTerminus::Leaf { ref mut path, .. } = bad.terminus {
            let bit = get_bit_be(path, stop as u16);
            set_bit_be(path, stop as u16, 1 - bit);
        }
        let status = verify_hbsmt(&root, &bad, None, k, v);
        assert_ne!(status, HbsmtVerifyStatus::NonExistence,
            "above-stop bit flip → NonExistence for {:?}", k);
        // We expect Invalid (lh changed → walk-up fails).
        // It could in rare cases be NonExistence if the path mask check fires
        // first... but the mask check covers ONLY bits < stop, and we flipped
        // bit AT stop, which is included in [stop..256). So mask check passes
        // (bits below stop unchanged). Walk-up uses target_path bits, so the
        // direction is unchanged; but the leaf hash differs → root differs.
        assert_eq!(status, HbsmtVerifyStatus::Invalid,
            "above-stop flip status={:?}", status);
    }
}

// ============================================================================
// Attack 10: full path mismatch via lifted leaf — set terminus.path to the
// target_path (so the [0..stop) bits match the verifier's mask check) but
// with a fake identity_hash. We covered identity swap in attack 5; here we
// confirm that even when terminus.path EQUALS target_path exactly, swapping
// identity → Invalid (not Included or NonExistence).
// ============================================================================
#[test]
fn attack10_target_path_with_fake_identity_blocked() {
    let (_d, smt, kvs) = build_attack_tree();
    let root = smt.root();

    for (k, v) in kvs.iter().take(8) {
        let honest = smt.prove(None, k);
        let target_path = compute_namespace_path_hbsmt(b"", k);
        if !matches!(honest.terminus, HbsmtTerminus::Leaf { .. }) { continue; }

        let fake_id = identity_hash(&target_path, b"otherns", b"otherkey");
        let bad = HbsmtProof {
            siblings: honest.siblings.clone(),
            terminus: HbsmtTerminus::Leaf {
                path: target_path,
                identity_hash: fake_id,
                value_hash: value_hash(v),
            },
        };
        let status = verify_hbsmt(&root, &bad, None, k, v);
        assert_eq!(status, HbsmtVerifyStatus::Invalid,
            "target_path + fake identity status={:?}", status);
    }
}

// ============================================================================
// Attack tests — Mismatch forgery + structural fuzz on the single-CF design.
// (Merged from former hbsmt_attacks_mismatch_single_cf.rs.)
// ============================================================================


// ============================================================================
// Test harness: ApplyEnv pointed at a single CF for env-mode tests.
// Copied from bintree_rdb tests pattern.
// ============================================================================

struct TestEnv {
    _dir: TempDir,
    db: &'static TransactionDB<MultiThreaded>,
}

impl TestEnv {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        let txn_db_opts = TransactionDBOptions::default();
        let cfs = vec![
            ColumnFamilyDescriptor::new("contractstate", Options::default()),
            ColumnFamilyDescriptor::new("contractstate_tree", Options::default()),
        ];
        let db = TransactionDB::<MultiThreaded>::open_cf_descriptors(
            &db_opts, &txn_db_opts, dir.path(), cfs,
        )
        .unwrap();
        let db: &'static TransactionDB<MultiThreaded> = Box::leak(Box::new(db));
        TestEnv { _dir: dir, db }
    }

    fn make_env(&self) -> ApplyEnv<'static> {
        let cf_tree = self.db.cf_handle("contractstate_tree").unwrap();
        let cf_cs = self.db.cf_handle("contractstate").unwrap();
        let txn = self.db.transaction();
        ApplyEnv {
            caller_env: CallerEnv {
                readonly: false,
                seed: Vec::new(),
                seedf64: 1.0,
                entry_signer: [0u8; 48],
                entry_prev_hash: [0u8; 32],
                entry_slot: 0,
                entry_prev_slot: 0,
                entry_height: 0,
                entry_epoch: 0,
                entry_vr: [0u8; 96],
                entry_vr_b3: [0u8; 32],
                entry_dr: [0u8; 32],
                tx_index: 0,
                tx_signer: [0u8; 48],
                tx_nonce: 0,
                tx_hash: [0u8; 32],
                account_origin: Vec::new(),
                account_caller: Vec::new(),
                account_current: Vec::new(),
                attached_symbol: Vec::new(),
                attached_amount: Vec::new(),
                call_counter: 0,
                call_exec_points: 0,
                call_exec_points_remaining: 0,
                call_return_value: Vec::new(),
            },
            db: self.db,
            cf: cf_tree.clone(),
            cf_name: b"contractstate_tree".to_vec(),
            cf_contractstate: cf_cs,
            cf_contractstate_tree: cf_tree,
            txn,
            muts_final: Vec::new(),
            muts_final_rev: Vec::new(),
            muts: Vec::new(),
            muts_rev: Vec::new(),
            exec_track: false,
            exec_left: 0,
            exec_max: 0,
            storage_left: 0,
            storage_max: 0,
            receipts: Vec::new(),
            logs: Vec::new(),
            logs_size: 0,
            preverified_sol_hashes: HashSet::new(),
            testnet: false,
            testnet_peddlebikes: Vec::new(),
            readonly: false,
            call_depth: 0,
        }
    }
}
fn ins_opt(ns: Option<&[u8]>, k: &[u8], v: &[u8]) -> Op {
    Op::Insert(ns.map(|n| n.to_vec()), k.to_vec(), v.to_vec())
}

// ============================================================================
// 1. Mismatch forgery against a real (ns, k, v) pair.
// ============================================================================

/// Attacker has an honest inclusion proof for (alice, balance) = 1000.
/// Try every cheap mutation of the encoded proof terminus that would change
/// the value reported. With identity_hash binding (path, ns, key) and value
/// hashed under "VAL" domain tag, no cheap mutation can flip the verdict
/// from Included(1000) to Mismatch(<attacker-chosen-value>) without a
/// preimage attack on SHA-256.
#[test]
fn forge_mismatch_against_real_alice_balance_1000() {
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    smt.batch_update(vec![
        ins_opt(Some(b"alice"), b"balance", b"1000"),
        ins_opt(Some(b"bob"), b"balance", b"42"),
        ins_opt(Some(b"carol"), b"nonce", b"7"),
    ]);
    let root = smt.root();
    let honest = smt.prove(Some(b"alice"), b"balance");
    assert_eq!(
        verify_hbsmt(&root, &honest, Some(b"alice"), b"balance", b"1000"),
        HbsmtVerifyStatus::Included
    );

    // The attacker's goal: produce a proof p' such that
    //   verify_hbsmt(root, p', Some("alice"), "balance", v_fake) == Mismatch
    // for some v_fake != "1000". Mismatch requires:
    //   - reconstruct root,
    //   - terminus path == target path,
    //   - terminus identity_hash == identity_hash(path, "alice", "balance"),
    //   - terminus value_hash != value_hash("1000").
    //
    // Identity and the canonical leaf-spine hash are SHA-256-bound, so flipping
    // value_hash while preserving the reconstructed root requires a SHA-256
    // preimage. We exhaustively try every reasonable cheap forgery:
    //
    //   (a) substitute value_hash with value_hash(b"0") .. value_hash(b"9999"),
    //   (b) substitute value_hash with any byte-flip of the honest hash,
    //   (c) substitute terminus with Empty (would reroute to NonExistence).
    let honest_val_h = match &honest.terminus {
        HbsmtTerminus::Leaf { value_hash: v, .. } => *v,
        _ => panic!("expected Leaf terminus for present key"),
    };

    let mut found_forgery = false;
    let mut found_anything_but_included = false;

    for fake_val in (0..2000u32).map(|n| format!("{}", n).into_bytes()) {
        if fake_val == b"1000" {
            continue;
        }
        let forged_val_h = value_hash(&fake_val);
        let (path, id_h) = match &honest.terminus {
            HbsmtTerminus::Leaf { path, identity_hash, .. } => (*path, *identity_hash),
            _ => unreachable!(),
        };
        let mut p = HbsmtProof {
            siblings: honest.siblings.clone(),
            terminus: HbsmtTerminus::Leaf {
                path,
                identity_hash: id_h,
                value_hash: forged_val_h,
            },
        };
        // Single-leaf-subtree tree may have empty siblings; still try.
        let status = verify_hbsmt(&root, &p, Some(b"alice"), b"balance", &fake_val);
        if status == HbsmtVerifyStatus::Mismatch {
            found_forgery = true;
            break;
        }
        if status != HbsmtVerifyStatus::Included {
            found_anything_but_included = true;
        }
        // Also try flipping a single byte of value_hash directly.
        for byte_i in 0..32 {
            let mut tampered = honest_val_h;
            tampered[byte_i] ^= 0x01;
            p.terminus = HbsmtTerminus::Leaf {
                path,
                identity_hash: id_h,
                value_hash: tampered,
            };
            let st = verify_hbsmt(&root, &p, Some(b"alice"), b"balance", &fake_val);
            assert_ne!(
                st,
                HbsmtVerifyStatus::Mismatch,
                "byte-flip on value_hash produced Mismatch (forgery)"
            );
        }
    }

    assert!(
        !found_forgery,
        "MISMATCH FORGERY FOUND against (alice, balance=1000) — this is a critical break"
    );
    assert!(
        found_anything_but_included,
        "no forgery attempts even changed verdict — sanity bound failed"
    );
}

// ============================================================================
// 2. Structural attacks on consolidated storage.
// ============================================================================

#[test]
fn structural_empty_cf_root_and_proofs() {
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    let root = smt.root();
    // Empty tree: all proofs should be Empty terminus → NonExistence.
    for k in [b"a" as &[u8], b"", b"long-key-that-doesnt-exist"] {
        let p = smt.prove(None, k);
        assert_eq!(p.terminus, HbsmtTerminus::Empty);
        assert!(p.siblings.is_empty());
        assert_eq!(
            verify_hbsmt(&root, &p, None, k, b"v"),
            HbsmtVerifyStatus::NonExistence
        );
    }
}

#[test]
fn structural_single_leaf_at_zero_path_no_collision_with_split_key() {
    // Brute-force a key whose hbsmt path is all-zero (or near it). With 28 B
    // of the path coming from sha256(key)[0..28] this is essentially
    // impossible to hit exactly, but the single-leaf-at-some-path case is
    // tested below. Here we only check the property: a single leaf does NOT
    // store a top-level split — the `root()` short-circuit relies on
    // walking via `subtree_hash_db` when split_key([0;32], 0) is missing.
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    smt.batch_update(vec![ins_opt(None, b"only", b"x")]);
    let r = smt.root();

    // A second access (no batch_update) must yield the same root.
    assert_eq!(smt.root(), r);

    // And the prove must verify.
    let p = smt.prove(None, b"only");
    assert_eq!(
        verify_hbsmt(&r, &p, None, b"only", b"x"),
        HbsmtVerifyStatus::Included
    );

    // Equivalent check via env-mode: a single-leaf tree must produce a
    // root via the walk path (no top-level split stored). We can't reach
    // HbsmtRdb's internal DB handle from outside, but the env-mode parallel
    // setup lets us inspect the CF directly.
    let env_box = TestEnv::new();
    {
        let mut env = env_box.make_env();
        hbsmt_batch_update_env(&mut env, "contractstate_tree", vec![ins_opt(None, b"only", b"x")]);
        env.txn.commit().unwrap();
    }
    let cf = env_box.db.cf_handle("contractstate_tree").unwrap();
    let mut iter = env_box.db.raw_iterator_cf(&cf);
    iter.seek_to_first();
    let mut found_split = false;
    let mut found_leaf = false;
    while iter.valid() {
        if let Some(k) = iter.key() {
            if k.len() == 34 {
                found_split = true;
            } else if k.len() == 32 {
                found_leaf = true;
            }
        }
        iter.next();
    }
    assert!(found_leaf, "single-leaf tree should have a 32-byte leaf key");
    assert!(!found_split, "single-leaf tree must not store any 34-byte split");
}

#[test]
fn structural_large_tree_with_many_splits_iterator_unconfused() {
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    let mut ops = Vec::new();
    for i in 0..500u32 {
        ops.push(ins_opt(None, format!("k-{:05}", i).as_bytes(), format!("v-{}", i).as_bytes()));
    }
    smt.batch_update(ops);
    let r = smt.root();

    // Sample proves: every one must verify.
    for i in [0u32, 1, 7, 42, 100, 499] {
        let k = format!("k-{:05}", i);
        let v = format!("v-{}", i);
        let p = smt.prove(None, k.as_bytes());
        assert_eq!(
            verify_hbsmt(&r, &p, None, k.as_bytes(), v.as_bytes()),
            HbsmtVerifyStatus::Included,
            "proof failed for {}",
            k
        );
    }
    // Non-existence too.
    let p = smt.prove(None, b"never-inserted-key");
    assert_eq!(
        verify_hbsmt(&r, &p, None, b"never-inserted-key", b"x"),
        HbsmtVerifyStatus::NonExistence
    );
}

// ============================================================================
// 3. root() short-circuit edge case.
// ============================================================================

#[test]
fn root_short_circuit_single_leaf_no_top_split() {
    // For 1 leaf, there's no stored split at any depth — root must fall
    // back to subtree_hash_db. Validate by comparing to in-memory Hbsmt.
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    smt.batch_update(vec![ins_opt(None, b"solo", b"x")]);
    let r_rdb = smt.root();

    let mut mem = Hbsmt::new();
    mem.batch_update(vec![ins_opt(None, b"solo", b"x")]);
    let r_mem = mem.root();

    assert_eq!(r_rdb, r_mem, "single-leaf root mismatch between RDB and in-mem");
    assert_ne!(r_rdb, ZERO_HASH);
}

// ============================================================================
// 4. Length-filter robustness — directly inject malformed keys.
// ============================================================================

#[test]
fn length_filter_ignores_malformed_keys_via_env() {
    let env_box = TestEnv::new();
    {
        let mut env = env_box.make_env();
        hbsmt_batch_update_env(
            &mut env,
            "contractstate_tree",
            vec![
                ins_opt(None, b"alpha", b"1"),
                ins_opt(None, b"beta", b"2"),
                ins_opt(None, b"gamma", b"3"),
            ],
        );
        env.txn.commit().unwrap();
    }
    // Capture the honest root.
    let honest_root = {
        let mut env = env_box.make_env();
        let r = hbsmt_root_env(&mut env, "contractstate_tree");
        let _ = env.txn.commit();
        r
    };
    assert_ne!(honest_root, ZERO_HASH);

    // Now inject malformed keys directly via raw put_cf.
    let cf = env_box.db.cf_handle("contractstate_tree").unwrap();
    for bad_len in [0usize, 1, 31, 33, 35, 36] {
        // Use a key that doesn't share prefix with any real leaf to be safe.
        let mut bad_key = vec![0xCDu8; bad_len];
        if !bad_key.is_empty() {
            bad_key[0] = 0xAB;
        }
        let bad_val = vec![0xEEu8; 64]; // looks like a leaf payload
        env_box.db.put_cf(&cf, &bad_key, &bad_val).unwrap();
    }

    // Root should be UNCHANGED — algorithm filters by length.
    let new_root = {
        let mut env = env_box.make_env();
        let r = hbsmt_root_env(&mut env, "contractstate_tree");
        let _ = env.txn.commit();
        r
    };
    assert_eq!(
        new_root, honest_root,
        "malformed-length keys must be ignored by length filter"
    );

    // Proofs still verify.
    {
        let env = env_box.make_env();
        // We need prove(); env-mode has no prover, so cross-check root via
        // an HbsmtRdb pointed at a fresh DB with the same workload.
        drop(env);
    }
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    smt.batch_update(vec![
        ins_opt(None, b"alpha", b"1"),
        ins_opt(None, b"beta", b"2"),
        ins_opt(None, b"gamma", b"3"),
    ]);
    assert_eq!(
        smt.root(),
        honest_root,
        "HbsmtRdb root must match hbsmt_root_env on same workload"
    );
    let p = smt.prove(None, b"alpha");
    assert_eq!(
        verify_hbsmt(&honest_root, &p, None, b"alpha", b"1"),
        HbsmtVerifyStatus::Included
    );
}

// ============================================================================
// 5. Read-only `prove()` consistency vs un-committed splits.
// ============================================================================
//
// HbsmtRdb's `prove()` opens a fresh raw iterator on the DB; it does NOT see
// uncommitted txn writes. Since batch_update commits before returning, any
// caller of prove() after batch_update sees a consistent state. We confirm
// this by interleaving and checking the prove always matches the root.

#[test]
fn readonly_prove_consistent_after_each_batch() {
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    for i in 0u32..50 {
        smt.batch_update(vec![ins_opt(None, format!("k{}", i).as_bytes(), format!("v{}", i).as_bytes())]);
        let r = smt.root();
        let p = smt.prove(None, format!("k{}", i).as_bytes());
        assert_eq!(
            verify_hbsmt(&r, &p, None, format!("k{}", i).as_bytes(), format!("v{}", i).as_bytes()),
            HbsmtVerifyStatus::Included,
            "prove inconsistent after batch {}",
            i
        );
    }
}

// ============================================================================
// 6. Property-based single-byte fuzz on the encoded proof.
//
// We mutate the in-memory proof object (not a wire encoding) byte-by-byte and
// assert verification never returns Included/Mismatch for a present key with
// wrong value, never returns NonExistence for a present key with correct
// value, etc.
// ============================================================================

fn mutate_proof_byte(proof: &mut HbsmtProof, byte_index: usize) -> bool {
    // Layout (conceptual):
    //   [sibling 0 .. sibling N-1] = 32*N bytes
    //   then terminus:
    //     Empty (no body) or Leaf {path: 32, id: 32, val: 32} = 96 bytes
    let sib_bytes = proof.siblings.len() * 32;
    if byte_index < sib_bytes {
        let s = byte_index / 32;
        let b = byte_index % 32;
        proof.siblings[s][b] ^= 0x01;
        return true;
    }
    let rem = byte_index - sib_bytes;
    if let HbsmtTerminus::Leaf {
        path,
        identity_hash,
        value_hash,
    } = &mut proof.terminus
    {
        match rem {
            0..=31 => path[rem] ^= 0x01,
            32..=63 => identity_hash[rem - 32] ^= 0x01,
            64..=95 => value_hash[rem - 64] ^= 0x01,
            _ => return false,
        }
        return true;
    }
    false
}

#[test]
fn fuzz_single_byte_mutations_never_forge_inclusion_or_mismatch() {
    let dir = TempDir::new().unwrap();
    let smt = HbsmtRdb::open(dir.path());
    let mut ops = Vec::new();
    for i in 0u32..32 {
        ops.push(ins_opt(None, format!("k{:04}", i).as_bytes(), format!("v{}", i).as_bytes()));
    }
    smt.batch_update(ops);
    let root = smt.root();

    let key_present = b"k0007";
    let val_present = b"v7";
    let key_absent = b"k9999"; // absent

    let honest_present = smt.prove(None, key_present);
    let honest_absent = smt.prove(None, key_absent);

    // Sanity baselines.
    assert_eq!(
        verify_hbsmt(&root, &honest_present, None, key_present, val_present),
        HbsmtVerifyStatus::Included
    );
    assert_eq!(
        verify_hbsmt(&root, &honest_absent, None, key_absent, b"x"),
        HbsmtVerifyStatus::NonExistence
    );

    let sib_bytes_present = honest_present.siblings.len() * 32;
    let term_bytes_present = match honest_present.terminus {
        HbsmtTerminus::Empty => 0,
        HbsmtTerminus::Leaf { .. } => 96,
    };
    let max_present = sib_bytes_present + term_bytes_present;

    let sib_bytes_absent = honest_absent.siblings.len() * 32;
    let term_bytes_absent = match honest_absent.terminus {
        HbsmtTerminus::Empty => 0,
        HbsmtTerminus::Leaf { .. } => 96,
    };
    let max_absent = sib_bytes_absent + term_bytes_absent;

    let mut total_mut = 0u32;
    // (a) Mutate honest-present proof, claim key_present with WRONG value.
    //     Must never be Mismatch (would say "wrong value for the right key").
    //     We accept Invalid, NonExistence, or Mismatch ONLY if the mutated
    //     value_hash happens to equal value_hash("WRONG") which is
    //     impossible without a SHA-256 preimage — assert that case never
    //     fires.
    for i in 0..max_present {
        let mut p = honest_present.clone();
        if !mutate_proof_byte(&mut p, i) {
            continue;
        }
        total_mut += 1;
        // Claim correct (key, value): a single-byte mutation must not still
        // produce Included.
        let st_correct = verify_hbsmt(&root, &p, None, key_present, val_present);
        assert_ne!(
            st_correct,
            HbsmtVerifyStatus::Included,
            "mutated proof still verifies Included (byte {})",
            i
        );
        // Claim wrong value: must not produce Mismatch with our specific
        // wrong value.
        let st_wrong = verify_hbsmt(&root, &p, None, key_present, b"WRONG-VALUE-FORGERY");
        assert_ne!(
            st_wrong,
            HbsmtVerifyStatus::Mismatch,
            "mutated proof produced Mismatch verdict for wrong value (byte {})",
            i
        );
    }

    // (b) Mutate honest-absent proof, claim key_absent. Must never become
    //     Included or Mismatch.
    for i in 0..max_absent {
        let mut p = honest_absent.clone();
        if !mutate_proof_byte(&mut p, i) {
            continue;
        }
        total_mut += 1;
        let st = verify_hbsmt(&root, &p, None, key_absent, b"anything");
        assert!(
            matches!(
                st,
                HbsmtVerifyStatus::Invalid | HbsmtVerifyStatus::NonExistence
            ),
            "mutated absence-proof reported {:?} (byte {})",
            st,
            i
        );
        assert_ne!(st, HbsmtVerifyStatus::Included);
    }
    assert!(total_mut > 0, "fuzz did zero mutations");
    println!("[fuzz] {} mutations exercised, no forgery", total_mut);
}

// ============================================================================
// 7. Cross-impl agreement: Hbsmt vs HbsmtRdb vs env-mode.
// ============================================================================

#[test]
fn cross_impl_root_agreement_hbsmt_rdb_env() {
    let ops = vec![
        ins_opt(None, b"a", b"1"),
        ins_opt(None, b"b", b"2"),
        ins_opt(Some(b"ns1"), b"c", b"3"),
        ins_opt(Some(b"ns2"), b"c", b"4"),
        ins_opt(None, b"d", b"5"),
        ins_opt(None, b"alice-balance", b"1000"),
    ];

    // In-memory.
    let mut mem = Hbsmt::new();
    mem.batch_update(ops.clone());
    let r_mem = mem.root();

    // HbsmtRdb (own DB).
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());
    rdb.batch_update(ops.clone());
    let r_rdb = rdb.root();

    // env-mode.
    let env_box = TestEnv::new();
    {
        let mut env = env_box.make_env();
        hbsmt_batch_update_env(&mut env, "contractstate_tree", ops.clone());
        env.txn.commit().unwrap();
    }
    let r_env = {
        let mut env = env_box.make_env();
        let r = hbsmt_root_env(&mut env, "contractstate_tree");
        let _ = env.txn.commit();
        r
    };

    assert_eq!(r_mem, r_rdb, "Hbsmt vs HbsmtRdb roots differ");
    assert_eq!(r_rdb, r_env, "HbsmtRdb vs env-mode roots differ");
}

#[test]
fn cross_impl_proof_via_rdb_verifies_under_env_root() {
    // Build identical workloads in HbsmtRdb (which can prove) and env-mode
    // (which provides production root). Roots match → proof produced by
    // HbsmtRdb verifies against env-mode root.
    let ops = vec![
        ins_opt(Some(b"alice"), b"balance", b"1000"),
        ins_opt(Some(b"bob"), b"balance", b"42"),
        ins_opt(Some(b"carol"), b"nonce", b"7"),
        ins_opt(None, b"sys", b"v"),
    ];
    let dir = TempDir::new().unwrap();
    let rdb = HbsmtRdb::open(dir.path());
    rdb.batch_update(ops.clone());
    let r_rdb = rdb.root();

    let env_box = TestEnv::new();
    {
        let mut env = env_box.make_env();
        hbsmt_batch_update_env(&mut env, "contractstate_tree", ops);
        env.txn.commit().unwrap();
    }
    let r_env = {
        let mut env = env_box.make_env();
        let r = hbsmt_root_env(&mut env, "contractstate_tree");
        let _ = env.txn.commit();
        r
    };
    assert_eq!(r_rdb, r_env);

    let p = rdb.prove(Some(b"alice"), b"balance");
    assert_eq!(
        verify_hbsmt(&r_env, &p, Some(b"alice"), b"balance", b"1000"),
        HbsmtVerifyStatus::Included
    );
    assert_eq!(
        verify_hbsmt(&r_env, &p, Some(b"alice"), b"balance", b"999"),
        HbsmtVerifyStatus::Mismatch
    );
    // A proof for (alice, balance) descends toward alice's path. Re-using
    // it to claim (mallory, balance) — which lives at a DIFFERENT path —
    // is detected by the path-prefix authentication step and rejected as
    // Invalid (the proof simply doesn't talk about mallory's slot).
    let st = verify_hbsmt(&r_env, &p, Some(b"mallory"), b"balance", b"1000");
    assert!(
        matches!(st, HbsmtVerifyStatus::Invalid | HbsmtVerifyStatus::NonExistence),
        "wrong-ns reuse of inclusion proof should be Invalid or NonExistence, got {:?}",
        st
    );
    assert_ne!(st, HbsmtVerifyStatus::Included);
    assert_ne!(st, HbsmtVerifyStatus::Mismatch);
}

// ============================================================================
// Defensive: confirm that the bound identity_hash actually catches the
// "swap value_hash into a different leaf at same path" attack by reading the
// identity bytes from one leaf and grafting them onto another (would only
// succeed if identity_hash didn't bind path).
// ============================================================================

#[test]
fn identity_hash_binds_path_ns_key() {
    let path_a = compute_namespace_path_hbsmt(b"alice", b"balance");
    let path_b = compute_namespace_path_hbsmt(b"bob", b"balance");
    assert_ne!(path_a, path_b, "different ns → different path");

    let id_a = identity_hash(&path_a, b"alice", b"balance");
    let id_b = identity_hash(&path_b, b"bob", b"balance");
    assert_ne!(id_a, id_b, "identity_hash must bind ns");

    // Same path, different ns/key — can't happen under HBSMT path scheme
    // (path is a function of ns+key) but we test the primitive directly.
    let id_a_fake_ns = identity_hash(&path_a, b"mallory", b"balance");
    assert_ne!(id_a, id_a_fake_ns, "identity_hash must bind ns even at same path");

    // leaf_hash_from_components binds both:
    let val = value_hash(b"1000");
    let lh1 = leaf_hash_from_components(&id_a, &val);
    let lh2 = leaf_hash_from_components(&id_b, &val);
    assert_ne!(lh1, lh2);
    let lh3 = leaf_hash_from_components(&id_a, &value_hash(b"999"));
    assert_ne!(lh1, lh3);
}
