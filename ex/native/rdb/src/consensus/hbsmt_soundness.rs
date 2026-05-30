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
    get_bit_be, mask_after_be, set_bit_be, Op, Path,
};
use crate::consensus::hbsmt::Hbsmt;
use crate::consensus::hbsmt_common::{
    compute_namespace_path_hbsmt,
    lcp_depth, lift_single_leaf, make_empties, subtree_range, verify_hbsmt, HbsmtTerminus,
    HbsmtVerifyStatus,
};
use crate::consensus::hbsmt_rdb::HbsmtRdb;
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
