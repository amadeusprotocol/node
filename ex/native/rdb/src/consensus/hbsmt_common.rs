//! Shared types, helpers, and proof primitives for the Compact Sparse Merkle
//! Tree. Used by the in-memory `Hbsmt` (smt.rs) and the RocksDB-backed
//! `HbsmtRdb` (smt_rdb.rs).

use crate::consensus::bintree::{
    get_bit_be, mask_after_be, set_bit_be, sha256, Hash, Path, ZERO_HASH,
};
use sha2::{Digest, Sha256};

/// HBSMT path scheme: `sha256(ns)[0..4] || sha256(key)[0..28]`.
/// "No namespace" is represented as `ns = b""` — its `sha256(b"")[0..4]`
/// bucket is a single fixed prefix where all unnamespaced keys cluster.
#[inline]
pub fn compute_namespace_path_hbsmt(ns: &[u8], key: &[u8]) -> Path {
    let ns_hash = sha256(ns);
    let key_hash = sha256(key);
    let mut path = [0u8; 32];
    path[0..4].copy_from_slice(&ns_hash[0..4]);
    path[4..32].copy_from_slice(&key_hash[0..28]);
    path
}

// ============================================================================
// SMT-specific leaf hashing: two-component decomposition.
//
// The leaf is committed as `leaf_hash = sha256("LEAF" || identity || value)`
// — what gets hashed up the tree spine. Proofs carry the two components
// separately so the verifier can distinguish:
//   - identity matches, value matches → Included
//   - identity matches, value differs → Mismatch  (right writer, wrong value)
//   - identity differs                → NonExistence  (someone else wrote here)
//
// `identity_hash` pre-hashes the variable-length `ns` and `key` to fixed-size
// digests, so the slot layout is rigid and length-confusion attacks are ruled
// out without explicit length prefixes.
//
// These primitives are SMT-specific and intentionally live here, not in
// `bintree.rs`, so the legacy Hubt (Patricia trie) is not touched.
// ============================================================================

#[inline]
fn sha256_bytes(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Identity hash: `sha256("ID" || path || sha256(ns) || sha256(key))`.
/// Binds the writer's (path, ns, key) — two leaves with the same identity but
/// different values share this hash. `ns = b""` means "no namespace".
///
/// Both `ns` and `key` are pre-hashed to fixed-size 32-byte digests before
/// concatenation, so the slot layout is rigid (32 + 32 + 32 + 32 = 128 bytes
/// of input) and no length-prefix or tag byte is needed — there's no
/// ambiguity about where one field ends and the next begins.
#[inline]
pub fn identity_hash(path: &Path, ns: &[u8], key: &[u8]) -> Hash {
    let ns_h: Hash = sha256_bytes(ns);
    let key_h: Hash = sha256_bytes(key);
    let mut hasher = Sha256::new();
    hasher.update(b"ID");
    hasher.update(path);
    hasher.update(&ns_h);
    hasher.update(&key_h);
    hasher.finalize().into()
}

/// Value hash: `sha256("VAL" || value)`. Domain-tagged so it cannot collide
/// with a raw `sha256(v)` or with an `identity_hash`.
#[inline]
pub fn value_hash(value: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"VAL");
    hasher.update(value);
    hasher.finalize().into()
}

/// Combine identity and value hashes into the leaf-level hash that gets
/// hashed up the SMT spine: `sha256("LEAF" || identity_hash || value_hash)`.
#[inline]
pub fn leaf_hash_from_components(identity_h: &Hash, value_h: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"LEAF");
    hasher.update(identity_h);
    hasher.update(value_h);
    hasher.finalize().into()
}

/// Hash an internal node from its two child hashes. Domain-tagged with "NODE"
/// to keep node hashes disjoint from leaf hashes and from raw payload hashes.
#[inline]
pub fn hbsmt_node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(b"NODE");
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Precompute empty-subtree hashes: `empties[d]` = hash of an empty subtree
/// rooted at depth d. `empties[256]` = the empty-leaf sentinel.
pub fn make_empties() -> [Hash; 257] {
    let mut empties = [ZERO_HASH; 257];
    empties[256] = ZERO_HASH;
    for d in (0..256).rev() {
        empties[d] = hbsmt_node_hash(&empties[d + 1], &empties[d + 1]);
    }
    empties
}

/// Lift a leaf hash from depth 256 up to `target_depth`, hashing in empty
/// siblings at each step along the leaf's path. Used both when computing a
/// compressed-edge subtree hash and when reconstructing proofs.
#[inline]
pub fn lift_single_leaf(mut h: Hash, leaf_path: &Path, target_depth: u16,
                        empties: &[Hash; 257]) -> Hash {
    for d in (target_depth..256).rev() {
        let bit = get_bit_be(leaf_path, d);
        let empty = &empties[(d + 1) as usize];
        h = if bit == 0 { hbsmt_node_hash(&h, empty) } else { hbsmt_node_hash(empty, &h) };
    }
    h
}

/// First depth at which `a` and `b` differ (in bits, 0..=256).
#[inline]
pub fn lcp_depth(a: &Path, b: &Path) -> u16 {
    let mut d = 0u16;
    for i in 0..32 {
        if a[i] == b[i] { d += 8; }
        else { return d + (a[i] ^ b[i]).leading_zeros() as u16; }
    }
    256
}

/// Inclusive byte-range of paths that fall under `(prefix, depth)`.
#[inline]
pub fn subtree_range(prefix: &Path, depth: u16) -> (Path, Path) {
    if depth >= 256 { return (*prefix, *prefix); }
    let byte_pos = (depth / 8) as usize;
    let bit_in_byte = (depth % 8) as u8;
    let mut lo = [0u8; 32];
    if byte_pos > 0 { lo[0..byte_pos].copy_from_slice(&prefix[0..byte_pos]); }
    let mut hi = lo;
    if bit_in_byte == 0 {
        for i in byte_pos..32 { hi[i] = 0xFF; }
    } else {
        let mask_keep = 0xFFu8 << (8 - bit_in_byte);
        let mask_fill = !mask_keep;
        lo[byte_pos] = prefix[byte_pos] & mask_keep;
        hi[byte_pos] = lo[byte_pos] | mask_fill;
        for i in (byte_pos + 1)..32 { hi[i] = 0xFF; }
    }
    (lo, hi)
}

/// Set the left/right children of `(prefix, depth)`. Cheap helper.
#[inline]
pub fn child_prefixes(prefix: &Path, depth: u16) -> (Path, Path) {
    let mut lp = *prefix;
    set_bit_be(&mut lp, depth, 0);
    mask_after_be(&mut lp, depth + 1);
    let mut rp = *prefix;
    set_bit_be(&mut rp, depth, 1);
    mask_after_be(&mut rp, depth + 1);
    (lp, rp)
}

// ============================================================================
// Proofs
// ============================================================================

/// SMT proof for a target path. The descent stopped at depth `siblings.len()`
/// and what was found there is recorded in `terminus`. The verifier:
///   1. Computes the subtree hash at the stop depth from `terminus`.
///   2. Walks back up to depth 0 by hashing with each sibling and the
///      corresponding bit of the target path.
///   3. Checks the result equals the expected root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HbsmtProof {
    /// Off-path siblings encountered descending from depth 0; `siblings[d]`
    /// is the sibling at depth d. Length determines the stop depth.
    pub siblings: Vec<Hash>,
    /// What occupies the subtree at the stop depth.
    pub terminus: HbsmtTerminus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HbsmtTerminus {
    /// The subtree is fully empty.
    Empty,
    /// The subtree contains exactly one leaf at `path`, represented by its
    /// two-component decomposition: `identity_hash` binds the writer
    /// `(path, ns, key)`, `value_hash` binds the stored value. The full
    /// leaf hash that gets hashed up the spine is
    /// `sha256("LEAF" || identity_hash || value_hash)`.
    ///
    /// Carrying them separately lets the verifier distinguish:
    ///   - identity match + value match  → Included
    ///   - identity match + value differ → Mismatch
    ///   - identity differ               → NonExistence
    ///
    /// This is defense-in-depth: under the application convention "key must
    /// embed the writer's namespace identifier", same-path collisions can't
    /// happen. But if that convention is violated (logic error: someone
    /// forgets to include the namespace in the key), the SMT layer still
    /// reports the correct status instead of leaking another writer's data
    /// as a false `Mismatch`.
    Leaf {
        path: Path,
        identity_hash: Hash,
        value_hash: Hash,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum HbsmtVerifyStatus {
    /// Proof is well-formed, reconstructs the expected root, and the leaf at
    /// the target path hashes to the claimed (key, value).
    Included,
    /// Proof is well-formed and reconstructs the expected root, but a leaf
    /// exists at the target path with a different value than claimed.
    Mismatch,
    /// Proof is well-formed and reconstructs the expected root, and no value
    /// is stored at the target path (empty subtree, or a different leaf in
    /// the compressed slot).
    NonExistence,
    /// Proof is malformed or does not reconstruct the expected root. The
    /// claim is unverifiable.
    Invalid,
}

/// Verify an SMT proof against an expected root for a claimed (ns, key, value).
pub fn verify_hbsmt(
    expected_root: &Hash,
    proof: &HbsmtProof,
    ns: Option<&[u8]>,
    k: &[u8],
    v: &[u8],
) -> HbsmtVerifyStatus {
    let target_path = compute_namespace_path_hbsmt(ns.unwrap_or(b""), k);
    let claimed_identity = identity_hash(&target_path, ns.unwrap_or(b""), k);
    let claimed_value = value_hash(v);
    let empties = make_empties();
    verify_hbsmt_raw(expected_root, proof, &target_path, &claimed_identity, &claimed_value, &empties)
}

/// Lower-level verifier — takes pre-computed `target_path`, claimed
/// `identity_hash` and `value_hash`, and `empties`. Useful when verifying
/// many proofs against the same context.
pub fn verify_hbsmt_raw(
    expected_root: &Hash,
    proof: &HbsmtProof,
    target_path: &Path,
    claimed_identity: &Hash,
    claimed_value: &Hash,
    empties: &[Hash; 257],
) -> HbsmtVerifyStatus {
    let stop = proof.siblings.len();
    if stop > 256 { return HbsmtVerifyStatus::Invalid; }

    // 1. Hash at the stop depth from terminus.
    let mut h = match &proof.terminus {
        HbsmtTerminus::Empty => empties[stop],
        HbsmtTerminus::Leaf { path, identity_hash, value_hash } => {
            let lh = leaf_hash_from_components(identity_hash, value_hash);
            lift_single_leaf(lh, path, stop as u16, empties)
        }
    };

    // 2. Walk back up to root.
    for d in (0..stop).rev() {
        let bit = get_bit_be(target_path, d as u16);
        let sibling = &proof.siblings[d];
        h = if bit == 0 {
            hbsmt_node_hash(&h, sibling)
        } else {
            hbsmt_node_hash(sibling, &h)
        };
    }

    if h != *expected_root { return HbsmtVerifyStatus::Invalid; }

    // 3. Authenticate `terminus.path` upper bits — bits `[0..stop)` are
    //    never consumed by `lift_single_leaf` (which only uses `[stop..256)`)
    //    and the walk-up uses `target_path` bits. Without this guard, an
    //    attacker with an honest inclusion proof could flip a bit at depth
    //    d < stop in `terminus.path` and the reconstructed root would still
    //    match — but `path != target_path` then fires → false NonExistence.
    if let HbsmtTerminus::Leaf { path, .. } = &proof.terminus {
        let stop_u16 = stop as u16;
        let mut a = *path;
        let mut b = *target_path;
        mask_after_be(&mut a, stop_u16);
        mask_after_be(&mut b, stop_u16);
        if a != b { return HbsmtVerifyStatus::Invalid; }
    }

    // 4. Status from terminus + target. The two-component leaf hash lets
    //    the verifier distinguish "different writer at same path bucket"
    //    (which is correctly `NonExistence` for the queried (ns, k)) from
    //    "same writer, wrong value" (which is `Mismatch`). Under the
    //    application convention this is overkill (distinct writers have
    //    distinct keys → distinct paths), but it's a small defense-in-depth
    //    against the human-error case where someone forgets to embed the
    //    namespace in the key.
    match &proof.terminus {
        HbsmtTerminus::Empty => HbsmtVerifyStatus::NonExistence,
        HbsmtTerminus::Leaf { path, identity_hash: id, value_hash: val } => {
            if path != target_path {
                HbsmtVerifyStatus::NonExistence
            } else if id != claimed_identity {
                HbsmtVerifyStatus::NonExistence
            } else if val == claimed_value {
                HbsmtVerifyStatus::Included
            } else {
                HbsmtVerifyStatus::Mismatch
            }
        }
    }
}
