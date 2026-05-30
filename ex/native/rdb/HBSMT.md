# HBSMT — Hot Binary Sparse Merkle Tree

> A namespace-aware, binary, sparse Merkle tree designed for blockchain state with hot contracts.
> SHA-256 (quantum-safe), RocksDB-backed, single-leaf-lift compression, LCP-jump locality,
> and a two-component leaf hash that closes a class of cross-namespace identity attacks.

## TL;DR

- **Hot.** A 4-byte `sha256(namespace)` prefix buckets writes from the same contract into a shared
  subtree, so popular contracts cluster. The "LCP-jump" optimization collapses the shared spine into
  a single flat loop instead of 64+ levels of recursion. **Hot-namespace batches are 4× faster than
  random-key batches at the same scale.**
- **Binary.** Two children per internal node, depth 256. Compared with JMT's 16-ary trie, binary
  gives **simpler and more native non-inclusion proofs**: a non-inclusion is either "empty subtree
  at the lift depth" or "a different leaf occupies the compressed slot" — both representable in the
  same proof shape as an inclusion. No extra structural commitments, no NodeType discrimination.
- **Sparse.** Empty subtrees are precomputed (`empties[d]` for d ∈ 0..256) and never stored.
  Single-leaf subtrees are "lifted" — only the leaf hash plus the leaf path are kept, not the chain
  of empty siblings up to it.
- **Production target hit.** 1M-entry tree, 10k-update hot-namespace batch, RocksDB-backed:
  **239 ms apply, 12 µs root, 82 s build** on a single thread. Well under a 500 ms block budget.

## Why it exists

The chain's state is dominated by **hot contracts** — a small number of namespaces (tokens, AMM
pools, popular dApps) absorbing most writes per block. A naive SMT scatters writes randomly across
the tree by hashing keys; every update touches a fresh path and pays log₂(N) hashing + RocksDB
write amplification. At 10M state entries this puts a 10k-update block at ~880 ms apply — too slow
for a 500 ms budget.

HBSMT exploits the fact that the hot contracts are *known* (they have a namespace identifier) and
groups their writes together at the *top* of the tree. The result: the LCP-jump short-circuits the
shared-prefix descent, hot-namespace blocks cost the same as touching a much smaller subtree.

## Architecture

### Path layout (4 + 28)

```
path = sha256(ns)[0..4]  ||  sha256(key)[0..28]
```

The 4-byte namespace prefix is a **locality hint**, not a security primitive. Two contracts with
colliding 4-byte prefixes share a subtree bucket — performance-neutral if the application convention
holds (keys embed their writer's identifier, so the 28-byte key hash always separates them).

### Leaf hash — two components

```
identity_hash = sha256("ID"   || path || sha256(ns) || sha256(key))
value_hash    = sha256("VAL"  || value)
leaf_hash     = sha256("LEAF" || identity_hash || value_hash)   ← hashed up the tree
```

`ns` and `key` are pre-hashed to fixed-size 32-byte digests before concatenation, so the slot
layout is rigid (4 fixed-size fields). No length prefixes, no presence-tag byte, no shift-attack
surface. "No namespace" is `ns = b""` — `sha256(b"")` is a well-known fixed digest, structurally
distinguishable from any non-empty namespace's hash.

The leaf is committed by `leaf_hash`. Proofs carry `identity_hash` and `value_hash` *separately* so
the verifier can distinguish:

- identity matches + value matches  → **Included**
- identity matches + value differs  → **Mismatch**
- identity differs                  → **NonExistence** (some other writer occupies the slot)

This costs 32 extra bytes per leaf on disk (~15% total tree growth for 1M leaves). It's
**defense-in-depth** against logic-error namespace collisions: without it, a verifier asking
"is `(ns_B, k)` set to `v`?" against a leaf written by `(ns_A, k)` (under engineered 4-byte
collision) would incorrectly report `Mismatch` — leaking `ns_A`'s data as "this exists with a
different value."

### Storage

| CF       | Key                          | Value                              |
|----------|------------------------------|------------------------------------|
| `leaves` | `path[32]`                   | `identity_hash[32] ‖ value_hash[32]` (64 B) |
| `splits` | `path[32] ‖ depth_be[2]`     | `node_hash[32]`                    |

`splits` only stores *real bifurcations* — internal nodes where both children are non-empty. A
binary tree with N leaves contains ≈ N − 1 real bifurcations, so total split count is bounded.

## The "Hot" part

### Why namespace locality matters

For a random-key 10k batch on a 1M tree, descent visits ~10k × log₂(1M) = 240k internal-node
positions. With hot-namespace clustering, 10k dirty paths share their first 32 bits, so the top 32
levels of descent are *identical* for all 10k paths — they all go the same direction at each bit.

### LCP-jump

`descend_and_rehash` detects this with `lcp_depth(&dirty[0], &dirty[dirty.len() - 1])` (cost: O(32)
byte cmps). If the LCP exceeds the current depth, it:

1. Recurses *once* into the LCP-aligned subtree.
2. On the way back up, walks each depth from `lcp_d - 1` down to current in a **flat iterative loop**,
   hashing in the "other side" (clean sibling) at each level.

Result: instead of 64 levels of recursive function calls with 64 cached-sibling fetches, you get
one recursion + 64 iterations. The CPU cost is identical, but the cache behavior and branch
predictor are much happier — and the algorithm composes correctly with the single-leaf-lift
collapse on the dirty side.

### Measured

Both at 1M scale:

| Workload | Apply time |
|---|---|
| 10k random keys | 942 ms |
| 10k hot-namespace (all in `ns-00`) | **210 ms** |

The 4.5× speedup is purely from the locality structure — no change in tree size or per-hash cost.

## The "Binary" part — why non-inclusion proofs are easy

### Binary HBSMT non-inclusion

A binary SMT has **only two children per internal node**. The proof's structure is:

```rust
struct HbsmtProof {
    siblings: Vec<Hash>,  // one sibling per depth, indexed by depth
    terminus: HbsmtTerminus,
}
enum HbsmtTerminus {
    Empty,                                    // subtree at stop depth is fully empty
    Leaf { path, identity_hash, value_hash }, // single leaf occupies the compressed slot
}
```

A non-inclusion is then **one of two shapes**:

1. **Empty terminus** — the queried path leads to an empty subtree at depth `stop`. The verifier
   computes `empties[stop]` and walks back up. No extra structural info needed.
2. **Different-leaf terminus** — the queried path lands in a compressed slot occupied by some
   other leaf at path P. The verifier sees `terminus.path != target_path` (or, with the two-component
   hash, `terminus.identity_hash != claimed_identity`) and returns `NonExistence`.

Both shapes share the *exact same* `(siblings, terminus)` layout as an inclusion proof. No
discriminator bytes, no sub-shapes, no node-type tags. The verifier walks a single algorithm and
the status pops out at the end. Wider-fanout trees (16-ary etc.) generally need to commit to
internal-node structure with extra discriminators in their non-inclusion proofs; binary doesn't.

## Verifier — the security-critical part

```rust
fn verify_hbsmt(root, proof, ns, k, v) -> {Included|Mismatch|NonExistence|Invalid}
```

The verifier's decision tree, in order:

1. **`siblings.len() > 256` → Invalid.** Reject malformed proofs upfront.
2. **Compute leaf hash from terminus.** For `Leaf`, combine `identity_hash` and `value_hash` via
   `sha256("LEAF" || id || val)`. For `Empty`, use `empties[stop]`.
3. **Walk up to root.** At each depth `d` in `[0..stop)` descending, combine the running hash with
   `siblings[d]` using the `d`-th bit of `target_path` to choose left/right.
4. **Check `reconstructed_root == expected_root` → Invalid if mismatch.**
5. **Authenticate `terminus.path` upper bits.** Bits `[0..stop)` of `terminus.path` were *never*
   consumed by `lift_single_leaf` (which only uses `[stop..256)`) or by the walk-up (which uses
   `target_path` bits). Without this guard, an attacker holding an honest inclusion proof could flip
   any single bit at depth `d < stop` in `terminus.path` and the verifier would still reconstruct
   the real root — but the final `terminus.path != target_path` check would then fire and return
   `NonExistence` for an actually-included key. **This is the "free-bit malleability censorship
   oracle" we fixed.**
6. **Status dispatch:**
   - `Empty` terminus → `NonExistence`
   - `Leaf` terminus + path mismatch → `NonExistence`
   - `Leaf` terminus + identity mismatch → `NonExistence` *(the two-component hash)*
   - `Leaf` terminus + identity match + value match → `Included`
   - `Leaf` terminus + identity match + value mismatch → `Mismatch`

All four statuses are reachable by honest proofs. `Invalid` is reserved for malformed inputs and
proofs that don't reconstruct.

## Algorithm — One-Phase Batch Update

Based on arXiv 2310.13328 (Aergo, modified). For a batch of K updates on a tree of N leaves:

1. **Resolve to paths and collapse**: build a `BTreeMap<Path, Option<(id, val)>>` so multiple writes
   to the same key collapse to the last-write-wins state. O(K log K).
2. **Detect dirty paths**: compare each path's new vs current state. Only changed paths get into
   the `dirty` list. Sorted by `BTreeMap` traversal.
3. **Single sorted descent**: `descend_and_rehash(prefix, depth, dirty)` partitions `dirty` by the
   bit at `depth`. Each internal node is *hashed exactly once* per batch regardless of how many
   dirty paths fall under it.

Three short-circuits keep the descent cheap:

- **dirty.is_empty()** → return cached subtree hash.
- **dirty.len() == 1 AND subtree has ≤ 1 leaf** → use `lift_single_leaf` directly. Skips the
  ~250-level walk through a compressed edge.
- **LCP-jump** (described above) — collapses shared-prefix descents.

Total work: **O(K log K + dirty internal nodes)**. Critically, it's *not* O(K log N) — the
algorithm doesn't pay for empty subtrees.

## Performance (1M tree, hot-ns 10k batch, RocksDB-backed, single thread)

| Metric | Value |
|---|---|
| Build (1M leaves, 50k-op chunks) | 82.5 s |
| Apply (10k-update hot batch) | **239 ms** |
| Root computation | 12 µs |
| Tree on disk (estimate) | ~390 MB |
| Storage overhead vs single-hash leaves | +15% |

**95%+ of apply time is RocksDB overhead** — transactional locking, WAL appends, memtable inserts,
write conflict tracking. Pure hashing with SHA-NI is ~15 ms of the 239 ms. The algorithm itself is
not the bottleneck at this scale and won't be at 10× scale either. Going meaningfully faster
requires moving off RocksDB (custom log-structured store, mmap'd flat-file with in-RAM index, etc.)
— see the limitations section.

## Security model

- **Hash**: SHA-256 throughout. SHA-NI acceleration on modern x86 means hashing is ~15 ms of the
  240 ms apply at 1M — not the bottleneck.
- **Quantum**: hash-based → only Grover applies (256-bit → 128-bit effective). No reliance on
  discrete log or pairings, unlike Verkle.
- **Domain separation**: leaf, identity, value, and internal-node hashes all use distinct ASCII
  domain tags (`"LEAF"`, `"ID"`, `"VAL"`, `"NODE"`). Cross-type collisions require a SHA-256 break.
- **Length confusion**: `identity_hash` pre-hashes `ns` and `key` to fixed-size digests before
  concatenating, so shift-attacks between `ns` and `key` fields are structurally impossible.
- **Path bit-flip authentication**: `verify_hbsmt_raw` requires `terminus.path[0..stop)` to match
  `target_path[0..stop)` — without this, a single-bit flip in the unauthenticated upper bits of
  `terminus.path` lets an attacker convert any honest inclusion proof into a `NonExistence` verdict
  (a censorship oracle).
- **Cross-namespace identity binding**: the two-component leaf hash ensures the verifier
  cryptographically distinguishes which writer authored a leaf, even under engineered 4-byte path
  collisions. Defense-in-depth against the human-error case where a write lands with a key that
  doesn't embed the writer's identifier.

## What's tested

54 tests in the consensus module under `cargo test --release --lib consensus::hbsmt`, including:

- Cryptographic correctness on small trees and at 1M scale.
- Round-trip prove → verify for each of `Included`, `Mismatch`, `NonExistence`, `Invalid`.
- Engineered 4-byte namespace collision tests — both same-key (impossible under convention but
  defended) and different-key (the normal case).
- Bit-flip regression: every single-bit flip at depth `< stop` in `terminus.path` is rejected.
- Order independence: a batch shuffled in any permutation (where each key appears once) produces
  the same root.
- Chunked vs single-batch equivalence: same final state reached via different batch decompositions
  produces the same root.
- In-memory `Hbsmt` and RocksDB `HbsmtRdb` produce identical roots and proofs on the same workload.

## API

```rust
use rdb::consensus::hbsmt::Hbsmt;
use rdb::consensus::hbsmt_rdb::HbsmtRdb;
use rdb::consensus::hbsmt_common::{verify_hbsmt, HbsmtProof, HbsmtTerminus, HbsmtVerifyStatus};
use rdb::consensus::bintree::Op;

// In-memory:
let mut tree = Hbsmt::new();
tree.batch_update(vec![
    Op::Insert(Some(b"ns-1".to_vec()), b"key-1".to_vec(), b"value-1".to_vec()),
    Op::Insert(Some(b"ns-1".to_vec()), b"key-2".to_vec(), b"value-2".to_vec()),
]);
let root = tree.root();
let proof = tree.prove(Some(b"ns-1"), b"key-1");
assert_eq!(
    verify_hbsmt(&root, &proof, Some(b"ns-1"), b"key-1", b"value-1"),
    HbsmtVerifyStatus::Included,
);

// RocksDB-backed:
let smt = HbsmtRdb::open(std::path::Path::new("/var/lib/state"));
smt.batch_update(ops);
let root = smt.root();
let proof = smt.prove(Some(b"ns-1"), b"key-1");
```

## Known limitations / future work

- **RocksDB is the wall.** 95%+ of apply time is RocksDB transactional overhead — pessimistic
  locking, WAL appends, memtable inserts, conflict tracking, snapshot bookkeeping. The HBSMT
  algorithm itself contributes a small fraction. To scale meaningfully past current numbers, the
  storage layer needs to move off RocksDB: either a Reth-style persistent in-memory overlay
  (defer disk writes off the hot path, async flush), or a custom flat-store (NOMT-style:
  append-only log + in-RAM index, no LSM compaction). Algorithm tuning alone won't move the needle.
- **Storage growth from two-component leaf hash.** 64 B per leaf instead of 32 B. Acceptable but
  not free; only justified if the cross-namespace defense matters for the application.
- **Pathological inputs.** Keys engineered to maximize binary depth (forcing deep bifurcations
  across the entire 256-bit space) can push apply time beyond the budget. In practice this requires
  ~2^128 work to construct.

## Acknowledgments

The HBSMT borrows ideas from:
- **One-Phase Batch Update** — arXiv 2310.13328 (Aergo SMT).
- **Single-leaf-lift compression** — Jellyfish Merkle Tree (Diem / Aptos / Penumbra).
- **Penumbra-style in-place mutate** — write-the-same-key-N-times costs one hash.
- **EMPTY[d] precomputed constants** — folklore in many SMT designs.

The specific combination (binary + 4-byte namespace prefix path + LCP-jump + two-component
identity/value leaf hash + prefix-authenticated verifier) is, to our knowledge, novel.
