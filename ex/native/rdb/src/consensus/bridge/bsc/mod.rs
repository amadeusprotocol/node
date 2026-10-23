//! BNB Smart Chain light-client primitives: RLP, Merkle-Patricia proofs, Parlia headers
//! and fast-finality vote attestations (ported from bnb-chain/bsc consensus/parlia).
//!
//! Notes (checked against mainnet 2026-10, BSC height ~129.3M):
//! - BSC runs 21 validators with turnLength 8 (Fermi lowered it from 16). Both are read from
//!   the epoch header; only EPOCH_LENGTH = 1000 (Maxwell) is a constant.
//! - Public BSC RPCs mostly refuse eth_getProof except at the head block: the relayer needs its
//!   own BSC node or a provider that serves proofs.
//! - Since Fermi BSC accepts attestations targeting an ancestor up to 3 blocks back. We only
//!   treat a source as final when the target is its direct child (BEP-126): stricter, so safe;
//!   at worst the relayer waits for the next such attestation.

pub mod finality;
pub mod header;
pub mod mpt;
pub mod rlp;

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(data).into()
}
