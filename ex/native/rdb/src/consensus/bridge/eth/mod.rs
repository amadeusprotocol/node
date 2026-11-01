//! Ethereum light client (beacon chain sync committees), as the consensus specs' light client
//! sync protocol (Gloas). A sync committee of 512 validators signs each beacon block; the light
//! client keeps the committee of the current ~27 h period and adopts the next one from an update
//! the current one signed. A signed attested header proves a finalized header (finality branch),
//! whose body proves the hash of the execution block it builds on (execution branch); that
//! execution header then gives the state root orders are proven against.
//!
//! Keys travel uncompressed (96 bytes) and are checked against the committee's SSZ root, so a
//! verification is additions and one pairing, never 512 decompressions.

use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::BLST_ERROR;
use sha2::{Digest, Sha256};

pub const SLOTS_PER_PERIOD: u64 = 32 * 256;
pub const COMMITTEE_SIZE: usize = 512;
/// at least 2/3 of the committee must sign (the spec needs only one signer; we want BFT safety)
pub const MIN_PARTICIPANTS: usize = 342;

/// Gloas generalized indices (consensus-specs gloas/light-client/sync-protocol.md)
pub const FINALIZED_ROOT_GINDEX: u64 = 735;
pub const CURRENT_SYNC_COMMITTEE_GINDEX: u64 = 2945;
pub const NEXT_SYNC_COMMITTEE_GINDEX: u64 = 2946;
pub const EXECUTION_BLOCK_HASH_GINDEX: u64 = 2856;

const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [7, 0, 0, 0];
/// the Ethereum consensus BLS ciphersuite (proof of possession)
pub const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    BadLength,
    BadBranch,
    BadKey,
    BadCommittee,
    TooFewSigners,
    BadSignature,
    BadSlots,
}

/// the network constants a signature commits to
pub struct Network {
    pub genesis_validators_root: [u8; 32],
    /// (first epoch, fork version), ascending
    pub forks: &'static [(u64, [u8; 4])],
}

impl Network {
    pub fn fork_version(&self, epoch: u64) -> [u8; 4] {
        self.forks.iter().rev().find(|(e, _)| epoch >= *e).map(|(_, v)| *v).unwrap_or(self.forks[0].1)
    }
}

fn sha256(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// SSZ merkleization of `chunks`, padded with zero chunks to a power of two at least `limit`
fn merkleize(chunks: &[[u8; 32]], limit: usize) -> [u8; 32] {
    let mut width = 1;
    while width < limit.max(chunks.len()) { width *= 2; }
    let mut layer: Vec<[u8; 32]> = chunks.to_vec();
    layer.resize(width, [0u8; 32]);
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|p| sha256(&p[0], &p[1])).collect();
    }
    layer[0]
}

fn uint64(v: u64) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

impl BeaconHeader {
    /// slot u64 BE | proposer u64 BE | parent 32 | state 32 | body 32
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() != 112 { return Err(Error::BadLength); }
        Ok(Self {
            slot: u64::from_be_bytes(b[0..8].try_into().unwrap()),
            proposer_index: u64::from_be_bytes(b[8..16].try_into().unwrap()),
            parent_root: b[16..48].try_into().unwrap(),
            state_root: b[48..80].try_into().unwrap(),
            body_root: b[80..112].try_into().unwrap(),
        })
    }

    pub fn root(&self) -> [u8; 32] {
        merkleize(&[uint64(self.slot), uint64(self.proposer_index), self.parent_root, self.state_root, self.body_root], 8)
    }

    pub fn period(&self) -> u64 { self.slot / SLOTS_PER_PERIOD }
}

/// the leaf at generalized index `gindex` under `root`
pub fn verify_branch(leaf: &[u8; 32], branch: &[u8], gindex: u64, root: &[u8; 32]) -> Result<(), Error> {
    let depth = 63 - gindex.leading_zeros() as usize;
    if branch.len() != depth * 32 { return Err(Error::BadBranch); }
    let mut node = *leaf;
    for (i, sibling) in branch.chunks_exact(32).enumerate() {
        node = if gindex >> i & 1 == 1 { sha256(sibling, &node) } else { sha256(&node, sibling) };
    }
    if &node != root { return Err(Error::BadBranch); }
    Ok(())
}

fn pubkey_root(pk: &[u8; 48]) -> [u8; 32] {
    let mut hi = [0u8; 32];
    hi[..16].copy_from_slice(&pk[32..]);
    sha256(&pk[..32], &hi)
}

/// a sync committee as it travels: 512 uncompressed keys (96 bytes each), then its aggregate key
/// compressed (48)
pub struct Committee {
    pub keys: Vec<PublicKey>,
    pub root: [u8; 32],
}

impl Committee {
    pub const BYTES: usize = COMMITTEE_SIZE * 96 + 48;

    /// keys are checked to be on the curve; the SSZ root binds them to the committee's compressed
    /// keys (genuine validator keys), so no subgroup check is needed
    pub fn parse(b: &[u8]) -> Result<Self, Error> {
        if b.len() != Self::BYTES { return Err(Error::BadLength); }
        let mut keys = Vec::with_capacity(COMMITTEE_SIZE);
        let mut roots = Vec::with_capacity(COMMITTEE_SIZE);
        for raw in b[..COMMITTEE_SIZE * 96].chunks_exact(96) {
            let pk = PublicKey::deserialize(raw).map_err(|_| Error::BadKey)?;
            roots.push(pubkey_root(&pk.compress()));
            keys.push(pk);
        }
        let aggregate: [u8; 48] = b[COMMITTEE_SIZE * 96..].try_into().unwrap();
        let root = sha256(&merkleize(&roots, COMMITTEE_SIZE), &pubkey_root(&aggregate));
        Ok(Self { keys, root })
    }
}

/// the domain a sync committee signs under at `slot`
pub fn sync_committee_domain(net: &Network, signature_slot: u64) -> [u8; 32] {
    let epoch = signature_slot.max(1).saturating_sub(1) / 32;
    let mut version = [0u8; 32];
    version[..4].copy_from_slice(&net.fork_version(epoch));
    let fork_data_root = sha256(&version, &net.genesis_validators_root);
    let mut d = [0u8; 32];
    d[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    d[4..].copy_from_slice(&fork_data_root[..28]);
    d
}

/// `bits` (64 bytes, bit i = committee member i) of `committee` signed `header` at `signature_slot`
pub fn verify_sync_aggregate(net: &Network, committee: &Committee, bits: &[u8], signature: &[u8], header: &BeaconHeader, signature_slot: u64) -> Result<(), Error> {
    if bits.len() != COMMITTEE_SIZE / 8 || signature.len() != 96 { return Err(Error::BadLength); }
    let signers: Vec<&PublicKey> = committee.keys.iter().enumerate().filter(|(i, _)| bits[i / 8] >> (i % 8) & 1 == 1).map(|(_, k)| k).collect();
    if signers.len() < MIN_PARTICIPANTS { return Err(Error::TooFewSigners); }
    let aggregate = AggregatePublicKey::aggregate(&signers, false).map_err(|_| Error::BadKey)?.to_public_key();
    let sig = Signature::sig_validate(signature, true).map_err(|_| Error::BadSignature)?;
    let signing_root = sha256(&header.root(), &sync_committee_domain(net, signature_slot));
    match sig.verify(false, &signing_root, BLS_DST, &[], &aggregate, false) {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(Error::BadSignature),
    }
}
