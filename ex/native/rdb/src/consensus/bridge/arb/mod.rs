//! Arbitrum chains: an L2 -> L1 message (ArbSys.sendTxToL1) is a leaf of the send Merkle tree,
//! whose root the parent chain's Outbox stores (`roots[sendRoot] = l2BlockHash`) once the rollup
//! confirms the assertion carrying it. Same hashing as Outbox.calculateItemHash / calculateMerkleRoot.

use sha3::{Digest, Keccak256};

/// Outbox storage: `mapping(bytes32 => bytes32) roots` at this slot
pub const OUTBOX_ROOTS_SLOT: u64 = 3;
const MAX_PROOF: usize = 64;

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts { h.update(p); }
    h.finalize().into()
}

fn u256(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

pub struct Message<'a> {
    pub caller: [u8; 20],
    pub destination: [u8; 20],
    pub l2_block: u64,
    pub l1_block: u64,
    pub timestamp: u64,
    pub callvalue: [u8; 32],
    pub data: &'a [u8],
}

impl Message<'_> {
    pub fn item_hash(&self) -> [u8; 32] {
        keccak(&[&self.caller, &self.destination, &u256(self.l2_block), &u256(self.l1_block), &u256(self.timestamp), &self.callvalue, self.data])
    }
}

/// the send root over `item` at leaf `index`; None for a proof the Outbox would refuse
pub fn send_root(item: &[u8; 32], index: u64, proof: &[[u8; 32]]) -> Option<[u8; 32]> {
    if proof.len() > MAX_PROOF || (proof.len() < 64 && index >> proof.len() != 0) { return None; }
    let mut node = keccak(&[item]);
    for (i, sibling) in proof.iter().enumerate() {
        node = if index >> i & 1 == 0 { keccak(&[&node, sibling]) } else { keccak(&[sibling, &node]) };
    }
    Some(node)
}

/// the Outbox storage slot of `roots[send_root]`
pub fn roots_slot(send_root: &[u8; 32]) -> [u8; 32] {
    keccak(&[send_root, &u256(OUTBOX_ROOTS_SLOT)])
}
