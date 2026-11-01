//! Polygon PoS: checkpoints on Ethereum (RootChain.headerBlocks) commit a Merkle tree of the blocks
//! they cover, each leaf keccak256(number, timestamp, transactionsRoot, receiptsRoot) (Polygon's
//! Merkle.checkMembership, padded to a power of two). A block's receipts root then proves a receipt
//! and its logs (receipt trie, key rlp(transaction index)).

use super::bsc::{keccak256, rlp};

/// RootChain storage: `mapping(uint256 => HeaderBlock) headerBlocks` at this slot; a HeaderBlock is
/// root, start, end, createdAt, proposer
pub const HEADER_BLOCKS_SLOT: u64 = 5;
const MAX_DEPTH: usize = 32;

fn u256(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

pub fn checkpoint_leaf(number: u64, timestamp: u64, transactions_root: &[u8; 32], receipts_root: &[u8; 32]) -> [u8; 32] {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(&u256(number));
    b.extend_from_slice(&u256(timestamp));
    b.extend_from_slice(transactions_root);
    b.extend_from_slice(receipts_root);
    keccak256(&b)
}

/// the checkpoint root over `leaf` at `index`; None for a proof RootChain would refuse
pub fn checkpoint_root(leaf: &[u8; 32], index: u64, siblings: &[[u8; 32]]) -> Option<[u8; 32]> {
    if siblings.len() > MAX_DEPTH || index >> siblings.len() != 0 { return None; }
    let mut node = *leaf;
    for (i, s) in siblings.iter().enumerate() {
        let mut b = [0u8; 64];
        if index >> i & 1 == 0 { b[..32].copy_from_slice(&node); b[32..].copy_from_slice(s); } else { b[..32].copy_from_slice(s); b[32..].copy_from_slice(&node); }
        node = keccak256(&b);
    }
    Some(node)
}

/// the storage slot of field `field` (0 root, 1 start, 2 end) of headerBlocks[id]
pub fn header_block_slot(id: u64, field: u8) -> [u8; 32] {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&u256(id));
    b[32..].copy_from_slice(&u256(HEADER_BLOCKS_SLOT));
    let mut slot = keccak256(&b);
    let mut carry = field as u16;
    for byte in slot.iter_mut().rev() {
        let v = *byte as u16 + carry;
        *byte = v as u8;
        carry = v >> 8;
        if carry == 0 { break; }
    }
    slot
}

/// rlp(index): the receipt trie key of a transaction
pub fn receipt_key(index: u64) -> Vec<u8> {
    let mut out = Vec::new();
    rlp::encode_u64(&mut out, index);
    out
}

pub struct Log<'a> {
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: &'a [u8],
}

/// a receipt (typed: type byte then RLP) -> succeeded?, its logs
pub fn receipt_logs(raw: &[u8]) -> Result<(bool, Vec<Log<'_>>), rlp::Error> {
    let body = match raw.first() {
        Some(t) if *t < 0x80 => &raw[1..],
        _ => raw,
    };
    let f = rlp::decode_exact(body)?.list()?;
    if f.len() != 4 { return Err(rlp::Error::Expected("receipt")); }
    let ok = f[0].bytes()? == [1u8];
    let mut logs = Vec::new();
    for l in f[3].list()? {
        let l = l.list()?;
        if l.len() != 3 { return Err(rlp::Error::Expected("receipt")); }
        let address: [u8; 20] = l[0].bytes()?.try_into().map_err(|_| rlp::Error::Expected("receipt"))?;
        let topics = l[1].list()?.iter().map(|t| t.bytes32()).collect::<Result<Vec<_>, _>>()?;
        logs.push(Log { address, topics, data: l[2].bytes()? });
    }
    Ok((ok, logs))
}

/// the bytes of ABI-encoded `(bytes)` event data
pub fn abi_bytes(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 64 || data[..32] != u256(32) { return None; }
    if data[32..56] != [0u8; 24] { return None; }
    let len = u64::from_be_bytes(data[56..64].try_into().unwrap()) as usize;
    let padded = len.checked_add(31)? / 32 * 32;
    if data.len() != 64 + padded || data[64 + len..].iter().any(|b| *b != 0) { return None; }
    Some(&data[64..64 + len])
}
