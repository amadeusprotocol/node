//! Ethereum Merkle-Patricia trie proof verification (eth_getProof accountProof/storageProof).

use super::keccak256;
use super::rlp::{self, Item};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Rlp(rlp::Error),
    BadNode,
    HashMismatch,
    UnusedProofNodes,
    ProofTooShort,
}

impl From<rlp::Error> for Error {
    fn from(e: rlp::Error) -> Self { Error::Rlp(e) }
}

enum Next<'a> {
    Hash([u8; 32]),
    Inline(Item<'a>),
    Absent,
}

fn child<'a>(item: &Item<'a>) -> Result<Next<'a>, Error> {
    if item.is_list {
        //nodes under 32 bytes are embedded in their parent instead of hashed
        if item.raw.len() >= 32 { return Err(Error::BadNode); }
        return Ok(Next::Inline(*item));
    }
    match item.payload.len() {
        0 => Ok(Next::Absent),
        32 => Ok(Next::Hash(item.payload.try_into().unwrap())),
        _ => Err(Error::BadNode),
    }
}

/// hex-prefix encoded path -> (is_leaf, nibbles)
fn decode_path(encoded: &[u8]) -> Result<(bool, Vec<u8>), Error> {
    let first = *encoded.first().ok_or(Error::BadNode)?;
    let flag = first >> 4;
    if flag > 3 { return Err(Error::BadNode); }
    let mut nibbles = Vec::with_capacity(encoded.len() * 2);
    if flag & 1 == 1 { nibbles.push(first & 0x0f); } else if first & 0x0f != 0 { return Err(Error::BadNode); }
    for b in &encoded[1..] { nibbles.push(b >> 4); nibbles.push(b & 0x0f); }
    Ok((flag >= 2, nibbles))
}

/// Value stored under `key` (32-byte keccak path) in the trie with root `root`, or None if
/// the proof shows it is absent. Every proof node must be used, in order.
pub fn verify(root: &[u8; 32], key: &[u8; 32], proof: &[&[u8]]) -> Result<Option<Vec<u8>>, Error> {
    let path: Vec<u8> = key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect();
    let mut pos = 0;
    let mut nodes = proof.iter();
    let mut next = Next::Hash(*root);
    loop {
        let node = match next {
            Next::Absent => return finish(nodes, None),
            Next::Inline(item) => item,
            Next::Hash(h) => {
                let raw = nodes.next().ok_or(Error::ProofTooShort)?;
                if keccak256(raw) != h { return Err(Error::HashMismatch); }
                rlp::decode_exact(raw)?
            }
        };
        let items = node.list()?;
        match items.len() {
            17 => {
                if pos == path.len() {
                    let v = items[16].bytes()?;
                    return finish(nodes, if v.is_empty() { None } else { Some(v.to_vec()) });
                }
                next = child(&items[path[pos] as usize])?;
                pos += 1;
            }
            2 => {
                let (is_leaf, node_path) = decode_path(items[0].bytes()?)?;
                let rest = &path[pos..];
                if is_leaf {
                    let v = items[1].bytes()?;
                    return finish(nodes, if rest == node_path.as_slice() { Some(v.to_vec()) } else { None });
                }
                if node_path.is_empty() || !rest.starts_with(&node_path) { return finish(nodes, None); }
                pos += node_path.len();
                next = child(&items[1])?;
            }
            _ => return Err(Error::BadNode),
        }
    }
}

fn finish(mut rest: std::slice::Iter<&[u8]>, value: Option<Vec<u8>>) -> Result<Option<Vec<u8>>, Error> {
    if rest.next().is_some() { return Err(Error::UnusedProofNodes); }
    Ok(value)
}

pub struct Account {
    pub nonce: u64,
    pub balance: Vec<u8>,
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
}

/// account at `address` under a block's stateRoot
pub fn verify_account(state_root: &[u8; 32], address: &[u8; 20], proof: &[&[u8]]) -> Result<Option<Account>, Error> {
    let Some(raw) = verify(state_root, &keccak256(address), proof)? else { return Ok(None) };
    let f = rlp::decode_exact(&raw)?.list()?;
    if f.len() != 4 { return Err(Error::BadNode); }
    Ok(Some(Account { nonce: f[0].u64()?, balance: f[1].bytes()?.to_vec(), storage_root: f[2].bytes32()?, code_hash: f[3].bytes32()? }))
}

/// 32-byte big-endian storage word at `slot` under an account's storageRoot (zero when absent)
pub fn verify_storage(storage_root: &[u8; 32], slot: &[u8; 32], proof: &[&[u8]]) -> Result<[u8; 32], Error> {
    let mut word = [0u8; 32];
    if let Some(raw) = verify(storage_root, &keccak256(slot), proof)? {
        let v = rlp::decode_exact(&raw)?.bytes()?;
        if v.is_empty() || v.len() > 32 || v[0] == 0 { return Err(Error::BadNode); }
        word[32 - v.len()..].copy_from_slice(v);
    }
    Ok(word)
}
