use super::polygon_amoy_vectors as v;
use crate::consensus::bridge::bsc::mpt;
use crate::consensus::bridge::polygon::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn h32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn nodes(vecpak_hex: &str) -> Vec<Vec<u8>> {
    match vecpak::decode(&hex(vecpak_hex)).unwrap() {
        vecpak::Term::List(items) => items.into_iter().map(|t| match t { vecpak::Term::Binary(b) => b, _ => panic!() }).collect(),
        _ => panic!(),
    }
}

fn refs(p: &[Vec<u8>]) -> Vec<&[u8]> {
    p.iter().map(|x| x.as_slice()).collect()
}

#[test]
fn polygon_log_is_in_a_checkpoint_the_sepolia_root_chain_holds() {
    let rootchain: [u8; 20] = [0xbd, 0x07, 0xd7, 0xe1, 0xe9, 0x3c, 0x8d, 0x4b, 0x2a, 0x26, 0x13, 0x27, 0xf3, 0xc2, 0x8a, 0x8e, 0xa7, 0x16, 0x72, 0x09];
    let account = mpt::verify_account(&h32(v::L1_STATE_ROOT), &rootchain, &refs(&nodes(v::ROOT_CHAIN_ACCOUNT_PROOF))).unwrap().unwrap();
    let root = mpt::verify_storage(&account.storage_root, &header_block_slot(v::CHECKPOINT_ID, 0), &refs(&nodes(v::ROOT_STORAGE_PROOF))).unwrap();
    let start = mpt::verify_storage(&account.storage_root, &header_block_slot(v::CHECKPOINT_ID, 1), &refs(&nodes(v::START_STORAGE_PROOF))).unwrap();
    assert_eq!(root, h32(v::CHECKPOINT_ROOT));
    assert_eq!(u64::from_be_bytes(start[24..].try_into().unwrap()), v::START);

    let (txs, receipts) = (h32(v::TRANSACTIONS_ROOT), h32(v::RECEIPTS_ROOT));
    let siblings: Vec<[u8; 32]> = hex(v::BLOCK_PROOF).chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
    let leaf = checkpoint_leaf(v::NUMBER, v::TIMESTAMP, &txs, &receipts);
    assert_eq!(checkpoint_root(&leaf, v::NUMBER - v::START, &siblings), Some(root));
    assert_ne!(checkpoint_root(&checkpoint_leaf(v::NUMBER, v::TIMESTAMP + 1, &txs, &receipts), v::NUMBER - v::START, &siblings), Some(root));
    assert_ne!(checkpoint_root(&leaf, v::NUMBER - v::START + 1, &siblings), Some(root));
    assert_eq!(checkpoint_root(&leaf, 1 << siblings.len(), &siblings), None);

    let receipt = mpt::verify_key(&receipts, &receipt_key(v::TX_INDEX), &refs(&nodes(v::RECEIPT_PROOF))).unwrap().unwrap();
    assert!(mpt::verify_key(&receipts, &receipt_key(v::TX_INDEX + 1), &refs(&nodes(v::RECEIPT_PROOF))).map_or(true, |r| r.is_none()));
    let (ok, logs) = receipt_logs(&receipt).unwrap();
    assert!(ok);
    assert_eq!(logs[0].address.to_vec(), hex(v::LOG_ADDRESS));
    assert_eq!(logs[0].topics.len(), v::LOG_TOPICS);
    assert_eq!(logs[0].topics[0], h32(v::LOG_TOPIC0));
    assert_eq!(logs[0].data, hex(v::LOG_DATA).as_slice());
}

#[test]
fn polygon_abi_bytes_is_strict() {
    let mut data = vec![0u8; 32];
    data[31] = 32;
    data.extend_from_slice(&[0u8; 31]);
    data.push(3);
    data.extend_from_slice(&[1, 2, 3]);
    data.extend_from_slice(&[0u8; 29]);
    assert_eq!(abi_bytes(&data), Some(&[1u8, 2, 3][..]));
    let mut dirty = data.clone();
    dirty[70] = 1;
    assert_eq!(abi_bytes(&dirty), None);
    assert_eq!(abi_bytes(&data[..data.len() - 1]), None);
    let mut moved = data.clone();
    moved[31] = 64;
    assert_eq!(abi_bytes(&moved), None);
}
