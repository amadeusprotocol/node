use super::arb_robinhood_vectors as v;
use crate::consensus::bridge::arb::*;
use crate::consensus::bridge::bsc::mpt;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn refs(p: &[Vec<u8>]) -> Vec<&[u8]> {
    p.iter().map(|x| x.as_slice()).collect()
}

fn proof_nodes(vecpak_hex: &str) -> Vec<Vec<u8>> {
    match vecpak::decode(&hex(vecpak_hex)).unwrap() {
        vecpak::Term::List(items) => items.into_iter().map(|t| match t { vecpak::Term::Binary(b) => b, _ => panic!() }).collect(),
        _ => panic!(),
    }
}

#[test]
fn arb_message_is_under_a_send_root_the_sepolia_outbox_holds() {
    let data = hex(v::DATA);
    let msg = Message {
        caller: hex(v::CALLER).try_into().unwrap(), destination: hex(v::DESTINATION).try_into().unwrap(),
        l2_block: v::ARB_BLOCK, l1_block: v::ETH_BLOCK, timestamp: v::TIMESTAMP, callvalue: hex(v::CALLVALUE).try_into().unwrap(), data: &data,
    };
    assert_eq!(msg.item_hash().to_vec(), hex(v::ITEM_HASH));
    let siblings: Vec<[u8; 32]> = hex(v::MERKLE_PROOF).chunks_exact(32).map(|c| c.try_into().unwrap()).collect();
    let root = send_root(&msg.item_hash(), v::POSITION, &siblings).unwrap();
    assert_eq!(root.to_vec(), hex(v::SEND_ROOT));
    assert_ne!(send_root(&msg.item_hash(), v::POSITION ^ 1, &siblings), Some(root));
    assert_eq!(send_root(&msg.item_hash(), v::POSITION | 1 << siblings.len(), &siblings), None);

    let state_root: [u8; 32] = hex(v::L1_STATE_ROOT).try_into().unwrap();
    let outbox: [u8; 20] = [0x8d, 0x18, 0x0c, 0xaf, 0x58, 0x8f, 0x3d, 0xa0, 0x27, 0xbe, 0xf1, 0xf4, 0x2a, 0x10, 0x6d, 0xa9, 0x3f, 0x90, 0xb1, 0x66];
    let (ap, sp) = (proof_nodes(v::OUTBOX_ACCOUNT_PROOF), proof_nodes(v::ROOTS_STORAGE_PROOF));
    let account = mpt::verify_account(&state_root, &outbox, &refs(&ap)).unwrap().unwrap();
    let l2_hash = mpt::verify_storage(&account.storage_root, &roots_slot(&root), &refs(&sp)).unwrap();
    assert_ne!(l2_hash, [0u8; 32]);
    let mut other = root;
    other[0] ^= 1;
    assert!(mpt::verify_storage(&account.storage_root, &roots_slot(&other), &refs(&sp)).map_or(true, |w| w == [0u8; 32]));
}
