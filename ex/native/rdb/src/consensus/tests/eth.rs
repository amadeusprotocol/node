use super::eth_sepolia_vectors as v;
use crate::consensus::bridge::bsc::{header, keccak256};
use crate::consensus::bridge::eth::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

const SEPOLIA: Network = Network {
    genesis_validators_root: [0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05, 0x2a, 0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b, 0x80, 0x78],
    forks: &[(0, [0x90, 0x00, 0x00, 0x75]), (353024, [0x90, 0x00, 0x00, 0x76])],
};

#[test]
fn eth_bootstrap_committee_is_in_the_header_state() {
    let h = BeaconHeader::parse(&hex(v::BOOTSTRAP_HEADER)).unwrap();
    let c = Committee::parse(&hex(v::BOOTSTRAP_COMMITTEE)).unwrap();
    verify_branch(&c.root, &hex(v::BOOTSTRAP_BRANCH), CURRENT_SYNC_COMMITTEE_GINDEX, &h.state_root).unwrap();
    assert_eq!(verify_branch(&c.root, &hex(v::BOOTSTRAP_BRANCH), NEXT_SYNC_COMMITTEE_GINDEX, &h.state_root), Err(Error::BadBranch));
}

#[test]
fn eth_update_proves_a_finalized_execution_state_root() {
    let t = std::time::Instant::now();
    let committee = Committee::parse(&hex(v::BOOTSTRAP_COMMITTEE)).unwrap();
    eprintln!("committee parsed and hashed in {:?}", t.elapsed());
    let attested = BeaconHeader::parse(&hex(v::ATTESTED_HEADER)).unwrap();
    let finalized = BeaconHeader::parse(&hex(v::FINALIZED_HEADER)).unwrap();
    let t = std::time::Instant::now();
    verify_sync_aggregate(&SEPOLIA, &committee, &hex(v::SYNC_BITS), &hex(v::SYNC_SIGNATURE), &attested, v::SIGNATURE_SLOT).unwrap();
    eprintln!("sync aggregate verified in {:?}", t.elapsed());
    verify_branch(&finalized.root(), &hex(v::FINALITY_BRANCH), FINALIZED_ROOT_GINDEX, &attested.state_root).unwrap();
    let exec_hash: [u8; 32] = hex(v::FINALIZED_EXEC_HASH).try_into().unwrap();
    verify_branch(&exec_hash, &hex(v::FINALIZED_EXEC_BRANCH), EXECUTION_BLOCK_HASH_GINDEX, &finalized.body_root).unwrap();
    let next = Committee::parse(&hex(v::NEXT_COMMITTEE)).unwrap();
    verify_branch(&next.root, &hex(v::NEXT_COMMITTEE_BRANCH), NEXT_SYNC_COMMITTEE_GINDEX, &attested.state_root).unwrap();
    //the execution header with that hash gives the state root orders are proven against
    let raw = hex(v::EXEC_HEADER);
    assert_eq!(keccak256(&raw), exec_hash);
    let el = header::parse(&raw).unwrap();
    assert_eq!((el.number, el.state_root.to_vec()), (v::EXEC_NUMBER, hex(v::EXEC_STATE_ROOT)));

    //wrong fork version, too few signers, a forged header: refused
    let other = Network { genesis_validators_root: SEPOLIA.genesis_validators_root, forks: &[(0, [0x90, 0x00, 0x00, 0x75])] };
    assert_eq!(verify_sync_aggregate(&other, &committee, &hex(v::SYNC_BITS), &hex(v::SYNC_SIGNATURE), &attested, v::SIGNATURE_SLOT), Err(Error::BadSignature));
    let mut few = hex(v::SYNC_BITS);
    for b in few.iter_mut().take(22) { *b = 0; }
    assert_eq!(verify_sync_aggregate(&SEPOLIA, &committee, &few, &hex(v::SYNC_SIGNATURE), &attested, v::SIGNATURE_SLOT), Err(Error::TooFewSigners));
    let mut forged = attested.clone();
    forged.state_root[0] ^= 1;
    assert_eq!(verify_sync_aggregate(&SEPOLIA, &committee, &hex(v::SYNC_BITS), &hex(v::SYNC_SIGNATURE), &forged, v::SIGNATURE_SLOT), Err(Error::BadSignature));
}

#[test]
fn eth_light_client_on_amadeus_stores_a_finalized_state_root() {
    use super::chain_harness::Chain;
    let chain = Chain::new();
    let w = chain.wallet(1_000_000_000);
    let call = |f: &[u8], args: &[&[u8]]| chain.call_metered(&w, b"Bridge", f, args);
    let slot = v::SIGNATURE_SLOT.to_string();
    let (bh, bc, bb) = (hex(v::BOOTSTRAP_HEADER), hex(v::BOOTSTRAP_COMMITTEE), hex(v::BOOTSTRAP_BRANCH));
    let (att, fin, fb, eh, eb, el, bits, sig, nc, nb) = (hex(v::ATTESTED_HEADER), hex(v::FINALIZED_HEADER), hex(v::FINALITY_BRANCH), hex(v::FINALIZED_EXEC_HASH),
        hex(v::FINALIZED_EXEC_BRANCH), hex(v::EXEC_HEADER), hex(v::SYNC_BITS), hex(v::SYNC_SIGNATURE), hex(v::NEXT_COMMITTEE), hex(v::NEXT_COMMITTEE_BRANCH));
    let update = |committee: &[u8], next: &[u8], next_branch: &[u8]| call(b"eth_update", &[b"eth-testnet", &att, &fin, &fb, &eh, &eb, &el, committee, &bits, &sig, slot.as_bytes(), next, next_branch]);

    assert_eq!(update(&bc, &[], &[]), Err("bridge_not_initialized".into()));
    let mut other = bh.clone();
    other[0] ^= 1;
    assert_eq!(call(b"eth_init", &[b"eth-testnet", &other, &bc, &bb]), Err("bridge_not_the_trust_anchor".into()));
    call(b"eth_init", &[b"eth-testnet", &bh, &bc, &bb]).unwrap();
    assert_eq!(call(b"eth_init", &[b"eth-testnet", &bh, &bc, &bb]), Err("bridge_already_initialized".into()));

    //signed by another committee (here: the next one) is refused
    assert_eq!(update(&nc, &[], &[]), Err("bridge_wrong_committee".into()));
    //a committee-only update (no finality) stores no root but learns the next committee
    let e: &[u8] = &[];
    call(b"eth_update", &[b"eth-testnet", &att, e, e, e, e, e, &bc, &bits, &sig, slot.as_bytes(), &nc, &nb]).unwrap();
    assert!(chain.get(format!("bic:bridge:eth-testnet:root:{:020}", v::EXEC_NUMBER).as_bytes()).is_none());
    assert_eq!(&chain.get(b"bic:bridge:eth:lc").unwrap()[40..72], Committee::parse(&nc).unwrap().root.as_slice());
    update(&bc, &nc, &nb).unwrap();
    let root = chain.get(format!("bic:bridge:eth-testnet:root:{:020}", v::EXEC_NUMBER).as_bytes()).unwrap();
    assert_eq!(root, hex(v::EXEC_STATE_ROOT));
    let st = chain.get(b"bic:bridge:eth:lc").unwrap();
    assert_eq!(u64::from_be_bytes(st[..8].try_into().unwrap()), v::SIGNATURE_SLOT / SLOTS_PER_PERIOD);
    assert_eq!(&st[40..72], Committee::parse(&nc).unwrap().root.as_slice()); //next committee known now
    update(&bc, &[], &[]).unwrap(); //the same update again changes nothing

    //headers back from the finalized block store an earlier block's root too
    let first = v::EXEC_NUMBER - 3;
    let anc = hex(v::EXEC_ANCESTRY);
    let mut broken = anc.clone();
    let at = broken.len() - 300;
    broken[at] ^= 1;
    assert!(call(b"eth_update", &[b"eth-testnet", &att, &fin, &fb, &eh, &eb, &broken, &bc, &bits, &sig, slot.as_bytes(), &[], &[]]).is_err());
    call(b"eth_update", &[b"eth-testnet", &att, &fin, &fb, &eh, &eb, &anc, &bc, &bits, &sig, slot.as_bytes(), &[], &[]]).unwrap();
    assert_eq!(chain.get(format!("bic:bridge:eth-testnet:root:{:020}", first).as_bytes()).unwrap(), hex(v::EXEC_FIRST_STATE_ROOT));
}
