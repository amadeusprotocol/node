use super::bsc_vectors as v;
use crate::consensus::bridge::bsc::{finality, header, keccak256, mpt, rlp};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn h32(s: &str) -> [u8; 32] { hex(s).try_into().unwrap() }

fn epoch_set(raw: &[u8]) -> finality::ValidatorSet {
    let (vals, turn) = header::epoch_validators(&header::parse(raw).unwrap()).unwrap();
    finality::ValidatorSet::new(vals, turn).unwrap()
}

#[test]
fn bsc_headers_hash_and_parse() {
    for (raw, hash, number) in [(v::LATEST_RAW, v::LATEST_HASH, v::LATEST_NUMBER), (v::SOURCE_RAW, v::SOURCE_HASH, v::SOURCE_NUMBER),
                                (v::EPOCH0_RAW, v::EPOCH0_HASH, v::EPOCH0_NUMBER), (v::EPOCH1_RAW, v::EPOCH1_HASH, v::EPOCH1_NUMBER)] {
        let raw = hex(raw);
        let h = header::parse(&raw).unwrap();
        assert_eq!(h.hash, h32(hash), "hash of block {number}");
        assert_eq!(h.number, number);
    }
    assert_eq!(header::parse(&hex(v::SOURCE_RAW)).unwrap().state_root, h32(v::SOURCE_STATE_ROOT));
    //an epoch block announces its set; other blocks do not
    let (vals, turn) = header::epoch_validators(&header::parse(&hex(v::EPOCH1_RAW)).unwrap()).unwrap();
    assert_eq!((vals.len(), turn), (21, 8));
    let mut bad = vals.clone();
    bad[0].vote_key[47] ^= 1;
    assert_eq!(finality::ValidatorSet::new(bad, turn), Err(finality::Error::BadVoteKey));
    assert_eq!(finality::ValidatorSet::new(vals, turn).unwrap().switch_offset(), (21 / 2 + 1) * 8 - 1);
    assert_eq!(header::epoch_validators(&header::parse(&hex(v::LATEST_RAW)).unwrap()), Err(header::Error::NotEpochBlock));
}

#[test]
fn bsc_attestation_finalizes_its_source() {
    let latest_raw = hex(v::LATEST_RAW);
    let latest = header::parse(&latest_raw).unwrap();
    let att = header::attestation(&latest).unwrap().expect("attestation");
    assert_eq!((att.data.source_number, att.data.target_number), (v::SOURCE_NUMBER, v::TARGET_NUMBER));
    assert_eq!(att.data.target_hash, latest.parent_hash);

    let (old, new) = (epoch_set(&hex(v::EPOCH0_RAW)), epoch_set(&hex(v::EPOCH1_RAW)));
    let set = if finality::uses_announced_set(att.data.target_number, v::EPOCH1_NUMBER, &old) { &new } else { &old };
    finality::verify_attestation(&att, set).unwrap();
    assert_eq!(finality::finalized(&att), Some((v::SOURCE_NUMBER, h32(v::SOURCE_HASH))));

    //the finalized source and its child are parent-linked to the attested target
    let source_raw = hex(v::SOURCE_RAW);
    let source = header::parse(&source_raw).unwrap();
    assert_eq!(source.hash, att.data.source_hash);
    finality::verify_ancestry(&[source], &att.data.source_hash).unwrap();

    //tampering breaks it
    let mut bad = att.clone();
    bad.data.source_hash[0] ^= 1;
    assert_eq!(finality::verify_attestation(&bad, set), Err(finality::Error::BadSignature));
    let mut few = att.clone();
    while few.vote_set.count_ones() as usize >= set.quorum() { few.vote_set &= few.vote_set - 1; }
    assert_eq!(finality::verify_attestation(&few, set), Err(finality::Error::NotEnoughVotes));
    let other = if std::ptr::eq(set, &old) { &new } else { &old };
    if other != set { assert!(finality::verify_attestation(&att, other).is_err()); }
}

#[test]
fn bsc_storage_proofs_against_finalized_state_root() {
    let root = h32(v::SOURCE_STATE_ROOT);
    let address: [u8; 20] = hex(v::WBNB).try_into().unwrap();
    let account_proof: Vec<Vec<u8>> = v::ACCOUNT_PROOF.iter().map(|p| hex(p)).collect();
    let refs: Vec<&[u8]> = account_proof.iter().map(|p| p.as_slice()).collect();
    let account = mpt::verify_account(&root, &address, &refs).unwrap().expect("account");
    assert_eq!(account.storage_root, h32(v::WBNB_STORAGE_ROOT));
    assert_eq!(account.code_hash, h32(v::WBNB_CODE_HASH));
    assert_eq!(account.nonce, v::WBNB_NONCE);

    for (slot, value, proof) in [(v::SLOT0, v::SLOT0_VALUE, v::SLOT0_PROOF), (v::SLOT1, v::SLOT1_VALUE, v::SLOT1_PROOF)] {
        let proof: Vec<Vec<u8>> = proof.iter().map(|p| hex(p)).collect();
        let refs: Vec<&[u8]> = proof.iter().map(|p| p.as_slice()).collect();
        assert_eq!(mpt::verify_storage(&account.storage_root, &h32(slot), &refs).unwrap(), h32(value));
    }
    //slot 0 holds "Wrapped BNB"
    assert_eq!(&h32(v::SLOT0_VALUE)[..11], b"Wrapped BNB");

    //a wrong root, a tampered node or a dropped node never verifies
    let mut bad_root = root;
    bad_root[0] ^= 1;
    assert_eq!(mpt::verify_account(&bad_root, &address, &refs).err(), Some(mpt::Error::HashMismatch));
    let mut tampered = account_proof.clone();
    let last = tampered.len() - 1;
    tampered[last][5] ^= 1;
    let t: Vec<&[u8]> = tampered.iter().map(|p| p.as_slice()).collect();
    assert!(mpt::verify_account(&root, &address, &t).is_err());
    assert!(mpt::verify_account(&root, &address, &refs[..refs.len() - 1]).is_err());
    let mut extra = refs.clone();
    extra.push(refs[0]);
    assert_eq!(mpt::verify_account(&root, &address, &extra).err(), Some(mpt::Error::UnusedProofNodes));
}

#[test]
fn bsc_rlp_is_canonical() {
    assert_eq!(rlp::decode_exact(&[0x81, 0x05]).err(), Some(rlp::Error::NonCanonical));
    assert_eq!(rlp::decode_exact(&[0xb8, 0x01, 0xff]).err(), Some(rlp::Error::NonCanonical));
    assert_eq!(rlp::decode_exact(&[0x82, 0x00, 0x01]).unwrap().u64().err(), Some(rlp::Error::NonCanonical));
    assert_eq!(rlp::decode_exact(&[0x83, 0x01]).err(), Some(rlp::Error::Truncated));
    assert_eq!(rlp::decode_exact(&[0x01, 0x02]).err(), Some(rlp::Error::TrailingBytes));
    let mut out = Vec::new();
    rlp::encode_u64(&mut out, 0);
    rlp::encode_u64(&mut out, 1024);
    assert_eq!(out, [0x80, 0x82, 0x04, 0x00]);
    assert_eq!(keccak256(b""), h32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
}



