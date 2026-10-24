use super::bsc_vectors as v;
use super::chain_harness::{Chain, Wallet};
use crate::bcat;
use crate::consensus::bic::bridge::{self, ESCROW};
use crate::consensus::bic::coin::BURN_ADDRESS;
use crate::consensus::bridge::bsc::{keccak256, rlp};
use crate::consensus::bridge::order::{chain_name, Order};

const AMA: i128 = 1_000_000_000;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn send(chain: &Chain, w: &Wallet, amount: i128, recipient: &[u8]) -> Result<(), String> {
    chain.call(w, b"Bridge", b"send", &[b"AMA", amount.to_string().as_bytes(), b"bsc-testnet", &bridge::BSC_TESTNET_WAMA, recipient, b"", b"0"])
}

fn order(chain: &Chain, nonce: u64) -> Order {
    Order::unpack(&chain.get(format!("bic:bridge:order:{:020}", nonce).as_bytes()).unwrap()).unwrap()
}

#[test]
fn bridge_order_packs_and_names_chains() {
    let o = Order { src_chain: chain_name(b"amadeus").unwrap(), nonce: 7, sender: vec![1; 48], src_coin: b"AMA".to_vec(), amount: 5,
                    dst_chain: chain_name(b"bsc").unwrap(), recipient: vec![2; 20], output_amount: 5, message: vec![9], ..Default::default() };
    assert_eq!(Order::unpack(&o.pack()), Some(o.clone()));
    assert_eq!(Order::unpack(&[o.pack(), vec![0]].concat()), None);
    assert_eq!(&chain_name(b"bsc-testnet").unwrap()[..11], b"bsc-testnet");
    for bad in [&b""[..], b"BSC", b"b s c", &[b'a'; 33]] { assert_eq!(chain_name(bad), None); }
    assert!(!crate::consensus::bls12_381::validate_public_key(&ESCROW));
}

#[test]
fn bridge_send_locks_burns_fee_and_records_order() {
    let chain = Chain::new();
    let w = chain.wallet(1_000 * AMA);
    let recipient = [7u8; 20];
    send(&chain, &w, 100 * AMA, &recipient).unwrap();
    let fee = 100 * AMA / 100_000;
    assert_eq!(chain.balance(&w.pk), 900 * AMA);
    assert_eq!(chain.balance(&BURN_ADDRESS), fee);
    assert_eq!(chain.balance(&ESCROW), 100 * AMA - fee);
    let o = order(&chain, 1);
    assert_eq!((o.nonce, o.amount, o.output_amount), (1, (100 * AMA) as u128, (100 * AMA - fee) as u128));
    assert_eq!((o.src_chain, o.dst_chain), (chain_name(b"amadeus-testnet").unwrap(), chain_name(b"bsc-testnet").unwrap()));
    assert_eq!((o.sender.as_slice(), o.refund_to.as_slice(), o.recipient.as_slice()), (&w.pk[..], &w.pk[..], &recipient[..]));

    send(&chain, &w, 99_999, &recipient).unwrap();
    assert_eq!(order(&chain, 2).output_amount, 99_999); //below 100k base units: no fee

    assert_eq!(send(&chain, &w, 1_000 * AMA, &recipient), Err("insufficient_funds".into()));
    assert_eq!(send(&chain, &w, AMA, &[7u8; 48]), Err("bridge_invalid_address".into()));
    assert_eq!(chain.call(&w, b"Bridge", b"send", &[b"AMA", b"1", b"bsc-testnet", &[1u8; 20], &recipient, b"", b"0"]), Err("bridge_no_route".into()));
    assert_eq!(chain.call(&w, b"Bridge", b"send", &[b"AMA", b"1", b"BSC", &bridge::BSC_TESTNET_WAMA, &recipient, b"", b"0"]), Err("bridge_invalid_chain".into()));
}

#[test]
fn bridge_route_cap_and_admin_pause() {
    let mut chain = Chain::new();
    let w = chain.wallet(20_000_000 * AMA);
    send(&chain, &w, 10_000_000 * AMA, &[7u8; 20]).unwrap();
    assert_eq!(send(&chain, &w, 1, &[7u8; 20]), Err("bridge_route_cap_reached".into()));
    chain.advance_epochs(1);
    send(&chain, &w, AMA, &[7u8; 20]).unwrap();

    assert_eq!(chain.call(&w, b"Bridge", b"pause", &[b"ama-to-bsc", b"true"]), Err("no_permissions".into()));
    chain.call_as(&bridge::ADMIN, b"Bridge", b"pause", &[b"ama-to-bsc", b"true"]).unwrap();
    assert_eq!(send(&chain, &w, AMA, &[7u8; 20]), Err("bridge_route_paused".into()));
    chain.call_as(&bridge::ADMIN, b"Bridge", b"pause", &[b"ama-to-bsc", b"false"]).unwrap();
    send(&chain, &w, AMA, &[7u8; 20]).unwrap();
    assert_eq!(chain.call_as(&bridge::ADMIN, b"Bridge", b"pause", &[b"nope", b"true"]), Err("bridge_no_route".into()));
}

#[test]
fn bridge_bsc_update_stores_finalized_root() {
    let chain = Chain::new();
    let w = chain.wallet(AMA);
    let (latest, source) = (hex(v::LATEST_RAW), hex(v::SOURCE_RAW));
    //testnet starts from the baked Chapel trust header: mainnet votes do not verify against it
    assert_eq!(chain.call(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &source]), Err("bridge_invalid_attestation".into()));
    chain.with_env(&w.pk, |env| bridge::init_bsc(env, &hex(v::EPOCH1_RAW)));
    assert_eq!(chain.call(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &hex(v::EPOCH0_RAW)]), Err("bridge_wrong_source_header".into()));
    let sig = crate::consensus::bridge::bsc::header::attestation(&crate::consensus::bridge::bsc::header::parse(&latest).unwrap()).unwrap().unwrap().agg_sig;
    let i = latest.windows(96).position(|w| w == sig).unwrap();
    let mut forged = latest.clone();
    forged[i + 50] ^= 1;
    assert!(chain.call(&w, b"Bridge", b"update", &[b"bsc-testnet", &forged, &source]).is_err());
    chain.call(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &source]).unwrap();
    let root = chain.get(format!("bic:bridge:bsc-testnet:root:{:020}", v::SOURCE_NUMBER).as_bytes()).unwrap();
    assert_eq!(root, hex(v::SOURCE_STATE_ROOT));
}

//a one-leaf trie: root = keccak(rlp([hp(path), value]))
fn leaf(path: &[u8; 32], value: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    rlp::encode_bytes(&mut p, &[&[0x20u8][..], path].concat());
    rlp::encode_bytes(&mut p, value);
    let mut out = Vec::new();
    rlp::encode_list(&mut out, &p);
    out
}

fn proof_arg(nodes: &[Vec<u8>]) -> Vec<u8> {
    crate::consensus::bic::list_of_binaries_to_vecpak(nodes.to_vec())
}

//a BSC state root whose bridge contract has orders[nonce] = keccak(packed)
fn bsc_state_with_order(nonce: u64, packed: &[u8]) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let mut slot = [0u8; 64];
    slot[24..32].copy_from_slice(&nonce.to_be_bytes());
    let mut word = Vec::new();
    rlp::encode_bytes(&mut word, &keccak256(packed));
    let storage_leaf = leaf(&keccak256(&keccak256(&slot)), &word);
    let mut account = Vec::new();
    rlp::encode_u64(&mut account, 1);
    rlp::encode_bytes(&mut account, &[]);
    rlp::encode_bytes(&mut account, &keccak256(&storage_leaf));
    rlp::encode_bytes(&mut account, &[0u8; 32]);
    let mut account_rlp = Vec::new();
    rlp::encode_list(&mut account_rlp, &account);
    let account_leaf = leaf(&keccak256(&bridge::BSC_TESTNET.contract), &account_rlp);
    (keccak256(&account_leaf), proof_arg(&[account_leaf]), proof_arg(&[storage_leaf]))
}

#[test]
fn bridge_receive_releases_once_against_a_proven_order() {
    let chain = Chain::new();
    let sender = chain.wallet(1_000 * AMA);
    send(&chain, &sender, 500 * AMA, &[7u8; 20]).unwrap();
    let escrow = chain.balance(&ESCROW);
    let recipient = chain.wallet(0);

    let amount = (200 * AMA) as u128;
    let o = Order { src_chain: chain_name(b"bsc-testnet").unwrap(), nonce: 3, sender: vec![5; 20], refund_to: vec![5; 20], src_coin: bridge::BSC_TESTNET_WAMA.to_vec(), amount,
                    dst_chain: chain_name(b"amadeus-testnet").unwrap(), dst_coin: b"AMA".to_vec(), recipient: recipient.pk.to_vec(),
                    output_amount: amount, ..Default::default() }; //no fee on the BSC side
    let packed = o.pack();
    let (root, account_proof, storage_proof) = bsc_state_with_order(3, &packed);
    let receive = |packed: &[u8], height: &[u8]| chain.call(&sender, b"Bridge", b"receive", &[b"bsc-testnet", height, packed, &account_proof, &storage_proof]);

    assert_eq!(receive(&packed, b"100"), Err("bridge_unknown_root".into()));
    chain.put(&bcat(&[b"bic:bridge:bsc-testnet:root:", format!("{:020}", 100).as_bytes()]), &root);
    let mut tampered = o.clone();
    tampered.amount += 100_000;
    tampered.output_amount = tampered.amount;
    assert_eq!(receive(&tampered.pack(), b"100"), Err("bridge_order_not_found".into()));
    let mut bad_out = o.clone();
    bad_out.output_amount += 1;
    assert_eq!(receive(&bad_out.pack(), b"100"), Err("bridge_invalid_output_amount".into()));

    receive(&packed, b"100").unwrap();
    assert_eq!(chain.balance(&recipient.pk), o.output_amount as i128);
    assert_eq!(chain.balance(&ESCROW), escrow - o.output_amount as i128);
    assert_eq!(receive(&packed, b"100"), Err("bridge_already_received".into()));

    let mut big = o.clone();
    big.nonce = 4;
    big.amount = (10_000 * AMA) as u128;
    big.output_amount = big.amount;
    let (root, account_proof, storage_proof) = bsc_state_with_order(4, &big.pack());
    chain.put(&bcat(&[b"bic:bridge:bsc-testnet:root:", format!("{:020}", 101).as_bytes()]), &root);
    assert_eq!(chain.call(&sender, b"Bridge", b"receive", &[b"bsc-testnet", b"101", &big.pack(), &account_proof, &storage_proof]), Err("bridge_escrow_insufficient".into()));
}

//trusted set stored as the BIC keeps it: epoch u64 | turn u8 | n * (address 20 | vote key 48), sorted by address
fn put_bsc_set(chain: &Chain, epoch: u64, set: &crate::consensus::bridge::bsc::finality::ValidatorSet) {
    let mut b = epoch.to_be_bytes().to_vec();
    b.push(set.turn_length);
    for v in &set.validators { b.extend_from_slice(&v.address); b.extend_from_slice(&v.vote_key); }
    chain.put(b"bic:bridge:bsc:set", &b);
}

#[test]
fn bridge_bsc_skips_epochs_with_two_thirds_of_the_trusted_set() {
    use super::bsc_testnet_vectors as t;
    use crate::consensus::bridge::bsc::{finality, header};
    let chain = Chain::new();
    let w = chain.wallet(AMA);
    let (latest, source, epoch1) = (hex(t::LATEST_RAW), hex(t::SOURCE_RAW), hex(t::EPOCH1_RAW));
    let att = header::attestation(&header::parse(&latest).unwrap()).unwrap().unwrap();
    let (vals, turn) = header::epoch_validators(&header::parse(&epoch1).unwrap()).unwrap();
    let signing = finality::ValidatorSet::new(vals, turn).unwrap();
    let signers: Vec<usize> = (0..signing.validators.len()).filter(|i| att.vote_set >> i & 1 == 1).collect();
    let quorum = signing.quorum();

    //a trusted set where `replaced` of the actual signers were swapped for unrelated validators
    let trusted_with = |replaced: usize| {
        let mut t = signing.clone();
        for i in &signers[..replaced] {
            t.validators[*i].vote_key = crate::consensus::bls12_381::get_public_key(&crate::consensus::bls12_381::generate_sk()).unwrap();
        }
        finality::ValidatorSet::new(t.validators, turn).unwrap()
    };
    let update = |extra: Option<&[u8]>| {
        let mut args: Vec<&[u8]> = vec![b"bsc-testnet", &latest, &source];
        if let Some(e) = extra { args.push(e); }
        chain.call(&w, b"Bridge", b"update", &args)
    };

    put_bsc_set(&chain, t::EPOCH1_NUMBER, &trusted_with(signers.len() - quorum + 1));
    assert_eq!(update(None), Err("bridge_invalid_attestation".into())); //stale set: no direct path
    assert_eq!(update(Some(&epoch1)), Err("bridge_not_enough_trusted_signers".into()));

    put_bsc_set(&chain, t::EPOCH1_NUMBER - 2_000_000, &trusted_with(signers.len() - quorum));
    update(Some(&epoch1)).unwrap(); //exactly 2/3 of the trusted set signed, epochs skipped
    let root = chain.get(format!("bic:bridge:bsc-testnet:root:{:020}", t::SOURCE_NUMBER).as_bytes()).unwrap();
    assert_eq!(root, header::parse(&source).unwrap().state_root);

    put_bsc_set(&chain, t::EPOCH1_NUMBER - 3_000_000, &signing);
    assert_eq!(update(Some(&epoch1)), Err("bridge_trust_period_expired".into()));

    //the supplied signing header is never adopted: with a forged one the vote does not verify
    let mut forged = epoch1.clone();
    let i = forged.windows(48).position(|w| w == signing.validators[signers[0]].vote_key).unwrap();
    forged[i + 47] ^= 1;
    put_bsc_set(&chain, t::EPOCH1_NUMBER, &signing);
    assert!(update(Some(&forged)).is_err());
}

#[test]
fn bridge_send_with_gas_drop_pays_the_deliverer_out_of_the_order() {
    let chain = Chain::new();
    let w = chain.wallet(1_000 * AMA);
    let send9 = |amount: i128, drop: &str, tip: i128| chain.call(&w, b"Bridge", b"send",
        &[b"AMA", amount.to_string().as_bytes(), b"bsc-testnet", &bridge::BSC_TESTNET_WAMA, &[7u8; 20], b"", b"0", drop.as_bytes(), tip.to_string().as_bytes()]);
    send9(100 * AMA, "2000000000000000", 2 * AMA).unwrap();
    let fee = 100 * AMA / 100_000;
    let o = order(&chain, 1);
    assert_eq!((o.gas_drop, o.gas_drop_fee, o.output_amount), (2_000_000_000_000_000, (2 * AMA) as u128, (98 * AMA - fee) as u128));
    assert_eq!(chain.balance(&ESCROW), 100 * AMA - fee); //the tip is minted on BSC to the deliverer, so it stays locked
    assert_eq!(send9(AMA, "0", AMA), Err("bridge_gas_drop_fee_too_large".into()));
}

#[test]
fn bridge_receive_pays_the_tip_to_the_deliverer_and_forwards_the_gas_drop() {
    let chain = Chain::new();
    let sender = chain.wallet(1_000 * AMA);
    send(&chain, &sender, 500 * AMA, &[7u8; 20]).unwrap();
    let escrow = chain.balance(&ESCROW);
    let (recipient, relay) = (chain.wallet(0), chain.wallet(AMA));
    let amount = (200 * AMA) as u128;
    let o = Order { src_chain: chain_name(b"bsc-testnet").unwrap(), nonce: 1, sender: vec![5; 20], refund_to: vec![5; 20], src_coin: bridge::BSC_TESTNET_WAMA.to_vec(), amount,
                    dst_chain: chain_name(b"amadeus-testnet").unwrap(), dst_coin: b"AMA".to_vec(), recipient: recipient.pk.to_vec(),
                    output_amount: amount - AMA as u128, gas_drop_fee: AMA as u128, gas_drop: (AMA / 50) as u128, ..Default::default() };
    let (root, account_proof, storage_proof) = bsc_state_with_order(1, &o.pack());
    chain.put(&bcat(&[b"bic:bridge:bsc-testnet:root:", format!("{:020}", 100).as_bytes()]), &root);
    let relay_before = chain.balance(&relay.pk);
    chain.call(&relay, b"Bridge", b"receive", &[b"bsc-testnet", b"100", &o.pack(), &account_proof, &storage_proof]).unwrap();
    assert_eq!(chain.balance(&recipient.pk), 199 * AMA + AMA / 50);
    assert_eq!(chain.balance(&ESCROW), escrow - 200 * AMA);
    let relay_gain = chain.balance(&relay.pk) - relay_before;
    assert_eq!(relay_gain, AMA - AMA / 50); //the tip minus the drop it handed over

    let mut bad = o.clone();
    bad.nonce = 2;
    bad.output_amount = amount;
    let (root, account_proof, storage_proof) = bsc_state_with_order(2, &bad.pack());
    chain.put(&bcat(&[b"bic:bridge:bsc-testnet:root:", format!("{:020}", 101).as_bytes()]), &root);
    assert_eq!(chain.call(&relay, b"Bridge", b"receive", &[b"bsc-testnet", b"101", &bad.pack(), &account_proof, &storage_proof]), Err("bridge_invalid_output_amount".into()));
}
