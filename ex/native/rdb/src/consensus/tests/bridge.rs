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
    //the first call plants the baked Chapel trust header, under a tx's exec cap, and does nothing else
    chain.call_metered(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &source]).unwrap();
    assert!(chain.get(b"bic:bridge:bsc:set").is_some());
    assert!(chain.get(format!("bic:bridge:bsc-testnet:root:{:020}", v::SOURCE_NUMBER).as_bytes()).is_none());
    //these mainnet votes are for blocks before it
    assert_eq!(chain.call_metered(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &source]), Err("bridge_target_before_set".into()));
    chain.with_env(&w.pk, |env| bridge::init_bsc(env, &hex(v::EPOCH1_RAW)));
    assert_eq!(chain.call_metered(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &hex(v::EPOCH0_RAW)]), Err("bridge_wrong_source_header".into()));
    let sig = crate::consensus::bridge::bsc::header::attestation(&crate::consensus::bridge::bsc::header::parse(&latest).unwrap()).unwrap().unwrap().agg_sig;
    let i = latest.windows(96).position(|w| w == sig).unwrap();
    let mut forged = latest.clone();
    forged[i + 50] ^= 1;
    assert!(chain.call_metered(&w, b"Bridge", b"update", &[b"bsc-testnet", &forged, &source]).is_err());
    chain.call_metered(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &source]).unwrap();
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
    bsc_state_with_word(&bridge::BSC_TESTNET.contract, &slot, &keccak256(packed))
}

//one account holding one storage word at keccak(slot_preimage)
fn bsc_state_with_word(address: &[u8; 20], slot_preimage: &[u8], value: &[u8]) -> ([u8; 32], Vec<u8>, Vec<u8>) {
    let mut word = Vec::new();
    rlp::encode_bytes(&mut word, value);
    let storage_leaf = leaf(&keccak256(&keccak256(slot_preimage)), &word);
    let mut account = Vec::new();
    rlp::encode_u64(&mut account, 1);
    rlp::encode_bytes(&mut account, &[]);
    rlp::encode_bytes(&mut account, &keccak256(&storage_leaf));
    rlp::encode_bytes(&mut account, &[0u8; 32]);
    let mut account_rlp = Vec::new();
    rlp::encode_list(&mut account_rlp, &account);
    let account_leaf = leaf(&keccak256(address), &account_rlp);
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
fn bridge_bsc_votes_stay_between_the_set_epoch_and_its_trust_period() {
    use super::bsc_testnet_vectors as t;
    use crate::consensus::bridge::bsc::{finality, header};
    let chain = Chain::new();
    let w = chain.wallet(AMA);
    let (latest, source, epoch1) = (hex(t::LATEST_RAW), hex(t::SOURCE_RAW), hex(t::EPOCH1_RAW));
    let target = header::attestation(&header::parse(&latest).unwrap()).unwrap().unwrap().data.target_number;
    let (vals, turn) = header::epoch_validators(&header::parse(&epoch1).unwrap()).unwrap();
    let signing = finality::ValidatorSet::new(vals, turn).unwrap();
    let update = || chain.call_metered(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &source]);

    put_bsc_set(&chain, target - bridge::BSC_TRUST_PERIOD_BLOCKS - 1, &signing);
    assert_eq!(update(), Err("bridge_trust_period_expired".into()));
    //a set never vouches for blocks before it was announced (votes BSC may no longer slash)
    put_bsc_set(&chain, target, &signing);
    assert_eq!(update(), Err("bridge_target_before_set".into()));
    put_bsc_set(&chain, target - bridge::BSC_TRUST_PERIOD_BLOCKS, &signing);
    update().unwrap();
    let root = chain.get(format!("bic:bridge:bsc-testnet:root:{:020}", t::SOURCE_NUMBER).as_bytes()).unwrap();
    assert_eq!(root, header::parse(&source).unwrap().state_root);
    assert_eq!(chain.call_metered(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, &source, &epoch1, b""]), Err("invalid_args".into()));
}

#[test]
fn bridge_bsc_catches_up_with_two_thirds_of_the_trusted_set_and_known_keys() {
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
    let know = |s: &finality::ValidatorSet| for v in &s.validators { chain.put(&bcat(&[b"bic:bridge:bsc:vote_key:", &v.vote_key]), b""); };

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
        chain.call_metered(&w, b"Bridge", b"update", &args)
    };

    //every signer is a known key, but one too many of them are new to the trusted set
    know(&signing);
    put_bsc_set(&chain, t::EPOCH1_NUMBER, &trusted_with(signers.len() - quorum + 1));
    assert_eq!(update(None), Err("bridge_invalid_attestation".into())); //stale set: no direct path
    assert_eq!(update(Some(&epoch1)), Err("bridge_not_enough_trusted_signers".into()));

    put_bsc_set(&chain, t::EPOCH1_NUMBER - 100_000, &trusted_with(signers.len() - quorum));
    update(Some(&epoch1)).unwrap(); //exactly 2/3 of the trusted set signed, epochs skipped
    let root = chain.get(format!("bic:bridge:bsc-testnet:root:{:020}", t::SOURCE_NUMBER).as_bytes()).unwrap();
    assert_eq!(root, header::parse(&source).unwrap().state_root);

    //a signing header listing a key Amadeus never adopted is refused: an aggregate over unvetted
    //keys could cancel the trusted ones out (rogue key) and be signed by anyone
    let fresh = Chain::new();
    let w2 = fresh.wallet(AMA);
    let mut rogue = epoch1.clone();
    let i = rogue.windows(48).position(|w| w == signing.validators[signers[0]].vote_key).unwrap();
    let key = crate::consensus::bls12_381::get_public_key(&crate::consensus::bls12_381::generate_sk()).unwrap();
    rogue[i..i + 48].copy_from_slice(&key);
    let mut b = t::EPOCH1_NUMBER.to_be_bytes().to_vec();
    b.push(signing.turn_length);
    for v in &signing.validators { b.extend_from_slice(&v.address); b.extend_from_slice(&v.vote_key); }
    fresh.put(b"bic:bridge:bsc:set", &b);
    let r = fresh.call_metered(&w2, b"Bridge", b"update", &[b"bsc-testnet", &latest, &source, &rogue]);
    assert!(matches!(&r, Err(e) if e == "bridge_unknown_vote_key"), "{r:?}");
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

#[test]
fn bridge_recipient_claims_its_own_order_without_paying_the_gas_drop() {
    let chain = Chain::new();
    let sender = chain.wallet(1_000 * AMA);
    send(&chain, &sender, 500 * AMA, &[7u8; 20]).unwrap();
    let recipient = chain.wallet(0);
    let amount = (10 * AMA) as u128;
    //a gas drop no deliverer would ever pay
    let o = Order { src_chain: chain_name(b"bsc-testnet").unwrap(), nonce: 1, sender: vec![5; 20], refund_to: vec![5; 20], src_coin: bridge::BSC_TESTNET_WAMA.to_vec(), amount,
                    dst_chain: chain_name(b"amadeus-testnet").unwrap(), dst_coin: b"AMA".to_vec(), recipient: recipient.pk.to_vec(),
                    output_amount: amount - AMA as u128, gas_drop_fee: AMA as u128, gas_drop: u128::MAX / 2, ..Default::default() };
    let (root, account_proof, storage_proof) = bsc_state_with_order(1, &o.pack());
    chain.put(&bcat(&[b"bic:bridge:bsc-testnet:root:", format!("{:020}", 100).as_bytes()]), &root);
    let receive = |w: &Wallet| chain.call(w, b"Bridge", b"receive", &[b"bsc-testnet", b"100", &o.pack(), &account_proof, &storage_proof]);
    assert!(receive(&sender).is_err()); //a deliverer must pay the drop
    receive(&recipient).unwrap();
    assert_eq!(chain.balance(&recipient.pk), 10 * AMA); //output plus the tip it delivered itself
}

#[test]
fn bridge_bsc_learns_a_vote_key_from_stake_hub() {
    let chain = Chain::new();
    let w = chain.wallet(AMA);
    let key = crate::consensus::bls12_381::get_public_key(&crate::consensus::bls12_381::generate_sk()).unwrap();
    let stake_hub = { let mut a = [0u8; 20]; a[18] = 0x20; a[19] = 0x02; a };
    let mut slot = key.to_vec();
    slot.extend_from_slice(&[0u8; 24]);
    slot.extend_from_slice(&69u64.to_be_bytes());
    let operator = [0x77u8; 20];
    let (root, account_proof, storage_proof) = bsc_state_with_word(&stake_hub, &slot, &operator);
    let learn = |h: &[u8], k: &[u8], a: &[u8], s: &[u8]| chain.call_metered(&w, b"Bridge", b"vote_key", &[b"bsc-testnet", h, k, a, s]);

    assert_eq!(learn(b"100", &key, &account_proof, &storage_proof), Err("bridge_unknown_root".into()));
    chain.put(&bcat(&[b"bic:bridge:bsc-testnet:root:", format!("{:020}", 100).as_bytes()]), &root);
    learn(b"100", &key, &account_proof, &storage_proof).unwrap();
    assert!(chain.get(&bcat(&[b"bic:bridge:bsc:vote_key:", &key])).is_some());

    //a key StakeHub never registered: its slot is absent, which the proof shows
    let unregistered = crate::consensus::bls12_381::get_public_key(&crate::consensus::bls12_381::generate_sk()).unwrap();
    assert_eq!(learn(b"100", &unregistered, &account_proof, &storage_proof), Err("bridge_vote_key_not_registered".into()));
    assert!(chain.get(&bcat(&[b"bic:bridge:bsc:vote_key:", &unregistered])).is_none());
}

#[test]
fn bridge_receive_refunds_an_order_whose_recipient_is_not_a_key() {
    let chain = Chain::new();
    let sender = chain.wallet(1_000 * AMA);
    send(&chain, &sender, 500 * AMA, &[7u8; 20]).unwrap();
    let (escrow, burned) = (chain.balance(&ESCROW), chain.balance(&BURN_ADDRESS));
    let relay = chain.wallet(AMA);
    let amount = (100 * AMA) as u128;
    let tip = AMA as u128;
    //BSC only checks the compression flag: this passes there but is no point on the curve
    let mut bad_key = vec![0x80u8; 48];
    bad_key[47] = 0x01;
    let o = Order { src_chain: chain_name(b"bsc-testnet").unwrap(), nonce: 9, sender: vec![5; 20], refund_to: vec![6; 20], src_coin: bridge::BSC_TESTNET_WAMA.to_vec(), amount,
                    dst_chain: chain_name(b"amadeus-testnet").unwrap(), dst_coin: b"AMA".to_vec(), recipient: bad_key,
                    output_amount: amount - tip, gas_drop_fee: tip, ..Default::default() };
    let (root, account_proof, storage_proof) = bsc_state_with_order(9, &o.pack());
    chain.put(&bcat(&[b"bic:bridge:bsc-testnet:root:", format!("{:020}", 100).as_bytes()]), &root);
    let relay_before = chain.balance(&relay.pk);
    //the refund is an outbound order: it waits while that route is paused
    chain.call_as(&bridge::ADMIN, b"Bridge", b"pause", &[b"ama-to-bsc", b"true"]).unwrap();
    assert_eq!(chain.call(&relay, b"Bridge", b"receive", &[b"bsc-testnet", b"100", &o.pack(), &account_proof, &storage_proof]), Err("bridge_route_paused".into()));
    chain.call_as(&bridge::ADMIN, b"Bridge", b"pause", &[b"ama-to-bsc", b"false"]).unwrap();
    chain.call(&relay, b"Bridge", b"receive", &[b"bsc-testnet", b"100", &o.pack(), &account_proof, &storage_proof]).unwrap();
    assert_eq!(chain.balance(&relay.pk) - relay_before, AMA); //the deliverer still earns the tip
    //received per bridge contract
    let contract: String = bridge::BSC_TESTNET.contract.iter().map(|b| format!("{:02x}", b)).collect();
    assert!(chain.get(format!("bic:bridge:received:bsc-testnet:{contract}:{:020}", 9).as_bytes()).is_some());

    let back_amount = amount - tip;
    let fee = back_amount / 100_000;
    let back = order(&chain, 2);
    assert_eq!((back.recipient, back.amount, back.output_amount, back.dst_chain), (vec![6; 20], back_amount, back_amount - fee, chain_name(b"bsc-testnet").unwrap()));
    assert_eq!(back.dst_coin, bridge::BSC_TESTNET_WAMA.to_vec());
    //escrow keeps backing exactly what BSC mints for the refund
    assert_eq!(chain.balance(&ESCROW), escrow - (tip + fee) as i128);
    assert_eq!(chain.balance(&BURN_ADDRESS), burned + fee as i128);
    assert_eq!(chain.call(&relay, b"Bridge", b"receive", &[b"bsc-testnet", b"100", &o.pack(), &account_proof, &storage_proof]), Err("bridge_already_received".into()));
}

#[test]
fn bridge_bsc_adopts_an_epoch_block_final_only_through_its_descendants() {
    use super::bsc_testnet_vectors as t;
    use crate::consensus::bridge::bsc::{finality, header};
    let chain = Chain::new();
    let w = chain.wallet(AMA);
    let latest = hex(t::LATEST_RAW);
    //EPOCH1 .. SOURCE: no vote finalizes EPOCH1 itself here, the one finalizing SOURCE covers it
    let ancestry: Vec<Vec<u8>> = include_str!("bsc_testnet_ancestry.hex").split_whitespace().map(hex).collect();
    let (vals, turn) = header::epoch_validators(&header::parse(&ancestry[0]).unwrap()).unwrap();
    let signing = finality::ValidatorSet::new(vals, turn).unwrap();
    //the set signing SOURCE's vote, stored as if announced at the previous epoch block
    put_bsc_set(&chain, t::EPOCH0_NUMBER, &signing);
    let update = |src: &[u8]| chain.call_metered(&w, b"Bridge", b"update", &[b"bsc-testnet", &latest, src]);

    let mut gap = ancestry.clone();
    gap.remove(70);
    assert_eq!(update(&proof_arg(&gap)), Err("bridge_invalid_ancestry".into()));
    assert_eq!(update(&proof_arg(&ancestry[..139])), Err("bridge_wrong_source_header".into()));
    update(&proof_arg(&ancestry)).unwrap();
    for (i, n) in [(0, t::EPOCH1_NUMBER), (139, t::SOURCE_NUMBER)] {
        let root = chain.get(format!("bic:bridge:bsc-testnet:root:{:020}", n).as_bytes()).unwrap();
        assert_eq!(root, header::parse(&ancestry[i]).unwrap().state_root);
    }
    let next = chain.get(b"bic:bridge:bsc:next").unwrap();
    assert_eq!(u64::from_be_bytes(next[..8].try_into().unwrap()), t::EPOCH1_NUMBER);
}

#[test]
fn bridge_bsc_adopts_a_set_from_seals_of_a_majority_of_the_trusted_set() {
    use super::bsc_testnet_vectors as t;
    use crate::consensus::bridge::bsc::{finality, header};
    let chain = Chain::new();
    let w = chain.wallet(AMA);
    let ancestry: Vec<Vec<u8>> = include_str!("bsc_testnet_ancestry.hex").split_whitespace().map(hex).collect();
    //every header was sealed by a validator of the set signing at that height
    let (vals, turn) = header::epoch_validators(&header::parse(&ancestry[0]).unwrap()).unwrap();
    let set = finality::ValidatorSet::new(vals, turn).unwrap();
    let mut sealers: Vec<[u8; 20]> = ancestry.iter().map(|r| header::sealer(r, 97).unwrap()).collect();
    sealers.sort();
    sealers.dedup();
    assert!(sealers.iter().all(|a| set.validators.iter().any(|v| v.address == *a)));
    let n = set.validators.len();
    assert_eq!(sealers.len(), n);
    assert_ne!(header::sealer(&ancestry[5], 56).unwrap(), header::sealer(&ancestry[5], 97).unwrap()); //chain id is sealed in

    //a trusted set where `replaced` validators are strangers who sealed nothing
    let trusted_with = |replaced: usize| {
        let mut s = set.clone();
        for (i, v) in s.validators.iter_mut().take(replaced).enumerate() { v.address = [0xee, i as u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; }
        finality::ValidatorSet::new(s.validators, turn).unwrap()
    };
    let seal = |cand: &[u8], hs: &[Vec<u8>]| chain.call_metered(&w, b"Bridge", b"seal_update", &[b"bsc-testnet", cand, &proof_arg(hs)]);
    let e_hash = header::parse(&ancestry[0]).unwrap().hash;
    //in parts of 30 headers, each within a tx's exec cap; true once the set was adopted
    let seal_all = |hs: &[Vec<u8>]| -> Result<bool, String> {
        for (i, part) in hs.chunks(30).enumerate() {
            seal(if i == 0 { &[] } else { &e_hash }, part)?;
            if chain.get(b"bic:bridge:bsc:next").is_some() { return Ok(true) }
        }
        Ok(false)
    };

    put_bsc_set(&chain, t::EPOCH0_NUMBER, &trusted_with(n - n / 2)); //n/2 of n sealed: not more than half
    assert_eq!(seal_all(&ancestry), Ok(false));
    assert_eq!(seal(&[], &ancestry[1..31]), Err("bridge_no_epoch_block".into()));
    assert_eq!(seal(&e_hash, &ancestry[100..110]), Err("bridge_invalid_ancestry".into())); //must continue from its last header

    let chain2 = Chain::new();
    let w2 = chain2.wallet(AMA);
    let seal2 = |cand: &[u8], hs: &[Vec<u8>]| chain2.call_metered(&w2, b"Bridge", b"seal_update", &[b"bsc-testnet", cand, &proof_arg(hs)]);
    put_bsc_set(&chain2, t::EPOCH0_NUMBER, &trusted_with(n - n / 2 - 1)); //n/2 + 1 sealed
    assert_eq!(seal2(&[], &ancestry[..60]), Err("exec_insufficient_exec_budget".into())); //too many seals for one tx

    //someone appends a fabricated child (another state root, still linked to E): it spoils only their candidate
    let griefer = chain2.wallet(AMA);
    let mut fake = ancestry[1].clone();
    let root = header::parse(&fake).unwrap().state_root;
    let i = fake.windows(32).position(|w| w == root).unwrap();
    fake[i] ^= 1;
    chain2.call_metered(&griefer, b"Bridge", b"seal_update", &[b"bsc-testnet", &[], &proof_arg(&[ancestry[0].clone(), fake])]).unwrap();
    assert_eq!(chain2.call_metered(&griefer, b"Bridge", b"seal_update", &[b"bsc-testnet", &e_hash, &proof_arg(&ancestry[2..10])]), Err("bridge_invalid_ancestry".into()));
    let mut adopted = false;
    for (i, part) in ancestry.chunks(30).enumerate() {
        seal2(if i == 0 { &[] } else { &e_hash }, part).unwrap();
        if chain2.get(b"bic:bridge:bsc:next").is_some() { adopted = true; break }
    }
    assert!(adopted);
    let next = chain2.get(b"bic:bridge:bsc:next").unwrap();
    assert_eq!(u64::from_be_bytes(next[..8].try_into().unwrap()), t::EPOCH1_NUMBER);
    assert!(chain2.get(&bcat(&[b"bic:bridge:bsc:seal:", &e_hash, b":", &w2.pk])).is_none());
    assert!(chain2.get(format!("bic:bridge:bsc-testnet:root:{:020}", t::SOURCE_NUMBER).as_bytes()).is_none()); //no roots from seals
}
