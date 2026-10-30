//! Pins the exact output of `apply_entry` (roots, receipts, muts, muts_rev and
//! the committed state) for fixed blocks. Execution-layer refactors must leave
//! every byte unchanged; a changed digest here is a consensus fork.

#![cfg(test)]

use crate::bcat;
use crate::consensus::consensus_apply::{apply_entry, make_apply_env};
use crate::consensus::consensus_muts::Mutation;
use crate::consensus::hbsmt_common::Op;
use crate::consensus::tests::chain_harness::{new_wallet, Chain, Wallet};
use crate::model::entry::{Entry, Header};
use crate::model::tx::{Action, TX, TXU};

const HEIGHT: u64 = 90_000_123;

fn txu(signer: &Wallet, nonce: u64, contract: &[u8], function: &[u8], args: Vec<Vec<u8>>) -> TXU {
    txu_attached(signer, nonce, contract, function, args, None)
}

fn txu_attached(signer: &Wallet, nonce: u64, contract: &[u8], function: &[u8], args: Vec<Vec<u8>>, attached: Option<(&[u8], i128)>) -> TXU {
    let hash = blake3::hash(&bcat(&[&signer.pk, &nonce.to_be_bytes(), contract, function])).as_bytes().to_vec();
    TXU {
        hash,
        signature: vec![0u8; 96],
        tx: TX {
            signer: signer.pk.to_vec(),
            nonce,
            action: Action {
                op: b"call".to_vec(),
                contract: contract.to_vec(),
                function: function.to_vec(),
                args,
                attached_symbol: attached.map(|(sym, _)| sym.to_vec()),
                attached_amount: attached.map(|(_, amt)| amt.to_string().into_bytes()),
                attached_gas: None,
            },
        },
    }
}

fn entry(height: u64, signer: &Wallet, txs: Vec<TXU>) -> Entry {
    Entry {
        hash: blake3::hash(&height.to_be_bytes()).as_bytes().to_vec(),
        signature: vec![0u8; 96],
        header: Header {
            prev_hash: blake3::hash(&(height - 1).to_be_bytes()).as_bytes().to_vec(),
            height,
            slot: height,
            prev_slot: height - 1,
            signer: signer.pk.to_vec(),
            dr: vec![7u8; 32],
            vr: vec![9u8; 96],
            root_tx: vec![0u8; 32],
        },
        txs,
        mask: None,
        mask_active: None,
    }
}

fn wallet_from(seed: u8) -> Wallet {
    //deterministic keys: the digest covers balances keyed by pk
    let mut sk = [0u8; 64];
    sk[..32].copy_from_slice(blake3::hash(&[seed]).as_bytes());
    let pk = crate::consensus::bls12_381::get_public_key(&sk).unwrap();
    Wallet { sk, pk }
}

fn sol_bytes(epoch: u64, pk: &[u8; 48], salt: u8) -> Vec<u8> {
    let mut sol = vec![salt; crate::consensus::bic::sol::SOL_SIZE];
    sol[0..4].copy_from_slice(&(epoch as u32).to_le_bytes());
    sol[36..84].copy_from_slice(pk);
    sol
}

fn hash_muts(h: &mut blake3::Hasher, muts: &[Mutation]) {
    h.update(&(muts.len() as u64).to_be_bytes());
    for m in muts {
        h.update(format!("{:?}", m).as_bytes());
    }
}

fn state_digest(chain: &Chain, cf: &str) -> [u8; 32] {
    let cf = chain.db.cf_handle(cf).unwrap();
    let mut iter = chain.db.raw_iterator_cf(&cf);
    let mut h = blake3::Hasher::new();
    iter.seek_to_first();
    while iter.valid() {
        h.update(&(iter.key().unwrap().len() as u64).to_be_bytes());
        h.update(iter.key().unwrap());
        h.update(&(iter.value().unwrap().len() as u64).to_be_bytes());
        h.update(iter.value().unwrap());
        iter.next();
    }
    *h.finalize().as_bytes()
}

fn apply(chain: &Chain, e: Entry, h: &mut blake3::Hasher) {
    apply_net(chain, e, h, false)
}

fn apply_net(chain: &Chain, e: Entry, h: &mut blake3::Hasher, testnet: bool) {
    let txn = chain.db.transaction();
    let (txn, muts, muts_rev, receipts, root_receipts, root_contractstate) = apply_entry(chain.db, txn, e, &[0u8; 48], &[0u8; 64], testnet);
    txn.commit().unwrap();
    h.update(&root_receipts);
    h.update(&root_contractstate);
    hash_muts(h, &muts);
    hash_muts(h, &muts_rev);
    for r in &receipts {
        h.update(format!("{:?}|{:?}|{:?}|{:?}|{:?}", r.txid, r.success, r.result, r.exec_used, r.logs).as_bytes());
    }
    h.update(&state_digest(chain, "contractstate"));
    h.update(&state_digest(chain, "contractstate_tree_hbsmt"));
}

//seed the tree with the genesis state so the root covers it
fn seed_tree(chain: &Chain) {
    let cf = chain.db.cf_handle("contractstate").unwrap();
    let mut ops = Vec::new();
    let mut iter = chain.db.raw_iterator_cf(&cf);
    iter.seek_to_first();
    while iter.valid() {
        let k = iter.key().unwrap().to_vec();
        ops.push(Op::Insert(crate::consensus::consensus_kv::contractstate_namespace(&k), k, iter.value().unwrap().to_vec()));
        iter.next();
    }
    let mut env = make_apply_env(
        chain.db, chain.db.transaction(), chain.db.cf_handle("contractstate").unwrap(), b"contractstate".to_vec(),
        chain.db.cf_handle("contractstate").unwrap(), chain.db.cf_handle("contractstate_tree_hbsmt").unwrap(),
        &[0u8; 48], &[0u8; 32], HEIGHT - 1, HEIGHT - 2, HEIGHT - 1, (HEIGHT - 1) / 100_000, &[0u8; 96], &[0u8; 32], &[0u8; 32], false,
    );
    crate::consensus::hbsmt_rdb::hbsmt_batch_update_env(&mut env, "contractstate_tree_hbsmt", ops);
    env.txn.commit().unwrap();
}

fn run_blocks() -> [u8; 32] {
    let chain = Chain::new();
    let producer = wallet_from(1);
    let alice = wallet_from(2);
    let bob = wallet_from(3);
    let carol = wallet_from(4);
    let ama = 1_000_000_000_000_000i128;
    for w in [&alice, &bob, &carol] {
        chain.fund(&w.pk, 50 * ama);
    }
    chain.put(b"bic:epoch:segment_vr_hash", &[5u8; 32]);
    chain.put(b"bic:epoch:diff_bits", b"24");

    seed_tree(&chain);

    let epoch = HEIGHT / 100_000;
    let transfer = |to: &Wallet, amt: i128| vec![to.pk.to_vec(), amt.to_string().into_bytes(), b"AMA".to_vec()];
    let mut h = blake3::Hasher::new();

    //block 1: transfers (one creating a new account), a same-signer sequence,
    //a failing transfer (revert), sols that set bloom bits then fail (revert),
    //a duplicate sol, and an unknown contract call
    let dave = new_wallet_det(5);
    apply(&chain, entry(HEIGHT, &producer, vec![
        txu(&alice, 1, b"Coin", b"transfer", transfer(&bob, 3 * ama)),
        txu(&alice, 2, b"Coin", b"transfer", transfer(&dave, 1 * ama)),
        txu(&bob, 1, b"Coin", b"transfer", transfer(&carol, 1_000 * ama)),
        txu(&carol, 1, b"Epoch", b"submit_sol", vec![sol_bytes(epoch, &carol.pk, 1)]),
        txu(&carol, 2, b"Epoch", b"submit_sol", vec![sol_bytes(epoch, &carol.pk, 1)]),
        txu(&carol, 3, b"Epoch", b"submit_sol", vec![sol_bytes(epoch + 1, &carol.pk, 2)]),
        txu(&bob, 2, b"Nope", b"nothing", vec![]),
        txu(&carol, 4, b"Coin", b"transfer", transfer(&alice, 7 * ama)),
    ]), &mut h);

    //block 2: builds on block 1's state, including the producer's own fee income
    apply(&chain, entry(HEIGHT + 1, &producer, vec![
        txu(&dave, 1, b"Coin", b"transfer", transfer(&alice, ama / 2)),
        txu(&bob, 3, b"Coin", b"transfer", transfer(&dave, 2 * ama)),
        txu(&alice, 3, b"Coin", b"transfer", transfer(&bob, 0)),
    ]), &mut h);

    *h.finalize().as_bytes()
}

//module exporting run() with an empty body
const WASM_RUN_EMPTY: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
    0x07, 0x07, 0x01, 0x03, b'r', b'u', b'n', 0x00, 0x00, 0x0a, 0x04, 0x01, 0x02, 0x00, 0x0b,
];

//module exporting run() that loops forever
const WASM_RUN_LOOP: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
    0x07, 0x07, 0x01, 0x03, b'r', b'u', b'n', 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b,
];

fn run_blocks_extended() -> [u8; 32] {
    let chain = Chain::new();
    let producer = wallet_from(11);
    let alice = wallet_from(12);
    let bob = wallet_from(13);
    let wasm_ok = wallet_from(14);
    let wasm_loop = wallet_from(15);
    let ama = 1_000_000_000_000_000i128;
    for w in [&alice, &bob] {
        chain.fund(&w.pk, 50 * ama);
    }
    chain.put(b"bic:epoch:segment_vr_hash", &[5u8; 32]);
    chain.put(b"bic:epoch:diff_bits", b"24");
    chain.put(&bcat(&[b"account:", &wasm_ok.pk, b":attribute:bytecode"]), WASM_RUN_EMPTY);
    chain.put(&bcat(&[b"account:", &wasm_loop.pk, b":attribute:bytecode"]), WASM_RUN_LOOP);

    //bloom pages the failing sol touches already exist, one with a bit preset,
    //so its revert clears bits on existing pages
    let epoch = HEIGHT / 100_000;
    let sol = sol_bytes(epoch, &alice.pk, 3);
    let segs = crate::consensus::bic::sol_bloom::segs_from_digest(blake3::hash(&sol).as_bytes());
    for (i, seg) in segs.iter().enumerate() {
        let mut page = vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize];
        let neighbour = (seg.bit_offset as usize / 8 + 1) % page.len();
        page[neighbour] = 0xa5;
        if i == 0 {
            page[seg.bit_offset as usize / 8] |= 1u8 << (7 - (seg.bit_offset % 8) as u8);
        }
        chain.put(format!("bic:epoch:solbloom:{}", seg.page).as_bytes(), &page);
    }
    seed_tree(&chain);

    let transfer = |to: &Wallet, amt: i128| vec![to.pk.to_vec(), amt.to_string().into_bytes(), b"AMA".to_vec()];
    let mut h = blake3::Hasher::new();

    apply(&chain, entry(HEIGHT, &producer, vec![
        txu(&alice, 1, b"Epoch", b"submit_sol", vec![sol.clone()]),
        txu_attached(&alice, 2, &wasm_ok.pk, b"run", vec![], Some((b"AMA", 5))),
        txu_attached(&bob, 1, &wasm_loop.pk, b"run", vec![], Some((b"AMA", 7))),
        txu(&bob, 2, b"Coin", b"transfer", transfer(&alice, ama)),
        txu(&alice, 3, b"Coin", b"transfer", transfer(&bob, 10_000 * ama)),
    ]), &mut h);

    apply(&chain, entry(HEIGHT + 1, &producer, vec![]), &mut h);

    //wasm only executes on testnet: a call that runs, and one that loops until
    //its exec budget is gone after the attachment's balance writes
    apply_net(&chain, entry(HEIGHT + 2, &producer, vec![
        txu_attached(&alice, 5, &wasm_ok.pk, b"run", vec![], Some((b"AMA", 5))),
        txu_attached(&bob, 5, &wasm_loop.pk, b"run", vec![], Some((b"AMA", 7))),
        txu(&bob, 6, b"Coin", b"transfer", transfer(&alice, ama)),
    ]), &mut h, true);

    let segment_height = (HEIGHT / 1000 + 1) * 1000;
    apply(&chain, entry(segment_height, &producer, vec![
        txu(&bob, 7, b"Coin", b"transfer", transfer(&alice, ama)),
    ]), &mut h);

    let epoch_last = (HEIGHT / 100_000 + 1) * 100_000 - 1;
    apply(&chain, entry(epoch_last, &producer, vec![
        txu(&alice, 6, b"Coin", b"transfer", transfer(&bob, 2 * ama)),
        txu(&bob, 8, b"Coin", b"transfer", transfer(&alice, 0)),
    ]), &mut h);

    *h.finalize().as_bytes()
}

fn new_wallet_det(seed: u8) -> Wallet {
    let _ = new_wallet;
    wallet_from(seed)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

//apply_entry installs a silent panic hook, so report panics by payload
fn run_reporting(run: fn() -> [u8; 32]) -> [u8; 32] {
    let res = std::panic::catch_unwind(run);
    //take_hook resets the global hook to the default printer
    let _ = std::panic::take_hook();
    match res {
        Ok(digest) => digest,
        Err(payload) => {
            let msg = payload.downcast_ref::<&str>().map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            panic!("run_blocks panicked: {}", msg)
        }
    }
}

#[test]
fn apply_entry_output_is_pinned() {
    let a = run_reporting(run_blocks);
    //deterministic across runs (fresh db, same inputs)
    assert_eq!(a, run_reporting(run_blocks));
    assert_eq!(hex(&a), GOLDEN, "apply_entry output changed");
}

#[test]
fn apply_entry_output_is_pinned_extended() {
    let a = run_reporting(run_blocks_extended);
    assert_eq!(a, run_reporting(run_blocks_extended));
    assert_eq!(hex(&a), GOLDEN_EXTENDED, "apply_entry output changed");
}

const GOLDEN: &str = "060254327e907419385e434f9367378d37a4651a4dbe841f2f0c8fe9d14f46f1";
const GOLDEN_EXTENDED: &str = "1fde8ae4be5163ca0979769e2775099fe04c914a56eead4ad979b160011be146";
