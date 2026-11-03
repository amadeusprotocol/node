#![cfg(test)]

use crate::bcat;
use crate::consensus::consensus_apply::{apply_entry_mode, SPECULATIVE_BUDGET_BYTES};
use crate::consensus::tests::apply_golden::{entry, hash_muts, seed_tree, state_digest, txu, txu_attached, wallet_from, HEIGHT};
use crate::consensus::tests::riscv_contracts::{COUNTER, EMPTY, KITCHEN, SPIN};
use crate::consensus::tests::chain_harness::{Chain, Wallet};
use crate::model::entry::Entry;
use crate::model::tx::TXU;
use std::collections::HashMap;

const AMA: i128 = 1_000_000_000_000_000;

struct World {
    w: Vec<Wallet>,
    nonces: HashMap<usize, u64>,
}

impl World {
    fn new() -> World {
        World { w: (0..24).map(|i| wallet_from(100 + i as u8)).collect(), nonces: HashMap::new() }
    }

    fn nonce(&mut self, i: usize) -> u64 {
        let n = self.nonces.entry(i).or_insert(0);
        *n += 1;
        *n
    }

    fn transfer(&mut self, from: usize, to: &[u8], amount: i128) -> TXU {
        let nonce = self.nonce(from);
        txu(&self.w[from], nonce, b"Coin", b"transfer", vec![to.to_vec(), amount.to_string().into_bytes(), b"AMA".to_vec()])
    }

    fn sol(&mut self, from: usize, solver: usize, seed: u64) -> TXU {
        let nonce = self.nonce(from);
        let sol = valid_sol(&self.w[solver].pk, seed);
        txu(&self.w[from], nonce, b"Epoch", b"submit_sol", vec![sol])
    }

    fn kitchen(&mut self, from: usize, function: &[u8], args: Vec<Vec<u8>>, attachments: Option<Vec<u8>>) -> TXU {
        let nonce = self.nonce(from);
        let mut t = txu(&self.w[from], nonce, &kitchen_pk(), function, args);
        t.tx.action.attachments = attachments;
        t
    }

    fn call(&mut self, from: usize, contract: &[u8], amount: i128) -> TXU {
        let nonce = self.nonce(from);
        txu_attached(&self.w[from], nonce, contract, b"run", vec![], Some((b"AMA", amount)))
    }
}

fn valid_sol(pk: &[u8; 48], seed: u64) -> Vec<u8> {
    let mut preamble = [0u8; crate::upow::PREAMBLE];
    preamble[0..4].copy_from_slice(&((HEIGHT / 100_000) as u32).to_le_bytes());
    preamble[4..36].copy_from_slice(&[5u8; 32]);
    preamble[36..84].copy_from_slice(pk);
    crate::upow::compute(&preamble, 0, 1, 1, &[seed]).unwrap()
}

fn kitchen_pk() -> [u8; 48] {
    wallet_from(201).pk
}

fn attachments(entries: Vec<(&[u8], vecpak::Term)>) -> Vec<u8> {
    vecpak::encode(vecpak::Term::PropList(entries.into_iter().map(|(k, v)| (vecpak::Term::Binary(k.to_vec()), v)).collect())).unwrap()
}

fn genesis(world: &World) -> Chain {
    let chain = Chain::new();
    for w in &world.w {
        chain.fund(&w.pk, 50 * AMA);
        chain.put(&bcat(&[b"account:", &w.pk, b":attribute:pop"]), &[1u8; 96]);
    }
    chain.put(b"bic:epoch:segment_vr_hash", &[5u8; 32]);
    chain.put(b"bic:epoch:diff_bits", b"0");
    chain.put(&bcat(&[b"account:", &world.w[22].pk, b":attribute:bytecode"]), EMPTY);
    chain.put(&bcat(&[b"account:", &world.w[23].pk, b":attribute:bytecode"]), SPIN);
    chain.put(&bcat(&[b"account:", &kitchen_pk(), b":attribute:bytecode"]), KITCHEN);
    chain.put(&bcat(&[b"account:", &wallet_from(202).pk, b":attribute:bytecode"]), COUNTER);
    chain.put(b"nft:RPG:permission", &world.w[0].pk);
    chain.put(b"nft:RPG:gold:totalSupply", b"10");
    for i in 0..4 {
        chain.put(&bcat(&[b"account:", &world.w[i].pk, b":nft:RPG:gold"]), b"2");
    }
    seed_tree(&chain);
    chain
}

fn apply(chain: &Chain, e: Entry, testnet: bool, budget: Option<usize>) -> ([u8; 32], usize, Vec<bool>) {
    let txn = chain.db.transaction();
    let ((txn, muts, muts_rev, receipts, root_receipts, root_contractstate), reexecuted) =
        apply_entry_mode(chain.db, txn, e, &[0u8; 48], &[0u8; 64], testnet, budget);
    txn.commit().unwrap();
    let mut h = blake3::Hasher::new();
    h.update(&root_receipts);
    h.update(&root_contractstate);
    hash_muts(&mut h, &muts);
    hash_muts(&mut h, &muts_rev);
    for r in &receipts {
        h.update(format!("{:?}|{:?}|{:?}|{:?}|{:?}", r.txid, r.success, r.result, r.exec_used, r.logs).as_bytes());
    }
    h.update(&state_digest(chain, "contractstate"));
    h.update(&state_digest(chain, "contractstate_tree_hbsmt"));
    (*h.finalize().as_bytes(), reexecuted, receipts.iter().map(|r| r.success).collect())
}

fn blocks(world: &mut World) -> Vec<(Entry, bool)> {
    let producer = 21;
    let fresh = wallet_from(200).pk;
    let p = world.w[producer].pk;
    let (contract_ok, contract_loop) = (world.w[22].pk, world.w[23].pk);

    let mut mixed = Vec::new();
    for i in 0..6 {
        let to = world.w[i + 10].pk;
        mixed.push(world.transfer(i, &to, AMA));
    }
    for to in [7, 8, 9] {
        let to = world.w[to].pk;
        mixed.push(world.transfer(6, &to, 2 * AMA));
    }
    for seed in 0..4 {
        mixed.push(world.sol(7, 7, seed));
    }
    mixed.push(world.sol(8, 7, 0));
    mixed.push(world.sol(9, 9, 77));
    mixed.push(world.transfer(16, &p, AMA));
    mixed.push(world.transfer(producer, &world.w[17].pk.clone(), 3 * AMA));
    mixed.push(world.transfer(18, &fresh, AMA));
    mixed.push(world.transfer(19, &fresh, AMA));
    mixed.push(world.transfer(20, &p, 1_000 * AMA));
    mixed.push(world.transfer(10, &world.w[0].pk.clone(), AMA / 3));

    let contracts = vec![
        world.call(11, &contract_ok, 5),
        world.call(12, &contract_ok, 6),
        world.call(13, &contract_loop, 7),
        world.transfer(14, &contract_ok, AMA),
    ];

    let mut independent = Vec::new();
    for i in 0..8 {
        let to = world.w[i + 12].pk;
        independent.push(world.transfer(i, &to, AMA / 10));
    }

    let mut large = Vec::new();
    for i in 0..300usize {
        let to = world.w[(i * 7 + 3) % 20].pk;
        large.push(world.transfer(i % 20, &to, AMA / 100));
    }

    let int = vecpak::Term::VarInt;
    let gold = |n| vecpak::Term::PropList(vec![(vecpak::Term::Binary(b"gold".to_vec()), vecpak::Term::VarInt(n))]);
    let (k, e) = (kitchen_pk().to_vec(), contract_ok.to_vec());
    let vm = vec![
        world.kitchen(0, b"storage", vec![], Some(attachments(vec![(b"AMA", int(3)), (b"RPG", gold(1))]))),
        world.kitchen(1, b"call", vec![k.clone(), b"echo".to_vec(), b"x".to_vec()], None),
        world.kitchen(2, b"call_attached", vec![e.clone(), b"run".to_vec(), b"AMA".to_vec(), b"1".to_vec()], Some(attachments(vec![(b"AMA", int(5))]))),
        world.kitchen(3, b"abort", vec![], Some(attachments(vec![(b"AMA", int(2)), (b"RPG", gold(2))]))),
        world.kitchen(4, b"fill", vec![b"3".to_vec(), b"64".to_vec(), b"p".to_vec()], None),
        world.kitchen(5, b"next", vec![b"f:".to_vec(), b"".to_vec()], None),
        world.kitchen(0, b"storage", vec![], Some(attachments(vec![(b"RPG", gold(1))]))),
        world.kitchen(1, b"call_attached", vec![e, b"run".to_vec(), b"AMA".to_vec(), b"100".to_vec()], None),
        world.kitchen(6, b"frame", vec![wallet_from(202).pk.to_vec()], Some(attachments(vec![(b"AMA", int(1))]))),
    ];

    vec![
        (entry(HEIGHT, &world.w[producer], mixed), false),
        (entry(HEIGHT + 1, &world.w[producer], contracts), true),
        (entry(HEIGHT + 2, &world.w[producer], independent), false),
        (entry(HEIGHT + 3, &world.w[producer], large), false),
        (entry(HEIGHT + 4, &world.w[producer], vm), true),
    ]
}

#[test]
fn parallel_apply_matches_serial() {
    let mut world = World::new();
    let blocks = blocks(&mut world);
    let (par, ser) = (genesis(&world), genesis(&world));

    let mut reexecuted = Vec::new();
    for (i, (e, testnet)) in blocks.into_iter().enumerate() {
        let n = e.txs.len();
        let (a, re, ok) = apply(&par, e.clone(), testnet, Some(SPECULATIVE_BUDGET_BYTES));
        let (b, re_serial, _) = apply(&ser, e, testnet, None);
        let _ = std::panic::take_hook();
        assert_eq!(re_serial, 0);
        assert_eq!(a, b, "block {} differs between parallel and serial", i);
        assert!(re <= n);
        reexecuted.push((re, n, ok));
    }

    let (mixed_re, mixed_n, mixed_ok) = &reexecuted[0];
    assert!(*mixed_re > 0 && *mixed_re < *mixed_n, "mixed block re-executed {} of {}", mixed_re, mixed_n);
    assert!(mixed_ok[9..13].iter().all(|ok| *ok), "valid sols must succeed: {:?}", mixed_ok);
    assert!(!mixed_ok[13], "duplicate sol must fail");
    assert_eq!(reexecuted[2].0, 0, "independent block must need no re-execution");
    let (vm_re, _, vm_ok) = &reexecuted[4];
    assert_eq!(vm_ok, &vec![true, true, true, false, true, true, true, false, true], "{vm_re} re-executed");
    assert!(*vm_re > 0);
}

fn contract_exec_used(bytecode: &[u8], warm_first: bool) -> Vec<u8> {
    let world = World::new();
    let chain = genesis(&world);
    let contract = wallet_from(201);
    chain.put(&bcat(&[b"account:", &contract.pk, b":attribute:bytecode"]), bytecode);
    let mut nonce = 0;
    let mut call = |attached: Option<(&[u8], i128)>| {
        nonce += 1;
        txu_attached(&world.w[0], nonce, &contract.pk, b"get", vec![], attached)
    };
    if warm_first {
        let e = entry(HEIGHT, &world.w[21], vec![call(Some((b"AMA", 5)))]);
        apply_entry_mode(chain.db, chain.db.transaction(), e, &[0u8; 48], &[0u8; 64], true, None).0 .0.commit().unwrap();
    }
    let e = entry(HEIGHT + 1, &world.w[21], vec![call(None)]);
    let ((txn, _, _, receipts, _, _), _) = apply_entry_mode(chain.db, chain.db.transaction(), e, &[0u8; 48], &[0u8; 64], true, None);
    txn.commit().unwrap();
    assert!(receipts[0].success, "{:?}", receipts[0].result);
    receipts[0].exec_used.clone()
}

#[test]
fn contract_gas_does_not_depend_on_the_program_cache() {
    let variant = |tag: u8| [COUNTER, &[tag]].concat();
    let warmed = contract_exec_used(&variant(b'w'), true);
    let reference = contract_exec_used(&variant(b'c'), false);
    let _ = std::panic::take_hook();
    assert_eq!(warmed, reference);
}

#[test]
fn over_budget_speculation_falls_back_to_serial() {
    let mut world = World::new();
    let blocks = blocks(&mut world);
    let (par, ser) = (genesis(&world), genesis(&world));
    for (i, (e, testnet)) in blocks.into_iter().enumerate() {
        let n = e.txs.len();
        let (a, re, _) = apply(&par, e.clone(), testnet, Some(2_000));
        let (b, _, _) = apply(&ser, e, testnet, None);
        let _ = std::panic::take_hook();
        assert_eq!(a, b, "block {} differs with a tiny speculation budget", i);
        assert!(re > 0 || n == 1, "a tiny budget must force serial fallbacks");
    }
}
