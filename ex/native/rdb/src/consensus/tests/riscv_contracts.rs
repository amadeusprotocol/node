#![cfg(test)]

use crate::bcat;
use crate::consensus::bic::protocol;
use crate::consensus::bls12_381;
use crate::consensus::consensus_apply::{call_bic, call_vm};
use crate::consensus::tests::chain_harness::{panic_message, Chain};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub(crate) const EMPTY: &[u8] = include_bytes!("fixtures/riscv/empty.elf");
pub(crate) const SPIN: &[u8] = include_bytes!("fixtures/riscv/spin.elf");
pub(crate) const COUNTER: &[u8] = include_bytes!("fixtures/riscv/counter.elf");
pub(crate) const KITCHEN: &[u8] = include_bytes!("fixtures/riscv/kitchen.elf");
const DEPOSIT: &[u8] = include_bytes!("fixtures/riscv/deposit.elf");
const COIN: &[u8] = include_bytes!("fixtures/riscv/coin.elf");
const NFT: &[u8] = include_bytes!("fixtures/riscv/nft.elf");
const RPG: &[u8] = include_bytes!("fixtures/riscv/rpg.elf");

pub(crate) struct Out {
    pub(crate) result: Result<Vec<u8>, String>,
    pub(crate) logs: Vec<Vec<u8>>,
    pub(crate) exec_used: i128,
    pub(crate) storage_used: i128,
}

pub(crate) fn install(chain: &Chain, code: &[u8]) -> [u8; 48] {
    let w = chain.wallet(0);
    chain.put(&bcat(&[b"account:", &w.pk, b":attribute:bytecode"]), code);
    w.pk
}

fn attachments(entries: Vec<(&[u8], vecpak::Term)>) -> Vec<u8> {
    vecpak::encode(vecpak::Term::PropList(entries.into_iter().map(|(k, v)| (vecpak::Term::Binary(k.to_vec()), v)).collect())).unwrap()
}

fn coins(list: &[(&[u8], i128)]) -> Vec<u8> {
    attachments(list.iter().map(|&(s, a)| (s, vecpak::Term::VarInt(a))).collect())
}

fn tokens(list: &[(&[u8], i128)]) -> vecpak::Term {
    vecpak::Term::PropList(list.iter().map(|&(t, a)| (vecpak::Term::Binary(t.to_vec()), vecpak::Term::VarInt(a))).collect())
}

fn run(chain: &Chain, caller: &[u8], contract: &[u8], function: &[u8], args: &[&[u8]], attach: Option<Vec<u8>>, testnet: bool) -> Out {
    let args: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        chain.with_env(caller, |env| {
            env.testnet = testnet;
            env.caller_env.account_current = contract.to_vec();
            env.exec_track = true;
            env.exec_left = protocol::TX_EXEC_LOCK;
            env.exec_max = protocol::TX_EXEC_LOCK;
            env.storage_left = protocol::AMA_1_DOLLAR;
            env.storage_max = protocol::AMA_1_DOLLAR;
            let r = catch_unwind(AssertUnwindSafe(|| call_vm(env, contract.to_vec(), function.to_vec(), args, attach)));
            let out = (r.map_err(panic_message), env.logs.clone(), protocol::TX_EXEC_LOCK - env.exec_left, protocol::AMA_1_DOLLAR - env.storage_left);
            if out.0.is_err() {
                std::panic::panic_any(out);
            }
            out
        })
    }));
    let (result, logs, exec_used, storage_used) = match outcome {
        Ok(out) => out,
        Err(p) => *p.downcast::<(Result<Vec<u8>, String>, Vec<Vec<u8>>, i128, i128)>().unwrap_or_else(|p| Box::new((Err(panic_message(p)), Vec::new(), 0, 0))),
    };
    Out { result, logs, exec_used, storage_used }
}

pub(crate) fn testnet(chain: &Chain, caller: &[u8], contract: &[u8], function: &[u8], args: &[&[u8]]) -> Out {
    run(chain, caller, contract, function, args, None, true)
}

fn ok(out: &Out) -> Vec<u8> {
    out.result.clone().unwrap_or_else(|e| panic!("call failed: {e}, logs {:?}", out.logs))
}

fn deploy(chain: &Chain, code: &[u8]) -> Result<(), String> {
    let w = chain.wallet(0);
    chain.call_as(&w.pk, b"Contract", b"deploy", &[code])
}

#[test]
fn deploy_validates_riscv_bytecode() {
    let chain = Chain::new();
    assert_eq!(deploy(&chain, KITCHEN), Ok(()));
    assert_eq!(deploy(&chain, &KITCHEN[..KITCHEN.len() / 2]), Err("riscv_load_elf_parse_failed".to_string()));
    assert_eq!(deploy(&chain, b"\0asm\x01\0\0\0"), Err("riscv_invalid_bytecode".to_string()));
    let mut huge = KITCHEN.to_vec();
    huge.resize(protocol::MAX_CONTRACT_SIZE + 1, 0);
    assert_eq!(deploy(&chain, &huge), Err("riscv_bytecode_too_large".to_string()));
}

#[test]
fn counter_persists_storage_under_the_contract_prefix() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, COUNTER);
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"inc", &[])), b"1");
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"inc", &[b"41"])), b"42");
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"get", &[])), b"42");
    assert_eq!(chain.get(&bcat(&[b"account:", &contract, b":storage:count"])), Some(b"42".to_vec()));
}

#[test]
fn arguments_environment_and_storage_calls() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, KITCHEN);
    let out = testnet(&chain, &caller.pk, &contract, b"echo", &[b"alpha", b"", &[7u8; 300]]);
    ok(&out);
    assert_eq!(out.logs, vec![b"echo".to_vec(), b"alpha".to_vec(), b"".to_vec(), vec![7u8; 300]]);

    let out = testnet(&chain, &caller.pk, &contract, b"env", &[]);
    ok(&out);
    assert_eq!(out.logs[0].len(), 32);
    assert_eq!(out.logs[2], caller.pk.to_vec());
    assert_eq!(out.logs[3], contract.to_vec());
    assert_eq!(out.logs[4], caller.pk.to_vec());
    assert_eq!(out.logs[5], caller.pk.to_vec());
    assert_eq!(out.logs[6], b"".to_vec());

    let out = testnet(&chain, &caller.pk, &contract, b"storage", &[]);
    ok(&out);
    assert_eq!(out.logs, vec![vec![1, 0], b"333".to_vec(), b"c333".to_vec(), b"c333".to_vec(), b"-5".to_vec()]);
}

#[test]
fn hash_host_calls_match_native() {
    use sha2::Digest;
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, KITCHEN);
    for data in [b"".to_vec(), b"abc".to_vec(), vec![9u8; 55], vec![9u8; 56], vec![1u8; 5000]] {
        let out = testnet(&chain, &caller.pk, &contract, b"hashes", &[&data]);
        ok(&out);
        let sha: [u8; 32] = sha2::Sha256::digest(&data).into();
        let keccak: [u8; 32] = sha3::Keccak256::digest(&data).into();
        assert_eq!(out.logs, vec![sha.to_vec(), keccak.to_vec(), blake3::hash(&data).as_bytes().to_vec()]);
    }
}

#[test]
fn bls_host_calls() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, KITCHEN);
    let dst = b"AMADEUS_TEST_DST";
    let keys: Vec<[u8; 64]> = (0..3).map(|_| bls12_381::generate_sk()).collect();
    let pks: Vec<[u8; 48]> = keys.iter().map(|sk| bls12_381::get_public_key(sk).unwrap()).collect();
    let msg = b"hello";
    let sig = bls12_381::sign(&keys[0], msg, dst).unwrap();
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"bls", &[&pks[0], &sig, msg, dst])), b"1");
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"bls", &[&pks[1], &sig, msg, dst])), b"0");
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"bls", &[&pks[0], &sig, b"other", dst])), b"0");

    let sigs: Vec<[u8; 96]> = keys.iter().map(|sk| bls12_381::sign(sk, msg, dst).unwrap()).collect();
    let agg = bls12_381::aggregate_signatures(sigs.iter()).unwrap();
    let all: Vec<u8> = pks.concat();
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"bls_agg", &[&all, &agg, msg, dst])), b"1");
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"bls_agg", &[&pks[..2].concat(), &agg, msg, dst])), b"0");
}

#[test]
fn secp256k1_host_calls() {
    use k256::ecdsa::SigningKey;
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, KITCHEN);
    let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let hash = [3u8; 32];
    let (sig, recid) = sk.sign_prehash_recoverable(&hash).unwrap();
    let out = testnet(&chain, &caller.pk, &contract, b"secp", &[&hash, &sig.to_bytes(), &[recid.to_byte()]]);
    assert_eq!(ok(&out), b"1");
    assert_eq!(out.logs, vec![sk.verifying_key().to_encoded_point(false).as_bytes().to_vec()]);
    let out = testnet(&chain, &caller.pk, &contract, b"secp", &[&hash, &[0u8; 64], &[0]]);
    assert_eq!(ok(&out), b"none");
}

#[test]
fn ed25519_host_call() {
    use ed25519_dalek::{Signer, SigningKey};
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, KITCHEN);
    let sk = SigningKey::from_bytes(&[5u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    let sig = sk.sign(b"payload").to_bytes();
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"ed25519", &[&pk, &sig, b"payload"])), b"1");
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"ed25519", &[&pk, &sig, b"payloaD"])), b"0");
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"ed25519", &[&[0u8; 32], &sig, b"payload"])), b"0");
}

#[test]
fn contracts_call_other_contracts() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    let counter = install(&chain, COUNTER);
    assert_eq!(ok(&testnet(&chain, &caller.pk, &kitchen, b"call", &[&counter, b"inc", b"5"])), b"5");
    assert_eq!(chain.get(&bcat(&[b"account:", &counter, b":storage:count"])), Some(b"5".to_vec()));
    assert_eq!(ok(&testnet(&chain, &caller.pk, &kitchen, b"call", &[&kitchen, b"call", &counter, b"inc", b"1"])), b"6");
}

fn put_coin(chain: &Chain, owner: &[u8], symbol: &[u8]) {
    chain.put(&bcat(&[b"coin:", symbol, b":totalSupply"]), b"10");
    chain.put(&bcat(&[b"account:", owner, b":balance:", symbol]), b"10");
}

#[test]
fn attachments_enforce_coin_transfer_policies() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, EMPTY);
    let attached = |symbol: &[u8]| run(&chain, &caller.pk, &contract, b"run", &[], Some(coins(&[(symbol, 1)])), true).result;

    chain.put(&bcat(&[b"account:", &caller.pk, b":balance:AMA"]), b"10");
    assert_eq!(attached(b"AMA"), Ok(Vec::new()));
    assert_eq!(chain.get(&bcat(&[b"account:", &caller.pk, b":balance:AMA"])), Some(b"9".to_vec()));
    assert_eq!(chain.get(&bcat(&[b"account:", &contract, b":balance:AMA"])), Some(b"1".to_vec()));

    put_coin(&chain, &caller.pk, b"PAUSED");
    chain.put(b"coin:PAUSED:pausable", b"true");
    chain.put(b"coin:PAUSED:paused", b"true");
    assert_eq!(attached(b"PAUSED"), Err("attachments_paused".to_string()));

    put_coin(&chain, &caller.pk, b"SOULBOUND");
    chain.put(b"coin:SOULBOUND:soulbound", b"true");
    assert_eq!(attached(b"SOULBOUND"), Err("attachments_soulbound".to_string()));

    for symbol in [b"PAUSED".as_slice(), b"SOULBOUND".as_slice()] {
        assert_eq!(chain.get(&bcat(&[b"account:", &contract, b":balance:", symbol])), None);
        assert_eq!(chain.get(&bcat(&[b"account:", &caller.pk, b":balance:", symbol])).as_deref(), Some(b"10".as_slice()));
    }

    let kitchen = install(&chain, KITCHEN);
    chain.put(&bcat(&[b"account:", &kitchen, b":balance:AMA"]), b"3");
    assert_eq!(ok(&testnet(&chain, &caller.pk, &kitchen, b"call_attached", &[&contract, b"run", b"AMA", b"2"])), b"");
    assert_eq!(chain.get(&bcat(&[b"account:", &kitchen, b":balance:AMA"])), Some(b"1".to_vec()));
    assert_eq!(chain.get(&bcat(&[b"account:", &contract, b":balance:AMA"])), Some(b"3".to_vec()));
}

#[test]
fn failures_revert_with_fixed_reasons() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    let fail = |f: &[u8]| {
        let out = testnet(&chain, &caller.pk, &kitchen, f, &[]);
        (out.result.unwrap_err(), out.logs)
    };
    assert_eq!(fail(b"abort"), ("abort".to_string(), vec![b"boom".to_vec()]));
    assert_eq!(fail(b"panic"), ("abort".to_string(), vec![b"panic".to_vec()]));
    assert_eq!(fail(b"exit7"), ("abort".to_string(), vec![]));
    assert_eq!(fail(b"trap"), ("trap".to_string(), vec![b"riscv_trap_load_out_of_bounds".to_vec()]));
    assert_eq!(fail(b"big_return").0, "host_return_value_too_large");
    assert_eq!(fail(b"missing").0, "abort");

    let spin = install(&chain, SPIN);
    let out = testnet(&chain, &caller.pk, &spin, b"run", &[]);
    assert_eq!(out.result, Err("exec_insufficient_exec_budget".to_string()));
}

#[test]
fn vecpak_roundtrips_inside_the_vm() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, KITCHEN);
    use vecpak::Term;
    let term = Term::PropList(vec![
        (Term::Binary(b"amount".to_vec()), Term::VarInt(-123456789)),
        (Term::Binary(b"list".to_vec()), Term::List(vec![Term::Nil(), Term::Bool(true), Term::Binary(vec![1, 2, 3])])),
        (Term::Binary(b"z".to_vec()), Term::VarInt(i128::MIN)),
    ]);
    let bytes = vecpak::encode(term).unwrap();
    assert_eq!(ok(&testnet(&chain, &caller.pk, &contract, b"vecpak", &[&bytes, b"3"])), b"same");
}

#[test]
fn mainnet_still_refuses_contract_execution() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, COUNTER);
    let out = run(&chain, &caller.pk, &contract, b"inc", &[], None, false);
    assert_eq!(out.result, Err("wasm_noop".to_string()));
    assert_eq!(chain.get(&bcat(&[b"account:", &contract, b":storage:count"])), None);
    let _ = call_bic;
}

#[test]
fn exec_charges_are_deterministic_and_bounded() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, COUNTER);
    let a = testnet(&chain, &caller.pk, &contract, b"get", &[]);
    let b = testnet(&chain, &caller.pk, &contract, b"get", &[]);
    assert_eq!(a.exec_used, b.exec_used);
    assert!(a.exec_used > 0 && a.exec_used < protocol::TX_EXEC_LOCK);
}

fn balance(chain: &Chain, who: &[u8], symbol: &[u8]) -> i128 {
    chain.get(&bcat(&[b"account:", who, b":balance:", symbol])).map_or(0, |v| std::str::from_utf8(&v).unwrap().parse().unwrap())
}

#[test]
fn deposit_contract_holds_and_returns_funds() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    chain.put(&bcat(&[b"account:", &caller.pk, b":balance:AMA"]), b"1000");
    let vault = install(&chain, DEPOSIT);
    let deposit = |amount: &[u8]| run(&chain, &caller.pk, &vault, b"deposit", &[], Some(coins(&[(b"AMA", std::str::from_utf8(amount).unwrap().parse().unwrap())])), true);

    assert_eq!(ok(&deposit(b"500")), b"500");
    assert_eq!(deposit(b"50").result, Err("abort".to_string()));
    assert_eq!(ok(&testnet(&chain, &caller.pk, &vault, b"balance", &[b"AMA"])), b"500");
    assert_eq!((balance(&chain, &caller.pk, b"AMA"), balance(&chain, &vault, b"AMA")), (500, 500));

    assert_eq!(ok(&testnet(&chain, &caller.pk, &vault, b"withdraw", &[b"AMA", b"200"])), b"300");
    assert_eq!((balance(&chain, &caller.pk, b"AMA"), balance(&chain, &vault, b"AMA")), (700, 300));
    assert_eq!(testnet(&chain, &caller.pk, &vault, b"withdraw", &[b"AMA", b"301"]).result, Err("abort".to_string()));
    assert_eq!(testnet(&chain, &caller.pk, &vault, b"withdraw", &[b"AMA", b"0"]).result, Err("abort".to_string()));

    let other = chain.wallet(0);
    assert_eq!(ok(&testnet(&chain, &other.pk, &vault, b"balance", &[b"AMA"])), b"0");
    assert_eq!(testnet(&chain, &other.pk, &vault, b"withdraw", &[b"AMA", b"1"]).result, Err("abort".to_string()));
}

#[test]
fn coin_contract_creates_and_distributes_a_token() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let coin = install(&chain, COIN);
    ok(&testnet(&chain, &caller.pk, &coin, b"init", &[]));
    assert_eq!(balance(&chain, &coin, b"USDFAKE"), 1_000_000_000_000_000_000);
    ok(&testnet(&chain, &caller.pk, &coin, b"airdrop", &[&caller.pk, b"25"]));
    assert_eq!(balance(&chain, &caller.pk, b"USDFAKE"), 25);
    assert_eq!(testnet(&chain, &caller.pk, &coin, b"init", &[]).result, Err("symbol_exists".to_string()));
}

#[test]
fn nft_contract_creates_a_collection_and_mints() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let nft = install(&chain, NFT);
    ok(&testnet(&chain, &caller.pk, &nft, b"init", &[]));
    let token = ok(&testnet(&chain, &caller.pk, &nft, b"claim", &[]));
    assert!(matches!(token.as_slice(), [b'1'..=b'6']));
    let held = |t: &[u8]| chain.get(&bcat(&[b"account:", &caller.pk, b":nft:AGENTIC:", t])).map_or(0, |v| std::str::from_utf8(&v).unwrap().parse::<i128>().unwrap());
    assert_eq!(held(b"2"), if token == b"2" { 3 } else { 2 });
    assert_eq!(held(&token), if token == b"2" { 3 } else { 1 });
    assert!(ok(&testnet(&chain, &caller.pk, &nft, b"view_nft", &[b"AGENTIC", b"3"])).starts_with(b"ipfs://"));
}

#[test]
fn rpg_heroes_fight_monsters_and_loot_nfts() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let rpg = install(&chain, RPG);
    ok(&testnet(&chain, &caller.pk, &rpg, b"init", &[]));
    assert!(chain.get(b"nft:RPGSOULBOUND:soulbound").is_some());
    assert_eq!(testnet(&chain, &caller.pk, &rpg, b"fight", &[]).result, Err("abort".to_string()));
    ok(&testnet(&chain, &caller.pk, &rpg, b"create_hero", &[]));
    assert_eq!(testnet(&chain, &caller.pk, &rpg, b"create_hero", &[]).result, Err("abort".to_string()));
    let fight = |i: u8| {
        chain.with_env(&caller.pk, |env| {
            env.testnet = true;
            env.caller_env.tx_hash = [i; 32];
            env.caller_env.account_current = rpg.to_vec();
            (env.exec_track, env.exec_left, env.exec_max) = (true, protocol::TX_EXEC_LOCK, protocol::TX_EXEC_LOCK);
            (env.storage_left, env.storage_max) = (protocol::AMA_1_DOLLAR, protocol::AMA_1_DOLLAR);
            call_vm(env, rpg.to_vec(), b"fight".to_vec(), vec![], None);
            env.logs.iter().map(|l| String::from_utf8_lossy(l).into_owned()).collect::<Vec<_>>()
        })
    };
    let logs: Vec<Vec<String>> = (0..60).map(fight).collect();
    let saw = |needle: &str| logs.iter().flatten().any(|l| l.contains(needle));
    assert!(logs.iter().all(|l| l[0].starts_with("A wild ") && l.len() <= protocol::LOG_TOTAL_ELEMENTS));
    for needle in ["goblin appears", "orc appears", "goblin died", "You have died, reviving", "dropped gold"] {
        assert!(saw(needle), "{needle}");
    }
    let gold = chain.get(&bcat(&[b"account:", &caller.pk, b":nft:RPG:gold"])).map(|v| String::from_utf8(v).unwrap().parse::<u64>().unwrap());
    assert_eq!(gold, Some(logs.iter().flatten().filter(|l| l.ends_with("dropped gold")).count() as u64));
    assert!(ok(&testnet(&chain, &caller.pk, &rpg, b"view_nft", &[b"RPG", b"gold"])).starts_with(b"https://"));
}

#[test]
fn deposit_burn_requires_and_debits_the_callers_vault() {
    let chain = Chain::new();
    let (alice, mallory) = (chain.wallet(0), chain.wallet(0));
    chain.put(&bcat(&[b"account:", &alice.pk, b":balance:AMA"]), b"1000");
    let vault = install(&chain, DEPOSIT);
    ok(&run(&chain, &alice.pk, &vault, b"deposit", &[], Some(coins(&[(b"AMA", 500)])), true));
    assert_eq!(testnet(&chain, &mallory.pk, &vault, b"burn", &[b"AMA", b"100"]).result, Err("abort".to_string()));
    assert_eq!(balance(&chain, &vault, b"AMA"), 500);
    assert_eq!(ok(&testnet(&chain, &alice.pk, &vault, b"burn", &[b"AMA", b"100"])), b"400");
    assert_eq!((balance(&chain, &vault, b"AMA"), balance(&chain, &protocol_burn(), b"AMA")), (400, 100));
    assert_eq!(testnet(&chain, &alice.pk, &vault, b"burn", &[b"AMA", b"401"]).result, Err("abort".to_string()));
}

fn protocol_burn() -> [u8; 48] {
    crate::consensus::bic::coin::BURN_ADDRESS
}

#[test]
fn nested_calls_do_not_leak_frame_state() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    chain.put(&bcat(&[b"account:", &caller.pk, b":balance:AMA"]), b"10");
    let kitchen = install(&chain, KITCHEN);
    let counter = install(&chain, COUNTER);
    let out = run(&chain, &caller.pk, &kitchen, b"frame", &[&counter], Some(coins(&[(b"AMA", 1)])), true);
    assert_eq!(out.result, Ok(Vec::new()));
    assert_eq!(out.logs, vec![b"same".to_vec()]);
    let out = testnet(&chain, &caller.pk, &kitchen, b"frame", &[&counter]);
    assert_eq!((out.result, out.logs), (Ok(Vec::new()), vec![b"same".to_vec()]));
}

#[test]
fn over_aligned_allocations_are_aligned() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    assert_eq!(ok(&testnet(&chain, &caller.pk, &kitchen, b"align", &[])), b"1");
}

#[test]
fn host_byte_charges_are_exact() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    let used = |f: &[u8], args: &[&[u8]]| {
        let out = testnet(&chain, &caller.pk, &kitchen, f, args);
        ok(&out);
        (out.exec_used, out.storage_used)
    };
    let (long, short) = (used(b"ret_len", &[b"100"]), used(b"ret_len", &[b"000"]));
    assert_eq!((long.0 - short.0, long.1 - short.1), (4, protocol::cost_per_bytes_historical(100)));
    let copied = used(b"argcopy", &[&[9u8; 4096]]).0 - used(b"argcopy", &[b""]).0;
    assert_eq!(copied, 4096 / protocol::RISCV_COPY_BYTES_PER_UNIT as i128);
}


fn action(contract: &[u8], function: &[u8], args: Vec<Vec<u8>>) -> crate::model::tx::Action {
    crate::model::tx::Action {
        op: b"call".to_vec(), contract: contract.to_vec(), function: function.to_vec(), args,
        attached_gas: None, attachments: None,
    }
}

fn deploy_tx(chain: &Chain, signer: &crate::consensus::tests::chain_harness::Wallet, nonce: u64, height: u64, code: &[u8], attached_gas: Option<i128>) -> crate::model::tx_receipt::TXReceipt {
    apply_tx(chain, signer, nonce, height, crate::model::tx::Action { attached_gas, ..action(b"Contract", b"deploy", vec![code.to_vec()]) })
}

fn apply_tx(chain: &Chain, signer: &crate::consensus::tests::chain_harness::Wallet, nonce: u64, height: u64, action: crate::model::tx::Action) -> crate::model::tx_receipt::TXReceipt {
    use crate::consensus::tests::apply_golden::entry;
    use crate::model::tx::{TX, TXU};
    let txu = TXU {
        hash: blake3::hash(&[&signer.pk[..], &nonce.to_be_bytes()].concat()).as_bytes().to_vec(),
        signature: vec![0u8; 96],
        tx: TX { signer: signer.pk.to_vec(), nonce, action },
    };
    let txn = chain.db.transaction();
    let (txn, _, _, mut receipts, _, _) = crate::consensus::consensus_apply::apply_entry(chain.db, txn, entry(height, signer, vec![txu]), &[0u8; 48], &[0u8; 64], true);
    let _ = std::panic::take_hook();
    txn.commit().unwrap();
    receipts.remove(0)
}

#[test]
fn deploys_pay_for_storage_with_attached_gas_up_to_the_size_cap() {
    use crate::consensus::tests::apply_golden::{seed_tree, wallet_from, HEIGHT};
    let chain = Chain::new();
    let signer = wallet_from(12);
    chain.fund(&signer.pk, 100 * protocol::AMA_1_DOLLAR);
    seed_tree(&chain);
    let gas = |code: &[u8]| code.len() as i128 * (protocol::COST_PER_BYTE_STATE + protocol::COST_PER_BYTE_HISTORICAL) + protocol::AMA_10_CENT;
    let key = bcat(&[b"account:", &signer.pk, b":attribute:bytecode"]);

    assert!(!deploy_tx(&chain, &signer, 1, HEIGHT, COUNTER, None).success);
    assert_eq!(chain.get(&key), None);
    assert!(deploy_tx(&chain, &signer, 2, HEIGHT + 1, COUNTER, Some(gas(COUNTER))).success);
    assert_eq!(chain.get(&key).as_deref(), Some(COUNTER));

    let mut max = KITCHEN.to_vec();
    max.resize(protocol::MAX_CONTRACT_SIZE, 0);
    let r = deploy_tx(&chain, &signer, 3, HEIGHT + 2, &max, Some(gas(&max)));
    assert!(r.success, "{}", String::from_utf8_lossy(&r.result));
    assert_eq!(chain.get(&key), Some(max));
}

#[test]
fn testnet_reads_and_writes_of_the_largest_value_fit_the_exec_cap() {
    use crate::consensus::consensus_kv::{kv_get, kv_put};
    let chain = Chain::new();
    let w = chain.wallet(0);
    let key = bcat(&[b"account:", &w.pk, b":storage:big"]);
    let value = vec![7u8; protocol::MAX_DB_VALUE_SIZE];
    let bytes = (key.len() + value.len()) as i128;
    let metered = |f: &dyn Fn(&mut crate::consensus::consensus_apply::ApplyEnv)| chain.with_env(&w.pk, |env| {
        assert!(env.testnet);
        (env.exec_track, env.exec_left, env.exec_max) = (true, protocol::TX_EXEC_LOCK, protocol::TX_EXEC_LOCK);
        (env.storage_left, env.storage_max) = (100 * protocol::AMA_1_DOLLAR, 100 * protocol::AMA_1_DOLLAR);
        f(env);
        protocol::TX_EXEC_LOCK - env.exec_left
    });
    let used = (
        metered(&|env| kv_put(env, &key, &value)),
        metered(&|env| assert_eq!(kv_get(env, &key).map(|v| v.len()), Some(value.len()))),
    );
    assert_eq!(used, (protocol::COST_PER_DB_WRITE_BASE + bytes, protocol::COST_PER_DB_READ_BASE + bytes));
}

#[test]
fn nested_call_arguments_cost_only_their_copies() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    let empty = install(&chain, EMPTY);
    let used = |arg: &[u8]| {
        let out = testnet(&chain, &caller.pk, &kitchen, b"call", &[&empty, b"run", arg]);
        ok(&out);
        out.exec_used
    };
    let extra = used(&[1u8; 4096]) - used(b"");
    assert!(extra > 0 && extra < 4096, "{extra}");
}

fn put_nft(chain: &Chain, owner: &[u8], collection: &[u8], token: &[u8], amount: &[u8]) {
    chain.put(&bcat(&[b"nft:", collection, b":permission"]), owner);
    chain.put(&bcat(&[b"nft:", collection, b":", token, b":totalSupply"]), amount);
    chain.put(&bcat(&[b"account:", owner, b":nft:", collection, b":", token]), amount);
}

fn held(chain: &Chain, owner: &[u8], key: &[&[u8]]) -> Option<Vec<u8>> {
    chain.get(&bcat(&[&[b"account:".as_slice(), owner].concat(), &key.concat()]))
}

#[test]
fn attachments_move_coins_and_nfts_together() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    chain.put(&bcat(&[b"account:", &caller.pk, b":balance:AMA"]), b"100");
    put_coin(&chain, &caller.pk, b"USDFAKE");
    put_nft(&chain, &caller.pk, b"RPG", b"gold", b"5");
    put_nft(&chain, &caller.pk, b"RPG", b"sword", b"1");
    let att = attachments(vec![(b"USDFAKE", vecpak::Term::VarInt(3)), (b"AMA", vecpak::Term::VarInt(7)), (b"RPG", tokens(&[(b"sword", 1), (b"gold", 2)]))]);
    let out = run(&chain, &caller.pk, &kitchen, b"env", &[], Some(att.clone()), true);
    ok(&out);
    assert_eq!(out.logs.last(), Some(&att));
    assert_eq!(held(&chain, &caller.pk, &[b":balance:AMA"]), Some(b"93".to_vec()));
    assert_eq!(held(&chain, &kitchen, &[b":balance:AMA"]), Some(b"7".to_vec()));
    assert_eq!(held(&chain, &caller.pk, &[b":balance:USDFAKE"]), Some(b"7".to_vec()));
    assert_eq!(held(&chain, &kitchen, &[b":balance:USDFAKE"]), Some(b"3".to_vec()));
    assert_eq!(held(&chain, &caller.pk, &[b":nft:RPG:gold"]), Some(b"3".to_vec()));
    assert_eq!(held(&chain, &kitchen, &[b":nft:RPG:gold"]), Some(b"2".to_vec()));
    assert_eq!(held(&chain, &caller.pk, &[b":nft:RPG:sword"]), None);
    assert_eq!(held(&chain, &kitchen, &[b":nft:RPG:sword"]), Some(b"1".to_vec()));
    assert_eq!(ok(&testnet(&chain, &caller.pk, &kitchen, b"env", &[])).len(), 0);
}

#[test]
fn attachments_check_every_entry_and_revert_all_on_failure() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, EMPTY);
    chain.put(&bcat(&[b"account:", &caller.pk, b":balance:AMA"]), b"100");
    put_coin(&chain, &caller.pk, b"USDFAKE");
    put_nft(&chain, &caller.pk, b"RPG", b"gold", b"5");
    put_nft(&chain, &caller.pk, b"RPG", b"sword", b"1");
    chain.put(b"nft:RPG:sword:soulbound", b"true");
    put_nft(&chain, &caller.pk, b"BOUND", b"ring", b"1");
    chain.put(b"nft:BOUND:soulbound", b"true");
    let fail = |att: Vec<u8>| run(&chain, &caller.pk, &contract, b"run", &[], Some(att), true).result.unwrap_err();
    let int = vecpak::Term::VarInt;
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (coins(&[(b"NOPE", 1)]), "attachments_unknown_coin"),
        (coins(&[(b"RPG", 1)]), "attachments_unknown_coin"),
        (attachments(vec![(b"USDFAKE", tokens(&[(b"x", 1)]))]), "attachments_unknown_collection"),
        (attachments(vec![(b"RPG", tokens(&[(b"nope", 1)]))]), "attachments_unknown_token"),
        (coins(&[(b"AMA", 101)]), "attachments_insufficient_funds"),
        (attachments(vec![(b"RPG", tokens(&[(b"gold", 6)]))]), "attachments_insufficient_tokens"),
        (attachments(vec![(b"RPG", tokens(&[(b"sword", 1)]))]), "attachments_soulbound"),
        (attachments(vec![(b"BOUND", tokens(&[(b"ring", 1)]))]), "attachments_soulbound"),
        (coins(&[(b"AMA", 0)]), "attachments_invalid_amount"),
        (coins(&[(b"AMA", -5)]), "attachments_invalid_amount"),
        (attachments(vec![(b"AMA", vecpak::Term::Binary(b"5".to_vec()))]), "attachments_invalid_amount"),
        (attachments(vec![(b"RPG", tokens(&[]))]), "attachments_invalid_amount"),
        (coins(&[(b"AM-A", 1)]), "attachments_invalid_name"),
        (coins(&[(b"AMA\n", 1)]), "attachments_invalid_name"),
        (coins(&[(b"nil", 1)]), "attachments_invalid_name"),
        (attachments(vec![(b"RPG", tokens(&[(b"true", 1)]))]), "attachments_invalid_name"),
        (attachments(vec![(b"RPG", tokens(&[(b"go ld", 1)]))]), "attachments_invalid_name"),
        (attachments(vec![]), "attachments_empty"),
        (b"\x07\x01".to_vec(), "attachments_invalid"),
        (vec![0u8; protocol::TX_EXEC_LOCK as usize + 1], "exec_insufficient_exec_budget"),
        (attachments(vec![(b"AMA", int(5)), (b"RPG", tokens(&[(b"gold", 1), (b"nope", 1)]))]), "attachments_unknown_token"),
    ];
    for (att, err) in cases {
        assert_eq!(fail(att), err);
    }
    assert_eq!(held(&chain, &caller.pk, &[b":balance:AMA"]), Some(b"100".to_vec()));
    assert_eq!(held(&chain, &caller.pk, &[b":nft:RPG:gold"]), Some(b"5".to_vec()));
    assert_eq!(held(&chain, &contract, &[b":balance:AMA"]), None);
    assert_eq!(held(&chain, &contract, &[b":nft:RPG:gold"]), None);
}

#[test]
fn attachments_are_rejected_on_builtin_calls_and_need_a_contract() {
    use crate::consensus::tests::apply_golden::{seed_tree, wallet_from, HEIGHT};
    let chain = Chain::new();
    let signer = wallet_from(12);
    let to = wallet_from(13);
    chain.fund(&signer.pk, 100 * protocol::AMA_1_DOLLAR);
    seed_tree(&chain);
    let transfer = action(b"Coin", b"transfer", vec![to.pk.to_vec(), b"1".to_vec(), b"AMA".to_vec()]);
    let r = apply_tx(&chain, &signer, 1, HEIGHT, crate::model::tx::Action { attachments: Some(coins(&[(b"AMA", 1)])), ..transfer.clone() });
    assert_eq!((r.success, r.result.as_slice()), (false, b"attachments_not_allowed_on_builtin".as_slice()));
    assert!(apply_tx(&chain, &signer, 2, HEIGHT + 1, transfer).success);

    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    chain.put(&bcat(&[b"account:", &kitchen, b":balance:AMA"]), b"3");
    let nested = testnet(&chain, &caller.pk, &kitchen, b"call_attached", &[b"Coin", b"transfer", b"AMA", b"1"]);
    assert_eq!(nested.result, Err("attachments_not_allowed_on_builtin".to_string()));
    chain.put(&bcat(&[b"account:", &caller.pk, b":balance:AMA"]), b"10");
    let wallet = chain.wallet(0);
    assert_eq!(run(&chain, &caller.pk, &wallet.pk, b"run", &[], Some(coins(&[(b"AMA", 1)])), true).result, Err("account_has_no_bytecode".to_string()));
}


#[test]
fn attachments_to_self_debit_before_crediting() {
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    put_coin(&chain, &kitchen, b"BIG");
    let max = i128::MAX.to_string();
    chain.put(&bcat(&[b"account:", &kitchen, b":balance:BIG"]), max.as_bytes());
    ok(&testnet(&chain, &caller.pk, &kitchen, b"call_attached", &[&kitchen, b"echo", b"BIG", b"1"]));
    assert_eq!(held(&chain, &kitchen, &[b":balance:BIG"]), Some(max.into_bytes()));
}
