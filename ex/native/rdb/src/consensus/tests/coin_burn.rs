#![cfg(test)]

//Coin.burn: holder-only destroy of allowlisted coins (PRIME redemptions) against a
//per-account ref, dispatched from FORKHEIGHT2. Soulbound does not block it,
//pause does, and every (symbol, holder, ref) leaves one permanent record.

use crate::bcat;
use crate::consensus::bic::coin::{burn_record_key, burned_key, BURN_ADDRESS, MAX_BURN_REF_LEN, MAX_MINT_PER_CALL};
use crate::consensus::bic::prime::{issue_prime, PRIME_ADMIN_COLD};
use crate::consensus::bic::protocol::{self, FORKHEIGHT2, FORKHEIGHT2_TESTNET};
use crate::consensus::consensus_apply::call_bic;
use crate::consensus::tests::chain_harness::{panic_message, Chain, Cluster};
use std::panic::{catch_unwind, AssertUnwindSafe};

const TX_HASH: [u8; 32] = [7u8; 32];

fn call_on(chain: &Chain, testnet: bool, signer: &[u8], contract: &[u8], function: &[u8], args: &[&[u8]]) -> Result<(), String> {
    let args: Vec<Vec<u8>> = args.iter().map(|arg| arg.to_vec()).collect();
    catch_unwind(AssertUnwindSafe(|| {
        chain.with_env(signer, |env| {
            env.testnet = testnet;
            env.caller_env.tx_hash = TX_HASH;
            call_bic(env, contract.to_vec(), function.to_vec(), args.clone(), None, None);
        })
    }))
    .map_err(panic_message)
}

fn burn(chain: &Chain, signer: &[u8], args: &[&[u8]]) -> Result<(), String> {
    call_on(chain, false, signer, b"Coin", b"burn", args)
}

fn get_int(chain: &Chain, key: &[u8]) -> i128 {
    chain.get(key).and_then(|value| atoi::atoi::<i128>(&value)).unwrap_or(0)
}

fn balance_of(chain: &Chain, account: &[u8], symbol: &[u8]) -> i128 {
    get_int(chain, &bcat(&[b"account:", account, b":balance:", symbol]))
}

fn supply_of(chain: &Chain, symbol: &[u8]) -> i128 {
    get_int(chain, &bcat(&[b"coin:", symbol, b":totalSupply"]))
}

fn expected_record(amount: &[u8], height: u64) -> Vec<u8> {
    bcat(&[amount, b":", height.to_string().as_bytes(), b":", bs58::encode(&TX_HASH).into_string().as_bytes()])
}

//mainnet chain at FORKHEIGHT2 with PRIME issued and minted to the holders
fn mainnet_with_prime(holders: &[&[u8]], amount: &[u8]) -> Chain {
    let mut chain = Chain::new();
    chain.height = FORKHEIGHT2;
    chain.with_env(&[0u8; 48], |env| {
        env.testnet = false;
        issue_prime(env);
    });
    for holder in holders {
        call_on(&chain, false, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[holder, amount, b"PRIME"]).unwrap();
    }
    chain.height = FORKHEIGHT2;
    chain
}

#[test]
fn burn_is_dispatched_only_from_forkheight2_on_mainnet() {
    let holder = Chain::new().wallet(0);
    let mut chain = mainnet_with_prime(&[&holder.pk], b"1000");

    chain.height = FORKHEIGHT2 - 1;
    let before = chain.state_digest();
    assert_eq!(burn(&chain, &holder.pk, &[b"10", b"PRIME", b"order1"]), Err("invalid_bic_action".to_string()));
    assert_eq!(chain.state_digest(), before);

    chain.height = FORKHEIGHT2;
    burn(&chain, &holder.pk, &[b"10", b"PRIME", b"order1"]).unwrap();
    assert_eq!(balance_of(&chain, &holder.pk, b"PRIME"), 990);
}

#[test]
fn burn_is_dispatched_only_from_forkheight2_on_testnet() {
    assert!(FORKHEIGHT2_TESTNET > 0, "a zero testnet fork would change replay of historical testnet txs");
    let mut chain = Chain::new();
    let holder = chain.wallet(0);
    chain.with_env(&[0u8; 48], |env| issue_prime(env));
    call_on(&chain, true, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[&holder.pk, b"100", b"PRIME"]).unwrap();

    chain.height = FORKHEIGHT2_TESTNET - 1;
    assert_eq!(call_on(&chain, true, &holder.pk, b"Coin", b"burn", &[b"1", b"PRIME", b"ref"]), Err("invalid_bic_action".to_string()));
    chain.height = FORKHEIGHT2_TESTNET;
    call_on(&chain, true, &holder.pk, b"Coin", b"burn", &[b"1", b"PRIME", b"ref"]).unwrap();
    assert_eq!(balance_of(&chain, &holder.pk, b"PRIME"), 99);
}

#[test]
fn fork_guard_reads_nothing_before_activation() {
    let holder = Chain::new().wallet(0);
    let mut chain = mainnet_with_prime(&[&holder.pk], b"1000");
    chain.height = FORKHEIGHT2 - 1;

    let budget_after = |function: &[u8]| {
        let args: Vec<Vec<u8>> = vec![b"10".to_vec(), b"PRIME".to_vec(), b"order1".to_vec()];
        chain.with_env(&holder.pk, |env| {
            env.testnet = false;
            env.exec_track = true;
            env.exec_left = protocol::TX_EXEC_LOCK;
            env.storage_left = protocol::TX_BUDGET;
            let outcome = catch_unwind(AssertUnwindSafe(|| call_bic(env, b"Coin".to_vec(), function.to_vec(), args, None, None))).map_err(panic_message);
            (outcome, env.exec_left, env.storage_left)
        })
    };
    let burn_outcome = budget_after(b"burn");
    let unknown_outcome = budget_after(b"no_such_function");
    assert_eq!(burn_outcome.0, Err("invalid_bic_action".to_string()));
    assert_eq!(burn_outcome, unknown_outcome);
}

#[test]
fn burn_destroys_balance_and_writes_record() {
    let holder = Chain::new().wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"5000");

    burn(&chain, &holder.pk, &[b"600", b"PRIME", b"order_A-1"]).unwrap();

    assert_eq!(balance_of(&chain, &holder.pk, b"PRIME"), 4400);
    assert_eq!(balance_of(&chain, &BURN_ADDRESS, b"PRIME"), 600);
    assert_eq!(supply_of(&chain, b"PRIME"), 4400);
    assert_eq!(get_int(&chain, &burned_key(b"PRIME", &holder.pk)), 600);
    assert_eq!(chain.get(&burn_record_key(b"PRIME", &holder.pk, b"order_A-1")), Some(expected_record(b"600", FORKHEIGHT2)));
    assert_eq!(
        burn_record_key(b"PRIME", &holder.pk, b"order_A-1"),
        bcat(&[b"bic:coin:burn:PRIME:", &holder.pk, b":order_A-1"]),
        "backend reads this exact key shape"
    );
}

#[test]
fn ref_is_single_use_per_holder_and_cannot_be_squatted() {
    let probe = Chain::new();
    let holder = probe.wallet(0);
    let attacker = probe.wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk, &attacker.pk], b"1000");

    //attacker front-runs the holder's ref: it only lands under the attacker's own key
    burn(&chain, &attacker.pk, &[b"1", b"PRIME", b"order42"]).unwrap();
    burn(&chain, &holder.pk, &[b"100", b"PRIME", b"order42"]).unwrap();
    assert_eq!(chain.get(&burn_record_key(b"PRIME", &holder.pk, b"order42")), Some(expected_record(b"100", FORKHEIGHT2)));
    assert_eq!(chain.get(&burn_record_key(b"PRIME", &attacker.pk, b"order42")), Some(expected_record(b"1", FORKHEIGHT2)));

    let before = chain.state_digest();
    assert_eq!(burn(&chain, &holder.pk, &[b"100", b"PRIME", b"order42"]), Err("ref_already_used".to_string()));
    assert_eq!(burn(&chain, &holder.pk, &[b"5", b"PRIME", b"order42"]), Err("ref_already_used".to_string()));
    assert_eq!(chain.state_digest(), before);
    assert_eq!(balance_of(&chain, &holder.pk, b"PRIME"), 900);

    burn(&chain, &holder.pk, &[b"100", b"PRIME", b"order43"]).unwrap();
    assert_eq!(balance_of(&chain, &holder.pk, b"PRIME"), 800);
    assert_eq!(get_int(&chain, &burned_key(b"PRIME", &holder.pk)), 200);
}

#[test]
fn only_allowlisted_symbols_are_burnable() {
    let holder = Chain::new().wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"1000");
    chain.put(b"coin:OTHER:totalSupply", b"50");
    chain.put(&bcat(&[b"account:", &holder.pk, b":balance:OTHER"]), b"50");

    let before = chain.state_digest();
    assert_eq!(burn(&chain, &holder.pk, &[b"10", b"OTHER", b"same"]), Err("symbol_not_burnable".to_string()));
    assert_eq!(burn(&chain, &holder.pk, &[b"10", b"AMA", b"same"]), Err("symbol_not_burnable".to_string()));
    assert_eq!(chain.state_digest(), before);
    burn(&chain, &holder.pk, &[b"10", b"PRIME", b"same"]).unwrap();
}

#[test]
fn third_party_soulbound_coin_stays_unburnable_on_testnet() {
    let mut chain = Chain::new();
    let issuer = chain.wallet(0);
    let holder = chain.wallet(0);
    chain.height = FORKHEIGHT2_TESTNET;
    //soulbound and not pausable: the issuer would have no brake if this were burnable
    call_on(&chain, true, &issuer.pk, b"Coin", b"create_and_mint", &[b"ZQXBADGE", b"100", b"9", b"true", b"false", b"true"]).unwrap();
    call_on(&chain, true, &issuer.pk, b"Coin", b"mint", &[&holder.pk, b"5", b"ZQXBADGE"]).unwrap();

    assert_eq!(call_on(&chain, true, &holder.pk, b"Coin", b"burn", &[b"5", b"ZQXBADGE", b"r"]), Err("symbol_not_burnable".to_string()));
    assert_eq!(call_on(&chain, true, &holder.pk, b"Coin", b"transfer", &[&BURN_ADDRESS, b"5", b"ZQXBADGE"]), Err("soulbound".to_string()));
    assert_eq!(balance_of(&chain, &holder.pk, b"ZQXBADGE"), 5);
}

#[test]
fn failure_after_a_write_is_undone_by_apply_revert() {
    let holder = Chain::new().wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"1000");
    //the burn-address credit overflows after the holder debit was already written
    chain.put(&bcat(&[b"account:", &BURN_ADDRESS, b":balance:PRIME"]), i128::MAX.to_string().as_bytes());
    let before = chain.state_digest();

    chain.with_env(&holder.pk, |env| {
        env.testnet = false;
        env.caller_env.tx_hash = TX_HASH;
        let args: Vec<Vec<u8>> = vec![b"10".to_vec(), b"PRIME".to_vec(), b"r1".to_vec()];
        let outcome = catch_unwind(AssertUnwindSafe(|| call_bic(env, b"Coin".to_vec(), b"burn".to_vec(), args, None, None))).map_err(panic_message);
        assert_eq!(outcome, Err("exec_kv_increment_integer_overflow".to_string()));
        assert!(!env.muts_rev.is_empty(), "the holder debit must have been written before the overflow");
        crate::consensus::consensus_kv::revert(env);
    });
    assert_eq!(chain.state_digest(), before);
}

#[test]
fn burn_up_to_exact_balance() {
    let probe = Chain::new();
    let holder = probe.wallet(0);
    let empty = probe.wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"300");

    assert_eq!(burn(&chain, &holder.pk, &[b"301", b"PRIME", b"too_much"]), Err("insufficient_funds".to_string()));
    burn(&chain, &holder.pk, &[b"300", b"PRIME", b"all"]).unwrap();
    assert_eq!(chain.get(&bcat(&[b"account:", &holder.pk, b":balance:PRIME"])), Some(b"0".to_vec()));
    assert_eq!(burn(&chain, &holder.pk, &[b"1", b"PRIME", b"more"]), Err("insufficient_funds".to_string()));
    assert_eq!(burn(&chain, &empty.pk, &[b"1", b"PRIME", b"none"]), Err("insufficient_funds".to_string()));
    assert_eq!(supply_of(&chain, b"PRIME"), 0);
}

#[test]
fn pause_blocks_burn_until_unpaused() {
    let holder = Chain::new().wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"1000");

    call_on(&chain, false, &PRIME_ADMIN_COLD, b"Coin", b"pause", &[b"PRIME", b"true"]).unwrap();
    assert_eq!(burn(&chain, &holder.pk, &[b"1", b"PRIME", b"r1"]), Err("paused".to_string()));
    call_on(&chain, false, &PRIME_ADMIN_COLD, b"Coin", b"pause", &[b"PRIME", b"false"]).unwrap();
    burn(&chain, &holder.pk, &[b"1", b"PRIME", b"r1"]).unwrap();
}

#[test]
fn soulbound_still_blocks_transfers_including_to_burn_address() {
    let probe = Chain::new();
    let holder = probe.wallet(0);
    let other = probe.wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"1000");

    assert_eq!(call_on(&chain, false, &holder.pk, b"Coin", b"transfer", &[&other.pk, b"1", b"PRIME"]), Err("soulbound".to_string()));
    assert_eq!(call_on(&chain, false, &holder.pk, b"Coin", b"transfer", &[&BURN_ADDRESS, b"1", b"PRIME"]), Err("soulbound".to_string()));
    burn(&chain, &holder.pk, &[b"1", b"PRIME", b"r1"]).unwrap();
}

#[test]
fn burn_rejects_malformed_args_without_state_change() {
    let holder = Chain::new().wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"1000");
    chain.fund(&holder.pk, 1_000_000_000);
    let max_ref = vec![b'a'; MAX_BURN_REF_LEN];
    let long_ref = vec![b'a'; MAX_BURN_REF_LEN + 1];
    let padded_amount = bcat(&[&[b'0'; 47], b"5"]);
    let i128_max = i128::MAX.to_string();

    let before = chain.state_digest();
    let rejects = |args: &[&[u8]], expected: &str| {
        assert_eq!(burn(&chain, &holder.pk, args), Err(expected.to_string()), "args {:?}", args);
    };
    rejects(&[b"1", b"PRIME"], "invalid_args");
    rejects(&[b"1", b"PRIME", b"r", b"extra"], "invalid_args");
    rejects(&[b"0", b"PRIME", b"r"], "invalid_amount");
    rejects(&[b"-1", b"PRIME", b"r"], "invalid_amount");
    rejects(&[b"+5", b"PRIME", b"r"], "invalid_amount");
    rejects(&[b"05", b"PRIME", b"r"], "invalid_amount");
    rejects(&[b" 5", b"PRIME", b"r"], "invalid_amount");
    rejects(&[b"5 ", b"PRIME", b"r"], "invalid_amount");
    rejects(&[b"5.0", b"PRIME", b"r"], "invalid_amount");
    rejects(&[b"1e3", b"PRIME", b"r"], "invalid_amount");
    rejects(&[&padded_amount, b"PRIME", b"r"], "invalid_amount");
    rejects(&[b"170141183460469231731687303715884105728", b"PRIME", b"r"], "invalid_amount");
    rejects(&[i128_max.as_bytes(), b"PRIME", b"r"], "insufficient_funds");
    rejects(&[b"1", b"AMA", b"r"], "symbol_not_burnable");
    rejects(&[b"1", b"PR-ME", b"r"], "invalid_symbol");
    rejects(&[b"1", b"", b"r"], "symbol_too_short");
    rejects(&[b"1", b"prime", b"r"], "symbol_not_burnable");
    rejects(&[b"1", b"NOPE", b"r"], "symbol_not_burnable");
    rejects(&[b"1", b"PRIME", b""], "invalid_ref");
    rejects(&[b"1", b"PRIME", &long_ref], "invalid_ref");
    rejects(&[b"1", b"PRIME", b"a:b"], "invalid_ref");
    rejects(&[b"1", b"PRIME", b"a b"], "invalid_ref");
    rejects(&[b"1", b"PRIME", b"a/b"], "invalid_ref");
    rejects(&[b"1", b"PRIME", "caf\u{e9}".as_bytes()], "invalid_ref");
    assert_eq!(chain.state_digest(), before);

    burn(&chain, &holder.pk, &[b"1", b"PRIME", &max_ref]).unwrap();
    assert_eq!(balance_of(&chain, &holder.pk, b"AMA"), 1_000_000_000);
}

#[test]
fn view_dry_run_reports_would_succeed_as_write_refusal() {
    let holder = Chain::new().wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"1000");
    let dry_run = |args: &[&[u8]]| {
        let args: Vec<Vec<u8>> = args.iter().map(|arg| arg.to_vec()).collect();
        catch_unwind(AssertUnwindSafe(|| {
            chain.with_env(&holder.pk, |env| {
                env.testnet = false;
                env.readonly = true;
                call_bic(env, b"Coin".to_vec(), b"burn".to_vec(), args, None, None);
            })
        }))
        .map_err(panic_message)
    };
    let before = chain.state_digest();
    assert_eq!(dry_run(&[b"10", b"PRIME", b"r1"]), Err("exec_cannot_write_during_view".to_string()));
    assert_eq!(dry_run(&[b"5000", b"PRIME", b"r1"]), Err("insufficient_funds".to_string()));
    assert_eq!(chain.state_digest(), before);
}

#[test]
fn worst_case_burn_fits_default_tx_budget() {
    let holder = Chain::new().wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], MAX_MINT_PER_CALL.to_string().as_bytes());
    let max_ref = vec![b'z'; MAX_BURN_REF_LEN];
    let amount = (MAX_MINT_PER_CALL / 2).to_string();
    let second_amount = (MAX_MINT_PER_CALL / 4).to_string();
    let storage_start = protocol::TX_BUDGET - protocol::TX_EXEC_LOCK - 400 * protocol::COST_PER_BYTE_HISTORICAL;

    let metered = |amount: &[u8], burn_ref: &[u8]| {
        let args: Vec<Vec<u8>> = vec![amount.to_vec(), b"PRIME".to_vec(), burn_ref.to_vec()];
        chain.with_env(&holder.pk, |env| {
            env.testnet = false;
            env.caller_env.tx_hash = TX_HASH;
            env.exec_track = true;
            env.exec_left = protocol::TX_EXEC_LOCK;
            env.storage_left = storage_start;
            call_bic(env, b"Coin".to_vec(), b"burn".to_vec(), args, None, None);
            (protocol::TX_EXEC_LOCK - env.exec_left, storage_start - env.storage_left)
        })
    };
    //first burn ever: creates the burn-address balance, the counter and the record
    let (first_exec, first_storage) = metered(amount.as_bytes(), &max_ref);
    let (second_exec, second_storage) = metered(second_amount.as_bytes(), b"second");
    assert!(first_exec < 300_000, "exec {}", first_exec);
    assert!(first_storage < 5_000_000, "storage {}", first_storage);
    assert!(second_exec < 300_000, "exec {}", second_exec);
    assert!(second_storage < first_storage, "{} >= {}", second_storage, first_storage);
}

#[test]
fn supply_and_counters_stay_consistent() {
    let probe = Chain::new();
    let holders = [probe.wallet(0), probe.wallet(0), probe.wallet(0)];
    let holder_pks: Vec<&[u8]> = holders.iter().map(|holder| holder.pk.as_slice()).collect();
    let chain = mainnet_with_prime(&holder_pks, b"10000");
    let minted = 30_000i128;

    let mut burned_by = [0i128; 3];
    for round in 0..12usize {
        let index = round % 3;
        let amount = ((round as i128) * 37 + 11) % 400 + 1;
        let burn_ref = format!("round{}", round);
        burn(&chain, &holders[index].pk, &[amount.to_string().as_bytes(), b"PRIME", burn_ref.as_bytes()]).unwrap();
        burned_by[index] += amount;
        if round == 5 {
            call_on(&chain, false, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[&holders[0].pk, b"500", b"PRIME"]).unwrap();
        }
    }
    let minted = minted + 500;

    let holder_total: i128 = holders.iter().map(|holder| balance_of(&chain, &holder.pk, b"PRIME")).sum();
    let burnt = balance_of(&chain, &BURN_ADDRESS, b"PRIME");
    assert_eq!(supply_of(&chain, b"PRIME"), holder_total);
    assert_eq!(minted - burnt, supply_of(&chain, b"PRIME"));
    for (index, holder) in holders.iter().enumerate() {
        assert_eq!(get_int(&chain, &burned_key(b"PRIME", &holder.pk)), burned_by[index]);
    }
    assert_eq!(burned_by.iter().sum::<i128>(), burnt);
}

#[test]
fn burns_apply_identically_across_nodes() {
    let mut cluster = Cluster::new(3, 100_000);
    let holder = cluster.nodes[0].wallet(0);
    for node in &mut cluster.nodes {
        node.height = FORKHEIGHT2;
        node.with_env(&[0u8; 48], |env| {
            env.testnet = false;
            issue_prime(env);
        });
        call_on(node, false, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[&holder.pk, b"1000", b"PRIME"]).unwrap();
    }
    let calls: [(&[u8], &[u8]); 4] = [(b"100", b"a"), (b"100", b"a"), (b"5000", b"b"), (b"900", b"c")];
    for (amount, burn_ref) in calls {
        let outcomes: Vec<Result<(), String>> = cluster.nodes.iter().map(|node| burn(node, &holder.pk, &[amount, b"PRIME", burn_ref])).collect();
        assert!(outcomes.iter().all(|outcome| outcome == &outcomes[0]), "nodes diverged: {:?}", outcomes);
    }
    cluster.assert_in_sync();
    assert_eq!(balance_of(&cluster.nodes[0], &holder.pk, b"PRIME"), 0);
}

#[test]
fn contract_caller_burns_only_its_own_balance() {
    let probe = Chain::new();
    let holder = probe.wallet(0);
    let contract = probe.wallet(0);
    let chain = mainnet_with_prime(&[&holder.pk], b"1000");

    //as in a wasm import_call: origin is the user, caller is the contract
    let burn_via_contract = |amount: &[u8], burn_ref: &[u8]| {
        let args: Vec<Vec<u8>> = vec![amount.to_vec(), b"PRIME".to_vec(), burn_ref.to_vec()];
        catch_unwind(AssertUnwindSafe(|| {
            chain.with_env(&holder.pk, |env| {
                env.testnet = false;
                env.caller_env.account_caller = contract.pk.to_vec();
                call_bic(env, b"Coin".to_vec(), b"burn".to_vec(), args, None, None);
            })
        }))
        .map_err(panic_message)
    };

    assert_eq!(burn_via_contract(b"10", b"order1"), Err("insufficient_funds".to_string()));
    assert_eq!(balance_of(&chain, &holder.pk, b"PRIME"), 1000);
    assert_eq!(chain.get(&burned_key(b"PRIME", &holder.pk)), None);
    assert_eq!(chain.get(&burn_record_key(b"PRIME", &holder.pk, b"order1")), None);

    call_on(&chain, false, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[&contract.pk, b"50", b"PRIME"]).unwrap();
    burn_via_contract(b"10", b"order1").unwrap();
    assert_eq!(balance_of(&chain, &holder.pk, b"PRIME"), 1000);
    assert_eq!(balance_of(&chain, &contract.pk, b"PRIME"), 40);
    assert!(chain.get(&burn_record_key(b"PRIME", &contract.pk, b"order1")).is_some());
    assert_eq!(chain.get(&burn_record_key(b"PRIME", &holder.pk, b"order1")), None);
}
