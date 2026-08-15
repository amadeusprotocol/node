#![cfg(test)]

//PRIME issuance fork: the symbol is created once at the boundary into the
//per-network issuance epoch (792 mainnet, 462 testnet) with the cold/hot admin
//keys on the permission list — admin-mintable, pausable, soulbound. The
//LockupPrime vault stays testnet-only.

use crate::bcat;
use crate::consensus::bic::prime::{PRIME_ADMIN_COLD, PRIME_ADMIN_HOT, PRIME_ADMIN_HOT_2, PRIME_ISSUANCE_EPOCH, PRIME_ISSUANCE_EPOCH_TESTNET};
use crate::consensus::consensus_apply::call_bic;
use crate::consensus::tests::chain_harness::{panic_message, Chain};
use std::panic::{catch_unwind, AssertUnwindSafe};
use vecpak::{decode, encode, Term};

//epoch::next on the last height of the current epoch, with env.testnet cleared
//so the mainnet-only issuance path runs (the harness defaults to testnet)
fn run_mainnet_boundary(chain: &mut Chain) {
    if chain.get(b"bic:epoch:diff_bits").is_none() {
        chain.put(b"bic:epoch:diff_bits", b"24");
    }
    chain.height = (chain.epoch() + 1) * 100_000 - 1;
    chain.with_env(&[0u8; 48], |env| {
        env.testnet = false;
        crate::consensus::bic::epoch::next(env);
    });
    chain.height += 1;
}

fn call_mainnet(chain: &Chain, signer: &[u8], contract: &[u8], function: &[u8], args: &[&[u8]]) -> Result<(), String> {
    let args: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
    catch_unwind(AssertUnwindSafe(|| {
        chain.with_env(signer, |env| {
            env.testnet = false;
            call_bic(env, contract.to_vec(), function.to_vec(), args.clone(), None, None);
        })
    }))
    .map_err(panic_message)
}

fn prime_balance(chain: &Chain, addr: &[u8]) -> i128 {
    chain.get(&bcat(&[b"account:", addr, b":balance:PRIME"])).and_then(|v| atoi::atoi::<i128>(&v)).unwrap_or(0)
}

fn encode_admins(admins: &[&[u8]]) -> Vec<u8> {
    encode(Term::List(admins.iter().map(|admin| Term::Binary(admin.to_vec())).collect())).expect("vecpak encode")
}

fn encode_permission_update(add: &[&[u8]], remove: &[&[u8]], symbol: &[u8]) -> Vec<u8> {
    let addresses = |items: &[&[u8]]| Term::List(items.iter().map(|item| Term::Binary(item.to_vec())).collect());
    encode(Term::PropList(vec![
        (Term::Binary(b"add".to_vec()), addresses(add)),
        (Term::Binary(b"remove".to_vec()), addresses(remove)),
        (Term::Binary(b"symbol".to_vec()), Term::Binary(symbol.to_vec())),
    ]))
    .expect("vecpak encode")
}

fn coin_permissions(chain: &Chain, symbol: &[u8]) -> Vec<Vec<u8>> {
    let encoded = chain.get(&bcat(&[b"coin:", symbol, b":permission"])).expect("permission list missing");
    let Term::List(admins) = decode(&encoded).expect("invalid permission list") else { panic!("permission list is not a list") };
    admins
        .into_iter()
        .map(|admin| match admin {
            Term::Binary(admin) => admin,
            _ => panic!("permission entry is not a binary"),
        })
        .collect()
}

#[test]
fn prime_admin_keys_are_valid_bls_pubkeys() {
    assert!(crate::consensus::bls12_381::validate_public_key(&PRIME_ADMIN_COLD), "cold admin key invalid");
    assert!(crate::consensus::bls12_381::validate_public_key(&PRIME_ADMIN_HOT), "hot admin key invalid");
    assert!(crate::consensus::bls12_381::validate_public_key(&PRIME_ADMIN_HOT_2), "second hot admin key invalid");
    assert_ne!(PRIME_ADMIN_COLD, PRIME_ADMIN_HOT);
    assert_ne!(PRIME_ADMIN_HOT, PRIME_ADMIN_HOT_2);
}

#[test]
fn prime_issued_at_fork_boundary_with_admin_keys() {
    let mut chain = Chain::new();
    chain.height = (PRIME_ISSUANCE_EPOCH - 1) * 100_000;
    run_mainnet_boundary(&mut chain);

    assert_eq!(chain.get(b"coin:PRIME:totalSupply"), Some(b"0".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:mintable"), Some(b"true".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:pausable"), Some(b"true".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:soulbound"), Some(b"true".to_vec()));
    //not paused at issuance; paused is runtime state the admins toggle later
    assert_eq!(chain.get(b"coin:PRIME:paused"), None);

    let perm = chain.get(b"coin:PRIME:permission").expect("permission list missing");
    match decode(perm.as_slice()).unwrap() {
        Term::List(admins) => {
            let pks: Vec<Vec<u8>> = admins
                .into_iter()
                .map(|t| match t {
                    Term::Binary(b) => b,
                    _ => panic!("admin entry not a binary"),
                })
                .collect();
            assert_eq!(pks, vec![PRIME_ADMIN_COLD.to_vec(), PRIME_ADMIN_HOT.to_vec(), PRIME_ADMIN_HOT_2.to_vec()]);
        }
        _ => panic!("permission list not a vecpak list"),
    }
}

#[test]
fn prime_admins_mint_and_pause_holders_cannot_move_it() {
    let mut chain = Chain::new();
    chain.height = (PRIME_ISSUANCE_EPOCH - 1) * 100_000;
    let user = chain.wallet(0);
    let other = chain.wallet(0);

    //before the fork boundary Coin.mint is not dispatched on mainnet at all
    let err = call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[&user.pk, b"5000", b"PRIME"]);
    assert_eq!(err, Err("invalid_bic_action".to_string()));

    run_mainnet_boundary(&mut chain);

    //every canonical mainnet admin key can mint
    call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[&user.pk, b"5000", b"PRIME"]).unwrap();
    call_mainnet(&chain, &PRIME_ADMIN_HOT, b"Coin", b"mint", &[&user.pk, b"1000", b"PRIME"]).unwrap();
    call_mainnet(&chain, &PRIME_ADMIN_HOT_2, b"Coin", b"mint", &[&user.pk, b"1000", b"PRIME"]).unwrap();
    assert_eq!(prime_balance(&chain, &user.pk), 7000);
    assert_eq!(chain.get(b"coin:PRIME:totalSupply"), Some(b"7000".to_vec()));

    //non-admins cannot mint, holders cannot transfer (soulbound)
    let err = call_mainnet(&chain, &user.pk, b"Coin", b"mint", &[&user.pk, b"5000", b"PRIME"]);
    assert_eq!(err, Err("no_permissions".to_string()));
    let err = call_mainnet(&chain, &user.pk, b"Coin", b"transfer", &[&other.pk, b"100", b"PRIME"]);
    assert_eq!(err, Err("soulbound".to_string()));

    //pause halts minting until an admin unpauses
    call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"pause", &[b"PRIME", b"true"]).unwrap();
    let err = call_mainnet(&chain, &PRIME_ADMIN_HOT, b"Coin", b"mint", &[&user.pk, b"1", b"PRIME"]);
    assert_eq!(err, Err("paused".to_string()));
    call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"pause", &[b"PRIME", b"false"]).unwrap();
    call_mainnet(&chain, &PRIME_ADMIN_HOT, b"Coin", b"mint", &[&user.pk, b"1", b"PRIME"]).unwrap();
    assert_eq!(prime_balance(&chain, &user.pk), 7001);
}

#[test]
fn prime_permissions_rotate_atomically_on_mainnet() {
    let mut chain = Chain::new();
    chain.height = (PRIME_ISSUANCE_EPOCH - 1) * 100_000;
    let new_hot = chain.wallet(0);
    let outsider = chain.wallet(0);
    let receiver = chain.wallet(0);
    let update = encode_permission_update(&[&new_hot.pk], &[&PRIME_ADMIN_HOT], b"PRIME");

    //The entry point is not available until the same boundary that creates
    //PRIME and enables mint/pause.
    assert_eq!(call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"update_permission", &[&update]), Err("invalid_bic_action".to_string()));
    run_mainnet_boundary(&mut chain);

    assert_eq!(call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"update_permission", &[&update, &update]), Err("invalid_args".to_string()));

    //A non-admin cannot rotate the list.
    assert_eq!(call_mainnet(&chain, &outsider.pk, b"Coin", b"update_permission", &[&update]), Err("no_permissions".to_string()));

    //One call adds the replacement and removes the old HOT admin.
    call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"update_permission", &[&update]).unwrap();
    assert_eq!(coin_permissions(&chain, b"PRIME"), vec![PRIME_ADMIN_COLD.to_vec(), PRIME_ADMIN_HOT_2.to_vec(), new_hot.pk.to_vec()]);

    assert_eq!(call_mainnet(&chain, &PRIME_ADMIN_HOT, b"Coin", b"mint", &[&receiver.pk, b"1", b"PRIME"],), Err("no_permissions".to_string()));
    call_mainnet(&chain, &new_hot.pk, b"Coin", b"mint", &[&receiver.pk, b"1", b"PRIME"]).unwrap();

    //An existing admin may replace itself, but cannot empty the list. Failed
    //updates leave the permission list unchanged.
    let remove_all = encode_permission_update(&[], &[&PRIME_ADMIN_COLD, &PRIME_ADMIN_HOT_2, &new_hot.pk], b"PRIME");
    assert_eq!(call_mainnet(&chain, &new_hot.pk, b"Coin", b"update_permission", &[&remove_all]), Err("permissions_cannot_be_empty".to_string()));
    assert_eq!(coin_permissions(&chain, b"PRIME"), vec![PRIME_ADMIN_COLD.to_vec(), PRIME_ADMIN_HOT_2.to_vec(), new_hot.pk.to_vec()]);

    let overlap = encode_permission_update(&[&PRIME_ADMIN_COLD], &[&PRIME_ADMIN_COLD], b"PRIME");
    assert_eq!(call_mainnet(&chain, &new_hot.pk, b"Coin", b"update_permission", &[&overlap]), Err("permission_update_overlap".to_string()));
    assert_eq!(coin_permissions(&chain, b"PRIME"), vec![PRIME_ADMIN_COLD.to_vec(), PRIME_ADMIN_HOT_2.to_vec(), new_hot.pk.to_vec()]);

    let invalid_admin = encode_permission_update(&[&[1u8; 48]], &[], b"PRIME");
    assert_eq!(call_mainnet(&chain, &new_hot.pk, b"Coin", b"update_permission", &[&invalid_admin]), Err("invalid_permission_pk".to_string()));
    assert_eq!(coin_permissions(&chain, b"PRIME"), vec![PRIME_ADMIN_COLD.to_vec(), PRIME_ADMIN_HOT_2.to_vec(), new_hot.pk.to_vec()]);
}

#[test]
fn permission_update_requires_symbol_to_exist() {
    let mut chain = Chain::new();
    chain.height = PRIME_ISSUANCE_EPOCH * 100_000;
    let update = encode_permission_update(&[], &[], b"MISSING");

    assert_eq!(call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"update_permission", &[&update]), Err("symbol_doesnt_exist".to_string()));
}

#[test]
fn permission_update_applies_to_any_existing_coin() {
    let mut chain = Chain::new();
    chain.height = (PRIME_ISSUANCE_EPOCH - 1) * 100_000;
    run_mainnet_boundary(&mut chain);
    let original_admin = chain.wallet(0);
    let new_admin = chain.wallet(0);
    let receiver = chain.wallet(0);

    //Model a coin created before or after this fork. The permission updater is
    //keyed by the supplied symbol and has no PRIME-specific state dependency.
    chain.put(b"coin:FUTURE:totalSupply", b"0");
    chain.put(b"coin:FUTURE:mintable", b"true");
    let initial_permissions = encode_admins(&[&original_admin.pk]);
    chain.put(b"coin:FUTURE:permission", &initial_permissions);

    let update = encode_permission_update(&[&new_admin.pk], &[&original_admin.pk], b"FUTURE");
    call_mainnet(&chain, &original_admin.pk, b"Coin", b"update_permission", &[&update]).unwrap();
    assert_eq!(coin_permissions(&chain, b"FUTURE"), vec![new_admin.pk.to_vec()]);

    assert_eq!(call_mainnet(&chain, &original_admin.pk, b"Coin", b"mint", &[&receiver.pk, b"1", b"FUTURE"],), Err("no_permissions".to_string()));
    call_mainnet(&chain, &new_admin.pk, b"Coin", b"mint", &[&receiver.pk, b"1", b"FUTURE"]).unwrap();
    assert_eq!(chain.get(&bcat(&[b"account:", &receiver.pk, b":balance:FUTURE"])), Some(b"1".to_vec()));
}

#[test]
fn mainnet_fork_does_not_enable_coin_creation_or_unknown_symbol_admin_calls() {
    let mut chain = Chain::new();
    chain.height = (PRIME_ISSUANCE_EPOCH - 1) * 100_000;
    let receiver = chain.wallet(0);
    run_mainnet_boundary(&mut chain);

    //The fork exposes mint/pause only; it does not expose coin creation.
    let err = call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"create_and_mint", &[b"OTHER", b"1", b"9", b"true", b"true", b"false"]);
    assert_eq!(err, Err("invalid_bic_action".to_string()));
    assert_eq!(chain.get(b"coin:OTHER:totalSupply"), None);

    //Without existing coin metadata and permissions, generic mint/pause calls
    //cannot operate on an arbitrary symbol or on AMA.
    let err = call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[&receiver.pk, b"1", b"OTHER"]);
    assert_eq!(err, Err("no_permissions".to_string()));
    let err = call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"pause", &[b"OTHER", b"true"]);
    assert_eq!(err, Err("symbol_doesnt_exist".to_string()));

    let err = call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"mint", &[&receiver.pk, b"1", b"AMA"]);
    assert_eq!(err, Err("no_permissions".to_string()));
    let err = call_mainnet(&chain, &PRIME_ADMIN_COLD, b"Coin", b"pause", &[b"AMA", b"true"]);
    assert_eq!(err, Err("symbol_doesnt_exist".to_string()));
}

#[test]
fn prime_issued_on_testnet_at_its_own_epoch() {
    //testnet issues at its own (earlier) epoch, via the harness default testnet env
    let mut chain = Chain::new();
    let holder = chain.wallet(0);
    let receiver = chain.wallet(0);
    chain.height = (PRIME_ISSUANCE_EPOCH_TESTNET - 1) * 100_000;
    chain.step_epoch();
    assert_eq!(chain.get(b"coin:PRIME:totalSupply"), Some(b"0".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:mintable"), Some(b"true".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:pausable"), Some(b"true".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:soulbound"), Some(b"true".to_vec()));
    assert!(chain.get(b"coin:PRIME:permission").is_some());

    chain.call_as(&PRIME_ADMIN_COLD, b"Coin", b"mint", &[&holder.pk, b"10", b"PRIME"]).unwrap();
    assert_eq!(chain.call(&holder, b"Coin", b"transfer", &[&receiver.pk, b"1", b"PRIME"]), Err("soulbound".to_string()));

    //the mainnet epoch does nothing on testnet, and vice versa
    let mut chain = Chain::new();
    chain.height = (PRIME_ISSUANCE_EPOCH - 1) * 100_000;
    chain.step_epoch();
    assert_eq!(chain.get(b"coin:PRIME:totalSupply"), None);

    let mut chain = Chain::new();
    chain.height = (PRIME_ISSUANCE_EPOCH_TESTNET - 1) * 100_000;
    run_mainnet_boundary(&mut chain);
    assert_eq!(chain.get(b"coin:PRIME:totalSupply"), None);
}

#[test]
fn prime_permission_update_activates_at_testnet_fork() {
    let mut chain = Chain::new();
    chain.height = (PRIME_ISSUANCE_EPOCH_TESTNET - 1) * 100_000;
    let new_hot = chain.wallet(0);
    let receiver = chain.wallet(0);
    let update = encode_permission_update(&[&new_hot.pk], &[&PRIME_ADMIN_HOT], b"PRIME");

    assert_eq!(chain.call_as(&PRIME_ADMIN_COLD, b"Coin", b"update_permission", &[&update]), Err("invalid_bic_action".to_string()));

    chain.step_epoch();
    chain.call_as(&PRIME_ADMIN_COLD, b"Coin", b"update_permission", &[&update]).unwrap();
    assert_eq!(coin_permissions(&chain, b"PRIME"), vec![PRIME_ADMIN_COLD.to_vec(), new_hot.pk.to_vec()]);

    assert_eq!(chain.call_as(&PRIME_ADMIN_HOT, b"Coin", b"mint", &[&receiver.pk, b"1", b"PRIME"],), Err("no_permissions".to_string()));
    chain.call_as(&new_hot.pk, b"Coin", b"mint", &[&receiver.pk, b"1", b"PRIME"]).unwrap();
    assert_eq!(prime_balance(&chain, &receiver.pk), 1);
}

#[test]
fn prime_not_issued_off_epoch() {
    //boundary at any other epoch: nothing happens
    let mut chain = Chain::new();
    chain.height = 500 * 100_000;
    run_mainnet_boundary(&mut chain);
    assert_eq!(chain.get(b"coin:PRIME:totalSupply"), None);
}

#[test]
fn existing_testnet_prime_keeps_supply_and_receives_canonical_config() {
    //Simulate PRIME lazily created by the legacy LockupPrime path. At the
    //testnet fork its supply is preserved, soulbound is enforced, and its
    //permissions are rotated.
    let mut chain = Chain::new();
    chain.put(b"coin:PRIME:totalSupply", b"123");
    chain.put(b"coin:PRIME:mintable", b"true");
    chain.put(b"coin:PRIME:pausable", b"true");
    assert_eq!(chain.get(b"coin:PRIME:soulbound"), None);
    let legacy_permissions = encode(Term::List(vec![Term::Binary(vec![1u8; 48])])).expect("vecpak encode");
    chain.put(b"coin:PRIME:permission", &legacy_permissions);

    chain.height = (PRIME_ISSUANCE_EPOCH_TESTNET - 1) * 100_000;
    chain.step_epoch();

    assert_eq!(chain.get(b"coin:PRIME:totalSupply"), Some(b"123".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:mintable"), Some(b"true".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:pausable"), Some(b"true".to_vec()));
    assert_eq!(chain.get(b"coin:PRIME:soulbound"), Some(b"true".to_vec()));

    let permission = chain.get(b"coin:PRIME:permission").expect("permission list missing");
    assert_eq!(decode(permission.as_slice()).unwrap(), Term::List(vec![Term::Binary(PRIME_ADMIN_COLD.to_vec()), Term::Binary(PRIME_ADMIN_HOT.to_vec())]));
}
