use crate::consensus::bic::coin::BURN_ADDRESS;
use crate::consensus::consensus_kv::{kv_exists, kv_get, kv_increment, kv_put};
use crate::{bcat, consensus};
use std::panic::panic_any;
use vecpak::{decode, encode, Term};

pub fn balance_burnt(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8], token: &[u8]) -> i128 {
    balance(env, &BURN_ADDRESS, collection, token)
}

pub fn balance(env: &mut crate::consensus::consensus_apply::ApplyEnv, address: &[u8], collection: &[u8], token: &[u8]) -> i128 {
    match kv_get(env, &bcat(&[b"account:", address, b":nft:", collection, b":", token])) {
        Some(amount) => std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_balance")),
        None => 0,
    }
}

pub fn view_account(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8]) -> Option<Vec<u8>> {
    kv_get(env, &bcat(&[b"nft:", collection, b":view_account"]))
}

pub fn exists(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8]) -> bool {
    kv_get(env, &bcat(&[b"nft:", collection, b":view_account"])).is_some()
}

pub fn soulbound(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"nft:", collection, b":soulbound"])).as_deref() {
        Some(b"true") => true,
        _ => false,
    }
}

pub fn has_permission(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8], signer: &[u8]) -> bool {
    match view_account(env, collection) {
        None => false,
        Some(account) => account == signer,
    }
}

pub fn call_transfer(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 4 {
        panic_any("invalid_args")
    }
    let receiver = args[0].as_slice();
    let amount = args[1].as_slice();
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_amount"));
    let collection = args[2].as_slice();
    let token = args[3].as_slice();

    if receiver.len() != 48 {
        panic_any("invalid_receiver_pk")
    }
    if !(consensus::bls12_381::validate_public_key(receiver) || receiver == &BURN_ADDRESS) {
        panic_any("invalid_receiver_pk")
    }
    if amount <= 0 {
        panic_any("invalid_amount")
    }
    if amount > balance(env, &env.caller_env.account_caller.clone(), &collection, &token) {
        panic_any("insufficient_tokens")
    }

    if soulbound(env, collection) {
        panic_any("soulbound")
    }

    kv_increment(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":nft:", collection, b":", token]), -amount);
    kv_increment(env, &bcat(&[b"account:", receiver, b":nft:", collection, b":", token]), amount);
}

pub fn validate_collection(collection: &[u8]) {
    crate::consensus::bic::coin::validate_name(collection, "invalid_collection", "collection_too_short", "collection_too_long")
}

pub fn call_create_collection(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() < 2 {
        panic_any("invalid_args")
    }
    let collection_original = args[0].as_slice();
    let soulbound = args.get(1).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"false");

    validate_collection(collection_original);
    let collection = collection_original.to_vec();

    if !consensus::bic::coin_symbol_reserved::is_free(&collection, &env.caller_env.account_caller) {
        panic_any("collection_reserved")
    }
    if exists(env, &collection) {
        panic_any("collection_exists")
    }

    kv_put(env, &bcat(&[b"nft:", &collection, b":view_account"]), &env.caller_env.account_caller.clone());

    if soulbound == b"true" {
        kv_put(env, &bcat(&[b"nft:", &collection, b":soulbound"]), b"true")
    }
}

pub fn call_mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 4 {
        panic_any("invalid_args")
    }
    let receiver = args[0].as_slice();
    let amount = args[1].as_slice();
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_amount"));
    let collection = args[2].as_slice();
    let token = args[3].as_slice();
    if receiver.len() != 48 {
        panic_any("invalid_receiver_pk")
    }

    if token.len() < 1 {
        panic_any("token_too_short")
    }
    if token.len() > 32 {
        panic_any("token_too_long")
    }

    match view_account(env, collection) {
        None => panic_any("collection_doesnt_exist"),
        Some(account) => {
            if account != env.caller_env.account_caller {
                panic_any("no_permissions")
            }
        }
    }

    mint(env, receiver, amount, collection, token);
}

pub fn mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, receiver: &[u8], amount: i128, collection: &[u8], token: &[u8]) {
    if !(consensus::bls12_381::validate_public_key(receiver)) {
        panic_any("invalid_receiver_pk")
    }
    if amount <= 0 {
        panic_any("invalid_amount")
    }

    if !exists(env, &collection) {
        panic_any("collection_doesnt_exist")
    }

    kv_increment(env, &bcat(&[b"account:", receiver, b":nft:", collection, b":", token]), amount);
}
