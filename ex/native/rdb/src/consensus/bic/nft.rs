use crate::consensus::bic::coin::BURN_ADDRESS;
use crate::consensus::consensus_kv::{kv_delete, kv_get, kv_increment, kv_put};
use crate::{bcat, consensus};
use std::panic::panic_any;
use vecpak::{decode, Term};

pub fn balance_burnt(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8], token: &[u8]) -> i128 {
    balance(env, &BURN_ADDRESS, collection, token)
}

pub fn balance(env: &mut crate::consensus::consensus_apply::ApplyEnv, address: &[u8], collection: &[u8], token: &[u8]) -> i128 {
    match kv_get(env, &bcat(&[b"account:", address, b":nft:", collection, b":", token])) {
        Some(amount) => std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_balance")),
        None => 0,
    }
}

pub fn total_supply(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8], token: &[u8]) -> i128 {
    match kv_get(env, &bcat(&[b"nft:", collection, b":", token, b":totalSupply"])) {
        Some(amount) => std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_total_supply")),
        None => 0,
    }
}

pub fn collection_exists(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8]) -> bool {
    kv_get(env, &bcat(&[b"nft:", collection, b":permission"])).is_some()
}

pub fn collection_soulbound(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"nft:", collection, b":soulbound"])).as_deref() {
        Some(b"true") => true,
        _ => false,
    }
}

pub fn collection_nonfungible(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8]) -> bool {
    matches!(kv_get(env, &bcat(&[b"nft:", collection, b":nonfungible"])).as_deref(), Some(b"true"))
}

pub fn token_exists(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8], token: &[u8]) -> bool {
    kv_get(env, &bcat(&[b"nft:", collection, b":", token, b":totalSupply"])).is_some()
}

pub fn token_soulbound(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8], token: &[u8]) -> bool {
    matches!(kv_get(env, &bcat(&[b"nft:", collection, b":", token, b":soulbound"])).as_deref(), Some(b"true"))
}

pub fn has_permission(env: &mut crate::consensus::consensus_apply::ApplyEnv, collection: &[u8], signer: &[u8]) -> bool {
    consensus::bic::permission::has(env, &bcat(&[b"nft:", collection, b":permission"]), signer)
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

    transfer(env, receiver, amount, collection, token);
}

//Keep transfer policy and state mutation together for direct NFT transfers.
pub fn transfer(env: &mut crate::consensus::consensus_apply::ApplyEnv, receiver: &[u8], amount: i128, collection: &[u8], token: &[u8]) {
    if !collection_exists(env, collection) {
        panic_any("collection_doesnt_exist")
    }
    if !token_exists(env, collection, token) {
        panic_any("token_doesnt_exist")
    }

    if receiver.len() != 48 {
        panic_any("invalid_receiver_pk")
    }
    if !(consensus::bls12_381::validate_public_key(receiver) || receiver == &BURN_ADDRESS) {
        panic_any("invalid_receiver_pk")
    }
    if amount <= 0 {
        panic_any("invalid_amount")
    }
    let caller = env.caller_env.account_caller.clone();
    let sender_balance = balance(env, &caller, collection, token);
    if amount > sender_balance {
        panic_any("insufficient_tokens")
    }

    if collection_soulbound(env, collection) || token_soulbound(env, collection, token) {
        panic_any("soulbound")
    }

    let sender_key = bcat(&[b"account:", &caller, b":nft:", collection, b":", token]);
    if amount == sender_balance && receiver != caller {
        kv_delete(env, &sender_key);
    } else {
        kv_increment(env, &sender_key, -amount);
    }
    kv_increment(env, &bcat(&[b"account:", receiver, b":nft:", collection, b":", token]), amount);

    if receiver == &BURN_ADDRESS {
        kv_increment(env, &bcat(&[b"nft:", collection, b":", token, b":totalSupply"]), -amount);
    }
}

pub fn validate_collection(collection: &[u8]) {
    crate::consensus::bic::coin::validate_name(collection, "invalid_collection", "collection_too_short", "collection_too_long")
}

pub fn validate_token(token: &[u8]) {
    crate::consensus::bic::coin::validate_name(token, "invalid_token", "token_too_short", "token_too_long")
}

fn decode_binary_map(args: Vec<Vec<u8>>, expected_keys: &[&[u8]]) -> Vec<(Vec<u8>, Vec<u8>)> {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let Term::PropList(pairs) = decode(&args[0]).unwrap_or_else(|_| panic_any("invalid_args")) else { panic_any("invalid_args") };
    let mut decoded = Vec::with_capacity(pairs.len());
    for (key, value) in pairs {
        let Term::Binary(key) = key else { panic_any("invalid_args") };
        let Term::Binary(value) = value else { panic_any("invalid_args") };
        if !expected_keys.iter().any(|expected| key == *expected) {
            panic_any("unknown_arg")
        }
        if decoded.iter().any(|(existing, _)| existing == &key) {
            panic_any("invalid_args")
        }
        decoded.push((key, value));
    }
    if decoded.len() != expected_keys.len() {
        panic_any("invalid_args")
    }
    decoded
}

fn map_value<'a>(args: &'a [(Vec<u8>, Vec<u8>)], key: &[u8]) -> &'a [u8] {
    args.iter().find(|(candidate, _)| candidate == key).map(|(_, value)| value.as_slice()).unwrap_or_else(|| panic_any("invalid_args"))
}

fn parse_bool(value: &[u8], error: &'static str) -> bool {
    match value {
        b"true" => true,
        b"false" => false,
        _ => panic_any(error),
    }
}

pub fn call_create_collection(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    let args = decode_binary_map(args, &[b"collection", b"soulbound", b"nonfungible"]);
    let collection_original = map_value(&args, b"collection");
    let is_soulbound = parse_bool(map_value(&args, b"soulbound"), "invalid_soulbound");
    let is_nonfungible = parse_bool(map_value(&args, b"nonfungible"), "invalid_nonfungible");

    validate_collection(collection_original);
    let collection = collection_original.to_vec();

    if !consensus::bic::coin_symbol_reserved::is_free(&collection, &env.caller_env.account_caller) {
        panic_any("collection_reserved")
    }
    if consensus::bic::coin::exists(env, &collection) {
        panic_any("collection_conflicts_with_coin")
    }
    if collection_exists(env, &collection) {
        panic_any("collection_exists")
    }

    let permission_key = bcat(&[b"nft:", &collection, b":permission"]);
    let admin = env.caller_env.account_caller.clone();
    consensus::bic::permission::initialize(env, &permission_key, &admin);

    if is_soulbound {
        kv_put(env, &bcat(&[b"nft:", &collection, b":soulbound"]), b"true")
    }
    if is_nonfungible {
        kv_put(env, &bcat(&[b"nft:", &collection, b":nonfungible"]), b"true")
    }
}

pub fn call_update_permission(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    let update = consensus::bic::permission::decode_update(args, b"collection", "invalid_collection");
    validate_collection(&update.identifier);
    if !collection_exists(env, &update.identifier) {
        panic_any("collection_doesnt_exist")
    }
    let permission_key = bcat(&[b"nft:", &update.identifier, b":permission"]);
    let caller = env.caller_env.account_caller.clone();
    consensus::bic::permission::apply_update(env, &permission_key, &caller, update);
}

pub fn call_mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    let args = decode_binary_map(args, &[b"receiver", b"amount", b"collection", b"token", b"soulbound"]);
    let receiver = map_value(&args, b"receiver");
    let amount = map_value(&args, b"amount");
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_amount"));
    let collection = map_value(&args, b"collection");
    let token = map_value(&args, b"token");
    let is_soulbound = parse_bool(map_value(&args, b"soulbound"), "invalid_soulbound");
    if receiver.len() != 48 {
        panic_any("invalid_receiver_pk")
    }
    validate_collection(collection);
    validate_token(token);

    if !collection_exists(env, collection) {
        panic_any("collection_doesnt_exist")
    }
    if !has_permission(env, collection, &env.caller_env.account_caller.clone()) {
        panic_any("no_permissions")
    }

    mint(env, receiver, amount, collection, token, is_soulbound);
}

pub fn mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, receiver: &[u8], amount: i128, collection: &[u8], token: &[u8], is_soulbound: bool) {
    if !(consensus::bls12_381::validate_public_key(receiver)) {
        panic_any("invalid_receiver_pk")
    }
    if amount <= 0 {
        panic_any("invalid_amount")
    }

    if !collection_exists(env, &collection) {
        panic_any("collection_doesnt_exist")
    }

    let supply_key = bcat(&[b"nft:", collection, b":", token, b":totalSupply"]);
    let already_minted = token_exists(env, collection, token);
    if collection_nonfungible(env, collection) {
        if amount != 1 {
            panic_any("nonfungible_amount_must_be_one")
        }
        if already_minted {
            panic_any("nonfungible_token_already_minted")
        }
    }

    if already_minted {
        if token_soulbound(env, collection, token) != is_soulbound {
            panic_any("token_soulbound_immutable")
        }
    } else if is_soulbound {
        kv_put(env, &bcat(&[b"nft:", collection, b":", token, b":soulbound"]), b"true");
    }

    kv_increment(env, &bcat(&[b"account:", receiver, b":nft:", collection, b":", token]), amount);
    kv_increment(env, &supply_key, amount);
}
