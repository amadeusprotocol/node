use crate::consensus::consensus_kv::{kv_exists, kv_get, kv_increment, kv_put};
use crate::{bcat, consensus};
use std::panic::panic_any;
use vecpak::{decode, encode, Term};

pub const DECIMALS: u32 = 9;
pub const BURN_ADDRESS: [u8; 48] = [0u8; 48];

pub fn to_flat(coins: i128) -> i128 {
    coins.checked_mul(1_000_000_000).expect("i128_overflow")
}
pub fn to_cents(coins: i128) -> i128 {
    coins.checked_mul(10_000_000).expect("i128_overflow")
}
pub fn to_tenthousandth(coins: i128) -> i128 {
    coins.checked_mul(100_000).expect("i128_overflow")
}
pub fn from_flat(coins: i128) -> f64 {
    let whole = (coins / 1_000_000_000) as f64;
    let frac = ((coins % 1_000_000_000).abs() as f64) / 1_000_000_000.0;
    let x = if coins >= 0 { whole + frac } else { whole - frac };
    (x * 1e9).round() / 1e9
}

pub fn balance_burnt(env: &mut crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> i128 {
    balance(env, &BURN_ADDRESS, symbol)
}

pub fn balance(env: &mut crate::consensus::consensus_apply::ApplyEnv, address: &[u8], symbol: &[u8]) -> i128 {
    match kv_get(env, &bcat(&[b"account:", address, b":balance:", symbol])) {
        Some(amount) => std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_balance")),
        None => 0,
    }
}

pub fn mintable(env: &mut crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":mintable"])).as_deref() {
        Some(b"true") => true,
        _ => false,
    }
}

pub fn pausable(env: &mut crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":pausable"])).as_deref() {
        Some(b"true") => true,
        _ => false,
    }
}

pub fn paused(env: &mut crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":paused"])).as_deref() {
        Some(b"true") => pausable(env, symbol),
        _ => false,
    }
}

pub fn soulbound(env: &mut crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":soulbound"])).as_deref() {
        Some(b"true") => true,
        _ => false,
    }
}

pub fn total_supply(env: &mut crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> i128 {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":totalSupply"])) {
        Some(amount) => std::str::from_utf8(&amount).unwrap().parse::<i128>().unwrap_or_else(|_| panic_any("invalid_total_supply")),
        None => 0,
    }
}

pub fn exists(env: &mut crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":totalSupply"])) {
        Some(_) => true,
        None => false,
    }
}

pub fn has_permission(env: &mut crate::consensus::consensus_apply::ApplyEnv, symbol: &[u8], signer: &[u8]) -> bool {
    match kv_get(env, &bcat(&[b"coin:", symbol, b":permission"])) {
        None => false,
        Some(permission_list) => {
            let term = decode(permission_list.as_slice()).unwrap();
            match term {
                Term::List(term_list) => term_list.iter().any(|el| matches!(el, Term::Binary(b) if b.as_slice() == signer)),
                _ => false,
            }
        }
    }
}

pub fn call_transfer(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 3 {
        panic_any("invalid_args")
    }
    let receiver = args[0].as_slice();
    let amount = args[1].as_slice();
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_amount"));
    let symbol = args[2].as_slice();

    if receiver.len() != 48 {
        panic_any("invalid_receiver_pk")
    }
    if !(consensus::bls12_381::validate_public_key(receiver) || receiver == &BURN_ADDRESS) {
        panic_any("invalid_receiver_pk")
    }
    if amount <= 0 {
        panic_any("invalid_amount")
    }
    if amount > balance(env, &env.caller_env.account_caller.clone(), &symbol) {
        panic_any("insufficient_funds")
    }

    if paused(env, symbol) {
        panic_any("paused")
    }
    if soulbound(env, symbol) {
        panic_any("soulbound")
    }

    kv_increment(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":balance:", symbol]), -amount);
    kv_increment(env, &bcat(&[b"account:", receiver, b":balance:", symbol]), amount);

    //Account burnt coins
    if symbol != b"AMA" && receiver == &BURN_ADDRESS {
        kv_increment(env, &bcat(&[b"coin:", symbol, b":totalSupply"]), -amount);
    }
}

pub fn call_create_and_mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() < 2 {
        panic_any("invalid_args")
    }
    let symbol_original = args[0].as_slice();
    let amount = args[1].as_slice();
    let decimals = args.get(2).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"9");
    let mintable = args.get(3).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"false");
    let pausable = args.get(4).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"false");
    let soulbound = args.get(5).and_then(|v| if v.is_empty() { None } else { Some(v.as_slice()) }).unwrap_or(b"false");

    let symbol: Vec<u8> = symbol_original.iter().copied().filter(u8::is_ascii_alphanumeric).collect();
    if symbol_original != symbol.as_slice() {
        panic_any("invalid_symbol")
    }
    if symbol.len() < 1 {
        panic_any("symbol_too_short")
    }
    if symbol.len() > 32 {
        panic_any("symbol_too_long")
    }

    if !consensus::bic::coin_symbol_reserved::is_free(&symbol, &env.caller_env.account_caller) {
        panic_any("symbol_reserved")
    }
    if exists(env, &symbol) {
        panic_any("symbol_exists")
    }

    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_amount"));
    if amount <= 0 {
        panic_any("invalid_amount")
    }

    let decimals = std::str::from_utf8(&decimals).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_decimals"));
    //if decimals < 0 { panic_any("invalid_decimals") }
    if decimals >= 10 {
        panic_any("invalid_decimals")
    }

    kv_increment(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":balance:", &symbol]), amount);
    kv_increment(env, &bcat(&[b"coin:", &symbol, b":totalSupply"]), amount);

    let mut admin = Vec::new();
    admin.push(Term::Binary(env.caller_env.account_caller.to_vec()));
    let buf = encode(Term::List(admin));
    kv_put(env, &bcat(&[b"coin:", &symbol, b":permission"]), &buf);

    if mintable == b"true" {
        kv_put(env, &bcat(&[b"coin:", &symbol, b":mintable"]), b"true")
    }
    if pausable == b"true" {
        kv_put(env, &bcat(&[b"coin:", &symbol, b":pausable"]), b"true")
    }
    if soulbound == b"true" {
        kv_put(env, &bcat(&[b"coin:", &symbol, b":soulbound"]), b"true")
    }
}

pub fn call_mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 3 {
        panic_any("invalid_args")
    }
    let receiver = args[0].as_slice();
    let amount = args[1].as_slice();
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_amount"));
    let symbol = args[2].as_slice();
    if receiver.len() != 48 {
        panic_any("invalid_receiver_pk")
    }

    if !has_permission(env, &symbol, &env.caller_env.account_caller.clone()) {
        panic_any("no_permissions")
    }

    mint(env, receiver, amount, symbol);
}

pub fn mint(env: &mut crate::consensus::consensus_apply::ApplyEnv, receiver: &[u8], amount: i128, symbol: &[u8]) {
    if !(consensus::bls12_381::validate_public_key(receiver)) {
        panic_any("invalid_receiver_pk")
    }
    if amount <= 0 {
        panic_any("invalid_amount")
    }

    if !exists(env, &symbol) {
        panic_any("symbol_doesnt_exist")
    }
    if !mintable(env, &symbol) {
        panic_any("not_mintable")
    }
    if paused(env, &symbol) {
        panic_any("paused")
    }

    kv_increment(env, &bcat(&[b"account:", receiver, b":balance:", symbol]), amount);
    kv_increment(env, &bcat(&[b"coin:", symbol, b":totalSupply"]), amount);
}

pub fn call_pause(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 2 {
        panic_any("invalid_args")
    }
    let symbol = args[0].as_slice();
    let direction = args[1].as_slice();

    if direction != b"true" && direction != b"false" {
        panic_any("invalid_direction")
    }

    if !exists(env, &symbol) {
        panic_any("symbol_doesnt_exist")
    }
    if !has_permission(env, &symbol, &env.caller_env.account_caller.clone()) {
        panic_any("no_permissions")
    }
    if !pausable(env, &symbol) {
        panic_any("not_pausable")
    }

    kv_put(env, &bcat(&[b"coin:", &symbol, b":paused"]), &direction);
}
