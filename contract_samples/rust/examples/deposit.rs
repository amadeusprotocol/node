#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use amadeus_sdk::*;

fn vault_key(symbol: &Vec<u8>) -> Vec<u8> {
    b!("vault:", account_caller(), ":", symbol)
}

#[contract]
fn balance(symbol: Vec<u8>) -> i128 {
    kv_get(vault_key(&symbol)).unwrap_or(0)
}

#[contract]
fn deposit() -> String {
    log("deposit called");
    let (has_attachment, (symbol, amount)) = get_attachment();
    amadeus_sdk::assert!(has_attachment, "deposit has no attachment");
    let amount_i128 = i128::from_bytes(amount);
    amadeus_sdk::assert!(amount_i128 > 100, "deposit amount less than 100");
    kv_increment(vault_key(&symbol), amount_i128)
}

#[contract]
fn withdraw(symbol: Vec<u8>, amount: Vec<u8>) -> i128 {
    log("withdraw called");
    let withdraw_amount_int = encoding::bytes_to_i128(&amount);
    amadeus_sdk::assert!(withdraw_amount_int > 0, "amount lte 0");
    let key = vault_key(&symbol);
    let vault_balance: i128 = kv_get(&key).unwrap_or(0);
    amadeus_sdk::assert!(vault_balance >= withdraw_amount_int, "insufficient funds");
    kv_increment(key, -withdraw_amount_int);
    call!("Coin", "transfer", [account_caller(), amount, symbol]);
    vault_balance - withdraw_amount_int
}

#[contract]
fn burn(symbol: String, amount: Vec<u8>) -> Vec<u8> {
    log("burn");
    call!("Coin", "transfer", [BURN_ADDRESS, amount, symbol])
}
