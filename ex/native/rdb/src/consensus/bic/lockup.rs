use crate::bcat;
use crate::consensus::bic::{coin::balance, coin::BURN_ADDRESS};
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_delete, kv_get, kv_increment, kv_put};
use std::panic::panic_any;

pub fn create_lock(
    env: &mut ApplyEnv,
    receiver: &[u8],
    amount: i128,
    symbol: &[u8],
    unlock_height: u64,
) {
    if amount <= 0 {
        panic_any("invalid_amount")
    }

    let vault_index = kv_increment(env, &bcat(&[b"bic:lockup:unique_index"]), 1);
    let vault_value = bcat(&[
        unlock_height.to_string().as_bytes(),
        b"-",
        amount.to_string().as_bytes(),
        b"-",
        &symbol,
    ]);
    kv_put(
        env,
        &bcat(&[
            b"bic:lockup:vault:",
            &receiver,
            b":",
            vault_index.to_string().as_bytes(),
        ]),
        &vault_value,
    );
}

pub fn call_lock(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 4 {
        panic_any("invalid_args")
    }
    let receiver = args[0].as_slice();
    let amount = args[1].as_slice();
    let symbol = args[2].as_slice();
    let duration = args[3].as_slice();

    if receiver.len() != 48 {
        panic_any("invalid_receiver_pk")
    }
    if !(crate::consensus::bls12_381::validate_public_key(receiver) || receiver == &BURN_ADDRESS) {
        panic_any("invalid_receiver_pk")
    }
    let amount = std::str::from_utf8(&amount)
        .ok()
        .and_then(|s| s.parse::<i128>().ok())
        .unwrap_or_else(|| panic_any("invalid_amount"));
    let duration = std::str::from_utf8(&duration)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| panic_any("invalid_amount"));

    if amount <= 0 {
        panic_any("invalid_amount")
    }
    if duration <= 0 {
        panic_any("invalid_duration")
    }

    if amount > balance(env, &env.caller_env.account_caller.clone(), &symbol) {
        panic_any("insufficient_funds")
    }

    let unlock_height = env.caller_env.entry_height + duration;
    kv_increment(
        env,
        &bcat(&[
            b"account:",
            &env.caller_env.account_caller.clone(),
            b":balance:",
            symbol,
        ]),
        -amount,
    );
    create_lock(env, receiver, amount, symbol, unlock_height)
}

pub fn call_unlock(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let vault_index = args[0].as_slice();

    let vault_key = &bcat(&[
        b"bic:lockup:vault:",
        &env.caller_env.account_caller,
        b":",
        vault_index,
    ]);

    let vault = kv_get(env, vault_key);
    if vault.is_none() {
        panic_any("invalid_vault")
    }
    let vault = vault.unwrap();

    let vault_parts: Vec<Vec<u8>> = vault
        .split(|&b| b == b'-')
        .map(|seg| seg.to_vec())
        .collect();
    let unlock_height = vault_parts[0].as_slice();
    let unlock_height = std::str::from_utf8(&unlock_height)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| panic_any("invalid_unlock_height"));
    let amount = vault_parts[1].as_slice();
    let amount = std::str::from_utf8(&amount)
        .ok()
        .and_then(|s| s.parse::<i128>().ok())
        .unwrap_or_else(|| panic_any("invalid_unlock_amount"));
    let symbol = vault_parts[2].as_slice();

    if env.caller_env.entry_height < unlock_height {
        panic_any("vault_is_locked")
    } else {
        kv_increment(
            env,
            &bcat(&[
                b"account:",
                &env.caller_env.account_caller,
                b":balance:",
                symbol,
            ]),
            amount,
        );
        kv_delete(env, vault_key);
    }
}
