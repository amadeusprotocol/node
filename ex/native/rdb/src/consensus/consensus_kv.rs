use std::panic::panic_any;

use crate::consensus::{bic::protocol, consensus_apply};
use consensus_apply::ApplyEnv;

use crate::consensus::consensus_muts;
use consensus_muts::Mutation;

pub fn exec_budget_decr(env: &mut ApplyEnv, amount: i128) {
    if amount < 0 {
        panic_any("exec_invalid_amount_negative");
    }

    if env.exec_track {
        match env.exec_left.checked_sub(amount) {
            Some(new_budget) => {
                if new_budget < 0 {
                    env.exec_left = 0;
                    panic_any("exec_insufficient_exec_budget");
                }
                env.exec_left = new_budget;
            }
            None => panic_any("exec_critical_underflow"),
        }
    }
}

pub fn storage_budget_decr(env: &mut ApplyEnv, amount: i128) {
    if amount < 0 {
        panic_any("exec_storage_invalid_amount_negative");
    }

    if env.exec_track {
        match env.storage_left.checked_sub(amount) {
            Some(new_budget) => {
                if new_budget < 0 {
                    env.storage_left = 0;
                    panic_any("exec_insufficient_storage_budget");
                }
                env.storage_left = new_budget;
            }
            None => panic_any("exec_storage_critical_underflow"),
        }
    }
}

fn charge_read_value(env: &mut ApplyEnv, value_len: usize) {
    if env.caller_env.entry_height >= protocol::forkheight(env) {
        exec_budget_decr(env, protocol::cost_db_read_byte(env) * value_len as i128);
    }
}

pub fn exec_kv_size(key: &[u8], value: Option<&[u8]>) {
    if key.len() > protocol::MAX_DB_KEY_SIZE {
        panic_any("exec_too_large_key_size");
    }
    if let Some(v) = value {
        if v.len() > protocol::MAX_DB_VALUE_SIZE {
            panic_any("exec_too_large_value_size");
        }
    }
}

pub fn kv_put(env: &mut ApplyEnv, key: &[u8], value: &[u8]) {
    if env.readonly {
        panic!("exec_cannot_write_during_view");
    }

    exec_kv_size(key, Some(value));
    exec_budget_decr(env, protocol::COST_PER_DB_WRITE_BASE + protocol::cost_db_write_byte(env) * (key.len() + value.len()) as i128);

    let old_value = env.txn.get_cf(&env.cf, key).unwrap();
    match old_value {
        None => {
            storage_budget_decr(env, protocol::COST_PER_NEW_LEAF_MERKLE);
            storage_budget_decr(env, protocol::COST_PER_BYTE_STATE * (key.len() + value.len()) as i128);
            env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec() });

            env.muts.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: value.to_vec() });
            env.txn.put_cf(&env.cf, key, value).unwrap_or_else(|_| panic_any("exec_kv_put_failed"))
        }
        Some(old) => {
            //TODO: consider gas refund on delete? gas-token attack?
            storage_budget_decr(env, protocol::COST_PER_BYTE_STATE * value.len().saturating_sub(old.len()) as i128);
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: old.to_vec() });

            env.muts.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: value.to_vec() });
            env.txn.put_cf(&env.cf, key, value).unwrap_or_else(|_| panic_any("exec_kv_put_failed"))
        }
    }
}

pub fn kv_increment(env: &mut ApplyEnv, key: &[u8], value: i128) -> i128 {
    if env.readonly {
        panic!("exec_cannot_write_during_view");
    }

    let value_str = value.to_string().into_bytes();
    exec_budget_decr(env, protocol::COST_PER_DB_WRITE_BASE + protocol::cost_db_write_byte(env) * (key.len() + value_str.len()) as i128);

    match env.txn.get_cf(&env.cf, key).unwrap() {
        None => {
            exec_kv_size(key, Some(&value_str));
            storage_budget_decr(env, protocol::COST_PER_NEW_LEAF_MERKLE);
            storage_budget_decr(env, protocol::COST_PER_BYTE_STATE * (key.len() + value_str.len()) as i128);
            env.muts.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: value.to_string().into_bytes() });
            env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec() });
            env.txn.put_cf(&env.cf, key, value_str).unwrap_or_else(|_| panic_any("exec_kv_increment_failed"));
            value
        }
        Some(old) => {
            let old_int: i128 = atoi::atoi::<i128>(&old).unwrap_or_else(|| panic_any("exec_kv_increment_invalid_integer"));
            let new_value = old_int.checked_add(value).unwrap_or_else(|| panic_any("exec_kv_increment_integer_overflow"));
            let new_value_str = new_value.to_string().into_bytes();
            exec_kv_size(key, Some(&new_value_str));
            storage_budget_decr(env, protocol::COST_PER_BYTE_STATE * new_value_str.len().saturating_sub(old.len()) as i128);
            env.muts.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: new_value.to_string().into_bytes() });
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: old });
            env.txn.put_cf(&env.cf, key, new_value.to_string().into_bytes()).unwrap_or_else(|_| panic_any("kv_put_failed"));
            new_value
        }
    }
}

pub fn kv_delete(env: &mut ApplyEnv, key: &[u8]) {
    if env.readonly {
        panic!("exec_cannot_write_during_view");
    }

    exec_budget_decr(env, protocol::COST_PER_DB_WRITE_BASE + protocol::cost_db_write_byte(env) * (key.len()) as i128);

    match env.txn.get_cf(&env.cf, key).unwrap() {
        None => (),
        Some(old) => {
            env.muts.push(Mutation::Delete { op: b"delete".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec() });
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: old.to_vec() })
        }
    }
    env.txn.delete_cf(&env.cf, key).unwrap_or_else(|_| panic_any("exec_kv_delete_failed"));
}

pub fn kv_set_bit(env: &mut ApplyEnv, key: &[u8], bit_idx: u64) -> bool {
    if env.readonly {
        panic!("exec_cannot_write_during_view");
    }

    exec_budget_decr(env, protocol::COST_PER_DB_WRITE_BASE + protocol::cost_db_write_byte(env) * (key.len()) as i128);

    let (mut old, exists) = match env.txn.get_cf(&env.cf, key).unwrap() {
        None => (vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize], false),
        Some(value) => (value, true),
    };

    let byte_idx = (bit_idx / 8) as usize;
    let bit_in_byte = (bit_idx % 8) as u8;
    let mask: u8 = 1u8 << (7 - bit_in_byte);

    if (old[byte_idx] & mask) != 0 {
        false
    } else {
        env.muts.push(Mutation::SetBit {
            op: b"set_bit".to_vec(),
            table: env.cf_name.to_vec(),
            key: key.to_vec(),
            value: bit_idx,
            bloomsize: crate::consensus::bic::sol_bloom::PAGE_SIZE,
        });
        match exists {
            true => env.muts_rev.push(Mutation::ClearBit { op: b"clear_bit".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: bit_idx }),
            false => env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec() }),
        };
        old[byte_idx] |= mask;
        env.txn.put_cf(&env.cf, key, &old).unwrap_or_else(|_| panic_any("exec_kv_set_bit_failed"));
        true
    }
}

pub fn kv_exists(env: &mut ApplyEnv, key: &[u8]) -> bool {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::cost_db_read_byte(env) * (key.len()) as i128);

    match env.txn.get_cf(&env.cf, key).unwrap() {
        None => false,
        Some(v) => {
            charge_read_value(env, v.len());
            true
        }
    }
}

pub fn kv_get(env: &mut ApplyEnv, key: &[u8]) -> Option<Vec<u8>> {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::cost_db_read_byte(env) * (key.len()) as i128);

    let v = env.txn.get_cf(&env.cf, key).unwrap();
    if let Some(ref val) = v {
        charge_read_value(env, val.len());
    }
    v
}

pub fn kv_get_next(env: &mut ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::cost_db_read_byte(env) * (prefix.len() + key.len()) as i128);

    let seek = [prefix, key].concat();

    let result = {
        let mut it = env.txn.raw_iterator_cf(&env.cf);
        it.seek(&seek);
        if !it.valid() {
            None
        } else {
            if let Some(k) = it.key() {
                if k == &seek {
                    it.next();
                }
            }
            match it.item() {
                Some((k, v)) if k.starts_with(prefix) => {
                    let next_key_wo_prefix = k[prefix.len()..].to_vec();
                    Some((next_key_wo_prefix, v.to_vec()))
                }
                _ => None,
            }
        }
    };

    if let Some((_, ref v)) = result {
        charge_read_value(env, v.len());
    }
    result
}

pub fn kv_get_prev(env: &mut ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::cost_db_read_byte(env) * (prefix.len() + key.len()) as i128);

    let seek = [prefix, key].concat();

    let result = {
        let mut it = env.txn.raw_iterator_cf(&env.cf);
        it.seek_for_prev(&seek);
        if !it.valid() {
            None
        } else {
            if let Some(k) = it.key() {
                if k == &seek {
                    it.prev();
                }
            }
            match it.item() {
                Some((k, v)) if k.starts_with(prefix) => {
                    let next_key_wo_prefix = k[prefix.len()..].to_vec();
                    Some((next_key_wo_prefix, v.to_vec()))
                }
                _ => None,
            }
        }
    };

    if let Some((_, ref v)) = result {
        charge_read_value(env, v.len());
    }
    result
}

pub fn kv_get_prev_or_first(env: &mut ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::cost_db_read_byte(env) * (prefix.len() + key.len()) as i128);

    let seek = [prefix, key].concat();

    let result = {
        let mut it = env.txn.raw_iterator_cf(&env.cf);
        it.seek_for_prev(&seek);
        match it.item() {
            Some((k, v)) if k.starts_with(prefix) => {
                let next_key_wo_prefix = k[prefix.len()..].to_vec();
                Some((next_key_wo_prefix, v.to_vec()))
            }
            _ => None,
        }
    };

    if let Some((_, ref v)) = result {
        charge_read_value(env, v.len());
    }
    result
}

pub fn contractstate_namespace(key: &[u8]) -> Option<Vec<u8>> {
    if key.starts_with(b"account:") {
        Some(key[0..56].to_vec())
    } else if key.starts_with(b"coin") {
        Some(b"coin".to_vec())
    } else if key.starts_with(b"bic") {
        Some(b"bic".to_vec())
    } else {
        None
    }
}

pub fn revert(env: &mut ApplyEnv) {
    for m in env.muts_rev.clone().iter().rev() {
        match m {
            Mutation::Put { op, table, key, value } => match table.as_slice() {
                b"contractstate" => env.txn.put_cf(&env.cf_contractstate, key, value).unwrap(),
                b"contractstate_tree" => env.txn.put_cf(&env.cf_contractstate_tree, key, value).unwrap(),
                _ => panic!("Unknown table"),
            },
            Mutation::Delete { op, table, key } => match table.as_slice() {
                b"contractstate" => env.txn.delete_cf(&env.cf_contractstate, key).unwrap(),
                b"contractstate_tree" => env.txn.delete_cf(&env.cf_contractstate_tree, key).unwrap(),
                _ => panic!("Unknown table"),
            },
            Mutation::SetBit { op, table, key, value, bloomsize } => {}
            Mutation::ClearBit { op, table, key, value } => {
                let bit_idx = value;
                if let Some(mut old) = kv_get(env, key.as_slice()) {
                    let byte_idx = (bit_idx / 8) as usize;
                    let bit_in = (bit_idx % 8) as u8; // 0..=7, MSB-first
                    if byte_idx < old.len() {
                        let mask: u8 = 1u8 << (7 - bit_in);
                        // Force bit to 0 (idempotent)
                        old[byte_idx] &= !mask;
                        match table.as_slice() {
                            b"contractstate" => env.txn.put_cf(&env.cf_contractstate, key, &old).unwrap(),
                            b"contractstate_tree" => env.txn.put_cf(&env.cf_contractstate_tree, key, &old).unwrap(),
                            _ => panic!("Unknown table"),
                        }
                    }
                }
            }
        }
    }
}
