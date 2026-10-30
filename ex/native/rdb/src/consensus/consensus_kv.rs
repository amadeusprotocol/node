use std::panic::panic_any;

use crate::consensus::{bic::protocol, consensus_apply};
use consensus_apply::ApplyEnv;

use crate::consensus::consensus_muts;
use consensus_muts::Mutation;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;

pub type Writes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
pub type BitWrites = BTreeMap<Vec<u8>, BTreeSet<u64>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    Key { key: Vec<u8>, value: Option<Vec<u8>> },
    Next { seek: Vec<u8>, found: Option<(Vec<u8>, Vec<u8>)> },
    Prev { seek: Vec<u8>, inclusive: bool, found: Option<(Vec<u8>, Vec<u8>)> },
    Bit { key: Vec<u8>, bit: u64, exists: bool, set: bool },
}

#[derive(Default)]
pub struct Overlay {
    pub block: Writes,
    pub tx: Writes,
    pub bits: BitWrites,
    pub reads: Vec<Read>,
}

fn overlay_active(env: &ApplyEnv) -> bool {
    env.cf_name.as_slice() == b"contractstate"
}

fn layered_get(env: &ApplyEnv, key: &[u8]) -> Option<Vec<u8>> {
    if overlay_active(env) {
        if let Some(v) = env.overlay.tx.get(key) {
            return v.clone();
        }
        if let Some(v) = env.overlay.block.get(key) {
            return v.clone();
        }
    }
    env.txn.get_cf(&env.cf, key).unwrap()
}

fn raw_get(env: &mut ApplyEnv, key: &[u8]) -> Option<Vec<u8>> {
    let value = layered_get(env, key);
    if overlay_active(env) {
        if !env.overlay.tx.contains_key(key) {
            env.overlay.reads.push(Read::Key { key: key.to_vec(), value: value.clone() });
        } else if env.overlay.bits.contains_key(key) {
            let outside = outside_get(env, key);
            env.overlay.reads.push(Read::Key { key: key.to_vec(), value: outside });
        }
    }
    value
}

fn record(env: &mut ApplyEnv, read: Read) {
    if overlay_active(env) {
        env.overlay.reads.push(read);
    }
}

fn raw_put(env: &mut ApplyEnv, key: &[u8], value: &[u8], err: &'static str) {
    if overlay_active(env) {
        env.overlay.bits.remove(key);
        env.overlay.tx.insert(key.to_vec(), Some(value.to_vec()));
    } else {
        env.txn.put_cf(&env.cf, key, value).unwrap_or_else(|_| panic_any(err));
    }
}

fn raw_delete(env: &mut ApplyEnv, key: &[u8]) {
    if overlay_active(env) {
        env.overlay.bits.remove(key);
        env.overlay.tx.insert(key.to_vec(), None);
    } else {
        env.txn.delete_cf(&env.cf, key).unwrap_or_else(|_| panic_any("exec_kv_delete_failed"));
    }
}

pub fn overlay_commit_tx(env: &mut ApplyEnv) {
    let (writes, bits, _) = overlay_take_tx(env);
    overlay_apply(env, writes, bits);
}

pub fn overlay_discard_tx(env: &mut ApplyEnv) {
    overlay_take_tx(env);
}

pub fn overlay_take_tx(env: &mut ApplyEnv) -> (Writes, BitWrites, Vec<Read>) {
    let mut writes = std::mem::take(&mut env.overlay.tx);
    let bits = std::mem::take(&mut env.overlay.bits);
    for key in bits.keys() {
        writes.remove(key);
    }
    (writes, bits, std::mem::take(&mut env.overlay.reads))
}

pub fn overlay_apply(env: &mut ApplyEnv, writes: Writes, bits: BitWrites) {
    env.overlay.block.extend(writes);
    for (key, set) in bits {
        let mut page = match env.overlay.block.get(&key) {
            Some(v) => v.clone(),
            None => env.txn.get_cf(&env.cf_contractstate, &key).unwrap(),
        }
        .unwrap_or_else(|| vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize]);
        for bit in set {
            page[(bit / 8) as usize] |= 1u8 << (7 - (bit % 8) as u8);
        }
        env.overlay.block.insert(key, Some(page));
    }
}

fn outside_get(env: &ApplyEnv, key: &[u8]) -> Option<Vec<u8>> {
    match env.overlay.block.get(key) {
        Some(v) => v.clone(),
        None => env.txn.get_cf(&env.cf, key).unwrap(),
    }
}

pub fn overlay_flush(env: &mut ApplyEnv) {
    overlay_commit_tx(env);
    let block = std::mem::take(&mut env.overlay.block);
    for (key, value) in block {
        match value {
            Some(v) => env.txn.put_cf(&env.cf_contractstate, &key, &v).unwrap_or_else(|_| panic_any("exec_kv_flush_failed")),
            None => env.txn.delete_cf(&env.cf_contractstate, &key).unwrap_or_else(|_| panic_any("exec_kv_flush_failed")),
        }
    }
}

fn overlay_next(env: &ApplyEnv, cursor: &[u8], inclusive: bool) -> Option<Vec<u8>> {
    let lo = if inclusive { Bound::Included(cursor) } else { Bound::Excluded(cursor) };
    let a = env.overlay.tx.range::<[u8], _>((lo, Bound::Unbounded)).next().map(|(k, _)| k.clone());
    let b = env.overlay.block.range::<[u8], _>((lo, Bound::Unbounded)).next().map(|(k, _)| k.clone());
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

fn overlay_prev(env: &ApplyEnv, cursor: &[u8], inclusive: bool) -> Option<Vec<u8>> {
    let hi = if inclusive { Bound::Included(cursor) } else { Bound::Excluded(cursor) };
    let a = env.overlay.tx.range::<[u8], _>((Bound::Unbounded, hi)).next_back().map(|(k, _)| k.clone());
    let b = env.overlay.block.range::<[u8], _>((Bound::Unbounded, hi)).next_back().map(|(k, _)| k.clone());
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

fn merged_next(env: &ApplyEnv, seek: &[u8], inclusive: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    let active = overlay_active(env);
    let mut it = env.txn.raw_iterator_cf(&env.cf);
    let mut cursor = seek.to_vec();
    let mut inclusive = inclusive;
    loop {
        it.seek(&cursor);
        if !inclusive && it.valid() && it.key() == Some(&cursor[..]) {
            it.next();
        }
        let db_key = if it.valid() { it.key().map(|k| k.to_vec()) } else { None };
        let ov_key = if active { overlay_next(env, &cursor, inclusive) } else { None };
        let key = match (db_key, ov_key) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => return None,
        };
        match layered_get(env, &key) {
            Some(v) => return Some((key, v)),
            None => {
                cursor = key;
                inclusive = false;
            }
        }
    }
}

fn merged_prev(env: &ApplyEnv, seek: &[u8], inclusive: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    let active = overlay_active(env);
    let mut it = env.txn.raw_iterator_cf(&env.cf);
    let mut cursor = seek.to_vec();
    let mut inclusive = inclusive;
    loop {
        it.seek_for_prev(&cursor);
        if !inclusive && it.valid() && it.key() == Some(&cursor[..]) {
            it.prev();
        }
        let db_key = if it.valid() { it.key().map(|k| k.to_vec()) } else { None };
        let ov_key = if active { overlay_prev(env, &cursor, inclusive) } else { None };
        let key = match (db_key, ov_key) {
            (Some(a), Some(b)) => a.max(b),
            (Some(a), None) | (None, Some(a)) => a,
            (None, None) => return None,
        };
        match layered_get(env, &key) {
            Some(v) => return Some((key, v)),
            None => {
                cursor = key;
                inclusive = false;
            }
        }
    }
}

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
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BYTE * value_len as i128);
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
    exec_budget_decr(env, protocol::COST_PER_DB_WRITE_BASE + protocol::COST_PER_DB_WRITE_BYTE * (key.len() + value.len()) as i128);

    let old_value = raw_get(env, key);
    match old_value {
        None => {
            storage_budget_decr(env, protocol::COST_PER_NEW_LEAF_MERKLE);
            storage_budget_decr(env, protocol::COST_PER_BYTE_STATE * (key.len() + value.len()) as i128);
            env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec() });

            env.muts.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: value.to_vec() });
            raw_put(env, key, value, "exec_kv_put_failed")
        }
        Some(old) => {
            //TODO: consider gas refund on delete? gas-token attack?
            storage_budget_decr(env, protocol::COST_PER_BYTE_STATE * value.len().saturating_sub(old.len()) as i128);
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: old.to_vec() });

            env.muts.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: value.to_vec() });
            raw_put(env, key, value, "exec_kv_put_failed")
        }
    }
}

pub fn kv_increment(env: &mut ApplyEnv, key: &[u8], value: i128) -> i128 {
    if env.readonly {
        panic!("exec_cannot_write_during_view");
    }

    let value_str = value.to_string().into_bytes();
    exec_budget_decr(env, protocol::COST_PER_DB_WRITE_BASE + protocol::COST_PER_DB_WRITE_BYTE * (key.len() + value_str.len()) as i128);

    match raw_get(env, key) {
        None => {
            exec_kv_size(key, Some(&value_str));
            storage_budget_decr(env, protocol::COST_PER_NEW_LEAF_MERKLE);
            storage_budget_decr(env, protocol::COST_PER_BYTE_STATE * (key.len() + value_str.len()) as i128);
            env.muts.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: value.to_string().into_bytes() });
            env.muts_rev.push(Mutation::Delete { op: b"delete".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec() });
            raw_put(env, key, &value_str, "exec_kv_increment_failed");
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
            raw_put(env, key, &new_value_str, "kv_put_failed");
            new_value
        }
    }
}

pub fn kv_delete(env: &mut ApplyEnv, key: &[u8]) {
    if env.readonly {
        panic!("exec_cannot_write_during_view");
    }

    exec_budget_decr(env, protocol::COST_PER_DB_WRITE_BASE + protocol::COST_PER_DB_WRITE_BYTE * (key.len()) as i128);

    match raw_get(env, key) {
        None => (),
        Some(old) => {
            env.muts.push(Mutation::Delete { op: b"delete".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec() });
            env.muts_rev.push(Mutation::Put { op: b"put".to_vec(), table: env.cf_name.to_vec(), key: key.to_vec(), value: old.to_vec() })
        }
    }
    raw_delete(env, key);
}

pub fn kv_set_bit(env: &mut ApplyEnv, key: &[u8], bit_idx: u64) -> bool {
    if env.readonly {
        panic!("exec_cannot_write_during_view");
    }

    exec_budget_decr(env, protocol::COST_PER_DB_WRITE_BASE + protocol::COST_PER_DB_WRITE_BYTE * (key.len()) as i128);

    let own_page = env.overlay.tx.contains_key(key) && !env.overlay.bits.contains_key(key);
    let own_bit = env.overlay.bits.get(key).map_or(false, |set| set.contains(&bit_idx));
    let (mut old, exists) = match layered_get(env, key) {
        None => (vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize], false),
        Some(value) => (value, true),
    };

    let byte_idx = (bit_idx / 8) as usize;
    let bit_in_byte = (bit_idx % 8) as u8;
    let mask: u8 = 1u8 << (7 - bit_in_byte);
    if overlay_active(env) && !own_page && !own_bit {
        let outside = outside_get(env, key);
        let set = outside.as_ref().map_or(false, |page| (page[byte_idx] & mask) != 0);
        record(env, Read::Bit { key: key.to_vec(), bit: bit_idx, exists: outside.is_some(), set });
    }

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
        let bits = env.overlay.bits.remove(key);
        raw_put(env, key, &old, "exec_kv_set_bit_failed");
        if overlay_active(env) && !own_page {
            let mut bits = bits.unwrap_or_default();
            bits.insert(bit_idx);
            env.overlay.bits.insert(key.to_vec(), bits);
        }
        true
    }
}

pub fn kv_exists(env: &mut ApplyEnv, key: &[u8]) -> bool {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::COST_PER_DB_READ_BYTE * (key.len()) as i128);

    match raw_get(env, key) {
        None => false,
        Some(v) => {
            charge_read_value(env, v.len());
            true
        }
    }
}

pub fn kv_get(env: &mut ApplyEnv, key: &[u8]) -> Option<Vec<u8>> {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::COST_PER_DB_READ_BYTE * (key.len()) as i128);

    let v = raw_get(env, key);
    if let Some(ref val) = v {
        charge_read_value(env, val.len());
    }
    v
}

pub fn kv_get_next(env: &mut ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::COST_PER_DB_READ_BYTE * (prefix.len() + key.len()) as i128);

    let seek = [prefix, key].concat();

    let found = merged_next(env, &seek, false);
    record(env, Read::Next { seek: seek.clone(), found: found.clone() });
    let result = match found {
        Some((k, v)) if k.starts_with(prefix) => Some((k[prefix.len()..].to_vec(), v)),
        _ => None,
    };

    if let Some((_, ref v)) = result {
        charge_read_value(env, v.len());
    }
    result
}

pub fn kv_get_prev(env: &mut ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::COST_PER_DB_READ_BYTE * (prefix.len() + key.len()) as i128);

    let seek = [prefix, key].concat();

    let found = merged_prev(env, &seek, false);
    record(env, Read::Prev { seek: seek.clone(), inclusive: false, found: found.clone() });
    let result = match found {
        Some((k, v)) if k.starts_with(prefix) => Some((k[prefix.len()..].to_vec(), v)),
        _ => None,
    };

    if let Some((_, ref v)) = result {
        charge_read_value(env, v.len());
    }
    result
}

pub fn kv_get_prev_or_first(env: &mut ApplyEnv, prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    exec_budget_decr(env, protocol::COST_PER_DB_READ_BASE + protocol::COST_PER_DB_READ_BYTE * (prefix.len() + key.len()) as i128);

    let seek = [prefix, key].concat();

    let found = merged_prev(env, &seek, true);
    record(env, Read::Prev { seek: seek.clone(), inclusive: true, found: found.clone() });
    let result = match found {
        Some((k, v)) if k.starts_with(prefix) => Some((k[prefix.len()..].to_vec(), v)),
        _ => None,
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
