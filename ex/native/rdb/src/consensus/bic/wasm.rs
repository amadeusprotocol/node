use crate::consensus::bic::protocol;
use crate::consensus::consensus_apply::{ApplyEnv};
use crate::consensus::consensus_kv::{kv_get, kv_get_prev, kv_get_next, kv_put, kv_exists, kv_delete, kv_set_bit, kv_increment, kv_get_prev_or_first};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use std::panic::panic_any;
use std::time::Instant;
use lazy_static::lazy_static;
use sha2::{Sha256, Digest};
use wasmparser::{DataKind, Operator as ParserOperator, Parser, Payload};

use wasmer::{
    imports,
    wasmparser::Operator as WasmerOperator,
    sys::{EngineBuilder, Features, CompilerConfig as _},
    AsStoreMut, Function, FunctionEnv, FunctionEnvMut, FunctionType, Global, Instance, Memory, MemoryType, Engine,
    MemoryView, Module, Pages, Store, Type, Value,
    RuntimeError
};
use wasmer_compiler_singlepass::Singlepass;
use wasmer_middlewares::{
    metering::{get_remaining_points, set_remaining_points, MeteringPoints},
    Metering,
};

use std::ffi::c_void;
#[derive(Clone)]
pub struct ApplyEnvPtr {
    pub ptr: *mut c_void,
}
unsafe impl Send for ApplyEnvPtr {}
unsafe impl Sync for ApplyEnvPtr {}
impl ApplyEnvPtr {
    pub unsafe fn as_mut<'a>(&self) -> &'a mut ApplyEnv<'a> {
        &mut *(self.ptr as *mut ApplyEnv<'a>)
    }
}

struct HostEnv {
    applyenv_ptr: ApplyEnvPtr,
    instance: Option<Instance>,
    memory: Memory,
}

const ARTIFACT_CACHE_MAX_BYTES: usize = 4 * 1024 * 1024 * 1024;

struct ArtifactEntry {
    value: Vec<u8>,
    last_used: u64,
}

struct ArtifactCache {
    map: HashMap<Vec<u8>, ArtifactEntry>,
    bytes: usize,
    tick: u64,
}

impl ArtifactCache {
    fn new() -> Self {
        Self { map: HashMap::new(), bytes: 0, tick: 0 }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    // &mut self because a hit refreshes the entry's last_used tick (LRU).
    fn get(&mut self, key: &[u8]) -> Option<&Vec<u8>> {
        let tick = self.next_tick();
        let entry = self.map.get_mut(key)?;
        entry.last_used = tick;
        Some(&entry.value)
    }

    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        if let Some(entry) = self.map.get_mut(&key) {
            // Same bytes already cached — just refresh the tick.
            entry.last_used = self.tick.wrapping_add(1);
            self.tick = entry.last_used;
            return;
        }
        // Evict least-recently-used entries until the new artifact fits.
        while self.bytes + value.len() > ARTIFACT_CACHE_MAX_BYTES {
            let lru_key = self.map.iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| k.clone());
            match lru_key {
                Some(k) => {
                    if let Some(old) = self.map.remove(&k) {
                        self.bytes -= old.value.len();
                    }
                }
                None => break,
            }
        }
        let tick = self.next_tick();
        self.bytes += value.len();
        self.map.insert(key, ArtifactEntry { value, last_used: tick });
    }

    fn remove(&mut self, key: &[u8]) {
        if let Some(old) = self.map.remove(key) {
            self.bytes -= old.value.len();
        }
    }
}

lazy_static! {
    static ref ARTIFACT_CACHE: Mutex<ArtifactCache> = Mutex::new(ArtifactCache::new());
}

const ENGINE_VERSION_TAG: &[u8] =
    b"wasmer-7.1.0+singlepass+canonicalize_nans+metering+bulk_memory/v1";

fn artifact_cache_key(wasm_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(ENGINE_VERSION_TAG);
    hasher.update(wasm_bytes);
    hasher.finalize().to_vec()
}

fn artifact_cache_get(cache_key: &[u8]) -> Option<Vec<u8>> {
    let mut cache = ARTIFACT_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    cache.get(cache_key).cloned()
}

fn artifact_cache_insert(cache_key: Vec<u8>, artifact: Vec<u8>) {
    let mut cache = ARTIFACT_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    cache.insert(cache_key, artifact);
}

fn artifact_cache_remove(cache_key: &[u8]) {
    let mut cache = ARTIFACT_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    cache.remove(cache_key);
}

fn compile_and_cache_module(store: &Store, wasm_bytes: &[u8], cache_key: Vec<u8>) -> Module {
    let new_module = Module::new(store, wasm_bytes)
        .unwrap_or_else(|_| panic_any("exec_invalid_module"));
    // If serialize fails, skip caching but still return a working module --
    // the next call will simply recompile.
    if let Ok(artifact) = new_module.serialize() {
        artifact_cache_insert(cache_key, artifact.to_vec());
    }
    new_module
}

fn set_return_value(applyenv: &mut ApplyEnv, return_value: Vec<u8>) {
    if return_value.len() > protocol::WASM_MAX_PANIC_MSG_SIZE {
        panic_any("exec_return_value_too_large")
    }
    applyenv.caller_env.call_return_value = return_value
}

fn budget_sync_in(store: &mut impl AsStoreMut, instance: &Instance, applyenv: &mut ApplyEnv) {
    let wasm_remaining: i128 = match get_remaining_points(store, instance) {
        MeteringPoints::Remaining(v) => v as i128,
        MeteringPoints::Exhausted => 0,
    };
    if wasm_remaining < applyenv.exec_left {
        applyenv.exec_left = wasm_remaining;
    }
}

fn import_log_implementation(mut env: FunctionEnvMut<HostEnv>, ptr: i32, len: i32) {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);
    let len = len as usize;

    if len <= 0 {
        panic_any("exec_ptr_term_too_short")
    }
    if len > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    crate::consensus::consensus_kv::storage_budget_decr(applyenv, protocol::COST_PER_BYTE_HISTORICAL * len as i128);
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);

    let view = data.memory.clone().view(&store);

    let mut buffer = vec![0u8; len as usize];
    view.read(ptr as u64, &mut buffer).unwrap_or_else(|_| panic_any("exec_log_invalid_ptr"));
    log_line(applyenv, buffer.to_vec())
}

fn import_return_implementation(mut env: FunctionEnvMut<HostEnv>, ptr: i32, len: i32) -> Result<(), RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);
    let len = len as usize;

    if len > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    crate::consensus::consensus_kv::exec_budget_decr(applyenv, protocol::COST_PER_BYTE_HISTORICAL * len as i128);
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);

    let view = data.memory.clone().view(&store);

    let mut buffer = vec![0u8; len as usize];
    view.read(ptr as u64, &mut buffer).unwrap_or_else(|_| panic_any("exec_log_invalid_ptr"));
    set_return_value(applyenv, buffer.to_vec());
    Err(RuntimeError::new("EXIT_IMPORT_RETURN"))
}

fn import_call_implementation(mut env: FunctionEnvMut<HostEnv>, table_ptr: i32, extra_table_ptr: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    let (contract, function, args, attached_symbol, attached_amount) = {
        let view = data.memory.clone().view(&store);

        // First pass: read tables (cheap — only ptr/len pairs), validate per-arg cap,
        // and sum total marshalled bytes. NO allocation/copy yet.
        let mut count_buf = [0u8; 4];
        view.read(table_ptr as u64, &mut count_buf).unwrap_or_else(|_| panic_any("exec_call_table_invalid_ptr"));
        let arg_count = i32::from_le_bytes(count_buf) as usize;
        if arg_count > 16 { panic_any("exec_call_too_many_args") }

        let mut main_table: Vec<(i32, i32)> = Vec::with_capacity(arg_count);
        let mut total_bytes: usize = 0;
        for i in 0..arg_count {
            let offset = (table_ptr as u64) + 4 + (i as u64 * 8);
            let mut row_buf = [0u8; 8];
            view.read(offset, &mut row_buf).unwrap_or_else(|_| panic_any("exec_read_call_table_error"));
            let arg_ptr = i32::from_le_bytes(row_buf[0..4].try_into().unwrap());
            let arg_len = i32::from_le_bytes(row_buf[4..8].try_into().unwrap());

            if arg_len < 0 || arg_len as usize > protocol::WASM_MAX_PTR_LEN { panic_any("exec_call_ptr_term_too_long") }

            total_bytes = total_bytes.saturating_add(arg_len as usize);
            main_table.push((arg_ptr, arg_len));
        }

        let mut extra_table: Vec<(i32, i32)> = Vec::new();
        if extra_table_ptr != 0 {
            view.read(extra_table_ptr as u64, &mut count_buf).unwrap_or_else(|_| panic_any("exec_call_extra_invalid"));
            let extra_count = i32::from_le_bytes(count_buf) as usize;
            if extra_count > 16 { panic_any("exec_call_extra_too_many") }

            for i in 0..extra_count {
                let offset = (extra_table_ptr as u64) + 4 + (i as u64 * 8);
                let mut row_buf = [0u8; 8];
                view.read(offset, &mut row_buf).unwrap_or_else(|_| panic_any("exec_read_extra_row"));
                let arg_ptr = i32::from_le_bytes(row_buf[0..4].try_into().unwrap());
                let arg_len = i32::from_le_bytes(row_buf[4..8].try_into().unwrap());

                if arg_len < 0 || arg_len as usize > protocol::WASM_MAX_PTR_LEN { panic_any("exec_call_extra_ptr_term_too_long") }

                total_bytes = total_bytes.saturating_add(arg_len as usize);
                extra_table.push((arg_ptr, arg_len));
            }
        }

        if total_bytes > protocol::WASM_MAX_CALL_ARGS_TOTAL { panic_any("exec_call_total_args_too_long") }

        crate::consensus::consensus_kv::exec_budget_decr(
            applyenv,
            protocol::COST_PER_BYTE_HISTORICAL * total_bytes as i128,
        );

        // Second pass: now allocate and copy. Total bytes already capped + paid for.
        let mut final_args: Vec<Vec<u8>> = Vec::with_capacity(main_table.len());
        for (arg_ptr, arg_len) in &main_table {
            let mut arg_data = vec![0u8; *arg_len as usize];
            view.read(*arg_ptr as u64, &mut arg_data).unwrap_or_else(|_| panic_any("exec_read_call_table_data_error"));
            final_args.push(arg_data);
        }
        let mut final_args_extra: Vec<Vec<u8>> = Vec::with_capacity(extra_table.len());
        for (arg_ptr, arg_len) in &extra_table {
            let mut arg_data = vec![0u8; *arg_len as usize];
            view.read(*arg_ptr as u64, &mut arg_data).unwrap_or_else(|_| panic_any("exec_read_extra_data"));
            final_args_extra.push(arg_data);
        }

        // Process Arguments
        if final_args.len() < 2 { panic_any("exec_call_missing_args"); }
        let contract = final_args[0].clone();
        let function = final_args[1].clone();
        let args = final_args[2..].to_vec();

        let (attached_symbol, attached_amount) = if final_args_extra.len() == 2 {
            (Some(final_args_extra[0].clone()), Some(final_args_extra[1].clone()))
        } else {
            (None, None)
        };

        (contract, function, args, attached_symbol, attached_amount)
    };

    crate::consensus::consensus_kv::exec_budget_decr(applyenv, protocol::COST_PER_CALL);
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);

    let og_account_caller = applyenv.caller_env.account_caller.clone();
    let og_account_current = applyenv.caller_env.account_current.clone();

    applyenv.caller_env.account_caller = og_account_current.clone();
    applyenv.caller_env.account_current = contract.clone();
    applyenv.caller_env.call_counter = applyenv.caller_env.call_counter.saturating_add(1);
    applyenv.caller_env.call_return_value = Vec::new();

    let result = match crate::consensus::bls12_381::validate_public_key(contract.as_slice()) {
        false => {
            crate::consensus::consensus_apply::call_bic(applyenv, contract, function, args, attached_symbol, attached_amount);
            b"ok".to_vec()
        }
        true => {
            crate::consensus::consensus_apply::call_wasmvm(applyenv, contract, function, args, attached_symbol, attached_amount)
        }
    };

    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);

    applyenv.caller_env.account_caller = og_account_caller;
    applyenv.caller_env.account_current = og_account_current;

    let view = data.memory.clone().view(&store);
    view.write(10_000, &(result.len() as u32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
    view.write(10_004, &result).unwrap_or_else(|_| panic_any("exec_memwrite"));

    Ok(10_000)
}

fn build_prefixed_key(applyenv: &mut ApplyEnv, view: &MemoryView, ptr: i32, len: i32) -> Vec<u8> {
    let mut key = vec![0u8; len as usize];
    view.read(ptr as u64, &mut key).unwrap_or_else(|_| panic_any("exec_log_invalid_ptr"));

    crate::bcat(&[&b"account:"[..], &applyenv.caller_env.account_current, &b":storage:"[..], &key])
}

fn import_storage_kv_put_implementation(mut env: FunctionEnvMut<HostEnv>, key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> Result<(), RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    if key_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }
    if val_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    let view = data.memory.clone().view(&store);
    let key = build_prefixed_key(applyenv, &view, key_ptr, key_len);
    let mut value = vec![0u8; val_len as usize];
    view.read(val_ptr as u64, &mut value).unwrap_or_else(|_| panic_any("exec_log_invalid_ptr"));

    kv_put(applyenv, &key, &value);
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);
    Ok(())
}

fn import_storage_kv_increment_implementation(mut env: FunctionEnvMut<HostEnv>, key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    if key_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }
    if val_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    let view = data.memory.clone().view(&store);
    let key = build_prefixed_key(applyenv, &view, key_ptr, key_len);
    let mut value = vec![0u8; val_len as usize];
    view.read(val_ptr as u64, &mut value).unwrap_or_else(|_| panic_any("exec_log_invalid_ptr"));

    let value_int128 = std::str::from_utf8(&value).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_integer"));
    let new_value = kv_increment(applyenv, &key, value_int128).to_string();
    let new_value = new_value.as_bytes();

    view.write(10_000, &(new_value.len() as u32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
    view.write(10_004, &new_value).unwrap_or_else(|_| panic_any("exec_memwrite"));

    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);
    Ok(10_000)
}

fn import_storage_kv_delete_implementation(mut env: FunctionEnvMut<HostEnv>, key_ptr: i32, key_len: i32) -> Result<(), RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    if key_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    let view = data.memory.clone().view(&store);
    let key = build_prefixed_key(applyenv, &view, key_ptr, key_len);

    kv_delete(applyenv, &key);

    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);
    Ok(())
}

fn import_storage_kv_get_implementation(mut env: FunctionEnvMut<HostEnv>, ptr: i32, len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    if len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    let view = data.memory.clone().view(&store);
    let key = build_prefixed_key(applyenv, &view, ptr, len);
    match kv_get(applyenv, &key) {
        None => {
            view.write(10_000, &(-1i32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
        },
        Some(value) => {
            view.write(10_000, &(value.len() as u32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
            view.write(10_004, &value).unwrap_or_else(|_| panic_any("exec_memwrite"));
        }
    }
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);
    Ok(10_000)
}

fn import_storage_kv_get_prev_implementation(mut env: FunctionEnvMut<HostEnv>, prefix_ptr: i32, prefix_len: i32, key_ptr: i32, key_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    if prefix_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }
    if key_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    let view = data.memory.clone().view(&store);
    let prefix = build_prefixed_key(applyenv, &view, prefix_ptr, prefix_len);
    let mut key = vec![0u8; key_len as usize];
    view.read(key_ptr as u64, &mut key).unwrap_or_else(|_| panic_any("exec_log_invalid_ptr"));

    match kv_get_prev(applyenv, &prefix, &key) {
        None => {
            view.write(10_000, &(-1i32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
        },
        Some((prev_key, value)) => {
            view.write(10_000, &(prev_key.len() as u32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
            view.write(10_000 + 4, &prev_key).unwrap_or_else(|_| panic_any("exec_memwrite"));

            view.write(10_000 + 4 + prev_key.len() as u64, &(value.len() as u32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
            view.write(10_000 + 4 + prev_key.len() as u64 + 4, &value).unwrap_or_else(|_| panic_any("exec_memwrite"));
        }
    }
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);
    Ok(10_000)
}

fn import_storage_kv_get_next_implementation(mut env: FunctionEnvMut<HostEnv>, prefix_ptr: i32, prefix_len: i32, key_ptr: i32, key_len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    if prefix_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }
    if key_len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    let view = data.memory.clone().view(&store);
    let prefix = build_prefixed_key(applyenv, &view, prefix_ptr, prefix_len);
    let mut key = vec![0u8; key_len as usize];
    view.read(key_ptr as u64, &mut key).unwrap_or_else(|_| panic_any("exec_log_invalid_ptr"));

    match kv_get_next(applyenv, &prefix, &key) {
        None => {
            view.write(10_000, &(-1i32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
        },
        Some((next_key, value)) => {
            view.write(10_000, &(next_key.len() as u32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
            view.write(10_000 + 4, &next_key).unwrap_or_else(|_| panic_any("exec_memwrite"));

            view.write(10_000 + 4 + next_key.len() as u64, &(value.len() as u32).to_le_bytes()).unwrap_or_else(|_| panic_any("exec_memwrite"));
            view.write(10_000 + 4 + next_key.len() as u64 + 4, &value).unwrap_or_else(|_| panic_any("exec_memwrite"));
        }
    }
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);
    Ok(10_000)
}

fn import_storage_kv_exists_implementation(mut env: FunctionEnvMut<HostEnv>, ptr: i32, len: i32) -> Result<i32, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    if len as usize > protocol::WASM_MAX_PTR_LEN {
        panic_any("exec_ptr_term_too_long")
    }

    let view = data.memory.clone().view(&store);
    let key = build_prefixed_key(applyenv, &view, ptr, len);

    let result = kv_exists(applyenv, &key);
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);
    match result {
        true => Ok(1),
        false => Ok(0)
    }
}

//AssemblyScript specific
fn as_read_string(view: &MemoryView, ptr: i32) -> String {
    if ptr == 0 { return "null".to_string(); }

    let ptr = ptr as u64;

    // 1. Read Length (stored at ptr - 4)
    // AssemblyScript stores length in BYTES (not characters) at offset -4
    let len_ptr = match ptr.checked_sub(4) {
        Some(p) => p,
        None => return "<invalid-ptr>".to_string(),
    };
    let mut len_buf = [0u8; 4];
    if view.read(len_ptr, &mut len_buf).is_err() {
        return "<invalid-ptr>".to_string();
    }
    let len_bytes = u32::from_le_bytes(len_buf) as usize;

    // Cap before allocating: len_bytes is attacker-controlled and could otherwise
    // force a multi-GB zero-init before the view.read bounds check runs.
    if len_bytes > protocol::WASM_MAX_PTR_LEN {
        return "<invalid-len>".to_string();
    }

    // 2. Read UTF-16 Bytes
    let mut str_buf = vec![0u8; len_bytes];
    if view.read(ptr, &mut str_buf).is_err() {
        return "<invalid-mem>".to_string();
    }

    // 3. Convert [u8] -> [u16] -> String
    let u16_vec: Vec<u16> = str_buf
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();

    String::from_utf16_lossy(&u16_vec)
}

fn as_abort_implementation(mut env: FunctionEnvMut<HostEnv>, msg_ptr: i32, filename_ptr: i32, line: i32, column: i32) -> Result<(), RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);
    let view = data.memory.clone().view(&store);

    //set_return_value(applyenv, b"as_abort".to_vec());

    let msg = as_read_string(&view, msg_ptr);
    let filename = as_read_string(&view, filename_ptr);

    let full_error_msg = format!("as_abort: '{}' at {}:{}:{}",
        msg, filename, line, column
    );

    crate::consensus::consensus_kv::exec_budget_decr(applyenv, protocol::COST_PER_BYTE_HISTORICAL * full_error_msg.len() as i128);
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);

    log_line(applyenv, full_error_msg.as_bytes().to_vec());

    //TODO: is this OK?
    panic_any("as_abort");
    Ok(())
    //Err(RuntimeError::new("as_abort"))
}

fn as_seed_implementation(mut env: FunctionEnvMut<HostEnv>) -> Result<f64, RuntimeError> {
    let (data, mut store) = env.data_and_store_mut();
    let instance = data.instance.clone().unwrap_or_else(|| panic_any("exec_instance_not_injected"));
    let applyenv = unsafe { data.applyenv_ptr.as_mut() };
    budget_sync_in(&mut store, &instance, applyenv);

    crate::consensus::consensus_kv::exec_budget_decr(applyenv, 100);
    set_remaining_points(&mut store, &instance, applyenv.exec_left.max(0) as u64);

    Ok(applyenv.caller_env.seedf64)
}

fn log_line(applyenv: &mut ApplyEnv, line: Vec<u8>) {
    let len = line.len();
    if len > protocol::LOG_MSG_SIZE {
        panic_any("exec_log_msg_size_exceeded")
    }
    if (applyenv.logs_size.saturating_add(len)) > protocol::LOG_TOTAL_SIZE {
        panic_any("exec_logs_total_size_exceeded")
    }
    if applyenv.logs.len() > protocol::LOG_TOTAL_ELEMENTS {
        panic_any("exec_logs_total_elements_exceeded")
    }

    applyenv.logs.push(line);
    applyenv.logs_size += len
}

pub fn check_module_limits(wasm_bytes: &[u8]) -> Result<(), &'static str> {
    if wasm_bytes.len() > protocol::WASM_MAX_BINARY_SIZE {
        return Err("wasmparser_binary_size_exceeds_limit");
    }

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        match payload.map_err(|_| "wasmparser_parse_error")? {
            Payload::FunctionSection(reader) => {
                let count = reader.count();
                if count > protocol::WASM_MAX_FUNCTIONS {
                    return Err("wasmparser_function_count_exceeds_limit");
                }
            },
            Payload::GlobalSection(reader) => {
                let count = reader.count();
                if count > protocol::WASM_MAX_GLOBALS {
                    return Err("wasmparser_global_count_exceeds_limit");
                }
            },
            Payload::ExportSection(reader) => {
                let count = reader.count();
                if count > protocol::WASM_MAX_EXPORTS {
                    return Err("wasmparser_export_count_exceeds_limit");
                }
            },
            Payload::ImportSection(reader) => {
                let count = reader.count();
                if count > protocol::WASM_MAX_IMPORTS {
                    return Err("wasmparser_import_count_exceeds_limit");
                }
            },
            Payload::CodeSectionStart { count, .. } => {
                if count > protocol::WASM_MAX_FUNCTIONS {
                    return Err("wasmparser_code_body_count_exceeds_limit");
                }
            },
            Payload::DataSection(reader) => {
                for data in reader {
                    let d = data.map_err(|_| "wasmparser_data_section_error")?;
                    if let DataKind::Active { offset_expr, .. } = d.kind {
                        let mut r = offset_expr.get_operators_reader();
                        if let Ok(ParserOperator::I32Const { value }) = r.read() {
                            if value >= 0 && value < 65536 {
                                return Err("wasmparser_first_65536_bytes_not_reserved");
                            }
                        }
                    }
                }
            }
            Payload::StartSection { .. } => {
                return Err("wasmparser_start_section_not_allowed");
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn validate_contract(env: &mut ApplyEnv, wasm_bytes: &[u8]) {
    if let Err(e) = check_module_limits(wasm_bytes) {
        panic_any(e)
    }

    let engine = make_engine(env.exec_left.max(0) as u64);
    let mut store = Store::new(engine);

    let module = Module::new(&store, wasm_bytes).unwrap_or_else(|_| panic_any("exec_invalid_module"));

    setup_wasm_instance(env, &module, &mut store, true, &[]);
}

fn cost_function(operator: &WasmerOperator) -> u64 {
    match operator {
        WasmerOperator::Loop { .. }
        | WasmerOperator::Block { .. }
        | WasmerOperator::End { .. }
        | WasmerOperator::Br { .. } => 1,

        WasmerOperator::I32Load { .. }
        | WasmerOperator::I64Load { .. }
        | WasmerOperator::I32Store { .. }
        | WasmerOperator::I64Store { .. } => 3,

        WasmerOperator::F32Load { .. }
        | WasmerOperator::F64Load { .. }
        | WasmerOperator::F32Store { .. }
        | WasmerOperator::F64Store { .. } => 10,

        WasmerOperator::Call { .. }
        | WasmerOperator::CallIndirect { .. } => 10,

        // Static upper-bound: wasmer's metering middleware can't see the size
        // operand on the wasm stack, so per-byte metering needs a custom middleware.
        // Until that's written, charge a flat cost that approximates ~33KB worth
        // of equivalent I32Store ops (≈ 100_000 / 3). MemoryGrow is per-page
        // (64KB) so a similar flat cost is reasonable.
        // TODO: replace with custom middleware that injects size-aware gas
        // decrement before each MemoryCopy/Fill/Grow (reads operand off stack).
        WasmerOperator::MemoryCopy { .. }
        | WasmerOperator::MemoryFill { .. } => 100_000,
        WasmerOperator::MemoryGrow { .. } => 100_000,

        WasmerOperator::If { .. }
        | WasmerOperator::Else { .. }
        | WasmerOperator::BrIf { .. }
        | WasmerOperator::Return { .. }
        | WasmerOperator::Unreachable { .. } => 2,
        _ => 2,
    }
}

// ⚠ ARTIFACT-CACHE INVARIANT
// Cached compilation artifacts are keyed by Sha256(ENGINE_VERSION_TAG || wasm_bytes)
// — see `artifact_cache_key` near the top of this file. If you change ANY of the
// settings below (compiler, canonicalize_nans, the `cost_function`, the feature
// flags, the wasmer crate version, or anything else that affects the compiled
// artifact's bit-for-bit layout), you MUST bump the /vN suffix in
// ENGINE_VERSION_TAG. Otherwise old cached artifacts will be deserialized into
// the new engine via `unsafe Module::deserialize`, which is undefined behavior.
fn make_engine(exec_remaining: u64) -> Engine {
    let metering = Arc::new(Metering::new(exec_remaining, cost_function));

    let mut compiler = Singlepass::default();
    compiler.canonicalize_nans(true);
    compiler.push_middleware(metering);

    let mut features = Features::new();
    features.threads(false);
    features.reference_types(false);
    features.simd(false);
    features.multi_value(false);
    features.tail_call(false);
    features.module_linking(false);
    features.memory64(false);
    features.bulk_memory(true);

    EngineBuilder::new(compiler)
        .set_features(Some(features))
        .into()
}

fn stub_panic_validation() -> ! {
    panic_any("validation_must_not_call_host")
}
fn stub_log(_env: FunctionEnvMut<HostEnv>, _ptr: i32, _len: i32) {
    stub_panic_validation();
}
fn stub_two_void(_env: FunctionEnvMut<HostEnv>, _: i32, _: i32) -> Result<(), RuntimeError> {
    stub_panic_validation();
}
fn stub_two_i32(_env: FunctionEnvMut<HostEnv>, _: i32, _: i32) -> Result<i32, RuntimeError> {
    stub_panic_validation();
}
fn stub_four_void(_env: FunctionEnvMut<HostEnv>, _: i32, _: i32, _: i32, _: i32) -> Result<(), RuntimeError> {
    stub_panic_validation();
}
fn stub_four_i32(_env: FunctionEnvMut<HostEnv>, _: i32, _: i32, _: i32, _: i32) -> Result<i32, RuntimeError> {
    stub_panic_validation();
}
fn stub_seed(_env: FunctionEnvMut<HostEnv>) -> Result<f64, RuntimeError> {
    stub_panic_validation();
}

pub fn setup_wasm_instance(env: &mut ApplyEnv, module: &Module, store: &mut Store, validation_only: bool, function_args: &[Vec<u8>]) -> (Instance, Vec<Value>) {
    // Setup Memory
    let memory = Memory::new(store, MemoryType::new(Pages(2), Some(Pages(30)), false)).unwrap_or_else(|_| panic_any("exec_memory_alloc"));

    let mut wasm_arg_ptrs: Vec<Value> = Vec::new();
    {
        let view = memory.view(store);
        inject_env_data(&view, env);
        let mut current_offset: u64 = 10_000;
        for arg_bytes in function_args {
            // Write the length + bytes
            let len = arg_bytes.len() as i32;
            view.write(current_offset, &len.to_le_bytes()).unwrap_or_else(|_| panic_any("exec_arg_len_write"));
            view.write(current_offset + 4, arg_bytes).unwrap_or_else(|_| panic_any("exec_arg_write"));
            // Save the POINTER (i32) to pass to the function call later
            wasm_arg_ptrs.push(Value::I32(current_offset as i32));
            // Advance offset
            current_offset += 4 + (arg_bytes.len() as u64);
        }
    }

    // Setup Host Environment
    let apply_ptr = env as *mut ApplyEnv as *mut c_void;
    let applyenv_ptr = ApplyEnvPtr { ptr: apply_ptr };

    let host_env_data = HostEnv {
        memory: memory.clone(),
        instance: None,
        applyenv_ptr,
    };

    let host_env = FunctionEnv::new(store, host_env_data);

    let import_object = if validation_only {
        imports! {
            "env" => {
                "memory" => memory,
                "import_log"           => Function::new_typed_with_env(store, &host_env, stub_log),
                "import_return"        => Function::new_typed_with_env(store, &host_env, stub_two_void),
                "import_call"          => Function::new_typed_with_env(store, &host_env, stub_two_i32),
                "import_kv_put"        => Function::new_typed_with_env(store, &host_env, stub_four_void),
                "import_kv_increment"  => Function::new_typed_with_env(store, &host_env, stub_four_i32),
                "import_kv_delete"     => Function::new_typed_with_env(store, &host_env, stub_two_void),
                "import_kv_get"        => Function::new_typed_with_env(store, &host_env, stub_two_i32),
                "import_kv_exists"     => Function::new_typed_with_env(store, &host_env, stub_two_i32),
                "import_kv_get_prev"   => Function::new_typed_with_env(store, &host_env, stub_four_i32),
                "import_kv_get_next"   => Function::new_typed_with_env(store, &host_env, stub_four_i32),
                "abort"                => Function::new_typed_with_env(store, &host_env, stub_four_void),
                "seed"                 => Function::new_typed_with_env(store, &host_env, stub_seed),
            }
        }
    } else {
        imports! {
            "env" => {
                "memory" => memory,
                "import_log" => Function::new_typed_with_env(store, &host_env, import_log_implementation),
                "import_return" => Function::new_typed_with_env(store, &host_env, import_return_implementation),
                "import_call" => Function::new_typed_with_env(store, &host_env, import_call_implementation),

                //Storage
                "import_kv_put" => Function::new_typed_with_env(store, &host_env, import_storage_kv_put_implementation),
                "import_kv_increment" => Function::new_typed_with_env(store, &host_env, import_storage_kv_increment_implementation),
                "import_kv_delete" => Function::new_typed_with_env(store, &host_env, import_storage_kv_delete_implementation),

                "import_kv_get" => Function::new_typed_with_env(store, &host_env, import_storage_kv_get_implementation),
                "import_kv_exists" => Function::new_typed_with_env(store, &host_env, import_storage_kv_exists_implementation),
                "import_kv_get_prev" => Function::new_typed_with_env(store, &host_env, import_storage_kv_get_prev_implementation),
                "import_kv_get_next" => Function::new_typed_with_env(store, &host_env, import_storage_kv_get_next_implementation),

                //AssemblyScript specific
                "abort" => Function::new_typed_with_env(store, &host_env, as_abort_implementation),
                "seed" => Function::new_typed_with_env(store, &host_env, as_seed_implementation),
            }
        }
    };

    // Create Instance
    let instance = Instance::new(store, module, &import_object).unwrap_or_else(|e| {
        log_line(env, e.to_string().into_bytes());
        panic_any("exec_instance")
    });
    host_env.as_mut(store).instance = Some(instance.clone());
    (instance, wasm_arg_ptrs)
}

fn inject_env_data(view: &MemoryView, env: &ApplyEnv) {
    let mut w = |offset: u64, data: &[u8]| {
        view.write(offset, data).unwrap_or_else(|_| panic_any("exec_init_memwrite"))
    };

    //Reserve first 1024 bytes
    //Reserve first page 65536 bytes
    w(1_100, &(env.caller_env.seed.len() as u32).to_le_bytes());
    w(1_104, &env.caller_env.seed);

    // Entry
    w(2_000, &env.caller_env.entry_slot.to_le_bytes());
    w(2_010, &env.caller_env.entry_height.to_le_bytes());
    w(2_020, &env.caller_env.entry_epoch.to_le_bytes());
    //
    w(2_100, &(env.caller_env.entry_signer.len() as u32).to_le_bytes());
    w(2_104, &env.caller_env.entry_signer);
    w(2_200, &(env.caller_env.entry_prev_hash.len() as u32).to_le_bytes());
    w(2_204, &env.caller_env.entry_prev_hash);
    w(2_300, &(env.caller_env.entry_vr.len() as u32).to_le_bytes());
    w(2_304, &env.caller_env.entry_vr);
    w(2_400, &(env.caller_env.entry_dr.len() as u32).to_le_bytes());
    w(2_404, &env.caller_env.entry_dr);

    // TX
    w(3_000, &env.caller_env.tx_nonce.to_le_bytes());
    //
    w(3_100, &(env.caller_env.tx_signer.len() as u32).to_le_bytes());
    w(3_104, &env.caller_env.tx_signer);

    // Accounts
    w(4_000, &(env.caller_env.account_current.len() as u32).to_le_bytes());
    w(4_004, &env.caller_env.account_current);
    w(4_100, &(env.caller_env.account_caller.len() as u32).to_le_bytes());
    w(4_104, &env.caller_env.account_caller);
    w(4_200, &(env.caller_env.account_origin.len() as u32).to_le_bytes());
    w(4_204, &env.caller_env.account_origin);

    // Assets
    w(5_000, &(env.caller_env.attached_symbol.len() as u32).to_le_bytes());
    w(5_004, &env.caller_env.attached_symbol);
    w(5_100, &(env.caller_env.attached_amount.len() as u32).to_le_bytes());
    w(5_104, &env.caller_env.attached_amount);
}

pub fn call_contract(env: &mut ApplyEnv, wasm_bytes: &[u8], function_name: String, function_args: Vec<Vec<u8>>) -> Vec<u8> {
    env.caller_env.call_return_value = Vec::new();

    let engine = make_engine(env.exec_left.max(0) as u64);
    let mut store = Store::new(engine);

    // Load Module (From Cache or Compile)
    let cache_key = artifact_cache_key(wasm_bytes);
    let module = match artifact_cache_get(&cache_key) {
        Some(artifact_bytes) => match unsafe { Module::deserialize(&store, &artifact_bytes) } {
            Ok(m) => m,
            Err(_) => {
                artifact_cache_remove(&cache_key);
                compile_and_cache_module(&store, wasm_bytes, cache_key)
            }
        },
        None => compile_and_cache_module(&store, wasm_bytes, cache_key),
    };

    let (instance, wasm_args) = setup_wasm_instance(env, &module, &mut store, false, &function_args);

    let entry_to_call = instance.exports.get_function(&function_name).unwrap_or_else(|e| {
        log_line(env, e.to_string().into_bytes());
        panic_any("exec_function_not_found")
    });
    let start = Instant::now();
    let call_result = entry_to_call.call(&mut store, &wasm_args);
    let duration = start.elapsed();
    //println!("call result {} {:?}", duration.as_millis(), call_result);

    let remaining = match get_remaining_points(&mut store, &instance) {
        MeteringPoints::Remaining(v) => v,
        MeteringPoints::Exhausted => {
            env.exec_left = 0;
            panic_any("exec_insufficient_exec_budget")
        },
    };
    env.exec_left = remaining as i128;

    match call_result {
        Ok(_) => env.caller_env.call_return_value.clone(),
        Err(ref e) if e.message() == "EXIT_IMPORT_RETURN" => env.caller_env.call_return_value.clone(),
        Err(err) => {
            log_line(env, err.message().into_bytes());
            panic_any("exec_error");
        }
    }
}
