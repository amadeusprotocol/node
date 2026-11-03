use super::vm::{Ecall, Exit, Machine, Memory, Program};
use crate::consensus::bic::protocol;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{exec_budget_decr, kv_delete, kv_exists, kv_get, kv_get_next, kv_get_prev, kv_increment, kv_put, storage_budget_decr};
use std::collections::HashMap;
use std::panic::panic_any;
use std::sync::{Arc, Mutex, OnceLock};

pub const ELF_MAGIC: &[u8] = b"\x7fELF";

pub mod id {
    pub const LOG: u64 = 1;
    pub const RETURN: u64 = 2;
    pub const CALL: u64 = 3;
    pub const KV_PUT: u64 = 4;
    pub const KV_INCREMENT: u64 = 5;
    pub const KV_DELETE: u64 = 6;
    pub const KV_GET: u64 = 7;
    pub const KV_EXISTS: u64 = 8;
    pub const KV_GET_PREV: u64 = 9;
    pub const KV_GET_NEXT: u64 = 10;
    pub const ENV: u64 = 11;
    pub const ARG_COUNT: u64 = 12;
    pub const ARG: u64 = 13;
    pub const FUNCTION: u64 = 14;
    pub const ABORT: u64 = 15;
    pub const SHA256: u64 = 30;
    pub const BLAKE3: u64 = 31;
    pub const KECCAK256: u64 = 32;
    pub const BLS_VERIFY: u64 = 50;
    pub const BLS_AGGREGATE_VERIFY: u64 = 51;
    pub const SECP256K1_RECOVER: u64 = 52;
    pub const SECP256K1_VERIFY: u64 = 53;
    pub const ED25519_VERIFY: u64 = 54;
    pub const EXIT: u64 = 93;
}

pub mod field {
    pub const SEED: u64 = 0;
    pub const ENTRY_SLOT: u64 = 10;
    pub const ENTRY_HEIGHT: u64 = 11;
    pub const ENTRY_EPOCH: u64 = 12;
    pub const ENTRY_SIGNER: u64 = 13;
    pub const ENTRY_PREV_HASH: u64 = 14;
    pub const ENTRY_VR: u64 = 15;
    pub const ENTRY_DR: u64 = 16;
    pub const TX_NONCE: u64 = 30;
    pub const TX_SIGNER: u64 = 31;
    pub const TX_HASH: u64 = 32;
    pub const ACCOUNT_CURRENT: u64 = 50;
    pub const ACCOUNT_CALLER: u64 = 51;
    pub const ACCOUNT_ORIGIN: u64 = 52;
    pub const ATTACHED_SYMBOL: u64 = 70;
    pub const ATTACHED_AMOUNT: u64 = 71;
}

const NOT_FOUND: u64 = u64::MAX;
const CACHE_MAX_BYTES: usize = 512 << 20;
const PREFAULT_BYTES_PER_THREAD: usize = 64 << 20;
const BLANK: [u8; 32] = [0xff; 32];

#[derive(Default)]
struct Pool {
    spare: HashMap<[u8; 32], Vec<Memory>>,
    bytes: usize,
    max: usize,
}

impl Pool {
    fn take(&mut self, key: &[u8; 32], size: usize, lend: bool) -> Option<Memory> {
        let key = match self.spare.contains_key(key) {
            true => *key,
            false if !lend => return None,
            false => *self.spare.iter().filter_map(|(k, list)| list.last().filter(|m| m.capacity() >= size).map(|m| (m.capacity(), k))).min()?.1,
        };
        let list = self.spare.get_mut(&key)?;
        let mem = list.pop()?;
        if list.is_empty() {
            self.spare.remove(&key);
        }
        self.bytes -= mem.bytes();
        Some(mem)
    }

    fn put(&mut self, key: [u8; 32], mem: Memory) {
        if self.bytes + mem.bytes() > self.max {
            return;
        }
        self.bytes += mem.bytes();
        self.spare.entry(key).or_default().push(mem);
    }
}

fn pool() -> &'static Mutex<Pool> {
    static POOL: OnceLock<Mutex<Pool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let threads = crate::consensus::consensus_apply::apply_pool().current_num_threads() + 1;
        Mutex::new(Pool { max: threads * PREFAULT_BYTES_PER_THREAD, ..Pool::default() })
    })
}

fn pool_take(key: &[u8; 32], size: usize, lend: bool) -> Option<Memory> {
    pool().lock().unwrap_or_else(|p| p.into_inner()).take(key, size, lend)
}

fn pool_put(key: [u8; 32], mem: Memory) {
    pool().lock().unwrap_or_else(|p| p.into_inner()).put(key, mem)
}

pub fn prefault() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    if cfg!(test) {
        return;
    }
    ONCE.call_once(|| {
        std::thread::spawn(|| {
            let max = pool().lock().unwrap_or_else(|p| p.into_inner()).max;
            for _ in 0..max / (super::vm::MAX_MEM as usize) {
                pool_put(BLANK, Memory::blank(super::vm::MAX_MEM as usize));
            }
        });
    });
}

pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(ELF_MAGIC)
}

pub fn validate(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() > protocol::MAX_CONTRACT_SIZE {
        return Err("riscv_bytecode_too_large");
    }
    if !is_elf(bytes) {
        return Err("riscv_invalid_bytecode");
    }
    super::vm::load(bytes).map(|_| ())
}

struct Cache {
    map: HashMap<[u8; 32], (Arc<Program>, u64)>,
    bytes: usize,
    tick: u64,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cache { map: HashMap::new(), bytes: 0, tick: 0 }))
}

fn program(bytecode: &[u8]) -> ([u8; 32], Arc<Program>) {
    let key: [u8; 32] = *blake3::hash(bytecode).as_bytes();
    {
        let mut c = cache().lock().unwrap_or_else(|p| p.into_inner());
        c.tick += 1;
        let tick = c.tick;
        if let Some((p, last)) = c.map.get_mut(&key) {
            *last = tick;
            return (key, p.clone());
        }
    }
    if bytecode.len() > protocol::MAX_CONTRACT_SIZE {
        panic_any("riscv_bytecode_too_large")
    }
    let p = Arc::new(super::vm::load(bytecode).unwrap_or_else(|_| panic_any("riscv_invalid_bytecode")));
    let mut c = cache().lock().unwrap_or_else(|p| p.into_inner());
    let size = p.footprint();
    while c.bytes + size > CACHE_MAX_BYTES && !c.map.is_empty() {
        let lru = *c.map.iter().min_by_key(|(_, (_, last))| *last).map(|(k, _)| k).unwrap();
        if let Some((old, _)) = c.map.remove(&lru) {
            c.bytes -= old.footprint();
        }
    }
    c.tick += 1;
    let tick = c.tick;
    if c.map.insert(key, (p.clone(), tick)).is_none() {
        c.bytes += size;
    }
    (key, p)
}

struct Meter {
    units: i128,
    points: u64,
}

impl Meter {
    fn start(env: &ApplyEnv) -> Meter {
        let units = env.exec_left.max(0);
        Meter { units, points: units.saturating_mul(protocol::RISCV_GAS_PER_UNIT).min(u64::MAX as i128) as u64 }
    }

    fn sync_in(&self, env: &mut ApplyEnv, gas_left: u64) {
        let used = self.points.saturating_sub(gas_left) as i128;
        env.exec_left = self.units - used / protocol::RISCV_GAS_PER_UNIT;
    }

    fn sync_out(&mut self, env: &ApplyEnv, m: &mut Machine) {
        *self = Meter::start(env);
        m.gas = self.points;
    }
}

struct Call {
    function: String,
    args: Vec<Vec<u8>>,
    meter: Meter,
}

fn copy_cost(env: &mut ApplyEnv, len: u64) {
    exec_budget_decr(env, len.div_ceil(protocol::RISCV_COPY_BYTES_PER_UNIT) as i128);
}

fn read(env: &mut ApplyEnv, m: &Machine, ptr: u64, len: u64) -> Vec<u8> {
    if len > protocol::MAX_PTR_LEN as u64 {
        panic_any("riscv_ptr_too_long")
    }
    copy_cost(env, len);
    m.mem(ptr, len).unwrap_or_else(|| panic_any("riscv_invalid_ptr")).to_vec()
}

fn write(env: &mut ApplyEnv, m: &mut Machine, out: u64, cap: u64, data: &[u8]) -> u64 {
    let n = cap.min(data.len() as u64);
    copy_cost(env, n);
    m.mem_mut(out, n).unwrap_or_else(|| panic_any("riscv_invalid_ptr")).copy_from_slice(&data[..n as usize]);
    data.len() as u64
}

fn storage_key(env: &ApplyEnv, key: &[u8]) -> Vec<u8> {
    crate::bcat(&[b"account:", &env.caller_env.account_current, b":storage:", key])
}

pub fn log_line(env: &mut ApplyEnv, line: Vec<u8>) {
    let len = line.len();
    if len > protocol::LOG_MSG_SIZE {
        panic_any("host_log_msg_size_exceeded")
    }
    if env.logs_size.saturating_add(len) > protocol::LOG_TOTAL_SIZE {
        panic_any("host_logs_total_size_exceeded")
    }
    if env.logs.len() >= protocol::LOG_TOTAL_ELEMENTS {
        panic_any("host_logs_total_elements_exceeded")
    }
    env.logs.push(line);
    env.logs_size += len
}

fn arg_table(env: &mut ApplyEnv, m: &Machine, table: u64) -> Vec<(u64, u64)> {
    let count = u64::from_le_bytes(read(env, m, table, 8).try_into().unwrap());
    if count > 16 {
        panic_any("host_call_too_many_args")
    }
    let raw = read(env, m, table + 8, 16 * count);
    raw.chunks_exact(16).map(|c| (u64::from_le_bytes(c[..8].try_into().unwrap()), u64::from_le_bytes(c[8..].try_into().unwrap()))).collect()
}

fn call_out(env: &mut ApplyEnv, m: &mut Machine, table: u64, extra: u64) -> Vec<u8> {
    let main = arg_table(env, m, table);
    let extra = if extra == 0 { Vec::new() } else { arg_table(env, m, extra) };
    let mut total: u64 = 0;
    for &(_, len) in main.iter().chain(&extra) {
        if len > protocol::MAX_PTR_LEN as u64 {
            panic_any("riscv_call_ptr_too_long")
        }
        total = total.saturating_add(len);
    }
    if total > protocol::MAX_CALL_ARGS_TOTAL as u64 {
        panic_any("host_call_total_args_too_long")
    }
    let main: Vec<Vec<u8>> = main.iter().map(|&(p, l)| read(env, m, p, l)).collect();
    let extra: Vec<Vec<u8>> = extra.iter().map(|&(p, l)| read(env, m, p, l)).collect();
    if main.len() < 2 {
        panic_any("host_call_missing_args")
    }
    let (contract, function, args) = (main[0].clone(), main[1].clone(), main[2..].to_vec());
    let (attached_symbol, attached_amount) = if extra.len() == 2 { (Some(extra[0].clone()), Some(extra[1].clone())) } else { (None, None) };

    exec_budget_decr(env, protocol::RISCV_CALL_COST);
    if env.call_depth >= protocol::MAX_CALL_DEPTH {
        panic_any("exec_call_depth_exceeded")
    }
    let og_caller = env.caller_env.account_caller.clone();
    let og_current = env.caller_env.account_current.clone();
    let og_symbol = env.caller_env.attached_symbol.clone();
    let og_amount = env.caller_env.attached_amount.clone();
    let og_seed = env.caller_env.seed.clone();
    env.caller_env.account_caller = og_current.clone();
    env.caller_env.account_current = contract.clone();
    env.caller_env.call_counter = env.caller_env.call_counter.saturating_add(1);
    env.caller_env.call_return_value = Vec::new();

    let result = match contract.len() {
        48 => crate::consensus::consensus_apply::call_vm(env, contract, function, args, attached_symbol, attached_amount),
        _ => {
            crate::consensus::consensus_apply::call_bic(env, contract, function, args, attached_symbol, attached_amount);
            b"ok".to_vec()
        }
    };

    env.caller_env.account_caller = og_caller;
    env.caller_env.account_current = og_current;
    env.caller_env.attached_symbol = og_symbol;
    env.caller_env.attached_amount = og_amount;
    env.caller_env.seed = og_seed;
    env.caller_env.call_return_value = Vec::new();
    result
}

fn env_field(env: &ApplyEnv, f: u64) -> Vec<u8> {
    let c = &env.caller_env;
    match f {
        field::SEED => c.seed.clone(),
        field::ENTRY_SLOT => c.entry_slot.to_le_bytes().to_vec(),
        field::ENTRY_HEIGHT => c.entry_height.to_le_bytes().to_vec(),
        field::ENTRY_EPOCH => c.entry_epoch.to_le_bytes().to_vec(),
        field::ENTRY_SIGNER => c.entry_signer.to_vec(),
        field::ENTRY_PREV_HASH => c.entry_prev_hash.to_vec(),
        field::ENTRY_VR => c.entry_vr.to_vec(),
        field::ENTRY_DR => c.entry_dr.to_vec(),
        field::TX_NONCE => c.tx_nonce.to_le_bytes().to_vec(),
        field::TX_SIGNER => c.tx_signer.to_vec(),
        field::TX_HASH => c.tx_hash.to_vec(),
        field::ACCOUNT_CURRENT => c.account_current.clone(),
        field::ACCOUNT_CALLER => c.account_caller.clone(),
        field::ACCOUNT_ORIGIN => c.account_origin.clone(),
        field::ATTACHED_SYMBOL => c.attached_symbol.clone(),
        field::ATTACHED_AMOUNT => c.attached_amount.clone(),
        _ => panic_any("host_invalid_env_field"),
    }
}

fn found_pair(k: &[u8], v: &[u8]) -> Vec<u8> {
    crate::bcat(&[&(k.len() as u32).to_le_bytes(), k, &(v.len() as u32).to_le_bytes(), v])
}

fn host(env: &mut ApplyEnv, call: &mut Call, m: &mut Machine) -> Ecall {
    let id = m.regs[17];
    let [a0, a1, a2, a3, a4, a5, a6] = [m.regs[10], m.regs[11], m.regs[12], m.regs[13], m.regs[14], m.regs[15], m.regs[16]];
    call.meter.sync_in(env, m.gas);
    if id == id::EXIT {
        return Ecall::Done(a0);
    }
    exec_budget_decr(env, protocol::RISCV_HOST_CALL_COST);
    let ret: u64 = match id {
        id::LOG => {
            let line = read(env, m, a0, a1);
            storage_budget_decr(env, protocol::cost_per_bytes_historical(line.len()));
            log_line(env, line);
            0
        }
        id::RETURN => {
            let value = read(env, m, a0, a1);
            storage_budget_decr(env, protocol::cost_per_bytes_historical(value.len()));
            if value.len() > protocol::MAX_RETURN_SIZE {
                panic_any("host_return_value_too_large")
            }
            env.caller_env.call_return_value = value;
            call.meter.sync_out(env, m);
            return Ecall::Done(0);
        }
        id::CALL => {
            let result = call_out(env, m, a0, a1);
            write(env, m, a2, a3, &result)
        }
        id::KV_PUT => {
            let (key, value) = (read(env, m, a0, a1), read(env, m, a2, a3));
            kv_put(env, &storage_key(env, &key), &value);
            0
        }
        id::KV_INCREMENT => {
            let (key, value) = (read(env, m, a0, a1), read(env, m, a2, a3));
            let delta = std::str::from_utf8(&value).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("host_invalid_integer"));
            let new_value = kv_increment(env, &storage_key(env, &key), delta).to_string();
            write(env, m, a4, a5, new_value.as_bytes())
        }
        id::KV_DELETE => {
            let key = read(env, m, a0, a1);
            kv_delete(env, &storage_key(env, &key));
            0
        }
        id::KV_GET => {
            let key = read(env, m, a0, a1);
            match kv_get(env, &storage_key(env, &key)) {
                Some(v) => write(env, m, a2, a3, &v),
                None => NOT_FOUND,
            }
        }
        id::KV_EXISTS => {
            let key = read(env, m, a0, a1);
            kv_exists(env, &storage_key(env, &key)) as u64
        }
        id::KV_GET_PREV | id::KV_GET_NEXT => {
            let (prefix, key) = (read(env, m, a0, a1), read(env, m, a2, a3));
            let prefix = storage_key(env, &prefix);
            let found = if id == id::KV_GET_PREV { kv_get_prev(env, &prefix, &key) } else { kv_get_next(env, &prefix, &key) };
            match found {
                Some((k, v)) => write(env, m, a4, a5, &found_pair(&k, &v)),
                None => NOT_FOUND,
            }
        }
        id::ENV => {
            let value = env_field(env, a0);
            write(env, m, a1, a2, &value)
        }
        id::ARG_COUNT => call.args.len() as u64,
        id::ARG => match call.args.get(a0 as usize) {
            Some(arg) => write(env, m, a1, a2, arg),
            None => NOT_FOUND,
        },
        id::FUNCTION => write(env, m, a0, a1, call.function.as_bytes()),
        id::ABORT => {
            let msg = read(env, m, a0, a1.min(protocol::LOG_MSG_SIZE as u64));
            storage_budget_decr(env, protocol::cost_per_bytes_historical(msg.len()));
            log_line(env, msg);
            panic_any("abort")
        }
        id::SHA256 => {
            use sha2::Digest;
            exec_budget_decr(env, protocol::RISCV_SHA256_BLOCK_COST.saturating_mul(a1.saturating_add(72) as i128 / 64));
            let digest: [u8; 32] = sha2::Sha256::digest(read(env, m, a0, a1)).into();
            write(env, m, a2, 32, &digest)
        }
        id::BLAKE3 => {
            exec_budget_decr(env, protocol::RISCV_BLAKE3_CHUNK_COST.saturating_mul(a1.saturating_add(1024) as i128 / 1024));
            let digest = *blake3::hash(&read(env, m, a0, a1)).as_bytes();
            write(env, m, a2, 32, &digest)
        }
        id::BLS_VERIFY => {
            if a3 > protocol::MAX_PTR_LEN as u64 || a5 > 255 {
                panic_any("riscv_ptr_too_long")
            }
            exec_budget_decr(env, protocol::RISCV_BLS_VERIFY_COST.saturating_add(protocol::RISCV_SHA256_BLOCK_COST.saturating_mul(a3.saturating_add(72) as i128 / 64)));
            let (pk, sig, msg, dst) = (read(env, m, a0, 48), read(env, m, a1, 96), read(env, m, a2, a3), read(env, m, a4, a5));
            crate::consensus::bls12_381::verify(&pk, &sig, &msg, &dst).is_ok() as u64
        }
        id::BLS_AGGREGATE_VERIFY => {
            if a1 == 0 || a1 > 1024 || a4 > protocol::MAX_PTR_LEN as u64 || a6 > 255 {
                panic_any("riscv_ptr_too_long")
            }
            exec_budget_decr(
                env,
                protocol::RISCV_BLS_VERIFY_COST
                    .saturating_add(protocol::RISCV_BLS_AGGREGATE_KEY_COST.saturating_mul(a1 as i128))
                    .saturating_add(protocol::RISCV_SHA256_BLOCK_COST.saturating_mul(a4.saturating_add(72) as i128 / 64)),
            );
            let pks = read(env, m, a0, 48 * a1);
            let (sig, msg, dst) = (read(env, m, a2, 96), read(env, m, a3, a4), read(env, m, a5, a6));
            match crate::consensus::bls12_381::aggregate_public_keys(pks.chunks_exact(48)) {
                Ok(agg) => crate::consensus::bls12_381::verify(&agg, &sig, &msg, &dst).is_ok() as u64,
                Err(_) => 0,
            }
        }
        id::KECCAK256 => {
            use sha3::Digest;
            exec_budget_decr(env, protocol::RISCV_KECCAK_BLOCK_COST.saturating_mul(a1.saturating_add(136) as i128 / 136));
            let digest: [u8; 32] = sha3::Keccak256::digest(read(env, m, a0, a1)).into();
            write(env, m, a2, 32, &digest)
        }
        id::SECP256K1_RECOVER => {
            use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
            exec_budget_decr(env, protocol::RISCV_SECP256K1_RECOVER_COST);
            let (hash, sig) = (read(env, m, a0, 32), read(env, m, a1, 64));
            let key = Signature::from_slice(&sig).ok().zip(u8::try_from(a2).ok().and_then(RecoveryId::from_byte)).and_then(|(sig, id)| VerifyingKey::recover_from_prehash(&hash, &sig, id).ok());
            match key {
                Some(key) => write(env, m, a3, 65, key.to_encoded_point(false).as_bytes()),
                None => NOT_FOUND,
            }
        }
        id::SECP256K1_VERIFY => {
            use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
            exec_budget_decr(env, protocol::RISCV_SECP256K1_VERIFY_COST);
            if a1 != 33 && a1 != 65 {
                panic_any("host_invalid_pubkey_len")
            }
            let (pk, hash, sig) = (read(env, m, a0, a1), read(env, m, a2, 32), read(env, m, a3, 64));
            let ok = VerifyingKey::from_sec1_bytes(&pk).ok().zip(Signature::from_slice(&sig).ok()).is_some_and(|(key, sig)| key.verify_prehash(&hash, &sig).is_ok());
            ok as u64
        }
        id::ED25519_VERIFY => {
            if a3 > protocol::MAX_PTR_LEN as u64 {
                panic_any("riscv_ptr_too_long")
            }
            exec_budget_decr(env, protocol::RISCV_ED25519_VERIFY_COST.saturating_add(protocol::RISCV_SHA256_BLOCK_COST.saturating_mul(a3.saturating_add(72) as i128 / 64)));
            let (pk, sig, msg) = (read(env, m, a0, 32), read(env, m, a1, 64), read(env, m, a2, a3));
            let key = ed25519_dalek::VerifyingKey::from_bytes(&pk.try_into().unwrap()).ok();
            let sig = ed25519_dalek::Signature::from_bytes(&sig.try_into().unwrap());
            key.is_some_and(|k| k.verify_strict(&msg, &sig).is_ok()) as u64
        }
        _ => panic_any("riscv_invalid_host_call"),
    };
    m.regs[10] = ret;
    call.meter.sync_out(env, m);
    Ecall::Continue
}

pub fn call(env: &mut ApplyEnv, bytecode: &[u8], function: String, args: Vec<Vec<u8>>) -> Vec<u8> {
    env.caller_env.call_return_value = Vec::new();
    let (key, p) = program(bytecode);
    let setup = protocol::RISCV_CODE_WORD_COST.saturating_mul(p.code_words() as i128).saturating_add(protocol::RISCV_PAGE_COST.saturating_mul(p.pages() as i128));
    exec_budget_decr(env, setup);

    let meter = Meter::start(env);
    let mut m = Machine::reuse(&p, meter.points, pool_take(&key, p.pages() << 12, !env.readonly));
    let mut call = Call { function, args, meter };
    let exit = m.run(&mut |m: &mut Machine| host(env, &mut call, m));
    call.meter.sync_in(env, m.gas);
    pool_put(key, m.into_memory());
    match exit {
        Exit::Done(0) => env.caller_env.call_return_value.clone(),
        Exit::Done(_) => panic_any("abort"),
        Exit::OutOfGas => {
            env.exec_left = 0;
            panic_any("exec_insufficient_exec_budget")
        }
        Exit::Trap(reason) => {
            log_line(env, reason.as_bytes().to_vec());
            panic_any("trap")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_keeps_no_empty_entries_and_lends_spare_buffers() {
        let p = super::super::vm::load_raw(0x1000, 0x1000, &[0x73, 0, 0, 0], vec![], 0x1004).unwrap();
        let mut pool = Pool { max: 64 << 20, ..Pool::default() };
        let (key, other) = ([7u8; 32], [8u8; 32]);
        pool.put(key, Machine::new(&p, 1).into_memory());
        assert!(pool.take(&key, 4096, true).is_some());
        assert!(pool.take(&key, 4096, true).is_none());
        assert!(pool.spare.is_empty() && pool.bytes == 0);

        pool.put(BLANK, Memory::blank(1 << 20));
        pool.put(BLANK, Memory::blank(8 << 20));
        assert!(pool.take(&other, 4096, false).is_none());
        assert_eq!(pool.take(&other, 2 << 20, true).map(|m| m.capacity()), Some(8 << 20));
        assert!(pool.take(&other, 2 << 20, true).is_none());
        assert_eq!(pool.take(&other, 4096, true).map(|m| m.capacity()), Some(1 << 20));
        assert!(pool.spare.is_empty() && pool.bytes == 0);

        pool.put(BLANK, Memory::blank(60 << 20));
        pool.put(key, Memory::blank(8 << 20));
        assert_eq!(pool.spare.len(), 1);
    }
}
