use crate::consensus::bic::coin;
use crate::consensus::consensus_kv;

//epoch 858 mainnet: cheaper fees and a 0.01 AMA per-tx budget (see the _FORK
//constants below). everything before it keeps the old prices
pub const FORKHEIGHT: u64 = 858_00000;
pub const FORKHEIGHT_TESTNET: u64 = 0;

pub fn forkheight(env: &crate::consensus::consensus_apply::ApplyEnv) -> u64 {
    if env.testnet {
        FORKHEIGHT_TESTNET
    } else {
        FORKHEIGHT
    }
}

pub fn is_fork(env: &crate::consensus::consensus_apply::ApplyEnv) -> bool {
    env.caller_env.entry_height >= forkheight(env)
}

pub const AMA_1_DOLLAR: i128 = 1_000_000_000;
pub const AMA_10_CENT: i128 = 100_000_000;
pub const AMA_1_CENT: i128 = 10_000_000;
pub const AMA_01_CENT: i128 = 1_000_000;

pub const RESERVE_AMA_PER_TX_EXEC: i128 = AMA_10_CENT; //reserved for exec balance (refunded at end of TX execution)
pub const RESERVE_AMA_PER_TX_STORAGE: i128 = AMA_1_DOLLAR; //reserved for storage writes

pub const COST_PER_BYTE_HISTORICAL: i128 = 6_666; //cost to increase the ledger size
pub const COST_PER_BYTE_STATE: i128 = 16_666; //cost to grow the contract state
pub const COST_PER_OP_WASM: i128 = 1; //cost to execute a wasm op

pub const COST_PER_DB_READ_BASE: i128 = 5_000 * 10;
pub const COST_PER_DB_READ_BYTE: i128 = 50;

pub const COST_PER_DB_WRITE_BASE: i128 = 25_000 * 10;
pub const COST_PER_DB_WRITE_BYTE: i128 = 250;

pub const COST_PER_CALL: i128 = AMA_01_CENT;
pub const COST_PER_DEPLOY: i128 = AMA_1_CENT; //cost to deploy contract
pub const COST_PER_SLASH: i128 = AMA_1_CENT; //cost to slash_trainer (BLS aggregation over the validator set)
pub const COST_PER_NEW_LEAF_MERKLE: i128 = COST_PER_BYTE_STATE * 128; //cost to grow the merkle tree

//from FORKHEIGHT. a tx locks one budget, TX_BUDGET_FORK + its attached_gas, that
//covers its history charge, a hard exec cap and storage: exec = TX_EXEC_LOCK_FORK,
//storage = budget - exec - history charge. the exec cap bounds runtime, so
//attached_gas only ever buys storage and history. unused budget is refunded
pub const TX_BUDGET_FORK: i128 = AMA_1_CENT;
pub const TX_EXEC_LOCK_FORK: i128 = 2 * AMA_01_CENT;

pub const COST_PER_BYTE_HISTORICAL_FORK: i128 = 1_111;
pub const COST_PER_BYTE_STATE_FORK: i128 = 5_555;
pub const COST_PER_NEW_LEAF_MERKLE_FORK: i128 = COST_PER_BYTE_STATE_FORK * 128;
pub const COST_PER_DB_READ_BASE_FORK: i128 = 5_000;
pub const COST_PER_DB_READ_BYTE_FORK: i128 = 5;
pub const COST_PER_DB_WRITE_BASE_FORK: i128 = 25_000;
pub const COST_PER_DB_WRITE_BYTE_FORK: i128 = 25;
pub const COST_PER_CALL_FORK: i128 = 100_000;
//wasm ops are metered 1 point each; from FORKHEIGHT a tx pays floor(points / 10)
pub const WASM_POINTS_PER_UNIT_FORK: i128 = 10;

pub fn cost_db_read_base(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if is_fork(env) { COST_PER_DB_READ_BASE_FORK } else { COST_PER_DB_READ_BASE }
}

pub fn cost_db_read_byte(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if is_fork(env) { COST_PER_DB_READ_BYTE_FORK } else { COST_PER_DB_READ_BYTE }
}

pub fn cost_db_write_base(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if is_fork(env) { COST_PER_DB_WRITE_BASE_FORK } else { COST_PER_DB_WRITE_BASE }
}

pub fn cost_db_write_byte(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if is_fork(env) { COST_PER_DB_WRITE_BYTE_FORK } else { COST_PER_DB_WRITE_BYTE }
}

pub fn cost_byte_state(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if is_fork(env) { COST_PER_BYTE_STATE_FORK } else { COST_PER_BYTE_STATE }
}

pub fn cost_new_leaf_merkle(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if is_fork(env) { COST_PER_NEW_LEAF_MERKLE_FORK } else { COST_PER_NEW_LEAF_MERKLE }
}

pub fn cost_call(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if is_fork(env) { COST_PER_CALL_FORK } else { COST_PER_CALL }
}

pub fn wasm_points_per_unit(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if is_fork(env) { WASM_POINTS_PER_UNIT_FORK } else { 1 }
}

pub const LOG_MSG_SIZE: usize = 4096; //max log line length
pub const LOG_TOTAL_SIZE: usize = 16384; //max log total size
pub const LOG_TOTAL_ELEMENTS: usize = 32; //max elements in list
pub const WASM_MAX_PTR_LEN: usize = 1048576; //largest term passable from inside WASM to HOST
pub const WASM_MAX_PANIC_MSG_SIZE: usize = 128;

pub const MAX_DB_KEY_SIZE: usize = 512;
pub const MAX_DB_VALUE_SIZE: usize = 1048576;

pub const WASM_MAX_BINARY_SIZE: usize = 1048576;
pub const WASM_MAX_CALL_ARGS_TOTAL: usize = 1 * 1024 * 1024;
pub const WASM_MAX_FUNCTIONS: u32 = 1000;
pub const WASM_MAX_GLOBALS: u32 = 100;
pub const WASM_MAX_EXPORTS: u32 = 50;
pub const WASM_MAX_IMPORTS: u32 = 50;

pub const MAX_CALL_DEPTH: u32 = 16;

pub fn pay_cost(env: &mut crate::consensus::consensus_apply::ApplyEnv, cost: i128) {
    if cost < 0 {
        std::panic::panic_any("pay_cost_negative")
    }
    consensus_kv::kv_increment(env, &crate::bcat(&[b"account:", &env.caller_env.account_origin, b":balance:AMA"]), -cost);
    // Increment validator / burn
    consensus_kv::kv_increment(env, &crate::bcat(&[b"account:", &env.caller_env.entry_signer, b":balance:AMA"]), cost / 2);
    consensus_kv::kv_increment(env, &crate::bcat(&[b"account:", &coin::BURN_ADDRESS, b":balance:AMA"]), cost / 2);
}

pub fn cost_per_bytes_historical(env: &crate::consensus::consensus_apply::ApplyEnv, bytes: usize) -> i128 {
    let per_byte = if is_fork(env) { COST_PER_BYTE_HISTORICAL_FORK } else { COST_PER_BYTE_HISTORICAL };
    per_byte
        .checked_mul(bytes as i128)
        .unwrap_or_else(|| std::panic::panic_any("cost_per_byte_overflow"))
}

//before FORKHEIGHT a tx paid at least AMA_1_CENT; from it, just its bytes
pub fn tx_historical_cost(env: &crate::consensus::consensus_apply::ApplyEnv, txu: &crate::model::tx::TXU) -> i128 {
    let tx_bytes = crate::model::tx::to_bytes_tx(&txu.tx).unwrap_or_else(|_| std::panic::panic_any("invalid_tx_serialization"));
    let cost = cost_per_bytes_historical(env, tx_bytes.len());
    if is_fork(env) { cost } else { std::cmp::max(AMA_1_CENT, cost) }
}

//(exec lock, storage lock) for a tx, given its history charge and attached_gas.
//before FORKHEIGHT: the fixed RESERVE_AMA_PER_TX_EXEC / _STORAGE
pub fn tx_locks(env: &crate::consensus::consensus_apply::ApplyEnv, historical_cost: i128, attached_gas: Option<i128>) -> (i128, i128) {
    if !is_fork(env) {
        return (RESERVE_AMA_PER_TX_EXEC, RESERVE_AMA_PER_TX_STORAGE)
    }
    let budget = TX_BUDGET_FORK + attached_gas.unwrap_or(0);
    (TX_EXEC_LOCK_FORK, budget - TX_EXEC_LOCK_FORK - historical_cost)
}
