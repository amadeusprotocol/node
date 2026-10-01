use crate::consensus::bic::coin;
use crate::consensus::consensus_kv;

pub const FORKHEIGHT: u64 = 858_00000;
pub const FORKHEIGHT_TESTNET: u64 = 0;

pub fn forkheight(env: &crate::consensus::consensus_apply::ApplyEnv) -> u64 {
    if env.testnet {
        FORKHEIGHT_TESTNET
    } else {
        FORKHEIGHT
    }
}

pub const AMA_1_DOLLAR: i128 = 1_000_000_000;
pub const AMA_10_CENT: i128 = 100_000_000;
pub const AMA_1_CENT: i128 = 10_000_000;
pub const AMA_01_CENT: i128 = 1_000_000;

//a tx locks one budget, TX_BUDGET + its attached_gas, that covers its history
//charge, a hard exec cap and storage: exec = TX_EXEC_LOCK, storage = budget - exec
//- history charge. the exec cap bounds runtime, so attached_gas only ever buys
//storage and history. unused budget is refunded
pub const TX_BUDGET: i128 = AMA_1_CENT;
pub const TX_EXEC_LOCK: i128 = 2 * AMA_01_CENT;

pub const COST_PER_BYTE_HISTORICAL: i128 = 1_111; //cost to increase the ledger size
pub const COST_PER_BYTE_STATE: i128 = 5_555; //cost to grow the contract state
pub const COST_PER_OP_WASM: i128 = 1; //cost to execute a wasm op

pub const COST_PER_DB_READ_BASE: i128 = 5_000;
pub const COST_PER_DB_READ_BYTE: i128 = 5;

pub const COST_PER_DB_WRITE_BASE: i128 = 25_000;
pub const COST_PER_DB_WRITE_BYTE: i128 = 25;

pub const COST_PER_CALL: i128 = 100_000;
pub const COST_PER_DEPLOY: i128 = AMA_1_CENT; //cost to deploy contract
pub const COST_PER_SLASH: i128 = AMA_1_CENT; //cost to slash_trainer (BLS aggregation over the validator set)
pub const COST_PER_NEW_LEAF_MERKLE: i128 = COST_PER_BYTE_STATE * 128; //cost to grow the merkle tree

//wasm ops are metered 1 point each; a tx pays floor(points / 10)
pub const WASM_POINTS_PER_UNIT: i128 = 10;

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

pub fn cost_per_bytes_historical(bytes: usize) -> i128 {
    COST_PER_BYTE_HISTORICAL
        .checked_mul(bytes as i128)
        .unwrap_or_else(|| std::panic::panic_any("cost_per_byte_overflow"))
}

pub fn tx_historical_cost(txu: &crate::model::tx::TXU) -> i128 {
    let tx_bytes = crate::model::tx::to_bytes_tx(&txu.tx).unwrap_or_else(|_| std::panic::panic_any("invalid_tx_serialization"));
    cost_per_bytes_historical(tx_bytes.len())
}

//(exec lock, storage lock) for a tx, given its history charge and attached_gas
pub fn tx_locks(historical_cost: i128, attached_gas: Option<i128>) -> (i128, i128) {
    let budget = TX_BUDGET.saturating_add(attached_gas.unwrap_or(0));
    (TX_EXEC_LOCK, budget - TX_EXEC_LOCK - historical_cost)
}
