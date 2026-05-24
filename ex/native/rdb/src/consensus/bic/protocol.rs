use crate::consensus::bic::coin;
use crate::consensus::consensus_kv;

pub const FORKHEIGHT: u64 = 490_00000;
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

pub const RESERVE_AMA_PER_TX_EXEC: i128 = AMA_10_CENT; //reserved for exec balance (refunded at end of TX execution)
pub const RESERVE_AMA_PER_TX_STORAGE: i128 = AMA_1_DOLLAR; //reserved for storage writes

pub const COST_PER_BYTE_HISTORICAL: i128 = 6_666; //cost to increase the ledger size
pub const COST_PER_BYTE_STATE: i128 = 16_666; //cost to grow the contract state
pub const COST_PER_OP_WASM: i128 = 1; //cost to execute a wasm op

pub const COST_PER_DB_READ_BASE: i128 = 5_000 * 10;
pub const COST_PER_DB_READ_BYTE: i128 = 50;

pub const COST_PER_DB_WRITE_BASE: i128 = 25_000 * 10;
pub const COST_PER_DB_WRITE_BYTE: i128 = 250;

pub fn cost_db_read_byte(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if env.caller_env.entry_height >= forkheight(env) {
        COST_PER_DB_READ_BYTE
    } else {
        COST_PER_DB_READ_BYTE
    };
    COST_PER_DB_READ_BYTE
}

pub fn cost_db_write_byte(env: &crate::consensus::consensus_apply::ApplyEnv) -> i128 {
    if env.caller_env.entry_height >= forkheight(env) {
        COST_PER_DB_WRITE_BYTE
    } else {
        COST_PER_DB_WRITE_BYTE
    };
    COST_PER_DB_WRITE_BYTE
}

pub const COST_PER_CALL: i128 = AMA_01_CENT;
pub const COST_PER_DEPLOY: i128 = AMA_1_CENT; //cost to deploy contract
pub const COST_PER_SOL: i128 = AMA_1_CENT; //cost to submit_sol
pub const COST_PER_NEW_LEAF_MERKLE: i128 = COST_PER_BYTE_STATE * 128; //cost to grow the merkle tree

pub const LOG_MSG_SIZE: usize = 4096; //max log line length
pub const LOG_TOTAL_SIZE: usize = 16384; //max log total size
pub const LOG_TOTAL_ELEMENTS: usize = 32; //max elements in list
pub const WASM_MAX_PTR_LEN: usize = 1048576; //largest term passable from inside WASM to HOST
                                             //pub const WASM_MAX_PTR_LEN: usize = 32768; //dont smash passed first page
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
    consensus_kv::kv_increment(
        env,
        &crate::bcat(&[b"account:", &env.caller_env.account_origin, b":balance:AMA"]),
        -cost,
    );
    // Increment validator / burn
    consensus_kv::kv_increment(
        env,
        &crate::bcat(&[b"account:", &env.caller_env.entry_signer, b":balance:AMA"]),
        cost / 2,
    );
    consensus_kv::kv_increment(
        env,
        &crate::bcat(&[b"account:", &coin::BURN_ADDRESS, b":balance:AMA"]),
        cost / 2,
    );
}

pub fn tx_historical_cost(txu: &crate::model::tx::TXU) -> i128 {
    let tx_bytes = crate::model::tx::to_bytes_tx(&txu.tx)
        .unwrap_or_else(|_| std::panic::panic_any("invalid_tx_serialization"));
    std::cmp::max(
        AMA_1_CENT,
        COST_PER_BYTE_HISTORICAL * tx_bytes.len() as i128,
    )
}
