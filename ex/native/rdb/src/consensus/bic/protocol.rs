use crate::consensus::bic::coin;
use crate::consensus::consensus_kv;

pub const FORKHEIGHT: u64 = 0;
pub const FORKHEIGHT_TESTNET: u64 = 0;

pub const BRIDGE_FORKHEIGHT: u64 = u64::MAX;
pub const BRIDGE_FORKHEIGHT_TESTNET: u64 = 0;

pub fn riscv_enabled(env: &crate::consensus::consensus_apply::ApplyEnv) -> bool {
    env.testnet
}

pub fn bridge_forkheight(env: &crate::consensus::consensus_apply::ApplyEnv) -> u64 {
    if env.testnet { BRIDGE_FORKHEIGHT_TESTNET } else { BRIDGE_FORKHEIGHT }
}

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

pub const COST_PER_DB_READ_BASE: i128 = 5_000;
pub const COST_PER_DB_READ_BYTE: i128 = 1;

pub const COST_PER_DB_WRITE_BASE: i128 = 25_000;
pub const COST_PER_DB_WRITE_BYTE: i128 = 1;

pub const COST_PER_NEW_LEAF_MERKLE: i128 = COST_PER_BYTE_STATE * 128; //cost to grow the merkle tree

pub const RISCV_GAS_PER_UNIT: i128 = 2;
pub const RISCV_HOST_CALL_COST: i128 = 10;
pub const RISCV_COPY_BYTES_PER_UNIT: u64 = 32;
pub const RISCV_CALL_COST: i128 = 2_000;
pub const RISCV_CODE_WORD_COST: i128 = 6;
pub const RISCV_DEPLOY_BYTE_COST: i128 = 1;
pub const RISCV_PAGE_COST: i128 = 140;
pub const RISCV_SHA256_BLOCK_COST: i128 = 10;
pub const RISCV_KECCAK_BLOCK_COST: i128 = 100;
pub const RISCV_BLAKE3_CHUNK_COST: i128 = 45;
pub const RISCV_BLS_VERIFY_COST: i128 = 250_000;
pub const RISCV_BLS_AGGREGATE_KEY_COST: i128 = 64_000;
pub const RISCV_SECP256K1_RECOVER_COST: i128 = 50_000;
pub const RISCV_SECP256K1_VERIFY_COST: i128 = 25_000;
pub const RISCV_ED25519_VERIFY_COST: i128 = 10_000;

pub const LOG_MSG_SIZE: usize = 4096; //max log line length
pub const LOG_TOTAL_SIZE: usize = 16384; //max log total size
pub const LOG_TOTAL_ELEMENTS: usize = 128; //max elements in list
pub const MAX_PTR_LEN: usize = 1048576;
pub const MAX_RETURN_SIZE: usize = 128;

pub const MAX_DB_KEY_SIZE: usize = 512;
pub const MAX_DB_VALUE_SIZE: usize = 1048576;

pub const MAX_CONTRACT_SIZE: usize = 524288;
pub const MAX_CALL_ARGS_TOTAL: usize = 1 * 1024 * 1024;
pub const MAX_CALL_ARGS: u64 = 16;

pub const MAX_CALL_DEPTH: u32 = 16;
pub const ATTACHMENTS_DECODE_BYTE_COST: i128 = 3;

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
