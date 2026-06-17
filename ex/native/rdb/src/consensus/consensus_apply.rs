use crate::{consensus, BoundColumnFamily, MultiThreaded, Transaction, TransactionDB, TransactionOptions, WriteOptions};

use crate::consensus::bic::protocol;
use crate::consensus::consensus_muts;
use crate::consensus::{consensus_kv, hbsmt_common};
use crate::model::tx_receipt::TXReceipt;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::panic::panic_any;
use std::sync::OnceLock;

static SOL_VERIFY_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

pub struct CallerEnv {
    pub readonly: bool,
    pub seed: Vec<u8>,
    pub seedf64: f64,
    pub entry_signer: [u8; 48],
    pub entry_prev_hash: [u8; 32],
    pub entry_slot: u64,
    pub entry_prev_slot: u64,
    pub entry_height: u64,
    pub entry_epoch: u64,
    pub entry_vr: [u8; 96],
    pub entry_vr_b3: [u8; 32],
    pub entry_dr: [u8; 32],
    pub tx_index: u64,
    pub tx_signer: [u8; 48],
    pub tx_nonce: u64,
    pub tx_hash: [u8; 32],
    pub account_origin: Vec<u8>,
    pub account_caller: Vec<u8>,
    pub account_current: Vec<u8>,
    pub attached_symbol: Vec<u8>,
    pub attached_amount: Vec<u8>,
    pub call_counter: u32,
    pub call_exec_points: u64,
    pub call_exec_points_remaining: u64,
    pub call_return_value: Vec<u8>,
}

pub fn make_caller_env(
    entry_signer: &[u8; 48],
    entry_prev_hash: &[u8; 32],
    entry_slot: u64,
    entry_prev_slot: u64,
    entry_height: u64,
    entry_epoch: u64,
    entry_vr: &[u8; 96],
    entry_vr_b3: &[u8; 32],
    entry_dr: &[u8; 32],
) -> CallerEnv {
    CallerEnv {
        readonly: false,
        seed: Vec::new(),
        seedf64: 1.0,
        entry_signer: *entry_signer,
        entry_prev_hash: *entry_prev_hash,
        entry_slot: entry_slot,
        entry_prev_slot: entry_prev_slot,
        entry_height: entry_height,
        entry_epoch: entry_epoch,
        entry_vr: *entry_vr,
        entry_vr_b3: *entry_vr_b3,
        entry_dr: *entry_dr,
        tx_index: 0,
        tx_signer: [0u8; 48],
        tx_nonce: 0,
        tx_hash: [0u8; 32],
        account_origin: Vec::new(),
        account_caller: Vec::new(),
        account_current: Vec::new(),
        attached_symbol: Vec::new(),
        attached_amount: Vec::new(),
        call_counter: 0,
        call_exec_points: 10_000_000,
        call_exec_points_remaining: 10_000_000,
        call_return_value: Vec::new(),
    }
}

pub struct ApplyEnv<'db> {
    pub caller_env: CallerEnv,
    pub db: &'db TransactionDB<MultiThreaded>,
    pub cf: std::sync::Arc<BoundColumnFamily<'db>>,
    pub cf_name: Vec<u8>,
    pub cf_contractstate: std::sync::Arc<BoundColumnFamily<'db>>,
    pub cf_contractstate_tree_hbsmt: std::sync::Arc<BoundColumnFamily<'db>>,
    pub txn: Transaction<'db, TransactionDB<MultiThreaded>>,
    pub muts_final: Vec<consensus_muts::Mutation>,
    pub muts_final_rev: Vec<consensus_muts::Mutation>,
    pub muts: Vec<consensus_muts::Mutation>,
    pub muts_rev: Vec<consensus_muts::Mutation>,
    pub exec_track: bool,
    pub exec_left: i128,
    pub exec_max: i128,
    pub storage_left: i128,
    pub storage_max: i128,
    pub receipts: Vec<TXReceipt>,
    pub logs: Vec<Vec<u8>>,
    pub logs_size: usize,
    pub preverified_sol_hashes: HashSet<[u8; 32]>,
    pub testnet: bool,
    pub testnet_peddlebikes: Vec<Vec<u8>>,
    pub readonly: bool,
    pub call_depth: u32,
}

impl<'db> ApplyEnv<'db> {
    fn into_parts(
        self,
        root_receipts: [u8; 32],
        root_contractstate: [u8; 32],
    ) -> (Transaction<'db, TransactionDB<MultiThreaded>>, Vec<consensus_muts::Mutation>, Vec<consensus_muts::Mutation>, Vec<TXReceipt>, [u8; 32], [u8; 32])
    {
        (self.txn, self.muts_final, self.muts_final_rev, self.receipts, root_receipts, root_contractstate)
    }
}

pub fn make_apply_env<'db>(
    db: &'db TransactionDB<MultiThreaded>,
    txn: Transaction<'db, TransactionDB<MultiThreaded>>,
    cf: std::sync::Arc<BoundColumnFamily<'db>>,
    cf_name: Vec<u8>,
    cf_contractstate: std::sync::Arc<BoundColumnFamily<'db>>,
    cf_contractstate_tree_hbsmt: std::sync::Arc<BoundColumnFamily<'db>>,
    entry_signer: &[u8; 48],
    entry_prev_hash: &[u8; 32],
    entry_slot: u64,
    entry_prev_slot: u64,
    entry_height: u64,
    entry_epoch: u64,
    entry_vr: &[u8; 96],
    entry_vr_b3: &[u8; 32],
    entry_dr: &[u8; 32],
    testnet: bool,
    testnet_peddlebikes: Vec<Vec<u8>>,
) -> ApplyEnv<'db> {
    ApplyEnv {
        caller_env: make_caller_env(entry_signer, entry_prev_hash, entry_slot, entry_prev_slot, entry_height, entry_epoch, entry_vr, entry_vr_b3, entry_dr),
        db: db,
        cf: cf,
        cf_name: cf_name,
        cf_contractstate: cf_contractstate,
        cf_contractstate_tree_hbsmt: cf_contractstate_tree_hbsmt,
        txn: txn,
        muts_final: Vec::new(),
        muts_final_rev: Vec::new(),
        muts: Vec::new(),
        muts_rev: Vec::new(),
        exec_track: false,
        exec_left: 0,
        exec_max: protocol::AMA_10_CENT,
        storage_left: 0,
        storage_max: protocol::AMA_1_DOLLAR,
        receipts: Vec::new(),
        logs: Vec::new(),
        logs_size: 0,
        preverified_sol_hashes: HashSet::new(),
        testnet: testnet,
        testnet_peddlebikes: testnet_peddlebikes,
        readonly: false,
        call_depth: 0,
    }
}

fn sol_verify_pool() -> &'static rayon::ThreadPool {
    SOL_VERIFY_POOL.get_or_init(|| {
        let threads = std::thread::available_parallelism().map(|n| ((n.get() * 3) / 4).max(1)).unwrap_or(1);

        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("rdb-sol-verify-{}", i))
            .build()
            .unwrap_or_else(|_| panic_any("sol_verify_pool_failed"))
    })
}

fn submit_sol_arg(txu: &crate::model::tx::TXU) -> Option<[u8; consensus::bic::sol::SOL_SIZE]> {
    let action = &txu.tx.action;
    if action.contract.as_slice() != b"Epoch" || action.function.as_slice() != b"submit_sol" {
        return None;
    }
    if action.args.len() != 1 || action.args[0].len() != consensus::bic::sol::SOL_SIZE {
        return None;
    }

    action.args[0].as_slice().try_into().ok()
}

fn preverify_entry_sols(env: &mut ApplyEnv, txs: &[crate::model::tx::TXU]) -> HashSet<[u8; 32]> {
    let sols: Vec<[u8; consensus::bic::sol::SOL_SIZE]> = txs.iter().filter_map(submit_sol_arg).collect();

    if sols.is_empty() {
        return HashSet::new();
    }

    let Some(segment_vr_hash) = consensus_kv::kv_get(env, b"bic:epoch:segment_vr_hash") else {
        return HashSet::new();
    };
    let Some(diff_bits) = consensus_kv::kv_get(env, b"bic:epoch:diff_bits") else {
        return HashSet::new();
    };
    let Some(diff_bits_int) = std::str::from_utf8(&diff_bits).ok().and_then(|s| s.parse::<u64>().ok()) else {
        return HashSet::new();
    };

    let entry_epoch = env.caller_env.entry_epoch;
    let entry_vr_b3 = env.caller_env.entry_vr_b3;

    let verify_one = |sol: &[u8; consensus::bic::sol::SOL_SIZE]| {
        let usol = consensus::bic::sol::unpack(sol);
        if usol.epoch != entry_epoch {
            return None;
        }

        let hash = blake3::hash(sol);
        match consensus::bic::sol::verify(sol, hash.as_bytes(), &segment_vr_hash, &entry_vr_b3, diff_bits_int) {
            Ok(true) => Some(*hash.as_bytes()),
            _ => None,
        }
    };

    if sols.len() == 1 {
        sols.iter().filter_map(verify_one).collect()
    } else {
        sol_verify_pool().install(|| sols.par_iter().filter_map(verify_one).collect())
    }
}

pub fn set_apply_env_tx<'db>(env: &mut ApplyEnv<'db>, tx_hash: &[u8; 32], tx_signer: &[u8; 48], tx_nonce: u64) {
    env.caller_env.tx_hash = *tx_hash;
    env.caller_env.tx_nonce = tx_nonce;
    env.caller_env.tx_signer = *tx_signer;
    env.caller_env.account_origin = tx_signer.to_vec();
}

pub fn apply_entry<'db, 'a>(
    db: &'db TransactionDB<MultiThreaded>,
    txn: Transaction<'db, TransactionDB<MultiThreaded>>,
    entry: crate::model::entry::Entry,
    pk: &[u8],
    sk: &[u8],
    testnet: bool,
    testnet_peddlebikes: Vec<Vec<u8>>,
) -> (Transaction<'db, TransactionDB<MultiThreaded>>, Vec<consensus_muts::Mutation>, Vec<consensus_muts::Mutation>, Vec<TXReceipt>, [u8; 32], [u8; 32]) {

    let cf_h = db.cf_handle("contractstate").unwrap();
    let cf2_h = db.cf_handle("contractstate").unwrap();
    let cf_tree_hbsmt_h = db.cf_handle("contractstate_tree_hbsmt").unwrap();

    let entry_signer = entry.header.signer.as_slice().try_into().unwrap_or_else(|_| panic!("entry_signer_len_wrong"));
    let entry_prev_hash = entry.header.prev_hash.as_slice().try_into().unwrap_or_else(|_| panic!("entry_prev_hash_len_wrong"));
    let entry_vr = entry.header.vr.as_slice().try_into().unwrap_or_else(|_| panic!("entry_vr_len_wrong"));
    let entry_vr_b3_binding = blake3::hash(&entry.header.vr);
    let entry_vr_b3 = entry_vr_b3_binding.as_bytes().try_into().unwrap_or_else(|_| panic!("entry_vr_len_wrong"));
    let entry_dr = entry.header.dr.as_slice().try_into().unwrap_or_else(|_| panic!("entry_dr_len_wrong"));

    let entry_epoch = entry.header.height / 100_000;
    let mut applyenv = make_apply_env(
        db,
        txn,
        cf_h,
        b"contractstate".to_vec(),
        cf2_h,
        cf_tree_hbsmt_h,
        entry_signer,
        entry_prev_hash,
        entry.header.slot,
        entry.header.prev_slot,
        entry.header.height,
        entry_epoch,
        entry_vr,
        entry_vr_b3,
        entry_dr,
        testnet,
        testnet_peddlebikes,
    );


    applyenv.preverified_sol_hashes = preverify_entry_sols(&mut applyenv, &entry.txs);

    call_txs_pre_upfront_cost(&mut applyenv, &entry.txs);

    let txs_count = entry.txs.len();
    for (i, txu) in entry.txs.into_iter().enumerate() {
        let tx_historical_cost = crate::consensus::bic::protocol::tx_historical_cost(&txu);

        let tx_hash = txu.hash.as_slice().try_into().unwrap_or_else(|_| panic!("tx_hash_len_wrong"));
        let tx_signer = txu.tx.signer.as_slice().try_into().unwrap_or_else(|_| panic!("tx_signer_len_wrong"));
        let tx_nonce = txu.tx.nonce;
        let action = txu.tx.action;

        applyenv.caller_env.tx_index = i as u64;
        applyenv.caller_env.tx_hash = tx_hash;
        applyenv.caller_env.tx_signer = tx_signer;
        applyenv.caller_env.tx_nonce = tx_nonce;
        applyenv.caller_env.account_origin = tx_signer.to_vec();
        applyenv.caller_env.account_caller = tx_signer.to_vec();

        //let op = action.map_get(crate::atoms::op()).unwrap().decode::<rustler::Binary>().unwrap().as_slice();
        let contract = action.contract;
        let function = action.function;
        let args = action.args;
        let attached_symbol = action.attached_symbol.clone();
        let attached_amount = action.attached_amount.clone();

        applyenv.caller_env.call_counter = 1;
        applyenv.caller_env.account_current = contract.to_vec();
        applyenv.muts = Vec::new();
        applyenv.muts_rev = Vec::new();
        applyenv.logs = Vec::new();
        applyenv.logs_size = 0;
        applyenv.exec_left = protocol::AMA_10_CENT;
        applyenv.exec_max = protocol::AMA_10_CENT;
        applyenv.storage_left = protocol::AMA_1_DOLLAR;
        applyenv.storage_max = protocol::AMA_1_DOLLAR;
        applyenv.call_depth = 0;

        std::panic::set_hook(Box::new(|_| {}));
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            applyenv.exec_track = true;
            match consensus::bls12_381::validate_public_key(contract.as_slice()) {
                false => {
                    //println!("{:?}->{:?} {:?} {:?}", String::from_utf8_lossy(&contract), String::from_utf8_lossy(&function), attached_amount, attached_symbol);
                    call_bic(&mut applyenv, contract, function, args, attached_symbol, attached_amount);
                    b"ok".to_vec()
                }
                true => {
                    //println!("{:?}->{:?} {:?} {:?}", bs58::encode(&contract).into_string(), String::from_utf8_lossy(&function), attached_amount, attached_symbol);
                    let result = call_wasmvm(&mut applyenv, contract, function, args, attached_symbol, attached_amount);
                    result
                }
            }
        }));

        applyenv.exec_track = false;

        let exec_cost_total =
            ((tx_historical_cost + (applyenv.exec_max - applyenv.exec_left) + (applyenv.storage_max - applyenv.storage_left)) as u64).to_string();


        match res {
            Ok(result) => {
                applyenv.muts_final.append(&mut applyenv.muts);
                applyenv.muts_final_rev.append(&mut applyenv.muts_rev);
                refund_exec_storage_deposit(&mut applyenv);

                //max logs 100
                //max logs size 1024bytes
                //
                //status	🚨 Critical	1 = Success, 0 = Revert. Always check this first. If it is 0, ignore the rest.
                //logs	🚨 Critical	Contains the actual data of what happened (token transfers, updates).
                //transactionHash	ℹ️ Medium	Links the receipt back to your original request.
                //logsBloom
                /*
                                let mut m = std::collections::HashMap::new();
                                if applyenv.caller_env.entry_height >= 416_00000 {
                                    let vecpak_term = vecpak::Term::PropList(vec![
                                        (vecpak::Term::Binary(b"error".to_vec()), vecpak::Term::Binary(b"ok".to_vec())),
                                        (vecpak::Term::Binary(b"exec_used".to_vec()), vecpak::Term::Binary(b"0".to_vec())),
                                        (vecpak::Term::Binary(b"logs".to_vec()), vecpak::Term::List(Vec::new())),
                                    ]);
                                    applyenv.result_log.push(vecpak::encode(vecpak_term))
                                } else {
                                    m.insert("error", "ok");
                                    applyenv.result_log.push(m)
                                }
                */
                let receipt = TXReceipt {
                    txid: tx_hash.into(),
                    success: true,
                    result: result.into(),
                    exec_used: exec_cost_total.clone().into(),
                    logs: applyenv.logs.clone(),
                };
                applyenv.receipts.push(receipt);
            }
            Err(payload) => {
                //TODO: refund storage costs on revert?
                consensus_kv::revert(&mut applyenv);
                refund_exec_storage_deposit(&mut applyenv);

                if let Some(&s) = payload.downcast_ref::<&'static str>() {
                    let receipt = TXReceipt {
                        txid: tx_hash.into(),
                        success: false,
                        result: s.to_string().into(),
                        exec_used: exec_cost_total.clone().into(),
                        logs: applyenv.logs.clone(),
                    };
                    applyenv.receipts.push(receipt);
                } else {
                    let receipt = TXReceipt {
                        txid: tx_hash.into(),
                        success: false,
                        result: b"unknown".into(),
                        exec_used: exec_cost_total.clone().into(),
                        logs: applyenv.logs.clone(),
                    };
                    applyenv.receipts.push(receipt);
                }
            }
        }
    }

    call_exit(&mut applyenv);

    let root_receipts = root_receipts(txs_count, applyenv.receipts.clone());
    let root_contractstate = update_and_root_contractstate(&mut applyenv);
    applyenv.into_parts(root_receipts, root_contractstate)

    //println!("r{:?} {}", applyenv.caller_env.entry_height, root_receipts(txus.clone(), applyenv.result_log.clone()).iter().map(|b| format!("{:02x}", b)).collect::<String>() );
    //println!("c{:?} {}", applyenv.caller_env.entry_height, hubt_contractstate_root.iter().map(|b| format!("{:02x}", b)).collect::<String>());
}

pub fn contract_view<'db, 'a>(
    db: &'db TransactionDB<MultiThreaded>,
    entry: crate::model::entry::Entry,
    view_pk: Vec<u8>,
    contract: Vec<u8>,
    function: Vec<u8>,
    args: Vec<Vec<u8>>,
    testnet: bool,
) -> (bool, Vec<u8>, Vec<Vec<u8>>) {
    let cf_h = db.cf_handle("contractstate").unwrap();
    let cf2_h = db.cf_handle("contractstate").unwrap();
    let cf_tree_hbsmt_h = db.cf_handle("contractstate_tree_hbsmt").unwrap();

    let entry_signer = entry.header.signer.as_slice().try_into().unwrap_or_else(|_| panic!("entry_signer_len_wrong"));
    let entry_prev_hash = entry.header.prev_hash.as_slice().try_into().unwrap_or_else(|_| panic!("entry_prev_hash_len_wrong"));
    let entry_vr = entry.header.vr.as_slice().try_into().unwrap_or_else(|_| panic!("entry_vr_len_wrong"));
    let entry_vr_b3_binding = blake3::hash(&entry.header.vr);
    let entry_vr_b3 = entry_vr_b3_binding.as_bytes().try_into().unwrap_or_else(|_| panic!("entry_vr_len_wrong"));
    let entry_dr = entry.header.dr.as_slice().try_into().unwrap_or_else(|_| panic!("entry_dr_len_wrong"));

    let txn_opts = TransactionOptions::default();
    let write_opts = WriteOptions::default();
    let txn = db.transaction_opt(&write_opts, &txn_opts);

    let entry_epoch = entry.header.height / 100_000;
    let mut applyenv = make_apply_env(
        db,
        txn,
        cf_h,
        b"contractstate".to_vec(),
        cf2_h,
        cf_tree_hbsmt_h,
        entry_signer,
        entry_prev_hash,
        entry.header.slot,
        entry.header.prev_slot,
        entry.header.height,
        entry_epoch,
        entry_vr,
        entry_vr_b3,
        entry_dr,
        testnet,
        Vec::new(),
    );
    applyenv.readonly = true;

    let view_pk: [u8; 48] = view_pk.as_slice().try_into().unwrap_or_else(|_| panic!("view_pk_len_wrong"));
    applyenv.caller_env.tx_signer = view_pk;
    applyenv.caller_env.account_current = contract.to_vec();
    applyenv.caller_env.account_origin = view_pk.to_vec();
    applyenv.caller_env.account_caller = view_pk.to_vec();
    applyenv.exec_left = protocol::AMA_10_CENT;
    applyenv.storage_left = protocol::AMA_1_DOLLAR;

    std::panic::set_hook(Box::new(|_| {}));
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match consensus::bls12_381::validate_public_key(contract.as_slice()) {
        false => {
            call_bic(&mut applyenv, contract, function, args, None, None);
            b"ok".to_vec()
        }
        true => {
            let result = call_wasmvm(&mut applyenv, contract, function, args, None, None);
            result
        }
    }));

    applyenv.txn.rollback();

    match res {
        Ok(result) => (true, result.into(), applyenv.logs.clone()),
        Err(payload) => {
            if let Some(&s) = payload.downcast_ref::<&'static str>() {
                (false, s.to_string().into(), applyenv.logs.clone())
            } else {
                (false, b"unknown".into(), applyenv.logs.clone())
            }
        }
    }
}

pub fn contract_validate<'db, 'a>(
    db: &'db TransactionDB<MultiThreaded>,
    entry: crate::model::entry::Entry,
    wasm_bytes: &[u8],
    testnet: bool,
) -> (Vec<u8>, Vec<Vec<u8>>) {
    let cf_h = db.cf_handle("contractstate").unwrap();
    let cf2_h = db.cf_handle("contractstate").unwrap();
    let cf_tree_hbsmt_h = db.cf_handle("contractstate_tree_hbsmt").unwrap();

    let entry_signer = entry.header.signer.as_slice().try_into().unwrap_or_else(|_| panic!("entry_signer_len_wrong"));
    let entry_prev_hash = entry.header.prev_hash.as_slice().try_into().unwrap_or_else(|_| panic!("entry_prev_hash_len_wrong"));
    let entry_vr = entry.header.vr.as_slice().try_into().unwrap_or_else(|_| panic!("entry_vr_len_wrong"));
    let entry_vr_b3_binding = blake3::hash(&entry.header.vr);
    let entry_vr_b3 = entry_vr_b3_binding.as_bytes().try_into().unwrap_or_else(|_| panic!("entry_vr_len_wrong"));
    let entry_dr = entry.header.dr.as_slice().try_into().unwrap_or_else(|_| panic!("entry_dr_len_wrong"));

    let txn_opts = TransactionOptions::default();
    let write_opts = WriteOptions::default();
    let txn = db.transaction_opt(&write_opts, &txn_opts);

    let entry_epoch = entry.header.height / 100_000;
    let mut applyenv = make_apply_env(
        db,
        txn,
        cf_h,
        b"contractstate".to_vec(),
        cf2_h,
        cf_tree_hbsmt_h,
        entry_signer,
        entry_prev_hash,
        entry.header.slot,
        entry.header.prev_slot,
        entry.header.height,
        entry_epoch,
        entry_vr,
        entry_vr_b3,
        entry_dr,
        testnet,
        Vec::new(),
    );
    applyenv.readonly = true;

    applyenv.exec_left = protocol::AMA_10_CENT;
    applyenv.storage_left = protocol::AMA_1_DOLLAR;

    std::panic::set_hook(Box::new(|_| {}));
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::consensus::bic::wasm::validate_contract(&mut applyenv, wasm_bytes)));

    applyenv.txn.rollback();

    match res {
        Ok(result) => (b"ok".to_vec(), applyenv.logs.clone()),
        Err(payload) => {
            if let Some(&s) = payload.downcast_ref::<&'static str>() {
                (s.to_string().into(), applyenv.logs.clone())
            } else {
                (b"error".to_vec(), applyenv.logs.clone())
            }
        }
    }
}

/// Computes the contractstate root. The HBSMT in `contractstate_tree_hbsmt` IS the
/// consensus contractstate tree (the legacy Hubt over `contractstate_tree` is gone).
fn update_and_root_contractstate(applyenv: &mut ApplyEnv) -> [u8; 32] {
    //Select only the last muts, rest are irrelevent for tree
    let mut map: HashMap<Vec<u8>, consensus_muts::Mutation> = HashMap::new();
    for m in applyenv.muts_final.clone() {
        match m {
            consensus_muts::Mutation::Put { ref key, .. }
            | consensus_muts::Mutation::Delete { ref key, .. }
            | consensus_muts::Mutation::SetBit { ref key, .. }
            | consensus_muts::Mutation::ClearBit { ref key, .. } => {
                map.insert(key.clone(), m);
            }
        }
    }
    let mut ops: Vec<consensus::hbsmt_common::Op> = Vec::with_capacity(map.len());
    for (key, m) in map {
        let namespace = consensus_kv::contractstate_namespace(&key);
        let op = match m {
            consensus_muts::Mutation::Put { value, .. } => consensus::hbsmt_common::Op::Insert(namespace, key, value),
            consensus_muts::Mutation::Delete { .. } => consensus::hbsmt_common::Op::Delete(namespace, key),
            consensus_muts::Mutation::SetBit { .. } => {
                let val = applyenv.txn.get_cf(&applyenv.cf, &key).unwrap().unwrap();
                consensus::hbsmt_common::Op::Insert(namespace, key, val)
            }
            consensus_muts::Mutation::ClearBit { .. } => {
                let val = applyenv.txn.get_cf(&applyenv.cf, &key).unwrap().unwrap();
                consensus::hbsmt_common::Op::Insert(namespace, key, val)
            }
        };
        ops.push(op);
    }

    // The HBSMT in `contractstate_tree_hbsmt` IS the contractstate tree. Incremental
    // update whose leaf/split writes flow through kv_put/kv_delete into the mutation set —
    // rewind-safe AND folded into mutations_hash. The tree is always seeded (live nodes
    // crossed the fork; fresh nodes import a state bundle that carries this CF).
    applyenv.cf = applyenv.db.cf_handle("contractstate_tree_hbsmt").unwrap();
    applyenv.cf_name = b"contractstate_tree_hbsmt".to_vec();
    applyenv.muts = Vec::new();
    applyenv.muts_rev = Vec::new();

    if hbsmt_cf_is_empty(applyenv) {
        panic_any("hbsmt_contractstate_tree_not_seeded");
    }
    crate::consensus::hbsmt_rdb::hbsmt_batch_update_env_muts(applyenv, "contractstate_tree_hbsmt", ops);

    let mut muts = unique_mutations(applyenv.muts.clone(), false);
    applyenv.muts_final.append(&mut muts);
    let mut muts_rev = unique_mutations(applyenv.muts_rev.clone(), true);
    applyenv.muts_final_rev.append(&mut muts_rev);

    crate::consensus::hbsmt_rdb::hbsmt_root_env(applyenv, "contractstate_tree_hbsmt")
}

/// Safety guard: the `contractstate_tree_hbsmt` CF must never be empty on an applying
/// node (live nodes seeded it crossing the fork; fresh nodes import a state bundle that
/// carries this CF). An empty tree here means corruption — fail loud rather than commit a
/// wrong root.
fn hbsmt_cf_is_empty(env: &ApplyEnv) -> bool {
    let cf = match env.db.cf_handle("contractstate_tree_hbsmt") {
        Some(cf) => cf,
        None => return true,
    };
    let mut iter = env.txn.raw_iterator_cf(&cf);
    iter.seek_to_first();
    !iter.valid()
}

fn root_receipts(count: usize, receipts: Vec<TXReceipt>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut kvs = Vec::with_capacity((count * 4) + 1);

    kvs.push(hbsmt_common::Op::Insert(None, b"count".to_vec(), (count as u32).to_be_bytes().to_vec()));

    //TODO: for parallel processing fix this later
    for (index, receipt) in receipts.into_iter().enumerate() {
        let index_bytes = (index as u32).to_be_bytes().to_vec();
        let success_bytes = vec![u8::from(receipt.success)];

        let mut log_hasher = Sha256::new();
        for log in receipt.logs {
            let log: Vec<u8> = log;
            log_hasher.update(&(log.len() as u32).to_be_bytes());
            log_hasher.update(log);
        }
        let log_hash = log_hasher.finalize();

        kvs.push(hbsmt_common::Op::Insert(Some(b"index".to_vec()), receipt.txid.to_vec(), index_bytes));
        kvs.push(hbsmt_common::Op::Insert(Some(b"success".to_vec()), receipt.txid.to_vec(), success_bytes));
        kvs.push(hbsmt_common::Op::Insert(Some(b"result".to_vec()), receipt.txid.to_vec(), receipt.result));
        kvs.push(hbsmt_common::Op::Insert(Some(b"logs".to_vec()), receipt.txid.to_vec(), log_hash.to_vec()));
    }

    let mut t = crate::consensus::hbsmt::Hbsmt::new();
    t.batch_update(kvs);
    t.root()
}

pub trait ToTerm {
    fn to_term(self) -> vecpak::Term;
}
impl ToTerm for Vec<Vec<u8>> {
    fn to_term(self) -> vecpak::Term {
        let list_content: Vec<vecpak::Term> = self.into_iter().map(|bin| vecpak::Term::Binary(bin)).collect();
        vecpak::Term::List(list_content)
    }
}
impl ToTerm for HashMap<String, String> {
    fn to_term(self) -> vecpak::Term {
        let props: Vec<(vecpak::Term, vecpak::Term)> =
            self.into_iter().map(|(k, v)| (vecpak::Term::Binary(k.as_bytes().to_vec()), vecpak::Term::Binary(v.as_bytes().to_vec()))).collect();

        vecpak::Term::PropList(props)
    }
}
impl ToTerm for Vec<HashMap<String, String>> {
    fn to_term(self) -> vecpak::Term {
        let list_content: Vec<vecpak::Term> = self
            .into_iter()
            .map(|map| {
                // Convert HashMap to PropList
                let props: Vec<(vecpak::Term, vecpak::Term)> =
                    map.into_iter().map(|(k, v)| (vecpak::Term::Binary(k.as_bytes().to_vec()), vecpak::Term::Binary(v.as_bytes().to_vec()))).collect();
                vecpak::Term::PropList(props)
            })
            .collect();
        vecpak::Term::List(list_content)
    }
}

fn refund_exec_storage_deposit(applyenv: &mut ApplyEnv) {
    applyenv.muts = Vec::new();
    applyenv.muts_rev = Vec::new();

    //Refund remainder of the exec deposit
    {
        let refund = applyenv.exec_left.max(0);
        if refund > 0 {
            let key = &crate::bcat(&[b"account:", &applyenv.caller_env.account_origin, b":balance:AMA"]);
            consensus_kv::kv_increment(applyenv, key, refund);
        }
        // Increment validator / burn
        let cost = applyenv.exec_max - refund;
        consensus_kv::kv_increment(applyenv, &crate::bcat(&[b"account:", &applyenv.caller_env.entry_signer, b":balance:AMA"]), cost / 2);
        consensus_kv::kv_increment(applyenv, &crate::bcat(&[b"account:", &consensus::bic::coin::BURN_ADDRESS, b":balance:AMA"]), cost / 2);
    }

    //Refund remainder of the storage deposit
    {
        let refund = applyenv.storage_left.max(0);
        if refund > 0 {
            let key = &crate::bcat(&[b"account:", &applyenv.caller_env.account_origin, b":balance:AMA"]);
            consensus_kv::kv_increment(applyenv, key, refund);
        }
        // Increment validator / burn
        let cost = applyenv.storage_max - refund;
        consensus_kv::kv_increment(applyenv, &crate::bcat(&[b"account:", &applyenv.caller_env.entry_signer, b":balance:AMA"]), cost / 2);
        consensus_kv::kv_increment(applyenv, &crate::bcat(&[b"account:", &consensus::bic::coin::BURN_ADDRESS, b":balance:AMA"]), cost / 2);
    }
    applyenv.muts_final.append(&mut applyenv.muts);
    applyenv.muts_final_rev.append(&mut applyenv.muts_rev);
}

fn call_txs_pre_upfront_cost<'a>(env: &mut ApplyEnv, txus: &[crate::model::tx::TXU]) {
    env.muts = Vec::new();
    env.muts_rev = Vec::new();
    for txu in txus {
        let tx_hash = txu.hash.as_slice().try_into().unwrap_or_else(|_| panic!("tx_hash_len_wrong"));
        let tx_signer = txu.tx.signer.as_slice().try_into().unwrap_or_else(|_| panic!("tx_signer_len_wrong"));
        let tx_nonce = txu.tx.nonce;

        set_apply_env_tx(env, &tx_hash, &tx_signer, tx_nonce);

        // Update nonce — defensive monotonicity check (Elixir validate_next is the
        // primary enforcement; this catches regressions in that layer).
        let nonce_key = crate::bcat(&[b"account:", &tx_signer, b":attribute:nonce"]);
        if let Some(existing) = consensus_kv::kv_get(env, &nonce_key) {
            let existing_nonce: u64 =
                std::str::from_utf8(&existing).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_existing_nonce"));
            if tx_nonce <= existing_nonce {
                panic_any("invalid_tx_nonce_not_monotonic")
            }
        }
        consensus_kv::kv_put(env, &nonce_key, &tx_nonce.to_string().into_bytes());

        // Deduct tx historical cost
        let tx_historical_cost = crate::consensus::bic::protocol::tx_historical_cost(txu);
        protocol::pay_cost(env, tx_historical_cost);

        //lock 0.1 AMA during execution
        consensus_kv::kv_increment(env, &crate::bcat(&[b"account:", &env.caller_env.account_origin, b":balance:AMA"]), -protocol::AMA_10_CENT);
        //lock 1.0 storage AMA during execution
        consensus_kv::kv_increment(env, &crate::bcat(&[b"account:", &env.caller_env.account_origin, b":balance:AMA"]), -protocol::AMA_1_DOLLAR);
    }
    env.muts_final.append(&mut env.muts);
    env.muts_final_rev.append(&mut env.muts_rev);
}

fn call_exit(env: &mut ApplyEnv) {
    //seed RNG for random validator selection
    let vr = env.caller_env.entry_vr.to_vec();
    let seed_hash = blake3::hash(&vr);
    env.caller_env.seed = seed_hash.as_bytes().to_vec();
    //for assemblyscript
    // Canonicalize NaN: interpreting hash bytes as f64 yields a NaN ~1/2048 of the
    // time, and NaN payload/signaling-bit handling differs across CPU archs and wasm
    // runtimes. An un-canonicalized NaN seed reaching a contract would diverge
    // tx_state_root across validators (consensus fork). Only the NaN case changes.
    let seedf64 = f64::from_le_bytes(seed_hash.as_bytes()[0..8].try_into().unwrap_or([0u8; 8]));
    let seedf64 = if seedf64.is_nan() { f64::from_bits(0x7ff8_0000_0000_0000) } else { seedf64 };
    env.caller_env.seedf64 = seedf64;

    env.muts = Vec::new();
    env.muts_rev = Vec::new();

    if env.caller_env.entry_height % 1000 == 0 {
        let digest = blake3::hash(&env.caller_env.entry_vr);
        consensus_kv::kv_put(env, b"bic:epoch:segment_vr_hash", digest.as_bytes());
    }
    if env.caller_env.entry_height % 100_000 == 99_999 {
        consensus::bic::epoch::next(env);
    }
    env.muts_final.append(&mut env.muts);
    env.muts_final_rev.append(&mut env.muts_rev);
}

fn unique_mutations(mutations: Vec<consensus_muts::Mutation>, reverse: bool) -> Vec<consensus_muts::Mutation> {
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    // Iterate BACKWARDS (Newest -> Oldest)
    let iter: Box<dyn Iterator<Item = consensus_muts::Mutation>> =
        if reverse { Box::new(mutations.into_iter()) } else { Box::new(mutations.into_iter().rev()) };
    for m in iter {
        match m {
            consensus_muts::Mutation::Put { ref key, .. }
            | consensus_muts::Mutation::Delete { ref key, .. }
            | consensus_muts::Mutation::SetBit { ref key, .. }
            | consensus_muts::Mutation::ClearBit { ref key, .. } => {
                if seen.insert(key.clone()) {
                    result.push(m);
                }
            }
        }
    }

    if !reverse {
        result.reverse();
    }
    result
}

fn migrate_db(env: &mut ApplyEnv) {
    let mut cursor: Vec<u8> = Vec::new();
    while let Some((next_key_wo_prefix, _val)) = crate::consensus::consensus_kv::kv_get_next(env, b"bic:epoch:trainers:height:", &cursor) {
        let height = std::str::from_utf8(&next_key_wo_prefix).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_epoch"));
        let trainers: Vec<vecpak::Term> = consensus::bic::epoch::kv_get_trainers(env, height).into_iter().map(vecpak::Term::Binary).collect();
        let buf = vecpak::encode(vecpak::Term::List(trainers));
        crate::consensus::consensus_kv::kv_put(env, &crate::bcat(&[b"bic:epoch:validators:height:", &next_key_wo_prefix]), &buf);
        cursor = next_key_wo_prefix;
    }

    /*
    //"bic:epoch:trainers:85"
    //"bic:epoch:trainers:height:000039625024"
    //"bic:epoch:trainers:removed:
    let mut cursor: Vec<u8> = Vec::new();
    while let Some((next_key_wo_prefix, _val)) = crate::consensus::consensus_kv::kv_get_next(env, b"bic:epoch:trainers:height:", &cursor) {
        let height = std::str::from_utf8(&next_key_wo_prefix).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_epoch"));
        let trainers: Vec<vecpak::Term> = consensus::bic::epoch::kv_get_trainers(env, height)
            .into_iter()
            .map(vecpak::Term::Binary)
            .collect();
        let buf = vecpak::encode(vecpak::Term::List(trainers));
        crate::consensus::consensus_kv::kv_put(env, &crate::bcat(&[b"bic:epoch:validators:height:", &next_key_wo_prefix]), &buf);
        cursor = next_key_wo_prefix;
    }
    cursor = Vec::new();
    while let Some((next_key_wo_prefix, _val)) = crate::consensus::consensus_kv::kv_get_next(env, b"bic:epoch:trainers:", &cursor) {
        let full_key = [b"bic:epoch:trainers:" as &[u8], &next_key_wo_prefix].concat();
        crate::consensus::consensus_kv::kv_delete(env, &full_key);
        cursor = next_key_wo_prefix;
    }

    //"bic:coin:balance:???ii?????d???K\\?????c??[??y????)?o??{=?;????n?9:AMA"
    cursor = Vec::new();
    while let Some((next_key_wo_prefix, val)) = crate::consensus::consensus_kv::kv_get_next(env, b"bic:coin:balance:", &cursor) {
        let pk = &next_key_wo_prefix[..48];
        crate::consensus::consensus_kv::kv_put(env, &crate::bcat(&[b"account:", &pk, b":balance:AMA"]), &val);

        let full_key = [b"bic:coin:balance:" as &[u8], &next_key_wo_prefix].concat();
        crate::consensus::consensus_kv::kv_delete(env, &full_key);

        cursor = next_key_wo_prefix;
    }

    //"bic:base:nonce:????GH??D?ss???????dT??14o?P??nA?I&??6?????e3I??"
    cursor = Vec::new();
    while let Some((next_key_wo_prefix, val)) = crate::consensus::consensus_kv::kv_get_next(env, b"bic:base:nonce:", &cursor) {
        let pk = &next_key_wo_prefix[..48];
        crate::consensus::consensus_kv::kv_put(env, &crate::bcat(&[b"account:", &pk, b":attribute:nonce"]), &val);

        let full_key = [b"bic:base:nonce:" as &[u8], &next_key_wo_prefix].concat();
        crate::consensus::consensus_kv::kv_delete(env, &full_key);

        cursor = next_key_wo_prefix;
    }

    //"bic:epoch:emission_address:????GH??D?ss???????dT??14o?P??nA?I&??6?????e3I??"
    cursor = Vec::new();
    while let Some((next_key_wo_prefix, val)) = crate::consensus::consensus_kv::kv_get_next(env, b"bic:epoch:emission_address:", &cursor) {
        let pk = &next_key_wo_prefix[..48];
        crate::consensus::consensus_kv::kv_put(env, &crate::bcat(&[b"account:", &pk, b":attribute:emission_address"]), &val);

        let full_key = [b"bic:epoch:emission_address:" as &[u8], &next_key_wo_prefix].concat();
        crate::consensus::consensus_kv::kv_delete(env, &full_key);

        cursor = next_key_wo_prefix;
    }

    //"bic:epoch:pop:????GH??D?ss???????dT??14o?P??nA?I&??6?????e3I??"
    cursor = Vec::new();
    while let Some((next_key_wo_prefix, val)) = crate::consensus::consensus_kv::kv_get_next(env, b"bic:epoch:pop:", &cursor) {
        let pk = &next_key_wo_prefix[..48];
        crate::consensus::consensus_kv::kv_put(env, &crate::bcat(&[b"account:", &pk, b":attribute:pop"]), &val);

        let full_key = [b"bic:epoch:pop:" as &[u8], &next_key_wo_prefix].concat();
        crate::consensus::consensus_kv::kv_delete(env, &full_key);

        cursor = next_key_wo_prefix;
    }
    */
}

pub fn call_bic(
    env: &mut ApplyEnv,
    contract: Vec<u8>,
    function: Vec<u8>,
    args: Vec<Vec<u8>>,
    attached_symbol: Option<Vec<u8>>,
    attached_amount: Option<Vec<u8>>,
) {
    if env.testnet {
        match (contract.as_slice(), function.as_slice()) {
            (b"Coin", b"create_and_mint") => return consensus::bic::coin::call_create_and_mint(env, args),
            (b"Coin", b"mint") => return consensus::bic::coin::call_mint(env, args),
            (b"Coin", b"pause") => return consensus::bic::coin::call_pause(env, args),
            (b"Nft", b"transfer") => return consensus::bic::nft::call_transfer(env, args),
            (b"Nft", b"create_collection") => return consensus::bic::nft::call_create_collection(env, args),
            (b"Nft", b"mint") => return consensus::bic::nft::call_mint(env, args),
            (b"Lockup", b"lock") => return consensus::bic::lockup::call_lock(env, args),
            (b"Lockup", b"unlock") => return consensus::bic::lockup::call_unlock(env, args),
            (b"Contract", b"deploy") => {
                consensus_kv::exec_budget_decr(env, protocol::COST_PER_DEPLOY);
                return consensus::bic::contract::call_deploy(env, args);
            }
            (b"LockupPrime", b"lock") => return consensus::bic::lockup_prime::call_lock(env, args),
            (b"LockupPrime", b"unlock") => return consensus::bic::lockup_prime::call_unlock(env, args),
            (b"LockupPrime", b"daily_checkin") => return consensus::bic::lockup_prime::call_daily_checkin(env, args),
            // FIX: Allow non-testnet logic to fall through if no match found here
            _ => {}
        }
    }

    match (contract.as_slice(), function.as_slice()) {
        (b"Epoch", b"submit_sol") => {
            consensus_kv::exec_budget_decr(env, protocol::COST_PER_SOL);
            consensus::bic::epoch::call_submit_sol(env, args)
        }
        (b"Epoch", b"set_emission_address") => consensus::bic::epoch::call_set_emission_address(env, args),
        (b"Epoch", b"slash_trainer") => {
            consensus_kv::exec_budget_decr(env, protocol::COST_PER_SLASH);
            consensus::bic::epoch::call_slash_trainer(env, args)
        }

        (b"Coin", b"transfer") => consensus::bic::coin::call_transfer(env, args),

        /*
        (b"Coin", b"create_and_mint") => consensus::bic::coin::call_create_and_mint(env, args),
        (b"Coin", b"mint") => consensus::bic::coin::call_mint(env, args),
        (b"Coin", b"pause") => consensus::bic::coin::call_pause(env, args),
        (b"Nft", b"transfer") => consensus::bic::nft::call_transfer(env, args),
        (b"Nft", b"create_collection") => consensus::bic::nft::call_create_collection(env, args),
        (b"Nft", b"mint") => consensus::bic::nft::call_mint(env, args),
        (b"Lockup", b"lock") => consensus::bic::lockup::call_lock(env, args),
        (b"Lockup", b"unlock") => consensus::bic::lockup::call_unlock(env, args),
        (b"Contract", b"deploy") => {
                consensus_kv::exec_budget_decr(env, protocol::COST_PER_DEPLOY);
                consensus::bic::contract::call_deploy(env, args)
        },
        (b"LockupPrime", b"lock") => consensus::bic::lockup_prime::call_lock(env, args),
        (b"LockupPrime", b"unlock") => consensus::bic::lockup_prime::call_unlock(env, args),
        (b"LockupPrime", b"daily_checkin") => consensus::bic::lockup_prime::call_daily_checkin(env, args),
        */
        _ => std::panic::panic_any("invalid_bic_action"),
    }
}

pub fn call_wasmvm(
    env: &mut ApplyEnv,
    contract: Vec<u8>,
    function: Vec<u8>,
    args: Vec<Vec<u8>>,
    attached_symbol: Option<Vec<u8>>,
    attached_amount: Option<Vec<u8>>,
) -> Vec<u8> {
    env.call_depth = env.call_depth.saturating_add(1);
    if env.call_depth > protocol::MAX_CALL_DEPTH {
        panic_any("exec_call_depth_exceeded");
    }

    let function = String::from_utf8(function).unwrap_or_else(|_| panic_any("invalid_function"));

    //seed the rng
    // Inputs:
    //   entry_vr      — block-level VRF, fixed for the entry
    //   tx_hash       — unique per TX and signed, producer can't tamper
    //   tx_index      — TX position within the entry
    //   call_counter  — call ordinal within THIS tx (reset per-tx in apply_entry)
    // call_counter is per-tx so a prior failed/reverted tx cannot shift this seed.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&env.caller_env.entry_vr);
    hasher.update(&env.caller_env.tx_hash);
    hasher.update(&env.caller_env.tx_index.to_le_bytes());
    hasher.update(&env.caller_env.call_counter.to_le_bytes());
    let result_hash = hasher.finalize();

    let mut buf = [0u8; 8];
    buf.copy_from_slice(&result_hash.as_bytes()[0..8]);

    env.caller_env.seed = result_hash.as_bytes().to_vec();
    // Canonicalize NaN seed (see call_exit derivation): a NaN payload diverges across
    // archs/wasm runtimes -> tx_state_root fork. Only the NaN case changes.
    let seedf64 = f64::from_le_bytes(buf);
    env.caller_env.seedf64 = if seedf64.is_nan() { f64::from_bits(0x7ff8_0000_0000_0000) } else { seedf64 };

    //attachments
    env.caller_env.attached_symbol = Vec::new();
    env.caller_env.attached_amount = Vec::new();

    let bytecode = consensus::bic::contract::bytecode(env, contract.as_slice());
    if bytecode.is_none() {
        panic_any("account_has_no_bytecode")
    }

    match (attached_symbol, attached_amount) {
        (Some(attached_symbol), Some(attached_amount)) => {
            let amount =
                std::str::from_utf8(&attached_amount).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_attached_amount"));
            if amount <= 0 {
                panic_any("invalid_attached_amount")
            }
            if amount > consensus::bic::coin::balance(env, &env.caller_env.account_caller.clone(), &attached_symbol) {
                panic_any("attached_amount_insufficient_funds")
            }

            consensus_kv::kv_increment(env, &crate::bcat(&[b"account:", &contract, b":balance:", &attached_symbol]), amount);
            consensus_kv::kv_increment(env, &crate::bcat(&[b"account:", &env.caller_env.account_caller, b":balance:", &attached_symbol]), -amount);

            env.caller_env.attached_symbol = attached_symbol;
            env.caller_env.attached_amount = attached_amount;
        }
        _ => (),
    }

    if !env.testnet {
        std::panic::panic_any("wasm_noop");
    }

    let error = consensus::bic::wasm::call_contract(env, bytecode.as_deref().unwrap_or_else(|| panic_any("invalid_bytecode")), function, args);
    env.call_depth = env.call_depth.saturating_sub(1);
    error
}
