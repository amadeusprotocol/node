//! Replay-style test harness.
//!
//! `Chain` is a single node: a real RocksDB-backed state with funded BLS
//! wallets, where `call` applies a tx through the live `call_bic` dispatch
//! with commit-on-success / rollback-on-panic semantics.
//!
//! `Cluster` runs N independent `Chain` nodes in lockstep over the same tx
//! stream (with an optionally shortened epoch interval) and asserts their
//! state digests never diverge — the integrity check future hardforks need.

#![cfg(test)]

use crate::bcat;
use crate::consensus::bls12_381;
use crate::consensus::consensus_apply::{call_bic, make_apply_env, ApplyEnv};
use rust_rocksdb::{ColumnFamilyDescriptor, MultiThreaded, Options, TransactionDB, TransactionDBOptions};
use std::panic::{catch_unwind, AssertUnwindSafe};
use tempfile::TempDir;

pub const DEFAULT_EPOCH_INTERVAL: u64 = 100_000;

pub struct Wallet {
    pub sk: [u8; 64],
    pub pk: [u8; 48],
}

pub fn new_wallet() -> Wallet {
    let sk = bls12_381::generate_sk();
    let pk = bls12_381::get_public_key(&sk).unwrap_or_else(|_| panic!("wallet_keygen_failed"));
    Wallet { sk, pk }
}

pub struct Chain {
    _dir: TempDir,
    pub db: &'static TransactionDB<MultiThreaded>,
    pub height: u64,
    pub epoch_interval: u64,
}

impl Chain {
    pub fn new() -> Chain {
        Chain::with_epoch_interval(DEFAULT_EPOCH_INTERVAL)
    }

    pub fn with_epoch_interval(epoch_interval: u64) -> Chain {
        let dir = TempDir::new().unwrap();
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        let txn_db_opts = TransactionDBOptions::default();
        let cfs = vec![
            ColumnFamilyDescriptor::new("contractstate", Options::default()),
            ColumnFamilyDescriptor::new("contractstate_tree_hbsmt", Options::default()),
        ];
        let db = TransactionDB::<MultiThreaded>::open_cf_descriptors(&db_opts, &txn_db_opts, dir.path(), cfs).unwrap();
        let db: &'static TransactionDB<MultiThreaded> = Box::leak(Box::new(db));
        Chain { _dir: dir, db, height: 0, epoch_interval }
    }

    pub fn epoch(&self) -> u64 {
        self.height / self.epoch_interval
    }

    pub fn advance_blocks(&mut self, n: u64) {
        self.height += n;
    }

    pub fn advance_epochs(&mut self, n: u64) {
        self.height += n * self.epoch_interval;
    }

    //run the epoch boundary like production: epoch::next on the last height of
    //the current epoch, then move to the first height of the next one.
    //epoch.rs internals assume 100_000-block epochs, so use the default interval.
    pub fn step_epoch(&mut self) {
        if self.get(b"bic:epoch:diff_bits").is_none() {
            self.put(b"bic:epoch:diff_bits", b"24");
        }
        self.height = (self.epoch() + 1) * self.epoch_interval - 1;
        self.with_env(&[0u8; 48], |env| crate::consensus::bic::epoch::next(env));
        self.height += 1;
    }

    pub fn wallet(&self, ama_flat: i128) -> Wallet {
        let wallet = new_wallet();
        if ama_flat > 0 {
            self.fund(&wallet.pk, ama_flat);
        }
        wallet
    }

    pub fn fund(&self, addr: &[u8], amount_flat: i128) {
        let key = bcat(&[b"account:", addr, b":balance:AMA"]);
        let prev = self.get(&key).and_then(|v| atoi::atoi::<i128>(&v)).unwrap_or(0);
        self.put(&key, (prev + amount_flat).to_string().as_bytes());
    }

    pub fn balance(&self, addr: &[u8]) -> i128 {
        self.get(&bcat(&[b"account:", addr, b":balance:AMA"])).and_then(|v| atoi::atoi::<i128>(&v)).unwrap_or(0)
    }

    pub fn put(&self, key: &[u8], value: &[u8]) {
        let cf = self.db.cf_handle("contractstate").unwrap();
        let txn = self.db.transaction();
        txn.put_cf(&cf, key, value).unwrap();
        txn.commit().unwrap();
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let cf = self.db.cf_handle("contractstate").unwrap();
        self.db.transaction().get_cf(&cf, key).unwrap()
    }

    fn make_env(&self, signer: &[u8]) -> ApplyEnv<'static> {
        let cf = self.db.cf_handle("contractstate").unwrap();
        let cf_cs = self.db.cf_handle("contractstate").unwrap();
        let cf_tree_hbsmt = self.db.cf_handle("contractstate_tree_hbsmt").unwrap();
        let txn = self.db.transaction();
        let mut env = make_apply_env(
            self.db,
            txn,
            cf,
            b"contractstate".to_vec(),
            cf_cs,
            cf_tree_hbsmt,
            &[0u8; 48],
            &[0u8; 32],
            self.height,
            self.height.saturating_sub(1),
            self.height,
            self.epoch(),
            &[0u8; 96],
            &[0u8; 32],
            &[0u8; 32],
            true,
            Vec::new(),
        );
        env.caller_env.account_origin = signer.to_vec();
        env.caller_env.account_caller = signer.to_vec();
        env.caller_env.account_current = signer.to_vec();
        if signer.len() == 48 {
            env.caller_env.tx_signer.copy_from_slice(signer);
        }
        env
    }

    pub fn call(&self, signer: &Wallet, contract: &[u8], function: &[u8], args: &[&[u8]]) -> Result<(), String> {
        self.call_as(&signer.pk, contract, function, args)
    }

    //run a closure against a live env, for helpers not dispatched via call_bic
    pub fn with_env<R>(&self, signer: &[u8], f: impl FnOnce(&mut ApplyEnv<'static>) -> R) -> R {
        let mut env = self.make_env(signer);
        let result = f(&mut env);
        let ApplyEnv { txn, .. } = env;
        txn.commit().unwrap();
        result
    }

    pub fn call_as(&self, signer: &[u8], contract: &[u8], function: &[u8], args: &[&[u8]]) -> Result<(), String> {
        let mut env = self.make_env(signer);
        let args: Vec<Vec<u8>> = args.iter().map(|a| a.to_vec()).collect();
        let result = catch_unwind(AssertUnwindSafe(|| {
            call_bic(&mut env, contract.to_vec(), function.to_vec(), args, None, None);
        }));
        match result {
            Ok(()) => {
                let ApplyEnv { txn, .. } = env;
                txn.commit().unwrap();
                Ok(())
            }
            Err(payload) => {
                drop(env);
                Err(panic_message(payload))
            }
        }
    }

    pub fn state_digest(&self) -> [u8; 32] {
        let cf = self.db.cf_handle("contractstate").unwrap();
        let mut iter = self.db.raw_iterator_cf(&cf);
        let mut hasher = blake3::Hasher::new();
        iter.seek_to_first();
        while iter.valid() {
            let k = iter.key().unwrap();
            let v = iter.value().unwrap();
            hasher.update(&(k.len() as u64).to_be_bytes());
            hasher.update(k);
            hasher.update(&(v.len() as u64).to_be_bytes());
            hasher.update(v);
            iter.next();
        }
        *hasher.finalize().as_bytes()
    }
}

pub fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown_panic".to_string()
    }
}

pub struct Cluster {
    pub nodes: Vec<Chain>,
}

impl Cluster {
    pub fn new(node_count: usize, epoch_interval: u64) -> Cluster {
        Cluster {
            nodes: (0..node_count).map(|_| Chain::with_epoch_interval(epoch_interval)).collect(),
        }
    }

    pub fn fund(&self, addr: &[u8], amount_flat: i128) {
        for node in &self.nodes {
            node.fund(addr, amount_flat);
        }
    }

    pub fn advance_blocks(&mut self, n: u64) {
        for node in &mut self.nodes {
            node.advance_blocks(n);
        }
    }

    pub fn advance_epochs(&mut self, n: u64) {
        for node in &mut self.nodes {
            node.advance_epochs(n);
        }
    }

    //every node applies the same tx; the outcome must be identical on all of them
    pub fn call_as(&self, signer: &[u8], contract: &[u8], function: &[u8], args: &[&[u8]]) -> Result<(), String> {
        let mut results: Vec<Result<(), String>> = self.nodes.iter().map(|n| n.call_as(signer, contract, function, args)).collect();
        let first = results.remove(0);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(&first, result, "node {} diverged on tx outcome", i + 1);
        }
        first
    }

    pub fn assert_in_sync(&self) {
        let digests: Vec<[u8; 32]> = self.nodes.iter().map(|n| n.state_digest()).collect();
        for (i, digest) in digests.iter().enumerate() {
            assert_eq!(digest, &digests[0], "node {} state diverged", i);
        }
    }
}
