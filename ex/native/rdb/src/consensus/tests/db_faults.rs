#![cfg(test)]

use crate::consensus::consensus_apply::make_apply_env;
use crate::consensus::consensus_kv::{db_fault, kv_get, kv_get_next, rethrow_db_fault, DbFault};
use rust_rocksdb::{ColumnFamilyDescriptor, DBCompressionType, MultiThreaded, Options, TransactionDB, TransactionDBOptions};
use std::panic::{catch_unwind, AssertUnwindSafe};

const KEYS: usize = 2000;

fn key(i: usize) -> Vec<u8> {
    format!("acct:{i:06}").into_bytes()
}

fn value(i: usize) -> Vec<u8> {
    (0..512).map(|j| (i * 31 + j * 7) as u8).collect()
}

fn cf_opts() -> Options {
    let mut o = Options::default();
    o.set_compression_type(DBCompressionType::None);
    o
}

fn open(path: &std::path::Path) -> TransactionDB<MultiThreaded> {
    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    let cfs = vec![ColumnFamilyDescriptor::new("contractstate", cf_opts()), ColumnFamilyDescriptor::new("contractstate_tree_hbsmt", cf_opts())];
    TransactionDB::<MultiThreaded>::open_cf_descriptors(&db_opts, &TransactionDBOptions::default(), path, cfs).unwrap()
}

fn corrupted_db() -> (tempfile::TempDir, TransactionDB<MultiThreaded>) {
    let dir = tempfile::TempDir::new().unwrap();
    {
        let db = open(dir.path());
        let cf = db.cf_handle("contractstate").unwrap();
        for i in 0..KEYS {
            db.put_cf(&cf, key(i), value(i)).unwrap();
        }
        db.flush_cf(&cf).unwrap();
    }
    let sst = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "sst")).max_by_key(|p| std::fs::metadata(p).unwrap().len()).unwrap();
    let mut bytes = std::fs::read(&sst).unwrap();
    let mid = bytes.len() / 3;
    for b in &mut bytes[mid..mid + 256] {
        *b ^= 0x5a;
    }
    std::fs::write(&sst, bytes).unwrap();
    let db = open(dir.path());
    (dir, db)
}

fn env(db: &TransactionDB<MultiThreaded>) -> crate::consensus::consensus_apply::ApplyEnv<'_> {
    let cf = || db.cf_handle("contractstate").unwrap();
    make_apply_env(
        db, db.transaction(), cf(), b"contractstate".to_vec(), cf(), db.cf_handle("contractstate_tree_hbsmt").unwrap(),
        &[0u8; 48], &[0u8; 32], 1, 0, 1, 0, &[0u8; 96], &[0u8; 32], &[0u8; 32], false,
    )
}

#[test]
fn corrupt_point_reads_raise_db_fault_never_a_wrong_answer() {
    let (_dir, db) = corrupted_db();
    let mut faults = 0;
    for i in 0..KEYS {
        let mut e = env(&db);
        match catch_unwind(AssertUnwindSafe(|| kv_get(&mut e, &key(i)))) {
            Ok(v) => assert_eq!(v, Some(value(i)), "key {i} read back wrong instead of faulting"),
            Err(p) => {
                assert!(p.is::<DbFault>(), "key {i} panicked with something other than DbFault");
                faults += 1;
            }
        }
    }
    assert!(faults > 0, "corruption was not detected by any read");
}

#[test]
fn corrupt_range_scan_raises_db_fault_instead_of_ending_early() {
    let (_dir, db) = corrupted_db();
    let mut e = env(&db);
    let mut seen = 0usize;
    let scan = catch_unwind(AssertUnwindSafe(|| {
        let mut cursor = Vec::new();
        while let Some((k, _)) = kv_get_next(&mut e, b"acct:", &cursor) {
            seen += 1;
            cursor = k;
        }
    }));
    let p = scan.expect_err(&format!("scan ended normally after {seen} of {KEYS} keys"));
    assert!(p.is::<DbFault>());
    assert!(seen < KEYS);
}

#[test]
fn tx_level_catch_rethrows_db_faults_but_keeps_contract_errors() {
    let receipt_for = |f: fn()| catch_unwind(AssertUnwindSafe(|| match catch_unwind(f) {
        Ok(()) => "ok".to_string(),
        Err(p) => {
            let p = rethrow_db_fault(p);
            p.downcast_ref::<&'static str>().map(|s| s.to_string()).unwrap_or("unknown".into())
        }
    }));
    assert_eq!(receipt_for(|| std::panic::panic_any("insufficient_funds")).unwrap(), "insufficient_funds");
    assert_eq!(receipt_for(|| ()).unwrap(), "ok");
    let fault = receipt_for(|| db_fault("kv_get_failed")).expect_err("db fault became a receipt");
    assert_eq!(fault.downcast_ref::<DbFault>().map(|f| f.0), Some("kv_get_failed"));
}
