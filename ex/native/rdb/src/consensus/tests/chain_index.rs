#![cfg(test)]
use crate::model::tx_receipt::TXReceipt;
use rust_rocksdb::{ColumnFamilyDescriptor, MultiThreaded, Options, TransactionDB, TransactionDBOptions};
use vecpak::Term;

fn get<'a>(t: &'a Term, name: &[u8]) -> &'a Term {
    let Term::PropList(p) = t else { panic!("not a map") };
    &p.iter().find(|(k, _)| matches!(k, Term::Binary(b) if b == name)).unwrap().1
}
fn bin(t: &Term) -> Vec<u8> { match t { Term::Binary(b) => b.clone(), Term::Nil() => panic!("nil"), o => panic!("{:?}", o) } }
fn pairs(t: &Term) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Term::List(l) = t else { panic!() };
    l.iter().map(|p| { let Term::List(kv) = p else { panic!() }; (bin(&kv[0]), bin(&kv[1])) }).collect()
}

#[test]
fn rust_chain_index_matches_rows_written_by_the_old_elixir_code() {
    let samples: [&[u8]; 3] = [include_bytes!("fixtures/index_89199999.vecpak"), include_bytes!("fixtures/index_89364717.vecpak"), include_bytes!("fixtures/index_89200001.vecpak")];
    for raw in samples {
        let sample = vecpak::decode(raw).unwrap();
        let entry_bytes = bin(get(&sample, b"entry"));
        let entry = crate::model::entry::from_bytes(&entry_bytes).unwrap();
        let meta = pairs(get(&sample, b"meta"));
        let txptr = pairs(get(&sample, b"txptr"));
        let filters = pairs(get(&sample, b"filters"));

        let receipts: Vec<TXReceipt> = txptr.iter().map(|(hash, ptr)| {
            let r = get(&vecpak::decode(ptr).unwrap(), b"receipt").clone();
            let Term::Bool(success) = get(&r, b"success") else { panic!() };
            let Term::List(logs) = get(&r, b"logs") else { panic!() };
            TXReceipt { txid: hash.clone(), success: *success, result: bin(get(&r, b"result")), exec_used: bin(get(&r, b"exec_used")), logs: logs.iter().map(bin).collect() }
        }).collect();
        let root = |suffix: &[u8]| -> [u8; 32] { meta.iter().find(|(k, _)| k.ends_with(suffix)).unwrap().1.clone().try_into().unwrap() };

        let dir = tempfile::TempDir::new().unwrap();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = ["sysconf", "entry_meta", "tx", "tx_filter"].map(|n| ColumnFamilyDescriptor::new(n, Options::default()));
        let db = TransactionDB::<MultiThreaded>::open_cf_descriptors(&opts, &TransactionDBOptions::default(), dir.path(), cfs).unwrap();

        let index = crate::consensus::chain_index::prepare(&entry_bytes, &entry).unwrap();
        let txn = db.transaction();
        crate::consensus::chain_index::write(&db, &txn, &index, &receipts, &root(b":root_receipts"), &root(b":root_contractstate")).unwrap();
        txn.commit().unwrap();

        let read = |cf: &str, k: &[u8]| db.get_cf(&db.cf_handle(cf).unwrap(), k).unwrap();
        for (k, v) in &meta { assert_eq!(read("entry_meta", k).as_ref(), Some(v), "meta key {:?}", String::from_utf8_lossy(k)); }
        for (k, v) in &txptr { assert_eq!(read("tx", k).as_ref(), Some(v), "tx pointer"); }
        let mut last = std::collections::BTreeMap::new();
        for (k, v) in &filters { last.insert(k.clone(), v.clone()); }
        for (k, v) in &last { assert_eq!(read("tx_filter", k).as_ref(), Some(v), "filter row"); }
        let stored = db.iterator_cf(&db.cf_handle("tx_filter").unwrap(), rust_rocksdb::IteratorMode::Start).count();
        assert_eq!(stored, last.len(), "no extra filter rows");
        assert_eq!(read("sysconf", b"tx_count"), Some(entry.txs.len().to_string().into_bytes()));
        assert_eq!(read("sysconf", b"temporal_tip"), Some(entry.hash.clone()));
    }
}
