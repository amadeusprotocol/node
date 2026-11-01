use crate::model::entry::Entry;
use crate::model::tx_receipt::TXReceipt;
use rust_rocksdb::{MultiThreaded, Transaction, TransactionDB};
use vecpak::Term;

pub struct ChainIndex {
    hash: Vec<u8>,
    prev_hash: Vec<u8>,
    height: u64,
    txs: Vec<(Vec<u8>, usize, usize)>,
    filters: Vec<(Vec<u8>, Vec<u8>)>,
}

fn tx_spans(entry_bytes: &[u8]) -> Result<Vec<(usize, usize)>, &'static str> {
    if entry_bytes.first() != Some(&7) {
        return Err("entry_not_a_map");
    }
    let mut i = 1;
    let pairs = vecpak::decode_varint(entry_bytes, &mut i)?;
    for _ in 0..pairs {
        let key = vecpak::decode_term(entry_bytes, &mut i)?;
        if key != Term::Binary(b"txs".to_vec()) {
            vecpak::decode_term(entry_bytes, &mut i)?;
            continue;
        }
        if entry_bytes.get(i) != Some(&6) {
            return Err("entry_txs_not_a_list");
        }
        i += 1;
        let count = vecpak::decode_varint(entry_bytes, &mut i)?;
        let mut spans = Vec::new();
        for _ in 0..count {
            let start = i;
            vecpak::decode_term(entry_bytes, &mut i)?;
            spans.push((start, i - start));
        }
        return Ok(spans);
    }
    Err("entry_has_no_txs")
}

pub fn prepare(entry_bytes: &[u8], entry: &Entry) -> Result<ChainIndex, &'static str> {
    let spans = tx_spans(entry_bytes)?;
    if spans.len() != entry.txs.len() {
        return Err("entry_txs_span_mismatch");
    }
    let mut filters = Vec::new();
    for txu in &entry.txs {
        let action = &txu.tx.action;
        let arg0 = action.args.first().map(|a| a.as_slice()).unwrap_or(&[0u8]);
        filters.extend(crate::tx_filter::filter_rows(&txu.hash, txu.tx.nonce, &txu.tx.signer, &action.contract, &action.function, arg0));
    }
    Ok(ChainIndex {
        hash: entry.hash.clone(),
        prev_hash: entry.header.prev_hash.clone(),
        height: entry.header.height,
        txs: entry.txs.iter().zip(spans).map(|(txu, (start, size))| (txu.hash.clone(), start, size)).collect(),
        filters,
    })
}

fn receipt_term(r: &TXReceipt) -> Term {
    Term::PropList(vec![
        (Term::Binary(b"success".to_vec()), Term::Bool(r.success)),
        (Term::Binary(b"result".to_vec()), Term::Binary(r.result.clone())),
        (Term::Binary(b"exec_used".to_vec()), Term::Binary(r.exec_used.clone())),
        (Term::Binary(b"logs".to_vec()), Term::List(r.logs.iter().map(|l| Term::Binary(l.clone())).collect())),
    ])
}

pub fn write(
    db: &TransactionDB<MultiThreaded>,
    txn: &Transaction<TransactionDB<MultiThreaded>>,
    index: &ChainIndex,
    receipts: &[TXReceipt],
    root_receipts: &[u8; 32],
    root_contractstate: &[u8; 32],
) -> Result<(), &'static str> {
    let cf = |name: &str| db.cf_handle(name).ok_or("missing_column_family");
    let (sysconf, entry_meta, tx_cf, tx_filter) = (cf("sysconf")?, cf("entry_meta")?, cf("tx")?, cf("tx_filter")?);
    let put = |cf, key: &[u8], value: &[u8]| txn.put_cf(cf, key, value).map_err(|_| "chain_index_put_failed");
    let hash = index.hash.as_slice();
    let height = format!("{:012}", index.height).into_bytes();
    let meta = |suffix: &[u8]| crate::bcat(&[b"entry:", hash, suffix]);

    put(&entry_meta, &crate::bcat(&[b"by_height:", &height, b":", hash]), hash)?;
    put(&entry_meta, &crate::bcat(&[b"by_height_in_main_chain:", &height]), hash)?;
    put(&entry_meta, &meta(b":prev"), &index.prev_hash)?;
    put(&entry_meta, &crate::bcat(&[b"entry:", &index.prev_hash, b":next"]), hash)?;
    put(&entry_meta, &meta(b":in_chain"), b"")?;
    put(&entry_meta, &meta(b":root_receipts"), root_receipts)?;
    put(&entry_meta, &meta(b":root_contractstate"), root_contractstate)?;

    for (key, value) in &index.filters {
        put(&tx_filter, key, value)?;
    }

    let old_count = txn.get_cf(&sysconf, b"tx_count").map_err(|_| "tx_count_read_failed")?;
    let old_count = match old_count {
        Some(v) => std::str::from_utf8(&v).ok().and_then(|s| s.parse::<i128>().ok()).ok_or("tx_count_invalid")?,
        None => 0,
    };
    let new_count = old_count.checked_add(index.txs.len() as i128).ok_or("tx_count_overflow")?;
    put(&sysconf, b"tx_count", new_count.to_string().as_bytes())?;

    let by_txid: std::collections::HashMap<&[u8], &TXReceipt> = receipts.iter().map(|r| (r.txid.as_slice(), r)).collect();
    for (tx_hash, start, size) in &index.txs {
        let receipt = *by_txid.get(tx_hash.as_slice()).ok_or("missing_receipt")?;
        let pointer = vecpak::encode(Term::PropList(vec![
            (Term::Binary(b"entry_hash".to_vec()), Term::Binary(index.hash.clone())),
            (Term::Binary(b"receipt".to_vec()), receipt_term(receipt)),
            (Term::Binary(b"index_start".to_vec()), Term::VarInt(*start as i128)),
            (Term::Binary(b"index_size".to_vec()), Term::VarInt(*size as i128)),
        ]))?;
        put(&tx_cf, tx_hash, &pointer)?;
    }

    put(&sysconf, b"temporal_tip", hash)?;
    Ok(())
}
