pub use rust_rocksdb::{
    AsColumnFamilyRef, BlockBasedIndexType, BlockBasedOptions, BottommostLevelCompaction, BoundColumnFamily, Cache, ColumnFamilyDescriptor, CompactOptions,
    DBCompressionType, DBRawIteratorWithThreadMode, LruCacheOptions, MultiThreaded, Options, ReadOptions, SliceTransform, Transaction, TransactionDB,
    TransactionDBOptions, TransactionOptions, WriteOptions,
};

use rustler::{Atom, Binary, Env, Error, NewBinary, NifResult, Term};

rustler::atoms! {
    signer,
    tx,
    action,
    contract,
    function,
    args,
    nonce,
    hash,
}
const ZERO: &[u8] = &[0u8];

#[inline(always)]
pub fn create_filter_key(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0u8; 16];
    hasher.finalize_xof().fill(&mut output);
    output
}

pub fn build_tx_hashfilters<'a>(env: Env<'a>, txus: Vec<Term<'a>>) -> NifResult<Vec<(Binary<'a>, Binary<'a>)>> {
    let mut all_filters = Vec::with_capacity(txus.len() * 8);

    for txu in txus {
        let full_tx_hash: Binary = txu.map_get(hash())?.decode()?;
        let full_hash_slice = full_tx_hash.as_slice();

        //take only 8 bytes of the 32byte hash
        let mut prefix_bytes = [0u8; 8];
        let len = full_hash_slice.len().min(8);
        prefix_bytes[0..len].copy_from_slice(&full_hash_slice[0..len]);
        let mut tx_val_bin = NewBinary::new(env, 8);
        tx_val_bin.as_mut_slice().copy_from_slice(&prefix_bytes);
        let tx_hash8: Binary = tx_val_bin.into();

        let tx = txu.map_get(tx())?;

        let nonce_u64: u64 = tx.map_get(nonce())?.decode()?;
        let nonce_bytes = nonce_u64.to_be_bytes();

        let signer_bin: Binary = tx.map_get(signer())?.decode()?;
        let signer = signer_bin.as_slice();

        let action_map = tx.map_get(action())?;
        let contract_bin: Binary = action_map.map_get(contract())?.decode()?;
        let contract = contract_bin.as_slice();
        let function_bin: Binary = action_map.map_get(function())?.decode()?;
        let func = function_bin.as_slice();

        let args_list: Vec<Term> = action_map.map_get(args())?.decode()?;
        let arg0 = if let Some(first_arg) = args_list.first() {
            let b: Binary = first_arg.decode()?;
            b.as_slice()
        } else {
            ZERO
        };

        let mut push_key = |parts: &[&[u8]]| {
            let raw_hash = create_filter_key(parts);

            let mut bin = NewBinary::new(env, 24);
            let s = bin.as_mut_slice();

            s[0..16].copy_from_slice(&raw_hash);
            s[16..24].copy_from_slice(&nonce_bytes);

            all_filters.push((bin.into(), tx_hash8));
        };

        match (contract, func) {
            (b"Epoch", b"submit_sol") => {
                push_key(&[signer, ZERO, ZERO, ZERO]);
                push_key(&[ZERO, arg0, ZERO, ZERO]);
                // Do we care about this?
                // tx_filter CF goes from 10G to 22G if we add this back
                // reevaluate later difference is OK
                push_key(&[signer, ZERO, contract, ZERO]);
                push_key(&[signer, ZERO, contract, func]);
                push_key(&[ZERO, ZERO, contract, ZERO]);
                push_key(&[ZERO, ZERO, contract, func]);
            }
            _ => {
                push_key(&[signer, ZERO, ZERO, ZERO]);
                push_key(&[ZERO, arg0, ZERO, ZERO]);
                push_key(&[signer, arg0, ZERO, ZERO]);
                push_key(&[ZERO, ZERO, contract, ZERO]);
                push_key(&[ZERO, ZERO, contract, func]);
                push_key(&[signer, ZERO, contract, ZERO]);
                push_key(&[signer, ZERO, contract, func]);
                push_key(&[ZERO, arg0, contract, ZERO]);
                push_key(&[ZERO, arg0, contract, func]);
                push_key(&[signer, arg0, contract, func]);
            }
        }
    }

    Ok(all_filters)
}

pub fn query_tx_hashfilter<'a, 'db>(
    env: Env<'a>,
    db: &'db TransactionDB<MultiThreaded>,
    signer: &[u8],
    arg0: &[u8],
    contract: &[u8],
    function: &[u8],
    limit: usize,
    sort: bool,
    cursor: Option<&[u8]>,
) -> NifResult<(Option<Binary<'a>>, Vec<Binary<'a>>)> {
    let cf_txfilter = &db.cf_handle("tx_filter").unwrap();
    let cf_tx = &db.cf_handle("tx").unwrap();

    let snapshot = &db.snapshot();

    let mut opts_txfilter = ReadOptions::default();
    opts_txfilter.set_snapshot(&snapshot);
    opts_txfilter.set_prefix_same_as_start(true);

    let mut opts_tx = ReadOptions::default();
    opts_tx.set_snapshot(&snapshot);
    opts_tx.set_prefix_same_as_start(true);

    let mut iter_txfilter = db.raw_iterator_cf_opt(cf_txfilter, opts_txfilter);
    let mut iter_tx = db.raw_iterator_cf_opt(cf_tx, opts_tx);

    let key = create_filter_key(&[signer, arg0, contract, function]);
    let prefix = &key[0..16];

    let is_desc = sort == true;

    let start_key = if let Some(c) = cursor {
        c.to_vec()
    } else {
        let mut k = Vec::with_capacity(24);
        k.extend_from_slice(prefix);
        if is_desc {
            k.extend_from_slice(&[0xFF; 8]); // End of bucket
        } else {
            k.extend_from_slice(&[0x00; 8]); // Start of bucket
        }
        k
    };

    if is_desc {
        iter_txfilter.seek_for_prev(&start_key);
    } else {
        iter_txfilter.seek(&start_key);
    }

    // Skip the cursor itself if present (Pagination "After")
    if cursor.is_some() && iter_txfilter.valid() {
        if let Some(k) = iter_txfilter.key() {
            if k == &start_key {
                if is_desc {
                    iter_txfilter.prev();
                } else {
                    iter_txfilter.next();
                }
            }
        }
    }

    let mut results = Vec::new();
    let mut last_cursor_bytes: Option<Vec<u8>> = None;
    while iter_txfilter.valid() {
        // Check if we are still in the correct 8-byte bucket
        match iter_txfilter.key() {
            Some(k) if k.len() >= 16 && &k[0..16] == prefix => {
                // Key is valid, get the value (Tx Prefix)
            }
            _ => break, // Exit loop if prefix mismatches or key invalid
        }

        let tx_prefix_8 = iter_txfilter.value().unwrap();

        // TODO: check for collisions when signer/arg0/contract/function is used
        iter_tx.seek(tx_prefix_8);
        while iter_tx.valid() {
            match iter_tx.key() {
                Some(k) if k.len() >= 8 && &k[0..8] == tx_prefix_8 => {
                    if let Some(k) = iter_txfilter.key() {
                        last_cursor_bytes = Some(k.to_vec());
                    }
                    let tx_data = iter_tx.value().unwrap();
                    let mut bin = rustler::NewBinary::new(env, tx_data.len());
                    bin.as_mut_slice().copy_from_slice(tx_data);
                    results.push(bin.into());
                    if results.len() >= limit {
                        let cursor_bin = make_cursor_bin(env, last_cursor_bytes);
                        return Ok((cursor_bin, results));
                    }
                }
                _ => break, // Stop inner loop
            }
            iter_tx.next();
        }

        // Advance Outer Iterator
        if is_desc {
            iter_txfilter.prev();
        } else {
            iter_txfilter.next();
        }
    }

    let cursor_bin = make_cursor_bin(env, last_cursor_bytes);
    Ok((cursor_bin, results))
}

fn make_cursor_bin<'a>(env: Env<'a>, bytes: Option<Vec<u8>>) -> Option<Binary<'a>> {
    match bytes {
        Some(v) => {
            let mut bin = rustler::NewBinary::new(env, v.len());
            bin.as_mut_slice().copy_from_slice(&v);
            Some(bin.into())
        }
        None => None,
    }
}
