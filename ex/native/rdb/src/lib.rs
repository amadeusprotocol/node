pub mod atoms;
pub mod consensus;
pub mod model;
pub mod tx_filter;
pub mod upow;

use rustler::types::{Binary, OwnedBinary};
use rustler::{Atom, Encoder, Env, Error, NifResult, NifTaggedEnum, ResourceArc, Term};

pub use rust_rocksdb::{
    AsColumnFamilyRef, BlockBasedIndexType, BlockBasedOptions, BottommostLevelCompaction, BoundColumnFamily, Cache, ColumnFamilyDescriptor, CompactOptions,
    DBCompressionType, DBRawIteratorWithThreadMode, LruCacheOptions, MultiThreaded, Options, ReadOptions, SliceTransform, Transaction, TransactionDB,
    TransactionDBOptions, TransactionOptions, WriteOptions,
};

use std::path::Path;
use std::ptr::NonNull;
use std::sync::Mutex;

use vecpak_ex;

use crate::consensus::bic::protocol;
use crate::consensus::{bintree, consensus_kv, consensus_muts};

pub struct DbResource {
    pub db: TransactionDB<MultiThreaded>,
}

pub struct CfResource {
    db: ResourceArc<DbResource>,
    _name: String,
    handle: NonNull<rust_librocksdb_sys::rocksdb_column_family_handle_t>,
}
unsafe impl Send for CfResource {}
unsafe impl Sync for CfResource {}
impl AsColumnFamilyRef for CfResource {
    fn inner(&self) -> *mut rust_librocksdb_sys::rocksdb_column_family_handle_t {
        self.handle.as_ptr()
    }
}

type Tx<'a> = Transaction<'a, TransactionDB<MultiThreaded>>;
pub struct TxResource {
    tx: Mutex<Option<Tx<'static>>>,
    _db: ResourceArc<DbResource>,
}
unsafe impl Send for TxResource {}
unsafe impl Sync for TxResource {}
impl Drop for TxResource {
    fn drop(&mut self) {
        // Best effort: if still open, rollback to release locks
        let tx = match self.tx.get_mut() {
            Ok(tx) => tx,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(txn) = tx.take() {
            let _ = txn.rollback(); // ignore error; we're cleaning up
        }
    }
}

type DbIter<'a> = DBRawIteratorWithThreadMode<'a, TransactionDB<MultiThreaded>>;
enum IterInner {
    Db(DbIter<'static>),
}
pub struct ItResource {
    it: Mutex<Option<IterInner>>,
    _db: ResourceArc<DbResource>,
    _cf: Option<ResourceArc<CfResource>>,
}
unsafe impl Send for ItResource {}
unsafe impl Sync for ItResource {}

impl ItResource {
    pub fn new(db: ResourceArc<DbResource>, cf: Option<ResourceArc<CfResource>>) -> ResourceArc<Self> {
        let real: DbIter<'_> = match &cf {
            Some(cf) => db.db.raw_iterator_cf(&**cf),
            None => db.db.raw_iterator(),
        };
        let it = IterInner::Db(unsafe { std::mem::transmute::<DbIter<'_>, DbIter<'static>>(real) });

        ResourceArc::new(Self { it: Mutex::new(Some(it)), _db: db, _cf: cf })
    }
}

impl Drop for ItResource {
    fn drop(&mut self) {
        let it = match self.it.get_mut() {
            Ok(it) => it,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ = it.take();
    }
}

#[allow(non_local_definitions)]
fn on_load(env: Env, _: Term) -> bool {
    let _ = rustler::resource!(DbResource, env);
    let _ = rustler::resource!(CfResource, env);
    let _ = rustler::resource!(TxResource, env);
    let _ = rustler::resource!(ItResource, env);
    true
}

fn to_nif_rdb_err(err: rust_rocksdb::Error) -> Error {
    Error::Term(Box::new(err.to_string()))
}

fn to_nif_err(err: Atom) -> Error {
    Error::Term(Box::new(err))
}

#[rustler::nif]
fn open_transaction_db<'a>(env: Env<'a>, path: String, cf_names: Vec<String>) -> NifResult<Term<'a>> {
    let mut lru_opts = LruCacheOptions::default();
    lru_opts.set_capacity(512 * 1024 * 1024); // 512MB row cache (hot accounts)
    lru_opts.set_num_shard_bits(6);
    let row_cache = Cache::new_lru_cache_opts(&lru_opts);

    let block_cache = Cache::new_lru_cache(3 * 1024 * 1024 * 1024); // 3GB block cache (shared)

    let mut db_opts = Options::default();
    db_opts.create_if_missing(true);
    db_opts.create_missing_column_families(true);
    db_opts.set_max_open_files(10000);
    db_opts.increase_parallelism(4);
    db_opts.set_max_background_jobs(4);

    db_opts.set_max_total_wal_size(512 * 1024 * 1024); // 512MB

    /*
    db_opts.enable_statistics();
    db_opts.set_statistics_level(rust_rocksdb::statistics::StatsLevel::All);
    db_opts.set_skip_stats_update_on_db_open(true);
    */

    let mut txn_db_opts = TransactionDBOptions::default();
    txn_db_opts.set_default_lock_timeout(3000);
    txn_db_opts.set_txn_lock_timeout(3000);
    txn_db_opts.set_num_stripes(32);

    let mut cf_opts = Options::default();
    cf_opts.set_row_cache(&row_cache);

    let mut block_based_options = BlockBasedOptions::default();
    block_based_options.set_block_cache(&block_cache);

    block_based_options.set_bloom_filter(10.0, false);
    block_based_options.set_index_type(BlockBasedIndexType::TwoLevelIndexSearch);
    block_based_options.set_cache_index_and_filter_blocks(true);
    block_based_options.set_cache_index_and_filter_blocks_with_high_priority(true);
    block_based_options.set_pin_top_level_index_and_filter(true);
    block_based_options.set_partition_filters(true);
    block_based_options.set_pin_l0_filter_and_index_blocks_in_cache(false);
    cf_opts.set_block_based_table_factory(&block_based_options);

    let dict_bytes = 32 * 1024;
    cf_opts.set_compression_per_level(&[
        DBCompressionType::None, // L0
        DBCompressionType::None, // L1
        DBCompressionType::Zstd, // L2
        DBCompressionType::Zstd, // L3
        DBCompressionType::Zstd, // L4
        DBCompressionType::Zstd, // L5
        DBCompressionType::Zstd, // L6
    ]);

    cf_opts.set_compression_type(DBCompressionType::Zstd);
    cf_opts.set_compression_options(-14, 2, 0, dict_bytes);
    cf_opts.set_zstd_max_train_bytes(100 * dict_bytes);

    // SST sizing: 256MB base, doubling per level — L1=256MB, L2=512MB, L3=1GB, L4=2GB, L5+=4GB
    cf_opts.set_target_file_size_base(256 * 1024 * 1024);
    cf_opts.set_target_file_size_multiplier(2);
    cf_opts.set_max_compaction_bytes(2 * 1024 * 1024 * 1024); // 2GB

    // Memtable: 128MB × 3 per CF, flush as soon as one is full
    cf_opts.set_write_buffer_size(128 * 1024 * 1024);
    cf_opts.set_max_write_buffer_number(3);
    cf_opts.set_min_write_buffer_number_to_merge(1);
    // L0 thresholds — back to sane defaults now that compactions actually work
    cf_opts.set_level_zero_file_num_compaction_trigger(4);
    cf_opts.set_level_zero_slowdown_writes_trigger(20);
    cf_opts.set_level_zero_stop_writes_trigger(36);
    cf_opts.set_max_subcompactions(1);

    //cf_opts.set_level_compaction_dynamic_level_bytes(false);

    let cf_descriptors: Vec<_> = cf_names
        .iter()
        .map(|name| {
            let mut opts = cf_opts.clone();

            if name == "tx" {
                opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(8));
                opts.set_memtable_prefix_bloom_ratio(0.1);
            }
            if name == "tx_filter" {
                opts.set_prefix_extractor(SliceTransform::create_fixed_prefix(16));
                opts.set_memtable_prefix_bloom_ratio(0.1);
            }

            ColumnFamilyDescriptor::new(name.as_str(), opts)
        })
        .collect();

    match TransactionDB::open_cf_descriptors(&db_opts, &txn_db_opts, Path::new(&path), cf_descriptors) {
        Ok(db) => {
            let resource = ResourceArc::new(DbResource { db });

            let mut out = Vec::with_capacity(cf_names.len());
            for name in cf_names {
                let cf_arc = resource.db.cf_handle(&name).ok_or_else(|| Error::Term(Box::new(format!("unknown column family: {}", name))))?;
                let raw = cf_arc.inner();
                let handle = NonNull::new(raw).ok_or_else(|| Error::Term(Box::new("null CF handle")))?;
                let cf_res = ResourceArc::new(CfResource { db: resource.clone(), _name: name.clone(), handle });
                out.push(cf_res);
            }

            Ok((atoms::ok(), resource, out).encode(env))
        }
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn close_db(db: ResourceArc<DbResource>) -> NifResult<Atom> {
    unsafe {
        let ptr = &db.db as *const TransactionDB<MultiThreaded> as *mut TransactionDB<MultiThreaded>;

        //(*ptr).cancel_all_background_work(true);
        let _ = (*ptr).flush_wal(true);

        std::ptr::drop_in_place(ptr);
    }
    Ok(atoms::ok())
}

#[rustler::nif(schedule = "DirtyCpu")]
fn drop_cf<'a>(env: Env<'a>, db: ResourceArc<DbResource>, cf_name: String) -> NifResult<Term<'a>> {
    match db.db.drop_cf(cf_name.as_str()) {
        Ok(()) => Ok(atoms::ok().encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn property_value<'a>(env: Env<'a>, db: ResourceArc<DbResource>, key: String) -> NifResult<Term<'a>> {
    match db.db.property_value(&key) {
        Ok(Some(value)) => Ok((atoms::ok(), value).encode(env)),
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn property_value_cf<'a>(env: Env<'a>, cf: ResourceArc<CfResource>, key: String) -> NifResult<Term<'a>> {
    match cf.db.db.property_value_cf(&*cf, &key) {
        Ok(Some(value)) => Ok((atoms::ok(), value).encode(env)),
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn compact_range_cf_all<'a>(env: Env<'a>, cf: ResourceArc<CfResource>) -> NifResult<Term<'a>> {
    let mut copts = CompactOptions::default();
    copts.set_exclusive_manual_compaction(false);
    copts.set_bottommost_level_compaction(BottommostLevelCompaction::ForceOptimized);

    cf.db.db.compact_range_cf_opt(&*cf, None::<&[u8]>, None::<&[u8]>, &copts);

    Ok(atoms::ok().encode(env))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn checkpoint(db: ResourceArc<DbResource>, path: String) -> NifResult<Atom> {
    db.db.create_checkpoint(&path).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn flush_wal(db: ResourceArc<DbResource>) -> NifResult<Atom> {
    db.db.flush_wal(true).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn flush(db: ResourceArc<DbResource>) -> NifResult<Atom> {
    db.db.flush().map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn flush_cf(cf: ResourceArc<CfResource>) -> NifResult<Atom> {
    cf.db.db.flush_cf(&*cf).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn get<'a>(env: Env<'a>, db: ResourceArc<DbResource>, key: Binary) -> NifResult<Term<'a>> {
    match db.db.get(key.as_slice()) {
        Ok(Some(value)) => {
            let mut ob = OwnedBinary::new(value.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&value);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        }
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn get_cf<'a>(env: Env<'a>, cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Term<'a>> {
    match cf.db.db.get_cf(&*cf, key.as_slice()) {
        Ok(Some(value)) => {
            let mut ob = OwnedBinary::new(value.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&value);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        }
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn exists<'a>(env: Env<'a>, db: ResourceArc<DbResource>, key: Binary) -> NifResult<Term<'a>> {
    let mut ro = ReadOptions::default();
    ro.fill_cache(false);
    match db.db.get_pinned_opt(key.as_slice(), &ro) {
        Ok(Some(_)) => Ok((atoms::ok(), true).encode(env)),
        Ok(None) => Ok((atoms::ok(), false).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn exists_cf<'a>(env: Env<'a>, cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Term<'a>> {
    let mut ro = ReadOptions::default();
    ro.fill_cache(false);
    match cf.db.db.get_pinned_cf_opt(&*cf, key.as_slice(), &ro) {
        Ok(Some(_)) => Ok((atoms::ok(), true).encode(env)),
        Ok(None) => Ok((atoms::ok(), false).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn put(db: ResourceArc<DbResource>, key: Binary, value: Binary) -> NifResult<Atom> {
    db.db.put(key.as_slice(), value.as_slice()).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn put_cf(cf: ResourceArc<CfResource>, key: Binary, value: Binary) -> NifResult<Atom> {
    cf.db.db.put_cf(&*cf, key.as_slice(), value.as_slice()).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn delete(db: ResourceArc<DbResource>, key: Binary) -> NifResult<Atom> {
    db.db.delete(key.as_slice()).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn delete_cf(cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Atom> {
    cf.db.db.delete_cf(&*cf, key.as_slice()).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif(schedule = "DirtyIo")]
fn delete_range_cf(cf: ResourceArc<CfResource>, start_key: Binary, end_key: Binary, compact: bool) -> NifResult<Atom> {
    cf.db.db.delete_range_cf(&*cf, start_key.as_slice(), end_key.as_slice()).map_err(to_nif_rdb_err)?;
    if compact {
        cf.db.db.compact_range_cf(&*cf, Option::<&[u8]>::None, Option::<&[u8]>::None);
    }
    Ok(atoms::ok())
}

#[rustler::nif]
fn iterator<'a>(env: Env<'a>, db: ResourceArc<DbResource>) -> NifResult<Term<'a>> {
    let res = ItResource::new(db.clone(), None);
    Ok((atoms::ok(), res).encode(env))
}

#[rustler::nif]
fn iterator_close(it_resource: ResourceArc<ItResource>) -> Atom {
    let mut guard = it_resource.it.lock().unwrap_or_else(|p| p.into_inner());
    *guard = None;
    atoms::ok()
}

#[rustler::nif]
fn iterator_cf<'a>(env: Env<'a>, cf: ResourceArc<CfResource>) -> NifResult<Term<'a>> {
    let res = ItResource::new(cf.db.clone(), Some(cf.clone()));
    Ok((atoms::ok(), res).encode(env))
}

// Transaction
#[rustler::nif]
fn transaction<'a>(env: Env<'a>, db: ResourceArc<DbResource>) -> NifResult<Term<'a>> {
    let wopts = WriteOptions::default();
    let topts = TransactionOptions::default();

    let tx_local: Tx<'_> = db.db.transaction_opt(&wopts, &topts);
    let tx_static: Tx<'static> = unsafe { std::mem::transmute::<Tx<'_>, Tx<'static>>(tx_local) };

    Ok((atoms::ok(), ResourceArc::new(TxResource { _db: db, tx: Mutex::new(Some(tx_static)) })).encode(env))
}

#[rustler::nif]
fn transaction_with_snapshot<'a>(env: Env<'a>, db: ResourceArc<DbResource>) -> NifResult<Term<'a>> {
    let wopts = WriteOptions::default();
    let mut topts = TransactionOptions::default();
    topts.set_snapshot(true);

    let tx_local: Tx<'_> = db.db.transaction_opt(&wopts, &topts);
    let tx_static: Tx<'static> = unsafe { std::mem::transmute::<Tx<'_>, Tx<'static>>(tx_local) };

    Ok((atoms::ok(), ResourceArc::new(TxResource { _db: db, tx: Mutex::new(Some(tx_static)) })).encode(env))
}

#[rustler::nif(schedule = "DirtyIo")]
fn transaction_commit(tx: ResourceArc<TxResource>) -> NifResult<Atom> {
    let mut guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.take().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    drop(guard); // don’t hold the lock while committing
    txn.commit().map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_rollback(tx: ResourceArc<TxResource>) -> NifResult<Atom> {
    let mut guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.take().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    drop(guard);
    txn.rollback().map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_set_savepoint(tx: ResourceArc<TxResource>) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.set_savepoint();
    Ok(atoms::ok())
}

#[rustler::nif]
fn transaction_rollback_to_savepoint(tx: ResourceArc<TxResource>) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.rollback_to_savepoint().map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_get<'a>(env: Env<'a>, tx: ResourceArc<TxResource>, key: Binary) -> NifResult<Term<'a>> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    match txn.get(key.as_slice()) {
        Ok(Some(value)) => {
            let mut ob = OwnedBinary::new(value.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&value);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        }
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn transaction_get_cf<'a>(env: Env<'a>, tx: ResourceArc<TxResource>, cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Term<'a>> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    match txn.get_cf(&*cf, key.as_slice()) {
        Ok(Some(value)) => {
            let mut ob = OwnedBinary::new(value.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&value);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        }
        Ok(None) => Ok((atoms::ok(), atoms::nil()).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    }
}

#[rustler::nif]
fn transaction_exists<'a>(env: Env<'a>, tx: ResourceArc<TxResource>, key: Binary) -> NifResult<Term<'a>> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    let mut ro = ReadOptions::default();
    ro.fill_cache(false);
    let rustlol = match txn.get_pinned_opt(key.as_slice(), &ro) {
        Ok(Some(_)) => Ok((atoms::ok(), true).encode(env)),
        Ok(None) => Ok((atoms::ok(), false).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    };
    rustlol
}

#[rustler::nif]
fn transaction_exists_cf<'a>(env: Env<'a>, tx: ResourceArc<TxResource>, cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Term<'a>> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    let mut ro = ReadOptions::default();
    ro.fill_cache(false);
    let rustlol = match txn.get_pinned_cf_opt(&*cf, key.as_slice(), &ro) {
        Ok(Some(_)) => Ok((atoms::ok(), true).encode(env)),
        Ok(None) => Ok((atoms::ok(), false).encode(env)),
        Err(e) => Err(to_nif_rdb_err(e)),
    };
    rustlol
}

#[rustler::nif]
fn transaction_put(tx: ResourceArc<TxResource>, key: Binary, val: Binary) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.put(key.as_slice(), val.as_slice()).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_put_cf(tx: ResourceArc<TxResource>, cf: ResourceArc<CfResource>, key: Binary, val: Binary) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.put_cf(&*cf, key.as_slice(), val.as_slice()).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_delete(tx: ResourceArc<TxResource>, key: Binary) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.delete(key.as_slice()).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif]
fn transaction_delete_cf(tx: ResourceArc<TxResource>, cf: ResourceArc<CfResource>, key: Binary) -> NifResult<Atom> {
    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    txn.delete_cf(&*cf, key.as_slice()).map(|_| atoms::ok()).map_err(to_nif_rdb_err)
}

#[rustler::nif(schedule = "DirtyIo")]
fn transaction_scan_cf<'a>(
    env: Env<'a>,
    tx: ResourceArc<TxResource>,
    cf: Option<ResourceArc<CfResource>>,
    prefix: Binary<'a>,
    cursor: Binary<'a>,
    direction: Atom,
    skip_cursor: bool,
    offset: u32,
    limit: u32,
    max_bytes: u64,
) -> NifResult<(Option<Binary<'a>>, Vec<(Binary<'a>, Binary<'a>)>)> {
    let reverse = if direction == atoms::reverse() {
        true
    } else if direction == atoms::forward() {
        false
    } else {
        return Err(Error::BadArg);
    };

    if limit == 0 {
        return Ok((None, Vec::new()));
    }

    let prefix = prefix.as_slice();
    let cursor = cursor.as_slice();
    let mut start_key = Vec::with_capacity(prefix.len() + cursor.len());
    start_key.extend_from_slice(prefix);
    start_key.extend_from_slice(cursor);

    let guard = tx.tx.lock().unwrap_or_else(|p| p.into_inner());
    let txn = guard.as_ref().ok_or_else(|| to_nif_err(atoms::mutex_closed()))?;
    let mut it = match cf {
        Some(cf) => txn.raw_iterator_cf(&*cf),
        None => txn.raw_iterator(),
    };

    if reverse {
        it.seek_for_prev(&start_key);
    } else {
        it.seek(&start_key);
    }

    if skip_cursor && it.valid() {
        if let Some(k) = it.key() {
            if k == start_key.as_slice() {
                if reverse {
                    it.prev();
                } else {
                    it.next();
                }
            }
        }
    }

    for _ in 0..offset {
        if !it.valid() {
            break;
        }
        match it.key() {
            Some(k) if k.starts_with(prefix) => {
                if reverse {
                    it.prev();
                } else {
                    it.next();
                }
            }
            _ => break,
        }
    }

    let mut rows = Vec::new();
    let mut last_cursor = None;
    let mut bytes = 0u64;

    while rows.len() < limit as usize && it.valid() {
        let Some(k) = it.key() else { break };
        if !k.starts_with(prefix) {
            break;
        }
        let Some(v) = it.value() else { break };

        let suffix = &k[prefix.len()..];
        let next_bytes = bytes.saturating_add(suffix.len() as u64).saturating_add(v.len() as u64);
        if max_bytes > 0 && !rows.is_empty() && next_bytes > max_bytes {
            break;
        }
        bytes = next_bytes;

        let mut kb = OwnedBinary::new(suffix.len()).ok_or_else(|| Error::Term(Box::new("alloc key")))?;
        kb.as_mut_slice().copy_from_slice(suffix);
        let key_bin = Binary::from_owned(kb, env);

        let mut vb = OwnedBinary::new(v.len()).ok_or_else(|| Error::Term(Box::new("alloc val")))?;
        vb.as_mut_slice().copy_from_slice(v);
        let val_bin = Binary::from_owned(vb, env);

        last_cursor = Some(key_bin);
        rows.push((key_bin, val_bin));

        if reverse {
            it.prev();
        } else {
            it.next();
        }
    }

    Ok((last_cursor, rows))
}

//Iterator Generic
#[derive(NifTaggedEnum)]
pub enum IterMove<'a> {
    First,
    Last,
    Next,
    Prev,
    Seek(Binary<'a>),
    SeekForPrev(Binary<'a>),
}

fn parse_iter_move<'a>(term: Term<'a>) -> Result<IterMove<'a>, Error> {
    term.decode::<IterMove<'a>>()
}

#[rustler::nif]
fn iterator_move<'a>(env: Env<'a>, res: ResourceArc<ItResource>, action: Term<'a>) -> NifResult<Term<'a>> {
    let action = parse_iter_move(action)?;
    let mut g = res.it.lock().unwrap_or_else(|p| p.into_inner());

    macro_rules! move_and_encode {
        ($it:ident) => {{
            match action {
                IterMove::First => $it.seek_to_first(),
                IterMove::Last => $it.seek_to_last(),
                IterMove::Next => $it.next(),
                IterMove::Prev => $it.prev(),
                IterMove::Seek(ref key) => $it.seek(key.as_slice()),
                IterMove::SeekForPrev(ref key) => $it.seek_for_prev(key.as_slice()),
            }

            if !$it.valid() {
                return Ok((atoms::error(), atoms::invalid_iterator()).encode(env));
            }

            match ($it.key(), $it.value()) {
                (Some(k), Some(v)) => {
                    let mut kb = OwnedBinary::new(k.len()).ok_or_else(|| Error::Term(Box::new("alloc key")))?;
                    kb.as_mut_slice().copy_from_slice(k);
                    let mut vb = OwnedBinary::new(v.len()).ok_or_else(|| Error::Term(Box::new("alloc val")))?;
                    vb.as_mut_slice().copy_from_slice(v);
                    Ok((atoms::ok(), Binary::from_owned(kb, env), Binary::from_owned(vb, env)).encode(env))
                }
                _ => Ok((atoms::ok(), atoms::nil(), atoms::nil()).encode(env)),
            }
        }};
    }

    match &mut *g {
        Some(IterInner::Db(it)) => move_and_encode!(it),
        None => Ok((atoms::error(), atoms::invalid_iterator()).encode(env)),
    }
}

#[inline]
pub fn bcat(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut v = Vec::with_capacity(total);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

#[inline]
pub fn fixed<const N: usize>(t: Term<'_>) -> Result<[u8; N], Error> {
    let b: Binary = t.decode()?;
    let s = b.as_slice();
    if s.len() != N {
        return Err(Error::BadArg);
    }
    let mut a = [0u8; N];
    a.copy_from_slice(s);
    Ok(a)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn apply_entry<'a>(
    env: Env<'a>,
    db: ResourceArc<DbResource>,
    entry_vecpak: Binary,
    pk: Binary,
    sk: Binary,
    testnet: bool,
    testnet_peddlebikes: Vec<Binary>,
) -> Result<Term<'a>, Error> {
    let __res: std::thread::Result<Result<Term<'a>, Error>> = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let entry = crate::model::entry::from_bytes(entry_vecpak.as_slice()).map_err(|_| Error::BadArg)?;

        let txn_opts = TransactionOptions::default();
        let write_opts = WriteOptions::default();
        let txn = db.db.transaction_opt(&write_opts, &txn_opts);

        let (txn, muts, muts_rev, receipts, root_receipts, root_contractstate, root_contractstate_hbsmt) = consensus::consensus_apply::apply_entry(
            &db.db,
            txn,
            entry,
            pk.as_slice(),
            sk.as_slice(),
            testnet,
            testnet_peddlebikes.iter().map(|bin| bin.as_slice().to_vec()).collect(),
        );

        let tx_static: Tx<'static> = unsafe { std::mem::transmute::<Tx<'_>, Tx<'static>>(txn) };
        let term_txn = ResourceArc::new(TxResource { _db: db, tx: Mutex::new(Some(tx_static)) }).encode(env);

        let mut ob1 = OwnedBinary::new(root_receipts.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
        ob1.as_mut_slice().copy_from_slice(&root_receipts);
        let mut ob2 = OwnedBinary::new(root_contractstate.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
        ob2.as_mut_slice().copy_from_slice(&root_contractstate);
        // SHIM: shadow HBSMT root (observation only, not consensus). Remove at hardfork.
        let mut ob3 = OwnedBinary::new(root_contractstate_hbsmt.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
        ob3.as_mut_slice().copy_from_slice(&root_contractstate_hbsmt);

        let mut receipts_list = Vec::new();
        for r in receipts {
            let mut map = Term::map_new(env);
            map = map.map_put(atoms::success(), r.success).ok().unwrap();
            map = map.map_put(atoms::txid(), to_binary2(env, &r.txid)).ok().unwrap();
            map = map.map_put(atoms::result(), to_binary2(env, &r.result)).ok().unwrap();
            map = map.map_put(atoms::exec_used(), to_binary2(env, &r.exec_used)).ok().unwrap();
            let logs_list: Vec<Binary> = r.logs.iter().map(|log| to_binary2(env, log)).collect();
            map = map.map_put(atoms::logs(), logs_list).ok().unwrap();
            receipts_list.push(map);
        }

        Ok((
            term_txn,
            consensus_muts::mutations_to_map(muts),
            consensus_muts::mutations_to_map(muts_rev),
            receipts_list,
            Binary::from_owned(ob1, env).encode(env),
            Binary::from_owned(ob2, env).encode(env),
            Binary::from_owned(ob3, env).encode(env),
        )
            .encode(env))
    }));
    match __res { Ok(inner) => inner, Err(_) => Err(Error::BadArg) }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn contract_view<'a>(
    env: Env<'a>,
    db: ResourceArc<DbResource>,
    entry_vecpak: Binary,
    view_pk: Binary,
    contract: Binary,
    function: Binary,
    fargs: Vec<Binary>,
    testnet: bool,
) -> Result<Term<'a>, Error> {
    let __res: std::thread::Result<Result<Term<'a>, Error>> = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
    let entry = crate::model::entry::from_bytes(entry_vecpak.as_slice()).map_err(|_| Error::BadArg)?;

    let (success, result, logs) = consensus::consensus_apply::contract_view(
        &db.db,
        entry,
        view_pk.as_slice().to_vec(),
        contract.as_slice().to_vec(),
        function.as_slice().to_vec(),
        fargs.iter().map(|bin| bin.as_slice().to_vec()).collect(),
        testnet,
    );

    let mut ob_result = OwnedBinary::new(result.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
    ob_result.as_mut_slice().copy_from_slice(&result);

    let mut logs_list = Vec::new();
    for l in logs {
        let mut ob_log = OwnedBinary::new(l.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
        ob_log.as_mut_slice().copy_from_slice(&l);
        logs_list.push(Binary::from_owned(ob_log, env))
    }

    Ok((success, Binary::from_owned(ob_result, env), logs_list).encode(env))
    }));
    match __res { Ok(inner) => inner, Err(_) => Err(Error::BadArg) }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn contract_validate<'a>(env: Env<'a>, db: ResourceArc<DbResource>, entry_vecpak: Binary, wasmbytes: Binary, testnet: bool) -> Result<Term<'a>, Error> {
    let __res: std::thread::Result<Result<Term<'a>, Error>> = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
    let entry = crate::model::entry::from_bytes(entry_vecpak.as_slice()).map_err(|_| Error::BadArg)?;

    let (result, logs) = consensus::consensus_apply::contract_validate(&db.db, entry, wasmbytes.as_slice(), testnet);

    let mut ob_result = OwnedBinary::new(result.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
    ob_result.as_mut_slice().copy_from_slice(&result);

    let mut logs_list = Vec::new();
    for l in logs {
        let mut ob_log = OwnedBinary::new(l.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
        ob_log.as_mut_slice().copy_from_slice(&l);
        logs_list.push(Binary::from_owned(ob_log, env))
    }

    Ok((Binary::from_owned(ob_result, env), logs_list).encode(env))
    }));
    match __res { Ok(inner) => inner, Err(_) => Err(Error::BadArg) }
}

#[rustler::nif]
fn vecpak_encode<'a>(env: Env<'a>, map: Term<'a>) -> Result<Term<'a>, Error> {
    let mut buf = Vec::with_capacity(1024);
    vecpak_ex::encode_term(env, &mut buf, map)?;

    let mut ob = OwnedBinary::new(buf.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
    ob.as_mut_slice().copy_from_slice(&buf);

    Ok(Binary::from_owned(ob, env).encode(env))
}

#[rustler::nif]
fn vecpak_decode<'a>(env: Env<'a>, bin: Binary) -> Result<Term<'a>, Error> {
    let term = vecpak_ex::decode_term_from_slice(env, bin.as_slice())?;
    Ok(term.encode(env))
}

#[rustler::nif(schedule = "DirtyCpu")]
fn freivalds(tensor: Binary, vr_b3: Binary) -> bool {
    crate::consensus::bic::sol_freivalds::freivalds(tensor.as_slice(), vr_b3.as_slice())
}

/// UPOW2 computer. Computes up to `iterations` nonce attempts (each a real 16x50240
/// * 50240x16 matmul), split across `threads` workers (min 1), and returns the first
/// 1264-byte sol whose Blake3 hash has at least `diff_bits` leading zero bits (the
/// network difficulty), or nil. DirtyCpu.
#[rustler::nif(schedule = "DirtyCpu")]
fn compute_upow<'a>(
    env: Env<'a>,
    epoch: u64,
    segment_vr_hash: Binary,
    trainer: Binary,
    pop: Binary,
    computor: Binary,
    diff_bits: u64,
    iterations: u64,
    threads: u64,
) -> NifResult<Term<'a>> {
    use crate::upow;
    if segment_vr_hash.len() != 32 || trainer.len() != 48 || pop.len() != 96 || computor.len() != 48 {
        return Err(Error::BadArg);
    }

    // Build the 240-byte seed template; nonce bytes [228..240] are filled per attempt.
    let mut seed = [0u8; upow::PREAMBLE];
    seed[0..4].copy_from_slice(&(epoch as u32).to_le_bytes());
    seed[4..36].copy_from_slice(segment_vr_hash.as_slice());
    seed[36..84].copy_from_slice(trainer.as_slice());
    seed[84..180].copy_from_slice(pop.as_slice());
    seed[180..228].copy_from_slice(computor.as_slice());

    let nthreads = (threads as usize).max(1);
    let rng_seeds: Vec<u64> = (0..nthreads).map(|_| rand::random::<u64>()).collect();

    let found = std::panic::catch_unwind(|| upow::compute(&seed, diff_bits as u32, iterations, nthreads, &rng_seeds)).unwrap_or(None);

    match found {
        Some(sol) => {
            let mut ob = OwnedBinary::new(sol.len()).ok_or_else(|| Error::Term(Box::new("alloc failed")))?;
            ob.as_mut_slice().copy_from_slice(&sol);
            Ok((atoms::ok(), Binary::from_owned(ob, env)).encode(env))
        }
        None => Ok(atoms::nil().encode(env)),
    }
}

#[rustler::nif]
fn bintree_root<'a>(env: Env<'a>, proplist: Vec<(Option<Binary<'a>>, Binary<'a>, Binary<'a>)>) -> Term<'a> {
    let mut ops = Vec::with_capacity(100);
    for (ns, k_bin, v_bin) in &proplist {
        let ns_vec: Option<Vec<u8>> = ns.map(|b| b.to_vec());
        ops.push(bintree::Op::Insert(ns_vec, k_bin.to_vec(), v_bin.to_vec()));
    }

    let mut hubt = bintree::Hubt::new();
    hubt.batch_update(ops);
    let root = hubt.root();

    let mut ob = match OwnedBinary::new(root.len()) {
        Some(b) => b,
        None => return atoms::error().encode(env),
    };
    ob.as_mut_slice().copy_from_slice(&root);
    Binary::from_owned(ob, env).encode(env)
}

#[rustler::nif]
fn hbsmt_root<'a>(env: Env<'a>, proplist: Vec<(Option<Binary<'a>>, Binary<'a>, Binary<'a>)>) -> Term<'a> {
    let mut ops = Vec::with_capacity(100);
    for (ns, k_bin, v_bin) in &proplist {
        let ns_vec: Option<Vec<u8>> = ns.map(|b| b.to_vec());
        ops.push(bintree::Op::Insert(ns_vec, k_bin.to_vec(), v_bin.to_vec()));
    }

    let mut t = crate::consensus::hbsmt::Hbsmt::new();
    t.batch_update(ops);
    let root = t.root();

    let mut ob = match OwnedBinary::new(root.len()) {
        Some(b) => b,
        None => return atoms::error().encode(env),
    };
    ob.as_mut_slice().copy_from_slice(&root);
    Binary::from_owned(ob, env).encode(env)
}

// Helper to convert &[u8] -> Elixir Binary (<<...>>)
fn to_binary2<'a>(env: Env<'a>, data: &[u8]) -> Binary<'a> {
    let mut binary = OwnedBinary::new(data.len()).unwrap();
    binary.as_mut_slice().copy_from_slice(data);
    binary.release(env)
}

#[rustler::nif]
fn bintree_root_prove<'a>(env: Env<'a>, proplist: Vec<(Option<Binary<'a>>, Binary<'a>, Binary<'a>)>, ns: Option<Binary<'a>>, key: Binary<'a>) -> Term<'a> {
    let mut ops = Vec::with_capacity(100);
    for (ns, k_bin, v_bin) in &proplist {
        let ns_vec: Option<Vec<u8>> = ns.map(|b| b.to_vec());
        ops.push(bintree::Op::Insert(ns_vec, k_bin.to_vec(), v_bin.to_vec()));
    }

    let mut hubt = bintree::Hubt::new();
    hubt.batch_update(ops);
    let ns_vec: Option<Vec<u8>> = ns.map(|b| b.to_vec());
    let proof = hubt.prove(ns_vec, key.to_vec());

    let nodes_list: Vec<Term> = proof
        .nodes
        .iter()
        .map(|node| {
            let mut map = Term::map_new(env);

            let hash_term = to_binary2(env, &node.hash);
            let dir_term = node.direction.encode(env);
            let len_term = node.len.encode(env);

            map = map.map_put(atoms::hash(), hash_term).ok().unwrap();
            map = map.map_put(atoms::direction(), dir_term).ok().unwrap();
            map = map.map_put(atoms::len(), len_term).ok().unwrap();
            map
        })
        .collect();

    let mut proof_map = Term::map_new(env);

    let root_term = to_binary2(env, &proof.root);
    let path_term = to_binary2(env, &proof.path);
    let hash_term = to_binary2(env, &proof.hash);

    proof_map = proof_map.map_put(atoms::root(), root_term).ok().unwrap();
    proof_map = proof_map.map_put(atoms::path(), path_term).ok().unwrap();
    proof_map = proof_map.map_put(atoms::hash(), hash_term).ok().unwrap();
    proof_map = proof_map.map_put(atoms::nodes(), nodes_list.encode(env)).ok().unwrap();

    (proof_map).encode(env)
}

fn term_to_fixed_array(term: Term) -> Result<[u8; 32], Error> {
    // 1. Decode term to a Binary view (zero-copy wrapper)
    let binary: Binary = term.decode()?;

    // 2. Check length strictly
    if binary.len() != 32 {
        return Err(Error::BadArg);
    }

    // 3. Copy bytes to fixed array
    let mut array = [0u8; 32];
    array.copy_from_slice(binary.as_slice());
    Ok(array)
}

fn term_to_proof(term: Term) -> Result<bintree::Proof, Error> {
    // 1. Extract Top-Level Fields
    let root_term = term.map_get(atoms::root())?;
    let path_term = term.map_get(atoms::path())?;
    let hash_term = term.map_get(atoms::hash())?;
    let nodes_term = term.map_get(atoms::nodes())?;

    // 2. Convert Top-Level Binaries
    let root = term_to_fixed_array(root_term)?;
    let path = term_to_fixed_array(path_term)?;
    let hash = term_to_fixed_array(hash_term)?;

    // 3. Decode List of Maps -> Vec<ProofNode>
    let nodes_list: Vec<Term> = nodes_term.decode()?;

    let nodes: Result<Vec<bintree::ProofNode>, Error> = nodes_list
        .into_iter()
        .map(|node_term| {
            // Extract fields from the inner map
            let n_hash_term = node_term.map_get(atoms::hash())?;
            let n_dir_term = node_term.map_get(atoms::direction())?;
            let n_len_term = node_term.map_get(atoms::len())?;

            Ok(bintree::ProofNode { hash: term_to_fixed_array(n_hash_term)?, direction: n_dir_term.decode::<u8>()?, len: n_len_term.decode::<u16>()? })
        })
        .collect();

    // 4. Construct the final struct
    Ok(bintree::Proof {
        root,
        nodes: nodes?, // Unwraps the Result from the iterator
        path,
        hash,
    })
}

#[rustler::nif]
fn bintree_root_verify<'a>(env: Env<'a>, expected_root: Binary<'a>, proof_ex: Term<'a>, ns: Option<Binary<'a>>, key: Binary<'a>, value: Binary<'a>) -> Term<'a> {
    let proof = term_to_proof(proof_ex).unwrap();
    let ns_vec: Option<Vec<u8>> = ns.map(|b| b.to_vec());
    let expected_root_arr: bintree::Hash = match expected_root.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => return (atoms::invalid()).encode(env),
    };
    let result = bintree::Hubt::verify(&expected_root_arr, &proof, ns_vec, key.to_vec(), value.to_vec());
    match result {
        bintree::VerifyStatus::Invalid => (atoms::invalid()).encode(env),
        bintree::VerifyStatus::Included => (atoms::included()).encode(env),
        bintree::VerifyStatus::Mismatch => (atoms::mismatch()).encode(env),
        bintree::VerifyStatus::NonExistence => (atoms::nonexistance()).encode(env),
    }
}

//rocksdb proof
#[rustler::nif(schedule = "DirtyIo")]
fn bintree_contractstate_root_prove<'a>(env: Env<'a>, db: ResourceArc<DbResource>, ns: Option<Binary<'a>>, key: Binary<'a>) -> Term<'a> {
    let cf_handle = db.db.cf_handle("contractstate_tree").unwrap();
    let mut iter = db.db.raw_iterator_cf(&cf_handle);

    //let namespace_data = consensus_kv::contractstate_namespace(&key);
    //let namespace = namespace_data.as_deref();
    let ns_vec: Option<Vec<u8>> = ns.map(|b| b.to_vec());
    let proof = crate::consensus::bintree_rdb_prove::RocksHubtProveViaIterator::prove(&mut iter, ns_vec, key.as_slice());

    let nodes_list: Vec<Term> = proof
        .nodes
        .iter()
        .map(|node| {
            let mut map = Term::map_new(env);

            let hash_term = to_binary2(env, &node.hash);
            let dir_term = node.direction.encode(env);

            map = map.map_put(atoms::hash(), hash_term).ok().unwrap();
            map = map.map_put(atoms::direction(), dir_term).ok().unwrap();
            map
        })
        .collect();

    let mut proof_map = Term::map_new(env);

    let root_term = to_binary2(env, &proof.root);
    let path_term = to_binary2(env, &proof.path);
    let hash_term = to_binary2(env, &proof.hash);

    proof_map = proof_map.map_put(atoms::root(), root_term).ok().unwrap();
    proof_map = proof_map.map_put(atoms::path(), path_term).ok().unwrap();
    proof_map = proof_map.map_put(atoms::hash(), hash_term).ok().unwrap();
    proof_map = proof_map.map_put(atoms::nodes(), nodes_list.encode(env)).ok().unwrap();

    (proof_map).encode(env)
}
/*
#[rustler::nif(schedule = "DirtyCpu")]
fn contract_view<'a>(env: Env<'a>, db: ResourceArc<DbResource>, cur_entry_trimmed_map: Term<'a>, as_pk: Binary,
    contract: Binary, function: Binary, args: Vec<Binary>) -> Result<Term<'a>, Error> {
    let entry_signer = fixed::<48>(next_entry_trimmed_map.map_get(atoms::entry_signer())?)?;
    let entry_prev_hash = fixed::<32>(next_entry_trimmed_map.map_get(atoms::entry_prev_hash())?)?;
    let entry_vr = fixed::<96>(next_entry_trimmed_map.map_get(atoms::entry_vr())?)?;
    let entry_vr_b3 = fixed::<32>(next_entry_trimmed_map.map_get(atoms::entry_vr_b3())?)?;
    let entry_dr = fixed::<32>(next_entry_trimmed_map.map_get(atoms::entry_dr())?)?;

    let entry_slot = next_entry_trimmed_map.map_get(atoms::entry_slot())?.decode::<u64>()?;
    let entry_prev_slot = next_entry_trimmed_map.map_get(atoms::entry_prev_slot())?.decode::<u64>()?;
    let entry_height = next_entry_trimmed_map.map_get(atoms::entry_height())?.decode::<u64>()?;
    let entry_epoch = next_entry_trimmed_map.map_get(atoms::entry_epoch())?.decode::<u64>()?;

    let txn_opts = TransactionOptions::default();
    let write_opts = WriteOptions::default();
    let txn = db.db.transaction_opt(&write_opts, &txn_opts);

    let (txn, muts, muts_rev, result_log, root_receipts, root_contractstate) =
        consensus::consensus_apply::apply_entry(&db.db, pk.as_slice(), sk.as_slice(), &entry_signer, &entry_prev_hash,
            entry_slot, entry_prev_slot, entry_height, entry_epoch, &entry_vr, &entry_vr_b3, &entry_dr, txus, txn,
            testnet, testnet_peddlebikes.iter().map(|bin| bin.as_slice().to_vec()).collect()
        );

    let tx_static: Tx<'static> = unsafe { std::mem::transmute::<Tx<'_>, Tx<'static>>(txn) };
    let term_txn = ResourceArc::new(TxResource {
        _db: db,
        tx: Mutex::new(Some(tx_static)),
    }).encode(env);

    let mut ob1 = OwnedBinary::new(root_receipts.len()).ok_or_else(|| Error::Term(Box::new("alloc failed"))).unwrap();
    ob1.as_mut_slice().copy_from_slice(&root_receipts);
    let mut ob2 = OwnedBinary::new(root_contractstate.len()).ok_or_else(|| Error::Term(Box::new("alloc failed"))).unwrap();
    ob2.as_mut_slice().copy_from_slice(&root_contractstate);


    Ok((term_txn, consensus_muts::mutations_to_map(muts), consensus_muts::mutations_to_map(muts_rev), result_log,
        Binary::from_owned(ob1, env).encode(env), Binary::from_owned(ob2, env).encode(env)).encode(env))
}
*/
#[rustler::nif]
fn protocol_constants<'a>(env: Env<'a>) -> Term<'a> {
    let mut map = Term::map_new(env);

    map = map.map_put(atoms::forkheight(), protocol::FORKHEIGHT).ok().unwrap();

    map = map.map_put(atoms::ama_1_dollar(), protocol::AMA_1_DOLLAR).ok().unwrap();
    map = map.map_put(atoms::ama_10_cent(), protocol::AMA_10_CENT).ok().unwrap();
    map = map.map_put(atoms::ama_1_cent(), protocol::AMA_1_CENT).ok().unwrap();

    map = map.map_put(atoms::reserve_ama_per_tx_exec(), protocol::RESERVE_AMA_PER_TX_EXEC).ok().unwrap();
    map = map.map_put(atoms::reserve_ama_per_tx_storage(), protocol::RESERVE_AMA_PER_TX_STORAGE).ok().unwrap();

    map = map.map_put(atoms::cost_per_byte_historical(), protocol::COST_PER_BYTE_HISTORICAL).ok().unwrap();
    map = map.map_put(atoms::cost_per_byte_state(), protocol::COST_PER_BYTE_STATE).ok().unwrap();
    map = map.map_put(atoms::cost_per_op_wasm(), protocol::COST_PER_OP_WASM).ok().unwrap();

    map = map.map_put(atoms::cost_per_db_read_base(), protocol::COST_PER_DB_READ_BASE).ok().unwrap();
    map = map.map_put(atoms::cost_per_db_read_byte(), protocol::COST_PER_DB_READ_BYTE).ok().unwrap();
    map = map.map_put(atoms::cost_per_db_write_base(), protocol::COST_PER_DB_WRITE_BASE).ok().unwrap();
    map = map.map_put(atoms::cost_per_db_write_byte(), protocol::COST_PER_DB_WRITE_BYTE).ok().unwrap();

    map = map.map_put(atoms::cost_per_sol(), protocol::COST_PER_SOL).ok().unwrap();
    map = map.map_put(atoms::cost_per_new_leaf_merkle(), protocol::COST_PER_NEW_LEAF_MERKLE).ok().unwrap();

    (map).encode(env)
}

#[rustler::nif]
fn protocol_epoch_emission<'a>(env: Env<'a>, epoch: u64) -> i128 {
    crate::consensus::bic::epoch::epoch_emission(epoch)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn protocol_circulating_without_burn<'a>(env: Env<'a>, epoch: u64) -> i128 {
    crate::consensus::bic::epoch::circulating_without_burn(epoch)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn build_tx_hashfilter<'a>(env: Env<'a>, signer: Binary<'a>, arg0: Binary<'a>, contract: Binary<'a>, function: Binary<'a>) -> Binary<'a> {
    let key = tx_filter::create_filter_key(&[&signer, &arg0, &contract, &function]);
    to_binary2(env, &key)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn build_tx_hashfilters<'a>(env: Env<'a>, txus: Vec<Term<'a>>) -> NifResult<Vec<(Binary<'a>, Binary<'a>)>> {
    tx_filter::build_tx_hashfilters(env, txus)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn query_tx_hashfilter<'a>(
    env: Env<'a>,
    db: ResourceArc<DbResource>,
    signer: Binary<'a>,
    arg0: Binary<'a>,
    contract: Binary<'a>,
    function: Binary<'a>,
    limit: u32,
    sort: bool,
    cursor: Option<Binary<'a>>,
) -> NifResult<(Option<Binary<'a>>, Vec<Binary<'a>>)> {
    if limit > 100_000 {
        return Err(Error::BadArg);
    }
    for b in [&signer, &arg0, &contract, &function] {
        if b.as_slice().len() > 4096 {
            return Err(Error::BadArg);
        }
    }
    tx_filter::query_tx_hashfilter(env, &db.db, &signer, &arg0, &contract, &function, limit as usize, sort, cursor.map(|b| b.as_slice()))
}

rustler::init!("Elixir.RDB", load = on_load);
