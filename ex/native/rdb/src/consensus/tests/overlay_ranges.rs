//! Range reads (kv_get_next / kv_get_prev / kv_get_prev_or_first) over the
//! contractstate overlay must match a plain sorted map of the same state, with
//! writes spread across rocksdb, the block layer and the tx layer.

#![cfg(test)]

use crate::consensus::bic::protocol::{COST_PER_DB_READ_BASE, COST_PER_DB_READ_BYTE};
use crate::consensus::consensus_apply::make_apply_env;
use crate::consensus::consensus_kv::{kv_delete, kv_get, kv_get_next, kv_get_prev, kv_get_prev_or_first, kv_put, overlay_commit_tx, overlay_discard_tx};
use crate::consensus::tests::chain_harness::Chain;
use std::collections::BTreeMap;

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

//nested and 0xff-edged prefixes; suffixes of 0..=2 bytes, so a key can equal its prefix
const PREFIXES: [&[u8]; 7] = [b"", b"a", b"a:", b"a:b", b"b:", b"\xff", b"\xff\xff"];
const BYTES: [u8; 5] = [0x00, 0x01, b'b', 0xfe, 0xff];

fn suffix(rng: &mut Lcg) -> Vec<u8> {
    (0..rng.below(3)).map(|_| BYTES[rng.below(BYTES.len() as u64) as usize]).collect()
}

fn prefix(rng: &mut Lcg) -> &'static [u8] {
    PREFIXES[rng.below(PREFIXES.len() as u64) as usize]
}

fn key(rng: &mut Lcg) -> Vec<u8> {
    let k = [prefix(rng), &suffix(rng)].concat();
    if k.is_empty() { vec![0x00] } else { k }
}

fn read_cost(seek_len: usize, value: Option<&Vec<u8>>) -> i128 {
    COST_PER_DB_READ_BASE + COST_PER_DB_READ_BYTE * seek_len as i128 + value.map_or(0, |v| COST_PER_DB_READ_BYTE * v.len() as i128)
}

fn model_next(m: &BTreeMap<Vec<u8>, Vec<u8>>, prefix: &[u8], seek: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let s = [prefix, seek].concat();
    m.range(s.clone()..).find(|(k, _)| **k != s).filter(|(k, _)| k.starts_with(prefix)).map(|(k, v)| (k[prefix.len()..].to_vec(), v.clone()))
}

fn model_prev(m: &BTreeMap<Vec<u8>, Vec<u8>>, prefix: &[u8], seek: &[u8], inclusive: bool) -> Option<(Vec<u8>, Vec<u8>)> {
    let s = [prefix, seek].concat();
    m.range(..=s.clone()).rev().find(|(k, _)| inclusive || **k != s).filter(|(k, _)| k.starts_with(prefix)).map(|(k, v)| (k[prefix.len()..].to_vec(), v.clone()))
}

fn run(seed: u64) {
    let chain = Chain::new();
    let mut rng = Lcg(seed);
    let mut committed: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for _ in 0..20 {
        let k = key(&mut rng);
        let v = vec![rng.below(256) as u8];
        chain.put(&k, &v);
        committed.insert(k, v);
    }

    let cf = || chain.db.cf_handle("contractstate").unwrap();
    let mut env = make_apply_env(
        chain.db, chain.db.transaction(), cf(), b"contractstate".to_vec(), cf(), chain.db.cf_handle("contractstate_tree_hbsmt").unwrap(),
        &[0u8; 48], &[0u8; 32], 1, 0, 1, 0, &[0u8; 96], &[0u8; 32], &[0u8; 32], false,
    );

    //block = committed state + kept tx layers; tx = the running tx layer on top
    env.exec_track = true;
    env.exec_left = i128::MAX / 4;
    env.storage_left = i128::MAX / 4;

    let mut block = committed.clone();
    let mut tx = block.clone();
    for step in 0..400 {
        match rng.below(10) {
            0..=3 => {
                let (k, v) = (key(&mut rng), vec![rng.below(256) as u8]);
                kv_put(&mut env, &k, &v);
                tx.insert(k, v);
            }
            4..=5 => {
                let k = key(&mut rng);
                kv_delete(&mut env, &k);
                tx.remove(&k);
            }
            6 => {
                overlay_commit_tx(&mut env);
                block = tx.clone();
            }
            7 => {
                overlay_discard_tx(&mut env);
                tx = block.clone();
            }
            _ => {}
        }

        let prefix = prefix(&mut rng);
        let seek = suffix(&mut rng);
        let probe = key(&mut rng);
        let seek_len = prefix.len() + seek.len();

        let before = env.exec_left;
        let want = tx.get(&probe).cloned();
        assert_eq!(kv_get(&mut env, &probe), want, "seed {} step {} get", seed, step);
        assert_eq!(before - env.exec_left, read_cost(probe.len(), want.as_ref()), "seed {} step {} get cost", seed, step);

        let checks: [(&str, Option<(Vec<u8>, Vec<u8>)>, fn(&mut crate::consensus::consensus_apply::ApplyEnv, &[u8], &[u8]) -> Option<(Vec<u8>, Vec<u8>)>); 3] = [
            ("next", model_next(&tx, prefix, &seek), kv_get_next),
            ("prev", model_prev(&tx, prefix, &seek, false), kv_get_prev),
            ("prev_or_first", model_prev(&tx, prefix, &seek, true), kv_get_prev_or_first),
        ];
        for (name, want, read) in checks {
            let before = env.exec_left;
            assert_eq!(read(&mut env, prefix, &seek), want, "seed {} step {} {}", seed, step, name);
            assert_eq!(before - env.exec_left, read_cost(seek_len, want.as_ref().map(|(_, v)| v)), "seed {} step {} {} cost", seed, step, name);
        }
    }

    //flushed into rocksdb, the committed state is exactly the model
    env.into_txn().commit().unwrap();
    let mut it = chain.db.raw_iterator_cf(&cf());
    it.seek_to_first();
    let mut db = BTreeMap::new();
    while it.valid() {
        db.insert(it.key().unwrap().to_vec(), it.value().unwrap().to_vec());
        it.next();
    }
    assert_eq!(db, tx, "seed {} flushed state", seed);
}

#[test]
fn overlay_range_reads_match_model() {
    for seed in 0..200 {
        run(seed);
    }
}
