#![cfg(test)]

use crate::consensus::consensus_apply::make_apply_env;
use crate::consensus::consensus_kv::{kv_get, kv_get_next, kv_get_prev, kv_get_prev_or_first, kv_increment, kv_put, kv_set_bit, overlay_commit_tx, overlay_discard_tx, overlay_apply, overlay_take_tx, Read};
use crate::consensus::tests::chain_harness::Chain;

fn env(chain: &Chain) -> crate::consensus::consensus_apply::ApplyEnv<'static> {
    let cf = || chain.db.cf_handle("contractstate").unwrap();
    make_apply_env(
        chain.db, chain.db.transaction(), cf(), b"contractstate".to_vec(), cf(), chain.db.cf_handle("contractstate_tree_hbsmt").unwrap(),
        &[0u8; 48], &[0u8; 32], 1, 0, 1, 0, &[0u8; 96], &[0u8; 32], &[0u8; 32], false,
    )
}

fn key(k: &[u8], v: Option<&[u8]>) -> Read {
    Read::Key { key: k.to_vec(), value: v.map(|v| v.to_vec()) }
}

#[test]
fn point_reads_record_what_was_seen_but_not_own_writes() {
    let chain = Chain::new();
    chain.put(b"a", b"1");
    let mut env = env(&chain);

    assert_eq!(kv_get(&mut env, b"a"), Some(b"1".to_vec()));
    assert_eq!(kv_get(&mut env, b"missing"), None);
    kv_put(&mut env, b"b", b"x");
    assert_eq!(kv_get(&mut env, b"b"), Some(b"x".to_vec()));
    kv_increment(&mut env, b"n", 5);
    kv_increment(&mut env, b"n", 1);

    let (writes, _, reads) = overlay_take_tx(&mut env);
    assert_eq!(reads, vec![key(b"a", Some(b"1")), key(b"missing", None), key(b"b", None), key(b"n", None)]);
    assert_eq!(writes.get(b"n".as_slice()), Some(&Some(b"6".to_vec())));
}

#[test]
fn reads_served_by_the_block_layer_are_recorded() {
    let chain = Chain::new();
    let mut env = env(&chain);
    kv_put(&mut env, b"a", b"1");
    overlay_commit_tx(&mut env);

    assert_eq!(kv_get(&mut env, b"a"), Some(b"1".to_vec()));
    assert_eq!(overlay_take_tx(&mut env).2, vec![key(b"a", Some(b"1"))]);
}

#[test]
fn set_bit_records_the_bit_not_the_page() {
    let chain = Chain::new();
    let mut env = env(&chain);

    assert!(kv_set_bit(&mut env, b"page", 3));
    assert!(!kv_set_bit(&mut env, b"page", 3));
    overlay_commit_tx(&mut env);
    assert!(kv_set_bit(&mut env, b"page", 4));
    assert!(!kv_set_bit(&mut env, b"page", 3));

    let reads = overlay_take_tx(&mut env).2;
    assert_eq!(reads, vec![
        Read::Bit { key: b"page".to_vec(), bit: 4, exists: true, set: false },
        Read::Bit { key: b"page".to_vec(), bit: 3, exists: true, set: true },
    ]);
}

#[test]
fn every_bit_read_from_outside_is_recorded_even_on_a_page_the_tx_wrote() {
    let chain = Chain::new();
    chain.put(b"page", &vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize]);
    let mut env = env(&chain);

    assert!(kv_set_bit(&mut env, b"page", 1));
    assert!(kv_set_bit(&mut env, b"page", 2));
    assert!(!kv_set_bit(&mut env, b"page", 1));

    assert_eq!(overlay_take_tx(&mut env).2, vec![
        Read::Bit { key: b"page".to_vec(), bit: 1, exists: true, set: false },
        Read::Bit { key: b"page".to_vec(), bit: 2, exists: true, set: false },
    ]);
}

#[test]
fn bit_writes_merge_into_the_page_at_commit() {
    let chain = Chain::new();
    chain.put(b"page", &vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize]);
    let mut env = env(&chain);

    kv_set_bit(&mut env, b"page", 1);
    let (writes, bits, _) = overlay_take_tx(&mut env);
    assert!(writes.is_empty());
    kv_set_bit(&mut env, b"page", 2);
    overlay_commit_tx(&mut env);
    overlay_apply(&mut env, writes, bits);

    let page = env.overlay.block.get(b"page".as_slice()).cloned().flatten().unwrap();
    assert_eq!(page[0], 0b0110_0000);
}

#[test]
fn a_page_the_tx_put_whole_is_its_own() {
    let chain = Chain::new();
    let mut env = env(&chain);
    kv_put(&mut env, b"page", &vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize]);
    kv_set_bit(&mut env, b"page", 5);

    let (writes, bits, reads) = overlay_take_tx(&mut env);
    assert!(bits.is_empty());
    assert_eq!(writes.get(b"page".as_slice()).cloned().flatten().unwrap()[0], 0b0000_0100);
    assert_eq!(reads, vec![Read::Key { key: b"page".to_vec(), value: None }]);
}

#[test]
fn set_bit_on_a_new_page_records_absence() {
    let chain = Chain::new();
    let mut env = env(&chain);
    kv_set_bit(&mut env, b"page", 9);
    assert_eq!(overlay_take_tx(&mut env).2, vec![Read::Bit { key: b"page".to_vec(), bit: 9, exists: false, set: false }]);
}

#[test]
fn range_reads_record_seek_and_result() {
    let chain = Chain::new();
    chain.put(b"p:1", b"x");
    chain.put(b"p:3", b"y");
    let mut env = env(&chain);

    kv_get_next(&mut env, b"p:", b"1");
    kv_get_prev(&mut env, b"p:", b"3");
    kv_get_prev_or_first(&mut env, b"p:", b"3");
    kv_get_next(&mut env, b"p:", b"3");

    let found = |k: &[u8], v: &[u8]| Some((k.to_vec(), v.to_vec()));
    assert_eq!(overlay_take_tx(&mut env).2, vec![
        Read::Next { seek: b"p:1".to_vec(), found: found(b"p:3", b"y") },
        Read::Prev { seek: b"p:3".to_vec(), inclusive: false, found: found(b"p:1", b"x") },
        Read::Prev { seek: b"p:3".to_vec(), inclusive: true, found: found(b"p:3", b"y") },
        Read::Next { seek: b"p:3".to_vec(), found: None },
    ]);
}

#[test]
fn commit_and_discard_clear_recorded_reads() {
    let chain = Chain::new();
    let mut env = env(&chain);
    kv_get(&mut env, b"a");
    overlay_commit_tx(&mut env);
    kv_get(&mut env, b"b");
    overlay_discard_tx(&mut env);
    assert_eq!(overlay_take_tx(&mut env).2, vec![]);
}

#[test]
fn a_whole_read_of_a_bit_written_page_depends_on_the_outside_page() {
    let chain = Chain::new();
    let zero = vec![0u8; crate::consensus::bic::sol_bloom::PAGE_SIZE as usize];
    chain.put(b"page", &zero);
    let mut env = env(&chain);

    kv_set_bit(&mut env, b"page", 1);
    assert_eq!(kv_get(&mut env, b"page").unwrap()[0], 0b0100_0000);

    assert_eq!(overlay_take_tx(&mut env).2, vec![
        Read::Bit { key: b"page".to_vec(), bit: 1, exists: true, set: false },
        Read::Key { key: b"page".to_vec(), value: Some(zero) },
    ]);
}
