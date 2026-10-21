use super::chain_harness::{new_wallet, Chain, Wallet};
use crate::consensus::{aggsig::DST_MOTION, bic::epoch, bls12_381, validator_set::{valid_mask, ValidatorSet}};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn key(height: u64) -> Vec<u8> {
    format!("bic:epoch:validators:height:{:012}", height).into_bytes()
}

fn motion(wallets: &[Wallet], target: usize, epoch: u64, signed: &[usize]) -> Vec<Vec<u8>> {
    let mut msg = b"slash_trainer".to_vec();
    msg.extend_from_slice(&(epoch as u32).to_le_bytes());
    msg.extend_from_slice(&wallets[target].pk);
    let sigs: Vec<_> = signed.iter().map(|i| bls12_381::sign(&wallets[*i].sk, &msg, DST_MOTION).unwrap()).collect();
    let sig = bls12_381::aggregate_signatures(sigs).unwrap();
    let mut mask = vec![0; wallets.len().div_ceil(8)];
    for i in signed { mask[i / 8] |= 1 << (7 - i % 8); }
    vec![wallets[target].pk.to_vec(), epoch.to_string().into_bytes(), sig.to_vec(), wallets.len().to_string().into_bytes(), mask]
}

#[test]
fn validator_set_scales_and_preserves_slots_and_canonical_padding() {
    let roster: Vec<_> = (0u32..1001).map(|i| i.to_le_bytes().repeat(12)).collect();
    let mut set = ValidatorSet::new(roster.clone());
    assert_eq!(set.mask_active.len(), 126);
    assert_eq!(set.mask_active[125], 128);
    for i in [0, 255, 256, 999] { set.remove(&roster[i]).unwrap(); }
    assert_eq!(set.validators, roster);
    assert_eq!(set.active().len(), 997);
    assert_eq!(set.signers(&set.mask_active, 1001).unwrap().last(), Some(&roster[1000].as_slice()));
    assert_eq!(ValidatorSet::decode(&set.encode()), set);
    assert!(!valid_mask(&[255], 3));
    assert!(!valid_mask(&[224, 0], 3));
    assert!(valid_mask(&[], 0));
    let mut removed_vote = set.mask_active.clone();
    removed_vote[32] |= 128;
    assert_eq!(set.signers(&removed_vote, 1001), Err("inactive_signer"));
    assert_eq!(set.signers(&set.mask_active, 997), Err("invalid_mask_size"));
    let mut bad_padding = set.mask_active.clone();
    bad_padding[125] |= 1;
    assert_eq!(set.signers(&bad_padding, 1001), Err("invalid_mask_size"));
}

#[test]
fn validator_set_slashes_accumulate_and_take_effect_at_next_height() {
    let mut chain = Chain::new();
    let wallets: Vec<_> = (0..5).map(|_| new_wallet()).collect();
    let roster: Vec<_> = wallets.iter().map(|w| w.pk.to_vec()).collect();
    chain.put(&key(0), &crate::consensus::bic::list_of_binaries_to_vecpak(roster.clone()));
    chain.with_env(&wallets[0].pk, |env| {
        epoch::call_slash_trainer(env, motion(&wallets, 1, 0, &[0, 2, 3, 4]));
        epoch::call_slash_trainer(env, motion(&wallets, 2, 0, &[0, 1, 3, 4]));
        assert_eq!(epoch::kv_get_trainers(env, 0), roster);
        let next = epoch::kv_get_validator_set(env, 1);
        assert_eq!(next.validators, roster);
        assert_eq!(next.mask_active, vec![0b10011000]);
        assert_eq!(epoch::kv_get_trainers_removed(env), vec![roster[1].clone(), roster[2].clone()]);
    });
    chain.height = 1;
    let before = chain.state_digest();
    // Two of the three remaining validators are less than AMA's 67% threshold.
    assert!(catch_unwind(AssertUnwindSafe(|| chain.with_env(&wallets[0].pk, |env| {
        epoch::call_slash_trainer(env, motion(&wallets, 4, 0, &[0, 3]));
    }))).is_err());
    assert_eq!(chain.state_digest(), before);
    // A removed key cannot vote, even though it still occupies its old slot.
    assert!(catch_unwind(AssertUnwindSafe(|| chain.with_env(&wallets[0].pk, |env| {
        epoch::call_slash_trainer(env, motion(&wallets, 4, 0, &[0, 1, 3, 4]));
    }))).is_err());
    assert_eq!(chain.state_digest(), before);
    chain.with_env(&wallets[0].pk, |env| {
        epoch::call_slash_trainer(env, motion(&wallets, 4, 0, &[0, 3, 4]));
        let set = epoch::kv_get_validator_set(env, 2);
        assert_eq!(set.validators, roster);
        assert_eq!(set.mask_active, vec![0b10010000]);
        assert_eq!(epoch::kv_get_trainers(env, 1).len(), 3);
    });
}

#[test]
fn validator_set_legacy_list_record_seeds_roster() {
    // epoch 877 opened on a list record written before the fork: it reads as an
    // all-active roster, and a slash on top of it writes roster + mask
    let mut chain = Chain::new();
    chain.height = 87_700_000;
    let wallets: Vec<_> = (0..4).map(|_| new_wallet()).collect();
    let roster: Vec<_> = wallets.iter().map(|w| w.pk.to_vec()).collect();
    chain.put(&key(0), &crate::consensus::bic::list_of_binaries_to_vecpak(roster.clone()));
    chain.with_env(&wallets[0].pk, |env| {
        env.testnet = false;
        epoch::call_slash_trainer(env, motion(&wallets, 1, 87_700_000 / 100_000, &[0, 2, 3]));
    });
    let set = ValidatorSet::decode(&chain.get(&key(87_700_000 + 1)).unwrap());
    assert_eq!(set.validators, roster);
    assert_eq!(set.mask_active, vec![176]);
}

#[test]
fn validator_set_epoch_boundary_resets_roster_after_accounting_for_removals() {
    let mut chain = Chain::new();
    let wallets: Vec<_> = (0..4).map(|_| new_wallet()).collect();
    let roster: Vec<_> = wallets.iter().map(|w| w.pk.to_vec()).collect();
    chain.put(&key(0), &crate::consensus::bic::list_of_binaries_to_vecpak(roster.clone()));
    for pk in &roster {
        chain.put(&[b"bic:epoch:solutions_count:".as_slice(), pk].concat(), b"1");
    }
    chain.put(b"bic:epoch:diff_bits", b"24");
    chain.height = 99_999;
    chain.with_env(&wallets[0].pk, |env| {
        epoch::call_slash_trainer(env, motion(&wallets, 1, 0, &[0, 2, 3]));
        epoch::next(env);
        let next = epoch::kv_get_validator_set(env, 100_000);
        assert_eq!(next.validators.len(), 3);
        assert!(!next.validators.contains(&roster[1]));
        assert_eq!(next.mask_active, vec![224]);
        assert_eq!(epoch::kv_get_trainers(env, 99_999), roster);
    });
}
