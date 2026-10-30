#![cfg(test)]

use crate::consensus::consensus_apply::make_apply_env;
use crate::consensus::hbsmt::Hbsmt;
use crate::consensus::hbsmt_common::Op;
use crate::consensus::hbsmt_rdb::{hbsmt_batch_update_env_muts, hbsmt_root_env};
use crate::consensus::tests::chain_harness::Chain;

struct Lcg(u64);
impl Lcg {
    fn below(&mut self, n: u64) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

fn op(rng: &mut Lcg) -> Op {
    let ns = match rng.below(3) {
        0 => None,
        1 => Some(b"bic".to_vec()),
        _ => Some(vec![rng.below(4) as u8; 56]),
    };
    let key = vec![rng.below(40) as u8, rng.below(3) as u8];
    if rng.below(10) < 4 { Op::Delete(ns, key) } else { Op::Insert(ns, key, vec![rng.below(256) as u8; 1 + rng.below(40) as usize]) }
}

fn run(seed: u64) {
    let chain = Chain::new();
    let mut reference = Hbsmt::new();
    let mut rng = Lcg(seed);
    let tree = || chain.db.cf_handle("contractstate_tree_hbsmt").unwrap();
    for batch in 0..60 {
        let ops: Vec<Op> = (0..1 + rng.below(30)).map(|_| op(&mut rng)).collect();
        reference.batch_update(ops.clone());
        let mut env = make_apply_env(
            chain.db, chain.db.transaction(), tree(), b"contractstate_tree_hbsmt".to_vec(), chain.db.cf_handle("contractstate").unwrap(), tree(),
            &[0u8; 48], &[0u8; 32], 1, 0, 1, 0, &[0u8; 96], &[0u8; 32], &[0u8; 32], false,
        );
        hbsmt_batch_update_env_muts(&mut env, "contractstate_tree_hbsmt", ops);
        let root = hbsmt_root_env(&mut env, "contractstate_tree_hbsmt");
        env.txn.commit().unwrap();
        assert_eq!(root, reference.root(), "seed {} batch {}", seed, batch);
    }
}

#[test]
fn tree_updates_match_the_in_memory_reference() {
    for seed in 0..40 {
        run(seed);
    }
}

#[test]
fn repeated_tree_updates_in_one_transaction_match_the_reference() {
    for seed in 100..130 {
        let chain = Chain::new();
        let mut reference = Hbsmt::new();
        let mut rng = Lcg(seed);
        let tree = || chain.db.cf_handle("contractstate_tree_hbsmt").unwrap();
        for batch in 0..20 {
            let mut env = make_apply_env(
                chain.db, chain.db.transaction(), tree(), b"contractstate_tree_hbsmt".to_vec(), chain.db.cf_handle("contractstate").unwrap(), tree(),
                &[0u8; 48], &[0u8; 32], 1, 0, 1, 0, &[0u8; 96], &[0u8; 32], &[0u8; 32], false,
            );
            for _ in 0..3 {
                let ops: Vec<Op> = (0..1 + rng.below(20)).map(|_| op(&mut rng)).collect();
                reference.batch_update(ops.clone());
                hbsmt_batch_update_env_muts(&mut env, "contractstate_tree_hbsmt", ops);
                assert_eq!(hbsmt_root_env(&mut env, "contractstate_tree_hbsmt"), reference.root(), "seed {} batch {}", seed, batch);
            }
            env.txn.commit().unwrap();
        }
    }
}
