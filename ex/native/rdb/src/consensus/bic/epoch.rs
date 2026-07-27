use crate::consensus::aggsig::DST_MOTION;
use crate::{bcat, consensus};
use num_bigint::BigUint;
use std::collections::{BTreeMap, HashSet};
use std::panic::panic_any;

use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_delete, kv_exists, kv_get, kv_get_next, kv_get_prev_or_first, kv_increment, kv_put, kv_set_bit};

pub const EPOCH_EMISSION_BASE: i128 = 1_000_000_000_000_000;
pub const EPOCH_INTERVAL: i128 = 100_000;

pub const NETWORK_TAX_BPS: i128 = 2_500; //25%

pub const SOLVER_PARTICIPATION_TARGET: i128 = 100;

//from PARTICIPATION_FLOOR_EPOCH on, participation never drops below this floor, so a
//low/idle network still pays out at least this percentage
pub const SOLVER_PARTICIPATION_FLOOR: i128 = 10;
pub const PARTICIPATION_FLOOR_EPOCH: u64 = 758;

pub const PARTICIPATION_VAULT_EPOCH: u64 = 1150;

//per-epoch emission not disbursed carries over in these pools: the vault pool feeds
//back into future vault APY budgets (and funds the network tax); the solver pool
//just accumulates for now (disposition TBD).
pub const VAULT_ACCRUED_POOL_KEY: &[u8] = b"bic:epoch:vault_accrued_pool";
pub const SOLVER_ACCRUED_POOL_KEY: &[u8] = b"bic:epoch:solver_accrued_pool";

pub const TREASURY_DONATION_ADDRESS: &[u8; 48] = &[
    140, 71, 6, 83, 31, 185, 171, 240, 47, 5, 14, 246, 98, 23, 105, 24, 183, 118, 193, 92, 66, 82, 64, 5, 239, 255, 254, 87, 139, 252, 148, 176, 113, 6, 207,
    153, 51, 25, 202, 45, 48, 153, 223, 248, 219, 210, 80, 254,
];

pub fn epoch_emission(epoch: u64) -> i128 {
    epoch_emission_1(epoch, EPOCH_EMISSION_BASE)
}

fn epoch_emission_1(epoch: u64, acc: i128) -> i128 {
    if epoch == 0 {
        acc
    } else {
        let sub = acc.checked_mul(333).expect("i128_overflow") / 1_000_000;
        let emitted = acc.saturating_sub(sub);
        epoch_emission_1(epoch - 1, emitted)
    }
}

pub fn circulating_without_burn(epoch: u64) -> i128 {
    fn rec(n: u64, acc: i128) -> i128 {
        if n == 0 {
            acc
        } else {
            rec(n - 1, acc + epoch_emission_active(n))
        }
    }
    rec(epoch, 0)
}

//---- emission curve v2 (Shenron), active from EMISSION2_EPOCH ----
//the documented total per-epoch emission, 1,430,936,428 / (epoch - 20)^1.3,
//with the +72 offset anchoring the epoch 750 activation at the documented
//curve's epoch 842 value (~232.4k AMA). from EMISSION2_EPOCH on this replaces
//the legacy geometric decay as the per-epoch total; distribution is unchanged.
pub const EMISSION2_EPOCH: u64 = 750;
pub const EMISSION2_NUMERATOR: i128 = 1_430_936_428 * 1_000_000_000;
pub const EMISSION2_OFFSET: u64 = 72;

//x^1.3 computed exactly in integers as floor((x^13)^(1/10))
pub fn emission2_total(epoch: u64) -> i128 {
    let x = BigUint::from(epoch.saturating_add(EMISSION2_OFFSET));
    let denom = x.pow(13).nth_root(10);
    let total = BigUint::from(EMISSION2_NUMERATOR as u128) / denom;
    u128::try_from(total).map(|v| v.min(i128::MAX as u128) as i128).unwrap_or(i128::MAX)
}

//the per-epoch emission active at `epoch`: the v2 curve from EMISSION2_EPOCH
//on, the legacy decay before it. single source of truth for minting, supply
//accounting, and the emission API so the switch is uniform.
pub fn epoch_emission_active(epoch: u64) -> i128 {
    if epoch >= EMISSION2_EPOCH {
        emission2_total(epoch)
    } else {
        epoch_emission(epoch)
    }
}

#[cfg(test)]
mod emission2_curve_tests {
    use super::*;

    #[test]
    fn curve_activates_at_750_and_decays() {
        //the documented 1,430,936,428/(epoch-20)^1.3 total, anchored (+72) so the
        //epoch 750 activation emits the agreed ~232.4k AMA
        assert_eq!(emission2_total(750) / 1_000_000_000, 232_445);
        assert_eq!(emission2_total(1200) / 1_000_000_000, 131_762);
        //strictly decreasing after activation
        assert!(emission2_total(751) < emission2_total(750));
        assert!(emission2_total(5000) < emission2_total(1200));
        //the router switches exactly at EMISSION2_EPOCH, legacy curve before it
        assert_eq!(epoch_emission_active(749), epoch_emission(749));
        assert_eq!(epoch_emission_active(750), emission2_total(750));
    }
}

pub fn call_set_emission_address(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let address = args[0].as_slice();
    if address.len() != 48 {
        panic_any("invalid_address_pk")
    }

    kv_put(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":attribute:emission_address"]), address);
}

pub fn call_submit_sol(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let sol = args[0].as_slice();
    if sol.len() != consensus::bic::sol::SOL_SIZE {
        panic_any("invalid_sol_seed_size")
    }
    let sol: [u8; consensus::bic::sol::SOL_SIZE] = sol.try_into().unwrap();

    let hash = blake3::hash(&sol);
    let mut flips = 0;
    for seg in consensus::bic::sol_bloom::segs_from_digest(hash.as_bytes()) {
        let key = format!("bic:epoch:solbloom:{}", seg.page).into_bytes();
        if kv_set_bit(env, &key, seg.bit_offset) {
            flips += 1
        }
    }
    if flips == 0 {
        panic_any("sol_exists")
    }

    let usol = consensus::bic::sol::unpack(&sol);
    if env.caller_env.entry_epoch != usol.epoch {
        panic_any("invalid_epoch")
    }

    let segment_vr_hash = kv_get(env, b"bic:epoch:segment_vr_hash").unwrap();
    let diff_bits = kv_get(env, b"bic:epoch:diff_bits").unwrap();
    let diff_bits_int = std::str::from_utf8(&diff_bits).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_diff_bits"));
    if !env.preverified_sol_hashes.contains(hash.as_bytes())
        && !consensus::bic::sol::verify(&sol, hash.as_bytes(), &segment_vr_hash, &env.caller_env.entry_vr_b3, diff_bits_int).unwrap_or(false)
    {
        panic_any("invalid_sol");
    }

    if !kv_exists(env, &bcat(&[b"account:", &usol.pk, b":attribute:pop"])) {
        match consensus::bls12_381::verify(&usol.pk, &usol.pop, &usol.pk, consensus::aggsig::DST_POP) {
            Ok(()) => kv_put(env, &bcat(&[b"account:", &usol.pk, b":attribute:pop"]), &usol.pop),
            Err(_) => panic_any("invalid_pop"),
        }
    }
    kv_increment(env, &bcat(&[b"bic:epoch:solutions_count:", usol.pk.as_slice()]), 1);
}

pub fn kv_get_trainers(env: &mut crate::consensus::consensus_apply::ApplyEnv, height: u64) -> Vec<Vec<u8>> {
    let height_padded = format!("{:012}", height).into_bytes();
    match kv_get_prev_or_first(env, b"bic:epoch:validators:height:", &height_padded) {
        None => Vec::new(),
        Some((_key_suffix, trainer_list)) => {
            let term = vecpak::decode(trainer_list.as_slice()).unwrap();
            match term {
                vecpak::Term::List(term_list) => {
                    let mut out = Vec::with_capacity(100);
                    for el in term_list {
                        if let vecpak::Term::Binary(b) = el {
                            out.push(b);
                        } else {
                            panic_any("invalid_trainer_list_element");
                        }
                    }
                    out
                }
                _ => panic_any("invalid_trainer_list_term"),
            }
        }
    }
}

pub fn kv_get_trainers_removed(env: &mut crate::consensus::consensus_apply::ApplyEnv) -> Vec<Vec<u8>> {
    let trainers_start = kv_get_trainers(env, env.caller_env.entry_epoch * 100_000);
    let trainers_now = kv_get_trainers(env, env.caller_env.entry_height.saturating_add(1));

    let trainers_now_set: HashSet<Vec<u8>> = trainers_now.into_iter().collect();
    trainers_start.into_iter().filter(|t| !trainers_now_set.contains(t)).collect()
}

pub fn call_slash_trainer(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 5 {
        panic_any("invalid_args")
    }
    let malicious_pk = args[0].as_slice();
    let epoch = args[1].as_slice();
    let epoch = std::str::from_utf8(&epoch).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_epoch"));
    let signature = args[2].as_slice();
    let mask_size = args[3].as_slice();
    let mask_size = std::str::from_utf8(&mask_size).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_mask_size"));
    let mask = args[4].to_vec();

    if epoch != env.caller_env.entry_epoch {
        panic_any("invalid_epoch")
    }

    let mut trainers = kv_get_trainers(env, env.caller_env.entry_height);
    if !trainers.iter().any(|v| v.as_slice() == malicious_pk) {
        panic_any("invalid_trainer_pk")
    }

    let signers = consensus::aggsig::unmask_trainers(&trainers, &mask, mask_size as usize);
    if (signers.len() as u64) * 100 < (trainers.len() as u64) * 67 {
        panic_any("invalid_amount_of_signatures")
    }

    let apk = consensus::bls12_381::aggregate_public_keys(signers).unwrap_or_else(|_| panic_any("invalid_aggregation"));
    let msg = bcat(&[b"slash_trainer", (epoch as u32).to_le_bytes().as_slice(), malicious_pk]);
    let signature_valid = match consensus::bls12_381::verify(&apk, signature, msg.as_slice(), DST_MOTION) {
        Ok(()) => true,
        _ => false,
    };
    if !signature_valid {
        panic_any("invalid_signature")
    }

    trainers.retain(|pk| pk.as_slice() != malicious_pk);
    let term_trainers = consensus::bic::list_of_binaries_to_vecpak(trainers);
    let height_next = format!("{:012}", env.caller_env.entry_height.saturating_add(1)).into_bytes();
    kv_put(env, &bcat(&[b"bic:epoch:validators:height:", &height_next]), term_trainers.as_slice());
}

//  * queued vault validator changes post once, first thing (the only promotion site)
//  * emission split in half: vault APY vs solvers
//  * vault APY paid from (this half + carried pool); leftover carries on
//  * a 25% treasury tax on all payouts, FUNDED from the vault leftover (not minted
//    on top) so issuance stays within the curve
//  * emission curbed by participation (pflops): below SOLVER_PARTICIPATION_TARGET only
//    pflops% pays, the rest accrues. always applies to the solver half; applies to
//    vault APY too from PARTICIPATION_VAULT_EPOCH on
//  * validator set = every >=1m-stake vault validator + top 33 solvers
pub fn next(env: &mut ApplyEnv) {
    let epoch_cur = env.caller_env.entry_epoch;
    let epoch_next = env.caller_env.entry_epoch + 1;

    consensus::bic::lockup_vault::promote_pending_validators(env, epoch_next);

    let trainers = kv_get_trainers(env, env.caller_env.entry_height.saturating_add(1));
    let trainers_map: HashSet<Vec<u8>> = trainers.into_iter().collect();
    let trainers_removed = kv_get_trainers_removed(env);
    let trainers_removed_map: HashSet<Vec<u8>> = trainers_removed.into_iter().collect();

    //total_score_all sums EVERY sol submitter (matching the stats `score()` used by
    //pflops); leaders excludes slashed (removed) trainers.
    let mut leaders: Vec<(Vec<u8>, i128)> = Vec::new();
    let mut total_score_all: i128 = 0;
    let mut cursor: Vec<u8> = Vec::new();
    while let Some((pk, val)) = kv_get_next(env, b"bic:epoch:solutions_count:", &cursor) {
        let count = std::str::from_utf8(&val).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_solutions_count"));
        total_score_all = total_score_all.checked_add(count).unwrap_or_else(|| panic_any("invalid_solutions_count"));
        if !trainers_removed_map.contains(&pk) {
            leaders.push((pk.clone(), count));
        }
        cursor = pk;
    }
    // sort descending; highest sol count first; tiebreak on PK
    leaders.sort_unstable_by(|(ka, ca), (kb, cb)| match cb.cmp(ca) {
        std::cmp::Ordering::Equal => kb.cmp(ka),
        other => other,
    });

    //every sol-submitting solver in the set is eligible — no cap
    let solvers: Vec<(Vec<u8>, i128)> =
        leaders.iter().cloned().filter(|(pk, _)| trainers_map.contains(pk)).collect();
    let total_sols: i128 = solvers.iter().map(|(_, count)| count).sum();

    let epoch_total_emission = epoch_emission_active(epoch_cur);
    let vault_half = epoch_total_emission / 2;
    let solver_half = epoch_total_emission - vault_half;

    //--- participation (pflops) — computed up front so it can also curb vault APY ---
    //at pflops >= SOLVER_PARTICIPATION_TARGET (100 PFLOPS) full emission pays; below that
    //only pflops% pays and the shortfall accrues, so a low-participation (bear) period
    //can't take the lion's share of easy emissions.
    let height_in_epoch = (env.caller_env.entry_height % 100_000) as i128;
    let pflops = net_pflops(env, total_score_all, height_in_epoch);
    //floor the participation from PARTICIPATION_FLOOR_EPOCH on; before it, no floor
    let floor = if epoch_cur >= PARTICIPATION_FLOOR_EPOCH { SOLVER_PARTICIPATION_FLOOR } else { 0 };
    let participation = pflops.clamp(floor, SOLVER_PARTICIPATION_TARGET);

    //participation curbs the solver half always; it curbs vault APY only from
    //PARTICIPATION_VAULT_EPOCH on. before that, vaults always pay full and only solvers
    //are curbed; after it, low solver participation heavily reduces vault APY too.
    let vault_reduction_pct: u64 = if epoch_cur >= PARTICIPATION_VAULT_EPOCH { participation as u64 } else { 100 };

    let mut report = consensus::bic::epoch_report::Report::new();

    //--- vault APY ---
    let vault_pool = kv_get(env, VAULT_ACCRUED_POOL_KEY).and_then(|v| std::str::from_utf8(&v).ok().and_then(|s| s.parse::<i128>().ok())).unwrap_or(0);
    let vault_budget = vault_half.checked_add(vault_pool).unwrap_or_else(|| panic_any("vault_budget_overflow"));
    let vault_paid = consensus::bic::lockup_vault::pay_epoch_yield(env, epoch_cur, &trainers_map, vault_reduction_pct, vault_budget, &mut report);
    let vault_leftover = vault_budget.checked_sub(vault_paid).unwrap_or_else(|| panic_any("vault_pool_underflow"));
    let vault_stakes = consensus::bic::lockup_vault::close_matured_and_sum_stakes(env, epoch_next);

    //--- solver emission, curbed by participation ---
    let solver_budget = solver_half.checked_mul(participation).unwrap_or_else(|| panic_any("emission_overflow")) / SOLVER_PARTICIPATION_TARGET;
    let solver_paid = distribute_emissions_to_trainers(env, &solvers, solver_budget, total_sols, &mut report);
    //the part of the solver half not paid (participation shortfall + rounding) accrues
    let solver_accrued = solver_half.checked_sub(solver_paid).unwrap_or_else(|| panic_any("emission_overflow"));
    if solver_accrued > 0 {
        let _ = kv_increment(env, SOLVER_ACCRUED_POOL_KEY, solver_accrued);
    }
    report.add(SOLVER_ACCRUED_POOL_KEY, "solver_pool", solver_accrued);

    //--- 25% network tax, charged AFTER all participation reductions so it tracks what
    //was actually paid (vault_paid and solver_paid are already reduced). funded from the
    //vault leftover so it never exceeds emission; capped at the leftover — payouts are
    //never cut, the tax yields first. remaining leftover rolls into the vault pool. ---
    let taxable = vault_paid.checked_add(solver_paid).unwrap_or_else(|| panic_any("emission_overflow"));
    let nominal_tax = taxable.checked_mul(NETWORK_TAX_BPS).unwrap_or_else(|| panic_any("emission_overflow")) / 10_000;
    let tax = nominal_tax.min(vault_leftover);
    if tax > 0 {
        let _ = kv_increment(env, &bcat(&[b"account:", TREASURY_DONATION_ADDRESS.as_slice(), b":balance:AMA"]), tax);
        report.add(TREASURY_DONATION_ADDRESS.as_slice(), "tax", tax);
    }
    let new_vault_pool = vault_leftover - tax;
    kv_put(env, VAULT_ACCRUED_POOL_KEY, new_vault_pool.to_string().as_bytes());
    report.add(VAULT_ACCRUED_POOL_KEY, "vault_pool", new_vault_pool - vault_pool);
    if !env.readonly {
        report.write(epoch_cur);
    }

    //--- validators for next epoch: >=1m vault validators + top 33 solvers ---
    let new_validators = build_and_shuffle_new_validators(env, &leaders, &vault_stakes);
    let new_validators = consensus::bic::list_of_binaries_to_vecpak(new_validators);
    let height_next = format!("{:012}", env.caller_env.entry_height.saturating_add(1)).into_bytes();
    let _ = kv_put(env, &bcat(&[b"bic:epoch:validators:height:", &height_next]), &new_validators);

    update_difficulty_and_log_sols(env, epoch_cur, epoch_next, total_sols);
    clear_epoch_data(env);
}

fn net_pflops(env: &mut ApplyEnv, total_sols: i128, height_in_epoch: i128) -> i128 {
    const OPS: i128 = 16 * 16 * 50_240 * 2; //25_722_880 (MACs x2, per pflops)

    let diff_bits = kv_get(env, b"bic:epoch:diff_bits")
        .and_then(|v| std::str::from_utf8(&v).ok().and_then(|s| s.parse::<u32>().ok()))
        .unwrap_or(24);
    let diff_multiplier: i128 = if diff_bits >= 127 { i128::MAX } else { 1i128 << diff_bits };

    let total_calcs = total_sols.checked_mul(diff_multiplier).unwrap_or(i128::MAX);
    let numer = total_calcs.checked_mul(OPS).unwrap_or(i128::MAX);
    let denom = (height_in_epoch + 2).checked_mul(500_000_000_000_000).unwrap_or_else(|| panic_any("pflops_denom_overflow"));
    numer / denom
}

//distributes `total_emission` to solvers pro rata by sol count (paid in full);
//returns the total actually paid, which the caller uses for tax accounting.
fn distribute_emissions_to_trainers(
    env: &mut ApplyEnv,
    trainers_to_recv: &Vec<(Vec<u8>, i128)>,
    total_emission: i128,
    total_sols: i128,
    report: &mut consensus::bic::epoch_report::Report,
) -> i128 {
    if total_sols == 0 {
        return 0;
    }

    let mut paid: i128 = 0;
    for (trainer, trainer_sols) in trainers_to_recv {
        let coins = trainer_sols
            .checked_mul(total_emission)
            .unwrap_or_else(|| panic_any("emission_overflow"))
            / total_sols;

        let emission_address = kv_get(env, &bcat(&[b"account:", trainer, b":attribute:emission_address"]));
        let credited = emission_address.unwrap_or_else(|| trainer.clone());
        let balance_key = bcat(&[b"account:", &credited, b":balance:AMA"]);

        let _ = kv_increment(env, &balance_key, coins);
        report.add(&credited, "emission", coins);
        paid = paid.checked_add(coins).unwrap_or_else(|| panic_any("emission_overflow"));
    }
    paid
}

//number of top solvers admitted to the validator set
const SOLVER_VALIDATOR_SLOTS: usize = 33;

//validator set: every >=1m-stake vault validator + top 33 solvers,
//deduped, no fixed size cap.
fn build_and_shuffle_new_validators(env: &ApplyEnv, leaders: &Vec<(Vec<u8>, i128)>, vault_stakes: &BTreeMap<Vec<u8>, i128>) -> Vec<Vec<u8>> {
    let mut new_validators: Vec<Vec<u8>> = Vec::new();

    //vault-backed validators with at least VALIDATOR_MIN_STAKE (1m AMA amount+accrued)
    for (validator, stake) in vault_stakes {
        if *stake >= consensus::bic::lockup_vault::VALIDATOR_MIN_STAKE {
            new_validators.push(validator.clone());
        }
    }

    //top SOLVER_VALIDATOR_SLOTS solvers (leaders are pre-sorted by sol count desc,
    //so a low-sol solver only enters if fewer than 33 out-sol it)
    let top_solvers = leaders
        .iter()
        .map(|(pk, _)| pk.clone())
        .take(SOLVER_VALIDATOR_SLOTS);
    new_validators.extend(top_solvers);

    //a vault validator may also be a top solver; keep first occurrence
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    new_validators.retain(|pk| seen.insert(pk.clone()));

    shuffle_validators(env, &mut new_validators);
    new_validators
}

fn shuffle_validators(env: &ApplyEnv, validators: &mut Vec<Vec<u8>>) {
    let seed_bytes = &env.caller_env.seed;
    let seed_array: [u8; 32] = seed_bytes.get(..32).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 32]);
    let mut rng = crate::consensus::bic::exsss::Exsss::from_seed(&seed_array);
    rng.shuffle(validators);
}

fn update_difficulty_and_log_sols(env: &mut ApplyEnv, epoch_cur: u64, epoch_next: u64, total_sols: i128) {
    use crate::consensus::consensus_kv::kv_put;
    let old_diff_bits = kv_get(env, b"bic:epoch:diff_bits").unwrap();
    let old_diff_bits = std::str::from_utf8(&old_diff_bits).ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or_else(|| panic_any("invalid_diff_bits"));

    //target keyed on epoch_next: the diff an epoch runs under is computed with the
    //target active in THAT epoch, so the 180k retarget lands exactly at FORKHEIGHT2
    let target = if epoch_next.saturating_mul(100_000) >= consensus::bic::protocol::forkheight2(env) {
        crate::consensus::bic::sol_difficulty::TARGET_SOLS_EPOCH2
    } else {
        crate::consensus::bic::sol_difficulty::TARGET_SOLS_EPOCH
    };
    let next_diff_bits = crate::consensus::bic::sol_difficulty::next(old_diff_bits, total_sols as u64, target);
    let _ = kv_put(env, b"bic:epoch:diff_bits", next_diff_bits.to_string().as_bytes());
    let _ = kv_put(env, format!("bic:epoch:diff_bits:{}", epoch_next).as_bytes(), next_diff_bits.to_string().as_bytes());
    let _ = kv_put(env, format!("bic:epoch:total_sols:{}", epoch_cur).as_bytes(), total_sols.to_string().as_bytes());
}

fn clear_epoch_data(env: &mut ApplyEnv) {
    let mut cursor: Vec<u8> = Vec::new();

    let prefix = b"bic:epoch:solbloom:";
    while let Some((next_key_wo_prefix, _val)) = kv_get_next(env, prefix, &cursor) {
        let mut key = Vec::with_capacity(prefix.len() + next_key_wo_prefix.len());
        key.extend_from_slice(prefix);
        key.extend_from_slice(&next_key_wo_prefix);

        kv_delete(env, &key);
        cursor = next_key_wo_prefix;
    }

    let prefix = b"bic:epoch:solutions_count:";
    cursor = Vec::new();
    while let Some((next_key_wo_prefix, _val)) = kv_get_next(env, prefix, &cursor) {
        let mut key = Vec::with_capacity(prefix.len() + next_key_wo_prefix.len());
        key.extend_from_slice(prefix);
        key.extend_from_slice(&next_key_wo_prefix);

        kv_delete(env, &key);
        cursor = next_key_wo_prefix;
    }
}
