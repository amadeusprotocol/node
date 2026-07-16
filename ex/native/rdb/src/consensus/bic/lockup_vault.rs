use crate::bcat;
use crate::consensus::bic::coin::balance;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_delete, kv_exists, kv_get, kv_get_next, kv_increment, kv_put};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::panic_any;
use vecpak::{decode, encode, Term};

pub const BLOCKS_PER_DAY: u64 = 86_400_000 / 500; //1 block per 500ms
pub const EPOCH_INTERVAL: u64 = crate::consensus::bic::epoch::EPOCH_INTERVAL as u64;
pub const DAYS_PER_MONTH: u64 = 30;

pub const fn days_to_epochs(days: u64) -> u64 {
    days.saturating_mul(BLOCKS_PER_DAY).saturating_add(EPOCH_INTERVAL - 1) / EPOCH_INTERVAL
}

pub const UNLOCK_PERIOD_EPOCHS: u64 = days_to_epochs(21);

pub const MIN_VAULT_AMOUNT: i128 = 1000 * 1_000_000_000; //1000 AMA

pub const MAX_LOCK_MONTHS: u64 = 1200;

pub const BONUS_RATE_BPS: u64 = 500; //additive, 12month vaults only
pub const BONUS_END_EPOCH: u64 = 1150; //12m vaults created from this epoch on no longer lock the bonus

pub const VALIDATOR_CHANGE_QUEUE_EPOCHS: u64 = 2;

pub const COMMISSION_RAISE_QUEUE_EPOCHS: u64 = VALIDATOR_CHANGE_QUEUE_EPOCHS + 1;

pub const VALIDATOR_MIN_STAKE: i128 = 1_000_000 * 1_000_000_000; //1m AMA

pub const APY_EPOCH_DENOM: i128 = 6_307_200; //10_000 bps x 630.72 epochs per 365 day year

const VAULT_KEY_PREFIX: &[u8] = b"bic:lockup_vault:vault:";
const VALIDATOR_COMMISSION_KEY_PREFIX: &[u8] = b"bic:lockup_vault:validator_commission:";

pub fn months_to_epochs(months: u64) -> u64 {
    days_to_epochs(months.saturating_mul(DAYS_PER_MONTH))
}

//tier => (apy bps locked at creation, lock duration in epochs)
pub fn tier_params(tier: &[u8], epoch: u64) -> (u64, u64) {
    let bonus = if epoch < BONUS_END_EPOCH { BONUS_RATE_BPS } else { 0 };
    match tier {
        b"og" => (0, 0),
        b"3m" => (500, months_to_epochs(3)),
        b"6m" => (1000, months_to_epochs(6)),
        b"12m" => (1500 + bonus, months_to_epochs(12)),
        _ => panic_any("invalid_vault_type"),
    }
}

pub struct Vault {
    pub vault_type: Vec<u8>, //tier string: "og" | "3m" | "6m" | "12m"
    pub amount: i128,
    pub accrued: i128,
    pub rate_bps: u64,
    pub created_epoch: u64,
    pub mature_epoch: u64,
    pub payout_address: Option<Vec<u8>>,
    pub validator: Option<Vec<u8>>,
    pub validator_pending: Option<Vec<u8>>,
    pub validator_pending_epoch: Option<u64>,
    pub unlock_start_epoch: Option<u64>,
    pub unlock_at_epoch: Option<u64>,
}

impl Vault {
    //the payout address alone decides yield routing: unset, yield accrues (compounds)
    //into the vault; set, it distributes there
    pub fn accrues_to_vault(&self) -> bool {
        self.payout_address.is_none()
    }

    //validator changes (set or clear) queue for VALIDATOR_CHANGE_QUEUE_EPOCHS;
    //a queued change with validator_pending = None is a clear
    pub fn validator_for_epoch(&self, epoch: u64) -> Option<&Vec<u8>> {
        match self.validator_pending_epoch {
            Some(pending_epoch) if epoch >= pending_epoch => self.validator_pending.as_ref(),
            _ => self.validator.as_ref(),
        }
    }

    pub fn promote_validator(&mut self, current_epoch: u64) {
        if let Some(pending_epoch) = self.validator_pending_epoch {
            if current_epoch >= pending_epoch {
                self.validator = self.validator_pending.take();
                self.validator_pending_epoch = None;
            }
        }
    }

    pub fn to_term(&self) -> Term {
        let opt_int = |v: Option<u64>| match v {
            Some(n) => Term::VarInt(n as i128),
            None => Term::Nil(),
        };
        let opt_bin = |v: &Option<Vec<u8>>| match v {
            Some(b) => Term::Binary(b.clone()),
            None => Term::Nil(),
        };
        Term::PropList(vec![
            (Term::Binary(b"type".to_vec()), Term::Binary(self.vault_type.clone())),
            (Term::Binary(b"amount".to_vec()), Term::VarInt(self.amount)),
            (Term::Binary(b"accrued".to_vec()), Term::VarInt(self.accrued)),
            (Term::Binary(b"rate_bps".to_vec()), Term::VarInt(self.rate_bps as i128)),
            (Term::Binary(b"created_epoch".to_vec()), Term::VarInt(self.created_epoch as i128)),
            (Term::Binary(b"mature_epoch".to_vec()), Term::VarInt(self.mature_epoch as i128)),
            (Term::Binary(b"payout_address".to_vec()), opt_bin(&self.payout_address)),
            (Term::Binary(b"validator".to_vec()), opt_bin(&self.validator)),
            (Term::Binary(b"validator_pending".to_vec()), opt_bin(&self.validator_pending)),
            (Term::Binary(b"validator_pending_epoch".to_vec()), opt_int(self.validator_pending_epoch)),
            (Term::Binary(b"unlock_start_epoch".to_vec()), opt_int(self.unlock_start_epoch)),
            (Term::Binary(b"unlock_at_epoch".to_vec()), opt_int(self.unlock_at_epoch)),
        ])
    }

    pub fn from_term(term: &Term) -> Vault {
        let pairs = match term {
            Term::PropList(pairs) => pairs,
            _ => panic_any("invalid_vault_data"),
        };
        let get = |key: &[u8]| -> &Term {
            pairs
                .iter()
                .find(|(k, _)| matches!(k, Term::Binary(b) if b.as_slice() == key))
                .map(|(_, v)| v)
                .unwrap_or_else(|| panic_any("invalid_vault_data"))
        };
        let int = |key: &[u8]| -> i128 {
            match get(key) {
                Term::VarInt(v) => *v,
                _ => panic_any("invalid_vault_data"),
            }
        };
        let uint = |key: &[u8]| -> u64 { u64::try_from(int(key)).unwrap_or_else(|_| panic_any("invalid_vault_data")) };
        let opt_uint = |key: &[u8]| -> Option<u64> {
            match get(key) {
                Term::Nil() => None,
                Term::VarInt(v) => Some(u64::try_from(*v).unwrap_or_else(|_| panic_any("invalid_vault_data"))),
                _ => panic_any("invalid_vault_data"),
            }
        };
        Vault {
            vault_type: match get(b"type") {
                Term::Binary(b) => b.clone(),
                _ => panic_any("invalid_vault_data"),
            },
            amount: int(b"amount"),
            accrued: int(b"accrued"),
            rate_bps: uint(b"rate_bps"),
            created_epoch: uint(b"created_epoch"),
            mature_epoch: uint(b"mature_epoch"),
            payout_address: match get(b"payout_address") {
                Term::Nil() => None,
                Term::Binary(b) => Some(b.clone()),
                _ => panic_any("invalid_vault_data"),
            },
            validator: match get(b"validator") {
                Term::Nil() => None,
                Term::Binary(b) => Some(b.clone()),
                _ => panic_any("invalid_vault_data"),
            },
            validator_pending: match get(b"validator_pending") {
                Term::Nil() => None,
                Term::Binary(b) => Some(b.clone()),
                _ => panic_any("invalid_vault_data"),
            },
            validator_pending_epoch: opt_uint(b"validator_pending_epoch"),
            unlock_start_epoch: opt_uint(b"unlock_start_epoch"),
            unlock_at_epoch: opt_uint(b"unlock_at_epoch"),
        }
    }
}

fn vault_key(owner: &[u8], vault_index: &[u8]) -> Vec<u8> {
    bcat(&[VAULT_KEY_PREFIX, owner, b":", vault_index])
}

fn store_vault(env: &mut ApplyEnv, key: &[u8], vault: &Vault) {
    let buf = encode(vault.to_term());
    kv_put(env, key, &buf);
}

fn load_vault(env: &mut ApplyEnv, key: &[u8]) -> Vault {
    let bytes = kv_get(env, key).unwrap_or_else(|| panic_any("invalid_vault"));
    let term = decode(&bytes).unwrap_or_else(|_| panic_any("invalid_vault_data"));
    Vault::from_term(&term)
}

//all vaults owned by a pk, as (index, vault) pairs in lexicographic index order
pub fn vaults_by_owner(env: &mut ApplyEnv, owner: &[u8]) -> Vec<(Vec<u8>, Vault)> {
    let prefix = bcat(&[VAULT_KEY_PREFIX, owner, b":"]);
    let mut cursor: Vec<u8> = Vec::new();
    let mut vaults = Vec::new();
    while let Some((index, bytes)) = kv_get_next(env, &prefix, &cursor) {
        let term = decode(&bytes).unwrap_or_else(|_| panic_any("invalid_vault_data"));
        vaults.push((index.clone(), Vault::from_term(&term)));
        cursor = index;
    }
    vaults
}

fn commission_key(validator: &[u8]) -> Vec<u8> {
    bcat(&[VALIDATOR_COMMISSION_KEY_PREFIX, validator])
}

fn load_commission(env: &mut ApplyEnv, key: &[u8]) -> (u64, u64, u64) {
    let bytes = match kv_get(env, key) {
        Some(b) => b,
        None => return (0, 0, 0),
    };
    let term = decode(&bytes).unwrap_or_else(|_| panic_any("invalid_commission_data"));
    let pairs = match term {
        Term::PropList(pairs) => pairs,
        _ => panic_any("invalid_commission_data"),
    };
    let get = |key: &[u8]| -> u64 {
        pairs
            .iter()
            .find(|(k, _)| matches!(k, Term::Binary(b) if b.as_slice() == key))
            .and_then(|(_, v)| match v {
                Term::VarInt(n) => u64::try_from(*n).ok(),
                _ => None,
            })
            .unwrap_or_else(|| panic_any("invalid_commission_data"))
    };
    (get(b"bps"), get(b"pending_bps"), get(b"pending_epoch"))
}

fn store_commission(env: &mut ApplyEnv, key: &[u8], bps: u64, pending_bps: u64, pending_epoch: u64) {
    let term = Term::PropList(vec![
        (Term::Binary(b"bps".to_vec()), Term::VarInt(bps as i128)),
        (Term::Binary(b"pending_bps".to_vec()), Term::VarInt(pending_bps as i128)),
        (Term::Binary(b"pending_epoch".to_vec()), Term::VarInt(pending_epoch as i128)),
    ]);
    kv_put(env, key, &encode(term));
}

pub fn commission_bps_for_epoch(env: &mut ApplyEnv, validator: &[u8], epoch: u64) -> u64 {
    let (bps, pending_bps, pending_epoch) = load_commission(env, &commission_key(validator));
    if epoch >= pending_epoch {
        pending_bps
    } else {
        bps
    }
}

//pays the ending epoch's yield for every vault whose backing validator is in the
//epoch's set (the set already excludes validators slashed during the epoch).
//promotion has already run (promote_pending_validators is first in epoch::next),
//so this reads vault.validator directly. unlocking vaults still earn (they keep
//backing their validator until withdrawn). yield is due on amount+accrued —
//everything locked in the vault earns. the backing validator's commission is
//skimmed off each payout (routed via its emission_address when set); the net
//routes per accrues_to_vault: to the payout address if one is set, else
//compounding into the vault. reduction_pct scales payouts (100 = full). pays at
//most budget, pro rata if the dues exceed it. returns the total GROSS paid
//(net + commission), which draws down the budget; the caller handles the network
//tax and accrued-pool accounting.
pub fn pay_epoch_yield(env: &mut ApplyEnv, epoch: u64, validators: &HashSet<Vec<u8>>, reduction_pct: u64, budget: i128) -> i128 {
    if budget <= 0 || reduction_pct == 0 {
        return 0;
    }
    let mut entries: Vec<(Vec<u8>, Vault, i128)> = Vec::new();
    let mut due_total: i128 = 0;
    let mut cursor: Vec<u8> = Vec::new();
    while let Some((suffix, bytes)) = kv_get_next(env, VAULT_KEY_PREFIX, &cursor) {
        cursor = suffix.clone();
        let term = decode(&bytes).unwrap_or_else(|_| panic_any("invalid_vault_data"));
        let vault = Vault::from_term(&term);
        let backed = match &vault.validator {
            Some(v) => v.clone(),
            None => continue,
        };
        if !validators.contains(&backed) {
            continue;
        }
        let base = vault.amount.checked_add(vault.accrued).unwrap_or_else(|| panic_any("vault_amount_overflow"));
        let due = base.checked_mul(vault.rate_bps as i128).unwrap_or_else(|| panic_any("yield_overflow")) / APY_EPOCH_DENOM;
        let due = due.checked_mul(reduction_pct.min(100) as i128).unwrap_or_else(|| panic_any("yield_overflow")) / 100;
        if due > 0 {
            due_total = due_total.checked_add(due).unwrap_or_else(|| panic_any("yield_overflow"));
            entries.push((bcat(&[VAULT_KEY_PREFIX, &suffix]), vault, due));
        }
    }
    if due_total == 0 {
        return 0;
    }

    let mut commissions: HashMap<Vec<u8>, u64> = HashMap::new();
    let mut paid_total: i128 = 0;
    for (key, mut vault, due) in entries {
        let pay = if due_total > budget {
            due.checked_mul(budget).unwrap_or_else(|| panic_any("yield_overflow")) / due_total
        } else {
            due
        };
        if pay <= 0 {
            continue;
        }

        let validator = vault.validator.as_ref().unwrap_or_else(|| panic_any("invalid_vault_data")).clone();
        let bps = match commissions.get(&validator) {
            Some(bps) => *bps,
            None => {
                let bps = commission_bps_for_epoch(env, &validator, epoch).min(10_000);
                commissions.insert(validator.clone(), bps);
                bps
            }
        };
        let commission = pay.checked_mul(bps as i128).unwrap_or_else(|| panic_any("yield_overflow")) / 10_000;
        if commission > 0 {
            let emission_address = kv_get(env, &bcat(&[b"account:", &validator, b":attribute:emission_address"]));
            let balance_key =
                if let Some(addr) = emission_address { bcat(&[b"account:", &addr, b":balance:AMA"]) } else { bcat(&[b"account:", &validator, b":balance:AMA"]) };
            kv_increment(env, &balance_key, commission);
        }

        let net = pay - commission;
        if net > 0 {
            if vault.accrues_to_vault() {
                vault.accrued = vault.accrued.checked_add(net).unwrap_or_else(|| panic_any("vault_amount_overflow"));
                store_vault(env, &key, &vault);
            } else {
                let addr = vault.payout_address.as_ref().unwrap_or_else(|| panic_any("invalid_vault_data")).clone();
                kv_increment(env, &bcat(&[b"account:", &addr, b":balance:AMA"]), net);
            }
        }
        paid_total = paid_total.checked_add(pay).unwrap_or_else(|| panic_any("yield_overflow"));
    }
    paid_total
}

//posts every queued validator change due by `epoch` (the epoch being entered).
//this is the ONLY place promotion persists — it runs FIRST in epoch::next, so
//mid-epoch state never carries a due-but-unposted change and everything downstream
//(yield, stakes, user calls) reads vault.validator / the pending fields directly.
pub fn promote_pending_validators(env: &mut ApplyEnv, epoch: u64) {
    let mut cursor: Vec<u8> = Vec::new();
    while let Some((suffix, bytes)) = kv_get_next(env, VAULT_KEY_PREFIX, &cursor) {
        cursor = suffix.clone();
        let term = decode(&bytes).unwrap_or_else(|_| panic_any("invalid_vault_data"));
        let mut vault = Vault::from_term(&term);
        if vault.validator_pending_epoch.is_some() {
            vault.promote_validator(epoch);
            if vault.validator_pending_epoch.is_none() {
                store_vault(env, &bcat(&[VAULT_KEY_PREFIX, &suffix]), &vault);
            }
        }
    }
}

//single post-pay boundary scan: closes every unlocked vault whose window has elapsed
//(unlock_at_epoch <= `epoch`, the epoch being entered) by crediting amount+accrued to
//its owner and deleting it, and sums amount+accrued per backing validator over the
//vaults that remain — matured vaults are closed and thus excluded from stake in the
//same pass. promotion has already run, so this reads vault.validator directly.
//BTreeMap keeps iteration deterministic across nodes.
pub fn close_matured_and_sum_stakes(env: &mut ApplyEnv, epoch: u64) -> BTreeMap<Vec<u8>, i128> {
    let mut stakes: BTreeMap<Vec<u8>, i128> = BTreeMap::new();
    let mut cursor: Vec<u8> = Vec::new();
    while let Some((suffix, bytes)) = kv_get_next(env, VAULT_KEY_PREFIX, &cursor) {
        cursor = suffix.clone();
        let term = decode(&bytes).unwrap_or_else(|_| panic_any("invalid_vault_data"));
        let vault = Vault::from_term(&term);
        let total = vault.amount.checked_add(vault.accrued).unwrap_or_else(|| panic_any("vault_amount_overflow"));
        match vault.unlock_at_epoch {
            Some(at) if epoch >= at => {
                //matured: auto-close to the owner (leading 48 bytes of the key suffix)
                if suffix.len() < 48 {
                    panic_any("invalid_vault_key")
                }
                if total > 0 {
                    kv_increment(env, &bcat(&[b"account:", &suffix[0..48], b":balance:AMA"]), total);
                }
                kv_delete(env, &bcat(&[VAULT_KEY_PREFIX, &suffix]));
            }
            _ => {
                //still open: count its stake toward its backing validator
                if let Some(validator) = &vault.validator {
                    let stake = stakes.entry(validator.clone()).or_insert(0);
                    *stake = stake.checked_add(total).unwrap_or_else(|| panic_any("validator_stake_overflow"));
                }
            }
        }
    }
    stakes
}

fn load_caller_vault(env: &mut ApplyEnv, vault_index: &[u8]) -> (Vec<u8>, Vault) {
    let key = vault_key(&env.caller_env.account_caller.clone(), vault_index);
    let vault = load_vault(env, &key);
    (key, vault)
}

fn validate_pk(pk: &[u8], error: &'static str) {
    if pk.len() != 48 || !crate::consensus::bls12_381::validate_public_key(pk) {
        panic_any(error)
    }
}

fn init_balance_if_missing(env: &mut ApplyEnv, address: &[u8]) {
    let key = bcat(&[b"account:", address, b":balance:AMA"]);
    if !kv_exists(env, &key) {
        kv_increment(env, &key, 0);
    }
}

struct ArgMap {
    pairs: Vec<(Vec<u8>, Term)>,
}

impl ArgMap {
    fn parse(args: &[Vec<u8>], allowed: &[&[u8]]) -> ArgMap {
        if args.len() != 1 {
            panic_any("invalid_args")
        }
        let term = decode(&args[0]).unwrap_or_else(|_| panic_any("invalid_args"));
        let pairs = match term {
            Term::PropList(pairs) => pairs,
            _ => panic_any("invalid_args"),
        };
        let mut out: Vec<(Vec<u8>, Term)> = Vec::with_capacity(pairs.len());
        for (k, v) in pairs {
            let key = match k {
                Term::Binary(b) => b,
                _ => panic_any("invalid_args"),
            };
            if !allowed.contains(&key.as_slice()) {
                panic_any("unknown_arg")
            }
            out.push((key, v));
        }
        ArgMap { pairs: out }
    }

    fn get(&self, key: &[u8]) -> Option<&Term> {
        self.pairs.iter().find(|(k, _)| k.as_slice() == key).map(|(_, v)| v)
    }

    fn require_int(&self, key: &[u8], err: &'static str) -> i128 {
        match self.get(key) {
            Some(Term::VarInt(v)) => *v,
            _ => panic_any(err),
        }
    }

    fn require_bin(&self, key: &[u8], err: &'static str) -> Vec<u8> {
        match self.get(key) {
            Some(Term::Binary(b)) => b.clone(),
            _ => panic_any(err),
        }
    }

    fn require_bool(&self, key: &[u8], err: &'static str) -> bool {
        match self.get(key) {
            Some(Term::Bool(b)) => *b,
            _ => panic_any(err),
        }
    }

    //None if the key is absent; a present-but-wrong-type value is an error
    fn opt_bin(&self, key: &[u8], err: &'static str) -> Option<Vec<u8>> {
        match self.get(key) {
            None => None,
            Some(Term::Binary(b)) => Some(b.clone()),
            _ => panic_any(err),
        }
    }

    fn opt_int(&self, key: &[u8], err: &'static str) -> Option<i128> {
        match self.get(key) {
            None => None,
            Some(Term::VarInt(v)) => Some(*v),
            _ => panic_any(err),
        }
    }
}

const CREATE_KEYS: &[&[u8]] = &[b"amount", b"tier", b"validator", b"payout_address", b"owner", b"unlock_epoch", b"months"];

//args: a single vecpak map (tag 7) with keys:
//  amount         (int,  required)
//  tier           (bin,  required) — "og" | "3m" | "6m" | "12m"
//  validator      (bin pk, optional) — enters the 2-epoch validator queue, same
//                 as a later set_validator (not live until it posts)
//  payout_address (bin pk, optional) — where yield distributes; when unset, yield
//                 accrues (compounds) into the vault
//  owner          (bin pk, optional) — who the vault is keyed under and controlled
//                 by; defaults to the caller. lets a treasury fund a vault held by
//                 a beneficiary. the caller is always the one debited.
//  unlock_epoch   (int,  optional) — may push maturity LATER than the tier
//                 schedule, never earlier (an earlier value is ignored).
//  months         (int,  optional) — og tier only: lock length in months
//                 (default 0). rejected on any other tier.
pub fn call_create(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    let map = ArgMap::parse(&args, CREATE_KEYS);

    let amount = map.require_int(b"amount", "invalid_amount");
    let tier = map.require_bin(b"tier", "invalid_vault_type");
    let (rate_bps, tier_duration) = tier_params(&tier, env.caller_env.entry_epoch);
    let duration_epochs = match map.opt_int(b"months", "invalid_months") {
        Some(_) if tier.as_slice() != b"og" => panic_any("months_not_allowed"),
        Some(m) => {
            let m = u64::try_from(m).unwrap_or_else(|_| panic_any("invalid_months"));
            if m > MAX_LOCK_MONTHS {
                panic_any("invalid_months")
            }
            months_to_epochs(m)
        }
        None => tier_duration,
    };

    let caller = env.caller_env.account_caller.clone();

    if amount < MIN_VAULT_AMOUNT {
        panic_any("vault_amount_below_minimum")
    }
    if amount > balance(env, &caller, b"AMA") {
        panic_any("insufficient_funds")
    }

    let validator = match map.opt_bin(b"validator", "invalid_validator_pk") {
        Some(pk) => {
            validate_pk(&pk, "invalid_validator_pk");
            init_balance_if_missing(env, &pk);
            Some(pk)
        }
        None => None,
    };
    let payout_address = match map.opt_bin(b"payout_address", "invalid_payout_pk") {
        Some(addr) => {
            validate_pk(&addr, "invalid_payout_pk");
            init_balance_if_missing(env, &addr);
            Some(addr)
        }
        None => None,
    };
    let owner = match map.opt_bin(b"owner", "invalid_owner_pk") {
        Some(pk) => {
            validate_pk(&pk, "invalid_owner_pk");
            pk
        }
        None => caller.clone(),
    };

    let entry_epoch = env.caller_env.entry_epoch;
    let tier_mature = entry_epoch.saturating_add(duration_epochs);
    let mature_epoch = match map.opt_int(b"unlock_epoch", "invalid_unlock_epoch") {
        Some(v) if v > tier_mature as i128 => u64::try_from(v).unwrap_or_else(|_| panic_any("invalid_unlock_epoch")),
        _ => tier_mature,
    };

    kv_increment(env, &bcat(&[b"account:", &caller, b":balance:AMA"]), -amount);

    //a validator chosen at creation enters the same 2-epoch queue as a later
    //set_validator: it is pending, not live, until VALIDATOR_CHANGE_QUEUE_EPOCHS pass
    let validator_pending_epoch = validator.as_ref().map(|_| entry_epoch.saturating_add(VALIDATOR_CHANGE_QUEUE_EPOCHS));

    let vault = Vault {
        vault_type: tier,
        amount,
        accrued: 0,
        rate_bps,
        created_epoch: entry_epoch,
        mature_epoch,
        payout_address,
        validator: None,
        validator_pending: validator,
        validator_pending_epoch,
        unlock_start_epoch: None,
        unlock_at_epoch: None,
    };

    let vault_index = kv_increment(env, &bcat(&[b"bic:lockup_vault:unique_index"]), 1);
    let key = vault_key(&owner, vault_index.to_string().as_bytes());
    store_vault(env, &key, &vault);
}

pub fn call_unlock(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let (key, mut vault) = load_caller_vault(env, &args[0]);

    if vault.unlock_start_epoch.is_some() {
        panic_any("vault_already_unlocking")
    }
    let entry_epoch = env.caller_env.entry_epoch;
    if entry_epoch < vault.mature_epoch {
        panic_any("vault_is_locked")
    }

    vault.unlock_start_epoch = Some(entry_epoch);
    vault.unlock_at_epoch = Some(entry_epoch.saturating_add(UNLOCK_PERIOD_EPOCHS));
    store_vault(env, &key, &vault);
}

pub fn call_set_payout_address(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 2 {
        panic_any("invalid_args")
    }
    let (key, mut vault) = load_caller_vault(env, &args[0]);
    if vault.unlock_start_epoch.is_some() {
        panic_any("vault_is_unlocking")
    }
    validate_pk(&args[1], "invalid_payout_pk");
    init_balance_if_missing(env, &args[1]);
    vault.payout_address = Some(args[1].to_vec());
    store_vault(env, &key, &vault);
}

pub fn call_clear_payout_address(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let (key, mut vault) = load_caller_vault(env, &args[0]);
    if vault.unlock_start_epoch.is_some() {
        panic_any("vault_is_unlocking")
    }
    vault.payout_address = None;
    store_vault(env, &key, &vault);
}

pub fn call_set_validator(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 2 {
        panic_any("invalid_args")
    }
    let (key, mut vault) = load_caller_vault(env, &args[0]);
    let validator = args[1].as_slice();
    validate_pk(validator, "invalid_validator_pk");
    init_balance_if_missing(env, validator);
    let heading_to = if vault.validator_pending_epoch.is_some() {
        vault.validator_pending.as_deref()
    } else {
        vault.validator.as_deref()
    };
    if heading_to == Some(validator) {
        return;
    }
    vault.validator_pending = Some(validator.to_vec());
    vault.validator_pending_epoch = Some(env.caller_env.entry_epoch.saturating_add(VALIDATOR_CHANGE_QUEUE_EPOCHS));
    store_vault(env, &key, &vault);
}

pub fn call_clear_validator(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let (key, mut vault) = load_caller_vault(env, &args[0]);
    if vault.validator_pending_epoch.is_some() && (vault.validator.is_none() || vault.validator_pending.is_some()) {
        vault.validator_pending = None;
        vault.validator_pending_epoch = None;
    } else if vault.validator.is_some() {
        vault.validator_pending = None;
        vault.validator_pending_epoch = Some(env.caller_env.entry_epoch.saturating_add(VALIDATOR_CHANGE_QUEUE_EPOCHS));
    } else {
        return;
    }
    store_vault(env, &key, &vault);
}

pub fn call_change_owner(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 2 {
        panic_any("invalid_args")
    }
    let (key, vault) = load_caller_vault(env, &args[0]);
    if vault.unlock_start_epoch.is_some() {
        panic_any("vault_is_unlocking")
    }
    validate_pk(&args[1], "invalid_owner_pk");
    init_balance_if_missing(env, &args[1]);

    let new_key = vault_key(&args[1], &args[0]);
    kv_delete(env, &key);
    store_vault(env, &new_key, &vault);
}

pub fn call_extend_lock(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 2 {
        panic_any("invalid_args")
    }
    let (key, mut vault) = load_caller_vault(env, &args[0]);
    if vault.unlock_start_epoch.is_some() {
        panic_any("vault_is_unlocking")
    }
    let extra = std::str::from_utf8(&args[1]).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_epochs"));
    if extra == 0 || extra > months_to_epochs(MAX_LOCK_MONTHS) {
        panic_any("invalid_epochs")
    }
    vault.mature_epoch = vault.mature_epoch.saturating_add(extra);
    store_vault(env, &key, &vault);
}

//sets the caller's validator commission in bps (0..=10000), skimmed off the yield
//of every vault backing it. cuts (and no-ops) apply instantly; raises queue for
//COMMISSION_RAISE_QUEUE_EPOCHS. re-setting the current rate cancels a queued raise.
//args: [bps].
pub fn call_set_commission(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let bps = std::str::from_utf8(&args[0]).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_commission"));
    if bps > 10_000 {
        panic_any("invalid_commission")
    }
    let caller = env.caller_env.account_caller.clone();
    init_balance_if_missing(env, &caller);

    let epoch = env.caller_env.entry_epoch;
    let key = commission_key(&caller);
    let current = commission_bps_for_epoch(env, &caller, epoch);
    if bps <= current {
        store_commission(env, &key, bps, bps, epoch);
    } else {
        store_commission(env, &key, current, bps, epoch.saturating_add(COMMISSION_RAISE_QUEUE_EPOCHS));
    }
}
