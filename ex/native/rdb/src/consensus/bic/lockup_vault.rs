use crate::bcat;
use crate::consensus::bic::coin::balance;
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{kv_delete, kv_exists, kv_get, kv_get_next, kv_increment, kv_put};
use std::collections::{BTreeMap, HashSet};
use std::panic::panic_any;
use vecpak::{decode, encode, Term};

pub const BLOCKS_PER_DAY: u64 = 86_400_000 / 500; //1 block per 500ms
pub const EPOCH_INTERVAL: u64 = crate::consensus::bic::epoch::EPOCH_INTERVAL as u64;
pub const DAYS_PER_MONTH: u64 = 30;

pub const fn days_to_epochs(days: u64) -> u64 {
    //saturating so absurd inputs cap out instead of wrapping (release) or panicking
    days.saturating_mul(BLOCKS_PER_DAY).saturating_add(EPOCH_INTERVAL - 1) / EPOCH_INTERVAL
}

pub const UNLOCK_PERIOD_EPOCHS: u64 = days_to_epochs(21);

pub const MIN_VAULT_AMOUNT: i128 = 1000 * 1_000_000_000; //1000 AMA

pub const MAX_OG_LOCK_MONTHS: u64 = 1200; //og `months` cap (100 years); bounds months_to_epochs well clear of overflow

pub const BONUS_RATE_BPS: u64 = 500; //additive, 12month vaults only
pub const BONUS_END_EPOCH: u64 = 1150; //12m vaults created from this epoch on no longer lock the bonus

pub const VALIDATOR_CHANGE_QUEUE_EPOCHS: u64 = 2;

pub const VALIDATOR_MIN_STAKE: i128 = 1_000_000 * 1_000_000_000; //1m AMA

pub const APY_EPOCH_DENOM: i128 = 6_307_200; //10_000 bps x 630.72 epochs per 365 day year

const VAULT_KEY_PREFIX: &[u8] = b"bic:lockup_vault:vault:";

pub fn months_to_epochs(months: u64) -> u64 {
    days_to_epochs(months.saturating_mul(DAYS_PER_MONTH))
}

//tier => (apy bps locked at creation, lock duration in epochs)
pub fn tier_params(tier: &[u8], epoch: u64) -> (u64, u64) {
    let bonus = if epoch < BONUS_END_EPOCH { BONUS_RATE_BPS } else { 0 };
    match tier {
        //TEMPORARY test tier: 1% APY, matures immediately, 0 epoch unlock window
        //(see unlock_window_epochs) for fast end-to-end testing. remove before mainnet.
        b"test" => (100, 0),
        //og: 0 APY, caller-chosen lock length (the `months` create arg; default 0
        //= immediate maturity). unlike test it serves the full UNLOCK_PERIOD_EPOCHS
        //window. duration here is the default; call_create applies `months`.
        b"og" => (0, 0),
        b"3m" => (500, months_to_epochs(3)),
        b"6m" => (1000, months_to_epochs(6)),
        b"12m" => (1500 + bonus, months_to_epochs(12)),
        _ => panic_any("invalid_vault_type"),
    }
}

//epochs between queuing unlock and being able to withdraw. every real tier
//serves the full period; the TEMPORARY test tier exits in the same epoch.
fn unlock_window_epochs(tier: &[u8]) -> u64 {
    match tier {
        b"test" => 0,
        _ => UNLOCK_PERIOD_EPOCHS,
    }
}

pub struct Vault {
    pub vault_type: Vec<u8>, //tier string: "test" | "og" | "3m" | "6m" | "12m"
    pub amount: i128,
    pub accrued: i128,
    pub rate_bps: u64,
    pub created_epoch: u64,
    pub mature_epoch: u64,
    pub compound: bool,
    pub payout_address: Option<Vec<u8>>,
    pub validator: Option<Vec<u8>>,
    pub validator_pending: Option<Vec<u8>>,
    pub validator_pending_epoch: Option<u64>,
    pub unlock_start_epoch: Option<u64>,
    pub unlock_at_epoch: Option<u64>,
}

impl Vault {
    //compound vaults always accrue into the vault; non-compound vaults accrue
    //only while no payout address is set, otherwise they distribute to it
    pub fn accrues_to_vault(&self) -> bool {
        self.compound || self.payout_address.is_none()
    }

    //yield accrues from created_epoch until unlock is queued
    pub fn accrual_end_epoch(&self, current_epoch: u64) -> u64 {
        match self.unlock_start_epoch {
            Some(start) => start.min(current_epoch),
            None => current_epoch,
        }
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
            (Term::Binary(b"compound".to_vec()), Term::Bool(self.compound)),
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
            compound: match get(b"compound") {
                Term::Bool(b) => *b,
                _ => panic_any("invalid_vault_data"),
            },
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

//pays the ending epoch's yield for every eligible vault: not unlocking, and
//the validator it backed this epoch is in the epoch's set and unslashed.
//compound vaults accrue on amount+accrued, others on amount alone; payouts
//route per accrues_to_vault. reduction_pct scales payouts (100 = full). pays
//at most budget, pro rata if the dues exceed it. returns the total paid.
pub fn pay_epoch_yield(
    env: &mut ApplyEnv,
    epoch: u64,
    validators: &HashSet<Vec<u8>>,
    slashed: &HashSet<Vec<u8>>,
    reduction_pct: u64,
    budget: i128,
) -> i128 {
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
        if vault.unlock_start_epoch.is_some() {
            continue;
        }
        let backed = match vault.validator_for_epoch(epoch) {
            Some(v) => v.clone(),
            None => continue,
        };
        if !validators.contains(&backed) || slashed.contains(&backed) {
            continue;
        }
        let base = if vault.compound {
            vault.amount.checked_add(vault.accrued).unwrap_or_else(|| panic_any("vault_amount_overflow"))
        } else {
            vault.amount
        };
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
        if vault.accrues_to_vault() {
            vault.accrued = vault.accrued.checked_add(pay).unwrap_or_else(|| panic_any("vault_amount_overflow"));
            store_vault(env, &key, &vault);
        } else {
            let addr = vault.payout_address.as_ref().unwrap_or_else(|| panic_any("invalid_vault_data")).clone();
            kv_increment(env, &bcat(&[b"account:", &addr, b":balance:AMA"]), pay);
        }
        paid_total = paid_total.checked_add(pay).unwrap_or_else(|| panic_any("yield_overflow"));
    }
    paid_total
}

//epoch boundary scan over every vault: skips unlocking vaults, persists due
//pending validator changes, and sums amount+accrued per live validator.
//BTreeMap keeps iteration deterministic across nodes. phase 3 reward accrual
//for the ending epoch must run BEFORE this (promotion rewrites the validator
//the vault was backing during the ending epoch).
pub fn validator_stakes(env: &mut ApplyEnv, epoch: u64) -> BTreeMap<Vec<u8>, i128> {
    let mut stakes: BTreeMap<Vec<u8>, i128> = BTreeMap::new();
    let mut cursor: Vec<u8> = Vec::new();
    while let Some((suffix, bytes)) = kv_get_next(env, VAULT_KEY_PREFIX, &cursor) {
        cursor = suffix.clone();
        let term = decode(&bytes).unwrap_or_else(|_| panic_any("invalid_vault_data"));
        let mut vault = Vault::from_term(&term);
        if vault.unlock_start_epoch.is_some() {
            continue;
        }
        if vault.validator_pending_epoch.is_some() {
            vault.promote_validator(epoch);
            if vault.validator_pending_epoch.is_none() {
                store_vault(env, &bcat(&[VAULT_KEY_PREFIX, &suffix]), &vault);
            }
        }
        if let Some(validator) = &vault.validator {
            let total = vault.amount.checked_add(vault.accrued).unwrap_or_else(|| panic_any("vault_amount_overflow"));
            let stake = stakes.entry(validator.clone()).or_insert(0);
            *stake = stake.checked_add(total).unwrap_or_else(|| panic_any("validator_stake_overflow"));
        }
    }
    stakes
}

fn load_caller_vault(env: &mut ApplyEnv, vault_index: &[u8]) -> (Vec<u8>, Vault) {
    let key = vault_key(&env.caller_env.account_caller.clone(), vault_index);
    let mut vault = load_vault(env, &key);
    vault.promote_validator(env.caller_env.entry_epoch);
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

//strict reader for a single vecpak map argument (tag 7). the codec already
//guarantees the map is canonical and duplicate-free (decode rejects anything
//else), so this layer only adds the policy the codec can't know: an allow-list
//of recognized keys (unknown keys are a hard error, so expanding the set is a
//consensus change to gate behind a forkheight), plus required-key presence and
//per-key value typing.
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

const CREATE_KEYS: &[&[u8]] = &[b"amount", b"tier", b"compound", b"validator", b"payout_address", b"owner", b"unlock_epoch", b"months"];

//args: a single vecpak map (tag 7) with keys:
//  amount         (int,  required)
//  tier           (bin,  required) — "test" | "og" | "3m" | "6m" | "12m"
//  compound       (bool, required)
//  validator      (bin pk, optional) — enters the 2-epoch validator queue, same
//                 as a later set_validator (not live until it posts)
//  payout_address (bin pk, optional)
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
    let compound = map.require_bool(b"compound", "invalid_compound");
    let (rate_bps, tier_duration) = tier_params(&tier, env.caller_env.entry_epoch);
    //og takes a caller-chosen lock length via `months` (default 0 = immediate
    //maturity); every other tier's duration is fixed and rejects a `months` arg
    let duration_epochs = match map.opt_int(b"months", "invalid_months") {
        Some(_) if tier.as_slice() != b"og" => panic_any("months_not_allowed"),
        Some(m) => {
            let m = u64::try_from(m).unwrap_or_else(|_| panic_any("invalid_months"));
            if m > MAX_OG_LOCK_MONTHS {
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
    //the tier schedule is the floor; unlock_epoch can only extend maturity later
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
        compound,
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

    //the unlock window runs from the moment unlock is queued; per-tier
    vault.unlock_start_epoch = Some(entry_epoch);
    vault.unlock_at_epoch = Some(entry_epoch.saturating_add(unlock_window_epochs(&vault.vault_type)));
    store_vault(env, &key, &vault);
}

pub fn call_withdraw(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 {
        panic_any("invalid_args")
    }
    let (key, vault) = load_caller_vault(env, &args[0]);

    let unlock_at = vault.unlock_at_epoch.unwrap_or_else(|| panic_any("vault_not_unlocking"));
    if env.caller_env.entry_epoch < unlock_at {
        panic_any("vault_is_unlocking")
    }

    let total = vault.amount.checked_add(vault.accrued).unwrap_or_else(|| panic_any("vault_amount_overflow"));
    kv_increment(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":balance:AMA"]), total);
    kv_delete(env, &key);
}

pub fn call_set_compound(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 2 {
        panic_any("invalid_args")
    }
    let (key, mut vault) = load_caller_vault(env, &args[0]);
    if vault.unlock_start_epoch.is_some() {
        panic_any("vault_is_unlocking")
    }
    vault.compound = match args[1].as_slice() {
        b"true" => true,
        b"false" => false,
        _ => panic_any("invalid_compound"),
    };
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
    if vault.unlock_start_epoch.is_some() {
        panic_any("vault_is_unlocking")
    }
    let validator = args[1].as_slice();
    validate_pk(validator, "invalid_validator_pk");
    init_balance_if_missing(env, validator);
    //the validator the vault is already heading toward: the queued one if a change
    //is in flight, otherwise the active one. re-selecting it is a no-op so the
    //2-epoch clock is not reset
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
    if vault.unlock_start_epoch.is_some() {
        panic_any("vault_is_unlocking")
    }
    //if a validator change is still queuing — a queued set to a (necessarily
    //different) validator, or any queue while none is active yet — just drop the
    //queue, reverting to the active validator (or to none). otherwise queue
    //removal of the active validator.
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
