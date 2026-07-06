#![cfg(test)]

use crate::bcat;
use crate::consensus::bic::coin::{from_flat, to_flat};
use crate::consensus::bic::lockup_vault::{
    days_to_epochs, months_to_epochs, promote_pending_validators, tier_params, vaults_by_owner, Vault, BONUS_END_EPOCH, MAX_LOCK_MONTHS,
    MIN_VAULT_AMOUNT, UNLOCK_PERIOD_EPOCHS, VALIDATOR_CHANGE_QUEUE_EPOCHS,
};
use crate::consensus::tests::chain_harness::{new_wallet, Chain, Cluster, Wallet};
use vecpak::{encode, Term};

const LV: &[u8] = b"LockupVault";

//build a canonical vecpak tag-7 map blob; encode sorts the keys, so the call
//order here is irrelevant and duplicate keys self-reject at decode
fn vp_map(pairs: Vec<(&[u8], Term)>) -> Vec<u8> {
    let terms: Vec<(Term, Term)> = pairs.into_iter().map(|(k, v)| (Term::Binary(k.to_vec()), v)).collect();
    encode(Term::PropList(terms))
}

fn create_call(chain: &Chain, w: &Wallet, pairs: Vec<(&[u8], Term)>) -> Result<(), String> {
    let blob = vp_map(pairs);
    chain.call(w, LV, b"create", &[&blob])
}

fn create(chain: &Chain, w: &Wallet, amount: i128, tier: &[u8]) -> Result<(), String> {
    create_call(
        chain,
        w,
        vec![
            (b"amount", Term::VarInt(amount)),
            (b"tier", Term::Binary(tier.to_vec())),
        ],
    )
}

fn vault_key(owner: &[u8], index: u64) -> Vec<u8> {
    bcat(&[b"bic:lockup_vault:vault:", owner, b":", index.to_string().as_bytes()])
}

fn get_vault(chain: &Chain, owner: &[u8], index: u64) -> Vault {
    let bytes = chain.get(&vault_key(owner, index)).expect("vault_missing");
    let term = vecpak::decode(&bytes).expect("vault_decode_failed");
    Vault::from_term(&term)
}

fn vault_exists(chain: &Chain, owner: &[u8], index: u64) -> bool {
    chain.get(&vault_key(owner, index)).is_some()
}

//run the epoch-boundary promotion pass exactly as epoch::next2 does first thing,
//posting queued validator changes due by the chain's current epoch
fn promote_due(chain: &Chain) {
    let epoch = chain.epoch();
    chain.with_env(&[0u8; 48], |env| promote_pending_validators(env, epoch));
}

#[test]
fn epoch_math_constants() {
    assert_eq!(UNLOCK_PERIOD_EPOCHS, 37); //21 days
    assert_eq!(months_to_epochs(0), 0);
    assert_eq!(months_to_epochs(3), 156);
    assert_eq!(months_to_epochs(6), 312);
    assert_eq!(months_to_epochs(12), 623);
    assert_eq!(days_to_epochs(0), 0);
    assert_eq!(MIN_VAULT_AMOUNT, to_flat(1000));

    //the full tier table: (apy bps, lock duration in epochs)
    assert_eq!(tier_params(b"og", 0), (0, 0)); //duration is set per-vault via `months`
    assert_eq!(tier_params(b"3m", 0), (500, 156));
    assert_eq!(tier_params(b"6m", 0), (1000, 312));
    assert_eq!(tier_params(b"12m", 0), (2000, 623));

    //the 12m bonus stops applying to vaults created from epoch 1150 on
    assert_eq!(BONUS_END_EPOCH, 1150);
    assert_eq!(tier_params(b"12m", BONUS_END_EPOCH - 1), (2000, 623));
    assert_eq!(tier_params(b"12m", BONUS_END_EPOCH), (1500, 623));
    assert_eq!(tier_params(b"3m", BONUS_END_EPOCH), (500, 156));
}

#[test]
fn bonus_locked_before_cutoff_is_kept_forever() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));

    //created before the cutoff: bonus rate locks in
    create(&chain, &w, to_flat(1000), b"12m").unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).rate_bps, 2000);

    //long past the cutoff the old vault keeps its locked rate, even after writes
    chain.advance_epochs(BONUS_END_EPOCH);
    chain.call(&w, LV, b"clear_payout_address", &[b"1"]).unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).rate_bps, 2000);

    //a fresh 12m vault created from the cutoff on locks the base rate
    create(&chain, &w, to_flat(1000), b"12m").unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 2).rate_bps, 1500);
}

#[test]
fn create_happy_path() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));

    create(&chain, &w, to_flat(1000), b"12m").unwrap();
    assert_eq!(chain.balance(&w.pk), to_flat(4000));

    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.vault_type, b"12m".to_vec());
    assert_eq!(vault.amount, to_flat(1000));
    assert_eq!(vault.accrued, 0);
    assert_eq!(vault.rate_bps, 2000); //15% + 5% bonus, locked in
    assert_eq!(vault.created_epoch, 0);
    assert_eq!(vault.mature_epoch, 623);
    assert_eq!(vault.payout_address, None); //no payout address: yield compounds
    assert_eq!(vault.validator, None);
    assert_eq!(vault.unlock_start_epoch, None);
    assert_eq!(vault.unlock_at_epoch, None);

    //wire format: the type field decodes as the string "12m" for web/js clients
    let raw = chain.get(&vault_key(&w.pk, 1)).unwrap();
    match vecpak::decode(&raw).unwrap() {
        vecpak::Term::PropList(pairs) => {
            let type_value = pairs
                .iter()
                .find(|(k, _)| matches!(k, vecpak::Term::Binary(b) if b.as_slice() == b"type"))
                .map(|(_, v)| v.clone());
            assert_eq!(type_value, Some(vecpak::Term::Binary(b"12m".to_vec())));
        }
        _ => panic!("expected proplist"),
    }
}

#[test]
fn create_enforces_minimum() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));

    let r = create(&chain, &w, to_flat(1000) - 1, b"3m");
    assert_eq!(r, Err("vault_amount_below_minimum".to_string()));
    assert_eq!(chain.balance(&w.pk), to_flat(5000));

    create(&chain, &w, to_flat(1000), b"3m").unwrap();
    assert_eq!(chain.balance(&w.pk), to_flat(4000));
}

#[test]
fn create_insufficient_funds() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(500));

    let r = create(&chain, &w, to_flat(1000), b"3m");
    assert_eq!(r, Err("insufficient_funds".to_string()));
    assert_eq!(chain.balance(&w.pk), to_flat(500));
}

#[test]
fn rates_lock_per_tier() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(10_000));

    create(&chain, &w, to_flat(1000), b"og").unwrap();
    create(&chain, &w, to_flat(1000), b"3m").unwrap();
    create(&chain, &w, to_flat(1000), b"6m").unwrap();
    create(&chain, &w, to_flat(1000), b"12m").unwrap();

    assert_eq!(get_vault(&chain, &w.pk, 1).rate_bps, 0);
    assert_eq!(get_vault(&chain, &w.pk, 2).rate_bps, 500);
    assert_eq!(get_vault(&chain, &w.pk, 3).rate_bps, 1000);
    assert_eq!(get_vault(&chain, &w.pk, 4).rate_bps, 2000);
}

// ---- map-arg strictness ------------------------------------------------------

#[test]
fn create_map_strict_decode() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));

    //unknown key is a hard error
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(b"3m".to_vec())),
                (b"bogus", Term::VarInt(1)),
            ]
        ),
        Err("unknown_arg".to_string())
    );

    //duplicate key: encode sorts the pair adjacent, decode rejects as non-canonical
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"amount", Term::VarInt(to_flat(2000))),
                (b"tier", Term::Binary(b"3m".to_vec())),
            ]
        ),
        Err("invalid_args".to_string())
    );

    //must be exactly one map blob
    assert_eq!(chain.call(&w, LV, b"create", &[]), Err("invalid_args".to_string()));
    let blob = vp_map(vec![(b"amount", Term::VarInt(to_flat(1000)))]);
    assert_eq!(chain.call(&w, LV, b"create", &[&blob, &blob]), Err("invalid_args".to_string()));

    //a non-map term (bare list) is rejected
    let not_map = encode(Term::List(vec![Term::VarInt(1)]));
    assert_eq!(chain.call(&w, LV, b"create", &[&not_map]), Err("invalid_args".to_string()));

    //wrong value types per key
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::Binary(b"1000".to_vec())), //should be VarInt
                (b"tier", Term::Binary(b"3m".to_vec())),
            ]
        ),
        Err("invalid_amount".to_string())
    );
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::VarInt(1)), //should be Binary
            ]
        ),
        Err("invalid_vault_type".to_string())
    );
    //the retired compound key is no longer recognized
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(b"3m".to_vec())),
                (b"compound", Term::Bool(true)),
            ]
        ),
        Err("unknown_arg".to_string())
    );

    //missing required keys
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![(b"tier", Term::Binary(b"3m".to_vec()))]
        ),
        Err("invalid_amount".to_string())
    );

    assert_eq!(chain.balance(&w.pk), to_flat(5000)); //nothing committed
}

#[test]
fn create_amount_bounds() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let try_amount = |v: i128| {
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(v)),
                (b"tier", Term::Binary(b"3m".to_vec())),
            ],
        )
    };

    //zero and negatives land under the minimum (rejected before the debit ever
    //negates the amount)
    let below = Err("vault_amount_below_minimum".to_string());
    assert_eq!(try_amount(0), below);
    assert_eq!(try_amount(-1), below);
    assert_eq!(try_amount(i128::MIN + 1), below); //most-negative representable varint
    assert_eq!(try_amount(MIN_VAULT_AMOUNT - 1), below);

    //i128::MIN itself is not a representable vecpak varint (|MIN| > i128::MAX), so
    //it is rejected at decode and never reaches the amount check
    assert_eq!(try_amount(i128::MIN), Err("invalid_args".to_string()));

    //above balance
    assert_eq!(try_amount(to_flat(99_999)), Err("insufficient_funds".to_string()));

    //exactly the minimum is accepted
    try_amount(MIN_VAULT_AMOUNT).unwrap();
    assert_eq!(chain.balance(&w.pk), to_flat(5000) - MIN_VAULT_AMOUNT);
}

#[test]
fn create_tier_validation() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(10_000));
    let try_tier = |t: &[u8]| {
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(t.to_vec())),
            ],
        )
    };

    //only the canonical tier strings hit; the retired 0m/1m are now invalid
    let bad = Err("invalid_vault_type".to_string());
    for t in [b"" as &[u8], b"0m", b"1m", b"2m", b"0M", b"12M", b"3m ", b"03m", b"12m\x00", b"m"] {
        assert_eq!(try_tier(t), bad, "tier {:?}", t);
    }

    //the live tiers all create (og with no months matures immediately)
    for t in [b"og" as &[u8], b"3m", b"6m", b"12m"] {
        try_tier(t).unwrap();
    }
    assert_eq!(chain.balance(&w.pk), to_flat(10_000) - to_flat(4000));
}

#[test]
fn create_validates_optional_pks() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let v = new_wallet();
    let burn = [0u8; 48];

    //validator, payout, and owner pks are each validated (burn / wrong length)
    let mk = |key: &'static [u8], pk: Vec<u8>| {
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(b"3m".to_vec())),
                (key, Term::Binary(pk)),
            ],
        )
    };
    assert_eq!(mk(b"validator", burn.to_vec()), Err("invalid_validator_pk".to_string()));
    assert_eq!(mk(b"payout_address", v.pk[..47].to_vec()), Err("invalid_payout_pk".to_string()));
    assert_eq!(mk(b"owner", burn.to_vec()), Err("invalid_owner_pk".to_string()));
    assert_eq!(chain.balance(&w.pk), to_flat(5000)); //nothing committed

    //all three together, valid
    let payee = new_wallet();
    let owner = new_wallet();
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"12m".to_vec())),
            (b"validator", Term::Binary(v.pk.to_vec())),
            (b"payout_address", Term::Binary(payee.pk.to_vec())),
            (b"owner", Term::Binary(owner.pk.to_vec())),
        ],
    )
    .unwrap();
    let vault = get_vault(&chain, &owner.pk, 1);
    assert_eq!(vault.validator, None); //queued at creation, not live yet
    assert_eq!(vault.validator_pending, Some(v.pk.to_vec()));
    assert_eq!(vault.validator_for_epoch(0), None);
    assert_eq!(vault.validator_for_epoch(VALIDATOR_CHANGE_QUEUE_EPOCHS), Some(&v.pk.to_vec()));
    assert_eq!(vault.payout_address, Some(payee.pk.to_vec()));
    assert_eq!(chain.balance(&w.pk), to_flat(4000)); //the caller is debited, not the owner
}

// ---- owner / beneficiary -----------------------------------------------------

#[test]
fn create_for_beneficiary_owner() {
    let mut chain = Chain::new();
    let treasury = chain.wallet(to_flat(5000));
    let investor = new_wallet();

    //treasury funds the vault; it is keyed under and controlled by the investor
    create_call(
        &chain,
        &treasury,
        vec![
            (b"amount", Term::VarInt(to_flat(1500))),
            (b"tier", Term::Binary(b"3m".to_vec())),
            (b"owner", Term::Binary(investor.pk.to_vec())),
        ],
    )
    .unwrap();

    //treasury was debited but holds no vault of its own
    assert_eq!(chain.balance(&treasury.pk), to_flat(3500));
    assert!(!vault_exists(&chain, &treasury.pk, 1));
    assert_eq!(get_vault(&chain, &investor.pk, 1).amount, to_flat(1500));

    //the funder cannot touch a vault it does not own
    assert_eq!(chain.call(&treasury, LV, b"unlock", &[b"1"]), Err("invalid_vault".to_string()));
    assert_eq!(chain.call(&treasury, LV, b"extend_lock", &[b"1", b"300"]), Err("invalid_vault".to_string()));

    //the investor controls it; after the 3m schedule + unlock window, withdraw
    //returns the principal to the investor, never to the treasury (no clawback)
    chain.advance_epochs(months_to_epochs(3));
    chain.call(&investor, LV, b"unlock", &[b"1"]).unwrap();
    chain.advance_epochs(UNLOCK_PERIOD_EPOCHS);
    chain.call(&investor, LV, b"withdraw", &[b"1"]).unwrap();
    assert_eq!(chain.balance(&investor.pk), to_flat(1500));
    assert_eq!(chain.balance(&treasury.pk), to_flat(3500));
}

// ---- og tier: zero APY, caller-chosen lock length ----------------------------

#[test]
fn og_tier_custom_lock_owner_and_zero_apy() {
    let mut chain = Chain::new();
    let treasury = chain.wallet(to_flat(5000));
    let investor = new_wallet();

    //og: 0 APY, a caller-chosen 6-month lock, held by a beneficiary
    create_call(
        &chain,
        &treasury,
        vec![
            (b"amount", Term::VarInt(to_flat(2000))),
            (b"tier", Term::Binary(b"og".to_vec())),
            (b"months", Term::VarInt(6)),
            (b"owner", Term::Binary(investor.pk.to_vec())),
        ],
    )
    .unwrap();

    let vault = get_vault(&chain, &investor.pk, 1);
    assert_eq!(vault.vault_type, b"og".to_vec());
    assert_eq!(vault.rate_bps, 0); //0 APY
    assert_eq!(vault.mature_epoch, months_to_epochs(6)); //312, the custom lock
    assert_eq!(chain.balance(&treasury.pk), to_flat(3000)); //funder debited
    assert!(!vault_exists(&chain, &treasury.pk, 1));

    //locked until the custom maturity, then the standard 37 epoch unlock window
    assert_eq!(chain.call(&investor, LV, b"unlock", &[b"1"]), Err("vault_is_locked".to_string()));
    chain.advance_epochs(months_to_epochs(6));
    chain.call(&investor, LV, b"unlock", &[b"1"]).unwrap();
    //og follows UNLOCK_PERIOD_EPOCHS (unlike test's 0 window)
    assert_eq!(get_vault(&chain, &investor.pk, 1).unlock_at_epoch, Some(months_to_epochs(6) + UNLOCK_PERIOD_EPOCHS));
    chain.advance_epochs(UNLOCK_PERIOD_EPOCHS);
    chain.call(&investor, LV, b"withdraw", &[b"1"]).unwrap();
    assert_eq!(chain.balance(&investor.pk), to_flat(2000));
}

#[test]
fn og_defaults_to_immediate_maturity_with_full_window() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));

    //no months => matures immediately (like the retired 0m), 0 APY
    create(&chain, &w, to_flat(1000), b"og").unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.rate_bps, 0);
    assert_eq!(vault.mature_epoch, 0);

    //but it still serves the full UNLOCK_PERIOD_EPOCHS window (not 0 like test)
    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).unlock_at_epoch, Some(UNLOCK_PERIOD_EPOCHS));
    assert_eq!(chain.call(&w, LV, b"withdraw", &[b"1"]), Err("vault_is_unlocking".to_string()));
    chain.advance_epochs(UNLOCK_PERIOD_EPOCHS);
    chain.call(&w, LV, b"withdraw", &[b"1"]).unwrap();
    assert_eq!(chain.balance(&w.pk), to_flat(5000));
}

#[test]
fn months_arg_rejected_off_og_and_validated() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));

    //months is only valid on the og tier
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(b"3m".to_vec())),
                (b"months", Term::VarInt(6)),
            ]
        ),
        Err("months_not_allowed".to_string())
    );

    //negative or non-int months on og are rejected
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(b"og".to_vec())),
                (b"months", Term::VarInt(-1)),
            ]
        ),
        Err("invalid_months".to_string())
    );
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(b"og".to_vec())),
                (b"months", Term::Binary(b"6".to_vec())),
            ]
        ),
        Err("invalid_months".to_string())
    );

    //months beyond the cap is rejected (saturating math keeps it safe either way)
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(b"og".to_vec())),
                (b"months", Term::VarInt(MAX_LOCK_MONTHS as i128 + 1)),
            ]
        ),
        Err("invalid_months".to_string())
    );

    assert_eq!(chain.balance(&w.pk), to_flat(5000)); //nothing committed
}

#[test]
fn og_months_cap_boundary_accepts() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));

    //exactly the cap is accepted and maps to a well-defined (non-overflowing) lock
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"og".to_vec())),
            (b"months", Term::VarInt(MAX_LOCK_MONTHS as i128)),
        ],
    )
    .unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).mature_epoch, months_to_epochs(MAX_LOCK_MONTHS));
}

// ---- unlock_epoch extension --------------------------------------------------

#[test]
fn unlock_epoch_extends_but_never_shortens_maturity() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(10_000));

    //3m tier matures at epoch 156; unlock_epoch pushes maturity out to 200
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"3m".to_vec())),
            (b"unlock_epoch", Term::VarInt(200)),
        ],
    )
    .unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).mature_epoch, 200);

    //an unlock_epoch earlier than the tier schedule is ignored (never shortens):
    //6m matures at 312, the requested 10 is dropped
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"6m".to_vec())),
            (b"unlock_epoch", Term::VarInt(10)),
        ],
    )
    .unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 2).mature_epoch, 312);

    //a non-int unlock_epoch is rejected
    assert_eq!(
        create_call(
            &chain,
            &w,
            vec![
                (b"amount", Term::VarInt(to_flat(1000))),
                (b"tier", Term::Binary(b"3m".to_vec())),
                (b"unlock_epoch", Term::Binary(b"100".to_vec())),
            ]
        ),
        Err("invalid_unlock_epoch".to_string())
    );
}

#[test]
fn unlock_blocked_until_extended_epoch() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));

    //3m normally matures at 156, but unlock_epoch holds it locked to epoch 300
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"3m".to_vec())),
            (b"unlock_epoch", Term::VarInt(300)),
        ],
    )
    .unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).mature_epoch, 300);

    assert_eq!(chain.call(&w, LV, b"unlock", &[b"1"]), Err("vault_is_locked".to_string()));
    chain.advance_epochs(299);
    assert_eq!(chain.call(&w, LV, b"unlock", &[b"1"]), Err("vault_is_locked".to_string()));

    chain.advance_epochs(1); //epoch 300 = extended maturity
    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).unlock_at_epoch, Some(300 + UNLOCK_PERIOD_EPOCHS));
}

// ---- unlock / withdraw -------------------------------------------------------

#[test]
fn unlock_respects_maturity() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    create(&chain, &w, to_flat(1000), b"3m").unwrap();

    assert_eq!(chain.call(&w, LV, b"unlock", &[b"1"]), Err("vault_is_locked".to_string()));

    chain.advance_epochs(155);
    assert_eq!(chain.call(&w, LV, b"unlock", &[b"1"]), Err("vault_is_locked".to_string()));

    chain.advance_epochs(1); //epoch 156 = maturity
    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();

    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.unlock_start_epoch, Some(156));
    assert_eq!(vault.unlock_at_epoch, Some(156 + UNLOCK_PERIOD_EPOCHS));
}

#[test]
fn unlock_window_is_full_regardless_of_hold() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    create(&chain, &w, to_flat(1000), b"3m").unwrap();
    create(&chain, &w, to_flat(1000), b"3m").unwrap();
    chain.advance_epochs(156); //both mature

    //unlocked at maturity: full 37 epoch period from the unlock point
    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).unlock_at_epoch, Some(156 + UNLOCK_PERIOD_EPOCHS));

    //held 100 epochs past maturity: still the full 37 from the unlock point
    chain.advance_epochs(100);
    chain.call(&w, LV, b"unlock", &[b"2"]).unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 2).unlock_at_epoch, Some(256 + UNLOCK_PERIOD_EPOCHS));
}

#[test]
fn unlock_twice_fails() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    create(&chain, &w, to_flat(1000), b"og").unwrap();

    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();
    assert_eq!(chain.call(&w, LV, b"unlock", &[b"1"]), Err("vault_already_unlocking".to_string()));
}

#[test]
fn withdraw_flow() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    create(&chain, &w, to_flat(1500), b"3m").unwrap();
    assert_eq!(chain.balance(&w.pk), to_flat(3500));

    assert_eq!(chain.call(&w, LV, b"withdraw", &[b"1"]), Err("vault_not_unlocking".to_string()));

    chain.advance_epochs(156); //maturity
    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();
    assert_eq!(chain.call(&w, LV, b"withdraw", &[b"1"]), Err("vault_is_unlocking".to_string()));

    chain.advance_epochs(36);
    assert_eq!(chain.call(&w, LV, b"withdraw", &[b"1"]), Err("vault_is_unlocking".to_string()));

    chain.advance_epochs(1); //epoch 193 = unlock_at (156 + 37)
    chain.call(&w, LV, b"withdraw", &[b"1"]).unwrap();
    assert_eq!(chain.balance(&w.pk), to_flat(5000));
    assert!(!vault_exists(&chain, &w.pk, 1));

    assert_eq!(chain.call(&w, LV, b"withdraw", &[b"1"]), Err("invalid_vault".to_string()));
}

#[test]
fn payout_address_lifecycle() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let payee = new_wallet();
    let payee2 = new_wallet();

    //created with an explicit payout address: yield distributes there
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"3m".to_vec())),
            (b"payout_address", Term::Binary(payee.pk.to_vec())),
        ],
    )
    .unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.payout_address, Some(payee.pk.to_vec()));
    assert!(!vault.accrues_to_vault());

    //cleared: yield accrues (compounds) into the vault
    chain.call(&w, LV, b"clear_payout_address", &[b"1"]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.payout_address, None);
    assert!(vault.accrues_to_vault());

    //set/updated again: distributes to the new address
    chain.call(&w, LV, b"set_payout_address", &[b"1", &payee2.pk]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.payout_address, Some(payee2.pk.to_vec()));
    assert!(!vault.accrues_to_vault());

    let junk_pk = [7u8; 48];
    assert_eq!(chain.call(&w, LV, b"set_payout_address", &[b"1", &junk_pk]), Err("invalid_payout_pk".to_string()));
}

// ---- validator queue ---------------------------------------------------------

#[test]
fn set_validator_queues_two_epochs() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let validator = new_wallet();
    create(&chain, &w, to_flat(1000), b"12m").unwrap();

    chain.call(&w, LV, b"set_validator", &[b"1", &validator.pk]).unwrap();

    //pending only: not active until the queue elapses
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, None);
    assert_eq!(vault.validator_pending, Some(validator.pk.to_vec()));
    assert_eq!(vault.validator_pending_epoch, Some(VALIDATOR_CHANGE_QUEUE_EPOCHS));
    assert_eq!(vault.validator_for_epoch(0), None);
    assert_eq!(vault.validator_for_epoch(1), None);
    assert_eq!(vault.validator_for_epoch(2), Some(&validator.pk.to_vec()));

    //the epoch-boundary promotion pass posts the queued validator once due
    chain.advance_epochs(VALIDATOR_CHANGE_QUEUE_EPOCHS);
    promote_due(&chain);
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, Some(validator.pk.to_vec()));
    assert_eq!(vault.validator_pending, None);
    assert_eq!(vault.validator_pending_epoch, None);

    //replacing queues again; the active validator holds until the switch
    let validator2 = new_wallet();
    chain.call(&w, LV, b"set_validator", &[b"1", &validator2.pk]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, Some(validator.pk.to_vec()));
    assert_eq!(vault.validator_for_epoch(chain.epoch()), Some(&validator.pk.to_vec()));
    assert_eq!(vault.validator_for_epoch(chain.epoch() + 1), Some(&validator.pk.to_vec()));
    assert_eq!(vault.validator_for_epoch(chain.epoch() + 2), Some(&validator2.pk.to_vec()));
}

#[test]
fn clear_validator_queues_two_epochs() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let validator = new_wallet();
    create(&chain, &w, to_flat(1000), b"12m").unwrap();

    chain.call(&w, LV, b"set_validator", &[b"1", &validator.pk]).unwrap();
    chain.advance_epochs(VALIDATOR_CHANGE_QUEUE_EPOCHS);
    promote_due(&chain);
    assert_eq!(get_vault(&chain, &w.pk, 1).validator, Some(validator.pk.to_vec()));

    //the clear queues; the active validator holds until the switch
    let clear_epoch = chain.epoch() + VALIDATOR_CHANGE_QUEUE_EPOCHS;
    chain.call(&w, LV, b"clear_validator", &[b"1"]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, Some(validator.pk.to_vec()));
    assert_eq!(vault.validator_pending, None);
    assert_eq!(vault.validator_pending_epoch, Some(clear_epoch));
    assert_eq!(vault.validator_for_epoch(clear_epoch - 1), Some(&validator.pk.to_vec()));
    assert_eq!(vault.validator_for_epoch(clear_epoch), None);

    chain.advance_epochs(VALIDATOR_CHANGE_QUEUE_EPOCHS);
    promote_due(&chain);
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, None);
    assert_eq!(vault.validator_pending, None);
    assert_eq!(vault.validator_pending_epoch, None);
}

#[test]
fn create_validator_enters_queue() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let v = new_wallet();
    let payee = new_wallet();

    //a validator chosen at creation enters the 2-epoch queue, not live at once
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"12m".to_vec())),
            (b"validator", Term::Binary(v.pk.to_vec())),
        ],
    )
    .unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, None);
    assert_eq!(vault.validator_pending, Some(v.pk.to_vec()));
    assert_eq!(vault.validator_pending_epoch, Some(VALIDATOR_CHANGE_QUEUE_EPOCHS)); //created at epoch 0
    assert_eq!(vault.validator_for_epoch(0), None);
    assert_eq!(vault.validator_for_epoch(1), None);
    assert_eq!(vault.validator_for_epoch(2), Some(&v.pk.to_vec()));

    //both optional pks together: validator still queues, payout takes effect now
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"3m".to_vec())),
            (b"validator", Term::Binary(v.pk.to_vec())),
            (b"payout_address", Term::Binary(payee.pk.to_vec())),
        ],
    )
    .unwrap();
    let vault = get_vault(&chain, &w.pk, 2);
    assert_eq!(vault.validator, None);
    assert_eq!(vault.validator_pending, Some(v.pk.to_vec()));
    assert_eq!(vault.payout_address, Some(payee.pk.to_vec()));

    //replacing the still-queued validator resets to the new pending one
    let v2 = new_wallet();
    chain.call(&w, LV, b"set_validator", &[b"1", &v2.pk]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, None);
    assert_eq!(vault.validator_pending, Some(v2.pk.to_vec()));
    assert_eq!(vault.validator_pending_epoch, Some(VALIDATOR_CHANGE_QUEUE_EPOCHS));
}

#[test]
fn set_validator_same_address_is_noop() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let v = new_wallet();
    create(&chain, &w, to_flat(1000), b"12m").unwrap();

    //queue v at epoch 0 -> posts at epoch 2
    chain.call(&w, LV, b"set_validator", &[b"1", &v.pk]).unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).validator_pending_epoch, Some(VALIDATOR_CHANGE_QUEUE_EPOCHS));

    //re-selecting the same queued pk an epoch later does NOT reset the clock
    chain.advance_epochs(1); //epoch 1
    chain.call(&w, LV, b"set_validator", &[b"1", &v.pk]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator_pending, Some(v.pk.to_vec()));
    assert_eq!(vault.validator_pending_epoch, Some(2)); //unchanged, not reset to 1+2

    //a different pk resets the clock to now + 2
    let v2 = new_wallet();
    chain.call(&w, LV, b"set_validator", &[b"1", &v2.pk]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator_pending, Some(v2.pk.to_vec()));
    assert_eq!(vault.validator_pending_epoch, Some(1 + VALIDATOR_CHANGE_QUEUE_EPOCHS)); //epoch 1 + 2

    //promote, then re-selecting the now-ACTIVE validator is also a no-op
    chain.advance_epochs(VALIDATOR_CHANGE_QUEUE_EPOCHS); //epoch 3, v2 due
    promote_due(&chain); //boundary pass posts v2
    assert_eq!(get_vault(&chain, &w.pk, 1).validator, Some(v2.pk.to_vec()));
    chain.call(&w, LV, b"set_validator", &[b"1", &v2.pk]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, Some(v2.pk.to_vec()));
    assert_eq!(vault.validator_pending, None);
    assert_eq!(vault.validator_pending_epoch, None); //no fresh queue created
}

#[test]
fn clear_validator_while_queuing_cancels_the_queue() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let v = new_wallet();
    let v2 = new_wallet();

    //create with a queued validator (none active yet); clear drops the queue
    create_call(
        &chain,
        &w,
        vec![
            (b"amount", Term::VarInt(to_flat(1000))),
            (b"tier", Term::Binary(b"12m".to_vec())),
            (b"validator", Term::Binary(v.pk.to_vec())),
        ],
    )
    .unwrap();
    assert_eq!(get_vault(&chain, &w.pk, 1).validator_pending, Some(v.pk.to_vec()));

    chain.call(&w, LV, b"clear_validator", &[b"1"]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, None);
    assert_eq!(vault.validator_pending, None);
    assert_eq!(vault.validator_pending_epoch, None);
    assert_eq!(vault.validator_for_epoch(VALIDATOR_CHANGE_QUEUE_EPOCHS), None); //never posts

    //promote v, then queue a switch to v2; clearing cancels the switch, v stays
    chain.call(&w, LV, b"set_validator", &[b"1", &v.pk]).unwrap();
    chain.advance_epochs(VALIDATOR_CHANGE_QUEUE_EPOCHS);
    promote_due(&chain); //boundary pass posts v
    assert_eq!(get_vault(&chain, &w.pk, 1).validator, Some(v.pk.to_vec()));

    chain.call(&w, LV, b"set_validator", &[b"1", &v2.pk]).unwrap(); //queue switch to v2
    assert_eq!(get_vault(&chain, &w.pk, 1).validator_pending, Some(v2.pk.to_vec()));
    chain.call(&w, LV, b"clear_validator", &[b"1"]).unwrap(); //drop the queued switch
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.validator, Some(v.pk.to_vec())); //reverted to the active v
    assert_eq!(vault.validator_pending, None);
    assert_eq!(vault.validator_pending_epoch, None);
}

#[test]
fn unlocking_vault_rejects_all_mutations() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    let validator = new_wallet();
    create(&chain, &w, to_flat(1000), b"og").unwrap();

    let junk_pk = [7u8; 48];
    assert_eq!(chain.call(&w, LV, b"set_validator", &[b"1", &junk_pk]), Err("invalid_validator_pk".to_string()));
    assert_eq!(chain.call(&w, LV, b"set_validator", &[b"1", b"short"]), Err("invalid_validator_pk".to_string()));

    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();
    let unlocking = Err("vault_is_unlocking".to_string());
    assert_eq!(chain.call(&w, LV, b"set_validator", &[b"1", &validator.pk]), unlocking);
    assert_eq!(chain.call(&w, LV, b"clear_validator", &[b"1"]), unlocking);
    assert_eq!(chain.call(&w, LV, b"set_payout_address", &[b"1", &validator.pk]), unlocking);
    assert_eq!(chain.call(&w, LV, b"clear_payout_address", &[b"1"]), unlocking);
    assert_eq!(chain.call(&w, LV, b"change_owner", &[b"1", &validator.pk]), unlocking);
    assert_eq!(chain.call(&w, LV, b"extend_lock", &[b"1", b"300"]), unlocking);
}

#[test]
fn vaults_are_owner_scoped() {
    let chain = Chain::new();
    let alice = chain.wallet(to_flat(5000));
    let mallory = chain.wallet(to_flat(5000));
    create(&chain, &alice, to_flat(1000), b"3m").unwrap();

    assert_eq!(chain.call(&mallory, LV, b"unlock", &[b"1"]), Err("invalid_vault".to_string()));
    assert_eq!(chain.call(&mallory, LV, b"withdraw", &[b"1"]), Err("invalid_vault".to_string()));
    assert_eq!(chain.call(&mallory, LV, b"extend_lock", &[b"1", b"300"]), Err("invalid_vault".to_string()));
}

#[test]
fn rate_stays_locked_past_maturity_and_through_unlock() {
    let mut chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    create(&chain, &w, to_flat(1000), b"12m").unwrap();

    //long past maturity (epoch 623) the locked rate is untouched
    chain.advance_epochs(1000);
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.mature_epoch, 623);
    assert_eq!(vault.rate_bps, 2000);

    //queueing the unlock keeps the locked rate; the vault keeps earning per
    //pay_epoch_yield until it is withdrawn
    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();
    let vault = get_vault(&chain, &w.pk, 1);
    assert_eq!(vault.unlock_start_epoch, Some(1000));
    assert_eq!(vault.unlock_at_epoch, Some(1000 + UNLOCK_PERIOD_EPOCHS));
    assert_eq!(vault.rate_bps, 2000);
}

#[test]
fn vaults_by_owner_prefix_scan() {
    let chain = Chain::new();
    let alice = chain.wallet(to_flat(10_000));
    let bob = chain.wallet(to_flat(5000));

    create(&chain, &alice, to_flat(1000), b"3m").unwrap();
    create(&chain, &alice, to_flat(1100), b"3m").unwrap();
    create(&chain, &alice, to_flat(1200), b"12m").unwrap();
    create(&chain, &bob, to_flat(1300), b"6m").unwrap();

    let alice_vaults = chain.with_env(&alice.pk, |env| vaults_by_owner(env, &alice.pk));
    assert_eq!(alice_vaults.len(), 3);
    assert_eq!(alice_vaults[0].0, b"1".to_vec());
    assert_eq!(alice_vaults[0].1.amount, to_flat(1000));
    assert_eq!(alice_vaults[1].0, b"2".to_vec());
    assert_eq!(alice_vaults[1].1.amount, to_flat(1100));
    assert_eq!(alice_vaults[2].0, b"3".to_vec());
    assert_eq!(alice_vaults[2].1.rate_bps, 2000);

    //the global index counter keeps bob's vault at 4, scoped under his own pk
    let bob_vaults = chain.with_env(&bob.pk, |env| vaults_by_owner(env, &bob.pk));
    assert_eq!(bob_vaults.len(), 1);
    assert_eq!(bob_vaults[0].0, b"4".to_vec());
    assert_eq!(bob_vaults[0].1.vault_type, b"6m".to_vec());

    let stranger = new_wallet();
    let none = chain.with_env(&stranger.pk, |env| vaults_by_owner(env, &stranger.pk));
    assert!(none.is_empty());
}

#[test]
fn failed_tx_leaves_state_untouched() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    create(&chain, &w, to_flat(1000), b"3m").unwrap();

    let before = chain.state_digest();
    assert!(chain.call(&w, LV, b"unlock", &[b"1"]).is_err());
    assert!(create(&chain, &w, to_flat(9999), b"3m").is_err());
    assert!(chain.call(&w, LV, b"extend_lock", &[b"1", b"maybe"]).is_err());
    assert_eq!(chain.state_digest(), before);
}

#[test]
fn audit_index_args_and_unknown_function() {
    let chain = Chain::new();
    let w = chain.wallet(to_flat(5000));
    create(&chain, &w, to_flat(1000), b"og").unwrap();

    //only the canonical decimal index hits; alias spellings miss
    let invalid_vault = Err("invalid_vault".to_string());
    for idx in [b"01" as &[u8], b"+1", b" 1", b"1 ", b"", b"0", b"2", b"-1", b"1\x00", b"99999999999999999999"] {
        assert_eq!(chain.call(&w, LV, b"unlock", &[idx]), invalid_vault, "index {:?}", idx);
    }

    //arg count strictness on every function
    let invalid_args = Err("invalid_args".to_string());
    assert_eq!(chain.call(&w, LV, b"unlock", &[]), invalid_args);
    assert_eq!(chain.call(&w, LV, b"unlock", &[b"1", b"1"]), invalid_args);
    assert_eq!(chain.call(&w, LV, b"withdraw", &[]), invalid_args);
    assert_eq!(chain.call(&w, LV, b"set_payout_address", &[b"1"]), invalid_args);
    assert_eq!(chain.call(&w, LV, b"extend_lock", &[b"1"]), invalid_args);
    assert_eq!(chain.call(&w, LV, b"change_owner", &[b"1"]), invalid_args);
    assert_eq!(chain.call(&w, LV, b"clear_payout_address", &[]), invalid_args);
    assert_eq!(chain.call(&w, LV, b"set_validator", &[b"1"]), invalid_args);
    assert_eq!(chain.call(&w, LV, b"clear_validator", &[b"1", b"x"]), invalid_args);

    //pk length strictness on the setters
    let v = new_wallet();
    let burn = [0u8; 48];
    assert_eq!(chain.call(&w, LV, b"set_payout_address", &[b"1", &v.pk[..47]]), Err("invalid_payout_pk".to_string()));
    assert_eq!(chain.call(&w, LV, b"set_payout_address", &[b"1", &burn]), Err("invalid_payout_pk".to_string()));
    assert_eq!(chain.call(&w, LV, b"set_validator", &[b"1", &burn]), Err("invalid_validator_pk".to_string()));

    //unknown functions fall through dispatch, including the retired set_compound
    assert_eq!(chain.call(&w, LV, b"steal", &[b"1"]), Err("invalid_bic_action".to_string()));
    assert_eq!(chain.call(&w, LV, b"set_compound", &[b"1", b"true"]), Err("invalid_bic_action".to_string()));

    //the vault survived every failure above and still works
    chain.call(&w, LV, b"unlock", &[b"1"]).unwrap();
}

#[test]
fn full_lifecycle_replay() {
    let mut chain = Chain::new();
    let alice = chain.wallet(to_flat(10_000));
    let bob = chain.wallet(to_flat(2_000));
    let payee = new_wallet();

    create(&chain, &alice, to_flat(5000), b"12m").unwrap();
    create_call(
        &chain,
        &bob,
        vec![
            (b"amount", Term::VarInt(to_flat(1500))),
            (b"tier", Term::Binary(b"3m".to_vec())),
            (b"payout_address", Term::Binary(payee.pk.to_vec())),
        ],
    )
    .unwrap();
    assert_eq!(chain.balance(&alice.pk), to_flat(5000));
    assert_eq!(chain.balance(&bob.pk), to_flat(500));

    //bob exits: 3m vault matures at 156, then the 37 epoch unlock window
    chain.advance_epochs(156);
    chain.call(&bob, LV, b"unlock", &[b"2"]).unwrap();
    chain.advance_epochs(37);
    chain.call(&bob, LV, b"withdraw", &[b"2"]).unwrap();
    assert_eq!(chain.balance(&bob.pk), to_flat(2_000));

    //alice still locked at epoch 193
    assert_eq!(chain.call(&alice, LV, b"unlock", &[b"1"]), Err("vault_is_locked".to_string()));

    //matures at 623, exits after the 21 day queue
    chain.advance_epochs(623 - 193);
    chain.call(&alice, LV, b"unlock", &[b"1"]).unwrap();
    chain.advance_epochs(37);
    chain.call(&alice, LV, b"withdraw", &[b"1"]).unwrap();
    assert_eq!(chain.balance(&alice.pk), to_flat(10_000));

    assert!(!vault_exists(&chain, &alice.pk, 1));
    assert!(!vault_exists(&chain, &bob.pk, 2));
}

#[test]
fn cluster_of_validators_stays_in_sync() {
    //5 nodes stepping 10-block epochs over the same tx stream
    let mut cluster = Cluster::new(5, 10);
    let validators: Vec<Wallet> = (0..5).map(|_| new_wallet()).collect();
    for v in &validators {
        cluster.fund(&v.pk, to_flat(50_000));
    }
    cluster.assert_in_sync();

    //even validators take the instant-maturity og tier, odd ones a 12m lock
    for (i, v) in validators.iter().enumerate() {
        let tier: &[u8] = if i % 2 == 0 { b"og" } else { b"12m" };
        let blob = vp_map(vec![
            (b"amount", Term::VarInt(to_flat(1000 + i as i128 * 100))),
            (b"tier", Term::Binary(tier.to_vec())),
        ]);
        cluster.call_as(&v.pk, LV, b"create", &[&blob]).unwrap();
        cluster.advance_blocks(3);
    }
    cluster.assert_in_sync();

    //vaults secure each validator's own key, queued for the next epoch
    for (i, v) in validators.iter().enumerate() {
        cluster.call_as(&v.pk, LV, b"set_validator", &[(i + 1).to_string().as_bytes(), &v.pk]).unwrap();
    }
    cluster.assert_in_sync();

    //failed txs must fail identically everywhere
    assert_eq!(cluster.call_as(&validators[0].pk, LV, b"unlock", &[b"99"]), Err("invalid_vault".to_string()));
    cluster.assert_in_sync();

    //step past maturity; the og holders queue exits
    cluster.advance_epochs(10);
    cluster.call_as(&validators[0].pk, LV, b"unlock", &[b"1"]).unwrap();
    cluster.call_as(&validators[2].pk, LV, b"unlock", &[b"3"]).unwrap();
    cluster.assert_in_sync();

    cluster.advance_epochs(UNLOCK_PERIOD_EPOCHS); //serve the full unlock window, then withdraw vault 1
    cluster.call_as(&validators[0].pk, LV, b"withdraw", &[b"1"]).unwrap();
    cluster.assert_in_sync();

    let final_digest = cluster.nodes[0].state_digest();
    for node in &cluster.nodes[1..] {
        assert_eq!(node.state_digest(), final_digest);
    }
}

//end-to-end emission snapshot: the real epoch::next2 boundary at epoch 751 with
//100m AMA staked across 100 vaults at 20% APY, at net phash 1, 5, and 50.
//prints the full money flow; run with --nocapture to see it.
#[test]
fn epoch_751_emission_scenarios_100m_stake() {
    use crate::consensus::bic::epoch::{emission2_total, next2, SOLVER_ACCRUED_POOL_KEY, TREASURY_DONATION_ADDRESS, VAULT_ACCRUED_POOL_KEY};

    for &target_phash in &[1i128, 5, 50] {
        let mut chain = Chain::new();
        let creator = chain.wallet(to_flat(200_000_000));
        let payee = new_wallet();
        let validator = new_wallet();
        let solver = new_wallet();

        //100 vaults x 1m AMA, 12m tier (locks 2000 bps = 20% pre-1150), yield
        //distributes to payee, all backing `validator`
        for _ in 0..100 {
            create_call(
                &chain,
                &creator,
                vec![
                    (b"amount", Term::VarInt(to_flat(1_000_000))),
                    (b"tier", Term::Binary(b"12m".to_vec())),
                    (b"payout_address", Term::Binary(payee.pk.to_vec())),
                    (b"validator", Term::Binary(validator.pk.to_vec())),
                ],
            )
            .unwrap();
        }

        //epoch's validator set: the vault-backed validator plus the solver
        let set = crate::consensus::bic::list_of_binaries_to_vecpak(vec![validator.pk.to_vec(), solver.pk.to_vec()]);
        chain.put(&bcat(&[b"bic:epoch:validators:height:", format!("{:012}", 0).as_bytes()]), &set);
        chain.put(b"bic:epoch:diff_bits", b"24");

        //sol count that lands net phash exactly on target at the 751 boundary
        //(phash = sols * 2^diff_bits * OPS / ((height_in_epoch + 2) * 5e14), floored)
        let per_sol: i128 = (1i128 << 24) * 25_722_880;
        let denom: i128 = (99_999 + 2) * 500_000_000_000_000;
        let sols = target_phash * denom / per_sol + 1;
        chain.put(&bcat(&[b"bic:epoch:solutions_count:", &solver.pk]), sols.to_string().as_bytes());

        //run the real epoch 751 boundary
        chain.advance_epochs(751);
        chain.advance_blocks(99_999);
        chain.with_env(&[0u8; 48], |env| next2(env));

        let total = emission2_total(751);
        let vault_paid = chain.balance(&payee.pk);
        let solver_paid = chain.balance(&solver.pk);
        let treasury = chain.balance(TREASURY_DONATION_ADDRESS.as_slice());
        let vault_pool = chain.get(VAULT_ACCRUED_POOL_KEY).and_then(|v| atoi::atoi::<i128>(&v)).unwrap_or(0);
        let solver_pool = chain.get(SOLVER_ACCRUED_POOL_KEY).and_then(|v| atoi::atoi::<i128>(&v)).unwrap_or(0);

        println!("=== epoch 751 boundary, net phash {} ===", target_phash);
        println!("  total emission curve: {:>12.3} AMA", from_flat(total));
        println!("  vault half:           {:>12.3} AMA", from_flat(total / 2));
        println!("  solver half:          {:>12.3} AMA", from_flat(total - total / 2));
        println!("  vault APY paid:       {:>12.3} AMA (100m at 20%, phash-independent until epoch 1150)", from_flat(vault_paid));
        println!("  solver paid:          {:>12.3} AMA ({}% participation)", from_flat(solver_paid), target_phash.min(100));
        println!("  treasury tax (25%):   {:>12.3} AMA", from_flat(treasury));
        println!("  vault pool carry:     {:>12.3} AMA", from_flat(vault_pool));
        println!("  solver pool carry:    {:>12.3} AMA", from_flat(solver_pool));
        println!("  minted this epoch:    {:>12.3} AMA (paid + tax; pools stay unminted)", from_flat(vault_paid + solver_paid + treasury));

        //conservation: paid + tax + carried pools == the emission curve, exactly
        assert_eq!(vault_paid + solver_paid + treasury + vault_pool + solver_pool, total);
    }
}
