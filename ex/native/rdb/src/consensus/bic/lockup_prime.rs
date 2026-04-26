use std::panic::panic_any;
use crate::{bcat};
use crate::consensus::{bic::{coin::{balance, mint, to_flat}, epoch::TREASURY_DONATION_ADDRESS, lockup::{create_lock}}, consensus_kv::{kv_get, kv_get_next, kv_increment, kv_put, kv_delete}};
use vecpak::{encode, Term};

pub fn call_lock(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if !crate::consensus::bic::coin::exists(env, b"PRIME") {
        kv_increment(env, &bcat(&[b"coin:PRIME:totalSupply"]), 0);

        let mut admin = Vec::new();
        let v0 = &[149, 216, 55, 255, 29, 8, 239, 251, 139, 112, 30, 29, 199, 57, 90, 67, 198, 220, 101, 18, 228, 100, 100, 241, 43, 213, 221, 230, 253, 58, 231, 1, 102, 166, 54, 66, 245, 148, 140, 44, 78, 56, 84, 12, 222, 205, 57, 210];
        admin.push(Term::Binary(v0.to_vec()));
        let term_admins = encode(Term::List(admin));
        kv_put(env, &bcat(&[b"coin:PRIME:permission"]), &term_admins);

        kv_put(env, &bcat(&[b"coin:PRIME:mintable"]), b"true");
        kv_put(env, &bcat(&[b"coin:PRIME:pausable"]), b"true");
        kv_put(env, &bcat(&[b"coin:PRIME:soulbound"]), b"true");
    }

    if args.len() != 2 { panic_any("invalid_args") }
    let amount = args[0].as_slice();
    let amount = std::str::from_utf8(&amount).ok().and_then(|s| s.parse::<i128>().ok()).unwrap_or_else(|| panic_any("invalid_amount"));
    let tier = args[1].as_slice();

    let (tier_epochs, multiplier) = if env.testnet {
        match args.get(1).map(|v| v.as_slice()).unwrap_or_else(|| panic_any("invalid_tier")) {
            b"7d"   => (1, 13),
            b"30d"  => (3, 17),
            b"90d"  => (9, 27),
            b"180d" => (18, 35),
            b"365d" => (36, 54),
            _ => panic_any("invalid_tier"),
        }
    } else {
        match args.get(1).map(|v| v.as_slice()).unwrap_or_else(|| panic_any("invalid_tier")) {
            b"7d"   => (10, 13),
            b"30d"  => (45, 17),
            b"90d"  => (135, 27),
            b"180d" => (270, 35),
            b"365d" => (547, 54),
            _ => panic_any("invalid_tier"),
        }
    };

    if amount <= to_flat(1) { panic_any("lockup_amount_insufficient") }
    if amount > balance(env, &env.caller_env.account_caller.clone(), b"AMA") { panic_any("insufficient_funds") }
    kv_increment(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":balance:AMA"]), -amount);

    let vault_index = kv_increment(env, &bcat(&[b"bic:lockup_prime:unique_index"]), 1);
    let vault_value = bcat(&[
        &tier,
        b"-", multiplier.to_string().as_bytes(),
        b"-", (env.caller_env.entry_epoch.saturating_add(tier_epochs)).to_string().as_bytes(),
        b"-", amount.to_string().as_bytes()]);
    kv_put(env, &bcat(&[b"bic:lockup_prime:vault:", &env.caller_env.account_caller, b":", vault_index.to_string().as_bytes()]), &vault_value);
}

pub fn call_unlock(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    if args.len() != 1 { panic_any("invalid_args") }
    let vault_index = args[0].as_slice();

    let vault_key = &bcat(&[b"bic:lockup_prime:vault:", &env.caller_env.account_caller, b":", vault_index]);

    let vault = kv_get(env, vault_key);
    if vault.is_none() { panic_any("invalid_vault") }
    let vault = vault.unwrap();

    let vault_parts: Vec<Vec<u8>> = vault.split(|&b| b == b'-').map(|seg| seg.to_vec()).collect();
    let tier = vault_parts[0].as_slice();
    let multiplier = vault_parts[1].as_slice();
    let multiplier = std::str::from_utf8(&multiplier).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_multiplier"));
    let unlock_epoch = vault_parts[2].as_slice();
    let unlock_epoch = std::str::from_utf8(&unlock_epoch).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_unlock_epoch"));
    let unlock_amount = vault_parts[3].as_slice();
    let unlock_amount = std::str::from_utf8(&unlock_amount).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_unlock_amount"));

    if env.caller_env.entry_epoch < unlock_epoch {
        let penalty = unlock_amount / 4;
        let disbursement = unlock_amount - penalty;

        kv_increment(env, &bcat(&[b"account:", TREASURY_DONATION_ADDRESS, b":balance:AMA"]), penalty as i128);
        //Lockup for 5 epochs
        let unlock_height = env.caller_env.entry_height.saturating_add(100_000 * 5);
        create_lock(env, env.caller_env.account_caller.to_vec().as_slice(), disbursement as i128, b"AMA", unlock_height);
    } else {
        let prime_points = unlock_amount.checked_mul(multiplier)
            .unwrap_or_else(|| panic_any("prime_points_overflow"));
        mint(env, env.caller_env.account_caller.to_vec().as_slice(), prime_points as i128, b"PRIME");
        kv_increment(env, &bcat(&[b"account:", &env.caller_env.account_caller, b":balance:AMA"]), unlock_amount as i128);
    }

    kv_delete(env, vault_key);
}

pub fn call_daily_checkin(env: &mut crate::consensus::consensus_apply::ApplyEnv, args: Vec<Vec<u8>>) {
    let prefix = bcat(&[b"bic:lockup_prime:vault:", &env.caller_env.account_caller, b":"]);
    let mut cursor: Vec<u8> = Vec::new();
    let mut total_unlock_amount: u64 = 0;
    let mut found_vaults = false;

    while let Some((next_key_suffix, val)) = kv_get_next(env, &prefix, &cursor) {
        found_vaults = true;
        let vault_parts: Vec<Vec<u8>> = val.split(|&b| b == b'-').map(|seg| seg.to_vec()).collect();
        let unlock_amount = vault_parts[3].as_slice();
        let unlock_amount = std::str::from_utf8(&unlock_amount).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_unlock_amount"));
        total_unlock_amount = total_unlock_amount.checked_add(unlock_amount)
            .unwrap_or_else(|| panic_any("total_unlock_amount_overflow"));
        cursor = next_key_suffix;
    }

    if !found_vaults {
        panic_any("no_vaults_found");
    }

    let next_checkin_epoch: u64 = kv_get(env, &bcat(&[b"bic:lockup_prime:next_checkin_epoch:", &env.caller_env.account_caller]))
        .map(|bytes| { std::str::from_utf8(&bytes).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("invalid_next_checkin_epoch")) })
        .unwrap_or(env.caller_env.entry_epoch);
    let delta = (env.caller_env.entry_epoch as i64) - (next_checkin_epoch as i64);
    if delta == 0 || delta == 1 {
        kv_put(env, &bcat(&[b"bic:lockup_prime:next_checkin_epoch:", &env.caller_env.account_caller]), env.caller_env.entry_epoch.saturating_add(2).to_string().as_bytes());

        let daily_bonus = total_unlock_amount / 100;
        mint(env, env.caller_env.account_caller.to_vec().as_slice(), daily_bonus as i128, b"PRIME");

        let streak = kv_increment(env, &bcat(&[b"bic:lockup_prime:daily_streak:", &env.caller_env.account_caller]), 1);
        if streak >= 30 {
            kv_put(env, &bcat(&[b"bic:lockup_prime:daily_streak:", &env.caller_env.account_caller]), b"0");
            let streak_bonus = daily_bonus.checked_mul(30)
                .unwrap_or_else(|| panic_any("streak_bonus_overflow"));
            mint(env, env.caller_env.account_caller.to_vec().as_slice(), streak_bonus as i128, b"PRIME");
        }
    } else if delta > 2 {
        kv_put(env, &bcat(&[b"bic:lockup_prime:next_checkin_epoch:", &env.caller_env.account_caller]), env.caller_env.entry_epoch.saturating_add(2).to_string().as_bytes());
        kv_put(env, &bcat(&[b"bic:lockup_prime:daily_streak:", &env.caller_env.account_caller]), b"1");

        let daily_bonus = total_unlock_amount / 100;
        mint(env, env.caller_env.account_caller.to_vec().as_slice(), daily_bonus as i128, b"PRIME");
    } else {
        //already checked in for the day, 2 epoch window
    }
}
