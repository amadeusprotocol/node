//PRIME: the symbol alone is issued at the boundary into the network's issuance
//epoch (hooked from epoch::next) — admin-mintable, pausable, soulbound. The
//LockupPrime points vault (lockup_prime.rs) is retired and stays testnet-only;
//minting is otherwise exclusive to the admin keys. If testnet already lazily
//created PRIME via LockupPrime, its supply and runtime state are preserved and
//it is made soulbound while its legacy permission list is replaced with the
//canonical admins.

use crate::bcat;
use crate::consensus::consensus_kv::{kv_increment, kv_put};
use vecpak::{encode, Term};

pub const PRIME_ISSUANCE_EPOCH: u64 = 792;
pub const PRIME_ISSUANCE_EPOCH_TESTNET: u64 = 462;

pub fn prime_issuance_epoch(env: &crate::consensus::consensus_apply::ApplyEnv) -> u64 {
    if env.testnet {
        PRIME_ISSUANCE_EPOCH_TESTNET
    } else {
        PRIME_ISSUANCE_EPOCH
    }
}

//69TDon8KJp3vicNeFR3dg5x5sKY8PJFLmoizX3RN31YL4fwr266AVcXgwy1mjCLy6M
//(same key as epoch::TREASURY_DONATION_ADDRESS, kept as explicit bytes so a
//treasury change can never silently rotate the PRIME admin)
pub const PRIME_ADMIN_COLD: [u8; 48] = [
    140, 71, 6, 83, 31, 185, 171, 240, 47, 5, 14, 246, 98, 23, 105, 24, 183, 118, 193, 92, 66, 82, 64, 5, 239, 255, 254, 87, 139, 252, 148, 176, 113, 6, 207,
    153, 51, 25, 202, 45, 48, 153, 223, 248, 219, 210, 80, 254,
];
//5qEya5o5EarWxj1272rhGTcG3PgqaWrFbpcxZRNe3tRt6wftRqtgbZHjA4xc6gihBx
pub const PRIME_ADMIN_HOT: [u8; 48] = [
    131, 183, 200, 195, 76, 135, 56, 133, 18, 200, 137, 227, 188, 238, 231, 39, 141, 224, 211, 62, 241, 139, 105, 5, 129, 17, 238, 228, 153, 43, 112, 17, 28,
    240, 85, 183, 196, 12, 149, 98, 125, 149, 117, 205, 84, 142, 123, 83,
];
//637zrNXKDKB3K8kfKgbUnZF7BTYzL2sH7iCU9PsgAmJRcfjVcZj2Z81FU7ZHfugzbC
pub const PRIME_ADMIN_HOT_2: [u8; 48] = [
    137, 77, 50, 255, 242, 67, 142, 20, 242, 20, 133, 142, 103, 24, 105, 42, 75, 181, 19, 253, 127, 52, 154, 255, 158, 64, 104, 124, 87, 144, 58, 130, 205, 11,
    175, 152, 216, 53, 82, 12, 154, 179, 141, 184, 53, 102, 45, 219,
];

pub fn issue_prime(env: &mut crate::consensus::consensus_apply::ApplyEnv) {
    let exists = crate::consensus::bic::coin::exists(env, b"PRIME");
    if !exists {
        kv_increment(env, &bcat(&[b"coin:PRIME:totalSupply"]), 0);

        kv_put(env, &bcat(&[b"coin:PRIME:mintable"]), b"true");
        kv_put(env, &bcat(&[b"coin:PRIME:pausable"]), b"true");
    }
    if !exists || env.testnet {
        kv_put(env, &bcat(&[b"coin:PRIME:soulbound"]), b"true");
    }

    let mut admins = vec![Term::Binary(PRIME_ADMIN_COLD.to_vec()), Term::Binary(PRIME_ADMIN_HOT.to_vec())];
    if !env.testnet {
        admins.push(Term::Binary(PRIME_ADMIN_HOT_2.to_vec()));
    }
    let encoded = encode(Term::List(admins)).unwrap_or_else(|error| std::panic::panic_any(error));
    kv_put(env, &bcat(&[b"coin:PRIME:permission"]), &encoded);
}
