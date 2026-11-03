#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use amadeus_contract as c;
use c::vecpak::Term;

const COLLECTION: &[u8] = b"AGENTIC";

fn named(pairs: &[(&[u8], &[u8])]) -> Vec<u8> {
    let map = Term::Map(pairs.iter().map(|(k, v)| (Term::Binary(k.to_vec()), Term::Binary(v.to_vec()))).collect());
    c::vecpak::encode(&map).unwrap_or_else(|e| c::abort(e.as_bytes()))
}

fn mint(token: &[u8]) {
    let args = named(&[(b"receiver", &c::account_caller()), (b"amount", b"1"), (b"collection", COLLECTION), (b"token", token), (b"soulbound", b"false")]);
    c::call(b"Nft", b"mint", &[&args], &[]);
}

fn roll_dice() -> u8 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in c::seed() {
        h = (h ^ b as u64).wrapping_mul(0x100_0000_01b3);
    }
    let x = h.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    ((x >> 32) % 6) as u8 + 1
}

fn dispatch(f: &[u8]) {
    match f {
        b"init" => {
            let args = named(&[(b"collection", COLLECTION), (b"soulbound", b"false"), (b"nonfungible", b"false")]);
            c::call(b"Nft", b"create_collection", &[&args], &[]);
        }
        b"view_nft" => {
            let token = c::arg(1).unwrap_or_default();
            let url: &[u8] = match token.as_slice() {
                b"2" => b"ipfs://QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
                b"3" => b"ipfs://QmPZ9gcCEpqKTo6aq61g2nXGUhM4iCL3ewB6LDXZCtioEB",
                b"4" => b"ipfs://QmYjtig7VJQ6XsnUjqqJvj7QaMcCAwtrgNdahSiFofrE7o",
                b"5" => b"ipfs://QmZULkCELmmk5XNfCgTnCyFgAVxBRBXyDHGGMVoLFLiXEN",
                b"6" => b"ipfs://QmTn4KLRkKPDkB3KpJWGXZHPPh5dFnKqNcPjX4ZcbPvKwv",
                _ => b"ipfs://bafybeicn7i3soqdgr7dwnrwytgq4zxy7a5jpkizrvhm5mv6bgjd32wm3q4",
            };
            c::ret(url)
        }
        b"claim" => {
            mint(b"2");
            mint(b"2");
            let token = [b'0' + roll_dice()];
            mint(&token);
            c::ret(&token)
        }
        _ => c::abort(b"unknown function"),
    }
}

c::entry!(dispatch);
