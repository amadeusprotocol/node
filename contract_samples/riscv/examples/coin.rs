#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use amadeus_contract as c;

const SYMBOL: &[u8] = b"USDFAKE";

fn arg(i: usize) -> Vec<u8> {
    c::arg(i).unwrap_or_else(|| c::abort(b"missing arg"))
}

fn dispatch(f: &[u8]) {
    match f {
        b"init" => {
            let mut buf = [0u8; 48];
            let billion = c::itoa(1_000_000_000 * 1_000_000_000, &mut buf);
            c::call(b"Coin", b"create_and_mint", &[SYMBOL, billion, b"9", b"false", b"false", b"false"], None);
        }
        b"airdrop" => {
            let (to, amount) = (arg(0), arg(1));
            c::call(b"Coin", b"transfer", &[&to, &amount, SYMBOL], None);
        }
        _ => c::abort(b"unknown function"),
    }
}

c::entry!(dispatch);
