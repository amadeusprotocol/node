#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use amadeus_contract as c;

fn vault_key(symbol: &[u8]) -> Vec<u8> {
    [b"vault:".as_slice(), &c::account_caller(), b":", symbol].concat()
}

fn arg(i: usize) -> Vec<u8> {
    c::arg(i).unwrap_or_else(|| c::abort(b"missing arg"))
}

fn ret_int(v: i128) -> ! {
    let mut buf = [0u8; 48];
    c::ret(c::itoa(v, &mut buf))
}

fn dispatch(f: &[u8]) {
    match f {
        b"balance" => ret_int(c::kv_get(&vault_key(&arg(0))).map_or(0, |v| c::atoi(&v))),
        b"deposit" => {
            let attached = c::attachments();
            if attached.is_empty() {
                c::abort(b"deposit has no attachment");
            }
            let mut last = 0;
            for asset in attached {
                let c::Asset::Coin { symbol, amount } = asset else { c::abort(b"only coins can be deposited") };
                if amount <= 100 {
                    c::abort(b"deposit amount less than 100");
                }
                last = c::kv_increment(&vault_key(&symbol), amount);
            }
            ret_int(last)
        }
        b"withdraw" => {
            let (symbol, amount) = (arg(0), arg(1));
            let amount_int = c::atoi(&amount);
            if amount_int <= 0 {
                c::abort(b"amount lte 0");
            }
            let key = vault_key(&symbol);
            let balance = c::kv_get(&key).map_or(0, |v| c::atoi(&v));
            if balance < amount_int {
                c::abort(b"insufficient funds");
            }
            c::kv_increment(&key, -amount_int);
            c::call(b"Coin", b"transfer", &[&c::account_caller(), &amount, &symbol], &[]);
            ret_int(balance - amount_int)
        }
        b"burn" => {
            let (symbol, amount) = (arg(0), arg(1));
            let amount_int = c::atoi(&amount);
            if amount_int <= 0 {
                c::abort(b"amount lte 0");
            }
            let key = vault_key(&symbol);
            let balance = c::kv_get(&key).map_or(0, |v| c::atoi(&v));
            if balance < amount_int {
                c::abort(b"insufficient funds");
            }
            c::kv_increment(&key, -amount_int);
            c::call(b"Coin", b"transfer", &[&c::BURN_ADDRESS, &amount, &symbol], &[]);
            ret_int(balance - amount_int)
        }
        _ => c::abort(b"unknown function"),
    }
}

c::entry!(dispatch);
