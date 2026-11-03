use crate::bcat;
use crate::consensus::bic::{coin, nft, protocol};
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{exec_budget_decr, kv_delete, kv_increment};
use std::panic::panic_any;
use vecpak::Term;

#[derive(Debug, PartialEq)]
pub enum Asset {
    Coin { symbol: Vec<u8>, amount: i128 },
    Nft { collection: Vec<u8>, token: Vec<u8>, amount: i128 },
}

fn name(t: Term) -> Vec<u8> {
    match t {
        Term::Binary(b) if !b.is_empty() && b.len() <= 32 && b.iter().all(u8::is_ascii_alphanumeric) && !matches!(b.as_slice(), b"true" | b"false" | b"nil") => b,
        _ => panic_any("attachments_invalid_name"),
    }
}

fn amount(t: Term) -> i128 {
    match t {
        Term::VarInt(a) if a > 0 => a,
        _ => panic_any("attachments_invalid_amount"),
    }
}

pub fn decode(env: &mut ApplyEnv, bytes: &[u8]) -> Vec<Asset> {
    exec_budget_decr(env, protocol::ATTACHMENTS_DECODE_BYTE_COST * bytes.len() as i128);
    let Ok(Term::PropList(entries)) = vecpak::decode(bytes) else { panic_any("attachments_invalid") };
    if entries.is_empty() {
        panic_any("attachments_empty")
    }
    let mut assets = Vec::new();
    for (k, v) in entries {
        let key = name(k);
        match v {
            Term::PropList(tokens) if !tokens.is_empty() => {
                for (t, a) in tokens {
                    assets.push(Asset::Nft { collection: key.clone(), token: name(t), amount: amount(a) });
                }
            }
            v => assets.push(Asset::Coin { symbol: key, amount: amount(v) }),
        }
    }
    assets
}

pub fn transfer(env: &mut ApplyEnv, to: &[u8], assets: &[Asset]) {
    let from = env.caller_env.account_caller.clone();
    for asset in assets {
        match asset {
            Asset::Coin { symbol, amount } => {
                if symbol != b"AMA" && !coin::exists(env, symbol) {
                    panic_any("attachments_unknown_coin")
                }
                if *amount > coin::balance(env, &from, symbol) {
                    panic_any("attachments_insufficient_funds")
                }
                if coin::paused(env, symbol) {
                    panic_any("attachments_paused")
                }
                if coin::soulbound(env, symbol) {
                    panic_any("attachments_soulbound")
                }
                kv_increment(env, &bcat(&[b"account:", &from, b":balance:", symbol]), -amount);
                kv_increment(env, &bcat(&[b"account:", to, b":balance:", symbol]), *amount);
            }
            Asset::Nft { collection, token, amount } => {
                if !nft::collection_exists(env, collection) {
                    panic_any("attachments_unknown_collection")
                }
                if !nft::token_exists(env, collection, token) {
                    panic_any("attachments_unknown_token")
                }
                let held = nft::balance(env, &from, collection, token);
                if *amount > held {
                    panic_any("attachments_insufficient_tokens")
                }
                if nft::collection_soulbound(env, collection) || nft::token_soulbound(env, collection, token) {
                    panic_any("attachments_soulbound")
                }
                let sender_key = bcat(&[b"account:", &from, b":nft:", collection, b":", token]);
                if *amount == held && to != from.as_slice() {
                    kv_delete(env, &sender_key);
                } else {
                    kv_increment(env, &sender_key, -amount);
                }
                kv_increment(env, &bcat(&[b"account:", to, b":nft:", collection, b":", token]), *amount);
            }
        }
    }
}
