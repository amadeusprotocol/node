//! Bridge: send coins to remote chains and receive from them, settled by proofs only.
//!
//! - Routes are constants here (add/remove = commit + fork); ADMIN can pause/unpause one.
//! - send: takes the coin, burns the fee, locks (native coin) or burns (wrapped) the rest
//!   and writes `bic:bridge:order:<nonce>`, which the remote contract proves.
//!   The fee is charged only here, on Amadeus: orders from remote chains carry none.
//! - update: advances a remote light client (BSC: Parlia fast finality) and stores the
//!   state root of each finalized block.
//! - receive: proves the remote contract's `orders[nonce] == keccak(order)` against a
//!   stored root, then releases (native) or mints (wrapped) on Amadeus. Once per nonce.
//!   Anyone may deliver: the caller gets the order's gas_drop_fee and pays its gas_drop
//!   (AMA) to the recipient, unless the caller is the recipient (consensus/bridge/order.rs).

use crate::bcat;
use crate::consensus::bic::{coin, protocol};
use crate::consensus::bridge::bsc::{finality, header, keccak256, mpt};
use crate::consensus::bridge::order::{chain_name, Order};
use crate::consensus::consensus_apply::ApplyEnv;
use crate::consensus::consensus_kv::{exec_budget_decr, kv_delete, kv_exists, kv_get, kv_increment, kv_put};
use std::panic::panic_any;

/// holds locked native coins; not a valid BLS key, so nobody can sign for it
pub const ESCROW: [u8; 48] = {
    let mut a = [0u8; 48];
    a[47] = 1;
    a
};
/// may pause/unpause routes, nothing else. set before the bridge fork
pub const ADMIN: [u8; 48] = [0u8; 48];
/// 0.1 bp on sends from Amadeus, burned
pub const FEE_DIVISOR: u128 = 100_000;

pub const COST_BLS_VERIFY: i128 = 500_000;
/// subgroup check of one vote key in a caller-supplied signing header
pub const COST_VOTE_KEY_CHECK: i128 = 20_000;
/// parsing and hashing one header (a tx may spend at most protocol::TX_EXEC_LOCK)
pub const COST_HEADER: i128 = 2_000;
/// headers in one source ancestry
pub const BSC_MAX_ANCESTRY: usize = 256;
/// recovering one header's seal: ~30 headers fit one tx, so seal_update spans several
pub const COST_SEAL_RECOVER: i128 = 50_000;
const BSC_CHAIN_ID: u64 = 56;
const BSC_TESTNET_CHAIN_ID: u64 = 97;
/// a stored set vouches for votes on blocks from its epoch block to this many blocks past it.
/// Bounds only how far one catch-up jumps: stepping one epoch past the stored set always fits,
/// so no amount of time without updates stalls the light client. Votes Amadeus takes while it
/// is current then stay inside BSC's slashing window (SlashIndicator 0x…1001 felonySlashScope
/// 192_000, ~1 day at 0.45 s; a governance value, recheck before mainnet)
pub const BSC_TRUST_PERIOD_BLOCKS: u64 = 128_000;
pub const COST_PROOF_NODE: i128 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// coin lives on Amadeus: locked in ESCROW on send, released on receive
    Native,
    /// coin lives on the remote chain: burned on send, minted on receive
    Wrapped,
}

pub struct Route {
    pub id: &'static [u8],
    /// true: Amadeus -> remote
    pub outbound: bool,
    pub remote_chain: &'static [u8],
    pub local_coin: &'static [u8],
    pub remote_coin: &'static [u8],
    pub kind: Kind,
    /// max `amount` per Amadeus epoch, in the local coin's base units
    pub cap_per_epoch: u128,
}

pub struct Remote {
    pub name: &'static [u8],
    pub address_len: usize,
    /// bridge contract whose `mapping(uint64 => bytes32) orders` we prove
    pub contract: [u8; 20],
    pub orders_slot: u64,
}

const CAP_10M_AMA: u128 = 10_000_000 * 1_000_000_000;

//TODO before the mainnet bridge fork: deployed BSC bridge, wAMA and the trust epoch header
pub const BSC: Remote = Remote { name: b"bsc", address_len: 20, contract: [0u8; 20], orders_slot: 0 };
const BSC_WAMA: [u8; 20] = [0u8; 20];
const BSC_TRUST_EPOCH_HEADER: &[u8] = &[];
pub const ROUTES: &[Route] = &[
    Route { id: b"ama-to-bsc", outbound: true, remote_chain: b"bsc", local_coin: b"AMA", remote_coin: &BSC_WAMA, kind: Kind::Native, cap_per_epoch: CAP_10M_AMA },
    Route { id: b"bsc-to-ama", outbound: false, remote_chain: b"bsc", local_coin: b"AMA", remote_coin: &BSC_WAMA, kind: Kind::Native, cap_per_epoch: CAP_10M_AMA },
];

//BSC testnet (Chapel, chain id 97), contracts in bridge/evm
//AmaBridge 0xbA423F25aa91301761d7cb4C0f63eE769047B884
pub const BSC_TESTNET: Remote = Remote { name: b"bsc", address_len: 20, contract: [0xba, 0x42, 0x3f, 0x25, 0xaa, 0x91, 0x30, 0x17, 0x61, 0xd7, 0xcb, 0x4c, 0x0f, 0x63, 0xee, 0x76, 0x90, 0x47, 0xb8, 0x84], orders_slot: 0 };
//WAMA 0x751D543E23E02BE2b40A0FB1dD36868746d4742e
pub const BSC_TESTNET_WAMA: [u8; 20] = [0x75, 0x1d, 0x54, 0x3e, 0x23, 0xe0, 0x2b, 0xe2, 0xb4, 0x0a, 0x0f, 0xb1, 0xdd, 0x36, 0x86, 0x87, 0x46, 0xd4, 0x74, 0x2e];
//finalized Chapel epoch header (bridge/relayer `init-trust`), re-baked before a deploy
const BSC_TESTNET_TRUST_EPOCH_HEADER: &[u8] = include_bytes!("bsc_testnet_trust_header.bin");
pub const ROUTES_TESTNET: &[Route] = &[
    Route { id: b"ama-to-bsc", outbound: true, remote_chain: b"bsc", local_coin: b"AMA", remote_coin: &BSC_TESTNET_WAMA, kind: Kind::Native, cap_per_epoch: CAP_10M_AMA },
    Route { id: b"bsc-to-ama", outbound: false, remote_chain: b"bsc", local_coin: b"AMA", remote_coin: &BSC_TESTNET_WAMA, kind: Kind::Native, cap_per_epoch: CAP_10M_AMA },
];

fn routes(env: &ApplyEnv) -> &'static [Route] {
    if env.testnet { ROUTES_TESTNET } else { ROUTES }
}

pub fn bsc(env: &ApplyEnv) -> &'static Remote {
    if env.testnet { &BSC_TESTNET } else { &BSC }
}

fn bsc_trust_epoch_header(env: &ApplyEnv) -> &'static [u8] {
    if env.testnet { BSC_TESTNET_TRUST_EPOCH_HEADER } else { BSC_TRUST_EPOCH_HEADER }
}

/// chain name on the wire: testnet networks carry a "-testnet" suffix
pub fn network_name(env: &ApplyEnv, chain: &[u8]) -> Vec<u8> {
    if env.testnet { bcat(&[chain, b"-testnet"]) } else { chain.to_vec() }
}

pub fn local_chain(env: &ApplyEnv) -> [u8; 32] {
    chain_name(&network_name(env, b"amadeus")).unwrap()
}

fn remote(env: &ApplyEnv, name: &[u8]) -> &'static Remote {
    [bsc(env)].into_iter().find(|r| network_name(env, r.name) == name).unwrap_or_else(|| panic_any("bridge_unknown_chain"))
}

fn route(env: &ApplyEnv, outbound: bool, remote_chain: &[u8], local_coin: &[u8], remote_coin: &[u8]) -> &'static Route {
    routes(env).iter()
        .find(|r| r.outbound == outbound && network_name(env, r.remote_chain) == remote_chain && r.local_coin == local_coin && r.remote_coin == remote_coin)
        .unwrap_or_else(|| panic_any("bridge_no_route"))
}

fn check_active(env: &ApplyEnv) {
    if env.caller_env.entry_height < protocol::bridge_forkheight(env) {
        panic_any("bridge_not_active")
    }
}

pub fn fee(amount: u128) -> u128 {
    amount / FEE_DIVISOR
}

fn key_paused(r: &Route) -> Vec<u8> { bcat(&[b"bic:bridge:paused:", r.id]) }
fn key_order(nonce: u64) -> Vec<u8> { bcat(&[b"bic:bridge:order:", format!("{:020}", nonce).as_bytes()]) }
/// per bridge contract: a redeployed remote contract starts its own nonces, no LAST_NONCE needed
fn key_received(chain: &[u8], contract: &[u8], nonce: u64) -> Vec<u8> {
    let hex: String = contract.iter().map(|b| format!("{:02x}", b)).collect();
    bcat(&[b"bic:bridge:received:", chain, b":", hex.as_bytes(), b":", format!("{:020}", nonce).as_bytes()])
}
fn key_root(chain: &[u8], height: u64) -> Vec<u8> { bcat(&[b"bic:bridge:", chain, b":root:", format!("{:020}", height).as_bytes()]) }
const KEY_NONCE: &[u8] = b"bic:bridge:nonce";
const KEY_BSC_SET: &[u8] = b"bic:bridge:bsc:set";
const KEY_BSC_NEXT: &[u8] = b"bic:bridge:bsc:next";
/// every vote key of a set adopted from a finalized epoch header: genuine BSC keys, registered
/// there with a proof of possession, so an aggregate over them cannot hide a rogue key
fn key_bsc_vote_key(k: &[u8; 48]) -> Vec<u8> { bcat(&[b"bic:bridge:bsc:vote_key:", k]) }
/// a seal_update in progress, by its epoch block's hash and who submits it: a fabricated header
/// someone appends only spoils their own candidate
fn key_bsc_seal(e_hash: &[u8; 32], caller: &[u8]) -> Vec<u8> { bcat(&[b"bic:bridge:bsc:seal:", e_hash, b":", caller]) }

/// BSC StakeHub: `mapping(bytes => address) voteToOperator` (slot 69), written only once the
/// owner proved possession of the key's BLS secret
const BSC_STAKE_HUB: [u8; 20] = { let mut a = [0u8; 20]; a[18] = 0x20; a[19] = 0x02; a };
const BSC_VOTE_TO_OPERATOR_SLOT: u64 = 69;

fn balance_key(addr: &[u8], symbol: &[u8]) -> Vec<u8> { bcat(&[b"account:", addr, b":balance:", symbol]) }

fn parse_u128(b: &[u8]) -> u128 {
    std::str::from_utf8(b).ok().and_then(|s| s.parse::<u128>().ok()).unwrap_or_else(|| panic_any("bridge_invalid_number"))
}
fn parse_u64(b: &[u8]) -> u64 {
    std::str::from_utf8(b).ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or_else(|| panic_any("bridge_invalid_number"))
}
fn to_i128(v: u128) -> i128 {
    i128::try_from(v).unwrap_or_else(|_| panic_any("bridge_amount_too_large"))
}

fn check_open(env: &mut ApplyEnv, r: &Route, amount: u128) {
    if kv_exists(env, &key_paused(r)) {
        panic_any("bridge_route_paused")
    }
    let volume_key = bcat(&[b"bic:bridge:volume:", r.id, b":", env.caller_env.entry_epoch.to_string().as_bytes()]);
    if kv_increment(env, &volume_key, to_i128(amount)) > to_i128(r.cap_per_epoch) {
        panic_any("bridge_route_cap_reached")
    }
}

/// send(src_coin, amount, dst_chain, dst_coin, recipient, refund_to, fill_deadline[, gas_drop, gas_drop_fee]).
/// gas_drop (remote native units) and gas_drop_fee (in dst_coin, out of the amount) ask a relay
/// to deliver and fund the recipient's gas; without them the recipient claims it
pub fn call_send(env: &mut ApplyEnv, mut args: Vec<Vec<u8>>) {
    check_active(env);
    let (gas_drop, gas_drop_fee) = match args.len() {
        7 => (0, 0),
        9 => { let fee = args.pop().unwrap(); let drop = args.pop().unwrap(); (parse_u128(&drop), parse_u128(&fee)) }
        _ => panic_any("invalid_args"),
    };
    let [src_coin, amount, dst_chain, dst_coin, recipient, refund_to, fill_deadline] =
        <[Vec<u8>; 7]>::try_from(args).unwrap_or_else(|_| panic_any("invalid_args"));
    let amount = parse_u128(&amount);
    if gas_drop_fee > amount - fee(amount) { panic_any("bridge_gas_drop_fee_too_large") }
    let dst = chain_name(&dst_chain).unwrap_or_else(|| panic_any("bridge_invalid_chain"));
    let r = route(env, true, &dst_chain, &src_coin, &dst_coin);
    if amount == 0 { panic_any("invalid_amount") }
    if recipient.len() != remote(env, &dst_chain).address_len || refund_to.len() > 48 { panic_any("bridge_invalid_address") }
    check_open(env, r, amount);

    let caller = env.caller_env.account_caller.clone();
    let (amount_i, fee_i) = (to_i128(amount), to_i128(fee(amount)));
    if amount_i > coin::balance(env, &caller, &src_coin) { panic_any("insufficient_funds") }
    if coin::paused(env, &src_coin) { panic_any("paused") }
    kv_increment(env, &balance_key(&caller, &src_coin), -amount_i);
    kv_increment(env, &balance_key(&coin::BURN_ADDRESS, &src_coin), fee_i);
    match r.kind {
        Kind::Native => { kv_increment(env, &balance_key(&ESCROW, &src_coin), amount_i - fee_i); }
        Kind::Wrapped => { kv_increment(env, &bcat(&[b"coin:", &src_coin, b":totalSupply"]), -(amount_i - fee_i)); }
    }

    let nonce = kv_increment(env, KEY_NONCE, 1) as u64;
    let order = Order {
        src_chain: local_chain(env),
        nonce,
        sender: caller.clone(),
        refund_to: if refund_to.is_empty() { caller } else { refund_to },
        src_coin,
        amount,
        dst_chain: dst,
        dst_coin,
        recipient,
        output_amount: amount - fee(amount) - gas_drop_fee,
        fill_deadline: parse_u64(&fill_deadline),
        gas_drop,
        gas_drop_fee,
        ..Default::default()
    };
    kv_put(env, &key_order(nonce), &order.pack());
}

fn refs(p: &[Vec<u8>]) -> Vec<&[u8]> {
    p.iter().map(|n| n.as_slice()).collect()
}

fn proof_list(arg: &[u8]) -> Vec<Vec<u8>> {
    match vecpak::decode(arg) {
        Ok(vecpak::Term::List(items)) => items.into_iter().map(|t| match t {
            vecpak::Term::Binary(b) => b,
            _ => panic_any("bridge_invalid_proof"),
        }).collect(),
        _ => panic_any("bridge_invalid_proof"),
    }
}

/// receive(src_chain, height, order, account_proof, storage_proof); proofs are vecpak lists of nodes
pub fn call_receive(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    check_active(env);
    let [src_chain, height, packed, account_proof, storage_proof] =
        <[Vec<u8>; 5]>::try_from(args).unwrap_or_else(|_| panic_any("invalid_args"));
    let remote = remote(env, &src_chain);
    let order = Order::unpack(&packed).unwrap_or_else(|| panic_any("bridge_invalid_order"));
    if order.src_chain != chain_name(&src_chain).unwrap() || order.dst_chain != local_chain(env) { panic_any("bridge_wrong_chain") }
    let r = route(env, false, &src_chain, &order.dst_coin, &order.src_coin);
    if order.output_amount.checked_add(order.gas_drop_fee) != Some(order.amount) { panic_any("bridge_invalid_output_amount") }
    if !(order.exclusive_filler.is_empty() && order.message.is_empty()) { panic_any("bridge_unsupported_order") }
    let received = key_received(&src_chain, &remote.contract, order.nonce);
    if kv_exists(env, &received) { panic_any("bridge_already_received") }

    let root: [u8; 32] = kv_get(env, &key_root(&src_chain, parse_u64(&height)))
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| panic_any("bridge_unknown_root"));
    let (account_proof, storage_proof) = (proof_list(&account_proof), proof_list(&storage_proof));
    exec_budget_decr(env, COST_PROOF_NODE * (account_proof.len() + storage_proof.len()) as i128);
    let account = mpt::verify_account(&root, &remote.contract, &refs(&account_proof))
        .ok().flatten().unwrap_or_else(|| panic_any("bridge_invalid_account_proof"));
    let mut slot_preimage = [0u8; 64];
    slot_preimage[24..32].copy_from_slice(&order.nonce.to_be_bytes());
    slot_preimage[56..64].copy_from_slice(&remote.orders_slot.to_be_bytes());
    let word = mpt::verify_storage(&account.storage_root, &keccak256(&slot_preimage), &refs(&storage_proof))
        .unwrap_or_else(|_| panic_any("bridge_invalid_storage_proof"));
    if word != keccak256(&packed) { panic_any("bridge_order_not_found") }

    check_open(env, r, order.amount);
    //the remote chain cannot check that the recipient is a valid key: the coins go back instead of sticking
    let valid = order.recipient.len() == 48 && crate::consensus::bls12_381::validate_public_key(&order.recipient);
    if !valid && r.kind == Kind::Native {
        refund(env, r, &order, &src_chain);
        kv_put(env, &received, b"");
        return;
    }
    if !valid { panic_any("bridge_invalid_recipient") }
    let (out, tip, total) = (to_i128(order.output_amount), to_i128(order.gas_drop_fee), to_i128(order.amount));
    match r.kind {
        Kind::Native => {
            if coin::balance(env, &ESCROW, r.local_coin) < total { panic_any("bridge_escrow_insufficient") }
            kv_increment(env, &balance_key(&ESCROW, r.local_coin), -total);
        }
        Kind::Wrapped => {
            if !coin::exists(env, r.local_coin) { panic_any("symbol_doesnt_exist") }
            kv_increment(env, &bcat(&[b"coin:", r.local_coin, b":totalSupply"]), total);
        }
    }
    if out > 0 { kv_increment(env, &balance_key(&order.recipient, r.local_coin), out); }
    let caller = env.caller_env.account_caller.clone();
    if tip > 0 { kv_increment(env, &balance_key(&caller, r.local_coin), tip); }
    //a recipient claiming its own order owes itself no gas drop, so no gas_drop can lock an order
    if order.gas_drop > 0 && caller != order.recipient {
        let drop = to_i128(order.gas_drop);
        if coin::balance(env, &caller, b"AMA") < drop { panic_any("bridge_gas_drop_insufficient_funds") }
        kv_increment(env, &balance_key(&caller, b"AMA"), -drop);
        kv_increment(env, &balance_key(&order.recipient, b"AMA"), drop);
    }
    kv_put(env, &received, b"");
}

/// vote_key(chain, height, vote_key, account_proof, storage_proof): learn a BSC vote key from
/// StakeHub's registry at a stored state root, so a set bringing it can be caught up to even if
/// no epoch block announcing it was ever finalized on its own
pub fn call_vote_key(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    check_active(env);
    let [chain, height, key, account_proof, storage_proof] =
        <[Vec<u8>; 5]>::try_from(args).unwrap_or_else(|_| panic_any("invalid_args"));
    if chain != network_name(env, b"bsc") { panic_any("invalid_args") }
    let key: [u8; 48] = key.try_into().unwrap_or_else(|_| panic_any("bridge_invalid_vote_key"));
    let root: [u8; 32] = kv_get(env, &key_root(&chain, parse_u64(&height)))
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| panic_any("bridge_unknown_root"));
    let (account_proof, storage_proof) = (proof_list(&account_proof), proof_list(&storage_proof));
    exec_budget_decr(env, COST_PROOF_NODE * (account_proof.len() + storage_proof.len()) as i128);
    let account = mpt::verify_account(&root, &BSC_STAKE_HUB, &refs(&account_proof))
        .ok().flatten().unwrap_or_else(|| panic_any("bridge_invalid_account_proof"));
    let mut preimage = key.to_vec();
    preimage.extend_from_slice(&[0u8; 24]);
    preimage.extend_from_slice(&BSC_VOTE_TO_OPERATOR_SLOT.to_be_bytes());
    let word = mpt::verify_storage(&account.storage_root, &keccak256(&preimage), &refs(&storage_proof))
        .unwrap_or_else(|_| panic_any("bridge_invalid_storage_proof"));
    if word == [0u8; 32] { panic_any("bridge_vote_key_not_registered") }
    let k = key_bsc_vote_key(&key);
    if !kv_exists(env, &k) { kv_put(env, &k, b""); }
}

/// an inbound native order whose recipient can hold nothing on Amadeus: the deliverer still gets
/// the tip, the rest goes back to the remote chain (refund_to, else the sender) as an outbound
/// order paying the usual fee. The coins never leave ESCROW, so it still backs what the remote
/// chain mints for the refund
fn refund(env: &mut ApplyEnv, inbound: &Route, order: &Order, src_chain: &[u8]) {
    let back = route(env, true, src_chain, inbound.local_coin, inbound.remote_coin);
    //a refund is an outbound order like any other: it waits while that route is paused or capped
    check_open(env, back, order.amount - order.gas_drop_fee);
    let len = remote(env, src_chain).address_len;
    let to = if order.refund_to.len() == len { order.refund_to.clone() } else { order.sender.clone() };
    if to.len() != len { panic_any("bridge_invalid_refund_address") }
    let tip = order.gas_drop_fee;
    let amount = order.amount - tip;
    let (tip_i, fee_i) = (to_i128(tip), to_i128(fee(amount)));
    if coin::balance(env, &ESCROW, inbound.local_coin) < tip_i + fee_i { panic_any("bridge_escrow_insufficient") }
    let caller = env.caller_env.account_caller.clone();
    kv_increment(env, &balance_key(&ESCROW, inbound.local_coin), -(tip_i + fee_i));
    if tip > 0 { kv_increment(env, &balance_key(&caller, inbound.local_coin), tip_i); }
    kv_increment(env, &balance_key(&coin::BURN_ADDRESS, inbound.local_coin), fee_i);
    if amount == 0 { return; }
    let nonce = kv_increment(env, KEY_NONCE, 1) as u64;
    let out = Order {
        src_chain: local_chain(env),
        nonce,
        sender: ESCROW.to_vec(),
        refund_to: ESCROW.to_vec(),
        src_coin: inbound.local_coin.to_vec(),
        amount,
        dst_chain: order.src_chain,
        dst_coin: back.remote_coin.to_vec(),
        recipient: to,
        output_amount: amount - fee(amount),
        ..Default::default()
    };
    kv_put(env, &key_order(nonce), &out.pack());
}

/// seal_update(chain, candidate, headers): the fallback for when fast finality cannot vouch
/// for a set any more (over 1/3 of the stored set stopped voting, then BSC replaced them).
/// Adopts the set an epoch block E announces once headers from E on, parent-linked, were sealed
/// by more than half of the trusted set (pending if any, else current): the rule BSC itself
/// relies on without fast finality. Seals cost too much for one tx, so headers come in parts:
/// candidate "" starts one with headers[0] = E, candidate = E's hash continues it from its last
/// header (GET /api/bridge/remote_seal/<chain>/<E hash>/<caller>). Each caller has its own. Adopts the set only: roots still
/// come only from finality votes, which that set then signs
pub fn call_seal_update(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    check_active(env);
    let [chain, candidate, list] = <[Vec<u8>; 3]>::try_from(args).unwrap_or_else(|_| panic_any("invalid_args"));
    if chain != network_name(env, b"bsc") { panic_any("invalid_args") }
    let raw = proof_list(&list);
    if raw.is_empty() || raw.len() > BSC_MAX_ANCESTRY { panic_any("bridge_invalid_ancestry") }
    exec_budget_decr(env, (COST_HEADER + COST_SEAL_RECOVER) * raw.len() as i128);
    if init_once(env) { return; }
    let caller = env.caller_env.account_caller.clone();
    let headers: Vec<header::Header> = raw.iter().map(|r| header::parse(r).unwrap_or_else(|_| panic_any("bridge_invalid_header"))).collect();
    let last = headers.last().unwrap();
    if finality::verify_ancestry(&headers, &last.hash).is_err() { panic_any("bridge_invalid_ancestry") }

    let current = kv_get(env, KEY_BSC_SET).unwrap_or_else(|| panic_any("bridge_not_initialized"));
    let (epoch, set) = decode_set(&current);
    let next = kv_get(env, KEY_BSC_NEXT).map(|n| decode_set(&n));
    let (trusted_epoch, trusted) = next.as_ref().map(|(e, s)| (*e, s)).unwrap_or((epoch, &set));

    //candidate: trusted epoch u64 | E number u64 | last hash 32 | last number u64 | len u32 | E's set (encode_set) | sealers 20 each
    let (e_hash, e_number, e_set, mut sealers) = if candidate.is_empty() {
        let e = &headers[0];
        if !header::is_epoch_block(e) || e.number <= trusted_epoch { panic_any("bridge_no_epoch_block") }
        check_vouches(trusted_epoch, e.number);
        let (validators, turn) = header::epoch_validators(e).unwrap_or_else(|_| panic_any("bridge_invalid_epoch_header"));
        let adopted = finality::ValidatorSet::new(validators, turn).unwrap_or_else(|_| panic_any("bridge_invalid_validator_set"));
        (e.hash, e.number, encode_set(e.number, &adopted), Vec::<[u8; 20]>::new())
    } else {
        let e_hash: [u8; 32] = candidate.try_into().unwrap_or_else(|_| panic_any("invalid_args"));
        let c = kv_get(env, &key_bsc_seal(&e_hash, &caller)).unwrap_or_else(|| panic_any("bridge_no_seal_candidate"));
        if u64::from_be_bytes(c[..8].try_into().unwrap()) != trusted_epoch { panic_any("bridge_seal_candidate_stale") }
        if headers[0].parent_hash != c[16..48] { panic_any("bridge_invalid_ancestry") }
        let n = u32::from_be_bytes(c[56..60].try_into().unwrap()) as usize;
        let sealers = c[60 + n..].chunks_exact(20).map(|a| a.try_into().unwrap()).collect();
        (e_hash, u64::from_be_bytes(c[8..16].try_into().unwrap()), c[60..60 + n].to_vec(), sealers)
    };

    let chain_id = if env.testnet { BSC_TESTNET_CHAIN_ID } else { BSC_CHAIN_ID };
    for r in &raw {
        let a = header::sealer(r, chain_id).unwrap_or_else(|_| panic_any("bridge_invalid_seal"));
        if trusted.validators.iter().any(|v| v.address == a) && !sealers.contains(&a) { sealers.push(a); }
    }
    if sealers.len() > trusted.validators.len() / 2 {
        kv_delete(env, &key_bsc_seal(&e_hash, &caller));
        let (_, adopted) = decode_set(&e_set);
        kv_put(env, KEY_BSC_NEXT, &e_set);
        remember_vote_keys(env, &adopted);
        return;
    }
    let mut c = trusted_epoch.to_be_bytes().to_vec();
    c.extend_from_slice(&e_number.to_be_bytes());
    c.extend_from_slice(&last.hash);
    c.extend_from_slice(&last.number.to_be_bytes());
    c.extend_from_slice(&(e_set.len() as u32).to_be_bytes());
    c.extend_from_slice(&e_set);
    for a in &sealers { c.extend_from_slice(a); }
    kv_put(env, &key_bsc_seal(&e_hash, &caller), &c);
}

pub fn call_update(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    check_active(env);
    match args.first() {
        Some(chain) if args.len() == 3 && *chain == network_name(env, b"bsc") => update_bsc(env, &args[1], &args[2], None),
        Some(chain) if args.len() == 4 && *chain == network_name(env, b"bsc") => update_bsc(env, &args[1], &args[2], Some(&args[3])),
        _ => panic_any("invalid_args"),
    }
}

//validator set: epoch u64 | turn_length u8 | n * (address 20 | vote key 48), sorted by address
fn encode_set(epoch: u64, set: &finality::ValidatorSet) -> Vec<u8> {
    let mut o = epoch.to_be_bytes().to_vec();
    o.push(set.turn_length);
    for v in &set.validators {
        o.extend_from_slice(&v.address);
        o.extend_from_slice(&v.vote_key);
    }
    o
}

fn decode_set(b: &[u8]) -> (u64, finality::ValidatorSet) {
    let epoch = u64::from_be_bytes(b[..8].try_into().unwrap());
    let validators = b[9..].chunks_exact(68)
        .map(|c| header::Validator { address: c[..20].try_into().unwrap(), vote_key: c[20..].try_into().unwrap() })
        .collect();
    //already validated and sorted when stored
    (epoch, finality::ValidatorSet { validators, turn_length: b[8] })
}

/// the trust anchor: a finalized BSC epoch header, baked in at the bridge fork
pub fn init_bsc(env: &mut ApplyEnv, epoch_header: &[u8]) {
    let h = header::parse(epoch_header).unwrap_or_else(|_| panic_any("bridge_invalid_header"));
    let (validators, turn) = header::epoch_validators(&h).unwrap_or_else(|_| panic_any("bridge_invalid_epoch_header"));
    let set = finality::ValidatorSet::new(validators, turn).unwrap_or_else(|_| panic_any("bridge_invalid_validator_set"));
    kv_put(env, KEY_BSC_SET, &encode_set(h.number, &set));
    remember_vote_keys(env, &set);
    kv_put(env, &key_root(&network_name(env, b"bsc"), h.number), &h.state_root);
}

/// the first light-client call only plants the baked trust anchor: together with the work it
/// was sent for it could pass a tx's exec cap, so that call is repeated (true: it did so)
fn init_once(env: &mut ApplyEnv) -> bool {
    if kv_exists(env, KEY_BSC_SET) { return false }
    let trust = bsc_trust_epoch_header(env);
    if trust.is_empty() { panic_any("bridge_not_initialized") }
    init_bsc(env, trust);
    true
}

fn remember_vote_keys(env: &mut ApplyEnv, set: &finality::ValidatorSet) {
    for v in &set.validators {
        let k = key_bsc_vote_key(&v.vote_key);
        if !kv_exists(env, &k) { kv_put(env, &k, b""); }
    }
}

/// update(chain, attesting_header, source[, signing_epoch_header]); source is the finalized
/// header, or a vecpak list of parent-linked headers ending at it.
/// Without the 4th arg the vote must come from the stored set. With it (a catch-up over any
/// number of epochs) the vote is checked against the set that epoch header announces, which is
/// NOT trusted: every signer's vote key must already be known (adopted from an earlier set, so
/// none is a rogue key) and >= 2/3 of the trusted set (pending if any, else current) must have
/// signed. Either way the target lies between the epoch block of the set vouching for it and
/// BSC_TRUST_PERIOD_BLOCKS past it, never at block numbers that set was not around for. Sets are
/// only ever adopted from the finalized source header, never from the signing header.
fn update_bsc(env: &mut ApplyEnv, attesting: &[u8], source: &[u8], signing_epoch: Option<&[u8]>) {
    let attesting = header::parse(attesting).unwrap_or_else(|_| panic_any("bridge_invalid_header"));
    let att = header::attestation(&attesting).ok().flatten().unwrap_or_else(|| panic_any("bridge_no_attestation"));
    let (number, hash) = finality::finalized(&att).unwrap_or_else(|| panic_any("bridge_not_finalizing"));
    //the source: one header, or a vecpak list of parent-linked headers ending at it, all final
    //with it (BSC finalizes some blocks only through a descendant, epoch blocks included)
    let raw_headers = match vecpak::decode(source) {
        Ok(vecpak::Term::List(items)) => items.into_iter().map(|t| match t {
            vecpak::Term::Binary(b) => b,
            _ => panic_any("bridge_invalid_header"),
        }).collect(),
        _ => vec![source.to_vec()],
    };
    if raw_headers.is_empty() || raw_headers.len() > BSC_MAX_ANCESTRY { panic_any("bridge_invalid_ancestry") }
    exec_budget_decr(env, COST_HEADER * raw_headers.len() as i128);
    let headers: Vec<header::Header> = raw_headers.iter()
        .map(|r| header::parse(r).unwrap_or_else(|_| panic_any("bridge_invalid_header")))
        .collect();
    let source = headers.last().unwrap();
    if source.number != number || source.hash != hash { panic_any("bridge_wrong_source_header") }
    if finality::verify_ancestry(&headers, &hash).is_err() { panic_any("bridge_invalid_ancestry") }
    let target = att.data.target_number;

    if init_once(env) { return; }
    let current = kv_get(env, KEY_BSC_SET).unwrap_or_else(|| panic_any("bridge_not_initialized"));
    let (mut epoch, mut set) = decode_set(&current);
    let mut next = kv_get(env, KEY_BSC_NEXT).map(|n| decode_set(&n));
    //a set announced at an epoch block signs from (epoch block + old set's switch offset)
    if let Some((next_epoch, next_set)) = next.take() {
        if finality::uses_announced_set(target, next_epoch, &set) {
            kv_put(env, KEY_BSC_SET, &encode_set(next_epoch, &next_set));
            kv_delete(env, KEY_BSC_NEXT);
            (epoch, set) = (next_epoch, next_set);
        } else {
            next = Some((next_epoch, next_set));
        }
    }
    exec_budget_decr(env, COST_BLS_VERIFY);
    match signing_epoch {
        None => {
            check_vouches(epoch, target);
            if finality::verify_attestation(&att, &set).is_err() { panic_any("bridge_invalid_attestation") }
        }
        Some(raw) => {
            let h = header::parse(raw).unwrap_or_else(|_| panic_any("bridge_invalid_header"));
            let (validators, turn) = header::epoch_validators(&h).unwrap_or_else(|_| panic_any("bridge_invalid_epoch_header"));
            //the caller picks this header: its keys are checked at the caller's expense
            exec_budget_decr(env, COST_VOTE_KEY_CHECK * validators.len() as i128);
            let signing = finality::ValidatorSet::new(validators, turn).unwrap_or_else(|_| panic_any("bridge_invalid_validator_set"));
            let (trusted_epoch, trusted) = next.as_ref().map(|(e, s)| (*e, s)).unwrap_or((epoch, &set));
            check_vouches(trusted_epoch, target);
            for v in finality::signers(&att, &signing) {
                if !kv_exists(env, &key_bsc_vote_key(&v.vote_key)) { panic_any("bridge_unknown_vote_key") }
            }
            if finality::trusted_signers(&att, &signing, trusted) < trusted.quorum() { panic_any("bridge_not_enough_trusted_signers") }
            if finality::verify_attestation(&att, &signing).is_err() { panic_any("bridge_invalid_attestation") }
        }
    }

    //the first header is the block wanted, the last the one finalized: their roots are stored
    let chain = network_name(env, b"bsc");
    for h in [&headers[0], source] {
        let root = key_root(&chain, h.number);
        if !kv_exists(env, &root) { kv_put(env, &root, &h.state_root); }
    }
    let pending = next.map(|(e, _)| e).unwrap_or(0);
    if let Some(e) = headers.iter().rev().find(|h| header::is_epoch_block(h) && h.number > epoch && h.number > pending) {
        let (validators, turn) = header::epoch_validators(e).unwrap_or_else(|_| panic_any("bridge_invalid_epoch_header"));
        let next = finality::ValidatorSet::new(validators, turn).unwrap_or_else(|_| panic_any("bridge_invalid_validator_set"));
        kv_put(env, KEY_BSC_NEXT, &encode_set(e.number, &next));
        remember_vote_keys(env, &next);
    }
}

fn check_vouches(set_epoch: u64, target: u64) {
    if target <= set_epoch { panic_any("bridge_target_before_set") }
    if target > set_epoch + BSC_TRUST_PERIOD_BLOCKS { panic_any("bridge_trust_period_expired") }
}

/// pause(route_id, "true" | "false"): ADMIN only
pub fn call_pause(env: &mut ApplyEnv, args: Vec<Vec<u8>>) {
    check_active(env);
    let [id, direction] = <[Vec<u8>; 2]>::try_from(args).unwrap_or_else(|_| panic_any("invalid_args"));
    if env.caller_env.account_caller != ADMIN { panic_any("no_permissions") }
    let r = routes(env).iter().find(|r| r.id == id.as_slice()).unwrap_or_else(|| panic_any("bridge_no_route"));
    match direction.as_slice() {
        b"true" => kv_put(env, &key_paused(r), b""),
        b"false" => kv_delete(env, &key_paused(r)),
        _ => panic_any("invalid_direction"),
    }
}
