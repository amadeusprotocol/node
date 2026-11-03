#![no_std]

extern crate alloc;

pub mod vecpak;

use alloc::vec;
use alloc::vec::Vec;

pub mod id {
    pub const LOG: u64 = 1;
    pub const RETURN: u64 = 2;
    pub const CALL: u64 = 3;
    pub const KV_PUT: u64 = 4;
    pub const KV_INCREMENT: u64 = 5;
    pub const KV_DELETE: u64 = 6;
    pub const KV_GET: u64 = 7;
    pub const KV_EXISTS: u64 = 8;
    pub const KV_GET_PREV: u64 = 9;
    pub const KV_GET_NEXT: u64 = 10;
    pub const ENV: u64 = 11;
    pub const ARG_COUNT: u64 = 12;
    pub const ARG: u64 = 13;
    pub const FUNCTION: u64 = 14;
    pub const ABORT: u64 = 15;
    pub const SHA256: u64 = 30;
    pub const BLAKE3: u64 = 31;
    pub const KECCAK256: u64 = 32;
    pub const BLS_VERIFY: u64 = 50;
    pub const BLS_AGGREGATE_VERIFY: u64 = 51;
    pub const SECP256K1_RECOVER: u64 = 52;
    pub const SECP256K1_VERIFY: u64 = 53;
    pub const ED25519_VERIFY: u64 = 54;
    pub const EXIT: u64 = 93;
}

pub mod field {
    pub const SEED: u64 = 0;
    pub const ENTRY_SLOT: u64 = 10;
    pub const ENTRY_HEIGHT: u64 = 11;
    pub const ENTRY_EPOCH: u64 = 12;
    pub const ENTRY_SIGNER: u64 = 13;
    pub const ENTRY_PREV_HASH: u64 = 14;
    pub const ENTRY_VR: u64 = 15;
    pub const ENTRY_DR: u64 = 16;
    pub const TX_NONCE: u64 = 30;
    pub const TX_SIGNER: u64 = 31;
    pub const TX_HASH: u64 = 32;
    pub const ACCOUNT_CURRENT: u64 = 50;
    pub const ACCOUNT_CALLER: u64 = 51;
    pub const ACCOUNT_ORIGIN: u64 = 52;
    pub const ATTACHMENTS: u64 = 70;
}

pub const NOT_FOUND: u64 = u64::MAX;

#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub fn syscall(id: u64, a: [u64; 7]) -> u64 {
    let r;
    unsafe {
        core::arch::asm!("ecall", inlateout("a0") a[0] => r, in("a1") a[1], in("a2") a[2], in("a3") a[3], in("a4") a[4], in("a5") a[5], in("a6") a[6], in("a7") id, options(nostack));
    }
    r
}

#[cfg(not(target_arch = "riscv64"))]
pub fn syscall(_id: u64, _a: [u64; 7]) -> u64 {
    unimplemented!("contracts only run on the amadeus riscv vm")
}

fn ptr(b: &[u8]) -> u64 {
    b.as_ptr() as u64
}

fn len(b: &[u8]) -> u64 {
    b.len() as u64
}

fn fetch(small: usize, f: impl Fn(&mut [u8]) -> u64) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; small];
    let n = f(&mut buf);
    if n == NOT_FOUND {
        return None;
    }
    if n as usize > small {
        buf = vec![0u8; n as usize];
        f(&mut buf);
    }
    buf.truncate(n as usize);
    Some(buf)
}

pub fn exit(code: u64) -> ! {
    syscall(id::EXIT, [code, 0, 0, 0, 0, 0, 0]);
    loop {}
}

pub fn ret(value: &[u8]) -> ! {
    syscall(id::RETURN, [ptr(value), len(value), 0, 0, 0, 0, 0]);
    loop {}
}

pub fn abort(msg: &[u8]) -> ! {
    syscall(id::ABORT, [ptr(msg), len(msg), 0, 0, 0, 0, 0]);
    loop {}
}

pub fn log(line: &[u8]) {
    syscall(id::LOG, [ptr(line), len(line), 0, 0, 0, 0, 0]);
}

pub fn function() -> Vec<u8> {
    fetch(64, |b| syscall(id::FUNCTION, [ptr(b), len(b), 0, 0, 0, 0, 0])).unwrap_or_default()
}

pub fn arg_count() -> usize {
    syscall(id::ARG_COUNT, [0; 7]) as usize
}

pub fn arg(i: usize) -> Option<Vec<u8>> {
    fetch(256, |b| syscall(id::ARG, [i as u64, ptr(b), len(b), 0, 0, 0, 0]))
}

pub fn env(f: u64) -> Vec<u8> {
    fetch(128, |b| syscall(id::ENV, [f, ptr(b), len(b), 0, 0, 0, 0])).unwrap_or_default()
}

pub fn env_u64(f: u64) -> u64 {
    let v = env(f);
    let mut le = [0u8; 8];
    le[..v.len().min(8)].copy_from_slice(&v[..v.len().min(8)]);
    u64::from_le_bytes(le)
}

pub const BURN_ADDRESS: [u8; 48] = [0u8; 48];

pub fn account_caller() -> Vec<u8> {
    env(field::ACCOUNT_CALLER)
}

pub fn account_current() -> Vec<u8> {
    env(field::ACCOUNT_CURRENT)
}

pub fn seed() -> Vec<u8> {
    env(field::SEED)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Asset {
    Coin { symbol: Vec<u8>, amount: i128 },
    Nft { collection: Vec<u8>, token: Vec<u8>, amount: i128 },
}

impl Asset {
    pub fn coin(symbol: &[u8], amount: i128) -> Asset {
        Asset::Coin { symbol: symbol.to_vec(), amount }
    }

    pub fn nft(collection: &[u8], token: &[u8], amount: i128) -> Asset {
        Asset::Nft { collection: collection.to_vec(), token: token.to_vec(), amount }
    }
}

pub fn attachments() -> Vec<Asset> {
    let bytes = env(field::ATTACHMENTS);
    if bytes.is_empty() {
        return Vec::new();
    }
    let Ok(vecpak::Term::Map(entries)) = vecpak::decode(&bytes) else { abort(b"bad attachments") };
    let mut assets = Vec::new();
    for (k, v) in entries {
        let vecpak::Term::Binary(key) = k else { abort(b"bad attachments") };
        match v {
            vecpak::Term::Int(amount) => assets.push(Asset::Coin { symbol: key, amount }),
            vecpak::Term::Map(tokens) => {
                for (t, a) in tokens {
                    let (vecpak::Term::Binary(token), vecpak::Term::Int(amount)) = (t, a) else { abort(b"bad attachments") };
                    assets.push(Asset::Nft { collection: key.clone(), token, amount });
                }
            }
            _ => abort(b"bad attachments"),
        }
    }
    assets
}

pub fn encode_attachments(assets: &[Asset]) -> Vec<u8> {
    use vecpak::Term;
    let mut entries: Vec<(Term, Term)> = Vec::new();
    for asset in assets {
        match asset {
            Asset::Coin { symbol, amount } => entries.push((Term::Binary(symbol.clone()), Term::Int(*amount))),
            Asset::Nft { collection, token, amount } => {
                let pair = (Term::Binary(token.clone()), Term::Int(*amount));
                match entries.iter_mut().find(|(k, v)| matches!((k, v), (Term::Binary(k), Term::Map(_)) if k == collection)) {
                    Some((_, Term::Map(tokens))) => tokens.push(pair),
                    _ => entries.push((Term::Binary(collection.clone()), Term::Map(alloc::vec![pair]))),
                }
            }
        }
    }
    vecpak::encode(&Term::Map(entries)).unwrap_or_else(|e| abort(e.as_bytes()))
}

pub fn kv_put(key: &[u8], value: &[u8]) {
    syscall(id::KV_PUT, [ptr(key), len(key), ptr(value), len(value), 0, 0, 0]);
}

pub fn kv_get(key: &[u8]) -> Option<Vec<u8>> {
    fetch(256, |b| syscall(id::KV_GET, [ptr(key), len(key), ptr(b), len(b), 0, 0, 0]))
}

pub fn kv_delete(key: &[u8]) {
    syscall(id::KV_DELETE, [ptr(key), len(key), 0, 0, 0, 0, 0]);
}

pub fn kv_exists(key: &[u8]) -> bool {
    syscall(id::KV_EXISTS, [ptr(key), len(key), 0, 0, 0, 0, 0]) == 1
}

pub fn kv_increment(key: &[u8], delta: i128) -> i128 {
    let mut d = [0u8; 48];
    let delta = itoa(delta, &mut d);
    let mut out = [0u8; 48];
    let n = syscall(id::KV_INCREMENT, [ptr(key), len(key), ptr(delta), len(delta), out.as_mut_ptr() as u64, out.len() as u64, 0]) as usize;
    atoi(&out[..n.min(out.len())])
}

fn split_pair(b: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let kl = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
    let k = b[4..4 + kl].to_vec();
    let v = b[8 + kl..].to_vec();
    (k, v)
}

pub fn kv_get_next(prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    fetch(1024, |b| syscall(id::KV_GET_NEXT, [ptr(prefix), len(prefix), ptr(key), len(key), ptr(b), len(b), 0])).map(split_pair)
}

pub fn kv_get_prev(prefix: &[u8], key: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    fetch(1024, |b| syscall(id::KV_GET_PREV, [ptr(prefix), len(prefix), ptr(key), len(key), ptr(b), len(b), 0])).map(split_pair)
}

pub fn call(contract: &[u8], function: &[u8], args: &[&[u8]], attachments: &[Asset]) -> Vec<u8> {
    let table = |items: &[&[u8]]| {
        let mut t = Vec::with_capacity(1 + 2 * items.len());
        t.push(items.len() as u64);
        for it in items {
            t.push(ptr(it));
            t.push(len(it));
        }
        t
    };
    let mut main: Vec<&[u8]> = vec![contract, function];
    main.extend_from_slice(args);
    let main = table(&main);
    let attached = if attachments.is_empty() { Vec::new() } else { encode_attachments(attachments) };
    let mut out = [0u8; 256];
    let n = syscall(id::CALL, [main.as_ptr() as u64, ptr(&attached), len(&attached), out.as_mut_ptr() as u64, out.len() as u64, 0, 0]) as usize;
    out[..n.min(out.len())].to_vec()
}

fn hash32(id: u64, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    syscall(id, [ptr(data), len(data), out.as_mut_ptr() as u64, 0, 0, 0, 0]);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    hash32(id::SHA256, data)
}

pub fn blake3(data: &[u8]) -> [u8; 32] {
    hash32(id::BLAKE3, data)
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    hash32(id::KECCAK256, data)
}

pub fn bls_verify(pk: &[u8; 48], sig: &[u8; 96], msg: &[u8], dst: &[u8]) -> bool {
    syscall(id::BLS_VERIFY, [pk.as_ptr() as u64, sig.as_ptr() as u64, ptr(msg), len(msg), ptr(dst), len(dst), 0]) == 1
}

pub fn bls_aggregate_verify(pks: &[[u8; 48]], sig: &[u8; 96], msg: &[u8], dst: &[u8]) -> bool {
    syscall(id::BLS_AGGREGATE_VERIFY, [pks.as_ptr() as u64, pks.len() as u64, sig.as_ptr() as u64, ptr(msg), len(msg), ptr(dst), len(dst)]) == 1
}

pub fn secp256k1_recover(hash: &[u8; 32], sig: &[u8; 64], recid: u8) -> Option<[u8; 65]> {
    let mut out = [0u8; 65];
    match syscall(id::SECP256K1_RECOVER, [hash.as_ptr() as u64, sig.as_ptr() as u64, recid as u64, out.as_mut_ptr() as u64, 0, 0, 0]) {
        NOT_FOUND => None,
        _ => Some(out),
    }
}

pub fn secp256k1_verify(pk: &[u8], hash: &[u8; 32], sig: &[u8; 64]) -> bool {
    syscall(id::SECP256K1_VERIFY, [ptr(pk), len(pk), hash.as_ptr() as u64, sig.as_ptr() as u64, 0, 0, 0]) == 1
}

pub fn ed25519_verify(pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool {
    syscall(id::ED25519_VERIFY, [pk.as_ptr() as u64, sig.as_ptr() as u64, ptr(msg), len(msg), 0, 0, 0]) == 1
}

pub fn itoa(v: i128, buf: &mut [u8; 48]) -> &[u8] {
    let neg = v < 0;
    let mut u = v.unsigned_abs();
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    &buf[i..]
}

pub fn parse_int(s: &[u8]) -> Option<i128> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: i128 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        let d = (c - b'0') as i128;
        v = v.checked_mul(10)?;
        v = if neg { v.checked_sub(d)? } else { v.checked_add(d)? };
    }
    Some(v)
}

pub fn atoi(s: &[u8]) -> i128 {
    parse_int(s).unwrap_or_else(|| abort(b"invalid integer"))
}

pub mod heap {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    pub const SIZE: usize = 256 * 1024;

    pub struct Bump {
        heap: UnsafeCell<[u8; SIZE]>,
        next: UnsafeCell<usize>,
        last: UnsafeCell<usize>,
    }

    unsafe impl Sync for Bump {}

    impl Bump {
        pub const fn new() -> Bump {
            Bump { heap: UnsafeCell::new([0; SIZE]), next: UnsafeCell::new(0), last: UnsafeCell::new(0) }
        }
    }

    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let next = &mut *self.next.get();
            let base = self.heap.get() as usize;
            let addr = match base.checked_add(*next).and_then(|a| a.checked_add(layout.align() - 1)) {
                Some(a) => a & !(layout.align() - 1),
                None => return core::ptr::null_mut(),
            };
            let start = addr - base;
            let end = match start.checked_add(layout.size()) {
                Some(end) if end <= SIZE => end,
                _ => return core::ptr::null_mut(),
            };
            *next = end;
            *self.last.get() = start + 1;
            (self.heap.get() as *mut u8).add(start)
        }

        unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
            let offset = ptr as usize - self.heap.get() as usize;
            if offset + 1 == *self.last.get() {
                *self.next.get() = offset;
                *self.last.get() = 0;
            }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let offset = ptr as usize - self.heap.get() as usize;
            if offset + 1 == *self.last.get() {
                if let Some(end) = offset.checked_add(new_size).filter(|&e| e <= SIZE) {
                    *self.next.get() = end;
                    return ptr;
                }
                return core::ptr::null_mut();
            }
            let new = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
            if !new.is_null() {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
            }
            new
        }
    }
}

#[cfg(target_arch = "riscv64")]
#[global_allocator]
static ALLOCATOR: heap::Bump = heap::Bump::new();

#[cfg(target_arch = "riscv64")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    abort(b"panic")
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::alloc::{GlobalAlloc, Layout};

    #[test]
    fn integers_roundtrip_at_the_edges() {
        let mut buf = [0u8; 48];
        for v in [0, 1, -1, 42, i128::MAX, i128::MIN, i128::MIN + 1] {
            assert_eq!(parse_int(itoa(v, &mut buf)), Some(v));
        }
        for bad in [&b""[..], b"-", b"+1", b"1a", b"--1", b"170141183460469231731687303715884105728", b"-170141183460469231731687303715884105729"] {
            assert_eq!(parse_int(bad), None, "{:?}", core::str::from_utf8(bad));
        }
    }

    #[test]
    fn bump_allocator_honours_alignment() {
        let heap = std::boxed::Box::new(heap::Bump::new());
        unsafe {
            for align in [1usize, 2, 8, 16, 64, 4096] {
                let p = heap.alloc(Layout::from_size_align(3, align).unwrap());
                assert!(!p.is_null());
                assert_eq!(p as usize % align, 0, "align {align}");
            }
            let p = heap.alloc(Layout::from_size_align(8, 8).unwrap());
            let q = heap.realloc(p, Layout::from_size_align(8, 8).unwrap(), 64);
            assert_eq!(p, q);
            assert!(heap.alloc(Layout::from_size_align(heap::SIZE, 1).unwrap()).is_null());
        }
    }
}

#[macro_export]
macro_rules! entry {
    ($dispatch:path) => {
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            let f = $crate::function();
            $dispatch(&f);
            $crate::exit(0)
        }
    };
}
