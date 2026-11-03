#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use amadeus_contract as c;

fn arg(i: usize) -> Vec<u8> {
    c::arg(i).unwrap_or_else(|| c::abort(b"missing arg"))
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().unwrap_or_else(|_| c::abort(b"bad length"))
}

fn dispatch(f: &[u8]) {
    match f {
        b"echo" => {
            c::log(f);
            for i in 0..c::arg_count() {
                c::log(&arg(i));
            }
            assert!(c::arg(c::arg_count()).is_none());
        }
        b"env" => {
            for fld in [c::field::SEED, c::field::ENTRY_HEIGHT, c::field::TX_SIGNER, c::field::ACCOUNT_CURRENT, c::field::ACCOUNT_CALLER, c::field::ACCOUNT_ORIGIN, c::field::ATTACHMENTS] {
                c::log(&c::env(fld));
            }
        }
        b"storage" => {
            c::kv_put(b"k:a", b"1");
            c::kv_put(b"k:b", b"22");
            c::kv_put(b"k:c", b"333");
            c::kv_delete(b"k:b");
            c::log(&[c::kv_exists(b"k:a") as u8, c::kv_exists(b"k:b") as u8]);
            c::log(&c::kv_get(b"k:c").unwrap());
            let (k, v) = c::kv_get_next(b"k:", b"a").unwrap();
            c::log(&[k, v].concat());
            let (k, v) = c::kv_get_prev(b"k:", b"z").unwrap();
            c::log(&[k, v].concat());
            assert!(c::kv_get(b"k:b").is_none());
            let mut buf = [0u8; 48];
            c::log(c::itoa(c::kv_increment(b"n", -5), &mut buf));
        }
        b"fill" => {
            let count = c::atoi(&arg(0)) as usize;
            let value = alloc::vec![0xa5u8; c::atoi(&arg(1)) as usize];
            let tag = arg(2);
            let mut buf = [0u8; 48];
            for i in 0..count {
                c::kv_put(&[b"f:", &tag[..], b":", c::itoa(i as i128, &mut buf)].concat(), &value);
            }
        }
        b"deep" => {
            let n = c::atoi(&arg(0));
            if n > 0 {
                let mut buf = [0u8; 48];
                c::call(&c::account_current(), b"deep", &[c::itoa(n - 1, &mut buf)], &[]);
            }
        }
        b"next" => c::ret(if c::kv_get_next(&arg(0), &arg(1)).is_some() { b"1" } else { b"0" }),
        b"hostloop" => {
            for _ in 0..c::atoi(&arg(0)) {
                core::hint::black_box(c::arg_count());
            }
        }
        b"callloop" => {
            let contract = arg(1);
            for _ in 0..c::atoi(&arg(0)) {
                core::hint::black_box(c::call(&contract, b"run", &[], &[]));
            }
        }
        b"hashes" => {
            let data = arg(0);
            c::log(&c::sha256(&data));
            c::log(&c::keccak256(&data));
            c::log(&c::blake3(&data));
        }
        b"bls" => {
            let ok = c::bls_verify(&arr(&arg(0)), &arr(&arg(1)), &arg(2), &arg(3));
            c::ret(if ok { b"1" } else { b"0" });
        }
        b"bls_agg" => {
            let pks: Vec<[u8; 48]> = arg(0).chunks(48).map(arr).collect();
            let ok = c::bls_aggregate_verify(&pks, &arr(&arg(1)), &arg(2), &arg(3));
            c::ret(if ok { b"1" } else { b"0" });
        }
        b"secp" => {
            let (hash, sig, recid) = (arr(&arg(0)), arr(&arg(1)), arg(2)[0]);
            match c::secp256k1_recover(&hash, &sig, recid) {
                Some(pk) => {
                    c::log(&pk);
                    c::ret(if c::secp256k1_verify(&pk, &hash, &sig) { b"1" } else { b"0" });
                }
                None => c::ret(b"none"),
            }
        }
        b"ed25519" => {
            let ok = c::ed25519_verify(&arr(&arg(0)), &arr(&arg(1)), &arg(2));
            c::ret(if ok { b"1" } else { b"0" });
        }
        b"call" => {
            let (contract, function) = (arg(0), arg(1));
            let rest: Vec<Vec<u8>> = (2..c::arg_count()).map(arg).collect();
            let refs: Vec<&[u8]> = rest.iter().map(|a| a.as_slice()).collect();
            c::ret(&c::call(&contract, &function, &refs, &[]));
        }
        b"call_attached" => {
            let (contract, function) = (arg(0), arg(1));
            let assets: Vec<c::Asset> = (2..c::arg_count()).step_by(2).map(|i| c::Asset::coin(&arg(i), c::atoi(&arg(i + 1)))).collect();
            c::ret(&c::call(&contract, &function, &[], &assets));
        }
        b"vecpak" => {
            let bytes = arg(0);
            let rounds = c::atoi(&arg(1));
            let mut out = Vec::new();
            for _ in 0..rounds {
                let t = c::vecpak::decode(&bytes).unwrap_or_else(|e| c::abort(e.as_bytes()));
                out = c::vecpak::encode(&t).unwrap_or_else(|e| c::abort(e.as_bytes()));
            }
            c::ret(if out == bytes { b"same" } else { b"diff" });
        }
        b"frame" => {
            let before = (c::attachments(), c::seed());
            c::call(&arg(0), b"inc", &[], &[]);
            let after = (c::attachments(), c::seed());
            c::log(if before == after { b"same" } else { b"leaked" });
            c::exit(0)
        }
        b"align" => {
            #[repr(align(4096))]
            struct Page([u8; 16]);
            let p = alloc::boxed::Box::new(Page([1; 16]));
            let addr = &*p as *const Page as usize;
            c::ret(if addr % 4096 == 0 && p.0[15] == 1 { b"1" } else { b"0" });
        }
        b"argcopy" => {
            let mut buf = [0u8; 4096];
            c::syscall(c::id::ARG, [0, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0]);
            core::hint::black_box(&buf);
        }
        b"ret_len" => {
            static BUF: [u8; 128] = [b'x'; 128];
            c::ret(&BUF[..c::atoi(&arg(0)) as usize])
        }
        b"abort" => c::abort(b"boom"),
        b"exit7" => c::exit(7),
        b"trap" => unsafe {
            core::ptr::read_volatile(0xffff_ffff_0000 as *const u64);
        },
        b"big_return" => c::ret(&[7u8; 200]),
        b"panic" => panic!("x"),
        _ => c::abort(b"unknown function"),
    }
}

c::entry!(dispatch);
