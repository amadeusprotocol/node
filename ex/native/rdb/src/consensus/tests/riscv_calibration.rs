#![cfg(test)]

use crate::consensus::bic::protocol;
use crate::consensus::bls12_381;
use crate::consensus::riscv::vm;
use crate::consensus::tests::riscv_contracts::KITCHEN;
use std::time::Instant;

const TARGET_NS_PER_UNIT: f64 = 10_000_000.0 / protocol::TX_EXEC_LOCK as f64;

fn best_ns(iters: u32, mut f: impl FnMut()) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        best = best.min(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    best
}

thread_local! {
    static OVER: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
}

fn report(name: &str, ns: f64, units: i128) {
    let per_unit = ns / units as f64;
    let over = per_unit > TARGET_NS_PER_UNIT;
    if over {
        OVER.with(|o| o.borrow_mut().push(name.to_string()));
    }
    println!("  {name:<36} {ns:>12.0} ns  charged {units:>9} units  {per_unit:>6.2} ns/unit{}", if over { "  OVER" } else { "" });
}

#[test]
#[ignore]
fn riscv_cost_calibration() {
    use sha2::Digest;
    println!("target: {TARGET_NS_PER_UNIT:.2} ns per exec unit (10 ms over TX_EXEC_LOCK = {})", protocol::TX_EXEC_LOCK);
    let data = vec![7u8; 64 * 1024];
    let blocks = |len: usize, per: usize| ((len + per) / per) as i128;

    let ns = best_ns(200, || drop(std::hint::black_box(sha2::Sha256::digest(&data))));
    report("sha256 64 KiB", ns, protocol::RISCV_SHA256_BLOCK_COST * blocks(data.len() + 8, 64) + protocol::RISCV_HOST_CALL_COST);
    let ns = best_ns(200, || drop(std::hint::black_box(sha3::Keccak256::digest(&data))));
    report("keccak256 64 KiB", ns, protocol::RISCV_KECCAK_BLOCK_COST * blocks(data.len(), 136) + protocol::RISCV_HOST_CALL_COST);
    let ns = best_ns(200, || drop(std::hint::black_box(blake3::hash(&data))));
    report("blake3 64 KiB", ns, protocol::RISCV_BLAKE3_CHUNK_COST * blocks(data.len(), 1024) + protocol::RISCV_HOST_CALL_COST);

    let dst = b"AMADEUS_CALIBRATION";
    let sks: Vec<[u8; 64]> = (0..64).map(|_| bls12_381::generate_sk()).collect();
    let pks: Vec<[u8; 48]> = sks.iter().map(|sk| bls12_381::get_public_key(sk).unwrap()).collect();
    let msg = [1u8; 32];
    let sig = bls12_381::sign(&sks[0], &msg, dst).unwrap();
    let ns = best_ns(20, || assert!(bls12_381::verify(&pks[0], &sig, &msg, dst).is_ok()));
    report("bls verify", ns, protocol::RISCV_BLS_VERIFY_COST + protocol::RISCV_SHA256_BLOCK_COST + protocol::RISCV_HOST_CALL_COST);
    let ns = best_ns(20, || drop(std::hint::black_box(bls12_381::aggregate_public_keys(pks.iter()).unwrap())));
    report("bls aggregate 64 keys", ns, protocol::RISCV_BLS_AGGREGATE_KEY_COST * 64);

    use k256::ecdsa::{signature::hazmat::PrehashVerifier, SigningKey, VerifyingKey};
    let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let (esig, recid) = sk.sign_prehash_recoverable(&msg).unwrap();
    let ns = best_ns(50, || drop(std::hint::black_box(VerifyingKey::recover_from_prehash(&msg, &esig, recid).unwrap())));
    report("secp256k1 recover", ns, protocol::RISCV_SECP256K1_RECOVER_COST + protocol::RISCV_HOST_CALL_COST);
    let vk = *sk.verifying_key();
    let ns = best_ns(50, || assert!(vk.verify_prehash(&msg, &esig).is_ok()));
    report("secp256k1 verify", ns, protocol::RISCV_SECP256K1_VERIFY_COST + protocol::RISCV_HOST_CALL_COST);

    use ed25519_dalek::{Signer, SigningKey as EdKey};
    let ek = EdKey::from_bytes(&[9u8; 32]);
    let esig2 = ek.sign(&msg);
    let evk = ek.verifying_key();
    let ns = best_ns(200, || assert!(evk.verify_strict(&msg, &esig2).is_ok()));
    report("ed25519 verify", ns, protocol::RISCV_ED25519_VERIFY_COST + protocol::RISCV_SHA256_BLOCK_COST + protocol::RISCV_HOST_CALL_COST);

    let p = vm::load(KITCHEN).unwrap();
    let ns = best_ns(50, || drop(std::hint::black_box(vm::load(KITCHEN).unwrap())));
    report(&format!("load kitchen ({} words)", p.code_words()), ns, protocol::RISCV_CODE_WORD_COST * p.code_words() as i128);
    let ns = best_ns(50, || crate::consensus::riscv::host::validate(KITCHEN).unwrap());
    report(&format!("deploy validation kitchen ({} bytes)", KITCHEN.len()), ns, protocol::RISCV_DEPLOY_BYTE_COST * KITCHEN.len() as i128);
    let ns = best_ns(200, || drop(std::hint::black_box(vm::Machine::new(&p, 1))));
    report(&format!("machine setup ({} pages)", p.pages()), ns, protocol::RISCV_PAGE_COST * p.pages() as i128);

    let big = vm::load_raw(0x1000, 0x1000, &[0x73, 0, 0, 0], vec![], vm::MAX_MEM).unwrap();
    let ns = best_ns(20, || drop(std::hint::black_box(vm::Machine::new(&big, 1))));
    report(&format!("machine setup ({} pages, max)", big.pages()), ns, protocol::RISCV_PAGE_COST * big.pages() as i128);

    for (name, prog) in [("kitchen", &p), ("max memory", &big)] {
        let fresh = best_ns(50, || {
            let mut m = vm::Machine::new(prog, 10);
            m.run(&mut |_: &mut vm::Machine| vm::Ecall::Done(0));
        });
        let mut spare = Some(vm::Machine::new(prog, 1).into_memory());
        let reused = best_ns(50, || {
            let mut m = vm::Machine::reuse(prog, 10, spare.take());
            m.run(&mut |_: &mut vm::Machine| vm::Ecall::Done(0));
            spare = Some(m.into_memory());
        });
        println!("  call setup {name:<12} fresh {fresh:>9.0} ns   reused {reused:>7.0} ns   ({:.0}x)", fresh / reused);
    }

    let ns = best_ns(20, || {
        let mut fresh = vec![0u8; vm::MAX_MEM as usize];
        for page in fresh.chunks_mut(4096) {
            page[0] = 1;
        }
        drop(std::hint::black_box(fresh));
    });
    report(&format!("first touch of {} fresh pages", vm::MAX_MEM / 4096), ns, protocol::RISCV_PAGE_COST * (vm::MAX_MEM as i128 / 4096));

    let mut spent = f64::MAX;
    for _ in 0..20 {
        let spare = vm::Memory::blank(vm::MAX_MEM as usize);
        let t = Instant::now();
        let mut m = vm::Machine::reuse(&big, 10, Some(spare));
        m.run(&mut |_: &mut vm::Machine| vm::Ecall::Done(0));
        spent = spent.min(t.elapsed().as_nanos() as f64);
        drop(m);
    }
    report(&format!("setup from a prefaulted spare ({} pages)", big.pages()), spent, protocol::RISCV_PAGE_COST * big.pages() as i128);

    let tiny = vm::load_raw(0x1000, 0x1000, &[0x73, 0, 0, 0], vec![], 0x1004).unwrap();
    let ns = best_ns(2000, || {
        let mut m = vm::Machine::new(&tiny, 10);
        m.run(&mut |_: &mut vm::Machine| vm::Ecall::Done(0));
    });
    report("smallest call (setup + one ecall)", ns, protocol::RISCV_PAGE_COST * tiny.pages() as i128 + protocol::RISCV_CODE_WORD_COST + protocol::RISCV_HOST_CALL_COST);

    let entries: Vec<(vecpak::Term, vecpak::Term)> = (0..2000).map(|i| (vecpak::Term::Binary(format!("C{i:05}").into_bytes()), vecpak::Term::PropList((0..4).map(|t| (vecpak::Term::Binary(format!("T{t}").into_bytes()), vecpak::Term::VarInt(1_000_000_007 * t + 1))).collect()))).collect();
    let attached = vecpak::encode(vecpak::Term::PropList(entries)).unwrap();
    let chain = crate::consensus::tests::chain_harness::Chain::new();
    let ns = chain.with_env(&[0u8; 48], |env| best_ns(20, || drop(std::hint::black_box(crate::consensus::bic::attachment::decode(env, &attached)))));
    report(&format!("attachments decode ({} bytes)", attached.len()), ns, protocol::ATTACHMENTS_DECODE_BYTE_COST * attached.len() as i128);

    let copy = vec![0u8; 1 << 20];
    let ns = best_ns(200, || drop(std::hint::black_box(copy.to_vec())));
    report("host copy 1 MiB", ns, (copy.len() as u64).div_ceil(protocol::RISCV_COPY_BYTES_PER_UNIT) as i128);

    let over = OVER.with(|o| o.borrow().clone());
    assert!(over.is_empty(), "priced below {TARGET_NS_PER_UNIT} ns/unit: {over:?}");
}

#[test]
#[ignore]
fn vecpak_in_vm_vs_native() {
    use crate::consensus::tests::chain_harness::Chain;
    use crate::consensus::tests::riscv_contracts::{install, testnet};
    use vecpak::Term;
    let b = |s: &str| Term::Binary(s.as_bytes().to_vec());
    let tx = Term::PropList(vec![
        (b("signer"), Term::Binary(vec![1; 48])),
        (b("nonce"), Term::VarInt(1_700_000_000_123)),
        (b("action"), Term::PropList(vec![
            (b("contract"), b("Coin")),
            (b("function"), b("transfer")),
            (b("args"), Term::List(vec![Term::Binary(vec![2; 48]), b("1000000000"), b("AMA")])),
        ])),
    ]);
    let big = Term::List((0..64).map(|i| Term::PropList(vec![(b("k"), Term::VarInt(i)), (b("v"), Term::Binary(vec![i as u8; 32]))])).collect());
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let contract = install(&chain, KITCHEN);
    for (name, term) in [("tx-shaped map", tx), ("64-entry list of maps", big)] {
        let bytes = vecpak::encode(term).unwrap();
        let native = best_ns(2000, || {
            let t = vecpak::decode(&bytes).unwrap();
            assert_eq!(vecpak::encode(t).unwrap().len(), bytes.len());
        });
        let time = |rounds: &[u8]| {
            let mut best = f64::MAX;
            let mut units = 0;
            for _ in 0..5 {
                let t = Instant::now();
                let out = testnet(&chain, &caller.pk, &contract, b"vecpak", &[&bytes, rounds]);
                best = best.min(t.elapsed().as_nanos() as f64);
                assert_eq!(out.result.as_deref(), Ok(&b"same"[..]));
                units = out.exec_used;
            }
            (best, units)
        };
        let (t1, u1) = time(b"1");
        let (t11, u11) = time(b"6");
        let (vm_ns, vm_units) = ((t11 - t1) / 5.0, (u11 - u1) / 5);
        println!("  {name:<24} {} bytes   native {native:>8.0} ns   in vm {vm_ns:>8.0} ns ({:.0}x), {vm_units} units", bytes.len(), vm_ns / native);
    }
}

#[test]
#[ignore]
fn storage_write_cost() {
    use crate::consensus::consensus_apply::apply_entry;
    use crate::consensus::tests::apply_golden::{entry, seed_tree, wallet_from, HEIGHT};
    use crate::consensus::tests::chain_harness::Chain;
    use crate::consensus::tests::riscv_contracts::install;
    use crate::model::tx::{Action, TX, TXU};
    const TXS: usize = 50;
    let run = |chain: &Chain, height: u64, nonce: &mut u64, signer: &crate::consensus::tests::chain_harness::Wallet, contract: &[u8; 48], args: &[&[u8]]| {
        let txs: Vec<TXU> = (0..TXS).map(|i| {
            *nonce += 1;
            let tag = format!("{i}");
            let mut a: Vec<Vec<u8>> = args.iter().map(|x| x.to_vec()).collect();
            a.push(tag.into_bytes());
            TXU {
                hash: blake3::hash(&[&signer.pk[..], &nonce.to_be_bytes()].concat()).as_bytes().to_vec(),
                signature: vec![0u8; 96],
                tx: TX { signer: signer.pk.to_vec(), nonce: *nonce, action: Action {
                    op: b"call".to_vec(), contract: contract.to_vec(), function: b"fill".to_vec(), args: a,
                    attached_gas: Some(protocol::AMA_1_DOLLAR), attachments: None,
                } },
            }
        }).collect();
        let t = Instant::now();
        let txn = chain.db.transaction();
        let (txn, _, _, receipts, _, _) = apply_entry(chain.db, txn, entry(height, signer, txs), &[0u8; 48], &[0u8; 64], true);
        txn.commit().unwrap();
        let ns = t.elapsed().as_nanos() as f64;
        let _ = std::panic::take_hook();
        for r in &receipts {
            assert!(r.success, "{:?}", String::from_utf8_lossy(&r.result));
        }
        (ns, receipts.iter().map(|r| std::str::from_utf8(&r.exec_used).unwrap().parse::<i128>().unwrap()).sum::<i128>())
    };
    let cases: [(&str, &[u8], &[u8]); 4] = [("nothing", b"0", b"0"), ("40 x 32 B", b"40", b"32"), ("1 x 48 KiB", b"1", b"49152"), ("4 x 12 KiB", b"4", b"12288")];
    let mut base = (0.0, 0);
    for (name, count, size) in cases {
        let chain = Chain::new();
        let signer = wallet_from(12);
        chain.fund(&signer.pk, 1_000_000 * protocol::AMA_1_DOLLAR);
        seed_tree(&chain);
        let contract = install(&chain, KITCHEN);
        let mut nonce = 0;
        let (fresh, units) = run(&chain, HEIGHT, &mut nonce, &signer, &contract, &[count, size]);
        let (over, _) = run(&chain, HEIGHT + 1, &mut nonce, &signer, &contract, &[count, size]);
        if name == "nothing" {
            base = (fresh, units);
            println!("  {name:<12} {:>8.0} ns/tx  {:>8} units/tx", fresh / TXS as f64, units / TXS as i128);
            continue;
        }
        let writes = TXS as f64 * std::str::from_utf8(count).unwrap().parse::<f64>().unwrap();
        let bytes = writes * std::str::from_utf8(size).unwrap().parse::<f64>().unwrap();
        let (f, o) = (fresh - base.0, over - base.0);
        println!("  {name:<12} new keys {:>8.0} ns/write {:>6.2} ns/byte   overwrite {:>8.0} ns/write {:>6.2} ns/byte   charged {:>8.0} units/write", f / writes, f / bytes, o / writes, o / bytes, (units - base.1) as f64 / writes);
    }
}

#[test]
#[ignore]
fn storage_read_cost() {
    use rust_rocksdb::{BlockBasedOptions, Cache, ColumnFamilyDescriptor, DBCompressionType, MultiThreaded, Options, TransactionDB, TransactionDBOptions};
    let dir = tempfile::TempDir::new().unwrap();
    let open = || {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        let mut cf = Options::default();
        let mut bb = BlockBasedOptions::default();
        bb.set_block_cache(&Cache::new_lru_cache(3 << 30));
        bb.set_bloom_filter(10.0, false);
        cf.set_block_based_table_factory(&bb);
        cf.set_compression_type(DBCompressionType::Zstd);
        cf.set_bottommost_compression_type(DBCompressionType::Zstd);
        TransactionDB::<MultiThreaded>::open_cf_descriptors(&db_opts, &TransactionDBOptions::default(), dir.path(), vec![ColumnFamilyDescriptor::new("cs", cf)]).unwrap()
    };
    let mut x = 0x9e3779b97f4a7c15u64;
    let mut next = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let big: Vec<(Vec<u8>, Vec<u8>)> = (0..48).map(|i| {
        let v: Vec<u8> = if i % 2 == 0 { (0..1 << 20).map(|_| next() as u8).collect() } else { (0..1 << 20).map(|_| b'a' + (next() >> 60) as u8).collect() };
        (format!("big:{i:04}").into_bytes(), v)
    }).collect();
    let small: Vec<(Vec<u8>, Vec<u8>)> = (0..200_000u64).map(|i| (blake3::hash(&i.to_be_bytes()).as_bytes().to_vec(), (0..32).map(|_| next() as u8).collect())).collect();
    {
        let db = open();
        let cf = db.cf_handle("cs").unwrap();
        for (k, v) in big.iter().chain(&small) {
            db.put_cf(&cf, k, v).unwrap();
        }
        db.flush_cf(&cf).unwrap();
        db.compact_range_cf(&cf, None::<&[u8]>, None::<&[u8]>);
    }
    let db = open();
    let cf = db.cf_handle("cs").unwrap();
    let read = |pass: &str, items: &[(Vec<u8>, Vec<u8>)]| {
        let t = Instant::now();
        let mut bytes = 0;
        for (k, v) in items {
            let txn = db.transaction();
            let got = txn.get_cf(&cf, k).unwrap().unwrap();
            assert_eq!(got.len(), v.len());
            bytes += k.len() + got.len();
        }
        let ns = t.elapsed().as_nanos() as f64;
        let charged = items.len() as i128 * protocol::COST_PER_DB_READ_BASE + bytes as i128 * protocol::COST_PER_DB_READ_BYTE;
        println!("  {pass:<34} {:>9.0} ns/read {:>6.2} ns/byte   charged {:>6.2} ns/unit", ns / items.len() as f64, ns / bytes as f64, ns / charged as f64);
    };
    let picks: Vec<_> = (0..20_000).map(|i| small[(i * 7919) % small.len()].clone()).collect();
    read("32 B values, cold block cache", &picks);
    read("32 B values, warm", &picks);
    let rand: Vec<_> = big.iter().step_by(2).cloned().collect();
    let text: Vec<_> = big.iter().skip(1).step_by(2).cloned().collect();
    read("1 MiB random, cold block cache", &rand);
    read("1 MiB random, warm", &rand);
    read("1 MiB compressible, cold block cache", &text);
    read("1 MiB compressible, warm", &text);
}

#[test]
#[ignore]
fn call_overheads() {
    use crate::consensus::tests::chain_harness::Chain;
    use crate::consensus::tests::riscv_contracts::{install, testnet, EMPTY};
    let chain = Chain::new();
    let caller = chain.wallet(0);
    let kitchen = install(&chain, KITCHEN);
    let empty = install(&chain, EMPTY);
    let time = |f: &[u8], args: &[&[u8]]| {
        let mut best = f64::MAX;
        let mut units = 0;
        for _ in 0..7 {
            let t = Instant::now();
            let out = testnet(&chain, &caller.pk, &kitchen, f, args);
            best = best.min(t.elapsed().as_nanos() as f64);
            assert!(out.result.is_ok(), "{:?}", out.result);
            units = out.exec_used;
        }
        (best, units)
    };
    for (name, f, n, extra) in [("host call (arg_count)", &b"hostloop"[..], 10_000i128, None), ("nested call to empty", &b"callloop"[..], 10, Some(&empty[..]))] {
        let mut a0: Vec<&[u8]> = vec![b"0"];
        let ns = n.to_string();
        let mut a1: Vec<&[u8]> = vec![ns.as_bytes()];
        if let Some(e) = extra {
            a0.push(e);
            a1.push(e);
        }
        let (t0, u0) = time(f, &a0);
        let (t1, u1) = time(f, &a1);
        report(&format!("{name} x{n}"), t1 - t0, u1 - u0);
        println!("    per iteration {:.0} ns, {} units", (t1 - t0) / n as f64, (u1 - u0) / n);
    }
}
