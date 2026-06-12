#![allow(non_snake_case)]
use std::arch::x86_64::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub const K: usize = 50_240;
pub const PREAMBLE: usize = 240;
pub const C_BYTES: usize = 1024;
pub const SOL_SIZE: usize = PREAMBLE + C_BYTES; // 1264
pub const A_BYTES: usize = 16 * K; // 803_840
pub const B_BYTES: usize = K * 16; // 803_840
pub const AB_BYTES: usize = A_BYTES + B_BYTES;
pub const NONCE_OFF: usize = 228;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Backend {
    Scalar,
    Avx2,
    Avx512Vnni,
}

fn detect_backend() -> Backend {
    if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512bw") && is_x86_feature_detected!("avx512vnni") {
        Backend::Avx512Vnni
    } else if is_x86_feature_detected!("avx2") {
        Backend::Avx2
    } else {
        Backend::Scalar
    }
}

struct Scratch {
    ab: Vec<u8>,
    bt: Vec<i8>,
    sol: Vec<u8>,
}

impl Scratch {
    fn new() -> Self {
        Scratch { ab: vec![0u8; AB_BYTES], bt: vec![0i8; 16 * K], sol: vec![0u8; SOL_SIZE] }
    }
}

#[inline]
fn store_c(out: &mut [u8], i: usize, j: usize, v: i32) {
    let off = (i * 16 + j) * 4;
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

// ---- transpose B (K x 16 i8) -> BT (16 x K i8), blocked to stay cache-hot ----
fn transpose_b(b: &[u8], bt: &mut [i8]) {
    const BLK: usize = 512;
    let mut k0 = 0;
    while k0 < K {
        let k1 = (k0 + BLK).min(K);
        for j in 0..16 {
            let dst = &mut bt[j * K + k0..j * K + k1];
            let mut idx = k0 * 16 + j;
            for d in dst.iter_mut() {
                *d = b[idx] as i8;
                idx += 16;
            }
        }
        k0 = k1;
    }
}

fn matmul_scalar(a: &[u8], bt: &[i8], out: &mut [u8]) {
    for i in 0..16 {
        let arow = &a[i * K..i * K + K];
        for j in 0..16 {
            let brow = &bt[j * K..j * K + K];
            let mut acc: i32 = 0;
            for k in 0..K {
                acc = acc.wrapping_add(arow[k] as i32 * brow[k] as i32);
            }
            store_c(out, i, j, acc);
        }
    }
}

/// Fused AVX2 matmul off native B layout (no pre-transpose). 2 k's per madd_epi16
/// (exact, no maddubs saturation); RT rows' C kept live in YMM (lo cols 0..7,
/// hi cols 8..15). B re-read 16/RT times.
#[target_feature(enable = "avx2")]
unsafe fn matmul_avx2_fused<const RT: usize>(a: &[u8], b_raw: &[u8], out: &mut [u8]) {
    let ap = a.as_ptr();
    let bp = b_raw.as_ptr();
    let mut it = 0usize;
    while it < 16 {
        let rows = RT.min(16 - it);
        let mut clo = [_mm256_setzero_si256(); RT];
        let mut chi = [_mm256_setzero_si256(); RT];

        let mut k = 0usize;
        while k < K {
            let base = bp.add(k * 16);
            let rk = _mm_loadu_si128(base as *const __m128i);
            let rk1 = _mm_loadu_si128(base.add(16) as *const __m128i);
            let blo = _mm256_cvtepi8_epi16(_mm_unpacklo_epi8(rk, rk1)); // cols 0..7 pairs
            let bhi = _mm256_cvtepi8_epi16(_mm_unpackhi_epi8(rk, rk1)); // cols 8..15 pairs

            for r in 0..rows {
                let arow = ap.add((it + r) * K + k);
                let a0 = *arow as i32;
                let a1 = *arow.add(1) as i32;
                let av = _mm256_set1_epi32(a0 | (a1 << 16)); // i16 lanes [a0,a1,...]
                clo[r] = _mm256_add_epi32(clo[r], _mm256_madd_epi16(blo, av));
                chi[r] = _mm256_add_epi32(chi[r], _mm256_madd_epi16(bhi, av));
            }
            k += 2;
        }

        for r in 0..rows {
            let o = out.as_mut_ptr().add((it + r) * 64);
            _mm256_storeu_si256(o as *mut __m256i, clo[r]);
            _mm256_storeu_si256(o.add(32) as *mut __m256i, chi[r]);
        }
        it += RT;
    }
}

#[inline]
unsafe fn read_u32(p: *const u8) -> i32 {
    let mut v = [0u8; 4];
    std::ptr::copy_nonoverlapping(p, v.as_mut_ptr(), 4);
    i32::from_le_bytes(v)
}

// Fused matmul off native B layout (no pre-transpose). 64 MACs/instr via VPDPBUSD.
// K = 50240 = 785*64 and = 12560*4, so no tails. Lane j of c[i] holds C[i][j].
#[target_feature(enable = "avx512f,avx512bw,avx512vnni")]
unsafe fn matmul_avx512_fused(a: &[u8], b_raw: &[u8], out: &mut [u8]) {
    let ap = a.as_ptr();
    let bp = b_raw.as_ptr();
    let mut c = [_mm512_setzero_si512(); 16];

    let mut k = 0usize;
    while k < K {
        let base = bp.add(k * 16);
        let r0 = _mm_loadu_si128(base as *const __m128i);
        let r1 = _mm_loadu_si128(base.add(16) as *const __m128i);
        let r2 = _mm_loadu_si128(base.add(32) as *const __m128i);
        let r3 = _mm_loadu_si128(base.add(48) as *const __m128i);

        // transpose 4x16 block: lane j = [B[k][j],B[k+1][j],B[k+2][j],B[k+3][j]]
        let t01l = _mm_unpacklo_epi8(r0, r1);
        let t01h = _mm_unpackhi_epi8(r0, r1);
        let t23l = _mm_unpacklo_epi8(r2, r3);
        let t23h = _mm_unpackhi_epi8(r2, r3);
        let x0 = _mm_unpacklo_epi16(t01l, t23l);
        let x1 = _mm_unpackhi_epi16(t01l, t23l);
        let x2 = _mm_unpacklo_epi16(t01h, t23h);
        let x3 = _mm_unpackhi_epi16(t01h, t23h);
        let bt = _mm512_castsi128_si512(x0);
        let bt = _mm512_inserti32x4(bt, x1, 1);
        let bt = _mm512_inserti32x4(bt, x2, 2);
        let bt = _mm512_inserti32x4(bt, x3, 3);

        let arow = ap.add(k);
        macro_rules! step {
            ($i:expr) => {{
                let a4 = _mm512_set1_epi32(read_u32(arow.add($i * K)));
                c[$i] = _mm512_dpbusd_epi32(c[$i], a4, bt);
            }};
        }
        step!(0); step!(1); step!(2); step!(3);
        step!(4); step!(5); step!(6); step!(7);
        step!(8); step!(9); step!(10); step!(11);
        step!(12); step!(13); step!(14); step!(15);

        k += 4;
    }

    for i in 0..16 {
        _mm512_storeu_si512(out.as_mut_ptr().add(i * 64) as *mut __m512i, c[i]);
    }
}

#[inline]
fn attempt(backend: Backend, seed: &[u8; PREAMBLE], sc: &mut Scratch) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(seed);
    h.finalize_xof().fill(&mut sc.ab[..AB_BYTES]);

    let (a, b) = sc.ab.split_at(A_BYTES);
    sc.sol[..PREAMBLE].copy_from_slice(seed);
    let (_, cdst) = sc.sol.split_at_mut(PREAMBLE);

    match backend {
        // VNNI and AVX2 fuse the transpose into the matmul — single pass over A, B.
        Backend::Avx512Vnni => unsafe { matmul_avx512_fused(a, b, cdst) },
        Backend::Avx2 => unsafe { matmul_avx2_fused::<8>(a, b, cdst) },
        Backend::Scalar => {
            transpose_b(b, &mut sc.bt);
            matmul_scalar(a, &sc.bt, cdst);
        }
    }

    *blake3::hash(&sc.sol).as_bytes()
}

#[inline]
fn meets_diff(hash: &[u8; 32], diff_bits: u32) -> bool {
    if diff_bits as usize > 256 {
        return false;
    }
    let full = (diff_bits / 8) as usize; // whole zero bytes
    let rem = (diff_bits % 8) as u8; // remaining high bits of the next byte
    hash[..full].iter().all(|&b| b == 0) && (rem == 0 || (hash[full] >> (8 - rem)) == 0)
}

#[inline]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Compute up to `iterations` total UPOW2 attempts across `threads` workers.
/// Returns the first solution whose Blake3(sol) has at least `diff_bits` leading
/// zero bits (the network difficulty), else None. `seeds` provides one u64 RNG
/// seed per worker (drawn from the OS by the caller).
pub fn compute(seed_template: &[u8; PREAMBLE], diff_bits: u32, iterations: u64, threads: usize, seeds: &[u64]) -> Option<Vec<u8>> {
    let backend = detect_backend();
    let nthreads = threads.max(1);
    let per = iterations.div_ceil(nthreads as u64);

    let found = AtomicBool::new(false);
    let result: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);

    std::thread::scope(|s| {
        for t in 0..nthreads {
            let found = &found;
            let result = &result;
            let template = *seed_template;
            let mut rng = seeds.get(t).copied().unwrap_or(0).wrapping_add((t as u64).wrapping_mul(0xD1B5_4A32_D192_ED03));
            s.spawn(move || {
                let mut sc = Scratch::new();
                let mut seed = template;
                for i in 0..per {
                    if (i & 0x3F) == 0 && found.load(Ordering::Relaxed) {
                        return;
                    }
                    let a = splitmix64(&mut rng).to_le_bytes();
                    let b = splitmix64(&mut rng).to_le_bytes();
                    seed[NONCE_OFF..NONCE_OFF + 8].copy_from_slice(&a);
                    seed[NONCE_OFF + 8..NONCE_OFF + 12].copy_from_slice(&b[..4]);

                    let hash = attempt(backend, &seed, &mut sc);
                    if meets_diff(&hash, diff_bits) {
                        if !found.swap(true, Ordering::SeqCst) {
                            *result.lock().unwrap() = Some(sc.sol.clone());
                        }
                        return;
                    }
                }
            });
        }
    });

    result.into_inner().unwrap_or(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matmul_reference(a: &[u8], b_raw: &[u8], out: &mut [u8]) {
        for i in 0..16 {
            for j in 0..16 {
                let mut acc: i64 = 0;
                for k in 0..K {
                    acc += a[i * K + k] as i64 * ((b_raw[k * 16 + j] as i8) as i64);
                }
                let off = (i * 16 + j) * 4;
                out[off..off + 4].copy_from_slice(&(acc as i32).to_le_bytes());
            }
        }
    }

    fn derive(seed: &[u8; PREAMBLE]) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(seed);
        let mut ab = vec![0u8; AB_BYTES];
        h.finalize_xof().fill(&mut ab);
        let (a, b) = ab.split_at(A_BYTES);
        let mut c = vec![0u8; C_BYTES];
        matmul_reference(a, b, &mut c);
        c
    }

    #[test]
    fn backends_match_reference() {
        for t in 0..3u64 {
            let mut seed = [0u8; PREAMBLE];
            for (i, b) in seed.iter_mut().enumerate() {
                *b = (i as u64).wrapping_mul(t + 1).wrapping_add(t) as u8;
            }
            let c_ref = derive(&seed);
            let mut sc = Scratch::new();
            let mut h = blake3::Hasher::new();
            h.update(&seed);
            h.finalize_xof().fill(&mut sc.ab[..AB_BYTES]);
            let (a, b) = sc.ab.split_at(A_BYTES);

            transpose_b(b, &mut sc.bt);
            let mut c = vec![0u8; C_BYTES];
            matmul_scalar(a, &sc.bt, &mut c);
            assert_eq!(c, c_ref, "scalar trial {t}");

            if is_x86_feature_detected!("avx2") {
                let mut c2 = vec![0u8; C_BYTES];
                unsafe { matmul_avx2_fused::<8>(a, b, &mut c2) };
                assert_eq!(c2, c_ref, "avx2 fused trial {t}");
            }
            if detect_backend() == Backend::Avx512Vnni {
                let mut c3 = vec![0u8; C_BYTES];
                unsafe { matmul_avx512_fused(a, b, &mut c3) };
                assert_eq!(c3, c_ref, "avx512 fused trial {t}");
            }
        }
    }

    #[test]
    fn computes_and_self_verifies_low_diff() {
        // diff_bits = 16 (2 leading zero bytes); generous budget so one is found.
        let mut seed = [3u8; PREAMBLE];
        seed[0..4].copy_from_slice(&156u32.to_le_bytes());
        let seeds: Vec<u64> = (0..4).map(|x| 0x1234_5678 ^ x).collect();
        let sol = compute(&seed, 16, 50_000_000, 4, &seeds).expect("found sol");
        assert_eq!(sol.len(), SOL_SIZE);
        // embedded C must equal independent reference, and hash must meet target
        let seed_arr: [u8; PREAMBLE] = sol[..PREAMBLE].try_into().unwrap();
        let c_ref = derive(&seed_arr);
        assert_eq!(&sol[PREAMBLE..], &c_ref[..], "embedded C != reference");
        let hash = blake3::hash(&sol);
        assert!(hash.as_bytes()[0] == 0 && hash.as_bytes()[1] == 0, "hash misses 2-byte target");
    }

    #[test]
    fn meets_diff_matches_bit_semantics() {
        let mut h = [0u8; 32];
        assert!(meets_diff(&h, 0));
        assert!(meets_diff(&h, 256));
        h[0] = 0x00;
        h[1] = 0b0000_1111;
        assert!(meets_diff(&h, 12)); // 8 + top 4 bits of byte 1 are zero
        assert!(!meets_diff(&h, 13)); // 5th bit of byte 1 is set
        assert!(meets_diff(&h, 8));
        assert!(!meets_diff(&h, 257)); // beyond hash width
    }
}
