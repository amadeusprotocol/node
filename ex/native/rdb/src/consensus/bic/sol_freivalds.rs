use std::arch::x86_64::*;
use std::{
    cell::RefCell,
    mem,
    mem::{size_of, MaybeUninit},
    ptr, slice,
};

//#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
//compile_error!("freivalds requires AVX2; build with -C target-feature=+avx2");

#[repr(C, align(4096))]
struct AMAMatMul {
    pub A: [[u8; 50240]; 16],
    pub B: [[i8; 16]; 50240],
    pub B2: [[i8; 64]; 16],
    pub Rs: [[i8; 16]; 3],
    pub C: [[i32; 16]; 16],
}

thread_local! {
    static SCRATCH: RefCell<Option<Box<AMAMatMul>>> = RefCell::new(None);
}

struct ScratchGuard {
    buf: Option<Box<AMAMatMul>>,
}

impl std::ops::Deref for ScratchGuard {
    type Target = AMAMatMul;
    fn deref(&self) -> &Self::Target {
        self.buf.as_ref().expect("buffer disappeared")
    }
}
impl std::ops::DerefMut for ScratchGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buf.as_mut().expect("buffer disappeared")
    }
}
impl Drop for ScratchGuard {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            SCRATCH.with(|tls| *tls.borrow_mut() = Some(buf));
        }
    }
}

/// Obtain the per‑thread scratch buffer, allocating it the first time.
fn borrow_scratch() -> ScratchGuard {
    SCRATCH.with(|tls| {
        let mut slot = tls.borrow_mut();
        let buf = slot.take().unwrap_or_else(|| {
            // First time on this thread: allocate **uninitialised** memory.
            let boxed_uninit: Box<MaybeUninit<AMAMatMul>> = Box::new_uninit(); // ≈ zero cost for the OS here
                                                                               // SAFETY: we promise to fully overwrite every byte before reading.
            unsafe { boxed_uninit.assume_init() }
        });
        ScratchGuard { buf: Some(buf) }
    })
}

pub fn freivalds(tensor: &[u8], vr_b3: &[u8]) -> bool {
    if tensor.len() < crate::consensus::bic::sol::SOL_SIZE {
        return false;
    }

    let mut scratch = borrow_scratch();

    let tensor_slice = tensor;
    let head = &tensor_slice[..240];
    let tail = &tensor_slice[tensor_slice.len() - 1024..];

    let mut hasher = blake3::Hasher::new();
    hasher.update(head);
    let mut xof = hasher.finalize_xof();

    let ab_bytes = 16 * 50_240           // A
                   + 50_240 * 16         // B
                   + 16 * 64; // B2

    unsafe {
        let dest = ptr::slice_from_raw_parts_mut((&mut scratch.A) as *mut _ as *mut u8, ab_bytes) as *mut [u8];
        xof.fill(&mut *dest);
    }

    unsafe {
        let dst = &mut scratch.C as *mut _ as *mut u8;
        ptr::copy_nonoverlapping(tail.as_ptr(), dst, 1024);
    }

    //Take R from entire sol + VRF
    let mut hasher_rs = blake3::Hasher::new();
    hasher_rs.update(tensor_slice);
    hasher_rs.update(vr_b3);
    let mut xof_rs = hasher_rs.finalize_xof();

    unsafe {
        let p = (&mut scratch.Rs) as *mut _ as *mut u8;
        let n = mem::size_of_val(&scratch.Rs);
        let dst = slice::from_raw_parts_mut(p, n);
        xof_rs.fill(dst);
    }

    freivalds_inner(&scratch.Rs, &scratch.A, &scratch.B, &scratch.C)
}

pub fn freivalds_inner(Rs: &[[i8; 16]; 3], A: &[[u8; 50_240]; 16], B: &[[i8; 16]; 50_240], C: &[[i32; 16]; 16]) -> bool {
    if std::is_x86_feature_detected!("avx2") {
        unsafe { freivalds_inner_avx2(Rs, A, B, C) }
    } else {
        freivalds_inner_scalar(Rs, A, B, C)
    }
}

#[inline(always)]
unsafe fn hsum256_epi32(v: __m256i) -> i32 {
    // Reduce 8 × i32 → scalar
    let hi = _mm256_extracti128_si256(v, 1);
    let lo = _mm256_castsi256_si128(v);
    let sum128 = _mm_add_epi32(lo, hi); // 4 lanes
    let sum64 = _mm_add_epi32(sum128, _mm_srli_si128(sum128, 8));
    let sum32 = _mm_add_epi32(sum64, _mm_srli_si128(sum64, 4));
    _mm_cvtsi128_si32(sum32)
}

#[inline(always)]
unsafe fn hsum256_epi64(v: __m256i) -> i64 {
    // Reduce 4 x i64 -> scalar
    let hi = _mm256_extracti128_si256(v, 1);
    let lo = _mm256_castsi256_si128(v);
    let sum2 = _mm_add_epi64(lo, hi);
    let hi64 = _mm_unpackhi_epi64(sum2, sum2);
    _mm_cvtsi128_si64(_mm_add_epi64(sum2, hi64))
}

#[inline(always)]
unsafe fn dot8_i32_to_i64(c: __m256i, r: __m256i) -> __m256i {
    let even = _mm256_mul_epi32(c, r);
    let odd = _mm256_mul_epi32(_mm256_srli_epi64(c, 32), _mm256_srli_epi64(r, 32));
    _mm256_add_epi64(even, odd)
}

#[inline(always)]
unsafe fn acc_i32x8_into_i64(acc: __m256i, prod: __m256i) -> __m256i {
    let lo = _mm256_cvtepi32_epi64(_mm256_castsi256_si128(prod));
    let hi = _mm256_cvtepi32_epi64(_mm256_extracti128_si256(prod, 1));
    _mm256_add_epi64(_mm256_add_epi64(acc, lo), hi)
}

#[repr(C)]
struct I32x16 {
    lo: __m256i,
    hi: __m256i,
}

/// Load 16 × i8 and sign‑extend to 16 × i32 (as two 256‑bit halves)
#[inline(always)]
unsafe fn load_i8x16_as_i32(ptr: *const i8) -> I32x16 {
    // load 16 bytes
    let v = _mm_loadu_si128(ptr as *const __m128i);
    let lo = _mm256_cvtepi8_epi32(v); // first 8
    let hi = _mm256_cvtepi8_epi32(_mm_srli_si128(v, 8));
    I32x16 { lo, hi }
}

pub unsafe fn freivalds_inner_avx2(Rs: &[[i8; 16]; 3], A: &[[u8; 50_240]; 16], B: &[[i8; 16]; 50_240], C: &[[i32; 16]; 16]) -> bool {
    const N: usize = 50_240;
    let mut U = [[0i64; 16]; 3];

    // --- Stage 1: U = C × R --------------------------------------------------
    let r0 = load_i8x16_as_i32(Rs[0].as_ptr());
    let r1 = load_i8x16_as_i32(Rs[1].as_ptr());
    let r2 = load_i8x16_as_i32(Rs[2].as_ptr());

    for i in 0..16 {
        let c_lo = _mm256_loadu_si256(C[i].as_ptr() as *const __m256i);
        let c_hi = _mm256_loadu_si256(C[i].as_ptr().add(8) as *const __m256i);

        U[0][i] = hsum256_epi64(_mm256_add_epi64(dot8_i32_to_i64(c_lo, r0.lo), dot8_i32_to_i64(c_hi, r0.hi)));
        U[1][i] = hsum256_epi64(_mm256_add_epi64(dot8_i32_to_i64(c_lo, r1.lo), dot8_i32_to_i64(c_hi, r1.hi)));
        U[2][i] = hsum256_epi64(_mm256_add_epi64(dot8_i32_to_i64(c_lo, r2.lo), dot8_i32_to_i64(c_hi, r2.hi)));
    }

    // --- Stage 2: P(k) = B[k] · R -------------------------------------------
    let mut P0 = vec![0i32; N];
    let mut P1 = vec![0i32; N];
    let mut P2 = vec![0i32; N];

    let r0_i16 = _mm256_cvtepi8_epi16(_mm_loadu_si128(Rs[0].as_ptr() as *const _));
    let r1_i16 = _mm256_cvtepi8_epi16(_mm_loadu_si128(Rs[1].as_ptr() as *const _));
    let r2_i16 = _mm256_cvtepi8_epi16(_mm_loadu_si128(Rs[2].as_ptr() as *const _));

    for k in 0..N {
        let row_i16 = _mm256_cvtepi8_epi16(_mm_loadu_si128(B[k].as_ptr() as *const _));

        P0[k] = hsum256_epi32(_mm256_madd_epi16(row_i16, r0_i16));
        P1[k] = hsum256_epi32(_mm256_madd_epi16(row_i16, r1_i16));
        P2[k] = hsum256_epi32(_mm256_madd_epi16(row_i16, r2_i16));
    }

    // --- Stage 3: dot( A[i], P ) --------------------------------------------
    for i in 0..16 {
        let mut acc0 = _mm256_setzero_si256();
        let mut acc1 = _mm256_setzero_si256();
        let mut acc2 = _mm256_setzero_si256();

        for k in (0..N).step_by(8) {
            let a_i32 = _mm256_cvtepu8_epi32(_mm_loadl_epi64(A[i].as_ptr().add(k) as *const _));
            let p0 = _mm256_loadu_si256(P0.as_ptr().add(k) as *const _);
            let p1 = _mm256_loadu_si256(P1.as_ptr().add(k) as *const _);
            let p2 = _mm256_loadu_si256(P2.as_ptr().add(k) as *const _);

            // a in [0,255], |p| < 2^21 => |a*p| < 2^29 fits i32; widen the running sum to i64.
            acc0 = acc_i32x8_into_i64(acc0, _mm256_mullo_epi32(a_i32, p0));
            acc1 = acc_i32x8_into_i64(acc1, _mm256_mullo_epi32(a_i32, p1));
            acc2 = acc_i32x8_into_i64(acc2, _mm256_mullo_epi32(a_i32, p2));
        }

        if hsum256_epi64(acc0) != U[0][i] || hsum256_epi64(acc1) != U[1][i] || hsum256_epi64(acc2) != U[2][i] {
            return false;
        }
    }
    true
}

fn freivalds_inner_scalar(Rs: &[[i8; 16]; 3], A: &[[u8; 50_240]; 16], B: &[[i8; 16]; 50_240], C: &[[i32; 16]; 16]) -> bool {
    let mut U = [[0i64; 16]; 3];
    for r in 0..3 {
        for i in 0..16 {
            let mut sum: i64 = 0;
            for j in 0..16 {
                sum += C[i][j] as i64 * Rs[r][j] as i64;
            }
            U[r][i] = sum;
        }
    }

    let mut P = [[0i32; 3]; 50_240];
    for k in 0..50_240 {
        let row = &B[k];
        let mut s0: i32 = 0;
        let mut s1: i32 = 0;
        let mut s2: i32 = 0;
        for j in 0..16 {
            let b = row[j] as i32;
            s0 += b * Rs[0][j] as i32;
            s1 += b * Rs[1][j] as i32;
            s2 += b * Rs[2][j] as i32;
        }
        P[k][0] = s0;
        P[k][1] = s1;
        P[k][2] = s2;
    }

    for i in 0..16 {
        let row_a = &A[i];
        let mut v0: i64 = 0;
        let mut v1: i64 = 0;
        let mut v2: i64 = 0;
        for k in 0..50_240 {
            let a = row_a[k] as i64;
            let p = P[k];
            v0 += a * p[0] as i64;
            v1 += a * p[1] as i64;
            v2 += a * p[2] as i64;
        }
        if v0 != U[0][i] || v1 != U[1][i] || v2 != U[2][i] {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }

    fn fill_random(s: &mut AMAMatMul, rng: &mut Rng) {
        for i in 0..16 {
            for k in 0..50_240 {
                s.A[i][k] = rng.next() as u8;
            }
        }
        for k in 0..50_240 {
            for j in 0..16 {
                s.B[k][j] = rng.next() as i8;
            }
        }
        for r in 0..3 {
            for j in 0..16 {
                s.Rs[r][j] = rng.next() as i8;
            }
        }
    }

    fn set_c_to_product(s: &mut AMAMatMul) -> [[i64; 16]; 16] {
        let mut m = [[0i64; 16]; 16];
        for i in 0..16 {
            for k in 0..50_240 {
                let a = s.A[i][k] as i64;
                if a == 0 {
                    continue;
                }
                for j in 0..16 {
                    m[i][j] += a * s.B[k][j] as i64;
                }
            }
        }
        for i in 0..16 {
            for j in 0..16 {
                assert!(m[i][j] >= i32::MIN as i64 && m[i][j] <= i32::MAX as i64, "honest A*B fits i32");
                s.C[i][j] = m[i][j] as i32;
            }
        }
        m
    }

    fn run_both(s: &AMAMatMul) -> (bool, bool) {
        let avx2 = if std::is_x86_feature_detected!("avx2") {
            Some(unsafe { freivalds_inner_avx2(&s.Rs, &s.A, &s.B, &s.C) })
        } else {
            None
        };
        let scalar = freivalds_inner_scalar(&s.Rs, &s.A, &s.B, &s.C);
        (avx2.unwrap_or(scalar), scalar)
    }

    #[test]
    fn honest_witness_still_accepted() {
        let mut s = borrow_scratch();
        let mut rng = Rng(0x1234_5678_9abc_def0);
        fill_random(&mut s, &mut rng);
        set_c_to_product(&mut s);
        let (avx2, scalar) = run_both(&s);
        assert!(scalar, "scalar rejected an honest C = A*B");
        assert!(avx2, "avx2 rejected an honest C = A*B");
    }

    #[test]
    fn i32min_wrap_now_rejected() {
        let mut s = borrow_scratch();
        for row in s.A.iter_mut() {
            row.fill(0);
        }
        for row in s.B.iter_mut() {
            row.fill(0);
        }
        for row in s.C.iter_mut() {
            row.fill(0);
        }
        s.Rs = [[2; 16], [-4; 16], [6; 16]];
        s.C[0][0] = i32::MIN; // A*B = 0 but C != 0

        let (avx2, scalar) = run_both(&s);
        assert!(!scalar, "scalar still accepts the i32::MIN wrap");
        assert!(!avx2, "avx2 still accepts the i32::MIN wrap");
    }

    #[test]
    fn avx2_matches_scalar_including_adversarial_c() {
        if !std::is_x86_feature_detected!("avx2") {
            eprintln!("skipping cross-check: no AVX2 on this host");
            return;
        }
        let mut s = borrow_scratch();
        let mut rng = Rng(0xdead_beef_0bad_f00d);
        for trial in 0..12 {
            fill_random(&mut s, &mut rng);
            let honest = trial % 2 == 0;
            if honest {
                set_c_to_product(&mut s);
            } else {
                // full-range, often-huge C -> exercises the i64 widening path
                for i in 0..16 {
                    for j in 0..16 {
                        s.C[i][j] = rng.next() as i32;
                    }
                }
            }
            let avx2 = unsafe { freivalds_inner_avx2(&s.Rs, &s.A, &s.B, &s.C) };
            let scalar = freivalds_inner_scalar(&s.Rs, &s.A, &s.B, &s.C);
            assert_eq!(avx2, scalar, "avx2 vs scalar disagree on trial {trial}");
            if honest {
                assert!(avx2, "honest C rejected on trial {trial}");
            }
        }
    }
}
