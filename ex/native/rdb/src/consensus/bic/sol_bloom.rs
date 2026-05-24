#[allow(dead_code)]
use blake3::Hasher;

pub const PAGES: u64 = 256;
pub const PAGE_SIZE: u64 = 65_536;
pub const M: u64 = PAGES * PAGE_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seg {
    pub page: u64,
    pub bit_offset: u64,
}

#[inline]
pub fn simulate_fpr(n: f64, m: f64, k: f64) -> f64 {
    assert!(n > 0.0 && m > 0.0 && k > 0.0, "n, m, k must be > 0");
    (1.0 - (-k * n / m).exp()).powf(k)
}

#[inline]
fn indices_from_digest(digest: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    //Iterate in reverse
    for chunk in digest.rchunks_exact(16) {
        let word = u128::from_le_bytes(chunk.try_into().unwrap());
        out.push((word % (M as u128)) as u64);
    }
    out
}

#[inline]
pub fn hash_to_indices(bin: &[u8]) -> Vec<u64> {
    let mut hasher = Hasher::new();
    hasher.update(bin);
    let digest = hasher.finalize();
    indices_from_digest(digest.as_bytes())
}

#[inline]
pub fn segs_from_digest(digest: &[u8]) -> Vec<Seg> {
    let idxs = indices_from_digest(digest);
    idxs.into_iter().map(|idx| Seg { page: (idx / PAGE_SIZE), bit_offset: (idx % PAGE_SIZE) }).collect()
}

#[inline]
pub fn hash(bin: &[u8]) -> Vec<u64> {
    hash_to_indices(bin)
}

#[inline]
pub fn segs(digest: &[u8]) -> Vec<Seg> {
    segs_from_digest(digest)
}
