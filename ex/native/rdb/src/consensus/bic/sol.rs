use std::convert::TryInto;

pub const PREAMBLE_SIZE: usize = 240;
pub const MATRIX_SIZE: usize = 1024;
pub const SOL_SIZE: usize = PREAMBLE_SIZE + MATRIX_SIZE; // 1264

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sol {
    pub epoch: u64,
    pub segment_vr_hash: [u8; 32],
    pub pk: [u8; 48],
    pub pop: [u8; 96],
    pub computor: [u8; 48],
    pub nonce: [u8; 12],
    pub tensor_c: [u8; 1024],
}

pub fn unpack(sol: &[u8; SOL_SIZE]) -> Sol {
    let epoch = u32::from_le_bytes(sol[0..4].try_into().unwrap()) as u64;
    let segment_vr_hash: [u8; 32] = sol[4..36].try_into().unwrap();
    let pk: [u8; 48] = sol[36..84].try_into().unwrap();
    let pop: [u8; 96] = sol[84..180].try_into().unwrap();
    let computor: [u8; 48] = sol[180..228].try_into().unwrap();
    let nonce: [u8; 12] = sol[228..240].try_into().unwrap();
    let tensor_c: [u8; 1024] = sol[240..(240 + 1024)].try_into().unwrap();
    Sol {
        epoch,
        segment_vr_hash,
        pk,
        pop,
        computor,
        nonce,
        tensor_c,
    }
}

pub fn verify_hash_diff(_epoch: u64, hash: &[u8], diff_bits: u64) -> bool {
    if diff_bits > 256 {
        return false;
    }
    let (full, rem) = ((diff_bits / 8) as usize, (diff_bits % 8) as u8);
    hash[..full].iter().all(|&b| b == 0) && (rem == 0 || (hash[full] & (0xFF << (8 - rem))) == 0)
}

pub fn verify(
    sol: &[u8; SOL_SIZE],
    solhash: &[u8],
    segment_vr_hash: &[u8],
    vr_b3: &[u8],
    diff_bits: u64,
) -> Result<bool, &'static str> {
    let usol = unpack(sol);
    if segment_vr_hash != &usol.segment_vr_hash {
        return Err("segment_vr_hash");
    }
    if sol.len() != SOL_SIZE {
        return Err("invalid_sol_seed_size");
    }
    Ok(verify_hash_diff(usol.epoch, solhash, diff_bits)
        && crate::consensus::bic::sol_freivalds::freivalds(sol, vr_b3))
}
