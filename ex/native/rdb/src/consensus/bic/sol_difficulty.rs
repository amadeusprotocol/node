use std::cmp::{max, min};

const TARGET_SOLS_EPOCH: u64 = 380_000;

const TOL_NUM: u64 = 1;
const TOL_DEN: u64 = 10;

const MAX_STEP_DOWN: u32 = 3;
const MAX_STEP_UP: u32 = 2;
const UP_SLOWDOWN: u32 = 2;

const DIFF_MIN_BITS: u32 = 20;
const DIFF_MAX_BITS: u32 = 64;

fn clamp_bits(b: u32) -> u32 {
    max(DIFF_MIN_BITS, min(b, DIFF_MAX_BITS))
}

fn ceil_div(a: u64, b: u64) -> u64 {
    (a + b - 1) / b
}

fn ilog2_floor(n: u64) -> u32 {
    if n < 1 {
        return 0;
    }
    63 - n.leading_zeros()
}

fn ceil_log2_ratio(a: u64, b: u64) -> u32 {
    if a <= b {
        return 0;
    }
    let d0 = ilog2_floor(a) - ilog2_floor(b);
    if b << d0 >= a {
        d0
    } else {
        d0 + 1
    }
}

pub fn next(prev_bits: u32, sols: u64) -> u32 {
    let target = TARGET_SOLS_EPOCH;

    let lo = max(1, (target * (TOL_DEN - TOL_NUM) + TOL_DEN / 2) / TOL_DEN);
    let hi = (target * (TOL_DEN + TOL_NUM) + TOL_DEN / 2) / TOL_DEN;

    if sols == 0 {
        clamp_bits(prev_bits.saturating_sub(min(MAX_STEP_DOWN, 3)))
    } else if sols > hi {
        let raw = ceil_log2_ratio(sols, target);
        let delta = max(1, min(MAX_STEP_UP, ceil_div(raw as u64, UP_SLOWDOWN as u64) as u32));
        clamp_bits(prev_bits + delta)
    } else if sols < lo {
        let delta = max(1, min(MAX_STEP_DOWN, ceil_log2_ratio(target, max(sols, 1))));
        clamp_bits(prev_bits.saturating_sub(delta))
    } else {
        prev_bits
    }
}
