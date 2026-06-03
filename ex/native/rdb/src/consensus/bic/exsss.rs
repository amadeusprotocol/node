/// Erlang :exsss (Xorshift116**) PRNG implementation
///
/// This provides exact compatibility with Erlang's :rand.seed(:exsss, seed) for
/// deterministic shuffling in consensus-critical code.
///
/// Algorithm: Xorshift116** - a scrambled linear generator with:
/// - 58 bits precision
/// - Period of 2^116-1
/// - Two 64-bit state values (s0, s1)
/// - Output scrambling via (S*5 rotl 7)*9

/// Xorshift116** state (matches Erlang :exsss)
#[derive(Debug, Clone, Copy)]
pub struct Exsss {
    s0: u64,
    s1: u64,
}

impl Exsss {
    /// Create new generator from 256-bit seed (little-endian)
    /// Matches Erlang: :rand.seed(:exsss, seed) where seed is <<...::256-little>>
    pub fn from_seed(seed_bytes: &[u8; 32]) -> Self {
        // extract integer seed from first bytes (matches Erlang <<seed::256-little>>)
        let seed = u128::from_le_bytes(seed_bytes[0..16].try_into().unwrap());

        Self::from_seed_u128(seed)
    }

    /// Create from integer seed (matches Erlang :rand.seed(:exsss, integer))
    pub fn from_seed_u128(seed: u128) -> Self {
        // Erlang's seed58(2, X) implementation
        let (s0, x1) = seed58(seed as u64);
        let (s1, _x2) = seed58(x1);

        Self { s0, s1 }
    }

    /// Generate next random u64 value (internal, 58-bit precision)
    /// Matches Erlang :rand.exsss_next
    fn next_u64(&mut self) -> u64 {
        const MASK_58: u64 = (1u64 << 58) - 1;

        // Erlang state format: [S1|S0] (improper list: head=S1, tail=S0)
        // Our struct stores (s0, s1) matching the seed58 output order
        // exsss_next([S1|S0]) parameter: S1=head, S0=tail
        // So when calling with our state: S1=self.s0 (first seed), S0=self.s1 (second seed)
        let s1 = self.s0;
        let s0 = self.s1;

        // S0_1 = S0 & MASK_58
        let s0_1 = s0 & MASK_58;

        // exs_next(S0_1, S1, S1_b):
        // S1_b = (S1 & MASK_58) ^ ((S1 << 24) & MASK_58)
        // NewS1 = S1_b ^ S0_1 ^ (S1_b >> 11) ^ (S0_1 >> 41)
        let s1_masked = s1 & MASK_58;
        let s1_b = s1_masked ^ ((s1_masked << 24) & MASK_58);
        let new_s1 = s1_b ^ s0_1 ^ (s1_b >> 11) ^ (s0_1 >> 41);

        // scramble_starstar(S0_1, ...):
        // V_a = S0_1 + (S0_1 << 2) mod 2^58  // S0_1 * 5
        // V_b = rotl(V_a, 7) in 58-bit space
        // Output = (V_b + (V_b << 3)) mod 2^58  // V_b * 9
        let v_a = (s0_1 + ((s0_1 << 2) & MASK_58)) & MASK_58;
        let v_b = ((v_a << 7) | (v_a >> 51)) & MASK_58;
        let output = (v_b + ((v_b << 3) & MASK_58)) & MASK_58;

        // Returns state [S0_1|NewS1]
        // Our struct: s0=S0_1 (new first), s1=NewS1 (new second)
        self.s0 = s0_1;
        self.s1 = new_s1 & MASK_58;

        output
    }

    /// Generate random float in range [0.0, 1.0) (matches Erlang :rand.uniform())
    pub fn uniform_float(&mut self) -> f64 {
        // exsss_uniform: (I >> 5) * 2^-53
        // where I is 58-bit output from next_u64
        const TWO_POW_MINUS53: f64 = 1.0 / (1u64 << 53) as f64;

        let i = self.next_u64();
        let shifted = i >> 5; // 58 - 53 = 5
        (shifted as f64) * TWO_POW_MINUS53
    }

    /// Generate random integer in range [1, n] (matches Erlang :rand.uniform(n))
    pub fn uniform(&mut self, range: u64) -> u64 {
        self.uniform_internal(range, 0)
    }

    fn uniform_internal(&mut self, range: u64, depth: u32) -> u64 {
        const BIT_58: u64 = 1u64 << 58;

        if range == 0 {
            return 0;
        }

        let v = self.next_u64(); // already 58-bit

        // Erlang checks: if 0 <= MaxMinusRange (i.e., Range <= BIT_58)
        // For our use case, range is always small (1000), so this is always true

        // fast path: if v < range, return v + 1
        if v < range {
            return v + 1;
        }

        // rejection sampling
        let i = v % range;
        let max_minus_range = BIT_58 - range;

        if v - i <= max_minus_range {
            i + 1
        } else {
            // v in truncated top range, retry
            self.uniform_internal(range, depth + 1)
        }
    }

    /// Shuffle a slice in place (matches Elixir Enum.shuffle)
    /// Uses sort_by with random floats, not Fisher-Yates
    pub fn shuffle<T: Clone>(&mut self, slice: &mut [T]) {
        if slice.len() <= 1 {
            return;
        }

        // Generate random key for each element with its value
        let mut keyed: Vec<(f64, T)> = slice.iter().map(|val| (self.uniform_float(), val.clone())).collect();

        // Sort by random keys.
        keyed.sort_by(|a, b| a.0.total_cmp(&b.0));

        // Write sorted values back
        for (idx, (_key, val)) in keyed.into_iter().enumerate() {
            slice[idx] = val;
        }
    }
}

/// Splitmix64 next step (matches Erlang splitmix64_next)
/// Returns (Z, NewX) where Z is the output and NewX is the updated state
fn splitmix64_next(x0: u64) -> (u64, u64) {
    let x = x0.wrapping_add(0x9e3779b97f4a7c15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z = z ^ (z >> 31);
    (z, x)
}

/// Seed58 (matches Erlang seed58/1)
/// Returns (Z masked to 58 bits, NewX) skipping zero values
fn seed58(x0: u64) -> (u64, u64) {
    const MASK_58: u64 = (1u64 << 58) - 1;

    let (z0, x) = splitmix64_next(x0);
    let z = z0 & MASK_58;

    if z == 0 {
        // retry with new x
        seed58(x)
    } else {
        (z, x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_initialization() {
        // Verify exact state initialization matches Erlang
        let test_cases = vec![
            (0u128, 153307352162749871u64, 178066366098138612u64),
            (42, 132629853624823445, 67522330609774851),
            (777, 132610673151668814, 220791266393211968),
            (12345, 149043579997720992, 31205127689074925),
            (54321, 144632915686665753, 52714770947718356),
            (99999, 51811462204453670, 95920375662433499),
            (123456789, 161132163074061945, 185172155811622446),
        ];

        for (seed, expected_s0, expected_s1) in test_cases {
            let rng = Exsss::from_seed_u128(seed);
            assert_eq!(rng.s0, expected_s0, "s0 mismatch for seed {}", seed);
            assert_eq!(rng.s1, expected_s1, "s1 mismatch for seed {}", seed);
        }
    }

    #[test]
    fn test_seed_test_1() {
        // Test 1 from Elixir IEx
        let seed_bytes: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let mut rng = Exsss::from_seed(&seed_bytes);

        let r1 = rng.uniform(1000);
        let r2 = rng.uniform(1000);
        let r3 = rng.uniform(1000);

        // Expected: 829, 169, 221
        assert_eq!(r1, 829, "first uniform(1000)");
        assert_eq!(r2, 169, "second uniform(1000)");
        assert_eq!(r3, 221, "third uniform(1000)");
    }

    #[test]
    fn test_shuffle_simple() {
        // Test 2 from Elixir IEx
        let seed_bytes = seed_from_u64(12345);
        let mut rng = Exsss::from_seed(&seed_bytes);

        let mut list = vec![1, 2, 3, 4, 5];
        rng.shuffle(&mut list);

        // Expected: [3, 4, 2, 1, 5]
        assert_eq!(list, vec![3, 4, 2, 1, 5]);
    }

    #[test]
    fn test_shuffle_zero_seed() {
        // Test 3 from Elixir IEx
        let seed_bytes = seed_from_u64(0);
        let mut rng = Exsss::from_seed(&seed_bytes);

        let mut list: Vec<u32> = (1..=10).collect();
        rng.shuffle(&mut list);

        // Expected: [5, 2, 1, 7, 9, 4, 8, 6, 10, 3]
        assert_eq!(list, vec![5, 2, 1, 7, 9, 4, 8, 6, 10, 3]);
    }

    #[test]
    fn test_random_sequence() {
        // Test 5 from Elixir IEx
        let seed_bytes = seed_from_u64(42);
        let mut rng = Exsss::from_seed(&seed_bytes);

        let mut randoms = Vec::new();
        for _ in 0..20 {
            randoms.push(rng.uniform(1000));
        }

        // Expected: [294, 431, 615, 198, 771, 458, 832, 264, 842, 111, 320, 936, 44, 92, 979, 44, 402, 648, 714, 722]
        assert_eq!(randoms, vec![294, 431, 615, 198, 771, 458, 832, 264, 842, 111, 320, 936, 44, 92, 979, 44, 402, 648, 714, 722]);
    }

    #[test]
    fn test_shuffle_large() {
        // Test 7 from Elixir IEx
        let seed_bytes = seed_from_u64(54321);
        let mut rng = Exsss::from_seed(&seed_bytes);

        let mut list: Vec<u32> = (1..=99).collect();
        rng.shuffle(&mut list);

        // Expected first 50: [74, 86, 38, 82, 89, 10, 84, 26, 98, 85, 34, 91, 87, 51, 93, 45, 41, 30, 17, 96, 28, 6, 27, 78, 23, 25, 92, 18, 32, 39, 48, 22, 49, 1, 61, 9, 20, 95, 72, 79, 70, 33, 50, 42, 77, 73, 81, 24, 60, 88]
        let expected_first_50 = vec![
            74, 86, 38, 82, 89, 10, 84, 26, 98, 85, 34, 91, 87, 51, 93, 45, 41, 30, 17, 96, 28, 6, 27, 78, 23, 25, 92, 18, 32, 39, 48, 22, 49, 1, 61, 9, 20,
            95, 72, 79, 70, 33, 50, 42, 77, 73, 81, 24, 60, 88,
        ];
        assert_eq!(list[0..50], expected_first_50[..]);
    }

    #[test]
    fn test_determinism() {
        // Test 8 from Elixir IEx
        let seed_bytes = seed_from_u64(777);

        let mut rng1 = Exsss::from_seed(&seed_bytes);
        let mut list1 = vec![1, 2, 3, 4, 5, 6, 7, 8];
        rng1.shuffle(&mut list1);

        let mut rng2 = Exsss::from_seed(&seed_bytes);
        let mut list2 = vec![1, 2, 3, 4, 5, 6, 7, 8];
        rng2.shuffle(&mut list2);

        // Expected: [2, 3, 6, 4, 1, 5, 7, 8]
        assert_eq!(list1, vec![2, 3, 6, 4, 1, 5, 7, 8]);
        assert_eq!(list1, list2, "determinism check");
    }

    /// Helper: create 32-byte seed from u64 (for simple integer seeds)
    fn seed_from_u64(n: u64) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&n.to_le_bytes());
        bytes
    }
}
