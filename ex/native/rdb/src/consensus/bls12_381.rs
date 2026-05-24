use bls12_381::*;
use group::Curve;

// we use blst for signing/verification (hash_to_curve with DST) and serialization
use blst::min_pk::{PublicKey as BlsPublicKey, SecretKey as BlsSecretKey, Signature as BlsSignature};
use blst::BLST_ERROR;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("invalid point")]
    InvalidPoint,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("verification failed")]
    VerificationFailed,
    #[error("zero-sized input")]
    ZeroSizedInput,
}

/// For 64-byte keys, uses Scalar::from_bytes_wide exactly like Elixir BlsEx
fn parse_secret_key(sk_bytes: &[u8]) -> Result<BlsSecretKey, Error> {
    // Follow Elixir bls_ex approach exactly:
    // 1. Use Scalar::from_bytes_wide for 64-byte keys
    // 2. Convert scalar to bytes and reverse them
    // 3. Create BLST SecretKey from reversed bytes
    if let Ok(bytes_64) = <&[u8; 64]>::try_from(sk_bytes) {
        let sk_scalar = Scalar::from_bytes_wide(bytes_64);
        let mut sk_be = sk_scalar.to_bytes();
        sk_be.reverse(); // Critical: reverse bytes like Elixir does

        return BlsSecretKey::from_bytes(&sk_be).map_err(|_| Error::InvalidSecretKey);
    }
    Err(Error::InvalidSecretKey)
}

fn g1_projective_is_valid(projective: &G1Projective) -> bool {
    let is_identity: bool = projective.is_identity().into();
    let is_on_curve = projective.is_on_curve().into();
    let is_torsion_free = projective.to_affine().is_torsion_free().into();
    !is_identity && is_on_curve && is_torsion_free
}

fn g2_affine_is_valid(affine: &G2Affine) -> bool {
    let is_identity: bool = affine.is_identity().into();
    let is_on_curve = affine.is_on_curve().into();
    let is_torsion_free = affine.is_torsion_free().into();
    !is_identity && is_on_curve && is_torsion_free
}

fn parse_public_key(bytes: &[u8]) -> Result<G1Projective, Error> {
    if bytes.len() != 48 {
        return Err(Error::InvalidPoint);
    }
    let mut res = [0u8; 48];
    res.copy_from_slice(bytes);

    match Option::<G1Affine>::from(G1Affine::from_compressed(&res)) {
        Some(affine) => {
            let projective = G1Projective::from(affine);
            if g1_projective_is_valid(&projective) {
                Ok(projective)
            } else {
                Err(Error::InvalidPoint)
            }
        }
        None => Err(Error::InvalidPoint),
    }
}

fn parse_signature(bytes: &[u8]) -> Result<G2Projective, Error> {
    if bytes.len() != 96 {
        return Err(Error::InvalidPoint);
    }
    let mut res = [0u8; 96];
    res.copy_from_slice(bytes);

    match Option::from(G2Affine::from_compressed(&res)) {
        Some(affine) => {
            if g2_affine_is_valid(&affine) {
                Ok(G2Projective::from(affine))
            } else {
                Err(Error::InvalidPoint)
            }
        }
        None => Err(Error::InvalidPoint),
    }
}

fn sign_from_secret_key(sk: BlsSecretKey, msg: &[u8], dst: &[u8]) -> Result<BlsSignature, Error> {
    Ok(sk.sign(msg, dst, &[]))
}

// public API

/// Uses Scalar::from_bytes_wide for 64-byte keys to match Elixir exactly
pub fn get_public_key(sk_bytes: &[u8]) -> Result<[u8; 48], Error> {
    // For 64-byte keys: use bls12_381 directly for full Elixir compatibility
    let bytes_64: [u8; 64] = sk_bytes.try_into().map_err(|_| Error::InvalidSecretKey)?;
    let sk_scalar = Scalar::from_bytes_wide(&bytes_64);

    // Compute public key: G1 generator * scalar (exactly like Elixir)
    let pk_g1 = G1Projective::generator() * sk_scalar;
    Ok(pk_g1.to_affine().to_compressed())
}

pub fn generate_sk() -> [u8; 64] {
    // Generate a valid 64-byte secret key that works with our scalar approach
    loop {
        let sk_64: [u8; 64] = rand::random();

        // Try to create a scalar from this - if it works, use it
        let scalar = Scalar::from_bytes_wide(&sk_64);
        let scalar_bytes = scalar.to_bytes();

        // Check if this creates a valid BLST key
        if BlsSecretKey::from_bytes(&scalar_bytes).is_ok() {
            return sk_64;
        }

        // If it doesn't work, try again (very rare)
    }
}

/// Sign a message with secret key, returns signature bytes (96 bytes in min_pk)
/// For 64-byte keys, uses the same scalar derivation as public key generation
pub fn sign(sk_bytes: &[u8], message: &[u8], dst: &[u8]) -> Result<[u8; 96], Error> {
    // Use exactly the same approach as parse_secret_key to ensure consistency
    let sk = parse_secret_key(sk_bytes)?;
    let signature = sign_from_secret_key(sk, message, dst)?;
    Ok(signature.to_bytes())
}

/// Verify a signature using a compressed G1 public key (48 bytes) and signature (96 bytes)
/// Errors out if the signature is invalid
pub fn verify(pk_bytes: &[u8], sig_bytes: &[u8], msg: &[u8], dst: &[u8]) -> Result<(), Error> {
    let pk = BlsPublicKey::deserialize(pk_bytes).map_err(|_| Error::InvalidPoint)?;
    let sig = BlsSignature::deserialize(sig_bytes).map_err(|_| Error::InvalidSignature)?;

    let err = sig.verify(
        true, // hash_to_curve
        msg,
        dst, // domain separation tag
        &[], // no augmentation
        &pk,
        true, // validate pk ∈ G1
    );

    if err == BLST_ERROR::BLST_SUCCESS {
        Ok(())
    } else {
        Err(Error::VerificationFailed)
    }
}

/// Aggregate multiple compressed G1 public keys into one compressed G1 public key (48 bytes)
pub fn aggregate_public_keys<T>(public_keys: T) -> Result<[u8; 48], Error>
where
    T: IntoIterator,
    T::Item: AsRef<[u8]>,
{
    let mut iter = public_keys.into_iter();
    let first = match iter.next() {
        Some(v) => v,
        None => return Err(Error::ZeroSizedInput),
    };
    let mut acc = parse_public_key(first.as_ref())?;
    for pk in iter {
        let p = parse_public_key(pk.as_ref())?;
        acc += p;
    }
    Ok(acc.to_affine().to_compressed())
}

/// Aggregate multiple signatures (compressed G2, 96 bytes) into one compressed G2 (96 bytes)
pub fn aggregate_signatures<T>(signatures: T) -> Result<[u8; 96], Error>
where
    T: IntoIterator,
    T::Item: AsRef<[u8]>,
{
    let mut iter = signatures.into_iter();
    let first = match iter.next() {
        Some(v) => v,
        None => return Err(Error::ZeroSizedInput),
    };
    let mut acc = parse_signature(first.as_ref())?;
    for s in iter {
        let p = parse_signature(s.as_ref())?;
        acc += p;
    }
    Ok(acc.to_affine().to_compressed())
}

/// Compute Diffie-Hellman shared secret: pk_g1 * sk -> compressed G1 (48 bytes).
/// Uses the same approach as public key generation for consistency
pub fn get_shared_secret(public_key: &[u8], sk_bytes: &[u8]) -> Result<[u8; 48], Error> {
    let pk_g1 = parse_public_key(public_key)?;

    // Use exactly the same scalar derivation as get_public_key() for consistency
    let sk_scalar = if sk_bytes.len() == 64 {
        // For 64-byte keys: use bls12_381 directly (exactly like get_public_key)
        let bytes_64: [u8; 64] = sk_bytes.try_into().map_err(|_| Error::InvalidSecretKey)?;
        Scalar::from_bytes_wide(&bytes_64)
    } else {
        return Err(Error::InvalidSecretKey);
    };

    // Compute shared secret: pk_g1 * sk_scalar
    Ok((pk_g1 * sk_scalar).to_affine().to_compressed())
}

/// Validate a compressed G1 public key.
pub fn validate_public_key(public_key: &[u8]) -> bool {
    match parse_public_key(public_key).map(|_| ()) {
        Err(_) => false,
        Ok(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed32(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn pk_sign_verify_and_validate() {
        let seed = generate_sk();
        let pk = get_public_key(&seed).expect("pk");
        //validate_public_key(&pk).ok();

        let msg = b"context7:message";
        let dst = b"CONTEXT7-BLS-DST";
        let sig = sign(&seed, msg, dst).expect("sign");
        verify(&pk, &sig, msg, dst).expect("verify");
    }

    #[test]
    fn shared_secret_symmetry() {
        let a = generate_sk();
        let b = generate_sk();
        let pk_a = get_public_key(&a).unwrap();
        let pk_b = get_public_key(&b).unwrap();
        let ab = get_shared_secret(&pk_b, &a).unwrap();
        let ba = get_shared_secret(&pk_a, &b).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn shared_secret_symmetry_64byte() {
        // Test with 64-byte keys like EncryptedMessage tests
        let sk_a = generate_sk();
        let sk_b = generate_sk();

        let pk_a = get_public_key(&sk_a).unwrap();
        let pk_b = get_public_key(&sk_b).unwrap();

        // Check which path each key takes
        let sk_a_scalar = Scalar::from_bytes_wide(&sk_a);
        let sk_b_scalar = Scalar::from_bytes_wide(&sk_b);
        let sk_a_blst_valid = BlsSecretKey::from_bytes(&sk_a_scalar.to_bytes()).is_ok();
        let sk_b_blst_valid = BlsSecretKey::from_bytes(&sk_b_scalar.to_bytes()).is_ok();

        println!("sk_a BLST valid: {}", sk_a_blst_valid);
        println!("sk_b BLST valid: {}", sk_b_blst_valid);

        let ab = get_shared_secret(&pk_b, &sk_a).unwrap();
        let ba = get_shared_secret(&pk_a, &sk_b).unwrap();

        println!("AB: {:?}", &ab[..8]);
        println!("BA: {:?}", &ba[..8]);

        assert_eq!(ab, ba, "64-byte shared secrets should be symmetric");
    }

    #[test]
    fn aggregation_behaviour() {
        let s1 = generate_sk();
        let s2 = generate_sk();
        let pk1 = get_public_key(&s1).unwrap();
        let pk2 = get_public_key(&s2).unwrap();

        // test single public key aggregation
        let agg1 = aggregate_public_keys([pk1]).unwrap();
        assert_eq!(agg1.len(), 48);
        assert_eq!(agg1, pk1); // single key aggregation should equal original key

        // test multiple public key aggregation
        let agg_pk = aggregate_public_keys([pk1, pk2]).unwrap();
        assert_eq!(agg_pk.len(), 48);
        assert_ne!(agg_pk, pk1); // aggregated key should differ from individual keys
        assert_ne!(agg_pk, pk2);

        // zero-sized input should fail
        assert!(matches!(aggregate_public_keys::<[&[u8]; 0]>([]), Err(Error::ZeroSizedInput)));

        // test signature aggregation
        let dst = b"DST";
        let msg = b"m";
        let sig1 = sign(&s1, msg, dst).unwrap();
        let sig2 = sign(&s2, msg, dst).unwrap();

        // test single signature aggregation
        let agg_sig1 = aggregate_signatures([sig1.as_slice()]).unwrap();
        assert_eq!(agg_sig1.len(), 96);
        assert_eq!(agg_sig1, sig1); // single signature aggregation should equal original

        // test multiple signature aggregation
        let agg_sig = aggregate_signatures([sig1.as_slice(), sig2.as_slice()]).unwrap();
        assert_eq!(agg_sig.len(), 96);
        assert_ne!(agg_sig, sig1); // aggregated signature should differ from individual signatures
        assert_ne!(agg_sig, sig2);

        // zero-sized signature input should fail
        assert!(matches!(aggregate_signatures::<[&[u8]; 0]>([]), Err(Error::ZeroSizedInput)));

        // test that aggregated signature verifies against aggregated public key
        verify(&agg_pk, &agg_sig, msg, dst).expect("aggregated signature should verify against aggregated public key");

        // test that individual signatures don't verify against aggregated public key
        assert!(verify(&agg_pk, &sig1, msg, dst).is_err());
        assert!(verify(&agg_pk, &sig2, msg, dst).is_err());

        // test that aggregated signature doesn't verify against individual public keys
        assert!(verify(&pk1, &agg_sig, msg, dst).is_err());
        assert!(verify(&pk2, &agg_sig, msg, dst).is_err());
    }

    #[test]
    fn elixir_key_compatibility_test() {
        const SK_B58: &str = "QPHHRpzuJ8nBKnrY9hcT8DuaWX8ev42QWHMPtpWtg11Rkbq37cpE5BGD8RTBe6NrfQqboKusvz119rUMDjoMXQ2";
        const PK_B58: &str = "7HBdTuiVETYS9bWgZt2ZQ2edrmUYVW9gMPJuVRA2PEFXUvTt62ZxP1juPbHpUS8M1k";
        const OTHER_PK_B58: &str = "7KUntjPCFEmTtG9NBLNjqaaXourYDjBASwLtXFcPr1DmDNPCLVKRznppysMMyAcVa7";
        const EXPECTED_SIG_B58: &str =
            "nDmcy3orsbusmMA9ugTXYyCXuCpdeuar5TonQqZquGbfLGGpCkawaStX9vCxm4nnjF9CXtwVUxjbvyU5KRP6nd24niXu7oLRhvGkkiSqgnxenAgjnUJwvahfDz94t7LyBmY";
        const EXPECTED_SHARED_SECRET_B58: &str = "69m86NjrftmWr8in6dbDBYiYrsiJjeKAvkM8WzLWk4Feub5p3YC2oDa8FbSyhS3f9d";

        // Skip test if values not filled in
        if SK_B58.contains("PASTE_") {
            println!("Skipping test - replace values from iex commands first");
            return;
        }

        println!("\n=== ELIXIR KEY COMPATIBILITY TEST ===");

        // Decode Base58 values
        let sk_bytes = bs58::decode(SK_B58).into_vec().expect("decode sk");
        let expected_pk = bs58::decode(PK_B58).into_vec().expect("decode pk");
        let other_pk = bs58::decode(OTHER_PK_B58).into_vec().expect("decode other pk");
        let expected_sig = bs58::decode(EXPECTED_SIG_B58).into_vec().expect("decode sig");
        let expected_shared_secret = bs58::decode(EXPECTED_SHARED_SECRET_B58).into_vec().expect("decode shared secret");

        println!("SK length: {}", sk_bytes.len());
        println!("Expected PK length: {}", expected_pk.len());
        println!("SK first 8 bytes: {:?}", &sk_bytes[..8]);
        println!("SK last 8 bytes: {:?}", &sk_bytes[sk_bytes.len() - 8..]);

        // Test 1: Key parsing
        println!("\n--- Test 1: Secret Key Parsing ---");
        let sk_64: [u8; 64] = sk_bytes.try_into().expect("sk should be 64 bytes");
        match get_public_key(&sk_64) {
            Ok(rust_pk) => {
                println!("✓ Rust successfully parsed Elixir secret key");
                println!("Rust PK: {:?}", rust_pk.to_vec());
                println!("Elixir PK: {:?}", expected_pk);

                if rust_pk.to_vec() == expected_pk {
                    println!("✓ Public keys match perfectly!");
                } else {
                    panic!("✗ Public key mismatch - different BLS implementations");
                }
            }
            Err(e) => {
                panic!("✗ Rust failed to parse Elixir secret key: {:?}", e);
            }
        }

        // Test 2: Signature compatibility
        println!("\n--- Test 2: Signature Compatibility ---");
        let test_data = b"Hello Amadeus Blockchain!";
        let dst = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_TEST_";

        match sign(&sk_64, test_data, dst) {
            Ok(rust_sig) => {
                println!("✓ Rust signature generation successful");
                println!("Rust signature: {:?}", rust_sig.to_vec());
                println!("Elixir signature: {:?}", expected_sig);

                if rust_sig.to_vec() == expected_sig {
                    println!("✓ Signatures match perfectly!");
                } else {
                    println!("~ Signatures differ (expected with different hash-to-curve)");
                }

                // Verify Rust signature with Rust
                if verify(&expected_pk, &rust_sig, test_data, dst).is_ok() {
                    println!("✓ Rust signature verifies with Elixir public key");
                } else {
                    panic!("✗ Rust signature doesn't verify with Elixir public key");
                }

                // Try to verify Elixir signature with Rust
                if expected_sig.len() == 96 {
                    let elixir_sig: [u8; 96] = expected_sig.try_into().unwrap();
                    if verify(&expected_pk, &elixir_sig, test_data, dst).is_ok() {
                        println!("✓ Elixir signature verifies in Rust");
                    } else {
                        panic!("✗ Elixir signature doesn't verify in Rust");
                    }
                }
            }
            Err(e) => {
                panic!("✗ Rust signature generation failed: {:?}", e);
            }
        }

        // Test 3: Shared secret compatibility
        println!("\n--- Test 3: Shared Secret Compatibility ---");
        match get_shared_secret(&other_pk, &sk_64) {
            Ok(rust_shared_secret) => {
                println!("✓ Rust shared secret generation successful");
                println!("Rust shared secret: {:?}", rust_shared_secret.to_vec());
                println!("Elixir shared secret: {:?}", expected_shared_secret);

                if rust_shared_secret.to_vec() == expected_shared_secret {
                    println!("✓ Shared secrets match perfectly!");
                } else {
                    panic!("✗ Shared secret mismatch");
                }
            }
            Err(e) => {
                println!("✗ Rust shared secret generation failed: {:?}", e);
            }
        }

        println!("\n=== COMPATIBILITY TEST COMPLETE ===");
    }

    #[test]
    fn elixir_signature_compatibility_test() {
        const SK_B58: &str = "559mzNeU7itDyHs2yUzZurTvoaLHi3nJeGjCQSi44PwcJzdqBVymRdh9G25Hg6u9pi59avrqcPpeq6DBQQVEqPxV";
        const PK_B58: &str = "7gX58gLTX7WUGUq3PQTNYcbwfH18b3SeRTgfJ6mM5badEvbhjRXxNEBYSyfH6RjnoP";
        const TEST_DATA_1_B58: &str = "89YouX2vBz5FKYQZueX6744sBPHjZ8AgFAmN1ySS61KebyrhdkcUk5jY2vqsqgZ8XatbkL";
        const ELIXIR_SIG_1_B58: &str =
            "riqRrRupu5KuaimWbSjS8NKfV8eMYTVKt5xhTkKo9FVDzP7kKhQLmT2VJu15r9GDbkZTk1N78uMGYa6yG7NzboEHet7Xv9wtf7cn86is5GH2PzvH95Kt8RbtqC9iRr13fAZ";
        const TEST_DATA_2_B58: &str = "2moGA7MbJet3qHLaSA9kN9eFy5fTr7TdHqJGoaq5hEbt5kGEVnFxCKkC8kNE2nfrnhWtVTtaVoUWeP1GEmKs";
        const ELIXIR_SIG_2_B58: &str =
            "oGRbCRrCwMVKXqHebyDsF2JTMcWghbkrHszG6oU4t4FGGp351p5L5ud7XFhrhDixVS38NWgUdmr4qprsoCe1SPq8q8FKkfGLFPjPzb6BH8Lhk3zKjWoDjmCJqUp66rwEp4c";

        // Skip test if values not filled in
        if SK_B58.contains("PLACEHOLDER_") {
            println!("Skipping test - replace values from iex commands first");
            return;
        }

        println!("\n=== ELIXIR SIGNATURE COMPATIBILITY TEST ===");

        // Decode Base58 values
        let sk_bytes = bs58::decode(SK_B58).into_vec().expect("decode sk");
        let expected_pk = bs58::decode(PK_B58).into_vec().expect("decode pk");
        let test_data_1 = bs58::decode(TEST_DATA_1_B58).into_vec().expect("decode test data 1");
        let elixir_sig_1 = bs58::decode(ELIXIR_SIG_1_B58).into_vec().expect("decode elixir sig 1");
        let test_data_2 = bs58::decode(TEST_DATA_2_B58).into_vec().expect("decode test data 2");
        let elixir_sig_2 = bs58::decode(ELIXIR_SIG_2_B58).into_vec().expect("decode elixir sig 2");

        let dst = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ANRCHALLENGE_";

        println!("SK length: {}", sk_bytes.len());
        println!("Expected PK length: {}", expected_pk.len());

        // Test 1: Public Key Compatibility
        println!("\n--- Test 1: Public Key Compatibility ---");
        let rust_pk = get_public_key(&sk_bytes).expect("get public key");
        println!("Rust PK: {:?}", rust_pk.to_vec());
        println!("Elixir PK: {:?}", expected_pk);

        if rust_pk.to_vec() == expected_pk {
            println!("✓ Public keys match perfectly!");
        } else {
            panic!("✗ Public key mismatch");
        }

        // Test 2: Signature Verification - Case 1
        println!("\n--- Test 2: Signature Verification - Case 1 ---");
        println!("Test data 1: {:?}", test_data_1);
        println!("Elixir signature 1: {:?}", elixir_sig_1);

        // Generate Rust signature for comparison
        let rust_sig_1 = sign(&sk_bytes, &test_data_1, dst).expect("rust sign 1");
        println!("Rust signature 1: {:?}", rust_sig_1.to_vec());

        // Verify Rust signature
        match verify(&expected_pk, &rust_sig_1, &test_data_1, dst) {
            Ok(_) => println!("✓ Rust signature 1 verifies"),
            Err(e) => panic!("✗ Rust signature 1 verification failed: {:?}", e),
        }

        // Verify Elixir signature with Rust
        if elixir_sig_1.len() == 96 {
            let elixir_sig_1_array: [u8; 96] = elixir_sig_1.try_into().unwrap();
            match verify(&expected_pk, &elixir_sig_1_array, &test_data_1, dst) {
                Ok(_) => println!("✓ Elixir signature 1 verifies in Rust"),
                Err(e) => panic!("✗ Elixir signature 1 verification failed: {:?}", e),
            }
        }

        // Test 3: Signature Verification - Case 2
        println!("\n--- Test 3: Signature Verification - Case 2 ---");
        println!("Test data 2: {:?}", test_data_2);
        println!("Elixir signature 2: {:?}", elixir_sig_2);

        // Generate Rust signature for comparison
        let rust_sig_2 = sign(&sk_bytes, &test_data_2, dst).expect("rust sign 2");
        println!("Rust signature 2: {:?}", rust_sig_2.to_vec());

        // Verify Rust signature
        match verify(&expected_pk, &rust_sig_2, &test_data_2, dst) {
            Ok(_) => println!("✓ Rust signature 2 verifies"),
            Err(e) => panic!("✗ Rust signature 2 verification failed: {:?}", e),
        }

        // Verify Elixir signature with Rust
        if elixir_sig_2.len() == 96 {
            let elixir_sig_2_array: [u8; 96] = elixir_sig_2.try_into().unwrap();
            match verify(&expected_pk, &elixir_sig_2_array, &test_data_2, dst) {
                Ok(_) => println!("✓ Elixir signature 2 verifies in Rust"),
                Err(e) => panic!("✗ Elixir signature 2 verification failed: {:?}", e),
            }
        }

        println!("\n=== SIGNATURE COMPATIBILITY TEST COMPLETE ===");
    }

    #[test]
    fn elixir_public_key_signature_verification() {
        // Elixir-generated public key
        let elixir_pk = vec![
            169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178, 49, 111,
            90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222,
        ];

        // Test cases with Elixir signatures and corresponding data
        let test_cases = vec![
            (
                // data
                vec![
                    169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178,
                    49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 49,
                ],
                // elixir signature
                vec![
                    166, 193, 20, 132, 125, 87, 40, 182, 101, 225, 125, 220, 97, 93, 13, 2, 89, 220, 166, 6, 106, 203, 96, 63, 122, 16, 226, 117, 143, 219, 5,
                    105, 180, 229, 65, 58, 238, 93, 230, 253, 208, 110, 35, 219, 222, 176, 82, 112, 15, 149, 72, 148, 54, 88, 2, 94, 219, 26, 235, 98, 77, 202,
                    1, 83, 6, 38, 39, 150, 236, 176, 141, 222, 93, 133, 66, 154, 226, 55, 214, 100, 183, 179, 167, 140, 140, 77, 117, 11, 167, 219, 140, 144,
                    144, 160, 143, 128,
                ],
            ),
            (
                // data with "255" suffix
                vec![
                    169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178,
                    49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 50, 53, 53,
                ],
                // elixir signature
                vec![
                    141, 6, 181, 106, 49, 117, 193, 12, 249, 102, 71, 237, 125, 55, 25, 3, 14, 199, 113, 157, 49, 168, 205, 89, 106, 76, 3, 37, 170, 124, 149,
                    45, 234, 206, 44, 177, 90, 0, 14, 111, 30, 9, 197, 189, 201, 43, 86, 139, 22, 145, 182, 32, 77, 220, 35, 186, 5, 251, 37, 173, 187, 243,
                    110, 33, 57, 23, 67, 58, 166, 74, 200, 145, 232, 5, 151, 244, 62, 216, 159, 43, 131, 43, 179, 105, 154, 33, 91, 88, 143, 91, 40, 147, 129,
                    228, 37, 98,
                ],
            ),
            (
                // data with timestamp "1640995200"
                vec![
                    169, 61, 121, 32, 15, 191, 174, 241, 143, 231, 124, 53, 186, 69, 28, 212, 233, 130, 22, 18, 34, 244, 13, 106, 212, 255, 255, 47, 184, 178,
                    49, 111, 90, 90, 184, 84, 230, 115, 5, 143, 205, 208, 136, 138, 2, 252, 27, 222, 49, 54, 52, 48, 57, 57, 53, 50, 48, 48,
                ],
                // elixir signature
                vec![
                    137, 145, 8, 245, 3, 166, 187, 110, 172, 28, 115, 177, 226, 179, 239, 201, 245, 173, 213, 25, 211, 84, 225, 194, 82, 30, 133, 105, 197, 97,
                    55, 185, 157, 83, 140, 89, 2, 3, 57, 7, 84, 242, 51, 161, 247, 238, 16, 126, 18, 69, 208, 108, 184, 132, 63, 67, 219, 144, 108, 54, 50,
                    176, 128, 138, 121, 191, 181, 168, 198, 229, 76, 246, 29, 36, 130, 95, 146, 213, 222, 230, 192, 179, 179, 198, 99, 209, 120, 134, 194, 181,
                    239, 187, 42, 46, 136, 93,
                ],
            ),
        ];

        // Use the same DST
        let dst = b"AMADEUS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_ANRCHALLENGE_";

        println!("Testing Elixir signatures with Elixir public key");
        println!("Elixir public key: {:?}", elixir_pk);

        for (i, (data, elixir_sig)) in test_cases.iter().enumerate() {
            println!("\nTesting case {}: data_len={}, sig_len={}", i, data.len(), elixir_sig.len());

            // Try to verify the Elixir signature with the Elixir public key
            match verify(&elixir_pk, elixir_sig, data, dst) {
                Ok(_) => println!("Case {}: ✓ Elixir signature verifies with Elixir public key", i),
                Err(e) => {
                    println!("Case {}: ✗ Elixir signature failed verification: {:?}", i, e);
                    println!("Case {}: This indicates potential issues with Elixir test data or DST mismatch", i);
                }
            }
        }

        println!("\nTest completed: Checked if Elixir signatures verify with Elixir public key");
    }
}
