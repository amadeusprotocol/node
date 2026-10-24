//! Writes Amadeus-side vectors for the BSC contracts' forge tests:
//!   cargo test --release bridge_vectors_gen -- --ignored
//! -> ../../../bridge/bsc/test/vectors/amadeus.json

use crate::consensus::aggsig::DST_ATT;
use crate::consensus::bls12_381;
use crate::consensus::bridge::order::{chain_name, Order};
use crate::consensus::hbsmt::Hbsmt;
use crate::consensus::hbsmt_common::{HbsmtTerminus, Op};
use crate::consensus::validator_set::ValidatorSet;
use ::bls12_381::{G1Affine, G2Affine};

const WAMA: [u8; 20] = [0x11; 20];
const BSC_RECIPIENT: [u8; 20] = [0x22; 20];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn pad64(b: &[u8]) -> Vec<u8> {
    [vec![0u8; 16], b.to_vec()].concat()
}

//EIP-2537 encodings: G1 = x | y, G2 = x.c0 | x.c1 | y.c0 | y.c1, each Fp left-padded to 64 bytes
fn g1_eip(compressed: &[u8]) -> Vec<u8> {
    let p = G1Affine::from_compressed(compressed.try_into().unwrap()).unwrap().to_uncompressed();
    [pad64(&p[..48]), pad64(&p[48..])].concat()
}

fn g2_eip(compressed: &[u8]) -> Vec<u8> {
    let p = G2Affine::from_compressed(compressed.try_into().unwrap()).unwrap().to_uncompressed();
    [pad64(&p[48..96]), pad64(&p[..48]), pad64(&p[144..192]), pad64(&p[96..144])].concat()
}

struct Key {
    sk: [u8; 64],
    pk: [u8; 48],
}

fn keys(tag: &str, n: usize) -> Vec<Key> {
    (0..n).map(|i| {
        let sk: [u8; 64] = blake3::Hasher::new().update(format!("{tag}{i}").as_bytes()).finalize_xof().fill_and_return();
        let pk = bls12_381::get_public_key(&sk).unwrap();
        Key { sk, pk }
    }).collect()
}

trait Fill { fn fill_and_return(self) -> [u8; 64]; }
impl Fill for blake3::OutputReader {
    fn fill_and_return(mut self) -> [u8; 64] { let mut b = [0u8; 64]; self.fill(&mut b); b }
}

fn mask(bits: &[usize], n: usize) -> Vec<u8> {
    let mut m = vec![0u8; n.div_ceil(8)];
    for i in bits { m[i / 8] |= 1 << (7 - i % 8); }
    m
}

fn claim(height: u64, entry_hash: &[u8; 32], root: &[u8; 32], receipts: &[u8; 32]) -> Vec<u8> {
    [&height.to_be_bytes()[..], entry_hash, root, receipts].concat()
}

fn signed(keys: &[Key], signers: &[usize], msg: &[u8]) -> Vec<u8> {
    let sigs: Vec<[u8; 96]> = signers.iter().map(|i| bls12_381::sign(&keys[*i].sk, msg, DST_ATT).unwrap()).collect();
    g2_eip(&bls12_381::aggregate_signatures(sigs).unwrap())
}

fn proof_json(tree: &mut Hbsmt, key: &[u8]) -> String {
    let p = tree.prove(Some(b"bic"), key);
    let siblings: Vec<String> = p.siblings.iter().map(|s| format!("\"0x{}\"", hex(s))).collect();
    let (path, id, val) = match p.terminus {
        HbsmtTerminus::Leaf { path, identity_hash, value_hash } => (path, identity_hash, value_hash),
        HbsmtTerminus::Empty => panic!("expected leaf"),
    };
    format!("{{\"siblings\":[{}],\"path\":\"0x{}\",\"identity\":\"0x{}\",\"value\":\"0x{}\"}}", siblings.join(","), hex(&path), hex(&id), hex(&val))
}

fn keys_json(keys: &[Key]) -> String {
    let g1: Vec<String> = keys.iter().map(|k| format!("\"0x{}\"", hex(&g1_eip(&k.pk)))).collect();
    format!("[{}]", g1.join(","))
}

#[test]
#[ignore]
fn bridge_vectors_gen() {
    let roster = keys("roster-a-", 10);
    let roster_b = keys("roster-b-", 6);
    let active = mask(&[0, 2, 3, 4, 5, 6, 7, 8, 9], 10);

    let order = Order {
        src_chain: chain_name(b"amadeus-testnet").unwrap(), nonce: 1, sender: roster[0].pk.to_vec(), refund_to: roster[0].pk.to_vec(),
        src_coin: b"AMA".to_vec(), amount: 250_000_000_000, dst_chain: chain_name(b"bsc-testnet").unwrap(), dst_coin: WAMA.to_vec(),
        recipient: BSC_RECIPIENT.to_vec(), output_amount: 250_000_000_000 - 250_000_000_000 / 100_000, ..Default::default()
    };
    let order_key = b"bic:bridge:order:00000000000000000001".to_vec();
    //delivered by a relay: 5 AMA tip out of the order, 0.002 BNB gas drop to the recipient
    let tipped = Order { nonce: 2, output_amount: order.output_amount - 5_000_000_000, gas_drop: 2_000_000_000_000_000, gas_drop_fee: 5_000_000_000, ..order.clone() };
    let tipped_key = b"bic:bridge:order:00000000000000000002".to_vec();
    let record_b = ValidatorSet { validators: roster_b.iter().map(|k| k.pk.to_vec()).collect(), mask_active: mask(&[0, 1, 2, 3, 4, 5], 6) }.encode();
    let record_key = b"bic:epoch:validators:height:000000005001".to_vec();

    let mut tree = Hbsmt::new();
    let mut ops = vec![
        Op::Insert(Some(b"bic".to_vec()), order_key.clone(), order.pack()),
        Op::Insert(Some(b"bic".to_vec()), tipped_key.clone(), tipped.pack()),
        Op::Insert(Some(b"bic".to_vec()), record_key.clone(), record_b.clone()),
    ];
    for i in 0..200u32 {
        ops.push(Op::Insert(Some(b"bic".to_vec()), format!("bic:decoy:{i}").into_bytes(), i.to_be_bytes().to_vec()));
    }
    tree.batch_update(ops);
    let root = tree.root();

    let claim_a = claim(5000, &[0xaa; 32], &root, &[0xbb; 32]);
    let sig_a = signed(&roster, &[0, 2, 3, 4, 5, 6, 7], &claim_a);
    let claim_b = claim(5001, &[0xcc; 32], &[0xdd; 32], &[0xee; 32]);
    let sig_b = signed(&roster_b, &[0, 1, 2, 4, 5], &claim_b);

    let compressed: Vec<String> = roster_b.iter().map(|k| format!("\"0x{}\"", hex(&k.pk))).collect();
    let json = format!(
        "{{\"roster\":{},\"mask_active\":\"0x{}\",\"claim\":\"0x{}\",\"mask\":\"0x{}\",\"sig\":\"0x{}\",\
\"order\":\"0x{}\",\"order_key\":\"0x{}\",\"order_proof\":{},\"tipped\":\"0x{}\",\"tipped_proof\":{},\
\"record_b\":\"0x{}\",\"record_key\":\"0x{}\",\"record_proof\":{},\"roster_b\":{},\"roster_b_compressed\":[{}],\
\"claim_b\":\"0x{}\",\"mask_b\":\"0x{}\",\"sig_b\":\"0x{}\",\"wama\":\"0x{}\",\"recipient\":\"0x{}\"}}",
        keys_json(&roster), hex(&active), hex(&claim_a), hex(&mask(&[0, 2, 3, 4, 5, 6, 7], 10)), hex(&sig_a),
        hex(&order.pack()), hex(&order_key), proof_json(&mut tree, &order_key), hex(&tipped.pack()), proof_json(&mut tree, &tipped_key),
        hex(&record_b), hex(&record_key), proof_json(&mut tree, &record_key), keys_json(&roster_b), compressed.join(","),
        hex(&claim_b), hex(&mask(&[0, 1, 2, 4, 5], 6)), hex(&sig_b), hex(&WAMA), hex(&BSC_RECIPIENT));
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../bridge/bsc/test/vectors");
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(format!("{dir}/amadeus.json"), json).unwrap();
}
