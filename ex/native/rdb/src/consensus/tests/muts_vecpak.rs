#![cfg(test)]
use crate::consensus::consensus_muts::{mutations_to_vecpak, Mutation};
use vecpak::Term;

fn field<'a>(pairs: &'a [(Term, Term)], name: &[u8]) -> Option<&'a Term> {
    pairs.iter().find(|(k, _)| matches!(k, Term::Binary(b) if b == name)).map(|(_, v)| v)
}
fn bin(t: Option<&Term>) -> Vec<u8> { match t { Some(Term::Binary(b)) => b.clone(), other => panic!("expected binary, got {:?}", other) } }
fn int(t: Option<&Term>) -> u64 { match t { Some(Term::VarInt(v)) => *v as u64, other => panic!("expected int, got {:?}", other) } }

fn to_mutations(bytes: &[u8]) -> Vec<Mutation> {
    let Term::List(items) = vecpak::decode(bytes).unwrap() else { panic!("not a list") };
    items.into_iter().map(|item| {
        let Term::PropList(p) = item else { panic!("not a map") };
        let (op, table, key) = (bin(field(&p, b"op")), bin(field(&p, b"table")), bin(field(&p, b"key")));
        match op.as_slice() {
            b"put" => Mutation::Put { op, table, key, value: bin(field(&p, b"value")) },
            b"delete" => Mutation::Delete { op, table, key },
            b"set_bit" => Mutation::SetBit { op, table, key, value: int(field(&p, b"value")), bloomsize: int(field(&p, b"bloomsize")) },
            b"clear_bit" => Mutation::ClearBit { op, table, key, value: int(field(&p, b"value")) },
            other => panic!("op {:?}", other),
        }
    }).collect()
}

#[test]
fn rust_encoder_reproduces_bytes_stored_by_the_elixir_path() {
    for stored in [&include_bytes!("fixtures/muts_89374417.vecpak")[..], &include_bytes!("fixtures/muts_rev_89374417.vecpak")[..], &[6u8, 0][..]] {
        assert_eq!(mutations_to_vecpak(&to_mutations(stored)), stored);
    }
}

#[test]
fn every_mutation_kind_encodes_as_a_canonical_map() {
    let t = |v: &[u8]| v.to_vec();
    let muts = vec![
        Mutation::Delete { op: t(b"delete"), table: t(b"contractstate"), key: t(b"k") },
        Mutation::Put { op: t(b"put"), table: t(b"contractstate"), key: t(b"k"), value: t(b"") },
        Mutation::SetBit { op: t(b"set_bit"), table: t(b"contractstate"), key: t(b"p"), value: 0, bloomsize: 65536 },
        Mutation::ClearBit { op: t(b"clear_bit"), table: t(b"contractstate"), key: t(b"p"), value: 524287 },
    ];
    let bytes = mutations_to_vecpak(&muts);
    assert_eq!(to_mutations(&bytes), muts);
    let canonical = |pairs: Vec<(&[u8], Term)>| Term::PropList(pairs.into_iter().map(|(k, v)| (Term::Binary(k.to_vec()), v)).collect());
    let via_bigint = vecpak::encode(Term::List(vec![
        canonical(vec![(b"key", Term::Binary(t(b"k"))), (b"op", Term::Binary(t(b"delete"))), (b"table", Term::Binary(t(b"contractstate")))]),
        canonical(vec![(b"value", Term::Binary(vec![])), (b"table", Term::Binary(t(b"contractstate"))), (b"op", Term::Binary(t(b"put"))), (b"key", Term::Binary(t(b"k")))]),
        canonical(vec![(b"bloomsize", Term::BigInt(65536.into())), (b"value", Term::BigInt(0.into())), (b"key", Term::Binary(t(b"p"))), (b"op", Term::Binary(t(b"set_bit"))), (b"table", Term::Binary(t(b"contractstate")))]),
        canonical(vec![(b"value", Term::BigInt(524287.into())), (b"key", Term::Binary(t(b"p"))), (b"op", Term::Binary(t(b"clear_bit"))), (b"table", Term::Binary(t(b"contractstate")))]),
    ])).unwrap();
    assert_eq!(bytes, via_bigint);
}
