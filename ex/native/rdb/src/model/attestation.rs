use crate::model::_codec as codec;
use crate::model::_codec::{DecodeFromTerm, EncodeToTerm};
use vecpak::Term;

#[derive(Debug, Clone)]
pub struct Attestation {
    pub entry_hash: Vec<u8>,
    pub mutations_hash: Vec<u8>,
    pub signer: Vec<u8>,
    pub signature: Vec<u8>,
}
impl EncodeToTerm for Attestation {
    fn to_term(&self) -> Result<Term, &'static str> {
        Ok(Term::PropList(vec![
            (Term::Binary(b"entry_hash".to_vec()), Term::Binary(self.entry_hash.to_vec())),
            (Term::Binary(b"mutations_hash".to_vec()), Term::Binary(self.mutations_hash.to_vec())),
            (Term::Binary(b"signer".to_vec()), Term::Binary(self.signer.to_vec())),
            (Term::Binary(b"signature".to_vec()), Term::Binary(self.signature.to_vec())),
        ]))
    }
}
impl DecodeFromTerm for Attestation {
    fn from_term(t: &Term) -> Self {
        let Term::PropList(pairs) = t else { unreachable!() };

        let entry_hash = codec::pl_get_bytes(pairs, b"entry_hash").to_vec();
        let mutations_hash = codec::pl_get_bytes(pairs, b"mutations_hash").to_vec();
        let signer = codec::pl_get_bytes(pairs, b"signer").to_vec();
        let signature = codec::pl_get_bytes(pairs, b"signature").to_vec();

        Attestation { entry_hash, mutations_hash, signer, signature }
    }
}
