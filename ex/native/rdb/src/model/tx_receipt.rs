use crate::model::_codec as codec;
use crate::model::_codec::{DecodeFromTerm, EncodeToTerm};
use vecpak::Term;

#[derive(Debug, Clone)]
pub struct TXReceipt {
    pub txid: Vec<u8>,
    pub success: bool,
    pub result: Vec<u8>,
    pub exec_used: Vec<u8>,
    pub logs: Vec<Vec<u8>>,
}

impl EncodeToTerm for TXReceipt {
    fn to_term(&self) -> Result<Term, &'static str> {
        Ok(Term::PropList(vec![
            (Term::Binary(b"txid".to_vec()), Term::Binary(self.txid.to_vec())),
            (Term::Binary(b"success".to_vec()), Term::Bool(self.success)),
            (Term::Binary(b"result".to_vec()), Term::Binary(self.result.to_vec())),
            (Term::Binary(b"exec_used".to_vec()), Term::Binary(self.exec_used.to_vec())),
            (Term::Binary(b"logs".to_vec()), Term::List(self.logs.iter().map(|log| Term::Binary(log.clone())).collect())),
        ]))
    }
}

impl DecodeFromTerm for TXReceipt {
    fn from_term(t: &Term) -> Self {
        let Term::PropList(pairs) = t else { unreachable!() };

        let txid = codec::pl_get_bytes(pairs, b"txid").to_vec();
        let success = codec::pl_get_bool(pairs, b"success");
        let result = codec::pl_get_bytes(pairs, b"result").to_vec();
        let exec_used = codec::pl_get_bytes(pairs, b"exec_used").to_vec();
        let logs = codec::pl_get_list_of_bytes(pairs, b"logs");

        TXReceipt { txid, success, result, exec_used, logs }
    }
}
