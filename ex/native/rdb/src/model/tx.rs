use crate::model::_codec as codec;
use crate::model::_codec::{DecodeFromTerm, EncodeToTerm};
use vecpak::Term;

#[derive(Debug, Clone)]
pub struct Action {
    pub op: Vec<u8>,
    pub contract: Vec<u8>,
    pub function: Vec<u8>,
    pub args: Vec<Vec<u8>>,
    pub attached_symbol: Option<Vec<u8>>,
    pub attached_amount: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TX {
    pub signer: Vec<u8>,
    pub nonce: u64,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub struct TXU {
    pub hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub tx: TX,
}

impl EncodeToTerm for Action {
    fn to_term(&self) -> Result<Term, &'static str> {
        let args_list: Vec<Term> = self.args.iter().map(|a| Term::Binary(a.clone())).collect();

        let mut pairs = vec![
            (Term::Binary(b"op".to_vec()), Term::Binary(self.op.clone())),
            (Term::Binary(b"contract".to_vec()), Term::Binary(self.contract.clone())),
            (Term::Binary(b"function".to_vec()), Term::Binary(self.function.clone())),
            (Term::Binary(b"args".to_vec()), Term::List(args_list)),
        ];

        if let Some(ref sym) = self.attached_symbol {
            pairs.push((Term::Binary(b"attached_symbol".to_vec()), Term::Binary(sym.clone())));
        }

        if let Some(ref amt) = self.attached_amount {
            pairs.push((Term::Binary(b"attached_amount".to_vec()), Term::Binary(amt.clone())));
        }

        Ok(Term::PropList(pairs))
    }
}

impl DecodeFromTerm for Action {
    fn from_term(t: &Term) -> Self {
        let Term::PropList(pairs) = t else { unreachable!("Expected PropList for Action") };

        let op = codec::pl_get_bytes(pairs, b"op").to_vec();
        let contract = codec::pl_get_bytes(pairs, b"contract").to_vec();
        let function = codec::pl_get_bytes(pairs, b"function").to_vec();

        let args_term_list = codec::pl_get_list(pairs, b"args");
        let args = args_term_list
            .iter()
            .map(|item| match item {
                Term::Binary(b) => b.clone(),
                _ => Vec::new(),
            })
            .collect();

        let attached_symbol = codec::pl_get_bytes_opt(pairs, b"attached_symbol").map(|b| b.to_vec());
        let attached_amount = codec::pl_get_bytes_opt(pairs, b"attached_amount").map(|b| b.to_vec());

        Action { op, contract, function, args, attached_symbol, attached_amount }
    }
}

impl EncodeToTerm for TX {
    fn to_term(&self) -> Result<Term, &'static str> {
        Ok(Term::PropList(vec![
            (Term::Binary(b"signer".to_vec()), Term::Binary(self.signer.clone())),
            (Term::Binary(b"nonce".to_vec()), Term::VarInt(self.nonce as i128)),
            (Term::Binary(b"action".to_vec()), self.action.to_term()?),
        ]))
    }
}

impl DecodeFromTerm for TX {
    fn from_term(t: &Term) -> Self {
        let Term::PropList(pairs) = t else { unreachable!("Expected PropList for TX") };

        let signer = codec::pl_get_bytes(pairs, b"signer").to_vec();
        let nonce = codec::pl_get_varint(pairs, b"nonce") as u64;

        let action_term = codec::pl_find(pairs, b"action");
        let action = Action::from_term(action_term);

        TX { signer, nonce, action }
    }
}

pub fn to_bytes_tx(tx: &TX) -> Result<Vec<u8>, &'static str> {
    let term = tx.to_term()?;
    Ok(vecpak::encode(term))
}

impl EncodeToTerm for TXU {
    fn to_term(&self) -> Result<Term, &'static str> {
        Ok(Term::PropList(vec![
            (Term::Binary(b"hash".to_vec()), Term::Binary(self.hash.clone())),
            (Term::Binary(b"signature".to_vec()), Term::Binary(self.signature.clone())),
            (Term::Binary(b"tx".to_vec()), self.tx.to_term()?),
        ]))
    }
}

impl DecodeFromTerm for TXU {
    fn from_term(t: &Term) -> Self {
        let Term::PropList(pairs) = t else { unreachable!("Expected PropList for TXU") };

        let hash = codec::pl_get_bytes(pairs, b"hash").to_vec();
        let signature = codec::pl_get_bytes(pairs, b"signature").to_vec();

        let tx_term = codec::pl_find(pairs, b"tx");
        let tx = TX::from_term(tx_term);

        TXU { hash, signature, tx }
    }
}

pub fn from_bytes(data: &[u8]) -> Result<TXU, &'static str> {
    let term = vecpak::decode(data)?;
    Ok(TXU::from_term(&term))
}
